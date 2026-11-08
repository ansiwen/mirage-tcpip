(*
 * Copyright (c) 2010-2012 Anil Madhavapeddy <anil@recoil.org>
 * Copyright (c) 2012 Balraj Singh <bs375@cl.cam.ac.uk>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *)

open Lwt.Infix

let src = Logs.Src.create "tcp.pcb" ~doc:"Mirage TCP PCB module"
module Log = (val Logs.src_log src : Logs.LOG)

module Make(Ip: Tcpip.Ip.S) =
struct

  module ACK = Ack.Immediate
  module RXS = Segment.Rx(ACK)
  module TXS = Segment.Tx
  module UTX = User_buffer.Tx
  module WIRE = Wire.Make(Ip)
  module KEEPALIVE = Keepalive

  type error = [ Tcpip.Tcp.error | WIRE.error | `No_free_port ]

  let pp_error ppf = function
    | `No_free_port -> Fmt.string ppf "no free local port for the connection"
    | #Tcpip.Tcp.error as e -> Tcpip.Tcp.pp_error ppf e
    | #WIRE.error as e -> WIRE.pp_error ppf e

  type write_error = [Tcpip.Tcp.write_error | `Not_ready]

  let pp_write_error ppf = function
    | `Not_ready ->
      Fmt.string ppf "attempted to send data before connection was ready"
    | #Tcpip.Tcp.write_error as e -> Tcpip.Tcp.pp_write_error ppf e

  type ipaddr = Ip.ipaddr

  type pcb = {
    id: WIRE.t;
    wnd: Window.t;            (* Window information *)
    rxq: RXS.t;               (* Received segments queue for out-of-order data *)
    txq: TXS.t;               (* Transmit segments queue *)
    ack: ACK.t;               (* Ack state *)
    state: State.t;           (* Connection state *)
    urx: User_buffer.Rx.t;    (* App rx buffer *)
    utx: UTX.t;               (* App tx buffer *)
    keepalive: KEEPALIVE.t option; (* Optional TCP keepalive state *)
  }

  type flow = pcb
  type connection = flow * unit Lwt.t

  type t = {
    ip : Ip.t;
    listeners : (int, Tcpip.Tcp.Keepalive.t option * (flow -> unit Lwt.t)) Hashtbl.t ;
    mutable active : bool ;
    channels: (WIRE.t, connection) Hashtbl.t;
    (* server connections the process of connecting - SYN-ACK sent
       waiting for ACK *)
    listens: (WIRE.t, (Sequence.t * ((flow -> unit Lwt.t) * connection)))
        Hashtbl.t;
    (* clients in the process of connecting *)
    connects: (WIRE.t, ((connection, error) result Lwt.u * Sequence.t * Tcpip.Tcp.Keepalive.t option)) Hashtbl.t;
  }

  let num_open_channels t = Hashtbl.length t.channels

  let listen t ~port ?keepalive cb =
    if port < 0 || port > 65535 then
      raise (Invalid_argument (Printf.sprintf "invalid port number (%d)" port))
    else
      Hashtbl.replace t.listeners port (keepalive, cb)

  let unlisten t ~port = Hashtbl.remove t.listeners port

  let _pp_pcb fmt pcb =
    Format.fprintf fmt "id=[%a] state=[%a]" WIRE.pp pcb.id State.pp pcb.state

  let pp_stats fmt t =
    Format.fprintf fmt "[channels=%d listens=%d connects=%d]"
      (Hashtbl.length t.channels)
      (Hashtbl.length t.listens)
      (Hashtbl.length t.connects)

  let log_with_stats name t = Log.debug (fun fmt -> fmt "%s: %a" name pp_stats t)

  let wscale_default = 2

  module Tx = struct

    (* Output a TCP packet, and calculate some settings from a state descriptor *)
    let xmit_pcb ip id ~flags ~wnd ~options ~seq (datav : Cstruct.t) =
      let window = Int32.to_int (Window.rx_wnd_unscaled wnd) in
      let rx_ack = Some (Window.rx_nxt wnd) in
      let syn = match flags with Segment.Syn -> true | _ -> false in
      let fin = match flags with Segment.Fin -> true | _ -> false in
      let rst = match flags with Segment.Rst -> true | _ -> false in
      let psh = match flags with Segment.Psh -> true | _ -> false in
      WIRE.xmit ~ip id ~syn ~fin ~rst ~psh ~rx_ack ~seq ~window ~options datav

    (* Reply with a RST to a segment that belongs to no connection (RFC 9293
       3.10.7.1): if it carried an ACK, the RST takes its sequence number from
       that ACK (and has no ACK itself); otherwise it has sequence number 0
       and acknowledges everything the segment occupied.  A RST is never
       answered with a RST. *)
    let send_rst { ip; _ } id (h : Tcp_packet.t) ~payload_len =
      if h.Tcp_packet.rst then Lwt.return_unit
      else
        let seq, rx_ack =
          if h.Tcp_packet.ack then h.Tcp_packet.ack_number, None
          else
            let len = payload_len + (if h.Tcp_packet.syn then 1 else 0)
                      + (if h.Tcp_packet.fin then 1 else 0) in
            Sequence.zero, Some Sequence.(add h.Tcp_packet.sequence (of_int len))
        in
        WIRE.xmit ~ip id ~rst:true ~rx_ack ~seq ~window:0 ~options:[] Cstruct.empty
        >|= fun _ -> () (* discard errors; we won't retry *)

    (* Output a SYN packet *)
    let send_syn { ip; _ } id ~tx_isn ~options ~window =
      WIRE.xmit ~ip id ~syn:true ~rx_ack:None ~seq:tx_isn ~window ~options
        (Cstruct.create 0)

    (* Queue up an immediate close segment *)
    let shutdown ctx pcb =
      Log.debug (fun f -> f "%s connection %a" (match ctx with `Close -> "Closing" | `Shutdown -> "Shutting down") WIRE.pp pcb.id);
      if ctx = `Close then State.user_close pcb.state;
      match State.state pcb.state with
      | State.Established | State.Close_wait ->
        UTX.wait_for_flushed pcb.utx >>= fun () ->
        (* the connection may have been reset or timed out while flushing *)
        begin match State.state pcb.state with
          | State.Established | State.Close_wait ->
            State.tick pcb.state (State.Send_fin (Window.tx_nxt pcb.wnd));
            TXS.output ~flags:Segment.Fin pcb.txq Cstruct.empty
          | _ -> Lwt.return_unit
        end
      | State.Closed | State.Syn_rcvd _ | State.Syn_sent _ when ctx = `Close ->
        State.on_close pcb.state;
        Lwt.return_unit
      | _ ->
        Log.debug (fun fmt ->
            let msg = match ctx with `Close -> "close" | `Shutdown -> "shutdown" in
            fmt "TX.%s: %s requested but no action needed, state=%a" msg msg State.pp pcb.state);
        Lwt.return_unit

    (* Thread that transmits ACKs in response to received packets,
       thus telling the other side that more can be sent, and
       also data from the user transmit queue *)
    let thread t pcb ~send_ack ~rx_ack  =
      let { wnd; ack; _ } = pcb in

      (* Transmit an empty ack when prompted by the Ack thread *)
      let rec send_empty_ack () =
        Lwt_mvar.take send_ack >>= fun _ ->
        let ack_number = Window.rx_nxt wnd in
        let flags = Segment.No_flags in
        let options = [] in
        let seq = Window.tx_nxt wnd in
        ACK.transmit ack ack_number >>= fun () ->
        xmit_pcb t.ip pcb.id ~flags ~wnd ~options ~seq (Cstruct.create 0) >>=
        fun _ -> (* TODO: what to do if sending failed.  Ignoring
                  * errors gives us the same behavior as if the packet
                  * was lost in transit *)
        send_empty_ack () in
      (* When something transmits an ACK, tell the delayed ACK thread *)
      let rec notify () =
        Lwt_mvar.take rx_ack >>= fun ack_number ->
        ACK.transmit ack ack_number >>= fun () ->
        notify () in
      send_empty_ack () <&> (notify ())
  end

  module Rx = struct

    (* Process an incoming TCP packet that has an active PCB *)
    let input _t parsed (pcb,_) =
      let { rxq; _ } = pcb in
      (* The connection is alive! (Only an acceptable segment counts: anyone
         can send a packet with the right addresses and ports.) *)
      begin match pcb.keepalive with
      | Some keepalive when RXS.acceptable rxq parsed -> KEEPALIVE.refresh keepalive
      | _ -> ()
      end;
      (* Coalesce any outstanding segments and retrieve ready segments *)
      RXS.input rxq parsed

    let shutdown pcb =
      User_buffer.Rx.remove_all pcb.urx;
      User_buffer.Rx.add_r pcb.urx None

    (* Thread that spools the data into an application receive buffer,
       and notifies the ACK subsystem that new data is here *)
    let thread pcb ~rx_data =
      let { wnd; ack; urx; _ } = pcb in
      (* Set once the peer's FIN was delivered.  The thread keeps running after
         that: segments still arrive (e.g. a retransmitted FIN whose ACK was
         lost) and must be ACKed, and [Segment.Rx.input] blocks on [rx_data]
         if nobody takes from it. *)
      let fin_received = ref false in
      (* Thread to monitor application receive and pass it up *)
      let rec rx_application_t () =
        Lwt_mvar.take rx_data >>= fun (data, winadv) ->
        let signal_ack = function
          | None        -> Lwt.return_unit
          | Some winadv when Sequence.(gt winadv zero) ->
              Window.rx_advance wnd winadv;
              ACK.receive ack (Window.rx_nxt wnd)
          | Some winadv ->
              Window.rx_advance wnd winadv;
              ACK.pushack ack (Window.rx_nxt wnd)
        in
        begin match data with
          | None ->
            (* don't send an ACK in this case; this already happened *)
            if !fin_received then rx_application_t ()
            else begin
              fin_received := true;
              State.tick pcb.state State.Recv_fin;
              User_buffer.Rx.add_r urx None >>= fun () ->
              rx_application_t ()
            end
          | Some data ->
            let rec queue = function
              | []     -> Lwt.return_unit
              | hd::tl ->
                User_buffer.Rx.add_r urx (Some hd) >>= fun () ->
                queue tl
            in
            (* Queue the data before ACKing it, so that the ACK advertises the
               receive window with this data already accounted for.  Data
               after the FIN is a protocol violation; don't deliver it. *)
            (if !fin_received then Lwt.return_unit else queue data) >>= fun () ->
            signal_ack winadv >>= fun () ->
            rx_application_t ()
        end
      in
      rx_application_t ()
  end

  module Wnd = struct

    let thread ~urx:_ ~utx ~wnd:_ ~state ~tx_wnd_update =
      (* Monitor our transmit window when updates are received
         remotely, and tell the application that new space is
         available when it is blocked *)
      let rec tx_window_t () =
        Lwt_mvar.take tx_wnd_update >>= fun tx_wnd ->
        begin match State.state state with
          | State.Reset -> UTX.reset utx
          | _ -> UTX.free utx tx_wnd
        end >>= fun () ->
        tx_window_t ()
      in
      tx_window_t ()

  end

  (* Helper function to apply function with contents of hashtbl, or
     take default action *)
  let with_hashtbl h k fn default =
    try fn (Hashtbl.find h k) with Not_found -> default k

  let hashtbl_find h k =
    try Some (Hashtbl.find h k) with Not_found -> None

  (* [wnd] identifies the connection being closed: a stale connection (e.g. an
     abandoned half-open one) must not remove a newer connection that reuses
     the same address/port tuple. *)
  let clearpcb t id tx_isn wnd =
    log_with_stats "removing pcb from connection tables" t;
    match hashtbl_find t.channels id with
    | Some (pcb, _) when pcb.wnd == wnd ->
      Hashtbl.remove t.channels id;
      Stats.decr_channel ();
      Log.debug (fun f -> f "removed %a from active channels" WIRE.pp id);
    | Some _ | None ->
      match hashtbl_find t.listens id with
      | Some (isn, _) ->
        if isn = tx_isn then (
          Hashtbl.remove t.listens id;
          Stats.decr_listen ();
          Log.debug (fun f -> f "removed %a from incomplete listen pcbs" WIRE.pp id);
        )
      | None ->
        Log.debug (fun f -> f "error in removing %a - no such connection" WIRE.pp id)

  let pcb_allocs = ref 0
  let th_allocs = ref 0
  let pcb_frees = ref 0
  let th_frees = ref 0

  let resolve_wnd_scaling options rx_wnd_scaleoffer =
    let tx_wnd_scale = List.fold_left (fun a ->
        function Options.Window_size_shift m -> Some m | _ -> a
      ) None options in
    match tx_wnd_scale with
    | None -> (0, 0), []
    | Some tx_f ->
      (* RFC 7323 2.3: a shift count above 14 MUST be treated as 14 *)
      let tx_f =
        if tx_f > 14 then begin
          Log.warn (fun f -> f "peer sent window scale %d, using 14" tx_f);
          14
        end else tx_f
      in
      (rx_wnd_scaleoffer, tx_f),
      (Options.Window_size_shift rx_wnd_scaleoffer :: [])

  type pcb_params =
    { tx_wnd: int;
      sequence: Sequence.t;
      options: Options.t list;
      tx_isn: Sequence.t;
      rx_wnd: int;
      rx_wnd_scaleoffer: int }


  let keepalive_cb t id wnd state urx = function
  | `SendProbe ->
    Log.debug (fun f -> f "Sending keepalive on connection %a" WIRE.pp id);
    (* From https://tools.ietf.org/html/rfc1122#page-101

      > 4.2.3.6  TCP Keep-Alives
      ...
      > Such a segment generally contains SEG.SEQ =
      > SND.NXT-1 and may or may not contain one garbage octet
      > of data.  Note that on a quiet connection SND.NXT =
      > RCV.NXT, so that this SEG.SEQ will be outside the
      > window.  Therefore, the probe causes the receiver to
      > return an acknowledgment segment, confirming that the
      > connection is still live.  If the peer has dropped the
      > connection due to a network partition or a crash, it
      > will respond with a RST instead of an acknowledgment
      > segment.
    *)
    let flags = Segment.No_flags in
    let options = [] in
    let seq = Sequence.pred @@ Window.tx_nxt wnd in
    (* if the sending fails this behaves like a packet drop which will cause
        the connection to be eventually closed after the probes are sent *)
    Tx.xmit_pcb t.ip id ~flags ~wnd ~options ~seq (Cstruct.create 0) >>= fun _ ->
    Lwt.return_unit
  | `Close ->
    Log.debug (fun f -> f "Keepalive timer expired, resetting connection %a" WIRE.pp id);
    State.tick state State.Recv_rst;
    (* Close the read direction *)
    User_buffer.Rx.add_r urx None >>= fun () ->
    Lwt.return_unit

  let emitted_keepalive_warning = ref false

  let pcb_id = ref (-1)

  let new_pcb t params id keepalive =
    let mtu_mss = Ip.mtu t.ip ~dst:(WIRE.dst id) - Tcp_wire.sizeof_tcp in
    let { tx_wnd; sequence; options; tx_isn; rx_wnd; rx_wnd_scaleoffer } =
      params
    in
    let tx_mss = List.fold_left (fun a ->
      function
      | Options.MSS m -> min m mtu_mss
      | _ -> a
    ) mtu_mss options
    in
    let (rx_wnd_scale, tx_wnd_scale), opts =
      resolve_wnd_scaling options rx_wnd_scaleoffer
    in
    (* Set up the windowing variables *)
    let rx_isn = sequence in
    (* Initialise the window handler *)
    let wnd =
      Window.t ~rx_wnd_scale ~tx_wnd_scale ~rx_wnd ~tx_wnd ~rx_isn ~tx_mss
        ~tx_isn
    in
    (* When we transmit an ACK for a received segment, rx_ack is written to *)
    let rx_ack = Lwt_mvar.create_empty () in
    (* When we receive an ACK for a transmitted segment, tx_ack is written to *)
    let tx_ack = Lwt_mvar.create_empty () in
    (* When new data is received, rx_data is written to *)
    let rx_data = Lwt_mvar.create_empty () in
    (* Write to this mvar to transmit an empty ACK to the remote side *)
    let send_ack = Lwt_mvar.create_empty () in
    (* The user application receive buffer and close notification *)
    let rx_buf_size = Window.rx_wnd wnd in
    (* Set up ACK module *)
    let ack = ACK.t ~send_ack ~last:(Sequence.succ rx_isn) in
    let on_window_update () = ACK.pushack ack (Window.rx_nxt wnd) in
    let urx = User_buffer.Rx.create ~max_size:rx_buf_size ~wnd ~on_window_update in
    (* The window handling thread *)
    let tx_wnd_update = Lwt_mvar.create_empty () in
    (* Set up transmit and receive queues *)
    (* Set once [utx] exists (it depends on [state], which needs [on_close]). *)
    let wake_writers = ref (fun () -> Lwt.return_unit) in
    let on_close () =
      clearpcb t id tx_isn wnd;
      (* The connection is gone (normal close, reset, retransmission or
         FIN_WAIT_2 timeout): blocked readers get [`Eof] and blocked writers
         [`Closed], as documented for [Tcpip.Tcp.S], instead of hanging. *)
      Lwt.async (fun () -> User_buffer.Rx.add_r urx None);
      Lwt.async (fun () -> !wake_writers ())
    in
    let state =
      incr pcb_id;
      State.t ~id:!pcb_id ~on_close
    in
    let txq, _tx_t =
      TXS.create ~xmit:(Tx.xmit_pcb t.ip id) ~wnd ~state ~rx_ack ~tx_ack ~tx_wnd_update
    in
    (* The user application transmit buffer *)
    let utx = UTX.create ~wnd ~txq ~max_size:16384l in
    wake_writers := (fun () -> UTX.reset utx);
    let rxq = RXS.create ~rx_data ~ack ~wnd ~state ~tx_ack in
    (* Set up the keepalive state if requested *)
    let keepalive = match keepalive with
      | None -> None
      | Some config ->
        (* Only omit the warning once to avoid spamming the logs *)
	if not !emitted_keepalive_warning then begin
          Log.warn (fun f -> f "using keep-alives can cause excessive memory consumption: https://github.com/mirage/mirage-tcpip/issues/367");
          emitted_keepalive_warning := true
        end;
        Some (KEEPALIVE.create config (keepalive_cb t id wnd state urx)) in
    (* Construct basic PCB in Syn_received state *)
    let pcb = { state; rxq; txq; wnd; id; ack; urx; utx; keepalive } in
    (* Compose the overall thread from the various tx/rx threads
       and the main listener function *)
    let tx_thread = (Tx.thread t pcb ~send_ack ~rx_ack) in
    let rx_thread = (Rx.thread pcb ~rx_data) in
    let wnd_thread = (Wnd.thread ~utx ~urx ~wnd ~state ~tx_wnd_update) in
    let threads = [ tx_thread; rx_thread; wnd_thread ] in
    let catch_and_cancel = function
      | Lwt.Canceled -> ()
      | ex ->
        (* cancel the other threads *)
        List.iter Lwt.cancel threads;
        Log.err (fun f -> f "thread failure: [%s]. Terminating threads and closing connection"
                    (Printexc.to_string ex));
        on_close ();
        !Lwt.async_exception_hook ex
    in
    List.iter (fun t -> Lwt.on_failure t catch_and_cancel) threads;
    let th = Lwt.join threads in
    pcb_allocs := !pcb_allocs + 1;
    th_allocs := !th_allocs + 1;
    let fnpcb = fun _ -> pcb_frees := !pcb_frees + 1 in
    let fnth = fun _ -> th_frees := !th_frees + 1 in
    Gc.finalise fnpcb pcb;
    Gc.finalise fnth th;
    Lwt.return (pcb, th, opts)

  let new_server_connection t params id pushf keepalive =
    log_with_stats "new-server-connection" t;
    new_pcb t params id keepalive >>= fun (pcb, th, opts) ->
    State.tick pcb.state State.Passive_open;
    State.tick pcb.state (State.Send_synack params.tx_isn);
    (* Add the PCB to our listens table ([process_syn] removed any previous
       half-open connection for this id) *)
    Hashtbl.add t.listens id (params.tx_isn, (pushf, (pcb, th)));
    Stats.incr_listen ();
    (* Queue a SYN ACK for transmission *)
    let options = Options.MSS (Ip.mtu t.ip ~dst:(WIRE.dst id) - Tcp_wire.sizeof_tcp) :: opts in
    TXS.output ~flags:Segment.Syn ~options pcb.txq (Cstruct.create 0) >>= fun () ->
    Lwt.return (pcb, th)

  let new_client_connection t params id ack_number keepalive =
    log_with_stats "new-client-connection" t;
    let tx_isn = params.tx_isn in
    let params = { params with tx_isn = Sequence.succ tx_isn } in
    new_pcb t params id keepalive >>= fun (pcb, th, _) ->
    (* A hack here because we create the pcb only after the SYN-ACK is rx-ed*)
    State.tick pcb.state (State.Send_syn tx_isn);
    (* Add the PCB to our connection table *)
    Hashtbl.add t.channels id (pcb, th);
    Stats.incr_channel ();
    State.tick pcb.state (State.Recv_synack ack_number);
    (* xmit ACK *)
    TXS.output pcb.txq (Cstruct.create 0) >>= fun () ->
    Lwt.return (pcb, th)

  let is_correct_ack ~tx_isn ~ack_number =
   (Sequence.compare (Sequence.succ tx_isn) ack_number) = 0

  (* Upper bound on half-open (SYN-RCVD) connections, so that a SYN flood
     cannot exhaust memory.  SYNs beyond it are dropped; the client will
     retransmit. *)
  let max_half_open = 1024

  let process_reset t id (h : Tcp_packet.t) =
    log_with_stats "process-reset" t;
    match hashtbl_find t.connects id with
    | Some (wakener, tx_isn, _) ->
      (* SYN-SENT: the RST is acceptable only if it acknowledges our SYN *)
      if h.ack && is_correct_ack ~tx_isn ~ack_number:h.ack_number then begin
        Hashtbl.remove t.connects id;
        Stats.decr_connect ();
        Lwt.wakeup wakener (Error `Refused)
      end;
      Lwt.return_unit
    | None ->
      match hashtbl_find t.listens id with
      | Some (_, (_, (pcb, th))) ->
        (* SYN-RCVD (RFC 5961 3.2): reset only if the sequence number is
           exactly the next expected one; answer a merely in-window RST with
           a challenge ACK, so that a blind RST cannot kill the connection. *)
        if Sequence.compare h.sequence (Window.rx_nxt pcb.wnd) = 0 then begin
          Hashtbl.remove t.listens id;
          Stats.decr_listen ();
          State.tick pcb.state State.Recv_rst;
          Lwt.cancel th;
          Lwt.return_unit
        end else if Window.valid pcb.wnd h.sequence then
          ACK.pushack pcb.ack (Window.rx_nxt pcb.wnd)
        else Lwt.return_unit
      | None ->
        (* no connection: a RST is never answered *)
        Lwt.return_unit

  let process_synack t id (h : Tcp_packet.t) ~payload_len =
    log_with_stats "process-synack" t;
    match hashtbl_find t.connects id with
    | Some (wakener, tx_isn, keepalive) ->
      if is_correct_ack ~tx_isn ~ack_number:h.ack_number then (
        Hashtbl.remove t.connects id;
        Stats.decr_connect ();
        let rx_wnd = 65535 in
        (* TODO: fix hardcoded value - it assumes that this value was
           sent in the SYN *)
        let rx_wnd_scaleoffer = wscale_default in
        new_client_connection t
          { tx_wnd = h.window; sequence = h.sequence; options = h.options;
            tx_isn; rx_wnd; rx_wnd_scaleoffer }
          id h.ack_number keepalive
        >>= fun (pcb, th) ->
        Lwt.wakeup wakener (Ok (pcb, th));
        Lwt.return_unit
      ) else
        (* SYN-SENT, unacceptable ACK: reset it (RFC 9293 3.10.7.3) *)
        Tx.send_rst t id h ~payload_len
    | None ->
      (* Incoming SYN-ACK with no pending connect and no matching pcb *)
      Tx.send_rst t id h ~payload_len

  let process_syn t id (h : Tcp_packet.t) ~payload_len =
    log_with_stats "process-syn" t;
    match Hashtbl.find_opt t.listeners (WIRE.src_port id) with
    | Some (keepalive, process) ->
      begin match hashtbl_find t.listens id with
      | Some (_, (_, (pcb, _))) when Sequence.succ h.sequence = Window.rx_nxt pcb.wnd ->
        (* The client retransmitted its SYN (our SYN-ACK was lost or is still
           in flight): answer with the original SYN-ACK, same ISN and options.
           Creating a new connection here would give the client two SYN-ACKs
           with different ISNs, and its ACK of the first would be dropped. *)
        Log.debug (fun f -> f "retransmitted SYN on %a, resending SYN-ACK" WIRE.pp id);
        TXS.retransmit_head pcb.txq
      | None when Hashtbl.length t.listens >= max_half_open ->
        Log.debug (fun f -> f "SYN backlog full (%d), dropping SYN on %a"
                      max_half_open WIRE.pp id);
        Lwt.return_unit
      | old ->
      (match old with
       | Some (_, (_, (pcb, th))) ->
         (* A SYN with a different ISN is a new connection attempt from the
            same port: abandon the old half-open connection.  Moving it to
            Closed stops its SYN-ACK retransmissions. *)
         Log.debug (fun f -> f "new SYN on %a replaces half-open connection" WIRE.pp id);
         Hashtbl.remove t.listens id;
         Stats.decr_listen ();
         State.tick pcb.state State.Recv_rst;
         Lwt.cancel th
       | None -> ());
      let tx_isn = Sequence.of_int32 (Randomconv.int32 Mirage_crypto_rng.generate) in
      (* TODO: make this configurable per listener *)
      let rx_wnd = 65535 in
      let rx_wnd_scaleoffer = wscale_default in
      new_server_connection t
        { tx_wnd = h.window; sequence = h.sequence; options = h.options;
          tx_isn; rx_wnd; rx_wnd_scaleoffer }
        id process keepalive
      >>= fun _ ->
      Lwt.return_unit
      end
    | None ->
      Tx.send_rst t id h ~payload_len

  let process_ack t id ~pkt =
    let open RXS in
    log_with_stats "process-ack" t;
    let payload_len = Cstruct.length pkt.payload in
    match hashtbl_find t.listens id with
    | Some (tx_isn, (pushf, newconn)) ->
      if Tcp_packet.(is_correct_ack ~tx_isn ~ack_number:pkt.header.ack_number) then begin
        (* Established connection - promote to active channels *)
        Hashtbl.remove t.listens id;
        Stats.decr_listen ();
        Hashtbl.add t.channels id newconn;
        Stats.incr_channel ();
        (* Finish processing ACK, so pcb.state is correct *)
        Rx.input t pkt newconn >>= fun () ->
        (* send new connection up to listener *)
        pushf (fst newconn)
      end else
        (* SYN-RCVD, unacceptable ACK: reset it (RFC 9293 3.10.7.4) *)
        Tx.send_rst t id pkt.header ~payload_len
    | None ->
      match hashtbl_find t.connects id with
      | Some (_, tx_isn, _) ->
        (* SYN-SENT: an acceptable ACK without SYN is dropped, an
           unacceptable one is reset (RFC 9293 3.10.7.3) *)
        if is_correct_ack ~tx_isn ~ack_number:pkt.header.ack_number
        then Lwt.return_unit
        else Tx.send_rst t id pkt.header ~payload_len
      | None ->
        (* ACK but no matching pcb and no listen - send RST *)
        Tx.send_rst t id pkt.header ~payload_len

  let input_no_pcb t (parsed, payload) id =
    if not t.active then
      (* TODO: eventually send an RST? *)
      Lwt.return_unit
    else
      let { Tcp_packet.syn; rst; ack; _ } = parsed in
      let payload_len = Cstruct.length payload in
      match rst, syn, ack with
      | true, _, _ -> process_reset t id parsed
      | false, true, true -> process_synack t id parsed ~payload_len
      | false, true , false -> process_syn t id parsed ~payload_len
      | false, false, true  ->
        let open RXS in
        process_ack t id ~pkt:{ header = parsed; payload}
      | false, false, false ->
        (* neither SYN, ACK nor RST: dropped in SYN-SENT and SYN-RCVD, reset
           when there is no connection at all (RFC 9293 3.10.7.1) *)
        if Hashtbl.mem t.connects id || Hashtbl.mem t.listens id then
          Lwt.return_unit
        else Tx.send_rst t id parsed ~payload_len

  (* Main input function for TCP packets *)
  let input t ~src ~dst data =
    let open Tcp_packet in
    match Unmarshal.of_cstruct data with
    | Error s -> Log.debug (fun f -> f "parsing TCP header failed: %s" s);
      Lwt.return_unit
    | Ok (pkt, payload) ->
      let id =
        WIRE.v ~src_port:pkt.dst_port ~dst_port:pkt.src_port ~dst:src ~src:dst
      in
      (* Lookup connection from the active PCB hash *)
      with_hashtbl t.channels id
        (* PCB exists, so continue the connection state machine in tcp_input *)
        (Rx.input t RXS.({header = pkt; payload}))
        (* No existing PCB, so check if it is a SYN for a listening function *)
        (input_no_pcb t (pkt, payload))

  (* Blocking read on a PCB *)
  let read pcb =
    User_buffer.Rx.take_l pcb.urx
    >>= function
    | None   -> Lwt.return @@ Ok `Eof
    | Some t -> Lwt.return @@ Ok (`Data t)

  (* Maximum allowed write *)
  let write_available pcb =
    (* Our effective outgoing MTU is what can fit in a page *)
    min 4000 (min (Window.tx_mss pcb.wnd)
                (Int32.to_int (UTX.available pcb.utx)))

  (* Wait for more write space *)
  let write_wait_for pcb sz =
    UTX.wait_for pcb.utx (Int32.of_int sz)

  let rec writefn pcb wfn data =
    match State.state pcb.state with
    (* but it's only appropriate to send data if the connection is ready for it *)
    | State.Established | State.Close_wait -> begin
      let len = Cstruct.length data in
      match write_available pcb with
      | 0 -> (* no room at all; we must wait *)
        write_wait_for pcb 1 >>= fun () ->
        writefn pcb wfn data
      | av_len when av_len >= len -> (* we have enough room for the whole packet *)
        wfn [data] >>= fun n -> Lwt.return (Ok n)
      | av_len -> (* partial send is possible *)
        let sendable = Cstruct.sub data 0 av_len in
        writefn pcb wfn sendable >>= function
        | Ok () -> writefn pcb wfn @@ Cstruct.sub data av_len (len - av_len)
        | Error _ as e -> Lwt.return e
      end
    | State.Listen | State.Syn_rcvd _ | State.Syn_sent _ ->
      Lwt.return (Error `Not_ready)
    (* flows are only handed out once established, so [Closed] here means the
       connection was torn down (e.g. retransmission timeout) *)
    | State.Closed | State.Reset | State.Fin_wait_1 _ | State.Fin_wait_2 _ | State.Closing _
    | State.Time_wait | State.Last_ack _ ->
      Lwt.return (Error `Closed)

  let rec iter_s f = function
    | [] -> Lwt.return (Ok ())
    | h :: t -> f h >>= function
      | Ok () -> iter_s f t
      | e -> Lwt.return e

  (* Blocking write on a PCB *)
  let cast x = (x :> (unit, write_error) result Lwt.t)

  let write pcb data = writefn pcb (UTX.write pcb.utx) data |> cast
  let writev pcb data = iter_s (write pcb) data |> cast

  let write_nodelay pcb data = writefn pcb (UTX.write_nodelay pcb.utx) data |> cast
  let writev_nodelay pcb data = iter_s (write_nodelay pcb) data |> cast

  (* Close *)
  let close pcb = Tx.shutdown `Close pcb

  let shutdown pcb mode =
    let wr, rd = match mode with | `read -> false, true | `write -> true, false | `read_write -> true, true in
    (if wr then Tx.shutdown `Shutdown pcb else Lwt.return_unit) >>= fun () ->
    (if rd then Rx.shutdown pcb else Lwt.return_unit)

  let dst pcb = WIRE.dst pcb.id, WIRE.dst_port pcb.id

  let src pcb = WIRE.src pcb.id, WIRE.src_port pcb.id

  (* Ephemeral port selection (RFC 6056): start at a random port in the
     range and probe each port at most once, skipping ports with a listener
     and ports already used for a connection to the same destination.
     [None] when every port is taken. *)
  let ephemeral_lo = 1024 and ephemeral_hi = 65535

  let getid t dst dst_port =
    let n = ephemeral_hi - ephemeral_lo + 1 in
    let start = Randomconv.int ~bound:n Mirage_crypto_rng.generate in
    let src = Ip.src t.ip ~dst in
    let inuse id =
      Hashtbl.mem t.listeners (WIRE.src_port id) ||
      Hashtbl.mem t.channels id ||
      Hashtbl.mem t.connects id ||
      Hashtbl.mem t.listens id
    in
    let rec probe i =
      if i = n then None
      else
        let src_port = ephemeral_lo + (start + i) mod n in
        let id = WIRE.v ~src ~src_port ~dst ~dst_port in
        if inuse id then probe (i + 1) else Some id
    in
    probe 0

  (* SYN retransmission timer *)
  let rec connecttimer t id tx_isn options window count =
    let rxtime = match count with
      | 0 -> 3 | 1 -> 6 | 2 -> 12 | 3 -> 24 | _ -> 48
    in
    Mirage_sleep.ns (Duration.of_sec rxtime) >>= fun () ->
    match hashtbl_find t.connects id with
    | None                -> Lwt.return_unit
    | Some (wakener, isn, _) ->
      if isn = tx_isn then
        if count > 3 then (
          Hashtbl.remove t.connects id;
          Stats.decr_connect ();
          Lwt.wakeup wakener (Error `Timeout);
          Lwt.return_unit
        ) else (
          Tx.send_syn t id ~tx_isn ~options ~window >>= function
          | Ok () -> connecttimer t id tx_isn options window (count + 1)
          | Error (`No_route _s) ->
            (* normal mechanism for recovery is fine *)
            connecttimer t id tx_isn options window (count + 1)
          | Error `Would_fragment ->
            (* this should not happen, if we've a transport that fragments syn..
               Fail the connect instead of leaving it pending forever. *)
            Log.err (fun m -> m "syn retransmission timer returned would fragment");
            Hashtbl.remove t.connects id;
            Stats.decr_connect ();
            Lwt.wakeup wakener (Error `Would_fragment);
            Lwt.return_unit
        )
      else Lwt.return_unit

  let connect ?keepalive t ~dst ~dst_port =
    match getid t dst dst_port with
    | None ->
      Log.warn (fun f -> f "no free local port to connect to %a:%d"
                   Ip.pp_ipaddr dst dst_port);
      Lwt.return (Error `No_free_port)
    | Some id ->
    let tx_isn = Sequence.of_int32 (Randomconv.int32 Mirage_crypto_rng.generate) in
    (* TODO: This is hardcoded for now - make it configurable *)
    let rx_wnd_scaleoffer = wscale_default in
    let options =
      Options.MSS (Ip.mtu t.ip ~dst - Tcp_wire.sizeof_tcp) :: Options.Window_size_shift rx_wnd_scaleoffer :: []
    in
    let window = 5840 in
    let th, wakener = Lwt.wait () in
    if Hashtbl.mem t.connects id then (
      Log.debug (fun f ->
          f "duplicate attempt to make a connection: [%a]. \
             Removing the old state and replacing with new attempt"
            WIRE.pp id);
      Hashtbl.remove t.connects id;
      Stats.decr_connect ();
    );
    Hashtbl.add t.connects id (wakener, tx_isn, keepalive);
    Stats.incr_connect ();
    Tx.send_syn t id ~tx_isn ~options ~window >>= function
    | Ok () | Error _ (* keep trying *) ->
      Lwt.async (fun () -> connecttimer t id tx_isn options window 0);
      th

  let log_failure daddr dport = function
  | `Timeout ->
    Log.debug (fun fmt ->
      fmt "Timeout attempting to connect to %a:%d\n%!"
        Ip.pp_ipaddr daddr dport)
  | `Refused ->
    Log.debug (fun fmt ->
      fmt "Refused connection to %a:%d\n%!"
        Ip.pp_ipaddr daddr dport)
  | e ->
    Log.debug (fun fmt ->
      fmt "%a error connecting to %a:%d\n%!"
        pp_error e Ip.pp_ipaddr daddr dport)

  let create_connection ?keepalive tcp (daddr, dport) =
    if not tcp.active then
      Lwt.return (Error `Timeout) (* TODO: custom error variant *)
    else
      connect ?keepalive tcp ~dst:daddr ~dst_port:dport >>= function
      | Error e -> log_failure daddr dport e; Lwt.return @@ Error e
      | Ok (fl, _) -> Lwt.return (Ok fl)

  (* Construct the main TCP thread *)
  let connect ip =
    let listens = Hashtbl.create 1 in
    let connects = Hashtbl.create 1 in
    let channels = Hashtbl.create 7 in
    Log.info (fun f -> f "TCP layer connected on %a"
                 Fmt.(list ~sep:(any ", ") Ip.pp_prefix)
                 (Ip.configured_ips ip));
    Lwt.return { ip; listeners = Hashtbl.create 7; active = true; channels; listens; connects }

  let disconnect t =
    t.active <- false;
    Log.info (fun f -> f "TCP layer disconnected on %a"
                 Fmt.(list ~sep:(any ", ") Ip.pp_prefix)
                 (Ip.configured_ips t.ip));
    let conns = Hashtbl.fold (fun _ (pcb, _) acc -> pcb :: acc) t.channels [] in
    Lwt_list.iter_p close conns >|= fun () ->
    Hashtbl.reset t.listens;
    Hashtbl.reset t.connects
    (* TODO: should there be Lwt tasks being cancelled? *)
end

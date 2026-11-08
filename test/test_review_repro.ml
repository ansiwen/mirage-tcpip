(* Packet-level regression tests for bugs found while reviewing src/tcp.
   Each test asserts the RFC-correct behaviour.

   - `Quick tests cover bugs that are fixed and run in the default test run.
   - The retransmission-timeout test is `Slow only because it needs ~3 minutes
     of real time for the retransmission timer to give up.
   Run one with e.g. `./test.exe test review_repro 0` from
   _build/default/test. *)

open Common
open Low_level
open Lwt.Infix

module Opt = Tcp.Options

let parse data =
  match Tcp_unmarshal.of_cstruct data with
  | Ok x -> x
  | Error e -> Alcotest.fail e

let sut_ip = Ipaddr.V4.Prefix.address sut_cidr

(* Like [Low_level.run], but the raw peer sends the first packet ([kick]) so
   the stack under test can be the passive (server) side. *)
let run_server ?(cap=5) ?(wait_fsm=true) backend ~kick (initial_state, fsm_handler) sut () =
  create_sut_stack backend >>= fun stack ->
  create_raw_stack backend >>= fun (netif, ethif, arp, rawip) ->
  let error_mbox = Lwt_mvar.create_empty () in
  let stream, pushf = Lwt_stream.create () in
  Lwt.pick [
    VNETIF_STACK.Stack.listen stack;
    begin
      let rec fsm_thread state =
        Lwt_stream.next stream >>= fun (src, dst, data) ->
        fsm_handler rawip state ~src ~dst data >>= function
        | Fsm_next s -> fsm_thread s
        | Fsm_done -> Lwt.return_unit
        | Fsm_error err -> Lwt_mvar.put error_mbox err >>= fun () -> fsm_thread state
      in
      Lwt.async (fun () ->
          V.listen netif ~header_size
            (E.input ~arpv4:(A.input arp)
               ~ipv4:(I.input
                        ~tcp:(fun ~src ~dst data -> pushf (Some (src, dst, data)); Lwt.return_unit)
                        ~udp:(fun ~src:_ ~dst:_ _ -> Lwt.return_unit)
                        ~default:(fun ~proto:_ ~src:_ ~dst:_ _ -> Lwt.return_unit)
                        rawip)
               ~ipv6:(fun _ -> Lwt.return_unit) ethif) >|= fun _ -> ());
      Lwt.pick [
        (Mirage_sleep.ns (Duration.of_sec cap) >>= fun () -> Lwt.return_some "timed out");
        (Lwt.join [
            (if wait_fsm then fsm_thread initial_state
             else (Lwt.async (fun () -> fsm_thread initial_state); Lwt.return_unit));
            sut stack;
            (Mirage_sleep.ns (Duration.of_ms 200) >>= fun () -> kick rawip);
          ] >>= fun () -> Lwt.return_none);
        (Lwt_mvar.take error_mbox >>= fun c -> Lwt.return_some c);
      ] >|= function None -> () | Some err -> Alcotest.fail err
    end
  ]

let client_port = 40000
let client_isn = 5000l
let client_id = WIRE.v ~src:server_ip ~src_port:client_port ~dst:sut_ip ~dst_port:80

let send_client_syn ?(isn=client_isn) ip =
  WIRE.xmit ~ip client_id ~syn:true ~rx_ack:None ~seq:(Sequence.of_int32 isn)
    ~window:65535 ~options:[Opt.MSS 1460; Opt.Window_size_shift 7] (Cstruct.create 0)
  >|= Result.get_ok

let sut_listens_other_port stack =
  VNETIF_STACK.Stack.TCP.listen (VNETIF_STACK.Stack.tcp stack) ~port:81 (fun _ -> Lwt.return_unit);
  Mirage_sleep.ns (Duration.of_ms 2500)

let sut_listens stack =
  VNETIF_STACK.Stack.TCP.listen (VNETIF_STACK.Stack.tcp stack) ~port:80 (fun flow ->
      VNETIF_STACK.Stack.TCP.read flow >|= fun _ -> ());
  Mirage_sleep.ns (Duration.of_sec 3)

let sut_connects_then k stack =
  let conn = VNETIF_STACK.Stack.TCP.create_connection (VNETIF_STACK.Stack.tcp stack) in
  or_error "connect" conn (Ipaddr.V4 server_ip, 80) >>= fun flow ->
  k flow >>= fun () -> Mirage_sleep.ns (Duration.of_sec 3)

let syn_ack ?(options=options) ?(window=window) ip ~src ~dst ~isn data =
  let id = reply_id_from ~src ~dst data in
  WIRE.xmit ~ip id ~syn:true ~rx_ack:(ack data) ~seq:(Sequence.of_int32 isn)
    ~window ~options (Cstruct.create 0) >|= Result.get_ok

(* 1. SYN-ACK retransmission must carry the same options (MSS, WS) as the first. *)
let synack_rexmit_options () =
  let fsm _ip state ~src:_ ~dst:_ data =
    match state with
    | `SYNACK1 when Tcp_wire.get_syn data -> Lwt.return (Fsm_next `SYNACK2) (* "lose" it *)
    | `SYNACK2 when Tcp_wire.get_syn data ->
      let pkt, _ = parse data in
      if List.exists (function Opt.Window_size_shift _ -> true | _ -> false) pkt.options
      then Lwt.return Fsm_done
      else Lwt.return (Fsm_error (Fmt.str "retransmitted SYN-ACK has options %a \
                                            (first SYN-ACK had MSS+WS)" Opt.pps pkt.options))
    | s -> Lwt.return (Fsm_next s)
  in
  `Server ((fun ip -> send_client_syn ip), (`SYNACK1, fsm), sut_listens)

(* 2. A retransmitted SYN while in SYN-RCVD must not replace the half-open
   connection (and its ISN): a client ACKing the first SYN-ACK must succeed. *)
let duplicate_syn () =
  let fsm ip state ~src:_ ~dst:_ data =
    match state with
    | `SYNACK1 when Tcp_wire.get_syn data ->
      send_client_syn ip >|= fun () -> Fsm_next (`SYNACK2 (Tcp_wire.get_sequence data))
    | `SYNACK2 a when Tcp_wire.get_syn data ->
      WIRE.xmit ~ip client_id ~rx_ack:(Some (Sequence.of_int32 (Int32.succ a)))
        ~seq:(Sequence.of_int32 (Int32.succ client_isn)) ~window:65535 ~options:[] (Cstruct.create 10)
      >|= Result.get_ok >|= fun () -> Fsm_next `DATA_ACK
    | `DATA_ACK when (not (Tcp_wire.get_syn data)) && Tcp_wire.get_ack data
                     && Tcp_wire.get_ack_number data = Int32.add client_isn 11l ->
      Lwt.return Fsm_done
    | s -> Lwt.return (Fsm_next s)
  in
  `Server ((fun ip -> send_client_syn ip), (`SYNACK1, fsm), sut_listens)

(* 3. A retransmitted FIN (our ACK of it was lost) must be ACKed again. *)
let fin_retransmit_acked () =
  let fin ip ~src ~dst data =
    WIRE.xmit ~ip (reply_id_from ~src ~dst data) ~fin:true ~rx_ack:(ack data)
      ~seq:(Sequence.of_int32 1000001l) ~window ~options (Cstruct.create 0) >|= Result.get_ok in
  let fsm ip state ~src ~dst data =
    match state with
    | `SYN -> syn_ack ip ~src ~dst ~isn:1000000l data >|= fun () -> Fsm_next `ACK
    | `ACK -> fin ip ~src ~dst data >|= fun () -> Fsm_next `FIN_ACK1
    | `FIN_ACK1 when Tcp_wire.get_ack_number data = 1000002l ->
      fin ip ~src ~dst data >|= fun () -> Fsm_next `FIN_ACK2
    | `FIN_ACK2 when Tcp_wire.get_ack_number data = 1000002l -> Lwt.return Fsm_done
    | s -> Lwt.return (Fsm_next s)
  in
  `Client ((`SYN, fsm), sut_connects_then (fun flow ->
      VNETIF_STACK.Stack.TCP.read flow >|= fun _ -> ()))

(* 4. Out-of-order reassembly must work across the 2^31 sequence boundary. *)
let ooo_reassembly ~isn () =
  let fsm ip state ~src ~dst data =
    let seg seq = WIRE.xmit ~ip (reply_id_from ~src ~dst data) ~rx_ack:(ack data)
        ~seq:(Sequence.of_int32 seq) ~window ~options (Cstruct.create 16) >|= Result.get_ok in
    match state with
    | `SYN -> syn_ack ip ~src ~dst ~isn data >|= fun () -> Fsm_next `ACK
    | `ACK ->
      seg Int32.(add isn 17l) >>= fun () ->  (* B, out of order *)
      seg Int32.(add isn 1l) >|= fun () ->   (* A, fills the gap *)
      Fsm_next `ACKS
    | `ACKS ->
      let a = Tcp_wire.get_ack_number data in
      if a = Int32.add isn 33l then Lwt.return Fsm_done
      else if a = Int32.add isn 17l then
        Lwt.return (Fsm_error "out-of-order segment B was discarded (ack stops after A)")
      else Lwt.return (Fsm_next `ACKS)
  in
  `Client ((`SYN, fsm), sut_connects_then (fun _ -> Lwt.return_unit))

(* 5. Window scale > 14 must be clamped to 14 (RFC 7323 2.3), not break sending. *)
let wscale ~shift () =
  let fsm ip state ~src ~dst data =
    match state with
    | `SYN -> syn_ack ~options:[Opt.Window_size_shift shift] ~window:65535 ip ~src ~dst
                ~isn:1000000l data >|= fun () -> Fsm_next `DATA
    | `DATA when Tcp_wire.get_ack data && Cstruct.length (snd (parse data)) > 0 ->
      Lwt.return Fsm_done
    | s -> Lwt.return (Fsm_next s)
  in
  `Client ((`SYN, fsm), sut_connects_then (fun flow ->
      VNETIF_STACK.Stack.TCP.write flow (Cstruct.create 100) >|= fun _ -> ()))

(* 6. A fast-retransmitted segment must be sent with its own sequence number. *)
let fast_rexmit_alignment () =
  let fsm ip state ~src ~dst data =
    let pkt, payload = parse data in
    let pseq = Sequence.to_int32 pkt.sequence in
    let id = reply_id_from ~src ~dst data in
    let pure_ack n = WIRE.xmit ~ip id ~rx_ack:(Some (Sequence.of_int32 n)) ~seq:(Sequence.of_int32 1000001l) ~window
        ~options:[] (Cstruct.create 0) >|= Result.get_ok in
    let has_data = Cstruct.length payload > 0 in
    match state with
    | `SYN ->
      syn_ack ~options:[Opt.MSS 100] ip ~src ~dst ~isn:1000000l data >|= fun () ->
      Fsm_next (`DATA (Sequence.to_int32 pkt.sequence))
    | `DATA s when has_data && pseq = Int32.succ s ->
      pure_ack (Int32.succ s) >>= fun () -> pure_ack (Int32.succ s) >>= fun () ->
      pure_ack (Int32.succ s) >|= fun () -> Fsm_next (`FAST_REXMIT s)
    | `FAST_REXMIT s when has_data && pseq = Int32.succ s ->
      (* partial ACK covering 50 of the first segment's 100 bytes *)
      pure_ack (Int32.add s 51l) >|= fun () -> Fsm_next (`PARTIAL s)
    | `PARTIAL s when has_data && pseq = Int32.add s 51l ->
      let b = Cstruct.get_uint8 payload 0 in
      if b = 50 then Lwt.return Fsm_done
      else Lwt.return (Fsm_error (Fmt.str
          "segment sent at seq=ISN+51 starts with stream byte %d (expected 50): \
           payload of the head segment was sent under the ACK's sequence number" b))
    | `PARTIAL s when has_data && pseq = Int32.succ s -> Lwt.return Fsm_done
    | s -> Lwt.return (Fsm_next s)
  in
  let pattern = Cstruct.of_string (String.init 300 (fun i -> Char.chr (i mod 256))) in
  `Client ((`SYN, fsm), sut_connects_then (fun flow ->
      VNETIF_STACK.Stack.TCP.write flow pattern >|= fun _ -> ()))


let no_kick _ = Lwt.return_unit

(* 7. After max retransmissions the connection is dropped; a blocked reader
   must be woken (Eof or error), not left hanging forever. *)
let rexmit_timeout_wakes_reader () =
  let fsm ip state ~src ~dst data =
    match state with
    | `SYN -> syn_ack ip ~src ~dst ~isn:1000000l data >|= fun () -> Fsm_done (* then blackhole *)
    | s -> Lwt.return (Fsm_next s) (* never ACK the data *)
  in
  let sut stack =
    let conn = VNETIF_STACK.Stack.TCP.create_connection (VNETIF_STACK.Stack.tcp stack) in
    or_error "connect" conn (Ipaddr.V4 server_ip, 80) >>= fun flow ->
    VNETIF_STACK.Stack.TCP.write flow (Cstruct.create 100) >>= fun _ ->
    let t0 = Unix.gettimeofday () in
    VNETIF_STACK.Stack.TCP.read flow >>= fun r ->
    Logs.app (fun m -> m "reader woken after %.0fs" (Unix.gettimeofday () -. t0));
    (match r with
     | Ok `Eof -> ()
     | _ -> Alcotest.fail "expected Ok `Eof from read after retransmission timeout");
    VNETIF_STACK.Stack.TCP.write flow (Cstruct.create 1) >|= function
    | Error `Closed -> ()
    | _ -> Alcotest.fail "expected Error `Closed from write after retransmission timeout"
  in
  `Long (240, (`SYN, fsm), sut)

(* 8. Half-close: after shutdown `write, a peer that stays quiet for >10s and
   then sends data must still be able to reach us. *)
let half_close_quiet_peer () =
  let fsm ip state ~src ~dst data =
    let id = reply_id_from ~src ~dst data in
    match state with
    | `SYN -> syn_ack ip ~src ~dst ~isn:1000000l data >|= fun () -> Fsm_next `FIN
    | `FIN when Tcp_wire.get_fin data ->
      WIRE.xmit ~ip id ~rx_ack:(ack data) ~seq:(Sequence.of_int32 1000001l) ~window
        ~options:[] (Cstruct.create 0) >|= Result.get_ok >>= fun () ->
      Mirage_sleep.ns (Duration.of_sec 12) >>= fun () ->   (* peer "computing" *)
      WIRE.xmit ~ip id ~rx_ack:(ack data) ~seq:(Sequence.of_int32 1000001l) ~window
        ~options:[] (Cstruct.create 5) >|= Result.get_ok >|= fun () -> Fsm_next `REPLY
    | `REPLY when Tcp_wire.get_rst data ->
      Lwt.return (Fsm_error "SUT answered the peer's reply with RST: connection was \
                             dropped by the FIN_WAIT_2 timer while half-open")
    | `REPLY when Tcp_wire.get_ack data && Tcp_wire.get_ack_number data = 1000006l ->
      Lwt.return Fsm_done
    | s -> Lwt.return (Fsm_next s)
  in
  let sut stack =
    let conn = VNETIF_STACK.Stack.TCP.create_connection (VNETIF_STACK.Stack.tcp stack) in
    or_error "connect" conn (Ipaddr.V4 server_ip, 80) >>= fun flow ->
    VNETIF_STACK.Stack.TCP.shutdown flow `write >>= fun () ->
    Mirage_sleep.ns (Duration.of_sec 15)
  in
  `Long (20, (`SYN, fsm), sut)

(* 9. The FIN_WAIT_2 timeout must still reclaim a connection the application
   [close]d when the peer ACKs our FIN but never sends its own. *)
let orphan_fin_wait_2_reclaimed () =
  let fsm ip state ~src ~dst data =
    match state with
    | `SYN -> syn_ack ip ~src ~dst ~isn:1000000l data >|= fun () -> Fsm_next `FIN
    | `FIN when Tcp_wire.get_fin data ->
      WIRE.xmit ~ip (reply_id_from ~src ~dst data) ~rx_ack:(ack data)
        ~seq:(Sequence.of_int32 1000001l) ~window ~options:[] (Cstruct.create 0)
      >|= Result.get_ok >|= fun () -> Fsm_done  (* ...and never send our FIN *)
    | s -> Lwt.return (Fsm_next s)
  in
  let sut stack =
    let tcp = VNETIF_STACK.Stack.tcp stack in
    let conn = VNETIF_STACK.Stack.TCP.create_connection tcp in
    or_error "connect" conn (Ipaddr.V4 server_ip, 80) >>= fun flow ->
    VNETIF_STACK.Stack.TCP.close flow >>= fun () ->
    Mirage_sleep.ns (Duration.of_sec 12) >|= fun () ->
    Alcotest.(check int) "orphaned FIN_WAIT_2 connection reclaimed" 0
      (VNETIF_STACK.T.num_open_channels tcp)
  in
  `Long (20, (`SYN, fsm), sut)

(* 10. A SYN with a different ISN while half-open is a new attempt: it replaces
   the old half-open connection, which must stop retransmitting its SYN-ACK,
   and the new connection must work. *)
let new_syn_replaces_half_open () =
  let isn2 = 9000l in
  let fsm ip state ~src:_ ~dst:_ data =
    let syn = Tcp_wire.get_syn data and seq = Tcp_wire.get_sequence data in
    match state with
    | `SYNACK1 when syn ->
      send_client_syn ~isn:isn2 ip >|= fun () -> Fsm_next (`SYNACK2 seq)
    | `SYNACK2 a when syn && seq = a ->
      Lwt.return (Fsm_error "old half-open connection still retransmits its SYN-ACK")
    | `SYNACK2 a when syn ->
      (* wait past the old SYN-ACK's RTO (667ms) before completing *)
      Mirage_sleep.ns (Duration.of_ms 1500) >>= fun () ->
      WIRE.xmit ~ip client_id ~rx_ack:(Some (Sequence.of_int32 (Int32.succ seq)))
        ~seq:(Sequence.of_int32 (Int32.succ isn2)) ~window:65535 ~options:[]
        (Cstruct.create 10)
      >|= Result.get_ok >|= fun () -> Fsm_next (`DATA_ACK a)
    | `DATA_ACK a when syn && seq = a ->
      Lwt.return (Fsm_error "old half-open connection still retransmits its SYN-ACK")
    | `DATA_ACK _ when (not syn) && Tcp_wire.get_ack data
                       && Tcp_wire.get_ack_number data = Int32.add isn2 11l ->
      Lwt.return Fsm_done
    | s -> Lwt.return (Fsm_next s)
  in
  `Server ((fun ip -> send_client_syn ip), (`SYNACK1, fsm), sut_listens)

(* 11. Receiver flow control: with an application that does not read, the
   window must close to 0 (and stay ACKing); data beyond it, like a 1-byte zero
   window probe, is not accepted but ACKed; reading reopens the window. *)
let zero_window_advertised () =
  let rx_wnd = 65535 in
  let edge = Int32.(add 1000001l (of_int rx_wnd)) in
  let fsm ip state ~src ~dst data =
    let id = reply_id_from ~src ~dst data in
    let ackn = Tcp_wire.get_ack_number data and win = Tcp_wire.get_window data in
    let send ~seq len = WIRE.xmit ~ip id ~rx_ack:(ack data) ~seq:(Sequence.of_int32 seq)
        ~window ~options:[] (Cstruct.create len) >|= Result.get_ok in
    match state with
    | `SYN -> syn_ack ~window:65535 ~options:[] ip ~src ~dst ~isn:1000000l data
      >|= fun () -> Fsm_next `ACK
    | `ACK ->
      (* more than the whole window *)
      let rec blast i = if i = 46 then Lwt.return_unit else
          send ~seq:Int32.(add 1000001l (of_int (i * 1460))) 1460 >>= fun () -> blast (i + 1) in
      blast 0 >|= fun () -> Fsm_next `ZERO
    | `ZERO when ackn = edge && win = 0 ->
      send ~seq:edge 1 >|= fun () -> Fsm_next `PROBE_ACK
    | `PROBE_ACK when ackn = Int32.succ edge ->
      Lwt.return (Fsm_error "data was accepted beyond a zero window")
    | `PROBE_ACK when ackn = edge && win = 0 -> Lwt.return (Fsm_next `UPDATE)
    | `UPDATE when ackn = edge && win > 0 -> Lwt.return Fsm_done
    | s -> Lwt.return (Fsm_next s)
  in
  let sut stack =
    let conn = VNETIF_STACK.Stack.TCP.create_connection (VNETIF_STACK.Stack.tcp stack) in
    or_error "connect" conn (Ipaddr.V4 server_ip, 80) >>= fun flow ->
    Mirage_sleep.ns (Duration.of_ms 1500) >>= fun () ->   (* not reading *)
    let rec drain n =
      if n >= rx_wnd then Lwt.return_unit else
        VNETIF_STACK.Stack.TCP.read flow >>= function
        | Ok (`Data b) -> drain (n + Cstruct.length b)
        | _ -> Alcotest.fail "unexpected end of stream"
    in
    drain 0 >>= fun () -> Mirage_sleep.ns (Duration.of_sec 1)
  in
  `Long (8, (`SYN, fsm), sut)

(* 12. Persist timer: data is queued against a zero window; the sender must
   probe (and not send data) until the window opens, then send.  The window
   update uses 65535, which an earlier bug mistook for "unchanged". *)
let zero_window_probe () =
  let fsm ip state ~src ~dst data =
    let has_data = Cstruct.length (snd (parse data)) > 0 in
    let seq = Tcp_wire.get_sequence data in
    match state with
    | `SYN -> syn_ack ~window:0 ip ~src ~dst ~isn:1000000l data
      >|= fun () -> Fsm_next (`PROBE (seq, 0))
    | `PROBE _ when has_data -> Lwt.return (Fsm_error "sent data into a zero window")
    | `PROBE (s, n) when seq = s ->  (* SND.NXT - 1: a probe *)
      if n = 0 then Lwt.return (Fsm_next (`PROBE (s, 1)))
      else
        WIRE.xmit ~ip (reply_id_from ~src ~dst data) ~rx_ack:(Some (Sequence.of_int32 (Int32.succ s)))
          ~seq:(Sequence.of_int32 1000001l) ~window:65535 ~options:[] Cstruct.empty
        >|= Result.get_ok >|= fun () -> Fsm_next `DATA
    | `DATA when has_data -> Lwt.return Fsm_done
    | s -> Lwt.return (Fsm_next s)
  in
  `Client ((`SYN, fsm), sut_connects_then (fun flow ->
      VNETIF_STACK.Stack.TCP.write flow (Cstruct.create 100) >|= fun _ -> ()))

(* 13. A peer window permanently smaller than the MSS must not stall sending;
   every segment must fit in the window. *)
let small_window () =
  let total = 300 and pwin = 100 in
  let fsm ip state ~src ~dst data =
    let _, payload = parse data in
    let len = Cstruct.length payload in
    match state with
    | `SYN -> syn_ack ~window:pwin ip ~src ~dst ~isn:1000000l data
      >|= fun () -> Fsm_next (`DATA 0)
    | `DATA _ when len > pwin ->
      Lwt.return (Fsm_error (Fmt.str "sent %d bytes into a %d byte window" len pwin))
    | `DATA got when len > 0 ->
      WIRE.xmit ~ip (reply_id_from ~src ~dst data) ~rx_ack:(ack data)
        ~seq:(Sequence.of_int32 1000001l) ~window:pwin ~options:[] Cstruct.empty
      >|= Result.get_ok >|= fun () ->
      if got + len >= total then Fsm_done else Fsm_next (`DATA (got + len))
    | s -> Lwt.return (Fsm_next s)
  in
  `Client ((`SYN, fsm), sut_connects_then (fun flow ->
      VNETIF_STACK.Stack.TCP.write flow (Cstruct.create total) >|= fun _ -> ()))

(* ---- Handshake and RST handling (RFC 9293 3.10.7, RFC 5961) ---- *)

let sut_idle stack = ignore stack; Mirage_sleep.ns (Duration.of_ms 2500)

let xmit_client ?(rst=false) ?(syn=false) ?(len=0) ip ~seq ~ack =
  WIRE.xmit ~ip client_id ~rst ~syn ~rx_ack:(Option.map Sequence.of_int32 ack)
    ~seq:(Sequence.of_int32 seq) ~window:65535 ~options:[] (Cstruct.create len)
  >|= Result.get_ok

let flags data =
  Tcp_wire.get_rst data, Tcp_wire.get_ack data, Tcp_wire.get_sequence data,
  Tcp_wire.get_ack_number data

(* expect exactly one reply, a RST with the given seq and (optional) ack *)
let expect_rst ~seq ~ack =
  fun _ip `RST ~src:_ ~dst:_ data ->
    let rst, has_ack, s, a = flags data in
    let ok = rst && s = seq &&
             (match ack with None -> not has_ack | Some x -> has_ack && a = x) in
    Lwt.return (if ok then Fsm_done else Fsm_error (Fmt.str
        "expected RST seq=%lu %s, got rst=%b ack=%b seq=%lu ack#=%lu" seq
        (match ack with None -> "without ACK" | Some x -> Fmt.str "ACK %lu" x)
        rst has_ack s a))

(* 14-16. segments to a port without connection or listener *)
let rst_closed_ack () =
  `Server ((fun ip -> xmit_client ip ~seq:777l ~ack:(Some 4242l)),
           (`RST, expect_rst ~seq:4242l ~ack:None), sut_idle)
let rst_closed_data () =
  `Server ((fun ip -> xmit_client ip ~len:10 ~seq:777l ~ack:None),
           (`RST, expect_rst ~seq:0l ~ack:(Some 787l)), sut_idle)
let rst_closed_syn () =
  `Server ((fun ip -> WIRE.xmit ~ip client_id ~syn:true ~rx_ack:None
               ~seq:(Sequence.of_int32 777l) ~window:65535 ~options:[] Cstruct.empty
             >|= Result.get_ok),
           (`RST, expect_rst ~seq:0l ~ack:(Some 778l)), sut_listens_other_port)

(* 17. SYN-RCVD: an in-window RST that is not exactly RCV.NXT gets a challenge
   ACK and the handshake can still complete *)
let blind_rst_syn_rcvd () =
  let fsm ip state ~src:_ ~dst:_ data =
    let rst, has_ack, seq, ackn = flags data in
    match state with
    | `SYNACK when Tcp_wire.get_syn data ->
      xmit_client ip ~rst:true ~seq:(Int32.add client_isn 101l)
        ~ack:(Some (Int32.succ seq)) >|= fun () -> Fsm_next (`CHALLENGE seq)
    | `CHALLENGE a when has_ack && not rst && ackn = Int32.succ client_isn ->
      xmit_client ip ~len:10 ~seq:(Int32.succ client_isn) ~ack:(Some (Int32.succ a))
      >|= fun () -> Fsm_next `DATA_ACK
    | `DATA_ACK when rst -> Lwt.return (Fsm_error "half-open connection was reset by a blind RST")
    | `DATA_ACK when has_ack && ackn = Int32.add client_isn 11l -> Lwt.return Fsm_done
    | s -> ignore seq; Lwt.return (Fsm_next s)
  in
  `Server ((fun ip -> send_client_syn ip), (`SYNACK, fsm), sut_listens)

(* 18. SYN-RCVD: a RST with exactly RCV.NXT aborts the half-open connection,
   even without the ACK flag *)
let exact_rst_syn_rcvd () =
  let fsm ip state ~src:_ ~dst:_ data =
    let rst, _, seq, _ = flags data in
    match state with
    | `SYNACK when Tcp_wire.get_syn data ->
      xmit_client ip ~rst:true ~seq:(Int32.succ client_isn) ~ack:None >>= fun () ->
      Mirage_sleep.ns (Duration.of_ms 200) >>= fun () ->
      xmit_client ip ~seq:(Int32.succ client_isn) ~ack:(Some (Int32.succ seq))
      >|= fun () -> Fsm_next `RST
    | `RST when rst -> Lwt.return Fsm_done
    | `RST when Tcp_wire.get_syn data -> Lwt.return (Fsm_next `RST) (* retransmitted SYN-ACK *)
    | `RST -> Lwt.return (Fsm_error "half-open connection survived an exact RST")
    | s -> Lwt.return (Fsm_next s)
  in
  `Server ((fun ip -> send_client_syn ip), (`SYNACK, fsm), sut_listens)

(* 19. SYN-SENT: a SYN-ACK with an unacceptable ACK is answered with a RST *)
let bad_ack_syn_sent () =
  let fsm ip state ~src ~dst data =
    match state with
    | `SYN ->
      let bad = Int32.add (Tcp_wire.get_sequence data) 5l in
      WIRE.xmit ~ip (reply_id_from ~src ~dst data) ~syn:true
        ~rx_ack:(Some (Sequence.of_int32 bad)) ~seq:(Sequence.of_int32 1000000l)
        ~window ~options:[] Cstruct.empty
      >|= Result.get_ok >|= fun () -> Fsm_next (`RST bad)
    | `RST bad ->
      expect_rst ~seq:bad ~ack:None ip `RST ~src ~dst data
  in
  `Client ((`SYN, fsm), fun stack ->
      let conn = VNETIF_STACK.Stack.TCP.create_connection (VNETIF_STACK.Stack.tcp stack) in
      Lwt.pick [ (conn (Ipaddr.V4 server_ip, 80) >|= fun _ -> ());
                 Mirage_sleep.ns (Duration.of_ms 2500) ])

(* 20. SYN-RCVD: an unacceptable ACK is answered with a RST *)
let bad_ack_syn_rcvd () =
  let fsm ip state ~src ~dst data =
    match state with
    | `SYNACK when Tcp_wire.get_syn data ->
      let bad = Int32.add (Tcp_wire.get_sequence data) 7l in
      xmit_client ip ~seq:(Int32.succ client_isn) ~ack:(Some bad)
      >|= fun () -> Fsm_next (`RST bad)
    | `RST _ when Tcp_wire.get_syn data -> Lwt.return (Fsm_next state)
    | `RST bad -> expect_rst ~seq:bad ~ack:None ip `RST ~src ~dst data
    | s -> Lwt.return (Fsm_next s)
  in
  `Server ((fun ip -> send_client_syn ip), (`SYNACK, fsm), sut_listens)

(* 21. the number of half-open connections is bounded *)
let syn_backlog () =
  let synacks = Hashtbl.create 2048 in
  let fsm _ip state ~src:_ ~dst:_ data =
    if Tcp_wire.get_syn data then Hashtbl.replace synacks (Tcp_wire.get_dst_port data) ();
    Lwt.return (Fsm_next state)
  in
  let kick ip =
    let rec go i = if i = 1100 then Lwt.return_unit else
        let id = WIRE.v ~src:server_ip ~src_port:(20000 + i) ~dst:sut_ip ~dst_port:80 in
        WIRE.xmit ~ip id ~syn:true ~rx_ack:None ~seq:(Sequence.of_int32 5000l)
          ~window:65535 ~options:[] Cstruct.empty >>= fun _ -> go (i + 1) in
    go 0
  in
  let sut stack =
    VNETIF_STACK.Stack.TCP.listen (VNETIF_STACK.Stack.tcp stack) ~port:80 (fun _ -> Lwt.return_unit);
    Mirage_sleep.ns (Duration.of_ms 2500) >|= fun () ->
    Alcotest.(check int) "SYN-ACKs sent (backlog limit 1024)" 1024 (Hashtbl.length synacks)
  in
  `Long_kick (5, (`ANY, fsm), sut, kick)

let run_test name = function
  | `Client (fsm, sut) -> fun () ->
    let backend = VNETIF_STACK.create_backend () in
    VNETIF_STACK.record_pcap backend (name ^ ".pcap")
      (run backend fsm (fun stack _fail -> sut stack))
  | `Server (kick, fsm, sut) -> fun () ->
    let backend = VNETIF_STACK.create_backend () in
    VNETIF_STACK.record_pcap backend (name ^ ".pcap") (run_server backend ~kick fsm sut)
  | `Long (cap, fsm, sut) -> fun () ->
    let backend = VNETIF_STACK.create_backend () in
    VNETIF_STACK.record_pcap backend (name ^ ".pcap") (run_server ~cap backend ~kick:no_kick fsm sut)
  | `Long_kick (cap, fsm, sut, kick) -> fun () ->
    let backend = VNETIF_STACK.create_backend () in
    VNETIF_STACK.record_pcap backend (name ^ ".pcap") (run_server ~cap ~wait_fsm:false backend ~kick fsm sut)

let suite = [
  "fast retransmit uses the segment's own seq", `Quick, run_test "r6" (fast_rexmit_alignment ());
  "OOO reassembly (no wrap)", `Quick, run_test "r4a" (ooo_reassembly ~isn:1000000l ());
  "OOO reassembly across 2^31", `Quick, run_test "r4b" (ooo_reassembly ~isn:0x7FFFFFF0l ());
  "retransmitted FIN is re-ACKed", `Quick, run_test "r3" (fin_retransmit_acked ());
  "half-closed connection survives a quiet peer", `Quick, run_test "r8" (half_close_quiet_peer ());
  "orphaned FIN_WAIT_2 connection is reclaimed", `Quick, run_test "r9" (orphan_fin_wait_2_reclaimed ());
  "SYN-ACK retransmission keeps options", `Quick, run_test "r1" (synack_rexmit_options ());
  "retransmitted SYN is answered with the same SYN-ACK", `Quick, run_test "r2" (duplicate_syn ());
  "new SYN replaces the half-open connection", `Quick, run_test "r10" (new_syn_replaces_half_open ());
  "wscale 14", `Quick, run_test "r5a" (wscale ~shift:14 ());
  "wscale > 14 is clamped to 14", `Quick, run_test "r5b" (wscale ~shift:16 ());
  "receiver advertises and enforces a zero window", `Quick, run_test "r11" (zero_window_advertised ());
  "persist timer probes a zero window", `Quick, run_test "r12" (zero_window_probe ());
  "window smaller than MSS does not stall", `Quick, run_test "r13" (small_window ());
  "RST to an ACK for a closed port", `Quick, run_test "r14" (rst_closed_ack ());
  "RST to data without ACK for a closed port", `Quick, run_test "r15" (rst_closed_data ());
  "RST to a SYN for a closed port", `Quick, run_test "r16" (rst_closed_syn ());
  "blind RST in SYN-RCVD gets a challenge ACK", `Quick, run_test "r17" (blind_rst_syn_rcvd ());
  "exact RST without ACK aborts SYN-RCVD", `Quick, run_test "r18" (exact_rst_syn_rcvd ());
  "unacceptable ACK in SYN-SENT is reset", `Quick, run_test "r19" (bad_ack_syn_sent ());
  "unacceptable ACK in SYN-RCVD is reset", `Quick, run_test "r20" (bad_ack_syn_rcvd ());
  "SYN backlog is bounded", `Quick, run_test "r21" (syn_backlog ());
  "retransmission timeout wakes reader and writer", `Slow, run_test "r7" (rexmit_timeout_wakes_reader ());
]

(*
 * Copyright (c) 2010-2011 Anil Madhavapeddy <anil@recoil.org>
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

let src = Logs.Src.create "tcp.segment" ~doc:"Mirage TCP Segment module"
module Log = (val Logs.src_log src : Logs.LOG)

let lwt_sequence_add_l s seq =
  let (_:'a Lwt_dllist.node) = Lwt_dllist.add_l s seq in
  ()

let lwt_sequence_add_r s seq =
  let (_:'a Lwt_dllist.node) = Lwt_dllist.add_r s seq in
  ()

let peek_opt_l seq =
  match Lwt_dllist.take_opt_l seq with
  | None -> None
  | Some s ->
    lwt_sequence_add_l s seq;
    Some s

let peek_l seq =
  match Lwt_dllist.take_opt_l seq with
  | None -> assert false
  | Some s ->
    let _ = Lwt_dllist.add_l s seq in
    s

let rec reset_seq segs =
  match Lwt_dllist.take_opt_l segs with
  | None -> ()
  | Some _ -> reset_seq segs

(* The receive queue stores out-of-order segments, and can
   coalesece them on input and pass on an ordered list up the
   stack to the application.

   It also looks for control messages and dispatches them to
   the Rtx queue to ack messages or close channels.
*)
module Rx(ACK: Ack.M) = struct
  open Tcp_packet

  (* Individual received TCP segment
     TODO: this will change when IP fragments work *)
  type segment = { header: Tcp_packet.t; payload: Cstruct.t }

  let pp_segment fmt {header; payload} =
    Format.fprintf fmt
      "RX seg seq=%a acknum=%a ack=%b rst=%b syn=%b fin=%b win=%d len=%d"
      Sequence.pp header.sequence Sequence.pp header.ack_number
      header.ack header.rst header.syn header.fin
      header.window (Cstruct.length payload)

  let len seg =
    Sequence.of_int ((Cstruct.length seg.payload) +
    (if seg.header.fin then 1 else 0) +
    (if seg.header.syn then 1 else 0))

  (* Set of segments, ordered by sequence number *)
  module S = Set.Make(struct
      type t = segment
      let compare a b = (Sequence.compare a.header.sequence b.header.sequence)
    end)

  type t = {
    mutable segs: S.t;
    rx_data: (Cstruct.t list option * Sequence.t option) Lwt_mvar.t; (* User receive channel *)
    ack: ACK.t;
    tx_ack: (Sequence.t * int) Lwt_mvar.t; (* Acks of our transmitted segs *)
    wnd: Window.t;
    state: State.t;
    mutable ooo_count: int;    (* segments waiting in [segs] *)
    mutable ooo_bytes: int;    (* payload bytes waiting in [segs] *)
    mutable last_invalid_ack: int64; (* when we last answered an invalid
                                        segment with an ACK (rate limit) *)
  }

  let create ~rx_data ~ack ~wnd ~state ~tx_ack =
    let segs = S.empty in
    { segs; rx_data; ack; tx_ack; wnd; state; ooo_count = 0; ooo_bytes = 0;
      last_invalid_ack = Int64.min_int }

  (* Bounds on the out-of-order queue: a peer sending many overlapping or
     tiny segments must not be able to use unbounded memory (or CPU, as the
     queue is walked for every segment). *)
  let max_ooo_segments = 1024

  let pp fmt t =
    let pp_v fmt seg =
      Format.fprintf fmt "%a[%a]" Sequence.pp seg.header.sequence Sequence.pp (len seg)
    in
    Format.pp_print_list pp_v fmt (S.elements t.segs)

  (* If there is a FIN flag at the end of this segment set.  TODO:
     should look for a FIN and chop off the rest of the set as they
     may be orphan segments *)
  let fin q =
    try (S.max_elt q).header.fin
    with Not_found -> false

  let is_empty q = S.is_empty q.segs

  let check_valid_segment q seg =
    if seg.header.rst then
      begin match State.state q.state with
        | State.Reset ->
          `Drop
        | _ ->
          if Sequence.compare seg.header.sequence (Window.rx_nxt q.wnd) = 0 then
            `Reset
          else if Window.valid q.wnd seg.header.sequence then
            `ChallengeAck
          else
            `Drop
      end
    else if seg.header.syn then
      `ChallengeAck
    else if not (Window.valid q.wnd seg.header.sequence) then
      (* unacceptable sequence number: drop, but answer with an ACK
         (RFC 9293 3.10.7.4) *)
      `Unacceptable
    else if not seg.header.ack then
      (* in a synchronized state a segment without ACK is dropped *)
      `Drop
    else
      let min = Sequence.(sub (Window.tx_una q.wnd) (of_int32 (Window.max_tx_wnd q.wnd))) in
      if Sequence.between seg.header.ack_number min (Window.tx_nxt q.wnd) then
        `Ok
      else
        (* rfc5961 5.2 *)
        `ChallengeAck

  (* Can [seg] be processed normally (as opposed to being dropped, answered
     with a challenge ACK, ...)? *)
  let acceptable q seg = check_valid_segment q seg = `Ok

  (* Cut off any data beyond the right edge of the advertised receive window
     (RFC 9293 3.10.7.4: only the part inside the window is acceptable, and an
     ACK must be sent for the rest).  With a zero window this drops all the
     data, e.g. of a 1-byte zero window probe, and the forced ACK answers the
     probe.  A FIN is only kept if all the data fits. *)
  let trim_to_window q seg =
    let edge = Window.rx_wnd_edge q.wnd in
    let len = Cstruct.length seg.payload in
    let allowed =
      if Sequence.lt seg.header.sequence edge then
        Sequence.to_int (Sequence.sub edge seg.header.sequence)
      else 0
    in
    if len <= allowed then seg, false
    else
      { header = { seg.header with fin = false };
        payload = Cstruct.sub seg.payload 0 (max 0 allowed) }, true

  (* ACKs sent in reply to invalid segments (RFC 5961 challenge ACKs and ACKs
     for out-of-window segments) are rate limited per connection, as Linux
     does (tcp_invalid_ratelimit), so that a flood of forged segments does
     not turn into a flood of ACKs.  A per-connection limit, unlike the
     global one suggested by RFC 5961 section 7, does not leak information
     between connections (CVE-2016-5696). *)
  let invalid_ack_interval = Duration.of_ms 500

  let send_challenge_ack q =
    let now = Mirage_mtime.elapsed_ns () in
    if Int64.sub now q.last_invalid_ack >= invalid_ack_interval
    || q.last_invalid_ack = Int64.min_int then begin
      q.last_invalid_ack <- now;
      ACK.pushack q.ack Sequence.zero
    end else Lwt.return_unit

  (* Given an input segment, the window information, and a receive
     queue, update the window, extract any ready segments into the
     user receive queue, and signal any acks to the Tx queue *)
  let input (q:t) seg =
    match check_valid_segment q seg with
    | `Ok ->
      let seg, trimmed = trim_to_window q seg in
      let force_ack = ref trimmed in
      (* Only segments that occupy sequence space go into the reassembly set.
         An empty one (pure ACK) stored there could shadow the real data
         segment arriving later at the same sequence number.  An empty
         segment with an old sequence number (e.g. a zero window probe or a
         keep-alive, which use RCV.NXT - 1) must be answered with an ACK. *)
      let occupies_seq_space = Cstruct.length seg.payload > 0 || seg.header.fin in
      if not occupies_seq_space
      && Sequence.lt seg.header.sequence (Window.rx_nxt_inseq q.wnd) then
        force_ack := true;
      let len_new = Cstruct.length seg.payload in
      let future =
        Sequence.gt seg.header.sequence (Window.rx_nxt_inseq q.wnd) in
      let segs =
        if not occupies_seq_space then q.segs
        else match S.find_opt seg q.segs with
          | Some old when Cstruct.length old.payload >= len_new && (old.header.fin || not seg.header.fin) ->
            (* already have this sequence number with at least as much data *)
            q.segs
          | Some old -> S.add seg (S.remove old q.segs)
          | None when future
                   && (q.ooo_count >= max_ooo_segments
                       || q.ooo_bytes + len_new > Int32.to_int (Window.max_rx_wnd q.wnd)) ->
            (* out-of-order queue full: drop it, the peer will retransmit *)
            force_ack := true;
            q.segs
          | None -> S.add seg q.segs
      in
      (* Walk through the set and get a list of contiguous segments *)
      let ready, waiting = S.fold (fun seg acc ->
          match Sequence.compare seg.header.sequence (Window.rx_nxt_inseq q.wnd) with
          | (-1) ->
            (* Sequence number is in the past, probably an overlapping
               segment. Drop it for now, but TODO segment
               coalescing *)
            force_ack := true;
            acc
          | 0 ->
            (* This is the next segment, so put it into the ready set
               and update the receive ack number *)
            let (ready,waiting) = acc in
            Window.rx_advance_inseq q.wnd (len seg);
            (S.add seg ready), waiting
          | 1 ->
            (* Sequence is in the future, so can't use it yet *)
            force_ack := true;
            let (ready,waiting) = acc in
            ready, (S.add seg waiting)
          | _ -> assert false
        ) segs (S.empty, S.empty) in
      q.segs <- waiting;
      q.ooo_count <- 0; q.ooo_bytes <- 0;
      S.iter (fun s ->
          q.ooo_count <- q.ooo_count + 1;
          q.ooo_bytes <- q.ooo_bytes + Cstruct.length s.payload) waiting;
      (* If the segment has an ACK, tell the transmit side *)
      let tx_ack =
        if seg.header.ack && (Sequence.geq seg.header.ack_number (Window.ack_seq q.wnd)) then begin
          State.tick q.state (State.Recv_ack seg.header.ack_number);
          (* Only take the window from this segment if it is not older than
             the one that last updated it (SND.WL1/SND.WL2, RFC 9293
             3.10.7.4): a reordered old segment must not shrink the window *)
          let window =
            if Window.accept_window_update q.wnd
                ~seq:seg.header.sequence ~ack:seg.header.ack_number
            then seg.header.window
            else Window.ack_win q.wnd
          in
          let data_in_flight = Window.tx_inflight q.wnd in
          let ack_has_advanced = (Window.ack_seq q.wnd) <> seg.header.ack_number in
          let win_has_changed = (Window.ack_win q.wnd) <> window in
          if ((data_in_flight && (Window.ack_serviced q.wnd || not ack_has_advanced)) ||
              (not data_in_flight && win_has_changed)) then begin
            Window.set_ack_serviced q.wnd false;
            Window.set_ack_seq_win q.wnd seg.header.ack_number window;
            Lwt_mvar.put q.tx_ack ((Window.ack_seq q.wnd), (Window.ack_win q.wnd))
          end else begin
            Window.set_ack_seq_win q.wnd seg.header.ack_number window;
            Lwt.return_unit
          end
        end else Lwt.return_unit
      in
      (* Inform the user application of new data *)
      let urx_inform =
        (* TODO: deal with overlapping fragments *)
        let elems_r, winadv = S.fold (fun seg (acc_l, acc_w) ->
            (if Cstruct.length seg.payload > 0 then seg.payload :: acc_l else acc_l),
            (Sequence.add (len seg) acc_w)
          ) ready ([], Sequence.zero) in
        let elems = List.rev elems_r in
        let w = if !force_ack || Sequence.(gt winadv zero)
          then Some winadv else None in
        Lwt_mvar.put q.rx_data (Some elems, w) >>= fun () ->
        (* If the last ready segment has a FIN, then mark the receive
           window as closed and tell the application *)
        (if fin ready then begin
            if S.cardinal waiting != 0 then
              Log.info (fun f -> f "application receive queue closed, but there are waiting segments.");
            Lwt_mvar.put q.rx_data (None, Some Sequence.zero)
          end else Lwt.return_unit)
      in
      tx_ack <&> urx_inform
    | `ChallengeAck | `Unacceptable ->
      send_challenge_ack q
    | `Drop ->
      Lwt.return_unit
    | `Reset ->
      State.tick q.state State.Recv_rst;
      (* Abandon our current segments *)
      q.segs <- S.empty;
      (* Signal TX side *)
      let txalert ack_svcd =
        if not ack_svcd then Lwt.return_unit
        else Lwt_mvar.put q.tx_ack (Window.ack_seq q.wnd, Window.ack_win q.wnd)
      in
      txalert (Window.ack_serviced q.wnd) >>= fun () ->
      (* Use the fin path to inform the application of end of stream *)
      Lwt_mvar.put q.rx_data (None, Some Sequence.zero)
end

(* Transmitted segments are sent in-order, and may also be marked
   with control flags (such as urgent, or fin to mark the end).
*)

type tx_flags = (* At most one of Syn/Fin/Rst/Psh allowed *)
  | No_flags
  | Syn
  | Fin
  | Rst
  | Psh

module Tx = struct

  type ('a, 'b) xmit =
    flags:tx_flags -> wnd:Window.t -> options:Options.t list ->
    seq:Sequence.t -> Cstruct.t -> ('a, 'b) result Lwt.t

  type seg = {
    data: Cstruct.t;
    flags: tx_flags;
    seq: Sequence.t;
    options: Options.t list; (* resent unchanged on retransmission, so a
                                retransmitted SYN(-ACK) keeps MSS/WS *)
  }

  (* Sequence length of the segment *)
  let len seg =
    Sequence.of_int
    ((match seg.flags with
     | No_flags | Psh | Rst -> 0
     | Syn | Fin -> 1) +
    (Cstruct.length seg.data))

  (* Queue of pre-transmission segments *)
  type ('a, 'b) q = {
    segs: seg Lwt_dllist.t;      (* Retransmitted segment queue *)
    xmit: ('a, 'b) xmit;           (* Transmit packet to the wire *)
    rx_ack: Sequence.t Lwt_mvar.t; (* RX Ack thread that we've sent one *)
    wnd: Window.t;                 (* TCP Window information *)
    state: State.t;                (* state of the TCP connection associated
                                      with this queue *)
    tx_wnd_update: int Lwt_mvar.t; (* Received updates to the transmit window *)
    rexmit_timer: Tcptimer.t;      (* Retransmission timer for this connection *)
    mutable dup_acks: int;         (* dup ack count for re-xmits *)
  }

  type t = T: ('a, 'b) q -> t

  let ack_segment _ _ = ()
  (* Take any action to the user transmit queue due to this being
     successfully ACKed *)

  (* URG_TODO: Add sequence number to the Syn_rcvd rexmit to only
     rexmit most recent *)
  let ontimer xmit st segs wnd seq =
    match State.state st with
    | State.Syn_rcvd _ | State.Established | State.Fin_wait_1 _
    | State.Close_wait | State.Closing _ | State.Last_ack _ ->
      begin match peek_opt_l segs with
        | None -> Lwt.return Tcptimer.Stoptimer
        | Some rexmit_seg ->
          match rexmit_seg.seq = seq with
          | false ->
            Log.debug (fun fmt ->
                fmt "PUSHING TIMER - new time=%Lu, new seq=%a"
                  (Window.rto wnd) Sequence.pp rexmit_seg.seq);
            let ret =
              Tcptimer.ContinueSetPeriod (Window.rto wnd, rexmit_seg.seq)
            in
            Lwt.return ret
          | true ->
            if (Window.max_rexmits_done wnd) then (
              (* TODO - include more in log msg like ipaddrs *)
              Log.debug (fun f -> f "Max retransmits reached: %a" Window.pp wnd);
              Log.info (fun fmt -> fmt "Max retransmits reached for connection - terminating");
              State.tick st State.Timeout;
              Lwt.return Tcptimer.Stoptimer
            ) else (
              let flags = rexmit_seg.flags in
              let options = rexmit_seg.options in
              Log.debug (fun fmt ->
                  fmt "TCP retransmission triggered by timer! seq = %d"
                    (Sequence.to_int rexmit_seg.seq));
              Lwt.async
                (fun () ->
                   xmit ~flags ~wnd ~options ~seq rexmit_seg.data
                   (* TODO should this return value really be ignored? *)
                   >|= fun (_: ('a,'b) result) -> () );
              if rexmit_seg.flags = Syn then Window.on_syn_retransmit wnd;
              Window.on_rto wnd;
              Window.backoff_rto wnd;
              Log.debug (fun fmt -> fmt "Backed off! %a" Window.pp wnd);
              Log.debug (fun fmt ->
                  fmt "PUSHING TIMER - new time = %Lu, new seq = %a"
                    (Window.rto wnd) Sequence.pp rexmit_seg.seq);
              let ret =
                Tcptimer.ContinueSetPeriod (Window.rto wnd, rexmit_seg.seq)
              in
              Lwt.return ret
            )
      end
    | _ -> Lwt.return Tcptimer.Stoptimer

  let rec clearsegs q ack_remaining segs =
    match Sequence.(gt ack_remaining zero) with
    | false -> Sequence.zero (* here we return 0l instead of ack_remaining in case
                     the ack was an old packet in the network *)
    | true ->
      match Lwt_dllist.take_opt_l segs with
      | None ->
        Log.debug (fun f -> f "Dubious ACK received");
        ack_remaining
      | Some s ->
        let seg_len = (len s) in
        match Sequence.lt ack_remaining seg_len with
        | true ->
          Log.debug (fun f -> f "Partial ACK received");
          (* return uncleared segment to the sequence *)
          lwt_sequence_add_l s segs;
          ack_remaining
        | false ->
          ack_segment q s;
          clearsegs q (Sequence.sub ack_remaining seg_len) segs

  let rto_t q tx_ack =
    (* Listen for incoming TX acks from the receive queue and ACK
       segments in our retransmission queue *)
    let rec tx_ack_t () =
      let serviceack dupack ack_len seq win =
        let partleft = clearsegs q ack_len q.segs in
        Window.tx_ack q.wnd (Sequence.sub seq partleft) win;
        match dupack || Window.fast_rec q.wnd with
        | true ->
          q.dup_acks <- q.dup_acks + 1;
          if q.dup_acks = 3 ||
            (Sequence.to_int32 ack_len > 0l) then begin
            (* alert window module to fall into fast recovery *)
            Window.alert_fast_rexmit q.wnd seq;
            (* retransmit the bottom of the unacked list of packets *)
            let rexmit_seg = peek_l q.segs in
            Log.debug (fun fmt ->
                fmt "TCP fast retransmission seq=%a, dupack=%a"
                  Sequence.pp rexmit_seg.seq Sequence.pp seq);
            let { wnd; _ } = q in
            let flags=rexmit_seg.flags in
            let options=rexmit_seg.options in
            (* The segment must go out under its own sequence number: [seq] is
               the ACK number, which can point into the middle of the segment
               (partial ACK), and sending the head segment's data under it
               would corrupt the peer's stream. *)
            Lwt.async (fun () ->
                q.xmit ~flags ~wnd ~options ~seq:rexmit_seg.seq rexmit_seg.data
                (* TODO should this return value really be ignored? *)
                >|= fun (_: ('a,'b) result) -> () );
            Lwt.return_unit
          end else
            Lwt.return_unit
        | false ->
          q.dup_acks <- 0;
          Lwt.return_unit
      in
      Lwt_mvar.take tx_ack >>= fun _ ->
      Window.set_ack_serviced q.wnd true;
      let seq = Window.ack_seq q.wnd in
      let win = Window.ack_win q.wnd in
      begin match State.state q.state with
        | State.Reset ->
          (* Note: This is not strictly necessary, as the PCB will be
             GCed later on.  However, it helps removing pressure on
             the GC. *)
          reset_seq q.segs;
          Lwt.return_unit
        | _ ->
          let ack_len = Sequence.sub seq (Window.tx_una q.wnd) in
          let dupacktest () =
            0l = Sequence.to_int32 ack_len &&
            Window.tx_wnd_unscaled q.wnd = Int32.of_int win &&
            not (Lwt_dllist.is_empty q.segs)
          in
          serviceack (dupacktest ()) ack_len seq win
      end >>= fun () ->
      (* Inform the window thread of updates to the transmit window *)
      Lwt_mvar.put q.tx_wnd_update win >>= fun () ->
      tx_ack_t ()
    in
    tx_ack_t ()

  let create ~xmit ~wnd ~state ~rx_ack ~tx_ack ~tx_wnd_update =
    let segs = Lwt_dllist.create () in
    let dup_acks = 0 in
    let expire = ontimer xmit state segs wnd in
    let period_ns = Window.rto wnd in
    let rexmit_timer = Tcptimer.t ~period_ns ~expire in
    let q =
      { xmit; wnd; state; rx_ack; segs; tx_wnd_update;
        rexmit_timer; dup_acks }
    in
    let t = rto_t q tx_ack in
    T q, t

  (* Queue a segment for transmission. May block if:
       - There is no transmit window available.
       - The wire transmit function blocks.
     The transmitter should check that the segment size will
     will not be greater than the transmit window.
  *)
  let output ?(flags=No_flags) ?(options=[]) (T q) data =
    (* Transmit the packet to the wire
         TODO: deal with transmission soft/hard errors here RFC5461 *)
    let { wnd; _ } = q in
    let ack = Window.rx_nxt wnd in
    let seq = Window.tx_nxt wnd in
    let seg = { data; flags; seq; options } in
    let seq_len = len seg in
    Window.tx_advance q.wnd seq_len;
    (* Queue up segment just sent for retransmission if needed *)
    let q_rexmit () =
      match Sequence.(gt seq_len zero) with
      | false -> Lwt.return_unit
      | true ->
        lwt_sequence_add_r seg q.segs;
        let p = Window.rto q.wnd in
        Tcptimer.start q.rexmit_timer ~p seg.seq
    in
    q_rexmit () >>= fun () ->
    q.xmit ~flags ~wnd ~options ~seq data >>= fun _ ->
    (* Inform the RX ack thread that we've just sent one *)
    Lwt_mvar.put q.rx_ack ack

  (* A window probe: an empty segment with an old sequence number (SND.NXT - 1,
     only sent when nothing is in flight), which the peer must answer with an
     ACK carrying its current window. *)
  let send_probe (T q) =
    let seq = Sequence.pred (Window.tx_nxt q.wnd) in
    q.xmit ~flags:No_flags ~wnd:q.wnd ~options:[] ~seq Cstruct.empty
    >|= fun _ -> ()

  (* Retransmit the oldest unacknowledged segment right away, unchanged (same
     sequence number, flags and options).  Used to answer a retransmitted SYN
     in SYN-RCVD with the original SYN-ACK. *)
  let retransmit_head (T q) =
    match peek_opt_l q.segs with
    | None -> Lwt.return_unit
    | Some s ->
      q.xmit ~flags:s.flags ~wnd:q.wnd ~options:s.options ~seq:s.seq s.data
      >|= fun _ -> ()
end

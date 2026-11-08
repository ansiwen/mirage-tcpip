(*
 * Copyright (c) 2010 Anil Madhavapeddy <anil@recoil.org>
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

let src = Logs.Src.create "tcp.window" ~doc:"Mirage TCP Window module"
module Log = (val Logs.src_log src : Logs.LOG)

type time = int64

type t = {
  tx_mss: int;
  tx_isn: Sequence.t;
  rx_isn: Sequence.t;
  max_rx_wnd: int32;               (* Max RX Window size after scaling *)
  tx_wnd_scale: int;               (* TX Window scaling option     *)
  rx_wnd_scale: int;               (* RX Window scaling option     *)

  mutable ack_serviced: bool;
  mutable ack_seq: Sequence.t;
  mutable ack_win: int;
  mutable snd_wl1: Sequence.t;     (* sequence number of the segment that
                                      last updated the send window *)
  mutable snd_wl2: Sequence.t;     (* acknowledgment number of that segment *)

  mutable snd_una: Sequence.t;
  mutable tx_nxt: Sequence.t;
  mutable rx_nxt: Sequence.t;
  mutable rx_nxt_inseq: Sequence.t;
  mutable fast_rec_th: Sequence.t;
  mutable max_tx_wnd : int32;      (* Max seen TX window after scaling *)
  mutable tx_wnd: int32;           (* TX Window size after scaling *)
  mutable rx_wnd: int32;           (* RX Window size after scaling *)
  mutable ssthresh: int32;         (* threshold to switch from exponential
                                      slow start to linear congestion
                                      avoidance *)
  mutable cwnd: int32;             (* congestion window *)
  mutable fast_recovery: bool;     (* in loss recovery (fast recovery or
                                      after a retransmission timeout): partial
                                      ACKs retransmit the next segment *)
  mutable rto_recovery: bool;      (* the recovery was entered by a
                                      retransmission timeout *)

  mutable rtt_timer_on: bool;
  mutable rtt_timer_reset: bool;
  mutable rtt_timer_seq: Sequence.t;
  mutable rtt_timer_starttime: time;
  mutable srtt: time;
  mutable rttvar: time;
  mutable rto: int64;
  mutable backoff_count: int;
}

(* To string for debugging *)
let pp fmt t =
  Format.fprintf fmt
    "Window: rx_nxt=%a rx_nxt_inseq=%a tx_nxt=%a rx_wnd=%lu tx_wnd=%lu snd_una=%a backoffs=%d rto=%Lu"
    Sequence.pp t.rx_nxt
    Sequence.pp t.rx_nxt_inseq
    Sequence.pp t.tx_nxt
    t.rx_wnd t.tx_wnd
    Sequence.pp t.snd_una
    t.backoff_count t.rto

(* Initialise the sequence space *)
let t ~rx_wnd_scale ~tx_wnd_scale ~rx_wnd ~tx_wnd ~rx_isn ~tx_mss ~tx_isn =
  let tx_nxt = tx_isn in
  let rx_nxt = Sequence.succ rx_isn in
  let rx_nxt_inseq = Sequence.succ rx_isn in
  let snd_una = tx_nxt in
  let fast_rec_th = tx_nxt in
  let ack_serviced = true in
  let ack_seq = tx_nxt in
  (* last window received from the peer (unscaled), to detect window updates *)
  let ack_win = tx_wnd in
  let snd_wl1 = rx_isn and snd_wl2 = tx_isn in
  let rx_wnd = Int32.(shift_left (of_int rx_wnd) rx_wnd_scale) in
  let max_rx_wnd = rx_wnd in
  let tx_wnd = Int32.(shift_left (of_int tx_wnd) tx_wnd_scale) in
  let max_tx_wnd = tx_wnd in
  (* ssthresh is initialized per RFC 2581 to a large value so slow-start
     can be used all the way till first loss *)
  let ssthresh = tx_wnd in
  let cwnd = Int32.of_int (tx_mss * 2) in
  let fast_recovery = false in
  let rto_recovery = false in
  let rtt_timer_on = false in
  let rtt_timer_reset = true in
  let rtt_timer_seq = tx_nxt in
  let rtt_timer_starttime = 0L in
  let srtt = (Duration.of_ms 667) in
  let rttvar = 0L in
  let rto = (Duration.of_ms 667) in
  let backoff_count = 0 in
  { tx_isn; rx_isn; max_rx_wnd; max_tx_wnd;
    ack_serviced; ack_seq; ack_win; snd_wl1; snd_wl2;
    snd_una; tx_nxt; tx_wnd; rx_nxt; rx_nxt_inseq;
    fast_rec_th; rx_wnd; tx_wnd_scale; rx_wnd_scale;
    ssthresh; cwnd; tx_mss; fast_recovery; rto_recovery;
    rtt_timer_on; rtt_timer_reset;
    rtt_timer_seq; rtt_timer_starttime; srtt; rttvar; rto; backoff_count }

(* Check if a sequence number is in the right range *)
let valid t seq =
  let redge = Sequence.(add t.rx_nxt (of_int32 t.rx_wnd)) in
  let ledge = Sequence.(sub t.rx_nxt (of_int32 t.max_rx_wnd)) in
  let r = Sequence.between seq ledge redge in
  Log.debug (fun f -> f "sequence validation: seq=%a range=%a[%lu] res=%b"
    Sequence.pp seq Sequence.pp t.rx_nxt t.rx_wnd r);
  r

(* Advance received packet sequence number *)
let rx_advance t b =
  t.rx_nxt <- Sequence.add t.rx_nxt b

(* Early advance received packet sequence number for packet ordering *)
let rx_advance_inseq t b =
  t.rx_nxt_inseq <- Sequence.add t.rx_nxt_inseq b

(* Next expected receive sequence number *)
let rx_nxt t = t.rx_nxt
let rx_nxt_inseq t = t.rx_nxt_inseq
let rx_wnd t = t.rx_wnd
(* Rounded up, so that the advertised right edge never moves left as data
   arrives (rounding down would shrink it by up to 2^scale - 1 bytes). *)
let rx_wnd_unscaled t =
  let round = Int32.(pred (shift_left 1l t.rx_wnd_scale)) in
  Int32.shift_right (Int32.add t.rx_wnd round) t.rx_wnd_scale

(* Right edge of the window as advertised on the wire *)
let rx_wnd_edge t =
  Sequence.add t.rx_nxt
    (Sequence.of_int32 (Int32.shift_left (rx_wnd_unscaled t) t.rx_wnd_scale))

let ack_serviced t = t.ack_serviced
let ack_seq t = t.ack_seq
let ack_win t = t.ack_win

(* RFC 9293 3.10.7.4: update the send window from a segment only if
   SND.WL1 < SEG.SEQ, or SND.WL1 = SEG.SEQ and SND.WL2 =< SEG.ACK *)
let accept_window_update t ~seq ~ack =
  let newer = Sequence.lt t.snd_wl1 seq
              || (Sequence.compare t.snd_wl1 seq = 0 && Sequence.leq t.snd_wl2 ack) in
  if newer then begin t.snd_wl1 <- seq; t.snd_wl2 <- ack end;
  newer

let max_rx_wnd t = t.max_rx_wnd

let set_ack_serviced t v = t.ack_serviced <- v
let set_ack_seq_win t s w =
  t.ack_seq <- s;
  t.ack_win <- w

(* The receive window is the free space in the application receive buffer.
   It may be 0: that is how the peer is told to stop sending. *)
let set_rx_wnd t sz =
  t.rx_wnd <- max 0l (min sz t.max_rx_wnd)

(* Take an unscaled value and scale it up *)
let set_tx_wnd t sz =
  let wnd = Int32.(shift_left (of_int sz) t.tx_wnd_scale) in
  t.tx_wnd <- wnd;
  if wnd > t.max_tx_wnd then
      t.max_tx_wnd <- wnd

(* transmit MSS of current connection *)
let tx_mss t =
  t.tx_mss

(* Advance transmitted packet sequence number *)
let tx_advance t b =
  if not t.rtt_timer_on && not t.fast_recovery then begin
    t.rtt_timer_on <- true;
    t.rtt_timer_seq <- t.tx_nxt;
    t.rtt_timer_starttime <- Mirage_mtime.elapsed_ns ();
  end;
  t.tx_nxt <- Sequence.add t.tx_nxt b

let mss t = Int32.of_int t.tx_mss

(* Congestion window growth for an ACK of [acked] new bytes (RFC 5681 3.1):
   slow start increases cwnd by at most one MSS per ACK, congestion avoidance
   by about one MSS per round trip. *)
let grow_cwnd t acked =
  let incr =
    if t.cwnd < t.ssthresh then min acked (mss t)
    else max (Int32.div (Int32.mul (mss t) (mss t)) t.cwnd) 1l
  in
  t.cwnd <- Int32.add t.cwnd incr

let rtt_sample t =
  t.rtt_timer_on <- false;
  let rtt_m = Int64.sub (Mirage_mtime.elapsed_ns ()) t.rtt_timer_starttime in
  if t.rtt_timer_reset then begin
    t.rtt_timer_reset <- false;
    t.rttvar <- Int64.div rtt_m 2L;
    t.srtt <- rtt_m;
  end else begin
    let (/) = Int64.div
    and ( * ) = Int64.mul
    and (-) = Int64.sub
    and (+) = Int64.add
    in
    (* RFC2988 2.3 *)
    t.rttvar <- (3L * t.rttvar / 4L) + (Int64.abs (t.srtt - rtt_m) / 4L);
    t.srtt <- (7L * t.srtt / 8L) + (rtt_m / 8L)
  end;
  t.rto <- max (Duration.of_ms 667) Int64.(add t.srtt (mul t.rttvar 4L))

(* An ACK was received - use it to adjust cwnd.  Only ACKs of new data grow
   the window; in fast recovery duplicate ACKs inflate it and partial ACKs
   deflate it (RFC 5681 3.2, RFC 6582 3.2). *)
let tx_ack t r win =
  set_tx_wnd t win;
  let acked =
    if Sequence.gt r t.snd_una then Sequence.to_int32 (Sequence.sub r t.snd_una)
    else 0l
  in
  if acked > 0l then begin
    t.backoff_count <- 0;
    t.snd_una <- r;
    (* Karn: the timer is off while retransmitted data is outstanding *)
    if t.rtt_timer_on && Sequence.gt r t.rtt_timer_seq then rtt_sample t
  end;
  if t.fast_recovery then begin
    if Sequence.geq r t.fast_rec_th then begin
      Log.debug (fun f -> f "EXITING recovery");
      (* after fast recovery, deflate to ssthresh; after a timeout cwnd
         has been growing from one segment by slow start, keep it *)
      if not t.rto_recovery then t.cwnd <- t.ssthresh;
      t.fast_recovery <- false;
      t.rto_recovery <- false
    end else if t.rto_recovery then
      (if acked > 0l then grow_cwnd t acked)
    else if acked > 0l then
      (* partial ACK: deflate by the amount acked, add back one segment *)
      t.cwnd <- max (mss t)
          (Int32.add (Int32.sub t.cwnd acked)
             (if acked >= mss t then mss t else 0l))
    else
      (* duplicate ACK: one more segment has left the network *)
      t.cwnd <- Int32.add t.cwnd (mss t)
  end else if acked > 0l then
    grow_cwnd t acked

let tx_nxt t = t.tx_nxt
let tx_wnd t = t.tx_wnd
let tx_wnd_unscaled t = Int32.shift_right t.tx_wnd t.tx_wnd_scale
let max_tx_wnd t = t.max_tx_wnd
let tx_una t = t.snd_una
let fast_rec t = t.fast_recovery
let tx_available t =
  let inflight = Sequence.to_int32 (Sequence.sub t.tx_nxt t.snd_una) in
  let win = min t.cwnd t.tx_wnd in
  let avail_win = Int32.sub win inflight in
  match avail_win < Int32.of_int t.tx_mss with
  | true -> 0l
  | false -> avail_win

let tx_usable t =
  let inflight = Sequence.to_int32 (Sequence.sub t.tx_nxt t.snd_una) in
  max 0l (Int32.sub (min t.cwnd t.tx_wnd) inflight)

let tx_inflight t =
  t.tx_nxt <> t.snd_una


(* Three duplicate ACKs: enter fast recovery (RFC 5681 3.2, RFC 6582) *)
let alert_fast_rexmit t _ =
  if not t.fast_recovery then begin
    let inflight = Sequence.to_int32 (Sequence.sub t.tx_nxt t.snd_una) in
    let newssthresh = max (Int32.div inflight 2l) (Int32.of_int (t.tx_mss * 2)) in
    let newcwnd = Int32.add newssthresh (Int32.of_int (t.tx_mss * 3)) in
    Log.debug (fun fmt ->
        fmt "ENTERING fast recovery inflight=%ld, ssthresh=%ld -> %ld, \
                    cwnd=%ld -> %ld"
          inflight t.ssthresh newssthresh t.cwnd newcwnd);
    t.fast_recovery <- true;
    t.rto_recovery <- false;
    t.fast_rec_th <- t.tx_nxt;
    t.ssthresh <- newssthresh;
    t.rtt_timer_on <- false;
    t.cwnd <- newcwnd
  end

(* The retransmission timer expired (RFC 5681 3.1, eq. 4): halve ssthresh
   (but keep it when the same segment times out again) and restart from a
   one-segment window.  Enter recovery, so that each partial ACK retransmits
   the next unacknowledged segment instead of waiting for another timeout.
   Must be called before [backoff_rto]. *)
let on_rto t =
  let inflight = Sequence.to_int32 (Sequence.sub t.tx_nxt t.snd_una) in
  if t.backoff_count = 0 then
    t.ssthresh <- max (Int32.div inflight 2l) (Int32.of_int (t.tx_mss * 2));
  Log.debug (fun f -> f "retransmission timeout: ssthresh=%ld cwnd=%ld -> %d"
                t.ssthresh t.cwnd t.tx_mss);
  t.cwnd <- mss t;
  t.fast_recovery <- true;
  t.rto_recovery <- true;
  t.fast_rec_th <- t.tx_nxt;
  t.rtt_timer_on <- false

let cwnd t = t.cwnd
let ssthresh t = t.ssthresh

(* RFC 6298 5.5: double the RTO on each backoff; 5.7 allows a maximum of at
   least 60 seconds. *)
let max_rto = Duration.of_sec 60

let rto t =
  let rec backoff r n = if n = 0 || r >= max_rto then r else backoff (Int64.mul r 2L) (n - 1) in
  min max_rto (backoff t.rto t.backoff_count)

let backoff_rto t =
  t.backoff_count <- t.backoff_count + 1;
  t.rtt_timer_on <- false;
  t.rtt_timer_reset <- true

let max_rexmits_done t =
  (t.backoff_count > 5)

let tx_totalbytes t =
  Sequence.(to_int (sub t.tx_nxt t.tx_isn))

let rx_totalbytes t =
  (-) Sequence.(to_int (sub t.rx_nxt t.rx_isn)) 1

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

type t

val pp: Format.formatter -> t -> unit

val t : rx_wnd_scale:int -> tx_wnd_scale:int -> rx_wnd:int ->
  tx_wnd:int -> rx_isn:Sequence.t -> tx_mss:int -> tx_isn:Sequence.t -> t

val valid : t -> Sequence.t -> bool

val rx_advance : t -> Sequence.t -> unit
val rx_advance_inseq : t -> Sequence.t -> unit
val rx_nxt : t -> Sequence.t
val rx_nxt_inseq : t -> Sequence.t

val tx_advance : t -> Sequence.t -> unit
val tx_ack: t -> Sequence.t -> int -> unit

val tx_nxt : t -> Sequence.t
val tx_una : t -> Sequence.t
val tx_mss : t -> int
val fast_rec : t -> bool

val ack_serviced : t -> bool
val ack_seq : t -> Sequence.t
val ack_win : t -> int

val set_ack_serviced : t -> bool -> unit
val set_ack_seq_win : t -> Sequence.t -> int -> unit

(* rx_wnd: number of bytes we are willing to accept *)
val rx_wnd : t -> int32
val max_rx_wnd : t -> int32
(** The size of the receive buffer, i.e. the largest receive window. *)

val accept_window_update : t -> seq:Sequence.t -> ack:Sequence.t -> bool
(** [accept_window_update t ~seq ~ack] is [true] if a segment with these
    sequence and acknowledgment numbers may update the send window (it is not
    older than the segment that last did, RFC 9293 SND.WL1/SND.WL2); it then
    records it as the latest. *)

val rx_wnd_unscaled : t -> int32
(** The receive window as advertised on the wire (scaled down, rounded up). *)

val rx_wnd_edge : t -> Sequence.t
(** The right edge of the advertised receive window: [rx_nxt] plus the
    advertised window. Data beyond it is not accepted. *)

val set_rx_wnd : t -> int32 -> unit
(** [set_rx_wnd t sz] sets the receive window to [sz] (the free space in the
    receive buffer), which may be 0. *)

(* tx_wnd: number of bytes other side is willing to accept *)
val tx_wnd : t -> int32
val tx_wnd_unscaled : t -> int32
(* tx_available: number of bytes we can currently send after
                 accounting for congestion *)
val tx_available : t -> int32

val tx_usable : t -> int32
(** [tx_usable t] is the number of bytes the send and congestion windows
    allow us to send now. Unlike [tx_available] it is not rounded down to 0
    below one MSS; sender-side silly window avoidance decides what to do with
    a small window. *)

(* tx_inflight: is there any data in flight *)
val tx_inflight : t -> bool
val set_tx_wnd : t -> int -> unit
val max_tx_wnd : t -> int32

val alert_fast_rexmit : t -> Sequence.t -> unit

val on_rto : t -> unit
(** [on_rto t] adjusts the congestion state for an expired retransmission
    timer (RFC 5681 3.1): ssthresh is halved, cwnd restarts at one segment and
    loss recovery is entered. Call it before [backoff_rto]. *)

val cwnd : t -> int32
(** The congestion window, in bytes. *)

val ssthresh : t -> int32
(** The slow start threshold, in bytes. *)

val rto : t -> int64
val backoff_rto : t -> unit
val max_rexmits_done : t -> bool

val tx_totalbytes : t -> int
val rx_totalbytes : t -> int

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

(** TCP segments *)

(** The receive queue stores out-of-order segments, and can coalesece
    them on input and pass on an ordered list up the stack to the
    application.

    It also looks for control messages and dispatches them to
    the Rtx queue to ack messages or close channels.
*)

module Rx (ACK:Ack.M) : sig

  type segment = { header: Tcp_packet.t; payload: Cstruct.t }
  (** Individual received TCP segment *)

  val pp_segment: Format.formatter -> segment -> unit

  type t
  (** Queue of receive segments *)

  val pp: Format.formatter -> t -> unit

  val create:
    rx_data:(Cstruct.t list option * Sequence.t option) Lwt_mvar.t ->
    ack:ACK.t ->
    wnd:Window.t ->
    state:State.t ->
    tx_ack:(Sequence.t * int) Lwt_mvar.t ->
    t

  val is_empty : t -> bool

  val input : t -> segment -> unit Lwt.t
  (** Given the current receive queue and an incoming packet,
      update the window, extract any ready segments into the
      user receive queue, and signal any acks to the Tx queue *)

  val acceptable : t -> segment -> bool
  (** [acceptable t seg] is [true] if [seg] would be processed normally by
      [input] (as opposed to being dropped or answered with an ACK only). *)

end

type tx_flags = No_flags | Syn | Fin | Rst | Psh
(** Either Syn/Fin/Rst allowed, but not combinations *)

(** Pre-transmission queue *)
module Tx : sig

  type ('a, 'b) xmit = flags:tx_flags -> wnd:Window.t -> options:Options.t list ->
    seq:Sequence.t -> Cstruct.t -> ('a, 'b) result Lwt.t

  type t
  (** Queue of pre-transmission segments *)

  val create:
    xmit:('a, 'b) xmit -> wnd:Window.t -> state:State.t ->
    rx_ack:Sequence.t Lwt_mvar.t ->
    tx_ack:(Sequence.t * int) Lwt_mvar.t ->
    tx_wnd_update:int Lwt_mvar.t -> t * unit Lwt.t

  val output:
    ?flags:tx_flags -> ?options:Options.t list -> t -> Cstruct.t -> unit Lwt.t
  (** Queue a segment for transmission. May block if:

      {ul
        {- There is no transmit window available.}
        {- The wire transmit function blocks.}}

      The transmitter should check that the segment size will not
      be greater than the transmit window.  *)

  val send_probe: t -> unit Lwt.t
  (** [send_probe t] sends a zero window probe: an empty segment with sequence
      number SND.NXT - 1, which the peer answers with an ACK carrying its
      current window. Only meaningful when no data is in flight. *)

  val retransmit_head: t -> unit Lwt.t
  (** [retransmit_head t] immediately resends the oldest unacknowledged
      segment unchanged (same sequence number, flags and options). Does nothing
      if no segment is outstanding. *)

end

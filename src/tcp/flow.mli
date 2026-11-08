(*
 * Copyright (c) 2011-2014 Anil Madhavapeddy <anil@recoil.org>
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

module Make (IP:Tcpip.Ip.S) : sig
  include Tcpip.Tcp.S with type ipaddr = IP.ipaddr
  val connect : ?verify_checksums:bool -> IP.t -> t Lwt.t
  (** [connect ?verify_checksums ip] starts the TCP layer on [ip].

      With [~verify_checksums:true], segments with an invalid TCP checksum are
      dropped, as RFC 9293 requires. It is off by default because some network
      interfaces deliver locally generated packets with the checksum left
      blank, relying on checksum offload: mirage-net-xen, for instance, does not
      handle the [rx_checksum_blank] flag, so traffic from dom0 or another guest
      on the same host could be dropped. Enable it when the network interface
      always delivers packets with complete checksums. *)

  (**/**)
  (* the number of open connections *)
  val num_open_channels : t -> int
  (**/**)

end

(*
 * Copyright (c) 2010 http://github.com/barko 00336ea19fcb53de187740c490f764f4
 * Copyright (c) 2011 Anil Madhavapeddy <anil@recoil.org>
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

let lwt_sequence_add_l s seq =
  let (_:'a Lwt_dllist.node) = Lwt_dllist.add_l s seq in
  ()

(* A bounded queue to receive data segments and let readers block on
   receiving them. Also supports a monitor that is informed when the
   queue size changes *)
module Rx = struct

  (* Flow control: the receive window advertised to the peer is the free
     space in this buffer (minus [holdback], below).  [add_r] never blocks: a
     peer that respects the window cannot overrun the buffer, and blocking here
     would stop the receive thread from ACKing anything. *)

  type t = {
    q: Cstruct.t option Lwt_dllist.t;
    wnd: Window.t;
    readers: Cstruct.t option Lwt.u Lwt_dllist.t;
    mutable watcher: int32 Lwt_mvar.t option;
    mutable max_size: int32;
    mutable cur_size: int32;
    mutable eof: bool; (* the end of stream was delivered to the reader *)
    mutable holdback: int32;
    (* Space freed by the application that is not advertised yet (receiver
       silly window syndrome avoidance, RFC 1122 4.2.3.3): the right edge of
       the window only moves once the freed space reaches [sws_threshold]. *)
    on_window_update: unit -> unit Lwt.t;
    (* Called (asynchronously) to send a window update ACK when a window that
       was smaller than [sws_threshold] opens up again. *)
  }

  let create ~max_size ~wnd ~on_window_update =
    let q = Lwt_dllist.create () in
    let readers = Lwt_dllist.create () in
    let watcher = None in
    let cur_size = 0l in
    { q; wnd; readers; max_size; cur_size; watcher; holdback = 0l; eof = false;
      on_window_update }

  let sws_threshold t =
    min (Int32.div t.max_size 2l) (Int32.of_int (Window.tx_mss t.wnd))

  let update_window t =
    let free = max 0l (Int32.sub t.max_size t.cur_size) in
    t.holdback <- min t.holdback free;
    Window.set_rx_wnd t.wnd (Int32.sub free t.holdback);
    match t.watcher with
    | None   -> ()
    | Some w -> Lwt.async (fun () -> Lwt_mvar.put w t.cur_size)

  (* The application consumed [len] bytes *)
  let consumed t len =
    let old_wnd = Window.rx_wnd t.wnd in
    t.holdback <- Int32.add t.holdback (Int32.of_int len);
    let threshold = sws_threshold t in
    if t.holdback >= threshold then t.holdback <- 0l;
    update_window t;
    if old_wnd < threshold && Window.rx_wnd t.wnd >= threshold then
      Lwt.async t.on_window_update

  let seglen s =
    match s with
    | None -> 0
    | Some b -> Cstruct.length b

  let remove_all t =
    let rec rm = function
      | 0 -> ()
      | n -> ignore (Lwt_dllist.take_l t.q); rm (pred n)
    in
    rm (Lwt_dllist.length t.q);
    t.cur_size <- 0l;
    update_window t

  let add_r t s =
    begin match Lwt_dllist.take_opt_l t.readers with
      | None ->
        t.cur_size <- Int32.(add t.cur_size (of_int (seglen s)));
        ignore(Lwt_dllist.add_r s t.q);
        update_window t
      | Some u ->
        (* handed straight to a waiting reader: arrived and consumed *)
        if s = None then t.eof <- true;
        Lwt.wakeup u s;
        consumed t (seglen s)
    end;
    Lwt.return_unit

  let take_l t =
    if t.eof then
      (* once the end of stream has been read, every further read is too *)
      Lwt.return None
    else if Lwt_dllist.is_empty t.q then begin
      let th,u = Lwt.wait () in
      let node = Lwt_dllist.add_r u t.readers in
      Lwt.on_cancel th (fun _ -> Lwt_dllist.remove node);
      th
    end else begin
      let s = Lwt_dllist.take_l t.q in
      if s = None then t.eof <- true;
      t.cur_size <- Int32.(sub t.cur_size (of_int (seglen s)));
      consumed t (seglen s);
      Lwt.return s
    end

  let cur_size t = t.cur_size
  let max_size t = t.max_size

  let monitor t mvar =
    t.watcher <- Some mvar

end

(* The transmit queue simply advertises how much data is allowed to be
   written, and a wakener for when it is full. It is up to the application
   to decide how to throttle or breakup its data production with this
   information.
*)
module Tx = struct

  module TXS = Segment.Tx

  type t = {
    wnd: Window.t;
    writers: unit Lwt.u Lwt_dllist.t;
    txq: TXS.t;
    buffer: Cstruct.t Lwt_dllist.t;
    max_size: int32;
    mutable bufbytes: int32;
    mutable persisting: bool; (* the persist timer is running *)
  }

  let create ~max_size ~wnd ~txq =
    let buffer = Lwt_dllist.create () in
    let writers = Lwt_dllist.create () in
    let bufbytes = 0l in
    { wnd; writers; txq; buffer; max_size; bufbytes; persisting = false }

  let len data =
    Int32.of_int (Cstruct.length data)

  let lenv datav =
    match datav with
    |[] -> 0l
    |[d] -> Int32.of_int (Cstruct.length d)
    |ds -> Int32.of_int (List.fold_left (fun a b -> Cstruct.length b + a) 0 ds)

  (* Check how many bytes are available to write to output buffer *)
  let available t =
    let a = Int32.sub t.max_size t.bufbytes in
    match a < (Int32.of_int (Window.tx_mss t.wnd)) with
    | true -> 0l
    | false -> a

  (* Check how many bytes are available to write to wire *)
  let available_cwnd t =
    Window.tx_available t.wnd

  (* Wait until at least sz bytes are available in the window *)
  let rec wait_for t sz =
    if (available t) >= sz then begin
      Lwt.return_unit
    end
    else begin
      let th,u = Lwt.wait () in
      let node = Lwt_dllist.add_r u t.writers in
      Lwt.on_cancel th (fun _ -> Lwt_dllist.remove node);
      th >>= fun () ->
      wait_for t sz
    end

  let compactbufs bl = Cstruct.concat bl

  (* Wait until the user buffer is flushed *)
  let rec wait_for_flushed t =
    if Lwt_dllist.is_empty t.buffer then begin
      Lwt.return_unit
    end
    else begin
      let th,u = Lwt.wait () in
      let node = Lwt_dllist.add_r u t.writers in
      Lwt.on_cancel th (fun _ -> Lwt_dllist.remove node);
      th >>= fun () ->
      wait_for_flushed t
    end

  (* How much buffered data may go out in the next segment.  Sender-side silly
     window syndrome avoidance (RFC 1122 4.2.3.4): send a full segment if the
     window allows it; otherwise only if all buffered data fits, or the usable
     window is at least half the largest window the peer has offered.
     [force] is the persist timer's override: send whatever fits. *)
  let sendable_len ~force t =
    let mss = Int32.of_int (Window.tx_mss t.wnd) in
    let usable = Window.tx_usable t.wnd in
    if usable >= mss then mss
    else if usable > 0l
         && (force || t.bufbytes <= usable
             || usable >= Int32.div (Window.max_tx_wnd t.wnd) 2l)
    then usable
    else 0l

  let max_persist_period = Duration.of_sec 60

  (* The persist timer (RFC 9293 3.8.6.1): data is waiting, nothing is in
     flight (so no ACK or retransmission timer will come), and the peer's
     window is too small to send.  Probe the peer so that a lost window update
     cannot stall the connection forever: with a zero window send a probe
     (which the peer must answer with an ACK carrying its window), otherwise
     send what fits.  Backs off exponentially and never gives up, as long as
     the connection exists. *)
  let rec persist t period =
    Mirage_sleep.ns period >>= fun () ->
    if Lwt_dllist.is_empty t.buffer || Window.tx_inflight t.wnd then begin
      t.persisting <- false;
      Lwt.return_unit
    end else begin
      (if Window.tx_usable t.wnd > 0l then clear_buffer ~force:true t
       else TXS.send_probe t.txq) >>= fun () ->
      persist t (min (Int64.mul 2L period) max_persist_period)
    end

  and start_persist t =
    if not t.persisting && not (Lwt_dllist.is_empty t.buffer)
       && not (Window.tx_inflight t.wnd) then begin
      t.persisting <- true;
      Lwt.async (fun () -> persist t (Window.rto t.wnd))
    end

  and clear_buffer ?(force=false) t =
    let rec addon_more curr_data l =
      match Lwt_dllist.take_opt_l t.buffer with
      | None -> List.rev curr_data
      | Some s ->
        let s_len = len s in
        match s_len > l with
        | true ->
          lwt_sequence_add_l s t.buffer;
          List.rev curr_data
        | false ->
          t.bufbytes <- Int32.sub t.bufbytes s_len;
          addon_more (s::curr_data) (Int32.sub l s_len)
    in
    let get_pkt_to_send () =
      let avail_len = sendable_len ~force t in
      let s = Lwt_dllist.take_l t.buffer in
      let s_len = len s in
      match s_len > avail_len with
      | true ->  begin
          match avail_len with
          |0l -> (* return pkt to buffer *)
            lwt_sequence_add_l s t.buffer;
            None
          |_ -> (* split buffer into a partial write *)
            let to_send,remaining = Cstruct.split s (Int32.to_int avail_len) in
            (* queue remaining view *)
            lwt_sequence_add_l remaining t.buffer;
            t.bufbytes <- Int32.sub t.bufbytes avail_len;
            Some [to_send]
        end
      | false ->
        match s_len < avail_len with
        | true ->
          t.bufbytes <- Int32.sub t.bufbytes s_len;
          Some (addon_more (s::[]) (Int32.sub avail_len s_len))
        | false ->
          t.bufbytes <- Int32.sub t.bufbytes s_len;
          Some [s]
    in
    match Lwt_dllist.is_empty t.buffer with
    | true -> Lwt.return_unit
    | false ->
      match get_pkt_to_send () with
      | None -> start_persist t; Lwt.return_unit
      | Some pkt ->
        let b = compactbufs pkt in
        TXS.output ~flags:Segment.Psh t.txq b >>= fun () ->
        clear_buffer t

  (* Chunk up the segments into MSS max for transmission *)
  let transmit_segments ~mss ~txq datav =
    let transmit acc =
      let b = compactbufs (List.rev acc) in
      TXS.output ~flags:Segment.Psh txq b
    in
    let rec chunk datav acc =
      match datav with
      |[] -> begin
          match acc with
          |[] -> Lwt.return_unit
          |_ -> transmit acc
        end
      |hd::tl ->
        let curlen = Cstruct.lenv acc in
        let tlen = Cstruct.length hd + curlen in
        if tlen > mss then begin
          let a,b = Cstruct.split hd (mss - curlen) in
          transmit (a::acc) >>= fun () ->
          chunk (b::tl) []
        end else
          chunk tl (hd::acc)
    in
    chunk datav []

  let write t datav =
    let l = lenv datav in
    let mss = Int32.of_int (Window.tx_mss t.wnd) in
    match Lwt_dllist.is_empty t.buffer &&
          (l = mss || not (Window.tx_inflight t.wnd)) with
    | false ->
      t.bufbytes <- Int32.add t.bufbytes l;
      List.iter (fun data -> ignore(Lwt_dllist.add_r data t.buffer)) datav;
      (* Nagle: hold back a small segment while data is unacknowledged (its
         ACK will flush the buffer); otherwise try to send now *)
      if t.bufbytes < mss && Window.tx_inflight t.wnd then
        Lwt.return_unit
      else
        clear_buffer t
    | true ->
      let avail_len = available_cwnd t in
      match avail_len < l with
      | true ->
        t.bufbytes <- Int32.add t.bufbytes l;
        List.iter (fun data -> ignore(Lwt_dllist.add_r data t.buffer)) datav;
        clear_buffer t
      | false ->
        let max_size = Window.tx_mss t.wnd in
        transmit_segments ~mss:max_size ~txq:t.txq datav

  let write_nodelay t datav =
    let l = lenv datav in
    match Lwt_dllist.is_empty t.buffer with
    | false ->
      t.bufbytes <- Int32.add t.bufbytes l;
      List.iter (fun data -> ignore(Lwt_dllist.add_r data t.buffer)) datav;
      clear_buffer t
    | true ->
      let avail_len = available_cwnd t in
      match avail_len < l with
      | true ->
        t.bufbytes <- Int32.add t.bufbytes l;
        List.iter (fun data -> ignore(Lwt_dllist.add_r data t.buffer)) datav;
        clear_buffer t
      | false ->
        let max_size = Window.tx_mss t.wnd in
        transmit_segments ~mss:max_size ~txq:t.txq datav


  let inform_app t =
    match Lwt_dllist.take_opt_l t.writers with
    | None   -> Lwt.return_unit
    | Some w ->
      Lwt.wakeup w ();
      (* TODO: check if this should wake all writers not just one *)
      Lwt.return_unit

  (* Indicate that more bytes are available for waiting writers.
     Note that sz does not take window scaling into account, and so
     should be passed as unscaled (i.e. from the wire) here.
     Window will internally scale it up. *)
  let free t _sz =
    clear_buffer t >>= fun () ->
    inform_app t

  let reset t =
    (* FIXME: duplicated code with Segment.reset_seq *)
    let rec reset_seq segs =
      match Lwt_dllist.take_opt_l segs with
      | None   -> ()
      | Some _ -> reset_seq segs
    in
    reset_seq t.buffer;
    t.bufbytes <- 0l;
    (* The connection is gone: wake every blocked writer (and a [close]
       waiting for the buffer to drain), not just one, so none hangs. *)
    let rec wake_all () =
      match Lwt_dllist.take_opt_l t.writers with
      | None -> ()
      | Some w -> Lwt.wakeup w (); wake_all ()
    in
    wake_all ();
    Lwt.return_unit

end

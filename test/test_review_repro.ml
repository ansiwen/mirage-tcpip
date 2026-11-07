(* Reproductions for findings from a review of src/tcp.  Each test asserts the
   RFC-correct behaviour, so a FAILING test confirms the corresponding bug.
   All are marked `Slow so the default (quick) test run stays green; run with
   e.g. `./test.exe test review_repro 7` from _build/default/test. *)

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
let run_server ?(cap=5) backend ~kick (initial_state, fsm_handler) sut () =
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
            fsm_thread initial_state;
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

let send_client_syn ip =
  WIRE.xmit ~ip client_id ~syn:true ~rx_ack:None ~seq:(Sequence.of_int32 client_isn)
    ~window:65535 ~options:[Opt.MSS 1460; Opt.Window_size_shift 7] (Cstruct.create 0)
  >|= Result.get_ok

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
  `Server (send_client_syn, (`SYNACK1, fsm), sut_listens)

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
  `Server (send_client_syn, (`SYNACK1, fsm), sut_listens)

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
    VNETIF_STACK.Stack.TCP.read flow >|= fun _ ->
    Logs.app (fun m -> m "REPRO: reader woken after %.0fs" (Unix.gettimeofday () -. t0))
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

let suite = [
  "1 synack rexmit keeps options", `Slow, run_test "r1" (synack_rexmit_options ());
  "2 duplicate SYN keeps half-open", `Slow, run_test "r2" (duplicate_syn ());
  "3 retransmitted FIN is re-ACKed", `Slow, run_test "r3" (fin_retransmit_acked ());
  "4a OOO reassembly (control, no wrap)", `Slow, run_test "r4a" (ooo_reassembly ~isn:1000000l ());
  "4b OOO reassembly across 2^31", `Slow, run_test "r4b" (ooo_reassembly ~isn:0x7FFFFFF0l ());
  "5a wscale 14 (control)", `Slow, run_test "r5a" (wscale ~shift:14 ());
  "5b wscale 16 clamped", `Slow, run_test "r5b" (wscale ~shift:16 ());
  "6 fast rexmit seq alignment", `Slow, run_test "r6" (fast_rexmit_alignment ());
  "7 rexmit timeout wakes reader", `Slow, run_test "r7" (rexmit_timeout_wakes_reader ());
  "8 half-close quiet peer", `Slow, run_test "r8" (half_close_quiet_peer ());
]

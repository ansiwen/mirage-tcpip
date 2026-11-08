let default_window () =
  Tcp.Window.t ~tx_wnd_scale:2 ~rx_wnd_scale:2 ~rx_wnd:65535 ~tx_wnd:65535 ~rx_isn:Tcp.Sequence.zero ~tx_mss:1460 ~tx_isn:Tcp.Sequence.zero

let fresh_window () =
  let window = default_window () in
  Alcotest.(check bool) "should be no data in flight" false @@ Tcp.Window.tx_inflight window;
  Alcotest.(check bool) "no rexmits yet" false @@ Tcp.Window.max_rexmits_done window;
  Alcotest.(check int) "no traffic transferred yet" 0 @@ Tcp.Window.tx_totalbytes window;
  Alcotest.(check int) "no traffic received yet" 0 @@ Tcp.Window.rx_totalbytes window;
  (* the window advertised in a SYN is never scaled (RFC 7323 2.2) *)
  Alcotest.(check int32) "should be able to send 65535 bytes before the first ACK" 65535l @@ Tcp.Window.tx_wnd window;
  Alcotest.(check int32) "should be able to receive 65535 <<= 2 bytes" Int32.(mul 65535l 4l) @@ Tcp.Window.rx_wnd window;
  Alcotest.(check int64) "initial rto is 1 second (RFC 6298 2.1)" (Duration.of_sec 1) @@ Tcp.Window.rto window;
  Lwt.return_unit

(* Congestion control, RFC 5681 / RFC 6582.  The default window has a
   1460-byte MSS, an initial cwnd of 2 MSS and a 262140-byte send window. *)

let mss = 1460l
let segs n = Int32.mul mss (Int32.of_int n)
let wnd = 65535 (* unscaled window carried by the ACKs *)

(* send [n] bytes *)
let send window n = Tcp.Window.tx_advance window (Tcp.Sequence.of_int32 n)

(* cumulative ACK of [n] bytes beyond the current snd_una *)
let ack_more window n =
  Tcp.Window.tx_ack window Tcp.Sequence.(add (Tcp.Window.tx_una window) (of_int32 n)) wnd

let dupack window = ack_more window 0l

let check_cwnd msg expected window =
  Alcotest.(check int32) msg expected (Tcp.Window.cwnd window)

let cwnd_growth () =
  let w = default_window () in
  check_cwnd "initial cwnd is 2 MSS" (segs 2) w;
  send w (segs 10);
  ack_more w 1000l;
  check_cwnd "slow start grows by the bytes acked when less than an MSS"
    Int32.(add (segs 2) 1000l) w;
  dupack w;
  check_cwnd "a duplicate ACK does not grow cwnd" Int32.(add (segs 2) 1000l) w;
  Tcp.Window.tx_ack w (Tcp.Window.tx_una w) 30000;
  check_cwnd "a window update does not grow cwnd" Int32.(add (segs 2) 1000l) w;
  ack_more w (segs 5);
  check_cwnd "slow start grows by at most one MSS per ACK"
    Int32.(add (segs 3) 1000l) w;
  Lwt.return_unit

let fast_recovery () =
  let w = default_window () in
  send w (segs 20);
  Tcp.Window.alert_fast_rexmit w Tcp.Sequence.zero;
  Alcotest.(check bool) "in fast recovery" true (Tcp.Window.fast_rec w);
  Alcotest.(check int32) "ssthresh = FlightSize / 2" (segs 10) (Tcp.Window.ssthresh w);
  check_cwnd "cwnd = ssthresh + 3 MSS" (segs 13) w;
  Alcotest.(check int32) "no new data right after entering fast recovery" 0l
    (Tcp.Window.tx_available w);
  (* each further duplicate ACK inflates cwnd by one MSS; new data can go out
     once cwnd exceeds the flight size by an MSS: 13 + 8 = 21 segments *)
  let rec dupacks n =
    if Tcp.Window.tx_available w > 0l then n else (dupack w; dupacks (n + 1)) in
  Alcotest.(check int) "new data after 8 more duplicate ACKs" 8 (dupacks 0);
  check_cwnd "inflated cwnd" (segs 21) w;
  ack_more w (segs 2);
  Alcotest.(check bool) "a partial ACK stays in fast recovery" true (Tcp.Window.fast_rec w);
  check_cwnd "partial ACK deflates by the bytes acked, plus one MSS" (segs 20) w;
  ack_more w (segs 18);
  Alcotest.(check bool) "a full ACK ends fast recovery" false (Tcp.Window.fast_rec w);
  check_cwnd "cwnd = ssthresh after fast recovery" (segs 10) w;
  Lwt.return_unit

let retransmission_timeout () =
  let w = default_window () in
  send w (segs 20);
  Tcp.Window.on_rto w;
  Tcp.Window.backoff_rto w;
  Alcotest.(check int32) "ssthresh = FlightSize / 2" (segs 10) (Tcp.Window.ssthresh w);
  check_cwnd "cwnd = 1 MSS (the loss window)" mss w;
  (* the same segment times out again, with more data outstanding *)
  send w (segs 20);
  Tcp.Window.on_rto w;
  Tcp.Window.backoff_rto w;
  Alcotest.(check int32) "ssthresh held constant on a repeated timeout" (segs 10)
    (Tcp.Window.ssthresh w);
  check_cwnd "cwnd still 1 MSS" mss w;
  ack_more w mss;
  Alcotest.(check bool) "partial ACK keeps recovering" true (Tcp.Window.fast_rec w);
  check_cwnd "slow start after a timeout" (segs 2) w;
  ack_more w (segs 39);
  Alcotest.(check bool) "full ACK ends recovery" false (Tcp.Window.fast_rec w);
  check_cwnd "cwnd keeps its slow start value (not set to ssthresh)" (segs 2) w;
  Lwt.return_unit

let rto_backoff () =
  let w = default_window () in
  let rto0 = Tcp.Window.rto w in
  Tcp.Window.backoff_rto w;
  Alcotest.(check int64) "first backoff doubles the RTO" (Int64.mul 2L rto0) (Tcp.Window.rto w);
  Tcp.Window.backoff_rto w;
  Alcotest.(check int64) "second backoff doubles it again" (Int64.mul 4L rto0) (Tcp.Window.rto w);
  for _ = 1 to 20 do Tcp.Window.backoff_rto w done;
  Alcotest.(check int64) "capped at 60 seconds" (Duration.of_sec 60) (Tcp.Window.rto w);
  Lwt.return_unit

let rto_rfc6298 () =
  let w = default_window () in
  send w (segs 1);
  Mirage_mtime_set.tick_for (Duration.of_ms 10);
  ack_more w (segs 1);
  Alcotest.(check int64) "RTO is at least 1 second (RFC 6298 2.4)"
    (Duration.of_sec 1) (Tcp.Window.rto w);
  (* RFC 6298 5.7: a retransmitted SYN-ACK raises the RTO to 3s once ACKed *)
  let w = default_window () in
  send w 1l;  (* the SYN-ACK *)
  Tcp.Window.on_syn_retransmit w;
  Tcp.Window.on_rto w;
  Tcp.Window.backoff_rto w;
  ack_more w 1l;
  Alcotest.(check int64) "RTO 3s after a retransmitted SYN-ACK"
    (Duration.of_sec 3) (Tcp.Window.rto w);
  check_cwnd "initial window one segment after a lost SYN-ACK" mss w;
  let w = default_window () in
  Tcp.Window.handshake_retransmitted w;
  Alcotest.(check int64) "RTO 3s after a retransmitted SYN"
    (Duration.of_sec 3) (Tcp.Window.rto w);
  check_cwnd "initial window one segment after a lost SYN" mss w;
  Lwt.return_unit

let initial_ssthresh () =
  let w = default_window () in
  Alcotest.(check int32) "initial ssthresh is the largest possible window"
    (Int32.shift_left 65535l 14) (Tcp.Window.ssthresh w);
  Lwt.return_unit

let rto_calculation () =
  let window = default_window () in
  (* RFC 2988 2.1 *)
  Alcotest.(check int64) "initial rto is 1 second (RFC 6298 2.1)" (Duration.of_sec 1) @@ Tcp.Window.rto window;
  let receive_window = Tcp.Window.ack_win window in
  Tcp.Window.tx_advance window (Tcp.Window.tx_nxt window);
  Mirage_mtime_set.tick_for (Duration.of_ms 400);
  let max_size = Tcp.Window.tx_available window |> Tcp.Sequence.of_int32 in
  let sz = Tcp.Sequence.add max_size @@ (Tcp.Window.tx_nxt window) in
  Tcp.Window.tx_ack window sz receive_window;
  (* RFC 2988 2.2 *)
  Alcotest.(check int64) "After one RTT measurement, the calculated rto is 400 + (4 * 200) = 1200ms" (Duration.of_ms 1200) @@ Tcp.Window.rto window;

  (* RFC 2988 2.3 *)
  Tcp.Window.tx_advance window (Tcp.Window.tx_nxt window);
  let receive_window = Tcp.Window.ack_win window in
  Mirage_mtime_set.tick_for (Duration.of_ms 300);
  let max_size = Tcp.Window.tx_available window |> Tcp.Sequence.of_int32 in
  let sz = Tcp.Sequence.add max_size @@ (Tcp.Window.tx_nxt window) in
  Tcp.Window.tx_ack window sz receive_window;
  Alcotest.(check int64) "After subsequent RTT measurement, the calculated rto is 1087.5ms" (Duration.of_us 1087500) @@ Tcp.Window.rto window;

  Lwt.return_unit


let suite = [
  "fresh window is sensible", `Quick, fresh_window;
  "cwnd grows only on ACKs of new data", `Quick, cwnd_growth;
  "fast recovery (RFC 5681, RFC 6582)", `Quick, fast_recovery;
  "retransmission timeout resets cwnd (RFC 5681 3.1)", `Quick, retransmission_timeout;
  "RTO backoff doubles and is capped", `Quick, rto_backoff;
  "RTO minimum and 3s rule (RFC 6298)", `Quick, rto_rfc6298;
  "initial ssthresh", `Quick, initial_ssthresh;
  "smoothed rtt, rtt variation and retransmission timer are calculated according to RFC2988", `Quick, rto_calculation;
]

let suite = [
  "tcp_window"     , suite  ;
]

let run test () =
  Lwt_main.run (test ())

let () =
  Printexc.record_backtrace true;
  Mirage_crypto_rng_unix.use_default ();
  (* enable logging to stdout for all modules *)
  Logs.set_reporter (Logs_fmt.reporter ());
  Logs.set_level ~all:true (Some Logs.Debug);
  let suite = List.map (fun (n, s) ->
      n, List.map (fun (d, s, f) -> d, s, run f) s
    ) suite
  in
  Alcotest.run "tcpip" suite

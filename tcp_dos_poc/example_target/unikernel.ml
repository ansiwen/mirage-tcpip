(* Simple TCP Echo Server for Testing
 *
 * This is a minimal MirageOS unikernel that runs a TCP echo server
 * suitable for testing the TCP DoS vulnerabilities.
 *
 * Build with:
 *   mirage configure -t unix
 *   make depend
 *   make
 *
 * Run with:
 *   sudo ./dist/unikernel
 *)

open Lwt.Infix

module Main (S: Tcpip.Stack.V4V6) = struct

  let log_src = Logs.Src.create "echo" ~doc:"TCP Echo Server"
  module Log = (val Logs.src_log log_src : Logs.LOG)

  let rec echo flow =
    S.TCP.read flow >>= function
    | Ok `Eof ->
      Log.info (fun f -> f "Connection closed by peer");
      Lwt.return_unit
    | Ok (`Data buf) ->
      Log.debug (fun f -> f "Received %d bytes" (Cstruct.length buf));
      S.TCP.write flow buf >>= (function
        | Ok () -> echo flow
        | Error e ->
          Log.warn (fun f -> f "Write error: %a" S.TCP.pp_write_error e);
          Lwt.return_unit
      )
    | Error e ->
      Log.warn (fun f -> f "Read error: %a" S.TCP.pp_error e);
      Lwt.return_unit

  let tcp_callback flow =
    let dst, dst_port = S.TCP.dst flow in
    let src, src_port = S.TCP.src flow in
    Log.info (fun f -> f "New connection from %a:%d to %a:%d"
      Ipaddr.pp src src_port Ipaddr.pp dst dst_port);
    echo flow >>= fun () ->
    S.TCP.close flow

  let start s =
    Log.info (fun f -> f "Starting TCP Echo Server on port 8080");
    Log.info (fun f -> f "This server is intentionally vulnerable for testing");
    Log.warn (fun f -> f "DO NOT use in production!");

    (* Listen on port 8080 *)
    S.TCP.listen (S.tcp s) ~port:8080 tcp_callback;

    (* Also provide some connection statistics *)
    let rec stats_loop () =
      Lwt_unix.sleep 30.0 >>= fun () ->
      Log.info (fun f -> f "Server still running - connections active");
      stats_loop ()
    in
    Lwt.async stats_loop;

    Log.info (fun f -> f "Ready to accept connections");
    S.listen s

end

#!/usr/bin/env python3
"""
Minimal TCP Echo Server for Testing

This is the simplest possible TCP echo server for testing TCP implementations.
No dependencies, no complexity, just echoes back whatever it receives.

Usage:
    python3 simple_echo_server.py [port]

Default port: 9999
"""

import socket
import sys
import threading

def handle_client(client_socket, addr):
    """Handle a single client connection"""
    print(f"[+] Connection from {addr[0]}:{addr[1]}")
    try:
        while True:
            data = client_socket.recv(4096)
            if not data:
                break
            # Echo it back
            client_socket.send(data)
            print(f"[*] Echoed {len(data)} bytes to {addr[0]}:{addr[1]}")
    except Exception as e:
        print(f"[-] Error with {addr[0]}:{addr[1]}: {e}")
    finally:
        client_socket.close()
        print(f"[-] Closed connection from {addr[0]}:{addr[1]}")

def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9999

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server.bind(('0.0.0.0', port))
        server.listen(100)
        print(f"[*] TCP Echo Server listening on 0.0.0.0:{port}")
        print(f"[*] Press Ctrl+C to stop")
        print()

        while True:
            client, addr = server.accept()
            # Handle each client in a thread
            thread = threading.Thread(target=handle_client, args=(client, addr))
            thread.daemon = True
            thread.start()

    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        server.close()

if __name__ == '__main__':
    main()

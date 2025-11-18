#!/usr/bin/env python3
"""
Simple standalone Challenge ACK rate limiting test

This tests ONLY the Challenge ACK behavior without interference from other tests.
"""

import sys
import time
from scapy.all import *

def test_challenge_ack_rate_limiting(target_ip, target_port, num_packets=50):
    """Test if Challenge ACKs are rate limited per RFC 5961"""

    sport = random.randint(10000, 65000)

    print(f"\n[*] Establishing connection to {target_ip}:{target_port}")

    # Establish connection
    ip = IP(dst=target_ip)
    syn = TCP(sport=sport, dport=target_port, flags='S', seq=1000)
    syn_ack = sr1(ip/syn, timeout=3, verbose=0)

    if not syn_ack or not syn_ack.haslayer(TCP) or syn_ack[TCP].flags != 'SA':
        print("[-] Failed to establish connection")
        return

    print(f"[+] Connection established")
    print(f"    Window: {syn_ack[TCP].window}")
    print(f"    Our seq: 1001, Their seq: {syn_ack[TCP].seq + 1}")

    # Complete handshake
    our_seq = 1001
    their_seq = syn_ack[TCP].seq + 1
    window = syn_ack[TCP].window

    ack = TCP(sport=sport, dport=target_port, flags='A', seq=our_seq, ack=their_seq)
    send(ip/ack, verbose=0)

    time.sleep(0.5)

    # Test Challenge ACK triggering
    print(f"\n[*] Testing Challenge ACK rate limiting")
    print(f"[*] Sending {num_packets} packets with:")
    print(f"    - IN-WINDOW sequence numbers (valid)")
    print(f"    - INVALID ACK numbers (should trigger Challenge ACK)")
    print()

    responses = []
    start_time = time.time()

    for i in range(num_packets):
        # Sequence: within window (cycles through window)
        seq_offset = (i * 200) % window
        valid_seq = our_seq + seq_offset

        # ACK: way beyond what they could have sent
        invalid_ack = their_seq + 0x70000000 + i

        # Send packet
        pkt = TCP(sport=sport, dport=target_port, flags='A',
                 seq=valid_seq, ack=invalid_ack)

        # Listen for response
        resp = sr1(ip/pkt, timeout=0.1, verbose=0)

        if resp and resp.haslayer(TCP):
            responses.append(time.time())
            if len(responses) <= 5:
                print(f"  [{len(responses)}] ACK received: seq={resp[TCP].seq} ack={resp[TCP].ack} flags={resp[TCP].flags}")

        # Small delay to not overwhelm
        time.sleep(0.02)

    elapsed = time.time() - start_time

    # Analysis
    print(f"\n{'='*60}")
    print("RESULTS")
    print('='*60)
    print(f"Packets sent:     {num_packets}")
    print(f"Responses:        {len(responses)}")
    print(f"Time elapsed:     {elapsed:.2f} seconds")
    print(f"Response rate:    {len(responses)/elapsed:.1f} ACKs/second")
    print(f"Response ratio:   {len(responses)/num_packets*100:.1f}%")
    print()

    # Verdict
    if len(responses) == 0:
        print("RESULT: No responses received")
        print("  Possible reasons:")
        print("  - Packets are being dropped/filtered")
        print("  - Challenge ACKs are not implemented")
        print("  - Test parameters are incorrect")
    elif len(responses) >= num_packets * 0.9:
        print("RESULT: VULNERABLE - No rate limiting detected")
        print(f"  Expected: ~{min(num_packets, int(elapsed * 100))} responses (RFC 5961: 100/sec limit)")
        print(f"  Got:      {len(responses)} responses (~{len(responses)/elapsed:.0f}/sec)")
        print("  Action:   Implement ACK throttling per RFC 5961 Section 5")
    elif len(responses) <= elapsed * 110:
        print("RESULT: PROTECTED - Rate limiting appears to be working")
        print(f"  Response rate {len(responses)/elapsed:.1f}/sec is within RFC 5961 limits")
    else:
        print("RESULT: UNCLEAR")
        print(f"  Got {len(responses)} responses at {len(responses)/elapsed:.1f}/sec")

    print('='*60)

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: python3 test_challenge_ack_simple.py <target_ip> <target_port> [num_packets]")
        print("Example: python3 test_challenge_ack_simple.py 10.30.0.88 80 50")
        sys.exit(1)

    target_ip = sys.argv[1]
    target_port = int(sys.argv[2])
    num_packets = int(sys.argv[3]) if len(sys.argv) > 3 else 50

    if os.geteuid() != 0:
        print("[-] Root privileges required")
        sys.exit(1)

    print("="*60)
    print("Challenge ACK Rate Limiting Test")
    print("="*60)
    print(f"Target: {target_ip}:{target_port}")
    print(f"Packets: {num_packets}")

    test_challenge_ack_rate_limiting(target_ip, target_port, num_packets)

# TCP DoS Proof of Concept Tests

This directory contains Proof of Concept (PoC) demonstrations of the DoS vulnerabilities identified in the TCP implementation review.

## Vulnerabilities Tested

### 1. Challenge ACK Storm (CVE-like - High Severity)
**File:** `challenge_ack_storm.py`

**Vulnerability:** The implementation doesn't rate-limit Challenge ACKs as required by RFC 5961 Section 5.

**Impact:** An attacker can trigger unlimited Challenge ACKs, causing:
- CPU exhaustion on the target
- Network bandwidth consumption
- Information disclosure (connection enumeration)

**How it works:**
1. Attacker sends packets with invalid sequence numbers but valid 4-tuple
2. Each packet triggers a Challenge ACK response
3. No rate limiting = unlimited response rate
4. Target becomes overwhelmed with ACK generation and transmission

### 2. Out-of-Order Segment Memory Exhaustion (High Severity)
**File:** `ooo_segment_dos.py`

**Vulnerability:** The out-of-order segment queue (`segs: S.t` in segment.ml) has no size limit.

**Impact:**
- Unbounded memory growth
- Memory exhaustion leading to OOM
- Service unavailability

**How it works:**
1. Attacker establishes valid TCP connection
2. Sends many segments with future sequence numbers
3. Each segment is queued waiting for missing segments
4. Queue grows without bound until memory exhausted

### 3. Timer Race Condition Exploitation (Medium Severity)
**File:** `timer_race_dos.py`

**Vulnerability:** Race condition in `tcptimer.ml:start()` allows multiple timer loops.

**Impact:**
- Multiple retransmission timers running
- Packet duplication
- Resource exhaustion

**How it works:**
1. Trigger rapid state changes requiring timer restarts
2. Race condition causes multiple timer loops to spawn
3. Retransmissions multiply exponentially
4. Network and CPU exhaustion

### 4. Connection Table Exhaustion (Medium Severity)
**File:** `connection_exhaustion.py`

**Vulnerability:** Incomplete resource cleanup on RST/timeout, connections linger in tables.

**Impact:**
- Connection table fills up
- New legitimate connections rejected
- Service unavailable

**How it works:**
1. Open many connections to different ports
2. Send RST or let them timeout
3. Resources not properly cleaned up
4. Hash tables fill up preventing new connections

## Prerequisites

```bash
# Install Python dependencies
pip3 install scapy

# Root/sudo access required for raw sockets
```

## Setup

### 1. Build a Test Mirage Unikernel

You'll need a simple TCP echo server using mirage-tcpip to test against:

```ocaml
(* test_server.ml *)
open Lwt.Infix

module Main (S: Tcpip.Stack.V4) = struct
  let start s =
    S.TCP.listen (S.tcp s) ~port:8080 (fun flow ->
      let rec echo () =
        S.TCP.read flow >>= function
        | Ok `Eof -> Lwt.return_unit
        | Ok (`Data buf) ->
          S.TCP.write flow buf >>= fun _ ->
          echo ()
        | Error _ -> Lwt.return_unit
      in
      echo ()
    );
    S.listen s
end
```

### 2. Network Setup

```bash
# Set up network interface for testing
sudo ip tuntap add tap0 mode tap
sudo ip addr add 10.0.0.1/24 dev tap0
sudo ip link set tap0 up
```

### 3. Run Target Unikernel

```bash
# Start your mirage unikernel (adjust based on your build)
sudo ./test_server --net direct --dhcp false --ipv4 10.0.0.2/24 --ipv4-gateway 10.0.0.1
```

## Running the PoCs

### Test 1: Challenge ACK Storm

```bash
sudo python3 challenge_ack_storm.py --target 10.0.0.2 --port 8080 --rate 1000
```

**What to observe:**
- Monitor CPU usage on target: `top` or `htop`
- Monitor network traffic: `tcpdump -i tap0 -n tcp`
- Watch for continuous stream of ACK packets
- Target CPU should spike to 100%

**Expected results:**
- Target sends ACKs at unlimited rate (no throttling)
- CPU consumption increases linearly with attack rate
- 1000 pps attack should cause significant load

### Test 2: Out-of-Order Segment DoS

```bash
sudo python3 ooo_segment_dos.py --target 10.0.0.2 --port 8080 --segments 10000
```

**What to observe:**
- Monitor target memory: `free -m` (if accessible)
- Watch for memory growth in unikernel logs
- Connection may become unresponsive

**Expected results:**
- Memory usage grows with number of OOO segments sent
- ~10000 segments with 1460 bytes each = ~14MB minimum growth
- Connection becomes unresponsive when queue full

### Test 3: Timer Race Condition

```bash
sudo python3 timer_race_dos.py --target 10.0.0.2 --port 8080 --iterations 100
```

**What to observe:**
- Watch for duplicate packets in tcpdump
- Monitor retransmission rate
- Check for exponentially increasing traffic

**Expected results:**
- Duplicate retransmissions observed
- Packet rate increases over time
- Multiple timer loops running simultaneously

### Test 4: Connection Exhaustion

```bash
sudo python3 connection_exhaustion.py --target 10.0.0.2 --connections 1000
```

**What to observe:**
- Try connecting legitimately: `telnet 10.0.0.2 8080`
- Monitor connection table size (if exposed via metrics)
- Watch for connection refused errors

**Expected results:**
- After attack, legitimate connections may fail
- Target cannot accept new connections
- Memory footprint remains high

## Monitoring Commands

```bash
# Continuous traffic monitoring
tcpdump -i tap0 -n tcp port 8080

# Packet rate
tcpdump -i tap0 -n tcp | pv -l -r > /dev/null

# Connection states (on Linux target)
ss -tan | grep 8080 | wc -l

# Network bandwidth
iftop -i tap0
```

## Mitigation Verification

After applying fixes from the review, re-run tests to verify:

1. **Challenge ACK Storm:** Should see rate limiting to ~100 ACKs/sec per RFC 5961
2. **OOO Segments:** Should see segment queue capped at reasonable limit
3. **Timer Race:** Should see only one timer loop per connection
4. **Connection Exhaustion:** Should see proper cleanup, tables don't fill

## Safety Warnings

⚠️ **WARNING:** These are attack tools. Only use against systems you own/control.

- Run only in isolated test environments
- Never use against production systems
- Never use against systems you don't own
- Some networks may flag this traffic as malicious
- Your IP may be blocked/banned if used improperly

## Understanding the Results

### Normal Behavior (Without Vulnerabilities)

- Challenge ACKs rate-limited to 100/sec
- OOO queue bounded (e.g., 100 segments max)
- One retransmission timer per connection
- Connections cleaned up within 2*MSL (4 minutes)

### Vulnerable Behavior (Current Implementation)

- Challenge ACKs unlimited (matches attack rate)
- OOO queue grows unbounded
- Multiple timers can spawn
- Connections linger in tables

## Additional Testing

### Stress Test Combination

Run multiple attacks simultaneously:

```bash
# Terminal 1
sudo python3 challenge_ack_storm.py --target 10.0.0.2 --port 8080 --rate 500 &

# Terminal 2
sudo python3 ooo_segment_dos.py --target 10.0.0.2 --port 8080 --segments 5000 &

# Terminal 3
sudo python3 connection_exhaustion.py --target 10.0.0.2 --connections 500 &
```

This amplifies the DoS effect and may crash the target faster.

### Performance Baseline

Before testing, establish baseline metrics:

```bash
# Record normal CPU usage
# Record normal memory usage
# Record normal connection handling capacity
# Record normal packet rate
```

Compare these to values during attack to quantify impact.

## References

- [RFC 5961 - Improving TCP's Robustness to Blind In-Window Attacks](https://tools.ietf.org/html/rfc5961)
- [TCP REVIEW.md](../TCP_REVIEW.md) - Full security analysis
- [CVE-2016-5696](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-5696) - Similar challenge ACK issue in Linux

## Responsible Disclosure

If you find these vulnerabilities affect real systems, please:

1. Do NOT exploit them maliciously
2. Report to the maintainers via GitHub Security Advisory
3. Allow time for fixes before public disclosure
4. Follow coordinated vulnerability disclosure practices

## License

These PoC scripts are provided for security research and testing purposes only.
Use at your own risk and only against systems you own or have explicit permission to test.

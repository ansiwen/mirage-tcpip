# TCP DoS PoC Quick Start Guide

This guide will help you quickly set up and run the TCP DoS vulnerability tests.

## Prerequisites

```bash
# Install Python and Scapy
sudo apt-get update
sudo apt-get install -y python3 python3-pip tcpdump
pip3 install scapy

# Install Mirage (if testing with the example unikernel)
opam install mirage
```

## Quick Test (5 minutes)

### Option 1: Test Against Existing Server

If you have a TCP server running:

```bash
cd tcp_dos_poc

# Run a single quick test
sudo python3 challenge_ack_storm.py --target <IP> --port <PORT> --rate 100
```

### Option 2: Build and Test Against Example Unikernel

```bash
# Build the test server
cd tcp_dos_poc/example_target
mirage configure -t unix
make depend
make

# In terminal 1: Start the server
sudo ./dist/unikernel

# In terminal 2: Run tests
cd ../
sudo python3 challenge_ack_storm.py --target 127.0.0.1 --port 8080 --rate 100
```

## Running All Tests

```bash
cd tcp_dos_poc

# Quick test suite (~5 minutes)
sudo ./run_all_tests.sh <target_ip> <port> quick

# Normal test suite (~15 minutes)
sudo ./run_all_tests.sh <target_ip> <port> normal

# Thorough test suite (~30 minutes)
sudo ./run_all_tests.sh <target_ip> <port> thorough
```

Example:
```bash
sudo ./run_all_tests.sh 10.0.0.2 8080 normal
```

## Individual Tests

### 1. Challenge ACK Storm (Most Critical)

Tests RFC 5961 rate limiting:

```bash
# Light test
sudo python3 challenge_ack_storm.py --target <IP> --port <PORT> --rate 100

# Aggressive test
sudo python3 challenge_ack_storm.py --target <IP> --port <PORT> --rate 1000
```

**What to watch for:**
- Check if target sends unlimited ACKs (VULNERABLE)
- Or limits to ~100/sec (PROTECTED)

### 2. Out-of-Order Segment Memory Exhaustion

Tests unbounded queue growth:

```bash
# Small test (~1.4 MB)
sudo python3 ooo_segment_dos.py --target <IP> --port <PORT> --segments 1000

# Medium test (~14 MB)
sudo python3 ooo_segment_dos.py --target <IP> --port <PORT> --segments 10000

# Large test (~140 MB)
sudo python3 ooo_segment_dos.py --target <IP> --port <PORT> --segments 100000
```

**What to watch for:**
- Increasing memory usage on target
- Connection becoming unresponsive
- OOM errors

### 3. Connection Exhaustion

Tests resource cleanup:

```bash
# RST-based test
sudo python3 connection_exhaustion.py --target <IP> --port <PORT> --connections 1000 --method rst

# Half-open (SYN flood variant)
sudo python3 connection_exhaustion.py --target <IP> --port <PORT> --connections 1000 --method half-open

# Timeout-based test
sudo python3 connection_exhaustion.py --target <IP> --port <PORT> --connections 500 --method timeout
```

**What to watch for:**
- New connections failing after attack
- Connection table filling up
- Service becoming unavailable

## Monitoring During Tests

### Monitor CPU and Memory

```bash
# On target (if accessible)
htop

# Or basic monitoring
watch -n 1 'ps aux | grep unikernel'
```

### Monitor Network Traffic

```bash
# Capture all traffic to target port
sudo tcpdump -i any -n "tcp port 8080"

# Count packets per second
sudo tcpdump -i any -n "tcp port 8080" | pv -l -r > /dev/null

# Analyze packet flags
sudo tcpdump -i any -n "tcp port 8080" -v | grep Flags
```

### Monitor Connections (Linux)

```bash
# Count connections to port 8080
watch -n 1 'ss -tan | grep 8080 | wc -l'

# Show connection states
watch -n 1 'ss -tan state established | grep 8080'
```

## Interpreting Results

### Challenge ACK Test

✅ **PROTECTED**: Response rate limited to ~100 ACKs/sec
❌ **VULNERABLE**: Response rate matches attack rate (500-1000 ACKs/sec)

### Out-of-Order Test

✅ **PROTECTED**: Connection remains responsive, memory stable
❌ **VULNERABLE**: Connection hangs, memory grows significantly

### Connection Exhaustion

✅ **PROTECTED**: New connections succeed after attack
❌ **VULNERABLE**: New connections fail or timeout

## Common Issues

### "Permission denied" error

```bash
# You need root for raw sockets
sudo python3 challenge_ack_storm.py ...
```

### "No module named 'scapy'"

```bash
pip3 install scapy
# Or
sudo pip3 install scapy
```

### Target not reachable

```bash
# Check target is running
ping <target_ip>

# Check port is open
nc -zv <target_ip> <port>

# Check firewall
sudo iptables -L
```

### Tests timeout or hang

- Target may be overwhelmed (vulnerability confirmed)
- Increase timeout values in scripts
- Reduce attack intensity (lower --rate, --segments, or --connections)

## Safety Reminders

⚠️ **CRITICAL**: Only test systems you own or have explicit permission to test

- These are real attack tools
- They can cause service disruption
- They may crash vulnerable systems
- Network monitoring may flag this as malicious
- You may be blocked or banned from networks

## Next Steps After Testing

### If Vulnerabilities Found:

1. **Document findings** - Save the report files
2. **Review TCP_REVIEW.md** - Find the specific issue details
3. **Apply fixes** - Implement the recommended mitigations
4. **Re-test** - Verify the fixes work
5. **Report** - If this affects others, follow responsible disclosure

### Fixes Overview:

From `TCP_REVIEW.md`:

- **Challenge ACK**: Implement rate limiting in `segment.ml:134-136`
- **OOO Queue**: Add max queue size in `segment.ml:81-92`
- **Connection Cleanup**: Fix `flow.ml:251-267` clearpcb function
- **Resource Limits**: Add per-connection memory limits

## Getting Help

- Read the full review: `../TCP_REVIEW.md`
- Check individual PoC help: `python3 <script>.py --help`
- Review logs for error messages
- Check the README.md in this directory

## Example Test Session

```bash
# 1. Start in the PoC directory
cd tcp_dos_poc

# 2. Quick verification target is up
nc -zv 10.0.0.2 8080

# 3. Run challenge ACK test
sudo python3 challenge_ack_storm.py --target 10.0.0.2 --port 8080 --rate 500

# 4. Wait for system to recover
sleep 15

# 5. Run OOO test
sudo python3 ooo_segment_dos.py --target 10.0.0.2 --port 8080 --segments 5000

# 6. Check if service still works
nc -zv 10.0.0.2 8080

# 7. Review results
# If tests show vulnerabilities, review TCP_REVIEW.md for fixes
```

## Automated Testing

For CI/CD integration:

```bash
# Run tests and check exit code
sudo ./run_all_tests.sh 10.0.0.2 8080 quick
if [ $? -eq 0 ]; then
    echo "Tests completed successfully"
else
    echo "Tests failed - check report"
fi
```

## Report Files

After running `run_all_tests.sh`, you'll get:

- `dos_test_report_YYYYMMDD_HHMMSS.txt` - Full test results
- Review this file for vulnerability indicators
- Compare against baseline from unpatched version
- Use to verify patches are effective

## Performance Baseline

Before testing, record baseline:

```bash
# CPU usage
top -bn1 | grep unikernel

# Memory usage
ps aux | grep unikernel | awk '{print $4 "% " $5 "KB"}'

# Connection count
ss -tan | grep 8080 | wc -l

# Packet rate
tcpdump -i any -n "tcp port 8080" -c 1000 -w /dev/null
```

Compare these values during attack to quantify impact.

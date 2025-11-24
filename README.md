# Scanner.py - Comprehensive Feature Summary

## Core Detection Capabilities

### Hybrid Detection System
- **Dual-mode operation**: Rule-based + Machine Learning detection
- **ML-only mode**: `--ml` flag disables rule-based detection
- **Rule-only mode**: Configurable via `USE_ML = False`
- **Real-time packet capture**: Scapy AsyncSniffer on configurable interface
- **Bidirectional flow tracking**: 5-tuple flow identification with forward/backward correlation

### Rule-Based Detection (Traditional)
- **ICMP Flood**: 50+ packets per 5-second window
- **Port Scan**: 20+ unique ports per 5-second window  
- **Self-filtering**: Ignores port 8000 traffic
- **Immediate blocking**: Sub-second response time

### Machine Learning Detection
- **Pre-trained HistGradientBoosting model**: 20-feature flow analysis
- **Minimum 10 packets per flow**: Ensures statistical reliability
- **Flow-based features**: Duration, packet lengths, IAT, rates, headers, TCP window
- **Detectable attacks**: DoS (GoldenEye, Hulk, SlowHTTPTest, Slowloris), DDoS, SSH/FTP Brute Force, SQL Injection, XSS, Infiltration, Bot traffic
- **Automatic model error handling**: Disables ML on prediction failures

## Advanced Security Features

### IP Whitelist System with Anti-Spoofing
- **13 pre-configured safe IPs**: Google DNS, Cloudflare DNS, Quad9, OpenDNS, AWS metadata, Microsoft DNS, localhost
- **Command-line management**: `--whitelist-add`, `--whitelist-remove`, `--whitelist-show`
- **Multi-layer spoofing detection**:
  - Rate limiting: 1000 packets/minute threshold
  - TTL variance analysis: Detects inconsistent hop counts
  - Early detection: 5-7 packets with variance triggers alert
  - Port-based heuristics: DNS servers on non-DNS ports flagged
- **Verification states**: Insufficient data, verified legitimate, or confirmed spoofed
- **Automatic blocking override**: Spoofed whitelisted IPs blocked despite whitelist
- **Minimum packet requirement**: 5 packets before trust decisions

### Multi-Stage Attack Chain Reconstruction
- **Temporal correlation**: 5-minute correlation window
- **5 attack phases tracked**:
  - Reconnaissance (port scans)s
  - DoS/DDoS attacks (all variants)
  - Brute force (SSH, FTP, Web)
  - Web attacks (SQL injection, XSS)
  - Infiltration/C2 (data exfil, bots)
- **Chain detection**: Triggers when ≥2 different phases from same IP
- **Attack timeline**: Chronological event reconstruction with timestamps
- **60-second cooldown**: Prevents alert spam per IP
- **Epic formatting**: Color-coded alerts with recommended actions

## Threat Intelligence Integration

### OWASP Top 10:2025 Mapping
- **All 10 categories covered**: A01-A10:2025
- **Attack-to-vulnerability mapping**: Each attack type linked to relevant OWASP categories
- **Detailed descriptions**: Vulnerability names and security implications
- **Official documentation links**: Direct OWASP reference URLs
- **Multi-category support**: Attacks can map to multiple vulnerabilities

### MITRE ATT&CK Framework Integration
- **17 attack types mapped**: Complete coverage of detectable threats
- **Full tactic coverage**: Reconnaissance, Initial Access, Credential Access, Lateral Movement, Command & Control, Impact
- **Technique IDs**: Specific TTPs (e.g., T1046, T1498, T1110)
- **Kill chain phases**: Attack lifecycle positioning
- **Integrated display**: Combined OWASP/MITRE telemetry in single output

### Threat Intelligence Display
- **Color-coded telemetry**: ANSI color formatting with box-drawing characters
- **Consistent formatting**: Unified style across OWASP, MITRE, spoofing, and chain alerts
- **UTF-8 box drawings**: Professional ╔═╗║╚╝ borders
- **Emoji indicators**: Visual threat severity markers
- **Source IP highlighting**: Cyan color-coded attacker identification

## IP Blocking & Management

### Dynamic IP Blocking
- **Delayed iptables execution**: 20-second grace period for multi-stage detection
- **Background threading**: Non-blocking firewall rule application
- **Configurable duration**: 5-second default block time (adjustable)
- **Automatic unblocking**: Expires after `BLOCK_DURATION`
- **Persistent tracking**: `blocked_ips` dictionary with timestamps
- **Graceful degradation**: Works without iptables (WSL/non-Linux)

### Attack Event Recording
- **Always-on tracking**: Events recorded even for blocked IPs
- **AttackEvent class**: Stores IP, type, timestamp, details
- **Cross-detection recording**: Rule-based and ML events unified
- **Flow-through recording**: Multiple attacks from same IP tracked

## Logging & Auditing

### CSV Logging System
- **File**: `log.csv` (configurable)
- **Per-packet logging**: Every processed packet recorded
- **Format**: Timestamp, IPs, ports, protocol, flags, classification label
- **Append-only**: No log rotation (manual management)
- **Forensic trail**: Complete audit history

### Console Output
- **Multi-level logging**: Standard, warnings, critical alerts
- **Color-coded messages**: 7-color ANSI palette
- **Spoofing alerts**: Dedicated formatted output
- **ML detection messages**: Whitelisted status indicators
- **Block/unblock notifications**: Timestamped actions
- **Suppressed duplicate alerts**: Rate limiting on repetitive messages

## Flow Management

### Bidirectional Flow Tracking
- **Flow class**: UUID-identified network conversations
- **5-tuple keying**: (src_ip, dst_ip, src_port, dst_port, protocol)
- **Direction detection**: Automatic forward/backward classification
- **Packet accumulation**: Separate lists for each direction
- **Header tracking**: IP header lengths per packet
- **TCP-specific**: Initial window size from SYN packets
- **10-minute timeout**: Configurable via `FLOW_TIMEOUT`
- **Automatic cleanup**: Expired flow removal every 5 seconds

### Flow Feature Extraction (20 Features)
1. **Duration**: Flow duration in microseconds
2-6. **Forward packets**: Total length, max, mean, min segment size, avg segment size
7-8. **Backward packets**: Mean length, std deviation
9. **Forward IAT**: Total, min, max inter-arrival time
10-12. **Flow IAT**: Mean, min, max
13-14. **Rate metrics**: Flow packets/s, forward packets/s
15. **Headers**: Forward header length
16. **Subflow**: Forward bytes
17. **TCP**: Initial forward window bytes

## Threading Architecture

### 2 Concurrent Threads
1. **Main thread**: Packet capture, processing pipeline, 1-second unblock loop
2. **Monitor thread**: 5-second intervals for ICMP/portscan checks, flow cleanup

### Thread Safety
- **Defaultdict usage**: Thread-safe counters
- **Daemon threads**: Automatic cleanup on exit

## Configuration & Customization

### Command-Line Arguments
- `--ml`: ML-only mode
- `--whitelist-add IP`: Add IP to whitelist
- `--whitelist-remove IP`: Remove IP from whitelist
- `--whitelist-show`: Display all whitelisted IPs

### Configurable Parameters
- `INTERFACE`: Network interface to monitor
- `MODEL_PATH`: ML model file location
- `LOG_FILE`: CSV log destination
- `THRESHOLD_ICMP`: ICMP flood threshold
- `THRESHOLD_PORTSCAN`: Port scan threshold
- `MONITOR_WINDOW`: Check interval (seconds)
- `BLOCK_DURATION`: IP block duration (seconds)
- `FLOW_TIMEOUT`: Flow expiration time (seconds)
- `ATTACK_CHAIN_WINDOW`: Event correlation window (300s)
- `WHITELIST_RATE_LIMIT`: Max packets/min from whitelisted IPs
- `WHITELIST_TTL_VARIANCE_THRESHOLD`: TTL std deviation limit
- `WHITELIST_MIN_PACKETS_FOR_VERIFICATION`: Minimum packets for trust
- `WHITELIST_SPOOF_ALERT_COOLDOWN`: Seconds between spoofing alerts

## Performance & Reliability

### Optimization Features
- **Async packet capture**: Non-blocking Scapy sniffer
- **Flow-based ML**: Reduces predictions from per-packet to per-flow
- **Periodic cleanup**: Prevents memory leaks
- **One-time alerts**: ML detection alert flag per flow
- **Efficient data structures**: Defaultdicts, sets for tracking

### Error Handling
- **ML model fallback**: Disables ML on errors, continues with rules
- **iptables graceful failure**: Works without firewall access
- **Missing file handling**: Checks for model existence
- **Packet layer validation**: Skips non-IP packets

## Security Best Practices

### Self-Protection
- **Port 8000 filtering**: Prevents detection of scanner's own traffic
- **Automatic unblocking**: Prevents permanent locks
- **Whitelist protection**: Preserves critical infrastructure access
- **Spoofing detection**: Identifies whitelisted IP abuse
- **Cooldown mechanisms**: Prevents alert storms

### Attack Coverage
- **Network layer**: ICMP floods
- **Transport layer**: SYN floods, port scans
- **Application layer**: HTTP DoS, brute force, injection attacks
- **Reconnaissance**: Port scanning detection
- **Persistence**: Bot and C2 traffic detection
- **Exfiltration**: Data infiltration patterns

## Attack Detection Matrix

| Attack Type | Detection | Threshold | Block Time | OWASP | MITRE |
|------------|-----------|-----------|------------|-------|-------|
| ICMP Flood | Rule-based | 50/5s | 5s | A02, A06 | T1498 |
| Port Scan | Rule-based | 20 ports/5s | 5s | A01, A02, A09 | T1046 |
| DoS GoldenEye | ML | 10 packets | 5s | A02, A06 | T1498 |
| DoS Hulk | ML | 10 packets | 5s | A02, A06 | T1498 |
| DoS SlowHTTPTest | ML | 10 packets | 5s | A02, A06, A10 | T1498 |
| DoS Slowloris | ML | 10 packets | 5s | A02, A06, A10 | T1498 |
| DDoS/LOIC | ML | 10 packets | 5s | A02, A06 | T1498 |
| SSH Brute Force | ML | 10 packets | 5s | A07, A09 | T1110.001 |
| FTP Brute Force | ML | 10 packets | 5s | A07, A09 | T1110.001 |
| Web Brute Force | ML | 10 packets | 5s | A07, A09 | T1110 |
| SQL Injection | ML | 10 packets | 5s | A05, A04 | T1190 |
| XSS | ML | 10 packets | 5s | A05, A08 | T1189 |
| Infiltration | ML | 10 packets | 5s | A01, A07 | T1021 |
| Bot Traffic | ML | 10 packets | 5s | A01, A07 | T1071 |
| Spoofed Whitelist | Anti-spoofing | 5 packets | 5s | Multiple | Multiple |
| Multi-Stage Chain | Correlation | 2 phases/5min | 5s + Epic Alert | Multiple | Multiple |

## System Requirements

### Software Dependencies
- Python 3.7+
- Scapy (packet capture)
- joblib (model loading)
- numpy (numerical operations)
- Linux/WSL with iptables (optional, for blocking)

### Runtime Requirements
- Root/sudo access (packet capture)
- Network interface access
- Pre-trained ML model file (`hgb_model.joblib`)

### Resource Usage
- **Memory**: ~1KB per active flow, 5-minute event history
- **CPU**: Low (async capture) + Medium (ML inference every 10 packets)
- **Disk**: Append-only CSV logging, no rotation

## Operational Modes

### 1. Full Hybrid Mode (Default)
```bash
sudo python3 scanner.py
```
- Rule-based + ML detection active
- Maximum coverage and accuracy
- Best for production

### 2. ML-Only Mode
```bash
sudo python3 scanner.py --ml
```
- Disables rule-based detection
- Only ML classifications
- Best for ML model evaluation

### 3. Rule-Only Mode
```python
# Edit: USE_ML = False
sudo python3 scanner.py
```
- No ML model required
- Fast, low resource usage
- Best for embedded/limited systems

## Key Innovations

1. **Delayed Firewall Blocking**: 20-second grace period allows multi-stage attack detection before packet dropping
2. **Whitelisted IP Verification**: Anti-spoofing system prevents abuse of trusted IPs
3. **Attack Chain Reconstruction**: Temporal correlation reveals coordinated multi-phase attacks
4. **Dual Framework Mapping**: Simultaneous OWASP and MITRE ATT&CK correlation
5. **Flow-Based ML**: Network conversation analysis (not packet-level) improves accuracy
6. **Async Architecture**: Non-blocking design prevents packet loss
7. **Progressive Trust**: Whitelisted IPs require proof of legitimacy over time
8. **Unified Telemetry**: Consistent formatting across all alert types
9. **Zero-Configuration Whitelist**: Pre-loaded with critical infrastructure IPs

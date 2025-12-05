# Automated Threat Hunting Framework

## Enterprise-Grade Security Operations Center (SOC) Platform

A comprehensive, real-time threat detection and response system combining Machine Learning-based network analysis, MITRE ATT&CK framework mapping, OWASP Top 10:2025 vulnerability correlation, and an advanced visual SOC dashboard.

---

## Architecture Overview

```
                    +------------------+
                    |    INTERNET      |
                    +--------+---------+
                             |
                    +--------v---------+
                    | PERIMETER FIREWALL|
                    +--------+---------+
                             |
                    +--------v---------+
                    |   CORE SWITCH    |
                    +--------+---------+
                             |
         +-------------------+-------------------+
         |                   |                   |
+--------v-------+  +--------v-------+  +--------v-------+
| THREAT SCANNER |  |  SERVER RACK   |  |   DATABASE     |
| (ML Analysis)  |  |                |  |   CLUSTER      |
+--------+-------+  +----------------+  +----------------+
         |
+--------v-------+
|  WORKSTATIONS  |
+----------------+
```

---

## Core Components

### 1. Scanner Engine (`scanner.py`)

The heart of the threat detection system featuring:

#### Hybrid Detection Architecture
- **Machine Learning Classification**: HistGradientBoosting model trained on 20 network flow features
- **Rule-Based Detection**: Traditional threshold-based analysis for ICMP floods and port scans
- **Flow-Based Analysis**: Bidirectional network conversation tracking with 5-tuple identification

#### Detection Capabilities
| Attack Category | Specific Attacks | Detection Method |
|----------------|------------------|------------------|
| **DoS/DDoS** | GoldenEye, HULK, Slowloris, SlowHTTPTest, HOIC, LOIC | ML Classifier |
| **Credential Attacks** | SSH Brute Force, FTP Brute Force, Generic Brute Force | ML Classifier |
| **Network Attacks** | ICMP Flood, Port Scan, SYN Flood | Rule + ML |
| **Exfiltration** | Data Infiltration, Bot C2 Communication | ML Classifier |
| **Web Attacks** | SQL Injection, XSS | ML Classifier |

#### Anti-Spoofing Protection
- TTL variance analysis across packet streams
- Rate limiting for whitelisted IP addresses
- Port-based heuristics for DNS server validation
- Progressive trust verification (minimum 5 packets)

---

### 2. SOC Dashboard (`gui.py`)

Professional Security Operations Center interface built with Tkinter:

#### Enterprise Network Topology Visualization
- Real-time network architecture display
- Attack path visualization with animated particle system
- Node status indicators (healthy/under attack)
- Equipment-accurate representations:
  - Cloud icon for Internet gateway
  - Rectangular nodes for network equipment
  - Stacked rectangles for server racks
  - Multi-monitor display for workstations

#### Attack Animation System
Each attack type has unique visual characteristics:
- **Inbound Floods** (DoS/DDoS): High-density particle streams from Internet to targets
- **Credential Attacks**: Burst patterns targeting authentication servers
- **Data Exfiltration**: Particles flowing from Database/Servers to Internet
- **C2 Beacons**: Periodic outbound pulses from compromised workstations
- **Port Scans**: Sequential probing animations across multiple targets

#### Threat Intelligence Panel
Dense, verbose threat logging with:
- Millisecond-precision timestamps
- ML classifier confidence scores
- Full MITRE ATT&CK technique details
- OWASP 2025 vulnerability mappings
- Recommended response actions

#### Firewall Response Panel
- Real-time block event logging
- Blocked IP management interface
- One-click unblock functionality
- Response action recommendations

#### Statistics Dashboard
- Live packet counter
- Active flow monitoring
- Threat detection counter
- Blocked IP counter

---

### 3. Attack Simulation Framework (`attack_demo.sh`)

Comprehensive penetration testing toolkit for security validation:

#### Network Attacks
- **ICMP Flood**: High-volume ping flood (T1498)
- **Port Scan**: Service enumeration (T1046)

#### Credential Attacks
- **SSH Brute Force**: Automated SSH credential testing (T1110.001)
- **FTP Brute Force**: FTP authentication attacks (T1110.001)
- **Generic Brute Force**: Multi-protocol credential attacks (T1110)

#### Application Layer DoS
- **GoldenEye**: HTTP keep-alive exhaustion (T1499.001)
- **HULK**: Unique URL flood bypassing cache (T1499.002)
- **Slowloris**: Slow header transmission attack (T1499.002)
- **SlowHTTPTest**: Slow POST body attack (T1499.002)

#### DDoS Simulation
- **HOIC**: High Orbit Ion Cannon simulation (T1498)
- **LOIC-HTTP**: Low Orbit Ion Cannon simulation (T1498)

#### Advanced Threats
- **Botnet C2**: Command and Control beacon simulation (T1071)
- **Data Exfiltration**: Sensitive data theft simulation (T1048)

#### Multi-Stage APT Chain
Full kill chain simulation:
1. Reconnaissance (Port Scan)
2. Initial Access (SSH Brute Force)
3. Impact (DoS Attack)
4. Exfiltration (Data Theft)

---

## Threat Intelligence Integration

### MITRE ATT&CK Framework

Complete tactic and technique mapping:

| Tactic | Techniques Covered |
|--------|-------------------|
| **Reconnaissance** | T1046 Network Service Scanning |
| **Initial Access** | T1190 Exploit Public-Facing Application |
| **Credential Access** | T1110 Brute Force, T1110.001 Password Guessing |
| **Lateral Movement** | T1021 Remote Services |
| **Command & Control** | T1071 Application Layer Protocol |
| **Exfiltration** | T1048 Exfiltration Over Alternative Protocol |
| **Impact** | T1498 Network DoS, T1499 Endpoint DoS |

### OWASP Top 10:2025 Mapping

| Code | Vulnerability | Related Attacks |
|------|--------------|-----------------|
| A01:2025 | Broken Access Control | Port Scan, Infiltration, Bot |
| A02:2025 | Security Misconfiguration | DoS, DDoS, Port Scan |
| A04:2025 | Insecure Design | Brute Force, SSH Attacks |
| A05:2025 | Injection | SQL Injection, XSS |
| A07:2025 | Authentication Failures | All Brute Force variants |
| A08:2025 | Data Integrity Failures | XSS, Bot Traffic |
| A09:2025 | Logging & Alerting Failures | Brute Force, Port Scan |
| A10:2025 | Mishandling Exceptional Conditions | Slowloris, SlowHTTPTest |

---

## Installation

### Prerequisites
```bash
# System requirements
- Python 3.8+
- Linux/WSL with root access
- Network interface access

# Python dependencies
pip install scapy joblib numpy requests
```

### Setup
```bash
# Clone repository
git clone <repository-url>
cd automated-threat-hunting-framework

# Train ML model (if not present)
cd training
python3 training.py
cd ..

# Verify model exists
ls -la hgb_model.joblib
```

---

## Usage

### Starting the SOC Dashboard
```bash
# Run with sudo for packet capture capabilities
sudo python3 gui.py

# In the GUI:
# 1. Set network interface (default: lo)
# 2. Browse and select ML model file
# 3. Click START to begin monitoring
```

### Running Attack Simulations
```bash
# In a separate terminal
sudo bash attack_demo.sh

# Interactive menu allows:
# - Individual attack selection
# - Quick test (5 attack types)
# - Full APT chain simulation
```

### Scanner Standalone Mode
```bash
# Full hybrid detection
sudo python3 scanner.py

# ML-only mode
sudo python3 scanner.py --ml

# Whitelist management
sudo python3 scanner.py --whitelist-show
sudo python3 scanner.py --whitelist-add 192.168.1.100
sudo python3 scanner.py --whitelist-remove 192.168.1.100
```

---

## Configuration

### Scanner Parameters (`scanner.py`)
```python
INTERFACE = "lo"              # Network interface
MODEL_PATH = "hgb_model.joblib"  # ML model location
THRESHOLD_ICMP = 50           # ICMP flood threshold
THRESHOLD_PORTSCAN = 20       # Port scan threshold
BLOCK_DURATION = 5            # IP block duration (seconds)
FLOW_TIMEOUT = 600            # Flow expiration (seconds)
ATTACK_CHAIN_WINDOW = 300     # Event correlation window
```

### Pre-Configured IP Whitelist
- Google DNS (8.8.8.8, 8.8.4.4)
- Cloudflare DNS (1.1.1.1, 1.0.0.1)
- Quad9 DNS (9.9.9.9)
- OpenDNS (208.67.222.222, 208.67.220.220)
- AWS Metadata Service (169.254.169.254)

---

## ML Model Training

### Dataset Requirements
- CIC-IDS compatible format (.parquet files)
- Place training data in `training/data/` directory

### Feature Set (20 Features)
```
Init Fwd Win Bytes, Fwd Header Length, Fwd Seg Size Min,
Fwd Packets Length Total, Fwd Packet Length Max, Subflow Fwd Bytes,
Fwd Packet Length Mean, Bwd Packet Length Mean, Fwd IAT Total,
Fwd Packets/s, Flow IAT Mean, Bwd Packet Length Std,
Flow IAT Min, Fwd IAT Min, Flow Packets/s, Flow IAT Max,
Flow Duration, Avg Fwd Segment Size, Fwd IAT Max, Avg Bwd Segment Size
```

### Training Command
```bash
cd training
python3 training.py
# Output: ../hgb_model.joblib
```

---

## Multi-Stage Attack Chain Detection

The system automatically correlates attacks from the same source IP within a 5-minute window to identify coordinated APT campaigns:

### Detection Phases
1. **Reconnaissance**: Port scanning, service enumeration
2. **DoS/DDoS**: Network and application layer attacks
3. **Credential Attacks**: Brute force attempts
4. **Web Attacks**: Injection, XSS attempts
5. **Infiltration/C2**: Data exfiltration, botnet traffic

### Alert Triggers
- 2+ different attack phases from same IP
- Generates comprehensive kill chain timeline
- Provides threat assessment and response recommendations

---

## Response Capabilities

### Automated Actions
- **IP Blocking**: Automatic iptables rule insertion
- **Grace Period**: 20-second delay allows multi-stage detection
- **Auto-Unblock**: Configurable block duration

### Recommended Manual Actions
Each threat type includes specific response guidance:
- Firewall rule recommendations
- IDS signature suggestions
- Incident response procedures
- Forensic preservation steps

---

## Output Formats

### Console Output
- Color-coded severity levels
- Box-drawing character formatting
- Real-time detection notifications
- OWASP/MITRE correlation display

### CSV Logging
```
Timestamp, Source IP, Destination IP, Src Port, Dst Port, Protocol, Flags, Label
```

### GUI Display
- Dense threat intelligence cards
- Timestamp precision to milliseconds
- Visual attack topology animations
- Real-time statistics counters

---

## System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **CPU** | 2 cores | 4+ cores |
| **RAM** | 2 GB | 4+ GB |
| **Python** | 3.8 | 3.10+ |
| **OS** | Linux/WSL | Ubuntu 22.04 |
| **Network** | Any interface | Dedicated monitoring |

---

## Security Considerations

- Requires root/sudo for packet capture
- Firewall rules require iptables access
- Whitelist verification prevents spoofing attacks
- Rate limiting protects against resource exhaustion
- Graceful degradation when iptables unavailable

---

## File Structure

```
automated-threat-hunting-framework/
├── scanner.py          # Core detection engine
├── gui.py              # SOC dashboard interface
├── attack_demo.sh      # Attack simulation toolkit
├── hgb_model.joblib    # Trained ML model
├── log.csv             # Detection audit log
├── training/
│   ├── training.py     # ML model training script
│   └── data/           # Training datasets
└── README.md           # Documentation
```

---

## License

This project is intended for authorized security testing and educational purposes only. Unauthorized use against systems you do not own or have explicit permission to test is illegal.

---

## Contributors

Developed as an advanced cybersecurity demonstration showcasing:
- Real-time ML-based threat detection
- Enterprise SOC visualization
- MITRE ATT&CK and OWASP framework integration
- Automated incident response capabilities

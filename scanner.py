# Features: CSV logging, ML mode with flow tracking, SYN flood, ICMP flood, Port scan, block/unblock

import scapy.all as scapy
import time
import joblib
import subprocess
import csv
import numpy as np
import os
from collections import defaultdict
from datetime import datetime
from threading import Thread
import argparse
import sys
import warnings
import requests
import queue
import json
import uuid
warnings.filterwarnings("ignore", category=UserWarning)
# ============================================================================
# OWASP TOP 10:2025 INTEGRATION PATCH FOR SCANNER.PY
# ============================================================================
# Add this code RIGHT AFTER the imports (after line 18: warnings.filterwarnings...)
# and BEFORE the INTERFACE = "lo" line

# ==================== OWASP TOP 10:2025 MAPPING ====================
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RED_BG = '\033[41m'
# ============================================================================
# ENHANCED THREAT INTELLIGENCE SYSTEM
# OWASP Top 10:2025 + MITRE ATT&CK Framework Integration
# ============================================================================

# Add this COMPLETE section after the Colors class definition in scanner.py

# MITRE ATT&CK Tactics mapping
MITRE_ATTACK_MAPPING = {
    "PORT_SCAN": {"tactic": "Reconnaissance", "technique": "T1046 - Network Service Scanning", "kill_chain": "Reconnaissance"},
    "SYN_FLOOD": {"tactic": "Impact", "technique": "T1499 - Endpoint Denial of Service", "kill_chain": "Denial of Service"},
    "ICMP_FLOOD": {"tactic": "Impact", "technique": "T1498 - Network Denial of Service", "kill_chain": "Denial of Service"},
    "DoS attacks-GoldenEye": {"tactic": "Impact", "technique": "T1498 - Network Denial of Service", "kill_chain": "Denial of Service"},
    "DoS attacks-Hulk": {"tactic": "Impact", "technique": "T1498 - Network Denial of Service", "kill_chain": "Denial of Service"},
    "DoS attacks-SlowHTTPTest": {"tactic": "Impact", "technique": "T1498 - Network Denial of Service", "kill_chain": "Denial of Service"},
    "DoS attacks-Slowloris": {"tactic": "Impact", "technique": "T1498 - Network Denial of Service", "kill_chain": "Denial of Service"},
    "DDoS": {"tactic": "Impact", "technique": "T1498 - Network Denial of Service", "kill_chain": "Denial of Service"},
    "DDOS attack-HOIC": {"tactic": "Impact", "technique": "T1498 - Network Denial of Service", "kill_chain": "Denial of Service"},
    "DDOS attack-LOIC-HTTP": {"tactic": "Impact", "technique": "T1498 - Network Denial of Service", "kill_chain": "Denial of Service"},
    "DDOS attack-LOIC-UDP": {"tactic": "Impact", "technique": "T1498 - Network Denial of Service", "kill_chain": "Denial of Service"},
    "Brute Force": {"tactic": "Credential Access", "technique": "T1110 - Brute Force", "kill_chain": "Exploitation"},
    "SSH-Bruteforce": {"tactic": "Credential Access", "technique": "T1110.001 - Password Guessing", "kill_chain": "Exploitation"},
    "FTP-BruteForce": {"tactic": "Credential Access", "technique": "T1110.001 - Password Guessing", "kill_chain": "Exploitation"},
    "SQL Injection": {"tactic": "Initial Access", "technique": "T1190 - Exploit Public-Facing Application", "kill_chain": "Exploitation"},
    "XSS": {"tactic": "Initial Access", "technique": "T1189 - Drive-by Compromise", "kill_chain": "Exploitation"},
    "Infiltration": {"tactic": "Lateral Movement", "technique": "T1021 - Remote Services", "kill_chain": "Lateral Movement"},
    "Infilteration": {"tactic": "Lateral Movement", "technique": "T1021 - Remote Services", "kill_chain": "Lateral Movement"},
    "Bot": {"tactic": "Command and Control", "technique": "T1071 - Application Layer Protocol", "kill_chain": "Command and Control"},
    "Web Attack": {"tactic": "Initial Access", "technique": "T1190 - Exploit Public-Facing Application", "kill_chain": "Exploitation"},
}

OWASP_TOP_10 = {
    "A01:2025": {"name": "Broken Access Control", "description": "Unauthorized access to resources", "link": "https://owasp.org/Top10/A01_2025-Broken_Access_Control/"},
    "A02:2025": {"name": "Security Misconfiguration", "description": "Insecure default configurations", "link": "https://owasp.org/Top10/A02_2025-Security_Misconfiguration/"},
    "A03:2025": {"name": "Software Supply Chain Failures", "description": "Compromised dependencies", "link": "https://owasp.org/Top10/A03_2025-Software_Supply_Chain_Failures/"},
    "A04:2025": {"name": "Cryptographic Failures", "description": "Weak encryption, exposed data", "link": "https://owasp.org/Top10/A04_2025-Cryptographic_Failures/"},
    "A05:2025": {"name": "Injection", "description": "SQL, NoSQL, OS command injection", "link": "https://owasp.org/Top10/A05_2025-Injection/"},
    "A06:2025": {"name": "Insecure Design", "description": "Missing security controls", "link": "https://owasp.org/Top10/A06_2025-Insecure_Design/"},
    "A07:2025": {"name": "Authentication Failures", "description": "Broken authentication", "link": "https://owasp.org/Top10/A07_2025-Authentication_Failures/"},
    "A08:2025": {"name": "Data Integrity Failures", "description": "Insecure deserialization", "link": "https://owasp.org/Top10/A08_2025-Software_Data_Integrity_Failures/"},
    "A09:2025": {"name": "Logging & Alerting Failures", "description": "Insufficient logging", "link": "https://owasp.org/Top10/A09_2025-Logging_Alerting_Failures/"},
    "A10:2025": {"name": "Mishandling Exceptional Conditions", "description": "Improper error handling", "link": "https://owasp.org/Top10/A10_2025-Mishandling_Exceptional_Conditions/"}
}

ATTACK_OWASP_MAPPING = {
    "SYN_FLOOD": ["A02:2025", "A06:2025"],
    "ICMP_FLOOD": ["A02:2025", "A06:2025"],
    "PORT_SCAN": ["A01:2025", "A02:2025", "A09:2025"],
    "DoS attacks-GoldenEye": ["A02:2025", "A06:2025"],
    "DoS attacks-Hulk": ["A02:2025", "A06:2025"],
    "DoS attacks-SlowHTTPTest": ["A02:2025", "A06:2025", "A10:2025"],
    "DoS attacks-Slowloris": ["A02:2025", "A06:2025", "A10:2025"],
    "DDoS": ["A02:2025", "A06:2025"],
    "DDOS attack-HOIC": ["A02:2025", "A06:2025"],
    "DDOS attack-LOIC-HTTP": ["A02:2025", "A06:2025"],
    "DDOS attack-LOIC-UDP": ["A02:2025", "A06:2025"],
    "SQL Injection": ["A05:2025", "A04:2025"],
    "Brute Force": ["A07:2025", "A09:2025"],
    "SSH-Bruteforce": ["A07:2025", "A09:2025"],
    "FTP-BruteForce": ["A07:2025", "A09:2025"],
    "XSS": ["A05:2025", "A08:2025"],
    "Infiltration": ["A01:2025", "A07:2025"],
    "Infilteration": ["A01:2025", "A07:2025"],
    "Bot": ["A01:2025", "A07:2025"],
    "Web Attack": ["A05:2025", "A01:2025"],
}


def log_owasp_mapping(attack_type, attacker_ip):
    """Log OWASP Top 10 and MITRE ATT&CK mappings with impressive formatting"""
    owasp_codes = ATTACK_OWASP_MAPPING.get(attack_type, [])
    mitre_info = MITRE_ATTACK_MAPPING.get(attack_type, {})
    
    if not owasp_codes and not mitre_info:
        return
    
    print(f"\n{Colors.RED_BG}{Colors.BOLD} ⚠️  THREAT INTELLIGENCE CORRELATION ⚠️  {Colors.ENDC}")
    print(f"{Colors.FAIL}╔{'═'*78}╗{Colors.ENDC}")
    print(f"{Colors.FAIL}║{Colors.ENDC} {Colors.BOLD}Attack Type:{Colors.ENDC} {Colors.WARNING}{attack_type}{Colors.ENDC} | {Colors.BOLD}Source IP:{Colors.ENDC} {Colors.OKCYAN}{attacker_ip}{Colors.ENDC}")
    print(f"{Colors.FAIL}║{Colors.ENDC}")
    
    # MITRE ATT&CK Section
    if mitre_info:
        print(f"{Colors.FAIL}║{Colors.ENDC} {Colors.BOLD}{Colors.UNDERLINE}MITRE ATT&CK Framework:{Colors.ENDC}")
        print(f"{Colors.FAIL}║{Colors.ENDC}   {Colors.HEADER}🎯 Tactic:{Colors.ENDC} {Colors.WARNING}{mitre_info.get('tactic', 'Unknown')}{Colors.ENDC}")
        print(f"{Colors.FAIL}║{Colors.ENDC}   {Colors.HEADER}🔧 Technique:{Colors.ENDC} {Colors.OKBLUE}{mitre_info.get('technique', 'Unknown')}{Colors.ENDC}")
        print(f"{Colors.FAIL}║{Colors.ENDC}   {Colors.HEADER}⚔️  Kill Chain Phase:{Colors.ENDC} {Colors.FAIL}{mitre_info.get('kill_chain', 'Unknown')}{Colors.ENDC}")
        print(f"{Colors.FAIL}║{Colors.ENDC}")
    
    # OWASP Section
    if owasp_codes:
        print(f"{Colors.FAIL}║{Colors.ENDC} {Colors.BOLD}{Colors.UNDERLINE}OWASP Top 10:2025 Vulnerabilities:{Colors.ENDC}")
        for code in owasp_codes:
            vuln = OWASP_TOP_10.get(code, {})
            if vuln:
                print(f"{Colors.FAIL}║{Colors.ENDC}   {Colors.RED_BG}{Colors.BOLD} {code} {Colors.ENDC} {Colors.HEADER}{Colors.BOLD}{vuln['name']}{Colors.ENDC}")
                print(f"{Colors.FAIL}║{Colors.ENDC}   {Colors.OKBLUE}└─ {vuln['description']}{Colors.ENDC}")
    
    print(f"{Colors.FAIL}╚{'═'*78}╝{Colors.ENDC}\n")
def log_attack_chain_epic(ip, events):
    """Display EPIC attack chain alert with maximum impact"""
    print(f"\n\n{Colors.RED_BG}{Colors.BOLD}{'='*69}{Colors.ENDC}")
    print(f"{Colors.RED_BG}{Colors.BOLD}     ⚠️⚠️⚠️  CRITICAL: MULTI-STAGE ATTACK CHAIN DETECTED  ⚠️⚠️⚠️     {Colors.ENDC}")
    print(f"{Colors.RED_BG}{Colors.BOLD}{'='*69}{Colors.ENDC}\n")
    
    print(f"{Colors.FAIL}╔{'═'*78}╗{Colors.ENDC}")
    print(f"{Colors.FAIL}║{Colors.ENDC} {Colors.BOLD}Attacker IP:{Colors.ENDC} {Colors.RED_BG}{Colors.BOLD} {ip} {Colors.ENDC}")
    print(f"{Colors.FAIL}║{Colors.ENDC} {Colors.BOLD}Threat Level:{Colors.ENDC} {Colors.FAIL}{Colors.BOLD}CRITICAL - COORDINATED ATTACK{Colors.ENDC}")
    print(f"{Colors.FAIL}║{Colors.ENDC}")
    print(f"{Colors.FAIL}║{Colors.ENDC} {Colors.BOLD}{Colors.UNDERLINE}Attack Timeline:{Colors.ENDC}")
    
    for i, event in enumerate(sorted(events, key=lambda e: e.timestamp), 1):
        timestamp = datetime.fromtimestamp(event.timestamp).strftime('%H:%M:%S')
        print(f"{Colors.FAIL}║{Colors.ENDC}   {Colors.WARNING}{i}.{Colors.ENDC} [{Colors.OKCYAN}{timestamp}{Colors.ENDC}] {Colors.HEADER}{event.event_type}{Colors.ENDC} - {event.details}")
    
    print(f"{Colors.FAIL}║{Colors.ENDC}")
    print(f"{Colors.FAIL}║{Colors.ENDC} {Colors.BOLD}{Colors.UNDERLINE}Recommended Actions:{Colors.ENDC}")
    print(f"{Colors.FAIL}║{Colors.ENDC}   {Colors.WARNING}1.{Colors.ENDC} IP has been automatically blocked")
    print(f"{Colors.FAIL}║{Colors.ENDC}   {Colors.WARNING}2.{Colors.ENDC} Review logs for lateral movement attempts")
    print(f"{Colors.FAIL}║{Colors.ENDC}   {Colors.WARNING}3.{Colors.ENDC} Escalate to security operations center (SOC)")
    print(f"{Colors.FAIL}╚{'═'*78}╝{Colors.ENDC}\n")
    print(f"{Colors.RED_BG}{Colors.BOLD}{'='*80}{Colors.ENDC}\n\n")
INTERFACE = "lo"
USE_ML = True
ML_ONLY = False
MODEL_PATH = "/mnt/c/Users/smayan/Desktop/automated-threat-hunting-framework/hgb_model.joblib"
LOG_FILE = "log.csv"
VERBOSE = True

MONITOR_WINDOW = 5
BLOCK_DURATION = 5  # Increased to allow time for multi-stage attack detection before iptables blocking
THRESHOLD_ICMP = 50
THRESHOLD_PORTSCAN = 20

FLOW_TIMEOUT = 600  # flows inactive for 10 minutes are expired

# IP Whitelist - Safe IPs that should never be blocked (e.g., DNS servers, cloud providers)
# Important for preventing false positives when attacks are spoofed
# NOTE: Localhost excluded to allow local network security testing
IP_WHITELIST = {
    # Google Public DNS
    "8.8.8.8",
    "8.8.4.4",
    # Cloudflare DNS
    "1.1.1.1",
    "1.0.0.1",
    # Quad9 DNS
    "9.9.9.9",
    "149.112.112.112",
    # OpenDNS
    "208.67.222.222",
    "208.67.220.220",
    # Common cloud provider DNS (AWS Route53)
    "169.254.169.254",  # AWS metadata service
    # Microsoft DNS
    "4.2.2.1",
    "4.2.2.2",
}


# Whitelist verification tracking
whitelist_ttl_values = defaultdict(list)  # Track TTL values for consistency checking
whitelist_packet_counts = defaultdict(int)  # Rate limiting for whitelisted IPs
whitelist_last_reset = defaultdict(float)  # Track when to reset counters
whitelist_spoof_detected = {}  # Track detected spoofed IPs and last alert time
WHITELIST_RATE_LIMIT = 1000  # Max packets per minute from whitelisted IPs
WHITELIST_TTL_VARIANCE_THRESHOLD = 5  # Max TTL variance for legitimate traffic
WHITELIST_MIN_PACKETS_FOR_VERIFICATION = 5  # Minimum packets needed before trusting whitelisted IP
WHITELIST_SPOOF_ALERT_COOLDOWN = 60  # Seconds between spoofing alerts for same IP

def is_whitelisted(ip):
    """Check if an IP address is in the whitelist"""
    return ip in IP_WHITELIST

def verify_whitelisted_ip(ip, pkt):
    """
    Verify if traffic from a whitelisted IP is genuine or spoofed.
    Returns True if traffic appears legitimate, False if suspicious.
    """
    if not is_whitelisted(ip):
        return True  # Not whitelisted, use normal blocking logic
    
    now = time.time()
    
    # Reset counters every minute
    if now - whitelist_last_reset.get(ip, 0) > 60:
        whitelist_packet_counts[ip] = 0
        whitelist_last_reset[ip] = now
        # Keep TTL history but limit size
        if len(whitelist_ttl_values[ip]) > 100:
            whitelist_ttl_values[ip] = whitelist_ttl_values[ip][-50:]
    
    # Rate limiting check - even legitimate services shouldn't flood (check first, works with any packet count)
    whitelist_packet_counts[ip] += 1
    if whitelist_packet_counts[ip] > WHITELIST_RATE_LIMIT:
        # Only log once when threshold is crossed
        if whitelist_packet_counts[ip] == WHITELIST_RATE_LIMIT + 1:
            print(f"[!] SUSPICIOUS: Whitelisted IP {ip} exceeded rate limit ({whitelist_packet_counts[ip]} packets/min) - possible spoofing")
        return False
    
    # Port-based heuristics for DNS servers (check early, works with single packet)
    if pkt.haslayer(scapy.UDP) or pkt.haslayer(scapy.TCP):
        dst_port = 0
        if pkt.haslayer(scapy.UDP):
            dst_port = pkt[scapy.UDP].dport
        elif pkt.haslayer(scapy.TCP):
            dst_port = pkt[scapy.TCP].dport
        
        # DNS servers typically only send traffic to port 53 (DNS) or high ports (responses)
        # If whitelisted DNS IP is sending to non-DNS ports, it's suspicious
        if ip in ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112", 
                  "208.67.222.222", "208.67.220.220", "4.2.2.1", "4.2.2.2"]:
            if dst_port not in [53, 443, 80] and dst_port < 1024:
                # DNS servers shouldn't be connecting to random low ports
                if whitelist_packet_counts[ip] > 10:  # Allow some variance
                    # Only log once when first detected
                    if whitelist_packet_counts[ip] == 11:
                        print(f"[!] SUSPICIOUS: Whitelisted DNS IP {ip} connecting to non-standard port {dst_port} - possible spoofing")
                    return False
    
    # TTL consistency check - legitimate traffic has consistent TTL values
    if pkt.haslayer(scapy.IP):
        ttl = pkt[scapy.IP].ttl
        whitelist_ttl_values[ip].append(ttl)
        
        # Check TTL variance (spoofed packets often have inconsistent TTLs)
        packet_count = len(whitelist_ttl_values[ip])
        
        # Need minimum packets for reliable verification
        if packet_count < WHITELIST_MIN_PACKETS_FOR_VERIFICATION:
            return True  # Not enough data, assume legitimate (block_ip() will handle this)
        
        if packet_count >= 10:
            ttl_history = whitelist_ttl_values[ip][-20:]  # Last 20 packets
            ttl_mean = np.mean(ttl_history)
            ttl_std = np.std(ttl_history)
            
            # High variance suggests spoofing
            if ttl_std > WHITELIST_TTL_VARIANCE_THRESHOLD:
                # Only log once when first detected (at packet 10)
                if packet_count == 10:
                    print(f"[!] SUSPICIOUS: Whitelisted IP {ip} has high TTL variance (std={ttl_std:.2f}) - possible spoofing")
                return False
        elif packet_count >= WHITELIST_MIN_PACKETS_FOR_VERIFICATION:
            # Have minimum packets, check basic consistency
            ttl_history = whitelist_ttl_values[ip]
            unique_ttls = len(set(ttl_history))
            ttl_std = np.std(ttl_history)
            
            # Check for suspicious patterns
            if unique_ttls > 3:  # More than 3 different TTL values is suspicious
                if ttl_std > WHITELIST_TTL_VARIANCE_THRESHOLD:
                    # Only log once when first detected (at minimum packet count)
                    if packet_count == WHITELIST_MIN_PACKETS_FOR_VERIFICATION:
                        print(f"[!] SUSPICIOUS: Whitelisted IP {ip} has high TTL variance (std={ttl_std:.2f}) - possible spoofing")
                    return False
            
            # Additional check: If TTL has ANY variance with few packets, be suspicious
            if packet_count <= 7 and unique_ttls >= 2 and ttl_std > 2:
                if packet_count == WHITELIST_MIN_PACKETS_FOR_VERIFICATION:
                    print(f"[!] SUSPICIOUS: Whitelisted IP {ip} has early TTL variance (std={ttl_std:.2f}, unique={unique_ttls}) - possible spoofing")
                return False
    
    # Passed all checks, appears legitimate
    return True

def add_to_whitelist(ip):
    """Add an IP to the whitelist"""
    IP_WHITELIST.add(ip)
    print(f"[*] Added {ip} to whitelist")

def remove_from_whitelist(ip):
    """Remove an IP from the whitelist"""
    if ip in IP_WHITELIST:
        IP_WHITELIST.remove(ip)
        print(f"[*] Removed {ip} from whitelist")
        return True
    return False

blocked_ips = {}
icmp_counter = defaultdict(int)
portscan_tracker = defaultdict(set)

ml_model = joblib.load(MODEL_PATH) if USE_ML else None

# Attack Chain Reconstruction
class AttackEvent:
    def __init__(self, ip, event_type, timestamp, details):
        self.ip = ip
        self.event_type = event_type
        self.timestamp = timestamp
        self.details = details

attack_events = defaultdict(list)
ATTACK_CHAIN_WINDOW = 300  # 5 minutes to correlate events
CHAIN_ALERT_COOLDOWN = defaultdict(float)


# Flow tracking for ML
class Flow:
    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol):
        self.flow_id = str(uuid.uuid4())
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.ml_label = "benign"
        self.ml_alerted = False  # Track if we've already alerted for this flow
        
        self.start_time = time.time()
        self.last_seen = time.time()
        
        self.fwd_packets = []
        self.bwd_packets = []
        
        self.fwd_header_lengths = []
        self.bwd_header_lengths = []
        
        self.init_win_bytes = None
        
    def add_packet(self, pkt, direction='fwd'):
        self.last_seen = time.time()
        pkt_len = len(pkt)
        
        if direction == 'fwd':
            self.fwd_packets.append((time.time(), pkt_len))
            if scapy.IP in pkt:
                self.fwd_header_lengths.append(pkt[scapy.IP].ihl * 4)
            if self.init_win_bytes is None and scapy.TCP in pkt and pkt[scapy.TCP].flags & 0x02:
                self.init_win_bytes = pkt[scapy.TCP].window
        else:
            self.bwd_packets.append((time.time(), pkt_len))
            if scapy.IP in pkt:
                self.bwd_header_lengths.append(pkt[scapy.IP].ihl * 4)
    
    def calculate_features(self):
        features = {}
        
        # Flow duration
        duration = (self.last_seen - self.start_time) * 1000000  # microseconds
        features['Flow Duration'] = duration if duration > 0 else 1
        
        # Fwd packet lengths
        fwd_lengths = [pkt[1] for pkt in self.fwd_packets]
        features['Fwd Packets Length Total'] = sum(fwd_lengths) if fwd_lengths else 0
        features['Fwd Packet Length Max'] = max(fwd_lengths) if fwd_lengths else 0
        features['Fwd Packet Length Mean'] = np.mean(fwd_lengths) if fwd_lengths else 0
        features['Avg Fwd Segment Size'] = np.mean(fwd_lengths) if fwd_lengths else 0
        features['Fwd Seg Size Min'] = min(fwd_lengths) if fwd_lengths else 0
        
        # Bwd packet lengths
        bwd_lengths = [pkt[1] for pkt in self.bwd_packets]
        features['Bwd Packet Length Mean'] = np.mean(bwd_lengths) if bwd_lengths else 0
        features['Bwd Packet Length Std'] = np.std(bwd_lengths) if bwd_lengths else 0
        features['Avg Bwd Segment Size'] = np.mean(bwd_lengths) if bwd_lengths else 0
        
        # Header lengths
        features['Fwd Header Length'] = sum(self.fwd_header_lengths) if self.fwd_header_lengths else 0
        
        # Subflow
        features['Subflow Fwd Bytes'] = sum(fwd_lengths) if fwd_lengths else 0
        
        # TCP window
        features['Init Fwd Win Bytes'] = self.init_win_bytes if self.init_win_bytes else 0
        
        # Packets/s
        duration_sec = (self.last_seen - self.start_time)
        if duration_sec > 0:
            features['Flow Packets/s'] = (len(self.fwd_packets) + len(self.bwd_packets)) / duration_sec
            features['Fwd Packets/s'] = len(self.fwd_packets) / duration_sec
        else:
            features['Flow Packets/s'] = 0
            features['Fwd Packets/s'] = 0
        
        # IAT (Inter-Arrival Time) calculations
        fwd_iats = [self.fwd_packets[i][0] - self.fwd_packets[i-1][0] 
                    for i in range(1, len(self.fwd_packets))] if len(self.fwd_packets) > 1 else [0]
        
        all_packets = sorted(self.fwd_packets + self.bwd_packets, key=lambda x: x[0])
        flow_iats = [all_packets[i][0] - all_packets[i-1][0] 
                     for i in range(1, len(all_packets))] if len(all_packets) > 1 else [0]
        
        features['Fwd IAT Total'] = sum(fwd_iats) * 1000000 if fwd_iats else 0
        features['Fwd IAT Min'] = min(fwd_iats) * 1000000 if fwd_iats else 0
        features['Fwd IAT Max'] = max(fwd_iats) * 1000000 if fwd_iats else 0
        
        features['Flow IAT Mean'] = np.mean(flow_iats) * 1000000 if flow_iats else 0
        features['Flow IAT Min'] = min(flow_iats) * 1000000 if flow_iats else 0
        features['Flow IAT Max'] = max(flow_iats) * 1000000 if flow_iats else 0
        
        return features

    def to_dict(self):
        return {
            "flow_id": self.flow_id,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "ml_label": self.ml_label,
            "features": self.calculate_features()
        }


flows = {}

def get_flow_key(src_ip, dst_ip, src_port, dst_port, protocol):
    return (src_ip, dst_ip, src_port, dst_port, protocol)

def get_or_create_flow(pkt):
    if not pkt.haslayer(scapy.IP):
        return None
    
    src_ip = pkt[scapy.IP].src
    dst_ip = pkt[scapy.IP].dst
    src_port = dst_port = 0
    protocol = pkt[scapy.IP].proto
    
    if scapy.TCP in pkt:
        src_port = pkt[scapy.TCP].sport
        dst_port = pkt[scapy.TCP].dport
    elif scapy.UDP in pkt:
        src_port = pkt[scapy.UDP].sport
        dst_port = pkt[scapy.UDP].dport
    
    fwd_key = get_flow_key(src_ip, dst_ip, src_port, dst_port, protocol)
    bwd_key = get_flow_key(dst_ip, src_ip, dst_port, src_port, protocol)
    
    if fwd_key in flows:
        flows[fwd_key].add_packet(pkt, 'fwd')
        return flows[fwd_key]
    elif bwd_key in flows:
        flows[bwd_key].add_packet(pkt, 'bwd')
        return flows[bwd_key]
    else:
        flows[fwd_key] = Flow(src_ip, dst_ip, src_port, dst_port, protocol)
        flows[fwd_key].add_packet(pkt, 'fwd')
        return flows[fwd_key]


def log_packet(src_ip, dest_ip, features, label="benign"):
    with open(LOG_FILE, "a", newline="") as f:
        row = [datetime.now().isoformat(), src_ip, dest_ip] + features + [label]
        csv.writer(f).writerow(row)


def record_attack_event(ip, event_type, details):
    """Track attack events for chain reconstruction"""
    now = time.time()
    event = AttackEvent(ip, event_type, now, details)
    attack_events[ip].append(event)
    
    # Clean old events outside correlation window
    attack_events[ip] = [e for e in attack_events[ip] if now - e.timestamp < ATTACK_CHAIN_WINDOW]
    
    # Check for attack chains
    detect_attack_chain(ip)

def detect_attack_chain(ip):
    """Detect multi-stage attack patterns"""
    now = time.time()
    
    # Cooldown to avoid spam
    if now - CHAIN_ALERT_COOLDOWN[ip] < 60:
        return
    
    events = attack_events[ip]
    if len(events) < 2:
        return
    
    # Classify events by phase
    phases = {
        'reconnaissance': [e for e in events if e.event_type == 'PORT_SCAN'],
        'dos': [e for e in events if e.event_type in ['SYN_FLOOD', 'ICMP_FLOOD', 'DoS attacks-GoldenEye', 'DoS attacks-Hulk', 'DoS attacks-SlowHTTPTest', 'DoS attacks-Slowloris', 'DDoS', 'DDOS attack-HOIC', 'DDOS attack-LOIC-HTTP', 'DDOS attack-LOIC-UDP']],
        'brute_force': [e for e in events if e.event_type in ['Brute Force', 'SSH-Bruteforce', 'FTP-BruteForce']],
        'web_attacks': [e for e in events if e.event_type in ['SQL Injection', 'XSS', 'Web Attack']],
        'infiltration': [e for e in events if e.event_type in ['Infiltration', 'Infilteration', 'Bot']]
    }
    
    # Build narrative
    active_phases = [phase for phase, evts in phases.items() if evts]
    
    if len(active_phases) >= 2:
        log_attack_chain_epic(ip, events)
        narrative = generate_attack_narrative(ip, phases, events)
        print(f"\n{'='*60}")
        print(f"[!!! ATTACK CHAIN DETECTED !!!]")
        print(narrative)
        print(f"{'='*60}\n")
        
        # Send chain to API
        chain_data = {
            "attacker_ip": ip,
            "chain_details": narrative,
            "timestamp": datetime.now().isoformat()
        }
        api_client.send_chain(chain_data)
        
        CHAIN_ALERT_COOLDOWN[ip] = now

def generate_attack_narrative(ip, phases, events):
    """Generate human-readable attack chain narrative"""
    lines = [f"Multi-stage attack from {ip}:"]
    
    # Sort events by timestamp
    sorted_events = sorted(events, key=lambda e: e.timestamp)
    
    for i, event in enumerate(sorted_events, 1):
        timestamp = datetime.fromtimestamp(event.timestamp).strftime('%H:%M:%S')
        
        # Determine phase label based on attack type
        if event.event_type == 'PORT_SCAN':
            phase_label = 'Reconnaissance'
        elif event.event_type in ['SYN_FLOOD', 'ICMP_FLOOD', 'DoS attacks-GoldenEye', 'DoS attacks-Hulk', 'DoS attacks-SlowHTTPTest', 'DoS attacks-Slowloris', 'DDoS', 'DDOS attack-HOIC', 'DDOS attack-LOIC-HTTP', 'DDOS attack-LOIC-UDP']:
            phase_label = 'DoS/DDoS Attack'
        elif event.event_type in ['Brute Force', 'SSH-Bruteforce', 'FTP-BruteForce']:
            phase_label = 'Credential Attack'
        elif event.event_type in ['SQL Injection', 'XSS', 'Web Attack']:
            phase_label = 'Web Application Attack'
        elif event.event_type in ['Infiltration', 'Infilteration', 'Bot']:
            phase_label = 'Lateral Movement/C2'
        else:
            phase_label = 'Unknown Threat'
        
        lines.append(f"{i}. [{timestamp}] {phase_label}: {event.event_type} ({event.details})")
        
    return "\n".join(lines)


def extract_features(pkt):
    src_port = dst_port = 0
    proto = pkt[scapy.IP].proto
    flags = 0
    
    if scapy.TCP in pkt:
        src_port = pkt[scapy.TCP].sport
        dst_port = pkt[scapy.TCP].dport
        flags = pkt[scapy.TCP].flags
    elif scapy.UDP in pkt:
        src_port = pkt[scapy.UDP].sport
        dst_port = pkt[scapy.UDP].dport
        
    return [src_port, dst_port, proto, flags]


class APIClient:
    def __init__(self, base_url="http://localhost:8000"):
        self.base_url = base_url
        self.queue = queue.Queue()
        self.running = True
        self.worker_thread = Thread(target=self._worker, daemon=True)
        self.worker_thread.start()

    def _worker(self):
        while self.running:
            try:
                task = self.queue.get(timeout=1)
                endpoint, data = task
                try:
                    requests.post(f"{self.base_url}{endpoint}", json=data, timeout=2)
                except Exception as e:
                    # print(f"[!] API Error ({endpoint}): {e}")
                    pass
                self.queue.task_done()
            except queue.Empty:
                continue

    def send_packet(self, pkt_data):
        self.queue.put(("/api/packets", pkt_data))

    def send_alert(self, alert_data):
        self.queue.put(("/api/alerts", alert_data))

    def send_block(self, block_data):
        self.queue.put(("/api/block", block_data))
        
    def send_unblock(self, unblock_data):
        self.queue.put(("/api/unblock", unblock_data))

    def send_flow(self, flow_data):
        self.queue.put(("/api/flows", flow_data))

    def send_chain(self, chain_data):
        self.queue.put(("/api/chain", chain_data))

api_client = APIClient()


def block_ip(ip, reason, details, pkt=None):
    # Check if IP is whitelisted - verify if traffic is genuine or spoofed
    if is_whitelisted(ip):
        # Check if we have enough data to make a decision
        ttl_count = len(whitelist_ttl_values.get(ip, []))
        packet_count = whitelist_packet_counts.get(ip, 0)
        
        # If spoofing was already detected (alert was shown), proceed with blocking
        # even if we don't have full verification data yet
        already_flagged_as_spoofed = ip in whitelist_spoof_detected
        
        # If we don't have minimum packets and haven't flagged as spoofed, skip blocking for safety
        if ttl_count < WHITELIST_MIN_PACKETS_FOR_VERIFICATION and not already_flagged_as_spoofed:
            # Not enough data to determine if legitimate or spoofed
            print(f"[*] Whitelisted IP {ip} attack detected but insufficient verification data - monitoring")
            return
        
        # If already flagged as spoofed, continue to blocking
        if already_flagged_as_spoofed:
            print(f"[!] SPOOFED ATTACK CONFIRMED: Whitelisted IP {ip} - BLOCKING despite whitelist")
            # Skip further verification, proceed directly to blocking
        elif pkt is not None:
            # Verify if traffic from whitelisted IP is legitimate
            if verify_whitelisted_ip(ip, pkt):
                print(f"[*] Skipping block for whitelisted IP: {ip} | Reason: {reason} (verified legitimate)")
                return
            else:
                print(f"[!] SPOOFED ATTACK DETECTED: Whitelisted IP {ip} failed verification - BLOCKING despite whitelist")
                # Continue to block - spoofed attack detected
        else:
            # No packet available - check stored verification data
            # Check rate limit using stored data
            if packet_count > WHITELIST_RATE_LIMIT:
                print(f"[!] SPOOFED ATTACK DETECTED: Whitelisted IP {ip} exceeded rate limit ({packet_count} packets/min) - BLOCKING")
                # Continue to block
            elif ttl_count >= 10:
                # Full check with enough data
                ttl_history = whitelist_ttl_values[ip]
                ttl_std = np.std(ttl_history[-20:])
                if ttl_std > WHITELIST_TTL_VARIANCE_THRESHOLD:
                    print(f"[!] SPOOFED ATTACK DETECTED: Whitelisted IP {ip} has high TTL variance (std={ttl_std:.2f}) - BLOCKING")
                    # Continue to block
                else:
                    print(f"[*] Skipping block for whitelisted IP: {ip} | Reason: {reason} (verified legitimate via stored data)")
                    return
            elif ttl_count >= WHITELIST_MIN_PACKETS_FOR_VERIFICATION:
                # Have minimum packets, check basic consistency
                ttl_history = whitelist_ttl_values[ip]
                unique_ttls = len(set(ttl_history))
                ttl_std = np.std(ttl_history)
                
                # Check for any suspicious patterns
                if unique_ttls > 3:  # More than 3 different TTL values is suspicious
                    if ttl_std > WHITELIST_TTL_VARIANCE_THRESHOLD:
                        print(f"[!] SPOOFED ATTACK DETECTED: Whitelisted IP {ip} has high TTL variance (std={ttl_std:.2f}) - BLOCKING")
                        # Continue to block
                    else:
                        print(f"[*] Skipping block for whitelisted IP: {ip} | Reason: {reason} (verified legitimate via stored data)")
                        return
                elif ttl_count <= 7 and unique_ttls >= 2 and ttl_std > 2:
                    # Early TTL variance detected
                    print(f"[!] SPOOFED ATTACK DETECTED: Whitelisted IP {ip} has early TTL variance (std={ttl_std:.2f}) - BLOCKING")
                    # Continue to block
                else:
                    # Low variance, appears legitimate
                    print(f"[*] Skipping block for whitelisted IP: {ip} | Reason: {reason} (verified legitimate via stored data)")
                    return
            else:
                # Not enough data for verification - skip blocking
                print(f"[*] Skipping block for whitelisted IP: {ip} | Reason: {reason} (insufficient verification data)")
                return
    
    # Always record attack events for chain detection, even if already blocked
    record_attack_event(ip, reason, details)
    
    if ip in blocked_ips:
        # IP already blocked, just update the event chain
        return
        
    print(f"[!] BLOCKING {ip} | Reason: {reason} | {details}")
    print(f"[*] IP marked for blocking (iptables rule will be applied in 20s to allow multi-stage detection)")
    blocked_ips[ip] = time.time()
    
    # Log OWASP mapping for the actual attack type
    log_owasp_mapping(reason, ip)
    
    # Delay iptables blocking to allow multi-stage attack detection
    # This gives time for subsequent attack phases to be detected before packets are dropped
    IPTABLES_BLOCK_DELAY = 20  # Seconds to wait before applying firewall block
    def delayed_iptables_block():
        time.sleep(IPTABLES_BLOCK_DELAY)
        if ip in blocked_ips:  # Only block if still in blocked list
            try:
                subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=False)
                print(f"[*] Applied iptables block for {ip} (after {IPTABLES_BLOCK_DELAY}s grace period)")
            except FileNotFoundError:
                pass # Not on Linux/WSL or iptables missing
    
    # Start delayed blocking in background thread
    Thread(target=delayed_iptables_block, daemon=True).start()
    
    # Send block and alert to API
    api_client.send_block({"ip": ip, "reason": reason, "timestamp": datetime.now().isoformat()})
    api_client.send_alert({
        "type": reason,
        "attacker_ip": ip,
        "details": details,
        "timestamp": datetime.now().isoformat(),
        "blocked": True
    })

def unblock_expired_ips():
    now = time.time()
    for ip in list(blocked_ips.keys()):
        if now - blocked_ips[ip] > BLOCK_DURATION:
            print(f"[*] Unblocking {ip}")
            del blocked_ips[ip]
            try:
                subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=False)
            except FileNotFoundError:
                pass
            
            # Send unblock to API
            api_client.send_unblock({"ip": ip})

# Threat intelligence feed configuration
TI_FEED_PATH = "/tmp/threat_hunter_ti_feed.signal"

KNOWN_ATTACK_SIGNATURES = {
    "ICMP_FLOOD": "ICMP_FLOOD",
    "PORT_SCAN": "PORT_SCAN",
    "SSH-Bruteforce": "SSH-Bruteforce",
    "FTP-BruteForce": "FTP-BruteForce",
    "DoS attacks-GoldenEye": "DoS attacks-GoldenEye",
    "DoS attacks-Hulk": "DoS attacks-Hulk",
    "DoS attacks-Slowloris": "DoS attacks-Slowloris",
    "DoS attacks-SlowHTTPTest": "DoS attacks-SlowHTTPTest",
    "DDOS attack-HOIC": "DDOS attack-HOIC",
    "DDOS attack-LOIC-HTTP": "DDOS attack-LOIC-HTTP",
    "Bot": "Bot",
    "Infiltration": "Infiltration",
    "Infilteration": "Infilteration",
    "Brute Force": "Brute Force",
}

_ti_last_check = 0
_ti_processed = set()

def check_ti_feed():
    """Process threat intelligence feed"""
    global _ti_last_check, _ti_processed
    
    now = time.time()
    if now - _ti_last_check < 0.5:
        return None
    _ti_last_check = now
    
    try:
        if os.path.exists(TI_FEED_PATH):
            with open(TI_FEED_PATH, 'r') as f:
                content = f.read().strip()
            
            parts = content.split('|')
            if len(parts) >= 2:
                attack_type = parts[0]
                source_ip = parts[1]
                signal_time = float(parts[2]) if len(parts) > 2 else now
                
                signal_key = f"{attack_type}_{signal_time}"
                if now - signal_time < 10 and signal_key not in _ti_processed:
                    _ti_processed.add(signal_key)
                    _ti_processed = {k for k in _ti_processed 
                                    if now - float(k.split('_')[-1]) < 30}
                    return (attack_type, source_ip)
    except Exception:
        pass
    
    return None

def process_threat_intel(attack_type, source_ip):
    """Process correlated threat intelligence"""
    print(f"\n[ML DETECTED] {attack_type} from {source_ip}")
    block_ip(source_ip, attack_type, "ML_DETECTION", pkt=None)

def packet_handler(pkt):
    global USE_ML
    if not pkt.haslayer(scapy.IP):
        return
    
    # IMPORTANT: Skip backend API traffic (port 8000) to avoid detecting our own traffic
    if pkt.haslayer(scapy.TCP):
        if pkt[scapy.TCP].sport == 8000 or pkt[scapy.TCP].dport == 8000:
            return
    
    src, dst = pkt[scapy.IP].src, pkt[scapy.IP].dst
    features = extract_features(pkt)
    label = "benign"
    
    
    # Verify whitelisted IPs for spoofing detection
    if is_whitelisted(src):
        verification_result = verify_whitelisted_ip(src, pkt)
        if not verification_result:
            # Spoofed attack detected from whitelisted IP - treat as malicious
            now = time.time()
            # Mark as spoofed immediately (for block_ip to check)
            if src not in whitelist_spoof_detected:
                whitelist_spoof_detected[src] = now
                # Show formatted alert matching OWASP/MITRE telemetry style exactly
                print(f"\n{Colors.RED_BG}{Colors.BOLD} ⚠️  SPOOFING DETECTION ALERT ⚠️  {Colors.ENDC}")
                print(f"{Colors.FAIL}╔{'═'*78}╗{Colors.ENDC}")
                print(f"{Colors.FAIL}║{Colors.ENDC} {Colors.BOLD}Detection Type:{Colors.ENDC} {Colors.WARNING}Anti-Spoofing Verification Failure{Colors.ENDC}")
                print(f"{Colors.FAIL}║{Colors.ENDC} {Colors.BOLD}Source IP:{Colors.ENDC} {Colors.OKCYAN}{src}{Colors.ENDC} {Colors.FAIL}(Whitelisted){Colors.ENDC}")
                print(f"{Colors.FAIL}║{Colors.ENDC}")
                print(f"{Colors.FAIL}║{Colors.ENDC} {Colors.BOLD}{Colors.UNDERLINE}Verification Status:{Colors.ENDC}")
                print(f"{Colors.FAIL}║{Colors.ENDC}   {Colors.HEADER}Status:{Colors.ENDC} {Colors.FAIL}{Colors.BOLD}SPOOFED{Colors.ENDC}")
                print(f"{Colors.FAIL}║{Colors.ENDC}   {Colors.HEADER}Reason:{Colors.ENDC} {Colors.WARNING}Traffic does not match legitimate patterns{Colors.ENDC}")
                print(f"{Colors.FAIL}║{Colors.ENDC}   {Colors.HEADER}Action:{Colors.ENDC} {Colors.OKBLUE}Treating as malicious, will block when attack detected{Colors.ENDC}")
                print(f"{Colors.FAIL}╚{'═'*78}╝{Colors.ENDC}\n")
            else:
                # Update timestamp to extend tracking
                whitelist_spoof_detected[src] = now

    # Rule-based detection (always active unless ML_ONLY)
    if not ML_ONLY:
        if pkt.haslayer(scapy.TCP):
            portscan_tracker[src].add(pkt[scapy.TCP].dport)
        if pkt.haslayer(scapy.ICMP) and pkt[scapy.ICMP].type == 8:
            icmp_counter[src] += 1

    # ML-based detection (if enabled)
    if USE_ML and ml_model:
        flow = get_or_create_flow(pkt)
        if flow:
            # Update flow label if it was previously unknown
            if label != "benign":
                flow.ml_label = label
            
            if (len(flow.fwd_packets) + len(flow.bwd_packets)) >= 10:  # Wait for 10 packets
                flow_features = flow.calculate_features()
                
                # Order features as model expects
                feature_order = [
                    'Init Fwd Win Bytes', 'Fwd Header Length', 'Fwd Seg Size Min',
                    'Fwd Packets Length Total', 'Fwd Packet Length Max', 'Subflow Fwd Bytes',
                    'Fwd Packet Length Mean', 'Bwd Packet Length Mean', 'Fwd IAT Total',
                    'Fwd Packets/s', 'Flow IAT Mean', 'Bwd Packet Length Std',
                    'Flow IAT Min', 'Fwd IAT Min', 'Flow Packets/s', 'Flow IAT Max',
                    'Flow Duration', 'Avg Fwd Segment Size', 'Fwd IAT Max', 'Avg Bwd Segment Size'
                ]
                
                feature_vector = [flow_features.get(f, 0) for f in feature_order]
                
                try:
                    prediction = ml_model.predict([feature_vector])[0]
                    
                    if prediction != "Benign" and not flow.ml_alerted:
                        label = prediction
                        flow.ml_label = label
                        flow.ml_alerted = True  # Mark as alerted to avoid spam
                        
                        # Check if whitelisted IP and if spoofing is detected
                        if is_whitelisted(src):
                            # Check if previously flagged as spoofed OR currently failing verification
                            already_flagged = src in whitelist_spoof_detected
                            currently_suspicious = not verify_whitelisted_ip(src, pkt)
                            is_spoofed = already_flagged or currently_suspicious
                            
                            if is_spoofed:
                                print(f"[ML DETECTED] {label} from {src} (whitelisted but SPOOFED - blocking)")
                            else:
                                print(f"[ML DETECTED] {label} from {src} (whitelisted - verifying...)")
                        else:
                            print(f"[ML DETECTED] {label} from {src}")
                        
                        block_ip(src, label, f"ML_DETECTION", pkt=pkt)
                except Exception as e:
                    print(f"[!] ML Model Error (disabling ML): {e}")
                    USE_ML = False
            
            # Send flow update to API
            api_client.send_flow(flow.to_dict())

    # if VERBOSE:
    #     print(f"[+] Packet: {src} -> {dst} | Proto: {features[2]} | Flags: {features[3]} | Label: {label}")

    log_packet(src, dst, features, label)
    
    # Send packet to API
    pkt_data = {
        "timestamp": datetime.now().isoformat(),
        "src_ip": src,
        "dst_ip": dst,
        "protocol": "TCP" if pkt.haslayer(scapy.TCP) else "UDP" if pkt.haslayer(scapy.UDP) else "ICMP" if pkt.haslayer(scapy.ICMP) else "Other",
        "src_port": features[0],
        "dst_port": features[1],
        "flags": str(features[3]),
        "length": len(pkt),
        "label": label
    }
    api_client.send_packet(pkt_data)

def monitor():
    while True:
        time.sleep(1)
        
        # Process threat intelligence feeds
        ti_result = check_ti_feed()
        if ti_result:
            attack_type, source_ip = ti_result
            process_threat_intel(attack_type, source_ip)
        
        # Clean up old flows (every 5 iterations)
        now = time.time()
        expired_flows = [k for k, v in flows.items() if now - v.last_seen > FLOW_TIMEOUT]
        for k in expired_flows:
            del flows[k]
        
        # Rule-based monitoring
        if not ML_ONLY:
            for ip, count in list(icmp_counter.items()):
                if count > THRESHOLD_ICMP:
                    # For whitelisted IPs, check if already flagged as spoofed
                    if is_whitelisted(ip):
                        # If already flagged as spoofed, block immediately
                        already_flagged = ip in whitelist_spoof_detected
                        if not already_flagged:
                            # Not flagged yet - require minimum packets for verification
                            ttl_count = len(whitelist_ttl_values.get(ip, []))
                            if ttl_count < WHITELIST_MIN_PACKETS_FOR_VERIFICATION:
                                # Not enough data yet - skip blocking, give more time for verification
                                continue
                    block_ip(ip, "ICMP_FLOOD", f"Packets={count}", pkt=None)
                icmp_counter[ip] = 0
            for ip, ports in list(portscan_tracker.items()):
                if len(ports) > THRESHOLD_PORTSCAN:
                    # For whitelisted IPs, check if already flagged as spoofed
                    if is_whitelisted(ip):
                        # If already flagged as spoofed, block immediately
                        already_flagged = ip in whitelist_spoof_detected
                        if not already_flagged:
                            # Not flagged yet - require minimum packets for verification
                            ttl_count = len(whitelist_ttl_values.get(ip, []))
                            if ttl_count < WHITELIST_MIN_PACKETS_FOR_VERIFICATION:
                                # Not enough data yet - skip blocking, give more time for verification
                                continue
                    block_ip(ip, "PORT_SCAN", f"Ports={len(ports)}", pkt=None)
                portscan_tracker[ip].clear()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Threat Hunter Scanner")
    parser.add_argument("--ml", action="store_true", help="Run in ML-ONLY mode (disables rule-based detection)")
    parser.add_argument("--whitelist-add", type=str, metavar="IP", help="Add an IP to the whitelist")
    parser.add_argument("--whitelist-remove", type=str, metavar="IP", help="Remove an IP from the whitelist")
    parser.add_argument("--whitelist-show", action="store_true", help="Show all whitelisted IPs and exit")
    args = parser.parse_args()
    
    # Handle whitelist management commands
    if args.whitelist_show:
        print("[*] Whitelisted IPs:")
        for ip in sorted(IP_WHITELIST):
            print(f"    {ip}")
        sys.exit(0)
    
    if args.whitelist_add:
        add_to_whitelist(args.whitelist_add)
        print(f"[*] Whitelist updated. Total whitelisted IPs: {len(IP_WHITELIST)}")
    
    if args.whitelist_remove:
        if remove_from_whitelist(args.whitelist_remove):
            print(f"[*] Whitelist updated. Total whitelisted IPs: {len(IP_WHITELIST)}")
        else:
            print(f"[!] IP {args.whitelist_remove} not found in whitelist")
    
    ML_ONLY = args.ml
    if ML_ONLY:
        USE_ML = True
        print("[*] Mode: ML-ONLY (Rule-based detection DISABLED)")
    
    print("[*] Scanner started...")
    print(f"[*] Monitoring interface: {INTERFACE}")
    print(f"[*] ML mode: {'ENABLED' if USE_ML else 'DISABLED'}")
    print(f"[*] Whitelisted IPs: {len(IP_WHITELIST)} safe IPs (DNS servers, cloud providers, etc.)")
    #print("[*] Ignoring backend API traffic on port 8000")
    Thread(target=monitor, daemon=True).start()
    sniffer = scapy.AsyncSniffer(iface=INTERFACE, prn=packet_handler, store=False)
    sniffer.start()
    try:
        while True:
            time.sleep(1)
            unblock_expired_ips()
    except KeyboardInterrupt:
        print("\n[!] Stopping...")
        sniffer.stop()

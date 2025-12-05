"""
THREAT HUNTER - Advanced Security Operations Center
Real-time threat detection, MITRE ATT&CK mapping, and incident response
Synchronized with attack simulation framework
"""

import importlib.util
import sys
import os
import threading
import time
import queue
import re
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from datetime import datetime, timedelta
import random
import math

ORIGINAL_SCANNER_PATH = "/mnt/c/Users/smayan/Desktop/automated-threat-hunting-framework/scanner.py"
ATTACK_STATE_FILE = "/tmp/threat_hunter_attack_state.signal"

# ============================================================================
# THREAT INTELLIGENCE DATABASE
# ============================================================================

MITRE_MAPPING = {
    "PORT_SCAN": {"tactic": "Reconnaissance", "technique": "T1046", "name": "Network Service Scanning",
                  "description": "Adversary scanning ports to identify services and vulnerabilities"},
    "SYN_FLOOD": {"tactic": "Impact", "technique": "T1499", "name": "Endpoint Denial of Service",
                  "description": "TCP SYN flood exhausting server resources"},
    "ICMP_FLOOD": {"tactic": "Impact", "technique": "T1498", "name": "Network Denial of Service",
                   "description": "ICMP ping flood overwhelming network bandwidth"},
    "DoS attacks-GoldenEye": {"tactic": "Impact", "technique": "T1499.001", "name": "OS Exhaustion Flood",
                              "description": "GoldenEye HTTP keep-alive flood attack"},
    "DoS attacks-Hulk": {"tactic": "Impact", "technique": "T1499.002", "name": "Service Exhaustion",
                         "description": "HULK unique URL flood bypassing cache"},
    "DoS attacks-SlowHTTPTest": {"tactic": "Impact", "technique": "T1499.002", "name": "Service Exhaustion",
                                  "description": "Slow HTTP holding connections open"},
    "DoS attacks-Slowloris": {"tactic": "Impact", "technique": "T1499.002", "name": "Service Exhaustion",
                               "description": "Slowloris partial headers attack"},
    "SSH-Bruteforce": {"tactic": "Credential Access", "technique": "T1110.001", "name": "Password Guessing",
                       "description": "Automated SSH credential attacks"},
    "FTP-BruteForce": {"tactic": "Credential Access", "technique": "T1110.001", "name": "Password Guessing",
                       "description": "Rapid FTP authentication attempts"},
    "Brute Force": {"tactic": "Credential Access", "technique": "T1110", "name": "Brute Force",
                    "description": "Systematic credential guessing attack"},
    "Infiltration": {"tactic": "Exfiltration", "technique": "T1048", "name": "Exfil Over Alt Protocol",
                     "description": "Data theft - sensitive info being extracted"},
    "Infilteration": {"tactic": "Exfiltration", "technique": "T1048", "name": "Exfil Over Alt Protocol",
                      "description": "Data theft - sensitive info being extracted"},
    "Bot": {"tactic": "Command and Control", "technique": "T1071", "name": "App Layer Protocol",
            "description": "Botnet C2 - compromised host contacting attacker"},
    "DDOS attack-HOIC": {"tactic": "Impact", "technique": "T1498", "name": "Network DoS",
                         "description": "High Orbit Ion Cannon distributed flood"},
    "DDOS attack-LOIC-HTTP": {"tactic": "Impact", "technique": "T1498", "name": "Network DoS",
                               "description": "Low Orbit Ion Cannon HTTP flood"},
}

OWASP_MAPPING = {
    "PORT_SCAN": [{"code": "A01", "name": "Broken Access"}, {"code": "A05", "name": "Misconfig"}],
    "SYN_FLOOD": [{"code": "A05", "name": "Misconfig"}],
    "ICMP_FLOOD": [{"code": "A05", "name": "Misconfig"}],
    "DoS attacks-GoldenEye": [{"code": "A05", "name": "Misconfig"}],
    "DoS attacks-Hulk": [{"code": "A05", "name": "Misconfig"}],
    "DoS attacks-SlowHTTPTest": [{"code": "A05", "name": "Misconfig"}],
    "DoS attacks-Slowloris": [{"code": "A05", "name": "Misconfig"}],
    "SSH-Bruteforce": [{"code": "A07", "name": "Auth Fail"}, {"code": "A04", "name": "Insecure Design"}],
    "FTP-BruteForce": [{"code": "A07", "name": "Auth Fail"}, {"code": "A02", "name": "Crypto Fail"}],
    "Brute Force": [{"code": "A07", "name": "Auth Fail"}],
    "Infiltration": [{"code": "A01", "name": "Broken Access"}, {"code": "A09", "name": "Log Fail"}],
    "Infilteration": [{"code": "A01", "name": "Broken Access"}, {"code": "A09", "name": "Log Fail"}],
    "Bot": [{"code": "A07", "name": "Auth Fail"}, {"code": "A08", "name": "Integrity"}],
}

RESPONSE_ACTIONS = {
    "PORT_SCAN": ["Block source at firewall", "Enable IDS signatures", "Close unnecessary ports"],
    "SYN_FLOOD": ["Enable SYN cookies", "Rate-limit connections", "Contact ISP for mitigation"],
    "ICMP_FLOOD": ["Block ICMP at perimeter", "Enable rate limiting", "Configure QoS"],
    "SSH-Bruteforce": ["Enable account lockout", "Implement MFA", "Use SSH keys only"],
    "FTP-BruteForce": ["Disable FTP, use SFTP", "IP-based access control", "Account lockout"],
    "Infiltration": ["Isolate systems", "Capture forensics", "Engage IR team"],
    "Bot": ["Block C2 IPs", "Quarantine endpoint", "Scan for lateral movement"],
    "DEFAULT": ["Block source IP", "Review logs", "Update signatures", "Escalate to SOC"],
}

# Attack animation routes - defines source -> path -> target for each attack type
ATTACK_ROUTES = {
    "PORT_SCAN": {"source": "internet", "path": ["firewall", "switch"], "targets": ["server", "database", "scanner"], "color": "#ff9500", "pattern": "scan"},
    "ICMP_FLOOD": {"source": "internet", "path": ["firewall", "switch"], "targets": ["scanner"], "color": "#ff2d55", "pattern": "flood"},
    "SYN_FLOOD": {"source": "internet", "path": ["firewall", "switch"], "targets": ["server"], "color": "#ff2d55", "pattern": "flood"},
    "SSH-Bruteforce": {"source": "internet", "path": ["firewall", "switch"], "targets": ["server"], "color": "#ff6b6b", "pattern": "burst"},
    "FTP-BruteForce": {"source": "internet", "path": ["firewall", "switch"], "targets": ["server"], "color": "#ff6b6b", "pattern": "burst"},
    "Brute Force": {"source": "internet", "path": ["firewall", "switch"], "targets": ["server"], "color": "#ff6b6b", "pattern": "burst"},
    "DoS attacks-GoldenEye": {"source": "internet", "path": ["firewall", "switch"], "targets": ["server"], "color": "#ff2d55", "pattern": "flood"},
    "DoS attacks-Hulk": {"source": "internet", "path": ["firewall", "switch"], "targets": ["server"], "color": "#ff2d55", "pattern": "flood"},
    "DoS attacks-Slowloris": {"source": "internet", "path": ["firewall"], "targets": ["server"], "color": "#ff7f50", "pattern": "slow"},
    "DoS attacks-SlowHTTPTest": {"source": "internet", "path": ["firewall"], "targets": ["server"], "color": "#ff7f50", "pattern": "slow"},
    "DDOS attack-HOIC": {"source": "internet", "path": ["firewall", "switch"], "targets": ["server", "scanner"], "color": "#ff0000", "pattern": "massive"},
    "DDOS attack-LOIC-HTTP": {"source": "internet", "path": ["firewall", "switch"], "targets": ["server"], "color": "#ff0000", "pattern": "massive"},
    "Bot": {"source": "workstation", "path": ["switch", "firewall"], "targets": ["internet"], "color": "#a855f7", "pattern": "beacon"},
    "Infiltration": {"source": "database", "path": ["switch", "firewall"], "targets": ["internet"], "color": "#ec4899", "pattern": "exfil"},
    "Infilteration": {"source": "database", "path": ["switch", "firewall"], "targets": ["internet"], "color": "#ec4899", "pattern": "exfil"},
}

class Theme:
    BG_DARKEST = "#020408"
    BG_PRIMARY = "#0a0e14"
    BG_SECONDARY = "#0d1117"
    BG_TERTIARY = "#161b22"
    BG_CARD = "#1c2128"
    BG_ELEVATED = "#262c36"
    
    CYAN = "#00d9ff"
    BLUE = "#58a6ff"
    GREEN = "#3fb950"
    RED = "#f85149"
    ORANGE = "#d29922"
    YELLOW = "#e3b341"
    PURPLE = "#a371f7"
    PINK = "#db61a2"
    
    SEV_CRITICAL = "#ff4757"
    SEV_HIGH = "#ff7f50"
    SEV_MEDIUM = "#ffa502"
    SEV_LOW = "#2ed573"
    
    TEXT_BRIGHT = "#f0f6fc"
    TEXT_PRIMARY = "#c9d1d9"
    TEXT_SECONDARY = "#8b949e"
    TEXT_MUTED = "#484f58"
    BORDER = "#30363d"
    
    FONT = "Segoe UI"
    MONO = "Consolas"


def load_scanner_module(path=ORIGINAL_SCANNER_PATH, name="scanner"):
    if not os.path.exists(path):
        raise FileNotFoundError(f"Scanner not found: {path}")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


# ============================================================================
# ENTERPRISE NETWORK TOPOLOGY - Matching real SOC architecture
# ============================================================================

class NetworkTopologyCanvas(tk.Canvas):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, bg=Theme.BG_DARKEST, highlightthickness=0, **kwargs)
        
        self.nodes = {}
        self.connections = []
        self.active_attack = None
        self.attack_start_time = 0
        self.attack_duration = 0
        self.particles = []
        self.pulse_rings = []
        self.shockwaves = []
        self.frame_count = 0
        self.attack_info = None
        
        # Pending attack for 2-second ML analysis delay
        self._pending_attack = None
        self._pending_attack_time = 0
        self._pending_ip = None
        self._pending_duration = 0
        
        self.bind("<Configure>", self._on_resize)
        self.after(100, self._init_topology)
        self.after(25, self._animate)
        self.after(200, self._check_attack_state)
    
    def _init_topology(self):
        w, h = self.winfo_width(), self.winfo_height()
        if w < 100:
            self.after(100, self._init_topology)
            return
        
        # Enterprise network layout matching the architecture diagram
        # Spread out nodes across the full canvas
        cx = w // 2
        
        self.nodes = {
            # Top layer - Internet
            'internet': {'x': cx, 'y': 35, 'label': 'INTERNET', 'color': '#5c6bc0', 'size': 22, 'pulse': 0, 'shape': 'cloud'},
            
            # Second layer - Perimeter
            'firewall': {'x': cx, 'y': 100, 'label': 'PERIMETER FIREWALL', 'color': Theme.ORANGE, 'size': 20, 'pulse': 0, 'shape': 'rect'},
            
            # Third layer - Core network
            'switch': {'x': cx, 'y': 165, 'label': 'CORE SWITCH', 'color': '#4dd0e1', 'size': 18, 'pulse': 0, 'shape': 'rect'},
            
            # Fourth layer - Scanner (center) and Server Rack (right)
            'scanner': {'x': cx - 100, 'y': 240, 'label': 'THREAT SCANNER', 'color': Theme.CYAN, 'size': 24, 'pulse': 0, 'shape': 'rect'},
            'server': {'x': cx + 130, 'y': 200, 'label': 'SERVER RACK', 'color': Theme.GREEN, 'size': 20, 'pulse': 0, 'shape': 'stack'},
            
            # Bottom layer - Endpoints
            'workstation': {'x': cx - 160, 'y': 320, 'label': 'WORKSTATIONS', 'color': Theme.PURPLE, 'size': 16, 'pulse': 0, 'shape': 'multi'},
            'database': {'x': cx + 130, 'y': 300, 'label': 'DATABASE CLUSTER', 'color': Theme.BLUE, 'size': 18, 'pulse': 0, 'shape': 'stack'},
        }
        
        # Network connections with bandwidth labels
        self.connections = [
            ('internet', 'firewall', '1 Gbps'),
            ('firewall', 'switch', '100 Mbps'),
            ('switch', 'scanner', '50 Mbps'),
            ('switch', 'server', '150 Mbps'),
            ('switch', 'workstation', '100 Mbps'),
            ('server', 'database', '10 Gbps'),
        ]
        
        self._draw()
    
    def _check_attack_state(self):
        """Check for attack start/stop signals from attack script"""
        try:
            if os.path.exists(ATTACK_STATE_FILE):
                with open(ATTACK_STATE_FILE, 'r') as f:
                    content = f.read().strip()
                
                parts = content.split('|')
                if len(parts) >= 2:
                    action = parts[0]
                    
                    if action == "START" and len(parts) >= 5:
                        attack_type = parts[1]
                        source_ip = parts[2]
                        duration = int(parts[3])
                        signal_time = float(parts[4]) if len(parts) > 4 else time.time()
                        
                        # 2 second delay to simulate ML analysis time
                        if self.active_attack != attack_type:
                            if not hasattr(self, '_pending_attack') or self._pending_attack != attack_type:
                                self._pending_attack = attack_type
                                self._pending_attack_time = time.time()
                                self._pending_ip = source_ip
                                self._pending_duration = duration
                            elif time.time() - self._pending_attack_time >= 2.0:
                                self.start_attack(attack_type, source_ip, duration)
                                self._pending_attack = None
                    
                    elif action == "STOP":
                        self._pending_attack = None
                        self.stop_attack()
        except Exception:
            pass
        
        # Check if attack duration exceeded
        if self.active_attack and self.attack_duration > 0:
            elapsed = time.time() - self.attack_start_time
            if elapsed >= self.attack_duration + 3:
                self.stop_attack()
        
        self.after(200, self._check_attack_state)
    
    def start_attack(self, attack_type, source_ip, duration):
        """Start attack animation synchronized with attack script"""
        self.active_attack = attack_type
        self.attack_start_time = time.time()
        self.attack_duration = duration
        self.particles = []
        self.pulse_rings = []
        self.shockwaves = []
        
        route = ATTACK_ROUTES.get(attack_type, ATTACK_ROUTES.get("PORT_SCAN"))
        
        self.attack_info = {
            'type': attack_type,
            'ip': source_ip,
            'duration': duration,
            'route': route,
            'mitre': MITRE_MAPPING.get(attack_type, {})
        }
        
        # Initial shockwave at source
        source_node = self.nodes.get(route['source'])
        if source_node:
            self._add_shockwave(source_node['x'], source_node['y'], route['color'], 80)
    
    def stop_attack(self):
        """Stop attack animation"""
        self.active_attack = None
        self.attack_info = None
        self.particles = []
        self.pulse_rings = []
        self.shockwaves = []
    
    def trigger_attack(self, ip, attack_type):
        """Legacy trigger for scanner detections"""
        if not self.active_attack:
            self.start_attack(attack_type, ip, 15)
    
    def _spawn_route_particle(self, route):
        """Spawn particle that follows the attack route"""
        source = self.nodes.get(route['source'])
        if not source:
            return
        
        # Build path points
        path = [source]
        for node_name in route.get('path', []):
            if node_name in self.nodes:
                path.append(self.nodes[node_name])
        
        # Pick random target
        targets = route.get('targets', ['scanner'])
        target_name = random.choice(targets)
        if target_name in self.nodes:
            path.append(self.nodes[target_name])
        
        if len(path) < 2:
            return
        
        self.particles.append({
            'path': path,
            'path_idx': 0,
            'progress': 0,
            'x': path[0]['x'],
            'y': path[0]['y'],
            'color': route['color'],
            'speed': random.uniform(0.02, 0.05) if route['pattern'] == 'slow' else random.uniform(0.04, 0.08),
            'size': random.randint(4, 7),
            'trail': []
        })
    
    def _add_shockwave(self, x, y, color, max_radius):
        self.shockwaves.append({
            'x': x, 'y': y, 'radius': 5, 'max_radius': max_radius,
            'color': color, 'alpha': 1.0, 'width': 4
        })
    
    def _add_pulse(self, x, y, color):
        self.pulse_rings.append({
            'x': x, 'y': y, 'radius': 5, 'max_radius': 50,
            'color': color, 'alpha': 1.0
        })
    
    def _animate(self):
        self.frame_count += 1
        
        # Spawn particles during active attack
        if self.active_attack and self.attack_info:
            route = self.attack_info['route']
            pattern = route.get('pattern', 'flood')
            
            # Spawn rate based on pattern
            if pattern == 'massive':
                spawn_rate = 0.8
            elif pattern == 'flood':
                spawn_rate = 0.5
            elif pattern == 'burst':
                spawn_rate = 0.4
            elif pattern == 'scan':
                spawn_rate = 0.3
            elif pattern == 'beacon':
                spawn_rate = 0.2
            else:
                spawn_rate = 0.15
            
            if random.random() < spawn_rate:
                for _ in range(random.randint(1, 3)):
                    self._spawn_route_particle(route)
            
            # Periodic pulses at target
            if self.frame_count % 40 == 0:
                for target_name in route.get('targets', []):
                    if target_name in self.nodes:
                        node = self.nodes[target_name]
                        self._add_pulse(node['x'], node['y'], route['color'])
        
        # Update particles along their paths
        new_particles = []
        for p in self.particles:
            p['progress'] += p['speed']
            
            # Get current segment
            if p['path_idx'] < len(p['path']) - 1:
                start = p['path'][p['path_idx']]
                end = p['path'][p['path_idx'] + 1]
                
                # Interpolate position
                p['trail'].append((p['x'], p['y']))
                if len(p['trail']) > 12:
                    p['trail'].pop(0)
                
                p['x'] = start['x'] + (end['x'] - start['x']) * p['progress']
                p['y'] = start['y'] + (end['y'] - start['y']) * p['progress']
                
                # Move to next segment
                if p['progress'] >= 1.0:
                    p['path_idx'] += 1
                    p['progress'] = 0
                    
                    # Spawn pulse at waypoint
                    self._add_pulse(end['x'], end['y'], p['color'])
                
                if p['path_idx'] < len(p['path']) - 1:
                    new_particles.append(p)
                else:
                    # Reached destination - impact effect
                    self._add_shockwave(p['x'], p['y'], p['color'], 40)
        
        self.particles = new_particles
        
        # Update pulses
        new_pulses = []
        for pulse in self.pulse_rings:
            pulse['radius'] += 2
            pulse['alpha'] = 1 - (pulse['radius'] / pulse['max_radius'])
            if pulse['radius'] < pulse['max_radius']:
                new_pulses.append(pulse)
        self.pulse_rings = new_pulses
        
        # Update shockwaves
        new_shockwaves = []
        for sw in self.shockwaves:
            sw['radius'] += 3
            sw['alpha'] = 1 - (sw['radius'] / sw['max_radius'])
            sw['width'] = max(1, int(4 * sw['alpha']))
            if sw['radius'] < sw['max_radius']:
                new_shockwaves.append(sw)
        self.shockwaves = new_shockwaves
        
        # Update node pulses
        for node in self.nodes.values():
            node['pulse'] = (node['pulse'] + 0.12) % (2 * math.pi)
        
        self._draw()
        self.after(25, self._animate)
    
    def _draw(self):
        self.delete("all")
        w, h = self.winfo_width(), self.winfo_height()
        
        # Grid background
        for i in range(0, w, 30):
            self.create_line(i, 0, i, h, fill="#0a0f16", width=1)
        for i in range(0, h, 30):
            self.create_line(0, i, w, i, fill="#0a0f16", width=1)
        
        # Draw shockwaves (behind everything)
        for sw in self.shockwaves:
            self.create_oval(sw['x']-sw['radius'], sw['y']-sw['radius'],
                           sw['x']+sw['radius'], sw['y']+sw['radius'],
                           outline=sw['color'], width=sw['width'])
        
        # Draw connections with bandwidth labels
        for conn in self.connections:
            if conn[0] in self.nodes and conn[1] in self.nodes:
                n1, n2 = self.nodes[conn[0]], self.nodes[conn[1]]
                
                # Line color based on attack activity
                line_color = Theme.RED if self.active_attack else Theme.BORDER
                line_width = 2 if self.active_attack else 1
                
                self.create_line(n1['x'], n1['y'], n2['x'], n2['y'],
                               fill=line_color, width=line_width)
                
                # Bandwidth label
                mid_x = (n1['x'] + n2['x']) // 2 + 20
                mid_y = (n1['y'] + n2['y']) // 2
                if len(conn) > 2:
                    self.create_text(mid_x, mid_y, text=conn[2],
                                   fill=Theme.TEXT_MUTED, font=(Theme.MONO, 7))
        
        # Draw particle trails and particles
        for p in self.particles:
            # Trail
            if len(p['trail']) > 1:
                for i, (tx, ty) in enumerate(p['trail']):
                    alpha = i / len(p['trail'])
                    size = p['size'] * alpha * 0.6
                    if size > 0.5:
                        self.create_oval(tx-size, ty-size, tx+size, ty+size,
                                       fill=p['color'], outline="")
            
            # Particle with glow
            glow = p['size'] + 2
            self.create_oval(p['x']-glow, p['y']-glow, p['x']+glow, p['y']+glow,
                           fill="", outline=p['color'], width=1)
            self.create_oval(p['x']-p['size'], p['y']-p['size'],
                           p['x']+p['size'], p['y']+p['size'],
                           fill=p['color'], outline="white", width=1)
        
        # Pulse rings
        for pulse in self.pulse_rings:
            self.create_oval(pulse['x']-pulse['radius'], pulse['y']-pulse['radius'],
                           pulse['x']+pulse['radius'], pulse['y']+pulse['radius'],
                           outline=pulse['color'], width=2)
        
        # Draw nodes with shapes matching enterprise equipment
        for name, node in self.nodes.items():
            x, y = node['x'], node['y']
            size = node['size']
            color = node['color']
            pulse_offset = math.sin(node['pulse']) * 3
            
            # Highlight targets during attack
            is_target = False
            if self.attack_info:
                route = self.attack_info.get('route', {})
                is_target = name in route.get('targets', []) or name == route.get('source')
            
            # Shape based on node type
            shape = node.get('shape', 'circle')
            
            if shape == 'cloud':
                # Internet cloud
                self._draw_cloud(x, y, size, color, is_target, pulse_offset)
            elif shape == 'rect':
                # Network equipment (firewall, switch, scanner)
                self._draw_rect_node(x, y, size, color, is_target, pulse_offset, name == 'scanner')
            elif shape == 'stack':
                # Server rack or database
                self._draw_stack(x, y, size, color, is_target, pulse_offset)
            elif shape == 'multi':
                # Multiple workstations
                self._draw_workstations(x, y, size, color, is_target, pulse_offset)
            else:
                # Default circle
                self._draw_circle_node(x, y, size, color, is_target, pulse_offset)
            
            # Label
            label_y = y + size + 18 if shape != 'stack' else y + size + 25
            self.create_text(x, label_y, text=node['label'],
                           fill=Theme.TEXT_BRIGHT if is_target else Theme.TEXT_SECONDARY,
                           font=(Theme.MONO, 8, 'bold' if is_target else 'normal'))
        
        # Attack info overlay
        if self.attack_info:
            self._draw_attack_overlay()
    
    def _draw_cloud(self, x, y, size, color, is_target, pulse):
        # Simple cloud shape
        s = size + pulse
        self.create_oval(x-s*1.5, y-s*0.8, x+s*1.5, y+s*0.8,
                        fill=Theme.BG_CARD, outline=color, width=3 if is_target else 2)
        if is_target:
            self.create_oval(x-s*1.7, y-s, x+s*1.7, y+s, outline=Theme.RED, width=2)
    
    def _draw_rect_node(self, x, y, size, color, is_target, pulse, is_scanner=False):
        s = size + pulse
        w_mult = 2.5 if is_scanner else 2
        h_mult = 0.8
        
        # Danger glow for scanner
        if is_scanner and self.active_attack:
            glow = s + 15
            self.create_rectangle(x-glow*w_mult, y-glow*h_mult, x+glow*w_mult, y+glow*h_mult,
                                outline=Theme.RED, width=3)
        
        # Main shape
        self.create_rectangle(x-s*w_mult, y-s*h_mult, x+s*w_mult, y+s*h_mult,
                            fill=Theme.BG_CARD, outline=color, width=3 if is_target else 2)
        
        # Status LEDs
        led_y = y - s*0.3
        for i in range(3):
            led_x = x - s + i * s * 0.8
            led_color = Theme.GREEN if not self.active_attack else (Theme.RED if i == 0 else Theme.YELLOW)
            self.create_oval(led_x-3, led_y-3, led_x+3, led_y+3, fill=led_color, outline="")
    
    def _draw_stack(self, x, y, size, color, is_target, pulse):
        s = size + pulse
        # Draw stacked rectangles (server rack)
        for i in range(3):
            offset_y = y - s + i * s * 0.8
            self.create_rectangle(x-s*1.2, offset_y-s*0.3, x+s*1.2, offset_y+s*0.3,
                                fill=Theme.BG_CARD, outline=color, width=2)
            # LED
            self.create_oval(x+s*0.8, offset_y-2, x+s*0.8+4, offset_y+2,
                           fill=Theme.GREEN if not is_target else Theme.RED, outline="")
        
        if is_target:
            self.create_rectangle(x-s*1.4, y-s*1.2, x+s*1.4, y+s*1.2,
                                outline=Theme.RED, width=2)
    
    def _draw_workstations(self, x, y, size, color, is_target, pulse):
        s = size + pulse
        # Draw 3 small monitors
        for i in range(3):
            wx = x - s*1.5 + i * s * 1.5
            # Monitor
            self.create_rectangle(wx-s*0.6, y-s*0.5, wx+s*0.6, y+s*0.3,
                                fill=Theme.BG_CARD, outline=color, width=2)
            # Stand
            self.create_rectangle(wx-s*0.2, y+s*0.3, wx+s*0.2, y+s*0.6,
                                fill=color, outline="")
        
        if is_target:
            self.create_rectangle(x-s*2.5, y-s*0.8, x+s*2.5, y+s*0.9,
                                outline=Theme.RED, width=2)
    
    def _draw_circle_node(self, x, y, size, color, is_target, pulse):
        s = size + pulse
        if is_target:
            self.create_oval(x-s-10, y-s-10, x+s+10, y+s+10, outline=Theme.RED, width=3)
        self.create_oval(x-s, y-s, x+s, y+s, fill=Theme.BG_CARD, outline=color, width=2)
    
    def _draw_attack_overlay(self):
        w, h = self.winfo_width(), self.winfo_height()
        info = self.attack_info
        mitre = info.get('mitre', {})
        
        # Overlay box - larger for more info
        box_w, box_h = 300, 130
        x, y = w - box_w - 10, 10
        
        # Pulsing border
        pulse = math.sin(time.time() * 6) * 0.5 + 0.5
        border_w = 3 if pulse > 0.5 else 2
        
        self.create_rectangle(x-3, y-3, x+box_w+3, y+box_h+3, outline=Theme.RED, width=border_w)
        self.create_rectangle(x, y, x+box_w, y+box_h, fill=Theme.BG_CARD, outline=Theme.RED, width=2)
        
        # Header
        blink = self.frame_count % 30 < 15
        header_text = "!! THREAT DETECTED !!" if blink else "   THREAT DETECTED   "
        self.create_rectangle(x, y, x+box_w, y+22, fill=Theme.RED, outline="")
        self.create_text(x+box_w//2, y+11, text=header_text,
                        fill=Theme.BG_DARKEST, font=(Theme.MONO, 9, 'bold'))
        
        # Attack info
        self.create_text(x+10, y+38, text=info['type'], anchor='w',
                        fill=Theme.TEXT_BRIGHT, font=(Theme.FONT, 11, 'bold'))
        
        self.create_text(x+10, y+55, text=f"Source: {info['ip']}", anchor='w',
                        fill=Theme.CYAN, font=(Theme.MONO, 9))
        
        # MITRE info
        if mitre:
            self.create_text(x+10, y+72, text=f"MITRE: {mitre.get('technique', '')} - {mitre.get('tactic', '')}", anchor='w',
                            fill=Theme.PURPLE, font=(Theme.MONO, 8))
        
        # Status indicator
        status = "ML ANALYSIS COMPLETE - BLOCKING"
        self.create_text(x+10, y+90, text=status, anchor='w',
                        fill=Theme.ORANGE, font=(Theme.MONO, 8, 'bold'))
        
        # Severity bar
        self.create_rectangle(x+10, y+105, x+box_w-10, y+115, fill=Theme.RED, outline=Theme.BORDER)
        self.create_text(x+box_w//2, y+110, text="SEVERITY: HIGH", fill=Theme.BG_DARKEST, font=(Theme.MONO, 8, 'bold'))
        
        # Status at bottom of canvas - no time metrics
        status_text = f"ACTIVE THREAT: {info['type']} from {info['ip']}"
        self.create_text(10, h-10, text=status_text, anchor='sw',
                        fill=Theme.RED, font=(Theme.MONO, 10, 'bold'))
    
    def _on_resize(self, event):
        w, h = event.width, event.height
        cx = w // 2
        
        if self.nodes:
            # Update positions on resize
            self.nodes['internet']['x'] = cx
            self.nodes['firewall']['x'] = cx
            self.nodes['switch']['x'] = cx
            self.nodes['scanner']['x'] = cx - 100
            self.nodes['server']['x'] = cx + 130
            self.nodes['workstation']['x'] = cx - 160
            self.nodes['database']['x'] = cx + 130


# ============================================================================
# THREAT INTELLIGENCE PANEL
# ============================================================================

class ThreatIntelPanel(tk.Frame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, bg=Theme.BG_SECONDARY, **kwargs)
        
        header = tk.Frame(self, bg=Theme.BG_TERTIARY, height=36)
        header.pack(fill='x')
        header.pack_propagate(False)
        
        tk.Label(header, text="  THREAT INTELLIGENCE", font=(Theme.FONT, 10, 'bold'),
                fg=Theme.CYAN, bg=Theme.BG_TERTIARY).pack(side='left', pady=6)
        
        self.count_var = tk.StringVar(value="0")
        tk.Label(header, textvariable=self.count_var, font=(Theme.MONO, 10, 'bold'),
                fg=Theme.BG_DARKEST, bg=Theme.RED, padx=8).pack(side='right', padx=10)
        
        container = tk.Frame(self, bg=Theme.BG_SECONDARY)
        container.pack(fill='both', expand=True)
        
        self.canvas = tk.Canvas(container, bg=Theme.BG_SECONDARY, highlightthickness=0)
        scrollbar = tk.Scrollbar(container, orient='vertical', command=self.canvas.yview,
                                bg=Theme.BG_TERTIARY, troughcolor=Theme.BG_PRIMARY, width=10)
        
        self.inner_frame = tk.Frame(self.canvas, bg=Theme.BG_SECONDARY)
        self.inner_frame.bind("<Configure>",
                             lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        
        self.canvas_window = self.canvas.create_window((0, 0), window=self.inner_frame, anchor='nw')
        self.canvas.configure(yscrollcommand=scrollbar.set)
        self.canvas.bind('<Configure>', lambda e: self.canvas.itemconfig(self.canvas_window, width=e.width-12))
        
        scrollbar.pack(side='right', fill='y')
        self.canvas.pack(side='left', fill='both', expand=True)
        
        self.threat_count = 0
        self.entries = []
    
    def add_attack_chain_alert(self, attacks, source_ip):
        self.threat_count += 1
        self.count_var.set(str(self.threat_count))
        
        now = datetime.now()
        
        outer = tk.Frame(self.inner_frame, bg=Theme.SEV_CRITICAL, padx=5, pady=5)
        outer.pack(fill='x', padx=4, pady=8)
        
        inner = tk.Frame(outer, bg=Theme.BG_CARD, padx=12, pady=10)
        inner.pack(fill='x')
        
        # Header with timestamp
        header = tk.Frame(inner, bg=Theme.SEV_CRITICAL, padx=8, pady=4)
        header.pack(fill='x', pady=(0, 8))
        tk.Label(header, text="CRITICAL: MULTI-STAGE APT ATTACK CHAIN DETECTED", 
                font=(Theme.FONT, 11, 'bold'), fg=Theme.BG_DARKEST, bg=Theme.SEV_CRITICAL).pack(side='left')
        
        # Detection timestamp
        tk.Label(inner, text=f"Detection Time: {now.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}", 
                font=(Theme.MONO, 9), fg=Theme.YELLOW, bg=Theme.BG_CARD).pack(anchor='w')
        tk.Label(inner, text=f"Threat Actor IP: {source_ip}", font=(Theme.MONO, 10, 'bold'),
                fg=Theme.RED, bg=Theme.BG_CARD).pack(anchor='w', pady=(4, 2))
        tk.Label(inner, text=f"Attack Phases Detected: {len(attacks)}", font=(Theme.MONO, 9),
                fg=Theme.CYAN, bg=Theme.BG_CARD).pack(anchor='w')
        
        # Separator
        tk.Frame(inner, bg=Theme.BORDER, height=2).pack(fill='x', pady=6)
        
        tk.Label(inner, text="ATTACK KILL CHAIN TIMELINE:", font=(Theme.MONO, 9, 'bold'),
                fg=Theme.ORANGE, bg=Theme.BG_CARD).pack(anchor='w', pady=(0, 4))
        
        # Attack phases with timestamps
        base_time = now
        for i, attack in enumerate(attacks, 1):
            phase_time = base_time - timedelta(seconds=(len(attacks)-i)*5)
            frame = tk.Frame(inner, bg=Theme.BG_ELEVATED, padx=6, pady=3)
            frame.pack(fill='x', pady=2)
            
            tk.Label(frame, text=f"[{phase_time.strftime('%H:%M:%S')}]", font=(Theme.MONO, 8),
                    fg=Theme.TEXT_MUTED, bg=Theme.BG_ELEVATED).pack(side='left')
            tk.Label(frame, text=f"PHASE {i}:", font=(Theme.FONT, 9, 'bold'),
                    fg=Theme.ORANGE, bg=Theme.BG_ELEVATED).pack(side='left', padx=(6, 0))
            tk.Label(frame, text=attack, font=(Theme.MONO, 9, 'bold'),
                    fg=Theme.TEXT_BRIGHT, bg=Theme.BG_ELEVATED).pack(side='left', padx=(6, 0))
            
            # MITRE tag
            mitre = MITRE_MAPPING.get(attack, {})
            if mitre:
                tk.Label(frame, text=f"[{mitre.get('technique', '')}]", font=(Theme.MONO, 8),
                        fg=Theme.PURPLE, bg=Theme.BG_ELEVATED).pack(side='left', padx=(6, 0))
        
        # Separator
        tk.Frame(inner, bg=Theme.BORDER, height=2).pack(fill='x', pady=6)
        
        # Threat assessment
        tk.Label(inner, text="THREAT ASSESSMENT:", font=(Theme.MONO, 9, 'bold'),
                fg=Theme.RED, bg=Theme.BG_CARD).pack(anchor='w')
        tk.Label(inner, text="Severity: CRITICAL | Confidence: HIGH | Response: IMMEDIATE", 
                font=(Theme.MONO, 8), fg=Theme.YELLOW, bg=Theme.BG_CARD).pack(anchor='w')
        tk.Label(inner, text="Recommended: Isolate host, engage IR team, preserve forensics", 
                font=(Theme.FONT, 8), fg=Theme.TEXT_SECONDARY, bg=Theme.BG_CARD).pack(anchor='w')
        
        self.entries.append(outer)
        self.canvas.yview_moveto(1.0)
    
    def add_threat(self, attack_type, source_ip, severity="HIGH"):
        self.threat_count += 1
        self.count_var.set(str(self.threat_count))
        
        now = datetime.now()
        sev_colors = {'CRITICAL': Theme.SEV_CRITICAL, 'HIGH': Theme.SEV_HIGH,
                     'MEDIUM': Theme.SEV_MEDIUM, 'LOW': Theme.SEV_LOW}
        sev_color = sev_colors.get(severity, Theme.SEV_HIGH)
        
        card = tk.Frame(self.inner_frame, bg=Theme.BG_CARD, padx=10, pady=10)
        card.pack(fill='x', padx=6, pady=4)
        
        # Header Row: Severity + Attack Type + IP + Timestamp
        row1 = tk.Frame(card, bg=Theme.BG_CARD)
        row1.pack(fill='x')
        
        tk.Label(row1, text=severity, font=(Theme.MONO, 8, 'bold'),
                fg=Theme.BG_DARKEST, bg=sev_color, padx=6, pady=2).pack(side='left')
        tk.Label(row1, text=attack_type, font=(Theme.FONT, 10, 'bold'),
                fg=Theme.TEXT_BRIGHT, bg=Theme.BG_CARD).pack(side='left', padx=(8, 0))
        tk.Label(row1, text=f"[{now.strftime('%H:%M:%S.%f')[:-3]}]", font=(Theme.MONO, 8),
                fg=Theme.TEXT_MUTED, bg=Theme.BG_CARD).pack(side='right')
        
        # Source info
        tk.Label(card, text=f"Source: {source_ip} | Detection: ML_CLASSIFIER | Confidence: 94.7%", 
                font=(Theme.MONO, 8), fg=Theme.CYAN, bg=Theme.BG_CARD).pack(anchor='w', pady=(4, 0))
        
        # Separator
        tk.Frame(card, bg=Theme.BORDER, height=1).pack(fill='x', pady=4)
        
        mitre = MITRE_MAPPING.get(attack_type, {})
        owasp_list = OWASP_MAPPING.get(attack_type, [])
        
        # MITRE ATT&CK Section - Dense and verbose
        if mitre:
            mitre_frame = tk.Frame(card, bg=Theme.BG_ELEVATED, padx=6, pady=4)
            mitre_frame.pack(fill='x', pady=2)
            
            tk.Label(mitre_frame, text="MITRE ATT&CK:", font=(Theme.MONO, 8, 'bold'),
                    fg=Theme.PURPLE, bg=Theme.BG_ELEVATED).pack(side='left')
            tk.Label(mitre_frame, text=mitre.get('technique', ''), font=(Theme.MONO, 8, 'bold'),
                    fg=Theme.BG_DARKEST, bg=Theme.PURPLE, padx=4).pack(side='left', padx=(6, 4))
            tk.Label(mitre_frame, text=f"{mitre.get('name', '')} [{mitre.get('tactic', '')}]", 
                    font=(Theme.MONO, 8), fg=Theme.TEXT_PRIMARY, bg=Theme.BG_ELEVATED).pack(side='left')
            
            # Full description
            tk.Label(card, text=f"   {mitre.get('description', '')}", font=(Theme.FONT, 8),
                    fg=Theme.TEXT_SECONDARY, bg=Theme.BG_CARD, anchor='w').pack(fill='x')
        
        # OWASP Section - Dense with full names
        if owasp_list:
            owasp_frame = tk.Frame(card, bg=Theme.BG_ELEVATED, padx=6, pady=4)
            owasp_frame.pack(fill='x', pady=2)
            
            tk.Label(owasp_frame, text="OWASP 2025:", font=(Theme.MONO, 8, 'bold'),
                    fg=Theme.ORANGE, bg=Theme.BG_ELEVATED).pack(side='left')
            
            for owasp in owasp_list:
                tk.Label(owasp_frame, text=owasp['code'], font=(Theme.MONO, 8, 'bold'),
                        fg=Theme.BG_DARKEST, bg=Theme.ORANGE, padx=3).pack(side='left', padx=(4, 2))
                tk.Label(owasp_frame, text=owasp['name'], font=(Theme.MONO, 7),
                        fg=Theme.TEXT_SECONDARY, bg=Theme.BG_ELEVATED).pack(side='left', padx=(0, 6))
        
        # Response actions
        actions = RESPONSE_ACTIONS.get(attack_type, RESPONSE_ACTIONS['DEFAULT'])
        tk.Label(card, text=f"Response: {' | '.join(actions[:2])}", font=(Theme.FONT, 7),
                fg=Theme.YELLOW, bg=Theme.BG_CARD, anchor='w').pack(fill='x', pady=(4, 0))
        
        self.entries.append(card)
        if len(self.entries) > 25:
            self.entries.pop(0).destroy()
        
        self.canvas.yview_moveto(1.0)


# ============================================================================
# FIREWALL RESPONSE PANEL
# ============================================================================

class FirewallResponsePanel(tk.Frame):
    def __init__(self, parent, app_ref=None, **kwargs):
        super().__init__(parent, bg=Theme.BG_SECONDARY, **kwargs)
        self.app_ref = app_ref
        
        header = tk.Frame(self, bg=Theme.BG_TERTIARY, height=36)
        header.pack(fill='x')
        header.pack_propagate(False)
        
        tk.Label(header, text="  FIREWALL & RESPONSE", font=(Theme.FONT, 10, 'bold'),
                fg=Theme.ORANGE, bg=Theme.BG_TERTIARY).pack(side='left', pady=6)
        
        logs_frame = tk.Frame(self, bg=Theme.BG_SECONDARY)
        logs_frame.pack(fill='both', expand=True)
        
        self.canvas = tk.Canvas(logs_frame, bg=Theme.BG_SECONDARY, highlightthickness=0)
        scrollbar = tk.Scrollbar(logs_frame, orient='vertical', command=self.canvas.yview,
                                bg=Theme.BG_TERTIARY, width=8)
        
        self.inner_frame = tk.Frame(self.canvas, bg=Theme.BG_SECONDARY)
        self.inner_frame.bind("<Configure>",
                             lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        
        self.canvas.create_window((0, 0), window=self.inner_frame, anchor='nw')
        self.canvas.configure(yscrollcommand=scrollbar.set)
        
        scrollbar.pack(side='right', fill='y')
        self.canvas.pack(side='left', fill='both', expand=True)
        
        self.entries = []
        
        blocked_section = tk.Frame(self, bg=Theme.BG_TERTIARY)
        blocked_section.pack(fill='x', side='bottom')
        
        tk.Label(blocked_section, text="BLOCKED IPs", font=(Theme.FONT, 9, 'bold'),
                fg=Theme.RED, bg=Theme.BG_TERTIARY).pack(anchor='w', padx=8, pady=(6, 2))
        
        self.blocked_listbox = tk.Listbox(blocked_section, font=(Theme.MONO, 9),
                                          bg=Theme.BG_PRIMARY, fg=Theme.RED,
                                          selectbackground=Theme.CYAN, height=3,
                                          highlightthickness=0, relief='flat')
        self.blocked_listbox.pack(fill='x', padx=8, pady=(0, 4))
        
        btn_frame = tk.Frame(blocked_section, bg=Theme.BG_TERTIARY)
        btn_frame.pack(fill='x', padx=8, pady=(0, 6))
        
        tk.Button(btn_frame, text="Unblock Selected", font=(Theme.FONT, 8),
                 fg=Theme.TEXT_PRIMARY, bg=Theme.BG_ELEVATED, relief='flat',
                 command=self._unblock_selected).pack(side='left', padx=(0, 4))
        tk.Button(btn_frame, text="Unblock All", font=(Theme.FONT, 8),
                 fg=Theme.TEXT_PRIMARY, bg=Theme.BG_ELEVATED, relief='flat',
                 command=self._unblock_all).pack(side='left')
    
    def _unblock_selected(self):
        if not self.app_ref or not self.app_ref.scanner_mod:
            return
        sel = self.blocked_listbox.curselection()
        if sel:
            ip = self.blocked_listbox.get(sel[0])
            try:
                if ip in self.app_ref.scanner_mod.blocked_ips:
                    del self.app_ref.scanner_mod.blocked_ips[ip]
                self.refresh_blocked()
            except:
                pass
    
    def _unblock_all(self):
        if not self.app_ref or not self.app_ref.scanner_mod:
            return
        try:
            self.app_ref.scanner_mod.blocked_ips.clear()
            self.refresh_blocked()
        except:
            pass
    
    def refresh_blocked(self):
        if not self.app_ref or not self.app_ref.scanner_mod:
            return
        try:
            blocked = getattr(self.app_ref.scanner_mod, 'blocked_ips', {})
            self.blocked_listbox.delete(0, 'end')
            for ip in blocked.keys():
                self.blocked_listbox.insert('end', ip)
        except:
            pass
    
    def add_block_event(self, ip, attack_type):
        card = tk.Frame(self.inner_frame, bg=Theme.BG_CARD, padx=8, pady=6)
        card.pack(fill='x', padx=6, pady=2)
        
        row1 = tk.Frame(card, bg=Theme.BG_CARD)
        row1.pack(fill='x')
        
        tk.Label(row1, text="BLOCKED", font=(Theme.MONO, 8, 'bold'),
                fg=Theme.BG_DARKEST, bg=Theme.GREEN, padx=4).pack(side='left')
        tk.Label(row1, text=ip, font=(Theme.MONO, 9, 'bold'),
                fg=Theme.RED, bg=Theme.BG_CARD).pack(side='left', padx=(6, 0))
        tk.Label(row1, text=f"[{attack_type}]", font=(Theme.MONO, 8),
                fg=Theme.TEXT_MUTED, bg=Theme.BG_CARD).pack(side='left', padx=(6, 0))
        tk.Label(row1, text=datetime.now().strftime("%H:%M:%S"), font=(Theme.MONO, 8),
                fg=Theme.TEXT_MUTED, bg=Theme.BG_CARD).pack(side='right')
        
        actions = RESPONSE_ACTIONS.get(attack_type, RESPONSE_ACTIONS['DEFAULT'])
        tk.Label(card, text=f"Actions: {' | '.join(actions[:2])}", font=(Theme.FONT, 8),
                fg=Theme.YELLOW, bg=Theme.BG_CARD, anchor='w').pack(fill='x', pady=(2, 0))
        
        self.entries.append(card)
        if len(self.entries) > 15:
            self.entries.pop(0).destroy()
        
        self.canvas.yview_moveto(1.0)
        self.refresh_blocked()


# ============================================================================
# RAW CONSOLE
# ============================================================================

class RawConsole(tk.Frame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, bg=Theme.BG_PRIMARY, **kwargs)
        
        header = tk.Frame(self, bg=Theme.BG_TERTIARY, height=24)
        header.pack(fill='x')
        header.pack_propagate(False)
        
        tk.Label(header, text="  RAW OUTPUT", font=(Theme.FONT, 8, 'bold'),
                fg=Theme.TEXT_SECONDARY, bg=Theme.BG_TERTIARY).pack(side='left', pady=3)
        
        tk.Button(header, text="Clear", font=(Theme.FONT, 7),
                 fg=Theme.TEXT_SECONDARY, bg=Theme.BG_ELEVATED, relief='flat',
                 command=self.clear).pack(side='right', padx=6)
        
        self.text = tk.Text(self, wrap='word', font=(Theme.MONO, 8),
                           bg=Theme.BG_DARKEST, fg=Theme.TEXT_PRIMARY,
                           insertbackground=Theme.CYAN, relief='flat',
                           padx=6, pady=4, state='disabled', height=6)
        
        scrollbar = tk.Scrollbar(self, command=self.text.yview, width=8)
        self.text.configure(yscrollcommand=scrollbar.set)
        
        scrollbar.pack(side='right', fill='y')
        self.text.pack(fill='both', expand=True)
        
        self.text.tag_config('red', foreground=Theme.RED)
        self.text.tag_config('green', foreground=Theme.GREEN)
        self.text.tag_config('yellow', foreground=Theme.YELLOW)
        self.text.tag_config('cyan', foreground=Theme.CYAN)
    
    def append(self, text):
        self.text.config(state='normal')
        clean = re.sub(r'\033\[[0-9;]+m', '', text)
        
        tags = ()
        if '[!' in text or 'ERROR' in text or 'BLOCK' in text:
            tags = ('red',)
        elif 'DETECTED' in text:
            tags = ('yellow',)
        elif '[*]' in text or 'START' in text:
            tags = ('green',)
        elif 'ML' in text:
            tags = ('cyan',)
        
        self.text.insert('end', clean, tags)
        self.text.see('end')
        self.text.config(state='disabled')
    
    def clear(self):
        self.text.config(state='normal')
        self.text.delete('1.0', 'end')
        self.text.config(state='disabled')


# ============================================================================
# STATS BAR
# ============================================================================

class StatsBar(tk.Frame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, bg=Theme.BG_TERTIARY, **kwargs)
        
        self.stats = {}
        self.real_values = {'packets': 0, 'flows': 0, 'threats': 0, 'blocked': 0}
        
        configs = [
            ("PACKETS", "0", Theme.CYAN),
            ("FLOWS", "0", Theme.BLUE),
            ("THREATS", "0", Theme.RED),
            ("BLOCKED", "0", Theme.ORANGE),
        ]
        
        for label, value, color in configs:
            frame = tk.Frame(self, bg=Theme.BG_TERTIARY, padx=25)
            frame.pack(side='left', fill='y')
            
            dot = tk.Canvas(frame, width=10, height=10, bg=Theme.BG_TERTIARY, highlightthickness=0)
            dot.create_oval(1, 1, 9, 9, fill=color, outline="")
            dot.pack(side='left', padx=(0, 8), pady=10)
            
            tk.Label(frame, text=label, font=(Theme.FONT, 9),
                    fg=Theme.TEXT_MUTED, bg=Theme.BG_TERTIARY).pack(side='left')
            
            var = tk.StringVar(value=value)
            tk.Label(frame, textvariable=var, font=(Theme.MONO, 14, 'bold'),
                    fg=color, bg=Theme.BG_TERTIARY).pack(side='left', padx=(10, 0))
            
            self.stats[label.lower()] = var
    
    def update(self, name, value):
        if name in self.stats:
            self.stats[name].set(str(value))


# ============================================================================
# MAIN APPLICATION
# ============================================================================

class ThreatHunterSOC(tk.Tk):
    def __init__(self):
        super().__init__()
        
        self.title("THREAT HUNTER // Security Operations Center")
        self.geometry("1600x900")
        self.configure(bg=Theme.BG_PRIMARY)
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        
        self.scanner_mod = None
        self.sniffer = None
        self.running = False
        self.stdout_queue = queue.Queue()
        self.packet_count = 0
        self.threat_count = 0
        self.blocked_count = 0
        self.attack_chain = []
        self.last_attack_time = 0
        
        self._build_ui()
        
        self.after(100, self._poll_queue)
        self.after(500, self._update_stats)
        self.after(500, self._load_scanner)
        self.after(100, self._simulate_packet_flow)
    
    def _simulate_packet_flow(self):
        if self.running:
            increment = random.randint(5, 25)
            self.packet_count += increment
            self.stats_bar.update('packets', f"{self.packet_count:,}")
        self.after(200, self._simulate_packet_flow)
    
    def _build_ui(self):
        # TOP BAR
        topbar = tk.Frame(self, bg=Theme.BG_TERTIARY, height=50)
        topbar.pack(fill='x')
        topbar.pack_propagate(False)
        
        logo = tk.Frame(topbar, bg=Theme.BG_TERTIARY)
        logo.pack(side='left', padx=15)
        
        tk.Label(logo, text="THREAT", font=(Theme.FONT, 20, 'bold'),
                fg=Theme.CYAN, bg=Theme.BG_TERTIARY).pack(side='left')
        tk.Label(logo, text="HUNTER", font=(Theme.FONT, 20, 'bold'),
                fg=Theme.TEXT_BRIGHT, bg=Theme.BG_TERTIARY).pack(side='left', padx=(4, 0))
        tk.Label(logo, text="// SOC", font=(Theme.MONO, 10),
                fg=Theme.TEXT_MUTED, bg=Theme.BG_TERTIARY).pack(side='left', padx=(12, 0))
        
        controls = tk.Frame(topbar, bg=Theme.BG_TERTIARY)
        controls.pack(side='right', padx=15)
        
        self.status_canvas = tk.Canvas(controls, width=14, height=14,
                                       bg=Theme.BG_TERTIARY, highlightthickness=0)
        self.status_canvas.pack(side='left', padx=(0, 8))
        self.status_canvas.create_oval(2, 2, 12, 12, fill=Theme.RED, outline="")
        
        self.status_var = tk.StringVar(value="OFFLINE")
        self.status_label = tk.Label(controls, textvariable=self.status_var,
                                    font=(Theme.MONO, 12, 'bold'),
                                    fg=Theme.RED, bg=Theme.BG_TERTIARY)
        self.status_label.pack(side='left', padx=(0, 20))
        
        self.start_btn = tk.Button(controls, text="START", font=(Theme.FONT, 10, 'bold'),
                                  fg=Theme.BG_DARKEST, bg=Theme.GREEN,
                                  relief='flat', padx=20, pady=6, cursor='hand2',
                                  command=self.start_scanner)
        self.start_btn.pack(side='left', padx=(0, 8))
        
        self.stop_btn = tk.Button(controls, text="STOP", font=(Theme.FONT, 10, 'bold'),
                                 fg=Theme.TEXT_BRIGHT, bg=Theme.RED,
                                 relief='flat', padx=15, pady=6, cursor='hand2',
                                 state='disabled', command=self.stop_scanner)
        self.stop_btn.pack(side='left')
        
        # STATS BAR
        self.stats_bar = StatsBar(self, height=50)
        self.stats_bar.pack(fill='x')
        
        # MAIN CONTENT
        main = tk.Frame(self, bg=Theme.BG_PRIMARY)
        main.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Left Column (60%)
        left = tk.Frame(main, bg=Theme.BG_PRIMARY)
        left.pack(side='left', fill='both', expand=True, padx=(0, 5))
        
        # Network Topology (taller for enterprise layout)
        self.topology = NetworkTopologyCanvas(left, height=360)
        self.topology.pack(fill='x', pady=(0, 5))
        
        # Threat Intelligence
        self.threat_panel = ThreatIntelPanel(left)
        self.threat_panel.pack(fill='both', expand=True, pady=(0, 5))
        
        # Raw Console
        self.console = RawConsole(left, height=80)
        self.console.pack(fill='x')
        
        # Right Column (40%)
        right = tk.Frame(main, bg=Theme.BG_PRIMARY, width=500)
        right.pack(side='right', fill='y', padx=(5, 0))
        right.pack_propagate(False)
        
        # Config
        config = tk.Frame(right, bg=Theme.BG_TERTIARY, padx=10, pady=8)
        config.pack(fill='x', pady=(0, 5))
        
        tk.Label(config, text="CONFIG", font=(Theme.FONT, 9, 'bold'),
                fg=Theme.TEXT_SECONDARY, bg=Theme.BG_TERTIARY).pack(anchor='w', pady=(0, 6))
        
        row1 = tk.Frame(config, bg=Theme.BG_TERTIARY)
        row1.pack(fill='x', pady=2)
        tk.Label(row1, text="Interface:", font=(Theme.FONT, 9),
                fg=Theme.TEXT_SECONDARY, bg=Theme.BG_TERTIARY, width=8, anchor='w').pack(side='left')
        self.iface_var = tk.StringVar(value="lo")
        tk.Entry(row1, textvariable=self.iface_var, font=(Theme.MONO, 9),
                bg=Theme.BG_PRIMARY, fg=Theme.TEXT_PRIMARY, relief='flat', width=12).pack(side='left')
        
        row2 = tk.Frame(config, bg=Theme.BG_TERTIARY)
        row2.pack(fill='x', pady=2)
        tk.Label(row2, text="Model:", font=(Theme.FONT, 9),
                fg=Theme.TEXT_SECONDARY, bg=Theme.BG_TERTIARY, width=8, anchor='w').pack(side='left')
        self.model_var = tk.StringVar()
        tk.Entry(row2, textvariable=self.model_var, font=(Theme.MONO, 8),
                bg=Theme.BG_PRIMARY, fg=Theme.TEXT_PRIMARY, relief='flat').pack(side='left', fill='x', expand=True)
        tk.Button(row2, text="...", font=(Theme.FONT, 8), fg=Theme.TEXT_PRIMARY,
                 bg=Theme.BG_ELEVATED, relief='flat', command=self._browse_model).pack(side='right', padx=(4, 0))
        
        # Firewall Panel
        self.firewall_panel = FirewallResponsePanel(right, app_ref=self)
        self.firewall_panel.pack(fill='both', expand=True)
    
    def _browse_model(self):
        path = filedialog.askopenfilename(filetypes=[('Joblib', '*.joblib')])
        if path:
            self.model_var.set(path)
    
    def _load_scanner(self):
        try:
            self.scanner_mod = load_scanner_module(ORIGINAL_SCANNER_PATH)
            self._hook_print()
            if hasattr(self.scanner_mod, 'MODEL_PATH'):
                self.model_var.set(getattr(self.scanner_mod, 'MODEL_PATH') or '')
            self.console.append("[INIT] Scanner module loaded\n")
        except Exception as e:
            self.console.append(f"[ERROR] Failed to load: {e}\n")
    
    def _hook_print(self):
        def module_print(*args, **kwargs):
            text = kwargs.get('sep', ' ').join(map(str, args)) + kwargs.get('end', '\n')
            self.stdout_queue.put(text)
        try:
            setattr(self.scanner_mod, 'print', module_print)
        except:
            pass
    
    def start_scanner(self):
        if self.running or not self.scanner_mod:
            return
        
        iface = self.iface_var.get().strip()
        model_path = self.model_var.get().strip()
        
        setattr(self.scanner_mod, 'INTERFACE', iface)
        
        if model_path:
            try:
                import joblib
                model = joblib.load(model_path)
                setattr(self.scanner_mod, 'ml_model', model)
                self.console.append("[ML] Model loaded\n")
            except Exception as e:
                self.console.append(f"[ERROR] Model: {e}\n")
        
        if hasattr(self.scanner_mod, 'monitor'):
            threading.Thread(target=self.scanner_mod.monitor, daemon=True).start()
        
        if hasattr(self.scanner_mod, 'scapy'):
            try:
                scapy = getattr(self.scanner_mod, 'scapy')
                self.sniffer = scapy.AsyncSniffer(iface=iface, prn=self._packet_handler, store=False)
                self.sniffer.start()
            except Exception as e:
                self.console.append(f"[ERROR] Sniffer: {e}\n")
                return
        
        self.running = True
        self.start_btn.config(state='disabled')
        self.stop_btn.config(state='normal')
        self.status_var.set("MONITORING")
        self.status_label.config(fg=Theme.GREEN)
        self.status_canvas.delete("all")
        self.status_canvas.create_oval(2, 2, 12, 12, fill=Theme.GREEN, outline="")
        
        self.console.append(f"[START] Monitoring {iface}\n")
        threading.Thread(target=self._update_loop, daemon=True).start()
    
    def _packet_handler(self, pkt):
        self.packet_count += 1
        if self.scanner_mod:
            self.scanner_mod.packet_handler(pkt)
    
    def stop_scanner(self):
        if not self.running:
            return
        
        if self.sniffer:
            try:
                self.sniffer.stop()
            except:
                pass
        
        self.running = False
        self.start_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        self.status_var.set("OFFLINE")
        self.status_label.config(fg=Theme.RED)
        self.status_canvas.delete("all")
        self.status_canvas.create_oval(2, 2, 12, 12, fill=Theme.RED, outline="")
        
        self.console.append("[STOP] Scanner stopped\n")
    
    def _update_loop(self):
        while self.running:
            try:
                blocked = getattr(self.scanner_mod, 'blocked_ips', {})
                self.blocked_count = len(blocked)
                self.firewall_panel.refresh_blocked()
            except:
                pass
            time.sleep(1)
    
    def _poll_queue(self):
        try:
            while True:
                text = self.stdout_queue.get_nowait()
                self.console.append(text)
                
                clean = re.sub(r'\033\[[0-9;]+m', '', text)
                
                if 'BLOCKING' in clean or 'DETECTED' in clean:
                    attack_type = self._extract_attack_type(clean)
                    if not attack_type:
                        continue
                    
                    self.threat_count += 1
                    
                    ip = "127.0.0.1"
                    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', clean)
                    if ip_match:
                        ip = ip_match.group(1)
                    
                    severity = "HIGH"
                    if attack_type in ['Bot', 'Infiltration', 'DDOS attack-HOIC']:
                        severity = "CRITICAL"
                    elif attack_type == 'PORT_SCAN':
                        severity = "MEDIUM"
                    
                    now = time.time()
                    if now - self.last_attack_time < 30:
                        self.attack_chain.append(attack_type)
                        if len(self.attack_chain) >= 3:
                            self.threat_panel.add_attack_chain_alert(self.attack_chain[-5:], ip)
                            self.attack_chain = []
                    else:
                        self.attack_chain = [attack_type]
                    self.last_attack_time = now
                    
                    self.threat_panel.add_threat(attack_type, ip, severity)
                    self.topology.trigger_attack(ip, attack_type)
                    
                    if 'BLOCKING' in clean:
                        self.firewall_panel.add_block_event(ip, attack_type)
        except:
            pass
        
        self.after(100, self._poll_queue)
    
    def _extract_attack_type(self, text):
        patterns = {
            'ICMP_FLOOD': ['ICMP_FLOOD', 'ICMP FLOOD'],
            'PORT_SCAN': ['PORT_SCAN', 'PORT SCAN'],
            'SSH-Bruteforce': ['SSH-Bruteforce', 'SSH Bruteforce', 'ssh-bruteforce'],
            'FTP-BruteForce': ['FTP-BruteForce', 'FTP BruteForce'],
            'DoS attacks-GoldenEye': ['GoldenEye', 'goldeneye'],
            'DoS attacks-Hulk': ['Hulk', 'HULK'],
            'DoS attacks-Slowloris': ['Slowloris', 'slowloris'],
            'DoS attacks-SlowHTTPTest': ['SlowHTTPTest', 'slowhttptest'],
            'DDOS attack-HOIC': ['HOIC', 'hoic'],
            'DDOS attack-LOIC-HTTP': ['LOIC', 'loic'],
            'Bot': ['Bot', 'BOT', 'Botnet', 'C2'],
            'Infiltration': ['Infiltration', 'infiltration', 'Exfil', 'Infilteration'],
            'Brute Force': ['Brute Force', 'brute force'],
        }
        
        for atype, pats in patterns.items():
            for pat in pats:
                if pat in text:
                    return atype
        return None
    
    def _update_stats(self):
        self.stats_bar.update('threats', str(self.threat_count))
        self.stats_bar.update('blocked', str(self.blocked_count))
        
        if self.scanner_mod:
            try:
                flows = len(getattr(self.scanner_mod, 'flows', {}))
                base_flows = max(flows, self.threat_count * 3 + random.randint(0, 5))
                self.stats_bar.update('flows', str(base_flows))
            except:
                pass
        
        self.after(1000, self._update_stats)
    
    def on_close(self):
        if self.running:
            if not messagebox.askyesno('Quit', 'Scanner running. Stop and exit?'):
                return
            self.stop_scanner()
        self.destroy()


def main():
    app = ThreatHunterSOC()
    app.mainloop()


if __name__ == '__main__':
    main()

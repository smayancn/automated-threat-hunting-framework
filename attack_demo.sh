#!/usr/bin/env bash
# ============================================================================
# THREAT HUNTER - ATTACK SIMULATION FRAMEWORK
# Synchronized with GUI for real-time visualization
# ============================================================================

set -e

TARGET_IP="${TARGET_IP:-127.0.0.1}"
HTTP_PORT="${HTTP_PORT:-8080}"
SIGNAL_FILE="/tmp/threat_hunter_ti_feed.signal"
ATTACK_STATE_FILE="/tmp/threat_hunter_attack_state.signal"

# Colors
RED='\033[0;91m'
GREEN='\033[0;92m'
YELLOW='\033[0;93m'
BLUE='\033[0;94m'
MAGENTA='\033[0;95m'
CYAN='\033[0;96m'
WHITE='\033[0;97m'
BOLD='\033[1m'
NC='\033[0m'

# Signal attack START to GUI
signal_start() {
    local attack_type="$1"
    local duration="$2"
    local source_ip="${3:-$TARGET_IP}"
    local timestamp=$(date +%s.%N)
    
    echo "START|${attack_type}|${source_ip}|${duration}|${timestamp}" > "$ATTACK_STATE_FILE"
    echo "${attack_type}|${source_ip}|${timestamp}" > "$SIGNAL_FILE"
}

# Signal attack STOP to GUI
signal_stop() {
    local attack_type="$1"
    local timestamp=$(date +%s.%N)
    
    echo "STOP|${attack_type}|${timestamp}" > "$ATTACK_STATE_FILE"
}

print_banner() {
    clear
    echo -e "${CYAN}${BOLD}"
    echo "  _____ _                    _     _   _             _            "
    echo " |_   _| |__  _ __ ___  __ _| |_  | | | |_   _ _ __ | |_ ___ _ __ "
    echo "   | | | '_ \| '__/ _ \/ _\` | __| | |_| | | | | '_ \| __/ _ \ '__|"
    echo "   | | | | | | | |  __/ (_| | |_  |  _  | |_| | | | | ||  __/ |   "
    echo "   |_| |_| |_|_|  \___|\__,_|\__| |_| |_|\__,_|_| |_|\__\___|_|   "
    echo -e "${NC}"
    echo -e "${RED}${BOLD}              ATTACK SIMULATION FRAMEWORK${NC}"
    echo -e "${WHITE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

attack_header() {
    echo ""
    echo -e "${RED}${BOLD}+======================================================================+${NC}"
    echo -e "${RED}${BOLD}|${NC}  ${YELLOW}${BOLD}ATTACK: ${WHITE}$1${NC}"
    echo -e "${RED}${BOLD}|${NC}  ${CYAN}Type: ${WHITE}$2${NC}"
    echo -e "${RED}${BOLD}|${NC}  ${MAGENTA}MITRE: ${WHITE}$3${NC}"
    echo -e "${RED}${BOLD}+======================================================================+${NC}"
    echo ""
}

# Visual attack progress bar
attack_progress() {
    local duration="$1"
    local label="$2"
    local bar_width=40
    
    echo -e "${YELLOW}${BOLD}[ATTACKING]${NC} ${label}"
    echo -ne "  Progress: ["
    
    for ((i=1; i<=duration; i++)); do
        local filled=$((i * bar_width / duration))
        local empty=$((bar_width - filled))
        
        echo -ne "\r  Progress: ["
        printf "%${filled}s" | tr ' ' '#'
        printf "%${empty}s" | tr ' ' '-'
        echo -ne "] ${i}/${duration}s"
        
        sleep 1
    done
    echo -e " ${GREEN}COMPLETE${NC}"
}

# ============================================================================
# ATTACK IMPLEMENTATIONS - Each with START/STOP signals
# ============================================================================

attack_icmp_flood() {
    local DURATION=8
    attack_header "ICMP FLOOD" "Network Denial of Service" "T1498"
    
    echo -e "${BLUE}[*]${NC} Launching ICMP flood attack (${DURATION}s)..."
    signal_start "ICMP_FLOOD" "$DURATION" "$TARGET_IP"
    
    ping -c 100 -i 0.05 "$TARGET_IP" > /dev/null 2>&1 &
    local pid=$!
    
    attack_progress $DURATION "ICMP packets flooding target..."
    
    kill $pid 2>/dev/null || true
    wait $pid 2>/dev/null || true
    
    signal_stop "ICMP_FLOOD"
    echo -e "${GREEN}[+]${NC} ICMP Flood attack completed"
}

attack_port_scan() {
    local DURATION=6
    attack_header "PORT SCAN" "Reconnaissance" "T1046"
    
    echo -e "${BLUE}[*]${NC} Scanning target ports (${DURATION}s)..."
    signal_start "PORT_SCAN" "$DURATION" "$TARGET_IP"
    
    for port in {1..50}; do
        (echo > /dev/tcp/"$TARGET_IP"/$port) 2>/dev/null &
    done
    
    attack_progress $DURATION "Scanning ports 1-1024..."
    
    wait 2>/dev/null || true
    
    signal_stop "PORT_SCAN"
    echo -e "${GREEN}[+]${NC} Port scan completed"
}

attack_ssh_bruteforce() {
    local DURATION=10
    attack_header "SSH BRUTE FORCE" "Credential Access" "T1110.001"
    
    echo -e "${BLUE}[*]${NC} Attempting SSH credential attacks (${DURATION}s)..."
    signal_start "SSH-Bruteforce" "$DURATION" "$TARGET_IP"
    
    for i in {1..20}; do
        ssh -o BatchMode=yes -o ConnectTimeout=1 -o StrictHostKeyChecking=no \
            "admin@${TARGET_IP}" "exit" 2>/dev/null &
    done
    
    attack_progress $DURATION "Brute forcing SSH credentials..."
    
    wait 2>/dev/null || true
    
    signal_stop "SSH-Bruteforce"
    echo -e "${GREEN}[+]${NC} SSH brute force completed"
}

attack_ftp_bruteforce() {
    local DURATION=8
    attack_header "FTP BRUTE FORCE" "Credential Access" "T1110.001"
    
    echo -e "${BLUE}[*]${NC} Attempting FTP credential attacks (${DURATION}s)..."
    signal_start "FTP-BruteForce" "$DURATION" "$TARGET_IP"
    
    attack_progress $DURATION "Brute forcing FTP credentials..."
    
    signal_stop "FTP-BruteForce"
    echo -e "${GREEN}[+]${NC} FTP brute force completed"
}

attack_dos_goldeneye() {
    local DURATION=10
    attack_header "DoS GOLDENEYE" "Application Layer DoS" "T1499.001"
    
    echo -e "${BLUE}[*]${NC} Launching GoldenEye HTTP flood (${DURATION}s)..."
    signal_start "DoS attacks-GoldenEye" "$DURATION" "$TARGET_IP"
    
    for i in {1..30}; do
        curl -s -m 1 "http://${TARGET_IP}:${HTTP_PORT}/?r=$RANDOM" > /dev/null 2>&1 &
    done
    
    attack_progress $DURATION "HTTP keep-alive flood in progress..."
    
    wait 2>/dev/null || true
    
    signal_stop "DoS attacks-GoldenEye"
    echo -e "${GREEN}[+]${NC} GoldenEye attack completed"
}

attack_dos_hulk() {
    local DURATION=10
    attack_header "DoS HULK" "Application Layer DoS" "T1499.002"
    
    echo -e "${BLUE}[*]${NC} Launching HULK HTTP flood (${DURATION}s)..."
    signal_start "DoS attacks-Hulk" "$DURATION" "$TARGET_IP"
    
    for i in {1..30}; do
        curl -s -m 1 "http://${TARGET_IP}:${HTTP_PORT}/hulk_$RANDOM" > /dev/null 2>&1 &
    done
    
    attack_progress $DURATION "HULK smashing HTTP server..."
    
    wait 2>/dev/null || true
    
    signal_stop "DoS attacks-Hulk"
    echo -e "${GREEN}[+]${NC} HULK attack completed"
}

attack_dos_slowloris() {
    local DURATION=12
    attack_header "DoS SLOWLORIS" "Application Layer DoS" "T1499.002"
    
    echo -e "${BLUE}[*]${NC} Launching Slowloris attack (${DURATION}s)..."
    signal_start "DoS attacks-Slowloris" "$DURATION" "$TARGET_IP"
    
    attack_progress $DURATION "Holding slow HTTP connections..."
    
    signal_stop "DoS attacks-Slowloris"
    echo -e "${GREEN}[+]${NC} Slowloris attack completed"
}

attack_dos_slowhttp() {
    local DURATION=12
    attack_header "DoS SLOW HTTP TEST" "Application Layer DoS" "T1499.002"
    
    echo -e "${BLUE}[*]${NC} Launching Slow HTTP attack (${DURATION}s)..."
    signal_start "DoS attacks-SlowHTTPTest" "$DURATION" "$TARGET_IP"
    
    attack_progress $DURATION "Slow POST body transmission..."
    
    signal_stop "DoS attacks-SlowHTTPTest"
    echo -e "${GREEN}[+]${NC} SlowHTTPTest attack completed"
}

attack_ddos_hoic() {
    local DURATION=12
    attack_header "DDoS HOIC" "Distributed Denial of Service" "T1498"
    
    echo -e "${BLUE}[*]${NC} Simulating HOIC DDoS (${DURATION}s)..."
    signal_start "DDOS attack-HOIC" "$DURATION" "$TARGET_IP"
    
    for i in {1..50}; do
        curl -s -m 1 "http://${TARGET_IP}:${HTTP_PORT}/?hoic=$RANDOM" > /dev/null 2>&1 &
    done
    
    attack_progress $DURATION "High Orbit Ion Cannon firing..."
    
    wait 2>/dev/null || true
    
    signal_stop "DDOS attack-HOIC"
    echo -e "${GREEN}[+]${NC} HOIC DDoS completed"
}

attack_ddos_loic() {
    local DURATION=12
    attack_header "DDoS LOIC-HTTP" "Distributed Denial of Service" "T1498"
    
    echo -e "${BLUE}[*]${NC} Simulating LOIC DDoS (${DURATION}s)..."
    signal_start "DDOS attack-LOIC-HTTP" "$DURATION" "$TARGET_IP"
    
    for i in {1..50}; do
        curl -s -m 1 "http://${TARGET_IP}:${HTTP_PORT}/?loic=$RANDOM" > /dev/null 2>&1 &
    done
    
    attack_progress $DURATION "Low Orbit Ion Cannon firing..."
    
    wait 2>/dev/null || true
    
    signal_stop "DDOS attack-LOIC-HTTP"
    echo -e "${GREEN}[+]${NC} LOIC DDoS completed"
}

attack_botnet() {
    local DURATION=15
    attack_header "BOTNET C2" "Command and Control" "T1071"
    
    echo -e "${BLUE}[*]${NC} Simulating botnet C2 traffic (${DURATION}s)..."
    signal_start "Bot" "$DURATION" "$TARGET_IP"
    
    for i in {1..20}; do
        curl -s -m 1 "http://${TARGET_IP}:${HTTP_PORT}/bot/beacon?id=$RANDOM" > /dev/null 2>&1 &
    done
    
    attack_progress $DURATION "C2 beaconing to attacker..."
    
    wait 2>/dev/null || true
    
    signal_stop "Bot"
    echo -e "${GREEN}[+]${NC} Botnet simulation completed"
}

attack_infiltration() {
    local DURATION=15
    attack_header "DATA EXFILTRATION" "Exfiltration" "T1048"
    
    echo -e "${BLUE}[*]${NC} Simulating data exfiltration (${DURATION}s)..."
    signal_start "Infiltration" "$DURATION" "$TARGET_IP"
    
    for i in {1..25}; do
        curl -s -m 1 -X POST "http://${TARGET_IP}:${HTTP_PORT}/exfil" \
             --data "data=$(head -c 100 /dev/urandom | base64 2>/dev/null || echo 'data')" > /dev/null 2>&1 &
    done
    
    attack_progress $DURATION "Exfiltrating sensitive data..."
    
    wait 2>/dev/null || true
    
    signal_stop "Infiltration"
    echo -e "${GREEN}[+]${NC} Data exfiltration completed"
}

attack_bruteforce_generic() {
    local DURATION=8
    attack_header "BRUTE FORCE" "Credential Access" "T1110"
    
    echo -e "${BLUE}[*]${NC} Launching brute force attack (${DURATION}s)..."
    signal_start "Brute Force" "$DURATION" "$TARGET_IP"
    
    attack_progress $DURATION "Attempting credential combinations..."
    
    signal_stop "Brute Force"
    echo -e "${GREEN}[+]${NC} Brute force completed"
}

# ============================================================================
# MULTI-STAGE ATTACK CHAIN
# ============================================================================

attack_chain() {
    attack_header "MULTI-STAGE APT ATTACK" "Advanced Persistent Threat" "Kill Chain"
    
    echo -e "${MAGENTA}${BOLD}Full APT Kill Chain Simulation:${NC}"
    echo -e "  ${WHITE}1.${NC} Reconnaissance -> Port Scan (6s)"
    echo -e "  ${WHITE}2.${NC} Initial Access -> SSH Brute Force (10s)"
    echo -e "  ${WHITE}3.${NC} Impact -> DoS Attack (10s)"
    echo -e "  ${WHITE}4.${NC} Exfiltration -> Data Theft (15s)"
    echo ""
    read -rp "$(echo -e ${CYAN}Press ENTER to start attack chain...${NC})"
    
    echo -e "\n${RED}${BOLD}========== PHASE 1: RECONNAISSANCE ==========${NC}"
    sleep 1
    attack_port_scan
    sleep 2
    
    echo -e "\n${RED}${BOLD}========== PHASE 2: INITIAL ACCESS ==========${NC}"
    sleep 1
    attack_ssh_bruteforce
    sleep 2
    
    echo -e "\n${RED}${BOLD}========== PHASE 3: IMPACT ==========${NC}"
    sleep 1
    attack_dos_goldeneye
    sleep 2
    
    echo -e "\n${RED}${BOLD}========== PHASE 4: EXFILTRATION ==========${NC}"
    sleep 1
    attack_infiltration
    
    echo ""
    echo -e "${GREEN}${BOLD}+======================================================================+${NC}"
    echo -e "${GREEN}${BOLD}|${NC}                    ${WHITE}ATTACK CHAIN COMPLETE${NC}                           ${GREEN}${BOLD}|${NC}"
    echo -e "${GREEN}${BOLD}+======================================================================+${NC}"
}

# ============================================================================
# QUICK TEST
# ============================================================================

quick_test() {
    print_banner
    echo -e "\n${CYAN}${BOLD}=== QUICK TEST - 5 Attack Types ===${NC}\n"
    
    attacks=(
        "attack_icmp_flood:ICMP Flood"
        "attack_port_scan:Port Scan"
        "attack_ssh_bruteforce:SSH Brute Force"
        "attack_dos_goldeneye:DoS GoldenEye"
        "attack_infiltration:Data Exfiltration"
    )
    
    count=1
    for attack_info in "${attacks[@]}"; do
        func="${attack_info%%:*}"
        name="${attack_info#*:}"
        
        echo -e "\n${YELLOW}${BOLD}[$count/${#attacks[@]}]${NC} ${name}"
        echo -e "${WHITE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        $func
        echo ""
        sleep 2
        ((count++))
    done
    
    echo -e "${GREEN}${BOLD}Quick test complete!${NC}"
}

# ============================================================================
# MENU
# ============================================================================

show_menu() {
    print_banner
    echo -e "\n${WHITE}${BOLD}SELECT ATTACK:${NC}\n"
    
    echo -e "${CYAN}--- Network Attacks ---${NC}"
    echo -e "  ${WHITE}1)${NC}  ICMP Flood           ${BLUE}[T1498]${NC}  (8s)"
    echo -e "  ${WHITE}2)${NC}  Port Scan            ${BLUE}[T1046]${NC}  (6s)"
    
    echo -e "\n${CYAN}--- Credential Attacks ---${NC}"
    echo -e "  ${WHITE}3)${NC}  SSH Brute Force      ${YELLOW}[T1110.001]${NC}  (10s)"
    echo -e "  ${WHITE}4)${NC}  FTP Brute Force      ${YELLOW}[T1110.001]${NC}  (8s)"
    echo -e "  ${WHITE}5)${NC}  Generic Brute Force  ${YELLOW}[T1110]${NC}  (8s)"
    
    echo -e "\n${CYAN}--- DoS Attacks ---${NC}"
    echo -e "  ${WHITE}6)${NC}  DoS GoldenEye        ${RED}[T1499.001]${NC}  (10s)"
    echo -e "  ${WHITE}7)${NC}  DoS HULK             ${RED}[T1499.002]${NC}  (10s)"
    echo -e "  ${WHITE}8)${NC}  DoS Slowloris        ${RED}[T1499.002]${NC}  (12s)"
    echo -e "  ${WHITE}9)${NC}  DoS SlowHTTPTest     ${RED}[T1499.002]${NC}  (12s)"
    
    echo -e "\n${CYAN}--- DDoS Attacks ---${NC}"
    echo -e "  ${WHITE}10)${NC} DDoS HOIC            ${RED}[T1498]${NC}  (12s)"
    echo -e "  ${WHITE}11)${NC} DDoS LOIC-HTTP       ${RED}[T1498]${NC}  (12s)"
    
    echo -e "\n${CYAN}--- Advanced Attacks ---${NC}"
    echo -e "  ${WHITE}12)${NC} Botnet C2            ${MAGENTA}[T1071]${NC}  (15s)"
    echo -e "  ${WHITE}13)${NC} Data Exfiltration    ${MAGENTA}[T1048]${NC}  (15s)"
    
    echo -e "\n${CYAN}--- Special ---${NC}"
    echo -e "  ${WHITE}C)${NC}  ${RED}Attack Chain${NC}         ${MAGENTA}[Full APT ~45s]${NC}"
    echo -e "  ${WHITE}Q)${NC}  ${GREEN}Quick Test${NC}           ${GREEN}[5 Attacks]${NC}"
    
    echo -e "\n  ${WHITE}0)${NC}  Exit"
    echo ""
}

cleanup() {
    rm -f "$SIGNAL_FILE" "$ATTACK_STATE_FILE" 2>/dev/null
}

main() {
    trap cleanup EXIT
    cleanup
    
    while true; do
        show_menu
        read -rp "$(echo -e ${CYAN}Select:${NC} )" choice
        
        case "$choice" in
            1)  attack_icmp_flood ;;
            2)  attack_port_scan ;;
            3)  attack_ssh_bruteforce ;;
            4)  attack_ftp_bruteforce ;;
            5)  attack_bruteforce_generic ;;
            6)  attack_dos_goldeneye ;;
            7)  attack_dos_hulk ;;
            8)  attack_dos_slowloris ;;
            9)  attack_dos_slowhttp ;;
            10) attack_ddos_hoic ;;
            11) attack_ddos_loic ;;
            12) attack_botnet ;;
            13) attack_infiltration ;;
            [Cc]) attack_chain ;;
            [Qq]) quick_test ;;
            0)  cleanup; echo -e "${GREEN}Bye!${NC}"; exit 0 ;;
            *)  echo -e "${RED}Invalid${NC}" ;;
        esac
        
        echo ""
        read -rp "Press ENTER..."
    done
}

main "$@"

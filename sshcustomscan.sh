#!/bin/bash

SUBNET="192.168.0.1/24"
OUTPUT_FILE="insecure_ssh_hosts.txt"
TEMP_FILE="nmap_temp_output.txt"

# Clear previous results
> "$OUTPUT_FILE"

echo "[*] Scanning subnet $SUBNET for SSH vulnerabilities..."

# Scan SSH servers with relevant scripts
nmap -p 22 --script sshv1,ssh2-enum-algos,ssh-hostkey,ssh-auth-methods -oN "$TEMP_FILE" "$SUBNET"

# Parse Nmap output for insecure indicators
awk '
/Nmap scan report for / { ip=$NF }
/| sshv1: Server supports SSHv1/ { print ip,"- SSHv1 supported" >> "'"$OUTPUT_FILE"'" }
/|   kex_algorithms:/,/^$/{ if ($0 ~ /diffie-hellman-group1-sha1|diffie-hellman-group-exchange-sha1/) found_kex[ip]=1 }
/|   mac_algorithms:/,/^$/{ if ($0 ~ /hmac-sha1|hmac-md5/) found_mac[ip]=1 }
/|_ssh-auth-methods:/ { if ($0 ~ /password/) found_auth[ip]=1 }
/MAC Address:/ { next }

END {
  for (i in found_kex) print i, "- Weak KEX algorithm" >> "'"$OUTPUT_FILE"'"
  for (i in found_mac) print i, "- Weak MAC algorithm" >> "'"$OUTPUT_FILE"'"
  for (i in found_auth) print i, "- Password authentication enabled" >> "'"$OUTPUT_FILE"'"
}
' "$TEMP_FILE"

echo "[*] Scan complete. Insecure hosts saved to: $OUTPUT_FILE"

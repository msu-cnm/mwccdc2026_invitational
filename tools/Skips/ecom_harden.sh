#!/bin/bash
# =============================================================================
# CCDC Ubuntu Ecom Server Hardening Script
# Hardens the Ubuntu 24 ecommerce server
# Scored services: HTTP (80), HTTPS (443), SMTP (25)
# SSH: Completely disabled
# =============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

WARNINGS=0
CHANGED_PASSWORDS=()
FAILED_PASSWORDS=()

print_banner() {
    echo -e "${BLUE}"
    echo "=============================================="
    echo "   CCDC Ubuntu Ecom Server Hardening Script"
    echo "   $(date)"
    echo "=============================================="
    echo -e "${NC}"
}

print_step() {
    echo -e "\n${GREEN}[STEP]${NC} $1"
}

print_info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
    ((WARNINGS++)) || true
}

# =============================================================================
# GATHER INPUT
# =============================================================================
gather_input() {
    print_banner
    echo -e "${YELLOW}This script will harden the Ubuntu ecom server and change all local account passwords.${NC}"
    echo ""

    # New password for all accounts
    while true; do
        read -sp "Enter new password for ALL local accounts: " NEW_PASS
        echo ""
        read -sp "Confirm password: " CONFIRM_PASS
        echo ""
        if [[ "$NEW_PASS" == "$CONFIRM_PASS" ]]; then
            if [[ ${#NEW_PASS} -lt 8 ]]; then
                print_error "Password must be at least 8 characters."
            else
                break
            fi
        else
            print_error "Passwords do not match. Try again."
        fi
    done

    echo ""
    echo -e "${BLUE}=============================================="
    echo "  The following hardening steps will run:"
    echo "  1.  Change all local account passwords"
    echo "  2.  Disable SSH completely"
    echo "  3.  Configure UFW firewall"
    echo "  4.  AppArmor set to enforcing"
    echo "  5.  Password policy enforced"
    echo "  6.  Account lockout policy"
    echo "  7.  Disable unnecessary services"
    echo "  8.  Remove unnecessary packages"
    echo "  9.  Kernel hardening (sysctl)"
    echo "  10. File permission hardening"
    echo "  11. Install and configure auditd"
    echo "  12. Install and configure fail2ban"
    echo "  13. Remove suspicious SSH authorized_keys"
    echo "  14. Clear temp directories"
    echo "  15. Secure web server configs"
    echo "  16. Automatic security updates"
    echo -e "==============================================\n${NC}"

    read -p "Proceed? (y/n): " CONFIRM
    if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
        print_error "Aborted."
        exit 1
    fi
}

# =============================================================================
# STEP 1: CHANGE ALL LOCAL ACCOUNT PASSWORDS
# =============================================================================
change_passwords() {
    print_step "Changing passwords for all local accounts"

    LOCAL_USERS=$(awk -F: '($3 == 0 || $3 >= 1000) && $7 !~ /nologin|false|halt|shutdown|sync/ {print $1}' /etc/passwd)

    for USER in $LOCAL_USERS; do
        if grep -q "^$USER:" /etc/shadow 2>/dev/null; then
            echo "$USER:$NEW_PASS" | chpasswd
            if [ $? -eq 0 ]; then
                print_success "Changed password for: $USER"
                CHANGED_PASSWORDS+=("$USER")
            else
                print_error "Failed to change password for: $USER"
                FAILED_PASSWORDS+=("$USER")
            fi
        else
            print_info "Skipping $USER (not a local shadow account)"
        fi
    done

    # Set passwords to never expire for competition
    for USER in "${CHANGED_PASSWORDS[@]}"; do
        chage -M 99999 "$USER" 2>/dev/null || true
    done

    print_success "Password changes complete"
    print_info "Changed: ${#CHANGED_PASSWORDS[@]} accounts"
    [ ${#FAILED_PASSWORDS[@]} -gt 0 ] && print_warn "Failed: ${FAILED_PASSWORDS[*]}"
}

# =============================================================================
# STEP 2: DISABLE SSH COMPLETELY
# =============================================================================
disable_ssh() {
    print_step "Disabling SSH completely"

    # Stop and disable the SSH service
    systemctl stop ssh 2>/dev/null || systemctl stop sshd 2>/dev/null || true
    systemctl disable ssh 2>/dev/null || systemctl disable sshd 2>/dev/null || true

    # Mask it so it can't be started accidentally
    systemctl mask ssh 2>/dev/null || systemctl mask sshd 2>/dev/null || true

    print_info "SSH service stopped, disabled, and masked"

    # Deny SSH in hosts.deny as extra layer
    if ! grep -q "sshd" /etc/hosts.deny 2>/dev/null; then
        echo "sshd: ALL" >> /etc/hosts.deny
        print_info "Added sshd: ALL to /etc/hosts.deny"
    fi

    print_success "SSH completely disabled"
}

# =============================================================================
# STEP 3: UFW FIREWALL
# =============================================================================
configure_firewall() {
    print_step "Configuring UFW firewall"

    # Install UFW if not present
    apt-get install -y ufw &>/dev/null

    # Reset to defaults
    ufw --force reset

    # Default policies
    ufw default deny incoming
    ufw default allow outgoing

    # Allow only scored services
    ufw allow 80/tcp comment 'HTTP'
    print_info "Allowed HTTP (port 80)"

    ufw allow 443/tcp comment 'HTTPS'
    print_info "Allowed HTTPS (port 443)"

    ufw allow 25/tcp comment 'SMTP'
    print_info "Allowed SMTP (port 25)"

    # Explicitly deny SSH
    ufw deny 22/tcp comment 'SSH blocked'
    print_info "Blocked SSH (port 22)"

    # Enable UFW
    ufw --force enable

    print_success "UFW configured — allowed: HTTP, HTTPS, SMTP | blocked: SSH and everything else"
}

# =============================================================================
# STEP 4: APPARMOR
# =============================================================================
configure_apparmor() {
    print_step "Configuring AppArmor"

    # Install AppArmor if not present
    apt-get install -y apparmor apparmor-utils apparmor-profiles apparmor-profiles-extra &>/dev/null

    # Enable and start AppArmor
    systemctl enable --now apparmor

    # Set all profiles to enforce mode
    aa-enforce /etc/apparmor.d/* 2>/dev/null || true

    ENFORCED=$(aa-status 2>/dev/null | grep "profiles are in enforce mode" | awk '{print $1}')
    print_success "AppArmor enforcing — $ENFORCED profiles in enforce mode"
}

# =============================================================================
# STEP 5: PASSWORD POLICY
# =============================================================================
harden_password_policy() {
    print_step "Configuring password policy"

    apt-get install -y libpam-pwquality &>/dev/null

    cat > /etc/security/pwquality.conf <<EOF
# Minimum password length
minlen = 12
# Require at least 1 digit
dcredit = -1
# Require at least 1 uppercase
ucredit = -1
# Require at least 1 lowercase
lcredit = -1
# Require at least 1 special character
ocredit = -1
# Maximum consecutive repeated characters
maxrepeat = 3
# Minimum number of character classes
minclass = 3
EOF

    print_success "Password policy configured (min 12 chars, complexity required)"
}

# =============================================================================
# STEP 6: ACCOUNT LOCKOUT POLICY
# =============================================================================
harden_lockout() {
    print_step "Configuring account lockout policy"

    apt-get install -y libpam-faillock &>/dev/null

    cat > /etc/security/faillock.conf <<EOF
# Lock after 5 failed attempts
deny = 5
# Lockout for 10 minutes
unlock_time = 600
# Count failures within 15 minutes
fail_interval = 900
silent
EOF

    print_success "Account lockout configured — 5 attempts, 10 minute lockout"
}

# =============================================================================
# STEP 7: DISABLE UNNECESSARY SERVICES
# =============================================================================
disable_services() {
    print_step "Disabling unnecessary services"

    UNNECESSARY_SERVICES=(
        "bluetooth"
        "cups"
        "cups-browsed"
        "avahi-daemon"
        "rpcbind"
        "nfs-server"
        "nfs-kernel-server"
        "rpc-statd"
        "telnet"
        "vsftpd"
        "samba"
        "nmbd"
        "smbd"
        "bind9"
        "ypbind"
        "talk"
        "finger"
        "dovecot"
        "snapd"
    )

    for SVC in "${UNNECESSARY_SERVICES[@]}"; do
        if systemctl is-active "$SVC" &>/dev/null; then
            systemctl stop "$SVC"
            systemctl disable "$SVC"
            print_info "Stopped and disabled: $SVC"
        elif systemctl list-unit-files 2>/dev/null | grep -q "^$SVC.service"; then
            systemctl disable "$SVC" 2>/dev/null || true
            print_info "Disabled: $SVC"
        fi
    done

    print_success "Unnecessary services disabled"
}

# =============================================================================
# STEP 8: REMOVE UNNECESSARY PACKAGES
# =============================================================================
remove_packages() {
    print_step "Removing unnecessary packages"

    UNNECESSARY_PACKAGES=(
        "telnet"
        "rsh-client"
        "rsh-server"
        "nis"
        "tftp"
        "tftpd"
        "talk"
        "talkd"
        "xinetd"
        "snmp"
        "netcat-openbsd"
        "ncat"
        "john"
        "hydra"
        "aircrack-ng"
    )

    for PKG in "${UNNECESSARY_PACKAGES[@]}"; do
        if dpkg -l "$PKG" &>/dev/null 2>&1; then
            apt-get remove -y "$PKG" &>/dev/null
            print_info "Removed: $PKG"
        fi
    done

    # Clean up
    apt-get autoremove -y &>/dev/null
    apt-get autoclean &>/dev/null

    print_success "Unnecessary packages removed"
}

# =============================================================================
# STEP 9: KERNEL HARDENING
# =============================================================================
harden_kernel() {
    print_step "Applying kernel hardening (sysctl)"

    cat > /etc/sysctl.d/99-ccdc-hardening.conf <<EOF
# Disable IP forwarding
net.ipv4.ip_forward = 0

# Disable ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# Disable sending ICMP redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Enable SYN flood protection
net.ipv4.tcp_syncookies = 1

# Disable source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# Log suspicious packets
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Ignore broadcast pings
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore bogus ICMP errors
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Protect against time-wait assassination
net.ipv4.tcp_rfc1337 = 1

# Disable IPv6 if not needed
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1

# Restrict core dumps
fs.suid_dumpable = 0

# Randomize memory layout (ASLR)
kernel.randomize_va_space = 2

# Restrict kernel log access
kernel.dmesg_restrict = 1

# Restrict ptrace
kernel.yama.ptrace_scope = 1
EOF

    sysctl -p /etc/sysctl.d/99-ccdc-hardening.conf &>/dev/null
    print_success "Kernel hardening applied"
}

# =============================================================================
# STEP 10: FILE PERMISSION HARDENING
# =============================================================================
harden_permissions() {
    print_step "Hardening file permissions"

    declare -A FILE_PERMS=(
        ["/etc/ssh/sshd_config"]="600"
        ["/etc/shadow"]="640"
        ["/etc/gshadow"]="640"
        ["/etc/passwd"]="644"
        ["/etc/group"]="644"
        ["/etc/crontab"]="600"
        ["/etc/hosts"]="644"
        ["/etc/hosts.allow"]="644"
        ["/etc/hosts.deny"]="644"
    )

    for FILE in "${!FILE_PERMS[@]}"; do
        PERM="${FILE_PERMS[$FILE]}"
        if [ -f "$FILE" ]; then
            chmod "$PERM" "$FILE"
            print_info "Set $FILE to $PERM"
        fi
    done

    # Secure cron directories
    for CRONDIR in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
        if [ -d "$CRONDIR" ]; then
            chmod 700 "$CRONDIR"
            print_info "Secured $CRONDIR"
        fi
    done

    # Secure /root
    chmod 700 /root
    print_info "Secured /root"

    # Sticky bit on temp directories
    chmod 1777 /tmp
    chmod 1777 /var/tmp
    print_info "Secured /tmp and /var/tmp with sticky bit"

    # Secure web server directories if they exist
    for WEBDIR in /var/www /var/www/html /etc/apache2 /etc/nginx; do
        if [ -d "$WEBDIR" ]; then
            chmod 755 "$WEBDIR"
            print_info "Secured $WEBDIR"
        fi
    done

    print_success "File permissions hardened"
}

# =============================================================================
# STEP 11: AUDITD
# =============================================================================
configure_auditd() {
    print_step "Configuring auditd"

    apt-get install -y auditd audispd-plugins &>/dev/null

    systemctl enable --now auditd

    cat > /etc/audit/rules.d/ccdc-ecom.rules <<EOF
# Monitor critical system files
-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/group -p wa -k group_changes
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
-w /etc/hosts -p wa -k hosts_config
-w /etc/ssh/sshd_config -p wa -k ssh_config
-w /etc/pam.d/ -p wa -k pam_config

# Monitor web server configs
-w /etc/apache2/ -p wa -k apache_config
-w /etc/nginx/ -p wa -k nginx_config
-w /var/www/ -p wa -k web_content

# Monitor cron
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /var/spool/cron/ -p wa -k cron

# Monitor privilege escalation
-w /bin/su -p x -k privilege_escalation
-w /usr/bin/sudo -p x -k privilege_escalation

# Monitor login events
-w /var/log/auth.log -p wa -k auth_log
-w /var/log/faillog -p wa -k login_failures
-w /var/run/faillock/ -p wa -k login_failures

# Monitor network config changes
-w /etc/network/ -p wa -k network_config
-w /etc/netplan/ -p wa -k network_config
EOF

    # Reload rules
    augenrules --load &>/dev/null || auditctl -R /etc/audit/rules.d/ccdc-ecom.rules 2>/dev/null || true
    print_success "Auditd configured and watching critical files"
}

# =============================================================================
# STEP 12: FAIL2BAN
# =============================================================================
configure_fail2ban() {
    print_step "Configuring fail2ban"

    apt-get install -y fail2ban &>/dev/null

    cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
# Ban for 1 hour
bantime = 3600
# Look back 10 minutes
findtime = 600
# Allow 5 attempts
maxretry = 5
# Use ufw
banaction = ufw

[apache-auth]
enabled = true
port = http,https
logpath = /var/log/apache2/error.log
maxretry = 5

[apache-badbots]
enabled = true
port = http,https
logpath = /var/log/apache2/access.log
maxretry = 2

[apache-overflows]
enabled = true
port = http,https
logpath = /var/log/apache2/error.log
maxretry = 2

[nginx-http-auth]
enabled = true
port = http,https
logpath = /var/log/nginx/error.log
maxretry = 5

[nginx-botsearch]
enabled = true
port = http,https
logpath = /var/log/nginx/error.log
maxretry = 2
EOF

    systemctl enable --now fail2ban
    systemctl restart fail2ban
    print_success "Fail2ban configured — protecting HTTP and HTTPS"
}

# =============================================================================
# STEP 13: REMOVE AUTHORIZED KEYS
# =============================================================================
remove_authorized_keys() {
    print_step "Removing all SSH authorized_keys"

    for DIR in /root /home/*; do
        if [ -d "$DIR/.ssh" ]; then
            USER=$(basename "$DIR")
            if [ -f "$DIR/.ssh/authorized_keys" ]; then
                cp "$DIR/.ssh/authorized_keys" "$DIR/.ssh/authorized_keys.harden_backup"
                rm -f "$DIR/.ssh/authorized_keys"
                print_info "Removed authorized_keys for $USER (backed up)"
            else
                print_info "No authorized_keys for $USER"
            fi
            chmod 700 "$DIR/.ssh"
            chown -R "$USER":"$USER" "$DIR/.ssh" 2>/dev/null || true
        fi
    done

    print_success "All authorized_keys removed"
}

# =============================================================================
# STEP 14: CLEAR TEMP DIRECTORIES
# =============================================================================
clear_temp() {
    print_step "Clearing temp directories"

    find /tmp -type f -delete 2>/dev/null || true
    find /tmp -type d ! -path /tmp -delete 2>/dev/null || true
    print_info "Cleared /tmp"

    find /var/tmp -type f -delete 2>/dev/null || true
    find /var/tmp -type d ! -path /var/tmp -delete 2>/dev/null || true
    print_info "Cleared /var/tmp"

    find /dev/shm -type f -delete 2>/dev/null || true
    print_info "Cleared /dev/shm"

    print_success "Temp directories cleared"
}

# =============================================================================
# STEP 15: SECURE WEB SERVER
# =============================================================================
secure_web_server() {
    print_step "Securing web server configuration"

    # Apache hardening
    if systemctl is-active apache2 &>/dev/null || systemctl is-active httpd &>/dev/null; then
        print_info "Apache detected — applying hardening"

        # Disable server signature and tokens
        APACHE_CONF="/etc/apache2/conf-available/security.conf"
        if [ -f "$APACHE_CONF" ]; then
            sed -i 's/^ServerTokens.*/ServerTokens Prod/' "$APACHE_CONF"
            sed -i 's/^ServerSignature.*/ServerSignature Off/' "$APACHE_CONF"
            sed -i 's/^TraceEnable.*/TraceEnable Off/' "$APACHE_CONF"
            print_info "Apache: ServerTokens=Prod, ServerSignature=Off, TraceEnable=Off"
        fi

        # Disable unused Apache modules
        for MOD in status autoindex; do
            a2dismod "$MOD" 2>/dev/null && print_info "Disabled Apache module: $MOD" || true
        done

        # Restart Apache
        systemctl restart apache2 2>/dev/null || true
        print_success "Apache hardened"
    fi

    # Nginx hardening
    if systemctl is-active nginx &>/dev/null; then
        print_info "Nginx detected — applying hardening"

        NGINX_CONF="/etc/nginx/nginx.conf"
        if [ -f "$NGINX_CONF" ]; then
            # Hide nginx version
            if ! grep -q "server_tokens off" "$NGINX_CONF"; then
                sed -i '/http {/a\\tserver_tokens off;' "$NGINX_CONF"
                print_info "Nginx: server_tokens off"
            fi
        fi

        # Add security headers to default site if it exists
        DEFAULT_SITE="/etc/nginx/sites-available/default"
        if [ -f "$DEFAULT_SITE" ]; then
            if ! grep -q "X-Frame-Options" "$DEFAULT_SITE"; then
                sed -i '/location \/ {/a\\t\tadd_header X-Frame-Options "SAMEORIGIN";\n\t\tadd_header X-Content-Type-Options "nosniff";\n\t\tadd_header X-XSS-Protection "1; mode=block";' "$DEFAULT_SITE"
                print_info "Nginx: Added security headers"
            fi
        fi

        systemctl restart nginx 2>/dev/null || true
        print_success "Nginx hardened"
    fi

    # If neither is running
    if ! systemctl is-active apache2 &>/dev/null && ! systemctl is-active nginx &>/dev/null; then
        print_warn "No active web server detected — skipping web server hardening"
    fi
}

# =============================================================================
# STEP 16: AUTOMATIC SECURITY UPDATES
# =============================================================================
configure_auto_updates() {
    print_step "Configuring automatic security updates"

    apt-get install -y unattended-upgrades &>/dev/null

    cat > /etc/apt/apt.conf.d/50unattended-upgrades <<EOF
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
EOF

    cat > /etc/apt/apt.conf.d/20auto-upgrades <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF

    systemctl enable --now unattended-upgrades
    print_success "Automatic security updates configured"
}

# =============================================================================
# SUMMARY
# =============================================================================
print_summary() {
    echo ""
    echo -e "${BLUE}══════════════════════════════════════════${NC}"
    echo -e "${BLUE}  HARDENING SUMMARY${NC}"
    echo -e "${BLUE}══════════════════════════════════════════${NC}"
    echo ""

    echo -e "  ${GREEN}Passwords changed for:${NC}"
    for USER in "${CHANGED_PASSWORDS[@]}"; do
        echo -e "    ${GREEN}✓${NC} $USER"
    done

    if [ ${#FAILED_PASSWORDS[@]} -gt 0 ]; then
        echo ""
        echo -e "  ${RED}Password changes failed for:${NC}"
        for USER in "${FAILED_PASSWORDS[@]}"; do
            echo -e "    ${RED}✗${NC} $USER"
        done
    fi

    echo ""
    [ "$WARNINGS" -gt 0 ] && \
        echo -e "  ${YELLOW}Warnings: $WARNINGS${NC}" || \
        echo -e "  ${GREEN}Warnings: 0${NC}"

    echo ""
    echo -e "${BLUE}  Hardening steps completed:${NC}"
    echo -e "  ${GREEN}✓${NC} Passwords changed"
    echo -e "  ${GREEN}✓${NC} SSH disabled completely"
    echo -e "  ${GREEN}✓${NC} UFW firewall (HTTP, HTTPS, SMTP only)"
    echo -e "  ${GREEN}✓${NC} AppArmor enforcing"
    echo -e "  ${GREEN}✓${NC} Password policy enforced"
    echo -e "  ${GREEN}✓${NC} Account lockout configured"
    echo -e "  ${GREEN}✓${NC} Unnecessary services disabled"
    echo -e "  ${GREEN}✓${NC} Unnecessary packages removed"
    echo -e "  ${GREEN}✓${NC} Kernel hardening applied"
    echo -e "  ${GREEN}✓${NC} File permissions hardened"
    echo -e "  ${GREEN}✓${NC} Auditd monitoring critical files"
    echo -e "  ${GREEN}✓${NC} Fail2ban protecting web services"
    echo -e "  ${GREEN}✓${NC} Authorized_keys removed"
    echo -e "  ${GREEN}✓${NC} Temp directories cleared"
    echo -e "  ${GREEN}✓${NC} Web server hardened"
    echo -e "  ${GREEN}✓${NC} Automatic security updates enabled"
    echo ""
    echo -e "${BLUE}  Open ports:${NC}"
    echo -e "  ${GREEN}✓${NC} 80/tcp  - HTTP"
    echo -e "  ${GREEN}✓${NC} 443/tcp - HTTPS"
    echo -e "  ${GREEN}✓${NC} 25/tcp  - SMTP"
    echo -e "  ${RED}✗${NC} 22/tcp  - SSH (BLOCKED)"
    echo ""
    echo -e "${BLUE}══════════════════════════════════════════${NC}\n"
}

# =============================================================================
# MAIN
# =============================================================================
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[ERROR]${NC} This script must be run as root (sudo)."
    exit 1
fi

# Verify running on Ubuntu
if ! grep -q "Ubuntu" /etc/os-release 2>/dev/null; then
    print_warn "This script is designed for Ubuntu. Proceed with caution on other distros."
    read -p "Continue anyway? (y/n): " CONT
    [[ "$CONT" != "y" && "$CONT" != "Y" ]] && exit 1
fi

gather_input
change_passwords
disable_ssh
configure_firewall
configure_apparmor
harden_password_policy
harden_lockout
disable_services
remove_packages
harden_kernel
harden_permissions
configure_auditd
configure_fail2ban
remove_authorized_keys
clear_temp
secure_web_server
configure_auto_updates
print_summary

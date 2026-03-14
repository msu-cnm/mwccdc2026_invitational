#!/bin/bash
# =============================================================================
# CCDC Mail Server Hardening Script
# Hardens the mail server and changes passwords for all local accounts
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
    echo "   CCDC Mail Server Hardening Script"
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
    echo -e "${YELLOW}This script will harden the server and change all local account passwords.${NC}"
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
    echo "  2.  SELinux set to enforcing"
    echo "  3.  Firewall configured"
    echo "  4.  SSH hardened"
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

    # Get all local users with login shells (excluding system accounts)
    # UID >= 1000 are regular users, also include root (UID 0)
    LOCAL_USERS=$(awk -F: '($3 == 0 || $3 >= 1000) && $7 !~ /nologin|false|halt|shutdown|sync/ {print $1}' /etc/passwd)

    for USER in $LOCAL_USERS; do
        # Skip AD/SSSD users (they won't be in /etc/shadow as local)
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

    # Force password expiry to never for competition (prevents lockout)
    for USER in "${CHANGED_PASSWORDS[@]}"; do
        chage -M 99999 "$USER" 2>/dev/null || true
    done

    print_success "Password changes complete"
    print_info "Changed: ${#CHANGED_PASSWORDS[@]} accounts"
    [ ${#FAILED_PASSWORDS[@]} -gt 0 ] && print_warn "Failed: ${FAILED_PASSWORDS[*]}"
}

# =============================================================================
# STEP 2: SELINUX
# =============================================================================
harden_selinux() {
    print_step "Configuring SELinux"

    CURRENT=$(getenforce)
    print_info "Current SELinux status: $CURRENT"

    # Set to enforcing immediately
    setenforce 1 2>/dev/null && print_success "SELinux set to Enforcing" || print_warn "Could not set SELinux to Enforcing (may not be supported)"

    # Make permanent
    if [ -f /etc/selinux/config ]; then
        sed -i 's/^SELINUX=permissive/SELINUX=enforcing/' /etc/selinux/config
        sed -i 's/^SELINUX=disabled/SELINUX=enforcing/' /etc/selinux/config
        print_success "SELinux set to enforcing in /etc/selinux/config"
    fi

    # Allow mail services in SELinux
    print_info "Configuring SELinux for mail services..."
    setsebool -P httpd_can_sendmail 0 2>/dev/null || true
    setsebool -P allow_postfix_local_write_mail_spool 1 2>/dev/null || true

    print_success "SELinux configured"
}

# =============================================================================
# STEP 3: FIREWALL
# =============================================================================
harden_firewall() {
    print_step "Configuring firewall"

    # Install firewalld if not present
    if ! rpm -q firewalld &>/dev/null; then
        dnf install -y firewalld &>/dev/null
        print_info "Installed firewalld"
    fi

    systemctl enable --now firewalld

    # Set default zone to drop
    firewall-cmd --permanent --set-default-zone=drop

    # Allow only required services
    # SSH
    firewall-cmd --permanent --add-service=ssh
    print_info "Allowed SSH (port 22)"

    # SMTP
    firewall-cmd --permanent --add-service=smtp
    print_info "Allowed SMTP (port 25)"

    # POP3
    firewall-cmd --permanent --add-port=110/tcp
    print_info "Allowed POP3 (port 110)"

    # POP3S
    firewall-cmd --permanent --add-service=pop3s
    print_info "Allowed POP3S (port 995)"

    # Kerberos (needed for AD auth)
    firewall-cmd --permanent --add-service=kerberos
    print_info "Allowed Kerberos (port 88)"

    # LDAP (needed for AD/SSSD)
    firewall-cmd --permanent --add-service=ldap
    print_info "Allowed LDAP (port 389)"

    # Apply changes
    firewall-cmd --reload
    print_success "Firewall configured — default zone: drop"
    print_info "Allowed services: SSH, SMTP, POP3, POP3S, Kerberos, LDAP"
}

# =============================================================================
# STEP 4: SSH HARDENING
# =============================================================================
harden_ssh() {
    print_step "Hardening SSH"

    SSHD_CONFIG="/etc/ssh/sshd_config"

    # Backup current config
    cp "$SSHD_CONFIG" "${SSHD_CONFIG}.harden_backup"

    # Apply hardening settings
    declare -A SSH_SETTINGS=(
        ["Protocol"]="2"
        ["MaxAuthTries"]="3"
        ["LoginGraceTime"]="30"
        ["ClientAliveInterval"]="300"
        ["ClientAliveCountMax"]="2"
        ["X11Forwarding"]="no"
        ["AllowTcpForwarding"]="no"
        ["PermitEmptyPasswords"]="no"
        ["PermitRootLogin"]="no"
        ["IgnoreRhosts"]="yes"
        ["HostbasedAuthentication"]="no"
        ["UseDNS"]="no"
        ["AllowUsers"]="sysadmin"
    )

    for KEY in "${!SSH_SETTINGS[@]}"; do
        VALUE="${SSH_SETTINGS[$KEY]}"
        if grep -q "^$KEY" "$SSHD_CONFIG"; then
            sed -i "s/^$KEY.*/$KEY $VALUE/" "$SSHD_CONFIG"
        elif grep -q "^#$KEY" "$SSHD_CONFIG"; then
            sed -i "s/^#$KEY.*/$KEY $VALUE/" "$SSHD_CONFIG"
        else
            echo "$KEY $VALUE" >> "$SSHD_CONFIG"
        fi
        print_info "Set: $KEY $VALUE"
    done

    systemctl restart sshd
    print_success "SSH hardened — only sysadmin can login"
}

# =============================================================================
# STEP 5: PASSWORD POLICY
# =============================================================================
harden_password_policy() {
    print_step "Configuring password policy"

    if ! rpm -q libpwquality &>/dev/null; then
        dnf install -y libpwquality &>/dev/null
    fi

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

    # Configure faillock
    if [ -f /etc/security/faillock.conf ]; then
        cat > /etc/security/faillock.conf <<EOF
# Lock after 5 failed attempts
deny = 5
# Lockout for 10 minutes
unlock_time = 600
# Count failures within 15 minutes
fail_interval = 900
# Log failed attempts silently
silent
EOF
        print_success "Account lockout configured via faillock.conf"
    else
        # Fallback to PAM pam_faillock
        for PAM_FILE in /etc/pam.d/system-auth /etc/pam.d/password-auth; do
            if [ -f "$PAM_FILE" ] && ! grep -q "pam_faillock" "$PAM_FILE"; then
                sed -i '/^auth.*pam_env/a auth        required      pam_faillock.so preauth silent audit deny=5 unlock_time=600' "$PAM_FILE"
                sed -i '/^auth.*pam_unix/a auth        [default=die] pam_faillock.so authfail audit deny=5 unlock_time=600' "$PAM_FILE"
                print_info "Added pam_faillock to $PAM_FILE"
            fi
        done
        print_success "Account lockout configured via PAM"
    fi
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
        "rpc-statd"
        "tftp"
        "telnet"
        "vsftpd"
        "httpd"
        "nginx"
        "named"
        "bind"
        "ypbind"
        "talk"
        "ntalk"
        "finger"
    )

    for SVC in "${UNNECESSARY_SERVICES[@]}"; do
        if systemctl is-active "$SVC" &>/dev/null; then
            systemctl stop "$SVC"
            systemctl disable "$SVC"
            print_info "Stopped and disabled: $SVC"
        elif systemctl list-unit-files | grep -q "^$SVC.service"; then
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
        "rsh"
        "rsh-server"
        "ypbind"
        "ypserv"
        "tftp"
        "tftp-server"
        "talk"
        "talk-server"
        "xinetd"
        "net-snmp"
    )

    for PKG in "${UNNECESSARY_PACKAGES[@]}"; do
        if rpm -q "$PKG" &>/dev/null; then
            dnf remove -y "$PKG" &>/dev/null
            print_info "Removed: $PKG"
        fi
    done

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

# Log suspicious (martian) packets
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

# Restrict access to kernel logs
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
        ["/etc/sssd/sssd.conf"]="600"
        ["/etc/krb5.keytab"]="600"
        ["/etc/ssh/sshd_config"]="600"
        ["/etc/postfix/main.cf"]="644"
        ["/etc/shadow"]="000"
        ["/etc/gshadow"]="000"
        ["/etc/passwd"]="644"
        ["/etc/group"]="644"
        ["/etc/crontab"]="600"
        ["/etc/krb5.conf"]="644"
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

    # Secure /root directory
    chmod 700 /root
    print_info "Secured /root"

    # Remove world-writable permissions from /tmp
    chmod 1777 /tmp
    chmod 1777 /var/tmp
    print_info "Secured /tmp and /var/tmp with sticky bit"

    print_success "File permissions hardened"
}

# =============================================================================
# STEP 11: AUDITD
# =============================================================================
configure_auditd() {
    print_step "Configuring auditd"

    if ! rpm -q audit &>/dev/null; then
        dnf install -y audit &>/dev/null
        print_info "Installed auditd"
    fi

    systemctl enable --now auditd

    # Add audit rules for critical files
    cat > /etc/audit/rules.d/ccdc-mail.rules <<EOF
# Monitor critical mail server config files
-w /etc/postfix/main.cf -p wa -k postfix_config
-w /etc/dovecot/ -p wa -k dovecot_config
-w /etc/sssd/sssd.conf -p wa -k sssd_config
-w /etc/ssh/sshd_config -p wa -k ssh_config
-w /etc/krb5.conf -p wa -k krb5_config
-w /etc/hosts -p wa -k hosts_config
-w /etc/resolv.conf -p wa -k dns_config
-w /etc/pam.d/ -p wa -k pam_config
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/group -p wa -k group_changes

# Monitor for privilege escalation
-w /bin/su -p x -k privilege_escalation
-w /usr/bin/sudo -p x -k privilege_escalation

# Monitor login/logout events
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins

# Monitor cron
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /var/spool/cron/ -p wa -k cron
EOF

    # Reload audit rules
    augenrules --load &>/dev/null || auditctl -R /etc/audit/rules.d/ccdc-mail.rules 2>/dev/null || true
    print_success "Auditd configured and watching critical files"
}

# =============================================================================
# STEP 12: FAIL2BAN
# =============================================================================
configure_fail2ban() {
    print_step "Configuring fail2ban"

    if ! rpm -q fail2ban &>/dev/null; then
        dnf install -y fail2ban &>/dev/null
        print_info "Installed fail2ban"
    fi

    cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
# Ban for 1 hour
bantime = 3600
# Look back 10 minutes
findtime = 600
# Allow 5 attempts
maxretry = 5
# Use firewalld
banaction = firewallcmd-ipset

[sshd]
enabled = true
maxretry = 3
bantime = 7200

[postfix]
enabled = true
port = smtp
logpath = /var/log/maillog
maxretry = 5

[dovecot]
enabled = true
port = pop3,pop3s
logpath = /var/log/maillog
maxretry = 5

[postfix-sasl]
enabled = true
port = smtp
logpath = /var/log/maillog
maxretry = 3
EOF

    systemctl enable --now fail2ban
    systemctl restart fail2ban
    print_success "Fail2ban configured — protecting SSH, Postfix, and Dovecot"
}

# =============================================================================
# STEP 13: REMOVE SUSPICIOUS SSH AUTHORIZED_KEYS
# =============================================================================
remove_authorized_keys() {
    print_step "Removing all SSH authorized_keys"

    for DIR in /root /home/*; do
        if [ -d "$DIR/.ssh" ]; then
            USER=$(basename "$DIR")
            if [ -f "$DIR/.ssh/authorized_keys" ]; then
                # Back it up first
                cp "$DIR/.ssh/authorized_keys" "$DIR/.ssh/authorized_keys.harden_backup"
                # Remove it
                rm -f "$DIR/.ssh/authorized_keys"
                print_info "Removed authorized_keys for $USER (backed up to authorized_keys.harden_backup)"
            else
                print_info "No authorized_keys for $USER"
            fi
            # Lock down .ssh directory permissions
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

    # Clear /tmp
    find /tmp -type f -delete 2>/dev/null || true
    find /tmp -type d ! -path /tmp -delete 2>/dev/null || true
    print_info "Cleared /tmp"

    # Clear /var/tmp
    find /var/tmp -type f -delete 2>/dev/null || true
    find /var/tmp -type d ! -path /var/tmp -delete 2>/dev/null || true
    print_info "Cleared /var/tmp"

    # Clear /dev/shm
    find /dev/shm -type f -delete 2>/dev/null || true
    print_info "Cleared /dev/shm"

    print_success "Temp directories cleared"
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
    echo -e "  ${GREEN}✓${NC} SELinux enforcing"
    echo -e "  ${GREEN}✓${NC} Firewall configured"
    echo -e "  ${GREEN}✓${NC} SSH hardened (sysadmin only)"
    echo -e "  ${GREEN}✓${NC} Password policy enforced"
    echo -e "  ${GREEN}✓${NC} Account lockout configured"
    echo -e "  ${GREEN}✓${NC} Unnecessary services disabled"
    echo -e "  ${GREEN}✓${NC} Unnecessary packages removed"
    echo -e "  ${GREEN}✓${NC} Kernel hardening applied"
    echo -e "  ${GREEN}✓${NC} File permissions hardened"
    echo -e "  ${GREEN}✓${NC} Auditd monitoring critical files"
    echo -e "  ${GREEN}✓${NC} Fail2ban protecting services"
    echo -e "  ${GREEN}✓${NC} Authorized_keys removed"
    echo -e "  ${GREEN}✓${NC} Temp directories cleared"
    echo ""
    echo -e "${BLUE}══════════════════════════════════════════${NC}"
    echo -e "${YELLOW}  NOTE: Run mail_backup.sh now to backup${NC}"
    echo -e "${YELLOW}  this hardened state!${NC}"
    echo -e "${BLUE}══════════════════════════════════════════${NC}\n"
}

# =============================================================================
# MAIN
# =============================================================================
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[ERROR]${NC} This script must be run as root (sudo)."
    exit 1
fi

gather_input
change_passwords
harden_selinux
harden_firewall
harden_ssh
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
print_summary

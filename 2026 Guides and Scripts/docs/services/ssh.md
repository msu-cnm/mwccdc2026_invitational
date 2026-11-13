# SSH Service Guide — All Linux Hosts (and Windows if installed)

Candidate service across all Linux hosts (Rocky Ecom, Ubuntu Email, Debian Splunk, Kali, workstations). The scoring check requires authenticated login; the packet explicitly warns "Do not disable password authentication blindly: SSH scoring authenticates" (p.17). Packet p.14 leaves precise scored services to the event portal.

## Discovery

> **Status:** candidate service — the packet lists this as a possible scored service but does not confirm it on any specific host. Verify on the live system before relying on any step below.

Confirm SSH is installed, running, and which authentication methods are enabled:

```bash
# All Linux hosts
systemctl status sshd 2>/dev/null || systemctl status ssh 2>/dev/null
ss -lnt | grep ':22'
grep -E '^(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|Port)' /etc/ssh/sshd_config
# Check for non-standard port
grep -r '^Port' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ 2>/dev/null
```

On Windows hosts (if OpenSSH is installed):

```powershell
Get-Service sshd | Select-Object Status, StartType
Get-NetTCPConnection -LocalPort 22 -ErrorAction SilentlyContinue
```

## Setup

Install only if missing and the portal confirms SSH is scored:

```bash
# Rocky / RHEL family
sudo dnf install -y openssh-server && sudo systemctl enable --now sshd

# Debian / Ubuntu family
sudo apt update && sudo apt install -y openssh-server && sudo systemctl enable --now ssh
```

On Windows Server (if required):

```powershell
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd
Set-Service sshd -StartupType Automatic
```

## Configuration

### Authentication methods

The packet requires preserving the scoring authentication method. Discover what is currently enabled before changing anything:

```bash
sshd -T | grep -E 'passwordauthentication|pubkeyauthentication|permitrootlogin|port'
```

**Critical rules:**
- Do **not** disable `PasswordAuthentication` unless the portal confirms key-only auth is scored.
- Do **not** change the port unless the portal specifies one.
- Preserve `PermitRootLogin` setting if it was working before.
- If both password and key auth are enabled, keep both until you confirm which the scorer uses.

### Firewall

Ensure TCP 22 (or the discovered port) is reachable from the scoring path:

```bash
# Rocky / RHEL
sudo firewall-cmd --query-port=22/tcp || sudo firewall-cmd --add-port=22/tcp --permanent && sudo firewall-cmd --reload

# Debian / Ubuntu (ufw or iptables)
sudo ufw status | grep 22
sudo iptables -L INPUT -n | grep ':22'
```

Check Palo Alto for any NAT or ACL affecting the SSH path.

PAN-OS CLI options (discovery only):

```
show running nat-policy | match 172.20.240.10
show running security-policy | match 172.20.240.10
show session all filter destination 172.20.240.10 destination-port 22
```

GUI equivalent: Policies > NAT, Policies > Security, Monitor > Traffic.

### SELinux (Rocky Ecom)

Do not disable SELinux. If SSH is on a non-standard port:

```bash
sudo semanage port -a -t ssh_port_t -p tcp <port>  # if needed
getenforce  # confirm Enforcing or Permissive; do not change
```

## Monitoring

```bash
systemctl status sshd
journalctl -u sshd --since 1h | grep -iE 'accepted|failed|error'
ss -lnt | grep ':22'
# Auth log
grep sshd /var/log/auth.log 2>/dev/null || journalctl -u sshd --since 1h | tail -20
```

Forward auth logs to Splunk via approved path. Verify at Quotient that SSH login succeeds with the scored credentials.

## Backup

Back up SSH configuration before any change:

```bash
BACKUP_DIR="/root/backup-ssh-$(date -u +%Y%m%d%H%M%S)"
mkdir -p "$BACKUP_DIR"
cp -rp /etc/ssh "$BACKUP_DIR/"
# Preserve authorized_keys if present
find /home -name 'authorized_keys' -exec cp --parents {} "$BACKUP_DIR/" \; 2>/dev/null
```

No VM snapshots. Retain on a protected path.

## Usage and scoring verification

Verify functional login (not just port open):

```bash
# From Kali or any authorized client
ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 <user>@<host> 'echo OK && whoami && hostname'
# If key-based:
ssh -i <keyfile> -o StrictHostKeyChecking=no <user>@<host> 'echo OK'
```

Test from both internal and public paths. Confirm Quotient shows successful SSH authentication.

## Recovery

1. Restore config: `cp -rp "$BACKUP_DIR"/ssh /etc/`
2. Validate: `sshd -t` (syntax check, no restart needed)
3. Restart: `systemctl restart sshd`
4. If key files were lost: restore from backup to the user's `.ssh/`
5. Verify with `ssh <user>@<host> 'echo OK'`
6. Record UTC time and residual exposure

## References

- [Rocky Ecom system guide](../systems/rocky-ecom.md)
- [Ubuntu Email system guide](../systems/ubuntu-email.md)
- [Debian Splunk system guide](../systems/debian-splunk.md)
- [Environment constraints](../environment.md)
- [Event checklist](../event-checklist.md)

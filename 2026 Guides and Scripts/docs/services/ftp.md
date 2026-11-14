# FTP Service Guide

The packet does not assign a specific FTP host; the owner must be discovered from live configuration and portal assignment. The scoring requirement is "authenticated access to required files" with correct NAT/connection tracking for data connections.

## Discovery

Read-only commands on candidate hosts:

```bash
ss -lntu | grep ':21'
systemctl list-units --type=service | grep -iE 'vsftpd|proftpd|pure-ftpd|ftp'
rpm -qa | grep -i ftp
dpkg-query -W -f='${Package}\n' | grep -i ftp
```

Check Palo Alto NAT rules for port 21 forwarding and passive range. Plausible candidates: Rocky Ecom (upload/content) or Ubuntu Email (attachment relay). Host is discovered via portal assignment and service presence.

PAN-OS CLI options (discovery only):

```
show running nat-policy | match 172.20.240.10
show running security-policy | match 172.20.240.10
show session all filter destination 172.20.240.10 destination-port 21
```

Preserve existing rules; add only what is confirmed missing after the portal assigns FTP to a host.

## Setup

Install free software only (vsftpd on Linux):

```bash
# Debian/Ubuntu
sudo apt update
sudo apt install vsftpd -y

# RHEL/CentOS
sudo yum install vsftpd -y
```

If already installed, verify user accounts and directory permissions:

```bash
systemctl status vsftpd
passwd <user>
ls -la /var/ftp/  # or custom chroot dir
```

Skip to configuration if service is running with users and directories present.

## Configuration

Active vs passive mode selection:

```bash
# vsftpd.conf (edit carefully, preserve existing config)
# Enable passive mode
pasv_enable=YES
pasv_min_port=PORT_START
pasv_max_port=PORT_END
```

Passive port range MUST match firewall/NAT rules. Check NAT configuration for allowed range.

User accounts and chroot jail:

```conf
# Optional chroot, only after verifying the existing scored layout
chroot_local_user=YES
# local_root=/var/ftp/<user>
```

`userlist_enable` controls login allow/deny lists, not chroot. Preserve the existing list and `userlist_deny` behavior. A chroot root normally must not be writable by the FTP user; use an owned writable subdirectory and test the existing upload workflow before enabling chroot.

TLS (FTPS) if required:

```bash
ssl_enable=YES
ssl_ciphers=HIGH:!aNULL:!MD5
rsa_cert_file=/etc/ssl/certs/ftp.crt
rsa_private_key_file=/etc/ssl/private/ftp.key
```

Connection tracking for data connections: Ensure firewall allows established/related connections on passive ports.

**Critical:** Preserve existing users, file permissions and directory structure. Do NOT create scoring-only allowlists; modify only necessary configuration entries.

## Monitoring

Service health:

```bash
systemctl status vsftpd
journalctl -u vsftpd --since 1h
```

FTP transfer logs (auth success/failure):

```bash
grep 'vsftpd' /var/log/auth.log
grep -E 'Accepted|Failed' /var/log/secure | grep ftp
```

Disk usage on data directories:

```bash
df -h /var/ftp/
du -sh /var/ftp/*
```

Splunk ingestion: Forward logs to Splunk with syslog.

Quotient verification: Verify authenticated file listing and read access, not just port open. Test with FTP client:

```bash
lftp <user>@<host> -e 'ls; get testfile; quit'
# List the FTP root; curl prompts for the account password.
curl --user '<user>' 'ftp://<host>/'
```

## Backup

Backup FTP configuration (vsftpd.conf, user accounts, chroot directory structure):

Run as root. Discover the configured file with `systemctl cat vsftpd`: Debian/Ubuntu usually uses `/etc/vsftpd.conf`, Rocky `/etc/vsftpd/vsftpd.conf`. Set `FTP_CONFIG` and `FTP_ROOT` to the actual configuration and scored data root:

```bash
umask 077
BACKUP_DIR="/root/backup-ftp-$(date -u +%Y%m%dT%H%M%SZ)"
FTP_CONFIG=/etc/vsftpd.conf
FTP_ROOT=/var/ftp
mkdir -m 700 "$BACKUP_DIR"
cp -a "$FTP_CONFIG" "$BACKUP_DIR/vsftpd.conf"
tar -czpf "$BACKUP_DIR/ftp-data.tar.gz" -C "$FTP_ROOT" .
tar -tzf "$BACKUP_DIR/ftp-data.tar.gz" >/dev/null
```

Include referenced user-list, PAM and TLS files separately if used. File backup does not recreate local accounts or AD integration. Quiesce writes for a consistent data copy; retain a protected off-host copy.

**No VM snapshots.** Use protected paths with timestamps.

## Usage and scoring verification

Verify functionally with a scored account:

```bash
# Active mode
lftp <user>@<host> -e 'set ftp:passive-mode 0; ls; get file.txt; quit'

# Passive mode (requires NAT config)
lftp <user>@<host> -e 'set ftp:passive-mode 1; ls; get file.txt; quit'
```

Test from internal and public paths. Confirm Quotient shows correct files.

## Recovery

Rollback steps:

Set `BACKUP_DIR`, `FTP_CONFIG`, and `FTP_ROOT` to the single selected backup and the original paths before restoring. Restarting briefly interrupts FTP;
perform it in the coordinated recovery window. vsftpd has no standalone syntax
test flag: check startup status and the journal after restoring configuration.

```bash
# Restore configuration
cp -a "$BACKUP_DIR/vsftpd.conf" "$FTP_CONFIG"

# Restart with the restored configuration and verify startup
systemctl restart vsftpd && systemctl is-active vsftpd
journalctl -u vsftpd --since '5 minutes ago' --no-pager
```

If startup fails, inspect the journal and correct or restore the configuration
before retrying. Once active, repeat authenticated listing and file retrieval
from the required scoring path; active status alone does not verify FTP access.

If file data is corrupted, restore from backup:

```bash
tar -xzpf "$BACKUP_DIR/ftp-data.tar.gz" -C "$FTP_ROOT"
```

Verify NAT rules for passive range are intact. Record UTC time of recovery action.

## References

- [../systems/rocky-ecom.md](../systems/rocky-ecom.md)
- [../systems/ubuntu-email.md](../systems/ubuntu-email.md)
- [../environment.md](../environment.md)
- [../event-checklist.md](../event-checklist.md)

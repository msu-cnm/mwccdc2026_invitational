# FTP Service Guide

The packet does not assign a specific FTP host; the owner must be discovered from live configuration and portal assignment. The scoring requirement is "authenticated access to required files" with correct NAT/connection tracking for data connections.

## Discovery

Read-only commands on candidate hosts:

```bash
ss -lntu | grep ':21'
systemctl list-units --type=service | grep -iE 'vsftpd|proftpd|pure-ftpd|ftp'
rpm -qa | grep -i ftp
dpkg-query -W -f='${Package}' | grep -i ftp
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

```bash
vsftpd.conf entries:
# user_list_enable=YES  # chroot to home directory
# local_root=/var/ftp/<user>
```

TLS (FTPS) if required:

```bash
ssl_enable=YES
ssl_ciphers=ECDHE-RSA-AES256-GCM-SHA56:ECDHE-RSA-AES128-GCM-SHA256
ssl_certificate_file=/etc/ssl/certs/ftp.crt
ssl_private_key_file=/etc/ssl/private/ftp.key
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
grep 'Accepted|Failed' /var/log/secure | grep ftp
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

```bash
# Timestamped protected paths
mkdir /backup/ftp-$(date +%Y%m%d-%H%M%S)
cp -r /etc/vsftpd.conf /backup/ftp-*/
cp -r /var/ftp/ /backup/ftp-*/
cp -r /var/lib/ftp/ /backup/ftp-*/
```

Backup file data in scored directories:

```bash
cp -r /var/ftp/scored/* /backup/ftp-*/scored/
```

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

Select the intended backup before restoring. Restarting briefly interrupts FTP;
perform it in the coordinated recovery window. vsftpd has no standalone syntax
test flag: check startup status and the journal after restoring configuration.

```bash
# Restore configuration
cp /backup/ftp-<timestamp>/vsftpd.conf /etc/vsftpd.conf

# Restart with the restored configuration and verify startup
systemctl restart vsftpd && systemctl is-active vsftpd
journalctl -u vsftpd --since '5 minutes ago' --no-pager
```

If startup fails, inspect the journal and correct or restore the configuration
before retrying. Once active, repeat authenticated listing and file retrieval
from the required scoring path; active status alone does not verify FTP access.

If file data is corrupted, restore from backup:

```bash
cp -r /backup/ftp-*/scored/* /var/ftp/scored/
```

Verify NAT rules for passive range are intact. Record UTC time of recovery action.

## References

- [../systems/rocky-ecom.md](../systems/rocky-ecom.md)
- [../systems/ubuntu-email.md](../systems/ubuntu-email.md)
- [../environment.md](../environment.md)
- [../event-checklist.md](../event-checklist.md)

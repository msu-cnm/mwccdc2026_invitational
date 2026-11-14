# POP3 / IMAP / Webmail Service Guide — Ubuntu Email

Candidate service (packet role: "Email; SMTP, POP3/IMAP and webmail are candidates, assignment unconfirmed"). The scoring check requires retrieval with AD usernames and stored messages. Packet p.14 leaves precise scored services to the event portal.

## Discovery

> **Status:** candidate service — the packet lists this as a possible scored service but does not confirm it on any specific host. Verify on the live system before relying on any step below.

Confirm the actual mail stack before assuming Dovecot or any specific webmail frontend:

```bash
systemctl list-units --type=service | grep -iE 'dovecot|cyrus|webmail|roundcube|rainloop'
ss -lnt '( sport = :110 or sport = :143 or sport = :995 or sport = :993 )'
dpkg-query -W | grep -iE 'dovecot|webmail|roundcube|rainloop|cyrus'
```

Check for AD/LDAP authentication backends:

```bash
grep -r 'auth_mechanisms\|ldap\|sasl' /etc/dovecot/ 2>/dev/null
systemctl status saslauthd 2>/dev/null
```

## Setup

Install free software only if the service is not present. Discover first; install only what the portal confirms is scored:

```bash
# Dovecot (POP3 + IMAP)
sudo apt update && sudo apt install -y dovecot-imapd dovecot-pop3d
sudo systemctl enable --now dovecot

# Webmail (choose one; Roundcube is common in competition environments)
sudo apt install -y roundcube-mysql roundcube-core
```

If already installed, skip to Configuration.

## Configuration

### Dovecot core

- `/etc/dovecot/dovecot.conf` — protocols, listen addresses.
- `/etc/dovecot/conf.d/10-auth.conf` — authentication mechanism (LDAP/SASL for AD integration).
- `/etc/dovecot/conf.d/10-mail.conf` — mail location (`mail_location = mbox:~/Mail:INDEX=~/Index` or `maildir:~/Maildir`).
- `/etc/dovecot/conf.d/10-ssl.conf` — TLS certificates for POP3S (995) and IMAPS (993).

### AD-integrated authentication

Preserve the working backend first: `sudo doveconf -n` shows the installed configuration (protect its output). On Ubuntu 22.04 with Dovecot 2.3, install `dovecot-ldap` only if the chosen existing design requires LDAP. Dovecot 2.4 uses different configuration syntax; check `dovecot --version` before adapting this recipe.

For a Dovecot 2.3 LDAP passdb, include `!include auth-ldap.conf.ext` inside `/etc/dovecot/conf.d/10-auth.conf`. The included file contains:

```conf
passdb {
  driver = ldap
  args = /etc/dovecot/dovecot-ldap.conf.ext
}
```

In `/etc/dovecot/dovecot-ldap.conf.ext`, use the actual AD endpoint and base DN:

```conf
uris = ldaps://<dc-fqdn>:636
ldap_version = 3
auth_bind = yes
auth_bind_userdn = %u@<ad-dns-domain>
base = DC=<domain>,DC=<tld>
tls_ca_cert_file = /etc/ssl/certs/<ad-ca>.pem
tls_require_cert = hard
```

This direct-bind example assumes login names without an existing domain suffix. It handles password verification only: retain the existing working userdb/UID/GID/home/mailbox mapping. Do not map every AD user to root or invent a mail location. Protect LDAP config and verify the DC certificate/CA first. Run `sudo doveconf -n`, reload only after it passes, then `sudo doveadm auth test '<owned-user>'` (password prompt) and test actual retrieval. If existing LDAP search uses a service bind, preserve its protected credentials and filter instead of replacing it with this direct-bind design.

### Webmail

- Roundcube: `/etc/roundcube/config.inc.php` — version-specific `$config['smtp_host']` and `$config['imap_host']` (older releases use other keys; check the installed defaults), database DSN.
- Preserve existing mailboxes and folder structure. Do not delete or rename accounts.

### Firewall / NAT

Ensure ports 110, 143, 995, 993 (and webmail port) are reachable from the scoring path. Check Palo Alto NAT rules for public-to-internal mapping. Preserve existing rules; add only what is confirmed missing.

PAN-OS CLI options (discovery only):

```
show running nat-policy | match 172.20.240.15
show running security-policy | match 172.20.240.15
show session all filter destination 172.20.240.15 destination-port 110
show session all filter destination 172.20.240.15 destination-port 993
```

GUI equivalent: Policies > NAT, Policies > Security, Monitor > Traffic.

## Monitoring

```bash
systemctl status dovecot
journalctl -u dovecot --since 1h | grep -iE 'login|auth|error'
ss -lnt '( sport = :110 or sport = :143 or sport = :995 or sport = :993 )'
# Webmail
systemctl status roundcube 2>/dev/null || systemctl status apache2 2>/dev/null
```

Log locations: `/var/log/mail.log`, `/var/log/auth.log`, journal. Forward to Splunk via approved syslog/forwarder path. Verify at Quotient that stored messages are retrievable with the scored AD username.

## Backup

Back up Dovecot configuration, mail location data, and webmail database before any change:

```bash
BACKUP_DIR="/root/backup-mail-$(date -u +%Y%m%d%H%M%S)"
umask 077
mkdir -m 700 "$BACKUP_DIR"
cp -rp /etc/dovecot "$BACKUP_DIR/"
# Substitute the existing mailbox root discovered with doveconf; quiesce writes first
tar -czpf "$BACKUP_DIR/maildir.tar.gz" -C /var/mail .
tar -tzf "$BACKUP_DIR/maildir.tar.gz" >/dev/null
# Webmail database (discover actual DB)
mysqldump --single-transaction -u <backup-user> -p roundcube > "$BACKUP_DIR/roundcube.sql"
```

No VM snapshots available. Retain backups on a protected path; verify restore before the event.

## Usage and scoring verification

Verify functionally with the scored AD account:

```bash
# IMAPS (993; port 143 requires IMAP4 + starttls instead)
python3 -c "
import imaplib, ssl, getpass
m = imaplib.IMAP4_SSL('<mail-fqdn>', 993, ssl_context=ssl.create_default_context(), timeout=10)
m.login('<ad_user>', getpass.getpass())
typ, data = m.select('INBOX', readonly=True)
if typ != 'OK': raise RuntimeError('INBOX selection failed')
print(typ, int(data[0]), 'messages')
m.logout()
"

# POP3S (995; port 110 requires POP3 + stls instead)
python3 -c "
import poplib, ssl, getpass
p = poplib.POP3_SSL('<mail-fqdn>', 995, context=ssl.create_default_context(), timeout=10)
p.user('<ad_user>'); p.pass_(getpass.getpass())
print(len(p.list()[1]), 'messages')
p.quit()
"

# Webmail
curl -s -o /dev/null -w '%{http_code}' https://<public_host>/<webmail_path>/
```

Test from both internal and public paths. Confirm Quotient shows successful retrieval.

## Recovery

1. Restore Dovecot config: `cp -rp "$BACKUP_DIR"/dovecot /etc/`
2. Validate: `doveconf -n` (prints effective config; check for errors)
3. Restart: `systemctl restart dovecot`
4. If mail data lost: `tar -xzpf "$BACKUP_DIR/maildir.tar.gz" -C /var/mail` (use the original discovered mailbox root)
5. If webmail DB corrupted: `mysql -u <restore-user> -p roundcube < "$BACKUP_DIR/roundcube.sql"`
6. Record UTC time and residual exposure.

## References

- [Ubuntu Email system guide](../systems/ubuntu-email.md)
- [Environment constraints](../environment.md)
- [Event checklist](../event-checklist.md)

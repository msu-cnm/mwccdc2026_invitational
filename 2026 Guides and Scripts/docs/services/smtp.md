# SMTP Mail Transfer Service Guide

Candidate service (packet role says "Email; SMTP, POP3/IMAP and webmail are candidates, assignment unconfirmed") — packet leaves to event portal on p.14.

## Discovery

> **Status:** candidate service — the packet lists this as a possible scored service but does not confirm it on any specific host. Verify on the live system before relying on any step below.

Confirm SMTP stack with read-only commands:

```bash
systemctl list-units --type=service
ss -lntu | grep -E ':25|:465|:587'
dpkg-query -W | grep -i 'postfix\|exim\|sendmail'
```

Note: Do not assume Postfix; discover the actual daemon. If `exim` or `sendmail` appears, adjust commands accordingly (e.g., `eximdbctl status`, `sendmail -bv`).

## Setup

On Ubuntu Email, first inspect `postconf -n` and `postconf -M` if Postfix exists. Save `/etc/postfix`, actual mailbox paths and authentication-backend configuration before changes. If Postfix is confirmed missing and is the intended replacement, install it interactively:

```bash
sudo apt-get update
sudo apt-get install postfix
sudo postfix check
sudo systemctl enable --now postfix
```

Select the verified mail domain in the package dialog. Installing Postfix alone does not recreate AD authentication, mailbox delivery or webmail. Restore these from the working baseline and test with the existing scored AD account before treating recovery as complete. For Exim use its own configuration/validation; do not apply Postfix settings to it.

## Configuration

Relay policy: Preserve legitimate inbound domain delivery and authenticated users while preventing unauthenticated third-party relay.

- TLS certificates: Generate or verify existing certs; configure Postfix `smtpd_tls_cert_file` and `smtpd_tls_key_file`.
- SASL authentication: Integrate with Active Directory via LDAP (`ldapauth`, `sasl_passwd`).
- DNS records: Ensure MX, A, and PTR are correct for reverse DNS checks.

Keep plaintext port 25 if scored until TLS requirements confirmed; do not disable without portal confirmation.

```conf
# /etc/postfix/main.cf (example)
smtpd_tls_security_level = may
smtpd_relay_restrictions = permit_mynetworks permit_sasl_authenticated reject_unauth_destination
mydestination = $myhostname, localhost.$mydomain, localhost
relay_domains = $mydestination
```

### Palo Alto CLI options

Discovery only — do not change policy from these commands:

```
show running nat-policy | match 172.20.240.15
show running security-policy | match 172.20.240.15
show session all filter destination 172.20.240.15 destination-port 25
```

GUI equivalent: Policies > NAT, Policies > Security, Monitor > Traffic. Preserve existing rules; add only what is confirmed missing.

## Monitoring

Service health: `systemctl status <service>`, `postfix check`, `postqueue -p` if Postfix. Mail queue depth: `mailq`. Log locations: `/var/log/mail.log` or `journalctl -u postfix`. Configure and verify collection with the [data-source recipe](../splunk-data-sources.md); Quotient verification is still required.

Note: A listening port is insufficient; verify send AND receive with a valid account.

```bash
# Test from authorized account
openssl s_client -starttls smtp -connect <server>:25 -servername <mail-fqdn> -crlf -quiet
mailq | wc -l
journalctl -u postfix --since 1h | grep -iE "accept|reject|deliver"
```

## Backup

Back up SMTP configuration (`main.cf`, virtual aliases, TLS certs), mailbox data, and queue state. Use protected paths with timestamps. No VM snapshots. A queue listing is evidence, not a message backup.

```bash
# Backup config with timestamp
cp -p /etc/postfix/main.cf "/backups/postfix-$(date +%Y%m%d-%H%M%S).cf"
tar czf "/backups/mailbox-$(date +%Y%m%d-%H%M%S).tar.gz" /var/mail /var/vmail
```

## Usage and scoring verification

Verify functionally: send a test mail to an owned account, verify delivery (check mailbox via IMAP/POP3), verify relay policy (authorized send + receive). Test from internal and public paths. Confirm Quotient. Never do an external open-relay probe; use owned authorized accounts.

On Kali, install `swaks` if missing (`sudo apt-get install swaks`). Send to an owned test mailbox, using the actual submission endpoint and authentication policy:

```bash
swaks --server <mail-fqdn> --port 587 --tls --auth LOGIN \
  --auth-user <owned-user> --from <owned-sender> --to <owned-recipient> \
  --header 'Subject: collection-check' --body 'Authorized delivery check' --auth-password
```

`--auth-password` without a value prompts interactively. Use `--tls-verify` with a trusted server certificate. For an inbound port-25 check use the discovered policy without assuming submission authentication. Confirm receipt via the retrieval guide; an SMTP 250 response alone does not prove mailbox delivery.

## Recovery

Rollback steps: restore saved configuration, run native validator (`postfix check` or equivalent), reload. If mail queue is corrupted, restore from backup. Record UTC time.

```bash
# Restore config
cp "/backups/postfix-YYYYMMDD-HHMMSS.cf" /etc/postfix/main.cf
postfix check
systemctl restart postfix
```

## References

- [Ubuntu Email system](../systems/ubuntu-email.md)
- [Environment constraints](../environment.md)
- [Event checklist](../event-checklist.md)

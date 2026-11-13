# HTTP/HTTPS Service Guide — Rocky Ecom

Candidate service (packet role says "Ecommerce; HTTP/HTTPS are candidate services, assignment unconfirmed") and the packet leaves precise scored services to the event portal (p.14). This guide covers setup, configuration, monitoring, backup and usage for the HTTP/HTTPS web service on Rocky Linux 9 (172.20.240.10).

## Discovery

> **Status:** candidate service — the packet lists this as a possible scored service but does not confirm it on any specific host. Verify on the live system before relying on any step below.

Confirm the actual web stack — do not assume Apache/nginx paths. Use these read-only commands:

```bash
systemctl list-units --type=service | grep -E 'httpd|nginx|apache'
ss -lntu | grep -E ':80$|:443$'
rpm -qa | grep -iE 'httpd|nginx|apache'
```

If a service is found, run `nginx -t` or `apachectl configtest`. Check `getenforce` for SELinux status.

## Setup

Choose the existing application's web server; run only one of these alternatives if confirmed missing. A default web page does not restore ecommerce content or its database:

```bash
# nginx
sudo dnf install -y nginx && sudo systemctl enable --now nginx

# httpd
sudo dnf install -y httpd && sudo systemctl enable --now httpd
```

If already installed, skip to Configuration.

## Configuration

Configure virtual host/server block basics, TLS, document root, SELinux and firewall rules. Preserve existing checkout/catalog content, certificates, database connectivity.

### Virtual host / server block

- nginx: `/etc/nginx/conf.d/<hostname>.conf`
- httpd: `/etc/httpd/conf.d/<hostname>.conf`

Set document root to serve ecommerce content from `/var/www/html`. Preserve any existing checkout/catalog files in that directory.

### TLS certificate setup

Use existing certificates at `/etc/pki/tls/certs/`:

```nginx
server { listen 443 ssl; server_name <domain>;
  ssl_certificate /etc/pki/tls/certs/<name>.crt;
  ssl_certificate_key /etc/pki/tls/certs/<name>.key;
  root /var/www/html; }
```

### SELinux context notes

Do not disable SELinux. Use persistent labels with `semanage fcontext -a -t httpd_sys_content_t '/var/www/html(/.*)?'` followed by `restorecon -Rv /var/www/html`. Review AVCs with `ausearch -m AVC -ts recent` and correct specific policy labels after testing rather than disabling SELinux.

### Firewall-cmd zone notes

Allow traffic on your assigned public IP: `firewall-cmd --zone=<zone> --add-port=443/tcp --permanent && firewall-cmd --reload`. Preserve existing rules.

### Palo Alto CLI options

Discovery only — do not change policy from these commands:

```
show running nat-policy | match 172.20.240.10
show running security-policy | match 172.20.240.10
show session all filter destination 172.20.240.10 destination-port 443
```

`| match` takes a plain text pattern (no field/value filters); for sessions use the `filter` keywords instead, with the port as a separate `destination-port` value.

GUI equivalent: Policies > NAT, Policies > Security, Monitor > Traffic. Preserve existing rules; add only what is confirmed missing after the portal assigns HTTP/HTTPS to Rocky Ecom.

## Monitoring

Verify service health beyond open ports. Confirm content matches portal expectation.

```bash
systemctl status <service_name>
curl --insecure http://localhost/ && curl --insecure https://localhost/
ss -lntu | grep -E ':80$|:443$'
```

Log locations: nginx `/var/log/nginx/`, httpd `/var/log/httpd/`. Check `/etc/logrotate.d/` for rotation. Ingest with approved forwarder/syslog path; no default access-log schema assumed. Verify at https://quotient.ccdc.events/.

## Backup

Back up configuration, document root, certificates, and database schema/data. Use protected paths with timestamps. No VM snapshots available:

```bash
BACKUP_DIR="/root/backup-$(date -u +%Y%m%d%H%M%S)"
mkdir -p "$BACKUP_DIR"
cp -r /etc/nginx/conf.d/* "$BACKUP_DIR/" 2>/dev/null
cp -r /var/www/html/* "$BACKUP_DIR/"
cp -r /etc/pki/tls/certs/* "$BACKUP_DIR/"
mysqldump --all-databases > "$BACKUP_DIR/db-backup.sql" 2>/dev/null
```

## Usage and scoring verification

Verify functionally using the exact URL/path from the portal. Check HTTP status and content. Test from internal (172.20.240.10) and public egress (172.25.(20+team).10). Confirm Quotient at https://quotient.ccdc.events/.

```bash
curl -I https://<portal_url>/ && curl https://<portal_url>/
curl -I https://quotient.ccdc.events/
```

Check HTTP status (200/301/302/404, etc.) and verify response content matches portal expectation.

## Recovery

If a change breaks the service, use saved configuration backup and native validation.

1. Validate: `nginx -t` (tests the full main configuration, including conf.d) or `apachectl configtest`
2. Restore if invalid: `cp "$BACKUP_DIR"/<config> /etc/nginx/conf.d/`
3. Reload/restart: `systemctl reload <service>`
4. If content corrupted: restore the preserved document-root directory, including hidden files and ownership, then validate content
5. Record UTC time and residual exposure.

## References

Reference URLs were opened through the web tool at event time; recheck live notices. No package CVE or fixed version is inferred from an OS name.

- [Rocky Ecom system guide](../systems/rocky-ecom.md)
- [Environment constraints](../environment.md)
- [Event checklist](../event-checklist.md)

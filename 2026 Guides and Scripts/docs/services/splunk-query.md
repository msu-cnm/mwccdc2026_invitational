# Splunk Query and Ingestion Guide — Debian Splunk

Candidate service (packet role: "Splunk authenticated query; exact endpoint, index and ingest paths unconfirmed"). The scoring check requires authentication and a query returning expected information. Packet p.14 leaves precise scored services to the event portal. Splunk 10.0.2 on Debian 12.

## Discovery

> **Status:** candidate service — the packet lists this as a possible scored service but does not confirm it on any specific host. Verify on the live system before relying on any step below.

Confirm Splunk is installed, running, and discover the actual endpoints:

```bash
systemctl status <discovered-unit>
ss -lnt '( sport = :8000 or sport = :8089 or sport = :9997 or sport = :8088 )'
# Web console port (default 8000, may differ)
grep -r 'http_port\|mgmt_port\|server.port' /opt/splunk/etc/system/ 2>/dev/null
# Check for configured inputs (forwarder/syslog)
/opt/splunk/bin/splunk btool inputs list --debug
# Check indexes
/opt/splunk/bin/splunk list indexes
```

From a client (Kali or another host):

```bash
curl --cacert /path/to/lab-ca.pem --connect-timeout 5 --max-time 15 \
  'https://<splunk-fqdn>:8089/services/server/info' -o /dev/null -w '%{http_code}\n'
# Splunk Web defaults to HTTP unless enableSplunkWebSSL is enabled in web.conf
curl --connect-timeout 5 --max-time 15 'http://<splunk-fqdn>:8000/en-US/account/login' \
  -o /dev/null -w '%{http_code}\n'
# Use HTTPS with the trusted CA when the discovered Web listener has TLS enabled.
```

## Setup

Use the existing installation; locate its real home and service before starting it:

```bash
ps -eo user,pid,args | grep '[s]plunkd'
systemctl list-unit-files | grep -i splunk
sudo /opt/splunk/bin/splunk version
sudo /opt/splunk/bin/splunk btool inputs list --debug
```

`/opt/splunk` is the candidate installation path. Substitute the discovered path throughout. Start the discovered systemd unit (`sudo systemctl start Splunkd` or `splunk`, as listed); do not create a second service. For a genuinely new installation follow the vendor license/bootstrap prompts interactively, under the intended service account. License acceptance is not a setting to infer from `default.conf`.

For concrete receiver, Linux/Windows forwarder and appliance onboarding, follow [data-source setup](../splunk-data-sources.md). It includes verification and rollback for every host.

## Configuration

### Authentication

- **Web console** (default port 8000, HTTP unless Web TLS is enabled): `http://<host>:8000` or the discovered HTTPS URL — requires username/password.
- **Management API** (default port 8089): `https://<host>:8089/services/...` — REST API with the same or a separate admin account.
- Discover the actual admin user: use Settings > Access controls > Users with an authorized administrator, or ask the portal.

### Ingestion endpoints

Splunk can receive data via:
- **HEC (HTTP Event Collector)** — port 8088 by default (discover; not always enabled)
- **TCP inputs** — port 9997 or custom
- **Syslog** — UDP 514 or TCP 601
- **Universal Forwarder** — from other hosts pushing to this indexer

```bash
# Check if HEC is enabled
/opt/splunk/bin/splunk list http-event-collector 2>/dev/null
# Check TCP/UDP inputs
/opt/splunk/bin/splunk btool inputs list --debug
# Inspect tcp://, udp:// and splunktcp:// stanzas separately in that output
```

### Indexes and search

- Discover indexes: `/opt/splunk/bin/splunk list indexes`
- The scored query likely targets a specific index. Confirm with the portal.
- SPL queries are case-sensitive on index names and field values.

### Firewall / NAT

Ensure the scoring path reaches the web/API port. Check Palo Alto for NAT rules mapping the public address to 172.20.240.20. Preserve existing rules.

PAN-OS CLI options (discovery only):

```
show running nat-policy | match 172.20.240.20
show running security-policy | match 172.20.240.20
show session all filter destination 172.20.240.20 destination-port 8000
```

GUI equivalent: Policies > NAT, Policies > Security, Monitor > Traffic.

## Monitoring

```bash
systemctl status <discovered-unit>
# Authenticated management health; curl prompts for the password
curl --cacert /path/to/lab-ca.pem --user '<user>' \
  'https://<splunk-fqdn>:8089/services/server/info?output_mode=json'
# Indexer stats
/opt/splunk/bin/splunk list indexes | grep -E 'name|homePath'
# Disk usage (Splunk data can grow)
df -h /opt/splunk/var/
du -sh /opt/splunk/var/lib/splunk/ 2>/dev/null
# Logs
tail -50 /opt/splunk/var/log/splunk/splunkd.log 2>/dev/null
```

Forward Splunk's own logs to monitoring if required. Verify at Quotient that the scored query returns expected data.

## Backup

Back up Splunk configuration and index data before any change:

```bash
BACKUP_DIR="/root/backup-splunk-$(date -u +%Y%m%d%H%M%S)"
umask 077
mkdir -m 700 "$BACKUP_DIR"
# Configuration (all conf files)
cp -rp /opt/splunk/etc "$BACKUP_DIR/"
# Stop the discovered Splunk unit in a coordinated maintenance window first.
# This is an offline single-instance backup, not a live bucket backup.
# Index data (full index backup can be large)
tar czf "$BACKUP_DIR/indexes.tar.gz" -C /opt/splunk/var/lib/splunk .
# Or selective:
# tar czf "$BACKUP_DIR/index-<name>.tar.gz" -C /opt/splunk/var/lib/splunk <index_name>
```

No VM snapshots. Retain on a protected path. Verify archive readability and file ownership. Rehearse restore on an isolated matching installation, never by starting a second instance over production data. Restart the discovered unit after the offline copy. Include custom index paths from `btool indexes list --debug`; the default directory alone may omit them.

## Usage and scoring verification

Verify the scored query returns expected information:

```bash
# Export returns results directly; a search/jobs POST alone returns a job ID.
# Use a discovered query/index and a CA that validates the server hostname.
curl --cacert /path/to/lab-ca.pem --user '<user>' \
  'https://<splunk-fqdn>:8089/services/search/jobs/export' \
  --data-urlencode 'search=search index=team_security earliest=-15m | stats count by host' \
  -d output_mode=json
```

HEC defaults to HTTPS 8088, with payload `{"event":"collection-test","host":"verified-host"}` at `/services/collector/event`; it requires an enabled token assigned to an existing permitted index. Use the receiver/forwarder recipe instead unless HEC is specifically needed. Never send a HEC token to the management API or a forwarder receiver (9997).

Test from both internal and public paths. Confirm Quotient shows the query returning expected data.

## Recovery

1. Stop Splunk: `sudo systemctl stop <discovered-unit>`
2. Restore config: `cp -rp "$BACKUP_DIR"/etc /opt/splunk/`
3. Restore index data if needed: `tar xzf "$BACKUP_DIR/indexes.tar.gz" -C /opt/splunk/var/lib/splunk/`
4. Start Splunk: `sudo systemctl start <discovered-unit>`
5. Wait for full startup (~30s): `systemctl status <discovered-unit>`
6. Verify with a test query via API
7. Record UTC time and residual exposure

## References

- [Debian Splunk system guide](../systems/debian-splunk.md)
- [Splunk threat hunting guide](../splunk-threat-hunting.md)
- [Environment constraints](../environment.md)
- [Event checklist](../event-checklist.md)

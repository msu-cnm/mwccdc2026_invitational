# Debian Splunk

Packet inventory: **Debian 12; Splunk 10.0.2**, **172.20.240.20**, public/egress **172.25.(20+team).20**. Splunk authenticated query; exact endpoint, index and ingest paths unconfirmed. These are packet facts, not verified live builds or service assignments.

Read [environment constraints](../environment.md) and complete the [event worksheet](../event-checklist.md). Keep a tested NETLAB console and official access, ICMP, general public service availability, names, data and usernames. Preserve NAT, DNS/time, AD, SQL and scoring dependencies. Never limit public services to scoring sources. Coordinate credential changes and PCR updates. No snapshots are available.

## Candidate services on this host

Consolidated per-host map: [host-service-map.md](../host-service-map.md). Packet p.14 leaves precise scored services to the event portal; every entry below is a candidate to discover and confirm, not a confirmed assignment.

| Candidate service | Guide |
|---|---|
| Splunk authenticated query (web/API endpoint) | [splunk-query.md](../services/splunk-query.md) |
| SSH for administration | [ssh.md](../services/ssh.md) |

## Initial checks and system-specific security

Discover Splunk installation, service owner, web/API bind ports, forwarding inputs, indexes and retention. Inspect `ss -lntu` and `systemctl list-units --type=service`; do not assume `/opt/splunk`. Use `<discovered-splunk-home>/bin/splunk status` as its intended service identity. Keep inputs, saved searches, indexes, users and query permissions. Splunk config exports and diagnostic bundles can contain secrets: do not attach them to general reports.

Back up local configuration and plan data-safe index recovery before edits. Review admin roles and app permissions while retaining the scored account's query capability. Confirm ingestion continues after any change; watch ingestion lag, index volume, disk thresholds and splunkd errors. Execute the exact portal query through its actual web/API endpoint and confirm expected records; a listening web port is insufficient. Do not change Splunk licensing or install trial software; the existing provided installation is not authority to add paid tools.

## Scripts and reversible changes

From the repository root (Python 3, no added runtime packages):

```bash
python3 scripts/linux_guard.py assess
python3 scripts/linux_guard.py harden
# After reviewing the plan, from a console, using a fresh protected backup path:
sudo python3 scripts/linux_guard.py harden --apply --backup /root/kernel-before.json
sudo python3 scripts/linux_guard.py rollback --backup /root/kernel-before.json
sudo python3 scripts/linux_guard.py rollback --apply --backup /root/kernel-before.json
```

Harden adjusts only four runtime kernel protections. It does not persist across reboot. A repeat application with the same backup path fails safely; retain the original backup. Applications needing kernel diagnostics may be affected: test this host before event use. Assess is read-only; elevated assessment may expose more metadata. Snapshot output contains hashes and metadata, not file contents; protect it and compare against a reviewed earlier capture. It is a one-shot collector, not an automatic incident detector.

## Monitoring and scoring verification

Capture a baseline before changes, then compare service health, listeners, authentication events, persistence and resources at least every few minutes. Follow the system-specific checks above and [incident workflow](../event-checklist.md). Confirm every assigned authenticated/content check in Quotient at `https://quotient.ccdc.events/`, available also through `https://auth.ccdc.events/`. Internal success alone does not prove public NAT or scoring success. No scripted connectivity check against arbitrary targets is provided.

After each single change test existing management, ICMP and the actual scored workflow; check every downstream dependent system. Coordinate password updates with dependency owners and immediately update Quotient PCR. Store secrets separately. If anything regresses, use the script rollback or saved native configuration, retest and record the outcome. Do not rely on VM snapshots; the packet says they are unavailable.

Validation status: documentation is based on packet facts, with uncertainty stated. No live competition system or representative VM was available for connectivity, service recovery or platform-specific runtime validation. Rehearsal remains mandatory before event deployment.

## Vulnerabilities and applicability

Run read-only discovery first; ordinary users can read inventory, but `sudo` is needed for complete journal/process/socket/config evidence. Missing files, denied permissions or an empty journal are collection gaps, not clean results. Do not print environment variables, secrets, private keys or whole credential-bearing configurations into reports.

```bash
date -u
cat /etc/os-release
uname -r
hostnamectl
systemctl list-units --type=service --state=running --no-pager
sudo ss -lntup
sudo journalctl --since '-15 minutes' --until now -p warning --no-pager -n 200
```

Resolve executable and configuration paths from `systemctl show UNIT -p MainPID -p FragmentPath -p ExecStart` and `systemctl cat UNIT` locally (substitute the discovered unit; redact credentials). Map a binary to its package with `dpkg-query -S /actual/binary` or `rpm -qf /actual/binary`. Record container/image and application manifests too: distribution package lists alone miss manually installed applications.

Packet says Splunk 10.0.2, but discover actual `$SPLUNK_HOME`, installation owner, topology (standalone/indexer/search head/forwarder/cluster), version with `/DISCOVERED/SPLUNK_HOME/bin/splunk version`, Debian package revision if packaged, configured Web/API/ingest listeners and enabled features. Set `SPLUNK_HOME` only to the verified path for commands below. Read discovery output locally; `btool ... --debug` and configs can expose secrets. Never put passwords/tokens on command lines.

| Possible scenario | Evidence and applicability | Remedy and temporary mitigation | Indicators/prerequisites |
|---|---|---|---|
| Splunk Web stored XSS, CVE-2026-20162 (SVD-2026-0301) | Vendor table includes 10.0.0–10.0.2; requires Web enabled, low-privileged view creation and victim browser interaction. Verify actual build/feature; packet version alone is not proof of exploitation. | Vendor lists 10.0.3 as the 10.0-branch fix, **not a claim it fixes all later advisories**. Select a currently supported release addressing all applicable notices and approved upgrade path. Vendor workaround disables Web, incompatible if Web is scored; then keep Web, defer with owner/expiry, review view changes and avoid untrusted links. | Unexpected view creation/modification and subsequent browser requests; collect audit.log and splunkd_access.log. Vendor publishes no specific detection; these are hunting leads with false negatives. |
| Excessive roles, token access or management/API exposure | Settings > Users/Roles/Tokens and effective listener/TLS configuration versus worksheet; confirm unauthorized capability, token metadata or exposure, not merely port 8089. | Apply least privilege and vendor security fixes; rotate only confirmed compromised tokens after coordinating integrations. Temporarily restrict an optional administrative path only if public scored query/official access/ingest remain available. | New admin capability, token creation, unauthorized REST use. Requires `_audit`/local audit logs and API access logs; not every token use is guaranteed logged. Never export token values. |
| App/scripted-input persistence or ingestion suppression | Compare app manifests, inputs, outputs, indexes, saved searches and executable ownership to reviewed baseline; discover Debian package advisories separately. | Restore vetted app/config and supported Splunk/Debian patches. While deferred disable only a confirmed unauthorized input after preserving evidence; keep required ingest/query paths. | New script/alert action under writable app directory, forwarder destination/index changes, queues/disk errors, audit gaps. Requires configuration baseline, audit/internal metrics and independent source inventory; a compromised server can alter its own logs. |

## Patching and recovery

1. Record actual Debian/Splunk versions, app compatibility, architecture, topology, licensing and scored query plus sources/indexes. Check all current Splunk advisories and Debian security tracker for the precise revision/features. Verify the installed release's supported Debian platform; don't infer support from successful startup.
2. Create a fresh protected backup with `sudo install -d -m 700 /root/event-backups` and `sudo mktemp -d /root/event-backups/splunk.XXXXXX`. Back up Splunk configuration, users/apps and required encryption-key material with mode-600 files, installation owner/ACLs and consistent vendor-supported index/data backup. Avoid raw secret dumps; preserve approved independent evidence/config copies. A live `etc` copy alone cannot recover indexed data. Test restore outside the event.
3. For Debian packages, inspect `apt-cache policy PACKAGE`, trusted sources and holds; manually refresh metadata then preview `apt-get -s install --only-upgrade PACKAGE`. Review specific dependencies and disk headroom. Splunk is often a vendor tar/deb, **not an apt repository package**: discover delivery type, obtain the supported signed/checksummed installer from the official permitted source, and read target release notes, upgrade path, app compatibility and topology-specific order. No guessed generic installer command or broad apt upgrade.
4. Rehearse the exact vendor procedure with compatible apps and data. Manually install only the reviewed Debian packages and Splunk target. Coordinate required stop/start and cluster upgrade order; ensure console and source log retention/buffering cover the gap. Don't run Splunk as root merely to upgrade it.
5. Restart the discovered instance as its designated service owner via the installed supported mechanism. OS kernel changes may require a maintenance reboot; application restart is separate. Preserve ingestion endpoints, Web/API scoring and authentication.
6. Verify actual version, health, login and the exact scored authenticated query. Compare recent event counts/timestamps against **all expected hosts**, forwarding queues, disk/license state and local inputs. Successful search login does not prove ingestion.
7. On failure stop changes and follow that release's supported recovery. Splunk downgrades across versions may be unsupported and migrations irreversible; recover a compatible configuration/data backup using retained vendor media and console, rather than overwriting binaries over upgraded data. Recheck queries and ingestion before declaring recovery.

## Detection when patching is deferred

Review advisory prerequisites and record expiry/owner. For XSS, audit UI view changes and suspicious links but acknowledge missing reliable exploit signatures. Review new users/roles/tokens in Settings without exposing secrets. Discover `$SPLUNK_HOME/var/log/splunk/` and actual `audit.log`, `splunkd.log`, `splunkd_access.log`, `metrics.log` availability/rotation; custom installations may differ. Configuration-file monitoring/exec audit are optional, not enabled by Linux guard. Baseline app/file hashes and expected inputs out of band; use independent source-local logs and ingestion checks because the monitoring host can falsify its own search results. Do not disable Web, management or all scripted inputs merely because they are risky: they may implement scoring/collection.

## Threat hunting

1. **Hypothesis: an administrator or token was added.** In Settings > Users/Roles/Tokens inspect identity, issuer, expiry and capabilities against the approved roster; use a last-30-minute `_audit` search below and locally `sudo journalctl -u UNIT --since '-30 minutes' --until now --no-pager -n 200`. Suspicious: unexplained admin grants, new tokens or off-hours changes. Benign: approved inject/operator setup. Follow up with change owner, auth source and API access metadata; require separate token-use collection if not logged.
2. **Hypothesis: a scripted input/app is executing unauthorized code.** Run `sudo find "$SPLUNK_HOME/etc/apps" -xdev -maxdepth 5 -type f -mmin -60 -printf '%TY-%Tm-%TdT%TH:%TM %u %m %p\n'` and `sudo ps -eo user,pid,ppid,lstart,comm`. Inspect changed input/alert definitions locally and compare hashes to vetted manifests; never execute unknown scripts to test them. Suspicious: unauthorized executable/writeable code or unexpected child. Benign: sanctioned app upgrade or deployment bundle. Preserve definitions/hash and correlate audit/app deployment timeline before disabling one input.
3. **Hypothesis: collection was suppressed.** Review `sudo journalctl -u UNIT --since '-30 minutes' --until now --no-pager -n 300`, `df -h`, `df -i`, and last 200 lines of the discovered `splunkd.log`/`metrics.log`. Compare input/output config metadata and source-local latest events against shared expected-host silence/lag searches. Suspicious: destination changes, blocked queues, disk full, disabled input or a wholly absent source. Benign: idle source, planned restart or clock skew. Follow up at the source and transport without trusting this host alone; preserve source logs before rotation.

## Splunk monitoring

For installation, input configuration, validation and rollback for this host, use [concrete data-source setup](../splunk-data-sources.md).

Use the [shared Splunk guide](../splunk-threat-hunting.md) for collection, time, health checks, field discovery and evidence handling. `debian-splunk` is a topology ID, **not a verified hostname**. Replace `HOST_DISCOVERED` and `INDEX_DISCOVERED` below after checking ingestion with `index=INDEX_DISCOVERED host="HOST_DISCOVERED" earliest=-15m latest=now | head 20`. Discover actual `source`, `sourcetype` and raw event formats before adding field-based filters.

Local `_audit` and `_internal` indexes are product candidates; verify this deployment indexes them, permissions and retention. The example uses `_audit`, not the placeholder data index; `user`, `action`, `info` are optional extracted fields, with `_raw` as fallback. Optional external syslog/config/file/exec audit improves independent visibility. Never assume Enterprise Security or detection add-ons are licensed/installed.

```spl
index=_audit host="HOST_DISCOVERED" earliest=-30m latest=now
| table _time host user action info _raw
| head 100
```

This bounded raw-event search returns candidate evidence for manual UTC correlation, not proof of compromise. No results can mean wrong host/index, absent logging/permissions, rotation or broken ingestion. Compare local logs and the shared expected-host silence check before concluding there is no activity. Redact secret-bearing events and keep original evidence protected independently of this host.

## References

Reference URLs were opened through the web tool on **2026-11-13**. Recheck live notices at event time; this is not a live vulnerability assessment. No package CVE or fixed version is inferred from an OS name. Local commands and SPL have not been executed against competition hosts.

- [Splunk SVD-2026-0301 / CVE-2026-20162](https://advisory.splunk.com/advisories/SVD-2026-0301) — affected range, Web/victim prerequisites, fix and no supplied detections.
- [Splunk advisories](https://advisory.splunk.com/) — check all newer applicable notices, not just the example.
- [Splunk upgrade documentation](https://help.splunk.com/en/splunk-enterprise/get-started/install-and-upgrade/10.0/upgrade-or-migrate-splunk-enterprise/how-to-upgrade-splunk-enterprise) — select installed/target version and deployment type.
- [Debian security information](https://www.debian.org/security/) — OS packages independently from Splunk.
- [Environment](../environment.md), [event worksheet](../event-checklist.md).

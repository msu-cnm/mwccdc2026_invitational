# Rocky Ecom

Packet inventory: **Rocky Linux 9**, **172.20.240.10**, public/egress **172.25.(20+team).10**. Ecommerce; HTTP/HTTPS are candidate services, assignment unconfirmed. These are packet facts, not verified live builds or service assignments.

Read [environment constraints](../environment.md) and complete the [event worksheet](../event-checklist.md). Keep a tested NETLAB console and official access, ICMP, general public service availability, names, data and usernames. Preserve NAT, DNS/time, AD, SQL and scoring dependencies. Never limit public services to scoring sources. Coordinate credential changes and PCR updates. No snapshots are available.

## Candidate services on this host

Consolidated per-host map: [host-service-map.md](../host-service-map.md). Packet p.14 leaves precise scored services to the event portal; every entry below is a candidate to discover and confirm, not a confirmed assignment.

| Candidate service | Guide |
|---|---|
| HTTP / HTTPS web service | [http-https.md](../services/http-https.md) |
| FTP (only if the portal assigns it here) | [ftp.md](../services/ftp.md) |
| SSH for administration | [ssh.md](../services/ssh.md) |

## Initial checks and system-specific security

Discover the actual web stack using `systemctl list-units --type=service`, `ss -lntu`, `rpm -qa` and `getenforce`. Check `firewall-cmd --list-all-zones` if firewalld is installed. Locate site configuration and document roots from the running web server; do not assume Apache/nginx paths. Preserve checkout/catalog content, upload data, sessions, certificates, database connectivity and any mail dependency. Read SELinux AVCs (`ausearch -m AVC -ts recent` if available); correct specific labels/policy after testing rather than disabling SELinux.

Use the installed server's configuration test (`nginx -t` or `apachectl configtest`, only for the stack found). Back up site configuration and data first. Review writable web directories and excessive privileges; avoid recursive chmod/chown. Patch only after rehearsing compatibility. Test the exact portal URL using the expected Host/SNI and verify body/content and application operations, including DB-backed requests. Monitor HTTP status/error rates and unexpected document-root hashes without archiving customer data.

## Scripts and reversible changes

From the repository root (Python 3, no added runtime packages):

```bash
python3 scripts/linux_guard.py assess
python3 scripts/linux_guard.py harden
# After reviewing the plan, from a console, using a fresh protected backup path:
sudo python3 scripts/linux_guard.py harden --apply --backup /root/kernel-before.json
sudo python3 scripts/linux_guard.py rollback --backup /root/kernel-before.json
sudo python3 scripts/linux_guard.py rollback --apply --backup /root/kernel-before.json
# Firewall hardening (plan-only; operator applies with nft):
python3 scripts/linux_guard.py firewall --host rocky-ecom
```

Harden adjusts only four runtime kernel protections. It does not persist across reboot. A repeat application with the same backup path fails safely; retain the original backup. Applications needing kernel diagnostics may be affected: test this host before event use. Assess is read-only; elevated assessment may expose more metadata. Snapshot output contains hashes and metadata, not file contents; protect it and compare against a reviewed earlier capture. It is a one-shot collector, not an automatic incident detector.

**Firewall hardening:** use the [per-host hardening procedure](../hardening.md). Windows uses supported `RemoteAddress` ranges for the complement of the selected host's trusted IPv4 networks and explicitly blocks IPv6 SSH. Existing effective GPO or block rules can still prevent trusted SSH; test fresh connections. Other service ports are preserved.

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

Record `rpm -qa`, `sudo dnf updateinfo list --security`, `getenforce` and the actual web-server/app versions, virtual-host roots, upload locations and remote SQL endpoints. Do not assume nginx, PHP or MariaDB exists. Consult Rocky errata and the discovered application's vendor advisories; upstream banners alone do not establish exposure.

| Possible scenario | Evidence and applicability | Remedy and temporary scoring-preserving mitigation | Exploitation indicators and prerequisites |
|---|---|---|---|
| Web/app dependency vulnerability | Package NEVRA, app lockfile/container digest, enabled module and vendor affected-build range must all match. An ecommerce role alone is not confirmation. | Install supported narrow package/app fix. Pending testing, disable only an optional affected feature after proving checkout/content checks work; keep the public endpoint available. | New error bursts, abnormal upload/admin requests and web-worker children/outbound sessions. Requires actual access/error/application logs; historical execution requires preconfigured audit/EDR. |
| Executable upload or worker-writable application code | Discover upload handler and configured root; inspect `namei -l PATH`, ACLs and worker UID. Writable storage is normal; executing uploaded content or writable executable code establishes the risky condition. | Separate non-executable upload storage and reviewed least-write permissions; preserve legitimate uploads. Temporarily remove script handling only in the upload location after functional tests. | New scripts in upload storage, executable code changes owned by web UID, subsequent requests to that filename. Needs file baseline, access logs, optionally preexisting audit watches. |
| Overprivileged app-to-SQL identity or exposed secrets | Review app's configured DB endpoint and DB-side grants with DBA; do not copy connection strings. Confirm unnecessary roles or readable secret files rather than guessing SQL product. | Narrow grants after testing exact app transactions; protect secrets and coordinate rotation/PCR if applicable. While deferred, monitor that identity and preserve required DB connectivity. | DB login from an unexpected host, administrative statements under app identity, export bursts or worker sockets to unknown destinations. Requires database login/query audit; socket snapshots do not show historical SQL. |

## Patching and recovery

1. Capture healthy storefront, login, read-only catalogue and approved test transaction plus SQL dependencies. Inventory packages, app manifests, SELinux labels and repository origins; compare actual versions/features to vendor errata, including backports.
2. Create a fresh protected backup directory using `sudo install -d -m 700 /root/event-backups` and `sudo mktemp -d /root/event-backups/ecom.XXXXXX`. Use mode-600 archives of discovered site/config paths, ownership, ACLs and labels; have the DBA create and verify a consistent native database backup. No plaintext secrets in `/tmp`, no guessed document roots, no snapshots.
3. Check disk/recovery media, then preview `sudo dnf upgrade --assumeno PACKAGE` for each explicit affected package. Inspect dependency and restart effects; application dependency upgrades need the discovered application's supported lockfile/build/deployment workflow and a disposable rehearsal. Do not run a broad security update or replace the OS release.
4. Manually apply `sudo dnf upgrade PACKAGE` only after reviewing the exact transaction. Review vendor config changes; run the installed server's native syntax check before reloading the discovered unit. Preserve SELinux; review denials rather than disabling it blindly.
5. Restart only affected workers/services as required. `sudo dnf needs-restarting -r` is optional if its plugin already exists; missing plugin is not evidence of no reboot requirement. Schedule kernel/vendor-required reboot with console recovery; verify the running kernel afterward.
6. Test public content and authentication, authorised checkout fixture, upload behavior, application-to-SQL, ICMP and official access; observe portal scoring and application errors.
7. Restore a failed configuration change with its original labels/permissions and retest. For incompatible code/schema changes restore the vendor-supported compatible application/data backup; do not assume `dnf history undo` is available or safe. Retain a known bootable kernel and trusted recovery packages before maintenance.

## Detection when patching is deferred

For each scenario above, document the affected build/feature, owner, expiry and why a tested patch is delayed. Keep a reviewed hash/metadata baseline outside the web root. Discover access/error paths from the installed server configuration (or journal/container log driver); do not assume `/var/log/nginx`. Correlate request UTC time, URL, remote source, app identity and DB events. Access logs often lack bodies and cannot reliably reveal SQL injection. Audit file/exec rules and DB auditing are **optional separately configured** telemetry; deploying them needs volume/privacy review. Retain native logs independently if the host may be compromised. A WAF/signature hit or writable upload alone is a lead, not proof.

## Threat hunting

1. **Hypothesis: a worker launched a shell or downloader.** Run `sudo ps -eo user,pid,ppid,lstart,comm --sort=ppid` and `sudo ss -ntp`; identify worker PIDs from the discovered unit. Review `sudo journalctl -u UNIT --since '-30 minutes' --until now --no-pager -n 300`. Suspicious: shell/download child or unrelated egress under worker UID. Benign: approved image/document converters and deployment hooks. Follow up by preserving PID/parent, executable hash (`sudo sha256sum /proc/PID/exe`) and matching request/optional exec-audit evidence; no historical children can be inferred from a current process listing.
2. **Hypothesis: an upload became executable code.** Substitute the discovered bounded site path: `sudo find /DISCOVERED/SITE -xdev -maxdepth 5 -type f -mmin -60 -printf '%TY-%Tm-%TdT%TH:%TM %u %m %p\n'`. Locally inspect unexpected filenames/permissions and correlate requests, not file contents in shared reports. Suspicious: new executable payload or modification outside intended upload storage by worker UID. Benign: content edits, deployments, cached templates. Preserve hash/metadata and compare trusted release manifest before quarantining a file; do not delete customer data blindly.
3. **Hypothesis: the app identity accessed SQL beyond normal operations.** Compare `sudo ss -ntp` with the worksheet DB endpoint, and ask the SQL owner for the last 30 minutes of that identity's login/query audit on [MSSQL](2019-mssql.md), only if that is the discovered backend. Suspicious: unapproved peers, privilege changes or bulk reads outside the baseline. Benign: connection pools, migrations and backups. Follow up with matched UTC app request/DB session IDs and DBA-approved grant review. No query history without DB-side collection.

## Splunk monitoring

For installation, input configuration, validation and rollback for this host, use [concrete data-source setup](../splunk-data-sources.md).

Use the [shared Splunk guide](../splunk-threat-hunting.md) for collection, time, health checks, field discovery and evidence handling. `rocky-ecom` is a topology ID, **not a verified hostname**. Replace `HOST_DISCOVERED` and `INDEX_DISCOVERED` below after checking ingestion with `index=INDEX_DISCOVERED host="HOST_DISCOVERED" earliest=-15m latest=now | head 20`. Discover actual `source`, `sourcetype` and raw event formats before adding field-based filters.

Available candidates are configured web/app logs and the system journal, only after local verification. Optional telemetry: web-worker exec auditing, file integrity baselines and database audit; the existing Linux guard does not enable these. Ingest discovered files with an approved existing forwarder/syslog path; no default access-log schema is assumed.

```spl
index=INDEX_DISCOVERED host="HOST_DISCOVERED" earliest=-30m latest=now
("POST" OR "upload" OR "permission denied" OR "SQL")
| table _time host source sourcetype _raw
| head 100
```

This bounded raw-event search returns candidate evidence for manual UTC correlation, not proof of compromise. No results can mean wrong host/index, absent logging/permissions, rotation or broken ingestion. Compare local logs and the shared expected-host silence check before concluding there is no activity. Redact secret-bearing events and keep original evidence protected independently of this host.

## References

Reference URLs were opened through the web tool on **2026-11-13**. Recheck live notices at event time; this is not a live vulnerability assessment. No package CVE or fixed version is inferred from an OS name. Local commands and SPL have not been executed against competition hosts.

- [Rocky SELinux documentation](https://docs.rockylinux.org/guides/security/learning_selinux/) — contexts and enforcing-policy review.
- [Rocky errata](https://errata.rockylinux.org/) — URL opened 2026-11-13 but returned no readable content; verify exact package advisories at event time.
- [Environment](../environment.md), [event worksheet](../event-checklist.md).

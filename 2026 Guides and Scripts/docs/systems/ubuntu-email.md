# Ubuntu Email

Packet inventory: **Ubuntu 22.04**, **172.20.240.15**, public/egress **172.25.(20+team).15**. Email; SMTP, POP3/IMAP and webmail are candidates, assignment unconfirmed. These are packet facts, not verified live builds or service assignments.

Read [environment constraints](../environment.md) and complete the [event worksheet](../event-checklist.md). Keep a tested NETLAB console and official access, ICMP, general public service availability, names, data and usernames. Preserve NAT, DNS/time, AD, SQL and scoring dependencies. Never limit public services to scoring sources. Coordinate credential changes and PCR updates. No snapshots are available.

## Candidate services on this host

Consolidated per-host map: [host-service-map.md](../host-service-map.md). Packet p.14 leaves precise scored services to the event portal; every entry below is a candidate to discover and confirm, not a confirmed assignment.

| Candidate service | Guide |
|---|---|
| SMTP mail transfer | [smtp.md](../services/smtp.md) |
| POP3 / IMAP / webmail | [pop3-imap-webmail.md](../services/pop3-imap-webmail.md) |
| FTP (only if the portal assigns it here) | [ftp.md](../services/ftp.md) |
| SSH for administration | [ssh.md](../services/ssh.md) |

## Initial checks and system-specific security

Discover daemons with `systemctl list-units --type=service`, `ss -lntu` and `dpkg-query -W`. Identify SMTP, IMAP/POP3, webmail and AD integration; do not assume Postfix/Dovecot. If present, use `postfix check`, `postqueue -p` and `doveconf -n` locally; configuration output may contain secrets and must not be placed in monitoring reports. Preserve mailboxes, aliases, queue, TLS material, authentication backends and DNS MX/A/PTR records.

Check relay policy carefully: preserve legitimate inbound domain delivery and authenticated users while preventing unauthenticated third-party relay. Rehearse using owned authorized accounts and destinations, never an external open-relay probe. Keep plaintext ports if scored until TLS requirements are confirmed. Do not purge queues or mass-delete messages. Validate a real send/receive cycle and retrieval via the exact scored protocol, plus webmail login. Watch queue depth, delivery failures, authentication failures, disk space and certificate expiry.

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
python3 scripts/linux_guard.py firewall --host ubuntu-email
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

Record `dpkg-query -W` and map each SMTP, retrieval, webmail and AD-authentication listener to its unit/binary/package. Discover logs from unit configuration and the daemon's logging configuration. Do not assume Postfix, Dovecot or Roundcube. For example, only if Postfix is confirmed, `sudo postconf -n` and `sudo postqueue -p` show configuration/queue; only if Dovecot is confirmed, `sudo doveconf -n` shows effective configuration. These outputs may contain sensitive information: review locally and redact. For another stack use its installed vendor's equivalent read-only UI/CLI.

| Possible scenario | Discovery and applicability | Patch/configuration remedy; interim mitigation | Indicators and logging prerequisites |
|---|---|---|---|
| Mail/webmail vulnerable component | Exact daemon/webmail version, Ubuntu release/package revision and enabled affected feature match a USN or application advisory. Installed package alone is not reachable exposure. | Narrow supported package/app update. Temporarily disable an optional affected plugin only after mail and scored webmail tests; never turn off scored retrieval/delivery. | Webmail error/request anomalies, crashes, unexpected files/worker children. Requires webmail access/error and daemon logs, optional exec/file auditing. |
| Relay or authentication abuse | Effective relay/trusted-network rules, TLS/auth settings, AD mapping and approved send/receive baseline. Do not test by sending to external/unowned recipients. | Correct relay/auth policy while retaining public inbound domain delivery and official accounts. Temporarily constrain only an evidenced malicious source or optional abused feature, never all public senders. | Unauthenticated forwarding to unauthorized domains, many failures followed by success, new client IP or sending burst. Requires daemon authentication/relay logs with sender/recipient metadata; failed attempts alone are not confirmed relay. |
| Queue/persistence abuse | Record queue count/age/reasons using actual vendor CLI, service UID, configured filters/hooks and timers. A large queue alone may be downstream outage. | Correct only unauthorized filter/hook or permissions; patch affected daemon; preserve messages. While deferred inspect queue rates and unknown service children; do not purge queues or mass-reset accounts. | Unexpected executable hook, repeated outbound recipients, old deferred queue or unknown worker egress. Requires queue IDs/defer reasons, service/config baseline and optional execution audit. |

## Patching and recovery

1. Record installed release, running kernel, package versions, repositories, holds and baseline listeners/authenticated workflows. Use `dpkg-query -W`, `apt-mark showhold` and `apt-cache policy PACKAGE` for each discovered affected package. Match the full distribution version and enabled feature against vendor advisories; old upstream version strings may contain backported fixes.
2. Before changing metadata or software, create a fresh root-only backup directory with `sudo install -d -m 700 /root/event-backups` then `sudo mktemp -d /root/event-backups/change.XXXXXX`. Record the returned path. Use root-owned mode-600 archives of discovered configuration, permissions and application data there, with `sudo sh -c 'umask 077; ...'`. Use the application's consistent backup procedure; a file copy of a running database/queue is not a consistent backup. Keep a protected independent copy through approved channels and test restoration in a disposable system. Never store secrets in `/tmp` or web-accessible directories.
3. Check trusted repository origin/signing settings, disk/inode space (`df -h; df -i`) and recovery packages. Manually run `sudo apt-get update` (metadata mutation only), then `apt-cache policy PACKAGE` and `apt-get -s install --only-upgrade PACKAGE`. Replace PACKAGE with explicit discovered names; review every dependency, removal, held package and service restart. Stop if the plan changes unrelated packages or a supported fix needs an untested release migration.
4. Apply only the reviewed transaction with `sudo apt-get install --only-upgrade PACKAGE`, interactively, without `-y`. Do not enable unattended upgrades or run a blanket upgrade. A package installation can restart services itself: schedule the interruption before starting.
5. Validate native configuration syntax for the discovered service. Restart/reload only affected units when required; updated libraries can leave old processes running. Decide whether the kernel or vendor instructions require reboot; check `/var/run/reboot-required` if present, but its absence does not prove no reboot is needed. Reboot only with console access and an agreed maintenance window.
6. Confirm installed versions, service health, listeners and exact portal authentication/content plus dependencies from authorized paths; observe scoring and logs. An open port is insufficient.
7. On regression, stop additional changes. Restore the single configuration change from its protected backup and native validation, or use a vendor-supported application/data recovery with compatible versions. A prior package may be unavailable or unsafe to downgrade; retain trusted recovery media/packages beforehand, and use console/previous kernel where supported. Recheck service/data integrity and scoring after recovery; record UTC times and the residual exposure.

Mail-specific recovery: back up discovered configuration, certificates, identity mapping and message stores using the installed stack's consistent backup process; a queue listing is evidence, not a message backup. Quiescing a queue may require a maintenance window. Preserve ownership/ACLs and avoid replaying already-delivered messages. Test native configuration syntax (for confirmed Postfix `sudo postfix check`; for other daemons use their documented validator) before reload. Verify authorized send **and** receive, SMTP acceptance to the assigned domain, retrieval of stored messages, webmail, AD authentication, TLS and DNS. Preserve existing usernames, mailboxes and scoring authentication methods.

## Detection when patching is deferred

Assign an expiry and owner to each scenario's temporary mitigation. Inspect discovered daemon logs or `sudo journalctl -u UNIT --since '-15 minutes' --until now --no-pager -n 300`; identify whether the actual unit emits to journal, rsyslog or application files. Collect queue **metadata**, not message bodies or passwords. Correlate queue ID with auth identity/client IP and final delivery status. Keep externally copied protected evidence if local logs might be tampered with. Authentication, webmail and mail logs can be separate; absence in one says nothing about the others. Process execution/file watches require separate preconfigured audit and are not enabled by linux_guard.py.

## Threat hunting

1. **Hypothesis: stolen credentials drive outbound mail.** Review the last 30 minutes in the discovered auth/mail unit: `sudo journalctl -u UNIT --since '-30 minutes' --until now --no-pager -n 500`. Correlate failure/success, authenticated sender and queue IDs using vendor log fields. Suspicious: success from a new client after failures plus unexplained sending. Benign: password typo, shared NAT or mail retry. Follow up with account owner, AD authentication timeline and permitted sender baseline before any coordinated credential change.
2. **Hypothesis: the relay is abused or the queue is stalled.** Capture the installed daemon's queue summary twice five minutes apart; for confirmed Postfix use `sudo postqueue -p` and limit report to counts/age/reasons, not mail content. Review last 30 minutes of delivery logs. Suspicious: rising unauthorized destinations or repeated deferrals associated with an unknown source. Benign: DNS/downstream outage or an authorized bulk mailing. Follow up by tracing representative queue IDs and worksheet DNS/route health; do not delete queued messages to reduce the count.
3. **Hypothesis: a malicious mail hook persists.** Run `sudo ps -eo user,pid,ppid,lstart,comm`, `sudo ss -ntp`, `systemctl list-timers --all --no-pager`, and `sudo find /DISCOVERED/MAIL/CONFIG -xdev -maxdepth 3 -type f -mmin -60 -ls`. Suspicious: new filter executable, root task invoking writable content or unexpected worker shell. Benign: spam/AV filters and approved upgrades. Compare the unit/filter definitions to a reviewed backup; hash unknown executables and correlate change time with auth/deployment evidence before isolating only the affected component.

## Splunk monitoring

For installation, input configuration, validation and rollback for this host, use [concrete data-source setup](../splunk-data-sources.md).

Use the [shared Splunk guide](../splunk-threat-hunting.md) for collection, time, health checks, field discovery and evidence handling. `ubuntu-email` is a topology ID, **not a verified hostname**. Replace `HOST_DISCOVERED` and `INDEX_DISCOVERED` below after checking ingestion with `index=INDEX_DISCOVERED host="HOST_DISCOVERED" earliest=-15m latest=now | head 20`. Discover actual `source`, `sourcetype` and raw event formats before adding field-based filters.

Available candidates: the discovered SMTP/retrieval/auth and webmail logs, not verified ingestion. Optional: AD events, application request fields, daemon queue snapshots and process/file auditing. The raw phrases below are examples to tune against that daemon; a different stack can use different wording.

```spl
index=INDEX_DISCOVERED host="HOST_DISCOVERED" earliest=-30m latest=now
("authentication failure" OR "auth failed" OR "relay denied" OR "deferred" OR "sasl")
| table _time host source sourcetype _raw
| head 100
```

This bounded raw-event search returns candidate evidence for manual UTC correlation, not proof of compromise. No results can mean wrong host/index, absent logging/permissions, rotation or broken ingestion. Compare local logs and the shared expected-host silence check before concluding there is no activity. Redact secret-bearing events and keep original evidence protected independently of this host.

## References

Reference URLs were opened through the web tool on **2026-11-13**. Recheck live notices at event time; this is not a live vulnerability assessment. No package CVE or fixed version is inferred from an OS name. Local commands and SPL have not been executed against competition hosts.

- [Ubuntu security notices](https://ubuntu.com/security/notices) and [security update/backport policy](https://documentation.ubuntu.com/security/security-updates/) — match full installed package revisions.
- [Postfix documentation](https://www.postfix.org/postfix-manuals.html) — search result reviewed 2026-11-13; full-page retrieval failed (402), so reverify installed-version manual before use; conditional on confirmed installation.
- [Dovecot documentation](https://doc.dovecot.org/) — conditional on confirmed installation and documentation major version.
- [Environment](../environment.md), [event worksheet](../event-checklist.md).

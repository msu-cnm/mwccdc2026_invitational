# Ubuntu Wkst

Packet inventory: **Ubuntu; version unspecified**, **DHCP**, public/egress **172.31.(20+team).2 (shared egress per packet)**. User workstation; Palo Alto browser management. These are packet facts, not verified live builds or service assignments.

Read [environment constraints](../environment.md) and complete the [event worksheet](../event-checklist.md). Keep a tested NETLAB console and official access, ICMP, general public service availability, names, data and usernames. Preserve NAT, DNS/time, AD, SQL and scoring dependencies. Never limit public services to scoring sources. Coordinate credential changes and PCR updates. No snapshots are available.

## Candidate services on this host

Consolidated per-host map: [host-service-map.md](../host-service-map.md). Packet p.14 leaves precise scored services to the event portal; every entry below is a candidate to discover and confirm, not a confirmed assignment.

| Candidate service | Guide |
|---|---|
| Browser, mail/FTP/SQL clients for scoring verification (outbound only) | [http-https.md](../services/http-https.md), [smtp.md](../services/smtp.md), [pop3-imap-webmail.md](../services/pop3-imap-webmail.md), [ftp.md](../services/ftp.md), [mssql.md](../services/mssql.md) |
| SSH if installed | [ssh.md](../services/ssh.md) |

## Initial checks and system-specific security

Record `ip -br address`, `ip route`, `resolvectl status` (if installed) and DHCP lease information. Keep DHCP, DNS, time, browser access and desktop login working. Use this workstation for Palo Alto management at the packet's management address, with a NETLAB console fallback. Do not turn it into a server or scanning appliance.

Review autostart entries, user crontabs, browser extensions and local privileged accounts without collecting browser cookies/passwords. Preserve normal user functionality; avoid generic kiosk lockdown or a forced firewall default-deny. Test browser access to management and authorized public resources. Watch unexpected listeners, new autostart files and resource exhaustion.

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

Record `dpkg-query -W`, `apt-cache policy`, `snap list` only if installed and `flatpak list` only if installed. Determine release codename and support window from the Ubuntu lifecycle; support for a release does not ensure every package/source is covered. Discover browser executable/package/channel and extensions through Firefox `about:support`/`about:addons` or Chromium-family `chrome://version`/`chrome://extensions`. Browser cookies and profiles contain management credentials; do not copy their contents to a general report.

| Possible scenario | Evidence and applicability | Remedy; interim mitigation | Indicators and required evidence |
|---|---|---|---|
| Unsupported release or unpatched kernel/local package | Actual release/kernel/package full revision matched to lifecycle and USN, with affected local execution/feature prerequisites. OS label alone is insufficient; backports matter. | Apply supported package fix. Unsupported-release migration requires planned tested recovery, not an in-event blanket distribution upgrade. While deferred, use an unprivileged account and avoid untrusted code while retaining management browser and egress. | Unexpected privileged identity/UID-0 process, crashes or changed privileged binaries. Needs auth journal, trusted integrity baseline and optional execution audit; not all local exploits log failures. |
| Vulnerable browser/extension or stolen browser session | Actual browser channel/build, enabled extension ID/version/permissions and vendor advisories; a browser's mere presence is normal. | Update through its discovered trusted delivery channel; review/disable only an unapproved extension after preserving metadata and testing firewall management. Avoid untrusted browsing/downloads pending a fix; do not break required 80/443 egress. | New all-sites extension, changed browser policy/proxy or browser child shell/outbound endpoint. Needs extension/policy baseline and optional process/DNS/proxy logs; URL alone is not proof. |
| Excessive sudo privilege or autostart persistence | `getent group sudo`, UID-0 accounts, effective sudo rules and enabled user/system units/autostart entries compared with roster. Account names containing admin do not establish privilege. | Remove only confirmed unauthorized grant/task with recovery access; use reviewed least privilege. Pending change, monitor elevation and preserve second console; no indiscriminate account resets. | Unapproved group/rule change, root service pointing to writable file, new user startup. Requires auth/sudo logs, config baseline and optional file/exec auditing. |

## Patching and recovery

1. Record installed release, running kernel, package versions, repositories, holds and baseline listeners/authenticated workflows. Use `dpkg-query -W`, `apt-mark showhold` and `apt-cache policy PACKAGE` for each discovered affected package. Match the full distribution version and enabled feature against vendor advisories; old upstream version strings may contain backported fixes.
2. Before changing metadata or software, create a fresh root-only backup directory with `sudo install -d -m 700 /root/event-backups` then `sudo mktemp -d /root/event-backups/change.XXXXXX`. Record the returned path. Use root-owned mode-600 archives of discovered configuration, permissions and application data there, with `sudo sh -c 'umask 077; ...'`. Use the application's consistent backup procedure; a file copy of a running database/queue is not a consistent backup. Keep a protected independent copy through approved channels and test restoration in a disposable system. Never store secrets in `/tmp` or web-accessible directories.
3. Check trusted repository origin/signing settings, disk/inode space (`df -h; df -i`) and recovery packages. Manually run `sudo apt-get update` (metadata mutation only), then `apt-cache policy PACKAGE` and `apt-get -s install --only-upgrade PACKAGE`. Replace PACKAGE with explicit discovered names; review every dependency, removal, held package and service restart. Stop if the plan changes unrelated packages or a supported fix needs an untested release migration.
4. Apply only the reviewed transaction with `sudo apt-get install --only-upgrade PACKAGE`, interactively, without `-y`. Do not enable unattended upgrades or run a blanket upgrade. A package installation can restart services itself: schedule the interruption before starting.
5. Validate native configuration syntax for the discovered service. Restart/reload only affected units when required; updated libraries can leave old processes running. Decide whether the kernel or vendor instructions require reboot; check `/var/run/reboot-required` if present, but its absence does not prove no reboot is needed. Reboot only with console access and an agreed maintenance window.
6. Confirm installed versions, service health, listeners and exact portal authentication/content plus dependencies from authorized paths; observe scoring and logs. An open port is insufficient.
7. On regression, stop additional changes. Restore the single configuration change from its protected backup and native validation, or use a vendor-supported application/data recovery with compatible versions. A prior package may be unavailable or unsafe to downgrade; retain trusted recovery media/packages beforehand, and use console/previous kernel where supported. Recheck service/data integrity and scoring after recovery; record UTC times and the residual exposure.

Workstation specifics: back up discovered browser profiles only while the browser is closed, preserving ownership and treating cookies/tokens as secrets; back up relevant NetworkManager/DNS settings and user/system autostart configuration. For snap/Flatpak/vendor browsers, inspect installed channel/revision and the vendor-supported preview/update/revert limits instead of apt placeholder packages. Review one browser's changes and close/reopen it after update; do not restart NetworkManager as a routine patch step. Test DHCP, route/DNS, time, required web egress, exact Palo Alto management login/UI and official access. Verify trusted certificate behavior rather than bypassing warnings. Recovery may require an earlier supported browser/profile backup or a known kernel via console; restoring a profile can reintroduce a malicious extension or stolen session, so inspect it first.

## Detection when patching is deferred

Associate each deferred exposure with an owner/expiry and the scenario's temporary controls. Linux guard does not enable auditd/process telemetry. Discover auth files from rsyslog and journals; `/var/log/auth.log` may not exist. Review log time/rotation and keep protected independent copies. Browser extension inventory is often only native UI/local profile evidence, not a central log feed. Changes to management cookies/credentials require coordinated session revocation and PCR updates where applicable; do not export profile secrets. Monitor sudo/auth events and new user/system startup entries against a reviewed baseline while preserving workstation role and outbound research/patch access.

## Threat hunting

1. **Hypothesis: unauthorized privilege was granted.** Run `getent passwd | awk -F: '$3==0 {print $1,$3,$6,$7}'`, `getent group sudo`, `sudo visudo -c`, and `sudo journalctl --since '-30 minutes' --until now --no-pager -n 500 SYSLOG_IDENTIFIER=sudo`. Inspect the last command's collection coverage and effective `sudo -l -U USER` for a specific reviewed identity. Suspicious: unexpected UID-0 account, NOPASSWD wildcard or new grant. Benign: approved operator provisioning. Follow up with roster/change history and preserve sudoers metadata before editing; `visudo -c` only validates syntax.
2. **Hypothesis: browser access persisted via extension/policy.** In the running browser's native version/extensions/policy pages record IDs, permissions, install source and policy; compare the saved roster. Run `sudo ps -eo user,pid,ppid,lstart,comm` and `sudo ss -ntp` for current children/peers. Suspicious: unknown all-sites extension or shell descendant correlated with recent navigation. Benign: approved password manager, browser subprocesses, proxy/SSO extension. Follow up with signed vendor package metadata and a bounded last-30-minute DNS/proxy/process history **only if collected**; preserve extension metadata without replaying suspicious URLs.
3. **Hypothesis: user startup launches a payload.** As the logged-in desktop user run `systemctl --user list-unit-files --state=enabled --no-pager` and `find "$HOME/.config/autostart" "$HOME/.config/systemd/user" -maxdepth 3 -type f -mmin -60 -ls` (missing directories are normal). Also `systemctl list-timers --all --no-pager`; inspect selected changed definitions locally. Suspicious: startup command from a writable temporary/download directory or unknown network fetch. Benign: approved desktop helper or updater. Follow up with file hashes, owner and install/change time; compare a known-good baseline before disabling a single entry and retesting management access.

## Splunk monitoring

For installation, input configuration, validation and rollback for this host, use [concrete data-source setup](../splunk-data-sources.md).

Use the [shared Splunk guide](../splunk-threat-hunting.md) for collection, time, health checks, field discovery and evidence handling. `ubuntu-workstation` is a topology ID, **not a verified hostname**. Replace `HOST_DISCOVERED` and `INDEX_DISCOVERED` below after checking ingestion with `index=INDEX_DISCOVERED host="HOST_DISCOVERED" earliest=-15m latest=now | head 20`. Discover actual `source`, `sourcetype` and raw event formats before adding field-based filters.

Candidate available telemetry is auth/sudo and service journal output if actually retained. Optional: browser extension/policy snapshots, auditd exec/file events, DNS/proxy logs; no existing guard setting collects browser history or process trees. Ingest only approved discovered files/exports and avoid collecting secrets from browser profiles.

```spl
index=INDEX_DISCOVERED host="HOST_DISCOVERED" earliest=-30m latest=now
("sudo" OR "session opened for user root" OR "useradd" OR "usermod")
| table _time host source sourcetype _raw
| head 100
```

This bounded raw-event search returns candidate evidence for manual UTC correlation, not proof of compromise. No results can mean wrong host/index, absent logging/permissions, rotation or broken ingestion. Compare local logs and the shared expected-host silence check before concluding there is no activity. Redact secret-bearing events and keep original evidence protected independently of this host.

## References

Reference URLs were opened through the web tool on **2026-11-13**. Recheck live notices at event time; this is not a live vulnerability assessment. No package CVE or fixed version is inferred from an OS name. Local commands and SPL have not been executed against competition hosts.

- [Ubuntu release lifecycle](https://ubuntu.com/about/release-cycle) and [USNs](https://ubuntu.com/security/notices).
- [Ubuntu security updates/backports](https://documentation.ubuntu.com/security/security-updates/).
- [Mozilla add-on management](https://support.mozilla.org/en-US/kb/find-and-install-add-ons-add-features-to-firefox) — native extension review, if Firefox is installed.
- [Environment](../environment.md), [event worksheet](../event-checklist.md).

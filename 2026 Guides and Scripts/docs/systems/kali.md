# Kali

Packet inventory: **Kali; version unspecified**, **172.17.0.2**, public/egress **172.31.(20+team).2 (shared egress per packet)**. User workstation directly connected to VyOS. These are packet facts, not verified live builds or service assignments.

Read [environment constraints](../environment.md) and complete the [event worksheet](../event-checklist.md). Keep a tested NETLAB console and official access, ICMP, general public service availability, names, data and usernames. Preserve NAT, DNS/time, AD, SQL and scoring dependencies. Never limit public services to scoring sources. Coordinate credential changes and PCR updates. No snapshots are available.

## Candidate services on this host

Consolidated per-host map: [host-service-map.md](../host-service-map.md). Packet p.14 leaves precise scored services to the event portal; every entry below is a candidate to discover and confirm, not a confirmed assignment.

| Candidate service | Guide |
|---|---|
| Attack/verification tooling (Nmap via kali_watch.py, mail/FTP/SQL/DNS clients) | [kali-operations](../kali-operations.md) |
| SSH for administration | [ssh.md](../services/ssh.md) |

## Initial checks and system-specific security

This workstation is directly attached to VyOS on 172.17.0.0/24, not the inside server LAN. Check `ip -br address`, `ip route`, `cat /etc/resolv.conf` and local listeners. Its packet address is 172.17.0.2; VyOS workstation interface is 172.17.0.1. Do not assign the shared external egress address locally.

Retain workstation function, router management, DNS and permitted outbound access. Review local privileged users, SSH configuration, cron/systemd persistence and desktop autostart. Kali includes offensive tools; their presence does not authorize scanning outside owned systems. Use local inspection and **bounded, explicitly authorized service checks** (see [kali_watch.py](../kali-operations.md)), not broad network scans. Monitor unexpected listeners and resource use; maintain a console before adjusting any local security setting.

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

Inventory `dpkg-query -W`, `apt-cache policy`, `apt-mark showhold`, repository definitions under `/etc/apt/sources.list` and `/etc/apt/sources.list.d/` (including `.sources`), and signing-key configuration. Compare actual branch and signed origin to official Kali documentation; do not replace sources with copied defaults. Kali is rolling: ordinary upstream Debian fixed versions do not by themselves establish Kali package status. Installed security tools and administrator research are expected and **are not evidence of compromise**; do not run scans/exploit demonstrations.

| Possible scenario | Evidence and applicability | Remedy; interim mitigation | Indicators and prerequisites |
|---|---|---|---|
| Vulnerable kernel/sudo/local package in rolling state | Record running kernel, full package revision, actual signed candidate and relevant vendor/Kali patch state. A tool listing or old upstream banner is insufficient. | Review a narrow compatible security fix; defer broad rolling transitions to rehearsal. While deferred avoid untrusted executables and daily root sessions without changing workstation role. | Unknown privileged binary/UID-0 identity, unexplained elevation or crashes. Needs auth journal, reviewed integrity baseline and optional execution audit. |
| Untrusted repository/key or mixed branches | Inspect `.list`/`.sources`, Signed-By, package origins and APT history against approved baseline. A mirror's different name alone does not prove compromise. | Restore authorized signed repositories/keys via official documented process, then reinstall only proven affected packages from trusted media after review. Never bypass signatures with trusted=yes or insecure apt flags. Temporarily stop installing from a suspect source while preserving egress/access. | Unexpected source/key changes, unauthenticated update warnings, packages from unapproved origin. Requires source/key baseline and apt/dpkg logs; historical origin may need retained metadata. |
| SSH/persistence or excessive privilege | Map actual ssh unit, `sudo /usr/sbin/sshd -T` if installed (Match behavior needs connection context), sudo policy, authorized-key metadata and units/timers versus roster. Preserve password-based scoring/official access. | Correct only unauthorized keys/grants/startup entries; narrowly patch OpenSSH if applicable. Pending fix watch sessions and changes; don't globally disable SSH/password authentication or delete users. | Unknown key, failures followed by success, new root task/writable executable. Requires SSH/auth logs, config baseline and optional file/exec audit. |

## Patching and recovery

1. Record installed release, running kernel, package versions, repositories, holds and baseline listeners/authenticated workflows. Use `dpkg-query -W`, `apt-mark showhold` and `apt-cache policy PACKAGE` for each discovered affected package. Match the full distribution version and enabled feature against vendor advisories; old upstream version strings may contain backported fixes.
2. Before changing metadata or software, create a fresh root-only backup directory with `sudo install -d -m 700 /root/event-backups` then `sudo mktemp -d /root/event-backups/change.XXXXXX`. Record the returned path. Use root-owned mode-600 archives of discovered configuration, permissions and application data there, with `sudo sh -c 'umask 077; ...'`. Use the application's consistent backup procedure; a file copy of a running database/queue is not a consistent backup. Keep a protected independent copy through approved channels and test restoration in a disposable system. Never store secrets in `/tmp` or web-accessible directories.
3. Check trusted repository origin/signing settings, disk/inode space (`df -h; df -i`) and recovery packages. Manually run `sudo apt-get update` (metadata mutation only), then `apt-cache policy PACKAGE` and `apt-get -s install --only-upgrade PACKAGE`. Replace PACKAGE with explicit discovered names; review every dependency, removal, held package and service restart. Stop if the plan changes unrelated packages or a supported fix needs an untested release migration.
4. Apply only the reviewed transaction with `sudo apt-get install --only-upgrade PACKAGE`, interactively, without `-y`. Do not enable unattended upgrades or run a blanket upgrade. A package installation can restart services itself: schedule the interruption before starting.
5. Validate native configuration syntax for the discovered service. Restart/reload only affected units when required; updated libraries can leave old processes running. Decide whether the kernel or vendor instructions require reboot; check `/var/run/reboot-required` if present, but its absence does not prove no reboot is needed. Reboot only with console access and an agreed maintenance window.
6. Confirm installed versions, service health, listeners and exact portal authentication/content plus dependencies from authorized paths; observe scoring and logs. An open port is insufficient.
7. On regression, stop additional changes. Restore the single configuration change from its protected backup and native validation, or use a vendor-supported application/data recovery with compatible versions. A prior package may be unavailable or unsafe to downgrade; retain trusted recovery media/packages beforehand, and use console/previous kernel where supported. Recheck service/data integrity and scoring after recovery; record UTC times and the residual exposure.

Kali-specific planning: official rolling-update guidance warns that updates can disrupt needed tools during an engagement. Inspect branch, dependencies and apt history before selecting a narrow fix. If the supported fix requires a large rolling transition, defer it with documented controls until rehearsal/maintenance; do not blindly run `full-upgrade`, change branches, mix Debian/Ubuntu repositories or add signing exceptions. Back up discovered SSH config/keys with protected permissions, package selections, source/key metadata and required user data. Validate existing SSH syntax with `sudo /usr/sbin/sshd -t` before a reload; retain a second authenticated session plus console, and test a fresh authorized login before closing either. Verify VyOS route/DNS, required browser egress, ICMP and official access. Retain known bootable kernel/trusted recovery media; a rolling downgrade may not be supported.

## Detection when patching is deferred

For each scenario record the actual package/build or config evidence, tested temporary control, owner and expiry. Use the actual SSH unit journal or rsyslog destination; Kali may not have `/var/log/auth.log`. Collect authorized change logs and package origin metadata, not private SSH keys or command environments. Linux guard does not enable execution/file auditing. Unknown network activity merits attribution to PID, owner and authorized purpose, not automatic blocking because a process is a security tool. Maintain independent protected log/baseline copies; local root compromise can alter timestamps and package verification data.

## Threat hunting

1. **Hypothesis: SSH credentials or keys were abused.** `sudo journalctl -u ssh -u sshd --since '-30 minutes' --until now --no-pager -n 500` and `last -n 20` provide bounded candidates if those sources exist. Inspect metadata (`stat`) for the reviewed user's actual authorized-key file and effective ssh config, without printing private keys. Suspicious: unfamiliar successful identity/source after failures or an unapproved key. Benign: NAT, operator reconnects and scoring logins. Correlate source/time with team roster and key fingerprints (`ssh-keygen -lf PUBLIC_KEY_FILE` only for discovered public-key files), then coordinate narrowly scoped recovery.
2. **Hypothesis: a package source was substituted.** Review `apt-cache policy`, `sudo find /etc/apt/sources.list.d -maxdepth 1 -type f -mtime -1 -ls`, and last 100 lines of actual `/var/log/apt/history.log` and `/var/log/dpkg.log` if present (`sudo tail -n 100 PATH`). Suspicious: unexpected source/signing changes or unapproved package installation. Benign: documented mirror/format migration or planned updates. Follow up by comparing protected source/key hashes and official metadata; preserve logs before restoring configuration. These current-file/history bounds do not prove that an earlier modification never happened.
3. **Hypothesis: local startup maintains elevated access.** Run `getent group sudo`, `getent passwd | awk -F: '$3==0 {print $1,$3,$6,$7}'`, `sudo visudo -c`, `systemctl list-timers --all --no-pager`, and `sudo ps -eo user,pid,ppid,lstart,comm`. Inspect only selected unexpected service/timer definitions with `systemctl cat UNIT`; as the actual user inspect `systemctl --user list-unit-files --state=enabled --no-pager`. Suspicious: unknown UID-0 account or privileged startup launching writable content. Benign: approved tools/services and operator provisioning. Follow up with owner, executable hash, bounded last-30-minute auth journal and change roster before modifying any task; tool presence alone is not malicious.

## Splunk monitoring

For installation, input configuration, validation and rollback for this host, use [concrete data-source setup](../splunk-data-sources.md).

Use the [shared Splunk guide](../splunk-threat-hunting.md) for collection, time, health checks, field discovery and evidence handling. `kali` is a topology ID, **not a verified hostname**. Replace `HOST_DISCOVERED` and `INDEX_DISCOVERED` below after checking ingestion with `index=INDEX_DISCOVERED host="HOST_DISCOVERED" earliest=-15m latest=now | head 20`. Discover actual `source`, `sourcetype` and raw event formats before adding field-based filters.

Candidate telemetry: the discovered SSH/auth journal and apt/dpkg logs if retained and collected. Optional: source/key hash inventory, exec/file audit, user-unit inventory and network flow. Do not assume installed offensive tools generate logs or that process command-line collection is enabled.

```spl
index=INDEX_DISCOVERED host="HOST_DISCOVERED" earliest=-30m latest=now
("Failed password" OR "Accepted password" OR "Accepted publickey" OR "sudo")
| table _time host source sourcetype _raw
| head 100
```

This bounded raw-event search returns candidate evidence for manual UTC correlation, not proof of compromise. No results can mean wrong host/index, absent logging/permissions, rotation or broken ingestion. Compare local logs and the shared expected-host silence check before concluding there is no activity. Redact secret-bearing events and keep original evidence protected independently of this host.

## References

Reference URLs were opened through the web tool on **2026-11-13**. Recheck live notices at event time; this is not a live vulnerability assessment. No package CVE or fixed version is inferred from an OS name. Local commands and SPL have not been executed against competition hosts.

- [Kali updating guidance](https://www.kali.org/docs/general-use/updating-kali/) — rolling changes and engagement timing.
- [Kali repository/signing configuration](https://www.kali.org/docs/general-use/kali-apt-sources/) — compare installed format/branch; no blind replacement.
- [Kali branches](https://www.kali.org/docs/general-use/kali-branches/) — branch-specific update behavior.
- [kali_watch operations guide](../kali-operations.md) — bounded network mapping, exposure assessment and service monitoring from this workstation.
- [Environment](../environment.md), [event worksheet](../event-checklist.md).

# VyOS Router

Packet p.13: **VyOS 1.4.0**. Address: **external 172.31.(20+team).2/29; wkst 172.17.0.1/24; internal 172.16.0.254/24**. Public/egress: **172.31.(20+team).2**. Role: Router; preserve forwarding, routes and NAT. Exact score checks are unconfirmed until the portal publishes them (p.14).

Read [environment constraints](../environment.md) and complete the [event worksheet](../event-checklist.md) first. Keep NETLAB console access. Do not change names, addresses, usernames or workstation roles. Preserve ICMP and official access. Do not close ports based on conventional port examples.

## Candidate services on this host

Consolidated per-host map: [host-service-map.md](../host-service-map.md). Packet p.14 leaves precise scored services to the event portal; every entry below is a candidate to discover and confirm, not a confirmed assignment.

| Candidate service | Guide |
|---|---|
| Routed interfaces, NAT for workstation egress, DHCP on 172.17.0.0/24 | [vyos-palo-alto.md](../services/vyos-palo-alto.md) |

## Initial checks and system-specific security

Verify `show version`, `show interfaces`, `show ip route`, `show configuration commands` and `show log` locally. Configuration/log output can include secrets; protect any export. External is 172.31.(20+team).2/29 toward core .1; internal 172.16.0.254/24 toward Palo Alto .1; workstation 172.17.0.1/24 toward Kali .2. Confirm actual NAT and routes, rather than replacing them with guessed defaults.

Back up the running saved configuration securely using the supported `save` path on the actual appliance, and verify it contains the current intended state. In configuration mode review `compare` before committing. Discover the installed 1.4 firewall syntax with CLI help; do not paste older-version firewall commands. Preserve forwarding, ICMP, established/related return traffic, public NAT and workstation egress. Any management restriction must retain console, team access and official troubleshooting.

Use `commit-confirm 5` only after verifying this build supports it and understanding the timeout. Test the resulting paths from authorized endpoints and observe Quotient before `confirm` and `save`. If testing fails, do not confirm; use the console to restore the known-good configuration or allow the confirmed-commit rollback, then verify routes/NAT/services. Do not save a failed candidate. Monitor interface counters, route changes, conntrack pressure and configuration commits. Do not run the generic Linux hardener on the router appliance.

## Scripts and reversible changes

Use native appliance CLI/GUI commands below; the Linux and Windows scripts are not supported on this appliance. No automatic firewall/routing script is supplied because live policies, dependencies and exact scored port assignments are not present in the packet.

## Monitoring and scoring verification

Capture a baseline before changes, then compare service health, listeners, authentication events, persistence and resources at least every few minutes. Follow the system-specific checks above and [incident workflow](../event-checklist.md). Confirm every assigned authenticated/content check in Quotient at `https://quotient.ccdc.events/`, available also through `https://auth.ccdc.events/`. Internal success alone does not prove public NAT or scoring success. No scripted connectivity check against arbitrary targets is provided.

After each single change test existing management, ICMP and the actual scored workflow; check every downstream dependent system. Coordinate password updates with dependency owners and immediately update Quotient PCR. Store secrets separately. If anything regresses, use the script rollback or saved native configuration, retest and record the outcome. Do not rely on VM snapshots; the packet says they are unavailable.

Validation status: documentation is based on packet facts, with uncertainty stated. No live competition system or representative VM was available for connectivity, service recovery or platform-specific runtime validation. Rehearsal remains mandatory before event deployment.

## Vulnerabilities and applicability

Packet **1.4.0** is not a verified current image. As an authorized operator record `show version`, `show system image`, `show configuration commands` and enabled services using local CLI completion. Keep complete build/commit/hotfix provenance, listening addresses and approved management sources privately. VyOS images bundle components; upstream package versions alone do not establish vulnerability or the presence of vendor fixes. Never use `apt upgrade`, `apt dist-upgrade` or the generic Linux guard on this appliance.

| Scenario and discovery evidence | Applicability and permanent remedy | Temporary mitigation preserving scoring | Exploitation indicators and logging prerequisites |
|---|---|---|---|
| Listening Zabbix agent RCE, **CVE-2023-32728**: inspect `show configuration commands` for `service monitoring zabbix-agent`, its listen address and allowed server; in configuration mode `show service monitoring` is read-only inspection. | Official VyOS advisory identifies 1.4.0's agent and requires it to be configured and listening. Record absence as an unmet prerequisite. Vendor hotfix or a supported image containing the fix is needed; the 1.4.1 release notes explicitly include it. Confirm current target's full advisory coverage and server compatibility. | If monitoring is unused/unscored, review disabling just that service; otherwise restrict only its management listener to verified collectors with official/team access retained. Do not restrict public scored services or interrupt routing. | Unexpected monitoring requests followed by service errors, administrator actions, outbound sessions or changed configuration. Requires existing service/syslog and firewall logging; commands executed through a vulnerable agent may not create authentication events. Missing request-level logs limits detection. |
| SSH/HTTP management software exposure: inspect enabled `service ssh` and `service https` and listen addresses, actual image/hotfix record. | VyOS 1.4.1 release notes include fixes for **CVE-2024-6387** (OpenSSH) and **CVE-2024-53981** (HTTP API multipart DoS). Treat 1.4.0 as a review candidate: confirm bundled fix status and the relevant listening service, and for API DoS the relevant API request handling. Do not infer exploitability from the OS name or claim every SSH error is exploitation. Use a supported fixed image or vendor hotfix explicitly matching the build. | Limit management exposure to discovered team/official paths; preserve required SSH authentication and tested console. Disable unused API only after dependency review. Keep forwarding, ICMP, workstation egress and public NAT untouched. | Abnormal unauthenticated connection bursts, API errors/unresponsiveness or SSH daemon failures plus unexpected successful access. Authorization/syslog/service logs and monitoring are prerequisites; race-condition attempts and DoS may leave no definitive marker. Correlate load and legitimate management automation before concluding compromise. |
| Unauthorized users, keys, hooks, route/NAT/firewall or syslog changes: compare protected baseline with current configuration and commit history. | Applies when unnecessary privileges or unapproved differences exist; this is a misconfiguration/persistence scenario, not a CVE. Restore individually reviewed changes and use least-privilege management identities where supported; coordinate credential changes/PCR. Review authorized `/config` scripts because these survive image upgrades. | Increase commit review and retain independent exports; revert only evidenced malicious changes with console/commit-confirm protection. Avoid broad deny policies or account resets. | Unknown administrator/key, unexpected post-config script, new next hop/NAT destination, permissive rule, or removed syslog target. Requires retained commit history, authorization logs, baseline hashes and optional logged firewall rules. A legitimate inject or operator commit can explain differences. |

The cited historical releases are evidence for individual fixes, not a recommendation to install an obsolete image. Review current official release/security notices and image entitlement, platform and migration compatibility before selecting a target. No appliance upgrade is performed by this guide.

## Patching and recovery

1. Discover full image/build, boot mode, storage capacity, current/saved configuration differences, interface mapping, NAT, firewall, routes and management services. Record exact portal checks and current public/internal functionality, ICMP, workstation egress through external `.2/29` and core next hop `.1`; substitute the assigned team subnet. Test NETLAB console before maintenance.
2. In configuration mode inspect `compare` before saving; do not accidentally save an unreviewed candidate. Save the known-good configuration to a unique protected file via native `save <path>` and securely export it using an authorized supported transfer. Preserve keys/certificates and reviewed `/config` scripts, commit history and relevant logs separately. Backups contain secrets. Retain a known-good installed image and its configuration; verify restoration on a disposable equivalent.
3. Preview manually: read target release notes and migration caveats, select the correct platform update ISO from the authorized vendor source, verify signature/checksum against trusted vendor material and record source/hash. Check free space and `show system image`; do not delete the only working fallback. Confirm signed LTS image access and competition software rules; do not substitute arbitrary rolling images or enable unattended upgrades. Review intended configuration migration and each supported intermediate step; rehearse it away from scoring.
4. Manually run operational `add system image <verified-local-ISO-path>` with the actual chosen file, following prompts for image name, copied configuration and SSH keys after reviewing their trust. This installs an image, not proof of a successful upgrade. Inspect `show system image` and confirm the intended next-boot selection. An installed image needs reboot to become running; schedule this disruption explicitly because router restart interrupts NAT, management and all downstream services. Configuration-only changes normally use native commit rather than reboot.
5. After the coordinated reboot, check `show version`, `show interfaces`, `show ip route`, `show configuration commands`, logs and current/default image. Compare interface addresses, route next hops, NAT/firewall and logging with baseline. Test public authenticated/content checks and ICMP, team/official management, workstation browser egress and all downstream dependencies from authorized locations; observe Quotient before accepting the change.
6. If the new image fails, use console to choose the retained known-good image in GRUB, or operational `set system image default-boot <known-good-image>` and reboot when reachable. Each image has its own configuration: confirm the old image's configuration matches the required current baseline, rather than assuming new-image changes carried back. Restore reviewed native configuration using `load <backup-path>`, inspect `compare`, then commit/verify/save only the healthy result. For configuration-only changes use supported `commit-confirm` and console rollback described above; it does not roll back an image. If no retained image boots, use staff-approved vendor installation/recovery media and protected backups; no snapshots exist. Patching alone does not establish removal of compromised `/config` persistence.

## Detection when patching is deferred

Name an owner, reason and next review time. Every 15 minutes inspect authorization/service events and compare current configuration and latest commits to a separately retained baseline. Check route/NAT/interface state and whether syslog still reaches the authorized collector. Keep UTC timestamps, hashes and original bounded logs outside the router when approved; redact credentials from incident reports. Unknown script/account additions or logging suppression plus a suspicious session warrant immediate evidence preservation and a coordinated response, not a blind reboot.

Syslog has local and optional remote targets; inspect actual `system syslog` settings and rotation before relying on history. Firewall/NAT packet events exist only for enabled logging rules/features and may be rate-limited. There is no universal appliance EDR or process audit assumed. Service failures alone do not prove exploitation, and clean authorization logs cannot exclude agent/API execution. Do not add unbounded traffic logging that exhausts router/collector disk or breaks forwarding.

## Threat hunting

Use an authorized operator account for the read-only commands below; CLI capabilities vary by image, so inspect `?`/tab completion rather than dropping into unsupported shell commands. Use a fixed UTC incident interval (start with 15 minutes). `show log tail 200` bounds output; if retained rows do not reach the interval start, this is incomplete coverage: inspect the appropriate bounded archived log through native categories or the collector. Configuration output can expose hashes/keys; store it privately.

1. **Hypothesis: an unauthorized administrator changed access or installed persistent configuration.** Inspect `show log tail 200` and the authorization category available through `show log ?`, retaining only events in the chosen interval. Run `show system commit` and inspect `show system commit diff 1` (confirm syntax in this build), then compare `show configuration commands` for login users/keys, SSH/API, syslog and task/script configuration against approved baseline. In configuration mode use `compare` to detect uncommitted edits without committing. Unknown source/login plus new key or logging removal is suspicious. Team maintenance and automation are benign explanations; verify operator/inject records, preserve diff and correlate later actions. A new committed configuration without an authentication record may signal missing logs or noninteractive access.
2. **Hypothesis: traffic was redirected by a route/NAT/firewall edit.** Capture `show ip route`, `show interfaces` and `show configuration commands`, comparing to the last approved export; inspect latest five commit entries and their relevant diffs. Look for changed core next hop, unexpected more-specific routes, changed destination NAT or permissive rule/order. Planned injects, DHCP changes or dynamic routing convergence can explain differences. Determine which routes are static/dynamic and correlate the control-plane peer/commit and affected service; test only authorized paths before targeted restoration. Current state cannot show a reverted transient attack without retained history.
3. **Hypothesis: an exposed management service is being abused or an internal host is creating unusual flows.** Inspect `show log tail 200` for SSH/API/monitoring errors and authentication source addresses during the fixed interval. Use the image's available `show conntrack ?` summary/table and native NAT operational subcommands via `show nat ?`; take one bounded display (at most 200 rows) and compare two snapshots five minutes apart. Filter to an already identified host/session when supported. Unexpected external management sources, new high-volume destinations or rapid failures after an unknown commit warrant endpoint correlation. Patches, backups, research and legitimate mail connections are benign explanations; compare with dependency inventory and peer host logs. Existing conntrack entries are state, not a historical packet log, and unsupported filtering should be replaced with bounded collector searches rather than full packet capture.

## Splunk monitoring

For installation, input configuration, validation and rollback for this host, use [concrete data-source setup](../splunk-data-sources.md).

See [shared telemetry, searches and collection checks](../splunk-threat-hunting.md). Locally retained syslog/authorization and commit history are discovery sources, not proof of central ingestion. Remote syslog is optional: inspect actual `system syslog` destinations, permitted transport and collector input before proposing changes. Do not install a forwarder on the appliance or assume port 514, a Splunk add-on, command auditing or logged firewall accepts exist. Propose `vyos:syslog` only as a collection label; discover actual source, hostname, facility, timezone and parsed fields. Some messages lack complete year/timezone; verify timestamp parsing and synchronization.

Replace all `REPLACE_*` labels with discovered values. This host-specific raw search needs ingested VyOS syslog with correct `_time`, `host` and readable `_raw`; it uses no add-on fields:

```spl
index=REPLACE_INDEX host="REPLACE_VYOS_HOST" sourcetype="REPLACE_VYOS_SOURCETYPE" earliest=-15m latest=now
("sshd" OR "commit" OR "configuration" OR "zabbix" OR "authentication")
| table _time host source _raw
| head 100
```

Expected rows are management/service messages to correlate with native authorization/commit history. Inspect raw text and map user, source-IP, result and command fields only when present (`| fieldsummary` on a separate bounded host search helps). Keyword matches can miss alternate daemon formats, so also review the same host/time without keywords before treating no rows as absence of activity. Approved commits and collector polling are benign explanations. Follow up unknown sources or configuration edits against the worksheet and local baseline. Zero events can indicate wrong labels, stopped ingestion or time parsing errors; compare local same-window events and the shared inventory-based silence check. Preserve independent local evidence if Splunk is compromised. No live SPL execution or collection deployment was performed.

## References

Official sources opened and checked **2026-11-13**. Recheck current advisories and release notes before selecting an image; no live vulnerability determination has been made.

- [VyOS advisory: CVE-2023-32728 and listening-agent prerequisite](https://blog.vyos.io/remote-code-execution-in-listening-zabbix-agent-cve-2023-32728).
- [VyOS 1.4.1 release: bundled security fixes and platform-specific update images](https://blog.vyos.io/vyos-1.4.1-release).
- [VyOS 1.4 supported image update workflow](https://docs.vyos.io/en/1.4/installation/update.html).
- [VyOS 1.4 image selection and rollback](https://docs.vyos.io/en/1.4/installation/image.html).
- [VyOS 1.4 syslog and native log inspection](https://docs.vyos.io/en/1.4/configuration/system/syslog.html).
- [VyOS 1.4 CLI and commit diffs](https://docs.vyos.io/en/1.4/cli.html).

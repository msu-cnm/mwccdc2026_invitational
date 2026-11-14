# Palo Alto

Packet p.13: **PAN-OS 11.0.2**. Address: **outside 172.16.0.1/24; inside 172.20.240.254/24; management 172.20.240.200**. Public/egress: **NAT mappings require discovery**. Role: Boundary firewall; preserve security rules, NAT, routes and management. Exact score checks are unconfirmed until the portal publishes them (p.14).

Read [environment constraints](../environment.md) and complete the [event worksheet](../event-checklist.md) first. Keep NETLAB console access. Do not change names, addresses, usernames or workstation roles. Preserve ICMP and official access. Do not close ports based on conventional port examples.

## Candidate services on this host

Consolidated per-host map: [host-service-map.md](../host-service-map.md). Packet p.14 leaves precise scored services to the event portal; every entry below is a candidate to discover and confirm, not a confirmed assignment.

| Candidate service | Guide |
|---|---|
| Firewall/NAT policies (source NAT to 172.25.(20+team).x, port forwarding for scored services) | [vyos-palo-alto.md](../services/vyos-palo-alto.md) |
| Security rules and management interface (172.20.240.200) | [vyos-palo-alto.md](../services/vyos-palo-alto.md) |

## Initial checks and system-specific security

Access management at `https://172.20.240.200` from an inside Ubuntu or Windows workstation; packet CLI console is available through NETLAB. Verify interfaces: inside 172.20.240.254/24, outside 172.16.0.1/24. Do not confuse the management address with the inside interface. Record actual zones, virtual router, route table, security/NAT rules and rule order.

In operational mode inspect `show system info`, `show interface all`, `show routing route` and `show session info`. In the GUI inspect Monitor > Traffic/System/Config and Policies > Security/NAT. Export a named configuration snapshot securely before editing. Review management administrators and services; change shared default passwords through the approved interactive path and retain a tested second console. Restrict management only after discovering actual operator and official access paths; public scored services must remain available to all sources.

For each rule, trace original public destination, translation, zones, application/service matching and return path; preserve ICMP and all discovered dependencies. Do not enable broad IPS blocks or application-default rules without testing actual scored traffic. Use candidate `validate full` before commit; inspect the validation job result and configuration diff. Have a second operator and rollback snapshot ready. After commit, test exact public services and management from authorized locations and check Quotient. If regression occurs, load the saved known-good configuration snapshot and commit, then recheck; loading a candidate alone does not restore running policy. Protect exports because they can contain sensitive configuration.

## CLI reference for the assigned operator

Run discovery commands in operational mode (`>`). Addresses in service guides are packet examples: substitute the confirmed host, interface and port. Use `?` or Tab at each command level to inspect options on the installed release.

```text
show system info
show interface all
show routing route
show running nat-policy
show running security-policy
show session info
show system resources
```

Service guides provide destination/port session examples. NAT can change the address or port visible in a session; compare original and translated tuples in Monitor > Traffic and inspect the full session before concluding a flow is absent. A `| match` address search only selects matching output lines: rules using address objects, groups or `any` may not contain that literal address. Inspect the complete policy and resolve objects as well. No matching sessions does not prove that a service is blocked or unused.

For a reviewed configuration edit, use configuration mode (`#`) with a tested console and backup first:

```text
configure
run show config diff
validate full
```

Inspect the returned validation job from configuration mode with `run show jobs id JOB_ID` (replace `JOB_ID`), or `show jobs id JOB_ID` at the operational prompt. `show config diff` is operational; use its `run` prefix while in configuration mode. Validation does not activate changes or test connectivity. After reviewing the diff and validation result, `commit` in configuration mode activates the candidate; check its job result and all scored workflows. See the [firewall service guide backup procedure](../services/vyos-palo-alto.md#backup) before proceeding.

To restore a saved named configuration, use `load config from SAVED_FILE.xml` in configuration mode, review `run show config diff`, run `validate full`, inspect the job, then `commit`. Substitute the actual known-good file; loading alone changes only the candidate. This replaces configuration and can interrupt access, so coordinate with service owners and recheck management, NAT, routes and scoring afterward.

## Scripts and reversible changes

Use native appliance CLI/GUI commands below; the Linux and Windows scripts are not supported on this appliance. No automatic firewall/routing script is supplied because live policies, dependencies and exact scored port assignments are not present in the packet.

## Monitoring and scoring verification

Capture a baseline before changes, then compare service health, listeners, authentication events, persistence and resources at least every few minutes. Follow the system-specific checks above and [incident workflow](../event-checklist.md). Confirm every assigned authenticated/content check in Quotient at `https://quotient.ccdc.events/`, available also through `https://auth.ccdc.events/`. Internal success alone does not prove public NAT or scoring success. No scripted connectivity check against arbitrary targets is provided.

After each single change test existing management, ICMP and the actual scored workflow; check every downstream dependent system. Coordinate password updates with dependency owners and immediately update Quotient PCR. Store secrets separately. If anything regresses, use the script rollback or saved native configuration, retest and record the outcome. Do not rely on VM snapshots; the packet says they are unavailable.

Validation status: documentation is based on packet facts, with uncertainty stated. No live competition system or representative VM was available for connectivity, service recovery or platform-specific runtime validation. Rehearsal remains mandatory before event deployment.

## Vulnerabilities and applicability

Treat packet **11.0.2** as a discovery lead. The vendor documentation labels the 11.0 train end of life; plan a supported release migration after compatibility and maintenance review, rather than treating an old branch hotfix as sufficient ongoing support. An authorized read-only administrator should record `show system info` (including complete hotfix suffix/model), installed content versions, management reachability, interface-management profiles, and Network > GlobalProtect > Portals/Gateways. Store dated evidence privately. Compare the actual build with each advisory's affected/unaffected table; a similar version string or an Internet connection alone does not confirm exploitation.

| Scenario and discovery evidence | Applicability and permanent remedy | Temporary mitigation preserving scoring | Exploitation evidence and prerequisites |
|---|---|---|---|
| Management web authentication bypass, **CVE-2024-0012**: inventory Device > Setup > Management and interface-management profiles, administrator accounts and reachable web-management interfaces. | Base 11.0.2 is in the affected branch; vendor lists 11.0.2-h5 as a branch fix. Verify actual suffix and current advisory; this historical fix is not a recommended overall target. Choose a supported vendor-approved release addressing all applicable advisories. Requires network access to management web interface; GlobalProtect is not required. | Limit management only to discovered team and official management paths, retaining workstation browser access and console. Remove unnecessary data-interface management exposure after testing. This restriction must never become a source allowlist for public scored applications. | Unknown administrative actions, new accounts/API use, configuration tampering or log gaps. Collect System and Config logs, administrator session/source information and configuration versions; bypass may lack normal failed-login events. No failed logins is not exoneration. |
| GlobalProtect command injection, **CVE-2024-3400**: record actual build and configured portal/gateway. | Vendor requires a configured GlobalProtect portal or gateway; telemetry enablement is **not** required. Base 11.0.2 is affected; 11.0.2-h4 is one branch fix. If neither feature exists, document this prerequisite as absent. Upgrade via a supported path, rather than assuming one famous CVE defines safety. | If feature is genuinely unused and unscored, review disabling it with dependency owner. Otherwise evaluate advisory-specific threat prevention mitigations only with required subscription/content and explicit policy coverage; do not promise protection from an unlicensed profile or block legitimate VPN/scored traffic. | Unexpected portal/gateway requests, correlated crashes, unknown outbound connections or configuration activity warrant escalation. Collect GlobalProtect/System/Threat logs where enabled, retained traffic and protected support bundle. Ordinary traffic logging may miss management-plane execution; obtain vendor-supported forensic review instead of running exploit probes or shell commands. |
| Excessive administrator privileges or unauthorized NAT/security/route changes: compare named accounts, roles, permitted IPs, policy order and configuration versions against approved baseline. | Applies when unnecessary privileges, shared credentials or unapproved changes exist; it is a configuration finding, not a CVE. Use individual least-privilege administrators and restore reviewed policy; coordinate credential changes and PCR/dependencies. | Increase review frequency and retain a second console; revert only the identified malicious change after evidence capture. Keep all public services generally reachable, ICMP, NAT return traffic, official access and workstation egress. | New superuser, changed syslog destination, broad allow rule, altered destination translation or route next hop. Requires Config/System logging and retained baseline; Traffic log evidence requires relevant rule logging. A legitimate inject/maintenance commit is a benign alternative. |

## Patching and recovery

1. Discover complete build, model/VM platform, licenses, plugins, content versions, HA state if any, disk capacity, current errors and portal checks. Record routes/NAT/security rules and management path. Read current advisories and target release notes, support lifecycle and vendor upgrade-path instructions; do not assume newer documentation's skip-upgrade capability exists on this build.
2. Keep tested NETLAB console access. Under Device > Setup > Operations, save and export a named configuration snapshot and export device state where supported. Protect both, record UTC/hash on the evidence workstation, retain required keys/certificates via supported export and verify a disposable restoration. Exports are not log backups; preserve relevant logs separately.
3. Preview manually: list each required intermediate image, content/plugin prerequisites, compatibility caveats and reboot. Review Device > Software availability and signed vendor image provenance. Use the vendor workflow for this exact source/target/model; do not run generic Linux updates. For configuration-only remediation inspect diff and run `validate full`, then inspect the job result. Validation cannot prove scoring connectivity.
4. During a coordinated maintenance window manually download/upload and install each approved image in order through Device > Software. Follow each step's reboot requirements; an image upgrade can interrupt forwarding and management. Do not reboot merely for a configuration edit unless its documentation requires it. Never presume HA exists or prevents downtime.
5. After each restart verify `show system info`, interfaces, routes, policy/NAT, administrator access, log forwarding and time. From authorized internal/public paths test actual scored content/authentication, ICMP, workstation web egress, SQL/mail/AD dependencies and Quotient before continuing.
6. If a configuration-only edit regresses, load the exported known-good snapshot, validate and commit; retest. Firmware rollback requires the vendor's supported downgrade procedure and compatible saved configuration; do not assume loading a snapshot downgrades software. If boot or management fails, use console and approved maintenance/recovery guidance with staff/vendor assistance. No VM snapshots are available. Suspected compromise needs protected evidence and trusted recovery, because patch installation does not remove every persistence mechanism.

## Detection when patching is deferred

Assign an owner and next review time for each deferred item. Every 15 minutes inspect the last 15 minutes of System/Config logs plus current administrator sessions, and compare the latest committed version to the approved baseline. For GlobalProtect exposure also inspect its logs and available threat events. Preserve UTC timestamps, sources, before/after configuration and original exports; redact credentials from reports. Forward copies to a protected collector when authorized, but retain independent workstation-held baselines if Splunk itself is suspect.

Traffic logs depend on Security rule logging (session-end records appear only after closure); Threat logs require configured profiles, relevant content and licensing. Config logs do not prove every attacker action is visible, and management traffic does not necessarily traverse a logged dataplane rule. Missing/disabled logging is a detection gap requiring escalation, not a clean result. Avoid blanket IPS enforcement or broad access changes during scoring.

## Threat hunting

These are read-only procedures for authorized monitor/admin roles; configure no new policy during a hunt. In Monitor use the time selector for a fixed UTC 15-minute interval, record it, and export only bounded results to protected storage.

1. **Hypothesis: an attacker gained administrative control.** Monitor > System: filter the chosen interval for authentication/admin/session activity and examine source IP, user and result. Monitor > Config: same interval, inspect every administrator/account/management-profile or logging edit and commit. Compare Device > Administrators with the approved list. Suspicious evidence is an unknown source followed by a new privileged account or removed forwarding. Legitimate teammate maintenance and automated management are possible; verify against worksheet/operator, preserve versions and investigate subsequent actions before disabling an account that may serve official access.
2. **Hypothesis: policy changes redirected or exposed a scored service.** Monitor > Config: review latest five commits within the incident interval; use Device > Config Audit to compare each relevant committed version with the approved version. Inspect NAT/security rules, virtual-router routes and log settings. Operational `show routing route` and `show interface all` provide current state. Unknown next hop, new broad allow or changed translation is suspicious. Injects, failover and intended application fixes can explain it; trace original destination through NAT/zones/return path, correlate commit owner and validate the exact service before a targeted rollback.
3. **Hypothesis: a compromised server or firewall is communicating unusually.** Monitor > Traffic: choose last 15 minutes, first filter the affected server's actual source IP, then inspect destination, application, bytes, rule and translated address; keep the export bounded (for example first 200 rows). Compare with the preceding equal window and approved dependency map; inspect related Threat/GlobalProtect/System events and `show session info`. New destinations after an unauthorized commit, unusual outbound volume or repeated portal failures warrant follow-up. Patching, research, backups and mail relays can explain traffic. Ask the endpoint owner to correlate local logs; traffic anomalies alone do not prove firewall exploitation. Management-plane traffic and sessions lacking configured logging may be absent.

## Splunk monitoring

For installation, input configuration, validation and rollback for this host, use [concrete data-source setup](../splunk-data-sources.md).

Use the [shared collection, field discovery and hunting guide](../splunk-threat-hunting.md). Local System/Config logs are available only to the extent actually retained; Traffic needs rule logging, GlobalProtect needs the feature, and Threat needs profiles/content/licenses. Remote syslog forwarding and a collector/input are **optional changes requiring authorization and testing**, not existing facts. Discover Device > Server Profiles > Syslog and log forwarding settings, collector transport/port, timezone, format and actual hostname. Never assume a Palo Alto add-on is installed. Proposed sourcetypes such as `pan:config` are labels to verify, not active ingestion claims.

Replace `REPLACE_INDEX`, `REPLACE_PAN_HOST` and `REPLACE_CONFIG_SOURCETYPE` after raw-event inspection. This bounded raw fallback requires Config syslog ingestion with searchable `_raw`, accurate `_time` and correct `host`; no optional field extraction is required:

```spl
index=REPLACE_INDEX host="REPLACE_PAN_HOST" sourcetype="REPLACE_CONFIG_SOURCETYPE" earliest=-15m latest=now
| table _time host source _raw
| head 100
```

Expected output is timestamped configuration activity to match against approved commits, including user/client/path/action if present in the actual schema. Inspect original events and compare local Config Audit before judging a change. Normal commits and management automation are benign explanations. Discover fields with `| fieldsummary` in a separate bounded search; map vendor user/source-IP/command/result fields before adapting shared detections. Zero rows can mean no changes, wrong labels, stopped forwarding or lost logs: compare local same-window events and collector health, and use the shared explicit-inventory silence search. Preserve local evidence if central logs disagree; this SPL has not been tested against live ingestion.

## References

Official sources opened and checked **2026-11-13**; recheck live advisories before an event change. Historical branch fixes above address those specific CVEs and do not select a universally safe upgrade target.

- [CVE-2024-0012 advisory and exact hotfix matrix](https://security.paloaltonetworks.com/CVE-2024-0012).
- [CVE-2024-3400 advisory, feature prerequisites and mitigations](https://security.paloaltonetworks.com/CVE-2024-3400).
- [PAN-OS 11.0 upgrade-path documentation](https://docs.paloaltonetworks.com/pan-os/11-0/pan-os-upgrade/upgrade-pan-os/upgrade-the-firewall-pan-os/determine-the-upgrade-path).
- [Vendor software upgrade and configuration export workflow](https://docs.paloaltonetworks.com/vm-series/upgrade/upgrade-pan-os).
- [Operations: configuration and device-state exports](https://docs.paloaltonetworks.com/ngfw/help/10-1/device/device-setup-operations); use actual installed-version UI/help for platform support.

## Scripted management restriction

Generate `python3 scripts/panos_guard.py plan --host palo-alto` and follow the [hardening procedure](../hardening.md). This restricts all services on the dedicated MGT interface at 172.20.240.200 using permitted addresses. It does not create transit security rules. Console access and a saved clean candidate are required; validate, commit, then test new connections.

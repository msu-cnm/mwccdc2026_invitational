# Packet coverage audit — 2026-11-13

Reviewed all 23 pages of the supplied “2026 Midwest Invitational CCDC Team Pack” against this checkout. `doc_outline`/`doc_read` were not exposed and Document Control reported no connected session; used local pypdf extraction and visually inspected the image tables on pp.12–13. No packet passwords are reproduced. No repository AGENTS.md or CLAUDE.md was found. This is an offline content/code review; “covered” means a local instruction or implementation exists, not that an event system passed.

## Requirements and actual coverage

| Packet requirement | Status | Local evidence and limits |
|---|---|---|
| pp.3–4: maintain business function while defending | Covered, manual | [Change gate](event-checklist.md#per-system-discovery) requires one change, backups, public functional tests and rollback; neither guard tests applications. |
| pp.4–5: team participation, captain and team-number identification | Covered in checklist after review | [Startup](event-checklist.md#startup-and-staff-coordination) records captain and team-only conference identity. Eight stadium accounts and invitational coach guidance are called out; local institution/staff rules still apply. |
| pp.6–9: NISE first, Welcome response, wait for drop flag, stadium login/password change | Gap corrected in checklist | Startup now records Welcome submission and drop-flag notification/time before NETLAB access. There is no packet-defined “start flag value” to put in topology.json: this is an official notification, not a configuration token. No portal automation or credential storage is appropriate here. |
| pp.8,10: PDF submissions, Central time, Nextcloud | Gap corrected in checklist | Startup now records assigned session and missing Nextcloud How-To; submission tracker records deadline, format and receipt. Nextcloud URL is not supplied in this packet. |
| pp.10–11: Quotient status and immediate PCR CSV updates | Covered, manual | [Environment constraints](environment.md#mandatory-constraints), all system guides and checklist require dependency coordination and PCR update. Guard scripts do not rotate passwords or update PCR. |
| pp.11–13: ten VMs and team-derived addressing | Covered offline | Visually rechecked all ten rows against [inventory](../config/topology.json) and environment matrix: OS, internal interfaces, public expressions and shared egress agree. `kali_watch.public_address_hint` computes five public server addresses for T=1–20; guards ignore topology. DHCP leases, NAT and assigned team remain live inputs. |
| p.11: Palo Alto management from LAN workstation; no switch access | Covered | [Palo Alto guide](systems/palo-alto.md#initial-checks-and-system-specific-security), both workstation guides and environment preserve browser/console management. Neither guard supports appliance configuration. |
| p.14: precise scored checks come from portal | Covered as discovery; live gap | Environment gives candidate ports, explicitly not an allowlist. Checklist now has nine functional-check rows. Packet gives no exact per-host port allocation; no script derives it. |
| pp.15–16: session schedule in CST | Gap corrected in checklist | Record date/session and staff-confirmed times. Packet cover lists November 14, 2026 but final schedule heading says November 1, 2025; do not silently choose a date. |
| p.17: public sources, names, addresses, VLANs, data, platform and workstation role preserved | Covered by narrow script scope and guides | `linux_guard.SETTINGS` changes four kernel keys only; Windows Harden changes Logon auditing only; Kali observes configured endpoints. No script changes firewall, services, accounts or addressing. Checklist requires manual preservation checks for other changes. |
| pp.17,19: ICMP and staff access | Covered manually; automation gap | Every machine guide preserves these; Kali has no ping check and intentionally excludes appliances from scanning. Use native ICMP/console and authorized management tests in checklist. Guard non-interference alone cannot prove reachability. |
| p.17: no snapshots/scrub; recovery | Covered | Each patch/recovery guide and checklist require protected backups, console and tested restore. Startup now records staff escalation for new lab reservation if recovery fails; recovery may affect score. |
| pp.18–20: requests, conduct, scope, software and Internet rules | Covered as operator rules | Startup adds numbered/timestamped staff requests and captain escalation; environment prohibits other-team/official scans and private staging. Kali `validate_target`, `protected_ip` and `load_config` restrict addresses/HTTP endpoint scope, but operator must establish ownership: an internal IP entered in config is not proof of authorization. Packet permits free **or** open-source software; trials need White Team direction. |
| p.21: uptime/inject/IR weights and incident report per detected incident | Covered, manual | Environment records 40/40/20; incident workflow now explicitly requires a report for each detected Red Team incident and approved sensitive-evidence handling. Guard outputs are snapshots/counts, not incident reports. |
| p.22: multipart tasks, disputes and publication | Covered after checklist additions | Inject tracker records parts, owner, receipt and resubmissions; captain raises disputes promptly. README/environment prohibit unauthorized publication. Sponsor list p.23 is informational and imposes no script requirement. |

## Functional scoring checks versus implementation

Page 14 specifies behavior, not exact ports or host assignments. The conventional ports in [environment](environment.md#scoring-traffic-and-dependencies) must remain candidates. Each row below now has a recording slot in the [functional verification sheet](event-checklist.md#functional-scoring-verification).

| Packet check | Guide coverage | Script coverage / remaining gap |
|---|---|---|
| HTTP and HTTPS: expected page content | Rocky initial checks preserve site and DB-backed operations; Kali guide explains Host/SNI/TLS | `http_check` verifies TLS, optional status and **substring** content only, bounded body read; it is not exact-file comparison or authenticated app testing. Manually compare expected page via approved portal workflow. |
| SMTP: send and receive with valid account | Ubuntu Email initial checks specify actual send/receive cycle | TCP/banner checks do not send/retrieve mail. Use owned accounts and verify delivery, not just queue acceptance. |
| POP3/IMAP/webmail: AD identities and command responses | Email guide preserves AD integration, mailboxes and exact protocol | No authenticated protocol automation. Verify existing message retrieval and correct responses using assigned identity and approved client. |
| FTP: authenticated file access | Previously only environment/dependency mention; concrete verification added to checklist | No dedicated FTP machine is assigned by packet and no FTP functional client exists in scripts. Discover owner and data-path mode, verify required file listing/read, preserve user set/files. |
| DNS: correct lookup | AD guide discovers zones, forwarders and DNS health | Kali only probes TCP; it does not query records or UDP. Manually verify assigned records over UDP and TCP, including externally assigned path. |
| SSH: authenticated connection | Linux guides preserve auth and SSH dependencies | Banner/TCP is insufficient. Manually log in with scoring-compatible identity/method; do not disable password auth blindly. |
| Ping: echo reply | All guides preserve ICMP | No scripted echo test. Verify each of ten devices from authorized paths. |
| Splunk: authenticated query for expected information | Debian Splunk initial checks plus shared collection/hunting guide | No Splunk authenticated-query client. Log in to assigned endpoint, execute expected query, compare result and confirm ingestion/time correctness. |

## Security script limits and findings

The packet does **not** prescribe kernel values, audit categories, CVE lists or a particular firewall ruleset. Security effectiveness must be assessed against the actual build and dependencies; these tools cannot claim a complete packet-mandated baseline.

- `linux_guard.py`: `SETTINGS` contains only `kernel.kptr_restrict=2`, `kernel.dmesg_restrict=1`, `fs.protected_hardlinks=1`, `fs.protected_symlinks=1`; `main` previews, backs up exclusively and verifies runtime writes. It does not persist settings, patch packages, secure web/mail/SSH config, inspect all user persistence, or configure firewall/SELinux. The per-system vulnerability/patch/hunt sections provide manual procedures. `assess` samples at most 500 journal records total before filtering auth identifiers; counts are neither all auth records nor success/failure classification. Native logs remain required.
- `windows_guard.ps1`: Harden enables only Logon success/failure, with full auditpol backup/restore. It does not enable task/account/process/PowerShell/SQL audit sources used in hunts. Assess suppresses Security log errors; empty counts can mean denied access, not no events. This remains an automation gap: verify log access/effective policy natively as described in all three Windows guides before using event counts as evidence. Runtime/PowerShell verification remains unavailable here.
- `kali_watch.py`: `run_map` is explicit-port TCP mapping, `probe_banner` reads greetings, and `run_monitor` runs TCP plus configured HTTP checks. None is a vulnerability scanner or full scoring validator. **Fixed during this review:** disabled example checks previously produced `healthy` with no observations; now `run_monitor` returns `collection_error`/exit 2 when no checks ran. A mocked regression checks that no probes occur. Plan-only examples still succeed.
- Monitoring is operator-driven: guards do not schedule, compare baselines, alert or deploy Splunk inputs. Shared Splunk guide supplies source prerequisites and silence checks; per-host SPL requires real labels, fields and retained logs. Kali JSON contains nested passes/checks; flatten/expand these deliberately before building dashboards. `--repeat` runs consecutive passes, not a 5-minute scheduler. Documentation now makes both limits explicit, and the output hint no longer claims flat JSON.

## Specific unresolved inputs and follow-up

The packet itself is available and reviewed. These are absent event inputs or unperformed checks, not unspecified “unavailable source material”:

| Missing evidence | Required action / affected files |
|---|---|
| Portal's exact host/check assignment, ports, identities, content/files/query, DNS names/records (p.14) | Populate functional sheet; update environment, relevant system guide and private Kali checks config. Keep credentials separately. Do not invent FTP ownership or port allowlists. |
| Running VyOS/PAN-OS firewall, NAT, routes, IPv6 and management sources (pp.11–13,17) | Export/read native config; complete firewall change gate and appliance guides' discovery; derive proposal from dependency evidence. Packet does not contain an exact firewall ruleset to copy. |
| Current OS/application builds, units, SQL edition/ports, DHCP leases, logging/index fields | Complete per-system worksheet, select applicable vendor updates in machine guides and map shared Splunk sources before interpreting SPL. No live CVE or fixed-version conclusion is established by packet versions. |
| Confirmed date/session and Nextcloud How-To (pp.10,15–16) | Captain obtains official schedule and separate How-To; complete startup fields. No Nextcloud endpoint is guessed. |
| Full prior-year source at pinned revision | Empty gitlink and partial review remain documented in prior-year-review.md. Restore original source, read nested instructions and inventory scripts before claiming reuse coverage. This does not block reading the supplied packet. |
| Representative Windows/appliance runtime, restore and public scoring tests | Complete validation.md rehearsal and record results in worksheet. Offline tests cannot close these gaps. |

Priority at drop flag: establish official access and portal requirements; capture baseline/backup; verify all functional rows; then apply one reviewed security change at a time. No live probes, patches, firewall mutations or credential rotations were performed by this review.

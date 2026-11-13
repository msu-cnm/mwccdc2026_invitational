# 2026 Midwest Invitational environment

Source: supplied `attachment-1.pdf`, 23 pages, titled “2026 Midwest Invitational CCDC Team Pack”. Text was extracted locally with pypdf and image tables on pages 12–13 were visually read. `doc_outline`/`doc_read` were unavailable; no connected document session existed. No packet credentials are reproduced here.

This matrix records packet facts, not live discovery. The packet says topology can change (p.13). Populate the [event checklist](event-checklist.md) from NISE/NETLAB before any service or firewall changes. Team number is 1–20; `(20+team)` is arithmetic, not literal addressing. **Our team: 17 (N = 20 + 17 = 37).**

| System | OS/version | Internal address/interfaces | Public address / egress | Role and uncertainty |
|---|---|---|---|---|
| Rocky Ecom | Rocky Linux 9 | 172.20.240.10 | 172.25.37.10 | Ecommerce; HTTP/HTTPS are candidate services, assignment unconfirmed |
| Ubuntu Email | Ubuntu 22.04 | 172.20.240.15 | 172.25.37.15 | Email; SMTP, POP3/IMAP and webmail are candidates, assignment unconfirmed |
| Debian Splunk | Debian 12; Splunk 10.0.2 | 172.20.240.20 | 172.25.37.20 | Splunk authenticated query; exact endpoint, index and ingest paths unconfirmed |
| 2022 AD | Windows Server 2022 Standard | 172.20.240.100 | 172.25.37.100 | AD; DNS and domain authentication dependencies require discovery |
| 2019 MSSQL | Windows Server 2019 Standard | 172.20.240.120 | 172.25.37.120 | SQL; instance, authentication mode and application dependencies unconfirmed |
| Ubuntu Wkst | Ubuntu; version unspecified | DHCP | 172.31.37.2 (shared egress per packet) | User workstation; Palo Alto browser management |
| Windows 11 Wks | Windows 11 | DHCP | 172.31.37.2 (shared egress per packet) | User workstation; Palo Alto browser management |
| Kali | Kali; version unspecified | 172.17.0.2 | 172.31.37.2 (shared egress per packet) | User workstation directly connected to VyOS |
| Palo Alto | PAN-OS 11.0.2 | outside 172.16.0.1/24; inside 172.20.240.254/24; management 172.20.240.200 | NAT mappings require discovery | Boundary firewall; preserve security rules, NAT, routes and management |
| VyOS Router | VyOS 1.4.0 | external 172.31.37.2/29; wkst 172.17.0.1/24; internal 172.16.0.254/24 | 172.31.37.2 | Router; preserve forwarding, routes and NAT |

Source: p.11 for count, access and management; p.12 core-address table; p.13 VM table. There are exactly 10 VMs: five servers, three workstations, firewall and router. No layer-2 switch access. Workstation public entries are copied as shared egress addresses; they do not authorize assigning that address locally. For team T, core next hop is `172.31.(20+T).1`, external router is `.2/29`, public pool `172.25.(20+T).0/24`. **Team 17 (ours):** core 172.31.37.1, router 172.31.37.2/29, public pool 172.25.37.0/24.

## Adapting to your assigned team number

These guides support packet team numbers **1–20**. Once assigned team `T`, calculate `N = 20 + T` (21–40) and substitute `N` only for the `(20+team)` or `(20+T)` expressions. These expressions are documentation placeholders, not valid IP addresses or executable configuration. **We are team 17: N = 37.**

| Item | Formula | Team 17 (N = 37) |
|---|---|---|
| Public server pool | `172.25.N.0/24` | `172.25.37.0/24` |
| Rocky / Email / Splunk public addresses | `172.25.N.10`, `.15`, `.20` | `172.25.37.10`, `172.25.37.15`, `172.25.37.20` |
| AD / MSSQL public addresses | `172.25.N.100`, `.120` | `172.25.37.100`, `172.25.37.120` |
| VyOS external / shared egress | `172.31.N.2/29` | `172.31.37.2/29` |
| Core next hop | `172.31.N.1` | `172.31.37.1` |

Keep the packet's internal addresses unchanged unless official live instructions supersede them. Discover DHCP workstation addresses locally. Shared egress is the router's address, not an address to assign to each workstation. Team number alone does not establish DNS names, domain names, scoring URLs, service ports or NAT rules; obtain those from the portal and live configuration.

Neither `scripts/linux_guard.py` nor `scripts/windows_guard.ps1` needs a team-number argument or code edits. They operate on the local host and do not read `config/topology.json`, assign addresses, configure NAT/routes or change firewall rules. The inventory retains placeholder strings; it does not automatically render them for a chosen team. Use the [event worksheet](event-checklist.md) to record resolved addresses and verify them before following a system guide. Threat-hunting searches also require discovered hostnames, indexes and field mappings as described in the Splunk guide.

## Scoring traffic and dependencies

Page 14 defines checks below, but explicitly leaves precise scored services to the event portal. Ports here are conventional discovery candidates, **not confirmed allowlists**. Do not close other listeners using this table.

| Check | Candidate traffic to discover | Functional requirement |
|---|---|---|
| HTTP / HTTPS | TCP 80 / 443, any configured alternate ports | Exact requested content, hostname, certificate and application dependencies |
| SMTP | TCP 25; discover 465/587 if used | Send AND receive mail with valid account |
| POP3 / IMAP / webmail | TCP 110/143/995/993; web ports | AD usernames, stored messages and correct command responses |
| FTP | TCP 21 plus discovered passive range or active data path | Authenticated access to required files; connection tracking/NAT |
| DNS | UDP AND TCP 53 | Expected records and response correctness |
| SSH | TCP 22 or discovered port | Authenticated login; preserve scoring authentication method |
| Ping | ICMP; retain existing IPv6 ICMP if configured | Echo reply on every device |
| Splunk query | Discover web/API endpoints, often TCP 8000/8089 | Authentication and query returns expected information |

AD candidates for internal dependency discovery: TCP/UDP 53, 88, 389, 464; TCP 135, 445, 636, 3268/3269 and dynamic RPC; UDP 123. This is not an exhaustive AD policy. SQL often uses TCP 1433, named instances may use dynamic ports and UDP 1434. Splunk ingestion may use 9997 or 8088 but must be discovered. Preserve DNS, time, DHCP, management, mail delivery, application-to-database, domain membership and logging paths actually in use. Preserve outbound research/patch access; workstation browser access needs TCP 80/443 (p.8). Network security rules must account for NAT direction, return traffic, routing, IPv6 and FTP data connections.

## Mandatory constraints

- Public services must remain generally available to **all source addresses**. No scoring-only allowlist. Restrict specific malicious sources only with evidence (p.17).
- Preserve all system names, internal/public addressing, VLAN scheme, service platform, data and user names unless an inject directs otherwise (pp.17,19). Workstations retain workstation roles.
- Keep ICMP on all devices; maintain official troubleshooting access (pp.17,19). Do not disable password authentication blindly: SSH scoring authenticates.
- No VM snapshot/scrub recovery is available (p.17). Take configuration backups; retain NETLAB console access. No fleet-wide automated application.
- Password changes require coordinating every dependency and immediately updating Quotient PCR in username,password CSV format (p.11). Never include passwords in monitoring output or ordinary incident logs.
- Only free or open-source software; trials require White Team direction; no offensive scans of other teams, officials, global assets or Red Team (p.19). Guard scripts inspect only the local machine. `kali_watch.py` performs **bounded, explicitly authorized** service checks against team-owned hosts only — it is not a broad network scan and does not target other teams, core infrastructure, or shared egress ranges.
- Internet sources must be public, with no private staging area (p.20). Confirm authorized script delivery through White Team. Packet restricts publication of event details (p.22); do not publish these artifacts without authorization.
- Uptime 40%, injects 40%, incident response/Red Team assessment 20% (p.21). HTTP content and authenticated workflows matter beyond open ports. Inject responses normally PDF via NISE; watch deadlines (p.8).

## Unresolved event inputs

Prior-year checkout restoration is blocked by download restrictions; the partial source review identifies an AD password-reset script that requires adaptation. See [review and source links](prior-year-review.md). Team number, actual live versions, unit names, port assignments, credentials, domains, URLs, expected content, FTP data ranges, NAT policy and management source networks remain unconfirmed. Obtain these at drop flag through authorized interfaces; do not substitute common defaults. Page 16 contains a stale “November 1, 2025” schedule heading despite the 2026 cover; confirm actual session time with staff (all schedules CST).

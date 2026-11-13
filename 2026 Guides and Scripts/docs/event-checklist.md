# Live event worksheet and change gate

Owner/team/date/time (UTC and CST): __________

## Team assignment

Use the [team-number setup instructions](environment.md#adapting-to-your-assigned-team-number). Fill this in from the official assignment and verify against live configuration before changes:

- Assigned team `T` (packet range 1–20): **17**; calculated `N = 20 + T`: **37**
- Public server pool `172.25.N.0/24`: **172.25.37.0/24**
- Public Rocky / Email / Splunk / AD / MSSQL addresses: **172.25.37.10, .15, .20, .100, .120** (verify live)
- VyOS external/shared egress `172.31.N.2/29`: **172.31.37.2/29**
- Core next hop `172.31.N.1`: **172.31.37.1**
- Verified internal addresses and DHCP leases: __________
- Portal DNS names, domain, scoring URLs and NAT mappings: __________
- Official topology deviations or inject reference: __________

The guard scripts need no team-number edits. Do not paste unresolved placeholders into appliance configuration or assign shared egress to workstations.

## Per-system discovery

For **each of the 10 systems** record actual hostname, addresses, OS/build, operator, console access tested, service unit/process, listeners/protocols, public NAT, management path, outbound dependencies, DNS/time/domain dependencies and official access requirements. Confirm this against `config/topology.json` without changing identifiers.

For **each portal check** record host/public IP, protocol/port, URL/hostname/content or query, account reference (no password here), expected result, baseline score and last successful test. For FTP record passive range/active behavior. Record inter-server flows and application-to-DB/AD dependencies. Record any inject deviations and source page/inject ID. Keep credentials separately in an approved protected store.

Before changing anything:

1. Capture healthy and unhealthy baselines; identify pre-existing failures. Keep a second NETLAB console open.
2. Back up configuration and data locally with restricted permissions. Confirm how to restore without snapshots.
3. Choose one change on one system. Review diff; preserve all scored traffic, ICMP, management, return traffic and dependencies. No source-only scoring filters.
4. For a firewall proposal, record exact old/new rules, direction, NAT stage, IPv4/IPv6, source/destination zones and dependency evidence. Run native validation (PAN-OS `validate full`; VyOS candidate validation with commit-confirm when supported; nftables `nft -c -f proposal.nft` only when nftables actually owns the rules). Never mix firewalld/UFW/nft/iptables ownership. Windows: inspect proposed rule objects and use a disposable representative VM first. Parser success alone does not prove connectivity.
5. Apply manually only after a rollback path has been tested. Test from authorized internal and public paths; observe Quotient. Validate authenticated service/content, not just TCP connect. Preserve general public availability.
6. If scoring, management or a dependency regresses, immediately restore the single change, retest, and record cause. Don't stack additional changes on an unexplained failure.

## Monitoring and incidents

Run one-shot local assessment every few minutes using a timestamped protected output path. Compare successive listener/service/task/persistence snapshots; establish a clean baseline after reviewing it, not merely trusting first boot. Review authentication failure/success patterns, new privileged accounts, new tasks/services, disk/memory/load, application error rates and Quotient status. Scripts do not detect every compromise and do not automatically block or remediate.

Use Windows Security IDs 4624/4625/4672 (authentication), 4697/4698 (service/task), 4720/4728/4732 (account/group); check System 7045 for installed services. Linux: locally review `journalctl -u sshd -u ssh --since '-15 min'`, `journalctl -p warning --since '-15 min'`, `/var/log/auth.log` or `/var/log/secure` where present. Review logs on screen with credential redaction; do not copy raw messages into monitoring artifacts. Hashes expose changes, not their cause. Investigate unknown persistence before deleting it.

Incident report: UTC timeline, evidence source/event ID/hash, source/destination addresses and ports, affected services/data, observed impact, containment, recovery and scoring verification. Keep secret material out of general reports; use staff's approved protected channel if sensitive evidence is required. Submit accurate reports and PDF inject responses through NISE, avoiding last-minute deadlines. Check announcements regularly.

## Startup and staff coordination

- Captain: __________; conference identity (team number only): __________. Share rules with participants; confirm local policies. Invitational permits eight stadium accounts and coach/alumni guidance, not coaches performing student tasks (p.4); clarify any conflict with general observer rules through staff.
- Assigned date/session: __________; staff-confirmed CST start/end: __________; UTC equivalents: __________. Resolve p.16's stale 2025 heading with staff; use the actual NISE deadline clock.
- Log in to NISE first at `https://injects.ccdc.events` with issued team account. Assign announcement/inject watcher: __________. Welcome inject ID: __________; required response/PDF submitted at: __________; receipt/status: __________.
- Wait for official drop-flag notification before stadium access. Notification reference and CST/UTC time: __________. This is a release notification, not a token to insert into topology config.
- At release, use issued stadium account at `ccdc.cit.morainevalley.edu`; change initial stadium password as prompted and retain it in approved protected storage. ENTER LAB, check topology/Content, verify all ten VM consoles. Client/browser and outbound 80/443 checked: __________.
- Confirm Quotient access through `https://quotient.ccdc.events/` or `https://auth.ccdc.events/`; record baseline service status and PCR process. Never put PCR passwords in this worksheet.
- Obtain separate `Nextcloud How-To.pdf`; approved endpoint/access verified: __________. Packet says use NISE credentials during active scoring; do not guess the endpoint or stage files in private external services.
- Staff requests: team number, action/item, date/time, ticket/reference, response: __________. Captain raises rule/scoring disputes promptly; use service reports and internal tests before requesting routine verification. Confirm permitted software delivery/media and use only free or open-source software; trials require staff direction.
- Recovery escalation: retain NETLAB console/power-cycle path; if tested restore fails, captain may request a new lab reservation through White Team. No snapshot/scrub; record recovery cost/score implications with staff before proceeding.

## Functional scoring verification

Fill each row from the portal. Mark unassigned only with portal/staff evidence. Account references must point to protected storage. For each assigned row record owner, actual host/public IP, protocol/ports, expected result, baseline/post-change result, CST/UTC time and Quotient status. A successful TCP probe alone is insufficient.

| Check | Required functional test | Assignment / owner / result / evidence |
|---|---|---|
| HTTP | Exact URL/Host and expected page content; check app/DB dependency | __________ |
| HTTPS | Exact URL, SNI, trusted TLS identity and expected page content | __________ |
| SMTP | Send AND receive through valid owned account; confirm delivery | __________ |
| POP3/IMAP/webmail | Assigned AD username, correct protocol responses and existing message retrieval | __________ |
| FTP | Discover server and active/passive data path; authenticate with approved client, list/read required existing file; no production write/delete unless explicitly required | __________ |
| DNS | Assigned record and expected answer via UDP AND TCP using approved DNS client | __________ |
| SSH | Actual authenticated login with assigned compatible method/account | __________ |
| Ping | Echo reply on each of ten devices from authorized paths; record per-device result | __________ |
| Splunk query | Assigned endpoint/account, actual expected query and returned information | __________ |

Public-path test source and routing/NAT limitations: __________. Kali behind VyOS is only one observation path; use Quotient and another authorized path where available. Preserve general public availability. Do not probe official scoring infrastructure.

## Inject submission tracker

For each task record ID/parts, owner, priority, CST deadline and UTC equivalent, required format (PDF unless inject says otherwise), reviewer, submission time and receipt/status: __________. Submit before the final minute. If invalidated while open, track resubmission and staff's retry limit. Verify every part and retained receipt rather than assuming upload equals acceptance.

Submit a report for **each detected Red Team incident** through staff's stipulated route/time. Include the incident workflow fields above and remediation plan; reference affected credentials and arrange any required cracked-password evidence through an approved protected channel. Never paste passwords into this worksheet, ordinary monitoring output or general reports.

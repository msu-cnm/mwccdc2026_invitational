# Competition operations

Start collection with the [per-host Splunk data-source setup](splunk-data-sources.md), including receiver configuration, forwarder inputs, appliance syslog, test events and alerts.

Start with the [environment and traffic matrix](environment.md), [prior-year source status](prior-year-review.md), and [event worksheet/change gate](event-checklist.md). The prior-year checkout is missing locally; a partial review at the pinned GitHub revision is documented. These are new packet-derived artifacts. The work is incomplete until the full source is restored/reviewed and platform rehearsal passes. Do not publish packet-derived details without competition authorization.

## Packet review

See the [packet coverage audit](packet-audit.md) for page-by-page requirements mapped to actual guide sections and script functions, corrected gaps, remaining automation limits and the event-input checklist. The packet has been reread, including the image tables on pp.12–13. Coverage does not establish live scoring readiness.

## System guides

- [Rocky Ecom](systems/rocky-ecom.md)
- [Ubuntu Email](systems/ubuntu-email.md)
- [Debian Splunk](systems/debian-splunk.md)
- [2022 AD](systems/2022-ad.md)
- [2019 MSSQL](systems/2019-mssql.md)
- [Ubuntu Wkst](systems/ubuntu-workstation.md)
- [Windows 11 Wks](systems/windows11-workstation.md)
- [Kali](systems/kali.md)
- [Palo Alto](systems/palo-alto.md)
- [VyOS Router](systems/vyos.md)

## Candidate services by host

The packet's topology matrix (p.13) and scoring traffic table (p.14) imply a set of **possible** scored services, but it does not confirm which host runs which. The [host service map](host-service-map.md) consolidates every candidate service per host in one place; each system guide also carries its own "Candidate services on this host" section with direct links to the relevant service guides. The [services index](services/README.md) lists the candidates per host with the packet page that supports each one, followed by one guide per candidate service:

- [HTTP/HTTPS web portal](services/http-https.md)
- [SMTP mail relay](services/smtp.md)
- [POP3/IMAP and webmail](services/pop3-imap-webmail.md)
- [FTP transfer](services/ftp.md)
- [DNS resolution](services/dns.md)
- [Active Directory domain services](services/ad-domain-services.md)
- [MSSQL database](services/mssql.md)
- [Splunk query access](services/splunk-query.md)
- [SSH remote administration](services/ssh.md)

Every guide follows the same structure — discovery, setup, configuration, monitoring, backup, usage/scoring verification, recovery, references — and every step is conditional on the live system matching the candidate. Verify before you rely on it.

## Threat hunting and monitoring

Use the [shared Splunk guide](splunk-threat-hunting.md) for the ten-machine telemetry matrix, collection prerequisites, bounded searches, missing-source checks and safe rehearsal. Each system guide includes discovery-based vulnerability, patch/recovery and local hunting procedures. Confirm actual builds and logging before applying them.

For bounded authorized network mapping, exposure assessment and service monitoring from the Kali workstation, see the [kali-operations guide](kali-operations.md).

## Scripts

The scripts work independently of team number. Before using the guides, follow [team-number setup](environment.md#adapting-to-your-assigned-team-number) and record your assigned addresses in the event worksheet. Address placeholders require manual substitution; there is no automatic team configuration step.

- [Linux guard](../scripts/linux_guard.py): Python 3 standard library; local one-shot assessment, dry-run runtime hardening, explicit application, exclusive backup, verified writes and rollback. Supported on the five Linux servers/workstations listed in the matrix (not VyOS/PAN-OS). Never modifies firewall rules, routing, SSH or services.
- [Windows guard](../scripts/windows_guard.ps1): Windows PowerShell 5.1+; local assessment, dry-run Logon auditing changes, explicit application, auditpol backup/restore. Three Windows hosts. Native built-in tools only.
- [Splunk setup (Windows)](../scripts/splunk_setup_windows.ps1): Windows PowerShell 5.1+; generates the Universal Forwarder `outputs.conf`/`inputs.conf` for the three Windows hosts (2022-ad, 2019-mssql, windows11-workstation), which have no Python installed. Preview first (no `-OutDir`); writes only when given an empty staging directory. Same content as `scripts/splunk_setup.py`'s Windows path.
- [Kali watch](../scripts/kali_watch.py): Python 3 standard library; bounded authorized network mapping (Nmap TCP connect), exposure assessment and service monitoring from the Kali workstation. Plan-first: all modes print a readable JSON plan by default; `--execute` required for any network activity. See [kali-operations guide](kali-operations.md).
- [Topology inventory](../config/topology.json): machine-readable transcription of packet p.13, used for coverage checks. Service ownership remains provisional.

Examples and rollback commands are in each guide. Assessment prints to stdout; it does not create files or schedule itself. If collecting snapshots, use operator-only directories, unique timestamped files and bounded retention. Compare Linux JSON persistence hashes and Windows task/service/listener sets against reviewed baselines. Auth counts are capped to 500 recent events; investigate using native protected logs, not just counts. No credentials, raw configuration contents or process arguments are intentionally collected.

Hardening defaults to preview. Apply only one host at a time after worksheet completion and backups. Linux settings are runtime only. Windows audit policy is persistent but may be overridden by GPO. Neither script is a full security baseline or malware-removal tool. No firewall policy is automatically applied; follow the native validation and public/management dependency tests in the worksheet.

## Validation

Run from the repository root:

```bash
python3 -m unittest discover -s tests -v
python3 -m unittest discover -s tests -p test_guides.py -v
git diff --check
python3 -m py_compile scripts/linux_guard.py
python3 scripts/linux_guard.py harden
```

See [test/rehearsal status](validation.md) for limits. Do not run apply tests on production, the development container, or live competition systems. Offline success cannot prove scoring availability.

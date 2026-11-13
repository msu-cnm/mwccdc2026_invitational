# Candidate services by host

This area lists **possible** services per host, derived from two packet facts only:

1. The topology matrix (packet p.13; transcribed in [config/topology.json](../../config/topology.json) and [environment.md](../environment.md)) — each host's stated role.
2. The scoring checks on packet p.14, summarized in [Scoring traffic and dependencies](../environment.md#scoring-traffic-and-dependencies) — HTTP/HTTPS, SMTP, POP3/IMAP/webmail, FTP, DNS (UDP and TCP), SSH, ICMP ping, and the Splunk authenticated query.

The packet explicitly leaves precise scored services, ports and host assignments to the event portal (p.14). Every entry below is therefore a **candidate to discover and confirm**, not a confirmed assignment. Do not close listeners, build allowlists or reconfigure NAT from this table; populate the [functional verification sheet](../event-checklist.md#functional-scoring-verification) from the portal first.

## Per-host candidate matrix

| Host | Candidate services (confirm against packet role + portal) | Scoring checks that could land here | Conventional ports to discover (not an allowlist) |
|---|---|---|---|
| [Rocky Ecom](../systems/rocky-ecom.md) — Rocky Linux 9, 172.20.240.10 | Web server (Apache or nginx) with ecommerce application; HTTP and/or HTTPS on conventional or alternate ports; possible application database dependency; possible FTP for upload/content transfer (unassigned by packet); SSH for administration | HTTP / HTTPS content; possibly FTP if portal assigns it here; SSH | TCP 80/443 or discovered alternates; TCP 21 + passive range if FTP present; TCP 22 |
| [Ubuntu Email](../systems/ubuntu-email.md) — Ubuntu 22.04, 172.20.240.15 | SMTP (Postfix or equivalent); POP3/IMAP (Dovecot or equivalent); webmail frontend; AD-integrated authentication backends; SSH for administration | SMTP send **and** receive with valid account; POP3/IMAP/webmail retrieval with AD usernames and stored messages | TCP 25, 465/587 if used; TCP 110/143/995/993; web ports for webmail; TCP 22 |
| [Debian Splunk](../systems/debian-splunk.md) — Debian 12, Splunk 10.0.2 | Splunk web console (authenticated query endpoint); Splunk management/API; possible ingestion endpoints (forwarder/syslog inputs) feeding it from other hosts; SSH for administration | Splunk authenticated query returning expected information | Discovered web/API ports (often TCP 8000/8089); ingestion often 9997 or 8088 — all must be discovered; TCP 22 |
| [2022 AD](../systems/2022-ad.md) — Windows Server 2022, 172.20.240.100 | DNS (UDP and TCP); Kerberos/LDAP/LDAPS; Global Catalog; SMB/RPC for domain services; possibly NTP; SSH if installed (not a default AD service); RDP/management | DNS expected records and response correctness; domain authentication dependencies for email/webmail scoring | TCP/UDP 53; TCP/UDP 88; TCP 389, 636, 3268/3269; TCP 135, 445 + dynamic RPC; UDP 123 |
| [2019 MSSQL](../systems/2019-mssql.md) — Windows Server 2019, 172.20.240.120 | SQL Server instance (default or named); possible client access from ecommerce/email applications; SSH if installed; RDP/management | Application/database dependencies behind HTTP or mail scoring checks | TCP 1433 (default instance) or discovered named-instance port; UDP 1434 |
| [Ubuntu Wkst](../systems/ubuntu-workstation.md) — DHCP, shared egress | Browser (outbound TCP 80/443 to public internet); SSH client; mail/FTP clients for scoring verification; no scored inbound services expected | Client-side verification of HTTP, mail, FTP and Splunk checks via authorized paths | Outbound only; discover assigned address locally |
| [Windows 11 Wks](../systems/windows11-workstation.md) — DHCP, shared egress | Same client profile as Ubuntu Wkst: browser, mail/FTP/SQL clients for verification; no scored inbound services expected | Client-side verification of the same checks | Outbound only |
| [Kali](../systems/kali.md) — 172.17.0.2 behind VyOS | Attack/verification tooling (Nmap via [kali_watch.py](../../scripts/kali_watch.py), mail/FTP/SQL/DNS clients); SSH; no scored inbound services expected | Observation path for public-path tests; bounded authorized service checks | Outbound only |
| [Palo Alto](../systems/palo-alto.md) — PAN-OS 11.0.2 | Firewall/NAT policies (source NAT to 172.25.37.x, port forwarding for scored services), security rules, management interface; no application services expected | All public scoring traffic transits here: HTTP, SMTP, POP3/IMAP/webmail, FTP (+ data path), DNS, SSH, Splunk query | Discovered NAT mappings; management 172.20.240.200 from authorized sources |
| [VyOS Router](../systems/vyos.md) — VyOS 1.4.0 | Routed interfaces (external 172.31.37.2/29, wkst 172.17.0.1/24, internal 172.16.0.254/24), NAT for workstation egress, DHCP on workstation segment; no application services expected | Shared egress for workstations/Kali; ICMP echo reply on the device | Interface addresses per packet; DHCP on 172.17.0.0/24 |

## Service guides

Each guide below covers **setup, configuration, monitoring, backup and usage** for one candidate service, in discovery-first order: confirm it is actually installed and scored before applying anything. All guides assume the constraints in [environment.md](../environment.md) (free software only, no snapshots, preserve general public availability, coordinate credential changes with Quotient PCR updates, back up before changes).

| Service | Guide | Typical candidate host(s) |
|---|---|---|
| HTTP / HTTPS web service | [http-https.md](http-https.md) | Rocky Ecom |
| SMTP mail transfer | [smtp.md](smtp.md) | Ubuntu Email |
| POP3 / IMAP / webmail | [pop3-imap-webmail.md](pop3-imap-webmail.md) | Ubuntu Email |
| FTP file transfer | [ftp.md](ftp.md) | Unassigned by packet; discover owner (Rocky Ecom or Ubuntu Email are plausible from their roles) |
| DNS | [dns.md](dns.md) | 2022 AD (domain DNS); verify whether standalone resolvers exist elsewhere |
| SSH | [ssh.md](ssh.md) | All Linux hosts (administration + possible scoring); Windows hosts only if installed |
| Splunk query and ingestion | [splunk-query.md](splunk-query.md) | Debian Splunk |
| AD domain services (Kerberos/LDAP/SMB) | [ad-domain-services.md](ad-domain-services.md) | 2022 AD |
| SQL Server | [mssql.md](mssql.md) | 2019 MSSQL |
| VyOS / Palo Alto hardening (interfaces, rules, DoS prevention) | [vyos-palo-alto.md](vyos-palo-alto.md) | VyOS Router + Palo Alto (not a scored service; protects all scored paths) |

## Rules for using this area

- **Discovery first.** Every guide starts with read-only discovery commands. A candidate service that is not actually installed, listening or scored must not be configured from the guide's defaults.
- **Portal assignment wins.** If the portal assigns a check to a different host than the plausible one above, follow the portal and record it in the [event worksheet](../event-checklist.md).
- **No scoring-only allowlists.** Public services must remain generally available to all source addresses; restrict only evidence-backed malicious sources (p.17).
- **Backups before changes, no snapshots.** Use each guide's backup section; recovery paths must be tested before the event.
- **Verify functionally, not by port.** A TCP connect is insufficient; use each guide's usage/verification section and confirm Quotient status.

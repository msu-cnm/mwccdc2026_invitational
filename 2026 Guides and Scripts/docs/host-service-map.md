# Host Service Map

Start collection with the [per-host Splunk data-source setup](splunk-data-sources.md), including receiver configuration, forwarder inputs, appliance syslog, test events and alerts.

Start with the assigned machine’s system guide below for addresses, hardening, patching, exploitation detection, threat hunting and Splunk searches. Its service links cover discovery, setup, configuration, monitoring, backup, usage and recovery. Record the owner and confirmed assignments in the [event worksheet](event-checklist.md).

These are candidates, not confirmed running services. Workstation service links describe client workflows; routed application traffic does not make VyOS or Palo Alto an application server. Confirm listeners and portal assignments before installing or exposing anything.

| Host ID | Candidate Services | Details |
|---------|-------------------|---------|
| [2019-mssql](systems/2019-mssql.md) | SQL Server, SSH | [mssql.md](services/mssql.md), [ssh.md](services/ssh.md) |
| [2022-ad](systems/2022-ad.md) | DNS, AD services, SSH | [dns.md](services/dns.md), [ad-domain-services.md](services/ad-domain-services.md), [ssh.md](services/ssh.md) |
| [debian-splunk](systems/debian-splunk.md) | Splunk query, SSH | [splunk-query.md](services/splunk-query.md), [ssh.md](services/ssh.md) |
| [kali](systems/kali.md) | Authorized mapping/monitoring tooling; SSH if discovered | [kali-operations.md](kali-operations.md), [ssh.md](services/ssh.md) |
| [palo-alto](systems/palo-alto.md) | Firewall/NAT policies, Security rules | [vyos-palo-alto.md](services/vyos-palo-alto.md) |
| [rocky-ecom](systems/rocky-ecom.md) | HTTP/HTTPS, FTP, SSH | [http-https.md](services/http-https.md), [ftp.md](services/ftp.md), [ssh.md](services/ssh.md) |
| [ubuntu-email](systems/ubuntu-email.md) | SMTP, POP3/IMAP, FTP, SSH | [smtp.md](services/smtp.md), [pop3-imap-webmail.md](services/pop3-imap-webmail.md), [ftp.md](services/ftp.md), [ssh.md](services/ssh.md) |
| [ubuntu-workstation](systems/ubuntu-workstation.md) | Client workflows; SSH if discovered | [http-https.md](services/http-https.md), [smtp.md](services/smtp.md), [pop3-imap-webmail.md](services/pop3-imap-webmail.md), [ftp.md](services/ftp.md), [mssql.md](services/mssql.md), [ssh.md](services/ssh.md) |
| [vyos](systems/vyos.md) | Routed interfaces, NAT; DHCP if discovered | [vyos-palo-alto.md](services/vyos-palo-alto.md) |
| [windows11-workstation](systems/windows11-workstation.md) | Client workflows; SSH if discovered | [http-https.md](services/http-https.md), [smtp.md](services/smtp.md), [pop3-imap-webmail.md](services/pop3-imap-webmail.md), [ftp.md](services/ftp.md), [mssql.md](services/mssql.md), [ssh.md](services/ssh.md) |

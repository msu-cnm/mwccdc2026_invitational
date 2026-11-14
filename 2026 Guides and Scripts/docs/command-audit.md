# Command review — 2026-11-13

This review covers the maintained documentation under `docs/`, all ten machine guides, all ten service guides, and command generation/invocation in `scripts/`. No AGENTS.md or CLAUDE.md was found in the repository or its parent directories. No commands were deployed to event machines. Repository checks establish offline behavior; they cannot establish appliance acceptance, installed packages, credentials, certificate trust, network paths or scoring success.

## Using the examples

Run Python tools from the repository root with Python 3. Replace every `<...>`, `REPLACE_*`, `JOB_ID`, example domain, interface, service unit, timestamp and path before execution. Shell angle brackets otherwise act as redirection. Use the assigned team number, confirmed portal assignments and actual installed services. Run privileged service/configuration/backup commands as root or elevated PowerShell on the named host. Install only missing tools needed for a confirmed task. Keep errors visible and check exit status; a file created by redirection can be empty after command failure.

Use the correct interpreter: T-SQL in SSMS/sqlcmd, SPL in Splunk Search, configuration stanzas in the named configuration file, and appliance commands in the stated CLI mode. Multi-line Python examples use `python3 -c` from Bash. Discovery filters can return nothing when a component is absent; this is not proof that the machine is healthy.

## Review results

| Platform/service | Corrections and execution prerequisites |
|---|---|
| VyOS 1.4.0 | Explicit NAT rules/statistics, DHCP leases/statistics and conntrack statistics commands; operational `run` prefix from configuration mode; native save/load backup; confirmed-commit reboot behavior; team/interface substitutions. The tagged current-boot log command is `show log 200`; `show log tail 200` is not its equivalent. |
| PAN-OS 11.0.2 | Diff is operational: `run show config diff` from configuration mode. Validation/commit jobs require successful completion. Removed bare operational `show zone`; use Network > Zones and the existing configuration. Preserve NAT/object references and management service routes. Syslog profiles require actual log-forwarding attachments. |
| HTTP/HTTPS | Listener filters now match local ports instead of the last output column. Local TLS checks preserve hostname/SNI. Backups include hidden content, full server configuration and TLS keys; database backup uses the discovered backend. |
| FTP | Correct vsftpd `rsa_cert_file`/`rsa_private_key_file`, cipher spelling and chroot settings. Single selected backup directory, actual Debian/Rocky config path and content-preserving archives replace ambiguous wildcard copies. No invented vsftpd syntax-check flag. |
| SMTP | Removed invalid Exim status example and inbound/outbound SASL confusion. Preserve recipient-domain maps. Create protected backup storage; mailbox/queue consistency requires mail-stack-specific handling. |
| POP3/IMAP/webmail | Correct listener filters; explicit verified TLS contexts, password prompts, timeouts and read-only IMAP selection. Archive and restore use the same discovered mailbox root. Dovecot 2.3 LDAP syntax remains conditional on the installed version and working userdb. |
| DNS/AD | Correct PowerShell filters and DNS properties/log channel; Linux LDAP tools separated from Windows commands. TLS bind checks use trusted AD certificates. DNS installation does not install AD DS unnecessarily. System State needs Windows Server Backup and a real backup volume; SYSVOL copies are inventories. |
| MSSQL | PowerShell wildcard for named instances corrected to `MSSQL$*`; SQL separated from PowerShell. Discover counter paths and instance ports. A Windows sqlcmd query uses the intended identity; unconfigured Linux integrated authentication is not assumed. Removed generic destructive restore example. |
| SSH | Debian/Ubuntu `ssh` versus Rocky `sshd` units distinguished. Firewall changes explicitly target the discovered zone and preserve runtime rules. Host-key confirmation remains enabled. Validate configuration before reload. |
| Splunk | Web HTTP/HTTPS depends on `enableSplunkWebSSL`; API 8089 uses TLS. Inspect effective inputs with btool. Discover systemd unit instead of assuming `splunk`. The indexer collects local logs directly without forwarding to itself. |
| Generated configuration | Reject invalid destinations, ports, stanza values and unsupported platform/method combinations before writing. Retain valid VyOS host-level `protocol tcp`: the tagged source confirms it even though a current documentation paragraph places it elsewhere. |
| IOC searches and student tools | Absolute ISO timestamps now become epoch seconds in SPL; explicit offsets are honored and absent offsets mean UTC. Existing relative-time examples remain unchanged. Searches still require the documented real fields and collection prerequisites. |

The three Linux server guides, both Windows server guides, both user workstation guides and Kali retain their OS-specific discovery and recovery procedures. Linux guard uses local runtime sysctl operations only; Windows guard uses auditpol and requires elevated Windows PowerShell. Kali Nmap calls and Splunk REST calls have offline regression coverage. The event worksheet, monitoring, evidence and report tools remain plan-first where documented. No offline check substitutes for a functional service test.

## Sources and version checks

VyOS was checked against the **1.4.0 tag**, rather than assuming all examples on the evolving 1.4 documentation match the packet image:

- [NAT operational definitions](https://github.com/vyos/vyos-1x/blob/1.4.0/op-mode-definitions/nat.xml.in)
- [Conntrack operational definitions](https://github.com/vyos/vyos-1x/blob/1.4.0/op-mode-definitions/show-conntrack.xml.in)
- [Log operational definitions](https://github.com/vyos/vyos-1x/blob/1.4.0/op-mode-definitions/show-log.xml.in)
- [Ethernet operational definitions](https://github.com/vyos/vyos-1x/blob/1.4.0/op-mode-definitions/show-interfaces-ethernet.xml.in)
- [Firewall operational definitions](https://github.com/vyos/vyos-1x/blob/1.4.0/op-mode-definitions/firewall.xml.in)
- [Syslog configuration definitions](https://github.com/vyos/vyos-1x/blob/1.4.0/interface-definitions/system_syslog.xml.in)
- [VyOS CLI modes, save/load and confirmed commits](https://docs.vyos.io/en/1.4/cli.html)
- [VyOS DHCP operation](https://docs.vyos.io/en/1.4/configuration/service/dhcp-server.html)

Other references: [PAN-OS operational/configuration modes](https://docs.paloaltonetworks.com/pan-os/11-0/pan-os-cli-quick-start/get-started-with-the-cli/understand-cli-command-modes), [vsftpd options](https://manpages.debian.org/bookworm/vsftpd/vsftpd.conf.5.en.html), [Splunk inputs.conf](https://docs.splunk.com/Documentation/Splunk/10.0.2/Admin/Inputsconf), [Splunk time modifiers](https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.0/time-format-variables-and-modifiers/time-modifiers), [sqlcmd utility](https://learn.microsoft.com/en-us/sql/tools/sqlcmd/sqlcmd-utility), [DNS PowerShell](https://learn.microsoft.com/en-us/powershell/module/dnsserver/).

Use the [validation procedure](validation.md) and record the actual build, substitutions, native validator result, functional test and rollback result for each deployment. Live validation remains outstanding for Windows, appliances, SQL, SPL and scoring.

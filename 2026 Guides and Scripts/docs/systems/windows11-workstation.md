# Windows 11 Wks

Packet p.13: **Windows 11**. Address: **DHCP**. Public/egress: **172.31.(20+team).2 (shared egress per packet)**. Role: User workstation; Palo Alto browser management. Exact score checks are unconfirmed until the portal publishes them (p.14).

Read [environment constraints](../environment.md) and complete the [event worksheet](../event-checklist.md) first. Keep NETLAB console access. Do not change names, addresses, usernames or workstation roles. Preserve ICMP and official access. Do not close ports based on conventional port examples.

## Candidate services on this host

Consolidated per-host map: [host-service-map.md](../host-service-map.md). Packet p.14 leaves precise scored services to the event portal; every entry below is a candidate to discover and confirm, not a confirmed assignment.

| Candidate service | Guide |
|---|---|
| Browser, mail/FTP/SQL clients for scoring verification (outbound only) | [http-https.md](../services/http-https.md), [smtp.md](../services/smtp.md), [pop3-imap-webmail.md](../services/pop3-imap-webmail.md), [ftp.md](../services/ftp.md), [mssql.md](../services/mssql.md) |
| SSH if installed | [ssh.md](../services/ssh.md) |

## Initial checks and system-specific security

Use `Get-NetIPConfiguration`, `Get-DnsClientServerAddress`, `Get-Service Dhcp,Dnscache` and `Get-NetConnectionProfile` to record DHCP and domain status. Preserve DHCP, DNS, time, workstation login and browser access to Palo Alto management and event resources. Do not retask it as a server.

Review startup apps, scheduled tasks, local administrators and installed browser extensions using native tools. Check `Get-MpComputerStatus` if Defender exists; do not run bulk quarantine or delete detected files before evaluating service impact/evidence. Keep existing protective controls enabled and rehearse updates before any reboot. Monitor task/service creation, privileged logons, listeners and disk/memory. Test normal login and browser workflows after changes.

## Scripts and reversible changes

From the repository root in PowerShell (elevate for application):

```powershell
.\scripts\windows_guard.ps1 -Action Assess
.\scripts\windows_guard.ps1 -Action Harden
# Use an existing operator-only directory and a fresh filename:
.\scripts\windows_guard.ps1 -Action Harden -Apply -Backup C:\Secure\audit-before.csv
.\scripts\windows_guard.ps1 -Action Rollback -Backup C:\Secure\audit-before.csv
.\scripts\windows_guard.ps1 -Action Rollback -Apply -Backup C:\Secure\audit-before.csv
```

Harden enables only success/failure Logon auditing. It backs up the full audit policy; rollback restores that full policy and may overwrite later audit changes. Coordinate with other operators and GPO before rollback. Repeat application to the same backup path is rejected. Restrict the backup directory's ACL to operators and SYSTEM. Increased audit volume can fill logs: monitor retention and disk use. Assess exports event counts rather than raw credential-bearing messages; unavailable event access can produce empty counts, which is not proof of no incidents. The script does not change firewall, accounts or services.

## Monitoring and scoring verification

Capture a baseline before changes, then compare service health, listeners, authentication events, persistence and resources at least every few minutes. Follow the system-specific checks above and [incident workflow](../event-checklist.md). Confirm every assigned authenticated/content check in Quotient at `https://quotient.ccdc.events/`, available also through `https://auth.ccdc.events/`. Internal success alone does not prove public NAT or scoring success. No scripted connectivity check against arbitrary targets is provided.

After each single change test existing management, ICMP and the actual scored workflow; check every downstream dependent system. Coordinate password updates with dependency owners and immediately update Quotient PCR. Store secrets separately. If anything regresses, use the script rollback or saved native configuration, retest and record the outcome. Do not rely on VM snapshots; the packet says they are unavailable.

Validation status: documentation is based on packet facts, with uncertainty stated. No live competition system or representative VM was available for connectivity, service recovery or platform-specific runtime validation. Rehearsal remains mandatory before event deployment.

## Vulnerabilities and applicability

Run read-only discovery in an elevated PowerShell session; reading Security logs requires administrative/Event Log Readers access and some AD/SQL queries require additional delegated rights. Keep output in an operator-only directory, with UTC timestamps and no passwords. An access-denied error or empty log is a collection gap.

```powershell
Get-ComputerInfo | Select-Object WindowsProductName,WindowsVersion,OsBuildNumber,OsArchitecture
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' |
  Select-Object ProductName,DisplayVersion,CurrentBuild,UBR,EditionID
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 15
Get-WindowsPackage -Online | Where-Object PackageState -eq Installed |
  Select-Object PackageName,ReleaseType,InstallTime
Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess
auditpol /get /category:* /r
```

`Get-HotFix` alone is not a complete servicing inventory; compare build/revision and installed packages with release history, the exact KB prerequisites/known issues and Microsoft Security Update Guide product filters. A product name or old-looking version is possible exposure, not a confirmed CVE. These guides deliberately do not infer a CVE or fixed build from the packet.

1. **Unsupported release or missing applicable Windows update.** Match actual edition, release/build and servicing channel to Microsoft's Windows 11 lifecycle/build table. A release can be unsupported for one edition and supported for another; do not infer from “Windows 11.” Confirm missing applicable updates and feature prerequisites using exact KB/advisory details. Apply a supported security update or stage an explicitly supported feature-update path after compatibility testing. While deferred, keep workstation role, DHCP/DNS, browser egress, Palo Alto management, ICMP and official access; use an existing patched approved browser and avoid unknown downloads. Unexpected service installs, crashes or privileged logons are indicators requiring System/Security collection, not proof of a named CVE.
2. **Browser/extension exposure.** Discover each installed browser's actual version through About (`edge://settings/help` for Edge), `edge://extensions` and `edge://policy` (or the installed vendor's equivalents); record extension ID/version/origin/permissions. Old applicable browser builds, unapproved extensions with all-site/cookie permissions or forced-install policy changes warrant review; an extension alone is not compromise. Manually update via the browser's supported signed updater and remove/restrict only confirmed unauthorized extensions after backing up approved policy/settings. While deferred, use a clean approved profile for management and keep required public/management web access. Watch new forced-install policy/extension changes and unexpected browser children; process history needs 4688 command-line/Sysmon, browser UI/current policy is only present-state evidence.
3. **Local privilege/persistence weaknesses.** Run `Get-LocalGroupMember -SID 'S-1-5-32-544'`, inspect service executable permissions and task principals/actions. A service path in a user-writable directory or unexplained administrator/task is an actionable misconfiguration after checking effective ACLs/ownership; a signed updater or quoted path alone is not suspicious. Correct only identified ACLs/grants/task definitions after exporting them and confirming owner/dependencies. While deferred, use standard-user browsing, retain the known operator/admin path and monitor the affected path/task; do not disable required management or mass-delete tasks. Indicators include 4732 local Administrators changes, 7045/4697 services, 4698/4702 tasks, and unexpected elevated scripts, with audit prerequisites below.

## Patching and recovery

1. Record actual release/edition/build, browser versions/extensions, domain/DHCP/DNS status, management browser workflow, local logon and outstanding restart. Confirm release support and driver/application compatibility before choosing a target.
2. Back up user work and approved browser policy/settings (exclude credentials from ordinary exports), task XML/service configuration for any intended edits, and BitLocker recovery material in the approved protected store. Confirm NETLAB console and a supported Windows recovery/repair path; snapshots are unavailable.
3. Preview selected updates in Settings > Windows Update and review exact KB applicability, prerequisites, known issues, disk needs and restart impact. For browser updates review the installed vendor's release/security notes. Rehearse a feature update separately; do not select every optional driver/update or enable unattended upgrades.
4. Manually install one approved Windows/browser update at a time. Schedule any requested OS reboot and browser relaunch with the operator; a browser relaunch can terminate firewall management sessions. Keep a second authorized management/console path and do not interrupt servicing.
5. Verify new build/browser version, sign-in, DHCP/DNS, browser TLS and Palo Alto management, event resources, normal workstation activity, ICMP and assigned scoring checks. Recheck extensions/policies and pending restart.
6. If broken, preserve WindowsUpdateClient/System events and update history. Restore only the specific reversible setting/task/extension policy first. Follow the exact KB's supported repair/recovery procedure; removal/feature rollback windows are not guaranteed. Use supported Windows recovery or staff-coordinated repair from approved media with protected data and BitLocker material, preserving machine identity/role; retest dependencies and scoring.

## Detection when patching is deferred

The repository's `windows_guard.ps1` enables **only Logon success/failure auditing** (typically 4624/4625); it does not enable every event below. Inspect effective policy with `auditpol`, log retention with `Get-WinEvent -ListLog Security,System`, and GPO ownership before requesting extra auditing. Account Management is required for 4720/4728/4732/4756; Special Logon for 4672; Security System Extension for 4697; Other Object Access Events for 4698/4702; Process Creation for 4688, with a separate policy for command lines. System 7045 is a separate service-install source. PowerShell 4104 requires Script Block Logging in `Microsoft-Windows-PowerShell/Operational`; Sysmon is optional and not presumed installed. Audit increases volume and may record secrets: protect exports, size retention and coordinate configuration changes. No event proves a malicious actor without context.

Review Defender status/history only if present (`Get-MpComputerStatus` and Windows Security UI); Defender Operational events 1116/1117 reflect detection/action, not all execution. Existing browser extension UI, service/task inventory and ACL checks provide local fallback when central event history is unavailable. Record policy/version evidence periodically; missing baseline means a change cannot be dated confidently. Preserve the browser profile and identified script safely before approved targeted remediation; do not export saved passwords/cookies into reports.

## Threat hunting

The event queries below cap returned records with `-MaxEvents`. If the cap is reached, subdivide the 30-minute window with explicit `StartTime` and `EndTime` to avoid hiding earlier activity. Current account/service/task inventories are present-state evidence, not a history of the entire window.

```powershell
$since=(Get-Date).AddMinutes(-30)
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624,4625,4732;StartTime=$since} -MaxEvents 200 |
  Select-Object TimeCreated,Id,Message
Get-WinEvent -FilterHashtable @{LogName='System';Id=7045;StartTime=$since} -MaxEvents 100 |
  Select-Object TimeCreated,Id,Message
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4698,4702;StartTime=$since} -MaxEvents 100 |
  Select-Object TimeCreated,Id,Message
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104;StartTime=$since} -MaxEvents 100 |
  Select-Object TimeCreated,Id,Message
Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location,User
Get-ScheduledTask | Select-Object TaskPath,TaskName,State,Actions,Principal
Get-CimInstance Win32_Service | Select-Object Name,StartName,State,PathName
```

- **Hypothesis: an unauthorized account gained local admin.** Use first query and `Get-LocalGroupMember -SID 'S-1-5-32-544'`; correlate 4732's target group SID with logons and baseline membership. Domain policies, authorized support and injects are benign explanations. Confirm account owner/effective rights and preserve actor LogonId before changing a specific grant; avoid indiscriminate account resets.
- **Hypothesis: services/tasks or PowerShell establish persistence.** Use the next three queries and current inventory; inspect only a suspect task with `Get-ScheduledTask -TaskName 'REPLACE_EXACT_TASK' | Select-Object -ExpandProperty Actions`. For a discovered executable use `Get-AuthenticodeSignature -LiteralPath 'REPLACE_EXACT_PATH'` and `Get-Acl -LiteralPath 'REPLACE_EXACT_PATH'`. Encoded commands, temp/profile paths, new privileged principals or surprising network destinations are leads. Signed updaters and legitimate admin scripts are common matches; verify signer/hash/owner and correlate installation/change records before disabling anything. 4104 absence without enabled logging is unknown, not clean.
- **Hypothesis: a malicious extension intercepts management browsing.** In each installed browser inspect About, extension IDs/permissions and policy pages; compare to the protected prior inventory and check current user's Run keys with `Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'`. An unapproved all-sites extension, unexpected forced-install policy or profile executable warrants investigation; approved password managers/security extensions may explain broad permissions. Correlate with user consent, browser vendor source and optional 4688 history from the same 30-minute interval. Preserve relevant extension metadata and check management account sessions; avoid copying tokens or browsing secrets into incident notes.

## Splunk monitoring

For installation, input configuration, validation and rollback for this host, use [concrete data-source setup](../splunk-data-sources.md).

Map `index=REPLACE_WINDOWS`, `host="REPLACE_LIVE_HOST"` and `sourcetype="REPLACE_SECURITY"` to discovered inputs first; topology IDs are inventory keys, not verified hostnames. This example assumes XML Security events and extracted `EventCode`, `SubjectUserName`, `TargetUserName`, `IpAddress`; map `EventID` or vendor add-on fields if necessary. Start with `index=REPLACE_WINDOWS host="REPLACE_LIVE_HOST" earliest=-30m latest=now | table _time source sourcetype _raw` to verify ingestion and fields. A zero-result detection with no matching raw records is unknown coverage. See [shared collection, tuning and evidence guide](../splunk-threat-hunting.md).

For `windows11-workstation`, Security Logon and System events may exist locally; collection is not established by the script. Task/account audit, 4104, Defender and Sysmon are optional, separately configured channels. WEF/existing approved forwarder can transport them; do not assume an add-on or universal forwarder exists.

```spl
index=REPLACE_WINDOWS host="REPLACE_LIVE_HOST" earliest=-30m latest=now
((source="WinEventLog:System" EventCode=7045) OR
 (sourcetype="REPLACE_SECURITY" (EventCode=4698 OR EventCode=4702 OR EventCode=4732)))
| table _time source EventCode SubjectUserName TargetUserName ServiceName ImagePath TaskName
| sort 0 - _time
```

Map the System `source` to actual WinEventLog/XML input values before use. Expect a timeline of new services, task edits and local-group changes. Inspect raw XML when fields are empty, identify the target Administrators SID for 4732, and compare service/task paths with the signed updater and approved-change baseline. Reboots/installers are common benign causes. Collection/retention failure can hide the entire interval; retain independent local event exports and current state.

## References

Official documentation inspected through the web tool on **2026-11-13**; live release/build/browser applicability and SPL remain untested.

- [Microsoft Security Update Guide](https://msrc.microsoft.com/update-guide) — product-specific applicability/KB lookup; page reachable but JavaScript product results must be checked live.
- [Advanced security auditing FAQ](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/advanced-security-auditing-faq) — audit policy and collection prerequisites.
- [Windows 11 release information and edition support periods](https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information).
- [Microsoft Edge extension policies and host/permission restrictions](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-manage-extensions-policies).

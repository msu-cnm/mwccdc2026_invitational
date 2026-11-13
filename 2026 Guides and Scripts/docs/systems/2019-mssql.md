# 2019 MSSQL

Packet p.13: **Windows Server 2019 Standard**. Address: **172.20.240.120**. Public/egress: **172.25.(20+team).120**. Role: SQL; instance, authentication mode and application dependencies unconfirmed. Exact score checks are unconfirmed until the portal publishes them (p.14).

Read [environment constraints](../environment.md) and complete the [event worksheet](../event-checklist.md) first. Keep NETLAB console access. Do not change names, addresses, usernames or workstation roles. Preserve ICMP and official access. Do not close ports based on conventional port examples.

## Candidate services on this host

Consolidated per-host map: [host-service-map.md](../host-service-map.md). Packet p.14 leaves precise scored services to the event portal; every entry below is a candidate to discover and confirm, not a confirmed assignment.

| Candidate service | Guide |
|---|---|
| SQL Server instance (default or named) | [mssql.md](../services/mssql.md) |
| SSH if installed (not a default Windows service) | [ssh.md](../services/ssh.md) |

## Initial checks and system-specific security

Discover instances with `Get-Service *SQL*`, SQL Server Configuration Manager and listening process/ports. Identify static/dynamic instance ports, SQL Browser requirements, authentication mode, database names and ecommerce/reporting dependencies. Do not assume 1433 or enable every SQL service.

Use an existing authorized SQL client to run `SELECT @@VERSION; SELECT name,state_desc FROM sys.databases;` locally with integrated authentication where configured. Do not put passwords on a command line. Back up databases with the established supported SQL backup process and protect backup files; verify restore in a disposable instance. Review sysadmin membership, Agent jobs and SQL logins without disabling a scored or dependent identity. Disable unused risky features only after proving no application depends on them. Test the actual application transaction/query as well as SQL authentication. Monitor ERRORLOG locally, failed logins, job changes, database state and disk growth. Preserve database contents and connection strings.

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

Discover SQL separately: **Windows Server 2019 does not imply SQL Server 2019**. In an existing authorized SQL client, integrated login where configured, run these read-only queries (metadata visibility depends on delegated SQL rights; do not grant sysadmin just for hunting):

```sql
SELECT @@VERSION AS version,
 SERVERPROPERTY('ProductVersion') AS product_version,
 SERVERPROPERTY('ProductLevel') AS product_level,
 SERVERPROPERTY('ProductUpdateLevel') AS update_level,
 SERVERPROPERTY('Edition') AS edition,
 SERVERPROPERTY('IsIntegratedSecurityOnly') AS windows_auth_only,
 SERVERPROPERTY('ErrorLogFileName') AS error_log;
SELECT name,state_desc,recovery_model_desc FROM sys.databases;
SELECT name,value_in_use FROM sys.configurations
 WHERE name IN ('xp_cmdshell','Ole Automation Procedures','external scripts enabled','Ad Hoc Distributed Queries');
SELECT r.name AS role_name,m.name AS member_name
 FROM sys.server_role_members rm JOIN sys.server_principals r ON rm.role_principal_id=r.principal_id
 JOIN sys.server_principals m ON rm.member_principal_id=m.principal_id;
SELECT name,type_desc,is_disabled,create_date,modify_date FROM sys.server_principals
 WHERE type IN ('S','U','G');
```

1. **Applicable Windows or SQL security update absent.** Compare discovered SQL branch/build/edition with Microsoft's SQL build tables and the applicable advisory's CU/GDR branch and prerequisites; compare Windows independently. Missing KB/build evidence plus an affected enabled component establishes applicability. Manually apply the supported update for that branch, not an invented application upgrade. While deferred, retain SQL/ecommerce and official access and restrict only proven unused execution surfaces or confirmed malicious sources with dependency approval. Correlate abnormal SQL errors, unexpected SQL service child processes (4688/Sysmon optional) and logons; these are leads, not a CVE signature.
2. **Excessive server roles or exposed authentication.** Inspect role membership above, Configuration Manager protocols/ports and authentication mode. Mixed mode, a listener or a SQL login is not inherently a vulnerability; an unnecessary effective sysadmin grant, weak approved credential or unencrypted connection requires verification. Remove specific unjustified grants and stage trusted TLS/client compatibility; coordinate any credential rotation and PCR. While deferred, alert on privileged logins/role changes and retain all required public services. SQL login failure auditing may record 18456 in discovered ERRORLOG; successful logins and role/permission changes need configured SQL Audit/appropriate Extended Events, not Windows Logon alone.
3. **Agent jobs or execution features enable persistence.** Review `msdb.dbo.sysjobs`, job steps/proxies/owners and configuration above. Enabled `xp_cmdshell` alone does not prove abuse; unapproved shell steps, privileged proxies or writable executable paths establish a risk. Export reviewed definitions and disable only the proven unused feature/job or correct its owner/ACL after app tests. While deferred, baseline jobs/features and watch SQL-worker children, unexpected outbound connections and job alterations. SQL Audit groups such as SERVER_OPERATION_GROUP/SERVER_PERMISSION_CHANGE_GROUP and appropriately scoped Extended Events must be deliberately selected for the discovered version; object/statement auditing for msdb changes is not guaranteed by default. Protect logged statement text as it may contain secrets.

## Patching and recovery

1. Record Windows and SQL builds, every instance, ports, databases, recovery models, jobs, authentication and app transactions. Check available disk, pending Windows restart and dependencies; SQL catalog reads are discovery, not a backup.
2. Use the established supported full/differential/log backup chain appropriate to recovery models, including system databases, Agent definitions, logins/SIDs and encryption certificates/keys in restricted storage. Rehearse a restore on a compatible disposable instance. `RESTORE VERIFYONLY` alone does not prove a working restore; never overwrite live databases as a test.
3. Preview the exact Windows KB and SQL CU/security package applicability, supported branch, supersedence, known issues, installer prerequisites and restart requirements. Use SQL setup's supported rule checks; confirm ecommerce/mail/reporting maintenance windows and a tested recovery path.
4. Manually install one approved signed package for the actual instance/branch; review installer summary/detail logs. Do not run broad automatic updates or assume a major-version upgrade is needed. Service interruption may occur; coordinate SQL/Agent restart and any OS reboot required by setup, with console access.
5. Requery version and database state, verify Agent/jobs as applicable, SQL ERRORLOG, owned app query/transaction and authentication, listeners, backups, ICMP, management and public Quotient workflows. Do not test by modifying production data without an approved reversible transaction.
6. If regression occurs preserve setup/ERRORLOG and stop stacking changes. Follow that package's supported repair/recovery instructions; do not assume CU/security update uninstall is supported. Use rehearsed compatible-instance restore/recovery with certificates and transaction logs if needed, preserving names/data and coordinating staff; no snapshots or unsafe database file copies. Revalidate scoring/dependencies.

## Detection when patching is deferred

The repository's `windows_guard.ps1` enables **only Logon success/failure auditing** (typically 4624/4625); it does not enable every event below. Inspect effective policy with `auditpol`, log retention with `Get-WinEvent -ListLog Security,System`, and GPO ownership before requesting extra auditing. Account Management is required for 4720/4728/4732/4756; Special Logon for 4672; Security System Extension for 4697; Other Object Access Events for 4698/4702; Process Creation for 4688, with a separate policy for command lines. System 7045 is a separate service-install source. PowerShell 4104 requires Script Block Logging in `Microsoft-Windows-PowerShell/Operational`; Sysmon is optional and not presumed installed. Audit increases volume and may record secrets: protect exports, size retention and coordinate configuration changes. No event proves a malicious actor without context.

Windows authentication is not equivalent to SQL authentication, particularly for SQL logins. Discover the actual ERRORLOG path from `SERVERPROPERTY` above; review the SQL instance's Application provider and configured SQL Audit destination and Extended Event sessions. Read `SELECT name,is_state_enabled FROM sys.server_audits; SELECT name FROM sys.server_event_sessions;` when permitted. Audit targets must be enabled, writable and retained; scopes/action groups determine visibility. Extended Events contents and file paths are configuration-specific. Do not presume queries, role changes, job edits or successful logins are recorded. Keep local copies of relevant error/audit/setup evidence protected outside the SQL service account's write access where possible.

## Threat hunting

The event queries below cap returned records with `-MaxEvents`. If the cap is reached, subdivide the 30-minute window with explicit `StartTime` and `EndTime` to avoid hiding earlier activity. Current account/service/task inventories are present-state evidence, not a history of the entire window.

1. **Hypothesis: an attacker escalated SQL privileges.** Rerun the bounded principal/role inventory above and compare to a reviewed baseline; in SSMS inspect existing SQL Audit records for the last 30 minutes for server-role/server-permission changes and actor/session. A DBA/inject can legitimately change membership. Confirm effective permissions, app owner and change record before removing a grant; absence of configured SQL Audit means history is unknown.
2. **Hypothesis: Agent jobs execute unauthorized commands.** Use these read-only queries (SQL Agent may not exist in the installed edition). Unexpected CmdExec/PowerShell steps, proxy/owner changes or user-writable paths are leads; maintenance/backup jobs are common benign matches. Follow up by reviewing only identified step definitions in a protected client and correlating audit/4688 evidence; do not run the job to test it.

```sql
SELECT TOP (100) j.name,j.enabled,j.date_created,j.date_modified,
 SUSER_SNAME(j.owner_sid) AS owner,s.step_id,s.subsystem,s.proxy_id
 FROM msdb.dbo.sysjobs j JOIN msdb.dbo.sysjobsteps s ON j.job_id=s.job_id
 ORDER BY j.date_modified DESC,j.name,s.step_id;
SELECT TOP (100) j.name,h.run_date,h.run_time,h.run_status
 FROM msdb.dbo.sysjobhistory h JOIN msdb.dbo.sysjobs j ON h.job_id=j.job_id
 ORDER BY h.instance_id DESC;
```

3. **Hypothesis: password abuse or SQL-to-OS persistence.** Read the discovered ERRORLOG's last 200 lines locally (`Get-Content -LiteralPath 'REPLACE_DISCOVERED_ERRORLOG' -Tail 200`) and correlate timestamped 18456 sources with successful logins only where Audit/XE collects them. Use the bounded Windows queries below to inspect service/process leads. Stale app connection strings and legitimate setup/backup programs can explain both failures and children. Follow up with app owner and signed executable/path inspection; preserve logs before any credential coordination or containment.

```powershell
$since=(Get-Date).AddMinutes(-30)
Get-WinEvent -FilterHashtable @{LogName='System';Id=7045;StartTime=$since} -MaxEvents 100 |
  Select-Object TimeCreated,Id,Message
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624,4625,4688;StartTime=$since} -MaxEvents 200 |
  Select-Object TimeCreated,Id,Message
Get-CimInstance Win32_Service | Where-Object Name -Match 'SQL' |
  Select-Object Name,StartName,State,PathName
```

ERRORLOG rotation/tail may omit the time interval; locate archived logs and explicitly bound by event timestamps. Permission errors must be recorded, not treated as clean hunts.

## Splunk monitoring

For installation, input configuration, validation and rollback for this host, use [concrete data-source setup](../splunk-data-sources.md).

Map `index=REPLACE_WINDOWS`, `host="REPLACE_LIVE_HOST"` and `sourcetype="REPLACE_SECURITY"` to discovered inputs first; topology IDs are inventory keys, not verified hostnames. This example assumes XML Security events and extracted `EventCode`, `SubjectUserName`, `TargetUserName`, `IpAddress`; map `EventID` or vendor add-on fields if necessary. Start with `index=REPLACE_WINDOWS host="REPLACE_LIVE_HOST" earliest=-30m latest=now | table _time source sourcetype _raw` to verify ingestion and fields. A zero-result detection with no matching raw records is unknown coverage. See [shared collection, tuning and evidence guide](../splunk-threat-hunting.md).

For `2019-mssql`, available sources depend on inputs: Windows Security Logon, System/Application and discovered SQL ERRORLOG; SQL Audit, Extended Events and process telemetry are optional with separate permissions/configuration. ERRORLOG file monitoring needs its actual path, multiline/time extraction and SQL service log rotation handling. SQL Audit binary files require supported decoding/export; do not treat them as plain text.

```spl
index=REPLACE_SQL host="REPLACE_LIVE_HOST" sourcetype="REPLACE_SQL_ERRORLOG" earliest=-30m latest=now
("18456" OR "Login failed")
| rex field=_raw "\[CLIENT: (?<sql_client>[^\]]+)\]"
| bin _time span=5m
| stats count AS failed_records values(sql_client) AS clients by _time host
| sort 0 _time
```

Expect failure-record counts per five minutes, not necessarily unique failed sessions: multi-line SQL errors may split across events. Inspect raw records and map client extraction/time parsing to the actual log format. Benign causes include stale app credentials; correlate with app changes and optional SQL Audit successes before declaring spraying. Silent errors/audits may indicate collection failure or log rollover rather than safety.

## References

Official documentation inspected through the web tool on **2026-11-13**; select the documentation version matching the discovered SQL major version before any change. No live instance, package applicability or runtime SPL was validated.

- [Microsoft Security Update Guide](https://msrc.microsoft.com/update-guide) — product-specific applicability/KB lookup; page reachable but JavaScript product results must be checked live.
- [Advanced security auditing FAQ](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/advanced-security-auditing-faq) — audit policy and collection prerequisites.
- [SQL Server update/build and branch tables](https://learn.microsoft.com/en-us/troubleshoot/sql/releases/download-and-install-latest-updates).
- [SQL Server Audit targets, scopes and edition prerequisites](https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-database-engine).
- [Windows Server release/build history](https://learn.microsoft.com/en-us/windows/release-health/windows-server-release-info).

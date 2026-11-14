# Splunk threat hunting and monitoring

Start collection with the [per-host Splunk data-source setup](splunk-data-sources.md), including receiver configuration, forwarder inputs, appliance syslog, test events and alerts.

Use the [environment](environment.md), [event worksheet](event-checklist.md) and individual [system guides](README.md) before changing collection. This is a reviewable collection and search plan, not deployed configuration or proof of detection. Preserve public scoring, ICMP, official access, NAT, workstation egress, authenticated Splunk queries and all discovered dependencies. No agents, add-ons, receiving ports, normalized fields or indexes are assumed installed. Installing software or changing collection requires the event change gate and permission under competition rules.

## Discover collection before searching

1. Record actual Splunk version/build, license, topology, current inputs, receiving endpoints, forwarders and permitted indexes in Settings and Monitoring Console using an authorized role. Do not expose API tokens or passwords. Compare local inputs and effective configuration with the Debian Splunk guide. Defaults such as 9997, 8088, 8000 and 8089 are candidates only.
2. Record each topology ID's actual hostname, Splunk `host` values, source, timezone, index, sourcetype, expected event cadence and retention. Topology IDs below are inventory keys, **not verified live hostnames**; DHCP and relay host rewriting can obscure identity. Preserve original appliance hostname/IP when receiving syslog.
3. Existing readable local logs are available only after confirming their existence and permissions. Central ingestion is unconfirmed for every machine. A forwarder can read permitted files/Windows channels if already approved; Windows Event Forwarding to an existing collector is another option. A syslog relay can persist appliance logs to protected files for existing collection. Prefer reliable authenticated/encrypted transport where supported; UDP may lose events. Do not assume TLS, receivers or certificates exist. Avoid duplicate collection, credential-bearing command lines and unrestricted log permissions.
4. Validate timestamp parsing, multiline framing, Windows XML extraction and source host attribution on one harmless event. Restrict collection privileges to needed channels/files. Root/administrator may be needed locally; Splunk search permissions may omit `_audit`, `_internal` or security indexes. Empty results can mean denied access, missing ingestion, wrong time/host/fields, disabled audit, filtering, dropped events or actual silence.

All examples use **SPL**, not SPL2. The generator uses `index=team_security` for external sources; replace that index only if deliberately configured differently. Verify sourcetypes and host placeholders with discovered values before use. `_audit` and `_internal` are built-in names, but access and local indexing still need verification. Proposed sourcetypes are labels to map to your actual parser; no Common Information Model or add-on is required or presumed. The raw alternatives below are a fallback for discovery, not equivalent detections.

## Ten-machine telemetry matrix

Every source in this table is a collection candidate, not a statement that it is ingested. Windows Logon success/failure is the only audit change made by `windows_guard.ps1`; existing policy/GPO and channel availability must be checked separately. Linux guard enables no audit rules.

| Topology ID | Source logs and local availability to check | Collection / privileges and optional prerequisites | Proposed sourcetypes; useful fields to map |
|---|---|---|---|
| `rocky-ecom` | journald, discovered web access/error/app logs; `/var/log/secure` only if rsyslog writes it | Existing file forwarder or approved journal export; root for protected logs; optional auditd/EDR for process ancestry, DB audit for SQL actions | `linux_auth`, `web_access`, `app_error`; host, user, src_ip, uri_path, status, method, process, dest_ip |
| `ubuntu-email` | discovered SMTP/IMAP/webmail logs, journal; auth.log if configured | Forward files/journal export; mail-log group/root; optional daemon authentication/queue logging, never message bodies or credentials | `linux_auth`, `mail_log`; user, src_ip, action, queue_id, recipient_count, relay, status |
| `debian-splunk` | Splunk audit.log, splunkd.log, metrics.log under actual SPLUNK_HOME; OS auth/journal | Existing Splunk self-monitoring verified in `_audit`/`_internal`; search role plus protected local access; optional process auditing | `audittrail`, `splunkd`, `splunkd_metrics`, `linux_auth`; user, action, info, component, group, name, host |
| `2022-ad` | Security, System; Directory Service; optional PowerShell Operational | Existing forwarder/WEF; Event Log Readers with channel ACLs; Account/Group Management, Directory Service Changes/Access with appropriate SACLs, Kerberos/Credential Validation auditing optional | `WinEventLog:Security`, `WinEventLog:System`; EventCode, TargetUserName, SubjectUserName, IpAddress, ObjectDN, AccessMask |
| `2019-mssql` | Security/System, actual SQL ERRORLOG and Agent history; optional SQL Audit/XE | Existing forwarder/WEF and approved SQL exports; SQL permissions scoped to metadata/audit; SQL Audit or Extended Events needed for many executed actions | `WinEventLog:Security`, `sql_error`, `sql_audit`; EventCode, user, client_ip, action_id, object_name, succeeded |
| `ubuntu-workstation` | auth/journal, apt history, discovered user autostart/browser policy | Existing file collection; root or relevant user; optional auditd/process and browser management logs | `linux_auth`, `linux_journal`, `package_history`; user, src_ip, unit, process, package |
| `windows11-workstation` | Security/System; optional TaskScheduler and PowerShell Operational, Defender Operational | Existing forwarder/WEF and channel ACLs; Process Creation/command-line policy and Script Block Logging separately required, Sysmon optional | `WinEventLog:Security`, `WinEventLog:System`, `powershell`; EventCode, user, ServiceName, TaskName, ScriptBlockText |
| `kali` | auth/journal, package history, SSH, reviewed persistence snapshots | Existing file collection or protected manual exports; root as needed; optional auditd, not tool-name signatures alone | `linux_auth`, `linux_journal`, `package_history`; user, src_ip, unit, package, process |
| `palo-alto` | local System/Config; Traffic only with rule/session logging; Threat only where profiles/features/log generation support it | Native syslog profile to approved relay, verified transport/schema/timezone; PAN administrator read access; licenses/subscriptions and content/features affect threat visibility | `pan_system`, `pan_config`, `pan_traffic`, `pan_threat`; serial, subtype, admin, action, rule, src_ip, dest_ip, session_id |
| `vyos` | native journal/syslog, authentication, commit history/config diff, interface/route state | Native supported remote syslog to approved relay; read/operational privilege; packet/flow/firewall logs optional and explicit, routing snapshots are not historical logs | `vyos_syslog`, `vyos_config`; hostname, user, message, action, interface, src_ip, dest_ip |

## Field discovery and raw-event fallback

Start with a small permitted index and bounded window, then discover source values and fields:

```spl
index=team_security earliest=-15m latest=now
| stats count by host source sourcetype
```

```spl
index=team_security host="REPLACE_HOST" earliest=-15m latest=now
| head 100
| fieldsummary
```

```spl
index=team_security host="REPLACE_HOST" earliest=-15m latest=now
| head 50
| table _time _indextime host source sourcetype _raw
```

Run the same discovery with the corresponding network/web/mail index for those searches. Read `_raw` only in the protected analyst view. Do not export credentials or message contents. Confirm each field below against raw records: a populated field with the wrong meaning can be worse than a missing field. A relay's `host` may identify the relay rather than the original device. Use verified original-device fields in that case. No-results troubleshooting begins with local evidence and this unfiltered bounded search, not with widening to unrestricted `index=*`.

## Authentication failures followed by success

Prerequisite: actual Linux authentication or Windows Security 4624/4625 collection. Normalize `user`, `src_ip`, and `action` (`failure`/`success`) from the actual event format first; Windows SubjectUserName is often the actor/system rather than the target. Map target account and source address, exclude missing/placeholder values and classify logon type. This example requires those normalized fields:

```spl
index=team_security earliest=-30m latest=now action IN ("failure","success")
| where isnotnull(user) AND isnotnull(src_ip)
| sort 0 _time
| streamstats time_window=10m count(eval(action="failure")) AS preceding_failures BY host user src_ip
| where action="success" AND preceding_failures>=5
| table _time host user src_ip preceding_failures
```

Expected: successful logins preceded by at least five failures for that account/source/host within ten minutes. Shared NAT, stale service credentials and human mistakes are benign possibilities. Compare local login/session records, authorized operator times and subsequent privilege changes before containment; preserve scoring accounts. Failures outside this window or spread across hosts are missed. Raw fallback: search the same index/time/host for `"Failed password" OR "Accepted password" OR "4624" OR "4625"`, then inspect actual records rather than inferring sequence from strings.

## Privileged accounts and groups

Prerequisite: Windows User Account/ Security Group Management auditing, Security ingestion, mapped EventCode and target/subject fields. 4719 is associated with Audit Policy Change but is logged regardless of that subcategory setting; 4739 requires Authentication Policy Change auditing. Security 1102 reports audit-log clearing independently of those account-management subcategories. Domain groups appear on DCs; local groups on member hosts. Linux changes require auditd rules for account files/executables or independent reviewed snapshots; ordinary auth logs do not record every account edit.

```spl
index=team_security earliest=-30m latest=now
| eval event_id=coalesce(EventCode,EventID)
| where event_id IN ("4720","4722","4724","4728","4732","4756","4738","4739","4719","1102")
| table _time host event_id SubjectUserName TargetUserName MemberName GroupName _raw
```

Expected: new/enabled/changed users, password resets, group additions, domain/audit-policy changes or log clearing. Membership event target is generally the group; inspect MemberName/MemberSid. Match privileged groups by SID and approved change worksheet. Help desk work and GPO deployment can explain events. Verify current membership and replication on the DC, correlate actor logon and ticket; never reset all accounts. Raw fallback: same bounded source with event IDs as strings; confirm XML EventID before classifying. Missing auditing cannot be repaired by a search.

## Services, tasks and PowerShell persistence

Prerequisite: System 7045 collection; Security 4697 requires Security System Extension auditing, 4698/4702 require Other Object Access Events auditing. PowerShell 4104 requires Script Block Logging in Microsoft-Windows-PowerShell/Operational; 4688 needs Process Creation auditing, with command lines separately enabled. TaskScheduler Operational must be enabled/collected for its history. These are optional beyond Logon auditing.

```spl
index=team_security earliest=-30m latest=now
| eval event_id=coalesce(EventCode,EventID)
| where event_id IN ("7045","4697","4698","4702","4104")
| table _time host source event_id SubjectUserName ServiceName ImagePath TaskName _raw
```

Expected: new services/tasks, task modifications and script blocks, not automatically malicious activity. Compare executable signer/hash, target path, actor and deployment records locally. Installers, backup software and management scripts are common benign causes. Raw fallback: inspect bounded System/Security/PowerShell events using discovery query; field names vary for XML and rendered logs. On Linux, collect approved audit/config-change events or compare local systemd/cron snapshots; a search cannot reconstruct prior persistence without evidence.

## Web and mail anomalies

Prerequisite: web access extraction (`status`, `src_ip`, `uri_path`, `method`) with trusted proxy handling. `src_ip` must not blindly trust client-supplied forwarded headers. Replace host with actual Rocky host mapping:

```spl
index=team_security host="REPLACE_ROCKY_HOST" earliest=-30m latest=now
| eval status=tonumber(status)
| bin _time span=5m
| stats count AS requests count(eval(status>=500)) AS server_errors values(uri_path) AS paths BY _time src_ip
| where server_errors>=10 OR requests>=200
```

Expected: bursts and error clusters. Promotions, crawlers, score checks and broken releases are benign explanations. Pivot to upload changes, web-worker children and application-to-SQL sessions on the host; response codes alone do not demonstrate exploitation. Large path lists can be sensitive. Raw fallback: bounded raw access records for the affected five minutes; look for new executable uploads, unusual methods and corresponding errors, using actual log syntax.

Prerequisite: actual mail daemon authentication/queue logs, mapped `action` (`auth_failure`, `accepted`, `deferred`, `rejected`), `src_ip`, `user`, `queue_id`; these labels require explicit normalization, not guessed strings:

```spl
index=team_security host="REPLACE_MAIL_HOST" earliest=-30m latest=now
| eval src_ip=coalesce(src_ip,"unknown"), user=coalesce(user,"unknown")
| bin _time span=5m
| stats count AS events dc(queue_id) AS messages count(eval(action="auth_failure")) AS auth_failures count(eval(action="deferred")) AS deferred BY _time src_ip user
| where auth_failures>=10 OR messages>=100 OR deferred>=20
```

Expected: authentication bursts, submission volume or deferrals. Queue-only events may lack user/source fields: the explicit unknown bucket retains them but represents queue-wide activity, not an attributable client or identity. Mail campaigns and remote delivery outages are plausible. Inspect the native queue and relay decisions without reading message bodies; preserve required mail authentication and delivery. Raw fallback: bounded actual daemon logs around queue IDs; daemon-specific statuses and trusted relays must be learned first. Absent fields can drop entire rows in `stats BY`; inspect nulls before relying on results.

## Network configuration changes

Prerequisite: verified appliance syslog schema with original-device `host`; Config logs for PAN-OS and commit/configuration messages for VyOS. Normalize `event_category="configuration"` and `user`, `action`, `object` from actual messages; no parser is assumed:

```spl
index=team_security earliest=-30m latest=now event_category="configuration"
| table _time host user action object source _raw
```

Expected: administrator commits, policy/NAT/routing/logging changes. Routine team work is benign only after matching the worksheet and native config diff. Compare new routes, NAT destinations, administrator accounts and disabled log forwarding locally. Traffic logs cannot prove absence of policy edits. Raw fallback: bounded network index for the known original hostname and `"commit" OR "configuration" OR "admin"`; verify actual message semantics. Preserve public availability, management paths and ICMP during any reversal.

## Splunk administrative changes

Prerequisite: `_audit` access and verified Splunk audit ingestion/host mapping. Actions vary by version and subsystem; inspect unfiltered records first, then tune action values. Some file edits or token actions may not be captured here; inspect local apps/configuration, OS logs and relevant splunkd components too.

```spl
index=_audit host="REPLACE_SPLUNK_HOST" earliest=-30m latest=now
| stats count values(info) AS results values(action) AS actions BY user
```

Expected: actor/action summaries; pivot into individual audit events for changed roles, saved searches, inputs, apps and unusual searches/login activity. Approved administration and scheduled searches are benign. Follow up with protected local configuration diffs and ownership; do not disable score-query accounts or remove apps blindly. Raw fallback: `_audit` same host/time `| head 100 | table _time user action info _raw`; if missing, inspect actual SPLUNK_HOME audit.log. Audit records on a compromised search host may be altered or suppressed.

## Ingestion lag and completely silent sources

Prerequisite: timestamp parsing and access to expected indexes. `_indextime-_time` mixes forwarding delay and source clock error; investigate both. Event-time bounds can miss severely delayed events:

```spl
index=team_security earliest=-24h latest=now _index_earliest=-30m _index_latest=now
| eval lag_seconds=_indextime-_time
| stats count perc95(lag_seconds) AS p95_lag max(lag_seconds) AS worst_lag min(lag_seconds) AS min_lag BY host source
| where p95_lag>120 OR min_lag < -60
```

Expected: late or future-dated events. Backfills, reboot and clock drift are benign possibilities. Check queues, relay persistence, host clock, storage, license/ingestion limits and permissions using Monitoring Console and local logs. Raw fallback: same bounds `| head 50 | table _time _indextime host source _raw`. Repeat with other discovered indexes; records older than 24h or dated in the future can be missed. Compare with an approved ingestion-time diagnostic in a controlled narrow source if investigating that condition.

Prepare a reviewed **expected-host inventory**, not one derived from events. Through approved lookup management create `expected_hosts.csv` with columns `topology_id,host,max_silence_seconds` for all ten IDs and each verified Splunk `host` mapping (multiple rows for aliases if appropriate). Values must match the observed events exactly; set thresholds using source cadence. The lookup is a prerequisite, not included/deployed here. This search seeds every expected host so an entirely absent machine stays visible:

```spl
| inputlookup expected_hosts.csv
| eval expected=1
| append [ search index=team_security earliest=-24h latest=now
    | stats latest(_time) AS last_seen BY host ]
| stats max(expected) AS expected values(topology_id) AS topology_id max(max_silence_seconds) AS max_silence_seconds max(last_seen) AS last_seen BY host
| where expected=1
| eval age_seconds=now()-last_seen
| where isnull(last_seen) OR age_seconds>max_silence_seconds
| eval state=if(isnull(last_seen),"absent in searched window","late")
| table topology_id host state last_seen age_seconds max_silence_seconds
```

Replace the subsearch base with **all explicit discovered collection indexes**, e.g. `(index=team_security OR index=team_network OR index=team_web OR index=team_mail OR index=_internal)`; the generated relay also uses team_security; include other indexes only if actually configured. Keep the 24h window and reasonable host count; append/subsearch limits can truncate observations, so inspect search warnings. Prefer one inventory row per expected host/source pair when distinguishing missing channels on an otherwise active host, and group both inventory and observed data by host/source. A quiet host needs an existing approved periodic signal or a generous documented threshold; no events alone do not imply compromise. Raw fallback: inspect local source records and receiver files independently; a search over events alone cannot reveal hosts that never sent any. Missing lookup access is an error to resolve, never a healthy result.

## Operating and rehearsing safely

Record UTC incident times plus original timezone/offset, daylight-saving behavior, event time and ingestion time. Verify NTP/time health locally without changing AD time hierarchy or appliance time sources casually. Set analyst display timezone explicitly and check a known event across local and central views.

After authorized fixture validation, an example alert cadence is every five minutes with a 15-minute search window and 2-minute ingestion allowance (`earliest=-17m latest=-2m`). Authentication correlation needs its full preceding-failure window too. Overlap can create duplicates: deduplicate alert delivery by host/user/source/event identity and retain an investigation timeline. Tune thresholds with actual scoring, backups, patch activity, shared NAT, expected administrators and service accounts. Never automatically block or reset credentials based on these starter searches. Review scheduler failures, skipped searches, role visibility and ingestion health separately; an empty dashboard is not a health signal.

Size retention against actual event volume, licensed ingestion, disk watermarks and search load. Confirm free/open-source-only event rules permit the existing Splunk deployment and any proposed components; do not add trial features. Restrict access to sensitive logs, limit collection of SQL statements/PowerShell contents, apply approved retention and redact exported reports. Do not disable logs silently when storage fills: investigate, preserve evidence and coordinate retention changes. Use local commands from each guide when central collection fails.

Non-destructive rehearsal (authorized disposable fixtures, no live scoring credentials):

1. Copy a small sanitized sample of actual approved log formats into a disposable test index using an existing permitted input, or use Search UI `makeresults` without ingestion. Do not install agents or change production logging to pass this check.
2. Use this self-contained SPL fixture to check ordering logic; expected output is one `fixture-only` success. It does not test extraction, collection or the real authentication search end to end:

```spl
| makeresults count=6
| streamstats count AS n
| eval _time=now()-360+n*30, host="fixture-only", user="test", src_ip="192.0.2.1", action=if(n=6,"success","failure")
| sort 0 _time
| streamstats time_window=10m count(eval(action="failure")) AS preceding_failures BY host user src_ip
| where action="success" AND preceding_failures>=5
| table _time host user src_ip preceding_failures
```

3. In the disposable lookup include one active fixture host and one intentionally absent fixture host; run the silence search against the fixture index and confirm the absent row survives. Test missing fields, renamed hosts, timezone offset, late arrivals, null users and duplicate forwarded events. Compare raw records to extracted fields and expected results for each search family.
4. Have a second operator review search permissions, audit prerequisites and retention. Record build, source/schema, substitutions, fixture IDs, expected/actual output and UTC time. No searches in this repository have been runtime-validated against live telemetry.
5. During an incident preserve native logs/configuration snapshots before remediation when practical: use operator-only storage, UTC labels, source/build, collector identity and SHA-256 hashes, and maintain an access/transfer record. Keep a protected independent copy in authorized storage separate from Splunk; use only competition-approved transfer paths. Avoid ordinary `/tmp` backups, public repositories and raw credential-bearing exports. Compare independent local evidence if Splunk itself may be compromised; hashes establish integrity after capture, not original truth.

## References

Official source review date: 2026-11-13. The linked official references were retrieved through the web research tool; recheck documentation for the installed build before implementation. Direct shell fetching is blocked in this workspace. No live collection, alert deployment or SPL execution was performed.

- [Splunk inputlookup reference](https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.0/search-commands/inputlookup): lookup-backed inventory; lookup permissions and field names matter.
- [Splunk search reference](https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.0): command syntax and version-specific search limits.
- [Splunk getting data in](https://help.splunk.com/en/splunk-enterprise/get-started/get-data-in/10.0): supported inputs and collection prerequisites.
- [Splunk monitoring](https://help.splunk.com/en/splunk-enterprise/administer/monitor/10.0): Monitoring Console, ingestion and platform health.
- [Microsoft advanced audit policy](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-audit-policy-settings): audit subcategories required to generate events.
- [Microsoft Windows Event Forwarding](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection): collection architecture and prerequisites.

- [Microsoft 4719 audit-policy change semantics](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4719) and [4739 domain-policy auditing](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4739): reviewed 2026-11-13.


## Expected source health and Kali pass expansion

Use `team_security` for generated Linux, Windows and appliance inputs; built-in Splunk logs remain in `_internal`/`_audit`. File sourcetypes include `linux_auth`, `linux_syslog`, `linux_journal`, `linux_audit`, `package_history`, `web_access`, `app_error`, `mail_log`, `ftp_log`, `sql_error`, `sql_agent`, `pan_raw`, `vyos_syslog`, and explicitly added `kali_watch`. Windows XML sourcetypes vary by installed input/add-on: discover them rather than forcing a label. Fields in detections require verified extractions; `pan_raw` does not itself supply `event_category`.

For a scheduled missing-source search, create `expected_sources.csv` with columns `topology_id,host,source,max_silence_seconds`. Include one row per **confirmed** source using observed host and source values, including full Windows source names. Do not inventory unavailable optional sources. Grant the scheduled-search owner lookup read and index search permissions. This starts from inventory and returns missing rows even if the entire event search returns zero events:

```spl
| inputlookup expected_sources.csv
| eval expected=1
| append [ search index=team_security earliest=-24h latest=-2m
    | stats latest(_time) AS last_seen by host source ]
| stats max(expected) AS expected max(last_seen) AS last_seen values(topology_id) AS topology_id max(max_silence_seconds) AS max_silence_seconds by host source
| where expected=1
| eval age_seconds=now()-last_seen
| where isnull(last_seen) OR age_seconds>tonumber(max_silence_seconds)
| eval state=if(isnull(last_seen),"absent in bounded window","late")
| table topology_id host source state last_seen age_seconds
```

Schedule every five minutes only after validating expected cadence. The 24-hour lookback bounds workload and caps detectable last-seen history; thresholds must fit that window and allow the two-minute ingestion delay. Overlap needs alert suppression keyed by host/source. Check subsearch limits, skipped jobs, lookup errors and role visibility; permission failures must never be treated as healthy. Quiet package logs need generous thresholds or exclusion from periodic health alerts. Test an inventory fixture with zero ingested events.

Kali results contain nested `passes` and `checks`. Preserve each pass timestamp before expanding checks; the root result timestamp is completion time, not every probe's time:

```spl
index=team_security sourcetype=kali_watch earliest=-17m latest=-2m host="REPLACE_KALI_HOST"
| spath path=passes{} output=pass
| mvexpand pass
| spath input=pass path=time_utc output=pass_time_utc
| spath input=pass path=checks{} output=check
| mvexpand check
| spath input=check
| eval pass_epoch=strptime(pass_time_utc,"%Y-%m-%dT%H:%M:%SZ")
| table pass_time_utc pass_epoch host check
```

Inspect the expanded `check` JSON and map its actual fields before alerting; retain `pass_time_utc` in exports and deduplicate repeated result-file ingestion. See the [collection recipe](splunk-data-sources.md#kali-nested-json-result-ingestion) for multiline event boundaries without changing the output schema.

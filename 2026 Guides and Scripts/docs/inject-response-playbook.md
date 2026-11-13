# Inject response playbook

A working reference for the time a scored inject happens: which indicators to look for, how to watch processes on the Windows and Linux workstations, and how to pull detection events to your own machine as a local evidence trail. This is a **reviewable plan and set of read-only observation tools**, not deployed detection and not proof that anything was caught.

Read the [environment](environment.md), [event worksheet/change gate](event-checklist.md) and the relevant [system guides](README.md#system-guides) first. Everything below assumes you have already started collection per the [per-host Splunk data-source setup](splunk-data-sources.md) and confirmed actual builds, indexes and field names. Nothing here installs software, changes collection or touches scoring traffic.

## When to use this playbook

- A live inject is announced or in progress and you need a fast, repeatable way to look for it.
- You want a **local, timestamped copy** of the detection events you see, independent of the Splunk UI, so you can review them after the window closes.
- You need to reason about what a specific technique (web shell, PowerShell, outbound C2) would look like in *your* event schema before you rely on a query.

Do **not** use this playbook to:

- change collection, indexes or forwarders mid-inject (that is the [event change gate](event-checklist.md));
- confirm a finding — every result here is a **detection lead**, and a query returning nothing is not proof of absence;
- run against any host, port or network that is not in your authorized scope.

## Indicator table

The indicators below are the patterns worth watching for during this competition. Each row names the technique, the observable signal, where it usually shows up, and the field names to look for. Field names are **candidates** — confirm against a `| head` of real events before trusting any query.

| # | Technique | Observable signal | Typical source | Candidate fields |
|---|-----------|-------------------|----------------|------------------|
| 1 | Web shell dropped on the e-commerce host | Request URI or POST body containing interpreter/eval markers (`eval(`, `base64_decode`, `system(`, `assert(`) | Rocky Ecom access log / WAF | `uri`, `request_body`, `src_ip`, `method` |
| 2 | Web shell executed by IIS | Child process of `w3wp.exe` that is a shell or interpreter (`cmd.exe`, `powershell.exe`, `whoami.exe`, `certutil.exe`) | Windows Security 4688 / Sysmon 1 | `parent_process`, `process`, `command_line` |
| 3 | Encoded / remote PowerShell | `powershell.exe -enc ...`, `FromBase64String`, `IEX`, `DownloadString`, `Invoke-Expression` | Windows Security 4688 / Sysmon 1 | `process`, `command_line` |
| 4 | Outbound C2 / exfiltration | New outbound connection to a non-standard port, or first-seen external endpoint | Palo Alto / VyOS flow logs, host telemetry | `dst_ip`, `dst_port`, `src_ip`, `process` |
| 5 | Credential access on the AD host | Kerberos TGT/TGS anomalies, unusual service-account logons, DCSync-style events | Windows Security 4768/4769; 4662 for replication access (requires directory-service auditing and appropriate SACLs) | `event_id`, `account`, `src_ip` |
| 6 | Database tampering on MSSQL | New login, `xp_cmdshell` use, bulk export, connection from a non-app host | Windows Security, SQL audit | `login`, `src_ip`, `command` |
| 7 | Scanning / tooling signature | User-agent or request patterns from known tools (`sqlmap`, `nmap`, `nikto`, `masscan`, `dirbuster`) | Web access logs | `user_agent`, `uri`, `src_ip` |
| 8 | Persistence via scheduled task / service | New task, service, or startup entry created during the window | Windows Security 4698 (task created), 4702 (task updated), 4699 (task deleted); System 7045 (service installed); Sysmon 13 (registry value set, if configured) | `task_name`, `service_name`, `account` |

Treat the table as a **starting checklist**, not an exhaustive list. The [threat hunting guide](splunk-threat-hunting.md) already covers authentication-failure→success, privileged accounts, persistence, web/mail anomalies and ingestion lag in depth — this playbook is the *live-inject* cut of that material, focused on fast look-up and local capture.

## IOC detection queries

These are the same shapes as the example config in [`config/splunk-poll.example.json`](../config/splunk-poll.example.json). They are deliberately scoped to one index and output-capped with `| head`. This limits returned rows, not necessarily search cost; use an explicit time window such as `earliest=-5m latest=now`. **Adjust field names to your actual schema** after a quick sanity check:

```spl
index=team_security | head 5
```

- **Web shell markers (URI/body):**
  ```spl
  index=team_security earliest=-5m latest=now ("eval(" OR "base64_decode" OR "system(" OR "cmd.exe /c")
    | table _time, host, uri, src_ip | head 100
  ```
- **IIS spawning a shell (row 2):**
  ```spl
  index=team_security earliest=-5m latest=now parent_process="w3wp.exe"
    (process="cmd.exe" OR process="powershell.exe" OR process="whoami.exe" OR process="certutil.exe")
    | table _time, host, process, command_line | head 100
  ```
- **Encoded / remote PowerShell (row 3):**
  ```spl
  index=team_security earliest=-5m latest=now process="powershell.exe"
    (command_line="*-enc*" OR command_line="*FromBase64String*" OR command_line="*IEX*" OR command_line="*DownloadString*")
    | table _time, host, command_line | head 100
  ```
- **New outbound connections (row 4):**
  ```spl
  index=team_security earliest=-5m latest=now eventtype=outbound (dst_port!=443 AND dst_port!=80) src_ip="172.20.240.*"
    | stats min(_time) as first_seen, max(_time) as last_seen, count by dst_ip, dst_port, process
    | head 100
  ```
- **Scanning / tooling signatures (row 7):**
  ```spl
  index=team_security earliest=-5m latest=now (user_agent="*sqlmap*" OR user_agent="*nmap*" OR user_agent="*nikto*"
    OR user_agent="*masscan*" OR user_agent="*dirbuster*")
    | table _time, src_ip, uri, user_agent | head 100
  ```

If your events do not use these field names, run the [field discovery procedure](splunk-threat-hunting.md#field-discovery-and-raw-event-fallback) first and rewrite each query against the real fields. A query that silently matches nothing because of a wrong field name is worse than no query — note in the worksheet which fields you actually verified.

## Suspicious downloads and unexpected programs

Network transfer size or an uncommon port alone does not establish a malicious download. Correlate the destination, user, file path, hash, download time and subsequent process execution. Ordinary web access logs usually omit POST bodies, and encrypted traffic logs do not expose file contents. Firewall connections are available only where traffic crosses a logging rule; they do not automatically include endpoint process names. IIS and normalized `eventtype=outbound` are conditional examples, not assumed topology features. The outbound query counts activity; it does not compare against a first-seen baseline.

On Windows, check available Defender Operational events (1116 detection, 1117 action), Sysmon 1/11 (process/file creation, if installed and configured), or Security 4663 (audited access with both File System auditing and a matching file/folder SACL). Event 4688 needs Process Creation auditing; command lines need the separate command-line policy. The Windows guard enables Logon auditing only. On Linux, correlate existing audit records for writes to download/temp/web directories with execution and authentication logs. Auth logs alone do not record every file download or process execution. Follow the [data-source guide](splunk-data-sources.md) before changing collection.

Compare executable paths, users, parent processes, services and scheduled tasks with an approved baseline. Investigate interpreters launched by web/mail services, execution from writable directories and newly added persistence. Do not terminate a process solely because it matches a query: preserve evidence and check service dependencies first. These checks need endpoint telemetry and permissions; missing events are a visibility gap.

## Live process monitoring during an inject

While the Splunk queries give you the historical view, these two local views let you watch a host *right now*. Both are read-only and print to your terminal; neither writes files or changes state.

### Windows workstation (PowerShell 5.1+)

Watch for shell/interpreter children and for encoded PowerShell. Run from an elevated prompt on the host being investigated. These are current snapshots with no time filter; short-lived processes can escape them. IIS examples apply only if IIS is actually installed:

```powershell
# Children of IIS worker processes (web shell execution)
Get-CimInstance Win32_Process -Filter "Name='w3wp.exe'" | ForEach-Object {
    Get-CimInstance Win32_Process -Filter "ParentProcessId=$($_.ProcessId)" |
        Select-Object ProcessId, Name, CommandLine
}

# Encoded / remote PowerShell anywhere on the host
Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" |
    Where-Object { $_.CommandLine -match '-enc|FromBase64String|IEX|DownloadString' } |
    Select-Object ProcessId, Name, CommandLine

# Current established connections (investigate against the approved baseline)
Get-NetTCPConnection -State Established |
    Where-Object { $_.RemotePort -ne 443 -and $_.RemotePort -ne 80 } |
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess
```

For the durable audit trail, prefer the Security log (4688 process creation) via `Get-WinEvent` rather than polling CIM — see the [Windows 11 workstation guide](systems/windows11-workstation.md#threat-hunting) for the event-ID set and the [Windows guard](../scripts/windows_guard.ps1) for enabling Logon auditing if it is not already on.

### Linux workstation / server (auditd + journal)

```bash
# Recent audit records (requires auditd and existing execve audit rules).
# Keep errors visible: missing audit access is a collection failure.
sudo ausearch -ts recent --interpret -m SYSCALL | tail -n 50

# Current established connections; no connection-age filter.
# Elevated privileges may be needed to see other users' process details.
ss -tnp state established
```

If auditd is not running, do **not** start it mid-inject without going through the [event change gate](event-checklist.md) — a new audit rule can change host behaviour and may be out of scope. Record in the worksheet that process-creation visibility was unavailable rather than improvising collection.

## Pulling detection events to your workstation

The goal: a **local, timestamped JSON evidence file** per poll cycle, so your findings survive whatever happens to the Splunk UI or the network during the window. This is what [`scripts/splunk_poll.py`](../scripts/splunk_poll.py) does.

### Setup

1. Copy the example config to a local file and edit it:
   ```bash
   cp config/splunk-poll.example.json config/splunk-poll.json
   $EDITOR config/splunk-poll.json
   ```
2. Set credentials **in the environment only** — they are never read from or written to the config file:
   ```bash
   export SPLUNK_USERNAME='your_readonly_user'
   export SPLUNK_PASSWORD='...'
   ```
3. Plan mode (no network, no side effects) to sanity-check what it will do:
   ```bash
   python3 scripts/splunk_poll.py --config config/splunk-poll.json
   ```
4. Rehearse one cycle against the lab before the live window:
   ```bash
   python3 scripts/splunk_poll.py --config config/splunk-poll.json --execute --once
   ```
5. During the inject, run a bounded number of cycles (e.g. 20 cycles, with 15 s sleeps between cycles plus query execution time) so it stops on its own:
   ```bash
   python3 scripts/splunk_poll.py --config config/splunk-poll.json --execute --max-cycles 20
   ```

Evidence files land in `inject_evidence/` (or the `evidence_dir` you set) as `events_<UTC>.json`, one per cycle that found new rows. The script dedupes identical returned rows across cycles within one process run and prunes to `max_evidence_files`. Deduplication resets on restart, uses the whole returned row (not an event ID), and shares one in-memory set across queries. Changing aggregate values count as new rows; identical rows from different queries are retained only once. Memory grows with unique rows, so use bounded runs. A query error appears in the evidence file only when another query returns new rows in the same cycle. If every query fails, the current CLI still prints `no new events` and writes no file; this message does **not** establish collection success. Verify each query independently in Splunk before relying on polling.

### What the script does and does not do

- Uses only the Python 3 standard library (`urllib`, `json`, `csv`, `ssl`). No dependencies.
- Plan-first: without `--execute` it prints a JSON plan and performs **no** network activity.
- HTTPS only, exact IPv4 management URL; specify `:8089` explicitly for the usual management port (omitting it uses HTTPS port 443). No credentials in the URL or fragments. TLS verification uses system trust or the CA file specified by `SPLUNK_CA_BUNDLE`; the certificate must cover the configured IP address.
- Reads `SPLUNK_USERNAME` / `SPLUNK_PASSWORD` from the environment; refuses to run with `--execute` if either is unset.
- Writes evidence only when a cycle found new rows. Returned command lines and query error messages may contain sensitive information: create an operator-only evidence directory (`mkdir -m 700 inject_evidence`) and use `umask 077` before execution. Filenames have one-second resolution; separate concurrent runs into different directories.
- Bounded: `--once`, `--max-cycles N`, and a per-request timeout from the config.

### Alternatives for pulling events to your machine

The Splunk REST poller is the recommended option because it is auditable, offline-testable and leaves a clean local trail. Two other approaches are worth knowing about; neither is provided as a script in this repo:

1. **Splunk UI export (manual).** Run each IOC query in the web UI, *Save As → CSV*, and drop the file into your operator-only evidence directory. Fast for one-off looks, but not repeatable and easy to mislabel — record the exact query text and time range next to each file.
2. **`splunk search` CLI from the host.** If you have shell access to the Splunk box, `splunk search 'search index=team_security earliest=-5m latest=now | head 100' -output json` runs a bounded search (substitute the verified index). It is tied to that host's local auth and is not a good fit for a remote workstation during a live window; prefer the REST poller for anything you want to re-run.

Whichever path you use, apply the same evidence hygiene as the [guard scripts](../scripts/linux_guard.py): operator-only directory, unique timestamped file names, bounded retention, review exported rows and errors for credentials or other sensitive material before sharing. Pruning deletes older files; copy evidence needed for submission to separate protected storage first.

## Reviewing and reporting after the window

- Open each `events_*.json` in time order. Each file is one poll cycle: `time_utc`, `index`, and a `queries` map of query id → new rows (or an `error`).
- Cross-reference every row back to the [indicator table](#indicator-table) and note which row(s) it matches. A row that matches no indicator is still worth keeping — it may be context for another.
- Record in the [event worksheet](event-checklist.md): which queries ran, their time ranges, what matched, what errored, and which field names you actually verified. "No hits" without a verified field name is not a finding either way.
- Do not publish packet-derived details or IOC specifics without competition authorization (see the [README](README.md)).

## Cross-references

- [Splunk threat hunting and monitoring](splunk-threat-hunting.md) — full matrix, collection prerequisites, bounded searches, missing-source checks.
- [Per-host Splunk data-source setup](splunk-data-sources.md) — receiver, forwarder inputs, appliance syslog, test events.
- [Event worksheet / change gate](event-checklist.md) — the gate any mid-inject collection change must go through.
- [Windows 11 workstation guide](systems/windows11-workstation.md) — host-specific detection and audit policy.
- [Splunk query access service](services/splunk-query.md) — the authorized read-only query path this playbook uses.
- [`scripts/splunk_poll.py`](../scripts/splunk_poll.py) and [`config/splunk-poll.example.json`](../config/splunk-poll.example.json) — the local evidence poller and its example config.

## References

- [Splunk REST API — search jobs](https://docs.splunk.com/Documentation/Splunk/latest/Developer/SplunkRESTAPI): job lifecycle (`services/search/jobs`) and CSV result export used by the poller.
- [Splunk search reference](https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.0): command syntax and version-specific limits.
- [Microsoft advanced audit policy](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-audit-policy-settings): subcategories required to generate the process-creation events the Windows watch relies on.
- [auditd / ausearch](https://man7.org/linux/man-pages/man8/ausearch.8.html): Linux process-creation event capture for the live view.

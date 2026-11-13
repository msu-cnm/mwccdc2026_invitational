# Add the ten hosts to Splunk

These are operator procedures for the existing Debian 12 / Splunk 10.0.2 environment. Run them only on assigned machines after recording the change in the [event worksheet](event-checklist.md). Preserve scoring inputs and accounts. Do not reinstall working services. Use competition-permitted Splunk components under the existing license; no trial features are needed. No commands here have been executed on event hosts.

`scripts/splunk_setup.py` generates the concrete per-host configuration files described below (universal-forwarder `outputs.conf`/`inputs.conf`, local UF `WinEventLog://` inputs for Windows, VyOS/PAN-OS syslog lines, or a Linux rsyslog relay). Select `plan` to preview; it writes nothing without `apply`. It does not install software, open ports, or change firewall/NAT rules. Example:

```bash
python3 scripts/splunk_setup.py rocky-ecom --receiver <splunk-ip> plan
python3 scripts/splunk_setup.py 2022-ad --receiver <splunk-ip> plan
python3 scripts/splunk_setup.py vyos --receiver <relay-ip> --port 1514 plan
```

Generate files in a staging directory, review them, then deploy using the platform procedures below. Use a new backup filename for each apply:

```bash
python3 scripts/splunk_setup.py rocky-ecom --receiver 172.20.240.20 apply --out ./generated-rocky --backup ./rocky-before.json
python3 scripts/splunk_setup.py rocky-ecom --receiver 172.20.240.20 rollback --out ./generated-rocky --backup ./rocky-before.json
python3 scripts/splunk_setup.py debian-splunk --receiver 172.20.240.20 --method syslog --port 5514 plan
```

Rollback restores generated files only; deployed copies, service restarts and appliance commits require the recovery steps below. The relay example listens on TCP 5514; configure both appliances and the approved firewall path for that same port. Default syslog port is 1514. For Debian Splunk's own logs, deploy only local `inputs.conf` into the existing Splunk instance; do not deploy the generated forwarding output back to itself or install a second forwarder. Default Linux paths require existing readable log files; use the journal recipe below if they are absent. Add discovered service logs with `--input PATH:SOURCE_TYPE`; this replaces the default input list, so include auth/system paths too.


## Values to record first

Record the actual Splunk hostname/IP, installation path, systemd unit, service owner, free disk space, approved retention, and source hostnames. `172.20.240.20` is the packet's internal Splunk address; workstation DHCP addresses and team-dependent addresses must be discovered using the [environment worksheet](environment.md). Replace all angle-bracket values before running commands. These recipes use a new `team_security` index to avoid changing scored data. Reuse an existing suitable index instead if collection already exists. Do not duplicate inputs.

On Debian Splunk, inspect locally:

```bash
hostname -f
ip -br address
sudo ss -lntup
ps -eo user,pid,args | grep '[s]plunkd'
systemctl list-unit-files | grep -i splunk
sudo /opt/splunk/bin/splunk btool inputs list --debug
sudo /opt/splunk/bin/splunk btool outputs list --debug
sudo /opt/splunk/bin/splunk btool indexes list --debug
df -h /opt/splunk
```

Use the discovered installation path throughout. Before editing any `.conf`, copy the containing app directory to root-only timestamped backup storage (`sudo install -d -m 0700 /root/collection-backups`). Preserve owner/mode. If an app is new, record that fact for rollback. Never edit `etc/system/default` or app `default` files.

## Receiver and index on Debian Splunk

In Splunk Web, Settings > Indexes > New Index: name `team_security`, type Events. Set retention and maximum size against measured disk capacity; record those settings. Settings > Access controls > Roles: give the analyst role search access to that index. Preserve the scorer's existing permissions. Settings > Forwarding and receiving > Configure receiving > New Receiving Port: `9997`, if not already enabled.

Port 9997 accepts Splunk forwarder traffic; it is not HEC or syslog. Allow only the assigned collection sources to this internal receiver through the host firewall and inter-zone path, preserving all existing scoring rules. Do not add public NAT for ingestion. This simple receiver is unencrypted: use it only on the approved isolated event network. If collection requires encryption, configure a TLS receiver and certificate-validating forwarder outputs per the installed Splunk version before sending real logs; do not merely point `tcpout` at an HTTPS port.

Verify locally with `sudo ss -lntp 'sport = :9997'`. On Windows use `Test-NetConnection <receiver> -Port 9997`; on Linux `nc -vz -w 5 <receiver> 9997` if netcat is installed. A connection proves reachability only.

## Linux forwarder: Rocky, Ubuntu Email, Ubuntu workstation and Kali

Use a compatible Universal Forwarder package downloaded from Splunk's official distribution channel, matching `uname -m` and the OS. Transfer it through an approved path and compare `sha256sum` with the vendor-published checksum. Do not invent a download URL or install the full Splunk server on each host.

```bash
# Debian/Ubuntu/Kali: use the actual downloaded filename
sudo dpkg -i /path/to/splunkforwarder-<version>-linux-amd64.deb
# Rocky: alternative, not an additional installation
sudo rpm -ivh /path/to/splunkforwarder-<version>-linux-x86_64.rpm
```

Use an existing forwarder's service owner if present. For a new installation, follow the package's supported service-account setup, then start interactively as that owner: `/opt/splunkforwarder/bin/splunk start --accept-license`. Set the local administrator credentials at the prompt; do not put them in shell history. Root may be needed to read protected logs. Prefer the least privileged supported account with explicit file/group access; do not make logs world-readable. Configure boot start using the installed forwarder's `enable boot-start --help` options and the chosen owner rather than assuming a unit name.

Create `/opt/splunkforwarder/etc/apps/team_collection/local/outputs.conf` (root or service-owner writable only):

```ini
[tcpout]
defaultGroup = team_indexer

[tcpout:team_indexer]
server = 172.20.240.20:9997
```

Create `inputs.conf` in the same directory. Add only existing readable files, with a separate stanza per discovered path:

```ini
[monitor:///var/log/auth.log]
disabled = 0
index = team_security
sourcetype = linux_auth

[monitor:///var/log/team-journal.log]
disabled = 0
index = team_security
sourcetype = linux_journal
```

Rocky normally uses `/var/log/secure` rather than `auth.log`; substitute it if present. Do not monitor both a journal export and equivalent rsyslog files unless intentionally accepting duplicates. Forwarders do not read binary journal files as text. For a journal-only machine, use an approved rsyslog journal input, or this bounded export as a temporary manual collection path:

```bash
# As root, once per explicit non-overlapping UTC window:
install -m 0600 /dev/null /var/log/team-journal.log
journalctl --utc --since '2026-11-13 10:00:00 UTC' --until '2026-11-13 10:05:00 UTC' \
  -o short-iso --no-pager >> /var/log/team-journal.log
```

The timestamps are examples: record the actual window and do not repeat it. Reuse the file without truncating for subsequent exports, with a documented rotation/retention policy. Grant the forwarder read access to this file only. Manual exports are not continuous monitoring; set an operator cadence or configure persistent supported journald-to-rsyslog collection before claiming real-time coverage.

Restart the discovered forwarder service, then run as its owner:

```bash
/opt/splunkforwarder/bin/splunk btool inputs list --debug
/opt/splunkforwarder/bin/splunk btool outputs list --debug
/opt/splunkforwarder/bin/splunk list forward-server
```

The last command may prompt for local Splunk credentials. Inspect `/opt/splunkforwarder/var/log/splunk/splunkd.log` for unreadable files, connection errors and blocked queues. Avoid forwarding whole mailboxes, browser profiles or application secrets.

## Windows forwarder: AD, MSSQL and Windows 11

Download the compatible x64 Universal Forwarder MSI through the official channel. Verify its checksum and `Get-AuthenticodeSignature -FilePath C:\Install\<package>.msi`; verify the expected publisher and valid chain. From elevated PowerShell, start `msiexec.exe /i C:\Install\<package>.msi` and use the interactive installer. Select the actual receiver and port 9997, preserve existing deployment-server settings, choose an appropriate service account and set local forwarder admin credentials interactively. Do not run a second collector if WEF already supplies the same events.

Under `C:\Program Files\SplunkUniversalForwarder\etc\apps\team_collection\local`, create `inputs.conf`:

```ini
[WinEventLog://Security]
disabled = 0
index = team_security
renderXml = true

[WinEventLog://System]
disabled = 0
index = team_security
renderXml = true

[WinEventLog://Application]
disabled = 0
index = team_security
renderXml = true
```

Add these stanzas only where the channel exists (`Get-WinEvent -ListLog '<channel>'`):

```ini
[WinEventLog://Directory Service]
disabled = 0
index = team_security
renderXml = true

[WinEventLog://Microsoft-Windows-PowerShell/Operational]
disabled = 0
index = team_security
renderXml = true

[WinEventLog://Microsoft-Windows-Windows Defender/Operational]
disabled = 0
index = team_security
renderXml = true
```

Directory Service applies to the DC only. PowerShell event 4104 requires separately enabled Script Block Logging; collecting a channel does not enable audit policy. Review privacy and volume before enabling it. On a DC, preserve domain GPO policy. `auditpol /get /category:*` shows existing auditing; the [hunting guide](splunk-threat-hunting.md) lists required subcategories. LocalSystem has broad log access; for a dedicated service identity grant Log on as a service and required channel permissions (Event Log Readers alone may not suffice for Security). Verify actual reads rather than relaxing all channel ACLs.

```powershell
Restart-Service SplunkForwarder
& 'C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe' btool inputs list --debug
& 'C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe' list forward-server
Get-Content 'C:\Program Files\SplunkUniversalForwarder\var\log\splunk\splunkd.log' -Tail 60
```

For MSSQL add a file monitor for the actual ERRORLOG discovered in SQL Server Configuration Manager > service startup parameter `-e`. Give the forwarder read access to that directory; use `index = team_security`, `sourcetype = sql_error`. SQL statement auditing requires a separate SQL Audit/Extended Events configuration; ERRORLOG alone cannot supply it.

## Appliance relay on Debian Splunk

Use rsyslog to persist messages to files, then Splunk local file inputs to read them. A dedicated approved relay is preferable if available; otherwise the following Debian recipe uses TCP 1514 on the existing Splunk host without a privileged Splunk listener. Check whether rsyslog and a TCP listener already exist before adding these files.

```bash
sudo apt-get update
sudo apt-get install rsyslog
sudo install -d -m 0750 /var/log/team-remote
```

Create `/etc/rsyslog.d/30-team-remote.conf`:

```conf
module(load="imtcp")
ruleset(name="team_remote") {
  if ($fromhost-ip == '172.20.240.200') then {
    action(type="omfile" file="/var/log/team-remote/palo-alto.log" fileCreateMode="0640")
    stop
  }
  if ($fromhost-ip == '172.16.0.254') then {
    action(type="omfile" file="/var/log/team-remote/vyos.log" fileCreateMode="0640")
    stop
  }
  stop
}
input(type="imtcp" port="1514" ruleset="team_remote")
```

Substitute the **observed source IPs** (service routes/NAT may change them). Load `imtcp` only once. Grant the discovered rsyslog writer directory access and the Splunk service account read/traverse access using a dedicated group or ACL; retain 0640 files, including after rotation. Do not run Splunk as root to fix this. Validate `sudo rsyslogd -N1`, restart `rsyslog`, inspect `journalctl -u rsyslog`, and confirm TCP 1514 listens. Allow only these appliances to this receiver. This example is plain TCP, not TLS. Use supported TLS on both ends when the collection network requires it.

In `/opt/splunk/etc/apps/team_collection/local/inputs.conf` add:

```ini
[monitor:///var/log/team-remote/palo-alto.log]
disabled = 0
index = team_security
sourcetype = pan_raw
host = palo-alto

[monitor:///var/log/team-remote/vyos.log]
disabled = 0
index = team_security
sourcetype = vyos_syslog
host = vyos
```

These explicit host values distinguish appliances from the relay. `pan_raw` is a raw label, not a PAN add-on parser. Restart the discovered Splunk unit in a coordinated window. For Debian's usual `root:adm` rsyslog file ownership, confirm it in `/etc/rsyslog.conf` and `/etc/rsyslog.d` before using the example below. Add the discovered Splunk service account to `adm` only if that group's access is approved (`sudo usermod -aG adm <splunk-owner>`); restart that service to acquire the group. Otherwise use a dedicated reader group/ACL rather than broadening access. Create `/etc/logrotate.d/team-remote`:

```conf
/var/log/team-remote/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
    sharedscripts
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate
    endscript
}
```

Verify that `/usr/lib/rsyslog/rsyslog-rotate` exists (use the installed distribution's rsyslog postrotate action if different). Substitute confirmed writer/group, set directory ownership/traverse permissions accordingly, and size the seven-day example against actual disk/volume. Validate with `sudo logrotate --debug /etc/logrotate.d/team-remote`; verify new files retain collector access.

### Palo Alto PAN-OS 11.0.2

Device > Server Profiles > Syslog: create `TEAM-SYSLOG`, server `172.20.240.20`, transport TCP, port 1514, BSD format. Device > Log Settings: add forwarding to that profile for System and Config logs (all relevant severities). Objects > Log Forwarding: create a profile with a Traffic match entry using filter `All Logs` and the syslog profile; add Threat entries only where supported. Policies > Security: attach that log-forwarding profile to the existing required rules and enable Log at Session End. Do not replace the rules or change their actions. Threat logs require actual threat profiles/features and generated events.

Operational CLI, then configuration CLI for the server profile only:

```text
show system info
show running security-policy
show running nat-policy
show session all filter destination 172.20.240.20 destination-port 1514
configure
set shared log-settings syslog TEAM-SYSLOG server splunk server 172.20.240.20
set shared log-settings syslog TEAM-SYSLOG server splunk transport TCP
set shared log-settings syslog TEAM-SYSLOG server splunk port 1514
set shared log-settings syslog TEAM-SYSLOG server splunk format BSD
show shared log-settings syslog TEAM-SYSLOG
validate full
```

Review the candidate diff and any other administrator's pending edits before `commit`; follow the [Palo Alto backup/recovery guide](systems/palo-alto.md). The server profile alone sends nothing: apply the GUI log settings and rule attachments above. Confirm management service-route reachability through Device > Setup > Services > Service Route Configuration; preserve existing routes. A CLI session filter uses `destination`, not `destination-ip`. Rule IP greps can miss address objects, so inspect full rules/object definitions when no match appears.

### VyOS 1.4

From console, inspect `show configuration commands | match syslog`, preserve existing destinations, then:

```text
configure
set system syslog host 172.20.240.20 facility all level info
set system syslog host 172.20.240.20 port 1514
set system syslog host 172.20.240.20 protocol tcp
compare
commit-confirm 5
```

After verifying receiver files and all required routes/scoring paths, issue `confirm`, then `save`. If verification fails, let the confirmation timer revert or restore the saved configuration from console. Verify the sender's actual source IP matches the relay filter; do not change routing just to fit the example. Syslog collection does not enable firewall/flow logging automatically.

## Complete host checklist

| Host | Apply recipe and extra inputs |
|---|---|
| rocky-ecom | Linux UF; secure/auth, discovered web access/error files, application logs |
| ubuntu-email | Linux UF; auth, actual mail daemon logs and webmail access/error logs; no mailbox contents |
| debian-splunk | Local file inputs in Splunk itself for auth/journal and relay; verify existing `_internal` / `_audit`, no second UF |
| 2022-ad | Windows UF; Security/System/Application, Directory Service |
| 2019-mssql | Windows UF plus discovered SQL ERRORLOG; audit/XE only if separately configured |
| ubuntu-workstation | Linux UF; auth/journal and existing `/var/log/apt/history.log` |
| windows11-workstation | Windows UF; Security/System/Application, existing Defender/PowerShell channels |
| kali | Linux UF; auth/journal and package history; authorized tool use is expected |
| palo-alto | Syslog profile, System/Config settings and Traffic log-forwarding attachments to relay |
| vyos | Native TCP syslog to relay; retain existing destinations |

## Verify collection and turn it into monitoring

For each source record one harmless test's UTC time. Linux: `logger -t team-collection 'collection-check unique-id'` then find it locally (`journalctl -t team-collection`) and in the collected auth/journal destination. A logger message does not necessarily go to auth.log; use the journal export path if necessary. Windows: `eventcreate /T INFORMATION /ID 100 /L APPLICATION /SO TeamCollection /D "collection-check unique-id"` from elevated PowerShell, then locate it locally in Application. For appliances compare an existing known Config/System/commit event, or a normal team login, with receiver file and search. Do not create fake attacks or failed-login storms.

In Splunk Search, select the appropriate app/role and run:

```spl
index=team_security earliest=-15m
| stats count latest(_time) AS last_seen values(source) AS sources values(sourcetype) AS types by host
```

Inspect the raw test event, original host, timestamp and ingestion delay. XML Windows events may use `XmlWinEventLog:*` sourcetypes; map EventID/EventCode explicitly before using detections. File labels do not extract web/mail/PAN fields. Use [field discovery and IOC searches](splunk-threat-hunting.md#field-discovery-and-raw-event-fallback), checking each prerequisite against actual data.

Create a CSV with header `topology_id,host,max_silence_seconds` and all ten host mappings from the table above, using **observed** host values and cadence-based thresholds. In Settings > Lookups > Lookup table files > New, upload it as `expected_hosts.csv` in the analyst app and grant the search role read access. Run `| inputlookup expected_hosts.csv` and confirm every row. Run the hunting guide's silence query with `index=team_security` and any other actual collection indexes; intentionally test a missing fixture host. Quiet machines require a documented periodic signal or generous thresholds.

For a first IOC alert use the privileged-account/group search from the hunting guide after verifying Windows XML extraction. Save As > Alert: scheduled cron `*/5 * * * *`, window `earliest=-17m latest=-2m`, trigger when results > 0, throttle by observed host/event identity for 15 minutes. Use Triggered Alerts for local operator review; configure external notifications only when authorized. Test using its sanitized fixture, then inspect Activity > Triggered Alerts and scheduler errors. Authentication sequence searches need their full correlation window. Check ingestion/silent-host alerts separately; no results with no incoming logs is unknown coverage.

## Rollback and failure isolation

If no event arrives, inspect in order: source event/channel, file permissions, forwarder effective inputs, active output, network reachability, receiver listener, index existence/role access, timestamp/time picker. Compare native logs to search results; do not widen firewall rules blindly.

To reverse this change, restore only the backed-up `team_collection` app files (remove that app if newly created), restart the affected collector in a coordinated window, and remove only new syslog destinations/profile attachments and receiver rules. Use VyOS confirmed commits and PAN-OS candidate validation. Keep existing inputs, scored indexes and stored evidence. Do not delete indexed data as rollback. Recheck scored functional services and record residual collection gaps.

References: [Splunk forwarder installation](https://help.splunk.com/en/splunk-enterprise/forward-and-process-data/universal-forwarder-manual), [Splunk inputs.conf](https://docs.splunk.com/Documentation/Splunk/latest/Admin/Inputsconf), [VyOS syslog](https://docs.vyos.io/en/1.4/configuration/system/syslog.html). Use installed-version help for platform differences. These links are references, not a claim of live validation.

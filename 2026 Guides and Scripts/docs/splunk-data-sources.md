# Add the ten hosts to Splunk

These are operator procedures for the existing Debian 12 / Splunk 10.0.2 environment. Run them only on assigned machines after recording the change in the [event worksheet](event-checklist.md). Preserve scoring inputs and accounts. Do not reinstall working services. Use competition-permitted Splunk components under the existing license; no trial features are needed. No commands here have been executed on event hosts.

## Splunk Universal Forward downloads

Windows
```bash
wget -O splunkforwarder-10.6.1.1-b2ae2962645c-windows-x64.msi "https://download.splunk.com/products/universalforwarder/releases/10.6.1.1/windows/splunkforwarder-10.6.1.1-b2ae2962645c-windows-x64.msi"
```
Linux
```bash
wget -O splunkforwarder-10.6.1.1-b2ae2962645c.x86_64.rpm "https://download.splunk.com/products/universalforwarder/releases/10.6.1.1/linux/splunkforwarder-10.6.1.1-b2ae2962645c.x86_64.rpm"
wget -O splunkforwarder-10.6.1.1-b2ae2962645c-linux-amd64.deb "https://download.splunk.com/products/universalforwarder/releases/10.6.1.1/linux/splunkforwarder-10.6.1.1-b2ae2962645c-linux-amd64.deb"
wget -O splunkforwarder-10.6.1.1-b2ae2962645c-linux-amd64.tgz "https://download.splunk.com/products/universalforwarder/releases/10.6.1.1/linux/splunkforwarder-10.6.1.1-b2ae2962645c-linux-amd64.tgz"
```

## How this guide works

Every host is configured in the same three-step loop:

1. **Generate** the config files for that host with `scripts/splunk_setup.py` (universal-forwarder `outputs.conf`/`inputs.conf`, local UF `WinEventLog://` inputs for Windows, VyOS/PAN-OS syslog lines, or a Linux rsyslog relay).
2. **Deploy** them on the host using the numbered procedure for that platform below (Linux: systemd; Windows: elevated PowerShell; appliances: device CLI).
3. **Verify end-to-end**: confirm the collector is connected and sending, then run the test-event check in [Verify collection](#verify-collection-and-turn-it-into-monitoring) and see the event land in Splunk Search.

`plan` only previews and writes nothing; `apply` writes files to your staging directory. The script never installs software, opens ports, or changes firewall/NAT rules — those steps are in the procedures below. Work through the sections in order; each one ends with a check you can see pass before you move on:

| Host | Procedure section |
|---|---|
| rocky-ecom, ubuntu-email, ubuntu-workstation, kali | [Linux forwarder](#linux-forwarder-rocky-ubuntu-email-ubuntu-workstation-and-kali) |
| 2022-ad, 2019-mssql, windows11-workstation | [Windows forwarder](#windows-forwarder-ad-mssql-and-windows-11) |
| palo-alto, vyos (sending side) | [Appliance relay — Step 4](#step-4--point-the-appliances-at-the-relay) |
| debian-splunk (receiving side) | [Receiver and index](#receiver-and-index-on-debian-splunk), [Appliance relay](#appliance-relay-on-debian-splunk) |

Example:

```bash
python3 scripts/splunk_setup.py rocky-ecom --receiver <splunk-ip> plan
python3 scripts/splunk_setup.py 2022-ad --receiver <splunk-ip> plan
python3 scripts/splunk_setup.py vyos --receiver <relay-ip> --port 1514 plan
```

Generate files in a staging directory, review them, then deploy using the platform procedures below. Use a new backup filename for each apply:

```bash
python3 scripts/splunk_setup.py rocky-ecom --receiver 172.20.240.20 apply --out ./generated-rocky --backup ./rocky-before.json
python3 scripts/splunk_setup.py rocky-ecom --receiver 172.20.240.20 rollback --out ./generated-rocky --backup ./rocky-before.json
python3 scripts/splunk_setup.py debian-splunk --receiver 172.20.240.20 --method syslog plan
```

Rollback restores generated files only; deployed copies, service restarts and appliance commits require the recovery steps below. The relay examples use TCP 1514 (the default `--port` for the syslog method); configure both appliances and the approved firewall path for that same port. For Debian Splunk's own logs, deploy only local `inputs.conf` into the existing Splunk instance; do not deploy the generated forwarding output back to itself or install a second forwarder. Default Linux paths require existing readable log files; use the journal recipe below if they are absent. Add discovered service logs with `--input PATH:SOURCE_TYPE`; this replaces the default input list, so include auth/system paths too.


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

Configure each of these hosts the same way. Substitute `<splunk-ip>` with the receiver IP you recorded in [Values to record first](#values-to-record-first).

### Step 1 — Install the Universal Forwarder (once per host)

First inspect `systemctl list-unit-files --type=service | grep -i splunk` and `ps -eo user,pid,args | grep '[s]plunkd'`. If a forwarder is already installed, preserve its installation path and service owner and go to **Discover and start the unit** below, before Step 2. An inactive unit is still an existing installation; do not reinstall it. For a new installation:

1. Download a compatible Universal Forwarder package from Splunk's official distribution channel, matching `uname -m` and the OS. Transfer it through an approved path and compare `sha256sum` with the vendor-published checksum. Do not invent a download URL or install the full Splunk server on each host.
2. Install it:

```bash
# Debian/Ubuntu/Kali: use the actual downloaded filename
sudo dpkg -i /path/to/splunkforwarder-<version>-linux-amd64.deb
# Rocky: alternative, not an additional installation
sudo rpm -ivh /path/to/splunkforwarder-<version>-linux-x86_64.rpm
```

3. Start it interactively as the service owner (use an existing forwarder's service owner if present; for a new installation follow the package's supported service-account setup):

```bash
sudo -u <splunk-owner> /opt/splunkforwarder/bin/splunk start --accept-license
```

   Set the local administrator credentials at the prompt; do not put them in shell history. Root may be needed to read protected logs. Prefer the least privileged supported account with explicit file/group access; do not make logs world-readable.

4. **Enable systemd boot start for a new installation, using the chosen owner.** Replace `<splunk-owner>` with the account used in step 3 and use the actual installation path. Check the installed version's `splunk help enable boot-start` for supported options. On versions supporting systemd management, run:

   ```bash
   # Stop the interactively started instance before handing it to systemd:
   sudo -u <splunk-owner> /opt/splunkforwarder/bin/splunk stop
   sudo /opt/splunkforwarder/bin/splunk enable boot-start -systemd-managed 1 -user <splunk-owner>
   sudo systemctl daemon-reload
   ```

   The command must report successful creation of a systemd service for that owner. If the installed version rejects these options, stop here and follow that version's documented systemd boot-start procedure; do not fall back to an init script or repeatedly run the same failing command. For an existing installation without a systemd unit, use this procedure with its existing owner after checking its version's help and stopping its interactive instance.

#### Discover and start the unit (all Linux installations)

Run this on **every host**, including existing installations, in the same shell you will use for Step 3:

```bash
systemctl list-unit-files --type=service | grep -i splunk
# Set this to the exact forwarder unit from that output (case-sensitive).
# SplunkForwarder.service is an example; custom names are possible.
UNIT='<discovered-forwarder-unit.service>'
systemctl cat "$UNIT"
systemctl show "$UNIT" -p User -p ExecStart
```

Confirm that `ExecStart` points to this forwarder's installation and `User` matches the chosen service owner (an empty `User` means root). Do not select the full Splunk server's unit. If no matching unit exists, complete the boot-start procedure above and repeat discovery. If multiple units exist, inspect each candidate with `systemctl cat` and choose the one for this installation. Resolve a wrong owner or path using the installed version's supported boot-start procedure before proceeding.

Once verified, start the discovered unit and check it:

```bash
sudo systemctl start "$UNIT"
systemctl status "$UNIT" --no-pager
```

**Expected:** **active (running)**. If startup fails, inspect `sudo journalctl -u "$UNIT" -n 60 --no-pager` and correct the reported problem before deploying configuration. If you open a new shell later, repeat discovery and set `UNIT` again.

### Step 2 — Generate and deploy the config files

1. On your workstation, generate the files:

```bash
python3 scripts/splunk_setup.py rocky-ecom --receiver <splunk-ip> apply \
  --out ./generated-rocky --backup ./rocky-before.json
```

   (Use the host's own id: `ubuntu-email`, `ubuntu-workstation`, `kali`. Add `--input PATH:SOURCE_TYPE` for extra service logs — this replaces the default list, so include auth/system paths too.) Note: the generated `inputs.conf` uses the OS's default log paths (`/var/log/auth.log` + `/var/log/syslog` on Ubuntu/Kali, `/var/log/secure` + `/var/log/messages` on Rocky) — verify each file exists on the host before deploying.

2. Review `./generated-rocky/outputs.conf` and `inputs.conf`, then copy them to the host through an approved path and deploy:

```bash
# On the host — replace /path/to/generated with where you copied the files
sudo mkdir -p /opt/splunkforwarder/etc/apps/team_collection/local
sudo cp /path/to/generated/outputs.conf /path/to/generated/inputs.conf \
  /opt/splunkforwarder/etc/apps/team_collection/local/
# Keep the app directory writable only by root or the service owner:
sudo chown -R <splunk-owner>: /opt/splunkforwarder/etc/apps/team_collection
```

   If the host has no `auth.log` (Rocky uses `/var/log/secure` instead), verify the generated stanzas point at files that actually exist there — `ls -l /var/log/secure /var/log/auth.log 2>/dev/null`. Add only existing readable files, with a separate stanza per discovered path. A minimal `inputs.conf` looks like:

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

### Step 3 — Restart and verify the forwarder is connected

1. Restart the service using the exact unit verified in Step 1. In a new shell, repeat **Discover and start the unit** first:

```bash
# Refuse to run if UNIT has not been set in this shell:
sudo systemctl restart "${UNIT:?Set UNIT using Step 1 discovery first}"
systemctl status "$UNIT" --no-pager
```

2. Check the inputs, outputs and receiver as the service owner:

```bash
/opt/splunkforwarder/bin/splunk btool inputs list --debug
/opt/splunkforwarder/bin/splunk btool outputs list --debug
/opt/splunkforwarder/bin/splunk list forward-server
```

   **Expected:** `inputs list` shows every `[monitor://...]` stanza from step 2; `outputs list` shows `server = <splunk-ip>:9997`; `list forward-server` prints `<splunk-ip>:9997`. The last command may prompt for local Splunk credentials.

3. Watch the log for connection errors:

```bash
sudo tail -n 60 /opt/splunkforwarder/var/log/splunk/splunkd.log
```

   **Expected:** no `Connection refused`, no "unreadable file" warnings for your monitored paths. If a monitored file is unreadable, fix the file's group/ACL for the forwarder owner — do not make logs world-readable.

4. Check the receiver accepted the connection (on the Splunk host or from this host):

```bash
# On the Splunk host:
sudo ss -lntp 'sport = :9997'
# From this host, once:
nc -vz -w 5 <splunk-ip> 9997     # if netcat is installed; a connection proves reachability only
```

5. Run the end-to-end test in [Verify collection](#verify-collection-and-turn-it-into-monitoring). If your test event appears in Splunk Search, this host is done.

### Optional — journal-only hosts

Do not monitor both a journal export and equivalent rsyslog files unless intentionally accepting duplicates. Forwarders do not read binary journal files as text. For a journal-only machine, use an approved rsyslog journal input, or this bounded export as a temporary manual collection path:

```bash
# As root, once per explicit non-overlapping UTC window:
install -m 0600 /dev/null /var/log/team-journal.log
journalctl --utc --since '2026-11-13 10:00:00 UTC' --until '2026-11-13 10:05:00 UTC' \
  -o short-iso --no-pager >> /var/log/team-journal.log
```

The timestamps are examples: record the actual window and do not repeat it. Reuse the file without truncating for subsequent exports, with a documented rotation/retention policy. Grant the forwarder read access to this file only (a `[monitor:///var/log/team-journal.log]` stanza in step 2). Manual exports are not continuous monitoring; set an operator cadence or configure persistent supported journald-to-rsyslog collection before claiming real-time coverage.

Avoid forwarding whole mailboxes, browser profiles or application secrets.

## Windows forwarder: AD, MSSQL and Windows 11

Configure each of these hosts the same way. Substitute `<splunk-ip>` with the receiver IP you recorded in [Values to record first](#values-to-record-first).

### Step 1 — Install the Universal Forwarder (once per host)

If `Get-Service SplunkForwarder` already shows a running forwarder, skip to step 2. Otherwise:

1. Download the compatible x64 Universal Forwarder MSI through the official channel. Verify its checksum and signature:

```powershell
# In PowerShell on the target host:
Get-AuthenticodeSignature -FilePath C:\Install\<package>.msi
```

   **Expected:** `Status : Valid`, with the expected publisher. Do not proceed with an invalid or unknown chain.

2. From elevated PowerShell, run the interactive installer:

```powershell
msiexec.exe /i C:\Install\<package>.msi
```

   In the installer: select the actual receiver `<splunk-ip>` and port **9997**, preserve existing deployment-server settings, choose an appropriate service account, and set local forwarder admin credentials interactively. Do not run a second collector if WEF already supplies the same events.

3. Check: `Get-Service SplunkForwarder` should show **Running**.

### Step 2 — Generate and deploy inputs.conf

1. On your workstation, generate the file:

```bash
python3 scripts/splunk_setup.py 2022-ad --receiver <splunk-ip> apply \
  --out ./generated-2022ad --backup ./2022ad-before.json
```

   (Use the host's own id: `2019-mssql`, `windows11-workstation`. The script already includes only channels that exist on each host, but confirm with `Get-WinEvent -ListLog '<channel>'` before deploying.)

2. Copy the generated files to the host through an approved path and deploy them:

```powershell
# In PowerShell on the target host:
$dir = 'C:\Program Files\SplunkUniversalForwarder\etc\apps\team_collection\local'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
Copy-Item C:\Temp\outputs.conf, C:\Temp\inputs.conf -Destination $dir -Force
```

   `outputs.conf` sets the receiver to `<splunk-ip>:9997`; if you already selected the same receiver in the installer you may skip it. A minimal `inputs.conf` looks like:

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

### Step 3 — Restart and verify the forwarder is connected

1. Restart the service:

```powershell
Restart-Service SplunkForwarder
```

2. Check the inputs and receiver:

```powershell
& 'C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe' btool inputs list --debug
& 'C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe' list forward-server
```

   **Expected:** `inputs list` shows every `[WinEventLog://...]` stanza from step 2; `list forward-server` prints `<splunk-ip>:9997`. It may prompt for local Splunk credentials.

3. Watch the log for connection errors and unreadable channels:

```powershell
Get-Content 'C:\Program Files\SplunkUniversalForwarder\var\log\splunk\splunkd.log' -Tail 60
```

   **Expected:** no `Connection refused`, no "Access denied" for your event channels. If a channel is denied, fix its ACL for the forwarder's service account — do not relax all channel ACLs.

4. Run the end-to-end test in [Verify collection](#verify-collection-and-turn-it-into-monitoring). If your test event appears in Splunk Search, this host is done.

For MSSQL additionally add a file monitor for the actual ERRORLOG discovered in SQL Server Configuration Manager > service startup parameter `-e`. Give the forwarder read access to that directory; use `index = team_security`, `sourcetype = sql_error`. SQL statement auditing requires a separate SQL Audit/Extended Events configuration; ERRORLOG alone cannot supply it.

## Appliance relay on Debian Splunk

Use rsyslog to persist messages to files, then Splunk local file inputs to read them. A dedicated approved relay is preferable if available; otherwise the following Debian recipe uses TCP 1514 on the existing Splunk host without a privileged Splunk listener. Do this **on the Splunk host** unless told otherwise.

### Step 1 — rsyslog TCP receiver (on the Splunk host)

1. Install rsyslog if absent and create the log directory:

```bash
sudo apt-get update
sudo apt-get install rsyslog
sudo install -d -m 0750 /var/log/team-remote
```

2. Create `/etc/rsyslog.d/30-team-remote.conf`:

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

   Substitute the **observed source IPs** (service routes/NAT may change them — see step 4 for how to find them). Load `imtcp` only once.

3. Validate and restart:

```bash
sudo rsyslogd -N1          # expected: "rsyslogd: version ..., config file /etc/rsyslog.conf: 0 errors"
sudo systemctl restart rsyslog
journalctl -u rsyslog --since '2 min ago' --no-pager   # expected: no error lines
sudo ss -lntup 'sport = :1514'                          # expected: one LISTEN line for rsyslogd
```

   Allow only these appliances to this receiver. This example is plain TCP, not TLS. Use supported TLS on both ends when the collection network requires it.

### Step 2 — Splunk local inputs (on the Splunk host)

1. In `/opt/splunk/etc/apps/team_collection/local/inputs.conf` add:

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

   These explicit `host` values distinguish appliances from the relay. `pan_raw` is a raw label, not a PAN add-on parser.

2. Grant the Splunk service account read/traverse access to `/var/log/team-remote` using a dedicated group or ACL; retain 0640 files, including after rotation. Do not run Splunk as root to fix this. For Debian's usual `root:adm` rsyslog file ownership, confirm it in `/etc/rsyslog.conf` and `/etc/rsyslog.d` before using the example below. Add the discovered Splunk service account to `adm` only if that group's access is approved (`sudo usermod -aG adm <splunk-owner>`); restart that service to acquire the group. Otherwise use a dedicated reader group/ACL rather than broadening access.

3. Restart the discovered Splunk unit in a coordinated window, then confirm the inputs:

```bash
/opt/splunk/bin/splunk btool inputs list --debug   # expected: both [monitor:///var/log/team-remote/...] stanzas
```

### Step 3 — Logrotate (on the Splunk host)

Create `/etc/logrotate.d/team-remote`:

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

### Step 4 — Point the appliances at the relay

**Palo Alto PAN-OS 11.0.2** (GUI, then CLI):

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

**VyOS 1.4** (console):

Inspect first, preserve existing destinations, then:

```text
show configuration commands | match syslog
configure
set system syslog remote 172.20.240.20 facility all level info
set system syslog remote 172.20.240.20 port 1514
set system syslog remote 172.20.240.20 protocol tcp
compare
commit-confirm 5
```

After verifying receiver files and all required routes/scoring paths, issue `confirm`, then `save`. If verification fails, let the confirmation timer revert or restore the saved configuration from console. Verify the sender's actual source IP matches the relay filter; do not change routing just to fit the example. Syslog collection does not enable firewall/flow logging automatically.

### Step 5 — End-to-end check

Generate an event on each appliance (a config change on VyOS, a policy test or session on Palo Alto), then on the Splunk host:

```bash
tail -n 5 /var/log/team-remote/palo-alto.log /var/log/team-remote/vyos.log
```

**Expected:** new lines appear for both appliances. Then run the [Verify collection](#verify-collection-and-turn-it-into-monitoring) search — appliance events should appear with `host = palo-alto` / `host = vyos`.

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

### Step 1 — Generate a harmless test event on the host

Record one harmless test's UTC time for each source:

- **Linux:** `logger -t team-collection 'collection-check unique-id'` — then find it locally with `journalctl -t team-collection` and in the collected auth/journal destination. A logger message does not necessarily go to auth.log; use the journal export path if necessary.
- **Windows** (elevated PowerShell): `eventcreate /T INFORMATION /ID 100 /L APPLICATION /SO TeamCollection /D "collection-check unique-id"` — then locate it locally in the Application log.
- **Appliances:** compare an existing known Config/System/commit event, or a normal team login, with the receiver file and search.

Do not create fake attacks or failed-login storms.

### Step 2 — Confirm it landed in Splunk Search

In Splunk Search, select the appropriate app/role and run:

```spl
index=team_security earliest=-15m
| stats count latest(_time) AS last_seen values(source) AS sources values(sourcetype) AS types by host
```

**Expected:** a row for each host you configured, with a recent `last_seen`. Then open the raw test event and inspect original host, timestamp and ingestion delay. XML Windows events may use `XmlWinEventLog:*` sourcetypes; map EventID/EventCode explicitly before using detections. File labels do not extract web/mail/PAN fields. Use [field discovery and IOC searches](splunk-threat-hunting.md#field-discovery-and-raw-event-fallback), checking each prerequisite against actual data.

### Step 3 — Silence detection (optional, recommended)

Create a CSV with header `topology_id,host,max_silence_seconds` and all ten host mappings from the table above, using **observed** host values and cadence-based thresholds. In Settings > Lookups > Lookup table files > New, upload it as `expected_hosts.csv` in the analyst app and grant the search role read access. Run `| inputlookup expected_hosts.csv` and confirm every row. Run the hunting guide's silence query with `index=team_security` and any other actual collection indexes; intentionally test a missing fixture host. Quiet machines require a documented periodic signal or generous thresholds.

### Step 4 — First IOC alert (optional)

For a first IOC alert use the privileged-account/group search from the hunting guide after verifying Windows XML extraction. Save As > Alert: scheduled cron `*/5 * * * *`, window `earliest=-17m latest=-2m`, trigger when results > 0, throttle by observed host/event identity for 15 minutes. Use Triggered Alerts for local operator review; configure external notifications only when authorized. Test using its sanitized fixture, then inspect Activity > Triggered Alerts and scheduler errors. Authentication sequence searches need their full correlation window. Check ingestion/silent-host alerts separately; no results with no incoming logs is unknown coverage.

## Rollback and failure isolation

If no event arrives, inspect in order: source event/channel, file permissions, forwarder effective inputs, active output, network reachability, receiver listener, index existence/role access, timestamp/time picker. Compare native logs to search results; do not widen firewall rules blindly.

To reverse this change, restore only the backed-up `team_collection` app files (remove that app if newly created), restart the affected collector in a coordinated window, and remove only new syslog destinations/profile attachments and receiver rules. Use VyOS confirmed commits and PAN-OS candidate validation. Keep existing inputs, scored indexes and stored evidence. Do not delete indexed data as rollback. Recheck scored functional services and record residual collection gaps.

References: [Splunk forwarder installation](https://help.splunk.com/en/splunk-enterprise/forward-and-process-data/universal-forwarder-manual), [Splunk inputs.conf](https://docs.splunk.com/Documentation/Splunk/latest/Admin/Inputsconf), [VyOS syslog](https://docs.vyos.io/en/1.4/configuration/system/syslog.html). Use installed-version help for platform differences. These links are references, not a claim of live validation.

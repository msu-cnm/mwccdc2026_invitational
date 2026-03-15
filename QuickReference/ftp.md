# FTP Server

## Baseline
- Windows Server 2022
- Joined to **CCDCTeam.com** domain
- FTP site "FTP-CCDC" running in IIS
- Windows Firewall:
  - Public: On
  - Domain/Private: Off
- SMTP role installed but not running
- No service-level hardening applied

### What to change
- Restrict authentication to local FTP-only users
- Remove unnecessary inbound firewall rules once scoring confirmed
- Reduce outbound connectivity to prevent lateral movement
- Disable unused Windows services and roles
- Lock filesystem permissions to FTP root only
- Maintain ICMP and FTP availability for scoring

#### FTP hardening

Run `lusrmgr.msc`

- Create local FTP users
- Create FTP users group
- Add FTP users to FTP group

Run `secpol.msc`

- Deny logon locally → Domain Admins (includes)
- Deny logon through RDP → Domain Admins (includes)

**Also allow auditing**

Local Security Policy → Advanced Audit Policy Configuration
Audit success and failure
- Audit Logon
- Audit Logoff
- Audit Account Logon
- Audit Object Access
- Audit Privilege use



**IIS Manager path:**  
`FILESERVER → Sites → FTP-CCDC`

- FTP Authentication: Disable Anonymous
- FTP Authorization Rules:
  - Add created FTP users
  - Keep AD users for possible scoring
  - Add Admin TEMPORARILY for splunkforwarder

#### Domain Privilege Reduction
Avoid using domain admin

Steps should include removing domain admins and creating a local admin for management.

```ps
net localgroup Administrators

# Remove present domain admins

net localgroup Administrators "Domain Admins" /delete

# Create local admin
net user localadmin <password> /add
net localgroup Administrators localadmin /add
```

Once created, sign out of domain admin, and log back in with the localadmin.
`.\localadmin`
---

### Firewall Rules

**INBOUND – ALLOW**

- FTP Server: TCP 21
- FTP Server Passive: IIS-defined
- ICMP: Echo, destination unreachable, fragmentation needed, etc.

**INBOUND – BLOCK**

- Implicit deny

---

**OUTBOUND – ALLOW**

- DNS (scoped to 172.20.240.102)
- FTP responses
- ICMP
- HTTPS (Windows updates, CRL, certs)
- Kerberos (scoped to 172.20.240.102)
- LDAP (scoped to 172.20.240.102)
- LDAPs (scoped to 172.20.240.102)

**OUTBOUND – BLOCK**

- SMB
- RPC
- WinRM
- RDP
- WMI (partially mitigated through TCP 135 block)

**Create block rules**

- Rule Type: Port
- Protocol: TCP (Add UDP for SMB 445 as a separate rule)
- Ports: 445 (SMB), 135 (RPC EPM), 5985–5986 (WinRM), 3389 (RDP)
- Action: Block
- Profile: Public
- Name: Variable on rule

**Scoped DNS block**

- Rule Type: Port
- Protocol: UDP
- Port: 53
- Action: Block
- Profile: Public
- Name: UDP DNS Default Block

**Scoped DNS allow**

- Rule Type: Port
- Protocol: UDP
- Port: 53
- Action: Allow
- Profile: Public
- Name: UDP DNS: DNS Server Only
- Scope: Remote IP Addresses → 172.20.240.102

#### Firewall Logging
Path:
Windows Defender Firewall → Advanced Settings → Properties

Enable:

Log dropped packets
Log successful connections

log location:
`C:\Windows\System32\LogFiles\Firewall\pfirewall.log`
---

### Logging

**Path:** IIS Manager → FILESERVER → Sites → FTP-CCDC → FTP Logging

**W3C Fields (select):**

- Date
- Time
- Client IP Address
- User Name
- Server IP Address
- Method
- URI Stem
- Protocol Status
- Protocol Substatus
- Win32 Status
- Bytes Sent
- Bytes Received

**Log file rollover:** Hourly

#### FTP Command Logging
Enable full FTP command logging.

Path:
IIS Manager → FTP-CCDC → FTP Logging → Log FTP Commands

Detects file uploads (STOR), downloads (RETR), directory enumeration (LIST), and brute force authentication attempts.

---

#### Splunk

Forwarder found at:
```
https://download.splunk.com/products/universalforwarder/releases/10.2.0/windows/
```

Move file to `C:\FTPSITE\` TEMPORARILY  
(Allow time for other servers to pull via FTP)

From elevated PowerShell:
```ps
msiexec /i C:\FTPSITE\splunkforwarder-10.2.0-d749cb17ea65-windows-x64.msi AGREETOLICENSE=Yes /quiet
Set-Service splunkforwarder -StartupType Automatic
Start-Service splunkforwarder
```

Configure outputs:
```ps
notepad C:\Program Files\SplunkUniversalForwarder\etc\system\local\outputs.conf
```

```ini
[tcpout]
defaultGroup = splunk_receivers

[tcpout:splunk_receivers]
server = 172.25.27.9:9997
```

Reinitialize and confirm:
```ps
Restart-Service splunkforwarder
Get-Service splunkforwarder
Get-Content "C:\Program Files\SplunkUniversalForwarder\var\log\splunk\splunkd.log" -Tail 50
```

Configure inputs:
```ps
notepad C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf
```

```ini
[monitor://C:\inetpub\logs\LogFiles]
disabled = false
recursive = true
sourcetype = iis:ftp
index = windows

[WinEventLog://Security]
disabled = 0
index = windows

[WinEventLog://System]
disabled = 0
index = windows

[WinEventLog://Application]
disabled = 0
index = windows
```

```ps
Restart-Service splunkforwarder
Get-Service splunkforwarder
```

After servers have pulled the Splunk forwarder MSI:
```ps
Remove-Item C:\FTPSITE\splunkforwarder-10.2.0-d749cb17ea65-windows-x64.msi
```

Remove Admin group from FTP authorization rules.

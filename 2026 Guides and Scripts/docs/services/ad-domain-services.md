# AD Domain Services Guide — 2022 AD (Kerberos / LDAP / SMB)

Candidate service (packet role: "AD; DNS and domain authentication dependencies require discovery"). The scoring check depends on domain authentication for email/webmail retrieval. Packet p.14 leaves precise scored services to the event portal. Windows Server 2022 Standard, 172.20.240.100.

## Discovery

> **Status:** candidate service — the packet lists this as a possible scored service but does not confirm it on any specific host. Verify on the live system before relying on any step below.

Confirm AD DS is installed, the domain is functional, and discover the domain name and key services:

```powershell
# AD DS service status
Get-Service KDC, Netlogon, LanmanWorkstation | Select-Object Name, Status, StartType
# Domain name
(Get-ADDomain).Name
(Get-ADDomain).DNSRoot
# Domain controllers
Get-ADDomainController -Filter * | Select-Object Name, Site, Domain
# Kerberos (port 88)
netstat -an | findstr ":88"
# LDAP / LDAPS
netstat -an | findstr ":389\|:636"
# Global Catalog
netstat -an | findstr ":3268\|:3269"
# SMB / RPC
netstat -an | findstr ":135\|:445"
# NTP (if relevant)
w32tm /query /status
```

From a Linux client:

```bash
# Kerberos
kinit <user>@<DOMAIN>  # expect prompt for password
klist  # verify ticket
# LDAP
ldapsearch -x -H ldap://172.20.240.100 -b "DC=<domain>,DC=<tld>" -s base "(objectClass=*)" 2>/dev/null | head -20
```

## Setup

AD DS is pre-installed on Windows Server 2022. Do not re-install or demote the domain controller. If a service is stopped:

```powershell
# Restart critical AD services (in order)
Start-Service KDC        # Kerberos
Start-Service Netlogon   # Domain membership
Start-Service DNS        # DNS server (if on this host)
Start-Service LanmanWorkstation
```

## Configuration

### Kerberos (TCP/UDP 88)

- Service: `KDC` (Key Distribution Center).
- Verify the KDC is reachable: `klist get ldap/<dc-fqdn>` from a client.
- Clock skew: ensure NTP is configured and accurate. Kerberos requires ≤5 min skew.
  ```powershell
  w32tm /query /status
  # Preserve the domain time hierarchy; do not set every DC as a reliable manual source.
  ```

### LDAP (TCP 389) and LDAPS (TCP 636)

- Verify `NTDS` service is running.
- Check for StartTLS vs LDAPS: `Get-ADDomainController -Identity <dc> | Select-Object LDAPPort, GlobalCatalogPort`
- If LDAPS is required, a valid certificate must be bound to the DC.

### Global Catalog (TCP 3268/3269)

- Verify: `Get-ADDomainController -Identity <dc> | Select-Object IsGlobalCatalog`
- If not GC, and scoring requires cross-domain queries, this is a gap.

### SMB / RPC (TCP 135, 445 + dynamic)

- Verify: `Get-Service LanmanServer | Select-Object Status`
- RPC endpoint mapper (135) + dynamic range for DCOM. Do not restrict the dynamic range without confirming what depends on it.
- Check Windows Firewall for these ports.

### NTP (UDP 123)

- Verify: `w32tm /query /source`
- AD relies on accurate time for Kerberos, replication, and logging.

### Firewall

Ensure all required ports are open on the relevant interfaces:

```powershell
# Check existing rules
netsh advfirewall firewall show rule name=all | findstr "88\|389\|636\|135\|445\|3268\|3269\|123"
# Add missing rules (only if confirmed needed)
netsh advfirewall firewall add rule name="Kerberos" dir=in action=allow protocol=TCP localport=88
netsh advfirewall firewall add rule name="LDAP" dir=in action=allow protocol=TCP localport=389
# ... etc.
```

Preserve existing rules. Do not create scoring-only allowlists.

### Palo Alto / VyOS

Verify NAT and routing allow AD traffic from workstations, email server, and Kali. Check for any ACL blocking Kerberos/LDAP on the internal or public path.

PAN-OS CLI options (discovery only):

```
show running security-policy | match 172.20.240.100
show session all filter destination 172.20.240.100 destination-port 389
show session all filter destination 172.20.240.100 destination-port 88
show interface ethernet1/2
show zone
```

GUI equivalent: Policies > Security, Monitor > Traffic, Network > Interfaces.

## Monitoring

```powershell
# Service health
Get-Service KDC, Netlogon, DNS, LanmanWorkstation | Select-Object Name, Status
# Event log (Directory Service)
Get-WinEvent -FilterHashtable @{LogName='Directory Service'; Level=2} -MaxEvents 20
Get-EventLog System -Newest 20 -Source "Kerberos"
# Replication health (if multiple DCs)
repadmin /replsummary
# Performance
Get-Counter '\Kerberos-Server\Ticket Requests/sec' -SampleInterval 5 -MaxSamples 3
```

Forward AD event logs to Splunk if the packet requires. Verify at Quotient that domain authentication works for the scored email/webmail check.

## Backup

Back up AD configuration before any change:

```powershell
# System State backup (includes AD, SYSVOL, registry)
# Requires Windows Server Backup and a separate approved E: backup volume.
# Check Get-Volume and wbadmin get versions -backupTarget:E: afterward.
# Do not substitute a directory on the source/system volume.
wbadmin start systemstatebackup -backuptarget:E: -quiet

# Alternative: export key config
$dc = Get-ADDomainController -Identity $env:COMPUTERNAME
$dc | Export-Csv "C:\backup\ad-dc-config-$(Get-Date -Format 'yyyyMMddHHmmss').csv" -NoTypeInformation

# SYSVOL (if accessible)
xcopy "C:\Windows\SYSVOL" "C:\backup\sysvol-$(Get-Date -Format 'yyyyMMddHHmmss')\" /E /I /H
```

No VM snapshots. Configuration exports and SYSVOL copies are inventories, not restorable AD backups. If no supported System State target exists, record that recovery gap and obtain an approved backup destination before claiming recoverability.

## Usage and scoring verification

Verify domain authentication end-to-end:

```powershell
# Kerberos ticket
klist get ldap/<dc-fqdn>  # from a client
# LDAP bind
ldapsearch -x -H ldap://172.20.240.100 -D "<user>@<domain>" -W -b "DC=<domain>,DC=<tld>" "(sAMAccountName=<user>)" 2>/dev/null

# From Linux (Kali or Ubuntu Email)
kinit <user>@<DOMAIN>
klist
# Then verify email/webmail auth uses this domain
```

Test from both internal and public paths. Confirm Quotient shows successful domain authentication.

## Recovery

1. Identify which service is down: `Get-Service KDC, Netlogon, DNS`
2. Restart in dependency order: DNS → KDC → Netlogon
3. If replication issue: `repadmin /syncall /AdeP`
4. If SYSVOL corrupted: `net share` to verify, then restore from backup
5. Verify with `kinit` and `ldapsearch` from a client
6. Record UTC time and residual exposure

## References

- [2022 AD system guide](../systems/2022-ad.md)
- [Environment constraints](../environment.md)
- [Event checklist](../event-checklist.md)

# DNS Service Guide — 2022 AD

Candidate service (packet role: "AD; DNS and domain authentication dependencies require discovery"). The scoring check requires expected records and response correctness on UDP AND TCP 53. Packet p.14 leaves precise scored services to the event portal.

## Discovery

> **Status:** candidate service — the packet lists this as a possible scored service but does not confirm it on any specific host. Verify on the live system before relying on any step below.

Confirm DNS is actually running and discover zone configuration:

```powershell
# Windows Server 2022 (2022 AD)
Get-Service DNS | Select-Object Status, StartType
dnscmd /enumzones
Get-DnsServerResourceRecord -ZoneName "<zone_name>"
# Check listening
netstat -an | findstr ":53"
# Check zone type and delegation
Get-DnsServerZone -Name "<zone_name>"
```

From a Linux client (Kali or Ubuntu Email):

```bash
dig @172.20.240.100 <record> <type> +short
nslookup <record> 172.20.240.100
```

## Setup

DNS on Windows Server 2022 is typically installed as part of the AD Domain Services role. If missing:

```powershell
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
# If DNS role was not included:
Install-WindowsFeature DNS -IncludeManagementTools
Start-Service DNS
Set-Service DNS -StartupType Automatic
```

In a competition environment, DNS is almost certainly already present. Do not re-install or reconfigure zones unless the portal confirms a deficiency.

## Configuration

### Zone management

- **Forward lookup zones**: `dnscmd /zoneinfo <zone_name>` — verify A/AAAA/MX/CNAME records match portal expectations.
- **Reverse lookup zones**: `dnscmd /enumzones | findstr "in-addr.arpa"` — verify PTR records.
- **Conditional forwarders**: `Get-DnsServerZone | Where-Object ZoneType -eq Forwarder` — verify upstream resolvers are correct for the lab network.

### AD-integrated zones

If zones are AD-integrated (stored in the directory), changes replicate via multi-master replication. Use:

```powershell
# View zone properties
Get-DnsServerZone | Select-Object Name, ZoneType, ReplicationScope
# Add/modify records (use only if portal requires)
Add-DnsServerResourceRecordA -Name "test" -IPv4Address "172.20.240.100" -ZoneName "<domain>"
```

### Firewall

Ensure TCP and UDP 53 are open on the relevant interface. Check Windows Firewall:

```powershell
netsh advfirewall firewall show rule name="DNS Server"
# If missing (rare on AD):
netsh advfirewall firewall add rule name="DNS Server TCP" dir=in action=allow protocol=TCP localport=53
netsh advfirewall firewall add rule name="DNS Server UDP" dir=in action=allow protocol=UDP localport=53
```

Preserve existing rules. Do not create scoring-only allowlists.

### Palo Alto / VyOS

Verify NAT and routing allow DNS traffic from workstations and Kali to the AD host. Check for any ACL that might block UDP 53 on the internal or public path.

PAN-OS CLI options (discovery only):

```
show running security-policy | match 172.20.240.100
show session all filter destination 172.20.240.100 destination-port 53
show interface ethernet1/2
show zone
```

GUI equivalent: Policies > Security, Monitor > Traffic, Network > Interfaces.

## Monitoring

```powershell
# Service health
Get-Service DNS | Select-Object Status
# Query statistics (requests, errors)
Get-DnsServerStatistics -ComputerName .
# Recent query log (if enabled)
Get-EventLog System -Newest 20 -Source "DNS Server"
```

From a client:

```bash
dig @172.20.240.100 <expected_record> +time=5 +tries=2
```

Forward DNS query logs to Splunk if the packet requires. Verify at Quotient that expected records resolve correctly.

## Backup

Back up zone data before any change:

Run elevated PowerShell. Export each zone to the DNS server's own directory:

```powershell
New-Item -ItemType Directory -Force C:\backup | Out-Null
Get-DnsServerZone | Format-List * | Out-File C:\backup\dns-zones.txt
Get-DnsServerForwarder | Format-List * | Out-File C:\backup\dns-forwarders.txt
Get-DnsServerZone | Where-Object { -not $_.IsAutoCreated -and $_.ZoneType -eq 'Primary' } | ForEach-Object {
    Export-DnsServerZone -Name $_.ZoneName -FileName ($_.ZoneName + '.backup.dns')
}
Copy-Item "$env:SystemRoot\System32\dns\*.backup.dns" C:\backup\
```

Restrict the backup directory to Administrators/SYSTEM and transfer an independent protected copy. Zone exports support record recovery, not full AD recovery; use the AD guide's System State procedure for AD-integrated zones. No VM snapshots.

## Usage and scoring verification

Verify the exact records the portal expects:

```bash
# From Kali or any authorized client
dig @<AD_public_or_internal_ip> <expected_record> A +short
dig @<AD_public_or_internal_ip> <expected_record> MX +short
dig @<AD_public_or_internal_ip> <expected_record> CNAME +short
# Reverse
dig -x <ip> +short
```

Test from both internal and public paths if the scoring check uses the public address. Confirm Quotient shows correct DNS responses.

## Recovery

1. Keep DNS running for record-level repair; compare the exported zone with `Get-DnsServerResourceRecord -ZoneName '<zone>'`.
2. Recreate only a confirmed missing A record: `Add-DnsServerResourceRecordA -ZoneName '<zone>' -Name '<label>' -IPv4Address '<verified-IP>'`. Use the matching `Add-DnsServerResourceRecord*` cmdlet for other types.
3. For full AD-integrated zone loss, follow the tested AD/System State recovery procedure; do not delete/recreate the zone or import an enumeration as a zone file.
4. Verify expected answers from clients over both UDP and TCP (`dig @<server> <record> A` and `dig +tcp @<server> <record> A`). Record UTC time and results.

## References

- [2022 AD system guide](../systems/2022-ad.md)
- [Environment constraints](../environment.md)
- [Event checklist](../event-checklist.md)

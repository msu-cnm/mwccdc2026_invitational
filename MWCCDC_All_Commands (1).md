# MWCCDC Command Reference: Active Directory + Mail Server

| Box | Name in NETLAB | IP | OS | Login |
|---|---|---|---|---|
| AD | 2022 AD | 172.20.240.100 | Windows Server 2022 | sysadmin / Changeme1! |
| Mail | Ubuntu Email | 172.20.240.15 | Ubuntu 22.04 | sysadmin / Changeme1! |
| Splunk | Debian Splunk | 172.20.240.20 | Debian 12 | (someone else's box) |

## How to use this file

- **AD commands:** right-click PowerShell, "Run as administrator".
- **Mail commands:** log in, then run `sudo -i` once so you are root.
- Anything in `<angle brackets>` is a blank you fill in. Delete the brackets too.
- Every step says what it does, what a good result looks like, and what to do if it is bad.
- Steps marked **RISKY** can break a scored service. Do them one at a time.

## The 6 rules that cost points if you forget them

1. **One change, then look at Quotient** (https://quotient.ccdc.events). If a check turns red right after your change, undo that change.
2. **Never rename** users, computers, or IP addresses. Leave ping (ICMP) working.
3. **Passwords the scoring engine uses must also go in Quotient's PCR tab** as `username,password`, one per line. If you change a password on the box and a check goes red, this is almost always why.
4. **Do not block everyone except the scorer.** You may block one specific attacker IP. Nothing wider.
5. **There is no undo button** (no snapshots). Back up before you change things.
6. **Do not replace the mail software.** Losing mailboxes is a penalty per user.

## Suggested order if you run both boxes alone

| Time | Do this |
|---|---|
| 0 to 10 min | A1, B1 (backups), B2, B3 (learn how mail works), A3, B4 (admin passwords) |
| 10 to 25 min | A2, B5 (baselines), A4, A5 (bad admins and users), B6 (bad Linux users) |
| 25 to 45 min | B8 (Postfix), B9 (Dovecot), A7 to A9 (Kerberos), A10 (quick settings) |
| 45 to 60 min | A11, A12 (persistence, DNS), B10, B11 (webmail, firewall), A13 |
| After that | Part C (logging), then repeat Part D (hunting) every 15 to 20 minutes |

---

# PART A: ACTIVE DIRECTORY

Run this once at the start of every new PowerShell window:
```powershell
Import-Module ActiveDirectory
```

## A1. Back up

**What it does:** saves group policies, DNS, and user lists to `C:\Backup` so you can look things up or rebuild if something is destroyed.
```powershell
New-Item -ItemType Directory C:\Backup\GPO -Force | Out-Null

# Group policies
Backup-GPO -All -Path C:\Backup\GPO

# DNS zones. Files are saved in C:\Windows\System32\dns\
Get-DnsServerZone | Where-Object { -not $_.IsAutoCreated -and $_.ZoneType -eq 'Primary' -and $_.ZoneName -ne 'TrustAnchors' } |
  ForEach-Object { Export-DnsServerZone -Name $_.ZoneName -FileName "bak_$($_.ZoneName).dns" }

# User and group lists
Get-ADUser -Filter * -Properties * | Export-Csv C:\Backup\users_full.csv -NoTypeInformation
Get-ADGroup -Filter * | Export-Csv C:\Backup\groups.csv -NoTypeInformation
```
**Good result:** no red errors, and `dir C:\Backup\GPO` shows folders.
**Note:** the DNS export gives an error if the backup file already exists. That is fine the second time.

Optional full copy of the AD database (takes a few minutes; the IFM folder must not exist yet):
```powershell
ntdsutil "activate instance ntds" ifm "create full C:\Backup\IFM" q q
```

## A2. Take a baseline

**What it does:** writes down what "normal" looks like right now, so later you can spot anything new.
```powershell
$b = "C:\Baseline"
New-Item -ItemType Directory $b -Force | Out-Null

Get-ADUser -Filter * | Select-Object SamAccountName,Enabled | Export-Csv $b\users.csv -NoTypeInformation

$admins = foreach ($g in "Domain Admins","Enterprise Admins","Schema Admins","Administrators") {
  Get-ADGroupMember $g -Recursive | Select-Object @{n='Group';e={$g}},SamAccountName
}
$admins | Export-Csv $b\admins.csv -NoTypeInformation

Get-Service | Select-Object Name,Status,StartType | Export-Csv $b\services.csv -NoTypeInformation
Get-ScheduledTask | Select-Object TaskName,TaskPath,State | Export-Csv $b\tasks.csv -NoTypeInformation
Get-NetTCPConnection -State Listen | Select-Object LocalPort,OwningProcess | Sort-Object LocalPort -Unique | Export-Csv $b\ports.csv -NoTypeInformation
Get-ChildItem C:\Windows\SYSVOL\domain -Recurse -File | Get-FileHash | Export-Csv $b\sysvol_hashes.csv -NoTypeInformation
```
**Compare later** (a line with `=>` is something new since the baseline):
```powershell
Compare-Object (Import-Csv C:\Baseline\users.csv).SamAccountName (Get-ADUser -Filter *).SamAccountName
Compare-Object (Import-Csv C:\Baseline\tasks.csv).TaskName (Get-ScheduledTask).TaskName
Compare-Object (Import-Csv C:\Baseline\services.csv).Name (Get-Service).Name
```

## A3. Change the admin passwords

**What it does:** the default password `Changeme1!` is printed in the team pack, so the Red Team has it.
```powershell
Set-ADAccountPassword -Identity Administrator -Reset -NewPassword (Read-Host "New Administrator password" -AsSecureString)
Set-ADAccountPassword -Identity sysadmin -Reset -NewPassword (Read-Host "New sysadmin password" -AsSecureString)
```
**Then:** use two different passwords, write them down, and look at Quotient. If the **AD WinRM** check turns red, put that account's new password in the PCR tab.

## A4. Check who is an admin

**What it does:** lists everyone in the powerful groups. Red Team often hides an extra account here.
```powershell
foreach ($g in "Domain Admins","Enterprise Admins","Schema Admins","Administrators","Account Operators","Backup Operators","Server Operators","DnsAdmins","Group Policy Creator Owners") {
  "== $g"
  Get-ADGroupMember $g -Recursive -ErrorAction SilentlyContinue | Select-Object SamAccountName,objectClass | Format-Table -HideTableHeaders
}
```
**Good result:** Administrator, sysadmin, and built-in groups only. Account Operators, Backup Operators, and Server Operators are normally empty.
**If you see someone who should not be there:**
```powershell
Remove-ADGroupMember -Identity "<group name>" -Members <username> -Confirm:$false
```

## A5. Look for fake or weak user accounts

**What it does:** shows the newest accounts and accounts with dangerous settings.
```powershell
# Newest 20 accounts
Get-ADUser -Filter * -Properties whenCreated | Sort-Object whenCreated -Descending |
  Select-Object -First 20 SamAccountName,whenCreated,Enabled

# Accounts allowed to have a blank password
Get-ADUser -Filter 'PasswordNotRequired -eq $true' | Select-Object SamAccountName

# Turn off the Guest account
Disable-ADAccount -Identity Guest
```
**If an account looks fake:** turn it off (do not delete it, you need it as evidence for your incident report).
```powershell
Disable-ADAccount -Identity <username>
```
**Fix a blank-password account:**
```powershell
Set-ADUser -Identity <username> -PasswordNotRequired $false
```
**Do not turn on account lockout.** Red Team could then lock out the users the scoring engine logs in as.

## A6. Reset every user's password (RISKY, ask your captain first)

**What it does:** gives every enabled user a new random password and makes a file you can paste into Quotient's PCR tab.
**Do B3 first.** If the mail server logs in to AD with a service account, add that account to the skip list or mail breaks.
```powershell
$skip = 'krbtgt','Guest','Administrator','sysadmin'      # add service accounts here, in quotes, separated by commas

$lines = foreach ($u in (Get-ADUser -Filter 'Enabled -eq $true' | Where-Object { $skip -notcontains $_.SamAccountName })) {
  $p = (-join ((48..57)+(65..90)+(97..122) | Get-Random -Count 14 | ForEach-Object { [char]$_ })) + 'Aa7!'
  Set-ADAccountPassword -Identity $u -Reset -NewPassword (ConvertTo-SecureString $p -AsPlainText -Force)
  "$($u.SamAccountName),$p"
}
$lines | Set-Content C:\Backup\pcr.csv
notepad C:\Backup\pcr.csv
```
**Then:** copy the whole file into Quotient's PCR tab right away. Checks stay red until you do. If mail logins stay red after that, see B4.

## A7. Reset krbtgt twice

**What it does:** krbtgt is the key that signs all login tickets. If Red Team stole it, they can forge tickets forever ("golden ticket"). Resetting it twice makes stolen copies useless.
```powershell
$new = { ConvertTo-SecureString ([guid]::NewGuid().ToString() + "Aa1!" + [guid]::NewGuid().ToString()) -AsPlainText -Force }
Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (& $new)
```
Wait at least 10 minutes, then run the second line again:
```powershell
Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (& $new)
```
**Note:** you only need to re-run the first line too if you opened a new PowerShell window.

## A8. Close the common Kerberos weak spots

**What it does:** finds accounts whose passwords can be cracked offline.
```powershell
# User accounts with a service name attached ("kerberoastable"). krbtgt is normal here.
Get-ADUser -Filter 'ServicePrincipalName -like "*"' -Properties ServicePrincipalName | Select-Object SamAccountName,ServicePrincipalName

# Accounts that skip pre-authentication ("AS-REP roastable"). Should be empty.
Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true' | Select-Object SamAccountName

# Unconstrained delegation. Only the domain controller itself should appear.
Get-ADComputer -Filter 'TrustedForDelegation -eq $true' | Select-Object Name
Get-ADUser -Filter 'TrustedForDelegation -eq $true' | Select-Object SamAccountName
```
**Fixes:**
```powershell
Set-ADAccountControl -Identity <username> -DoesNotRequirePreAuth $false
Set-ADAccountControl -Identity <username> -TrustedForDelegation $false
```
For a user that has a service name: give it a long random password. If a scored service uses that account, the service needs the new password too, so check Quotient.

**Stop normal users from adding computers to the domain** (blocks a known attack):
```powershell
Set-ADDomain -Identity (Get-ADDomain) -Replace @{'ms-DS-MachineAccountQuota'=0}
```

## A9. Check who can copy the whole password database (DCSync)

**What it does:** lists who holds the "replication" rights. Anyone with them can steal every password hash.
```powershell
$dn = (Get-ADDomain).DistinguishedName
$rights = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2','1131f6ad-9c07-11d1-f79f-00c04fc2dcd2','89e95b76-444d-4c62-991a-0facbeda640c'
(Get-Acl "AD:$dn").Access |
  Where-Object { $rights -contains $_.ObjectType.ToString() -and $_.AccessControlType -eq 'Allow' } |
  Select-Object IdentityReference -Unique
```
**Good result:** only `Domain Controllers`, `Enterprise Domain Controllers`, `Enterprise Read-only Domain Controllers`, and `Administrators`.
**If a normal user or group shows up:** tell your captain and write it in an incident report. Remove it in "Active Directory Users and Computers": View menu, Advanced Features, right-click the domain, Properties, Security tab, select that entry, Remove.

## A10. Quick safe settings

**What it does:** turns off old features that attackers abuse.
```powershell
# Print Spooler is not needed on a domain controller
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled

# Turn off the old SMB version 1
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

# Turn off LLMNR (name lookups attackers can answer with fake replies)
New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMulticast -Value 0 -Type DWord

# Turn off NetBIOS name lookups (same reason)
Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled = TRUE" |
  Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions=[uint32]2}

# Confirm
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol,RequireSecuritySignature
```
**Good result:** `EnableSMB1Protocol False` and `RequireSecuritySignature True`.

**RISKY, one at a time, then check Quotient:**
```powershell
# Only accept the newer NTLMv2 login method
Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name LmCompatibilityLevel -Value 5 -Type DWord
```
Undo it with the same command and `-Value 3`.

**Do not** force "LDAP signing required" unless you know the mail server connects with LDAPS or StartTLS. It can break mail logins.

## A11. Look for hidden backdoors (persistence)

**What it does:** checks the usual places attackers hide something that restarts itself.
```powershell
# Programs that start at boot or login
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run

# Scheduled tasks that are not Microsoft's own
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } |
  Select-Object TaskName,TaskPath,State,@{n='Runs';e={($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join '; '}} |
  Format-List

# Services whose program is not in C:\Windows
Get-CimInstance Win32_Service | Where-Object { $_.PathName -and $_.PathName -notmatch '^"?C:\\Windows\\' } |
  Select-Object Name,State,StartName,PathName | Format-List

# WMI event backdoors. "SCM Event Log Filter" and "SCM Event Log Consumer" are normal.
Get-CimInstance -Namespace root\subscription -ClassName __EventFilter | Select-Object Name,Query
Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer | Select-Object Name
Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding | Select-Object Filter,Consumer

# Scripts and programs inside group policy folders
Get-ChildItem C:\Windows\SYSVOL\domain -Recurse -File |
  Where-Object { $_.Extension -match '\.(ps1|bat|vbs|exe|dll|cmd|js)$' } | Select-Object FullName,LastWriteTime

# Group policies, newest change first
Get-GPO -All | Sort-Object ModificationTime -Descending | Select-Object DisplayName,ModificationTime

# Shared folders. ADMIN$, C$, IPC$, NETLOGON, SYSVOL are normal.
Get-SmbShare
```
**Remove something bad** (write down what it was first, for the incident report):
```powershell
Unregister-ScheduledTask -TaskName "<task name>" -Confirm:$false
Stop-Service <service name> -Force
sc.exe delete <service name>
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "<value name>" /f
Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -Filter "Name='<name>'" | Remove-CimInstance
Remove-SmbShare -Name "<share name>" -Force
```

## A12. Check DNS

**What it does:** DNS on this box is scored, and it tells everyone where the mail server is. Red Team can break mail just by changing a record here.
```powershell
$zones = (Get-DnsServerZone | Where-Object { -not $_.IsAutoCreated -and $_.ZoneType -eq 'Primary' -and $_.ZoneName -ne 'TrustAnchors' }).ZoneName
$zones

foreach ($z in $zones) {
  "== $z"
  Get-DnsServerResourceRecord -ZoneName $z -RRType A  | Select-Object HostName,@{n='IP';e={$_.RecordData.IPv4Address}}
  Get-DnsServerResourceRecord -ZoneName $z -RRType MX | Select-Object HostName,@{n='MailServer';e={$_.RecordData.MailExchange}}
}

# Stop outsiders copying the whole zone
foreach ($z in $zones) { Set-DnsServerPrimaryZone -Name $z -SecureSecondaries NoTransfer }
```
**Good result:** the mail server name points to 172.20.240.15, and other names match the IP table in the team pack. Save this output and compare it again later.
**Fix a wrong record:** open "DNS" from Server Manager's Tools menu, find the record, and correct the IP.

## A13. Firewall and antivirus

**What it does:** makes sure the Windows firewall and Defender are on and that Red Team did not add exceptions.
```powershell
# Firewall on for all three profiles
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True
Get-NetFirewallProfile | Select-Object Name,Enabled

# Inbound rules that allow traffic. Look for names you do not recognize.
Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow | Select-Object DisplayName,Profile | Sort-Object DisplayName

# Defender status
Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated
Set-MpPreference -DisableRealtimeMonitoring $false
Update-MpSignature

# Folders or programs Defender was told to ignore. Should be empty.
Get-MpPreference | Select-Object ExclusionPath,ExclusionProcess,ExclusionExtension

# Quick scan
Start-MpScan -ScanType QuickScan
```
**Fixes:**
```powershell
Disable-NetFirewallRule -DisplayName "<rule name>"
Remove-MpPreference -ExclusionPath "<path>"
```
**Do not** add a "block everything" rule. The domain controller needs its built-in rules, and the scoring engine needs WinRM (5985) and DNS (53).

## A14. Turn on logging

**What it does:** makes Windows record logins, account changes, and every program that runs, so you have evidence.
```powershell
$subs = "Logon","Logoff","Account Lockout","Special Logon","User Account Management","Security Group Management",
        "Directory Service Access","Directory Service Changes","Kerberos Service Ticket Operations",
        "Kerberos Authentication Service","Credential Validation","Process Creation","Audit Policy Change"
foreach ($s in $subs) { auditpol /set /subcategory:"$s" /success:enable /failure:enable }

# Record the full command line of every program
New-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Force | Out-Null
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -Type DWord

# Record PowerShell scripts that run
New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force | Out-Null
Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name EnableScriptBlockLogging -Value 1 -Type DWord

# Make the Security log bigger (512 MB) so it does not overwrite itself
wevtutil sl Security /ms:536870912
```
**Good result:** each auditpol line prints "The command was successfully executed."

## A15. Confirm the scored services still work

```powershell
Get-Service WinRM,DNS,NTDS,Netlogon,Kdc | Select-Object Name,Status
Test-WSMan localhost
Resolve-DnsName <mail server name> -Server 127.0.0.1
```
**Good result:** all five services say `Running`, Test-WSMan prints version details, and the name resolves to 172.20.240.15. Then confirm in Quotient.

---

# PART B: MAIL SERVER (Ubuntu 22.04)

Start every session with:
```bash
sudo -i
```
The team pack does not say which mail programs are installed. The commands below assume the usual set: **Postfix** (sends and receives mail), **Dovecot** (lets users read mail over POP3 and IMAP), and a **PHP webmail** page. B2 tells you what is really there.

## B1. Back up

**What it does:** copies settings, mailboxes, and the webmail site to `/root/bak`.
```bash
mkdir -p /root/bak
tar czf /root/bak/etc.tgz /etc 2>/dev/null
tar czf /root/bak/mail.tgz /var/mail /var/vmail /home /var/www 2>/dev/null
cp -a /etc/postfix /root/bak/postfix.orig 2>/dev/null
cp -a /etc/dovecot /root/bak/dovecot.orig 2>/dev/null
ls -lh /root/bak
```
**Good result:** `etc.tgz` and `mail.tgz` exist and are not zero bytes. Messages about missing folders are fine.
**Restore one file later:** `cp -a /root/bak/postfix.orig/main.cf /etc/postfix/main.cf`

## B2. See what is running

**What it does:** shows which programs are listening on the network and which mail software is installed.
```bash
ss -tulpn
systemctl list-units --type=service --state=running --no-pager
dpkg -l | grep -Ei "postfix|dovecot|exim|sendmail|roundcube|squirrelmail|rainloop|apache2|nginx|php"
```
**How to read it:**

| Port | What it is |
|---|---|
| 25, 465, 587 | Sending mail (SMTP) |
| 110, 995 | Reading mail (POP3) |
| 143, 993 | Reading mail (IMAP) |
| 80, 443 | Webmail |
| 22 | SSH |

Anything else listening that is not on `127.0.0.1` deserves a closer look.

## B3. Find out how mail users log in (do this before changing any passwords)

**What it does:** the scoring engine logs in to mail with Active Directory usernames. You need to know whether this box asks AD to check passwords, or keeps its own copy of the users.
```bash
# Dovecot's login settings
doveconf -n | grep -A6 -E "^passdb|^userdb"

# LDAP settings files (these hold the AD server, the account used to connect, and its password)
grep -rvE '^\s*#|^\s*$' /etc/dovecot/*ldap* 2>/dev/null
postconf -n | grep -i ldap
grep -rl ldap /etc/postfix 2>/dev/null

# Is this box joined to the domain?
realm list 2>/dev/null
grep -E "^(passwd|group|shadow)" /etc/nsswitch.conf

# Users that exist locally on this box
awk -F: '$3>=1000 && $3<65000 {print $1}' /etc/passwd
ls -la /var/mail /var/vmail 2>/dev/null
```
**How to read it:**
- You see `driver = ldap` and a file with `dn =` and `dnpass =`: mail checks passwords against AD using that account. **Write that account name down.** Never change its password on AD without changing `dnpass` here in the same minute.
- You see `driver = pam` and the mail users are in the local user list: passwords live on this box. A password changed on AD must also be changed here.
- You see `sss` or `winbind` in nsswitch.conf: the box is joined to the domain and AD passwords work directly.

## B4. Change passwords

```bash
passwd root
passwd sysadmin
```
**Then:** look at Quotient. If the **SSH** check turns red, put that account's new password in the PCR tab.

**If mail uses an AD connect account (from B3), change both sides together.**
On AD:
```powershell
Set-ADAccountPassword -Identity <connect account> -Reset -NewPassword (Read-Host "New password" -AsSecureString)
```
On mail: open the file you found in B3, change the `dnpass =` line, save, then:
```bash
nano /etc/dovecot/dovecot-ldap.conf.ext
systemctl restart dovecot
doveadm auth test <a mail username>
```
**Good result:** after typing that user's password you see `passdb: <user> auth succeeded`.

**If mail users are local accounts and you did A6**, copy `pcr.csv` to this box and apply the same passwords here:
```bash
tr -d '\r' < pcr.csv | while IFS=, read -r u p; do id "$u" >/dev/null 2>&1 && echo "$u:$p" | chpasswd; done
```

## B5. Take a baseline

```bash
mkdir -p /root/baseline && cd /root/baseline
cp /etc/passwd passwd.txt
ss -tulpn > ports.txt
ps auxf > ps.txt
systemctl list-unit-files --state=enabled --no-pager > units.txt
for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u "$u" 2>/dev/null | sed "s/^/$u: /"; done > cron.txt
find / -xdev -perm -4000 -type f 2>/dev/null | sort > suid.txt
postconf -n > postconf.txt 2>/dev/null
doveconf -n > doveconf.txt 2>/dev/null
find /etc/postfix /etc/dovecot /var/www -type f -exec sha256sum {} + > hashes.txt 2>/dev/null
cd /root
```
**Compare later** (any output means something changed):
```bash
diff /root/baseline/passwd.txt /etc/passwd
diff /root/baseline/postconf.txt <(postconf -n)
diff /root/baseline/doveconf.txt <(doveconf -n)
sha256sum -c /root/baseline/hashes.txt 2>/dev/null | grep -v ': OK'
diff /root/baseline/suid.txt <(find / -xdev -perm -4000 -type f 2>/dev/null | sort)
```

## B6. Look for bad users and hidden backdoors

```bash
# Accounts with full root power. Only "root" should print.
awk -F: '$3==0 {print $1}' /etc/passwd

# Accounts that can log in with a shell
grep -vE "nologin|/bin/false|/bin/sync" /etc/passwd

# Who is allowed to use sudo
grep -rvE '^\s*#|^\s*$' /etc/sudoers /etc/sudoers.d/ 2>/dev/null
getent group sudo

# SSH keys that let someone log in without a password
find / -xdev -name "authorized_keys*" 2>/dev/null -exec ls -la {} \; -exec cat {} \;

# This file should not exist. If it does, a rootkit may be loaded.
cat /etc/ld.so.preload 2>/dev/null

# Scheduled jobs
cat /root/baseline/cron.txt
ls -la /etc/cron.d /etc/cron.hourly /etc/cron.daily
cat /etc/crontab
systemctl list-timers --all --no-pager

# Who is logged in right now, and recent logins
w
last -n 20
```
**Fixes:**
```bash
usermod -L <username>                  # lock an account
gpasswd -d <username> sudo             # remove sudo rights
> /home/<username>/.ssh/authorized_keys   # empty a key file
crontab -e -u <username>               # edit that user's scheduled jobs
pkill -KILL -u <username>              # kick a logged-in user off
```
**Careful:** do not lock a mail user the scoring engine logs in as.

## B7. Tighten SSH

**What it does:** stops direct root logins over SSH. SSH is scored, so normal logins must keep working.
```bash
cp /etc/ssh/sshd_config /root/bak/sshd_config.orig
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sshd -t && systemctl restart ssh
```
**Good result:** `sshd -t` prints nothing. **Keep your current window open** and test a new login before closing it. Do not turn off password logins; the scoring engine probably uses a password.

## B8. Postfix (sending and receiving mail)

**Look first:**
```bash
postconf -n
grep -vE '^\s*#|^\s*$' /etc/postfix/master.cf
grep -vE '^\s*#|^\s*$' /etc/aliases
find /home /root -name ".forward" 2>/dev/null
postqueue -p | tail -3
```
**What bad looks like:**

| You see | What it means | Fix |
|---|---|---|
| `always_bcc`, `sender_bcc_maps`, or `recipient_bcc_maps` | A secret copy of mail is being sent somewhere | `postconf -X always_bcc` (same for the other two) |
| `mynetworks` containing `0.0.0.0/0` or a huge range | Anyone can send spam through you (open relay) | see below |
| A line in `/etc/aliases` with a `\|` pipe to a script | Mail to that name runs a command | delete the line, then run `newaliases` |
| A `.forward` file you did not expect | That user's mail is copied elsewhere | delete the file |
| A line in master.cf running a strange program | A backdoor service | compare with `/root/bak/postfix.orig/master.cf` |
| Thousands of messages in the queue | You are being used for spam | fix the relay, then `postsuper -d ALL deferred` |

**Safe settings:**
```bash
postconf -e "disable_vrfy_command = yes"
postconf -e "smtpd_banner = \$myhostname ESMTP"
postfix check && systemctl reload postfix
```
**RISKY (check Quotient right after):** close an open relay.
```bash
postconf mynetworks smtpd_relay_restrictions          # write down the current values first
postconf -e "mynetworks = 127.0.0.0/8 [::1]/128"
postconf -e "smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination"
postfix check && systemctl reload postfix
```
Undo with `postconf -e "mynetworks = <old value>"` and reload again.

**Test that mail still works:**
```bash
printf "Subject: test\n\nhello\n" | sendmail <a local mail username>
tail -n 20 /var/log/mail.log
```
**Good result:** a log line ending in `status=sent`.

## B9. Dovecot (reading mail)

**Look first:**
```bash
doveconf -n
grep -rnE "static|passwd-file|args" /etc/dovecot/conf.d/ | grep -v "^\S*:\s*#"
```
**What bad looks like:** a `passdb` block with `driver = static` and a `password=` value (one password that works for everyone), or a `passwd-file` pointing at a file with accounts you do not recognize. Compare against `/root/bak/dovecot.orig`.

**Turn on login logging so you can see password guessing:**
```bash
echo "auth_verbose = yes" >> /etc/dovecot/conf.d/10-logging.conf
doveconf -n > /dev/null && systemctl restart dovecot
doveadm auth test <a mail username>
```
**Good result:** `auth succeeded`.
**Leave `disable_plaintext_auth` alone.** If the scoring engine logs in on port 110 or 143 without encryption, changing it turns the check red.

## B10. Webmail

**Find it:**
```bash
ls -la /var/www/html
find / -xdev -name "config.inc.php" 2>/dev/null
find / -xdev -type d -name installer -path "*roundcube*" 2>/dev/null
```
**Hunt for webshells** (a webshell is a small file an attacker uploads so they can run commands through the website):
```bash
# Files changed in the last 5 hours
find /var/www -type f -mmin -300 -ls 2>/dev/null

# Files containing code that runs commands taken straight from the web request
grep -rlE 'eval\(\$_(POST|GET|REQUEST|COOKIE)|(system|shell_exec|passthru|exec)\(\$_(POST|GET|REQUEST)|base64_decode\(\$_(POST|GET|REQUEST)' /var/www 2>/dev/null

# Files anyone can overwrite
find /var/www -type f -perm -o+w 2>/dev/null
```
**Good result:** all three print nothing.
**If you find one:** move it out, do not delete it (evidence), and write the incident report.
```bash
mkdir -p /root/evidence && mv <file path> /root/evidence/
```
**Other fixes:**
```bash
rm -rf <path to the roundcube installer folder>       # only if the find above printed one
chmod 640 <path to config.inc.php>
```
**Do not edit the page content.** The HTTP check compares the page to an expected copy.
**Test:** `curl -I http://localhost/` should answer `200` or a `30x` redirect, and you can still log in to webmail from a workstation.

## B11. Firewall

**What it does:** closes every port except the scored ones. Ping keeps working with ufw's defaults.
```bash
ufw status verbose
ufw default deny incoming
ufw default allow outgoing
ufw allow 22,25,80,110,143,443,465,587,993,995/tcp
ufw --force enable
ufw status verbose
```
**Then look at Quotient immediately.** If a mail or web check turns red and B2 showed that service on a different port, add it: `ufw allow <port>/tcp`. In an emergency, `ufw disable` turns the firewall off again.

**Block one attacker IP (this is allowed):**
```bash
ufw insert 1 deny from <attacker IP>
```
**Leave AppArmor on.** Check with `aa-status`.
**Do not run `apt upgrade`** on everything. It can restart or reconfigure the mail programs mid-game.

## B12. Confirm everything still works

```bash
systemctl is-active postfix dovecot ssh
ss -tlnp | grep -E ":(22|25|80|110|143|443|587|993|995) "
printf "Subject: test\n\nhello\n" | sendmail <a local mail username>
doveadm auth test <a mail username>
tail -n 20 /var/log/mail.log
```
**Good result:** `active` three times, the ports you saw in B2 are still listed, the test mail says `status=sent`, and the login test says `auth succeeded`. Then confirm in Quotient.

---

# PART C: SEND LOGS TO SPLUNK (after hardening)

Ask whoever runs the Splunk box (172.20.240.20) two things first:
1. Turn on receiving: in Splunk, Settings, Forwarding and receiving, Configure receiving, New, port **9997**.
2. Which index name to use (default is `main`).

The Splunk Universal Forwarder is a free download from splunk.com, but the site asks you to sign in with a free account. If you cannot download it, skip to Part D, which works without Splunk.

## C1. AD: Sysmon (free Microsoft tool that records programs and network connections)
```powershell
New-Item -ItemType Directory C:\Tools -Force | Out-Null
Set-Location C:\Tools
Invoke-WebRequest https://download.sysinternals.com/files/Sysmon.zip -OutFile Sysmon.zip
Expand-Archive Sysmon.zip -DestinationPath C:\Tools\Sysmon -Force
Invoke-WebRequest https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -OutFile sysmonconfig.xml
.\Sysmon\Sysmon64.exe -accepteula -i sysmonconfig.xml
Get-Service Sysmon64
```
**Good result:** the service shows `Running`. You can read its log in Event Viewer under Applications and Services Logs, Microsoft, Windows, Sysmon, Operational.

## C2. AD: Splunk forwarder
Put the downloaded `.msi` in `C:\Tools`, then:
```powershell
Set-Location C:\Tools
msiexec.exe /i <forwarder file name>.msi RECEIVING_INDEXER="172.20.240.20:9997" AGREETOSLICENSE=Yes /quiet
```
Wait about a minute, then tell it which logs to send:
```powershell
@"
[WinEventLog://Security]
disabled = 0

[WinEventLog://System]
disabled = 0

[WinEventLog://Microsoft-Windows-PowerShell/Operational]
disabled = 0

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0

[WinEventLog://DNS Server]
disabled = 0
"@ | Set-Content "C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf"

Restart-Service SplunkForwarder
```

## C3. Mail: auditd (records changes to important files)
```bash
apt update && apt install -y auditd
cat > /etc/audit/rules.d/mail.rules <<'EOF'
-w /etc/postfix -p wa -k postfix_cfg
-w /etc/dovecot -p wa -k dovecot_cfg
-w /var/www -p wa -k webroot
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k identity
-w /etc/ssh/sshd_config -p wa -k sshd_cfg
EOF
augenrules --load
auditctl -l
```
**Good result:** `auditctl -l` lists the seven rules. Search them later with `ausearch -k postfix_cfg -ts recent`.

## C4. Mail: Splunk forwarder
Put the downloaded `.deb` on the box, then:
```bash
dpkg -i <forwarder file name>.deb
/opt/splunkforwarder/bin/splunk start --accept-license --answer-yes --no-prompt --seed-passwd '<pick a forwarder admin password>'
/opt/splunkforwarder/bin/splunk add forward-server 172.20.240.20:9997 -auth 'admin:<that password>'
/opt/splunkforwarder/bin/splunk add monitor /var/log/mail.log -auth 'admin:<that password>'
/opt/splunkforwarder/bin/splunk add monitor /var/log/auth.log -auth 'admin:<that password>'
/opt/splunkforwarder/bin/splunk add monitor /var/log/audit/audit.log -auth 'admin:<that password>'
/opt/splunkforwarder/bin/splunk list forward-server -auth 'admin:<that password>'
```
**Good result:** the last command lists 172.20.240.20:9997 under "Active forwards".
If webmail runs on Apache, also add `/var/log/apache2`. For nginx, add `/var/log/nginx`.

---

# PART D: THREAT HUNTING

Repeat every 15 to 20 minutes. These work even if Splunk is not set up.

## D1. AD hunting (PowerShell)
```powershell
$since = (Get-Date).AddMinutes(-30)

# Failed logins, counted by the IP they came from
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625;StartTime=$since} -ErrorAction SilentlyContinue |
  ForEach-Object { $_.Properties[19].Value } | Group-Object | Sort-Object Count -Descending | Select-Object -First 10 Count,Name

# Accounts created, enabled, password reset, or added to groups
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4720,4722,4724,4728,4732,4756;StartTime=$since} -ErrorAction SilentlyContinue |
  Select-Object TimeCreated,Id,@{n='What';e={($_.Message -split "`n")[0]}}

# New services and new scheduled tasks
Get-WinEvent -FilterHashtable @{LogName='System';Id=7045;StartTime=$since} -ErrorAction SilentlyContinue | Select-Object TimeCreated,Message | Format-List
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4698;StartTime=$since} -ErrorAction SilentlyContinue | Select-Object TimeCreated,Message | Format-List

# Suspicious PowerShell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104;StartTime=$since} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 'FromBase64String|DownloadString|DownloadFile|IEX|Invoke-Expression|-enc ' } |
  Select-Object TimeCreated,@{n='Script';e={$_.Message.Substring(0,[Math]::Min(300,$_.Message.Length))}} | Format-List

# Someone wiped a log
Get-WinEvent -FilterHashtable @{LogName='Security';Id=1102} -ErrorAction SilentlyContinue | Select-Object TimeCreated,Message

# Live network connections and the program behind each one
Get-NetTCPConnection -State Established | Where-Object { $_.RemoteAddress -notin '127.0.0.1','::1' } |
  Select-Object LocalPort,RemoteAddress,RemotePort,@{n='Program';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name}} |
  Sort-Object RemoteAddress | Format-Table

# Programs running from outside C:\Windows
Get-Process | Where-Object { $_.Path -and $_.Path -notlike 'C:\Windows\*' } | Select-Object Name,Id,Path

# Who is logged in, and who is connected to shared folders
quser
Get-SmbSession | Select-Object ClientComputerName,ClientUserName
```
**Kick someone out:**
```powershell
logoff <session ID from quser>
Get-SmbSession | Where-Object ClientComputerName -eq '<attacker IP>' | Close-SmbSession -Force
Stop-Process -Id <process ID> -Force
New-NetFirewallRule -DisplayName "Block <attacker IP>" -Direction Inbound -RemoteAddress <attacker IP> -Action Block
```

**What the event numbers mean:**

| Number | Meaning |
|---|---|
| 4625 | Failed login |
| 4624 | Successful login (type 3 is over the network, type 10 is remote desktop) |
| 4720 / 4722 / 4724 | Account created / enabled / password reset |
| 4728 / 4732 / 4756 | Someone added to a security group |
| 4769 | Service ticket requested (encryption type 0x17 many times in a row suggests kerberoasting) |
| 4662 | Directory access (with the replication IDs from A9, by a normal user, means DCSync) |
| 4698 / 7045 | Scheduled task created / service installed |
| 4104 | PowerShell script ran |
| 1102 | Security log was cleared |

## D2. Mail hunting (bash)
```bash
# Failed mail logins by IP (Dovecot)
grep -E "auth failed|Aborted login" /var/log/mail.log | grep -oE "rip=[0-9.]+" | sort | uniq -c | sort -rn | head

# Failed mail logins by IP (Postfix)
grep "SASL .* authentication failed" /var/log/mail.log | grep -oE "\[[0-9.]+\]" | sort | uniq -c | sort -rn | head

# Failed SSH logins by IP
grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head

# Successful SSH logins
grep "Accepted" /var/log/auth.log | tail -20

# Who is sending the most mail (a huge number means spam relay)
grep "postfix/qmgr" /var/log/mail.log | grep -oE "from=<[^>]*>" | sort | uniq -c | sort -rn | head

# Mail waiting in the queue
postqueue -p | tail -1

# Live connections and the program behind each
ss -tnp state established

# Who is logged in
w

# Rerun the baseline comparisons from B5
diff /root/baseline/postconf.txt <(postconf -n)
sha256sum -c /root/baseline/hashes.txt 2>/dev/null | grep -v ': OK'
find /var/www -type f -mmin -30 -ls 2>/dev/null
```

## D3. Optional tools for the mail box (all free, from Ubuntu's own package list)
```bash
apt install -y debsums pflogsumm rkhunter chkrootkit lynis clamav swaks tcpdump

debsums -c 2>/dev/null                 # lists program files that were modified after install
pflogsumm /var/log/mail.log | less     # readable summary of the mail log
rkhunter --check --sk                  # rootkit check
chkrootkit                             # second rootkit check
lynis audit system                     # general hardening report
clamscan -ri /var/www                  # scan the website for known malware
tcpdump -i any -nn port 25 or port 587 # watch mail traffic live (Ctrl+C to stop)
```
**Test your own server for open relay** (only ever aim this at your own box):
```bash
swaks --server 127.0.0.1 --from test@example.com --to someone@example.org
```
Run it from another machine on your team's network against 172.20.240.15 for a true test. **Good result:** `Relay access denied`.

Two more tools that are not in Ubuntu's package list: **pspy** (shows short-lived processes; download `pspy64` from its GitHub releases page, then `chmod +x pspy64 && ./pspy64`) and **osquery** (needs its own install package from osquery.io).

**fail2ban warning:** it bans IPs after failed logins. If a scored password is out of sync, it will ban the scoring engine and every check on this box goes red. Leave it off unless your captain wants it.

## D4. Tools for the AD box (all free)
```powershell
Set-Location C:\Tools
Invoke-WebRequest https://download.sysinternals.com/files/Autoruns.zip -OutFile Autoruns.zip
Invoke-WebRequest https://download.sysinternals.com/files/ProcessExplorer.zip -OutFile ProcessExplorer.zip
Invoke-WebRequest https://download.sysinternals.com/files/TCPView.zip -OutFile TCPView.zip
Expand-Archive Autoruns.zip -DestinationPath C:\Tools\Autoruns -Force
Expand-Archive ProcessExplorer.zip -DestinationPath C:\Tools\ProcessExplorer -Force
Expand-Archive TCPView.zip -DestinationPath C:\Tools\TCPView -Force

# Everything that starts automatically, hiding Microsoft's own entries, saved to a file
.\Autoruns\autorunsc64.exe -accepteula -a * -c -h -s -m > C:\Baseline\autoruns.csv
```
Open `Autoruns64.exe` for the same thing with a window; red or yellow rows are the ones to look at. **PingCastle**, **Hayabusa**, and **Chainsaw** are also free; get them from their official GitHub releases pages.

## D5. Splunk searches

Set the time picker to "Last 60 minutes". If your team uses a different index, change `index=*`.
```spl
index=* EventCode=4625 | stats count by Source_Network_Address, Account_Name | sort -count
```
```spl
index=* (EventCode=4720 OR EventCode=4722 OR EventCode=4724 OR EventCode=4728 OR EventCode=4732 OR EventCode=4756)
```
```spl
index=* EventCode=4769 "0x17" | stats count by Account_Name, Service_Name | sort -count
```
```spl
index=* EventCode=4662 ("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" OR "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2") NOT Account_Name="*$"
```
```spl
index=* (EventCode=4698 OR EventCode=7045)
```
```spl
index=* EventCode=4104 ("FromBase64String" OR "DownloadString" OR "IEX" OR "Invoke-Expression")
```
```spl
index=* (EventCode=1102 OR EventCode=104)
```
```spl
index=* source="/var/log/mail.log" ("auth failed" OR "authentication failed") | rex "(rip=|\[)(?<src>\d+\.\d+\.\d+\.\d+)" | stats count by src | sort -count
```
```spl
index=* source="/var/log/auth.log" "Failed password" | rex "from (?<src>\d+\.\d+\.\d+\.\d+)" | stats count by src | sort -count
```
```spl
index=* source="/var/log/audit/audit.log" ("postfix_cfg" OR "dovecot_cfg" OR "webroot" OR "identity" OR "sshd_cfg")
```
If a field name such as `Source_Network_Address` shows nothing, remove the `| stats` part and read the raw events instead.

---

# PART E: WHEN YOU FIND SOMETHING

1. **Write it down first:** time, attacker IP, your box's IP, what you saw, which command showed it.
2. **Save evidence:** move files to `/root/evidence` or `C:\Evidence`; disable accounts rather than deleting them.
3. **Stop it:** kick the session, remove the backdoor, block that one IP.
4. **Check Quotient** to make sure scored services still pass.
5. **Send one incident report** as a PDF through the inject site.

## Incident report template (worth 20% of the score, together with the Red Team assessment)
```
Team number: ____            Report time (Central): ________

What happened (one or two sentences):

Attacker IP(s):                    Our system and IP:

Timeline (Central time):
  __:__  first sign
  __:__  what we found
  __:__  what we did
  __:__  confirmed fixed

What was affected (accounts, files, services, passwords):

How we found it (log, command, or tool):

What we did to fix it:

What we will do to stop it happening again:
```
Reports are graded on being clear, complete, and correct. Send one per real incident. Junk reports can lose points.

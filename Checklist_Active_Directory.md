# Active Directory Checklist: Hardening + Threat Hunting

**2022 AD | 172.20.240.100 | Windows Server 2022 | sysadmin / Changeme1!**

The code after each item (A4, D1, and so on) is the section in `MWCCDC_All_Commands.md` with the exact commands.

## What this box is scored on
- **AD WinRM:** the scorer logs in over WinRM (port 5985) and runs a PowerShell command.
- **DNS:** the scorer asks this box to look up names.
- **Ping.**
- **Indirectly, mail and MSSQL:** those checks log in with Active Directory usernames. If you break or lock an AD user, someone else's check goes red.

## Rules to remember
- [ ] One change at a time, then look at Quotient
- [ ] Never rename users, the computer, or the IP address
- [ ] Leave ping working
- [ ] Scored passwords also go in Quotient's PCR tab (`username,password`)
- [ ] No snapshots: back up first
- [ ] Do not turn on account lockout (Red Team would lock out the scored users)
- [ ] Do not force "LDAP signing required" unless the mail owner confirms it is safe

---

## Phase 1: First 10 minutes
- [ ] Open PowerShell as administrator, run `Import-Module ActiveDirectory`
- [ ] Back up group policies, DNS zones, and user lists (A1)
- [ ] Take a baseline of users, admins, services, tasks, ports (A2)
- [ ] Change the Administrator and sysadmin passwords, two different ones (A3)
- [ ] Look at Quotient. If AD WinRM is red, put the new password in PCR
- [ ] Ask the mail owner: "Does mail log in to AD with a service account? Which one?" (B3)

## Phase 2: Accounts (10 to 25 minutes)
- [ ] List everyone in the admin groups; remove anyone who should not be there (A4)
- [ ] List the 20 newest accounts; disable fakes, do not delete them (A5)
- [ ] Find accounts allowed a blank password and fix them (A5)
- [ ] Disable Guest (A5)
- [ ] Decide with your captain whether to reset every user's password (A6). If yes, paste the file into PCR immediately
- [ ] First krbtgt reset. Note the time: ______ (A7)

## Phase 3: Kerberos and permissions (25 to 45 minutes)
- [ ] User accounts with a service name attached: give them long passwords (A8)
- [ ] Accounts that skip pre-authentication: fix them (A8)
- [ ] Unconstrained delegation: only the domain controller should have it (A8)
- [ ] Set the machine account quota to 0 (A8)
- [ ] Check who has replication (DCSync) rights (A9)
- [ ] Second krbtgt reset, at least 10 minutes after the first (A7)

## Phase 4: Settings (check Quotient after each)
- [ ] Print Spooler stopped and disabled (A10)
- [ ] SMB version 1 off (A10)
- [ ] LLMNR off, NetBIOS name lookups off (A10)
- [ ] NTLMv2 only: risky, do it alone and watch Quotient (A10)
- [ ] Firewall on for all three profiles; unknown allow rules disabled (A13)
- [ ] Defender on, updated, no exclusions, quick scan run (A13)

## Phase 5: Backdoor sweep
- [ ] Run and RunOnce registry keys (A11)
- [ ] Scheduled tasks that are not Microsoft's (A11)
- [ ] Services running from outside C:\Windows (A11)
- [ ] WMI event subscriptions; only the "SCM Event Log" ones are normal (A11)
- [ ] Scripts and programs in the SYSVOL folder (A11)
- [ ] Recently changed group policies (A11)
- [ ] Shared folders; only ADMIN$, C$, IPC$, NETLOGON, SYSVOL are normal (A11)
- [ ] DNS records correct, mail server points to 172.20.240.15, zone transfers off (A12)

## Phase 6: Logging
- [ ] Audit policy, command-line logging, PowerShell logging, bigger Security log (A14)
- [ ] Sysmon installed (C1)
- [ ] Splunk forwarder installed, if your team is using Splunk (C2)
- [ ] Final check that WinRM, DNS, NTDS, Netlogon, Kdc are running (A15)

---

## Threat hunting: repeat every 15 to 20 minutes (D1)
- [ ] Failed logins by IP. One IP trying many usernames is password spraying
- [ ] New accounts, password resets, group changes
- [ ] New services or scheduled tasks
- [ ] Suspicious PowerShell (encoded commands, downloads)
- [ ] Security log cleared
- [ ] Live connections to IPs you do not recognize
- [ ] Programs running from odd folders (Temp, Users, ProgramData)
- [ ] Who is logged in (`quser`) and who is on the shares
- [ ] Compare users, tasks, and services to the baseline (A2)
- [ ] Admin group members again (A4)
- [ ] DNS records again (A12)
- [ ] Quotient: anything red?

## What attacks look like on this box

| You see | It probably is | Do this |
|---|---|---|
| Many 4625 failures from one IP across many usernames | Password spraying | Block that IP, check for a 4624 success from it |
| A new user, or a new name in Domain Admins | Backdoor account | Disable it, remove from group, report |
| Many 4769 events with encryption 0x17 from one user | Kerberoasting | Reset passwords of accounts with service names |
| 4662 with replication IDs from a normal user | DCSync (all hashes stolen) | Remove the right, reset passwords, krbtgt twice |
| New service (7045) or task (4698) | Persistence | Remove it (A11), report |
| Event 1102 | Attacker hiding tracks | Check what happened just before, report |
| A DNS record pointing somewhere new | Mail or web redirect | Fix the record, report |
| WinRM check red, service is running | Password out of sync | Update PCR |

## Tools
- [ ] Event Viewer and the D1 commands (already on the box)
- [ ] Sysmon: records programs and connections (C1)
- [ ] Autoruns: shows everything that starts automatically (D4)
- [ ] Process Explorer and TCPView: live programs and connections (D4)
- [ ] PingCastle: scores your AD and lists the worst problems first
- [ ] Hayabusa or Chainsaw: scan event logs for known attack patterns
- [ ] Splunk at 172.20.240.20: one place to search every box's logs (D5)
- [ ] Palo Alto logs at 172.20.240.200: confirm an attacker IP before blocking
- [ ] Quotient: tells you if a failure started right after your own change

## When you find something (Part E)
- [ ] Write down time, attacker IP, what you saw
- [ ] Save evidence; disable rather than delete
- [ ] Stop it, then check Quotient
- [ ] One incident report, as a PDF

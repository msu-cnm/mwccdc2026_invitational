# Mail Server Checklist: Hardening + Threat Hunting

**Ubuntu Email | 172.20.240.15 | Ubuntu 22.04 | sysadmin / Changeme1!**

The code after each item (B8, D2, and so on) is the section in `MWCCDC_All_Commands.md` with the exact commands.

## What this box is scored on
- **SMTP:** the scorer sends and receives a test email.
- **POP3 / IMAP / Webmail:** the scorer logs in with **Active Directory usernames** and runs a few commands.
- **SSH** login and **Ping.**

The team pack does not name the mail software. The commands assume Postfix, Dovecot, and a PHP webmail page. Section B2 shows what is really installed; if it is different, stop and adjust.

## Rules to remember
- [ ] One change at a time, then look at Quotient
- [ ] Mail must be reachable from everywhere. Block single attacker IPs only
- [ ] Do not replace the mail software (penalty for each lost mailbox)
- [ ] Never rename users, the computer, or the IP address; leave ping working
- [ ] Scored passwords also go in Quotient's PCR tab
- [ ] No snapshots: back up first
- [ ] Do not change the webmail page content (the check compares it to a saved copy)
- [ ] Do not run a full `apt upgrade`

---

## Phase 1: First 10 minutes
- [ ] `sudo -i`
- [ ] Back up settings, mailboxes, and the website to /root/bak (B1)
- [ ] See what is running and on which ports (B2)
- [ ] **Find out how mail users log in** (B3). Write it here:
  - Login method (ldap / pam / other): ____________
  - AD connect account, if any: ____________
  - File holding its password: ____________
- [ ] Change root and sysadmin passwords (B4)
- [ ] Look at Quotient. If SSH is red, put the new password in PCR
- [ ] Take a baseline (B5)

## Phase 2: Users and backdoors
- [ ] Only root has user ID 0 (B6)
- [ ] Shell accounts are all expected (B6)
- [ ] sudo rights are all expected (B6)
- [ ] No unknown SSH keys (B6)
- [ ] `/etc/ld.so.preload` does not exist (B6)
- [ ] Scheduled jobs and timers look normal (B6)
- [ ] Nobody unexpected is logged in (B6)
- [ ] Root login over SSH turned off; tested a new login before closing the old window (B7)

## Phase 3: Postfix, sending and receiving (B8)
- [ ] No secret copy settings (`always_bcc`, `sender_bcc_maps`, `recipient_bcc_maps`)
- [ ] `mynetworks` is not wide open
- [ ] `/etc/aliases` has no lines that pipe mail into a script
- [ ] No unexpected `.forward` files
- [ ] `master.cf` matches the backup copy
- [ ] The mail queue is not huge
- [ ] VRFY off and banner cleaned
- [ ] Relay locked down: risky, do it alone and watch Quotient
- [ ] Test email sent, log says `status=sent`

## Phase 4: Dovecot, reading mail (B9)
- [ ] No `static` password or strange password file in the login settings
- [ ] Login logging on (`auth_verbose = yes`)
- [ ] `doveadm auth test` succeeds for a real user
- [ ] Left `disable_plaintext_auth` alone

## Phase 5: Webmail (B10)
- [ ] Found the webmail folder and its config file
- [ ] No recently changed files
- [ ] Webshell search prints nothing
- [ ] No files that anyone can overwrite
- [ ] Installer folder removed, if there was one
- [ ] Config file not readable by everyone
- [ ] Webmail login still works from a workstation

## Phase 6: Firewall and final check
- [ ] Firewall on, only the scored ports open (B11)
- [ ] Quotient checked right after turning it on
- [ ] AppArmor still on (B11)
- [ ] Postfix, Dovecot, SSH all active; test mail and test login pass (B12)
- [ ] Asked the AD owner to confirm the mail DNS record still points to 172.20.240.15 (A12)

## Phase 7: Logging
- [ ] auditd installed with the file-watch rules (C3)
- [ ] Splunk forwarder installed, if your team is using Splunk (C4)

---

## Threat hunting: repeat every 15 to 20 minutes (D2)
- [ ] Failed mail logins by IP
- [ ] Failed SSH logins by IP, and any successful ones you did not make
- [ ] Top mail senders (a huge count means spam relay)
- [ ] Mail queue size
- [ ] Live connections and the programs behind them
- [ ] Who is logged in (`w`)
- [ ] Postfix and Dovecot settings compared to baseline (B5)
- [ ] File hashes compared to baseline (B5)
- [ ] New files in the website folder
- [ ] New users, keys, or scheduled jobs (B6)
- [ ] Quotient: anything red?

## What attacks look like on this box

| You see | It probably is | Do this |
|---|---|---|
| Hundreds of failed mail logins from one IP | Password guessing | Block that IP (B11), check for a success |
| Thousands of queued messages | Open relay being used for spam | Fix relay (B8), clear the queue |
| A `bcc` setting you did not add | Mail being secretly copied | Remove it (B8), report |
| A new alias or `.forward` running a script | Backdoor triggered by email | Remove it, report |
| A new PHP file in the website folder | Webshell | Move to /root/evidence, report |
| "Accepted" SSH login from an unknown IP | Attacker has a password or key | Kick them, change password, check keys |
| New user, new sudo line, new cron job | Persistence | Remove it (B6), report |
| Mail login check red, services running | Password out of sync with AD or PCR | See B4 |
| Everything red right after the firewall | A needed port is closed | Add the port or `ufw disable` |

## Tools
- [ ] The D2 commands (nothing to install)
- [ ] auditd: records who changed mail settings and when (C3)
- [ ] debsums: finds program files that were tampered with (D3)
- [ ] pflogsumm: turns the mail log into a readable summary (D3)
- [ ] rkhunter and chkrootkit: rootkit checks (D3)
- [ ] ClamAV: scans the website for known malware (D3)
- [ ] Lynis: general hardening report (D3)
- [ ] swaks: test your own server for open relay, never anyone else's (D3)
- [ ] tcpdump: watch mail traffic live (D3)
- [ ] pspy: catches short-lived processes (D3)
- [ ] Splunk at 172.20.240.20 (D5), Palo Alto logs at 172.20.240.200, Quotient
- [ ] fail2ban: leave off unless your captain wants it; it can ban the scorer

## When you find something (Part E)
- [ ] Write down time, attacker IP, what you saw
- [ ] Save evidence in /root/evidence
- [ ] Stop it, then retest mail and check Quotient
- [ ] One incident report, as a PDF

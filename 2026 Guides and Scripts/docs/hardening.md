# Host-specific hardening

Run from the repository root. Review `config/host-firewall.json` against the event worksheet and actual management source (including NAT) before applying. The scripts restrict management SSH, rather than impose an unverified service allowlist that could break scoring. Candidate service lists document dependencies, not discovered listeners. Existing firewall policy remains authoritative. SSH may itself be scored: confirm its required sources before restricting it. Use console access and fresh trusted/untrusted connection tests; an existing session does not prove access will survive.

| Host | Firewall generator | Other implemented hardening |
| --- | --- | --- |
| rocky-ecom | `python3 scripts/linux_guard.py firewall --host rocky-ecom` | Linux kernel pointer/log disclosure and link protections |
| ubuntu-email | `python3 scripts/linux_guard.py firewall --host ubuntu-email` | Same kernel controls |
| debian-splunk | `python3 scripts/linux_guard.py firewall --host debian-splunk` | Same kernel controls |
| kali | `python3 scripts/linux_guard.py firewall --host kali` | Same kernel controls |
| ubuntu-workstation | `python3 scripts/linux_guard.py firewall --host ubuntu-workstation` | Same controls; narrower SSH source profile |
| 2022-ad | `.\scripts\windows_guard.ps1 -Action Firewall -HostId 2022-ad` | Logon success/failure auditing |
| 2019-mssql | `.\scripts\windows_guard.ps1 -Action Firewall -HostId 2019-mssql` | Logon success/failure auditing |
| windows11-workstation | `.\scripts\windows_guard.ps1 -Action Firewall -HostId windows11-workstation` | Same auditing; narrower SSH source profile |
| vyos | `python3 scripts/vyos_guard.py plan --host vyos` | Native input policy; no generic kernel modifications |
| palo-alto | `python3 scripts/panos_guard.py plan --host palo-alto` | Dedicated MGT permitted-address policy |

## Linux application and rollback

Create a protected output directory and generate both files with `--out DIRECTORY`. On the target, check `sudo nft list ruleset`, back it up in protected storage, and abort if `team_hardening` already exists. Check compatibility with firewalld/UFW and their reload behavior. Run `sudo nft -c -f linux-hardening.nft`, then `sudo nft -f linux-hardening.nft`. Test fresh trusted SSH, untrusted denial, IPv6 SSH denial and each scored service. Roll back with `sudo nft -f linux-rollback.nft`; this deletes only the added table. A trusted accept in this table cannot override a drop in another table. Established sessions are preserved. The rules are runtime only; reboot or another firewall manager may remove them. Do not blindly replace the host's boot ruleset.

For the four kernel controls, preview `python3 scripts/linux_guard.py harden`, apply with `sudo python3 scripts/linux_guard.py harden --apply --backup /root/kernel-before.json`, restore with `sudo python3 scripts/linux_guard.py rollback --apply --backup /root/kernel-before.json`. Use a fresh backup name each time. These settings are runtime only.

## Windows application and rollback

Run the table command in Windows PowerShell 5.1 on Server 2019/2022 or Windows 11. Inspect firewall profiles, GPO and the actual operator source. Apply elevated by adding `-Apply -Backup C:\Secure\firewall-before.wfw` with a fresh path in an operator-protected directory. Disabled firewall profiles cause application to stop; this script does not enable them silently. Verify effective rules in `Get-NetFirewallRule -PolicyStore ActiveStore`, plus real connection tests. Local policy may be ignored by GPO. Rules persist; do not rerun over existing team rules.

The block rule contains the complement of trusted IPv4 CIDRs using supported `-RemoteAddress` ranges, plus `::/0` to deny IPv6 SSH. For the default two trusted networks the blocked ranges are `0.0.0.0-172.16.255.255`, `172.17.1.0-172.20.239.255`, `172.20.241.0-255.255.255.255`. Other ports and outbound policy are unchanged. Existing blocks can still deny trusted sources.

Rollback elevated: `Remove-NetFirewallRule -Name 'TEAM-HARDEN-SSH-ALLOW','TEAM-HARDEN-SSH-MGMT'`. The `.wfw` snapshot is emergency whole-policy recovery (`netsh advfirewall import PATH`), which can overwrite intervening changes. The separate `-Action Rollback -Backup ...` restores audit policy, not firewall policy. For audit enable/restore commands use the assigned host guide.

## VyOS 1.4 application and rollback

The generator uses the sagitta `firewall ipv4 name` and `firewall ipv4 input filter` hierarchy. Inspect `show configuration commands` and local CLI completion. Abort if input rule 1 or `TEAM-HARDEN` exists. This early jump avoids later allow rules bypassing the restriction; trusted/non-SSH traffic continues through existing policy. It covers only IPv4 TCP 22 entering the configured interface (default eth2); it does not claim to secure other interfaces or IPv6. Inventory those before relying on it as a complete router management policy.

Save a baseline, paste the set commands in configuration mode, review `show | diff`, and `commit-confirm 5`. After successful activation test fresh trusted SSH, untrusted denial and downstream services, then `confirm` and `save`. Timeout is five minutes and can reboot by default. Never save an unconfirmed untested policy. Rollback removes input rule 1 before the named chain; use the same commit-confirm, test, confirm, save sequence. Keep console access throughout.

## PAN-OS application and rollback

This plan protects dedicated MGT at 172.20.240.200 using `deviceconfig system permitted-ip`; a transit security rule cannot protect that interface. It restricts HTTPS/API and other management services as well as SSH. IPv6 management sources are excluded because only trusted IPv4 prefixes are configured. Do not apply remotely without console recovery. Check actual workstation source and existing permitted addresses, and retain required official access in the reviewed profile.

Start with a clean candidate (operational `show config diff`); coordinate other administrators. In configuration mode `save config to team-before.xml` (use a unique name and substitute it in recovery), inspect `show deviceconfig system permitted-ip`, then paste the generated commands. If there is no permitted-ip node omit the initial delete. Review with `run show config diff`, run `validate full` and wait for success, then `commit` and wait for completion. Only a committed policy can be connection-tested. Test new trusted SSH/HTTPS and untrusted denial, then scored transit services. Recovery from console: `load config from team-before.xml`, review, `commit`, wait and retest. This snapshot restores the whole candidate; do not overwrite other administrators' work. Protect/export the baseline off-device.

Dataplane interface management is separate: inspect `show network profiles interface-management-profile` and attached interface profiles in configuration mode. Do not apply a broad SSH deny to transit destinations. No transit security, NAT or routing rules are changed by this generator.

## Verification limits

Offline tests check policy generation and input handling. VyOS hierarchy was checked against upstream sagitta interface definitions (`firewall.xml.in`, `ipv4-hook-input.xml.i`, `ipv4-custom-name.xml.i` and their includes). Local schema/completion and successful commit are still required for the installed build. PAN-OS candidate validation and Windows effective policy tests require their target systems; they have not run in this workspace. Backups and validation do not prove end-to-end scoring continuity.

Schema and platform references: [VyOS sagitta firewall definitions](https://github.com/vyos/vyos-1x/blob/sagitta/interface-definitions/firewall.xml.in), [VyOS input hook](https://github.com/vyos/vyos-1x/blob/sagitta/interface-definitions/include/firewall/ipv4-hook-input.xml.i), [Microsoft New-NetFirewallRule parameters](https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule), [PAN-OS management interface settings](https://docs.paloaltonetworks.com/pan-os/11-0/pan-os-admin/getting-started/integrate-the-firewall-into-your-management-network/set-up-network-access-for-external-services).

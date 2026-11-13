# VyOS / Palo Alto Hardening Guide — Router and Boundary Firewall

Candidate hardening area, not a scored service: the packet assigns VyOS (p.13) the role "Router; preserve forwarding, routes and NAT" and Palo Alto (p.13) the role "Boundary firewall; preserve security rules, NAT, routes and management." The goal here is to **harden both devices against an attacker taking them down** (DoS, management takeover, configuration wipe) **without breaking any scored path**. Packet p.14 leaves precise scored services to the event portal; p.17 warns against closing ports based on conventional examples and against scoring-only allowlists.

## Discovery

> **Status:** candidate hardening — the packet confirms both devices exist and their roles, but does not confirm which rules, NAT mappings or rate limits are currently active. Every step below starts from the live configuration, never from guessed defaults. Verify before relying on any step.

### VyOS 1.4.0 (read-only)

```bash
# Identity and interfaces
show version
show interfaces
show ip route
# Full current configuration (protect the output: it may contain secrets)
show configuration commands
# NAT and forwarding state
show nat
show ip traffic   # counters, sample briefly then stop
# DHCP server state on the workstation segment
show dhcp-server
# Any existing firewall rules (do not assume none exist)
show firewall
```

Confirm the three interfaces match the packet: external **172.31.37.2/29** toward core 172.31.37.1, internal **172.16.0.254/24** toward Palo Alto outside 172.16.0.1, workstation **172.17.0.1/24** toward Kali 172.17.0.2. Record the exact NAT rules providing workstation/Kali egress and any port forwards — these are the paths you must keep working.

### Palo Alto PAN-OS 11.0.2 (read-only)

CLI operational mode:

```
show system info
show interface all
show routing route
show session info
show zone
```

GUI: Monitor > Traffic, System, Config; Policies > Security, NAT. Record the **actual** rule order in every policy set — PAN-OS is first-match, so where your new rules land matters as much as what they say. Identify which NAT mappings produce the public 172.25.37.x egress and any port forwards for scored services.

## Setup

No installation steps: both appliances are provisioned by the event. "Setup" here means establishing a safe change procedure:

1. Complete the [event worksheet](../event-checklist.md) and read the [environment constraints](../environment.md).
2. Take the backup described in [Backup](#backup) **before any edit**.
3. Keep an independent console path (NETLAB console for both devices; the Palo Alto management IP **172.20.240.200** is separate from the inside interface 172.20.240.254 and must stay reachable from an authorized inside host).
4. Make one change at a time, verify with the [usage checks](#usage-and-scoring-verification) before the next.
5. Never remove or reorder an existing rule you do not understand; add narrowly-scoped rules instead.

## Configuration

Apply per vendor, in this order: interfaces first (so you know exactly what each rule protects), then recommended rules, then DoS prevention. All examples show **candidate syntax for the installed version** — confirm against on-device help (`?` / GUI help) because 1.4 and 11.0.x differ from older releases.

### VyOS interfaces

```
# Read current state first (config mode), then compare before commit
configure
compare
set interfaces ethernet eth0 address '172.31.37.2/29'      # external — only if discovery shows a mismatch
set interfaces ethernet eth1 address '172.16.0.254/24'     # internal toward Palo Alto
set interfaces ethernet eth2 address '172.17.0.1/24'       # workstation segment
# Preserve: ip forwarding, existing static routes, NAT rules, DHCP server
# Do not rename interfaces or change the DHCP pool without portal confirmation
commit-confirm 5
```

Use `commit-confirm 5` (auto-rollback on timeout) for every commit while hardening; it is the built-in safety net if a rule breaks your own console path.

### VyOS management and firewall changes

VyOS 1.4 uses the `firewall ipv4` configuration tree; older `firewall name` and per-interface firewall attachment examples are not interchangeable. Preserve the current forwarding policy. Do not paste a default-drop ruleset without explicit accepts for every required path. Inspect the active native configuration:

```text
show configuration commands | match firewall
show configuration commands | match service
show configuration commands | match syslog
```

For a concrete collection change that preserves the firewall, use the [VyOS TCP syslog setup](../splunk-data-sources.md#vyos-14). For management SSH changes, inspect `show configuration commands | match "service ssh"`; retain current listen addresses and official access until verified. Use `configure`, `compare`, `commit-confirm 5`, then `confirm` and `save` after validation. `commit-confirm` takes minutes and requires explicit confirmation. Do not apply speculative flood limits during scoring; measure traffic first and use the installed 1.4 firewall command tree and console-tested rollback for a reviewed rule.

### Palo Alto interfaces

Verify, don't reassign: zone membership of inside/outside/management, virtual router assignment, and that the management address is not being treated as an interface address in policies. Record the DHCP/serving state of each zone before touching anything.

### Palo Alto recommended rules

Order matters (first-match). Add at the **bottom** of the security policy unless a rule must precede a permissive one:

1. **Explicit deny with logging** for traffic between zones you have not verified as scored — log-only first, review, then convert to drop if no legitimate flow appears.
2. **Management access restriction**: allow GlobalProtect/HTTPS management (443) and SSH from the authorized inside sources only; deny management from the outside zone. Confirm the current administrator list first so you do not lock yourself out — keep a second console (NETLAB) open during the change.
3. **ICMP**: preserve echo reply for scored ping checks; add a rule allowing ICMP between zones where the packet requires it rather than relying on default behavior.
4. **Preserve** every existing NAT mapping and port forward you identified in Discovery — these carry the public scoring traffic.

### Palo Alto DoS prevention

1. **DoS protection profile**: enable TCP flood (SYN/ACK), UDP flood, and ICMP flood protection with rate limits set from your observed baseline (start permissive, measure, tighten). Apply to the outside zone interfaces.
2. **Session limits**: set a maximum session count and per-source session limits on the outside zone so one source cannot exhaust the session table; keep the global limit above the peak you measured in `show session info`.
3. **SYN proxy / SYN cookies**: enable for the outside zone if the installed 11.0.x supports it on this model — verify in help first.
4. **DNS abuse**: inspect DNS traffic and protect the DNS server against unintended recursion. Apply only supported, measured protection profiles while preserving UDP/TCP scoring queries; no generic RFC-based firewall toggle is assumed.
5. **Logging under load**: enable session event logging for dropped/DoS-flagged sessions so you can distinguish your own hardening drops from an attack in progress.

## Monitoring

### VyOS

```bash
show ip traffic            # per-interface counters — compare before/after any rule change
show firewall              # hit counters on each rule (candidate syntax — verify on device)
show conntrack             # connection table size; a flood shows as rapid growth
show log                   # local syslog; forward to Splunk if the packet's logging path requires it
```

Baseline the counter deltas for 5 minutes at idle, then re-check after any attacker activity or your own scoring tests. A jump in external-interface drops that correlates with a session-table spike is your DoS early warning.

### Palo Alto

```
show session info
show counter global filter delta yes severity drop
show system resources      # CPU/memory; sustained >80% during an event is a takeover risk
```

GUI: Monitor > Traffic (session trends), Monitor > System. Forward threat and traffic logs to Splunk and use the shared [Splunk threat hunting](../splunk-threat-hunting.md) searches, adapted to PAN-OS field names (discover with `| fieldsummary` in a bounded search before trusting any detection).

Alert on: session count approaching your configured maximum; DoS profile hit counts rising; management-login failures from outside-zone sources; CPU above baseline.

## Backup

**No VM snapshots** (environment constraint). Configuration is the state; back it up before every change and retain timestamped copies on a protected path.

### VyOS

```bash
# Export the running configuration to a file you control, then verify it contains the current state
show configuration commands > /home/<admin>/vyos-config-<UTC-timestamp>.txt
# On the appliance, use the supported save path (verify with `show help`) to persist the current config image
# Keep at least: (1) pre-hardening baseline, (2) post-change state. Retain both until the event ends.
```

Protect the export — it may contain secrets. Test the restore path in a safe window: load the baseline file on a non-event day and confirm `compare` is empty.

### Palo Alto

GUI: Device > Setup > Operations > **Configuration Backup** (create a named backup with a timestamp in the name). CLI:

```
configure
save config to pre-change.xml
exit
scp export configuration from pre-change.xml to backupuser@BACKUP_HOST:/protected/path/pre-change.xml
```

The CLI example saves the **candidate** configuration: review pending edits first and ensure this snapshot represents the intended known-good state. Replace the backup host/user/path; protect exports and use a unique filename for each backup. Do not treat an HA synchronization command as a backup.

Also export **device state** (Device > Setup > Operations > Device State) so you can restore licenses, certificates and admin accounts, not just policy. Retain at least one pre-hardening backup until the event ends; verify it opens in the restore dialog before relying on it.

## Usage and scoring verification

Hardening is only acceptable if every scored path still works end-to-end. After each rule change:

1. **Public egress**: from Ubuntu Wkst and Windows 11 Wks, confirm outbound TCP 80/443 to the public internet still succeeds (shared egress via 172.31.37.2 must be intact).
2. **Kali path**: from Kali 172.17.0.2, run one bounded authorized check per scored service type (HTTP, mail, DNS, SSH, Splunk query) using the [service guides](README.md) — a TCP connect is not enough; complete the functional check.
3. **ICMP**: ping the VyOS external address and the Palo Alto inside interface from an authorized host; echo reply must still be answered (scored check type).
4. **Management**: confirm you can still reach the Palo Alto GUI at 172.20.240.200 from an authorized inside host and the VyOS CLI via NETLAB console.
5. **Quotient**: confirm the scored checks show their expected status after each change; record results in the [functional verification sheet](../event-checklist.md#functional-scoring-verification).

If any check regresses, revert the last rule immediately (VyOS: `rollback 1`; PAN-OS: restore the pre-change backup) before diagnosing.

## Recovery

1. **Device unreachable via network but console works**: you broke a rule or interface config. VyOS: `rollback 1` (or load the baseline file) then `commit-confirm 5`. PAN-OS: restore the pre-change configuration backup from Device > Setup > Operations, then commit.
2. **Both paths lost (console and network)**: use NETLAB console on both devices; VyOS can be rolled back to the previous boot image per its [image workflow](../systems/vyos.md); PAN-OS can boot the previous configuration via console mode if the running config is corrupted.
3. **DoS in progress**: identify the source from session/conntrack counters and the Splunk searches; apply a targeted drop for that source (evidence-backed, p.17) rather than broad restrictions; verify scored paths still pass after the drop.
4. **Management takeover suspected**: change administrator credentials through the approved interactive path with a second console open, disable unused management services, and record UTC time and residual exposure in the [event worksheet](../event-checklist.md).
5. After any recovery, re-run the full [usage verification](#usage-and-scoring-verification) list and re-take backups.

## References

- [VyOS system guide](../systems/vyos.md) — includes the VyOS 1.4 image/rollback and advisory references checked 2026-11-13
- [Palo Alto system guide](../systems/palo-alto.md) — includes the PAN-OS 11.0 upgrade-path and CVE references checked 2026-11-13
- [Environment constraints](../environment.md)
- [Event checklist](../event-checklist.md)
- [Splunk threat hunting (shared)](../splunk-threat-hunting.md)

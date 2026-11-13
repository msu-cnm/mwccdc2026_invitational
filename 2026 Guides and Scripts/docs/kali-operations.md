# Kali Operations Guide

This document describes `scripts/kali_watch.py`, a Python tool for authorized network mapping, exposure assessment, and service monitoring on your Kali workstation during the CCDC competition.

---

## 1. Purpose and Scope

**What this tool does:**
- Maps open ports via TCP connect scans (Nmap)
- Collects passive greeting banners from enabled listeners (exposure mode)
- Monitors TCP and optional HTTP(S) health checks over time

**What it does NOT do:**
- No exploits, brute-force attempts, or intrusive NSE scripts
- No CVE inference from banners (backported fixes make banner claims unreliable)
- No scanning of other teams, officials, core infrastructure (VyOS, Palo Alto), or Red Team assets
- No response bodies stored in output or reports

**Plan mode is the default.** Use `--execute` flag for any network activity.

---

## 2. Dependencies

Python 3 standard library only: `argparse`, `json`, `socket`, `ssl`, `subprocess`, `xml.etree.ElementTree`, `urllib.request`.

- **Nmap** is required for `map` mode only. Install with `sudo apt-get install nmap`.
- Exposure and monitor modes use only the Python stdlib.

---

## 3. Configuration

Copy `config/kali-checks.example.json` to `config/kali-checks.json` and edit:

Set `target_scope` to `internal` or `public`; only that list is probed. HTTP endpoints must match an enabled target and its configured port. Public addresses must belong to the assigned team. The example explicitly selects internal inventory. Service monitoring and banner reads skip disabled targets; map still inventories configured ports after explicit execution.

### `team`
- Type: `null` or integer 1-20
- Required for public target validation
- Public targets compute as `172.25.(20+team).N` where N is the target index

### `internal_targets[]`
Structure per target:
```json
{
  "id": "server-name",
  "ip": "172.20.240.XX",   // Exact IPv4, no CIDR/hostname
  "ports": [80, 443],      // Integer list 1-65535
  "service_checks_enabled": false
}
```

### `public_targets[]`
Same structure as internal targets. Addresses computed as `172.25.(20+team).N`.
Fill in **after confirming live team assignment**. Exclude other teams' addresses and core infrastructure.

### `http_checks[]`
Structure per check:
```json
{
  "url": "http://172.20.240.XX/endpoint",
  "expected_status": 200,    // Optional
  "expected_content": "Welcome",   // Optional
  "sni_hostname": "gateway.netlab.local"   // Optional: SNI for IP-scoped HTTPS
}
```
- No credentials in URLs
- Response bodies are not stored
- Redirects are never followed (reported as state `redirect`)
- For IP-scoped HTTPS checks whose certificate is issued to a virtual-host name, set `sni_hostname` so the TLS handshake advertises that name instead of the IP address

### `timeouts`
```json
{
  "connect_seconds": 3,     // Range: 1-60
  "read_seconds": 5         // Range: 1-60
}
```

### `probe_limits`
```json
{
  "max_parallel": 1,        // Range: 1-8
  "delay_ms": 200           // Range: 0-60000
}
```

**Protected networks:** The script rejects `172.17.0.x` (Kali/VyOS internal) and `172.31.x` (core infrastructure and shared egress), router transit and Palo Alto management addresses.

---

## 4. Usage Examples

### Plan mode (default, no network activity)
```bash
python3 scripts/kali_watch.py map --config config/kali-checks.json
python3 scripts/kali_watch.py exposure --config config/kali-checks.json
python3 scripts/kali_watch.py monitor --config config/kali-checks.json
```

### Execute mode (performs probes only)
```bash
python3 scripts/kali_watch.py map --config config/kali-checks.json --execute
python3 scripts/kali_watch.py exposure --config config/kali-checks.json --execute
python3 scripts/kali_watch.py monitor --config config/kali-checks.json --execute --repeat 5
```

### JSON output structure
- **map mode:** `{"status": "<open|closed|filtered|unknown>", "port": <int>, "state": ...}` plus Nmap XML parsing results
- **exposure mode:** findings with `status: observed` or `skipped`, target, port and optional `banner`; collection errors exit 2.
- **monitor mode:** timestamped `passes`, each containing checks with `latency_ms` and `state` (`up`, `down`, `ok`, `mismatch`, `redirect`, or `error`).

### Exit codes
- `0` = successful plan or healthy completed checks
- `1` = unhealthy findings detected
- `2` = invalid configuration or collection error (errors take precedence), including monitor execution with no enabled checks.

---

## 5. Map Mode Details

Performs Nmap TCP connect scan (`-sT`) on explicit ports only. Uses `-n -Pn` flags with bounded timing: `--max-retries 2`, `--host-timeout 30s`, configured parallelism and delay, and a maximum rate of 10 probes/second. XML output is parsed in-process. Reports open/closed/filtered/unknown states distinctly. Discovery failure is a collection error, not host absence.

---

## 6. Exposure Mode Details

Bounded passive banner reads on enabled targets and configured ports. Services that require a client greeting may return no banner. Reports greeting strings as investigation leads; compare map snapshots to a reviewed expected-listener baseline to identify unexpected listeners. Does **NOT** infer CVEs or patch status from banners. Excludes exploit scripts, brute-force attempts, intrusive NSE, and UDP sweeps.

---

## 7. Monitor Mode Details

Bounded TCP connect checks plus optional HTTP(S) checks. One-pass by default; `--repeat N` for bounded repeated mode (range: 1-20). TLS verified by default for HTTPS; SNI preserved for IP-scoped checks; redirects reported but not followed. No credentials in URLs, no response bodies in output. Output includes UTC timestamp, latency, per-check state — JSON suitable for Splunk ingestion.

---

## 8. Conservative Scheduling

- Run map/exposure once at event start and after injects
- Monitor every 5-10 minutes during scoring windows
- Use `--repeat 3` max for repeated checks
- Never run during critical scoring moments without operator approval
- Coordinate with the event worksheet

---

## 9. Report Storage

Save JSON output to operator-only directories (700 permissions), timestamped filenames, bounded retention. Do not include credentials or response bodies in stored reports. Keep independent protected copies.

---

## 10. Baseline Comparison

Save the first map/exposure run as a baseline. Compare subsequent runs for:
- New open ports
- Changed service versions
- New listeners

Investigate changes before attributing them to an inject.

---

## 11. Exposure Triage

When exposure mode reports a version string, cross-reference with vendor advisories (Microsoft, Oracle, Apache, etc.) using the actual package/build info from the target system. Banner-based claims are unreliable due to backported fixes. Record: observed version, package name, build date, vendor advisory ID, applicability assessment. Never state a CVE is confirmed without package-level verification.

---

## 12. Monitoring Limitations

- TCP success does not establish authenticated scoring success
- HTTP 200 does not confirm content correctness
- Redirects may mask service degradation
- DNS resolution and NAT can cause false negatives
- Always verify with the actual scoring workflow (authenticated query, content check, etc.) before concluding a service is healthy

---

## 13. Safety Constraints

**Never scan:**
- Other teams
- Officials
- Core infrastructure (VyOS, Palo Alto)
- Red Team assets

The script rejects `172.17.0.x` and `172.31.x` ranges, router transit and Palo Alto management addresses. Lightweight version probes can affect fragile services; use explicit execution, bounded rates, and authorized rehearsal only.

---

## References

- [Kali system guide](systems/kali.md)
- [Environment constraints](environment.md)
- [Event worksheet](event-checklist.md)
- [Splunk threat hunting guide](splunk-threat-hunting.md)
- [Validation status](validation.md)

Checks originate from Kali at 172.17.0.2 behind VyOS. Record this observation path with reports: routing, NAT and filtering can affect internal and public results. A timeout cannot establish host absence. No DNS resolution is used for endpoints; optional HTTPS names affect Host, SNI and verified certificate identity only. Environment proxies are disabled.

`--repeat` performs consecutive passes with per-TCP-check delay, not a timed monitoring schedule. Use an operator-controlled scheduler for 5–10 minute intervals after rehearsal. All-disabled example targets are safe for plans; executing monitor without checks exits 2, never healthy.

Splunk output is nested (`passes[]` contains `checks[]`), not flat events. Extract/expand each pass and check with JSON parsing before charting target, state and latency; preserve pass time. The emitted hint describes this nesting; it does not configure ingestion. See the shared Splunk guide for source validation.

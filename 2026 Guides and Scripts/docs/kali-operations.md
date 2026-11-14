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

**Safety constraints:** Never scan other teams, officials, core infrastructure (VyOS, Palo Alto), or Red Team assets. The script rejects `172.17.0.x` (Kali/VyOS internal), `172.31.x` (core infrastructure and shared egress), router transit and Palo Alto management addresses. Lightweight version probes can affect fragile services; use explicit execution, bounded rates, and authorized rehearsal only.

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

### Internal scope example (plan by default, execute with --execute)
```bash
# Plan only (no network activity)
python3 scripts/kali_watch.py map --config config/kali-checks.json
python3 scripts/kali_watch.py exposure --config config/kali-checks.json
python3 scripts/kali_watch.py monitor --config config/kali-checks.json

# Execute with explicit authorization
python3 scripts/kali_watch.py map --config config/kali-checks.json --execute
python3 scripts/kali_watch.py exposure --config config/kali-checks.json --execute
python3 scripts/kali_watch.py monitor --config config/kali-checks.json --execute --repeat 5
```

### Public scope example (plan by default, execute with --execute)
For team 17 (N=37):
```bash
# Plan only (no network activity)
python3 scripts/kali_watch.py map --config config/kali-checks-public.json
python3 scripts/kali_watch.py exposure --config config/kali-checks-public.json
python3 scripts/kali_watch.py monitor --config config/kali-checks-public.json

# Execute with explicit authorization
python3 scripts/kali_watch.py map --config config/kali-checks-public.json --execute
python3 scripts/kali_watch.py exposure --config config/kali-checks-public.json --execute
python3 scripts/kali_watch.py monitor --config config/kali-checks-public.json --execute --repeat 5
```

### Activate a discovered endpoint in either scope

The shipped example has all service checks disabled and an empty `http_checks` array. Confirm team 17, the current addresses/NAT exposure, listeners, HTTP path, expected status/content, and HTTPS certificate name with the service owner first. Candidate lists include FTP/SSH on Rocky and Ubuntu mail, SSH on SQL/AD/Splunk, SMTP 25/465/587, POP/IMAP 110/143/993/995, and AD TCP 53/88/135/389/445/464/636/3268/3269. RPC dynamic ports and named SQL instance ports require separate discovery. These lists do not confirm listeners.

Run from the repository root. This creates an internal configuration enabling only the two **confirmed** Rocky web ports. Enter the discovered values when prompted; do not accept guessed endpoints:

```bash
umask 077
export WATCH_SCOPE=internal
read -r -p 'Confirmed HTTP/HTTPS path (e.g. /health): ' WATCH_PATH
read -r -p 'Confirmed expected content: ' WATCH_CONTENT
read -r -p 'Verified certificate DNS name: ' WATCH_TLS_NAME
export WATCH_PATH WATCH_CONTENT WATCH_TLS_NAME
python3 - <<'PYCONFIG'
import json, os
from pathlib import Path
scope = os.environ['WATCH_SCOPE']
cfg = json.loads(Path('config/kali-checks.example.json').read_text())
cfg['target_scope'] = scope
# Keep every other target disabled; replace candidates with confirmed listeners.
target = cfg[scope + '_targets'][0]
target['ports'] = [80, 443]
target['service_checks_enabled'] = True
cfg['http_checks'] = [
    dict(url='http://' + target['ip'] + os.environ['WATCH_PATH'],
         expected_status=200, expected_content=os.environ['WATCH_CONTENT']),
    dict(url='https://' + target['ip'] + os.environ['WATCH_PATH'],
         sni_hostname=os.environ['WATCH_TLS_NAME'],
         expected_status=200, expected_content=os.environ['WATCH_CONTENT'])]
Path('config/kali-checks-' + scope + '.json').write_text(json.dumps(cfg, indent=2) + '\n')
PYCONFIG
python3 scripts/kali_watch.py monitor --config config/kali-checks-internal.json
```

For public activation, confirm the public endpoint independently, set `export WATCH_SCOPE=public`, and rerun the prompts and Python block with the public service's discovered values. This selects the public list **and replaces HTTP endpoints together**; it does not retain internal URLs. Review with `monitor --config config/kali-checks-public.json` before any `--execute`. Use the generated internal filename in the internal usage commands above. To enable other hosts, set their selected-scope flag to true and replace their candidate ports with only confirmed TCP listeners. Change port numbers and expected status in the block if discovery found different values.

The separate `tests/fixtures/kali-http-internal.json` and `kali-http-public.json` demonstrate activated HTTP/content and HTTPS/SNI configurations for offline tests only. Their names, paths and content are illustrative; they are not live assignments.

### Mode details

**Map:** Nmap TCP connect scan (`-sT`) on explicit ports only, with `-n -Pn` and bounded timing: `--max-retries 2`, `--host-timeout 30s`, configured parallelism and delay, and a maximum rate of 10 probes/second. XML output is parsed in-process. Reports open/closed/filtered/unknown states distinctly; discovery failure is a collection error, not host absence.

**Exposure:** Bounded passive banner reads on enabled targets and configured ports. Services that require a client greeting may return no banner. Reports greeting strings as investigation leads; compare map snapshots to a reviewed expected-listener baseline to identify unexpected listeners. Does **NOT** infer CVEs or patch status from banners. Excludes exploit scripts, brute-force attempts, intrusive NSE, and UDP sweeps.

**Monitor:** Bounded TCP connect checks plus optional HTTP(S) checks. One pass by default; `--repeat N` for bounded repeated mode (range: 1-20). TLS verified by default for HTTPS; SNI preserved for IP-scoped checks; redirects reported but not followed. No credentials in URLs, no response bodies in output. Output includes UTC timestamp, latency, and per-check state — JSON suitable for Splunk ingestion.

### Output structure
- **map mode:** `{"status": "<open|closed|filtered|unknown>", "port": <int>, "state": ...}` plus Nmap XML parsing results
- **exposure mode:** findings with `status: observed` or `skipped`, target, port and optional `banner`; collection errors exit 2.
- **monitor mode:** timestamped `passes`, each containing checks with `latency_ms` and `state` (`up`, `down`, `ok`, `mismatch`, `redirect`, or `error`).

---

## 5. Plan vs Execute Modes

**Plan mode (`--execute` not set):** Generates a plan without any network activity. Useful for:
- Reviewing all configured targets before execution
- Verifying authorization with your team lead
- Confirming target addresses match the event worksheet
- Inspecting HTTP check URLs and expected content

**Execute mode (`--execute` set):** Performs actual probes after complete configuration validation. Uses bounded rates (max 10 probes/second) and respects `probe_limits.max_parallel`.

---

## 6. Bounded Repeats vs Real Scheduling

**`--repeat N` performs consecutive passes with per-TCP-check delay, NOT a timed monitoring schedule:**
- `--repeat 1`: Single pass through all targets
- `--repeat 5`: Five consecutive passes (recommended for bounded stress testing)
- Maximum allowed: `--repeat 20`

**For real continuous monitoring:** Use an operator-controlled scheduler to run `monitor --execute --repeat 3` every 5-10 minutes. The script does not implement automatic re-scheduling; it only performs the requested number of passes.

**Conservative scheduling guidance:**
- Run map/exposure once at event start and after injects
- Monitor every 5-10 minutes during scoring windows
- Use `--repeat 3` max for repeated checks
- Never run during critical scoring moments without operator approval
- Coordinate with the event worksheet

All-disabled example targets are safe for plans; executing monitor without checks exits 2, never healthy.

### Baseline comparison
Save the first map/exposure run as a baseline. Compare subsequent runs for:
- New open ports
- Changed service versions
- New listeners

Investigate changes before attributing them to an inject.

### Exposure triage
When exposure mode reports a version string, cross-reference with vendor advisories (Microsoft, Oracle, Apache, etc.) using the actual package/build info from the target system. Banner-based claims are unreliable due to backported fixes. Record: observed version, package name, build date, vendor advisory ID, applicability assessment. Never state a CVE is confirmed without package-level verification.

---

## 7. HTTP/HTTPS Check Details

### Relationship between enabled targets and HTTP validation
- Each HTTP endpoint IP and port must match a target with `service_checks_enabled: true` in the selected scope; otherwise configuration validation exits 2 before probing.
- Add the endpoint port to that enabled target and add the URL to `http_checks[]` together.
- Switching scope also requires replacing HTTP endpoints with enabled targets in the new scope; the activation block above does both.

### Example: HTTP content check on Rocky Ecom
```json
{
  "url": "http://172.20.240.10/",
  "expected_status": 200,
  "expected_content": "Welcome"
}
```

### Example: HTTPS/SNI check (certificate issued to virtual-host name)
```json
{
  "url": "https://172.25.37.20/",
  "sni_hostname": "splunk.internal",
  "expected_status": 200,
  "expected_content": "Splunk"
}
```

### Limitations of HTTP checks
- No credentials in URLs (authentication is not performed)
- Response bodies are not stored
- Redirects are never followed (reported as state `redirect`)
- Certificate validation is enabled by default (TLS trust required)
- TLS errors cause the check to fail with state `error`

---

## 8. Protected Timestamped Result Storage

Save JSON output to operator-only directories with timestamped filenames for Splunk file monitoring:
Run under a dedicated operator account from the repo root; use an operator-owned parent directory. For example, an administrator can provision it once with `sudo install -d -m 0700 -o "$(id -un)" -g "$(id -gn)" /srv/kali-results`. On **each invocation**, use:

```bash
umask 077
install -d -m 0700 /srv/kali-results
stamp=$(date -u +%Y%m%dT%H%M%S%NZ)
tmp=$(mktemp /srv/kali-results/.monitor-XXXXXXXX.tmp)
rc=0
python3 scripts/kali_watch.py monitor --config config/kali-checks-internal.json \
    --execute --repeat 3 > "$tmp" || rc=$?
# Publish only complete valid JSON; preserve unhealthy/collection-error results too.
if python3 -m json.tool "$tmp" > /dev/null; then
    mv -- "$tmp" "/srv/kali-results/monitor-$stamp.json"
else
    rm -f -- "$tmp"
    rc=2
fi
printf 'Monitor exit code: %s\n' "$rc"
```

The temporary file does not match the Splunk `*.json` monitor; rename publishes the completed document on the same filesystem. Each invocation generates a fresh timestamp and temporary file. Keep completed files immutable and apply a reviewed retention limit (for example 24 hours, allowing time for ingestion). Directory mode 0700 and files created under umask 077 protect results from creation onward. Grant the Splunk service account only the needed directory traversal and file read access through a reviewed group/ACL, including future files; verify with that identity before claiming ingestion. Do not make the directory or results world-readable. Configure ingestion and event framing using [the Kali result collection recipe](splunk-data-sources.md#kali-nested-json-result-ingestion).

### Splunk ingestion pattern
The output structure is nested: `passes[]` contains `checks[]`. For Splunk file monitoring:
```json
{
  "protocol": "kali-watch/1.0",
  "mode": "monitor",
  "time_utc": "2026-11-01T12:00:00Z",
  "passes": [
    {
      "time_utc": "2026-11-01T12:00:00Z",
      "checks": [
        {
          "target": "rocky-ecom-public",
          "ip": "172.25.37.10",
          "port": 80,
          "state": "up",
          "latency_ms": 45
        }
      ]
    }
  ],
  "note": "TCP success does not establish authenticated scoring success"
}
```

---

## 9. Exit Codes

- `0` = successful plan or healthy completed checks
- `1` = unhealthy findings detected (down/mismatch/redirect)
- `2` = invalid configuration or collection error, including monitor execution with no enabled checks

---

## 10. TCP-only and Unauthenticated Check Limitations

**TCP-only limitation:**
- Only TCP ports are probed; this tool has no UDP or ICMP checks. Validate UDP DNS, UDP Kerberos and SQL Browser UDP 1434 using separate approved tools.
- Port 1434 is absent from the example. Add it only if a TCP listener is actually discovered; the tool does not automatically distinguish UDP-only ports.

**Unauthenticated check limitation:**
- No credentials are sent in HTTP checks
- SSH, FTP, and database checks require separate authentication tools
- TCP success does not establish authenticated scoring success
- HTTP 200 does not confirm content correctness
- Redirects may mask service degradation
- DNS resolution and NAT can cause false negatives
- Always verify with the actual scoring workflow (authenticated query, content check, etc.) before concluding a service is healthy

---

## 11. TLS Trust Prerequisites

**Certificate validation is enabled by default for HTTPS checks.** To use IP-scoped HTTPS whose certificate is issued to a virtual-host name:
```json
{
  "url": "https://172.25.37.20/",
  "sni_hostname": "debian-splunk.netlab.local"
}
```

The TLS handshake advertises the SNI hostname, and the certificate is validated against that name. Verify the certificate chain, SAN name and clock first. Install the approved lab CA in the system trust store, or run with `SSL_CERT_FILE=/absolute/path/to/approved-ca-bundle.pem python3 scripts/kali_watch.py monitor --config config/kali-checks-public.json --execute` after confirming that bundle validates the full chain. Protect the CA bundle from modification. Do not disable certificate validation.

---

## 12. References

- [Kali system guide](systems/kali.md)
- [Environment constraints](environment.md)
- [Event worksheet](event-checklist.md)
- [Splunk threat hunting guide](splunk-threat-hunting.md)
- [Validation status](validation.md)

Checks originate from Kali at 172.17.0.2 behind VyOS. Record this observation path with reports: routing, NAT and filtering can affect internal and public results. A timeout cannot establish host absence. No DNS resolution is used for endpoints; optional HTTPS names affect Host, SNI and verified certificate identity only. Environment proxies are disabled.

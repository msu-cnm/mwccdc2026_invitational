# Student event toolkit

Run these commands from the repository root with Python 3. They work offline except for the existing monitoring tools when explicitly executed. Assign one operator to evidence collection and one to review the report before submission. Keep original evidence unchanged in an operator-only directory; use the event's approved channel to share it.

## Prepare addresses and searches

```bash
python3 scripts/team_addresses.py --team 7
python3 scripts/iot_query_builder.py ip 192.0.2.10 --index team_security --earliest=-30m
python3 scripts/iot_query_builder.py process suspicious.exe --output queries.md
```

Replace team 7 with your assigned team. The address helper prints the packet-derived map; verify it against the portal and existing interfaces before using it. It does not change configurations. The IOC examples are illustrative, not evidence of compromise. Replace the IOC and index with confirmed values. Paste generated searches into Splunk and verify sourcetypes, field extraction and collection using the [hunting guide](splunk-threat-hunting.md). No results can mean missing telemetry. Absolute ISO 8601 search times are emitted as epoch seconds; timestamps without a timezone are interpreted as UTC. Relative times remain unchanged. The builder's filename is `iot_query_builder.py` despite its IOC purpose.

## Assemble a timeline

Use the [poller instructions](inject-response-playbook.md) to collect bounded evidence. Select specific JSON files from Splunk poll or Kali watch; do not pass configuration files or the poller's state file as evidence. Manual notes can use this shape:

```json
[{"timestamp":"2026-11-13T12:00:00Z","source":"operator","message":"Observed service failure; referenced evidence file check-01.json"}]
```

```bash
python3 scripts/evidence_timeline.py evidence/poll-01.json evidence/check-01.json --output timeline.md
python3 scripts/evidence_timeline.py evidence/poll-01.json evidence/check-01.json --output timeline.md --execute --json
```

The first command only plans. The second writes the timeline. Exit 1 means unknown timestamps need review; exit 2 means an input or output error. Events are sorted in UTC. Messages are shortened to 200 characters: retain and review the original JSON for full details. The timeline does not redact secrets; protect its destination directory and review before sharing. Output overwrites an existing timeline, so use a unique filename per incident.

## Draft and review a report

Copy [the JSON template](../config/incident-report.example.json) to a protected working directory and replace every example value, including the example port. Record unavailable facts explicitly as unknown; never invent an event ID, hash or scoring result. Compute evidence hashes locally with `sha256sum evidence/poll-01.json` on Linux or `Get-FileHash evidence\poll-01.json -Algorithm SHA256` on Windows.

```bash
python3 scripts/incident_report.py --input incident.json
python3 scripts/incident_report.py --input incident.json --write report.md --json
```

The first command prints Markdown. The second writes Markdown and prints a JSON summary with the number of redacted occurrences. Existing reports are backed up to `report.md.bak`; an existing backup is replaced. On POSIX systems both files are created with mode 0600; output and backup symlinks are rejected. On Windows use a directory with operator-only NTFS permissions. Validation checks required structure, not factual completeness, timestamp correctness or whether placeholders have been replaced.

Secret assignment masking includes passwords, tokens, API keys, `private_key` and `sessionkey`. Automated masking is heuristic: manually inspect the entire report and backup for sensitive material before submission. Original input and evidence remain sensitive. Review impact, actions, service recovery and actual scoring evidence with the host operator, then submit through the event portal using the [event checklist](event-checklist.md).

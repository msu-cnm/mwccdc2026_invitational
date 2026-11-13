# Validation and remaining acceptance work

Rerun on 2026-11-13 in the supplied development checkout:

- `python3 -m unittest discover -s tests -v`: 7 tests pass. Kernel operations are mocked; no development or event kernel settings were changed. Tests cover dry-run non-mutation, exclusive/restricted backup creation, repeat-application rejection, repeated rollback, partial-apply failure recovery, invalid backup/CLI rejection, narrow setting scope and exact 10-guide coverage against the packet transcription.
- `python3 -m py_compile scripts/linux_guard.py`: passes.
- `python3 scripts/linux_guard.py harden`: passes, prints proposed values without writing them.

No existing repository test framework was present. PowerShell is not installed here. Windows parsing and runtime behavior, appliance commands on actual firmware, public service connectivity, authenticated scoring workflows and recovery have **not** been exercised. Do not interpret offline tests as event readiness. The supplied GitHub URL and pinned revision were verified through the browser. One AD script was reviewed; full restoration/inventory remains blocked by download and directory-browsing restrictions. See [source review](prior-year-review.md).

## Disposable-system rehearsal required before use

Provision representative OS versions outside the live competition using only authorized fixtures; include representative application versions and traffic. Do not alter live competition systems for acceptance tests. Never use actual scoring credentials in test fixtures.

1. Linux: collect assessment, run preview and compare kernel values/configuration hashes before/after; confirm no changes. Apply with a new backup, verify all four values, confirm listeners, ICMP, SSH authentication, application content and dependency connectivity are unchanged. Reapply using the same backup and confirm safe rejection. Roll back twice and compare original values. Simulate denied kernel writes in an isolated test environment and check automatic restoration. Reboot and verify runtime protections revert as expected.
2. Windows: parse with Windows PowerShell 5.1, then run Assess and preview on Server 2019, Server 2022 (domain controller) and Windows 11. Capture `auditpol /get /category:* /r` before/after preview and verify equality. Apply to a new protected backup path, confirm Logon success/failure auditing while other categories match baseline. Repeat with the same backup and verify rejection. Roll back twice and compare full policy; test failed backup/denied privilege paths and GPO refresh. Verify assessment with no matching events and investigate inaccessible event logs. Check event volume and retention.
3. Traffic: for each actual portal check, exercise the exact public endpoint with intended authentication and content/query. Exercise internal DB/domain/DNS/time/mail/ingestion dependencies, ICMP, management and return traffic. Use multiple authorized source paths to demonstrate general availability; never scan other teams or official assets. Test HTTP/HTTPS bodies, mail send/retrieve, FTP control/data, TCP and UDP DNS, SSH login and Splunk query only where assigned. A port probe alone is insufficient.
4. Appliances: export and restore native configuration in disposable equivalents; validate real candidate syntax and commit/rollback. Verify NAT and routing, public checks, workstation egress, management and ICMP before and after. No automated firewall mutation exists in this change.
5. Record host/build, fixture, commands, baseline/result, rollback result, operator and UTC timestamp. Resolve failures before event application. New inject requirements require an updated worksheet and renewed relevant tests.

## Requested artifact checks

The earlier handoff reports three Bash artifact checks, but their exact commands are not present in this checkout. The source directory is still empty, so the populated `mwccdc2026_invitational` requirement remains unsatisfied. It has not been replaced with invented files to make the check pass. Its pinned Git commit and configuration are unchanged. Completion requires restoring actual source and finishing the prior-year review, followed by representative rehearsal above. The URL is now known; working Git/archive download access or a complete source archive is still required.


## Expanded guide checks (2026-11-13)

The ten machine playbooks and [shared Splunk guide](splunk-threat-hunting.md) document discovery, possible exposure, manual remediation/recovery, compensating detection and local hunts. New `tests/test_guides.py` uses the topology inventory to check the six agreed nonempty sections, per-host SPL fences and shared links, dated external references, all ten IDs in the central guide, README navigation and relative Markdown file targets in the changed documentation. Existing guard tests and scripts are unchanged.

Acceptance commands, from the repository root in Bash:

```bash
python3 -m unittest discover -s tests -v
python3 -m unittest discover -s tests -p test_guides.py -v
git diff --check
```

Final run on 2026-11-13: full discovery passed **11 tests**; the guide-only command passed **4 tests**; `git diff --check` exited **0**.

These checks establish documentation structure and local link integrity only. They do not check external URLs, advisory applicability, source accuracy, command syntax on installed firmware, SQL or Windows behavior, field extraction, SPL execution, alert scheduling, ingestion or live scoring availability. Official sources were reviewed through the web research tool where recorded in each guide; live build/feature comparison and vendor backport checks remain required. Shell URL retrieval was blocked by the workspace proxy. Review the source documents, commands, scoring dependencies, telemetry prerequisites and search substitutions manually before use. The lookup-backed silence check requires an explicit populated expected-host inventory; it is not deployed by these docs.

## Kali watch tooling checks (2026-11-13)

New `scripts/kali_watch.py` with plan-first `map`, `exposure`, and `monitor` subcommands. New `config/kali-checks.example.json` with five fixed server addresses as provisional inventory (service checks disabled). New `tests/test_kali_watch.py` covers configuration rejection before probes, team boundaries and address calculation, preview making no network/subprocess calls, exact Nmap arguments, XML state parsing, all collection-error paths, monitor state and exit aggregation, TLS/redirect boundaries, finite repetition, and secret-free output.

Acceptance commands, from the repository root in Bash:

```bash
python3 -m unittest discover -s tests -p test_kali_watch.py -v
python3 -m unittest discover -s tests -v
python3 -m py_compile scripts/kali_watch.py
python3 scripts/kali_watch.py --help
python3 scripts/kali_watch.py map --config config/kali-checks.example.json
python3 scripts/kali_watch.py exposure --config config/kali-checks.example.json
python3 scripts/kali_watch.py monitor --config config/kali-checks.example.json
git diff --check
```

Final run on 2026-11-13: kali-watch tests passed **40 tests**; full suite passed **51 tests**; `py_compile` passes; all three plan-mode invocations exit 0 with readable JSON plans; `--help` exits 0; `git diff --check` exits **0**.

These checks establish offline behavior, configuration validation, Nmap argument construction, XML parsing, and exit-code semantics only. They do not establish live reachability, authenticated scoring success, actual service availability, or event readiness. Nmap is required for map mode; exposure and monitor use the Python standard library. Live rehearsal on authorized disposable systems remains required before event use.

No new logging, agents, receivers, firewall changes, updates, exploit demonstrations or live-system tests were performed. Rehearse the shared guide's sanitized fixtures on authorized disposable systems. Keep independent protected evidence if the monitoring host could be compromised. Existing prior-year checkout restrictions and the source-restoration blocker above remain unchanged; these documentation checks do not resolve that earlier requirement.

### Authorized Kali rehearsal (not performed)

1. Confirm team number, explicit internal/public scope, assigned server addresses, actual ports and HTTP expectations in the worksheet. Keep provisional checks disabled until confirmed.
2. On authorized disposable equivalents, install Nmap and review all three plans. Record Kali's source address, routing/NAT path and UTC time.
3. Execute each mode with conservative limits; compare open/closed/filtered observations with known fixtures. Exercise missing Nmap, blocked routing and unavailable services.
4. Verify HTTPS with a trusted certificate and virtual-host name while connecting only to the configured IP; confirm invalid certificates fail and redirects are reported without a second request.
5. Compare a protected baseline and rehearse finite monitoring. Independently verify authenticated scoring workflows; TCP/HTTP observations alone cannot establish scoring success.

The latest offline regression checks additionally cover valid public addresses for teams 1 and 20, rejection of core infrastructure, HTTP endpoint scope, the actual HTTPS connection class and SNI wrapping, redirect refusal and omission of expected response content from plans. No live probes were run.

## Packet re-review (2026-11-13)

See [packet coverage audit](packet-audit.md) for requirements, code-level scope, scoring gaps and specific missing inputs. All 23 pages were read via local PDF extraction with pp.12–13 image tables inspected; document tools were unavailable. This review adds startup, functional scoring and inject-submission worksheets, corrects the free-or-open-source rule and documents protocol/monitoring limits.

Fixed Kali monitor's zero-observation false success: executing with all checks disabled now exits 2 with collection_error; preview remains available. Added a mocked regression proving no probe runs in that case. Corrected its Splunk hint to describe nested arrays.

Verification: full unittest discovery passes **52 tests**; both Python scripts compile; Linux harden preview and all three Kali example plans exit 0; `git diff --check` passes. No application, network probe, kernel write, password change or firewall change was executed. Existing Windows/appliance, authenticated public scoring, full prior-year source review and restore rehearsal gaps above remain open. Tests of guide structure are navigation/coverage checks, not proof of correct live security settings or functioning SPL.

## Data-source setup rehearsal

Use [Splunk data-source setup](splunk-data-sources.md) on the assigned environment: validate one harmless local event per host through source, transport, receiver and search; check timestamp/host identity; then run the explicit-inventory silence search and a fixture alert. Record versions, substitutions, UTC times, expected/actual results and rollback location. Local repository tests cannot establish installation success or scoring continuity.


## Inject-response documentation and poller checks (2026-11-13)

The [inject-response playbook](inject-response-playbook.md) covers download/process detection prerequisites, schema-dependent IOC searches, local snapshots and workstation evidence collection. The example searches use a five-minute window; output caps do not bound all search work. No new collection or live probes were performed.

Safe checks run from the repository root:

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile scripts/splunk_poll.py
python3 scripts/splunk_poll.py --help
python3 scripts/splunk_poll.py --config config/splunk-poll.example.json
git diff --check
git diff --cached --check
```

All **96 tests** passed, compilation and plan/help commands succeeded, and both whitespace checks passed. REST calls in tests are mocked. Regression coverage includes form-encoded credentials, POST job submission, JSON response selection, session-key authorization, dispatch-state completion, two consecutive cycles returning identical rows (zero new rows and no second evidence file), and shared deduplication state in the CLI loop.

This does not validate a real Splunk login, field extraction, search results, certificates, appliance telemetry, Windows commands or scoring. Rehearse with the actual Splunk build and verified fields before operational use. Known limits: query-only failures can be reported as `no new events` without a file; deduplication is process-local and grows with distinct rows; second-resolution filenames can collide; pruning deletes old evidence. These limits are described in the playbook.

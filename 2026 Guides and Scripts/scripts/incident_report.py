#!/usr/bin/env python3
"""Incident report scaffolding and validation for CCDC competition ops toolkit.

Modes: validate (check required fields), render (output Markdown report).
Default behavior: validate input and render report to stdout.
--write PATH: write rendered report at mode 0600, backup existing file first.
--json: print machine-readable summary of validation + redaction counts.

Exit codes: 0 = valid report rendered; 2 = missing required fields or invalid input.

Observation only: this report is a formatting/verification aid and does not itself prove the incident.
Secret material is redacted in output; sensitive evidence must be transmitted via staff's approved protected channel.
"""
import argparse
import json
import os
import re
import sys
import stat
import tempfile
from typing import Any, Dict, List, NoReturn

PROTOCOL = 'incident-report/1.0'


def fail(message: str) -> NoReturn:
    """Print JSON error to stderr and exit with code 2."""
    print(json.dumps({'status': 'invalid_configuration', 'error': message}), file=sys.stderr)
    sys.exit(2)


# --------------------------
# Validation functions
# --------------------------

REQUIRED_FIELDS = [
    'incident_id',
    'reported_utc',
    'timeline',
    'evidence',
    'source_address',
    'destination_address',
    'port',
    'affected_services',
    'impact',
    'containment',
    'recovery',
    'scoring_verification',
]


def _is_text(value: Any) -> bool:
    """True for a non-empty string."""
    return isinstance(value, str) and value.strip() != ''


def validate(doc: Any) -> List[str]:
    """Validate required fields, their types and entry schemas.

    Returns list of missing/invalid field descriptions (empty list == valid).
    Pure function, testable without I/O.
    """
    if not isinstance(doc, dict):
        return ['input must be a JSON object']

    errors = []

    def text_field(field: str) -> None:
        value = doc.get(field)
        if value is None or not _is_text(value):
            errors.append(f'missing {field}')

    for field in ('incident_id', 'reported_utc'):
        text_field(field)

    # timeline: non-empty array of {utc, description} objects with text values.
    timeline = doc.get('timeline')
    if timeline is None:
        errors.append('missing timeline')
    elif not isinstance(timeline, list):
        errors.append('timeline must be an array')
    elif not timeline:
        errors.append('timeline is empty')
    else:
        for i, entry in enumerate(timeline):
            if not isinstance(entry, dict):
                errors.append(f'timeline[{i}] must be an object')
                continue
            if not _is_text(entry.get('utc')):
                errors.append(f'timeline[{i}].utc missing or empty')
            if not _is_text(entry.get('description')):
                errors.append(f'timeline[{i}].description missing or empty')

    # evidence: non-empty array of {source, event_id, hash} objects with text values.
    evidence = doc.get('evidence')
    if evidence is None:
        errors.append('missing evidence')
    elif not isinstance(evidence, list):
        errors.append('evidence must be an array')
    elif not evidence:
        errors.append('evidence is empty')
    else:
        for i, entry in enumerate(evidence):
            if not isinstance(entry, dict):
                errors.append(f'evidence[{i}] must be an object')
                continue
            for key in ('source', 'event_id', 'hash'):
                if not _is_text(entry.get(key)):
                    errors.append(f'evidence[{i}].{key} missing or empty')

    text_field('source_address')
    text_field('destination_address')

    # port: integer in 1-65535 (bool is an int subclass and must be rejected).
    port = doc.get('port')
    if port is None:
        errors.append('missing port')
    elif isinstance(port, bool) or not isinstance(port, int) or not (1 <= port <= 65535):
        errors.append('port must be an integer between 1 and 65535')

    # affected_services: non-empty array of non-empty strings.
    services = doc.get('affected_services')
    if services is None:
        errors.append('missing affected_services')
    elif not isinstance(services, list):
        errors.append('affected_services must be an array')
    elif not services:
        errors.append('affected_services is empty')
    else:
        for i, service in enumerate(services):
            if not _is_text(service):
                errors.append(f'affected_services[{i}] must be a non-empty string')

    for field in ('impact', 'containment', 'recovery', 'scoring_verification'):
        text_field(field)

    return errors


# --------------------------
# Redaction functions
# --------------------------

# Patterns for secret-like detection
SECRET_KEY_NAMES = {'password', 'passwd', 'secret', 'token', 'api_key', 'private_key', 'sessionkey'}
# Key name pattern (case-insensitive)
KEY_NAME_PATTERN = re.compile(r'^(?:password|passwd|secret|token|api[_-]?key|private_key|sessionkey)$', re.IGNORECASE)

# Value patterns for secret-like detection: keyword followed by an assignment
# and a value that may be quoted (multi-word) or a bare token. Every match is
# redacted so no occurrence of the secret survives.
KEYWORD_ASSIGN_PATTERN = re.compile(
    r'(?i)(password|passwd|secret|token|api[_-]?key|private_key|sessionkey)'
    r'(\s*[:=]\s*)'
    r'(?:"[^"]*"|\'[^\']*\'|\S+)')
# High-entropy base64-like runs (20+ chars, not IPv4, URL, or hash)
ENTROPY_PATTERN = re.compile(r'[A-Za-z0-9+/=_]{20,}')
# Excluded patterns (IPv4, IP range, URL, sha256, md5)
IPV4_PATTERN = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
IP_RANGE_PATTERN = re.compile(r'^(\d{1,3}\.){3}\d{1,3}-(\d{1,3}\.){3}\d{1,3}$')
URL_PATTERN = re.compile(r'^https?://[^\s]+$')
SHA256_PATTERN = re.compile(r'^[a-fA-F0-9]{64}$')
MD5_PATTERN = re.compile(r'^[a-fA-F0-9]{32}$')


def redact(value: str) -> str:
    """Redact secret-looking values in a string.

    Redacts if:
    - Key name matches password/passwd/secret/token/api_key/private_key/sessionkey
    - Value matches pattern like "password=..." or "api_key=..."
    - High-entropy base64 run of 20+ chars (excluding IPv4, URL, sha256, md5)

    Returns redacted string with "[REDACTED]" placeholders.
    """
    if not isinstance(value, str):
        return value

    # Redact every keyword=value occurrence (quoted or bare) so no secret
    # fragment survives, including multi-word quoted values.
    value = KEYWORD_ASSIGN_PATTERN.sub(r'\1\2[REDACTED]', value)

    # Redact every high-entropy run (excluding IPv4, IP ranges, URLs, hashes),
    # not just the first match.
    def _redact_entropy(match):
        ent = match.group()
        if (IPV4_PATTERN.match(ent) or IP_RANGE_PATTERN.match(ent)
                or URL_PATTERN.match(ent) or SHA256_PATTERN.match(ent)
                or MD5_PATTERN.match(ent)):
            return ent
        return '[REDACTED]'

    return ENTROPY_PATTERN.sub(_redact_entropy, value)


def redact_all(doc: Any) -> Any:
    """Recursively redact all string values in a document.

    A value under a secret-named key (password, token, api_key, ...) is always
    treated as sensitive, regardless of its shape — this catches plain secrets
    like "hunter2secret" that the string-level patterns would otherwise miss.
    """
    if isinstance(doc, str):
        return redact(doc)
    elif isinstance(doc, list):
        return [redact_all(item) for item in doc]
    elif isinstance(doc, dict):
        out = {}
        for k, v in doc.items():
            if isinstance(v, str) and KEY_NAME_PATTERN.match(k):
                out[k] = '[REDACTED]'
            else:
                out[k] = redact_all(v)
        return out
    else:
        return doc


# --------------------------
# Rendering functions
# --------------------------

def render_report(doc: Dict[str, Any], missing: List[str]) -> str:
    """Render a Markdown incident report from the document.

    Redacts secret material and returns Markdown string.
    """
    lines = []

    # Title
    lines.append(f"# Incident {doc['incident_id']}")

    # Reported UTC
    lines.append("")
    lines.append(f"## Reported ({doc['reported_utc']})")

    # Timeline
    lines.append("")
    lines.append("## Timeline")
    for entry in doc['timeline']:
        lines.append(f"- {entry['utc']}: {entry['description']}")

    # Evidence table
    lines.append("")
    lines.append("## Evidence")
    lines.append("| Source | Event ID | Hash |")
    lines.append("|--------|----------|------|")
    for ev in doc['evidence']:
        lines.append(f"| {ev['source']} | {ev['event_id']} | {ev['hash']} |")

    # Network
    lines.append("")
    lines.append("## Network")
    lines.append(f"- Source address: {doc['source_address']}")
    lines.append(f"- Destination address: {doc['destination_address']}")
    lines.append(f"- Port: {doc['port']}")

    # Affected services
    lines.append("")
    lines.append("## Affected services")
    for svc in doc['affected_services']:
        lines.append(f"- {svc}")

    # Impact
    lines.append("")
    lines.append("## Impact")
    lines.append(doc['impact'])

    # Containment
    lines.append("")
    lines.append("## Containment")
    lines.append(doc['containment'])

    # Recovery
    lines.append("")
    lines.append("## Recovery")
    lines.append(doc['recovery'])

    # Scoring verification
    lines.append("")
    lines.append("## Scoring verification")
    lines.append(doc['scoring_verification'])

    # Footer note
    lines.append("")
    lines.append("---")
    lines.append("*Secret material has been excluded from this report. If sensitive evidence is required, transmit it only via staff's approved protected channel. This report is a formatting aid and does not itself prove the incident.*")

    return '\n'.join(lines)


# --------------------------
# CLI functions
# --------------------------

def load_input(path=None) -> Dict[str, Any]:
    """Load input document from file (if path given) or stdin."""
    if path is not None:
        with open(path, 'r') as f:
            return json.load(f)
    return json.load(sys.stdin)


def write_output(path: str, content: str) -> None:
    """Atomically publish private files; reject symlinks and special files.

    Temporary files are created with mode 0600 before any content is written.
    Replacing directory entries never opens an output or backup symlink.
    """
    def check_regular(name):
        try:
            info = os.lstat(name)
        except FileNotFoundError:
            return False
        if not stat.S_ISREG(info.st_mode):
            raise OSError(f'refusing non-regular output: {name}')
        return True

    def publish(name, text):
        fd, temporary = tempfile.mkstemp(prefix='.incident-', dir=os.path.dirname(os.path.abspath(name)))
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                stream.write(text)
                stream.flush()
                os.fsync(stream.fileno())
            check_regular(name)
            os.replace(temporary, name)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    exists = check_regular(path)
    check_regular(path + '.bak')
    if exists:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, encoding='utf-8') as stream:
            publish(path + '.bak', stream.read())
    publish(path, content)


def redaction_count(original, redacted):
    """Count masked occurrences, including whole secret-key values."""
    if isinstance(original, str):
        if original == redacted:
            return 0
        return max(1, redacted.count('[REDACTED]') - original.count('[REDACTED]'))
    if isinstance(original, dict):
        return sum(redaction_count(value, redacted[key]) for key, value in original.items())
    if isinstance(original, list):
        return sum(redaction_count(a, b) for a, b in zip(original, redacted))
    return 0


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        prog='incident_report.py',
        description='Scaffold and validate scored-incident report for CCDC competition ops toolkit'
    )
    parser.add_argument(
        '--input', '-i',
        default=None,
        help='Input JSON document file (default: stdin)'
    )
    parser.add_argument(
        '--write', '-w',
        metavar='PATH',
        help='Write rendered report to PATH (mode 0600)'
    )
    parser.add_argument(
        '--json',
        action='store_true',
        help='Print machine-readable summary of validation + redaction counts'
    )

    args = parser.parse_args()

    # Load input
    try:
        doc = load_input(args.input)
    except json.JSONDecodeError as e:
        fail(f'invalid JSON input: {e}')
    except OSError as e:
        fail(f'cannot read input: {e}')

    # Validate first: missing fields are a hard error (exit 2), so we never
    # render a half-complete report.
    missing = validate(doc)
    if missing:
        fail('validation failed: ' + ', '.join(missing))

    # Redact and render
    redacted_doc = redact_all(doc)
    report = render_report(redacted_doc, [])

    # Prepare output
    output_path = args.write

    if args.write:
        try:
            write_output(output_path, report)
        except OSError as exc:
            fail(f'cannot write report: {exc}')

    if args.json:
        valid = len(missing) == 0
        output_path_str = output_path if output_path else None
        output = {
            'valid': valid,
            'missing': missing,
            'redacted_count': redaction_count(doc, redacted_doc),
            'output_path': output_path_str
        }
        print(json.dumps(output))
    elif not args.write:
        # Default mode: render to stdout
        print(report)


if __name__ == '__main__':
    main()

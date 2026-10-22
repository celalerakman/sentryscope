# SentryScope

Local static analysis and finding history for Python codebases.

SentryScope reads source files without importing or executing them. It combines
AST rules, conservative data-flow tracking and manifest checks, then keeps scan
snapshots and review decisions in SQLite. Reports are available as text, JSON,
self-contained HTML and SARIF 2.1.0.

## Quick start

Python 3.11 or newer. The runtime uses only the standard library.

```sh
python -m sentryscope scan examples/clean --no-store
python -m sentryscope scan examples/unsafe --project example --format json
python -m sentryscope history --project example
python -m sentryscope rules
```

The unsafe example returns exit status `1` because it contains findings. Its code
is analysis input, not a service to run. The clean example returns `0`.

Generate a filterable report:

```sh
python -m sentryscope scan examples/unsafe --no-store --format html --output runtime/report.html
```

Open `runtime/report.html` in a browser. A committed [example report](docs/example-report.html)
is also available. It contains severity filters, text search, finding identity,
remediation and source-to-operation traces. No external scripts or styles are loaded.

## What it analyzes

- Python imports and aliases, builtin shadowing and literal API options.
- Assignments, reassignments, method receivers, comprehensions and named expressions.
- Conservative joins across conditionals, loops, exception handlers and match cases.
- Top-level function return summaries, including chained wrapper calls.
- Caller-controlled SQL, file paths and outbound URLs.
- Code evaluation, shell execution, deserialization, YAML loading and TLS settings.
- Weak digests, temporary-file races, embedded credentials and insecure permissions.
- Requirements pinning, unencrypted package sources and final-stage Docker users.

See the [rule catalogue](docs/RULES.md) and [analysis semantics](docs/ANALYSIS.md) for
exact coverage. The scanner is intentionally conservative and does not prove that a
program is safe. Manifest checks are offline policies, not a CVE database.

## Scan history and review

Scan output contains a `scan_id`. Use it to inspect a snapshot or render it again:

```sh
python -m sentryscope show SCAN_ID
python -m sentryscope report SCAN_ID --format sarif --output runtime/report.sarif
python -m sentryscope report SCAN_ID --format html --output runtime/report.html
python -m sentryscope diff EARLIER_SCAN_ID LATER_SCAN_ID
```

Each finding has a structural fingerprint that survives unrelated line insertion.
Review state is separate from the immutable scan snapshot:

```sh
python -m sentryscope triage FINGERPRINT --project example --status reviewing --version 0 --reason "Inspecting input validation at this boundary"
python -m sentryscope audit --verify
python -m sentryscope backup runtime/history-backup.sqlite
```

Transitions require the current version and a reason. Concurrent decisions cannot
silently overwrite one another. The audit verifier checks the hash chain, recorded
scan content and current triage state. This detects accidental or partial database
tampering; a database administrator can rewrite the entire database and its chain.

## Policy and baseline

```sh
python -m sentryscope scan path/to/source --policy examples/policy.toml --fail-on medium
python -m sentryscope baseline SCAN_ID --output runtime/baseline.json
python -m sentryscope scan path/to/source --project PROJECT --baseline runtime/baseline.json
```

Baseline identity is bound to the project, engine version and policy digest. Existing
findings stay visible but do not fail the new-finding gate. A baseline cannot be
created from an incomplete scan. Expiring suppressions require an exact fingerprint
and a reason; they remain visible in reports.

## Exit statuses

| Status | Meaning |
|---|---|
| `0` | Complete scan with no new unsuppressed finding above the threshold, or successful command |
| `1` | New unsuppressed findings meet the severity threshold |
| `2` | Invalid input, incomplete scan, inconsistent comparison or state error |
| `3` | Audit verification failed |

An unreadable, oversized or syntactically invalid source is reported as incomplete,
not silently treated as clean. A finding absent from an incomplete scan is not a
verified resolution. See [the command reference](docs/CLI.md).

## Development

```sh
python scripts/check.py
```

The check runner executes unit tests and a temporary-database workflow covering
scan, report, baseline, comparison, audit verification and backup/restore. Tests
include hostile filenames, Unicode column positions, source modification, symlink
boundaries, concurrent decisions and redaction of credential-like literals.

An optional installation exposes the `sentryscope` command:

```sh
python -m pip install .
sentryscope --version
```

## Design notes

- [Architecture](docs/ARCHITECTURE.md)
- [Analysis semantics and limitations](docs/ANALYSIS.md)
- [Rule catalogue](docs/RULES.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Command reference](docs/CLI.md)
- [Database and audit model](docs/STORAGE.md)
- [Validation notes](docs/VALIDATION.md)

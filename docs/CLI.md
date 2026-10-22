# Command reference

Run `python -m sentryscope --help` or use the installed `sentryscope` entry point.
Commands that access history accept `--database`, defaulting to
`runtime/sentryscope.sqlite`.

## scan

```sh
python -m sentryscope scan SOURCE --project app --format json --database runtime/history.sqlite
```

| Option | Meaning |
|---|---|
| `--project` | Stable identity used to group snapshots; defaults to target directory name |
| `--policy` | TOML configuration file |
| `--baseline` | Compatible baseline of accepted existing fingerprints |
| `--fail-on` | Severity gate: critical, high, medium or low |
| `--format` | text, json, html or sarif |
| `--output` | Write atomically to a file rather than stdout |
| `--no-store` | Analyze without opening a history database |

The target must be a regular directory. The scanner ignores unsupported file types
and configured paths. Resource limits and unreadable source produce diagnostics.
High-severity findings return `1`; diagnostics return `2` even if findings are present.

## history and show

```sh
python -m sentryscope history --project app
python -m sentryscope show SCAN_ID --status reviewing
```

`history` returns snapshot IDs and creation/completeness metadata. `show` returns
the snapshot's findings joined with their current project review state and version.
The underlying historical finding payload remains unchanged.

## triage

```sh
python -m sentryscope triage FINGERPRINT --project app --status accepted --version 1 --actor local --reason "Reviewed the constrained input boundary"
```

Read the current version from `show`. The first decision for a new finding uses
version `0`. Decisions to the same state are rejected rather than generating
duplicate review events. Actor defaults to the local account name; it is a label,
not an authenticated identity assertion.

## diff

```sh
python -m sentryscope diff BEFORE_SCAN_ID AFTER_SCAN_ID
```

The output contains new, unchanged and absent fingerprint lists plus completeness.
Cross-project comparisons are rejected. Review state is not automatically changed.

## baseline

```sh
python -m sentryscope baseline SCAN_ID --output runtime/baseline.json
```

Only complete snapshots can become baselines. A baseline contains no source snippets.
It carries project identity, engine version, policy digest and unique fingerprints.
Using it with another policy/project/version returns `2` instead of silently hiding
incompatible results.

## report

```sh
python -m sentryscope report SCAN_ID --format html --output runtime/report.html
python -m sentryscope report SCAN_ID --format sarif --output runtime/report.sarif
```

The target source need not still exist. Reports are reconstructed from stored
snapshot payloads. Baseline annotations are applied during a baseline-aware scan;
a separately regenerated snapshot report does not infer an external baseline.

## audit and backup

```sh
python -m sentryscope audit --verify
python -m sentryscope audit
python -m sentryscope backup runtime/history-backup.sqlite
python -m sentryscope audit --verify --database runtime/history-backup.sqlite
```

Verification returns `3` when event links, snapshots or review state are inconsistent.
Without `--verify`, audit outputs canonical event payloads and their hashes.

## rules

```sh
python -m sentryscope rules
```

Lists rule IDs, titles, severities, CWE tags and remediation text without creating
a database or scanning files.

## Policy example

```toml
[scan]
workers = 4
fail_on = "high"
max_file_bytes = 1048576
max_files = 10000
max_total_bytes = 134217728
exclude = [".git", ".venv", "__pycache__", "runtime"]
disabled_rules = []
```

Unknown keys and invalid numeric values are errors. Exclusion patterns match a
relative path or any path component. When an `exclude` list is supplied, it replaces
the default list; include the defaults that should remain excluded.

To suppress a reviewed finding, add an array-of-tables entry:

```toml
[[suppressions]]
fingerprint = "REPLACE_WITH_THE_EXACT_FINDING_FINGERPRINT"
reason = "Reviewed isolated operation with a constrained caller"
expires = "2099-01-01"
```

The placeholder is intentionally not a valid fingerprint. Replace it and choose a
real review deadline. An expired, duplicated or unexplained suppression is rejected.
Suppression retains the finding in output and exempts it from the finding gate.

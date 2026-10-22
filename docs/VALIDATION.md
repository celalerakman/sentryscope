# Validation

The application and end-to-end workflow were exercised on Windows using Python
3.12 and Python 3.14. The runtime target is Python 3.11 or newer. Additional OS and
version combinations are configured in the repository workflow; a configured matrix
is not evidence of a completed run.

## Executed checks

- AST rule cases include positive and negative patterns, aliasing, shadowed builtins,
  control-flow joins, wrapper summaries and Unicode column conversion.
- File scanning checks include deterministic ordering under different worker counts,
  exclusion patterns, source modification, symlink boundaries, encoding failures and
  resource budgets.
- Persistence checks include transaction rollback, project isolation, concurrent
  triage, optimistic versions and backup/restore.
- Audit checks deliberately alter events, remove a terminal event, modify snapshot
  content and forge review state, then require verification to fail.
- Report checks include HTML escaping, literal credential non-disclosure, baseline
  annotations, atomic replacement and SARIF trace structure.
- End-to-end checks run scan, history, show, review, diff, report, baseline, audit and
  backup commands in isolated temporary directories.
- SARIF finding, empty, incomplete and suppressed reports were validated against the
  SARIF 2.1.0 JSON schema with an external development validator.
- A wheel was built and installed into a fresh virtual environment. The installed
  command entry point returned its version successfully.
- The scanner completed a scan of its own analysis modules without parse/read errors.
- The generated HTML report was opened in a browser; search reduced the visible
  findings correctly and the data-flow detail panel opened as expected.

## Reproduction

```sh
python scripts/check.py
python -m unittest discover -s tests -v
```

The runtime has no third-party dependencies. External JSON-schema validation was
a development check, not a scanner runtime requirement.

## Limits

No throughput benchmark, security certification or whole-program soundness claim is
made. The scanner's own source scan can report conservative review findings; a
completed self-scan is not a clean bill of security. Analysis limitations are listed
in `ANALYSIS.md` and filesystem/audit trust boundaries in `THREAT_MODEL.md`.

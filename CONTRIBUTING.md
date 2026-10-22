# Development notes

Run `python scripts/check.py` before changing analysis behavior. Keep positive and
negative examples beside each rule test. A change to flow semantics should cover
assignment kills, joins, wrapper returns and import shadowing, not only direct calls.

New rules need a stable ID, a concise description, a remediation statement and a
clear explanation of their trust boundary. Report text should explain the operation
without copying source snippets or literal secrets. Do not add imports of target code.

Data-layer changes must preserve transaction boundaries and audit verification.
Schema changes need a deliberate version/migration strategy; the current release
accepts schema version 1 only. Never silently reset an existing history database.

Output changes should preserve deterministic finding order and valid SARIF structure.
HTML values must remain escaped, and browser filtering must continue to use text
rather than injecting untrusted HTML. Keep runtime dependencies separate from
optional development tooling.

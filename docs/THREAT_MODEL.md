# Threat model

## Assets and trust boundaries

The scanner reads local source and writes reports and a local history database.
Target source is untrusted input. Policy files, baseline files, output locations
and review commands are explicit operator inputs. The tool has the privileges of
the account running it and does not provide an operating-system sandbox.

## Controls

| Risk | Implemented control | Boundary |
|---|---|---|
| Target code executes during analysis | AST parsing only; no import, eval or dynamic plugin loading | Python parser/resource bugs remain runtime concerns |
| Symlink traversal leaves the target | Symlink/reparse exclusion, resolved-root containment and no-follow open where supported | Not an adversarial filesystem sandbox |
| Files change during scanning | Identity, modification time and size checks before/after bounded reads | A privileged attacker can forge filesystem metadata |
| Large input exhausts resources | Per-file, total-byte, file-count and worker limits | No per-file process timeout or OS memory isolation |
| Parse failure looks clean | Diagnostic plus incomplete status and nonzero exit | Rules can still miss valid but unsupported behavior |
| Reports disclose credential literals | Findings contain rule text and traces, not source snippets | Operator-supplied notes can contain whatever was entered |
| HTML path or note injection | Escape all input strings; filter using textContent | Browser/runtime must still be maintained |
| Concurrent review overwrites a decision | Transactional version comparison | CLI actors are operator labels, not authenticated principals |
| Partial database tampering goes unnoticed | Hash chain, snapshot hashes and reconstructed triage state | A database owner can rewrite both data and audit chain |
| Old baselines hide new engine behavior | Project, engine-version and policy binding | Operators must still review a baseline before accepting it |

## Network behavior

The scanner makes no network requests. Source is not uploaded and no advisory
service is queried. Generated SARIF contains a schema URI as metadata; the scanner
does not fetch it. Optional development validation may download a schema, but that
is separate from runtime analysis.

## Intentionally excluded

There is no exploitation engine, network probing, credential testing, package
installation from analyzed manifests or automatic code rewriting. Findings are
review inputs. The tool cannot authorize or validate a deployment on its own.

## Reporting a defect

Provide the rule ID, Python version, expected behavior and a minimal source example
with private values removed. Preserve whether the result was complete. A report
export can include local relative paths and review notes; inspect it before sharing.

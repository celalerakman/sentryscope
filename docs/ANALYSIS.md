# Analysis semantics

## Sources and propagation

Known source calls include `input`, standard-input reads, environment lookups and
selected Flask/request mappings. Function parameters are treated as caller-controlled
when a function is analyzed in isolation. This reports risky helper contracts even
when every currently visible caller happens to pass a constant.

Origins propagate through expression children, formatting, method receivers,
container construction, subscripts and unknown function calls. Unknown calls are
not assumed to sanitize input. Return summaries can replace that fallback for
top-level functions defined in the same module.

Assignments kill the old variable value. Augmented assignments merge old and new
values. Conditional branches are merged. Loops include the zero-iteration state;
one abstract body pass does not establish an arbitrary loop fixed point. Exception
handlers conservatively see the union of entry and completed body states.

`match` captures receive subject flow. Comprehension targets are scoped to their
abstract evaluation and the surrounding environment is restored afterwards.

## Sink interpretation

SQL checking is structural: a caller-controlled first positional argument to
`execute`, `executemany` or `executescript` produces a finding. A fixed query with
separate bound values does not. Custom methods with those names may be false
positives. Keyword-only SQL APIs and ORM-specific query builders need separate rules.

Outbound URL checking recognizes selected module-level `requests`, `httpx` and
`urllib.request` calls. Session/client instance dispatch is not inferred. File-path
checking covers `open`, `io.open` and `os.open`; it does not model all pathlib APIs.

Shell detection requires an explicit literal `shell=True` for subprocess calls.
`os.system` and `os.popen` are always sensitive. Dynamic `shell` flags, environment
expansion and external process behavior are not modeled.

No general-purpose sanitizer is trusted automatically. Converting a value to `int`
may make a specific SQL interpolation safe, but a policy-specific proof of that
sanitizer is outside this domain. Parameter binding is recognized by keeping the
query constant, not by declaring every string-cleaning helper safe.

## Aliases and scope

Imports, import aliases, local API aliases and direct shadowing are tracked.
Conditional aliases are joined conservatively as unresolved when their branches
disagree. Dynamic imports, monkey patching and runtime attribute replacement are
outside the resolver. Nested function definitions and class methods are analyzed,
but their return summaries are not exported across scopes.

Global values are not propagated into independently analyzed function bodies.
Closures, recursive heap structures and cross-module data flow are not modeled.
These boundaries can cause false negatives. Conservative caller-controlled
parameters and unknown calls can cause false positives.

## Finding identity

Identity includes relative path, rule ID, scope, a hash of the sink AST and an
occurrence ordinal. It excludes line numbers. Moving unrelated lines does not
change the fingerprint; changing a sink, renaming its scope/path, or inserting an
identical sink before it can change identity.

AST literal values are used only inside a one-way structural hash. No code snippet
or credential literal is stored in a finding. Triage reasons and project identifiers
are explicit operator input and are retained as supplied.

Python AST columns are UTF-8 byte offsets. The result adapter converts them to
Unicode code-point columns; SARIF declares `columnKind: unicodeCodePoints`.

## Manifest boundaries

Requirements checks recognize direct line-level pins and HTTP references. They do
not resolve includes, evaluate environment markers, fetch packages or consult
advisories. Complex multiline syntax may need review. A pin by itself does not
establish package integrity or freedom from vulnerabilities.

Dockerfile checking is line-oriented. Each `FROM` resets the inferred user, and
the final stage must explicitly name a non-root user. Image metadata is not pulled,
so an image's own default user is not inferred. Stage aliases and multiline
instructions are not a full Dockerfile grammar.

## Meaning of a clean scan

A clean scan means no enabled rule produced an unsuppressed finding at the selected
threshold within the files that were analyzed. It is not a security proof. Parse,
read and budget failures make the scan incomplete and return status `2`.

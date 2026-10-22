# Rule catalogue

Checks describe reviewable risk patterns; a finding is not proof of exploitability.

| ID | Rule | Severity | CWE |
|---|---|---|---|
| PY001 | Dynamic code execution | high | CWE-95 |
| PY002 | Shell interpretation | high | CWE-78 |
| PY003 | Caller-controlled SQL | high | CWE-89 |
| PY004 | Unsafe object deserialization | high | CWE-502 |
| PY005 | Unsafe YAML loader | high | CWE-502 |
| PY006 | TLS verification disabled | high | CWE-295 |
| PY007 | Weak cryptographic digest | medium | CWE-327 |
| PY008 | Race-prone temporary name | medium | CWE-377 |
| PY009 | Caller-controlled outbound URL | medium | CWE-918 |
| PY010 | Caller-controlled filesystem path | medium | CWE-22 |
| PY011 | Non-cryptographic secret generation | medium | CWE-338 |
| PY012 | Embedded credential-like value | high | CWE-798 |
| PY013 | Debug mode enabled | medium | CWE-489 |
| PY014 | World-writable permissions | medium | CWE-732 |
| PY015 | Unrestricted tar extraction | high | CWE-22 |
| DEP001 | Unpinned dependency | low | CWE-1104 |
| DEP002 | Unencrypted dependency source | high | CWE-319 |
| CFG001 | Root container user | medium | CWE-250 |
| CFG002 | Mutable container base | low | CWE-1104 |

## PY001 — Dynamic code execution

eval or exec evaluates a string as Python code.

Replace code evaluation with explicit parsing or a fixed operation map.

## PY002 — Shell interpretation

A subprocess invokes a shell, or an os shell helper is used.

Pass a fixed executable and a separate argument list with shell disabled.

## PY003 — Caller-controlled SQL

A query expression carries untrusted or caller-controlled data.

Use a static SQL statement with bound parameters for values.

## PY004 — Unsafe object deserialization

An object deserializer can execute code when data is hostile.

Use a constrained data format such as JSON and validate its schema.

## PY005 — Unsafe YAML loader

YAML loading lacks an explicitly safe loader.

Use yaml.safe_load or an explicit SafeLoader/CSafeLoader.

## PY006 — TLS verification disabled

A known HTTP client disables certificate verification.

Keep verification enabled and configure a trusted CA bundle if needed.

## PY007 — Weak cryptographic digest

MD5 or SHA-1 is used without declaring a non-security purpose.

Use SHA-256 or a purpose-specific password hashing scheme.

## PY008 — Race-prone temporary name

mktemp returns a name without atomically creating the file.

Use TemporaryFile, NamedTemporaryFile or mkstemp.

## PY009 — Caller-controlled outbound URL

An outbound HTTP URL carries untrusted or caller-controlled data.

Allowlist schemes and destinations and validate every redirect target.

## PY010 — Caller-controlled filesystem path

A file operation receives an untrusted or caller-controlled path.

Resolve under an intended root and verify containment before opening.

## PY011 — Non-cryptographic secret generation

A security-named variable uses the random module.

Use secrets.token_bytes, token_hex or token_urlsafe.

## PY012 — Embedded credential-like value

A credential-named variable contains a non-placeholder string literal.

Read secrets from a protected runtime configuration; rotate exposed values.

## PY013 — Debug mode enabled

A run call explicitly enables debug mode.

Disable interactive debugging outside an isolated development environment.

## PY014 — World-writable permissions

A chmod call explicitly grants write permission to other users.

Grant only the permissions required by the intended owner/group.

## PY015 — Unrestricted tar extraction

Tar extraction explicitly uses the fully_trusted filter.

Use the data extraction filter and review member limits and destinations.

## DEP001 — Unpinned dependency

A requirements entry lacks an exact version pin.

Use reviewed lock data and hashes for reproducible installation.

## DEP002 — Unencrypted dependency source

A dependency manifest references an unencrypted HTTP source.

Use an authenticated HTTPS source and verify distribution hashes.

## CFG001 — Root container user

The final Docker build stage has no explicit non-root USER.

Create a dedicated runtime user and set USER in the final stage.

## CFG002 — Mutable container base

A Docker base image is not pinned by digest.

Pin a reviewed image digest and update it through a controlled process.

## Standards references

- [Python AST reference](https://docs.python.org/3/library/ast.html)
- [Python tokenization and source encoding](https://docs.python.org/3/library/tokenize.html)
- [SARIF 2.1.0 specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)

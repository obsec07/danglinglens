# Contributing

Install `python -m pip install -e '.[dev]'`, then run `ruff check .`,
`ruff format --check .`, and `pytest -q`. Tests must use fixtures or local
servers; do not scan live third-party assets from CI.

For a provider rule, include current primary documentation, a capture from an
owned test resource, and its naming and ownership limitations. Remove secrets
and third-party identifiers from fixtures. Include a positive fixture and
meaningful negative controls: generic errors, protected resources, valid sites,
wrong provider, wrong hostname, DNS failure and wildcard ambiguity as relevant.

Never introduce a `vulnerable` label solely from a fingerprint. Do not promote
DNS errors to NXDOMAIN, add generic 404 matches, or bypass domain-verification
checks. A rule describes an observed condition, not a promise of claimability.
All scan results retain unassessed informational severity. Color help must remain
disabled; ANSI styling belongs only on terminal severity labels, never in JSON.
Keep default console output short and free of emojis. Hidden scan rows must
remain in saved evidence and must not change exit codes. `--show-all` exposes
all rows; explicit marker-verification results must always stay visible.

Update the reviewed date, research notes, coverage table and CLI documentation
when behavior changes. Describe compatibility and false-negative tradeoffs.

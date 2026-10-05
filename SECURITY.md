# Security

The scanner accepts untrusted DNS and HTTP responses. It bounds CNAME depth,
response bytes and concurrency, does not reuse cookies, and does not follow
redirects. HTTP connections use captured DNS addresses; private addresses are
blocked by default. TLS verification is disabled by default and clearly shown
in the CLI; use `--verify-tls` when authenticated transport is required.

Report vulnerabilities in DanglingLens through the repository's private
security reporting feature if the maintainer has enabled it. Otherwise contact
the maintainer privately before publishing sensitive evidence. Do not attach
live credentials, program-confidential reports or third-party response bodies
to a public issue. Non-sensitive rule corrections can use ordinary issues.

The project has not been independently security audited. CI does not perform
cloud claims or live-target testing. Maintainers should enable GitHub private
vulnerability reporting before distributing a public fork.

# DanglingLens

Evidence-first subdomain takeover triage for authorized bug bounty work.

**No automated scanner can promise zero false positives.** DanglingLens reports
observed DNS and HTTP conditions, not confirmed vulnerabilities. It never claims a resource,
creates a cloud account, buys a domain, or changes DNS. A separate marker check
can record content control after your authorized manual validation.

## Install

Requires Python 3.11 or newer. Tested locally on Python 3.14; CI covers 3.11–3.14.

```bash
git clone https://github.com/obsec07/danglinglens.git
cd danglinglens

python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
danglinglens --help
```

If you already cloned the repository, enter that existing `danglinglens` directory
instead of cloning again. Run `python -m pip install .` from the directory containing
`pyproject.toml`; running it from your home directory or the `docs` directory fails.

To update an existing installation, run these commands from the repository root:

```bash
git pull --ff-only
source .venv/bin/activate
python -m pip install --upgrade .
danglinglens --version
```

On Windows, activate with `.venv\Scripts\activate`. Alternatively, install this
repository with `pipx install .`.

## Quick start

```bash
danglinglens example.com                     # one hostname
danglinglens subs.txt                        # a file, one hostname per line
subfinder -d example.com -silent | danglinglens
danglinglens subs.txt -o results.jsonl       # also save every result as JSON Lines
```

Only takeover findings are printed, one colored line each, most severe in red:

```text
[CRITICAL] assets.example.com -> assets.example.com.s3.amazonaws.com - Amazon S3: the bucket with this exact name does not exist
[HIGH] app.example.com -> oldapp.azurewebsites.net - Azure App Service: the target name does not exist and no ownership record was found
[MEDIUM] docs.example.com -> example.github.io - GitHub Pages: missing-site error; check the domain can be attached
Done: 5000 checked in 41s - 1 critical, 1 high, 1 medium.
```

## Inputs

Use only domains within your testing scope. Input files contain one hostname or
HTTP(S) URL per line. Blank lines and lines beginning with `#` are ignored.
URLs are normalized to hostnames; their paths and queries are not scanned.
Duplicate names are removed and internationalized names are normalized to IDNA.

```bash
# "scan" is the default command, so these are the same
danglinglens hosts.txt
danglinglens scan hosts.txt
danglinglens scan -l hosts.txt

# Multiple lists, or stdin
danglinglens scan hosts-a.txt hosts-b.txt
cat hosts.txt | danglinglens scan -

# One domain, or several domains
danglinglens scan -d example.com
danglinglens scan -d example.com -d example.org

# Expand prefixes such as www, staging, api.dev across base domains
danglinglens scan -d example.com -w prefixes.txt
danglinglens scan --domains-file roots.txt -w prefixes.txt

# Enforce a scope boundary, save every result, and retain response evidence
danglinglens scan hosts.txt --scope example.com \
  --jsonl results.jsonl --evidence-dir evidence/run-01
```

A single hostname list does not need `-w`. The `-w` option specifically means
**relative prefixes**, so it requires `-d` or `--domains-file`. Base domains
themselves are also checked. `@` in a prefix list represents the already included
base domain. A single domain without a wordlist checks only that hostname;
this release does not query certificate logs or passive enumeration services.

## TLS and network behavior

**TLS certificate verification is disabled by default**, as intended for
examining abandoned hostnames with invalid certificates. The explicit aliases
are `-k`, `--insecure`, and `--no-ssl-verify`. Enable authentication with:

```bash
danglinglens scan hosts.txt --verify-tls
```

Unverified TLS cannot exclude an intercepting proxy or network attacker. Such
observations are never treated as authenticated proof of content control.

The defaults are two DNS resolvers (`1.1.1.1` and `8.8.8.8`), 25 concurrent host
workers, 50 application-probe starts per second, an 8-second timeout per probe,
and a 64 KiB response-body cap. Customize them when needed:

```bash
danglinglens scan hosts.txt --resolver 1.1.1.1 --resolver 8.8.8.8 \
  --concurrency 5 --rate 10 --timeout 12 --repeat-delay 2
```

Each host first gets one quick DNS query (an `A` lookup, which also returns any CNAME
chain). Hosts without a CNAME, usually most of a list, stop there; anything with an
alias, or any DNS error, goes through the full two-resolver, two-round checks. So
large lists finish several times faster without loosening any rule.

At least two distinct resolver IPs are required. Use resolvers operated by
different organizations for stronger corroboration; different IPs alone do not
prove independent infrastructure or geographic coverage. DNS uses UDP with TCP
fallback on truncation. Both must be reachable on port 53. DNS and HTTP share
the rate limiter; DNS fallback and TCP connection attempts are not individual
application probes. No automatic retry storm occurs on failure.

HTTP connects to the addresses captured by the DNS checks while retaining the
original Host header and TLS SNI. Redirects are recorded without following them.
No cookies are reused. Environment proxies and `.netrc` authentication are not
used. Non-public addresses are blocked unless `--allow-private` is supplied for
an authorized lab. Observation checks also make DNS-only requests for two random
sibling names to detect wildcard similarity. They use child names instead when
siblings would fall outside `--scope`. CNAME targets are resolved as necessary
to trace the supplied hostname's routing; they are never requested directly over HTTP.

## Results

Human-readable progress goes to stderr. `--jsonl FILE` writes every result as
JSON Lines; use `--jsonl -` for machine-readable stdout. Existing output files
and evidence directories are never overwritten. Use a fresh name per run.

Help is always plain text, including on Python 3.14 and with forced-color
environment variables. By default the terminal shows **only takeover findings**,
one line each: severity, host, where its CNAME points, and why. Hosts without a
finding (no signal, incomplete checks, wildcard and ownership reviews) are hidden;
`--show-all` lists them too and `-v` adds the evidence behind each line.

```bash
danglinglens hosts.txt --raw                 # no colors, banner, progress or summary
danglinglens hosts.txt -v -o results.jsonl   # explain each finding, save everything
danglinglens hosts.txt --show-all -v         # also list hosts that are not findings
```

`--color auto|always|never` controls colors; `auto` colors only a terminal, and
`NO_COLOR` or `--raw` turn them off. JSONL and saved evidence never contain color
codes and keep every result, including hidden ones.

### Severity

Severity is set by fixed rules over the evidence (`severity_source: "rule"` in JSON):

| Severity | Color | When |
| --- | --- | --- |
| `CRITICAL` | White on red | Takeover proven by your marker over verified HTTPS (`verify`), or Amazon S3 says the bucket with the host's exact name does not exist, so the name is free to create. |
| `HIGH` | Red | An Azure App Service or Blob Storage CNAME target no longer exists (these names are global, first come first served) and no `asuid` ownership record was found; or your marker is served but HTTPS was not verified. |
| `MEDIUM` | Yellow | A GitHub Pages, Heroku, Netlify or Azure missing-site error, or a CNAME to any other name that no longer exists. Real, but the provider may still block another account (domain verification, reserved names). |
| not shown | | Wildcard routing, ownership records, suppressed providers, no signal, incomplete checks. |

Every finding still needs your manual confirmation before reporting, and only on
targets you are authorized to test. `CRITICAL` from a scan means the claimable name
is free, not that a takeover was performed; the tool never creates resources.
`verify --severity` lets you set the impact yourself after a verified marker; that
is recorded as `severity_source: "operator"`.

The statuses below are the stable values in JSONL and evidence files:

| Status | Meaning |
| --- | --- |
| `dangling_dns` | A CNAME target returned NXDOMAIN across the configured resolvers in two rounds. |
| `provider_error` | A supported provider error reproduced on the same protocol with the expected DNS routing. |
| `wildcard_review` | Random DNS controls match the suspect routing; review wildcard behavior separately. |
| `ownership_signal` | An Azure `asuid` TXT record was found; ownership protection may block a claim. |
| `provider_review` | A missing target belongs to a provider whose historical signature is suppressed. |
| `inconclusive` | DNS disagreement, timeout, failed control, changing evidence, or incomplete checks. |
| `no_signal` | No supported signal was observed. This is **not a security guarantee**. |
| `marker_observed` | Exact marker and negative controls passed, but transport was not authenticated. |
| `control_verified` | Exact marker and negative controls passed over verified HTTPS. |
| `marker_not_verified` | The marker or missing-path check did not match. |

```bash
# Prove control after you have legitimately claimed the resource in scope
danglinglens challenge -d docs.example.com -o challenge.json
danglinglens verify --challenge challenge.json --verify-tls
```

Versions 0.2.0 to 0.3.0 use result schema 2 (0.3.0 adds rule severities). The old
`candidate` status is replaced by the factual `dangling_dns` and `provider_error` statuses. Integrations consuming
JSON should update those status filters. Challenge-file schema remains version 1.

Exit codes: `0` completed (findings may exist); `1` a critical, high or medium
finding or wildcard review with `--fail-on-observation` (legacy alias:
`--fail-on-candidate`), or a marker that is not authenticated and verified;
`2` input/output/internal error; `3` one or more inconclusive checks; `130`
interrupted. Code 3 takes precedence over code 1. Interrupted or failed runs
can leave partial output; never treat those files as complete scans.

`--evidence-dir` writes DNS response text, resolver identities, timestamps,
request URLs/headers, response headers, HTTP status, body hashes and captured
body bytes. `Set-Cookie` is omitted. The hash covers the captured raw bytes,
including only the captured prefix when `truncated` is true. Truncated or
unexpectedly compressed responses cannot satisfy a provider fingerprint.
The default JSONL excludes bodies; full evidence includes base64 and decoded text.

## Provider coverage

Rules were reviewed on **2026-10-05**. Run `danglinglens providers` for sources
and provider-specific caveats.

| Provider | Observed signals |
| --- | --- |
| Amazon S3 | Recognized S3 CNAME, HTTP 404, AmazonS3 server identity, and a parsed `NoSuchBucket` error (XML, or the website endpoint's HTML page) with the original hostname as `BucketName`. |
| GitHub Pages | `github.io` CNAME, HTTP 404, GitHub server identity and the missing-Pages response. Domain verification still needs manual review. |
| Azure App Service | `azurewebsites.net` CNAME and repeated NXDOMAIN or missing-site HTTP 404; `asuid.<host>` TXT check. |
| Azure Blob Storage | `blob.core.windows.net` CNAME and repeated NXDOMAIN. Missing containers are not account takeover signals. |
| Heroku | Heroku CNAME, HTTP 404, Heroku server identity and missing-app response. Generated targets and ownership rules still need review. |
| Netlify | Netlify CNAME, HTTP 404, Netlify server identity and missing-site response. Domain reassignment still needs review. |
| Other CNAME targets | Repeated NXDOMAIN only, with no inference about registration or claimability. |

CloudFront, Fastly and Google Cloud Storage are recognized to suppress common
misleading historical signatures. Their reachable names are not tested using
those signatures. Other services with verification protections can appear as
generic dangling DNS observations: they still require provider review.

A matching error page does not override an incomplete check of the other
protocol. Timeouts, blocked/rate-limited responses, server failures, successful
pages and unchecked redirect destinations produce `inconclusive`. A redirect
is allowed as supporting evidence only when it points to the original hostname's
root on a protocol that was actually checked and matched the provider rule.
Provider server headers must match exactly where a rule requires them.

This deliberately narrow release misses some genuine issues. It does not cover
NS/MX delegation takeover, expired-domain registration checks, flattened
ALIAS/ANAME records, IP reuse, or every provider/error-page variant. S3 website
error pages are matched only in their standard form (one `Code` and one
`BucketName` item under a `404 Not Found` heading). A blocked,
changed, localized or proxied fingerprint may be missed. DNS agreement is not
DNSSEC validation, and repeated cached DNS responses are not authoritative
proof of deletion. See [the research and validation guide](docs/RESEARCH.md).

## Manual validation and a harmless proof

1. Read the result's DNS chain, original-host responses, controls, and references.
2. Check current provider rules, exact resource name, region, namespace,
   reservations and ownership-verification requirements. Resource-name
   availability alone does not establish custom-hostname claimability.
3. Follow the program's rules. Where resource claims are prohibited, report
   only the evidence permitted by that program. The scanner performs no claims.
4. Where an authorized isolated proof is permitted, generate a fresh challenge:

   ```bash
   danglinglens challenge -d docs.example.com -o challenge.json
   ```

   This writes a JSON manifest and `challenge.json.body.txt`. On your authorized
   provider resource, serve those exact body bytes at the printed random path
   with `Content-Type: text/plain`. Do not replace a live site's homepage.
   Unrelated missing paths must return 404 or 410.

5. Verify the deployed file without changing DNS:

   ```bash
   danglinglens verify --challenge challenge.json --verify-tls \
     --jsonl proof.jsonl --evidence-dir evidence/proof-01
   ```

   The verifier performs two rounds, checks DNS stability, and compares the
   exact body against a random missing-path control. The secret body token is
   never sent in the request path or query. Use a freshly generated challenge;
   the tool does not independently attest when a file was deployed.

6. Keep provider-account and before/after evidence separately. Marker delivery
   cannot establish that another account was allowed to claim the resource,
   or that a security boundary was crossed. Remove your proof and follow the
   program's cleanup instructions.

## Development and GitHub

```bash
python -m pip install -e '.[dev]'
ruff check .
ruff format --check .
pytest -q
python -m build
```

Tests use fixtures and local loopback HTTP/HTTPS servers, not live bounty
targets. OpenSSL is used to generate an ephemeral test certificate. The CI
workflow checks formatting, lint, tests, and wheel/source builds.

To publish your own repository, create an empty GitHub repository, then run:

```bash
git init -b main
git add .
git commit -m "Initial DanglingLens release"
git remote add origin https://github.com/YOUR_USERNAME/danglinglens.git
git push -u origin main
```

The `.gitignore` excludes virtual environments, build output, common result
files, evidence directories and challenge artifacts. Review `git diff --cached`
before publishing, especially if you used custom output filenames.

MIT licensed. See [CONTRIBUTING.md](CONTRIBUTING.md) for rule changes and
[SECURITY.md](SECURITY.md) for scanner security reports.

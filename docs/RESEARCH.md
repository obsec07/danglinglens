# Research and validation notes

Reviewed 2026-10-05 before implementation. Sources below are primary provider
documentation, original researcher articles, and the maintainers' own catalog.
They describe mechanisms and observations; they cannot establish whether any
particular hostname is exploitable today.

## How the issue happens

An organization connects a custom hostname to a third-party resource and later
deletes that resource while leaving DNS behind. A takeover is possible only if
another party can obtain the relevant resource or binding **and** traffic for
the original hostname reaches that party's content. A missing resource is one
prerequisite, not the whole vulnerability. Original research discusses several
DNS record types and differences in service naming and binding models.
[Patrik Hudak: Subdomain Takeover Basics](https://0xpatrik.com/subdomain-takeover-basics/)

OWASP separates discovery, fingerprinting and manual validation. Its guidance
also includes delegated nameservers, wildcard behavior, and downstream trust
relationships. This implementation focuses on CNAME-backed web services; its
output must not imply coverage of all of those other mechanisms.
[OWASP WSTG-CONF-10](https://owasp.github.io/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management/10-Subdomain_Takeover)

## What the provider research changed

| Source | Finding used in this design |
| --- | --- |
| [AWS S3 virtual hosting](https://docs.aws.amazon.com/AmazonS3/latest/userguide/VirtualHosting.html) | S3 routes custom-domain requests using the original Host value. The scanner requires the missing bucket's name to match that hostname. |
| [AWS security analysis](https://aws.amazon.com/blogs/security/threat-tactic-spotlight-subdomain-takeover/) | Resource naming models differ. Shared namespaces need different treatment from account-scoped or provider-assigned identifiers; an absent name is not universally reclaimable. |
| [GitHub Pages domain verification](https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site/verifying-your-custom-domain-for-github-pages) | Verification can protect a domain and its immediate subdomains. An HTTP error cannot reveal all account-level protections. Username-dependent TXT names cannot be exhaustively guessed. |
| [Microsoft dangling DNS guidance](https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover) | App Service ownership TXT records can stop another subscription binding a domain. Name reservations and service-specific lifecycle rules also matter. |
| [Heroku custom domains](https://devcenter.heroku.com/articles/custom-domains) | Custom-host routing uses provider-supplied DNS targets. Existing bindings, wildcard ownership and wildcard certificates constrain what another account can add. |
| [Netlify domain assignment](https://docs.netlify.com/manage/domains/manage-domains/assign-a-domain-to-your-site-app/) | Domain assignment is a separate control-plane operation. A deployment error alone does not establish that operation will succeed for another account. |
| [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) | Historical fingerprints are starting points. The catalog explicitly disclaims guaranteed accuracy and identifies edge cases and non-vulnerable services. |

Provider documentation takes precedence over a historical signature when they
conflict. The code stores source links with provider matches. No third-party
fingerprint database is silently downloaded or updated at runtime.

## Scanner sequence and rejection gates

1. Normalize the hostname and enforce any supplied scope suffix. Reject URLs
   containing credentials, custom ports, invalid labels, IP inputs and control
   characters. Enumerate only supplied names and wordlist combinations.
2. Follow CNAMEs through a bounded chain using two recursive resolver IPs.
   Preserve CNAME records carried in a recursive NXDOMAIN response. Distinguish
   NXDOMAIN from empty answers, SERVFAIL, refusal, timeout and alias loops.
3. Require both resolvers to agree on chain, final name and outcome. CDN address
   rotation is tolerated. HTTP uses those captured addresses and retains the
   original Host and SNI; it does not fetch the provider hostname as a substitute.
4. For supported HTTP signals, require the expected provider CNAME, status,
   body and, where specified, server identity. An error string alone is
   insufficient. S3 also requires structured bucket-name evidence.
5. Query two random sibling names as DNS-only controls. Similar routing is
   reported separately. These controls are a heuristic, not an authoritative
   wildcard inventory. An unusual wildcard can be missed.
6. Check Azure App Service ownership TXT records where relevant. Presence
   lowers the result to an ownership signal; absence does not prove availability.
7. Repeat the DNS checks and any matching HTTP fingerprint after a delay.
   Require the HTTP signal on the same protocol. Conflicting successful
   responses, changing DNS, failed controls, errors on the other protocol,
   access restrictions and unchecked redirects produce `inconclusive`.
8. Save observations as `dangling_dns` or `provider_error` with unassessed
   informational severity. These labels describe responses, not resource
   availability or impact. Provider caveats are stored as limitations, separate
   from observations. Only an explicit operator assessment after successful
   authenticated marker verification can add a higher severity label.

This sequence is an engineering choice derived from the sources, not a claim
that they prescribe this exact algorithm. Two rounds may hit the same recursive
cache and do not prove global convergence. Two successful fingerprints can
still describe an unclaimable service. Lower false-positive rates also mean
more false negatives; the tests establish behavior, not field accuracy.

## Establishing a reportable takeover

Review current provider documentation and the program's permitted proof method.
Check the **exact** hostname/resource pair and account boundary. Where permitted,
retain evidence that an independent account could establish the binding without
modifying the organization's DNS. A unique harmless marker at a non-root path
can demonstrate content delivery; compare it with a random missing path and
repeat it over verified HTTPS. The `challenge` and `verify` commands support
that read-only check after manual deployment. They do not perform the claim.

Attach DNS evidence, timestamps, provider/region, before/after observations,
account context, marker checks and cleanup evidence. Describe only demonstrated
impact. Do not infer cookie theft, authentication bypass, or arbitrary script
execution simply because content could be served from a subdomain. Follow the
program's rules if it accepts configuration-only reports or forbids claims.

## Implementation references

The HTTP client uses a custom resolver and explicit SSL behavior from the
[aiohttp client documentation](https://docs.aiohttp.org/en/stable/client_advanced.html).
DNS queries use the documented
[dnspython asynchronous query API](https://dnspython.readthedocs.io/en/stable/async-query.html).
These libraries handle protocol transport; the classification rules are local.

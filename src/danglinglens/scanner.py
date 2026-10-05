import asyncio
import secrets
from dataclasses import asdict

from .dnscheck import DNSClient, consensus
from .httpcheck import HTTPClient
from .inputs import in_scope
from .models import DNSView, Result
from .providers import CATALOG, identify


class Scanner:
    def __init__(
        self,
        dns: DNSClient,
        http: HTTPClient,
        resolvers: list[str],
        repeat_delay: float = 1,
        scopes: list[str] | None = None,
    ):
        self.dns, self.http, self.resolvers = dns, http, resolvers
        self.repeat_delay = repeat_delay
        self.scopes = scopes or []

    async def views(self, host: str) -> list[DNSView]:
        return list(await asyncio.gather(*(self.dns.trace(host, r) for r in self.resolvers)))

    async def wildcard(self, host: str, baseline: DNSView) -> dict:
        # DNS-only siblings, or children for a two-label input. Similarity is a caution,
        # not authoritative proof of a wildcard. Explicit records can look the same.
        parent = host.split(".", 1)[1] if host.count(".") >= 2 else host
        if not in_scope(f"dl-control.{parent}", self.scopes):
            parent = host
        names = [f"dl-{secrets.token_hex(10)}.{parent}" for _ in range(2)]
        controls = [await self.views(name) for name in names]
        if not all(consensus(group) for group in controls):
            state = "unknown"
        elif any(
            group[0].signature() == baseline.signature()
            and (baseline.chain or baseline.state == "RESOLVED")
            for group in controls
        ):
            state = "similar"
        else:
            state = "not_observed"
        return {"state": state, "controls": [[asdict(v) for v in g] for g in controls]}

    async def roots(self, host: str, views: list[DNSView]):
        addresses = sorted({ip for view in views for ip in view.addresses})
        return list(
            await asyncio.gather(
                self.http.fetch(host, addresses, "https"), self.http.fetch(host, addresses, "http")
            )
        )

    async def scan(self, host: str) -> Result:
        result = Result(host)
        first = await self.views(host)
        result.dns.extend(first)
        if not consensus(first):
            result.status = "inconclusive"
            result.reasons.append("DNS errors, disagreement, or fewer than two distinct resolvers")
            return result
        baseline = first[0]
        if not baseline.chain:
            result.reasons.append("No CNAME chain; this release does not infer takeover from IPs")
            return result
        provider = identify(baseline.chain)
        if provider:
            result.provider = provider.key
            result.references = list(dict.fromkeys([provider.source, CATALOG]))
        if provider and provider.suppress:
            result.status = "provider_review" if baseline.state == "NXDOMAIN" else "no_signal"
            result.reasons.append(provider.caveat)
            return result
        dangling = baseline.state == "NXDOMAIN"
        if baseline.state == "NODATA":
            result.status = "inconclusive"
            result.reasons.append("CNAME target has no A/AAAA records; this is not NXDOMAIN")
            return result
        if not dangling:
            if not provider or (provider.fingerprint is None and provider.key != "aws_s3"):
                result.reasons.append("No supported HTTP rule for this CNAME chain")
                return result
            result.http.extend(await self.roots(host, first))
            matches = {
                r.url.split(":", 1)[0] for r in result.http if provider.matches_response(r, host)
            }
            if not matches:
                if any(
                    r.error or r.truncated or r.status is None or r.status >= 500 or r.status == 429
                    for r in result.http
                ):
                    result.status = "inconclusive"
                    result.reasons.append(
                        "HTTP checks failed, were limited, or returned server errors"
                    )
                else:
                    result.reasons.append("No supported provider fingerprint on the original host")
                return result
            if any(r.status is not None and 200 <= r.status < 300 for r in result.http):
                result.status = "inconclusive"
                result.reasons.append(
                    "A live HTTP(S) response conflicts with the missing-site signature"
                )
                return result
        else:
            matches = set()
        result.wildcard = await self.wildcard(host, baseline)
        if provider and provider.key == "azure_app_service":
            # For foo.example.com, App Service's TXT name is asuid.foo.example.com.
            result.ownership = list(
                await asyncio.gather(*(self.dns.txt(f"asuid.{host}", r) for r in self.resolvers))
            )
        await asyncio.sleep(self.repeat_delay)
        second = await self.views(host)
        result.dns.extend(second)
        if not consensus(second) or baseline.signature() != second[0].signature():
            result.status = "inconclusive"
            result.reasons.append("DNS did not reproduce across both rounds")
            return result
        if not dangling:
            repeated = await self.roots(host, second)
            result.http.extend(repeated)
            again = {r.url.split(":", 1)[0] for r in repeated if provider.matches_response(r, host)}
            if not matches.intersection(again) or any(
                r.status is not None and 200 <= r.status < 300 for r in repeated
            ):
                result.status = "inconclusive"
                result.reasons.append("Missing-site signature did not reproduce consistently")
                return result
        result.reasons.append(
            "CNAME target is NXDOMAIN on both resolvers in both rounds"
            if dangling
            else "Provider DNS and HTTP signature reproduced on the same protocol"
        )
        if provider:
            result.reasons.append(provider.caveat)
        if any(record["values"] for record in result.ownership):
            result.status = "ownership_signal"
            result.reasons.append("asuid TXT exists; domain ownership protection may block claims")
        elif any(record["state"] not in {"NOERROR", "NXDOMAIN"} for record in result.ownership):
            result.status = "inconclusive"
            result.reasons.append("Could not check Azure domain verification TXT records")
        elif result.wildcard["state"] == "similar":
            result.status = "wildcard_review"
            result.reasons.append(
                "Random DNS controls match; review possible wildcard configuration"
            )
        elif result.wildcard["state"] == "unknown":
            result.status = "inconclusive"
            result.reasons.append("Wildcard controls could not be resolved consistently")
        else:
            result.status = "candidate"
        result.reasons.append(
            "Exact-name claimability remains unverified; manual provider review required"
        )
        return result

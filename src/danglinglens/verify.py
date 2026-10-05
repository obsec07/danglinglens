import asyncio
import base64
import json
import re
import secrets
from pathlib import Path

from .dnscheck import consensus
from .inputs import normalize_host
from .models import Result, utcnow
from .scanner import Scanner


def create_challenge(host: str) -> dict:
    return {
        "schema_version": 1,
        "host": normalize_host(host),
        "created_at": utcnow(),
        "path": f"/.well-known/danglinglens-{secrets.token_hex(16)}.txt",
        # The body token is deliberately unrelated to the request path and query.
        "body": f"danglinglens:{secrets.token_hex(32)}\n",
    }


def load_challenge(path: Path) -> dict:
    if path.stat().st_size > 4096:
        raise ValueError("challenge file is too large")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise ValueError("unsupported challenge file")
    if not all(isinstance(value.get(key), str) for key in ("host", "path", "body")):
        raise ValueError("invalid challenge fields")
    value["host"] = normalize_host(value["host"])
    if not re.fullmatch(r"/\.well-known/danglinglens-[a-f0-9]{32}\.txt", value["path"]):
        raise ValueError("invalid challenge path; generate one with the challenge command")
    if not re.fullmatch(r"danglinglens:[a-f0-9]{64}\n", value["body"]):
        raise ValueError("invalid challenge body; generate one with the challenge command")
    return value


async def verify_marker(scanner: Scanner, challenge: dict, scheme: str = "https") -> Result:
    host = challenge["host"]
    result = Result(host, status="marker_not_verified")
    expected = base64.b64encode(challenge["body"].encode()).decode()
    baseline = None
    for _ in range(2):
        views = await scanner.views(host)
        result.dns.extend(views)
        if not consensus(views) or views[0].state != "RESOLVED":
            result.status = "inconclusive"
            result.reasons.append(
                "Marker check requires resolving DNS agreement from two resolvers"
            )
            return result
        if baseline is not None and baseline != views[0].signature():
            result.status = "inconclusive"
            result.reasons.append("DNS chain changed during marker verification")
            return result
        baseline = views[0].signature()
        addresses = sorted({ip for view in views for ip in view.addresses})
        positive = await scanner.http.fetch(
            host, addresses, scheme, challenge["path"] + "?dlcheck=" + secrets.token_hex(8)
        )
        negative = await scanner.http.fetch(
            host,
            addresses,
            scheme,
            "/.well-known/danglinglens-absent-" + secrets.token_hex(16) + ".txt",
        )
        result.http.extend([positive, negative])
        if positive.error or negative.error or positive.truncated or negative.truncated:
            result.status = "inconclusive"
            result.reasons.append(
                "A marker request or negative control failed or exceeded the body cap"
            )
            return result
        if not (
            positive.status == 200
            and positive.body_base64 == expected
            and positive.headers.get("content-type", "").lower().split(";", 1)[0] == "text/plain"
            and negative.status in {404, 410}
            and challenge["body"].strip() not in negative.body
        ):
            result.reasons.append("Exact plain-text marker or missing-path negative control failed")
            return result
        if _ == 0:
            await asyncio.sleep(scanner.repeat_delay)
    trusted = all(r.tls_verified for r in result.http)
    result.status = "control_verified" if trusted else "marker_observed"
    result.reasons.append(
        "Exact marker and negative control reproduced in two rounds on the original host"
    )
    if not trusted:
        result.reasons.append("Transport was not authenticated; repeat with HTTPS and --verify-tls")
    result.reasons.append(
        "This demonstrates marker delivery only. Prior ownership, cross-account claimability, "
        "authorization and takeover impact require separate evidence."
    )
    return result

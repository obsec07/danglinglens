import asyncio
import ipaddress
from dataclasses import dataclass

import dns.asyncquery
import dns.exception
import dns.message
import dns.rcode
import dns.rdatatype

from .models import DNSView, utcnow


class RateLimiter:
    """Global application-probe start rate, shared by DNS and HTTP."""

    def __init__(self, rate: float):
        self.interval = 1 / rate
        self.lock = asyncio.Lock()
        self.next_start = 0.0

    async def acquire(self) -> None:
        async with self.lock:
            loop = asyncio.get_running_loop()
            await asyncio.sleep(max(0, self.next_start - loop.time()))
            self.next_start = loop.time() + self.interval


@dataclass
class Answer:
    state: str
    message: dns.message.Message | None = None
    error: str | None = None

    def records(self, name: str, kind: str) -> list:
        if self.message is None:
            return []
        return [
            record
            for rrset in self.message.answer
            if rrset.name.to_text().rstrip(".").lower() == name.rstrip(".").lower()
            and rrset.rdtype == dns.rdatatype.from_text(kind)
            for record in rrset
        ]


class DNSClient:
    def __init__(self, timeout: float, limiter: RateLimiter, max_depth: int = 12):
        self.timeout = timeout
        self.limiter = limiter
        self.max_depth = max_depth

    async def query(self, name: str, kind: str, resolver: str) -> Answer:
        await self.limiter.acquire()
        try:
            query = dns.message.make_query(name.rstrip(".") + ".", kind)
            response, _ = await dns.asyncquery.udp_with_fallback(
                query, resolver, timeout=self.timeout
            )
            code = dns.rcode.to_text(response.rcode())
            return Answer(code, response, None if code in {"NOERROR", "NXDOMAIN"} else code)
        except (dns.exception.DNSException, OSError, ValueError) as exc:
            return Answer("ERROR", error=f"{type(exc).__name__}: {exc}")

    async def trace(self, host: str, resolver: str) -> DNSView:
        view = DNSView(resolver=resolver, host=host, terminal=host)
        current, visited = host, set()

        def retain(answer: Answer) -> None:
            if answer.message is not None:
                view.messages.append(answer.message.to_text())

        for _ in range(self.max_depth + 1):
            if current in visited:
                view.error = "CNAME loop"
                return view
            visited.add(current)
            view.terminal = current
            answer = await self.query(current, "CNAME", resolver)
            retain(answer)
            if answer.state not in {"NOERROR", "NXDOMAIN"}:
                view.error = answer.error or answer.state
                return view
            aliases = answer.records(current, "CNAME")
            # A recursive NXDOMAIN response can contain a valid CNAME before the missing name.
            if aliases:
                if len(aliases) != 1 or len(view.chain) >= self.max_depth:
                    view.error = "ambiguous CNAME or chain depth exceeded"
                    return view
                current = aliases[0].target.to_text().rstrip(".").lower()
                view.chain.append(current)
                continue
            if answer.state == "NXDOMAIN":
                view.state = "NXDOMAIN"
                return view
            answers = await asyncio.gather(
                self.query(current, "A", resolver), self.query(current, "AAAA", resolver)
            )
            for reply in answers:
                retain(reply)
            if any(a.state not in {"NOERROR", "NXDOMAIN"} for a in answers):
                view.error = "address lookup failed: " + "; ".join(
                    a.error or a.state for a in answers if a.state != "NOERROR"
                )
                return view
            if any(a.records(current, "CNAME") for a in answers):
                view.error = "CNAME changed during address lookup"
                return view
            if any(a.state == "NXDOMAIN" for a in answers):
                # The preceding CNAME query was NOERROR. Do not treat a racing result as absent.
                view.error = "inconsistent existence across DNS query types"
                return view
            view.addresses = sorted(
                {
                    str(ipaddress.ip_address(record.address))
                    for kind, reply in zip(("A", "AAAA"), answers, strict=True)
                    for record in reply.records(current, kind)
                }
            )
            view.state = "RESOLVED" if view.addresses else "NODATA"
            return view
        view.error = "CNAME chain depth exceeded"
        return view

    async def txt(self, name: str, resolver: str) -> dict:
        answer = await self.query(name, "TXT", resolver)
        values = [
            b"".join(record.strings).decode("utf-8", "replace")
            for record in answer.records(name, "TXT")
        ]
        return {
            "name": name,
            "resolver": resolver,
            "state": answer.state,
            "values": values,
            "error": answer.error,
            "timestamp": utcnow(),
            "message": answer.message.to_text() if answer.message else None,
        }


def consensus(views: list[DNSView]) -> bool:
    return (
        len({v.resolver for v in views}) >= 2
        and all(v.state in {"RESOLVED", "NXDOMAIN", "NODATA"} for v in views)
        and len({v.signature() for v in views}) == 1
    )

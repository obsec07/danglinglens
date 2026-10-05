import base64
import hashlib
import ipaddress
import socket
import ssl
import time

import aiohttp

from .dnscheck import RateLimiter
from .models import HTTPView


def public_address(value: str) -> bool:
    address = ipaddress.ip_address(value)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return address.is_global and not address.is_multicast


class PinnedResolver(aiohttp.abc.AbstractResolver):
    def __init__(self, host: str, addresses: list[str]):
        self.host, self.addresses = host, addresses

    async def resolve(self, host, port=0, family=socket.AF_INET):
        if host != self.host:
            raise OSError("unexpected hostname: redirects and implicit DNS are disabled")
        return [
            {
                "hostname": host,
                "host": address,
                "port": port,
                "family": socket.AF_INET6 if ":" in address else socket.AF_INET,
                "proto": 0,
                "flags": socket.AI_NUMERICHOST,
            }
            for address in self.addresses
            if family in {socket.AF_UNSPEC, socket.AF_INET6 if ":" in address else socket.AF_INET}
        ]

    async def close(self):
        pass


class HTTPClient:
    def __init__(
        self,
        timeout: float,
        limiter: RateLimiter,
        verify_tls: bool = False,
        allow_private: bool = False,
        max_body: int = 65536,
    ):
        self.timeout, self.limiter = timeout, limiter
        self.verify_tls, self.allow_private, self.max_body = verify_tls, allow_private, max_body
        self.ssl_context = ssl.create_default_context() if verify_tls else False

    async def fetch(
        self,
        host: str,
        addresses: list[str],
        scheme: str = "https",
        path: str = "/",
        port: int | None = None,
    ) -> HTTPView:
        if scheme not in {"http", "https"} or not path.startswith("/") or path.startswith("//"):
            raise ValueError("invalid HTTP scheme or path")
        authority = f"{host}:{port}" if port else host
        response = HTTPView(url=f"{scheme}://{authority}{path}")
        response.request_headers = {
            "Host": authority,
            "User-Agent": "DanglingLens/0.1 (+authorized-security-research)",
            "Accept": "*/*",
            "Accept-Encoding": "identity",
            "Cache-Control": "no-cache",
        }
        if not addresses or (not self.allow_private and not all(map(public_address, addresses))):
            response.error = "no addresses or non-public address blocked (see --allow-private)"
            return response
        await self.limiter.acquire()
        started = time.monotonic()
        connector = aiohttp.TCPConnector(
            resolver=PinnedResolver(host, addresses),
            use_dns_cache=False,
            family=socket.AF_UNSPEC,
            ssl=self.ssl_context,
            force_close=True,
        )
        try:
            async with aiohttp.ClientSession(
                connector=connector,
                trust_env=False,
                cookie_jar=aiohttp.DummyCookieJar(),
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                auto_decompress=False,
            ) as session:
                async with session.get(
                    response.url,
                    headers=response.request_headers,
                    allow_redirects=False,
                ) as reply:
                    response.status = reply.status
                    response.headers = {
                        key.lower(): value
                        for key, value in reply.headers.items()
                        if key.lower() != "set-cookie"
                    }
                    response.tls_verified = scheme == "https" and self.verify_tls
                    if reply.connection and reply.connection.transport:
                        peer = reply.connection.transport.get_extra_info("peername")
                        response.peer = str(peer[0]) if peer else None
                    body = bytearray()
                    async for chunk in reply.content.iter_chunked(8192):
                        body.extend(chunk[: self.max_body + 1 - len(body)])
                        if len(body) > self.max_body:
                            response.truncated = True
                            break
                    raw = bytes(body[: self.max_body])
                    response.body = raw.decode("utf-8", "replace")
                    response.body_base64 = base64.b64encode(raw).decode("ascii")
                    response.body_sha256 = hashlib.sha256(raw).hexdigest()
                    response.bytes_read = len(raw)
                    if reply.headers.get("Content-Encoding", "identity").lower() != "identity":
                        response.error = "unexpected content encoding; body was not decompressed"
        except (TimeoutError, aiohttp.ClientError, OSError) as exc:
            response.error = f"{type(exc).__name__}: {exc}"
        response.elapsed_ms = round((time.monotonic() - started) * 1000)
        return response

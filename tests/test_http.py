import base64
import hashlib
import shutil
import socket
import ssl
import subprocess
from contextlib import asynccontextmanager

import pytest
from aiohttp import web

from danglinglens.dnscheck import RateLimiter
from danglinglens.httpcheck import HTTPClient, PinnedResolver, public_address


@asynccontextmanager
async def local_server(handler, tls=None):
    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", handler)
    runner = web.AppRunner(app)
    await runner.setup()
    sock = socket.socket()
    try:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        site = web.SockSite(runner, sock, ssl_context=tls)
        await site.start()
        yield port
    finally:
        await runner.cleanup()
        sock.close()


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.1",
        "169.254.169.254",
        "::1",
        "::ffff:127.0.0.1",
        "224.0.0.1",
        "100.64.0.1",
        "192.0.2.1",
    ],
)
def test_nonpublic_addresses(address):
    assert not public_address(address)


async def test_private_ip_blocked_before_connection():
    client = HTTPClient(1, RateLimiter(10000))
    result = await client.fetch("lab.example.test", ["127.0.0.1"])
    assert result.error and "blocked" in result.error


async def test_resolver_does_not_resolve_redirect_target():
    resolver = PinnedResolver("lab.example.test", ["127.0.0.1"])
    with pytest.raises(OSError):
        await resolver.resolve("evil.test", 443)


async def test_redirect_not_followed_and_host_preserved():
    seen = []

    async def handler(request):
        seen.append((request.host, request.path))
        return web.Response(status=302, headers={"Location": "http://other.test/"})

    async with local_server(handler) as port:
        client = HTTPClient(2, RateLimiter(10000), allow_private=True)
        result = await client.fetch("lab.example.test", ["127.0.0.1"], "http", port=port)
    assert result.status == 302
    assert result.error is None
    assert seen == [(f"lab.example.test:{port}", "/")]


async def test_body_cap_and_original_byte_hash():
    body = b"x" * 50000

    async def handler(request):
        return web.Response(body=body)

    async with local_server(handler) as port:
        client = HTTPClient(2, RateLimiter(10000), allow_private=True, max_body=1024)
        result = await client.fetch("lab.example.test", ["127.0.0.1"], "http", port=port)
    assert result.truncated
    assert result.bytes_read == 1024
    assert result.body_sha256 == hashlib.sha256(body[:1024]).hexdigest()
    assert base64.b64decode(result.body_base64) == body[:1024]


async def test_self_signed_tls_and_original_sni(tmp_path):
    openssl = shutil.which("openssl")
    if not openssl:
        pytest.skip("openssl is needed to generate the local test certificate")
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    subprocess.run(
        [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-subj",
            "/CN=lab.example.test",
            "-addext",
            "subjectAltName=DNS:lab.example.test",
        ],
        check=True,
        capture_output=True,
    )
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(cert, key)
    names = []
    tls.set_servername_callback(lambda sock, name, context: names.append(name))

    async def handler(request):
        return web.Response(text="test marker")

    async with local_server(handler, tls) as port:
        insecure = HTTPClient(3, RateLimiter(10000), allow_private=True)
        strict = HTTPClient(3, RateLimiter(10000), verify_tls=True, allow_private=True)
        good = await insecure.fetch("lab.example.test", ["127.0.0.1"], port=port)
        bad = await strict.fetch("lab.example.test", ["127.0.0.1"], port=port)
        strict.ssl_context.load_verify_locations(cert)
        trusted = await strict.fetch("lab.example.test", ["127.0.0.1"], port=port)
    assert good.status == 200 and not good.tls_verified
    assert bad.error and "Certificate" in bad.error
    assert trusted.status == 200 and trusted.tls_verified
    assert names and all(name == "lab.example.test" for name in names)

from unittest.mock import AsyncMock

import dns.exception
import dns.message
import dns.rcode
import dns.rrset
import pytest

from danglinglens.dnscheck import Answer, DNSClient, RateLimiter, consensus
from danglinglens.models import DNSView


def answer(name, kind, state="NOERROR", records=()):
    message = dns.message.make_response(dns.message.make_query(name + ".", kind))
    message.set_rcode(dns.rcode.from_text(state))
    for owner, rrtype, data in records:
        message.answer.append(dns.rrset.from_text(owner + ".", 60, "IN", rrtype, data))
    return Answer(state, message)


async def test_recursive_nxdomain_keeps_cname_evidence():
    client = DNSClient(1, RateLimiter(100000))
    client.query = AsyncMock(
        side_effect=[
            answer("x.test", "CNAME", "NXDOMAIN", [("x.test", "CNAME", "missing.vendor.test.")]),
            answer("missing.vendor.test", "CNAME", "NXDOMAIN"),
        ]
    )
    result = await client.trace("x.test", "1.1.1.1")
    assert result.chain == ["missing.vendor.test"]
    assert result.terminal == "missing.vendor.test"
    assert result.state == "NXDOMAIN"
    assert len(result.messages) == 2


async def test_cname_loop_is_error():
    client = DNSClient(1, RateLimiter(100000))
    client.query = AsyncMock(
        side_effect=[
            answer("x.test", "CNAME", records=[("x.test", "CNAME", "y.test.")]),
            answer("y.test", "CNAME", records=[("y.test", "CNAME", "x.test.")]),
        ]
    )
    result = await client.trace("x.test", "1.1.1.1")
    assert result.state == "ERROR"
    assert result.error == "CNAME loop"


async def test_ipv6_only_is_resolved():
    client = DNSClient(1, RateLimiter(100000))
    client.query = AsyncMock(
        side_effect=[
            answer("x.test", "CNAME"),
            answer("x.test", "A"),
            answer("x.test", "AAAA", records=[("x.test", "AAAA", "2606:4700:4700::1111")]),
        ]
    )
    result = await client.trace("x.test", "1.1.1.1")
    assert result.state == "RESOLVED"
    assert result.addresses == ["2606:4700:4700::1111"]


@pytest.mark.parametrize("failure", ["NXDOMAIN", "SERVFAIL"])
async def test_address_family_failure_is_not_silently_missing(failure):
    client = DNSClient(1, RateLimiter(100000))
    client.query = AsyncMock(
        side_effect=[
            answer("x.test", "CNAME"),
            answer("x.test", "A", failure),
            answer("x.test", "AAAA"),
        ]
    )
    assert (await client.trace("x.test", "1.1.1.1")).state == "ERROR"


async def test_timeout_recorded_without_promoting_to_nxdomain(monkeypatch):
    client = DNSClient(0.1, RateLimiter(100000))
    monkeypatch.setattr(
        "dns.asyncquery.udp_with_fallback", AsyncMock(side_effect=dns.exception.Timeout)
    )
    response = await client.query("x.test", "CNAME", "1.1.1.1")
    assert response.state == "ERROR"
    assert "Timeout" in response.error


def test_cdn_ip_rotation_does_not_break_dns_agreement():
    views = [
        DNSView(
            "1.1.1.1", "x.test", ["owner.github.io"], "owner.github.io", "RESOLVED", ["1.1.1.1"]
        ),
        DNSView(
            "8.8.8.8", "x.test", ["owner.github.io"], "owner.github.io", "RESOLVED", ["8.8.8.8"]
        ),
    ]
    assert consensus(views)


@pytest.mark.parametrize(
    "reply,expected",
    [
        (answer("x.test", "A", records=[("x.test", "CNAME", "y.vendor.test.")]), True),
        (answer("x.test", "A", "NXDOMAIN", [("x.test", "CNAME", "gone.vendor.test.")]), True),
        (answer("x.test", "A", records=[("x.test", "A", "93.184.216.34")]), False),
        (answer("x.test", "A", "NXDOMAIN"), False),
        (answer("x.test", "A", "SERVFAIL"), None),
        (Answer("ERROR", error="timeout"), None),
    ],
)
async def test_quick_alias_check(reply, expected):
    client = DNSClient(1, RateLimiter(100000))
    client.query = AsyncMock(return_value=reply)
    assert await client.aliased("x.test", "1.1.1.1") is expected
    client.query.assert_awaited_once_with("x.test", "A", "1.1.1.1")

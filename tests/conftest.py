import copy

import pytest

from danglinglens.models import DNSView, HTTPView
from danglinglens.scanner import Scanner

HOST = "docs.example.test"
RESOLVERS = ["1.1.1.1", "8.8.8.8"]


class FakeDNS:
    def __init__(self, target="owner.github.io", state="RESOLVED"):
        self.target, self.state = target, state
        self.wildcard = False
        self.wildcard_error = False
        self.disagree = False
        self.change_after_first = False
        self.txt_values = []
        self.txt_state = "NOERROR"
        self.calls = []

    async def trace(self, host, resolver):
        self.calls.append((host, resolver))
        is_control = host != HOST
        target = self.target
        state = self.state
        if self.disagree and resolver == RESOLVERS[1]:
            target = "different.github.io"
        if self.change_after_first and sum(h == HOST for h, _ in self.calls) > 2:
            state = "NXDOMAIN"
        if is_control and not self.wildcard:
            target, state = None, "ERROR" if self.wildcard_error else "NXDOMAIN"
        return DNSView(
            resolver,
            host,
            [target] if target else [],
            target or host,
            state,
            ["93.184.216.34"] if state == "RESOLVED" else [],
        )

    async def txt(self, name, resolver):
        return {
            "name": name,
            "resolver": resolver,
            "state": self.txt_state,
            "values": self.txt_values,
        }


class FakeHTTP:
    def __init__(self):
        self.calls = []
        self.responses = []
        self.default = HTTPView(
            "", 404, {"server": "GitHub.com"}, "There isn't a GitHub Pages site here."
        )

    async def fetch(self, host, addresses, scheme="https", path="/"):
        self.calls.append((host, addresses, scheme, path))
        response = copy.deepcopy(self.responses.pop(0) if self.responses else self.default)
        response.url = f"{scheme}://{host}{path}"
        return response


@pytest.fixture
def rig():
    dns, http = FakeDNS(), FakeHTTP()
    return Scanner(dns, http, RESOLVERS, repeat_delay=0), dns, http

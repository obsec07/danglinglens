from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any


def utcnow() -> str:
    return datetime.now(UTC).isoformat()


@dataclass
class DNSView:
    resolver: str
    host: str
    chain: list[str] = field(default_factory=list)
    terminal: str = ""
    state: str = "ERROR"
    addresses: list[str] = field(default_factory=list)
    messages: list[str] = field(default_factory=list)
    error: str | None = None
    timestamp: str = field(default_factory=utcnow)

    def signature(self) -> tuple:
        # CDN address rotation is normal; compare routing names and DNS outcome.
        return tuple(self.chain), self.terminal, self.state


@dataclass
class HTTPView:
    url: str
    status: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    body_base64: str = ""
    body_sha256: str = ""
    bytes_read: int = 0
    truncated: bool = False
    error: str | None = None
    peer: str | None = None
    tls_verified: bool = False
    elapsed_ms: int = 0
    timestamp: str = field(default_factory=utcnow)
    request_headers: dict[str, str] = field(default_factory=dict)


@dataclass
class Result:
    host: str
    status: str = "no_signal"
    provider: str | None = None
    reasons: list[str] = field(default_factory=list)
    dns: list[DNSView] = field(default_factory=list)
    http: list[HTTPView] = field(default_factory=list)
    wildcard: dict[str, Any] = field(default_factory=dict)
    ownership: list[dict[str, Any]] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    timestamp: str = field(default_factory=utcnow)
    claimability: str = "not_verified"
    schema_version: int = 1

    def as_dict(self, include_body: bool = False) -> dict:
        result = asdict(self)
        if not include_body:
            for response in result["http"]:
                response.pop("body", None)
                response.pop("body_base64", None)
        return result

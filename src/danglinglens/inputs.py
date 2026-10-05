import ipaddress
import re
from collections.abc import Iterable, Iterator
from pathlib import Path
from urllib.parse import urlsplit

import idna


def normalize_host(value: str) -> str:
    value = value.strip()
    if any(ord(c) < 33 or ord(c) == 127 for c in value):
        raise ValueError("hostnames cannot contain whitespace or control characters")
    if "://" in value:
        parsed = urlsplit(value)
        if (
            parsed.scheme not in {"http", "https"}
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port not in {None, 80, 443}
        ):
            raise ValueError("use a hostname or HTTP(S) URL without credentials or custom ports")
        value = parsed.hostname or ""
    value = value.removesuffix(".")
    try:
        host = idna.encode(value, uts46=True, std3_rules=True).decode("ascii").lower()
    except idna.IDNAError as exc:
        raise ValueError(f"invalid hostname: {value!r}") from exc
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("IP addresses are not subdomain inputs")
    if "." not in host or len(host) > 253 or host.rsplit(".", 1)[-1].isdigit():
        raise ValueError("a fully qualified hostname is required")
    return host


def read_lines(path: str, stdin: Iterable[str]) -> Iterator[str]:
    def clean(lines: Iterable[str]) -> Iterator[str]:
        for number, line in enumerate(lines, 1):
            value = line.strip()
            if value and not value.startswith("#"):
                if len(value) > 4096:
                    raise ValueError(f"{path}:{number}: input line exceeds 4096 characters")
                yield value

    if path == "-":
        yield from clean(stdin)
    else:
        with Path(path).open(encoding="utf-8-sig") as stream:
            yield from clean(stream)


def in_scope(host: str, scopes: list[str]) -> bool:
    return not scopes or any(host == root or host.endswith("." + root) for root in scopes)


def targets(
    domains: list[str],
    paths: list[str],
    wordlist: str | None,
    scopes: list[str],
    stdin: Iterable[str],
    max_targets: int = 100_000,
) -> Iterator[str]:
    if paths.count("-") + (wordlist == "-") > 1:
        raise ValueError("stdin can be used only once")
    if wordlist and not domains:
        raise ValueError("--wordlist requires at least one --domain")
    roots = list(dict.fromkeys(normalize_host(d) for d in domains))
    seen: set[str] = set()

    def source() -> Iterator[str]:
        yield from roots
        for path in paths:
            yield from read_lines(path, stdin)
        if wordlist:
            for prefix in read_lines(wordlist, stdin):
                if prefix == "@":
                    continue  # roots are already included
                if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", prefix):
                    raise ValueError(f"invalid subdomain prefix: {prefix!r}")
                for root in roots:
                    yield f"{prefix}.{root}"

    for value in source():
        host = normalize_host(value)
        if not in_scope(host, scopes):
            raise ValueError(f"host outside --scope: {host}")
        if host in seen:
            continue
        if len(seen) >= max_targets:
            raise ValueError(f"target limit ({max_targets}) exceeded; use --max-targets")
        seen.add(host)
        yield host

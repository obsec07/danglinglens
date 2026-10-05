import argparse
import asyncio
import base64
import ipaddress
import json
import math
import sys
from collections import Counter
from contextlib import ExitStack
from pathlib import Path

from . import __version__
from .dnscheck import DNSClient, RateLimiter
from .httpcheck import HTTPClient
from .inputs import normalize_host, read_lines, targets
from .models import Result
from .output import SEVERITIES, assign_severity, severity_label
from .providers import PROVIDERS, REVIEWED
from .scanner import Scanner
from .verify import create_challenge, load_challenge, verify_marker


class PlainArgumentParser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        if sys.version_info >= (3, 14):
            kwargs["color"] = False
        super().__init__(*args, **kwargs)


def positive_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("must be a finite number greater than zero")
    return number


def positive_int(value: str) -> int:
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return number


def resolver_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise argparse.ArgumentTypeError("resolver must be an IPv4 or IPv6 address") from exc


def network_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--color",
        choices=("auto", "always", "never"),
        default="auto",
        help="severity label colors; help and JSON always stay plain (auto)",
    )
    parser.add_argument("--raw", action="store_true", help="plain result lines without progress")
    parser.add_argument("-v", "--verbose", action="store_true", help="show reasons and limitations")
    parser.add_argument(
        "--resolver",
        action="append",
        type=resolver_ip,
        help="repeat for DNS resolver IPs (default: 1.1.1.1 and 8.8.8.8)",
    )
    parser.add_argument("--timeout", type=positive_float, default=8, help="seconds per probe (8)")
    parser.add_argument(
        "--rate", type=positive_float, default=20, help="probe starts per second (20)"
    )
    parser.add_argument(
        "--repeat-delay",
        type=positive_float,
        default=1,
        help="seconds before the second evidence round (1)",
    )
    tls = parser.add_mutually_exclusive_group()
    tls.add_argument("--verify-tls", action="store_true", help="verify HTTPS certificates")
    tls.add_argument(
        "-k",
        "--insecure",
        "--no-ssl-verify",
        dest="verify_tls",
        action="store_false",
        help="disable certificate verification (default)",
    )
    parser.set_defaults(verify_tls=False)
    parser.add_argument(
        "--allow-private", action="store_true", help="allow HTTP to private/lab IPs"
    )
    parser.add_argument(
        "--max-body", type=positive_int, default=65536, help="HTTP body cap in bytes"
    )
    parser.add_argument("--jsonl", metavar="FILE", help="write all results; '-' means stdout")
    parser.add_argument(
        "--evidence-dir", type=Path, help="new directory for full JSON and raw body bytes"
    )


def parser() -> argparse.ArgumentParser:
    root = PlainArgumentParser(
        prog="danglinglens",
        description="Conservative subdomain takeover triage for authorized targets.",
    )
    root.add_argument("--version", action="version", version=__version__)
    commands = root.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="check domains or hostname lists")
    scan.add_argument("files", nargs="*", help="files containing full hostnames, or '-' for stdin")
    scan.add_argument(
        "-l",
        "--list",
        dest="lists",
        action="append",
        default=[],
        help="hostname list file (repeatable)",
    )
    scan.add_argument("-d", "--domain", action="append", default=[], help="domain (repeatable)")
    scan.add_argument("--domains-file", help="base domains to combine with --wordlist")
    scan.add_argument("-w", "--wordlist", help="relative prefixes to append to each base domain")
    scan.add_argument(
        "--scope", action="append", default=[], help="allowed domain suffix (repeatable)"
    )
    scan.add_argument(
        "-c",
        "--concurrency",
        type=positive_int,
        default=10,
        help="concurrent host workers (10; maximum 100)",
    )
    scan.add_argument(
        "--max-targets",
        type=positive_int,
        default=100_000,
        help="maximum unique hosts per scan (100000)",
    )
    scan.add_argument("--show-all", action="store_true", help="also print no_signal results")
    scan.add_argument(
        "--fail-on-observation",
        "--fail-on-candidate",
        dest="fail_on_observation",
        action="store_true",
        help="exit 1 for repeated DNS/provider observations or wildcard review",
    )
    network_options(scan)
    challenge = commands.add_parser(
        "challenge", help="generate a harmless marker for manual deployment"
    )
    challenge.add_argument("-d", "--domain", required=True)
    challenge.add_argument("-o", "--out", type=Path, required=True, help="new challenge JSON file")
    verify = commands.add_parser(
        "verify", help="read an already deployed marker; creates no resources"
    )
    verify.add_argument("--challenge", type=Path, required=True)
    verify.add_argument("--scheme", choices=["https", "http"], default="https")
    verify.add_argument(
        "--severity",
        choices=SEVERITIES,
        help="your impact assessment; applied only after verified HTTPS marker proof",
    )
    network_options(verify)
    commands.add_parser("providers", help="list reviewed provider signals and limitations")
    return root


class Reporter:
    def __init__(self, args, stream):
        self.args, self.stream = args, stream
        self.counts: Counter = Counter()

    def emit(self, result: Result) -> None:
        self.counts[result.status] += 1
        if self.stream:
            self.stream.write(json.dumps(result.as_dict(), ensure_ascii=True) + "\n")
            self.stream.flush()
        if self.args.evidence_dir:
            # The normalized hostname is safe as a basename on supported platforms.
            folder = self.args.evidence_dir / result.host
            folder.mkdir()
            (folder / "evidence.json").write_text(
                json.dumps(result.as_dict(include_body=True), indent=2, ensure_ascii=True) + "\n",
                encoding="utf-8",
            )
            for i, response in enumerate(result.http, 1):
                if response.body_base64:
                    (folder / f"response-{i}.body").write_bytes(
                        base64.b64decode(response.body_base64)
                    )
        if result.status != "no_signal" or getattr(self.args, "show_all", False):
            # No response body or server-controlled text is printed to a terminal.
            mode = (
                "never" if getattr(self.args, "raw", False) else getattr(self.args, "color", "auto")
            )
            label = severity_label(result.severity, sys.stderr, mode)
            assessment = f"severity_source={result.severity_source}"
            print(
                f"{label} [{result.status}] {result.host} "
                f"provider={result.provider or 'unknown'} {assessment} "
                f"claimability={result.claimability}",
                file=sys.stderr,
            )
            if getattr(self.args, "verbose", False):
                for reason in result.reasons:
                    print(f"  observed: {reason}", file=sys.stderr)
                for limitation in result.limitations:
                    print(f"  limitation: {limitation}", file=sys.stderr)


async def scan_many(scanner: Scanner, hosts, concurrency: int, reporter: Reporter) -> None:
    queue: asyncio.Queue[str | None] = asyncio.Queue(maxsize=concurrency * 2)

    async def produce():
        for host in hosts:
            await queue.put(host)
        for _ in range(concurrency):
            await queue.put(None)

    async def worker():
        while (host := await queue.get()) is not None:
            reporter.emit(await scanner.scan(host))

    async def heartbeat():
        while True:
            await asyncio.sleep(5)
            print(f"Progress: {sum(reporter.counts.values())} hosts completed", file=sys.stderr)

    # TaskGroup cancels siblings on errors: a bad late input cannot deadlock a full queue.
    async with asyncio.TaskGroup() as group:
        progress = None if getattr(reporter.args, "raw", False) else group.create_task(heartbeat())
        producer = group.create_task(produce())
        workers = [group.create_task(worker()) for _ in range(concurrency)]
        await producer
        await asyncio.gather(*workers)
        if progress:
            progress.cancel()


def build_scanner(args) -> Scanner:
    limiter = RateLimiter(args.rate)
    resolvers = list(dict.fromkeys(args.resolver or ["1.1.1.1", "8.8.8.8"]))
    if len(resolvers) < 2:
        raise ValueError("use at least two distinct --resolver addresses for conservative checks")
    return Scanner(
        DNSClient(args.timeout, limiter),
        HTTPClient(args.timeout, limiter, args.verify_tls, args.allow_private, args.max_body),
        resolvers,
        args.repeat_delay,
    )


def run(args) -> int:
    if args.command == "providers":
        print(f"Rules reviewed {REVIEWED}; all claimability requires manual validation.")
        for p in PROVIDERS:
            mode = "review-only" if p.suppress else "observation rules"
            print(f"{p.key}: {mode}\n  {p.caveat}\n  {p.source}")
        return 0
    if args.command == "challenge":
        challenge = create_challenge(args.domain)
        body_path = args.out.with_name(args.out.name + ".body.txt")
        if args.out.exists() or body_path.exists():
            raise ValueError("challenge output already exists; choose a new filename")
        with args.out.open("x", encoding="utf-8") as stream:
            json.dump(challenge, stream, indent=2)
            stream.write("\n")
        with body_path.open("xb") as stream:
            stream.write(challenge["body"].encode())
        print(f"Challenge: {args.out}\nBody file: {body_path}")
        print(
            f"On your authorized provider resource, serve the body file as text/plain at:\n"
            f"https://{challenge['host']}{challenge['path']}"
        )
        print("Keep random missing paths returning 404 or 410. No resource was created or claimed.")
        return 0
    scanner = build_scanner(args)
    challenge = None
    input_paths = []
    if args.command == "scan":
        if args.concurrency > 100:
            raise ValueError("--concurrency cannot exceed 100")
        paths = args.files + args.lists
        if args.domains_file:
            if args.domains_file == "-" and ("-" in paths or args.wordlist == "-"):
                raise ValueError("stdin can be used only once")
            args.domain.extend(read_lines(args.domains_file, sys.stdin))
        if not args.domain and not paths:
            raise ValueError("supply --domain, --domains-file, or a hostname list")
        scopes = [normalize_host(scope) for scope in args.scope]
        scanner.scopes = scopes
        hosts = targets(args.domain, paths, args.wordlist, scopes, sys.stdin, args.max_targets)
        input_paths = paths + [p for p in (args.wordlist, args.domains_file) if p]
    else:
        challenge = load_challenge(args.challenge)
        input_paths = [str(args.challenge)]
    if args.jsonl and args.jsonl != "-":
        if Path(args.jsonl).resolve() in {Path(p).resolve() for p in input_paths if p != "-"}:
            raise ValueError("output file must not overwrite an input file")
    if args.evidence_dir:
        args.evidence_dir.mkdir(parents=True, exist_ok=False)
    with ExitStack() as stack:
        stream = None
        if args.jsonl:
            stream = (
                sys.stdout
                if args.jsonl == "-"
                else stack.enter_context(open(args.jsonl, "x", encoding="utf-8"))
            )
        reporter = Reporter(args, stream)
        if not args.raw:
            print(
                f"DanglingLens {__version__} | TLS verification: "
                f"{'on' if args.verify_tls else 'off'} | severity is not auto-assigned",
                file=sys.stderr,
            )
        if args.command == "verify":
            result = asyncio.run(verify_marker(scanner, challenge, args.scheme))
            if args.severity is not None:
                assign_severity(result, args.severity)
            reporter.emit(result)
            return (
                0
                if result.status == "control_verified"
                else (3 if result.status == "inconclusive" else 1)
            )
        asyncio.run(scan_many(scanner, hosts, args.concurrency, reporter))
        if not args.raw:
            print(
                "Completed: " + json.dumps(dict(sorted(reporter.counts.items()))), file=sys.stderr
            )
        if not reporter.counts:
            raise ValueError("no targets found in the input")
        if reporter.counts["inconclusive"]:
            return 3
        if args.fail_on_observation and any(
            reporter.counts[s] for s in ("dangling_dns", "provider_error", "wildcard_review")
        ):
            return 1
    return 0


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    try:
        return run(args)
    except (ValueError, OSError, UnicodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except ExceptionGroup as group:
        # TaskGroup errors are kept visible, with a failing exit code; no clean-scan fiction.
        print(f"Scan interrupted; previously written results are partial: {group}", file=sys.stderr)
        for exc in group.exceptions:
            print(f"  {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Interrupted; previously written results are partial.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())

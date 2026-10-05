import asyncio
import json
from types import SimpleNamespace

import pytest

from danglinglens.cli import Reporter, main, parser, scan_many
from danglinglens.models import Result


def test_tls_default_and_aliases():
    for flags in [[], ["-k"], ["--no-ssl-verify"]]:
        assert not parser().parse_args(["scan", "-d", "example.com", *flags]).verify_tls
    assert parser().parse_args(["scan", "-d", "example.com", "--verify-tls"]).verify_tls


@pytest.mark.parametrize(
    "argv",
    [
        ["scan"],
        ["scan", "-d", "example.com", "--resolver", "1.1.1.1"],
        ["scan", "-d", "example.com", "--concurrency", "101"],
    ],
)
def test_usage_errors_do_not_scan(argv):
    assert main(argv) == 2


@pytest.mark.parametrize("value", ["0", "-1", "nan", "inf"])
def test_invalid_rate(value):
    with pytest.raises(SystemExit):
        parser().parse_args(["scan", "-d", "example.com", "--rate", value])


def test_no_overwrite_input_file(tmp_path):
    path = tmp_path / "hosts.txt"
    path.write_text("docs.example.test\n")
    assert main(["scan", str(path), "--jsonl", str(path)]) == 2
    assert path.read_text() == "docs.example.test\n"


def test_challenge_is_local_and_non_overwriting(tmp_path):
    path = tmp_path / "proof.json"
    assert main(["challenge", "-d", "docs.example.test", "-o", str(path)]) == 0
    value = json.loads(path.read_text())
    assert path.with_name("proof.json.body.txt").read_text() == value["body"]
    assert main(["challenge", "-d", "docs.example.test", "-o", str(path)]) == 2


async def test_full_queue_and_late_input_error_dont_deadlock():
    class SlowScanner:
        async def scan(self, host):
            await asyncio.sleep(0.01)
            return Result(host)

    def broken_input():
        yield from (f"x{i}.test" for i in range(8))
        raise ValueError("bad late input")

    reporter = Reporter(SimpleNamespace(evidence_dir=None, show_all=False), None)
    with pytest.raises(ExceptionGroup):
        await asyncio.wait_for(scan_many(SlowScanner(), broken_input(), 2, reporter), 1)


def test_jsonl_stdout_is_parseable(monkeypatch, capsys):
    class OfflineScanner:
        async def scan(self, host):
            return Result(host, status="inconclusive")

    monkeypatch.setattr("danglinglens.cli.build_scanner", lambda args: OfflineScanner())
    assert main(["scan", "-d", "docs.example.test", "--jsonl", "-"]) == 3
    captured = capsys.readouterr()
    assert json.loads(captured.out)["status"] == "inconclusive"
    assert "Done:" in captured.err
    assert "1 incomplete" in captured.err


def test_evidence_retains_raw_bytes_and_jsonl_omits_body(tmp_path):
    import base64
    import io

    from danglinglens.models import HTTPView

    raw = b"proof\xff\n"
    result = Result("docs.example.test", status="provider_error")
    result.http = [
        HTTPView("http://docs.example.test/", body_base64=base64.b64encode(raw).decode())
    ]
    stream = io.StringIO()
    reporter = Reporter(SimpleNamespace(evidence_dir=tmp_path, show_all=False), stream)
    reporter.emit(result)
    assert (tmp_path / result.host / "response-1.body").read_bytes() == raw
    assert "body_base64" not in json.loads(stream.getvalue())["http"][0]
    evidence = json.loads((tmp_path / result.host / "evidence.json").read_text())
    assert base64.b64decode(evidence["http"][0]["body_base64"]) == raw

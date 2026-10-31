import io
import json
import os
import subprocess
import sys
from types import SimpleNamespace

import pytest

from danglinglens.cli import Reporter, main, parser
from danglinglens.models import Result
from danglinglens.output import assign_severity, severity_label


class Terminal(io.StringIO):
    def isatty(self):
        return True


@pytest.mark.parametrize("command", [[], ["scan"], ["verify"], ["challenge"], ["providers"]])
def test_help_stays_plain_even_when_environment_forces_colors(command):
    env = dict(os.environ, FORCE_COLOR="1", PYTHON_COLORS="1", TERM="xterm-256color")
    result = subprocess.run(
        [sys.executable, "-m", "danglinglens", *command, "--help"],
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    assert "usage:" in result.stdout
    assert "\x1b" not in result.stdout + result.stderr


@pytest.mark.parametrize(
    "severity,code", [("critical", "1;97;41"), ("high", "1;31"), ("medium", "1;33")]
)
def test_requested_severity_colors(severity, code, monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "xterm")
    assert severity_label(severity, Terminal()) == f"\x1b[{code}m[{severity.upper()}]\x1b[0m"


def test_color_respects_no_color_plain_stream_and_never(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    assert severity_label("critical", io.StringIO()) == "[CRITICAL]"
    assert severity_label("high", Terminal(), "never") == "[HIGH]"
    monkeypatch.setenv("NO_COLOR", "1")
    assert severity_label("critical", Terminal(), "always") == "[CRITICAL]"


@pytest.mark.parametrize(
    "status",
    [
        "dangling_dns",
        "provider_error",
        "wildcard_review",
        "marker_observed",
        "marker_not_verified",
        "inconclusive",
    ],
)
def test_unverified_results_cannot_receive_manual_critical_severity(status):
    result = Result("docs.example.test", status=status)
    assign_severity(result, "critical")
    assert result.severity == "info"
    assert result.severity_source == "unassessed"


def test_manual_severity_does_not_claim_takeover_proof():
    result = Result("docs.example.test", status="control_verified")
    assign_severity(result, "high")
    assert result.severity == "high"
    assert result.severity_source == "operator"
    assert result.claimability == "not_verified"


def test_only_console_severity_gets_color(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    terminal, stream = Terminal(), io.StringIO()
    monkeypatch.setattr(sys, "stderr", terminal)
    result = Result("docs.example.test", status="control_verified")
    assign_severity(result, "high")
    args = SimpleNamespace(evidence_dir=None, color="always", raw=False, verbose=False)
    Reporter(args, stream).emit(result)
    assert "\x1b[1;31m[HIGH]\x1b[0m" in terminal.getvalue()
    assert "\x1b" not in stream.getvalue()
    assert json.loads(stream.getvalue())["severity_source"] == "operator"


def test_raw_overrides_always_color_and_omits_banner_and_summary(monkeypatch, capsys):
    class OfflineScanner:
        async def scan(self, host):
            return Result(host, status="provider_error")

    monkeypatch.setattr("danglinglens.cli.build_scanner", lambda args: OfflineScanner())
    assert main(["scan", "-d", "docs.example.test", "--raw", "--color", "always"]) == 0
    captured = capsys.readouterr()
    assert len(captured.err.splitlines()) == 1
    assert captured.err.startswith("[MEDIUM] docs.example.test - ")
    assert "missing-site error" in captured.err
    assert captured.err.isascii()
    assert not any(
        field in captured.err for field in ("provider=", "severity_source=", "claimability=")
    )
    assert "\x1b" not in captured.out + captured.err


def test_compatibility_flag_does_not_restore_candidate_labels():
    assert parser().parse_args(["scan", "--fail-on-candidate"]).fail_on_observation


def test_info_does_not_hide_diagnostic_failures(monkeypatch, capsys):
    class OfflineScanner:
        async def scan(self, host):
            return Result(host, status="inconclusive", reasons=["DNS disagreement"])

    monkeypatch.setattr("danglinglens.cli.build_scanner", lambda args: OfflineScanner())
    assert main(["scan", "-d", "docs.example.test", "--raw", "--show-all", "-v"]) == 3
    assert "DNS disagreement" in capsys.readouterr().err


@pytest.mark.parametrize("raw", [False, True])
def test_incomplete_hosts_are_hidden_but_saved_and_fail_the_scan(
    monkeypatch, capsys, tmp_path, raw
):
    class OfflineScanner:
        async def scan(self, host):
            return Result(host, status="inconclusive", reasons=["DNS disagreement"])

    monkeypatch.setattr("danglinglens.cli.build_scanner", lambda args: OfflineScanner())
    hosts = [f"host{i}.example.test" for i in range(4)]
    input_path = tmp_path / "hosts.txt"
    input_path.write_text("\n".join(hosts))
    evidence = tmp_path / "evidence"
    options = ["--raw"] if raw else []
    assert (
        main(["scan", str(input_path), "--jsonl", "-", "--evidence-dir", str(evidence), *options])
        == 3
    )
    captured = capsys.readouterr()
    saved = [json.loads(line) for line in captured.out.splitlines()]
    assert {row["host"] for row in saved} == set(hosts)
    assert all(row["status"] == "inconclusive" for row in saved)
    assert all(host not in captured.err for host in hosts)
    for host in hosts:
        assert json.loads((evidence / host / "evidence.json").read_text())["reasons"] == [
            "DNS disagreement"
        ]
    if raw:
        assert captured.err == ""
    else:
        assert "4 incomplete" in captured.err
        assert "--show-all -v" in captured.err


@pytest.mark.parametrize(
    "status", ["no_signal", "wildcard_review", "ownership_signal", "provider_review"]
)
def test_other_non_leads_require_show_all(status, capsys):
    args = SimpleNamespace(evidence_dir=None, show_all=False)
    reporter = Reporter(args, None)
    result = Result("docs.example.test", status=status)
    reporter.emit(result)
    assert capsys.readouterr().err == ""
    assert reporter.counts[status] == 1
    args.show_all = True
    reporter.emit(result)
    assert result.host in capsys.readouterr().err


def test_hidden_wildcard_review_keeps_requested_exit_code(monkeypatch, capsys):
    class OfflineScanner:
        async def scan(self, host):
            return Result(host, status="wildcard_review")

    monkeypatch.setattr("danglinglens.cli.build_scanner", lambda args: OfflineScanner())
    assert main(["scan", "-d", "docs.example.test", "--fail-on-observation"]) == 1
    output = capsys.readouterr().err
    assert "docs.example.test" not in output
    assert "1 to review" in output


@pytest.mark.parametrize(
    "proof_status,expected_severity,exit_code",
    [
        ("control_verified", "high", 0),
        ("marker_observed", "high", 1),
        ("inconclusive", "info", 3),
    ],
)
def test_verify_cli_serializes_assessment_only_after_proof(
    monkeypatch,
    capsys,
    tmp_path,
    proof_status,
    expected_severity,
    exit_code,
):
    from danglinglens.verify import create_challenge

    challenge = tmp_path / "challenge.json"
    challenge.write_text(json.dumps(create_challenge("docs.example.test")))

    async def fake_verify(scanner, challenge, scheme):
        return Result(challenge["host"], status=proof_status)

    monkeypatch.setattr("danglinglens.cli.verify_marker", fake_verify)
    monkeypatch.setattr("danglinglens.cli.build_scanner", lambda args: object())
    assert (
        main(
            [
                "verify",
                "--challenge",
                str(challenge),
                "--verify-tls",
                "--severity",
                "high",
                "--jsonl",
                "-",
                "--color",
                "always",
            ]
        )
        == exit_code
    )
    captured = capsys.readouterr()
    value = json.loads(captured.out)
    assert value["severity"] == expected_severity
    assert value["claimability"] == "not_verified"
    assert "\x1b" not in captured.out
    # Explicit verification failures must stay visible despite quiet scan defaults.
    assert "docs.example.test" in captured.err


def scanned(status, provider=None, target="old.target.test"):
    from danglinglens.models import DNSView

    result = Result("docs.example.test", status=status, provider=provider)
    result.dns = [DNSView("1.1.1.1", "docs.example.test", [target], target, "NXDOMAIN")]
    return result


@pytest.mark.parametrize(
    "status,provider,severity",
    [
        ("provider_error", "aws_s3", "critical"),
        ("control_verified", None, "critical"),
        ("dangling_dns", "azure_app_service", "high"),
        ("dangling_dns", "azure_blob", "high"),
        ("marker_observed", None, "high"),
        ("provider_error", "github_pages", "medium"),
        ("provider_error", "heroku", "medium"),
        ("dangling_dns", None, "medium"),
        ("wildcard_review", None, "info"),
        ("ownership_signal", "azure_app_service", "info"),
        ("provider_review", "cloudfront", "info"),
        ("inconclusive", None, "info"),
        ("no_signal", None, "info"),
    ],
)
def test_rule_severity(status, provider, severity):
    from danglinglens.output import apply_rule

    result = scanned(status, provider)
    apply_rule(result)
    assert result.severity == severity
    assert result.severity_source == ("unassessed" if severity == "info" else "rule")


def test_finding_line_shows_severity_target_and_reason():
    from danglinglens.output import result_line

    line = result_line(scanned("provider_error", "aws_s3", "b.s3.amazonaws.com"), io.StringIO())
    assert line == (
        "[CRITICAL] docs.example.test -> b.s3.amazonaws.com - "
        "Amazon S3: the bucket with this exact name does not exist"
    )


def test_only_findings_are_printed_with_summary_by_severity(monkeypatch, capsys):
    results = {
        "a.example.test": ("provider_error", "aws_s3"),
        "b.example.test": ("dangling_dns", "azure_app_service"),
        "c.example.test": ("dangling_dns", None),
        "d.example.test": ("no_signal", None),
        "e.example.test": ("wildcard_review", None),
    }

    class OfflineScanner:
        async def scan(self, host):
            status, provider = results[host]
            return Result(host, status=status, provider=provider)

    monkeypatch.setattr("danglinglens.cli.build_scanner", lambda args: OfflineScanner())
    assert main([*results, "--color", "never"]) == 0
    err = capsys.readouterr().err
    assert "[CRITICAL] a.example.test" in err
    assert "[HIGH] b.example.test" in err
    assert "[MEDIUM] c.example.test" in err
    assert "d.example.test" not in err and "e.example.test" not in err
    assert "5 checked" in err and "1 critical, 1 high, 1 medium" in err and "1 to review" in err

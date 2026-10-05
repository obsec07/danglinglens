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


@pytest.mark.parametrize("severity,code", [("critical", "31"), ("high", "33")])
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
    assert "\x1b[33m[HIGH]\x1b[0m" in terminal.getvalue()
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
    assert captured.err.startswith("[INFO] [provider_error]")
    assert "\x1b" not in captured.out + captured.err


def test_compatibility_flag_does_not_restore_candidate_labels():
    assert parser().parse_args(["scan", "--fail-on-candidate"]).fail_on_observation


def test_info_does_not_hide_diagnostic_failures(monkeypatch, capsys):
    class OfflineScanner:
        async def scan(self, host):
            return Result(host, status="inconclusive", reasons=["DNS disagreement"])

    monkeypatch.setattr("danglinglens.cli.build_scanner", lambda args: OfflineScanner())
    assert main(["scan", "-d", "docs.example.test", "--raw", "-v"]) == 3
    assert "DNS disagreement" in capsys.readouterr().err


@pytest.mark.parametrize(
    "proof_status,expected_severity,exit_code",
    [
        ("control_verified", "high", 0),
        ("marker_observed", "info", 1),
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

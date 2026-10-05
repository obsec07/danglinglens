"""Color severity labels only; keep help, raw output and JSON free of ANSI."""

import os

SEVERITIES = ("critical", "high", "medium", "low", "info")
COLORS = {"critical": "31", "high": "33", "medium": "35", "low": "36"}


def severity_label(severity: str, stream, mode: str = "auto") -> str:
    if severity not in SEVERITIES:
        raise ValueError(f"unknown severity: {severity}")
    label = f"[{severity.upper()}]"
    enabled = (
        mode != "never"
        and "NO_COLOR" not in os.environ
        and (mode == "always" or (stream.isatty() and os.environ.get("TERM") != "dumb"))
    )
    if enabled and severity in COLORS:
        return f"\033[{COLORS[severity]}m{label}\033[0m"
    return label


def assign_severity(result, severity: str) -> None:
    """An operator assessment does not change what the verifier actually proved."""
    if result.status == "control_verified":
        result.severity = severity
        result.severity_source = "operator"
    elif severity != "info":
        result.reasons.append("Requested severity was not applied: HTTPS marker proof did not pass")

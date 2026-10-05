"""Color severity labels only; keep help, raw output and JSON free of ANSI."""

import os

from .models import Result

SEVERITIES = ("critical", "high", "medium", "low", "info")
COLORS = {"critical": "31", "high": "33", "medium": "35", "low": "36"}
SCAN_LEADS = frozenset({"dangling_dns", "provider_error"})
PROVIDER_NAMES = {
    "aws_s3": "Amazon S3",
    "github_pages": "GitHub Pages",
    "azure_app_service": "Azure App Service",
    "azure_blob": "Azure Blob Storage",
    "heroku": "Heroku",
    "netlify": "Netlify",
    "cloudfront": "CloudFront",
    "fastly": "Fastly",
    "google_cloud_storage": "Google Cloud Storage",
}


def result_line(result: Result, stream, mode: str = "auto") -> str:
    """Plain-language console text; evidence fields keep their machine-readable values."""
    provider = PROVIDER_NAMES.get(result.provider, "the provider")
    messages = {
        "dangling_dns": ("CHECK", "DNS points to a missing name; takeover? idk twin"),
        "provider_error": (
            "CHECK",
            f"missing-site error from {provider}; takeover? idk twin",
        ),
        "wildcard_review": (
            "REVIEW",
            "random names point to the same place; no clear lead",
        ),
        "ownership_signal": (
            "REVIEW",
            "ownership record found; the provider may block other accounts",
        ),
        "provider_review": (
            "REVIEW",
            f"{provider} needs a manual check; takeover? idk twin",
        ),
        "inconclusive": ("SKIP", "couldn't finish this check, twin"),
        "no_signal": ("SKIP", "no supported takeover signal"),
        "control_verified": ("MARKER OK", "your marker checked out over verified HTTPS"),
        "marker_observed": (
            "RECHECK",
            "marker found; rerun with --scheme https --verify-tls to check HTTPS",
        ),
        "marker_not_verified": ("NO PROOF", "marker check failed; no proof yet, twin"),
    }
    label, message = messages.get(
        result.status, ("REVIEW", "idk twin, this result needs a closer look")
    )
    label = f"[{label}]"
    if result.status == "control_verified" and result.severity_source == "operator":
        label = severity_label(result.severity, stream, mode)
        message += "; impact rated by you"
    return f"{label} {result.host} - {message}"


def scan_summary(counts) -> str:
    leads = sum(counts.get(status, 0) for status in SCAN_LEADS)
    message = f"Done: {sum(counts.values())} checked, {leads} leads"
    reviews = sum(
        counts.get(status, 0)
        for status in ("wildcard_review", "ownership_signal", "provider_review")
    )
    if reviews:
        message += f", {reviews} need review"
    incomplete = counts.get("inconclusive", 0)
    if incomplete:
        message += f", {incomplete} incomplete"
    if incomplete or reviews:
        message += ". Details: --show-all -v"
    return message + "."


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

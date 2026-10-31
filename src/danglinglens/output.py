"""What the console shows: one colored line per takeover finding, nothing else by default.

Severity comes from rules over the evidence (severity_source "rule"), or from you after a verified
marker (severity_source "operator"). Help, --raw output and JSON never contain ANSI colors.
"""

import os

from .models import Result

SEVERITIES = ("critical", "high", "medium", "low", "info")
# critical: white on red; high: bold red; medium: bold yellow; low: cyan
COLORS = {"critical": "1;97;41", "high": "1;31", "medium": "1;33", "low": "36"}
FINDINGS = ("critical", "high", "medium")
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
# Global, first-come names: NXDOMAIN for the target means the name itself is unused.
FREE_NAME_PROVIDERS = {"azure_app_service", "azure_blob"}


def rule(result: Result) -> tuple[str, str]:
    """(severity, plain-language reason) for a result; "info" means it is not a finding."""
    provider = PROVIDER_NAMES.get(result.provider or "", "")
    if result.status == "control_verified":
        return "critical", "takeover proven: your marker is served on this host over verified HTTPS"
    if result.status == "marker_observed":
        return "high", "your marker is served here; rerun verify with --verify-tls to prove it"
    if result.status == "provider_error" and result.provider == "aws_s3":
        return "critical", "Amazon S3: the bucket with this exact name does not exist"
    if result.status == "provider_error":
        return (
            "medium",
            f"{provider or 'Provider'}: missing-site error; check the domain can be attached",
        )
    if result.status == "dangling_dns" and result.provider in FREE_NAME_PROVIDERS:
        return (
            "high",
            f"{provider}: the target name does not exist and no ownership record was found",
        )
    if result.status == "dangling_dns":
        where = f"{provider}: " if provider else ""
        return "medium", f"{where}CNAME points to a name that no longer exists"
    return "info", ""


def apply_rule(result: Result) -> None:
    """Rate a result from its evidence, unless you already rated it after a verified marker."""
    if result.severity_source == "operator":
        return
    severity, _ = rule(result)
    result.severity = severity
    result.severity_source = "rule" if severity != "info" else "unassessed"


def target_of(result: Result) -> str:
    for view in result.dns:
        if view.chain:
            return view.chain[-1]
    return ""


OTHER = {
    "wildcard_review": "random names route the same way (wildcard); not a finding",
    "ownership_signal": "Azure ownership record found; another account cannot attach it",
    "provider_review": "provider needs a manual check; not a finding",
    "inconclusive": "could not finish the checks",
    "no_signal": "no takeover signal",
    "marker_not_verified": "marker check failed; no proof",
}


def result_line(result: Result, stream, mode: str = "auto") -> str:
    """One line: severity, host, where it points, and why. ASCII only."""
    severity, reason = rule(result)
    if result.severity_source == "operator" and result.status == "control_verified":
        severity, reason = result.severity, reason + "; impact rated by you"
    if severity == "info":
        return f"[INFO] {result.host} - {OTHER.get(result.status, result.status)}"
    target = target_of(result)
    via = f" -> {target}" if target and target != result.host else ""
    return f"{severity_label(severity, stream, mode)} {result.host}{via} - {reason}"


def scan_summary(counts, severities, seconds: float | None = None) -> str:
    took = f" in {seconds:.0f}s" if seconds is not None else ""
    checked = f"Done: {sum(counts.values())} checked{took}"
    found = [f"{severities[s]} {s}" for s in FINDINGS if severities.get(s)]
    message = checked + (" - " + ", ".join(found) if found else " - no takeovers found")
    extra = []
    reviews = sum(
        counts.get(s, 0) for s in ("wildcard_review", "ownership_signal", "provider_review")
    )
    if reviews:
        extra.append(f"{reviews} to review")
    if counts.get("inconclusive", 0):
        extra.append(f"{counts['inconclusive']} incomplete")
    if extra:
        message += f" ({', '.join(extra)}; details: --show-all -v)"
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
    """Your impact rating, accepted only after the HTTPS marker check passed."""
    if result.status == "control_verified":
        result.severity = severity
        result.severity_source = "operator"
    elif severity != "info":
        result.reasons.append("Requested severity was not applied: HTTPS marker proof did not pass")

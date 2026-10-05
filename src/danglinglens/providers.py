"""Small, reviewed signal set. No rule asserts exact-name claimability."""

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass

from .models import HTTPView

CATALOG = "https://github.com/EdOverflow/can-i-take-over-xyz"
REVIEWED = "2026-10-05"


@dataclass(frozen=True)
class Provider:
    key: str
    suffixes: tuple[str, ...]
    source: str
    caveat: str
    fingerprint: str | None = None
    statuses: tuple[int, ...] = (404,)
    header: tuple[str, str] | None = None
    suppress: bool = False

    def matches_host(self, host: str) -> bool:
        if self.key == "aws_s3":
            return bool(
                re.fullmatch(
                    r".+\.s3(?:[.-]website)?(?:[.-][a-z0-9-]+)?\.amazonaws\.com(?:\.cn)?",
                    host,
                )
            )
        return any(host == suffix or host.endswith("." + suffix) for suffix in self.suffixes)

    def matches_response(self, response: HTTPView, host: str) -> bool:
        if response.error or response.truncated or response.status not in self.statuses:
            return False
        if self.header:
            key, value = self.header
            if value not in response.headers.get(key, "").lower():
                return False
        if self.key == "aws_s3":
            # Reject copied strings, wrong bucket names, AccessDenied, and missing objects.
            if "<!DOCTYPE" in response.body.upper() or "<!ENTITY" in response.body.upper():
                return False
            try:
                root = ET.fromstring(response.body)
            except ET.ParseError:
                return False
            return (
                root.tag == "Error"
                and root.findtext("Code") == "NoSuchBucket"
                and root.findtext("BucketName") == host
            )
        return self.fingerprint is not None and self.fingerprint in response.body


PROVIDERS = (
    Provider(
        "aws_s3",
        (),
        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/VirtualHosting.html",
        "The original Host selects the bucket. Check exact bucket name, namespace, region, "
        "reservation and account restrictions; NoSuchBucket does not prove it is claimable.",
        header=("server", "amazons3"),
    ),
    Provider(
        "github_pages",
        ("github.io",),
        "https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site/"
        "verifying-your-custom-domain-for-github-pages",
        "Account-level verification of this domain or its immediate parent may block claims. "
        "Its username-specific TXT name cannot be exhaustively discovered by this scanner.",
        "There isn't a GitHub Pages site here.",
        header=("server", "github.com"),
    ),
    Provider(
        "azure_app_service",
        ("azurewebsites.net",),
        "https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover",
        "asuid TXT ownership records, reserved names, and generated default hostnames can "
        "prevent a claim; a missing app is not enough.",
        "404 Web Site not found",
    ),
    Provider(
        "azure_blob",
        ("blob.core.windows.net",),
        "https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover",
        "Validate storage-account name availability and custom-domain binding in the provider. "
        "A missing container is not a missing storage account.",
    ),
    Provider(
        "heroku",
        ("herokuapp.com", "herokudns.com", "herokuspace.com"),
        "https://devcenter.heroku.com/articles/custom-domains",
        "Generated DNS targets, existing domain bindings, wildcard ownership and wildcard "
        "certificates can block another account; check the exact binding.",
        "No such app",
        (404,),
        ("server", "heroku"),
    ),
    Provider(
        "netlify",
        ("netlify.app", "netlify.com"),
        "https://docs.netlify.com/manage/domains/manage-domains/assign-a-domain-to-your-site-app/",
        "A missing deployment does not show whether the exact domain can be reassigned "
        "to another account. Check current ownership restrictions.",
        "Not Found - Request ID:",
        (404,),
        ("server", "netlify"),
    ),
    # These identify common misleading historical signatures. They never produce candidates.
    Provider(
        "cloudfront",
        ("cloudfront.net",),
        "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/CNAMEs.html",
        "CloudFront distribution names are assigned; certificate and alias ownership checks "
        "require separate validation. No automatic takeover inference.",
        suppress=True,
    ),
    Provider(
        "fastly",
        ("fastly.net", "fastlylb.net"),
        CATALOG,
        "The historical unknown-domain fingerprint is not claimability evidence.",
        suppress=True,
    ),
    Provider(
        "google_cloud_storage",
        ("storage.googleapis.com",),
        CATALOG,
        "NoSuchBucket on Google Cloud Storage is not an S3 finding; domain ownership "
        "verification requires separate review.",
        suppress=True,
    ),
)


def identify(chain: list[str]) -> Provider | None:
    # Prefer the first recognizable customer-facing hop, not the final shared cloud backend.
    return next((p for target in chain for p in PROVIDERS if p.matches_host(target)), None)

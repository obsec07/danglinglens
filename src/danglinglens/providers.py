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
            if value != response.headers.get(key, "").strip().lower():
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
        "The requested hostname chooses the bucket. A missing bucket is only a lead. "
        "Check whether your account can create that exact name in the required region and "
        "namespace; reserved names and account rules may block it.",
        header=("server", "amazons3"),
    ),
    Provider(
        "github_pages",
        ("github.io",),
        "https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site/"
        "verifying-your-custom-domain-for-github-pages",
        "GitHub may already protect this domain or its direct parent for another account. "
        "A missing Pages site does not mean you can attach the domain to yours. The proof "
        "record uses the owner's username, so this scanner cannot check every possible record.",
        "There isn't a GitHub Pages site here.",
        header=("server", "github.com"),
    ),
    Provider(
        "azure_app_service",
        ("azurewebsites.net",),
        "https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover",
        "Azure may require a DNS ownership record (asuid), reserve the name, or assign a "
        "hostname you cannot choose. A missing app does not prove another account can use it.",
        "404 Web Site not found",
    ),
    Provider(
        "azure_blob",
        ("blob.core.windows.net",),
        "https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover",
        "Check whether Azure lets your account create that exact storage-account name and "
        "attach this domain. A missing container does not mean the storage account is missing.",
    ),
    Provider(
        "heroku",
        ("herokuapp.com", "herokudns.com", "herokuspace.com"),
        "https://devcenter.heroku.com/articles/custom-domains",
        "Heroku may assign a target you cannot choose or already link the domain to another "
        "account. Wildcard domains and certificates can also block a claim. Check whether "
        "your account can attach this exact domain.",
        "No such app",
        (404,),
        ("server", "heroku"),
    ),
    Provider(
        "netlify",
        ("netlify.app", "netlify.com"),
        "https://docs.netlify.com/manage/domains/manage-domains/assign-a-domain-to-your-site-app/",
        "A missing Netlify site does not mean the domain is free. Check whether Netlify lets "
        "your account attach this exact domain; another account may still own the link.",
        "Not Found - Request ID:",
        (404,),
        ("server", "netlify"),
    ),
    # These identify common misleading historical signatures. They never produce candidates.
    Provider(
        "cloudfront",
        ("cloudfront.net",),
        "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/CNAMEs.html",
        "AWS assigns CloudFront names; you cannot simply choose the missing one. Certificates "
        "and domain-ownership checks may also block another account from using the domain.",
        suppress=True,
    ),
    Provider(
        "fastly",
        ("fastly.net", "fastlylb.net"),
        CATALOG,
        "Fastly's unknown-domain error alone does not prove another account can use the domain.",
        suppress=True,
    ),
    Provider(
        "google_cloud_storage",
        ("storage.googleapis.com",),
        CATALOG,
        "Google's NoSuchBucket error is not an Amazon S3 result. Google may require proof "
        "that you own the domain before another account can use it.",
        suppress=True,
    ),
)


def identify(chain: list[str]) -> Provider | None:
    # Prefer the first recognizable customer-facing hop, not the final shared cloud backend.
    return next((p for target in chain for p in PROVIDERS if p.matches_host(target)), None)

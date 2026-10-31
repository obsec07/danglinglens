import pytest

from danglinglens.models import HTTPView
from danglinglens.providers import identify


@pytest.mark.parametrize(
    "target",
    [
        "bucket.s3.amazonaws.com",
        "bucket.s3.us-east-1.amazonaws.com",
        "bucket.s3-website-us-east-1.amazonaws.com",
        "bucket.s3-website.eu-west-2.amazonaws.com",
        "bucket.s3.cn-north-1.amazonaws.com.cn",
        "bucket.s3.dualstack.us-east-1.amazonaws.com",
        "bucket.s3-accelerate.amazonaws.com",
    ],
)
def test_s3_endpoint_forms(target):
    assert identify([target]).key == "aws_s3"


@pytest.mark.parametrize(
    "target",
    [
        "owner.github.io.evil.test",
        "notgithub.io",
        "bucket.s3.amazonaws.com.evil.test",
        "s3.amazonaws.com",
        "owner.azurewebsites.net.evil.test",
    ],
)
def test_provider_suffix_spoofing(target):
    assert identify([target]) is None


def s3_response(code="NoSuchBucket", bucket="docs.example.test"):
    return HTTPView(
        "https://docs.example.test/",
        404,
        {"server": "AmazonS3"},
        f"<Error><Code>{code}</Code><BucketName>{bucket}</BucketName></Error>",
    )


def test_s3_requires_exact_original_host_bucket():
    provider = identify(["bucket.s3.amazonaws.com"])
    assert provider.matches_response(s3_response(), "docs.example.test")
    assert not provider.matches_response(s3_response(bucket="other"), "docs.example.test")
    assert not provider.matches_response(s3_response(code="NoSuchKey"), "docs.example.test")
    assert not provider.matches_response(s3_response(code="AccessDenied"), "docs.example.test")


def test_s3_rejects_entity_declarations_and_generic_text():
    provider = identify(["bucket.s3.amazonaws.com"])
    response = s3_response()
    response.body = '<!DOCTYPE foo [<!ENTITY x "expanded">]>' + response.body
    assert not provider.matches_response(response, "docs.example.test")
    response.body = "Article about NoSuchBucket"
    assert not provider.matches_response(response, "docs.example.test")


def s3_website_response(code="NoSuchBucket", bucket="docs.example.test", heading="404 Not Found"):
    # The page S3 website endpoints return for a missing bucket.
    return HTTPView(
        "http://docs.example.test/",
        404,
        {"server": "AmazonS3"},
        "<html>\n<head><title>404 Not Found</title></head>\n<body>\n"
        f"<h1>{heading}</h1>\n<ul>\n<li>Code: {code}</li>\n"
        "<li>Message: The specified bucket does not exist</li>\n"
        f"<li>BucketName: {bucket}</li>\n<li>RequestId: ABC123</li>\n"
        "<li>HostId: abc=</li>\n</ul>\n<hr/>\n</body>\n</html>\n",
    )


def test_s3_website_html_missing_bucket():
    provider = identify(["docs.example.test.s3-website-us-east-1.amazonaws.com"])
    assert provider.matches_response(s3_website_response(), "docs.example.test")
    assert not provider.matches_response(s3_website_response(bucket="other"), "docs.example.test")
    assert not provider.matches_response(s3_website_response(code="NoSuchKey"), "docs.example.test")
    assert not provider.matches_response(
        s3_website_response(heading="403 Forbidden"), "docs.example.test"
    )


def test_s3_website_html_needs_s3_identity_and_one_answer():
    provider = identify(["docs.example.test.s3-website-us-east-1.amazonaws.com"])
    response = s3_website_response()
    response.headers = {"server": "nginx"}
    assert not provider.matches_response(response, "docs.example.test")
    response = s3_website_response()
    response.body = response.body.replace("</ul>", "<li>BucketName: someone-else</li>\n</ul>")
    assert not provider.matches_response(response, "docs.example.test")
    response = s3_website_response()
    response.status = 200
    assert not provider.matches_response(response, "docs.example.test")

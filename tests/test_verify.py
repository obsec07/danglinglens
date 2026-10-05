import base64
import json

import pytest
from conftest import HOST

from danglinglens.models import HTTPView
from danglinglens.verify import create_challenge, load_challenge, verify_marker


def marker_response(challenge, trusted=True):
    body = challenge["body"]
    return HTTPView(
        "",
        200,
        {"content-type": "text/plain; charset=utf-8"},
        body,
        base64.b64encode(body.encode()).decode(),
        tls_verified=trusted,
    )


@pytest.mark.parametrize(
    "trusted,expected",
    [
        (True, "control_verified"),
        (False, "marker_observed"),
    ],
)
async def test_marker_positive_and_negative_controls(rig, trusted, expected):
    scanner, _, http = rig
    challenge = create_challenge(HOST)
    good = marker_response(challenge, trusted)
    missing = HTTPView("", 404, {}, "missing", tls_verified=trusted)
    http.responses = [good, missing, good, missing]
    result = await verify_marker(scanner, challenge)
    assert result.status == expected
    assert result.claimability == "not_verified"
    assert len(http.calls) == 4
    assert all(challenge["body"].strip() not in call[3] for call in http.calls)


async def test_catch_all_marker_fails(rig):
    scanner, _, http = rig
    challenge = create_challenge(HOST)
    http.default = marker_response(challenge)
    assert (await verify_marker(scanner, challenge)).status == "marker_not_verified"


async def test_reflection_in_html_is_not_exact_plain_text_proof(rig):
    scanner, _, http = rig
    challenge = create_challenge(HOST)
    good = marker_response(challenge)
    good.headers["content-type"] = "text/html"
    http.responses = [good, HTTPView("", 404)]
    assert (await verify_marker(scanner, challenge)).status == "marker_not_verified"


async def test_negative_path_error_is_inconclusive(rig):
    scanner, _, http = rig
    challenge = create_challenge(HOST)
    http.responses = [marker_response(challenge), HTTPView("", error="timeout")]
    assert (await verify_marker(scanner, challenge)).status == "inconclusive"


async def test_dns_change_during_proof_is_inconclusive(rig):
    scanner, dns, http = rig
    challenge = create_challenge(HOST)
    dns.change_after_first = True
    http.responses = [marker_response(challenge), HTTPView("", 404)]
    assert (await verify_marker(scanner, challenge)).status == "inconclusive"


def test_challenge_validation(tmp_path):
    path = tmp_path / "challenge.json"
    challenge = create_challenge(HOST)
    path.write_text(json.dumps(challenge))
    assert load_challenge(path) == challenge
    challenge["path"] = "//evil.test/token"
    path.write_text(json.dumps(challenge))
    with pytest.raises(ValueError, match="path"):
        load_challenge(path)

import pytest
from conftest import HOST

from danglinglens.models import HTTPView


async def test_repeated_provider_fingerprint_is_an_unassessed_observation(rig):
    scanner, dns, http = rig
    result = await scanner.scan(HOST)
    assert result.status == "provider_error"
    assert result.severity == "info"
    assert result.severity_source == "unassessed"
    assert result.claimability == "not_verified"
    assert len(result.dns) == 4
    assert len(result.http) == 4
    assert all(call[0] == HOST for call in http.calls)


@pytest.mark.parametrize("state", ["ERROR", "SERVFAIL", "REFUSED"])
async def test_dns_failures_never_mean_dangling(rig, state):
    scanner, dns, http = rig
    dns.state = state
    result = await scanner.scan(HOST)
    assert result.status == "inconclusive"
    assert not http.calls


async def test_resolver_disagreement(rig):
    scanner, dns, http = rig
    dns.disagree = True
    assert (await scanner.scan(HOST)).status == "inconclusive"
    assert not http.calls


async def test_same_resolver_cannot_fake_corroboration(rig):
    scanner, _, _ = rig
    scanner.resolvers = ["1.1.1.1", "1.1.1.1"]
    assert (await scanner.scan(HOST)).status == "inconclusive"


async def test_nxdomain_input_without_alias_is_not_takeover(rig):
    scanner, dns, http = rig
    dns.target, dns.state = None, "NXDOMAIN"
    assert (await scanner.scan(HOST)).status == "no_signal"
    assert not http.calls


async def test_alias_to_missing_name_reports_dns_observation_only(rig):
    scanner, dns, http = rig
    dns.target, dns.state = "old.vendor.test", "NXDOMAIN"
    result = await scanner.scan(HOST)
    assert result.status == "dangling_dns"
    assert result.severity == "info"
    assert result.claimability == "not_verified"
    assert not http.calls


async def test_nodata_is_not_nxdomain(rig):
    scanner, dns, _ = rig
    dns.state = "NODATA"
    assert (await scanner.scan(HOST)).status == "inconclusive"


async def test_wildcard_is_separate_review(rig):
    scanner, dns, _ = rig
    dns.wildcard = True
    result = await scanner.scan(HOST)
    assert result.status == "wildcard_review"
    assert len(result.wildcard["controls"]) == 2


async def test_failed_wildcard_controls_block_candidate(rig):
    scanner, dns, _ = rig
    dns.wildcard_error = True
    assert (await scanner.scan(HOST)).status == "inconclusive"


async def test_wildcard_controls_respect_scope_boundary(rig):
    scanner, dns, _ = rig
    scanner.scopes = [HOST]
    await scanner.scan(HOST)
    assert all(host == HOST or host.endswith("." + HOST) for host, _ in dns.calls)


async def test_changing_dns_blocks_candidate(rig):
    scanner, dns, _ = rig
    dns.change_after_first = True
    assert (await scanner.scan(HOST)).status == "inconclusive"


@pytest.mark.parametrize(
    "field,value",
    [
        ("body", "Generic 404"),
        ("status", 200),
        ("headers", {"server": "unrelated"}),
    ],
)
async def test_non_provider_response_is_not_candidate(rig, field, value):
    scanner, _, http = rig
    setattr(http.default, field, value)
    assert (await scanner.scan(HOST)).status == "no_signal"


@pytest.mark.parametrize("field,value", [("error", "TLS failure"), ("truncated", True)])
async def test_broken_http_is_inconclusive(rig, field, value):
    scanner, _, http = rig
    setattr(http.default, field, value)
    assert (await scanner.scan(HOST)).status == "inconclusive"


async def test_live_https_conflicts_with_http_fingerprint(rig):
    scanner, _, http = rig
    http.responses = [HTTPView("", 200, {}, "real site")]
    assert (await scanner.scan(HOST)).status == "inconclusive"


async def test_match_must_repeat_on_same_scheme(rig):
    scanner, _, http = rig
    good = http.default
    bad = HTTPView("", 404, {}, "ordinary error")
    http.responses = [good, bad, bad, good]
    assert (await scanner.scan(HOST)).status == "inconclusive"


@pytest.mark.parametrize(
    "txt_state,values,expected",
    [
        ("NOERROR", ["ownership-id"], "ownership_signal"),
        ("ERROR", [], "inconclusive"),
        ("NXDOMAIN", [], "dangling_dns"),
    ],
)
async def test_azure_ownership_controls(rig, txt_state, values, expected):
    scanner, dns, _ = rig
    dns.target, dns.state = "old.azurewebsites.net", "NXDOMAIN"
    dns.txt_state, dns.txt_values = txt_state, values
    result = await scanner.scan(HOST)
    assert result.status == expected
    assert all(v["name"] == f"asuid.{HOST}" for v in result.ownership)


@pytest.mark.parametrize(
    "target",
    [
        "gone.cloudfront.net",
        "gone.fastly.net",
        "storage.googleapis.com",
    ],
)
async def test_historical_protected_providers_never_auto_candidate(rig, target):
    scanner, dns, _ = rig
    dns.target, dns.state = target, "NXDOMAIN"
    assert (await scanner.scan(HOST)).status == "provider_review"


@pytest.mark.parametrize(
    "other",
    [
        HTTPView("", error="TLS failed"),
        HTTPView("", 404, truncated=True),
        HTTPView("", 403),
        HTTPView("", 429),
        HTTPView("", 503),
        HTTPView("", 301, {"location": "https://active.other.test/"}),
        HTTPView("", 302, {"location": "https://docs.example.test/login"}),
        HTTPView("", 301, {"location": "https://docs.example.test:444/"}),
        HTTPView("", 301),
    ],
)
@pytest.mark.parametrize("round_number", [1, 2])
async def test_matching_fingerprint_cannot_hide_a_failed_other_protocol(rig, other, round_number):
    scanner, _, http = rig
    good = http.default
    http.responses = ([good, good] if round_number == 2 else []) + [good, other]
    assert (await scanner.scan(HOST)).status == "inconclusive"


async def test_redirect_allowed_only_to_the_matching_original_host_root(rig):
    scanner, _, http = rig
    redirect = HTTPView("", 301, {"location": f"https://{HOST}/"})
    http.responses = [http.default, redirect, http.default, redirect]
    assert (await scanner.scan(HOST)).status == "provider_error"


async def test_provider_word_inside_unrelated_server_name_is_not_a_match(rig):
    scanner, _, http = rig
    http.default.headers = {"server": "not-github.com"}
    assert (await scanner.scan(HOST)).status == "no_signal"

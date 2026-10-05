import pytest

from danglinglens.inputs import in_scope, normalize_host, targets


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (" Example.COM. ", "example.com"),
        ("https://Docs.Example.com/path?q=1", "docs.example.com"),
        ("bücher.example", "xn--bcher-kva.example"),
    ],
)
def test_normalize(value, expected):
    assert normalize_host(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "*.example.com",
        "127.0.0.1",
        "2130706433",
        "a.local\nHost:x",
        "-x.example.com",
        "localhost",
        "https://user:pass@example.com",
        "file:///tmp/test",
        "a.example:8080",
        "https://example.com:444",
        "example..com",
        "a.example.com;id",
        "https://example.com/\x1b",
        "example.com/abc",
        "a" * 64 + ".example.com",
    ],
)
def test_invalid_host(value):
    with pytest.raises(ValueError):
        normalize_host(value)


def test_scope_checks_label_boundary():
    assert in_scope("a.example.com", ["example.com"])
    assert not in_scope("notexample.com", ["example.com"])
    assert not in_scope("example.com.evil.test", ["example.com"])


def test_domain_wordlist_and_full_list_deduplicate(tmp_path):
    words = tmp_path / "words.txt"
    words.write_text("# comment\nwww\napi.dev\n@\nwww\n")
    hostfile = tmp_path / "hosts.txt"
    hostfile.write_text("https://WWW.example.com/\n")
    result = list(targets(["example.com"], [str(hostfile)], str(words), [], []))
    assert result == ["example.com", "www.example.com", "api.dev.example.com"]


def test_stdin_and_limit():
    assert list(targets([], ["-"], None, [], ["# hi", "a.example.com"])) == ["a.example.com"]
    with pytest.raises(ValueError, match="limit"):
        list(targets(["a.example.com", "b.example.com"], [], None, [], [], 1))
    with pytest.raises(ValueError, match="only once"):
        list(targets(["example.com"], ["-"], "-", [], []))


def test_bad_scope_and_missing_base():
    with pytest.raises(ValueError, match="outside"):
        list(targets(["evil.test"], [], None, ["example.com"], []))
    with pytest.raises(ValueError, match="requires"):
        list(targets([], [], "words.txt", [], []))

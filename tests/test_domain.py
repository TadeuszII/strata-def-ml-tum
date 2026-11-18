"""Tests for strata_def_features.domain (URL decomposition)."""

from __future__ import annotations

import json
import socket

import pytest

from strata_def_features.domain import (
    PathPlatform,
    PlatformList,
    UrlParseError,
    _extractor_for,
    _private_psl_suffixes,
    build_extractor,
    parse_url,
    private_suffixes_under,
)

PLATFORMS = PlatformList(
    path_platforms=(PathPlatform("sites.google.com", ("/view/", "/site/")),),
    subdomain_platforms=("weebly.com",),
)

# Same domain as xn--pypal-4ve.com, written with a Cyrillic small a (U+0430).
CYRILLIC_PAYPAL = "p\u0430ypal.com"


# --------------------------------------------------------------------------- S-B1: suffixes


def test_sb1_co_uk_is_not_the_registrable_domain() -> None:
    """S-B1: paypa1.co.uk must not collapse to co.uk; query string is redacted."""
    t = parse_url("https://paypa1.co.uk/login?session=abc", PLATFORMS)
    assert t.registrable_domain == "paypa1.co.uk"
    assert t.suffix == "co.uk"
    assert t.subdomain == ""
    assert t.url_redacted == "https://paypa1.co.uk/login"
    assert "session=abc" not in t.url_redacted
    assert t.url == "https://paypa1.co.uk/login?session=abc"
    assert t.on_platform is False


@pytest.mark.parametrize(
    ("url", "domain"),
    [("https://paypa1.com.pl/", "paypa1.com.pl"), ("https://allegr0.com.pl/", "allegr0.com.pl")],
)
def test_sb1_com_pl(url: str, domain: str) -> None:
    """S-B1: second-level Polish suffix com.pl."""
    t = parse_url(url, PLATFORMS)
    assert t.registrable_domain == domain
    assert t.suffix == "com.pl"


# --------------------------------------------------------------------------- platforms


def test_github_io_user_site_is_own_domain_on_platform() -> None:
    t = parse_url("https://jan.github.io/", PLATFORMS)
    assert t.registrable_domain == "jan.github.io"
    assert t.suffix == "github.io"
    assert t.on_platform is True


def test_sb6_myshopify_store_is_not_the_platform_domain() -> None:
    """S-B6: evil.myshopify.com is a separate site, not the official platform domain."""
    t = parse_url("https://evil.myshopify.com/", PLATFORMS)
    assert t.registrable_domain == "evil.myshopify.com"
    assert t.on_platform is True


def test_s3_bucket_is_own_domain_on_platform() -> None:
    t = parse_url("https://x.s3.amazonaws.com/", PLATFORMS)
    assert t.registrable_domain == "x.s3.amazonaws.com"
    assert t.on_platform is True


def test_weebly_via_extra_suffixes() -> None:
    t = parse_url("https://x.weebly.com/", PLATFORMS)
    assert t.registrable_domain == "x.weebly.com"
    assert t.suffix == "weebly.com"
    assert t.on_platform is True


def test_weebly_without_platform_list_is_plain_domain() -> None:
    t = parse_url("https://x.weebly.com/", PlatformList())
    assert t.registrable_domain == "weebly.com"
    assert t.on_platform is False


def test_google_sites_path_platform() -> None:
    t = parse_url("https://sites.google.com/view/paypal-login", PLATFORMS)
    assert t.registrable_domain == "google.com"
    assert t.subdomain == "sites"
    assert t.on_platform is True


@pytest.mark.parametrize(
    "url",
    ["https://sites.google.com/", "https://sites.google.com/view/", "https://sites.google.com/x/y"],
)
def test_google_sites_without_site_name_is_not_on_platform(url: str) -> None:
    assert parse_url(url, PLATFORMS).on_platform is False


def test_www_google_is_not_on_platform() -> None:
    t = parse_url("https://www.google.com/", PLATFORMS)
    assert t.on_platform is False
    assert t.subdomain == "www"
    assert t.registrable_domain == "google.com"


@pytest.mark.parametrize(
    ("url", "domain", "subdomain", "suffix"),
    [
        ("https://github.io/", "github.io", "", "io"),
        ("https://s3.amazonaws.com/", "amazonaws.com", "s3", "com"),
        ("https://weebly.com/", "weebly.com", "", "com"),
        ("https://sites.google.com/", "google.com", "sites", "com"),
    ],
)
def test_platform_root_is_not_a_site_on_platform(
    url: str, domain: str, subdomain: str, suffix: str
) -> None:
    """The platform's own address (no site name) is decomposed as a plain domain."""
    t = parse_url(url, PLATFORMS)
    assert t.on_platform is False
    assert t.registrable_domain == domain
    assert t.subdomain == subdomain
    assert t.suffix == suffix


def test_duckdns_dynamic_dns_is_platform() -> None:
    """Dynamic DNS providers are in the private PSL section."""
    t = parse_url("https://x.duckdns.org/", PLATFORMS)
    assert t.registrable_domain == "x.duckdns.org"
    assert t.on_platform is True


def test_uk_com_private_registry_counts_as_platform() -> None:
    """Known limitation: uk.com is a private registry in the PSL private section, so its
    domains are reported as on_platform. This test documents the behaviour."""
    t = parse_url("https://x.uk.com/", PLATFORMS)
    assert t.registrable_domain == "x.uk.com"
    assert t.on_platform is True


# --------------------------------------------------------------------------- hosts


def test_ipv4_host() -> None:
    t = parse_url("http://185.23.4.5/login", PLATFORMS)
    assert t.is_ip is True
    assert t.host_ascii == "185.23.4.5"
    assert t.registrable_domain == ""
    assert t.on_platform is False


def test_ipv6_host() -> None:
    t = parse_url("http://[2001:DB8::1]:8080/x", PLATFORMS)
    assert t.is_ip is True
    assert t.host_ascii == "2001:db8::1"
    assert t.port == 8080
    assert t.url_redacted == "http://[2001:db8::1]:8080/x"


@pytest.mark.parametrize("url", ["https://xn--pypal-4ve.com/", f"https://{CYRILLIC_PAYPAL}/"])
def test_idn_punycode_and_unicode(url: str) -> None:
    t = parse_url(url, PLATFORMS)
    assert t.is_idn is True
    assert t.host_ascii == "xn--pypal-4ve.com"
    assert t.host_unicode == CYRILLIC_PAYPAL
    assert t.registrable_domain == "xn--pypal-4ve.com"
    assert t.suffix == "com"


def test_ascii_host_is_not_idn() -> None:
    t = parse_url("https://Example.COM/A", PLATFORMS)
    assert t.is_idn is False
    assert t.host_ascii == t.host_unicode == "example.com"
    assert t.url == "https://example.com/A"  # scheme and host lowercased, path kept


def test_explicit_port() -> None:
    assert parse_url("https://example.com:8443/a", PLATFORMS).port == 8443


@pytest.mark.parametrize("url", ["https://example.com/", "https://example.com:443/"])
def test_default_port_is_none(url: str) -> None:
    t = parse_url(url, PLATFORMS)
    assert t.port is None
    assert t.url_redacted == "https://example.com/"


def test_fragment_is_redacted() -> None:
    t = parse_url("https://example.com/a#frag", PLATFORMS)
    assert t.url_redacted == "https://example.com/a"
    assert t.path == "/a"


def test_userinfo_host_confusion_trick() -> None:
    """www.paypal.com before '@' is userinfo; the real host is evil.com."""
    t = parse_url("https://www.paypal.com@evil.com/login", PLATFORMS)
    assert t.host_ascii == "evil.com"
    assert t.registrable_domain == "evil.com"
    assert t.has_userinfo is True
    assert t.userinfo == "www.paypal.com"
    assert "www.paypal.com@" in t.url
    assert t.url == "https://www.paypal.com@evil.com/login"
    assert t.url_redacted == "https://evil.com/login"


def test_userinfo_password_kept_in_url_only() -> None:
    t = parse_url("https://user:secret@example.com/a?x=1", PLATFORMS)
    assert t.url == "https://user:secret@example.com/a?x=1"
    assert t.has_userinfo is True
    assert t.userinfo == "user"
    assert t.url_redacted == "https://example.com/a"
    for leaked in ("user", "secret", "?x=1"):
        assert leaked not in t.url_redacted


def test_no_userinfo() -> None:
    t = parse_url("https://example.com/", PLATFORMS)
    assert t.has_userinfo is False
    assert t.userinfo == ""


def test_url_keeps_path_query_fragment_verbatim() -> None:
    t = parse_url("HTTPS://EXAMPLE.com/A/b%20c?Q=1&q=2#Frag", PLATFORMS)
    assert t.url == "https://example.com/A/b%20c?Q=1&q=2#Frag"
    assert t.url_redacted == "https://example.com/A/b%20c"


def test_url_uses_normalized_host_fullwidth_dot() -> None:
    t = parse_url("https://paypal。com/x", PLATFORMS)
    assert t.host_ascii == "paypal.com"
    assert t.url == "https://paypal.com/x"
    assert t.url_redacted == "https://paypal.com/x"


def test_url_uses_normalized_host_uppercase_and_idn() -> None:
    t = parse_url(f"https://WWW.{CYRILLIC_PAYPAL.upper()}/Login?a=B", PLATFORMS)
    assert t.host_ascii == "www.xn--pypal-4ve.com"
    assert t.host_unicode == f"www.{CYRILLIC_PAYPAL}"
    assert t.url == "https://www.xn--pypal-4ve.com/Login?a=B"


def test_empty_path_becomes_slash() -> None:
    t = parse_url("https://example.com?x=1", PLATFORMS)
    assert t.path == "/"
    assert t.url == "https://example.com/?x=1"


@pytest.mark.parametrize(
    "url",
    [
        "http://3105293317/login",  # single decimal number
        "http://0xb9170405/login",  # single hex number
        "http://0xb9.0x17.4.5/login",  # dotted hex
        "http://0271.027.4.5/login",  # dotted octal
        "http://185.23.1029/login",  # shortened (last part covers two bytes)
        "http://185.23.4.5./login",  # trailing dot: same address, unusual form
    ],
)
def test_obfuscated_ipv4_is_canonicalized(url: str) -> None:
    t = parse_url(url, PLATFORMS)
    assert t.is_ip is True
    assert t.host_ascii == t.host_unicode == "185.23.4.5"
    assert t.url == "http://185.23.4.5/login"
    assert t.registrable_domain == ""
    assert t.on_platform is False
    assert t.ip_obfuscated is True


def test_decimal_ipv4_from_task_description() -> None:
    """3105031173 (the number given in the task) is 185.19.4.5, not 185.23.4.5."""
    t = parse_url("http://3105031173/", PLATFORMS)
    assert t.host_ascii == "185.19.4.5"
    assert t.ip_obfuscated is True


def test_plain_ipv4_is_not_obfuscated() -> None:
    assert parse_url("http://185.23.4.5/", PLATFORMS).ip_obfuscated is False


@pytest.mark.parametrize(
    "url",
    [
        "http://4294967296/",  # > 2**32 - 1
        "http://256.1.1.1/",
        "http://1.2.3.256/",
        "http://1.2.65536/",
        "http://1.2.3.4.5/",
        "http://0x1g.1.1.1/",
        "http://08.1.1.1/",  # 8 is not an octal digit
        "http://example.123/",  # ends in a number, so must be an IPv4 address
    ],
)
def test_invalid_ipv4_raises(url: str) -> None:
    with pytest.raises(UrlParseError, match="IPv4"):
        parse_url(url, PLATFORMS)


@pytest.mark.parametrize(
    ("url", "host", "port", "is_ip"),
    [
        ("http://localhost:3000/", "localhost", 3000, False),
        ("http://intranet/", "intranet", None, False),
        ("http://printer.local/", "printer.local", None, False),
        ("http://[::1]:8080/", "::1", 8080, True),
        ("http://192.168.1.1/", "192.168.1.1", None, True),
    ],
)
def test_local_and_dotless_hosts(url: str, host: str, port: int | None, is_ip: bool) -> None:
    t = parse_url(url, PLATFORMS)
    assert t.host_ascii == host
    assert t.port == port
    assert t.is_ip is is_ip
    assert t.registrable_domain == ""
    assert t.on_platform is False


def test_backslash_before_at_is_path_separator() -> None:
    """Browsers open evil.com here; the '@' ends up in the path, not in userinfo."""
    t = parse_url("https://evil.com\\@paypal.com/", PLATFORMS)
    assert t.host_ascii == "evil.com"
    assert t.registrable_domain == "evil.com"
    assert t.has_userinfo is False
    assert t.userinfo == ""
    assert t.has_backslash is True
    assert t.path == "/@paypal.com/"
    assert t.url == "https://evil.com/@paypal.com/"


def test_backslash_in_path_converted_query_kept() -> None:
    t = parse_url("https://example.com\\a\\b?x=\\y", PLATFORMS)
    assert t.host_ascii == "example.com"
    assert t.path == "/a/b"
    assert t.url == "https://example.com/a/b?x=\\y"
    assert t.url_redacted == "https://example.com/a/b"
    assert t.has_backslash is True


def test_backslash_only_in_fragment_is_not_flagged() -> None:
    t = parse_url("https://example.com/a#x\\y", PLATFORMS)
    assert t.has_backslash is False
    assert t.url == "https://example.com/a#x\\y"


def test_no_backslash() -> None:
    assert parse_url("https://example.com/a?b=c", PLATFORMS).has_backslash is False


def test_trailing_dot_domain_kept_in_host_but_not_in_domain() -> None:
    """Browsers treat paypal.com. as its own host; domain-level fields drop the dot."""
    t = parse_url("https://paypal.com./x", PLATFORMS)
    assert t.host_ascii == t.host_unicode == "paypal.com."
    assert t.url == "https://paypal.com./x"
    assert t.url_redacted == "https://paypal.com./x"
    assert t.registrable_domain == "paypal.com"
    assert t.suffix == "com"
    assert t.subdomain == ""
    assert t.is_ip is False


def test_trailing_dot_platform_site() -> None:
    t = parse_url("https://jan.github.io./", PLATFORMS)
    assert t.host_ascii == "jan.github.io."
    assert t.registrable_domain == "jan.github.io"
    assert t.on_platform is True


def test_trailing_dot_ipv4_is_obfuscated() -> None:
    t = parse_url("http://185.23.4.5./", PLATFORMS)
    assert t.is_ip is True
    assert t.host_ascii == "185.23.4.5"
    assert t.url == "http://185.23.4.5/"
    assert t.ip_obfuscated is True


# --------------------------------------------------------------------------- errors


@pytest.mark.parametrize("url", ["ftp://example.com/", "javascript:alert(1)", "example.com/x"])
def test_non_http_scheme_raises(url: str) -> None:
    with pytest.raises(UrlParseError, match="scheme"):
        parse_url(url, PLATFORMS)


@pytest.mark.parametrize(
    "url",
    [
        "https:///path",
        "https://exa mple.com/",
        "https://-bad-.com/",
        "https://paypal.com../",
        "https://xn--zz.com/",
        "https://example.com:99999/",
        "",
    ],
)
def test_invalid_url_raises_readable_error(url: str) -> None:
    with pytest.raises(UrlParseError):
        parse_url(url, PLATFORMS)


# --------------------------------------------------------------------------- offline config


def test_extractor_never_downloads_suffix_list(monkeypatch: pytest.MonkeyPatch) -> None:
    """The extractor uses only the bundled PSL snapshot: no URLs, no disk cache, no network."""
    extractor = build_extractor(PLATFORMS)
    assert tuple(extractor.suffix_list_urls) == ()
    assert extractor._cache.enabled is False

    def no_network(*args: object, **kwargs: object) -> None:
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket, "create_connection", no_network)
    monkeypatch.setattr(socket.socket, "connect", no_network)
    _extractor_for.cache_clear()
    t = parse_url("https://paypa1.co.uk/", PLATFORMS)
    assert t.registrable_domain == "paypa1.co.uk"


def test_extractor_is_built_once_per_platform_list() -> None:
    same = PlatformList(subdomain_platforms=("WEEBLY.com",))
    assert build_extractor(PLATFORMS) is build_extractor(same)


# --------------------------------------------------------------------------- platform list


def test_platform_list_json_roundtrip_and_fingerprint(tmp_path) -> None:
    data = {
        "format_version": 1,
        "path_platforms": [{"host": "sites.google.com", "path_prefixes": ["/site/", "/view/"]}],
        "subdomain_platforms": ["weebly.com"],
    }
    path = tmp_path / "platforms.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    loaded = PlatformList.from_json(path)
    assert loaded == PLATFORMS
    assert loaded.to_dict() == data
    assert loaded.fingerprint == PLATFORMS.fingerprint
    assert len(loaded.fingerprint) == 12
    assert all(c in "0123456789abcdef" for c in loaded.fingerprint)


def test_fingerprint_ignores_order_and_case_but_not_content() -> None:
    a = PlatformList(subdomain_platforms=("weebly.com", "wixsite.com"))
    b = PlatformList(subdomain_platforms=("WixSite.com", "weebly.com", "weebly.com"))
    c = PlatformList(subdomain_platforms=("weebly.com",))
    assert a.fingerprint == b.fingerprint
    assert a.fingerprint != c.fingerprint


@pytest.mark.parametrize(
    "data",
    [
        {"format_version": 2},
        {"format_version": 1, "extra": []},
        {"format_version": 1, "path_platforms": [{"host": "x.com", "path_prefixes": ["view"]}]},
        {"format_version": 1, "subdomain_platforms": ["https://weebly.com/"]},
    ],
)
def test_invalid_platform_list_raises(data: dict) -> None:
    with pytest.raises(ValueError):
        PlatformList.from_dict(data)


# --------------------------------------------------------------------------- private suffixes


def test_private_suffixes_under_amazonaws() -> None:
    result = private_suffixes_under(["amazonaws.com", "google.com"])
    assert "s3.amazonaws.com" in result
    assert "*.compute.amazonaws.com" in result
    assert result == sorted(set(result))
    assert all(s.removeprefix("*.").endswith((".amazonaws.com", ".google.com")) for s in result)
    assert not any(s.startswith("!") for s in result)


def test_private_suffixes_under_includes_exact_match_and_normalizes_input() -> None:
    assert "github.io" in private_suffixes_under(["GitHub.IO."])


def test_private_suffixes_under_domain_without_private_suffixes() -> None:
    assert private_suffixes_under(["example.com"]) == []
    assert private_suffixes_under([]) == []


def test_private_suffixes_under_is_offline(monkeypatch: pytest.MonkeyPatch) -> None:
    def no_network(*args: object, **kwargs: object) -> None:
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket, "create_connection", no_network)
    monkeypatch.setattr(socket.socket, "connect", no_network)
    _private_psl_suffixes.cache_clear()
    _extractor_for.cache_clear()
    assert "s3.amazonaws.com" in private_suffixes_under(["amazonaws.com"])

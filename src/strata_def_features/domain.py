"""URL decomposition: the single place where a URL is split into host, domain and suffix.

The registrable domain is computed with the Public Suffix List (including its private
section) bundled in the pinned ``tldextract`` release, extended by a platform list that is
passed in by the caller. Nothing is downloaded and nothing is cached on disk, so the result
depends only on the input URL, the platform list and the package versions.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import idna
import tldextract

__all__ = [
    "PathPlatform",
    "PlatformList",
    "Target",
    "UrlParseError",
    "build_extractor",
    "parse_url",
    "private_suffixes_under",
]

PLATFORM_LIST_FORMAT_VERSION = 1
FINGERPRINT_LENGTH = 12

_ALLOWED_SCHEMES = frozenset({"http", "https"})
_DEFAULT_PORTS = {"http": 80, "https": 443}
# Dots that UTS #46 maps to U+002E (ideographic, fullwidth, halfwidth ideographic).
_ALT_DOTS = str.maketrans(dict.fromkeys("\u3002\uff0e\uff61", "."))
# Plain ASCII label. Underscore is allowed: it is not valid in hostnames, but browsers
# resolve such hosts and they do occur in real (also phishing) URLs.
_ASCII_LABEL = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")
_MAX_HOST_LENGTH = 253


class UrlParseError(ValueError):
    """Raised when a URL cannot be decomposed (bad scheme, missing or invalid host, ...)."""


# --------------------------------------------------------------------------- platform list


def _normalize_host(value: str, *, what: str) -> str:
    host = value.strip().lower().rstrip(".")
    if not host or "/" in host or ":" in host:
        raise ValueError(f"invalid {what} in platform list: {value!r}")
    try:
        return idna.encode(host, uts46=True).decode("ascii")
    except idna.IDNAError as exc:
        raise ValueError(f"invalid {what} in platform list: {value!r} ({exc})") from exc


@dataclass(frozen=True, slots=True)
class PathPlatform:
    """A platform that hosts user sites under a path, e.g. ``sites.google.com/view/<name>``.

    A URL matches when its host equals ``host`` and its path starts with one of
    ``path_prefixes`` followed by at least one more character (the site name).
    Prefixes are stored lowercase and compared with the lowercased path.
    """

    host: str
    path_prefixes: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "host", _normalize_host(self.host, what="path platform host"))
        prefixes: set[str] = set()
        for prefix in self.path_prefixes:
            p = prefix.strip().lower()
            if not p.startswith("/") or not p.endswith("/") or p == "/":
                raise ValueError(
                    f"path prefix must start and end with '/' and not be '/': {prefix!r}"
                )
            prefixes.add(p)
        if not prefixes:
            raise ValueError(f"path platform {self.host!r} has no path prefixes")
        object.__setattr__(self, "path_prefixes", tuple(sorted(prefixes)))

    def matches(self, host_ascii: str, path: str) -> bool:
        if host_ascii != self.host:
            return False
        lowered = path.lower()
        return any(lowered.startswith(p) and len(lowered) > len(p) for p in self.path_prefixes)


@dataclass(frozen=True, slots=True)
class PlatformList:
    """Hand-maintained list of hosting platforms, complementing the PSL private section.

    * ``path_platforms`` - platforms with user sites in the URL path.
    * ``subdomain_platforms`` - platforms with user sites in subdomains that the PSL does not
      know; they are passed to tldextract as ``extra_suffixes``, so ``x.weebly.com`` becomes
      its own registrable domain.

    Entries are normalized (lowercase, punycode, sorted, deduplicated), so two lists with the
    same meaning compare equal and have the same :attr:`fingerprint`.
    """

    path_platforms: tuple[PathPlatform, ...] = ()
    subdomain_platforms: tuple[str, ...] = ()
    fingerprint: str = field(init=False, compare=False)

    def __post_init__(self) -> None:
        merged: dict[str, set[str]] = {}
        for platform in self.path_platforms:
            merged.setdefault(platform.host, set()).update(platform.path_prefixes)
        path_platforms = tuple(
            PathPlatform(host, tuple(prefixes)) for host, prefixes in sorted(merged.items())
        )
        subdomain_platforms = tuple(
            sorted(
                {_normalize_host(s, what="subdomain platform") for s in self.subdomain_platforms}
            )
        )
        object.__setattr__(self, "path_platforms", path_platforms)
        object.__setattr__(self, "subdomain_platforms", subdomain_platforms)
        object.__setattr__(self, "fingerprint", _fingerprint(self.to_dict()))

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> PlatformList:
        version = data.get("format_version")
        if version != PLATFORM_LIST_FORMAT_VERSION:
            raise ValueError(
                f"unsupported platform list format_version {version!r}, "
                f"expected {PLATFORM_LIST_FORMAT_VERSION}"
            )
        unknown = set(data) - {"format_version", "path_platforms", "subdomain_platforms"}
        if unknown:
            raise ValueError(f"unknown keys in platform list: {sorted(unknown)}")
        path_platforms = tuple(
            PathPlatform(host=item["host"], path_prefixes=tuple(item["path_prefixes"]))
            for item in data.get("path_platforms", [])
        )
        return cls(
            path_platforms=path_platforms,
            subdomain_platforms=tuple(data.get("subdomain_platforms", [])),
        )

    @classmethod
    def from_json(cls, path: str | Path) -> PlatformList:
        with Path(path).open(encoding="utf-8") as fh:
            return cls.from_dict(json.load(fh))

    def to_dict(self) -> dict[str, Any]:
        return {
            "format_version": PLATFORM_LIST_FORMAT_VERSION,
            "path_platforms": [
                {"host": p.host, "path_prefixes": list(p.path_prefixes)}
                for p in self.path_platforms
            ],
            "subdomain_platforms": list(self.subdomain_platforms),
        }

    def matches_path_platform(self, host_ascii: str, path: str) -> bool:
        return any(p.matches(host_ascii, path) for p in self.path_platforms)

    def matches_subdomain_platform(self, host_ascii: str) -> bool:
        """True for a site *under* a subdomain platform (``x.weebly.com``, not ``weebly.com``)."""
        return any(host_ascii.endswith("." + s) for s in self.subdomain_platforms)


def _fingerprint(content: Mapping[str, Any]) -> str:
    """SHA-256 of the canonical JSON form of the normalized list, first 12 hex characters."""
    canonical = json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()[:FINGERPRINT_LENGTH]


# --------------------------------------------------------------------------- tldextract


_OFFLINE = {
    "suffix_list_urls": (),  # never download: use the snapshot bundled with tldextract
    "cache_dir": None,  # no disk cache (read-only filesystem in the Scraper container)
}


@lru_cache(maxsize=8)
def _extractor_for(extra_suffixes: tuple[str, ...]) -> tldextract.TLDExtract:
    return tldextract.TLDExtract(
        include_psl_private_domains=True,  # github.io, myshopify.com, blogspot.com, ...
        extra_suffixes=list(extra_suffixes),
        **_OFFLINE,
    )


@lru_cache(maxsize=1)
def _registry_extractor() -> tldextract.TLDExtract:
    """ICANN section only: decomposes a bare platform host (``github.io``) as a plain domain."""
    return tldextract.TLDExtract(include_psl_private_domains=False, **_OFFLINE)


def build_extractor(platforms: PlatformList) -> tldextract.TLDExtract:
    """Return the (memoized) offline tldextract instance for the given platform list."""
    return _extractor_for(platforms.subdomain_platforms)


@lru_cache(maxsize=1)
def _private_psl_suffixes() -> tuple[str, ...]:
    # tldextract has no public accessor for the parsed list; the attribute is stable within
    # the pinned version and covered by tests.
    raw = _extractor_for(())._get_tld_extractor().private_tlds
    out: set[str] = set()
    for entry in raw:
        if entry.startswith("!"):  # exception rule, not a suffix
            continue
        wildcard = entry.startswith("*.")
        body = entry[2:] if wildcard else entry
        ascii_body = idna.encode(body, uts46=True).decode("ascii")
        out.add(f"*.{ascii_body}" if wildcard else ascii_body)
    return tuple(sorted(out))


def private_suffixes_under(domains: Iterable[str]) -> list[str]:
    """Suffixes from the PSL *private* section that equal or lie under any of ``domains``.

    Uses only the PSL snapshot bundled with the pinned tldextract (no network, the manual
    platform list is not consulted). Entries are punycode; wildcard rules keep the PSL form
    ``*.compute.amazonaws.com`` (any single label in place of ``*`` is a suffix), exception
    rules (``!...``) are skipped. The result is sorted and deduplicated.
    """
    wanted = {_normalize_host(d, what="domain") for d in domains}
    if not wanted:
        return []
    result = []
    for entry in _private_psl_suffixes():
        body = entry.removeprefix("*.")
        if any(body == d or body.endswith("." + d) for d in wanted):
            result.append(entry)
    return result


# --------------------------------------------------------------------------- URL parsing


@dataclass(frozen=True, slots=True)
class Target:
    """Decomposed URL. Domain fields are in ASCII (punycode) form; '' when not applicable.

    ``url`` is the full address as the browser would request it (userinfo, query and
    fragment kept; only the host normalized). ``url_redacted`` drops userinfo, query and
    fragment and may be shared with third parties.
    """

    url: str
    url_redacted: str
    scheme: str
    has_userinfo: bool
    userinfo: str  # user name only, never the password
    has_backslash: bool  # a backslash before "?"/"#" (treated as "/", like browsers do)
    host_unicode: str
    host_ascii: str
    subdomain: str
    registrable_domain: str
    suffix: str
    port: int | None
    path: str
    is_ip: bool
    ip_obfuscated: bool
    is_idn: bool
    on_platform: bool


@dataclass(frozen=True, slots=True)
class _Host:
    ascii: str
    unicode: str
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
    ip_obfuscated: bool = False


def _encode_labels(host: str, url: str) -> tuple[str, str]:
    """Return ``(host_ascii, host_unicode)`` for a domain name; raise if invalid."""
    ascii_labels: list[str] = []
    unicode_labels: list[str] = []
    for label in host.split("."):
        try:
            if not label.isascii():
                a_label = idna.encode(label, uts46=True).decode("ascii")
                u_label = idna.decode(a_label)
            elif label.startswith("xn--"):
                u_label = idna.decode(label)
                a_label = idna.encode(u_label).decode("ascii")
            else:
                if not _ASCII_LABEL.match(label):
                    raise UrlParseError(f"invalid host label {label!r} in {url!r}")
                a_label = u_label = label
        except idna.IDNAError as exc:
            raise UrlParseError(f"invalid IDN label {label!r} in {url!r}: {exc}") from exc
        ascii_labels.append(a_label)
        unicode_labels.append(u_label)
    host_ascii = ".".join(ascii_labels)
    if len(host_ascii) > _MAX_HOST_LENGTH:
        raise UrlParseError(f"host longer than {_MAX_HOST_LENGTH} characters in {url!r}")
    return host_ascii, ".".join(unicode_labels)


def _ipv4_number(part: str) -> int | None:
    """WHATWG "IPv4 number parser": decimal, 0x-hex or 0-octal; None when not a number."""
    if not part:
        return None
    radix = 10
    if part.startswith(("0x", "0X")):
        part, radix = part[2:], 16
    elif len(part) > 1 and part.startswith("0"):
        part, radix = part[1:], 8
    if not part:
        return 0
    digits = {10: "0123456789", 16: "0123456789abcdefABCDEF", 8: "01234567"}[radix]
    if any(c not in digits for c in part):
        return None
    return int(part, radix)


def _ends_in_number(host: str) -> bool:
    """WHATWG "ends in a number checker"."""
    parts = host.split(".")
    if parts[-1] == "" and len(parts) > 1:
        parts.pop()
    last = parts[-1]
    if last and all(c in "0123456789" for c in last):
        return True
    return _ipv4_number(last) is not None


def _parse_ipv4(host: str, url: str) -> ipaddress.IPv4Address:
    """WHATWG IPv4 parser: accepts 1-4 parts, each decimal, hex or octal."""
    parts = host.split(".")
    if parts[-1] == "" and len(parts) > 1:
        parts.pop()
    if len(parts) > 4:
        raise UrlParseError(f"invalid IPv4 address {host!r} in {url!r}: more than 4 parts")
    numbers = []
    for part in parts:
        n = _ipv4_number(part)
        if n is None:
            raise UrlParseError(f"invalid IPv4 address {host!r} in {url!r}: bad part {part!r}")
        numbers.append(n)
    if any(n > 255 for n in numbers[:-1]) or numbers[-1] >= 256 ** (5 - len(numbers)):
        raise UrlParseError(f"invalid IPv4 address {host!r} in {url!r}: number out of range")
    value = numbers[-1]
    for i, n in enumerate(numbers[:-1]):
        value += n * 256 ** (3 - i)
    return ipaddress.IPv4Address(value)


def _parse_host(raw_host: str, url: str) -> _Host:
    """Normalize the host like a browser does (WHATWG host parser, IDNA2008 labels)."""
    if ":" in raw_host:  # urllib only yields ':' for a bracketed IPv6 literal
        if "%" in raw_host:
            raise UrlParseError(f"IPv6 zone identifiers are not allowed in {url!r}")
        try:
            ip6 = ipaddress.IPv6Address(raw_host)
        except ValueError as exc:
            raise UrlParseError(f"invalid IPv6 address in {url!r}: {exc}") from exc
        return _Host(ip6.compressed, ip6.compressed, ip6)

    host = raw_host.translate(_ALT_DOTS)
    # A trailing dot (fully qualified form) is kept for domains, as browsers keep it; the
    # domain decomposition strips it (see parse_url).
    trailing_dot = "." if host.endswith(".") else ""
    body = host.removesuffix(".")
    if not body:
        raise UrlParseError(f"missing host in {url!r}")
    host_ascii, host_unicode = _encode_labels(body, url)
    if _ends_in_number(host_ascii):
        ip4 = _parse_ipv4(host_ascii, url)
        canonical = str(ip4)
        return _Host(canonical, canonical, ip4, ip_obfuscated=host != canonical)
    return _Host(host_ascii + trailing_dot, host_unicode + trailing_dot)


def _netloc(host: _Host, port: int | None) -> str:
    rendered = f"[{host.ascii}]" if isinstance(host.ip, ipaddress.IPv6Address) else host.ascii
    return rendered if port is None else f"{rendered}:{port}"


def _decompose(host_ascii: str, platforms: PlatformList) -> tuple[str, str, str, bool]:
    """Return ``(subdomain, registrable_domain, suffix, is_platform_site)``."""
    extracted = build_extractor(platforms).extract_str(host_ascii)
    bare_platform = (
        not extracted.domain
        and bool(extracted.suffix)
        and (extracted.is_private or extracted.suffix in platforms.subdomain_platforms)
    )
    if bare_platform:
        # The platform's own host (github.io, s3.amazonaws.com, weebly.com) is not a user
        # site: decompose it against the ICANN section, e.g. github.io -> github.io / io.
        plain = _registry_extractor().extract_str(host_ascii)
        return plain.subdomain, plain.top_domain_under_public_suffix, plain.suffix, False
    is_site = bool(extracted.is_private) and bool(extracted.domain)
    return (
        extracted.subdomain,
        extracted.top_domain_under_public_suffix,
        extracted.suffix,
        is_site,
    )


def parse_url(url: str, platforms: PlatformList) -> Target:
    """Decompose an absolute http(s) URL.

    Raises :class:`UrlParseError` for non-http(s) schemes, a missing or invalid host
    (including invalid IDNA2008 labels and out-of-range IPv4 numbers) and an invalid port.
    """
    if not isinstance(url, str):
        raise UrlParseError(f"URL must be a string, got {type(url).__name__}")
    # Like browsers (and urllib), ignore surrounding whitespace and embedded tab/CR/LF.
    cleaned = url.strip().translate(dict.fromkeys(map(ord, "\t\r\n")))
    if not cleaned:
        raise UrlParseError("empty URL")
    # WHATWG: for http(s) a backslash before the query/fragment is a path separator, so
    # "https://evil.com\@paypal.com/" opens evil.com. Query and fragment keep it.
    # (Only http/https are accepted below, so the replacement is safe to do up front.)
    cut = min((i for i in (cleaned.find("?"), cleaned.find("#")) if i >= 0), default=len(cleaned))
    has_backslash = "\\" in cleaned[:cut]
    if has_backslash:
        cleaned = cleaned[:cut].replace("\\", "/") + cleaned[cut:]
    try:
        parts = urlsplit(cleaned)
    except ValueError as exc:
        raise UrlParseError(f"cannot parse URL {url!r}: {exc}") from exc
    scheme = parts.scheme  # lowercased by urllib
    if scheme not in _ALLOWED_SCHEMES:
        raise UrlParseError(f"unsupported scheme {parts.scheme!r} in {url!r} (only http/https)")
    authority_start = len(scheme) + 1
    if cleaned[authority_start : authority_start + 2] != "//" or not parts.hostname:
        raise UrlParseError(f"missing host in {url!r}")

    try:
        explicit_port = parts.port
    except ValueError as exc:
        raise UrlParseError(f"invalid port in {url!r}: {exc}") from exc
    port = None if explicit_port in (None, _DEFAULT_PORTS[scheme]) else explicit_port

    host = _parse_host(parts.hostname, url)  # urllib lowercases and strips IPv6 brackets

    raw_userinfo, has_userinfo, _ = parts.netloc.rpartition("@")
    has_userinfo = bool(has_userinfo)
    userinfo = raw_userinfo.partition(":")[0]

    # Path, query and fragment as given (only an empty path becomes "/" and backslashes
    # before the query become "/").
    rest = cleaned[authority_start + 2 + len(parts.netloc) :]
    if not rest.startswith("/"):
        rest = "/" + rest
    path = parts.path or "/"
    netloc = _netloc(host, port)
    url_full = f"{scheme}://{raw_userinfo + '@' if has_userinfo else ''}{netloc}{rest}"
    url_redacted = f"{scheme}://{netloc}{path}"

    if host.ip is not None:
        subdomain = registrable_domain = suffix = ""
        on_platform = False
    else:
        # "paypal.com." is the same domain as "paypal.com" for decomposition and platforms.
        site_host = host.ascii.removesuffix(".")
        subdomain, registrable_domain, suffix, is_site = _decompose(site_host, platforms)
        on_platform = (
            is_site
            or platforms.matches_subdomain_platform(site_host)
            or platforms.matches_path_platform(site_host, path)
        )

    return Target(
        url=url_full,
        url_redacted=url_redacted,
        scheme=scheme,
        has_userinfo=has_userinfo,
        userinfo=userinfo,
        has_backslash=has_backslash,
        host_unicode=host.unicode,
        host_ascii=host.ascii,
        subdomain=subdomain,
        registrable_domain=registrable_domain,
        suffix=suffix,
        port=port,
        path=path,
        is_ip=host.ip is not None,
        ip_obfuscated=host.ip_obfuscated,
        is_idn=host.ascii != host.unicode,
        on_platform=on_platform,
    )

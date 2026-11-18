# strata-def-ml-tum

# Data

The data itself is **not** stored in this repository. It lives on Google Drive:
`MyDrive/phishing-tum/data/` (`raw/` unchanged sources, `processed/` train / validation / test).

| Dataset | Version / date | Notes |
|---|---|---|
| PhreshPhish (Hugging Face) | commit `eca603e0ecd4f698f8d4d226c088659e72681239`, downloaded 2026-11-01 | main dataset for the content model; CC BY 4.0, anti-phishing research only |
# Usage

The package is installed by the main `strata-def` repository pinned to a tag (`features-vX.Y.Z`),
so that training and the running system decompose URLs identically.

```python
from strata_def_features import PlatformList, parse_url

platforms = PlatformList.from_json("platforms.json")  # file lives in the main repository
target = parse_url("https://paypa1.co.uk/login?session=abc", platforms)
target.registrable_domain  # 'paypa1.co.uk'
target.url_redacted  # 'https://paypa1.co.uk/login'
platforms.fingerprint  # 12-char SHA-256 prefix of the normalized list, for provenance
```

Platform list format (`format_version` 1):

```json
{
  "format_version": 1,
  "path_platforms": [
    {"host": "sites.google.com", "path_prefixes": ["/view/", "/site/"]}
  ],
  "subdomain_platforms": ["weebly.com"]
}
```

* `path_platforms` – user sites live in the path; a URL matches when the host is equal and the
  path continues past one of the prefixes (`/view/<name>`).
* `subdomain_platforms` – user sites live in subdomains unknown to the Public Suffix List; they are
  added to tldextract as `extra_suffixes`, so `x.weebly.com` is its own registrable domain.

`parse_url` is fully offline and deterministic: it uses the PSL snapshot bundled with the pinned
`tldextract` (private section included), never downloads the list and never writes a cache.
Only `http`/`https` URLs are accepted; an invalid host, IDN label, IPv4 number or port raises
`UrlParseError`.

## `Target` fields

| Field | Meaning |
|---|---|
| `url` | Full address as the browser requests it: userinfo (including password), path, query and fragment kept; only the host is normalized (lowercase, punycode, canonical IP) and, as in the WHATWG URL parser, `\` before `?`/`#` becomes `/` |
| `url_redacted` | `scheme://host[:port]/path` – no userinfo, query or fragment; safe to send to third parties (tokens inside the path remain – known limitation) |
| `scheme` | `http` or `https` |
| `has_userinfo` | the authority contained a part before `@` (e.g. `https://www.paypal.com@evil.com`) |
| `userinfo` | user name only, never the password (`""` when absent) |
| `has_backslash` | the part before `?`/`#` contained `\` (`https://evil.com\@paypal.com/` opens **evil.com**, path `/@paypal.com/`) |
| `host_ascii` / `host_unicode` | normalized host in punycode / decoded Unicode (for homoglyph checks) |
| `subdomain`, `registrable_domain`, `suffix` | PSL decomposition in punycode; `""` when not applicable (IP, `localhost`, `printer.local`) |
| `port` | explicit non-default port, otherwise `None` |
| `path` | path, `/` when empty |
| `is_ip` | host is an IPv4/IPv6 address |
| `ip_obfuscated` | IPv4 written unusually (`3105293317`, `0xb9.0x17.4.5`, `0271.027.4.5`, `185.23.1029`, `185.23.4.5.`) – parsed like the WHATWG URL parser and canonicalized to `185.23.4.5` |
| `is_idn` | host contains IDN (punycode) labels |
| `on_platform` | a user site on a hosting platform: PSL private suffix with a site name (`jan.github.io`), a `subdomain_platforms` entry (`x.weebly.com`) or a `path_platforms` match (`sites.google.com/view/<name>`) |

The platform's own address is not a site on it: `github.io`, `weebly.com` and
`sites.google.com/` give `on_platform = False` and are decomposed as plain domains
(`github.io` → registrable domain `github.io`). Trailing dot: for a domain it is kept in `host_ascii`, `host_unicode` and `url`
(`https://paypal.com./x`, a separate host for the browser), but `subdomain`, `registrable_domain`
and `suffix` are without it (`paypal.com`, `com`), so caches and domain-based data splits treat it
as the same domain. For IPv4 (`185.23.4.5.`) the host is canonicalized and `ip_obfuscated` is set.

Known limitation: private registries in the PSL
private section (e.g. `x.uk.com`) also count as `on_platform`.

## `private_suffixes_under`

```python
from strata_def_features import private_suffixes_under

private_suffixes_under(["amazonaws.com", "google.com"])
# ['*.compute.amazonaws.com', ..., 's3.amazonaws.com', ...]
```

Returns every suffix from the **private** PSL section bundled in the pinned `tldextract` that
equals or lies under one of the given domains (sorted, deduplicated, punycode, offline). Wildcard
rules keep the PSL form `*.<suffix>`; exception rules (`!…`) are skipped. The manual platform
list is not consulted.

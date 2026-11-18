"""Strata defensionis feature calculator."""

from strata_def_features.domain import (
    PathPlatform,
    PlatformList,
    Target,
    UrlParseError,
    parse_url,
    private_suffixes_under,
)
from strata_def_features.version import __version__

__all__ = [
    "PathPlatform",
    "PlatformList",
    "Target",
    "UrlParseError",
    "__version__",
    "parse_url",
    "private_suffixes_under",
]

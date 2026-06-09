"""IOCEXTRACT — defang-aware indicator-of-compromise extractor.

Defensive / authorized-triage use only. Reads text and reports the IOCs it
contains across 11 surfaced types (IPv4/IPv6, URL, domain, email,
MD5/SHA1/SHA256, CVE, Bitcoin address, Windows registry key) with analyst
enrichment (IP scope, hash family, URL host). No network, no active capability.

In the spirit of InQuest/iocextract; standard library only, zero-install.
"""

from __future__ import annotations

from .core import (
    IOC,
    IOC_TYPES,
    TOOL_NAME,
    TOOL_VERSION,
    ExtractResult,
    defang,
    extract,
    extract_from_files,
    hash_family,
    refang,
)

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "IOC",
    "IOC_TYPES",
    "ExtractResult",
    "extract",
    "extract_from_files",
    "refang",
    "defang",
    "hash_family",
]

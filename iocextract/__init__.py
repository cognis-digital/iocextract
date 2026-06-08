"""IOCEXTRACT — defang-aware indicator-of-compromise extractor.

Defensive / authorized-triage use only. Reads text and reports the IOCs it
contains (IPs, domains, URLs, emails, file hashes). No network, no active
capability.
"""

from __future__ import annotations

from .core import (
    IOC,
    ExtractResult,
    defang,
    extract,
    extract_from_files,
    refang,
)

TOOL_NAME = "iocextract"
TOOL_VERSION = "1.0.0"

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "IOC",
    "ExtractResult",
    "extract",
    "extract_from_files",
    "refang",
    "defang",
]

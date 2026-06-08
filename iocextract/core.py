"""IOCEXTRACT core engine.

Real, dependency-free extraction and defanging of indicators of compromise
(IOCs) from arbitrary text. Defensive/triage use only: this module reads text
and reports what it finds. It performs no network calls and no active actions.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable

# ---------------------------------------------------------------------------
# Regular expressions
# ---------------------------------------------------------------------------

# IPv4 octet 0-255.
_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
_IPV4_RE = re.compile(r"\b" + r"\.".join([_OCTET] * 4) + r"\b")

# IPv6 (covers full, compressed "::" and embedded IPv4 forms reasonably well).
_IPV6_RE = re.compile(
    r"\b(?:"
    r"(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}"          # full
    r"|(?:[0-9A-Fa-f]{1,4}:){1,7}:"                       # trailing ::
    r"|(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}"
    r"|[0-9A-Fa-f]{1,4}:(?::[0-9A-Fa-f]{1,4}){1,6}"
    r"|:(?::[0-9A-Fa-f]{1,4}){1,7}"
    r"|::"
    r")"
)

# Hashes (anchored by length, word boundaries).
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_SHA512_RE = re.compile(r"\b[a-fA-F0-9]{128}\b")

_EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+\-]+(?:@|\[at\]|\(at\))[A-Za-z0-9.\-]+"
    r"(?:\.|\[\.\]|\(\.\))[A-Za-z]{2,24}\b"
)

# Domains/URLs operate on a "refanged" copy so defanged input is matched too.
_URL_RE = re.compile(
    r"\b(?:hxxps?|https?|ftp)://[^\s<>\"'\)\]]+",
    re.IGNORECASE,
)
_DOMAIN_RE = re.compile(
    r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+"
    r"(?:[A-Za-z]{2,24})\b"
)

# Common TLDs to reduce false positives (e.g. "version.exe", "file.dll").
_VALID_TLDS = {
    "com", "net", "org", "io", "co", "gov", "edu", "mil", "info", "biz",
    "ru", "cn", "uk", "de", "fr", "us", "ca", "au", "jp", "br", "in",
    "tv", "me", "xyz", "top", "online", "site", "club", "pro", "app",
    "dev", "cloud", "ai", "cc", "ws", "to", "su", "tk", "ml", "ga",
    "cf", "gq", "live", "shop", "store", "tech", "space", "fun", "icu",
    "eu", "nl", "it", "es", "se", "no", "fi", "pl", "ch", "be", "at",
    "kr", "tw", "hk", "sg", "mx", "ar", "za", "ua", "ir", "tr", "vn",
}

# File-extension suffixes that look like domains but usually are not.
_FILE_EXT_TAIL = re.compile(
    r"\.(?:exe|dll|sys|bat|cmd|ps1|vbs|js|jar|doc[xm]?|xls[xm]?|ppt[xm]?|"
    r"pdf|zip|rar|7z|gz|tar|png|jpe?g|gif|bmp|txt|log|ini|cfg|conf|dat|"
    r"bin|tmp|lnk|scr|hta|py|sh|php|aspx?|html?|css|csv|json|xml|yaml|yml)$",
    re.IGNORECASE,
)

# Defang substitution table applied when refanging input.
_REFANG_SUBS = (
    ("[.]", "."), ("(.)", "."), ("{.}", "."), ("[dot]", "."),
    ("(dot)", "."), ("[DOT]", "."), ("\\.", "."),
    ("[:]", ":"), ("[://]", "://"),
    ("[at]", "@"), ("(at)", "@"),
    ("hxxps://", "https://"), ("hxxp://", "http://"),
    ("hXXps://", "https://"), ("hXXp://", "http://"),
    ("fxp://", "ftp://"),
)


@dataclass
class IOC:
    """A single extracted indicator."""

    value: str          # original (refanged) value
    type: str           # ipv4 | ipv6 | domain | url | email | md5 | sha1 ...
    defanged: str       # safe-to-display representation

    def as_dict(self) -> dict:
        return {"type": self.type, "value": self.value, "defanged": self.defanged}


@dataclass
class ExtractResult:
    iocs: list[IOC] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.iocs)

    def by_type(self) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for ioc in self.iocs:
            out.setdefault(ioc.type, []).append(ioc.value)
        return out

    def as_dict(self) -> dict:
        return {
            "count": self.count,
            "by_type": {k: len(v) for k, v in self.by_type().items()},
            "iocs": [i.as_dict() for i in self.iocs],
        }


def refang(text: str) -> str:
    """Convert defanged text back to a normal form for matching.

    Handles common analyst conventions: ``hxxp``, ``[.]``, ``(dot)``, ``[at]``.
    """
    out = text
    for needle, repl in _REFANG_SUBS:
        out = out.replace(needle, repl)
    # word forms with surrounding spaces e.g. "1 dot 2 dot 3"
    out = re.sub(r"\s*\[dot\]\s*", ".", out, flags=re.IGNORECASE)
    out = re.sub(r"\s*\(dot\)\s*", ".", out, flags=re.IGNORECASE)
    return out


def defang(value: str, ioc_type: str) -> str:
    """Produce a safe, non-clickable representation of an IOC."""
    if ioc_type in ("md5", "sha1", "sha256", "sha512"):
        return value  # hashes are inert
    out = value
    out = out.replace("https://", "hxxps://").replace("http://", "hxxp://")
    out = out.replace("ftp://", "fxp://")
    out = out.replace("@", "[at]")
    out = out.replace(".", "[.]")
    return out


def _is_plausible_domain(domain: str) -> bool:
    tld = domain.rsplit(".", 1)[-1].lower()
    if tld not in _VALID_TLDS:
        return False
    if _FILE_EXT_TAIL.search(domain):
        return False
    if len(domain) > 253:
        return False
    return True


def _add(seen: set, iocs: list[IOC], value: str, ioc_type: str) -> None:
    key = (ioc_type, value.lower())
    if key in seen:
        return
    seen.add(key)
    iocs.append(IOC(value=value, type=ioc_type, defanged=defang(value, ioc_type)))


def extract(text: str) -> ExtractResult:
    """Extract all supported IOC types from *text*.

    Returns a deduplicated :class:`ExtractResult`. Order of discovery is
    preserved per type; hashes are extracted longest-first to avoid a SHA256
    being mis-counted as an MD5 substring.
    """
    refanged = refang(text)
    iocs: list[IOC] = []
    seen: set = set()

    # Hashes first (longest-first), tracking spans to avoid sub-matches.
    consumed: list[tuple[int, int]] = []

    def _overlaps(span: tuple[int, int]) -> bool:
        return any(span[0] < e and s < span[1] for s, e in consumed)

    for rx, htype in (
        (_SHA512_RE, "sha512"),
        (_SHA256_RE, "sha256"),
        (_SHA1_RE, "sha1"),
        (_MD5_RE, "md5"),
    ):
        for m in rx.finditer(refanged):
            if _overlaps(m.span()):
                continue
            consumed.append(m.span())
            _add(seen, iocs, m.group(0).lower(), htype)

    # URLs (capture before bare domains so the full URL wins).
    url_hosts: set[str] = set()
    for m in _URL_RE.finditer(refanged):
        url = m.group(0).rstrip(".,);]'\"")
        url = url.replace("hxxps://", "https://").replace("hxxp://", "http://")
        _add(seen, iocs, url, "url")
        host = re.sub(r"^[a-z]+://", "", url, flags=re.IGNORECASE)
        host = host.split("/")[0].split(":")[0].split("@")[-1]
        if host:
            url_hosts.add(host.lower())

    # Emails.
    email_domains: set[str] = set()
    for m in _EMAIL_RE.finditer(refanged):
        email = m.group(0)
        _add(seen, iocs, email, "email")
        email_domains.add(email.rsplit("@", 1)[-1].lower())

    # IPv4 / IPv6.
    for m in _IPV4_RE.finditer(refanged):
        _add(seen, iocs, m.group(0), "ipv4")
    for m in _IPV6_RE.finditer(refanged):
        val = m.group(0)
        if val == "::" or len(val) < 3:
            continue
        _add(seen, iocs, val, "ipv6")

    # Domains (skip ones already represented inside a URL or email host,
    # skip anything that is actually an IPv4 literal, skip file names).
    for m in _DOMAIN_RE.finditer(refanged):
        dom = m.group(0).rstrip(".")
        low = dom.lower()
        if _IPV4_RE.fullmatch(dom):
            continue
        if not _is_plausible_domain(dom):
            continue
        if low in url_hosts or low in email_domains:
            continue
        _add(seen, iocs, low, "domain")

    return ExtractResult(iocs=iocs)


def extract_from_files(paths: Iterable[str]) -> ExtractResult:
    """Extract IOCs across multiple files, merged and deduplicated."""
    merged: list[IOC] = []
    seen: set = set()
    for path in paths:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            res = extract(fh.read())
        for ioc in res.iocs:
            key = (ioc.type, ioc.value.lower())
            if key not in seen:
                seen.add(key)
                merged.append(ioc)
    return ExtractResult(iocs=merged)

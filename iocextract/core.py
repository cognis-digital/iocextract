"""IOCEXTRACT core engine.

Real, dependency-free extraction and defanging of indicators of compromise
(IOCs) from arbitrary text. In the spirit of InQuest/iocextract, but standard
library only and zero-install.

Defensive / authorized-triage use only: this module reads text and reports
what it finds. It performs no network calls and takes no active actions.

Supported IOC types (11 surfaced)
---------------------------------
    ipv4      IPv4 addresses (0.0.0.0 - 255.255.255.255)
    ipv6      IPv6 addresses (full / compressed / IPv4-mapped)
    url       http(s)/ftp URLs (defanged hxxp:// understood)
    domain    fully-qualified domain names (TLD-validated)
    email     RFC-ish email addresses ([at]/[dot] understood)
    md5       128-bit hex digests
    sha1      160-bit hex digests
    sha256    256-bit hex digests
    cve       CVE-YYYY-NNNN+ identifiers
    btc       Bitcoin addresses (P2PKH/P2SH base58 + bech32)
    registry  Windows registry keys (HKLM/HKCU/...)

(SHA-512 is also detected internally and tagged so a 128-char hex digest is not
mis-bucketed as a shorter hash.)

The engine refangs input first (so defanged feeds match), classifies hashes
longest-first to avoid sub-matching, suppresses domains already represented
inside URLs/emails, deduplicates the final set, and enriches each indicator
with analyst-grade context (IP scope, hash family, URL host, defanged form).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Iterable

# ---------------------------------------------------------------------------
# Canonical type order (used for stable output ordering).
# ---------------------------------------------------------------------------
IOC_TYPES: tuple[str, ...] = (
    "ipv4", "ipv6", "url", "domain", "email",
    "md5", "sha1", "sha256", "cve", "btc", "registry",
)

# ---------------------------------------------------------------------------
# Regular expressions
# ---------------------------------------------------------------------------

# IPv4 octet 0-255.
_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
_IPV4_RE = re.compile(r"(?<![\w.])" + r"\.".join([_OCTET] * 4) + r"(?![\w.])")

# IPv6 (full / compressed "::" / IPv4-embedded forms).
_IPV6_RE = re.compile(
    r"(?<![:\w])(?:"
    # IPv4-mapped / -embedded forms first (so the trailing dotted-quad wins
    # over the generic compressed branch, which would otherwise eat "192").
    r"::(?:[fF]{4}:)?" + r"\.".join([_OCTET] * 4) +
    r"|(?:[0-9A-Fa-f]{1,4}:){1,4}:" + r"\.".join([_OCTET] * 4) +
    r"|(?:[0-9A-Fa-f]{1,4}:){6}" + r"\.".join([_OCTET] * 4) +
    # Pure-hex forms.
    r"|(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}"           # full
    r"|(?:[0-9A-Fa-f]{1,4}:){1,7}:"                        # trailing ::
    r"|(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}"
    r"|[0-9A-Fa-f]{1,4}:(?::[0-9A-Fa-f]{1,4}){1,6}"
    r"|:(?::[0-9A-Fa-f]{1,4}){1,7}"
    r")(?![:\w])"
)

# Hashes (anchored by length, word boundaries).
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_SHA512_RE = re.compile(r"\b[a-fA-F0-9]{128}\b")

# Email (defang-aware: [at]/(at)/ AT , [.]/(dot)).
_EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+\-]+(?:@|\[at\]|\(at\))[A-Za-z0-9.\-]+"
    r"(?:\.|\[\.\]|\(\.\))[A-Za-z]{2,24}\b"
)

# URLs operate on a "refanged" copy so defanged input is matched too.
_URL_RE = re.compile(
    r"\b(?:hxxps?|https?|ftp)://[^\s<>\"'\)\]\}]+",
    re.IGNORECASE,
)
_DOMAIN_RE = re.compile(
    r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+"
    r"(?:[A-Za-z]{2,24})\b"
)

# CVE identifiers (CVE-YYYY-NNNN, 4+ sequence digits).
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

# Bitcoin addresses: legacy base58 P2PKH/P2SH (1.../3...) and bech32 (bc1...).
_BTC_B58_RE = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,39}\b")
_BTC_BECH32_RE = re.compile(r"\bbc1[ac-hj-np-z02-9]{11,71}\b")
_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# Windows registry keys.
_REGISTRY_RE = re.compile(
    r"\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|"
    r"HKEY_USERS|HKEY_CURRENT_CONFIG|HKLM|HKCU|HKCR|HKU|HKCC)"
    r"(?:\\[A-Za-z0-9_.\-{}()$@]+)+",
    re.IGNORECASE,
)

# Valid TLDs to reduce domain false positives (e.g. "version.exe").
_VALID_TLDS = {
    "com", "net", "org", "io", "co", "gov", "edu", "mil", "info", "biz",
    "ru", "cn", "uk", "de", "fr", "us", "ca", "au", "jp", "br", "in",
    "tv", "me", "xyz", "top", "online", "site", "club", "pro", "app",
    "dev", "cloud", "ai", "cc", "ws", "to", "su", "tk", "ml", "ga",
    "cf", "gq", "live", "shop", "store", "tech", "space", "fun", "icu",
    "eu", "nl", "it", "es", "se", "no", "fi", "pl", "ch", "be", "at",
    "kr", "tw", "hk", "sg", "mx", "ar", "za", "ua", "ir", "tr", "vn",
    "gg", "lol", "vip", "win", "bid", "loan", "work", "link", "click",
    "download", "stream", "rest", "cyou", "monster", "buzz", "sbs",
}

# File-extension suffixes that look like domains but usually are not.
_FILE_EXT_TAIL = re.compile(
    r"\.(?:exe|dll|sys|bat|cmd|ps1|vbs|js|jar|doc[xm]?|xls[xm]?|ppt[xm]?|"
    r"pdf|zip|rar|7z|gz|tar|png|jpe?g|gif|bmp|txt|log|ini|cfg|conf|dat|"
    r"bin|tmp|lnk|scr|hta|py|sh|php|aspx?|html?|css|csv|json|xml|yaml|yml)$",
    re.IGNORECASE,
)

# Defang substitution table applied when refanging input. Order matters
# (longer/scheme markers before single-char markers).
_REFANG_SUBS = (
    ("hxxps[://]", "https://"), ("hxxp[://]", "http://"),
    ("hxxps://", "https://"), ("hxxp://", "http://"),
    ("hXXps://", "https://"), ("hXXp://", "http://"),
    ("fxp://", "ftp://"), ("ftp[:]//", "ftp://"),
    ("[://]", "://"), ("[:]", ":"),
    ("[.]", "."), ("(.)", "."), ("{.}", "."), ("\\.", "."),
    ("[at]", "@"), ("(at)", "@"), ("[@]", "@"),
)

# ---------------------------------------------------------------------------
# Hash family table (length -> canonical label). SHA-512 surfaced as a tag,
# not a first-class IOC_TYPE, to preserve the 11-type public surface.
# ---------------------------------------------------------------------------
_HASH_LEN = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}


@dataclass
class IOC:
    """A single extracted indicator."""

    value: str          # original (refanged / canonical) value
    type: str           # one of IOC_TYPES (or "sha512")
    defanged: str       # safe-to-display representation
    context: dict = field(default_factory=dict)  # analyst enrichment

    def as_dict(self) -> dict:
        d = {"type": self.type, "value": self.value, "defanged": self.defanged}
        if self.context:
            d["context"] = self.context
        return d


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

    def values(self, ioc_type: str) -> list[str]:
        return [i.value for i in self.iocs if i.type == ioc_type]

    def filter_types(self, types: Iterable[str]) -> "ExtractResult":
        wanted = set(types)
        return ExtractResult(iocs=[i for i in self.iocs if i.type in wanted])

    def drop_private(self) -> "ExtractResult":
        """Return a copy without RFC1918/loopback/reserved/doc IPs.

        Useful when you only want routable, externally-actionable indicators.
        """
        kept = []
        for i in self.iocs:
            if i.type in ("ipv4", "ipv6") and not i.context.get("global", True):
                continue
            kept.append(i)
        return ExtractResult(iocs=kept)

    def summary(self) -> dict:
        """Analyst summary: per-type counts + a few rolled-up signals."""
        counts = {k: len(v) for k, v in self.by_type().items()}
        ordered = {t: counts[t] for t in IOC_TYPES if t in counts}
        for k in counts:                                  # e.g. sha512 tag
            ordered.setdefault(k, counts[k])
        ip_scopes: dict[str, int] = {}
        for i in self.iocs:
            if i.type in ("ipv4", "ipv6"):
                scope = i.context.get("scope", "unknown")
                ip_scopes[scope] = ip_scopes.get(scope, 0) + 1
        networkable = sum(
            len(self.values(t)) for t in ("ipv4", "ipv6", "url", "domain")
        )
        return {
            "total": self.count,
            "by_type": ordered,
            "distinct_types": len(ordered),
            "ip_scopes": ip_scopes,
            "networkable": networkable,
        }

    def as_dict(self) -> dict:
        counts = {k: len(v) for k, v in self.by_type().items()}
        ordered = {t: counts[t] for t in IOC_TYPES if t in counts}
        for k in counts:
            ordered.setdefault(k, counts[k])
        return {
            "count": self.count,
            "by_type": ordered,
            "iocs": [i.as_dict() for i in self.iocs],
        }


def refang(text: str) -> str:
    """Convert defanged text back to a normal form for matching.

    Handles common analyst conventions: ``hxxp``, ``[.]``, ``(dot)``, ``[at]``,
    ``[:]``, ``[://]`` and spaced ``[dot]`` / ``(dot)`` word forms.
    """
    out = text
    for needle, repl in _REFANG_SUBS:
        out = out.replace(needle, repl)
    # word forms with optional surrounding spaces, case-insensitive.
    out = re.sub(r"\s*[\[(]\s*dot\s*[\])]\s*", ".", out, flags=re.IGNORECASE)
    out = re.sub(r"\s+dot\s+", ".", out)            # "1 dot 2 dot 3"
    out = re.sub(r"\s*[\[(]\s*at\s*[\])]\s*", "@", out, flags=re.IGNORECASE)
    return out


def defang(value: str, ioc_type: str) -> str:
    """Produce a safe, non-clickable representation of an IOC."""
    if ioc_type in ("md5", "sha1", "sha256", "sha512", "cve", "btc", "registry"):
        return value  # inert / not clickable
    out = value
    out = out.replace("https://", "hxxps://").replace("http://", "hxxp://")
    out = out.replace("ftp://", "fxp://")
    if ioc_type == "email":
        out = out.replace("@", "[at]")
    out = out.replace(".", "[.]")
    return out


def hash_family(value: str) -> str | None:
    """Return the hash family label for a hex digest, or None if not a hash."""
    if re.fullmatch(r"[a-fA-F0-9]+", value or ""):
        return _HASH_LEN.get(len(value))
    return None


def _ip_context(value: str) -> dict:
    """Classify an IP literal (scope/global/reserved) using stdlib ipaddress."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return {}
    if ip.is_loopback:
        scope = "loopback"
    elif ip.is_private:
        scope = "private"
    elif ip.is_multicast:
        scope = "multicast"
    elif ip.is_link_local:
        scope = "link-local"
    elif ip.is_reserved or ip.is_unspecified:
        scope = "reserved"
    else:
        scope = "global"
    ctx = {
        "version": ip.version,
        "scope": scope,
        "global": bool(ip.is_global),
        "private": bool(ip.is_private),
    }
    # Documentation ranges (TEST-NET / 2001:db8::/32) are a common decoy.
    if value in ("192.0.2.0", "198.51.100.0", "203.0.113.0") or \
            value.startswith(("192.0.2.", "198.51.100.", "203.0.113.")) or \
            value.lower().startswith("2001:db8"):
        ctx["documentation"] = True
    return ctx


def _is_plausible_domain(domain: str) -> bool:
    tld = domain.rsplit(".", 1)[-1].lower()
    if tld not in _VALID_TLDS:
        return False
    if _FILE_EXT_TAIL.search(domain):
        return False
    if len(domain) > 253:
        return False
    return True


def _b58_checksum_ok(addr: str) -> bool:
    """Validate a base58check Bitcoin address via 4-byte double-SHA256 checksum.

    This removes the bulk of base58 false positives. ``hashlib`` is stdlib.
    """
    import hashlib

    num = 0
    for ch in addr:
        idx = _B58_ALPHABET.find(ch)
        if idx < 0:
            return False
        num = num * 58 + idx
    # Convert to bytes (big-endian); account for leading '1' zero bytes.
    full = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    pad = len(addr) - len(addr.lstrip("1"))
    full = (b"\x00" * pad) + full
    if len(full) < 5:
        return False
    body, checksum = full[:-4], full[-4:]
    digest = hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4]
    return digest == checksum


def _url_host(url: str) -> str:
    host = re.sub(r"^[a-z]+://", "", url, flags=re.IGNORECASE)
    host = host.split("/")[0].split("?")[0].split("#")[0]
    host = host.split("@")[-1].split(":")[0]
    return host


def _add(seen: set, iocs: list[IOC], value: str, ioc_type: str,
         context: dict | None = None) -> None:
    key = (ioc_type, value.lower())
    if key in seen:
        return
    seen.add(key)
    iocs.append(IOC(
        value=value,
        type=ioc_type,
        defanged=defang(value, ioc_type),
        context=context or {},
    ))


def extract(text: str, types: Iterable[str] | None = None) -> ExtractResult:
    """Extract all supported IOC types from *text*.

    *types* optionally restricts extraction to a subset of :data:`IOC_TYPES`.
    Returns a deduplicated :class:`ExtractResult`. Discovery order is preserved
    per type; the final list is sorted by canonical type order then discovery.
    Each indicator carries an analyst ``context`` dict where it adds value
    (IP scope, hash family, URL host).
    """
    wanted = set(types) if types else set(IOC_TYPES)
    refanged = refang(text)
    iocs: list[IOC] = []
    seen: set = set()

    # Registry keys first; use raw text so backslash paths stay intact.
    if "registry" in wanted:
        for m in _REGISTRY_RE.finditer(text):
            val = m.group(0).rstrip(".,);]\"' ")
            hive = val.split("\\", 1)[0].upper()
            _add(seen, iocs, val, "registry", {"hive": hive})

    # Hashes (longest-first), tracking spans to avoid sub-matches.
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
            if htype in wanted or htype == "sha512":
                _add(seen, iocs, m.group(0).lower(), htype,
                     {"family": htype, "bits": len(m.group(0)) * 4})

    # URLs (capture before bare domains so the full URL wins).
    url_hosts: set[str] = set()
    if "url" in wanted or "domain" in wanted:
        for m in _URL_RE.finditer(refanged):
            url = m.group(0).rstrip(".,);]'\">}")
            url = url.replace("hxxps://", "https://").replace("hxxp://", "http://")
            host = _url_host(url)
            scheme = url.split("://", 1)[0].lower()
            if "url" in wanted:
                _add(seen, iocs, url, "url", {"host": host, "scheme": scheme})
            if host:
                url_hosts.add(host.lower())

    # Emails.
    email_domains: set[str] = set()
    if "email" in wanted or "domain" in wanted:
        for m in _EMAIL_RE.finditer(refanged):
            email = m.group(0)
            dom = email.rsplit("@", 1)[-1].lower()
            if "email" in wanted:
                _add(seen, iocs, email, "email", {"domain": dom})
            email_domains.add(dom)

    # IPv6 BEFORE IPv4 so embedded-IPv4 forms are not split, and so v4 inside
    # v6 spans is suppressed.
    v6_spans: list[tuple[int, int]] = []
    if "ipv6" in wanted:
        for m in _IPV6_RE.finditer(refanged):
            val = m.group(0)
            if val == "::" or len(val) < 3 or ":" not in val:
                continue
            v6_spans.append(m.span())
            _add(seen, iocs, val, "ipv6", _ip_context(val))

    if "ipv4" in wanted:
        for m in _IPV4_RE.finditer(refanged):
            s, e = m.span()
            if any(s >= vs and e <= ve for vs, ve in v6_spans):
                continue
            _add(seen, iocs, m.group(0), "ipv4", _ip_context(m.group(0)))

    # CVEs.
    if "cve" in wanted:
        for m in _CVE_RE.finditer(text):
            val = m.group(0).upper()
            _add(seen, iocs, val, "cve", {"year": int(val.split("-")[1])})

    # Bitcoin addresses (checksum-validated to cut false positives).
    if "btc" in wanted:
        for m in _BTC_B58_RE.finditer(text):
            addr = m.group(0)
            if _b58_checksum_ok(addr):
                fmt = "p2pkh" if addr.startswith("1") else "p2sh"
                _add(seen, iocs, addr, "btc", {"format": fmt})
        for m in _BTC_BECH32_RE.finditer(text):
            _add(seen, iocs, m.group(0).lower(), "btc", {"format": "bech32"})

    # Domains (skip URL/email hosts, IPv4 literals, and file names).
    if "domain" in wanted:
        for m in _DOMAIN_RE.finditer(refanged):
            dom = m.group(0).rstrip(".")
            low = dom.lower()
            if _IPV4_RE.fullmatch(dom):
                continue
            if not _is_plausible_domain(dom):
                continue
            if low in url_hosts or low in email_domains:
                continue
            _add(seen, iocs, low, "domain", {"tld": low.rsplit(".", 1)[-1]})

    # Stable canonical ordering: by type order, then original discovery order.
    order = {t: n for n, t in enumerate(IOC_TYPES)}
    indexed = list(enumerate(iocs))
    indexed.sort(key=lambda p: (order.get(p[1].type, 99), p[0]))
    return ExtractResult(iocs=[i for _, i in indexed])


def extract_from_files(
    paths: Iterable[str], types: Iterable[str] | None = None
) -> ExtractResult:
    """Extract IOCs across multiple files, merged and deduplicated."""
    merged: list[IOC] = []
    seen: set = set()
    for path in paths:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            res = extract(fh.read(), types=types)
        for ioc in res.iocs:
            key = (ioc.type, ioc.value.lower())
            if key not in seen:
                seen.add(key)
                merged.append(ioc)
    return ExtractResult(iocs=merged)


TOOL_NAME = "iocextract"
TOOL_VERSION = "2.1.0"

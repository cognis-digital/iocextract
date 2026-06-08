# Demo 02 — Deep extraction across all 12 IOC types

This scenario runs IOCEXTRACT against a realistic (synthetic) threat-intel
brief that contains **every supported indicator type**, much of it *defanged*
the way analysts hand off feeds: `hxxps://`, `[.]`, `[at]`, `(dot)`, `ftp[:]//`.

## What the report contains

| Type     | Example in `threat_report.txt`                              |
|----------|-------------------------------------------------------------|
| ipv4     | `185.220.101.47`, `8.8.8.8`, `1[.]1[.]1[.]1`                |
| ipv6     | `2001:db8::dead:beef`, `::ffff:192.168.1.10`                |
| url      | `hxxps://bad-host[.]top/gate.php?id=42`                     |
| domain   | `malware-update[.]live` (bare; URL/email hosts suppressed)  |
| email    | `billing[at]invoice-portal[.]shop`                          |
| md5      | `44d88612fea8a8f36de82e1278abb02f`                          |
| sha1     | `da39a3ee5e6b4b0d3255bfef95601890afd80709`                  |
| sha256   | `e3b0...b855`                                               |
| cve      | `CVE-2021-44228`, `cve-2023-23397`, `CVE-2017-0144`         |
| btc      | `1A1zP1...DivfNa` (P2PKH), `3J98...WNLy` (P2SH), `bc1q...`   |
| registry | `HKLM\SOFTWARE\...\Run\Updater`, `HKCU\Software\...`         |

It also includes **decoys** that must NOT be extracted as domains
(`invoice_2026.docx`, `wininet.dll`).

## Run it

```bash
# Full extraction, human-readable table (exit code 1 = findings present)
python -m iocextract extract demos/02-deep/threat_report.txt

# Machine-readable JSON for an ingest pipeline
python -m iocextract extract --format json demos/02-deep/threat_report.txt

# Only the indicators a blocklist cares about
python -m iocextract extract --type ipv4,url,domain,btc demos/02-deep/threat_report.txt

# List every supported type
python -m iocextract types

# Defang a URL by hand before pasting into a ticket
python -m iocextract defang https://evil.example.com/x
```

## Why the BTC addresses are trustworthy

Bitcoin base58 addresses are **base58check-validated** (double-SHA256
checksum) before being reported, so random `1...`/`3...` strings are rejected.
bech32 (`bc1...`) addresses are matched by their charset prefix.

All extraction is local, read-only, and network-free.

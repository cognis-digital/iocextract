# Demo 01 — Triage a SOC alert into a feed-ready, defanged IOC list

## Situation
A tier-1 analyst forwarded a messy incident note (`sample_alert.txt`). It mixes
**already-defanged** indicators (`hxxps://`, `[.]`, `[at]`), live-looking ones,
and decoys (`8.8.8.8` resolver, `update.dll` filename, `invoice_2026.exe`).
You need a clean, deduplicated, **safely defanged** IOC list to paste into the
shared ticket and to push to the internal sandbox/feed.

IOCEXTRACT is **defensive/triage only** — it reads the text and reports what it
finds. It never contacts any of the indicators.

## Run it

Table view (human triage):

```
python -m iocextract extract demos/01-basic/sample_alert.txt
```

Machine-readable for a feed pipeline:

```
python -m iocextract extract --format json demos/01-basic/sample_alert.txt
```

Or pipe text straight in:

```
cat demos/01-basic/sample_alert.txt | python -m iocextract extract --format json
```

## What you should see
- `refang` normalizes `hxxps://malicious-update[.]top/...` and
  `soc[at]corp[.]net` before matching, so defanged input is still extracted.
- One `url`, several `domain`/`ipv4`/`ipv6`, two-plus `email`, and three hashes
  (`md5`, `sha1`, `sha256`) — each rendered **defanged** (`hxxps://`, `[.]`,
  `[at]`) so the output is safe to paste anywhere.
- Decoys filtered: `update.dll` / `invoice_2026.exe` are **not** treated as
  domains.

## Exit codes
- Exit **1** when one or more IOCs are found (a pipeline signal that the input
  is "dirty" / actionable).
- Exit **0** when the text is clean.
- Exit **2** on usage/IO error.

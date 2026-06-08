"""Command-line interface for IOCEXTRACT.

Subcommands
-----------
    extract   Pull IOCs from files or stdin (optionally filtered by --type).
    types     List the IOC types the engine knows about.
    refang    Print the refanged form of input text (debug aid).
    defang    Defang an http(s)/ftp URL or domain handed on the command line.

Conventions: ``--format {table,json}`` everywhere it makes sense, ``--version``
top-level, and a non-zero exit (1) when findings exist so the tool slots into
pipelines / feed processors.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Sequence

from .core import (
    IOC_TYPES,
    TOOL_NAME,
    TOOL_VERSION,
    ExtractResult,
    defang,
    extract,
    extract_from_files,
    refang,
)


def _read_stdin() -> str:
    return sys.stdin.read()


def _render_table(result: ExtractResult) -> str:
    if result.count == 0:
        return "No IOCs found."
    lines = []
    width_t = max(4, max(len(i.type) for i in result.iocs))
    header = f"{'TYPE'.ljust(width_t)}  DEFANGED"
    lines.append(header)
    lines.append("-" * max(len(header), 24))
    for ioc in result.iocs:
        lines.append(f"{ioc.type.ljust(width_t)}  {ioc.defanged}")
    lines.append("")
    summary = ", ".join(
        f"{k}={v}" for k, v in result.as_dict()["by_type"].items()
    )
    lines.append(f"total={result.count}  ({summary})")
    return "\n".join(lines)


def _emit(result: ExtractResult, fmt: str) -> None:
    if fmt == "json":
        payload = result.as_dict()
        payload["tool"] = TOOL_NAME
        payload["version"] = TOOL_VERSION
        print(json.dumps(payload, indent=2, sort_keys=False))
    else:
        print(_render_table(result))


def _parse_types(spec: str | None) -> list[str] | None:
    if not spec:
        return None
    wanted = [t.strip().lower() for t in spec.split(",") if t.strip()]
    bad = [t for t in wanted if t not in IOC_TYPES]
    if bad:
        raise ValueError(
            f"unknown type(s): {', '.join(bad)}; "
            f"valid: {', '.join(IOC_TYPES)}"
        )
    return wanted


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Extract and defang IOCs (IPs/IPv6/URLs/domains/emails/"
                    "hashes/CVEs/BTC/registry) from text. Defensive triage only.",
    )
    parser.add_argument(
        "--version", action="version",
        version=f"{TOOL_NAME} {TOOL_VERSION}",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_ex = sub.add_parser("extract", help="Extract IOCs from files or stdin.")
    p_ex.add_argument(
        "paths", nargs="*",
        help="Input file(s). If omitted, reads from stdin.",
    )
    p_ex.add_argument(
        "--type", "-t", dest="types", default=None,
        help="Comma-separated subset of IOC types to extract "
             f"(any of: {', '.join(IOC_TYPES)}).",
    )
    p_ex.add_argument(
        "--format", choices=("table", "json"), default="table",
        help="Output format (default: table).",
    )

    p_ty = sub.add_parser("types", help="List supported IOC types.")
    p_ty.add_argument(
        "--format", choices=("table", "json"), default="table",
        help="Output format (default: table).",
    )

    p_rf = sub.add_parser("refang", help="Print refanged form of stdin/text.")
    p_rf.add_argument("text", nargs="*", help="Text (else read stdin).")

    p_df = sub.add_parser("defang", help="Defang a URL/domain/email argument.")
    p_df.add_argument("value", help="The indicator to defang.")
    p_df.add_argument(
        "--as", dest="as_type", choices=("url", "domain", "email", "ipv4"),
        default="url", help="How to treat the value (default: url).",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "extract":
        try:
            wanted = _parse_types(args.types)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        try:
            if args.paths:
                result = extract_from_files(args.paths, types=wanted)
            else:
                result = extract(_read_stdin(), types=wanted)
        except OSError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

        _emit(result, args.format)
        # Non-zero exit when findings exist (feed/pipeline signal).
        return 1 if result.count > 0 else 0

    if args.command == "types":
        if args.format == "json":
            print(json.dumps(
                {"tool": TOOL_NAME, "version": TOOL_VERSION,
                 "types": list(IOC_TYPES)},
                indent=2,
            ))
        else:
            print("\n".join(IOC_TYPES))
        return 0

    if args.command == "refang":
        text = " ".join(args.text) if args.text else _read_stdin()
        sys.stdout.write(refang(text))
        if not text.endswith("\n"):
            sys.stdout.write("\n")
        return 0

    if args.command == "defang":
        print(defang(args.value, args.as_type))
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())

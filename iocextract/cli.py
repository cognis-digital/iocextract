"""Command-line interface for IOCEXTRACT."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Sequence

from . import TOOL_NAME, TOOL_VERSION
from .core import ExtractResult, extract, extract_from_files


def _read_stdin() -> str:
    return sys.stdin.read()


def _render_table(result: ExtractResult) -> str:
    if result.count == 0:
        return "No IOCs found."
    lines = []
    width_t = max(4, max(len(i.type) for i in result.iocs))
    header = f"{'TYPE'.ljust(width_t)}  DEFANGED"
    lines.append(header)
    lines.append("-" * len(header))
    for ioc in result.iocs:
        lines.append(f"{ioc.type.ljust(width_t)}  {ioc.defanged}")
    lines.append("")
    summary = ", ".join(f"{k}={v}" for k, v in result.as_dict()["by_type"].items())
    lines.append(f"total={result.count}  ({summary})")
    return "\n".join(lines)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Extract and defang IOCs (IPs/domains/URLs/emails/hashes) "
                    "from text. Defensive triage only.",
    )
    parser.add_argument(
        "--version", action="version",
        version=f"{TOOL_NAME} {TOOL_VERSION}",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_ex = sub.add_parser(
        "extract",
        help="Extract IOCs from files or stdin.",
    )
    p_ex.add_argument(
        "paths", nargs="*",
        help="Input file(s). If omitted, reads from stdin.",
    )
    p_ex.add_argument(
        "--format", choices=("table", "json"), default="table",
        help="Output format (default: table).",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "extract":
        try:
            if args.paths:
                result = extract_from_files(args.paths)
            else:
                result = extract(_read_stdin())
        except OSError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

        if args.format == "json":
            payload = result.as_dict()
            payload["tool"] = TOOL_NAME
            payload["version"] = TOOL_VERSION
            print(json.dumps(payload, indent=2, sort_keys=False))
        else:
            print(_render_table(result))

        # Non-zero exit when findings exist (feed/pipeline signal).
        return 1 if result.count > 0 else 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())

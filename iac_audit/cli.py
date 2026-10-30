"""Command line entry point."""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from .engine import scan
from .models import Severity
from .report import render_json, render_markdown, render_text

FAIL_LEVELS = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "none": None,
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="iac-audit",
        description="Static audit of Terraform and CloudFormation for public exposure and weak defaults.",
    )
    parser.add_argument("paths", nargs="+", help="files or directories to audit")
    parser.add_argument(
        "-f",
        "--format",
        choices=("text", "markdown", "json"),
        default="text",
        help="output format (default: text)",
    )
    parser.add_argument("-o", "--output", help="write the report to a file instead of stdout")
    parser.add_argument(
        "--fail-on",
        choices=sorted(FAIL_LEVELS),
        default="high",
        help="exit 1 when a finding at or above this severity exists (default: high, 'none' never fails)",
    )
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colour in text output")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    result = scan(args.paths)

    if args.format == "json":
        report = render_json(result)
    elif args.format == "markdown":
        report = render_markdown(result)
    else:
        report = render_text(result, color=not args.no_color and sys.stdout.isatty())

    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(report + "\n")
        print(f"wrote {args.output}", file=sys.stderr)
    else:
        print(report)

    threshold = FAIL_LEVELS[args.fail_on]
    if threshold is None:
        return 0
    return 1 if result.at_or_above(threshold) else 0


if __name__ == "__main__":
    raise SystemExit(main())

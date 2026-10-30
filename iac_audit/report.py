"""Report rendering: Markdown for the repo, JSON for pipelines, ANSI for a terminal."""

from __future__ import annotations

import json
from typing import List

from .models import ScanResult, Severity

COLORS = {
    "Critical": "\033[1;35m",
    "High": "\033[1;31m",
    "Medium": "\033[1;33m",
    "Low": "\033[1;36m",
    "Info": "\033[1;37m",
}
RESET = "\033[0m"
DIM = "\033[2m"
BOLD = "\033[1m"


def counts_line(result: ScanResult) -> str:
    counts = result.counts()
    parts = [
        f"{counts[severity.value]} {severity.value}"
        for severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)
        if counts[severity.value]
    ]
    return ", ".join(parts) if parts else "no findings"


def render_text(result: ScanResult, color: bool = True) -> str:
    def paint(code: str, value: str) -> str:
        return f"{code}{value}{RESET}" if color else value

    file_count = len({resource.file for resource in result.resources})
    lines: List[str] = []
    lines.append(
        paint(BOLD, "IaC audit")
        + f" — {len(result.resources)} resources across {file_count} file{'' if file_count == 1 else 's'}"
    )
    lines.append("─" * 78)

    if result.errors:
        for error in result.errors:
            lines.append(paint(COLORS["Medium"], f"[warn] {error}"))
        lines.append("")

    findings = result.sorted_findings()
    if not findings:
        lines.append(paint("\033[1;32m", "No findings.") + " Every rule passed on every resource.")
    else:
        for finding in findings:
            tag = f"[{finding.severity.value.upper()}]"
            lines.append(f"{paint(COLORS[finding.severity.value], tag.ljust(10))} {finding.rule_id}  {finding.title}")
            lines.append(f"{'':11}{paint(DIM, finding.resource + '  ' + finding.location)}")
            lines.append(f"{'':11}{finding.evidence}")
            lines.append("")

    lines.append("─" * 78)
    lines.append(f"{counts_line(result)} across {len(result.resources)} resources")
    return "\n".join(lines)


def render_markdown(result: ScanResult) -> str:
    lines: List[str] = []
    files = sorted({resource.file for resource in result.resources})
    lines.append("# Infrastructure audit")
    lines.append("")
    lines.append(f"- **Roots:** {', '.join(f'`{root}`' for root in result.roots) or '(none)'}")
    lines.append(f"- **Files read:** {len(files)}")
    lines.append(f"- **Resources audited:** {len(result.resources)}")
    lines.append(f"- **Findings:** {len(result.findings)} ({counts_line(result)})")
    lines.append("")

    counts = result.counts()
    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("| --- | --- |")
    for severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        lines.append(f"| {severity.value} | {counts[severity.value]} |")
    lines.append("")

    if result.errors:
        lines.append("## Files that could not be read")
        lines.append("")
        for error in result.errors:
            lines.append(f"- {error}")
        lines.append("")

    lines.append("## Findings")
    lines.append("")
    if not result.findings:
        lines.append("No findings. Every rule passed on every resource in scope.")
        lines.append("")

    for index, item in enumerate(result.sorted_findings(), start=1):
        lines.append(f"### {index}. [{item.severity.value}] {item.title}")
        lines.append("")
        lines.append(f"- **Rule:** `{item.rule_id}`")
        lines.append(f"- **Resource:** `{item.resource}`")
        lines.append(f"- **Location:** `{item.location}`")
        lines.append(f"- **Why it matters:** {item.detail}")
        lines.append(f"- **Evidence:** `{item.evidence}`")
        lines.append(f"- **Remediation:** {item.remediation}")
        if item.reference:
            lines.append(f"- **Reference:** {item.reference}")
        lines.append("")

    lines.append("## Method and limits")
    lines.append("")
    lines.append(
        "Terraform is read with a small HCL parser that understands blocks, labels, literals and "
        "`jsonencode` payloads; anything it cannot evaluate stays opaque and is not guessed at. "
        "CloudFormation is read from JSON (or YAML when PyYAML is installed). Rules are static: "
        "nothing is deployed, no cloud credentials are used, and a passing scan is not proof that "
        "the deployed account matches the template."
    )
    lines.append("")

    return "\n".join(lines)


def render_json(result: ScanResult) -> str:
    payload = {
        "roots": result.roots,
        "resources": len(result.resources),
        "counts": result.counts(),
        "errors": result.errors,
        "findings": [
            {
                "rule_id": item.rule_id,
                "title": item.title,
                "severity": item.severity.value,
                "resource": item.resource,
                "file": item.file,
                "line": item.line,
                "detail": item.detail,
                "evidence": item.evidence,
                "remediation": item.remediation,
                "reference": item.reference,
            }
            for item in result.sorted_findings()
        ],
    }
    return json.dumps(payload, indent=2)

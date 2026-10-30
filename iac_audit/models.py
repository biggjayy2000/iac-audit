"""Data model for an infrastructure scan: resources, findings, and the run itself."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


_RANK = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
    "Info": 4,
}


@dataclass(frozen=True)
class Finding:
    """One weak configuration, tied to the resource and line that produced it."""

    rule_id: str
    title: str
    severity: Severity
    resource: str
    file: str
    line: int
    detail: str
    evidence: str
    remediation: str
    reference: str = ""

    @property
    def rank(self) -> int:
        return _RANK[self.severity.value]

    @property
    def location(self) -> str:
        return f"{self.file}:{self.line}" if self.line else self.file


@dataclass
class Resource:
    """A normalized infrastructure object, whatever the source language was.

    Terraform and CloudFormation describe the same things with different names. Rules
    run against `kind`, so a rule is written once instead of twice.
    """

    kind: str
    source_type: str
    name: str
    body: Dict[str, Any]
    file: str
    line: int = 0
    fmt: str = "terraform"

    @property
    def label(self) -> str:
        return f"{self.source_type}.{self.name}" if self.fmt == "terraform" else self.name


@dataclass
class ScanResult:
    roots: List[str]
    findings: List[Finding] = field(default_factory=list)
    resources: List[Resource] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def counts(self) -> Dict[str, int]:
        counts = {severity.value: 0 for severity in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def sorted_findings(self) -> List[Finding]:
        return sorted(self.findings, key=lambda f: (f.rank, f.rule_id, f.file, f.line))

    def at_or_above(self, severity: Severity) -> List[Finding]:
        threshold = _RANK[severity.value]
        return [f for f in self.findings if f.rank <= threshold]

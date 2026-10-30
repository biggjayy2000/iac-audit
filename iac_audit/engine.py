"""Discovery, parsing and the scan loop."""

from __future__ import annotations

import os
from typing import Iterable, List

from .cloudformation import is_template, load_template, parse_cloudformation
from .models import Resource, ScanResult
from .rules import run_rules
from .terraform import parse_terraform

TERRAFORM_SUFFIX = ".tf"
TEMPLATE_SUFFIXES = {".json", ".yaml", ".yml", ".template"}
SKIP_DIRECTORIES = {".git", ".terraform", "node_modules", "__pycache__"}


def discover(paths: Iterable[str]) -> List[str]:
    """Expand files and directories into the set of templates worth reading."""
    files: List[str] = []

    for path in paths:
        if os.path.isdir(path):
            for root, directories, names in os.walk(path):
                directories[:] = [d for d in directories if d not in SKIP_DIRECTORIES]
                for name in names:
                    suffix = os.path.splitext(name)[1].lower()
                    if name.endswith(TERRAFORM_SUFFIX) or suffix in TEMPLATE_SUFFIXES:
                        files.append(os.path.join(root, name))
        elif os.path.isfile(path):
            files.append(path)

    return sorted(set(files))


def parse_file(path: str) -> List[Resource]:
    """Parse one file. JSON that is not a CloudFormation template is ignored, not warned about.

    Terraform projects routinely contain policy JSON next to the configuration; reporting every
    one of them as a parse error would train the operator to ignore the error output.
    """
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        content = handle.read()

    # Report paths with forward slashes so a finding reads the same on any platform.
    display = path.replace(os.sep, "/")

    if path.endswith(TERRAFORM_SUFFIX):
        return parse_terraform(content, display)

    data = load_template(content, display)
    if not is_template(data):
        return []
    return parse_cloudformation(content, display)


def scan(paths: Iterable[str]) -> ScanResult:
    roots = list(paths)
    result = ScanResult(roots=roots)

    for path in discover(roots):
        try:
            result.resources.extend(parse_file(path))
        except (ValueError, OSError) as exc:
            result.errors.append(str(exc))

    for resource in result.resources:
        result.findings.extend(run_rules(resource, result.resources))

    return result

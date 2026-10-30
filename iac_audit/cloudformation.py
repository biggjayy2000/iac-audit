"""CloudFormation templates, normalized into the same Resource shape Terraform produces."""

from __future__ import annotations

import json
from typing import Any, Dict, List

from .models import Resource

CFN_KINDS = {
    "AWS::S3::Bucket": "s3_bucket",
    "AWS::S3::BucketPolicy": "s3_bucket_policy",
    "AWS::EC2::SecurityGroup": "security_group",
    "AWS::EC2::SecurityGroupIngress": "sg_rule",
    "AWS::EC2::Volume": "ebs_volume",
    "AWS::RDS::DBInstance": "rds_instance",
    "AWS::IAM::Policy": "iam_policy",
    "AWS::IAM::Role": "iam_role",
    "AWS::EC2::Instance": "ec2_instance",
}


def load_template(text: str, path: str) -> Dict[str, Any]:
    """JSON works with the standard library; YAML needs PyYAML and says so if missing."""
    if text.lstrip().startswith("{"):
        try:
            return json.loads(text)
        except ValueError as exc:
            raise ValueError(f"invalid JSON in {path}: {exc}") from exc

    try:
        import yaml  # type: ignore
    except ImportError as exc:
        raise ValueError(
            f"{path} looks like YAML. CloudFormation YAML needs PyYAML "
            "(pip install pyyaml); JSON templates work with the standard library."
        ) from exc

    loaded = yaml.safe_load(text)
    if not isinstance(loaded, dict):
        raise ValueError(f"{path} did not contain a CloudFormation mapping")
    return loaded


def _line_of(text: str, name: str) -> int:
    """Best effort: the line where the logical id appears."""
    for needle in (f'"{name}"', f"{name}:"):
        position = text.find(needle)
        if position != -1:
            return text.count("\n", 0, position) + 1
    return 0


def is_template(data: Any) -> bool:
    return isinstance(data, dict) and isinstance(data.get("Resources"), dict)


def parse_cloudformation(text: str, path: str) -> List[Resource]:
    data = load_template(text, path)
    if not is_template(data):
        raise ValueError(f"{path} has no Resources section")

    resources: List[Resource] = []
    for name, definition in data["Resources"].items():
        if not isinstance(definition, dict):
            continue
        source_type = str(definition.get("Type", ""))
        properties = definition.get("Properties")
        resources.append(
            Resource(
                kind=CFN_KINDS.get(source_type, source_type),
                source_type=source_type,
                name=name,
                body=properties if isinstance(properties, dict) else {},
                file=path,
                line=_line_of(text, name),
                fmt="cloudformation",
            )
        )

    return resources

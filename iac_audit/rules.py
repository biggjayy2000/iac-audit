"""The rules.

Each rule is a generator over one resource and receives every resource in the scan, so a rule
that needs context (a bucket and its policy, say) can look at both. Findings name the rule, not
the file, so a rule id stays stable when a template is reorganised.

Severities follow the same scale as `websec-audit`: what an attacker gains, not how clever the
check was. A bucket readable by the internet is High whether it got that way through an ACL, a
policy, or a website configuration.
"""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Tuple

from .models import Finding, Resource, Severity
from .terraform import Opaque

PUBLIC_CIDRS = {"0.0.0.0/0", "::/0"}
# Terraform spells these `public-read`, CloudFormation spells them `PublicRead`.
PUBLIC_ACLS = {"publicread", "publicreadwrite", "website"}
SENSITIVE_PORTS = {
    22: "SSH",
    23: "Telnet",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    9200: "Elasticsearch",
    27017: "MongoDB",
}

SECRET_SUFFIXES = ("password", "secret", "apikey", "accesskey", "privatekey", "token")
SECRET_NAMES = {
    "password",
    "secret",
    "secretkey",
    "accesskey",
    "apikey",
    "token",
    "privatekey",
    "credentials",
}

RULES: List[Callable[[Resource, List[Resource]], Iterator[Finding]]] = []


def rule(function: Callable[[Resource, List[Resource]], Iterator[Finding]]):
    RULES.append(function)
    return function


# --------------------------------------------------------------------------- helpers


def as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def text(value: Any) -> str:
    return value.strip().lower() if isinstance(value, str) else ""


def truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() == "true"
    return False


def policy_documents(value: Any) -> List[Dict[str, Any]]:
    """A policy may be a dict, a JSON string, or `jsonencode` output that parsed to a dict."""
    if isinstance(value, dict):
        return [value]
    if isinstance(value, str) and not isinstance(value, Opaque):
        try:
            parsed = json.loads(value)
        except ValueError:
            return []
        return [parsed] if isinstance(parsed, dict) else []
    return []


def statements(document: Dict[str, Any]) -> List[Dict[str, Any]]:
    entries = as_list(document.get("Statement"))
    return [entry for entry in entries if isinstance(entry, dict)]


def allows(statement: Dict[str, Any]) -> bool:
    effect = statement.get("Effect")
    if effect is None:
        return True
    return text(effect) == "allow"


def wildcard_principal(statement: Dict[str, Any]) -> bool:
    principal = statement.get("Principal")
    if principal == "*":
        return True
    if isinstance(principal, dict):
        for value in principal.values():
            if value == "*" or "*" in as_list(value):
                return True
    return False


def looks_secret(key: str) -> bool:
    """Match both naming styles: `master_password` and CloudFormation's `MasterUserPassword`."""
    name = text(key).replace("_", "").replace("-", "")
    if not name:
        return False
    return name in SECRET_NAMES or name.endswith(SECRET_SUFFIXES)


def flatten(body: Dict[str, Any]) -> Iterator[Tuple[str, Any]]:
    for key, value in body.items():
        if isinstance(value, dict):
            yield from flatten(value)
        elif isinstance(value, list):
            for entry in value:
                if isinstance(entry, dict):
                    yield from flatten(entry)
                else:
                    yield key, entry
        else:
            yield key, value


def finding(resource: Resource, **kwargs: Any) -> Finding:
    return Finding(
        resource=resource.label,
        file=resource.file,
        line=resource.line,
        **kwargs,
    )


def classify_ports(protocol: Any, from_port: Any, to_port: Any) -> Tuple[Severity, str]:
    """How bad is this open range? Returns the severity and a human description."""
    proto = text(protocol)
    low = from_port if isinstance(from_port, int) else None
    high = to_port if isinstance(to_port, int) else low

    if proto in ("-1", "all"):
        return Severity.CRITICAL, "every protocol and port"
    if low is not None and high is not None and low <= 0 and high >= 65535:
        return Severity.CRITICAL, "every port"

    if low is not None and high is not None:
        if low == high:
            name = SENSITIVE_PORTS.get(low)
            return (Severity.HIGH, f"{name} ({low})") if name else (Severity.MEDIUM, f"port {low}")
        covered = [port for port in SENSITIVE_PORTS if low <= port <= high]
        if covered:
            described = ", ".join(f"{SENSITIVE_PORTS[port]} ({port})" for port in sorted(covered))
            return Severity.HIGH, f"ports {low}-{high}, including {described}"
        return Severity.MEDIUM, f"ports {low}-{high}"

    return Severity.HIGH, "an unspecified port range"


def ingress_entries(resource: Resource) -> Iterator[Dict[str, Any]]:
    if resource.kind == "sg_rule":
        yield resource.body
        return
    if resource.kind != "security_group":
        return
    raw = resource.body.get("ingress") or resource.body.get("SecurityGroupIngress")
    for entry in as_list(raw):
        if isinstance(entry, dict):
            yield entry


# --------------------------------------------------------------------------- rules


@rule
def s3_bucket_public(resource: Resource, everything: List[Resource]) -> Iterator[Finding]:
    """IAC001 — a bucket readable by anyone on the internet."""
    if resource.kind != "s3_bucket":
        return

    raw_acl = resource.body.get("acl") or resource.body.get("AccessControl")
    acl = text(raw_acl).replace("-", "").replace("_", "")
    website = resource.body.get("website") or resource.body.get("WebsiteConfiguration")

    if acl in PUBLIC_ACLS:
        yield finding(
            resource,
            rule_id="IAC001",
            title="S3 bucket is publicly readable",
            severity=Severity.HIGH,
            detail=(
                f"The bucket ACL is '{raw_acl}', which grants anonymous read access. Bucket contents "
                "are then browsable by anyone who knows or guesses the name."
            ),
            evidence=f"acl = {raw_acl}",
            remediation=(
                "Remove the public ACL and enable all four S3 Block Public Access settings. If the "
                "content must be public, front it with CloudFront and an origin access control."
            ),
            reference="CIS AWS 2.1.5",
        )

    if website:
        yield finding(
            resource,
            rule_id="IAC001",
            title="S3 bucket is configured as a public website",
            severity=Severity.HIGH,
            detail=(
                "Website hosting serves objects to anonymous callers and cannot enforce "
                "authorisation. Any object in the bucket that is readable is public."
            ),
            evidence="website configuration present",
            remediation="Serve the site through CloudFront with a private bucket origin.",
            reference="CIS AWS 2.1.5",
        )


@rule
def security_group_open(resource: Resource, everything: List[Resource]) -> Iterator[Finding]:
    """IAC002 — a rule that admits the whole internet."""
    for entry in ingress_entries(resource):
        cidrs: List[str] = []
        for key in ("cidr_blocks", "CidrIp", "cidr_ipv4", "ipv6_cidr_blocks", "CidrIpv6"):
            for value in as_list(entry.get(key)):
                if isinstance(value, str):
                    cidrs.append(value)

        exposed = [cidr for cidr in cidrs if cidr.strip().lower() in PUBLIC_CIDRS]
        if not exposed:
            continue

        protocol = entry.get("protocol", entry.get("IpProtocol"))
        from_port = entry.get("from_port", entry.get("FromPort"))
        to_port = entry.get("to_port", entry.get("ToPort"))
        severity, description = classify_ports(protocol, from_port, to_port)

        yield finding(
            resource,
            rule_id="IAC002",
            title="Security group admits the internet",
            severity=severity,
            detail=(
                f"An ingress rule allows {', '.join(exposed)} to reach {description}. "
                f"{'Any host can reach this port.' if 'every' not in description else 'Any host can reach every port on this interface.'}"
            ),
            evidence=f"ingress {exposed[0]} -> {description}",
            remediation=(
                "Replace the CIDR with a specific range, or move the resource behind a load "
                "balancer and restrict the security group to it. For administrative ports, use a "
                "bastion or SSM Session Manager instead of exposing them."
            ),
            reference="CIS AWS 5.2",
        )


@rule
def ebs_unencrypted(resource: Resource, everything: List[Resource]) -> Iterator[Finding]:
    """IAC003 — a volume at rest with no encryption."""
    if resource.kind != "ebs_volume":
        return
    encrypted = resource.body.get("encrypted", resource.body.get("Encrypted"))
    if truthy(encrypted):
        return

    yield finding(
        resource,
        rule_id="IAC003",
        title="EBS volume is not encrypted at rest",
        severity=Severity.MEDIUM,
        detail=(
            "The volume has no encryption enabled. A snapshot of it can be shared or copied, and "
            "anyone who obtains the underlying storage reads the data without a key."
        ),
        evidence=f"encrypted = {encrypted if encrypted is not None else '(absent)'}",
        remediation=(
            "Set encrypted = true, and enable EBS encryption by default per region so new volumes "
            "cannot be created unencrypted."
        ),
        reference="CIS AWS 2.2.1",
    )


@rule
def rds_public(resource: Resource, everything: List[Resource]) -> Iterator[Finding]:
    """IAC004 — a database with a public endpoint."""
    if resource.kind != "rds_instance":
        return
    if not truthy(resource.body.get("publicly_accessible", resource.body.get("PubliclyAccessible"))):
        return

    yield finding(
        resource,
        rule_id="IAC004",
        title="RDS instance is publicly accessible",
        severity=Severity.HIGH,
        detail=(
            "The instance resolves to a public address and accepts connections from outside the "
            "VPC. Authentication becomes the only control, and it is reachable by the whole internet."
        ),
        evidence="publicly_accessible = true",
        remediation="Set publicly_accessible = false and reach the database through a bastion or VPN.",
        reference="CIS AWS 2.3.3",
    )


@rule
def rds_unencrypted(resource: Resource, everything: List[Resource]) -> Iterator[Finding]:
    """IAC005 — a database at rest with no encryption."""
    if resource.kind != "rds_instance":
        return
    if truthy(resource.body.get("storage_encrypted", resource.body.get("StorageEncrypted"))):
        return

    yield finding(
        resource,
        rule_id="IAC005",
        title="RDS storage is not encrypted",
        severity=Severity.MEDIUM,
        detail=(
            "Storage encryption is off. Snapshots inherit the setting, so backups of this instance "
            "are readable by anyone who can restore them."
        ),
        evidence="storage_encrypted is absent or false",
        remediation="Set storage_encrypted = true; the instance must be recreated to apply it.",
        reference="CIS AWS 2.3.1",
    )


@rule
def iam_wildcard(resource: Resource, everything: List[Resource]) -> Iterator[Finding]:
    """IAC006 — a policy that permits any action on any resource."""
    if resource.kind != "iam_policy":
        return

    raw = resource.body.get("policy") or resource.body.get("PolicyDocument")
    for document in policy_documents(raw):
        for statement in statements(document):
            if not allows(statement):
                continue
            actions = [text(action) for action in as_list(statement.get("Action"))]
            targets = [str(target) for target in as_list(statement.get("Resource"))]
            if "*" not in actions or "*" not in targets:
                continue

            yield finding(
                resource,
                rule_id="IAC006",
                title="IAM policy grants * on *",
                severity=Severity.CRITICAL,
                detail=(
                    "The statement allows every action on every resource. Any principal that can "
                    "assume this policy holds full control of the account, including the ability "
                    "to create new identities."
                ),
                evidence='Action = "*", Resource = "*"',
                remediation=(
                    "Replace the wildcard with the specific actions the workload calls, scoped to "
                    "the ARNs it actually uses. Use IAM Access Analyzer to generate a policy from "
                    "observed activity."
                ),
                reference="CIS AWS 1.16",
            )


@rule
def iam_trust_any(resource: Resource, everything: List[Resource]) -> Iterator[Finding]:
    """IAC007 — a role any AWS account can assume."""
    if resource.kind != "iam_role":
        return

    raw = resource.body.get("assume_role_policy") or resource.body.get("AssumeRolePolicyDocument")
    for document in policy_documents(raw):
        for statement in statements(document):
            if not allows(statement) or not wildcard_principal(statement):
                continue
            if statement.get("Condition"):
                continue  # conditioned trust is still a risk, but not the same finding

            yield finding(
                resource,
                rule_id="IAC007",
                title="IAM role trusts any principal",
                severity=Severity.HIGH,
                detail=(
                    "The trust policy allows Principal '*', so any AWS account can assume this "
                    "role. Cross-account access control is effectively disabled."
                ),
                evidence='Principal = "*" with no Condition',
                remediation=(
                    "Name the account, role or federated identity provider that should assume the "
                    "role. If the trust must be broad, require an ExternalId condition."
                ),
                reference="CIS AWS 1.17",
            )


@rule
def hardcoded_credential(resource: Resource, everything: List[Resource]) -> Iterator[Finding]:
    """IAC008 — a secret written into the template.

    The value is deliberately never printed: a scanner that echoes the credential into a report
    has moved it somewhere new, and that report gets attached to tickets.
    """
    for key, value in flatten(resource.body):
        if not looks_secret(key):
            continue
        if not isinstance(value, str) or isinstance(value, Opaque) or not value.strip():
            continue

        yield finding(
            resource,
            rule_id="IAC008",
            title="Credential hard-coded in the template",
            severity=Severity.HIGH,
            detail=(
                f"The '{key}' attribute holds a literal value. Templates are committed, reviewed "
                "and often retained in build logs, so the secret is already outside a secret store."
            ),
            evidence=f"{key} = <literal, masked>",
            remediation=(
                "Move the value to Secrets Manager or SSM Parameter Store and reference it, and "
                "rotate the credential that was committed."
            ),
            reference="CIS AWS 1.4",
        )


@rule
def ec2_public_ip(resource: Resource, everything: List[Resource]) -> Iterator[Finding]:
    """IAC009 — an instance that gets a public address."""
    if resource.kind != "ec2_instance":
        return

    direct = resource.body.get("associate_public_ip_address")
    interfaces = as_list(resource.body.get("NetworkInterfaces"))
    nested = any(
        truthy(entry.get("AssociatePublicIpAddress"))
        for entry in interfaces
        if isinstance(entry, dict)
    )

    if not truthy(direct) and not nested:
        return

    yield finding(
        resource,
        rule_id="IAC009",
        title="EC2 instance is assigned a public IP address",
        severity=Severity.LOW,
        detail=(
            "The instance receives a public address, so every service on it is reachable from the "
            "internet subject only to its security group."
        ),
        evidence="associate_public_ip_address = true",
        remediation=(
            "Place the instance in a private subnet and route egress through a NAT gateway; use a "
            "load balancer or Systems Manager for access."
        ),
        reference="CIS AWS 5.3",
    )


@rule
def s3_policy_public(resource: Resource, everything: List[Resource]) -> Iterator[Finding]:
    """IAC010 — a bucket policy that grants anyone access."""
    if resource.kind != "s3_bucket_policy":
        return

    raw = resource.body.get("policy") or resource.body.get("PolicyDocument")
    for document in policy_documents(raw):
        for statement in statements(document):
            if not allows(statement) or not wildcard_principal(statement):
                continue
            if statement.get("Condition"):
                continue

            yield finding(
                resource,
                rule_id="IAC010",
                title="S3 bucket policy allows any principal",
                severity=Severity.HIGH,
                detail=(
                    "The policy grants Principal '*' without a condition, which makes the bucket "
                    "open to anonymous requests regardless of its ACL."
                ),
                evidence='Principal = "*" with no Condition',
                remediation=(
                    "Scope the principal to the accounts or roles that need access, or require "
                    "aws:SourceArn / aws:SourceAccount conditions."
                ),
                reference="CIS AWS 2.1.5",
            )


def run_rules(resource: Resource, everything: List[Resource]) -> Iterator[Finding]:
    for check in RULES:
        yield from check(resource, everything)

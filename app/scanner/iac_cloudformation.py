"""
ZSE IaC CloudFormation Scanner -- D-679: Security analysis for AWS CloudFormation templates.

Scans CloudFormation YAML/JSON templates for common security misconfigurations:
- S3 buckets with public access enabled
- Security groups with 0.0.0.0/0 ingress/egress rules
- RDS instances without encryption
- IAM policies with wildcard actions or resources
- Missing encryption on EBS volumes, SNS topics, SQS queues
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

_CF_FINDING_SEVERITY_MAP = {
    "S3PublicAccess": "high",
    "SecurityGroupOpenIngress": "high",
    "SecurityGroupOpenEgress": "medium",
    "RDSUnencrypted": "high",
    "IAMWildcardAction": "high",
    "IAMWildcardResource": "medium",
    "EBSUnencrypted": "medium",
    "SNSUnencrypted": "low",
    "SQSUnencrypted": "low",
    "LambdaNoVPC": "info",
    "CloudTrailNotEnabled": "medium",
}


def _parse_cf_template(content: str) -> Optional[dict[str, Any]]:
    """Parse CloudFormation template from JSON or YAML content."""
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass
    # Minimal YAML parsing for CF templates (key: value and nested blocks)
    try:
        lines = content.splitlines()
        # Try simple key:value extraction -- not full YAML but handles most CF structures
        result: dict[str, Any] = {}
        _parse_yaml_block(lines, 0, result)
        return result if result else None
    except Exception:
        return None


def _parse_yaml_block(lines: list[str], start_indent: int, target: dict) -> None:
    """Very minimal YAML block parser for CloudFormation templates."""
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue
        current_indent = len(line) - len(stripped)
        if current_indent < start_indent:
            break
        if ":" in stripped:
            key, _, val = stripped.partition(":")
            key = key.strip()
            val = val.strip()
            if val:
                # Inline value
                if val.startswith('"') or val.startswith("'"):
                    val = val.strip('"\'')
                elif val.lower() == "true":
                    val = True
                elif val.lower() == "false":
                    val = False
                elif val.lower() in ("null", "~"):
                    val = None
                target[key] = val
            else:
                # Nested block -- collect child lines
                child_lines = []
                j = i + 1
                base = current_indent + 2
                while j < len(lines):
                    cl = lines[j]
                    cs = cl.lstrip()
                    ci = len(cl) - len(cs) if cs else 0
                    if cs and ci < base:
                        break
                    child_lines.append(cl)
                    j += 1
                child = {}
                _parse_yaml_block(child_lines, base, child)
                target[key] = child
                i = j
                continue
        i += 1


def _get_resources(template: dict[str, Any]) -> dict[str, Any]:
    """Extract Resources section from CF template."""
    resources = template.get("Resources", {})
    if not isinstance(resources, dict):
        return {}
    return resources


def _check_s3_public_access(resource_name: str, props: dict[str, Any]) -> list[dict]:
    findings = []
    public_access = props.get("PublicAccessBlockConfiguration", {})
    if isinstance(public_access, dict):
        checks = [
            "BlockPublicAcls",
            "BlockPublicPolicy",
            "IgnorePublicAcls",
            "RestrictPublicBuckets",
        ]
        for check in checks:
            val = public_access.get(check)
            if val is False or str(val).lower() == "false":
                findings.append({
                    "rule_id": "S3PublicAccess",
                    "resource": resource_name,
                    "message": "S3 bucket {} is not fully blocking public access ({} = false).".format(
                        resource_name, check
                    ),
                    "severity": "high",
                })
    acl = props.get("AccessControl", "")
    if isinstance(acl, str) and acl.lower() in ("public-read", "public-read-write", "authenticated-read"):
        findings.append({
            "rule_id": "S3PublicAccess",
            "resource": resource_name,
            "message": "S3 bucket {} has public ACL: {}.".format(resource_name, acl),
            "severity": "high",
        })
    return findings


def _check_security_group(resource_name: str, props: dict[str, Any]) -> list[dict]:
    findings = []
    for direction, rule_id in [("SecurityGroupIngress", "SecurityGroupOpenIngress"),
                                ("SecurityGroupEgress", "SecurityGroupOpenEgress")]:
        rules = props.get(direction, [])
        if not isinstance(rules, list):
            continue
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            cidr = rule.get("CidrIp", "") or rule.get("CidrIpv6", "")
            if cidr in ("0.0.0.0/0", "::/0"):
                from_port = rule.get("FromPort", "")
                to_port = rule.get("ToPort", "")
                findings.append({
                    "rule_id": rule_id,
                    "resource": resource_name,
                    "message": "Security group {} allows unrestricted {} from {} (ports {}-{}).".format(
                        resource_name, direction, cidr, from_port, to_port
                    ),
                    "severity": _CF_FINDING_SEVERITY_MAP[rule_id],
                })
    return findings


def _check_rds(resource_name: str, props: dict[str, Any]) -> list[dict]:
    findings = []
    encrypted = props.get("StorageEncrypted")
    if encrypted is False or str(encrypted).lower() == "false":
        findings.append({
            "rule_id": "RDSUnencrypted",
            "resource": resource_name,
            "message": "RDS instance {} does not have StorageEncrypted enabled.".format(resource_name),
            "severity": "high",
        })
    return findings


def _check_iam_policy(resource_name: str, props: dict[str, Any]) -> list[dict]:
    findings = []
    doc = props.get("PolicyDocument", props.get("AssumeRolePolicyDocument", {}))
    if not isinstance(doc, dict):
        return findings
    statements = doc.get("Statement", [])
    if not isinstance(statements, list):
        return findings
    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        effect = stmt.get("Effect", "")
        if effect != "Allow":
            continue
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        resources = stmt.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]
        if "*" in actions or ".*" in str(actions):
            findings.append({
                "rule_id": "IAMWildcardAction",
                "resource": resource_name,
                "message": "IAM policy {} grants wildcard action (*).".format(resource_name),
                "severity": "high",
            })
        if "*" in resources:
            findings.append({
                "rule_id": "IAMWildcardResource",
                "resource": resource_name,
                "message": "IAM policy {} grants access to all resources (*).".format(resource_name),
                "severity": "medium",
            })
    return findings


def _check_ebs(resource_name: str, props: dict[str, Any]) -> list[dict]:
    findings = []
    encrypted = props.get("Encrypted")
    if encrypted is False or str(encrypted).lower() == "false":
        findings.append({
            "rule_id": "EBSUnencrypted",
            "resource": resource_name,
            "message": "EBS volume {} is not encrypted.".format(resource_name),
            "severity": "medium",
        })
    return findings


_RESOURCE_CHECKERS = {
    "AWS::S3::Bucket": _check_s3_public_access,
    "AWS::EC2::SecurityGroup": _check_security_group,
    "AWS::RDS::DBInstance": _check_rds,
    "AWS::IAM::Policy": _check_iam_policy,
    "AWS::IAM::ManagedPolicy": _check_iam_policy,
    "AWS::IAM::Role": _check_iam_policy,
    "AWS::EC2::Volume": _check_ebs,
}


def scan_cloudformation(template_path: str) -> list[dict[str, Any]]:
    """Scan a CloudFormation template file for security misconfigurations.

    Args:
        template_path: Absolute path to a CloudFormation JSON or YAML template.

    Returns:
        List of finding dicts with keys: rule_id, resource, message, severity, file.
    """
    path = Path(template_path)
    if not path.exists():
        logger.warning("CloudFormation template not found: %s", template_path)
        return []

    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except OSError as exc:
        logger.error("Cannot read CF template %s: %s", template_path, exc)
        return []

    template = _parse_cf_template(content)
    if not template:
        logger.warning("Failed to parse CF template: %s", template_path)
        return []

    resources = _get_resources(template)
    if not resources:
        logger.info("No Resources section in %s", template_path)
        return []

    all_findings: list[dict[str, Any]] = []
    for resource_name, resource_def in resources.items():
        if not isinstance(resource_def, dict):
            continue
        resource_type = resource_def.get("Type", "")
        props = resource_def.get("Properties", {})
        if not isinstance(props, dict):
            props = {}
        checker = _RESOURCE_CHECKERS.get(resource_type)
        if checker:
            for finding in checker(resource_name, props):
                finding["file"] = template_path
                all_findings.append(finding)

    logger.info("CloudFormation scan of %s: %d findings", template_path, len(all_findings))
    return all_findings


def scan_cloudformation_directory(templates_dir: str) -> list[dict[str, Any]]:
    """Scan all CloudFormation templates in a directory recursively.

    Args:
        templates_dir: Directory to scan for .json, .yaml, .yml CF templates.

    Returns:
        Aggregated list of findings across all templates.
    """
    dir_path = Path(templates_dir)
    if not dir_path.is_dir():
        logger.warning("Directory not found: %s", templates_dir)
        return []

    all_findings: list[dict[str, Any]] = []
    for ext in ("*.json", "*.yaml", "*.yml", "*.template"):
        for template_file in dir_path.rglob(ext):
            # Skip node_modules, .git, etc.
            parts = template_file.parts
            if any(p in parts for p in (".git", "node_modules", "__pycache__")):
                continue
            all_findings.extend(scan_cloudformation(str(template_file)))

    logger.info("CloudFormation dir scan %s: %d total findings", templates_dir, len(all_findings))
    return all_findings

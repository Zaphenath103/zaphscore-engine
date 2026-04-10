"""
ZSE IaC Terraform Scanner -- D-683: Terraform variable substitution for
accurate security analysis.

Reads .tfvars files and substitutes ${var.name} patterns in Terraform
resource dicts before analysis, preventing false negatives from unresolved
variable references.
"""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Regex patterns for Terraform variable references
_INTERP_VAR_PATTERN: re.Pattern = re.compile(r'\$\{var\.([A-Za-z_][A-Za-z0-9_]*)\}')
_STANDALONE_VAR_PATTERN: re.Pattern = re.compile(r'^var\.([A-Za-z_][A-Za-z0-9_]*)$')


def _parse_tfvars_content(content: str) -> dict[str, Any]:
    """Parse .tfvars file content into a variable dict.

    Handles strings, numbers, booleans, lists, and simple maps.
    Ignores comment lines (# and //).
    """
    variables: dict[str, Any] = {}
    lines = content.splitlines()
    i = 0

    while i < len(lines):
        line = lines[i].strip()
        if not line or line.startswith("#") or line.startswith("//"):
            i += 1
            continue

        if "=" in line:
            key, _, rest = line.partition("=")
            key = key.strip()
            rest = rest.strip()

            if not re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', key):
                i += 1
                continue

            if rest.startswith('"'):
                full_val = rest[1:]
                while '"' not in full_val and i + 1 < len(lines):
                    i += 1
                    full_val += "\n" + lines[i].strip()
                end_idx = full_val.find('"')
                variables[key] = full_val[:end_idx] if end_idx >= 0 else full_val

            elif rest.startswith("["):
                list_content = rest
                while "]" not in list_content and i + 1 < len(lines):
                    i += 1
                    list_content += lines[i].strip()
                inner = list_content.strip("[]").strip()
                variables[key] = [
                    item.strip().strip('"\'')
                    for item in inner.split(",")
                    if item.strip()
                ]

            elif rest.startswith("{"):
                map_content = rest
                depth = map_content.count("{") - map_content.count("}")
                while depth > 0 and i + 1 < len(lines):
                    i += 1
                    next_line = lines[i].strip()
                    map_content += " " + next_line
                    depth += next_line.count("{") - next_line.count("}")
                variables[key] = _parse_map_literal(map_content)

            elif rest.lower() in ("true", "false"):
                variables[key] = rest.lower() == "true"

            elif rest.lower() == "null":
                variables[key] = None

            elif re.match(r'^-?\d+(\.\d+)?$', rest):
                variables[key] = float(rest) if "." in rest else int(rest)

            else:
                variables[key] = rest

        i += 1

    return variables


def _parse_map_literal(map_str: str) -> dict[str, Any]:
    """Parse a simple HCL map literal {key = value, ...} into a dict."""
    result = {}
    inner = map_str.strip().strip("{}")
    for part in re.split(r'[,\n]', inner):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            k = k.strip()
            v = v.strip().strip('"\'')
            if k:
                result[k] = v
    return result


def read_tfvars_file(var_file_path: str) -> dict[str, Any]:
    """Read and parse a Terraform .tfvars or .tfvars.json file.

    Args:
        var_file_path: Absolute path to the .tfvars file.

    Returns:
        Dict of variable name -> value. Empty dict if file not found or parse fails.
    """
    path = Path(var_file_path)
    if not path.exists():
        logger.warning("tfvars file not found: %s", var_file_path)
        return {}

    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except OSError as exc:
        logger.error("Cannot read tfvars file %s: %s", var_file_path, exc)
        return {}

    if var_file_path.endswith(".json"):
        try:
            return json.loads(content)
        except json.JSONDecodeError as exc:
            logger.error("Failed to parse JSON tfvars %s: %s", var_file_path, exc)
            return {}

    try:
        return _parse_tfvars_content(content)
    except Exception as exc:
        logger.error("Failed to parse tfvars %s: %s", var_file_path, exc)
        return {}


def _substitute_value(value: Any, variables: dict[str, Any]) -> Any:
    """Substitute variable references in a value recursively.

    Handles ${var.name} interpolation, standalone var.name, and recurses
    into nested dicts and lists.
    """
    if isinstance(value, str):
        standalone = _STANDALONE_VAR_PATTERN.match(value.strip())
        if standalone:
            var_name = standalone.group(1)
            if var_name in variables:
                return variables[var_name]

        def replace_interp(m: re.Match) -> str:
            resolved = variables.get(m.group(1))
            return str(resolved) if resolved is not None else m.group(0)

        return _INTERP_VAR_PATTERN.sub(replace_interp, value)

    elif isinstance(value, dict):
        return {k: _substitute_value(v, variables) for k, v in value.items()}

    elif isinstance(value, list):
        return [_substitute_value(item, variables) for item in value]

    else:
        return value


def resolve_tf_variables(
    tf_dict: dict[str, Any],
    var_file_path: str,
    extra_vars: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Resolve Terraform variable references in a parsed Terraform resource dict.

    Reads a .tfvars file and substitutes ${var.name} and var.name patterns
    throughout the dict before security analysis. Prevents false negatives from
    rules that cannot match unresolved variable references.

    Args:
        tf_dict: Parsed Terraform resource dict (from HCL or JSON).
        var_file_path: Path to the .tfvars or .tfvars.json file.
        extra_vars: Optional additional variables (override tfvars values,
                    mirrors Terraform -var CLI flag precedence).

    Returns:
        New dict with all resolvable variable references substituted.
        Unresolvable references are left unchanged.
    """
    variables = read_tfvars_file(var_file_path)
    if extra_vars:
        variables.update(extra_vars)

    if not variables:
        logger.info("No variables loaded from %s -- returning tf_dict unchanged.", var_file_path)
        return tf_dict

    logger.info("Resolving %d variable(s) from %s", len(variables), var_file_path)
    resolved = _substitute_value(tf_dict, variables)
    return resolved if isinstance(resolved, dict) else tf_dict


def resolve_tf_variables_from_dir(
    tf_dict: dict[str, Any],
    tf_dir: str,
    extra_vars: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Resolve Terraform variables using all .tfvars files in a directory.

    Loads files in Terraform's standard auto-loading precedence:
    1. terraform.tfvars
    2. terraform.tfvars.json
    3. *.auto.tfvars (alphabetical)
    4. *.auto.tfvars.json (alphabetical)
    5. extra_vars (highest precedence, mirrors -var CLI flags)

    Args:
        tf_dict: Parsed Terraform resource dict.
        tf_dir: Directory containing .tfvars files.
        extra_vars: Optional variable overrides.

    Returns:
        Dict with variable references resolved.
    """
    dir_path = Path(tf_dir)
    merged_vars: dict[str, Any] = {}

    for pf in ["terraform.tfvars", "terraform.tfvars.json"]:
        candidate = dir_path / pf
        if candidate.exists():
            merged_vars.update(read_tfvars_file(str(candidate)))

    auto_files = sorted([
        f for f in dir_path.iterdir()
        if f.name.endswith(".auto.tfvars") or f.name.endswith(".auto.tfvars.json")
    ])
    for af in auto_files:
        merged_vars.update(read_tfvars_file(str(af)))

    if extra_vars:
        merged_vars.update(extra_vars)

    if not merged_vars:
        logger.info("No .tfvars files found in %s", tf_dir)
        return tf_dict

    logger.info("Resolving %d variable(s) from dir %s", len(merged_vars), tf_dir)
    resolved = _substitute_value(tf_dict, merged_vars)
    return resolved if isinstance(resolved, dict) else tf_dict


def extract_tf_resources(tf_content: str) -> dict[str, dict[str, Any]]:
    """Extract resource blocks from HCL Terraform content.

    Returns a flat dict: resource_type.resource_name -> attributes dict.

    Args:
        tf_content: Raw Terraform HCL content as a string.

    Returns:
        Dict mapping resource identifiers to their attribute dicts.
    """
    resources: dict[str, dict[str, Any]] = {}
    lines = tf_content.splitlines()
    i = 0

    while i < len(lines):
        line = lines[i].strip()
        match = re.match(r'^resource\s+"([^"]+)"\s+"([^"]+)"\s*\{', line)
        if match:
            resource_type = match.group(1)
            resource_name = match.group(2)
            resource_key = "{}.{}".format(resource_type, resource_name)
            attrs: dict[str, Any] = {}
            depth = 1
            i += 1

            while i < len(lines) and depth > 0:
                inner = lines[i].strip()
                depth += inner.count("{") - inner.count("}")
                if depth > 0 and "=" in inner and not inner.startswith("#"):
                    k, _, v = inner.partition("=")
                    k = k.strip()
                    v = v.strip().rstrip(",").strip('"\'')
                    if re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', k):
                        if v.lower() in ("true", "false"):
                            attrs[k] = v.lower() == "true"
                        elif re.match(r'^-?\d+(\.\d+)?$', v):
                            attrs[k] = float(v) if "." in v else int(v)
                        else:
                            attrs[k] = v
                i += 1

            resources[resource_key] = attrs
            continue

        i += 1

    return resources

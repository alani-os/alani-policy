#!/usr/bin/env python3
"""Validate policy JSON examples against the local policy schema metadata."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas" / "policy-bundle.schema.json"
EXAMPLE_DIR = ROOT / "examples"
LABEL_RE = re.compile(r"^[A-Za-z0-9:_*.\-/@_]+$")
MAX_LABEL_LEN = 128


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def require_object(value: Any, path: str, errors: list[str]) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        errors.append(f"{path}: expected object")
        return None
    return value


def validate_label(value: Any, path: str, errors: list[str]) -> None:
    if not isinstance(value, str) or not value:
        errors.append(f"{path}: expected non-empty string")
        return
    if len(value) > MAX_LABEL_LEN:
        errors.append(f"{path}: label too long")
    if not LABEL_RE.fullmatch(value):
        errors.append(f"{path}: invalid label characters")


def validate_u64(value: Any, path: str, errors: list[str], minimum: int = 0) -> None:
    if not isinstance(value, int) or isinstance(value, bool):
        errors.append(f"{path}: expected integer")
        return
    if value < minimum:
        errors.append(f"{path}: value below {minimum}")


def validate_bool(value: Any, path: str, errors: list[str]) -> None:
    if not isinstance(value, bool):
        errors.append(f"{path}: expected boolean")


def validate_enum(
    value: Any, path: str, allowed: set[str], errors: list[str], *, required: bool = True
) -> None:
    if value is None and not required:
        return
    if not isinstance(value, str) or value not in allowed:
        errors.append(f"{path}: unsupported value {value!r}")


def validate_capabilities(
    values: Any, path: str, capabilities: set[str], errors: list[str]
) -> None:
    if not isinstance(values, list):
        errors.append(f"{path}: expected list")
        return
    seen: set[str] = set()
    for index, value in enumerate(values):
        item_path = f"{path}[{index}]"
        validate_enum(value, item_path, capabilities, errors)
        if isinstance(value, str):
            if value in seen:
                errors.append(f"{item_path}: duplicate capability")
            seen.add(value)


def validate_budget(value: Any, path: str, errors: list[str]) -> None:
    if value is None:
        return
    budget = require_object(value, path, errors)
    if budget is None:
        return
    allowed_keys = {"max_compute_units", "max_memory_bytes", "deadline_ns"}
    for key in budget:
        if key not in allowed_keys:
            errors.append(f"{path}.{key}: unexpected field")
    for key in allowed_keys:
        if key in budget:
            validate_u64(budget[key], f"{path}.{key}", errors)
    if (
        budget.get("deadline_ns", 0) != 0
        and budget.get("max_compute_units", 0) == 0
        and budget.get("max_memory_bytes", 0) == 0
    ):
        errors.append(f"{path}: deadline requires compute or memory budget")


def validate_rule(
    rule_value: Any,
    path: str,
    metadata: dict[str, set[str]],
    seen_ids: set[int],
    errors: list[str],
) -> None:
    rule = require_object(rule_value, path, errors)
    if rule is None:
        return
    required = {
        "id",
        "label",
        "effect",
        "resource_kind",
        "resource",
        "operation",
        "required_capabilities",
        "priority",
        "audit_required",
        "enabled",
    }
    for key in required:
        if key not in rule:
            errors.append(f"{path}.{key}: missing required field")
    for key in rule:
        if key not in required | {"principal_kind", "principal_id", "max_budget"}:
            errors.append(f"{path}.{key}: unexpected field")
    validate_u64(rule.get("id"), f"{path}.id", errors, minimum=1)
    if isinstance(rule.get("id"), int):
        if rule["id"] in seen_ids:
            errors.append(f"{path}.id: duplicate rule id")
        seen_ids.add(rule["id"])
    validate_label(rule.get("label"), f"{path}.label", errors)
    validate_enum(rule.get("effect"), f"{path}.effect", metadata["effects"], errors)
    validate_enum(
        rule.get("principal_kind"),
        f"{path}.principal_kind",
        metadata["principal_kinds"],
        errors,
        required=False,
    )
    if "principal_id" in rule:
        validate_label(rule["principal_id"], f"{path}.principal_id", errors)
    validate_enum(
        rule.get("resource_kind"), f"{path}.resource_kind", metadata["resource_kinds"], errors
    )
    validate_label(rule.get("resource"), f"{path}.resource", errors)
    validate_enum(rule.get("operation"), f"{path}.operation", metadata["operations"], errors)
    validate_capabilities(
        rule.get("required_capabilities"),
        f"{path}.required_capabilities",
        metadata["capabilities"],
        errors,
    )
    validate_budget(rule.get("max_budget"), f"{path}.max_budget", errors)
    validate_u64(rule.get("priority"), f"{path}.priority", errors)
    validate_bool(rule.get("audit_required"), f"{path}.audit_required", errors)
    validate_bool(rule.get("enabled"), f"{path}.enabled", errors)
    if rule.get("enabled") is False:
        errors.append(f"{path}.enabled: checked-in examples must not include disabled rules")


def validate_sandbox_profile(
    profile_value: Any,
    path: str,
    metadata: dict[str, set[str]],
    seen_ids: set[int],
    errors: list[str],
) -> None:
    profile = require_object(profile_value, path, errors)
    if profile is None:
        return
    required = {
        "id",
        "label",
        "principal_kind",
        "allowed_resources",
        "capabilities",
        "require_trace",
        "status",
        "audit_on_violation",
    }
    for key in required:
        if key not in profile:
            errors.append(f"{path}.{key}: missing required field")
    for key in profile:
        if key not in required | {"max_budget"}:
            errors.append(f"{path}.{key}: unexpected field")
    validate_u64(profile.get("id"), f"{path}.id", errors, minimum=1)
    if isinstance(profile.get("id"), int):
        if profile["id"] in seen_ids:
            errors.append(f"{path}.id: duplicate sandbox profile id")
        seen_ids.add(profile["id"])
    validate_label(profile.get("label"), f"{path}.label", errors)
    validate_enum(
        profile.get("principal_kind"),
        f"{path}.principal_kind",
        metadata["principal_kinds"],
        errors,
    )
    validate_capabilities(
        profile.get("capabilities"), f"{path}.capabilities", metadata["capabilities"], errors
    )
    resources = profile.get("allowed_resources")
    if not isinstance(resources, list):
        errors.append(f"{path}.allowed_resources: expected list")
    else:
        for index, resource in enumerate(resources):
            validate_enum(
                resource,
                f"{path}.allowed_resources[{index}]",
                metadata["sandbox_resources"],
                errors,
            )
        if not resources and profile.get("status") != "disabled":
            errors.append(f"{path}.allowed_resources: non-disabled profile needs resources")
    validate_budget(profile.get("max_budget"), f"{path}.max_budget", errors)
    validate_bool(profile.get("require_trace"), f"{path}.require_trace", errors)
    validate_enum(profile.get("status"), f"{path}.status", metadata["sandbox_statuses"], errors)
    validate_bool(profile.get("audit_on_violation"), f"{path}.audit_on_violation", errors)


def main() -> int:
    schema = load_json(SCHEMA_PATH)
    metadata = {
        "principal_kinds": set(schema.get("x-alani-principal-kinds", [])),
        "resource_kinds": set(schema.get("x-alani-resource-kinds", [])),
        "operations": set(schema.get("x-alani-operations", [])),
        "effects": set(schema.get("x-alani-effects", [])),
        "capabilities": set(schema.get("x-alani-capabilities", [])),
        "sandbox_resources": set(schema.get("x-alani-sandbox-resources", [])),
        "sandbox_statuses": set(schema.get("x-alani-sandbox-statuses", [])),
    }
    if schema.get("x-alani-schema-version") != "alani.policy.v1":
        print("invalid policy schema metadata", file=sys.stderr)
        return 1
    if any(not values for values in metadata.values()):
        print("policy schema metadata is incomplete", file=sys.stderr)
        return 1

    examples = sorted(EXAMPLE_DIR.glob("*.json"))
    if not examples:
        print("no policy JSON examples found", file=sys.stderr)
        return 1

    errors: list[str] = []
    for example in examples:
        bundle = require_object(load_json(example), example.name, errors)
        if bundle is None:
            continue
        for key in ("schema_version", "bundle", "generation", "rules", "sandbox_profiles"):
            if key not in bundle:
                errors.append(f"{example.name}.{key}: missing required field")
        if bundle.get("schema_version") != "alani.policy.v1":
            errors.append(f"{example.name}.schema_version: expected 'alani.policy.v1'")
        validate_label(bundle.get("bundle"), f"{example.name}.bundle", errors)
        validate_u64(bundle.get("generation"), f"{example.name}.generation", errors, minimum=1)

        rules = bundle.get("rules")
        if not isinstance(rules, list) or not rules:
            errors.append(f"{example.name}.rules: expected non-empty list")
        else:
            seen_rule_ids: set[int] = set()
            for index, rule in enumerate(rules):
                validate_rule(rule, f"{example.name}.rules[{index}]", metadata, seen_rule_ids, errors)

        sandbox_profiles = bundle.get("sandbox_profiles")
        if not isinstance(sandbox_profiles, list):
            errors.append(f"{example.name}.sandbox_profiles: expected list")
        else:
            seen_profile_ids: set[int] = set()
            for index, profile in enumerate(sandbox_profiles):
                validate_sandbox_profile(
                    profile,
                    f"{example.name}.sandbox_profiles[{index}]",
                    metadata,
                    seen_profile_ids,
                    errors,
                )

    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1

    print(f"validated {len(examples)} policy example(s) against {SCHEMA_PATH.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

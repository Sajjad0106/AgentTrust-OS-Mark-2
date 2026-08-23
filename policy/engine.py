from policy.loader import get_policies
from typing import Any
import json
from datetime import datetime, timezone


def _normalize_value(value: Any) -> str:
    """
    Normalize a value for comparison.
    Handles type coercion (e.g., treats 10 and "10" as equal).
    """
    if value is None:
        return "null"

    if isinstance(value, bool):
        return str(value).lower()

    if isinstance(value, (int, float)):
        return str(value)

    if isinstance(value, str):
        return value.lower().strip()

    if isinstance(value, (list, dict)):
        # Sort keys and normalize for consistent comparison
        try:
            return json.dumps(value, sort_keys=True, ensure_ascii=True).lower()
        except Exception:
            return str(value).lower()

    return str(value).lower()


def _matches_value(condition_value: Any, actual_value: Any) -> bool:
    """
    Compare condition value against actual value with type coercion.
    """
    cond_norm = _normalize_value(condition_value)
    actual_norm = _normalize_value(actual_value)
    return cond_norm == actual_norm


def _matches_value_contains(condition_value: Any, actual_value: Any) -> bool:
    """
    Check if condition value is contained in actual value (with type coercion).
    """
    cond_norm = _normalize_value(condition_value)
    actual_norm = _normalize_value(actual_value)
    return cond_norm in actual_norm


def _recursive_dict_compare(condition: dict, actual: dict, path: str = "") -> bool:
    """
    Recursively compare condition dict against actual dict.
    Handles nested paths (e.g., user.profile.id matching nested structures).
    """
    for key, cond_value in condition.items():
        current_path = f"{path}.{key}" if path else key

        if key not in actual:
            # Key not present - no match
            return False

        actual_value = actual[key]

        if isinstance(cond_value, dict) and isinstance(actual_value, dict):
            # Recurse into nested dict
            if not _recursive_dict_compare(cond_value, actual_value, current_path):
                return False
        elif isinstance(cond_value, list) and isinstance(actual_value, list):
            # Check if any item in condition list matches any item in actual list
            cond_set = {_normalize_value(v) for v in cond_value}
            actual_set = {_normalize_value(v) for v in actual_value}
            if not cond_set.intersection(actual_set):
                return False
        else:
            # Direct comparison with type coercion
            if not _matches_value(cond_value, actual_value):
                return False

    return True


def _check_parameters_match(condition: dict, parameters: dict) -> bool:
    """
    Check if parameters match condition using structured comparison.
    Handles nested paths and type coercion.
    """
    # Check exact value matches
    if "value_equals" in condition:
        value = condition["value_equals"]
        # Support nested path (e.g., "user.id" or "params.config.enabled")
        if isinstance(value, str) and "." in value:
            # Nested path lookup
            keys = value.split(".")
            val = parameters
            for key in keys:
                if isinstance(val, dict) and key in val:
                    val = val[key]
                else:
                    return False
            return _matches_value(condition.get("value_equals"), val)
        return _matches_value(condition.get("value_equals"), parameters)

    # Check value contains (substring match with type coercion)
    if "value_contains" in condition:
        for contain_val in condition["value_contains"]:
            if isinstance(parameters, dict):
                # Check all values in the parameters dict
                for param_val in parameters.values():
                    if _matches_value_contains(contain_val, param_val):
                        return True
            elif isinstance(parameters, str):
                if _matches_value_contains(contain_val, parameters):
                    return True
            elif isinstance(parameters, (list, dict)):
                # Check if any value in the structure contains the pattern
                params_str = _normalize_value(parameters)
                if _matches_value_contains(contain_val, params_str):
                    return True
        return False

    # Check value starts with
    if "value_starts_with" in condition:
        prefix = _normalize_value(condition["value_starts_with"])
        actual_norm = _normalize_value(parameters)
        return actual_norm.startswith(prefix)

    # Check value ends with
    if "value_ends_with" in condition:
        suffix = _normalize_value(condition["value_ends_with"])
        actual_norm = _normalize_value(parameters)
        return actual_norm.endswith(suffix)

    return False


def evaluate_policies(
    agent_id     : str,
    tool         : str,
    parameters   : dict[str, Any],
    trust_score  : float = 100.0,
    blast_level  : str   = "LOW",
    intent_gap   : int   = 0,
    is_sandboxed : bool  = False
) -> dict[str, Any]:
    """
    Evaluate policies using structured dictionary comparison.
    Handles type coercion and nested paths for robust matching.
    """

    policies: list[dict[str, Any]] = get_policies()
    tool_lower: str = tool.lower()
    violations: list[dict[str, Any]] = []

    for policy in policies:
        condition: dict[str, Any] = policy.get("condition", {})
        if not condition:
            continue

        # AND semantics: every key present in the condition must match
        # (a tool hit alone must not satisfy a policy that also requires
        # e.g. a specific blast level).
        checks: list[bool] = []

        # ── Sandboxed agent check ───
        if "agent_state" in condition:
            checks.append(is_sandboxed and "sandboxed" in condition["agent_state"])

        # ── Trust score threshold ───
        if "trust_score_below" in condition:
            checks.append(trust_score < condition["trust_score_below"])

        # ── Blast radius level ───
        if "blast_level_matches" in condition:
            checks.append(blast_level in condition["blast_level_matches"])

        # ── Intent gap threshold ───
        if "intent_gap_above" in condition:
            checks.append(intent_gap > condition["intent_gap_above"])

        # ── Tool + value matching with structured comparison ───
        if "tool_matches" in condition:
            tool_list: list[str] = condition.get("tool_matches", [])
            tool_hit: bool = tool_lower in [t.lower() for t in tool_list]
            if not tool_hit:
                checks.append(False)
            elif any(k in condition for k in ("value_contains", "value_equals", "value_starts_with", "value_ends_with")):
                checks.append(_check_parameters_match(condition, parameters))
            else:
                checks.append(True)

        # ── Nested-dict conditions: recursive comparison ───
        for cond_key, cond_val in condition.items():
            if isinstance(cond_val, dict):
                checks.append(
                    _recursive_dict_compare(cond_val, parameters, cond_key)
                    if isinstance(parameters, dict) else False
                )

        # ── Value-only / unknown condition shapes: structured comparison ───
        if not checks:
            checks.append(_check_parameters_match(condition, parameters))

        matched = all(checks)

        if matched:
            violations.append({
                "policy"      : policy["name"],
                "action"      : policy["action"],
                "severity"    : policy["severity"],
                "source"      : policy.get("_source", "unknown"),
                "matched_at"  : datetime.now(timezone.utc).isoformat(),
                "condition"   : condition,
            })

    # ── Determine final action from violations ───
    if any(v["action"] == "BLOCK" for v in violations):
        final_action = "BLOCK"
    elif any(v["action"] == "FLAG" for v in violations):
        final_action = "FLAG"
    else:
        final_action = "ALLOW"

    return {
        "final_action": final_action,
        "violations"  : violations,
        "policy_count": len(violations)
    }

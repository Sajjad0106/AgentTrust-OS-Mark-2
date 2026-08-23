import yaml
import os
from typing import Any, List

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
POLICY_DIR = os.path.join(BASE_DIR, "policies")
_policies: list[dict[str, Any]] = []


def load_policies() -> List[dict[str, Any]]:
    global _policies
    _policies = []

    for filename in os.listdir(POLICY_DIR):
        if not filename.endswith(".yaml"):
            continue
        path = os.path.join(POLICY_DIR, filename)
        with open(path, "r") as f:
            data = yaml.safe_load(f)
            if data and "policies" in data:
                for p in data["policies"]:
                    p["_source"] = filename
                    _policies.append(p)

    print(f"[PolicyLoader] Loaded {len(_policies)} policies from {POLICY_DIR}")
    return _policies


def get_policies() -> List[dict[str, Any]]:
    if not _policies:
        load_policies()
    return _policies
"""
AgentTrust OS — Honeypot Engine

Decoy assets planted where a malicious agent would look.
ANY access to a honeypot asset is by definition malicious — a legitimate
agent following its declared intent never needs them. Access = confirmed
threat (PDF demo: "Honeypot file is accessed" → "Threat generated").
"""

from datetime import datetime, timezone
from typing import Any

# ─────────────────────────────────────────────────────────────
# Honeypot Asset Registry
# Decoy files/credentials that look valuable but are traps.
# ─────────────────────────────────────────────────────────────

HONEYPOT_ASSETS: list[dict[str, Any]] = [
    {
        "id"          : "hp-payroll-001",
        "path"        : "/opt/finance/payroll_export_2025.csv",
        "type"        : "decoy_file",
        "sensitivity" : "CRITICAL",
        "description" : "Decoy full payroll export — planted finance honeypot",
    },
    {
        "id"          : "hp-payroll-002",
        "path"        : "/var/backup/employee_salaries_dump.sql",
        "type"        : "decoy_backup",
        "sensitivity" : "CRITICAL",
        "description" : "Decoy salary database backup — data-theft honeypot",
    },
    {
        "id"          : "hp-creds-003",
        "path"        : "/etc/agenttrust/decoy_credentials.env",
        "type"        : "decoy_credentials",
        "sensitivity" : "CRITICAL",
        "description" : "Decoy service credentials file — credential-theft honeypot",
    },
    {
        "id"          : "hp-key-004",
        "path"        : "/root/.ssh/id_rsa_agent",
        "type"        : "decoy_key",
        "sensitivity" : "HIGH",
        "description" : "Decoy SSH private key — lateral-movement honeypot",
    },
]

# ─────────────────────────────────────────────────────────────
# Detection
# ─────────────────────────────────────────────────────────────

# Detection log: every honeypot interaction, for the dashboard & audit trail
DETECTION_LOG: list[dict[str, Any]] = []


def _stringify(obj: Any) -> str:
    if isinstance(obj, str):
        return obj
    import json
    try:
        return json.dumps(obj)
    except Exception:
        return str(obj)


def check_honeypot_access(tool: str, parameters: dict[str, Any]) -> dict[str, Any]:
    """
    Check whether a tool call touches any honeypot asset.
    Returns:
      {
        "hit"    : bool,
        "asset"  : dict | None,   # the honeypot asset that was touched
        "reason" : str,
      }
    """
    text = (tool + " " + _stringify(parameters)).lower()

    for asset in HONEYPOT_ASSETS:
        needle = asset["path"].lower()
        # Also match a "bare" tail (e.g. "payroll_export_2025.csv") so that
        # path-normalised variants of the same decoy are caught.
        bare = needle.rsplit("/", 1)[-1]
        if needle in text or (len(bare) > 8 and bare in text):
            detection = {
                "hit"           : True,
                "asset"         : asset,
                "tool"          : tool,
                "parameters"    : parameters,
                "reason"        : (
                    f"HONEYPOT BREACH: agent accessed planted decoy asset "
                    f"'{asset['path']}' ({asset['description']}) — "
                    f"legitimate agents never access honeypots. Threat confirmed."
                ),
                "detected_at"   : datetime.now(timezone.utc).isoformat(),
            }
            DETECTION_LOG.append(detection)
            return detection

    return {"hit": False, "asset": None, "reason": ""}


def get_honeypot_assets() -> list[dict[str, Any]]:
    return list(HONEYPOT_ASSETS)


def get_detections(limit: int = 50) -> list[dict[str, Any]]:
    return DETECTION_LOG[-limit:]

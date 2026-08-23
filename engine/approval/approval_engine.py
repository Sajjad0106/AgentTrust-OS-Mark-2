"""
AgentTrust OS — Approval Workflow Engine

Human-in-the-loop approval for blocked high-risk actions.
When the Prevention Engine blocks a CRITICAL action and isolates an agent,
an approval request is created. A human can then:
  • APPROVE → the agent is released from isolation and may resume, or
  • REJECT  → the block stands; isolation continues.
"""

import itertools
from datetime import datetime, timezone
from typing import Any

_approval_ids = itertools.count(1)
APPROVALS: list[dict[str, Any]] = []


def create_approval(
    agent_id     : str,
    tool         : str,
    parameters   : dict[str, Any],
    reason       : str,
    decision_ref : dict[str, Any] | None = None
) -> dict[str, Any]:
    approval = {
        "id"           : f"APR-{next(_approval_ids):04d}",
        "agent_id"     : agent_id,
        "tool"         : tool,
        "parameters"   : parameters,
        "reason"       : reason,
        "status"       : "PENDING",
        "created_at"   : datetime.now(timezone.utc).isoformat(),
        "decided_at"   : None,
        "decided_by"   : None,
        "decision_ref" : decision_ref or {},
    }
    APPROVALS.append(approval)
    return approval


def _find(approval_id: str) -> dict[str, Any] | None:
    return next((a for a in APPROVALS if a["id"] == approval_id), None)


def approve(approval_id: str, decided_by: str = "human-reviewer") -> dict[str, Any]:
    approval = _find(approval_id)
    if not approval:
        return {"status": "error", "error": f"Approval '{approval_id}' not found"}
    approval["status"]     = "APPROVED"
    approval["decided_at"] = datetime.now(timezone.utc).isoformat()
    approval["decided_by"] = decided_by
    return approval


def reject(approval_id: str, decided_by: str = "human-reviewer") -> dict[str, Any]:
    approval = _find(approval_id)
    if not approval:
        return {"status": "error", "error": f"Approval '{approval_id}' not found"}
    approval["status"]     = "REJECTED"
    approval["decided_at"] = datetime.now(timezone.utc).isoformat()
    approval["decided_by"] = decided_by
    return approval


def get_approvals(limit: int = 100) -> list[dict[str, Any]]:
    return APPROVALS[-limit:]


def get_pending_approvals() -> list[dict[str, Any]]:
    return [a for a in APPROVALS if a["status"] == "PENDING"]

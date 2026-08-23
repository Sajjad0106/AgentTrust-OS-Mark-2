import json as _json
from engine.blast_radius.blast_engine import calculate_blast_radius
from engine.trust_score.trust_engine import get_or_create_profile
from infrastructure.database import register_agent_db, get_agent_db
from datetime import datetime, timezone
from typing import Any, List, Optional

AGENT_REGISTRY: dict[str, dict[str, Any]] = {}

# ── Agent Isolation State ─────────────────────────────────────────────────────
# Isolated agents are quarantined: every tool call is rejected until a human
# releases them (or an approval request is granted).
ISOLATED_AGENTS: dict[str, dict[str, Any]] = {}


def isolate_agent(agent_id: str, reason: str) -> dict[str, Any]:
    """Isolate an agent (quarantine). Idempotent — re-isolation updates the reason."""
    if agent_id not in ISOLATED_AGENTS:
        ISOLATED_AGENTS[agent_id] = {
            "agent_id"       : agent_id,
            "isolated"       : True,
            "reason"         : reason,
            "isolated_at"    : datetime.now(timezone.utc).isoformat(),
            "released_at"    : None,
        }
        entry = AGENT_REGISTRY.get(agent_id, {})
        entry["is_isolated"] = True
        entry["isolation_reason"] = reason
    return ISOLATED_AGENTS[agent_id]


def release_agent(agent_id: str) -> dict[str, str]:
    """Release a previously isolated agent (manual or via granted approval)."""
    info = ISOLATED_AGENTS.pop(agent_id, None)
    entry = AGENT_REGISTRY.get(agent_id, {})
    entry["is_isolated"] = False
    entry.pop("isolation_reason", None)
    return {
        "status"     : "released" if info else "not_isolated",
        "agent_id"   : agent_id,
        "was_isolated": info is not None,
    }


def is_isolated(agent_id: str) -> bool:
    return agent_id in ISOLATED_AGENTS


def get_isolated_agents() -> list[dict[str, Any]]:
    return list(ISOLATED_AGENTS.values())


def register_agent(
    agent_id            : str,
    name                : str,
    declared_intent     : str,
    declared_permissions: List[str],
    downstream_agents   : Optional[List[str]] = None
) -> dict[str, Any]:

    downstream_agents = downstream_agents or []
    blast  = calculate_blast_radius(agent_id, declared_permissions, downstream_agents)
    trust  = get_or_create_profile(agent_id)

    entry: dict[str, Any] = {
        "agent_id"            : agent_id,
        "name"                : name,
        "declared_intent"     : declared_intent,
        "declared_permissions": declared_permissions,
        "downstream_agents"   : downstream_agents,
        "blast_score"         : blast.blast_score,
        "blast_level"         : blast.blast_level,
        "blast_reason"        : blast.reason,
        "trust_score"         : trust.trust_score,
        "registered_at"       : datetime.now(timezone.utc).isoformat()
    }

    # Persist to the agents table — required for token FK + restart survival
    try:
        register_agent_db(
            agent_id             = agent_id,
            name                 = name,
            declared_intent      = declared_intent,
            declared_permissions = declared_permissions,
            downstream_agents    = downstream_agents,
            blast_score          = blast.blast_score,
            blast_level          = blast.blast_level,
            blast_reason         = blast.reason,
            trust_score          = trust.trust_score,
        )
    except Exception as e:
        print(f"[Registry] Warning: DB persistence failed: {e}")

    AGENT_REGISTRY[agent_id] = entry
    return entry


def get_agent(agent_id: str) -> dict[str, Any]:
    if agent_id in AGENT_REGISTRY:
        return AGENT_REGISTRY[agent_id]
    # Fall back to the persistent store (survives restarts)
    row = get_agent_db(agent_id)
    if row:
        entry = dict(row)
        for field in ("declared_permissions", "downstream_agents"):
            if isinstance(entry.get(field), str):
                try:
                    entry[field] = _json.loads(entry[field])
                except Exception:
                    pass
        entry.setdefault("declared_intent", "")
        AGENT_REGISTRY[agent_id] = entry
        return entry
    return {}


def get_all_agents() -> list[dict[str, Any]]:
    return list(AGENT_REGISTRY.values())


def is_registered(agent_id: str) -> bool:
    return agent_id in AGENT_REGISTRY
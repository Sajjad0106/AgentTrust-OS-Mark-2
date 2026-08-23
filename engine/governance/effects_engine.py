"""
AgentTrust OS — Downstream Effects Engine (Concept 3 of 3: EFFECTS)

A live, computed view answering: "What happens IF this action runs — which
entities consume the agent's output, how are they affected, and what does
the system itself record?"

Design contract (see PHASE3_Downstream_Effects_Plan.md):

  • DERIVED, NEVER STORED — the only stored input is the agent's RECORDED
    CONTEXT (`agents.downstream_agents`, declared at registration). Consumer
    state is read live (in-memory trust store → durable trust row → fresh-
    agent default), always read-only (no profiles are created as a side
    effect of inspection).

  • READ-ONLY — effects describe consequences; they never mutate state.

  • ONE ADVISORY (D3, stricter-only): a NON-BLOCKED call whose declared
    downstream consumer is QUARANTINED (isolated) carries a human-review
    reason — from ALLOWED it is escalated to FLAGGED; on an already-FLAGGED
    call the reason joins the existing review. Feeding a quarantined agent
    is a lateral-movement red flag. It never BLOCKs, never de-escalates,
    and never touches trust.

  • HONESTY (D4) — no rows are invented: undeclared consumers produce no
    rows; a declared-but-unregistered consumer produces an UNKNOWN row;
    self-references are excluded; any source failure yields UNKNOWN /
    "degraded" — never raises.

  • HOT-PATH SAFE — in-memory reads plus small PK SELECTs, sub-millisecond,
    exception-safe (degrades to {"status": "degraded"}).
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from typing import Any, Optional

from infrastructure import database as db
from registry import agent_registry as registry
from engine.trust_score import trust_engine as te
from engine.governance.governance_engine import _policy_trust_floor


_TTL_SECONDS = 1.0
_cache: dict[str, tuple[float, dict[str, Any]]] = {}
_cache_lock = threading.Lock()


def _parse_list(raw: Any) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, list):
        return [str(x) for x in raw if isinstance(x, (str, int)) and str(x).strip()]
    if isinstance(raw, str):
        try:
            data = json.loads(raw)
        except Exception:
            return []
        if isinstance(data, list):
            return [str(x) for x in data if isinstance(x, (str, int)) and str(x).strip()]
    return []


def _declared_consumers(agent_id: str) -> list[str]:
    """Recorded context: downstream agents declared at registration (durable)."""
    try:
        row = db.get_agent_db(agent_id)
    except Exception:
        return []
    if not row:
        return []
    consumers = _parse_list(row.get("downstream_agents"))
    # Self-references are meaningless (and could loop the narrative) — drop.
    return [c for c in dict.fromkeys(consumers) if c != agent_id]


def _consumer_state(consumer_id: str) -> dict[str, Any]:
    """Read-only live state of one consumer.

    Order: in-memory trust store (true live source during uptime) → durable
    trust row → fresh-agent default. Never creates a profile.
    """
    try:
        profile = te.TRUST_STORE.get(consumer_id)
        if profile is not None:
            return {
                "trust_score": round(float(profile.trust_score), 2),
                "containment_level": profile.containment_level or "NONE",
            }
        row = db.get_trust_profile_db(consumer_id)
        if row:
            return {
                "trust_score": round(float(row.get("trust_score", 100.0)), 2),
                "containment_level": row.get("containment_level") or "NONE",
            }
    except Exception:
        pass
    return {"trust_score": 100.0, "containment_level": "NONE"}


def _is_registered(agent_id: str) -> bool:
    try:
        return db.get_agent_db(agent_id) is not None
    except Exception:
        return False


def _classify(consumer_id: str, state: dict[str, Any]) -> tuple[str, str]:
    """Impact class + note for one consumer (D2/D4)."""
    try:
        isolated = registry.is_isolated(consumer_id)
    except Exception:
        isolated = False
    containment = str(state.get("containment_level", "NONE")).upper()
    score = float(state.get("trust_score", 100.0))

    if isolated:
        return "QUARANTINED", (
            "consumer is isolated (quarantined) — it cannot consume output, "
            "and feeding a quarantined agent is a lateral-movement red flag"
        )
    if containment in ("SANDBOX", "ISOLATE") or score < _policy_trust_floor():
        return "DEGRADED", (
            f"consumer operates under containment ({containment}, trust {score:g}) "
            f"— will consume output under reduced capability"
        )
    if containment == "RESTRICT":
        return "DEGRADED", f"consumer is restricted (trust {score:g}) — degraded consumption"
    return "HEALTHY", "will consume output normally"


def _status_of(consumers: list[dict[str, Any]]) -> str:
    if not consumers:
        return "NO_CONSUMERS"
    classes = {c["impact_class"] for c in consumers}
    if "QUARANTINED" in classes:
        return "QUARANTINED"
    if "DEGRADED" in classes or "UNKNOWN" in classes:
        return "DEGRADED"
    return "HEALTHY_CHAIN"


def compute_effects(agent_id: str, use_cache: bool = True) -> dict[str, Any]:
    """Agent-level downstream effects view. Never raises (degrades instead)."""
    if use_cache:
        with _cache_lock:
            hit = _cache.get(agent_id)
            if hit and (datetime.now(timezone.utc).timestamp() - hit[0]) < _TTL_SECONDS:
                return hit[1]

    out: dict[str, Any] = {
        "agent_id": agent_id,
        "status": "NO_CONSUMERS",
        "consumers": [],
        "systemic": [
            {"type": "audit_trail",
             "note": "every action is hash-chained into the audit log — downstream accountability is verifiable"},
        ],
        "computed_at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        consumers: list[dict[str, Any]] = []
        for cid in _declared_consumers(agent_id):
            registered = _is_registered(cid)
            state = _consumer_state(cid) if registered else None
            if not registered:
                consumers.append({
                    "id": cid,
                    "registered": False,
                    "trust_score": None,
                    "containment_level": None,
                    "isolated": False,
                    "impact_class": "UNKNOWN",
                    "note": "declared downstream consumer is not registered — effects cannot be verified",
                })
                continue
            try:
                isolated = registry.is_isolated(cid)
            except Exception:
                isolated = False
            cls, note = _classify(cid, state)
            consumers.append({
                "id": cid,
                "registered": True,
                "trust_score": state["trust_score"],
                "containment_level": state["containment_level"],
                "isolated": isolated,
                "impact_class": cls,
                "note": note,
            })
        out["consumers"] = consumers
        out["status"] = _status_of(consumers)
    except Exception as e:  # never break callers — see module contract
        out["status"] = "degraded"
        out["consumers"] = []
        out["reason"] = f"effects computation error (non-fatal): {e}"

    with _cache_lock:
        _cache[agent_id] = (datetime.now(timezone.utc).timestamp(), out)
    return out


def compute_call_effects(
    agent_id: str,
    tool: str,
    params: Optional[dict[str, Any]],
    action: str,
    trust_score: Optional[float] = None,
    correlated_agents: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Per-call effects snapshot for the decision payload.

    Combines the agent-level consumer table with action-specific impact,
    systemic effects, and the D3 advisory. Never raises.

    ALWAYS FRESH (cache bypassed): the advisory can drive a decision
    escalation, so — like the Phase-2 isolation guard — it must never
    answer from a pre-action snapshot (an operator's isolate/release can
    land between two calls).
    """
    out = compute_effects(agent_id, use_cache=False)
    if out.get("status") == "degraded":
        return out

    out = dict(out)  # shallow copy: never mutate the cached agent-level view
    out["tool"] = tool
    out["action"] = action
    consumers = out.get("consumers", [])

    # ── Action-specific impact ──────────────────────────────────────────
    quarantined = [c["id"] for c in consumers if c["impact_class"] == "QUARANTINED"]
    if action in ("ALLOWED", "FLAGGED"):
        if consumers:
            out["impact"] = (
                f"output of '{tool}' will flow to {len(consumers)} declared "
                f"consumer(s): {', '.join(c['id'] for c in consumers)}"
            )
        else:
            out["impact"] = f"no declared downstream consumers — effect stays with agent and audit trail"
    else:  # BLOCKED / ISOLATED
        if consumers:
            out["impact"] = (
                f"call denied — {len(consumers)} declared consumer(s) "
                f"({', '.join(c['id'] for c in consumers)}) will NOT receive this output (starved)"
            )
        else:
            out["impact"] = "call denied — no downstream consumers affected"
        if trust_score is not None:
            out["impact"] += f"; agent trust is now {trust_score:g}/100 (feedback loop)"

    # ── Systemic rows (beyond the always-on audit row) ──────────────────
    systemic = list(out.get("systemic", []))
    if action in ("BLOCKED", "ISOLATED") and trust_score is not None:
        systemic.append({
            "type": "trust_feedback",
            "note": f"denied action feeds the trust engine — agent trust is {trust_score:g}/100",
        })
    if correlated_agents:
        systemic.append({
            "type": "threat_correlation",
            "note": f"cross-agent correlation active for: {', '.join(correlated_agents)}",
            "agents": list(correlated_agents),
        })
    out["systemic"] = systemic

    # ── D3 advisory: non-blocked call + quarantined consumer → review ──
    # The proxy decides the escalation (ALLOWED → FLAGGED); on an already
    # FLAGGED call the reason simply joins the existing review context.
    advisory: list[str] = []
    if action in ("ALLOWED", "FLAGGED") and quarantined:
        for cid in quarantined:
            advisory.append(
                f"downstream consumer '{cid}' is QUARANTINED (isolated) — "
                f"flowing data into a quarantined agent requires human review"
            )
    out["advisory"] = advisory
    return out

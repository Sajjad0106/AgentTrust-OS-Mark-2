"""
AgentTrust OS — Blocker Engine (Concept 2 of 3: BLOCKERS)

A live, computed view answering: "Why can't agent X act RIGHT NOW — and how
do I fix it?"

Design contract (see PHASE2_Blockers_Plan.md):

  • DERIVED, NEVER STORED — blockers are a pure function of the live state of
    the engines that actually enforce them (isolation registry, token store,
    trust engine + policy floor, approval engine, Phase-1 prerequisite
    profile). Storing them would create a second source of truth that can lie;
    deriving them means the view can never be stale.

  • READ-ONLY — a blocker is only clearable by performing the real underlying
    action (release the agent, approve the request, reissue the token, let
    trust recover). There is deliberately no "override" or "dismiss" path.

  • SEVERITY MODEL —
      hard  = the condition is actively causing interceptions to deny right
              now (isolation, invalid token, trust below the policy floor,
              sandbox containment)
      soft  = advisory / degradation (restricted containment, awaiting human
              approval, standing custom gates)
    status  = BLOCKED (any hard) / DEGRADED (soft only) / CLEAR (none)

  • DEDUP — one root cause = one row. Trust-derived blockers come from the
    trust engine alone; a failed PR-TRUST prerequisite cross-references
    BLK-TRUST-FLOOR instead of producing a second row.

  • HOT-PATH SAFE — in-memory reads plus one small PK/agent SELECT
    (token state), sub-millisecond, and NEVER raises: any internal error
    degrades to {"status": "degraded"} so the 7-layer pipeline and the
    dashboard are never affected.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Any, Optional

# ── Sources of truth (single-sourced, never re-implemented) ─────────────────
from infrastructure import database as db
from registry import agent_registry as registry
from engine.trust_score.trust_engine import get_trust_summary
from engine.approval import approval_engine
from policy.loader import get_policies
from engine.governance.governance_engine import (
    get_profile,
    evaluate_prerequisites,
    _policy_trust_floor,
)


# Small TTL cache: the agent drawer can fire several fetches in a row and
# WS-driven refreshes can hammer the view; the underlying state only changes
# on explicit events, so 1 s of staleness is invisible and safe.
_TTL_SECONDS = 1.0
_cache: dict[str, tuple[float, dict[str, Any]]] = {}
_cache_lock = threading.Lock()


def _policy_floor() -> float:
    """Trust floor from the policy YAML — same source Phase 1 uses."""
    return _policy_trust_floor()


def _is_known_agent(agent_id: str) -> bool:
    """Durable check: the agent exists in the persistent store."""
    try:
        return db.get_agent_db(agent_id) is not None
    except Exception:
        # If the DB is unavailable we cannot prove the agent is real — treat
        # as unknown (404 is the honest answer, and the hot path degrades
        # independently via the never-raises contract).
        return False


def _check_isolated(agent_id: str) -> Optional[dict[str, Any]]:
    """BLK-ISOLATED — the isolation guard rejects ALL calls (hard).

    Uses the EXACT same state the intercept guard reads (is_isolated +
    ISOLATED_AGENTS), so the view can never disagree with the guard.
    """
    try:
        if not registry.is_isolated(agent_id):
            return None
        info = next((x for x in registry.get_isolated_agents()
                     if x.get("agent_id") == agent_id), {})
    except Exception:
        return None
    return {
        "id": "BLK-ISOLATED",
        "kind": "isolation",
        "severity": "hard",
        "reason": info.get("reason") or "agent is isolated",
        "since": info.get("isolated_at"),
        "clear_hint": "A human must release the agent (or the pending approval may be granted).",
        "clear_action": {"method": "POST", "endpoint": f"/agents/release/{agent_id}"},
    }


def _check_token(agent_id: str) -> Optional[dict[str, Any]]:
    """BLK-TOKEN — no valid unrevoked token: auth layer 403s every call (hard)."""
    try:
        state = db.get_token_state_db(agent_id)
    except Exception:
        return None
    s = state.get("state", "no_token")
    if s == "valid":
        return None
    reasons = {
        "no_token": "no token on record — the agent must register to obtain one",
        "revoked": "token has been revoked",
        "expired": "token TTL lapsed",
    }
    return {
        "id": "BLK-TOKEN",
        "kind": "token",
        "severity": "hard",
        "reason": reasons.get(s, f"token state '{s}'"),
        "since": state.get("issued_at"),
        "clear_hint": "Register the agent again to issue a fresh token (old tokens are superseded).",
        "clear_action": {"method": "POST", "endpoint": "/agents/register"},
    }


def _check_trust(agent_id: str) -> list[dict[str, Any]]:
    """BLK-TRUST-FLOOR / BLK-SANDBOX / BLK-RESTRICT — trust engine state.

    Dedup rule: these are the ONLY trust-derived rows. A failed PR-TRUST
    prerequisite cross-references BLK-TRUST-FLOOR via related_prereq.
    """
    rows: list[dict[str, Any]] = []
    try:
        trust = get_trust_summary(agent_id)
    except Exception:
        return rows
    if not isinstance(trust, dict):
        return rows

    floor = _policy_floor()
    score = float(trust.get("trust_score", 100.0))
    containment = str(trust.get("containment_level", "NONE") or "NONE").upper()
    since = trust.get("containment_at")

    if bool(trust.get("is_sandboxed")):
        rows.append({
            "id": "BLK-SANDBOX",
            "kind": "containment",
            "severity": "hard",
            "reason": (f"sandboxed (trust {score:g}) — "
                       f"{trust.get('sandbox_reason') or 'trust containment'}"),
            "since": since,
            "clear_hint": ("Sandbox containment is automatic: trust must recover "
                           "above the sandbox threshold through clean behaviour. "
                           "No manual override exists by design."),
            "clear_action": None,
            "related_prereq": "PR-SANDBOX",
        })
    elif containment == "RESTRICT":
        rows.append({
            "id": "BLK-RESTRICT",
            "kind": "containment",
            "severity": "soft",
            "reason": f"restricted (trust {score:g}) — {trust.get('containment_reason') or 'degraded trust'}",
            "since": since,
            "clear_hint": "Advisory: agent is operating under reduced trust; no calls are blocked by this level alone.",
            "clear_action": None,
        })

    if score < floor:
        rows.append({
            "id": "BLK-TRUST-FLOOR",
            "kind": "trust",
            "severity": "hard",
            "reason": f"trust {score:g} is below the policy floor {floor:g} — policy 'block-after-trust-threshold' denies calls",
            "since": since,
            "clear_hint": ("Trust recovery is behavioural, not manual: consistent "
                           "clean actions raise the score back above the floor. "
                           "See GET /trust/changelog/{agent_id} for the trajectory."),
            "clear_action": None,
            "related_prereq": "PR-TRUST",
        })
    return rows


def _check_approvals(agent_id: str) -> list[dict[str, Any]]:
    """BLK-APPROVAL — awaiting human decision (soft: other calls are not blocked)."""
    rows: list[dict[str, Any]] = []
    try:
        pending = approval_engine.get_pending_approvals()
    except Exception:
        return rows
    for a in pending:
        if a.get("agent_id") != agent_id:
            continue
        rows.append({
            "id": f"BLK-APPROVAL-{a.get('id')}",
            "kind": "approval",
            "severity": "soft",
            "reason": (f"approval {a.get('id')} pending: "
                       f"'{a.get('tool')}' — {a.get('reason') or 'no reason recorded'}"),
            "since": a.get("created_at"),
            "clear_hint": "A human must approve or reject the pending approval.",
            "clear_action": {"method": "POST", "endpoint": f"/approvals/{a.get('id')}/approve"},
        })
    return rows


def _check_custom_gates(agent_id: str) -> list[dict[str, Any]]:
    """BLK-CUSTOM-GATE — standing operator prerequisites (soft at agent level).

    Custom gates are per-CALL conditions (they inspect call parameters), so at
    the agent level they are surfaced as standing gates the operator can see;
    the call-level view (compute_call_blockers) marks them hard for the
    specific call that fails them.
    """
    rows: list[dict[str, Any]] = []
    try:
        profile = get_profile(agent_id)
    except Exception:
        return rows
    for p in profile.get("prerequisites", []):
        if p.get("source") != "custom" or not p.get("enforce", True):
            continue
        check = p.get("check", {}) or {}
        ctype = check.get("type", "?")
        if ctype == "param_equals":
            desc = ", ".join(f"{k} = {v!r}" for k, v in (check.get("pairs", {}) or {}).items())
        elif ctype == "param_in":
            desc = ", ".join(f"{k} ∈ {v}" for k, v in (check.get("pairs", {}) or {}).items())
        elif ctype == "param_present":
            desc = "requires " + ", ".join(check.get("keys", []) or [])
        else:
            desc = ctype
        rows.append({
            "id": f"BLK-CUSTOM-GATE-{p['id']}",
            "kind": "custom_gate",
            "severity": "soft",
            "reason": f"standing custom gate '{p.get('label', p['id'])}' — calls must satisfy: {desc}",
            "since": p.get("added_at"),
            "clear_hint": "Satisfied by calling with compliant parameters, or remove the prerequisite via PUT /agents/{id}/governance.",
            "clear_action": None,
            "related_prereq": p["id"],
        })
    return rows


# ────────────────────────────────────────────────────────────────────────────
# Public API
# ────────────────────────────────────────────────────────────────────────────

def _status_of(blockers: list[dict[str, Any]]) -> str:
    if any(b["severity"] == "hard" for b in blockers):
        return "BLOCKED"
    if blockers:
        return "DEGRADED"
    return "CLEAR"


def _sort_blockers(blockers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    # hard first, then approvals (time-sensitive), then the rest, then custom gates
    order = {"isolation": 0, "token": 1, "trust": 2, "containment": 3,
             "approval": 4, "custom_gate": 5}
    return sorted(
        blockers,
        key=lambda b: (0 if b["severity"] == "hard" else 1,
                       order.get(b["kind"], 9)),
    )


def compute_blockers(agent_id: str, use_cache: bool = True) -> dict[str, Any]:
    """Agent-level live blocker view. Never raises (degrades instead)."""
    if use_cache:
        with _cache_lock:
            hit = _cache.get(agent_id)
            if hit and (datetime.now(timezone.utc).timestamp() - hit[0]) < _TTL_SECONDS:
                return hit[1]

    out: dict[str, Any] = {
        "agent_id": agent_id,
        "status": "CLEAR",
        "blockers": [],
        "computed_at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        if not _is_known_agent(agent_id):
            out["status"] = "UNKNOWN_AGENT"
            out["blockers"] = []
            return out

        blockers: list[dict[str, Any]] = []
        for check in (_check_isolated(agent_id), _check_token(agent_id)):
            if check:
                blockers.append(check)
        blockers.extend(_check_trust(agent_id))
        blockers.extend(_check_approvals(agent_id))
        blockers.extend(_check_custom_gates(agent_id))

        blockers = _sort_blockers(blockers)
        out["status"] = _status_of(blockers)
        out["blockers"] = blockers
    except Exception as e:  # never break callers — see module contract
        out["status"] = "degraded"
        out["blockers"] = []
        out["reason"] = f"blocker computation error (non-fatal): {e}"

    # A freshly computed view always refreshes the cache (harmless for
    # bypassers, useful for the next TTL-bound reader). Note: the isolation
    # guard path deliberately calls with use_cache=False, because an
    # operator's isolate/release action can land between two calls and the
    # guard must never answer from a pre-action snapshot.
    with _cache_lock:
        _cache[agent_id] = (datetime.now(timezone.utc).timestamp(), out)
    return out


def compute_call_blockers(
    agent_id: str,
    tool: str,
    params: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Call-level snapshot: agent-level blockers + the prerequisite failures
    that apply to THIS specific call (intent/permission/blast/custom gates).

    Used in the decision payload so the audit chain records, per call,
    exactly which conditions were active and which failed. Never raises.
    """
    out = compute_blockers(agent_id, use_cache=True)
    if out.get("status") == "degraded":
        return out

    # Call-scoped prerequisite failures — reuse Phase 1's evaluation so the
    # two views can never disagree about intent/permission/blast/custom scope.
    try:
        gov = evaluate_prerequisites(agent_id, tool, params or {})
    except Exception:
        gov = {"status": "degraded", "prerequisites": []}

    # Prerequisite kinds that are call-scoped (the rest already appear as
    # agent-level rows: PR-TOKEN→BLK-TOKEN, PR-ISOLATED→BLK-ISOLATED,
    # PR-SANDBOX→BLK-SANDBOX, PR-TRUST→BLK-TRUST-FLOOR).
    call_scoped_kinds = {"intent_scope", "permission_scope", "blast", "custom"}

    call_rows: list[dict[str, Any]] = []
    # Recover the profile to map results back to kind/enforce (cheap, cached)
    try:
        profile = {p["id"]: p for p in get_profile(agent_id).get("prerequisites", [])}
    except Exception:
        profile = {}

    for r in gov.get("prerequisites", []):
        if r.get("satisfied"):
            continue
        p = profile.get(r.get("id"), {})
        if p.get("kind") not in call_scoped_kinds:
            continue  # already represented by an agent-level row (dedup)
        call_rows.append({
            "id": f"BLK-CALL-{r.get('id')}",
            "kind": "prerequisite_call",
            "severity": "hard" if r.get("enforce") else "soft",
            "reason": f"{r.get('label', r.get('id'))}: {r.get('reason', 'unsatisfied')}",
            "since": None,
            "clear_hint": "See the prerequisite detail; the fix is call-specific (compliant tool/parameters).",
            "clear_action": None,
            "related_prereq": r.get("id"),
        })

    if call_rows:
        # Merge: agent-level rows first, then call-scoped failures.
        merged = list(out.get("blockers", [])) + call_rows
        out = dict(out)
        out["blockers"] = merged
        out["status"] = _status_of(merged)
        out["call_scoped"] = [r["id"] for r in call_rows]
    return out

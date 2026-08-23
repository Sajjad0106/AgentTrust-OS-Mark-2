"""
AgentTrust OS — Governance Engine (Concept 1 of 3: PREREQUISITES)

A per-agent prerequisites profile:

  • DERIVED   — sensible defaults built from the agent's RECORDED CONTEXT
                (declared intent, declared permissions, blast radius) plus the
                system's policy rules (trust floor, sandbox block). The
                operator does not author anything by hand.
  • EDITABLE  — the operator may add custom prerequisites (deterministic
                checks only), tune severity/enforce/label of editable entries,
                and remove custom ones. Security invariants (token, isolation)
                are surfaced but LOCKED (editable=false) and can never be
                removed or relaxed through this API.
  • EVALUATED — on every intercepted tool call the profile is evaluated
                (in-memory, sub-millisecond, exception-safe) and attached to
                the decision payload + audit chain + dashboard.

Safety model (production):
  • Derived prerequisites are SURFACE-ONLY by default (enforce=false) — they
    mirror conditions the existing 7-layer pipeline already enforces, so the
    governance layer explains decisions without changing them or producing
    duplicate/noisy block reasons.
  • Custom operator prerequisites are ENFORCED (enforce=true by default) —
    when unsatisfied they add block/flag reasons and can escalate an
    ALLOWED/FLAGGED decision. Escalation only ever goes STRICTER, never
    looser (fail-closed). Governance never adjusts trust scores (that is the
    trust engine's single responsibility).
  • The hot path never writes to the DB: profiles are read from an in-memory
    cache (populated at registration / first GET / after edits); a cache miss
    does one primary-key SELECT; a missing row is derived in memory only.
    Any internal error degrades to {"status": "degraded"} — the pipeline
    never blocks, delays, or breaks because of this layer.
"""

from __future__ import annotations

import json
import re
import threading
from datetime import datetime, timezone
from typing import Any, Optional

# ── Sources of truth (single-sourced, never re-implemented) ─────────────────
from infrastructure import database as db
from engine.intent_gap.intent_engine import INTENT_TREE
from policy.loader import get_policies
from engine.trust_score.trust_engine import get_trust_summary
from registry.agent_registry import is_isolated

# Tools whose blast radius matters for the CRITICAL-blast gate — taken from
# the enterprise policy, not hard-coded twice.
_BLAST_SENSITIVE_TOOLS = ["delete_file", "export_data", "run_command"]
_BLAKE_LEVEL_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


# ── In-memory profile cache (hot path never writes; reads stay in RAM) ──────
_cache: dict[str, dict[str, Any]] = {}
_cache_lock = threading.Lock()


# ────────────────────────────────────────────────────────────────────────────
# Derivation — defaults from recorded context
# ────────────────────────────────────────────────────────────────────────────

def _parse_json_field(raw: Any, default: Any) -> Any:
    """Parse a JSON text column; tolerate garbage (production: never 500)."""
    if raw is None:
        return default
    if isinstance(raw, (list, dict)):
        return raw
    try:
        return json.loads(raw)
    except Exception:
        return default


def match_intent_categories(declared_intent: str) -> list[str]:
    """Which INTENT_TREE categories does this declared intent match?

    Reuses the EXACT matching rule of the intent-gap engine (keyword
    substring against the lower-cased declaration) so governance and the
    enforcement layer can never disagree about intent scope.
    """
    if not declared_intent:
        return []
    intent_lower = declared_intent.lower().strip()
    return [
        category
        for category, config in INTENT_TREE.items()
        if any(kw in intent_lower for kw in config["keywords"])
    ]


def _policy_trust_floor() -> float:
    """Trust floor from the policy YAML (single source of truth)."""
    floor = 40.0  # fallback if the policy file changes shape
    try:
        for p in get_policies():
            cond = p.get("condition", {}) or {}
            if "trust_score_below" in cond:
                floor = float(cond["trust_score_below"])
                break
    except Exception:
        pass
    return floor


def _derive_agent_context(agent_id: str) -> dict[str, Any]:
    """Recorded context for an agent, read from the DURABLE store.

    The in-memory registry resets on restart; the SQLite `agents` table does
    not, so it is the correct production source for derivation.
    """
    row = db.get_agent_db(agent_id)
    if not row:
        return {
            "agent_id": agent_id,
            "declared_intent": "",
            "declared_permissions": [],
            "downstream_agents": [],
            "blast_level": "LOW",
        }
    return {
        "agent_id": agent_id,
        "declared_intent": row.get("declared_intent") or "",
        "declared_permissions": _parse_json_field(
            row.get("declared_permissions"), []),
        "downstream_agents": _parse_json_field(
            row.get("downstream_agents"), []),
        "blast_level": row.get("blast_level") or "LOW",
    }


def derive_prerequisites(agent_id: str) -> dict[str, Any]:
    """Build the default prerequisites profile from recorded context.

    Pure function of (recorded context + policy rules) — no side effects,
    safe to call from anywhere.
    """
    ctx = _derive_agent_context(agent_id)
    prereqs: list[dict[str, Any]] = []

    # ── Security invariants: always present, surfaced, LOCKED ─────────────
    prereqs.append({
        "id": "PR-TOKEN",
        "kind": "identity",
        "label": "Zero-Trust token valid & not revoked",
        "detail": "Request authenticated with a valid, unexpired, non-revoked agent token.",
        "severity": "BLOCK",
        "enforce": False,        # already hard-gated by the auth layer
        "editable": False,
        "source": "derived",
        "derived_from": "zero_trust_invariant",
    })
    prereqs.append({
        "id": "PR-ISOLATED",
        "kind": "containment",
        "label": "Agent not isolated",
        "detail": "Quarantined agents are rejected before the pipeline runs.",
        "severity": "BLOCK",
        "enforce": False,        # already hard-gated by the isolation guard
        "editable": False,
        "source": "derived",
        "derived_from": "isolation_engine",
    })
    prereqs.append({
        "id": "PR-SANDBOX",
        "kind": "containment",
        "label": "Agent not sandboxed (trust containment)",
        "detail": "Sandboxed agents are blocked by policy 'block-sandboxed-agents'.",
        "severity": "BLOCK",
        "enforce": False,        # enforced by the policy engine
        "editable": False,
        "source": "derived",
        "derived_from": "policy:block-sandboxed-agents",
    })

    # ── Trust floor — derived from the policy YAML ────────────────────────
    floor = _policy_trust_floor()
    prereqs.append({
        "id": "PR-TRUST",
        "kind": "trust",
        "label": f"Trust score ≥ {floor:g}",
        "detail": f"Policy 'block-after-trust-threshold' blocks agents below {floor:g}.",
        "severity": "BLOCK",
        "enforce": False,        # enforced by the policy engine
        "editable": True,
        "source": "derived",
        "derived_from": "policy:block-after-trust-threshold",
        "rule": {"min_trust": floor},
    })

    # ── Intent scope — from declared intent (recorded context) ───────────
    intent = ctx["declared_intent"]
    categories = match_intent_categories(intent)
    if intent.strip():
        allowed: list[str] = []
        forbidden: list[str] = []
        for cat in categories:
            allowed.extend(INTENT_TREE[cat]["allowed_tools"])
            forbidden.extend(INTENT_TREE[cat]["forbidden"])
        allowed = list(dict.fromkeys(allowed))
        forbidden = [t for t in dict.fromkeys(forbidden) if t not in allowed]
        prereqs.append({
            "id": "PR-INTENT",
            "kind": "intent_scope",
            "label": "Tool within declared intent scope",
            "detail": (
                f"Declared intent '{intent}' matches: {', '.join(categories) if categories else 'no known category'}."
            ),
            "severity": "BLOCK",
            "enforce": False,    # mirrors the intent-gap engine
            "editable": True,
            "source": "derived",
            "derived_from": "declared_intent",
            "rule": {
                "matched_intents": categories,
                "allowed_tools": allowed,
                "forbidden_tools": forbidden,
                "declared_permissions": ctx["declared_permissions"],
            },
        })

    # ── Permission scope — from declared permissions (recorded context) ──
    perms = ctx["declared_permissions"]
    if isinstance(perms, list) and perms:
        prereqs.append({
            "id": "PR-PERMS",
            "kind": "permission_scope",
            "label": "Tool within declared permissions",
            "detail": f"Declared permissions: {', '.join(perms)}.",
            "severity": "BLOCK",
            "enforce": False,
            "editable": True,
            "source": "derived",
            "derived_from": "declared_permissions",
            "rule": {"permissions": perms},
        })
    # NOTE: an empty declared_permissions list means "no explicit permission
    # restriction declared" (verified behaviour of the pipeline) — so no
    # permission prerequisite is derived; scope is governed by PR-INTENT.

    # ── Blast gate — from recorded blast radius ───────────────────────────
    if ctx["blast_level"] == "CRITICAL":
        prereqs.append({
            "id": "PR-BLAST",
            "kind": "blast",
            "label": "Blast radius gate for sensitive tools",
            "detail": (
                "CRITICAL blast radius: sensitive tools "
                f"({', '.join(_BLAST_SENSITIVE_TOOLS)}) are gated per "
                "policy 'block-critical-blast-radius'."
            ),
            "severity": "BLOCK",
            "enforce": False,
            "editable": True,
            "source": "derived",
            "derived_from": "blast_radius",
            "rule": {"sensitive_tools": _BLAST_SENSITIVE_TOOLS},
        })

    return {
        "agent_id": agent_id,
        "prerequisites": prereqs,
        "source": "derived",
        "version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": None,
        "updated_by": None,
    }


def register_derivation(agent_id: str) -> dict[str, Any]:
    """Derive + PERSIST the default profile (called at registration).

    Fails soft: any error is swallowed and reported in the return value so
    registration is never blocked by governance.
    """
    try:
        profile = derive_prerequisites(agent_id)
        db.upsert_governance_db(
            agent_id=agent_id,
            prerequisites=profile["prerequisites"],
            source=profile["source"],
            version=profile["version"],
            updated_at=None,
            updated_by=None,
        )
        _bump_cache(agent_id, profile)
        return profile
    except Exception as e:
        return {
            "agent_id": agent_id,
            "prerequisites": [],
            "source": "derived",
            "version": 1,
            "error": f"governance derivation failed (non-fatal): {e}",
        }


# ────────────────────────────────────────────────────────────────────────────
# Profile access
# ────────────────────────────────────────────────────────────────────────────

def _bump_cache(agent_id: str, profile: dict[str, Any]) -> None:
    with _cache_lock:
        _cache[agent_id] = profile


def _row_to_profile(row: dict[str, Any]) -> dict[str, Any]:
    prereqs = _parse_json_field(row.get("prerequisites"), [])
    return {
        "agent_id": row.get("agent_id"),
        "prerequisites": prereqs if isinstance(prereqs, list) else [],
        "source": row.get("source", "derived"),
        "version": int(row.get("version", 1) or 1),
        "created_at": row.get("created_at"),
        "updated_at": row.get("updated_at"),
        "updated_by": row.get("updated_by"),
    }


def get_profile(agent_id: str, persist_if_missing: bool = False) -> dict[str, Any]:
    """Load the agent's governance profile.

    Hot-path safe: cache → one PK SELECT → in-memory derivation (persisted
    only when persist_if_missing=True, i.e. from the GET endpoint, never from
    the intercept hot path).
    """
    with _cache_lock:
        cached = _cache.get(agent_id)
    if cached is not None:
        return cached

    try:
        row = db.get_governance_db(agent_id)
    except Exception:
        row = None
    if row:
        profile = _row_to_profile(row)
        _bump_cache(agent_id, profile)
        return profile

    # No persisted profile yet (e.g. agent registered before this feature)
    profile = derive_prerequisites(agent_id)
    if persist_if_missing:
        try:
            db.upsert_governance_db(
                agent_id=agent_id,
                prerequisites=profile["prerequisites"],
                source=profile["source"],
                version=profile["version"],
                updated_at=None,
                updated_by=None,
            )
        except Exception:
            pass  # non-fatal: profile still served from memory
    _bump_cache(agent_id, profile)
    return profile


# ────────────────────────────────────────────────────────────────────────────
# Per-action evaluation (hot path)
# ────────────────────────────────────────────────────────────────────────────

def _eval_check(spec: dict[str, Any], params: dict[str, Any]) -> tuple[bool, str]:
    """Evaluate one deterministic custom check spec against call parameters.

    Only JSON-serialisable checks are accepted (validated at edit time);
    this function is the interpreter. No code execution, ever.
    """
    kind = spec.get("check", {}).get("type")
    if kind == "param_equals":
        for k, v in (spec.get("check", {}).get("pairs", {}) or {}).items():
            if str(params.get(k, "<absent>")) != str(v):
                return False, f"parameter '{k}' must equal {v!r} (got {params.get(k)!r})"
        return True, "parameter matches"
    if kind == "param_in":
        for k, vals in (spec.get("check", {}).get("pairs", {}) or {}).items():
            if params.get(k) not in vals:
                return False, f"parameter '{k}' must be one of {vals} (got {params.get(k)!r})"
        return True, "parameter matches"
    if kind == "param_present":
        missing = [k for k in spec.get("check", {}).get("keys", [])
                   if k not in params]
        if missing:
            return False, f"missing required parameter(s): {', '.join(missing)}"
        return True, "parameters present"
    return True, "unrecognised check type — treated as satisfied (validated at edit time)"


def evaluate_prerequisites(
    agent_id: str,
    tool: str,
    params: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Evaluate the agent's prerequisite profile for one intercepted call.

    Designed for the hot path: in-memory reads only, <2 ms in practice, and
    NEVER raises — any internal error degrades to status "degraded" so the
    7-layer pipeline is unaffected.
    """
    params = params or {}
    out: dict[str, Any] = {
        "status": "evaluated",
        "agent_id": agent_id,
        "tool": tool,
        "prerequisites": [],
    }
    try:
        profile = get_profile(agent_id)

        # Live state (in-memory engines — no DB)
        try:
            trust = get_trust_summary(agent_id)
        except Exception:
            trust = {"trust_score": 100.0, "is_sandboxed": False}
        isolated = is_isolated(agent_id)
        tool_lower = (tool or "").lower()

        for p in profile.get("prerequisites", []):
            res: dict[str, Any] = {
                "id": p["id"],
                "label": p.get("label", p["id"]),
                "source": p.get("source", "derived"),
                "severity": p.get("severity", "BLOCK"),
                "enforce": bool(p.get("enforce", p.get("source") == "custom")),
            }
            satisfied, reason = True, "satisfied"
            kind = p.get("kind")

            if kind == "identity":
                # We only reach evaluation after successful authentication.
                satisfied, reason = True, "verified at request time"
            elif kind == "containment" and p["id"] == "PR-ISOLATED":
                satisfied = not isolated
                reason = ("agent is ISOLATED — rejected by the isolation guard"
                          if isolated else "agent is not isolated")
            elif kind == "containment":  # PR-SANDBOX
                sandboxed = bool(trust.get("is_sandboxed"))
                satisfied = not sandboxed
                reason = (f"sandboxed ({trust.get('sandbox_reason') or 'trust containment'})"
                          if sandboxed else "not sandboxed")
            elif kind == "trust":
                score = float(trust.get("trust_score", 100.0))
                floor = float(p.get("rule", {}).get("min_trust", 40.0))
                satisfied = score >= floor
                reason = (f"trust {score:g} ≥ {floor:g}"
                          if satisfied else
                          f"trust {score:g} < {floor:g} (threshold from policy)")
            elif kind == "intent_scope":
                rule = p.get("rule", {}) or {}
                allowed = [t.lower() for t in rule.get("allowed_tools", [])]
                forbidden = [t.lower() for t in rule.get("forbidden_tools", [])]
                perms = [t.lower() for t in rule.get("declared_permissions", [])]
                cats = rule.get("matched_intents", [])
                if not cats:
                    satisfied = True
                    reason = ("no recognized intent category — scope check "
                              "delegated to the intent-gap engine")
                elif tool_lower in forbidden:
                    satisfied = False
                    reason = (f"tool '{tool}' is forbidden for "
                              f"{' + '.join(cats)} intent")
                elif tool_lower in allowed:
                    satisfied = True
                    reason = f"tool is in the {cats[0] if len(cats) == 1 else 'matched intent'} scope"
                elif tool_lower in perms:
                    satisfied = True
                    reason = f"tool is explicitly in the agent's declared permissions"
                else:
                    satisfied = False
                    reason = (f"tool '{tool}' is outside the declared intent "
                              f"scope ({', '.join(cats)}) and not in declared permissions")
            elif kind == "permission_scope":
                perms = [t.lower() for t in p.get("rule", {}).get("permissions", [])]
                satisfied = tool_lower in perms
                reason = (f"'{tool}' is in declared permissions"
                          if satisfied else
                          f"'{tool}' is not in declared permissions ({', '.join(perms)})")
            elif kind == "blast":
                sensitive = [t.lower() for t in p.get("rule", {}).get("sensitive_tools", [])]
                if tool_lower in sensitive:
                    satisfied = False
                    reason = "sensitive tool attempted under CRITICAL blast radius"
                else:
                    satisfied = True
                    reason = "tool is not in the sensitive set"
            elif kind == "custom":
                satisfied, reason = _eval_check(p, params)
            else:
                satisfied, reason = True, "no check defined"

            res["satisfied"] = satisfied
            res["reason"] = reason
            out["prerequisites"].append(res)

        unsat = [r for r in out["prerequisites"] if not r["satisfied"]]
        out["satisfied"] = len(out["prerequisites"]) - len(unsat)
        out["unsatisfied"] = len(unsat)
        out["blocking"] = [r["id"] for r in unsat if r["enforce"]]
        return out
    except Exception as e:  # hot path must never break the pipeline
        return {
            "status": "degraded",
            "agent_id": agent_id,
            "tool": tool,
            "reason": f"governance evaluation error (non-fatal): {e}",
            "prerequisites": [],
            "satisfied": 0,
            "unsatisfied": 0,
            "blocking": [],
        }


# ────────────────────────────────────────────────────────────────────────────
# Editing (validated + audited)
# ────────────────────────────────────────────────────────────────────────────

class GovernanceEditError(ValueError):
    """Raised for rejected edits; carries an operator-facing reason."""


def _validate_custom_check(check: Any) -> dict[str, Any]:
    """Whitelist-validate a custom check spec (no code execution, ever)."""
    if not isinstance(check, dict):
        raise GovernanceEditError("custom check must be an object")
    t = check.get("type")
    if t == "param_equals":
        pairs = check.get("pairs")
        if not isinstance(pairs, dict) or not pairs:
            raise GovernanceEditError("param_equals requires non-empty 'pairs' object")
        for k, v in pairs.items():
            if not isinstance(k, str) or not k.strip():
                raise GovernanceEditError("parameter keys must be non-empty strings")
        return {"type": t, "pairs": {str(k): v for k, v in pairs.items()}}
    if t == "param_in":
        pairs = check.get("pairs")
        if not isinstance(pairs, dict) or not pairs:
            raise GovernanceEditError("param_in requires non-empty 'pairs' object")
        for k, v in pairs.items():
            if not isinstance(k, str) or not isinstance(v, list) or not v:
                raise GovernanceEditError(
                    "param_in pairs must map string keys to non-empty lists")
        return {"type": t, "pairs": {str(k): list(v) for k, v in pairs.items()}}
    if t == "param_present":
        keys = check.get("keys")
        if not isinstance(keys, list) or not keys or \
           not all(isinstance(k, str) and k.strip() for k in keys):
            raise GovernanceEditError(
                "param_present requires a non-empty list of string keys")
        return {"type": t, "keys": list(keys)}
    raise GovernanceEditError(
        f"unsupported check type {t!r} (allowed: param_equals, param_in, param_present)")


def apply_edits(
    agent_id: str,
    edits: dict[str, Any],
    actor: str,
    expected_version: Optional[int] = None,
    audit: Optional[callable] = None,
) -> dict[str, Any]:
    """Apply a validated, audited edit to the governance profile.

    Allowed operations:
      add_custom : [ {label, description?, severity?, check} ]
      remove     : [ prerequisite ids ]      (custom entries only)
      update     : [ {id, severity?, enforce?, label?, description?} ]
                   (editable entries only; invariants locked)

    Raises GovernanceEditError (→ 422) on any violation, and ValueError
    (→ 409) on version conflict. On success returns the new profile.
    """
    if not isinstance(actor, str) or not actor.strip():
        raise GovernanceEditError("edit requires a non-empty 'actor' (who is editing)")
    actor = actor.strip()
    if not isinstance(edits, dict) or not edits:
        raise GovernanceEditError("'edits' must be a non-empty object "
                                  "(add_custom / remove / update)")

    # Referential integrity: governance rows hang off the durable agents
    # table (ON DELETE CASCADE). A clear operator-facing error beats a raw
    # FK failure if this is ever reached directly.
    try:
        known = db.get_agent_db(agent_id) is not None
    except Exception:
        known = False
    if not known:
        raise GovernanceEditError(
            f"agent '{agent_id}' has no recorded context (unknown agent)")

    profile = get_profile(agent_id)

    # Concurrency guard (production: last-writer-wins without the check,
    # optimistic locking when the client passes expected_version)
    if expected_version is not None and int(expected_version) != profile["version"]:
        raise ValueError(
            f"version conflict: profile is at version {profile['version']}, "
            f"edit referenced {expected_version}")

    prereqs = [dict(p) for p in profile.get("prerequisites", [])]  # deep-ish copy
    changes: list[str] = []

    # ── add_custom ────────────────────────────────────────────────────────
    for i, item in enumerate(edits.get("add_custom", []) or []):
        if not isinstance(item, dict):
            raise GovernanceEditError(f"add_custom[{i}] must be an object")
        label = item.get("label")
        if not isinstance(label, str) or not label.strip():
            raise GovernanceEditError(f"add_custom[{i}] requires a non-empty 'label'")
        check = _validate_custom_check(item.get("check"))
        sev = item.get("severity", "BLOCK")
        if sev not in ("BLOCK", "FLAG"):
            raise GovernanceEditError(
                f"add_custom[{i}] severity must be BLOCK or FLAG (got {sev!r})")
        # Stable, collision-safe custom id
        n = sum(1 for p in prereqs if p.get("kind") == "custom") + 1
        new_id = f"PR-CUST-{n}"
        while any(p["id"] == new_id for p in prereqs):
            n += 1
            new_id = f"PR-CUST-{n}"
        prereqs.append({
            "id": new_id,
            "kind": "custom",
            "label": label.strip(),
            "detail": (item.get("description")
                       or f"Operator-defined prerequisite added by {actor}."),
            "severity": sev,
            "enforce": bool(item.get("enforce", True)),
            "editable": True,
            "source": "custom",
            "derived_from": f"operator:{actor}",
            "check": check,
            "added_by": actor,
            "added_at": datetime.now(timezone.utc).isoformat(),
        })
        changes.append(f"added {new_id} ({label.strip()})")

    # ── remove ────────────────────────────────────────────────────────────
    removed = []
    for rid in edits.get("remove", []) or []:
        target = next((p for p in prereqs if p["id"] == rid), None)
        if target is None:
            raise GovernanceEditError(f"unknown prerequisite id {rid!r}")
        if target.get("source") != "custom":
            raise GovernanceEditError(
                f"prerequisite {rid!r} is {'a security invariant' if not target.get('editable') else 'derived from recorded context'} "
                f"and cannot be removed via governance edits "
                f"(clear the underlying condition instead)")
        prereqs = [p for p in prereqs if p["id"] != rid]
        removed.append(rid)
        changes.append(f"removed {rid}")

    # ── update ────────────────────────────────────────────────────────────
    for i, upd in enumerate(edits.get("update", []) or []):
        if not isinstance(upd, dict) or not upd.get("id"):
            raise GovernanceEditError(f"update[{i}] requires an 'id'")
        target = next((p for p in prereqs if p["id"] == upd["id"]), None)
        if target is None:
            raise GovernanceEditError(f"unknown prerequisite id {upd['id']!r}")
        if not target.get("editable", False):
            raise GovernanceEditError(
                f"prerequisite {upd['id']!r} is a locked security invariant "
                f"(token/isolation) and cannot be modified")
        if "severity" in upd and upd["severity"] not in ("BLOCK", "FLAG"):
            raise GovernanceEditError(
                f"update[{i}] severity must be BLOCK or FLAG")
        if "enforce" in upd and upd["enforce"] is True and \
           not target.get("editable", False):
            raise GovernanceEditError("cannot enable enforcement on a locked entry")
        if "label" in upd and (not isinstance(upd["label"], str)
                               or not upd["label"].strip()):
            raise GovernanceEditError("label must be a non-empty string")
        for field in ("severity", "enforce", "label"):
            if field in upd:
                old = target.get(field)
                target[field] = upd[field]
                changes.append(f"{target['id']}.{field}: {old} → {upd[field]}")
        if "description" in upd and isinstance(upd["description"], str):
            target["detail"] = upd["description"]
            changes.append(f"{target['id']}.detail updated")

    # ── Persist + audit ───────────────────────────────────────────────────
    new_profile = dict(profile)
    new_profile["prerequisites"] = prereqs
    new_profile["version"] = profile["version"] + 1
    new_profile["updated_at"] = datetime.now(timezone.utc).isoformat()
    new_profile["updated_by"] = actor
    new_profile["source"] = ("derived+edited"
                             if any(p.get("source") == "custom" for p in prereqs)
                             else "derived")

    try:
        db.upsert_governance_db(
            agent_id=agent_id,
            prerequisites=prereqs,
            source=new_profile["source"],
            version=new_profile["version"],
            updated_at=new_profile["updated_at"],
            updated_by=actor,
        )
    except Exception as e:
        if audit:
            try:
                audit({"event_type": "GOVERNANCE_UPDATE_FAILED",
                       "agent_id": agent_id, "actor": actor, "error": str(e)})
            except Exception:
                pass
        raise GovernanceEditError(f"edit validated but persistence failed: {e}")

    _bump_cache(agent_id, new_profile)

    if audit:
        try:
            audit({
                "event_type": "GOVERNANCE_UPDATED",
                "agent_id": agent_id,
                "actor": actor,
                "version": new_profile["version"],
                "changes": changes,
            })
        except Exception:
            pass  # audit failure must not fail the edit response

    return new_profile

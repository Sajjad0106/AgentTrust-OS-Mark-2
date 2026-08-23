"""
Unit tests for the Blocker Engine (Phase 2, concept 2 of 3).

Covers: per-source firing, severity model, status precedence, dedup
(one root cause = one row), call-scoped blocker merging, clear_action
correctness, sort order, and the never-raises contract.

The in-memory engines (registry isolation, approvals, trust profiles) are
exercised directly — no HTTP layer (that is test_blockers_api.py's job).
A fresh agent id per test avoids cross-talk between in-memory profiles.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import infrastructure.database as db  # noqa: E402
from engine.governance import blocker_engine as be  # noqa: E402
from engine.trust_score import trust_engine as te  # noqa: E402
from engine.approval import approval_engine as ae  # noqa: E402
from registry import agent_registry as reg  # noqa: E402


def _register_in_db(agent_id, intent="customer support", perms=None, blast="LOW"):
    """Register an agent in the durable store + issue a token — exactly what
    the real /agents/register endpoint does (a token-less agent genuinely
    cannot authenticate, so the token blocker must fire for it)."""
    db.register_agent_db(
        agent_id=agent_id,
        name=agent_id,
        declared_intent=intent,
        declared_permissions=perms or [],
        downstream_agents=[],
        blast_score=10 if blast == "LOW" else 90,
        blast_level=blast,
    )
    db.issue_token_db(agent_id, "test-token-raw", ttl_hours=24)


@pytest.fixture(autouse=True)
def fresh_state(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "blockers_test.db"))
    db.init_db()
    be._cache.clear()
    reg.ISOLATED_AGENTS.clear()
    ae.APPROVALS.clear()
    yield
    be._cache.clear()
    reg.ISOLATED_AGENTS.clear()
    ae.APPROVALS.clear()


def _kinds(v):
    return {b["kind"] for b in v["blockers"]}


# ── status & shape ──────────────────────────────────────────────────────────

def test_healthy_agent_is_clear():
    aid = "blk-t-healthy"
    _register_in_db(aid)
    v = be.compute_blockers(aid, use_cache=False)
    assert v["status"] == "CLEAR"
    assert v["blockers"] == []
    assert v["agent_id"] == aid
    assert v["computed_at"]


def test_unknown_agent():
    v = be.compute_blockers("blk-t-ghost", use_cache=False)
    assert v["status"] == "UNKNOWN_AGENT"
    assert v["blockers"] == []


def test_status_precedence_hard_beats_soft():
    aid = "blk-t-precedence"
    _register_in_db(aid)
    reg.isolate_agent(aid, "review")
    v = be.compute_blockers(aid, use_cache=False)
    assert v["status"] == "BLOCKED"
    reg.release_agent(aid)
    v = be.compute_blockers(aid, use_cache=False)
    assert v["status"] == "CLEAR"


# ── per-source firing ───────────────────────────────────────────────────────

def test_isolation_blocker_hard_with_clear_action():
    aid = "blk-t-iso"
    _register_in_db(aid)
    reg.isolate_agent(aid, "security review")
    v = be.compute_blockers(aid, use_cache=False)
    b = next(x for x in v["blockers"] if x["kind"] == "isolation")
    assert b["severity"] == "hard"
    assert "security review" in b["reason"]
    assert b["since"]
    assert b["clear_action"] == {"method": "POST", "endpoint": f"/agents/release/{aid}"}
    # guard consistency: same source as the intercept guard
    assert reg.is_isolated(aid) is True
    reg.release_agent(aid)
    assert "isolation" not in _kinds(be.compute_blockers(aid, use_cache=False))


def test_token_blocker_states():
    aid = "blk-t-token"
    _register_in_db(aid)
    db.issue_token_db(aid, "rawtoken123", ttl_hours=24)
    assert be.compute_blockers(aid, use_cache=False)["status"] == "CLEAR"

    # expire the token directly (simulates TTL lapse)
    conn = db.get_connection()
    conn.execute("UPDATE tokens SET expires_at = '2000-01-01T00:00:00' WHERE agent_id = ?", (aid,))
    conn.commit()
    conn.close()

    v = be.compute_blockers(aid, use_cache=False)
    b = next(x for x in v["blockers"] if x["kind"] == "token")
    assert b["severity"] == "hard"
    assert b["clear_action"]["endpoint"] == "/agents/register"

    # revocation also blocks
    db.revoke_token_db(aid)
    v = be.compute_blockers(aid, use_cache=False)
    b = next(x for x in v["blockers"] if x["kind"] == "token")
    assert "revoked" in b["reason"]


def test_trust_floor_and_sandbox_are_hard_and_deduped():
    aid = "blk-t-trust"
    _register_in_db(aid)
    p = te.get_or_create_profile(aid)
    p.trust_score = 15.0
    te._evaluate_containment(p)

    v = be.compute_blockers(aid, use_cache=False)
    assert v["status"] == "BLOCKED"
    trust_rows = [b for b in v["blockers"] if b["kind"] == "trust"]
    sandbox_rows = [b for b in v["blockers"] if b["kind"] == "containment" and b["id"] == "BLK-SANDBOX"]
    assert len(trust_rows) == 1, "exactly one trust-floor row (dedup)"
    assert len(sandbox_rows) == 1
    assert trust_rows[0]["severity"] == "hard"
    assert sandbox_rows[0]["severity"] == "hard"
    assert trust_rows[0]["related_prereq"] == "PR-TRUST"
    assert "40" in trust_rows[0]["reason"]


def test_restricted_is_soft():
    aid = "blk-t-restrict"
    _register_in_db(aid)
    p = te.get_or_create_profile(aid)
    p.trust_score = 45.0   # above floor (40), below RESTRICT threshold (50)
    te._evaluate_containment(p)
    v = be.compute_blockers(aid, use_cache=False)
    b = next(x for x in v["blockers"] if x["id"] == "BLK-RESTRICT")
    assert b["severity"] == "soft"
    assert v["status"] == "DEGRADED"


def test_pending_approval_is_soft_with_approve_action():
    aid = "blk-t-apr"
    _register_in_db(aid)
    a = ae.create_approval(aid, "export_data", {"table": "salaries"}, "HIGH risk action")
    v = be.compute_blockers(aid, use_cache=False)
    b = next(x for x in v["blockers"] if x["kind"] == "approval")
    assert b["severity"] == "soft"
    assert b["clear_action"] == {"method": "POST", "endpoint": f"/approvals/{a['id']}/approve"}
    # deciding it clears the blocker
    ae.approve(a["id"])
    assert "approval" not in _kinds(be.compute_blockers(aid, use_cache=False))


def test_custom_gate_surfaced_as_standing_soft_gate():
    aid = "blk-t-custom"
    _register_in_db(aid)
    from engine.governance import governance_engine as ge
    ge.apply_edits(aid, {
        "add_custom": [{"label": "EU residency",
                        "check": {"type": "param_equals", "pairs": {"region": "eu"}}}],
    }, actor="test")
    v = be.compute_blockers(aid, use_cache=False)
    b = next(x for x in v["blockers"] if x["kind"] == "custom_gate")
    assert b["severity"] == "soft"
    assert b["related_prereq"].startswith("PR-CUST-")
    assert "region" in b["reason"]


# ── call-level view ─────────────────────────────────────────────────────────

def test_call_blockers_adds_call_scoped_prerequisite_failures():
    aid = "blk-t-call"
    _register_in_db(aid, intent="customer support", perms=["read_ticket"])
    # out-of-intent tool + missing declared permission → both fail for this call
    v = be.compute_call_blockers(aid, "run_command", {"cmd": "ls"})
    ids = {b["id"] for b in v["blockers"]}
    assert "BLK-CALL-PR-INTENT" in ids
    assert "BLK-CALL-PR-PERMS" in ids
    # derived (surface-only) entries are soft
    for bid in ("BLK-CALL-PR-INTENT", "BLK-CALL-PR-PERMS"):
        assert next(b for b in v["blockers"] if b["id"] == bid)["severity"] == "soft"
    assert v["call_scoped"]


def test_call_blockers_custom_gate_failure_is_hard():
    aid = "blk-t-callcustom"
    _register_in_db(aid, intent="customer support", perms=["read_ticket"])
    from engine.governance import governance_engine as ge
    ge.apply_edits(aid, {
        "add_custom": [{"label": "EU residency", "severity": "BLOCK",
                        "check": {"type": "param_equals", "pairs": {"region": "eu"}}}],
    }, actor="test")
    v_fail = be.compute_call_blockers(aid, "send_email", {"region": "us"})
    b = next(x for x in v_fail["blockers"] if x["id"] == "BLK-CALL-PR-CUST-1")
    assert b["severity"] == "hard"
    assert v_fail["status"] == "BLOCKED"

    v_ok = be.compute_call_blockers(aid, "send_email", {"region": "eu"})
    assert "BLK-CALL-PR-CUST-1" not in {x["id"] for x in v_ok["blockers"]}


def test_call_blockers_no_duplicate_state_rows():
    """State-level prerequisite failures must not double their blocker rows
    (PR-TRUST → BLK-TRUST-FLOOR only, not a second BLK-CALL-PR-TRUST row)."""
    aid = "blk-t-nodup"
    _register_in_db(aid)
    p = te.get_or_create_profile(aid)
    p.trust_score = 15.0
    te._evaluate_containment(p)
    v = be.compute_call_blockers(aid, "read_ticket", {})
    ids = [b["id"] for b in v["blockers"]]
    assert "BLK-TRUST-FLOOR" in ids
    assert "BLK-CALL-PR-TRUST" not in ids


# ── sorting & never-raises ──────────────────────────────────────────────────

def test_sorting_hard_first_then_kind_order():
    aid = "blk-t-sort"
    _register_in_db(aid)
    reg.isolate_agent(aid, "r")
    ae.create_approval(aid, "t", {}, "x")
    v = be.compute_blockers(aid, use_cache=False)
    order = [b["kind"] for b in v["blockers"]]
    assert order[0] == "isolation"          # hard, first
    assert order[-1] == "approval"          # soft, last


def test_never_raises_on_corrupt_sources(monkeypatch):
    aid = "blk-t-degraded"
    _register_in_db(aid)
    monkeypatch.setattr(be, "_check_isolated",
                        lambda a: (_ for _ in ()).throw(RuntimeError("boom")))
    v = be.compute_blockers(aid, use_cache=False)
    assert v["status"] == "degraded"
    assert v["blockers"] == []
    # and the call-level view degrades too, without raising
    v2 = be.compute_call_blockers(aid, "read_ticket", {})
    assert v2["status"] == "degraded"

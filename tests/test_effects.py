"""
Unit tests for the Downstream Effects Engine (Phase 3, concept 3 of 3).

Covers: impact classes (HEALTHY / DEGRADED / QUARANTINED / UNKNOWN),
status precedence, honesty rules (no invented rows, self-references
excluded, undeclared ⇒ none), the D3 advisory semantics (fires for
ALLOWED and FLAGGED, never for BLOCKED; stricter-only), impact text per
action, systemic rows, read-only inspection (no profile side effects),
and the never-raises contract.

Fresh agent ids per test avoid cross-talk in the in-memory trust store.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import infrastructure.database as db  # noqa: E402
from engine.governance import effects_engine as ee  # noqa: E402
from engine.trust_score import trust_engine as te  # noqa: E402
from registry import agent_registry as reg  # noqa: E402


def _mk(agent_id, downstream=None, intent="customer support", blast="LOW"):
    db.register_agent_db(
        agent_id=agent_id,
        name=agent_id,
        declared_intent=intent,
        declared_permissions=["read_ticket"],
        downstream_agents=downstream or [],
        blast_score=10 if blast == "LOW" else 90,
        blast_level=blast,
    )


@pytest.fixture(autouse=True)
def fresh_state(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "effects_test.db"))
    db.init_db()
    ee._cache.clear()
    reg.ISOLATED_AGENTS.clear()
    yield
    ee._cache.clear()
    reg.ISOLATED_AGENTS.clear()


def _classes(v):
    return {c["id"]: c["impact_class"] for c in v["consumers"]}


# ── agent-level view ────────────────────────────────────────────────────────

def test_no_consumers_declared():
    _mk("fx-t-none")
    v = ee.compute_effects("fx-t-none", use_cache=False)
    assert v["status"] == "NO_CONSUMERS"
    assert v["consumers"] == []
    # audit-trail systemic row is always present
    assert any(s["type"] == "audit_trail" for s in v["systemic"])


def test_healthy_chain():
    _mk("fx-t-cons-1")
    _mk("fx-t-prod-1", downstream=["fx-t-cons-1"])
    v = ee.compute_effects("fx-t-prod-1", use_cache=False)
    assert v["status"] == "HEALTHY_CHAIN"
    assert _classes(v) == {"fx-t-cons-1": "HEALTHY"}
    c = v["consumers"][0]
    assert c["registered"] is True
    assert c["trust_score"] == 100.0


def test_quarantined_consumer():
    _mk("fx-t-cons-2")
    _mk("fx-t-prod-2", downstream=["fx-t-cons-2"])
    reg.isolate_agent("fx-t-cons-2", "compromised")
    v = ee.compute_effects("fx-t-prod-2", use_cache=False)
    assert v["status"] == "QUARANTINED"
    assert _classes(v)["fx-t-cons-2"] == "QUARANTINED"
    assert v["consumers"][0]["isolated"] is True


def test_degraded_consumer_restrict():
    _mk("fx-t-cons-3")
    _mk("fx-t-prod-3", downstream=["fx-t-cons-3"])
    p = te.get_or_create_profile("fx-t-cons-3")
    p.trust_score = 45.0
    te._evaluate_containment(p)
    v = ee.compute_effects("fx-t-prod-3", use_cache=False)
    assert _classes(v)["fx-t-cons-3"] == "DEGRADED"
    assert v["status"] == "DEGRADED"


def test_degraded_consumer_sandbox():
    _mk("fx-t-cons-4")
    _mk("fx-t-prod-4", downstream=["fx-t-cons-4"])
    p = te.get_or_create_profile("fx-t-cons-4")
    p.trust_score = 15.0
    te._evaluate_containment(p)
    v = ee.compute_effects("fx-t-prod-4", use_cache=False)
    assert _classes(v)["fx-t-cons-4"] == "DEGRADED"


def test_unknown_consumer_honesty():
    _mk("fx-t-prod-5", downstream=["fx-t-ghost-consumer"])
    v = ee.compute_effects("fx-t-prod-5", use_cache=False)
    c = v["consumers"][0]
    assert c["id"] == "fx-t-ghost-consumer"
    assert c["registered"] is False
    assert c["impact_class"] == "UNKNOWN"
    assert "not registered" in c["note"]
    assert v["status"] == "DEGRADED"


def test_self_reference_excluded():
    _mk("fx-t-self", downstream=["fx-t-self"])
    v = ee.compute_effects("fx-t-self", use_cache=False)
    assert v["consumers"] == []
    assert v["status"] == "NO_CONSUMERS"


def test_no_invented_rows():
    """An agent with no declarations must not show phantom consumers, and a
    consumer must not appear for an agent that never declared it."""
    _mk("fx-t-cons-6")
    _mk("fx-t-prod-6")
    v = ee.compute_effects("fx-t-prod-6", use_cache=False)
    assert v["consumers"] == []


def test_inspection_is_read_only():
    """Inspecting an unregistered declared consumer must not create a trust
    profile for it (no side effects from a read view)."""
    before = set(te.TRUST_STORE.keys())
    _mk("fx-t-prod-7", downstream=["fx-t-never-seen"])
    ee.compute_effects("fx-t-prod-7", use_cache=False)
    assert "fx-t-never-seen" not in te.TRUST_STORE
    assert set(te.TRUST_STORE.keys()) - before <= set()


# ── call-level view + D3 advisory ───────────────────────────────────────────

def test_call_effects_allowed_impact_text():
    _mk("fx-t-cons-8")
    _mk("fx-t-prod-8", downstream=["fx-t-cons-8"])
    v = ee.compute_call_effects("fx-t-prod-8", "read_ticket", {"t": 1}, "ALLOWED")
    assert "will flow to 1 declared consumer" in v["impact"]
    assert v["advisory"] == []


def test_call_effects_blocked_starvation_and_feedback():
    _mk("fx-t-cons-9")
    _mk("fx-t-prod-9", downstream=["fx-t-cons-9"])
    v = ee.compute_call_effects("fx-t-prod-9", "run_command", {"c": "ls"}, "BLOCKED",
                                trust_score=72.5)
    assert "starved" in v["impact"]
    assert "72.5" in v["impact"]
    assert any(s["type"] == "trust_feedback" for s in v["systemic"])
    assert v["advisory"] == []  # blocked calls execute nothing


def test_d3_advisory_fires_on_allowed_and_flagged_only():
    _mk("fx-t-cons-10")
    _mk("fx-t-prod-10", downstream=["fx-t-cons-10"])
    reg.isolate_agent("fx-t-cons-10", "quarantine")

    v_allow = ee.compute_call_effects("fx-t-prod-10", "read_ticket", {}, "ALLOWED")
    assert len(v_allow["advisory"]) == 1
    assert "QUARANTINED" in v_allow["advisory"][0]

    v_flag = ee.compute_call_effects("fx-t-prod-10", "read_ticket", {}, "FLAGGED")
    assert len(v_flag["advisory"]) == 1

    v_block = ee.compute_call_effects("fx-t-prod-10", "read_ticket", {}, "BLOCKED", trust_score=50)
    assert v_block["advisory"] == []

    # releasing the consumer clears the advisory (live state, not stored)
    reg.release_agent("fx-t-cons-10")
    v_after = ee.compute_call_effects("fx-t-prod-10", "read_ticket", {}, "ALLOWED")
    assert v_after["advisory"] == []


def test_d3_multiple_quarantined_consumers():
    _mk("fx-t-cons-11a")
    _mk("fx-t-cons-11b")
    _mk("fx-t-prod-11", downstream=["fx-t-cons-11a", "fx-t-cons-11b"])
    reg.isolate_agent("fx-t-cons-11a", "q1")
    reg.isolate_agent("fx-t-cons-11b", "q2")
    v = ee.compute_call_effects("fx-t-prod-11", "read_ticket", {}, "ALLOWED")
    assert len(v["advisory"]) == 2
    ids = [c["id"] for c in v["consumers"]]
    assert ids == ["fx-t-cons-11a", "fx-t-cons-11b"]  # declaration order, deduped


def test_threat_correlation_systemic_row():
    _mk("fx-t-prod-12")
    v = ee.compute_call_effects("fx-t-prod-12", "read_ticket", {}, "ALLOWED",
                                correlated_agents=["other-agent-1"])
    corr = [s for s in v["systemic"] if s["type"] == "threat_correlation"]
    assert len(corr) == 1 and corr[0]["agents"] == ["other-agent-1"]


def test_never_raises_on_corrupt_sources(monkeypatch):
    # consumer must be REGISTERED so the code path reaches _consumer_state
    _mk("fx-t-cons-13")
    _mk("fx-t-prod-13", downstream=["fx-t-cons-13"])
    monkeypatch.setattr(ee, "_consumer_state",
                        lambda cid: (_ for _ in ()).throw(RuntimeError("boom")))
    v = ee.compute_effects("fx-t-prod-13", use_cache=False)
    assert v["status"] == "degraded"
    v2 = ee.compute_call_effects("fx-t-prod-13", "read_ticket", {}, "ALLOWED")
    assert v2["status"] == "degraded"

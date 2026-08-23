"""
Offline tests for the Governance engine — PREREQUISITES concept.

Covers (per the build plan, production-grade):
  • derivation of sensible defaults from recorded context
  • hot-path evaluation (state + tool-scoped), never-raises guarantee
  • custom-check whitelist validation (no code execution)
  • edit validation: invariants locked, derived entries protected,
    version conflict (409 path), actor required (422 path)
  • persistence round-trip (SQLite)

Runs against an ISOLATED temp database (patches infrastructure.database.DB_PATH
before any DB access) and fresh agent ids, so it never touches production data.
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import infrastructure.database as db  # noqa: E402
from engine.governance import governance_engine as gov  # noqa: E402
from engine.governance.governance_engine import (  # noqa: E402
    GovernanceEditError,
    apply_edits,
    derive_prerequisites,
    evaluate_prerequisites,
    register_derivation,
)


# ── Fixture: isolated temp DB + clean engine caches ─────────────────────────

@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    db_path = str(tmp_path / "governance_test.db")
    monkeypatch.setattr(db, "DB_PATH", db_path)
    db.init_db()
    # The governance engine caches profiles per agent; keep tests isolated.
    gov._cache.clear()
    yield db_path
    gov._cache.clear()


def _register(agent_id, intent="customer support and help desk",
              permissions=("read_ticket", "send_email"),
              downstream=("report-agent-02",), blast_level="LOW",
              blast_score=0):
    """Simulate the recorded context that /agents/register would persist."""
    return db.register_agent_db(
        agent_id=agent_id,
        name=f"Test {agent_id}",
        declared_intent=intent,
        declared_permissions=list(permissions),
        downstream_agents=list(downstream),
        blast_score=blast_score,
        blast_level=blast_level,
        blast_reason="test",
        trust_score=100.0,
    )


# ── Derivation — defaults from recorded context ─────────────────────────────

def test_derive_full_context():
    _register("gov-derive-1")
    profile = derive_prerequisites("gov-derive-1")

    ids = [p["id"] for p in profile["prerequisites"]]
    # Invariants always present
    assert "PR-TOKEN" in ids and "PR-ISOLATED" in ids and "PR-SANDBOX" in ids
    # Trust floor derived from the policy YAML
    assert "PR-TRUST" in ids
    # Intent + permission prerequisites derived from recorded context
    assert "PR-INTENT" in ids and "PR-PERMS" in ids
    # LOW blast → no blast gate
    assert "PR-BLAST" not in ids

    intent_pr = next(p for p in profile["prerequisites"] if p["id"] == "PR-INTENT")
    assert intent_pr["rule"]["matched_intents"] == ["customer_support"]
    assert "send_email" in intent_pr["rule"]["allowed_tools"]

    assert profile["source"] == "derived"
    assert profile["version"] == 1
    # Invariants are locked; derived policy entries are editable
    for p in profile["prerequisites"]:
        if p["id"] in ("PR-TOKEN", "PR-ISOLATED", "PR-SANDBOX"):
            assert p["editable"] is False and p["enforce"] is False
        else:
            assert p["editable"] is True


def test_derive_no_recorded_context():
    # Agent never registered in the DB — must still yield a minimal,
    # valid profile (production: never crash, never nulls)
    profile = derive_prerequisites("gov-ghost-agent")
    ids = [p["id"] for p in profile["prerequisites"]]
    assert ids == ["PR-TOKEN", "PR-ISOLATED", "PR-SANDBOX", "PR-TRUST"]


def test_derive_empty_permissions_no_perm_prereq():
    _register("gov-empty-perms", permissions=(), intent="")
    ids = [p["id"] for p in derive_prerequisites("gov-empty-perms")["prerequisites"]]
    assert "PR-PERMS" not in ids
    assert "PR-INTENT" not in ids  # empty intent → no intent scope derived


def test_derive_critical_blast_gets_gate():
    _register("gov-blast-1", blast_level="CRITICAL", blast_score=80)
    ids = [p["id"] for p in derive_prerequisites("gov-blast-1")["prerequisites"]]
    assert "PR-BLAST" in ids
    blast_pr = next(p for p in derive_prerequisites("gov-blast-1")["prerequisites"]
                    if p["id"] == "PR-BLAST")
    assert "export_data" in blast_pr["rule"]["sensitive_tools"]


def test_derive_malformed_context_json_is_tolerated():
    _register("gov-bad-json")
    # Corrupt the recorded context the way a partial write could
    db.get_connection().execute(
        "UPDATE agents SET declared_permissions='not-json{{', "
        "downstream_agents='[broken' WHERE agent_id=?", ("gov-bad-json",))
    db.get_connection().commit()
    profile = derive_prerequisites("gov-bad-json")  # must not raise
    assert profile["prerequisites"]  # invariants still present


# ── Persistence (register hook) ─────────────────────────────────────────────

def test_register_derivation_persists():
    _register("gov-persist-1")
    profile = register_derivation("gov-persist-1")
    row = db.get_governance_db("gov-persist-1")
    assert row is not None
    assert json.loads(row["prerequisites"]) == profile["prerequisites"]
    assert row["source"] == "derived" and row["version"] == 1
    # Round-trip through get_profile returns the same data
    again = gov.get_profile("gov-persist-1")
    assert [p["id"] for p in again["prerequisites"]] == \
           [p["id"] for p in profile["prerequisites"]]


# ── Evaluation (hot path) ───────────────────────────────────────────────────

def test_evaluate_in_scope_all_satisfied():
    _register("gov-eval-1")
    register_derivation("gov-eval-1")
    out = evaluate_prerequisites("gov-eval-1", "read_ticket", {})
    assert out["status"] == "evaluated"
    by_id = {r["id"]: r for r in out["prerequisites"]}
    assert by_id["PR-TOKEN"]["satisfied"] is True
    assert by_id["PR-ISOLATED"]["satisfied"] is True
    assert by_id["PR-SANDBOX"]["satisfied"] is True
    assert by_id["PR-TRUST"]["satisfied"] is True
    assert by_id["PR-INTENT"]["satisfied"] is True
    assert by_id["PR-PERMS"]["satisfied"] is True
    assert out["unsatisfied"] == 0 and out["blocking"] == []


def test_evaluate_forbidden_tool_unsatisfied():
    _register("gov-eval-2")
    register_derivation("gov-eval-2")
    out = evaluate_prerequisites("gov-eval-2", "run_command", {})
    by_id = {r["id"]: r for r in out["prerequisites"]}
    assert by_id["PR-INTENT"]["satisfied"] is False
    assert "forbidden" in by_id["PR-INTENT"]["reason"]
    assert by_id["PR-PERMS"]["satisfied"] is False  # not in declared permissions either
    assert out["unsatisfied"] == 2
    # Derived entries are surface-only by default → no enforcement
    assert out["blocking"] == []


def test_evaluate_out_of_scope_tool():
    _register("gov-eval-3", permissions=())  # no permission override
    register_derivation("gov-eval-3")
    out = evaluate_prerequisites("gov-eval-3", "export_data", {})
    intent = next(r for r in out["prerequisites"] if r["id"] == "PR-INTENT")
    assert intent["satisfied"] is False
    assert "outside" in intent["reason"]


def test_evaluate_low_trust_and_sandboxed():
    _register("gov-eval-4")
    register_derivation("gov-eval-4")
    # Force the live state the way a risky history would
    from engine.trust_score.trust_engine import get_or_create_profile
    prof = get_or_create_profile("gov-eval-4")
    prof.trust_score = 20.0
    prof.is_sandboxed = True
    prof.sandbox_reason = "trust containment"
    out = evaluate_prerequisites("gov-eval-4", "read_ticket", {})
    by_id = {r["id"]: r for r in out["prerequisites"]}
    assert by_id["PR-TRUST"]["satisfied"] is False
    assert "20 < 40" in by_id["PR-TRUST"]["reason"]
    assert by_id["PR-SANDBOX"]["satisfied"] is False


def test_evaluate_never_raises_on_garbage_profile():
    _register("gov-garbage")
    register_derivation("gov-garbage")
    # Inject malformed entries directly into the cached profile
    prof = gov.get_profile("gov-garbage")
    prof["prerequisites"].append({"id": "PR-BROKEN"})          # no kind
    prof["prerequisites"].append({"id": "PR-BADCHECK", "kind": "custom"})
    out = evaluate_prerequisites("gov-garbage", "read_ticket", {})
    assert out["status"] in ("evaluated", "degraded")
    assert isinstance(out.get("prerequisites"), list)


def test_evaluate_hot_path_is_fast():
    import time
    _register("gov-fast")
    register_derivation("gov-fast")
    t0 = time.perf_counter()
    for _ in range(200):
        evaluate_prerequisites("gov-fast", "read_ticket", {"a": 1})
    dt = (time.perf_counter() - t0) / 200
    assert dt < 0.005, f"hot-path evaluation too slow: {dt*1000:.2f} ms"


# ── Editing (validated + audited) ───────────────────────────────────────────

def test_edit_add_custom_succeeds_and_persists():
    _register("gov-edit-1")
    register_derivation("gov-edit-1")
    audits = []
    new = apply_edits(
        "gov-edit-1",
        {"add_custom": [{
            "label": "Data residency EU only",
            "description": "Compliance: exports must target EU buckets",
            "severity": "BLOCK",
            "check": {"type": "param_equals", "pairs": {"region": "eu"}},
        }]},
        actor="ops@example.com",
        audit=audits.append,
    )
    custom = [p for p in new["prerequisites"] if p["kind"] == "custom"]
    assert len(custom) == 1
    assert custom[0]["id"] == "PR-CUST-1"
    assert custom[0]["enforce"] is True
    assert new["version"] == 2
    assert new["source"] == "derived+edited"
    # Persisted + audited
    row = db.get_governance_db("gov-edit-1")
    assert row["version"] == 2 and row["updated_by"] == "ops@example.com"
    assert any(a["event_type"] == "GOVERNANCE_UPDATED" for a in audits)


def test_custom_prerequisite_enforces_on_calls():
    _register("gov-edit-2")
    register_derivation("gov-edit-2")
    apply_edits(
        "gov-edit-2",
        {"add_custom": [{
            "label": "EU residency",
            "check": {"type": "param_equals", "pairs": {"region": "eu"}},
        }]},
        actor="ops",
    )
    ok = evaluate_prerequisites("gov-edit-2", "export_data", {"region": "eu"})
    assert all(r["satisfied"] or r["id"] != "PR-CUST-1" for r in ok["prerequisites"])
    bad = evaluate_prerequisites("gov-edit-2", "export_data", {"region": "us"})
    cust = next(r for r in bad["prerequisites"] if r["id"] == "PR-CUST-1")
    assert cust["satisfied"] is False and cust["enforce"] is True
    assert "PR-CUST-1" in bad["blocking"]


def test_edit_remove_custom_succeeds():
    _register("gov-edit-3")
    register_derivation("gov-edit-3")
    apply_edits("gov-edit-3",
                {"add_custom": [{"label": "x",
                                 "check": {"type": "param_present", "keys": ["k"]}}]},
                actor="ops")
    new = apply_edits("gov-edit-3", {"remove": ["PR-CUST-1"]}, actor="ops")
    assert all(p["id"] != "PR-CUST-1" for p in new["prerequisites"])
    assert new["version"] == 3


def test_edit_remove_derived_rejected():
    _register("gov-edit-4")
    register_derivation("gov-edit-4")
    audits = []
    with pytest.raises(GovernanceEditError):
        apply_edits("gov-edit-4", {"remove": ["PR-TRUST"]}, actor="ops",
                    audit=audits.append)
    with pytest.raises(GovernanceEditError):
        apply_edits("gov-edit-4", {"remove": ["PR-TOKEN"]}, actor="ops")
    # State unchanged
    assert len(gov.get_profile("gov-edit-4")["prerequisites"]) == 6


def test_edit_update_locked_invariant_rejected():
    _register("gov-edit-5")
    register_derivation("gov-edit-5")
    with pytest.raises(GovernanceEditError):
        apply_edits("gov-edit-5",
                    {"update": [{"id": "PR-TOKEN", "enforce": False}]},
                    actor="ops")
    with pytest.raises(GovernanceEditError):
        apply_edits("gov-edit-5",
                    {"update": [{"id": "PR-ISOLATED", "severity": "FLAG"}]},
                    actor="ops")


def test_edit_update_derived_allowed():
    _register("gov-edit-6")
    register_derivation("gov-edit-6")
    new = apply_edits("gov-edit-6",
                      {"update": [{"id": "PR-TRUST", "severity": "FLAG"}]},
                      actor="ops")
    trust_pr = next(p for p in new["prerequisites"] if p["id"] == "PR-TRUST")
    assert trust_pr["severity"] == "FLAG"


def test_edit_bad_checks_rejected():
    _register("gov-edit-7")
    register_derivation("gov-edit-7")
    bad_bodies = [
        {"add_custom": [{"label": "x", "check": {"type": "exec_code", "pairs": {}}}]},
        {"add_custom": [{"label": "x", "check": {"type": "param_equals", "pairs": {}}}]},
        {"add_custom": [{"label": "", "check": {"type": "param_present", "keys": ["k"]}}]},
        {"add_custom": [{"label": "x", "check": {"type": "param_in", "pairs": {"k": []}}}]},
        {"add_custom": [{"label": "x", "check": "not-a-dict"}]},
        {"add_custom": [{"label": "x", "check": {"type": "param_present", "keys": []}}]},
    ]
    for body in bad_bodies:
        with pytest.raises(GovernanceEditError):
            apply_edits("gov-edit-7", body, actor="ops")
    assert all(p["kind"] != "custom"
               for p in gov.get_profile("gov-edit-7")["prerequisites"])


def test_edit_requires_actor():
    _register("gov-edit-8")
    register_derivation("gov-edit-8")
    with pytest.raises(GovernanceEditError):
        apply_edits("gov-edit-8",
                    {"add_custom": [{"label": "x",
                                     "check": {"type": "param_present", "keys": ["k"]}}]},
                    actor="   ")
    with pytest.raises(GovernanceEditError):
        apply_edits("gov-edit-8", {}, actor="ops")


def test_edit_version_conflict():
    _register("gov-edit-9")
    register_derivation("gov-edit-9")
    apply_edits("gov-edit-9",
                {"add_custom": [{"label": "a",
                                 "check": {"type": "param_present", "keys": ["k"]}}]},
                actor="ops")
    with pytest.raises(ValueError):
        apply_edits("gov-edit-9",
                    {"add_custom": [{"label": "b",
                                     "check": {"type": "param_present", "keys": ["k"]}}]},
                    actor="ops", expected_version=1)  # stale
    # Correct version proceeds
    new = apply_edits("gov-edit-9",
                      {"add_custom": [{"label": "b",
                                       "check": {"type": "param_present", "keys": ["k"]}}]},
                      actor="ops", expected_version=2)
    assert new["version"] == 3


def test_edit_unknown_agent_rejected_cleanly():
    # An agent with no recorded context cannot be edited (the API returns
    # 404 first) — the engine must fail with a clear operator-facing error,
    # not a raw database error (production: referential integrity holds).
    with pytest.raises(GovernanceEditError, match="no recorded context"):
        apply_edits("gov-never-registered",
                    {"add_custom": [{"label": "x",
                                     "check": {"type": "param_present", "keys": ["k"]}}]},
                    actor="ops")


# ── Check interpreter (param_in / param_present) ────────────────────────────

def test_check_interpreter_variants():
    _register("gov-checks")
    register_derivation("gov-checks")
    apply_edits("gov-checks", {
        "add_custom": [
            {"label": "env", "check": {"type": "param_in", "pairs": {"env": ["prod", "staging"]}}},
            {"label": "needs ticket", "check": {"type": "param_present", "keys": ["ticket_id"]}},
        ],
    }, actor="ops")

    out = evaluate_prerequisites("gov-checks", "read_ticket",
                                 {"env": "prod", "ticket_id": "T-1"})
    assert out["unsatisfied"] == 0

    out2 = evaluate_prerequisites("gov-checks", "read_ticket", {"env": "dev"})
    cust_ids = [r["id"] for r in out2["prerequisites"] if not r["satisfied"]]
    assert "PR-CUST-1" in cust_ids and "PR-CUST-2" in cust_ids

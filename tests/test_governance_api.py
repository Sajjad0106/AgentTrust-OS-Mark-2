"""
Proxy-level (HTTP) tests for the governance endpoints — pin the exact
status-code semantics at the API boundary:

  GET  /agents/{id}/governance   200 profile+live_state · 404 unknown agent
  PUT  /agents/{id}/governance   200 ok · 404 unknown · 409 stale version ·
                                 422 validation rejection (invariants locked,
                                 derived entries protected, bad checks)

Runs against an ISOLATED temp database; the FastAPI app is exercised
in-process via TestClient (no live server needed).
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import infrastructure.database as db  # noqa: E402
from engine.governance import governance_engine as gov  # noqa: E402


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "gov_api_test.db"))
    db.init_db()
    gov._cache.clear()
    from fastapi.testclient import TestClient
    import proxy.main as pm
    with TestClient(pm.app) as c:
        yield c
    gov._cache.clear()


def _register(client, agent_id):
    r = client.post("/agents/register", json={
        "agent_id": agent_id,
        "name": agent_id,
        "declared_intent": "customer support and help desk",
        "declared_permissions": ["read_ticket", "send_email"],
        "downstream_agents": [],
    })
    assert r.status_code == 200, r.text
    body = r.json()
    # registration response carries the derivation summary
    assert body["governance"]["prerequisites"] >= 5
    return agent_id


def test_register_derives_governance(client):
    agent_id = _register(client, "api-inv-1")
    r = client.get(f"/agents/{agent_id}/governance")
    assert r.status_code == 200
    body = r.json()
    ids = [p["id"] for p in body["profile"]["prerequisites"]]
    assert "PR-TOKEN" in ids and "PR-TRUST" in ids and "PR-INTENT" in ids
    # live_state evaluated the state-based prerequisites
    assert "PR-TOKEN" in body["live_state"]
    assert body["live_state"]["PR-TOKEN"]["satisfied"] is True


def test_get_unknown_agent_404(client):
    r = client.get("/agents/api-ghost/governance")
    assert r.status_code == 404


def test_put_remove_locked_invariant_422(client):
    agent_id = _register(client, "api-inv-2")
    for locked in ("PR-TOKEN", "PR-ISOLATED", "PR-SANDBOX"):
        r = client.put(f"/agents/{agent_id}/governance", json={
            "actor": "rogue", "edits": {"remove": [locked]}})
        assert r.status_code == 422, (locked, r.text)
        assert "error" in r.json()


def test_put_remove_derived_422(client):
    agent_id = _register(client, "api-inv-3")
    r = client.put(f"/agents/{agent_id}/governance", json={
        "actor": "rogue", "edits": {"remove": ["PR-TRUST"]}})
    assert r.status_code == 422


def test_put_version_conflict_409(client):
    agent_id = _register(client, "api-inv-4")
    ok = client.put(f"/agents/{agent_id}/governance", json={
        "actor": "ops",
        "edits": {"add_custom": [
            {"label": "x", "check": {"type": "param_present", "keys": ["k"]}}]}})
    assert ok.status_code == 200
    stale = client.put(f"/agents/{agent_id}/governance", json={
        "actor": "ops", "expected_version": 1,
        "edits": {"add_custom": [
            {"label": "y", "check": {"type": "param_present", "keys": ["k"]}}]}})
    assert stale.status_code == 409
    assert "version conflict" in stale.json()["error"]


def test_put_rejects_bad_check_422(client):
    agent_id = _register(client, "api-inv-5")
    r = client.put(f"/agents/{agent_id}/governance", json={
        "actor": "ops",
        "edits": {"add_custom": [
            {"label": "x", "check": {"type": "exec_code", "pairs": {}}}]}})
    assert r.status_code == 422


def test_put_requires_actor_422(client):
    agent_id = _register(client, "api-inv-6")
    r = client.put(f"/agents/{agent_id}/governance", json={
        "actor": "",
        "edits": {"add_custom": [
            {"label": "x", "check": {"type": "param_present", "keys": ["k"]}}]}})
    assert r.status_code == 422


def test_put_unknown_agent_404(client):
    r = client.put("/agents/api-ghost/governance", json={
        "actor": "ops",
        "edits": {"add_custom": [
            {"label": "x", "check": {"type": "param_present", "keys": ["k"]}}]}})
    assert r.status_code == 404


def test_put_edit_flow_and_audit(client):
    agent_id = _register(client, "api-inv-7")
    ok = client.put(f"/agents/{agent_id}/governance", json={
        "actor": "ops@example.com",
        "edits": {"add_custom": [
            {"label": "EU residency", "severity": "BLOCK",
             "check": {"type": "param_equals", "pairs": {"region": "eu"}}}]}})
    assert ok.status_code == 200
    profile = ok.json()["profile"]
    assert profile["version"] == 2 and profile["source"] == "derived+edited"
    custom = [p for p in profile["prerequisites"] if p["kind"] == "custom"]
    assert len(custom) == 1 and custom[0]["enforce"] is True

    # reflected in the audit chain (records wrap the payload under "event")
    from audit.verifier import get_audit_log
    events = [rec["event"] for rec in get_audit_log(100)
              if rec.get("event", {}).get("event_type") == "GOVERNANCE_UPDATED"
              and rec.get("event", {}).get("agent_id") == agent_id]
    assert events and events[-1]["actor"] == "ops@example.com"

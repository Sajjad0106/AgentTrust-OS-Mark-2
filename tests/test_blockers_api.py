"""
Proxy-level (HTTP) tests for the Blockers endpoint (Phase 2).

Pins the exact semantics at the API boundary:

  GET /agents/{id}/blockers
      200 — itemized live view {agent_id, status, blockers[], computed_at}
      404 — unknown agent (never 500, never a stale/stored state)

  Decision payload (POST /mcp/tools/call)
      every decision carries a `blockers` snapshot (call-level view)

  403 isolation guard response
      carries `blockers` (fresh — never a cached pre-action snapshot) in
      addition to the legacy `guard` fields

Runs against an ISOLATED temp database; the FastAPI app is exercised
in-process via TestClient (no live server needed).
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import infrastructure.database as db  # noqa: E402
from engine.governance import blocker_engine as be  # noqa: E402
from engine.governance import governance_engine as gov  # noqa: E402
from engine.approval import approval_engine as ae  # noqa: E402
from registry import agent_registry as reg  # noqa: E402


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "blockers_api_test.db"))
    db.init_db()
    be._cache.clear()
    gov._cache.clear()
    reg.ISOLATED_AGENTS.clear()
    ae.APPROVALS.clear()
    from fastapi.testclient import TestClient
    import proxy.main as pm
    with TestClient(pm.app) as c:
        yield c
    be._cache.clear()
    gov._cache.clear()
    reg.ISOLATED_AGENTS.clear()
    ae.APPROVALS.clear()


def _register(client, agent_id, intent="customer support", perms=None):
    r = client.post("/agents/register", json={
        "agent_id": agent_id,
        "name": agent_id,
        "declared_intent": intent,
        "declared_permissions": perms or ["read_ticket", "send_email"],
        "downstream_agents": [],
    })
    assert r.status_code == 200, r.text
    return r.json()["identity_token"]["token"]


def test_get_blockers_shape_and_clear(client):
    aid = "api-blk-1"
    _register(client, aid)
    r = client.get(f"/agents/{aid}/blockers")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "CLEAR"
    assert body["blockers"] == []
    assert body["agent_id"] == aid
    assert body["computed_at"]


def test_get_blockers_unknown_agent_404(client):
    r = client.get("/agents/api-blk-ghost/blockers")
    assert r.status_code == 404
    assert "error" in r.json()


def test_isolation_appears_and_clears_via_api(client):
    aid = "api-blk-2"
    _register(client, aid)
    r = client.post(f"/agents/isolate/{aid}", json={"reason": "API test isolation"})
    assert r.status_code == 200

    r = client.get(f"/agents/{aid}/blockers")
    body = r.json()
    assert body["status"] == "BLOCKED"
    iso = next(b for b in body["blockers"] if b["kind"] == "isolation")
    assert iso["severity"] == "hard"
    assert iso["clear_action"] == {"method": "POST", "endpoint": f"/agents/release/{aid}"}

    r = client.post(f"/agents/release/{aid}")
    assert r.status_code == 200
    r = client.get(f"/agents/{aid}/blockers")
    assert r.json()["status"] == "CLEAR"


def test_pending_approval_appears_as_soft(client):
    aid = "api-blk-3"
    _register(client, aid)
    apr = ae.create_approval(aid, "export_data", {"table": "salaries"}, "high risk")
    r = client.get(f"/agents/{aid}/blockers")
    body = r.json()
    b = next(x for x in body["blockers"] if x["kind"] == "approval")
    assert b["severity"] == "soft"
    assert b["clear_action"]["endpoint"] == f"/approvals/{apr['id']}/approve"
    assert body["status"] == "DEGRADED"  # soft only


def test_decision_payload_carries_blockers(client):
    aid = "api-blk-4"
    tok = _register(client, aid)
    r = client.post("/mcp/tools/call",
                    json={"tool": "read_ticket", "parameters": {"ticket": "T-1"}},
                    headers={"X-Agent-Token": tok})
    assert r.status_code == 200, r.text
    d = r.json()
    assert "blockers" in d
    assert d["blockers"]["agent_id"] == aid
    assert d["blockers"]["status"] in ("CLEAR", "DEGRADED", "BLOCKED")


def test_guard_403_carries_fresh_blockers(client):
    aid = "api-blk-5"
    tok = _register(client, aid)
    # poison the cache with a pre-isolation snapshot
    be.compute_blockers(aid, use_cache=True)
    assert be.compute_blockers(aid, use_cache=True)["status"] == "CLEAR"

    r = client.post(f"/agents/isolate/{aid}", json={"reason": "cache trap"})
    assert r.status_code == 200

    r = client.post("/mcp/tools/call",
                    json={"tool": "read_ticket", "parameters": {"ticket": "T-1"}},
                    headers={"X-Agent-Token": tok})
    assert r.status_code == 403
    g = r.json()
    assert "blockers" in g                      # new field
    assert g["action"] == "ISOLATED"            # legacy guard fields kept
    assert g["blockers"]["status"] == "BLOCKED"  # fresh, not the cached CLEAR
    iso = next(b for b in g["blockers"]["blockers"] if b["kind"] == "isolation")
    assert "cache trap" in iso["reason"]

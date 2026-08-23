"""
O1 + O2 (PHASE2_Blockers_Plan §Optional stretch) — the last two items of the
blockers roadmap.

O1 — ⛔ dot on BLOCKED agent rows:
      GET /dashboard/agents and GET /dashboard/summary annotate every agent
      with its live `blocker_status` (CLEAR / DEGRADED / BLOCKED / null).

O2 — WS push on blocker-state change:
      `BLOCKERS_CHANGED` is broadcast whenever a source of truth behind the
      derived blocker view changes: isolate / release / revoke / register /
      approve / reject / governance edit / trust containment transition.
      The pushed status is recomputed fresh (never from a stale cache).

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
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "blockers_o1o2_test.db"))
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
    return r.json()


def _drain_until(ws, event_type, timeout_msgs=10):
    """Receive WS messages until the first one of `event_type` (others, e.g.
    the preceding AGENT_ISOLATED broadcast, are consumed and ignored)."""
    for _ in range(timeout_msgs):
        ev = ws.receive_json()
        if ev.get("type") == event_type:
            return ev
    raise AssertionError(f"never received {event_type}")


# ────────────────────────────────────────────────────────────────────
# O1 — dashboard agent rows carry blocker_status
# ────────────────────────────────────────────────────────────────────

def test_o1_dashboard_agents_annotated(client):
    _register(client, "agent-o1")
    r = client.get("/dashboard/agents")
    assert r.status_code == 200
    agents = r.json()["agents"]
    mine = [a for a in agents if a["agent_id"] == "agent-o1"]
    assert len(mine) == 1
    assert mine[0]["blocker_status"] == "CLEAR"
    # EVERY agent row is annotated (not just the one we registered)
    assert all("blocker_status" in a for a in agents)


def test_o1_dashboard_summary_annotated(client):
    _register(client, "agent-o1s")
    r = client.get("/dashboard/summary")
    assert r.status_code == 200
    agents = r.json()["agents"]
    mine = [a for a in agents if a["agent_id"] == "agent-o1s"]
    assert len(mine) == 1
    assert mine[0]["blocker_status"] == "CLEAR"


def test_o1_isolated_agent_shows_blocked(client):
    _register(client, "agent-o1b")
    r = client.post("/agents/isolate/agent-o1b", json={"reason": "test"})
    assert r.status_code == 200

    agents = client.get("/dashboard/agents").json()["agents"]
    mine = [a for a in agents if a["agent_id"] == "agent-o1b"][0]
    assert mine["blocker_status"] == "BLOCKED"

    # release → back to CLEAR
    assert client.post("/agents/release/agent-o1b").status_code == 200
    agents = client.get("/dashboard/agents").json()["agents"]
    mine = [a for a in agents if a["agent_id"] == "agent-o1b"][0]
    assert mine["blocker_status"] == "CLEAR"


# ────────────────────────────────────────────────────────────────────
# O2 — BLOCKERS_CHANGED pushed on state change
# ────────────────────────────────────────────────────────────────────

def test_o2_isolate_and_release_push(client):
    _register(client, "agent-o2")
    with client.websocket_connect("/ws/threats") as ws:
        # connection ack first
        assert ws.receive_json()["type"] == "CONNECTION_ESTABLISHED"

        assert client.post("/agents/isolate/agent-o2",
                           json={"reason": "manual"}).status_code == 200
        ev = _drain_until(ws, "BLOCKERS_CHANGED")
        assert ev["agent_id"] == "agent-o2"
        assert ev["status"] == "BLOCKED"
        assert "BLK-ISOLATED" in ev["blocker_ids"]

        assert client.post("/agents/release/agent-o2").status_code == 200
        ev = _drain_until(ws, "BLOCKERS_CHANGED")
        assert ev["agent_id"] == "agent-o2"
        assert ev["status"] == "CLEAR"
        assert ev["blocker_ids"] == []


def test_o2_revoke_pushes_token_blocker(client):
    _register(client, "agent-o2r")
    with client.websocket_connect("/ws/threats") as ws:
        assert ws.receive_json()["type"] == "CONNECTION_ESTABLISHED"

        assert client.post("/agents/revoke/agent-o2r").status_code == 200
        ev = _drain_until(ws, "BLOCKERS_CHANGED")
        assert ev["agent_id"] == "agent-o2r"
        assert ev["status"] == "BLOCKED"
        assert "BLK-TOKEN" in ev["blocker_ids"]


def test_o2_push_is_fresh_not_cached(client):
    """The pushed status must reflect the post-action state even if a
    pre-action snapshot sits in the blocker engine's TTL cache."""
    _register(client, "agent-o2f")
    # warm the cache with a pre-action view
    be.compute_blockers("agent-o2f", use_cache=True)
    with client.websocket_connect("/ws/threats") as ws:
        assert ws.receive_json()["type"] == "CONNECTION_ESTABLISHED"
        assert client.post("/agents/isolate/agent-o2f",
                           json={"reason": "x"}).status_code == 200
        ev = _drain_until(ws, "BLOCKERS_CHANGED")
        assert ev["status"] == "BLOCKED"
        assert "BLK-ISOLATED" in ev["blocker_ids"]


def test_o2_emit_never_breaks_state_change(client):
    """Even if blocker computation blew up, the state-changing endpoint must
    still succeed (telemetry-only contract)."""
    _register(client, "agent-o2x")
    import proxy.main as pm

    def _boom(agent_id, use_cache=False):
        raise RuntimeError("synthetic blocker-engine failure")

    orig = pm.compute_blockers
    pm.compute_blockers = _boom
    try:
        r = client.post("/agents/isolate/agent-o2x", json={"reason": "y"})
    finally:
        pm.compute_blockers = orig
    assert r.status_code == 200
    assert client.post("/agents/release/agent-o2x").status_code == 200
    # sanity: engine restored → view is consistent again
    assert be.compute_blockers("agent-o2x", use_cache=False)["status"] == "CLEAR"

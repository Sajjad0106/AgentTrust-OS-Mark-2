"""
Proxy-level (HTTP) tests for the Downstream Effects endpoint (Phase 3).

Pins the exact semantics at the API boundary:

  GET /agents/{id}/effects
      200 — consumer table {agent_id, status, consumers[], systemic[]}
      404 — unknown agent (never 500)

  Decision payload (POST /mcp/tools/call)
      every decision carries an `effects` snapshot (per-call view)

  D3 advisory at the HTTP layer (stricter-only, asserted end-to-end):
      ALLOWED + quarantined consumer  → FLAGGED + advisory_applied
      FLAGGED + quarantined consumer  → stays FLAGGED, reason appended
      never BLOCKED by the advisory; never de-escalates; never touches trust
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import infrastructure.database as db  # noqa: E402
from engine.governance import effects_engine as ee  # noqa: E402
from engine.governance import governance_engine as gov  # noqa: E402
from registry import agent_registry as reg  # noqa: E402


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "effects_api_test.db"))
    db.init_db()
    ee._cache.clear()
    gov._cache.clear()
    reg.ISOLATED_AGENTS.clear()
    from fastapi.testclient import TestClient
    import proxy.main as pm
    with TestClient(pm.app) as c:
        yield c
    ee._cache.clear()
    gov._cache.clear()
    reg.ISOLATED_AGENTS.clear()


def _register(client, agent_id, downstream=None, intent="support customer queries", perms=None):
    r = client.post("/agents/register", json={
        "agent_id": agent_id,
        "name": agent_id,
        "declared_intent": intent,
        "declared_permissions": perms or ["read_ticket"],
        "downstream_agents": downstream or [],
    })
    assert r.status_code == 200, r.text
    return r.json()["identity_token"]["token"]


def test_get_effects_shape_no_consumers(client):
    _register(client, "fxa-1")
    r = client.get("/agents/fxa-1/effects")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "NO_CONSUMERS"
    assert body["consumers"] == []
    assert body["computed_at"]
    assert any(s["type"] == "audit_trail" for s in body["systemic"])


def test_get_effects_unknown_agent_404(client):
    r = client.get("/agents/fxa-ghost/effects")
    assert r.status_code == 404
    assert "error" in r.json()


def test_get_effects_consumer_table(client):
    _register(client, "fxa-cons-1")
    _register(client, "fxa-prod-1", downstream=["fxa-cons-1"])
    r = client.get("/agents/fxa-prod-1/effects")
    body = r.json()
    assert body["status"] == "HEALTHY_CHAIN"
    c = body["consumers"][0]
    assert c["id"] == "fxa-cons-1"
    assert c["impact_class"] == "HEALTHY"
    assert c["trust_score"] == 100.0


def test_decision_payload_carries_effects(client):
    tok = _register(client, "fxa-2")
    r = client.post("/mcp/tools/call",
                    json={"tool": "read_ticket", "parameters": {"ticket": "T-1"}},
                    headers={"X-Agent-Token": tok})
    assert r.status_code == 200, r.text
    d = r.json()
    assert "effects" in d
    assert d["effects"]["agent_id"] == "fxa-2"
    assert d["effects"]["status"] in ("NO_CONSUMERS", "HEALTHY_CHAIN", "DEGRADED", "QUARANTINED")
    assert "action" in d["effects"] and "impact" in d["effects"]


def test_d3_advisory_allowed_to_flagged_via_http(client):
    _register(client, "fxa-cons-3")
    tok = _register(client, "fxa-prod-3", downstream=["fxa-cons-3"])

    # baseline: healthy consumer → ALLOWED, no advisory
    d = client.post("/mcp/tools/call",
                    json={"tool": "read_ticket", "parameters": {"ticket": "T-1"}},
                    headers={"X-Agent-Token": tok}).json()
    assert d["action"] == "ALLOWED"
    assert d["effects"].get("advisory_applied") in (None, False)

    # quarantine the consumer
    assert client.post("/agents/isolate/fxa-cons-3", json={"reason": "q"}).status_code == 200

    # same call → FLAGGED by the advisory (stricter-only)
    d = client.post("/mcp/tools/call",
                    json={"tool": "read_ticket", "parameters": {"ticket": "T-1"}},
                    headers={"X-Agent-Token": tok}).json()
    assert d["action"] == "FLAGGED"
    assert d["effects"].get("advisory_applied") is True
    assert any("QUARANTINED" in r for r in d["flag_reasons"])
    # stricter-only: the advisory never BLOCKs
    assert d["block_reasons"] == []
    # never touches trust
    assert d["trust_score"] == 100.0

    # release → back to ALLOWED
    assert client.post("/agents/release/fxa-cons-3").status_code == 200
    d = client.post("/mcp/tools/call",
                    json={"tool": "read_ticket", "parameters": {"ticket": "T-1"}},
                    headers={"X-Agent-Token": tok}).json()
    assert d["action"] == "ALLOWED"


def test_d3_reason_appended_to_existing_flag(client):
    """Refined D3: a call already FLAGGED (intent gap) with a quarantined
    consumer keeps its original reason AND gains the downstream reason."""
    _register(client, "fxa-cons-4")
    tok = _register(client, "fxa-prod-4", downstream=["fxa-cons-4"],
                    intent="support customer queries", perms=["read_ticket"])
    client.post("/agents/isolate/fxa-cons-4", json={"reason": "q"})
    # query_db is outside the support intent → intent-gap FLAG (not BLOCK)
    d = client.post("/mcp/tools/call",
                    json={"tool": "query_db", "parameters": {"sql": "SELECT 1"}},
                    headers={"X-Agent-Token": tok}).json()
    assert d["action"] == "FLAGGED"
    assert any("Intent gap" in r for r in d["flag_reasons"])
    assert any("QUARANTINED" in r for r in d["flag_reasons"])
    assert d["effects"].get("advisory_applied") is True

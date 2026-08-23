#!/usr/bin/env python3
"""
AgentTrust OS — Phase 3 Live Demo: DOWNSTREAM EFFECTS

Demonstrates the live "what happens if it runs" view end-to-end against the
running server (default http://localhost:8010):

  CASE 1 — Normal case: producer agent with a healthy declared downstream
           consumer → ALLOWED, effects list the consumer (HEALTHY) + the
           audit-trail systemic effect.
  CASE 2 — Exception case: the CONSUMER is quarantined (isolated) → the same
           call is escalated ALLOWED → FLAGGED by the D3 advisory ("feeding a
           quarantined agent requires human review") — stricter-only, audited.
  CASE 3 — Unblock: release the consumer → view recomputes live → ALLOWED
           again (the advisory is state, not a stored flag).
  CASE 4 — Blocked case: a denied action shows the consequence rows —
           consumers starved + trust-feedback loop.

Run:  python demo_agent/effects_demo.py
"""

import json
import sys
import time
import urllib.request
import urllib.error
import uuid

BASE = "http://localhost:8010"


def api(method, path, body=None, token=None):
    url = BASE + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("X-Agent-Token", token)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or "{}")


def line(s=""):
    print(s, flush=True)


def main():
    run = int(time.time()) % 100000
    producer = f"fx-demo-producer-{run}"
    consumer = f"fx-demo-consumer-{run}"

    line("=" * 74)
    line("PHASE 3 DEMO — DOWNSTREAM EFFECTS (live \"what happens if it runs\")")
    line("=" * 74)

    # declared context: producer → consumer (the only stored input)
    api("POST", "/agents/register", {
        "name": "Fx Demo Consumer", "agent_id": consumer,
        "declared_intent": "compile customer reports",
        "declared_permissions": ["read_file"],
        "downstream_agents": [], "blast_radius": {"score": 10, "level": "LOW"},
    })
    _, reg = api("POST", "/agents/register", {
        "name": "Fx Demo Producer", "agent_id": producer,
        "declared_intent": "support customer queries",
        "declared_permissions": ["read_ticket"],
        "downstream_agents": [consumer],
        "blast_radius": {"score": 10, "level": "LOW"},
    })
    tok = reg["identity_token"]["token"]

    # ────────────────────────────────────────────────────────────────────
    line("\nCASE 1 — NORMAL: healthy declared chain")
    line("-" * 74)
    _, v = api("GET", f"/agents/{producer}/effects")
    line(f"  view: {v['status']}")
    for c in v["consumers"]:
        line(f"    [{c['impact_class']}] {c['id']} (trust {c['trust_score']}) — {c['note'][:60]}")
    assert v["status"] == "HEALTHY_CHAIN"
    _, d = api("POST", "/mcp/tools/call",
               {"tool": "read_ticket", "parameters": {"ticket": "T-1"}}, token=tok)
    line(f"\n  call read_ticket → {d['action']}")
    line(f"  effects: {d['effects'].get('impact')}")
    assert d["action"] == "ALLOWED"
    assert not d["effects"].get("advisory_applied")

    # ────────────────────────────────────────────────────────────────────
    line("\nCASE 2 — EXCEPTION: the CONSUMER is quarantined (isolated)")
    line("-" * 74)
    api("POST", f"/agents/isolate/{consumer}", {"reason": "compromised report pipeline"})
    _, v = api("GET", f"/agents/{producer}/effects")
    line(f"  view: {v['status']} — consumer: {v['consumers'][0]['impact_class']}")
    assert v["status"] == "QUARANTINED"

    _, d = api("POST", "/mcp/tools/call",
               {"tool": "read_ticket", "parameters": {"ticket": "T-1"}}, token=tok)
    line(f"\n  same call now → {d['action']} (advisory_applied={d['effects'].get('advisory_applied')})")
    for r in d.get("flag_reasons", []):
        line(f"    flag: {r}")
    assert d["action"] == "FLAGGED"
    assert d["effects"].get("advisory_applied") is True
    line("  ✓ D3 advisory: stricter-only escalation for human review, audited")

    # ────────────────────────────────────────────────────────────────────
    line("\nCASE 3 — UNBLOCK: human releases the consumer")
    line("-" * 74)
    api("POST", f"/agents/release/{consumer}")
    _, v = api("GET", f"/agents/{producer}/effects")
    line(f"  view: {v['status']} — consumer: {v['consumers'][0]['impact_class']}")
    _, d = api("POST", "/mcp/tools/call",
               {"tool": "read_ticket", "parameters": {"ticket": "T-1"}}, token=tok)
    line(f"  same call now → {d['action']} (advisory_applied={d['effects'].get('advisory_applied')})")
    assert v["status"] == "HEALTHY_CHAIN" and d["action"] == "ALLOWED"
    line("  ✓ the advisory is live state — it disappears when the state does")

    # ────────────────────────────────────────────────────────────────────
    line("\nCASE 4 — BLOCKED CALL: consequence rows (starvation + trust feedback)")
    line("-" * 74)
    _, d = api("POST", "/mcp/tools/call",
               {"tool": "run_command", "parameters": {"command": "ls /"}}, token=tok)
    line(f"  call run_command (outside declared intent) → {d['action']}")
    fx = d["effects"]
    line(f"  impact: {fx.get('impact')}")
    for s in fx.get("systemic", []):
        line(f"    systemic[{s['type']}]: {s['note'][:80]}")
    assert d["action"] == "BLOCKED"
    assert "starved" in fx.get("impact", "")
    assert any(s["type"] == "trust_feedback" for s in fx.get("systemic", []))
    line("  ✓ a denied action itemizes exactly what its consumers lose")

    line("\n" + "=" * 74)
    line("PHASE 3 DEMO COMPLETE — normal + exception + unblock + blocked, all live")
    line("=" * 74)


if __name__ == "__main__":
    try:
        main()
    except AssertionError as e:
        line(f"\nDEMO ASSERTION FAILED: {e}")
        sys.exit(1)

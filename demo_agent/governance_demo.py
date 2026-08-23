#!/usr/bin/env python3
"""
AgentTrust OS — Governance (Prerequisites) live demo

Demonstrates the prerequisites capability end-to-end against the RUNNING
system (the real 7-layer pipeline, real SQLite, real audit chain):

  CASE 1 — NORMAL          inventory-agent-01
    register agent → defaults derived from recorded context → in-scope call
    → all prerequisites satisfied → ALLOWED (decision unchanged)

  CASE 2A — EXCEPTION      scope-creep-agent-01
    out-of-scope call → derived prerequisites itemize WHY it's blocked
    (explainability; the 7 layers decide, governance explains)

  CASE 2B — EXCEPTION      inventory-agent-01 (clean state)
    operator adds a custom BLOCK prerequisite → previously-ALLOWED call
    becomes BLOCKED by the governance gate (real enforcement) → satisfied
    call is ALLOWED again

  CASE 2C — EXCEPTION      inventory-agent-01
    edit safety → removing a locked invariant / derived entry is REJECTED
    (422 + audit), a legitimate tuning edit is accepted (200 + audit)

Run:  python demo_agent/governance_demo.py
"""

import os
import time

import httpx

BASE = os.getenv("AGENTTRUST_PROXY", "http://localhost:8010")
# Fresh agent ids per run: trust history is cumulative + persistent by design,
# so a deterministic demo must start from a clean-slate agent each time.
RUN = time.strftime("%H%M%S")
INV_AGENT = f"demo-inventory-{RUN}"
SCOPE_AGENT = f"demo-scope-creep-{RUN}"


def hr(title):
    print(f"\n{'=' * 74}\n  {title}\n{'=' * 74}")


def show_prereqs(gov, indent="  "):
    for p in gov.get("prerequisites", []):
        mark = "✓" if p["satisfied"] else "✗"
        flag = " [ENFORCED]" if (not p["satisfied"] and p.get("enforce")) else ""
        print(f"{indent}{mark} {p['id']:<10} {p['label']} — {p['reason']}{flag}")


def register(c, agent_id, intent="customer support and help desk",
             permissions=("read_ticket", "send_email", "query_db"),
             downstream=("report-agent-02",)):
    reg = c.post("/agents/register", json={
        "agent_id": agent_id,
        "name": agent_id,
        "declared_intent": intent,
        "declared_permissions": list(permissions),
        "downstream_agents": list(downstream),
    }).json()
    return {"token": reg["identity_token"]["token"],
            "gov": reg["governance"]}


def main():
    c = httpx.Client(base_url=BASE, timeout=30)

    inv = register(c, INV_AGENT)
    H = {"X-Agent-Token": inv["token"]}

    # ═══════════════════════════════════════════════════════════════════════
    hr("CASE 1 — NORMAL: defaults derived from recorded context")
    # ═══════════════════════════════════════════════════════════════════════
    print(f"registered {INV_AGENT} → governance: "
          f"{inv['gov']['prerequisites']} prerequisites derived "
          f"({inv['gov']['status']})")

    gov = c.get(f"/agents/{INV_AGENT}/governance").json()
    print("\nprofile (derived from recorded context):")
    for p in gov["profile"]["prerequisites"]:
        src = "LOCKED" if p.get("editable") is False else "editable"
        live = gov["live_state"].get(p["id"])
        live_txt = (f" → live: {'PASS' if live and live['satisfied'] else 'FAIL'} "
                    f"({live['reason']})") if live else ""
        print(f"  {p['id']:<10} {p['label']}  [{src}]{live_txt}")

    r = c.post("/mcp/tools/call", headers=H, json={
        "tool": "read_ticket",
        "parameters": {"ticket_id": "T-1042", "query": "delivery status"},
    })
    d = r.json()
    print(f"\ncall read_ticket → HTTP {r.status_code} · action {d['action']} · "
          f"risk {d['risk_level']} · trust {d['trust_score']}")
    print("prerequisites on the decision payload:")
    show_prereqs(d["governance"])
    assert d["action"] == "ALLOWED", "normal case must be ALLOWED"
    assert d["governance"]["unsatisfied"] == 0
    print("→ all prerequisites satisfied, decision unchanged: ALLOWED ✓")

    # ═══════════════════════════════════════════════════════════════════════
    hr("CASE 2A — EXCEPTION: out-of-scope call (explainability)")
    # ═══════════════════════════════════════════════════════════════════════
    sc = register(c, SCOPE_AGENT)
    HS = {"X-Agent-Token": sc["token"]}
    r = c.post("/mcp/tools/call", headers=HS, json={
        "tool": "run_command",
        "parameters": {"command": "ls -la /opt/finance"},
    })
    d = r.json()
    print(f"{SCOPE_AGENT} calls run_command → HTTP {r.status_code} · "
          f"action {d['action']} · risk {d.get('risk_level', '—')}")
    print("prerequisites itemize exactly why (derived, surface-only):")
    show_prereqs(d.get("governance", {}))
    assert any(not p["satisfied"]
               for p in d.get("governance", {}).get("prerequisites", []))

    # ═══════════════════════════════════════════════════════════════════════
    hr("CASE 2B — EXCEPTION: custom prerequisite enforced (real gate)")
    # ═══════════════════════════════════════════════════════════════════════
    put = c.put(f"/agents/{INV_AGENT}/governance", json={
        "actor": "compliance-officer",
        "edits": {"add_custom": [{
            "label": "EU data residency (compliance)",
            "description": "Emails containing customer data must target EU endpoints",
            "severity": "BLOCK",
            "enforce": True,
            "check": {"type": "param_equals", "pairs": {"region": "eu"}},
        }]},
    })
    print(f"PUT add_custom 'EU data residency' → HTTP {put.status_code} · "
          f"version now {put.json()['profile']['version']}")
    assert put.status_code == 200

    r1 = c.post("/mcp/tools/call", headers=H, json={
        "tool": "send_email",
        "parameters": {"to": "customer@example.com", "subject": "status",
                       "region": "us"},
    })
    d1 = r1.json()
    print(f"\nsend_email(region=us) → HTTP {r1.status_code} · action {d1['action']}")
    show_prereqs(d1.get("governance", {}))
    for b in d1.get("block_reasons", []):
        print(f"  block_reason: {b}")
    assert d1["action"] in ("BLOCKED", "ISOLATED"), "custom gate must block"
    assert d1["action"] == "BLOCKED", \
        f"expected clean BLOCK by custom gate, got {d1['action']}"
    assert any("PR-CUST-1" in b for b in d1.get("block_reasons", [])), \
        "custom prerequisite must be in block reasons"

    r2 = c.post("/mcp/tools/call", headers=H, json={
        "tool": "send_email",
        "parameters": {"to": "customer@example.com", "subject": "status",
                       "region": "eu"},
    })
    d2 = r2.json()
    print(f"\nsend_email(region=eu) → HTTP {r2.status_code} · action {d2['action']}")
    assert d2["action"] == "ALLOWED", \
        f"expected ALLOWED once satisfied, got {d2['action']}"
    print("→ same call ALLOWED once the prerequisite is satisfied ✓")

    # ═══════════════════════════════════════════════════════════════════════
    hr("CASE 2C — EXCEPTION: edit safety (invariants locked, audited)")
    # ═══════════════════════════════════════════════════════════════════════
    bad1 = c.put(f"/agents/{INV_AGENT}/governance", json={
        "actor": "rogue-actor", "edits": {"remove": ["PR-TOKEN"]}})
    print(f"PUT remove PR-TOKEN (locked invariant) → HTTP {bad1.status_code}")
    print(f"  {bad1.json()['error']}")
    assert bad1.status_code == 422

    bad2 = c.put(f"/agents/{INV_AGENT}/governance", json={
        "actor": "rogue-actor", "edits": {"remove": ["PR-TRUST"]}})
    print(f"PUT remove PR-TRUST  (derived default)   → HTTP {bad2.status_code}")
    print(f"  {bad2.json()['error']}")
    assert bad2.status_code == 422

    good = c.put(f"/agents/{INV_AGENT}/governance", json={
        "actor": "compliance-officer",
        "edits": {"update": [{"id": "PR-TRUST", "severity": "FLAG"}]},
    })
    print(f"PUT update PR-TRUST severity → FLAG (legit) → HTTP {good.status_code} · "
          f"version now {good.json()['profile']['version']}")
    assert good.status_code == 200

    # audit trail proof
    logs = c.get("/dashboard/logs?limit=100").json()["logs"]
    gov_events = [l["event"] for l in logs
                  if l["event"].get("event_type") in
                  ("GOVERNANCE_UPDATED", "GOVERNANCE_EDIT_REJECTED")
                  and l["event"].get("agent_id") == INV_AGENT]
    print(f"\naudit chain now holds {len(gov_events)} governance event(s) for "
          f"{INV_AGENT}:")
    for e in gov_events[:6]:
        detail = (f"v{e['version']}: " + ", ".join(e.get("changes", [])[:3])
                  if "version" in e else e.get("reason", "")[:70])
        print(f"  {e['event_type']:<26} actor={e.get('actor')}  {detail}")

    print("\n" + "=" * 74)
    print("  DEMO COMPLETE — normal + exception cases verified live")
    print("=" * 74)


if __name__ == "__main__":
    main()

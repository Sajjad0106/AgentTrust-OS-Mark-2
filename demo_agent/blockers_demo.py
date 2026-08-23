#!/usr/bin/env python3
"""
AgentTrust OS — Phase 2 Live Demo: BLOCKERS

Demonstrates the live "why can't agent X act right now" view end-to-end
against the running server (default http://localhost:8010):

  CASE 1 — Normal case: healthy agent → status CLEAR, zero blockers,
           decision payload carries the blockers snapshot.
  CASE 2 — Exception case: agent hits a planted honeypot → auto-isolation +
           approval request → status BLOCKED with every active condition
           itemized (isolation / pending approval / trust floor / sandbox),
           each with its clear_hint + clear_action. The 403 guard response
           for the next call carries the same itemized view.
  CASE 3 — Unblock flow: human approves the pending approval and releases
           the agent → isolation + approval blockers clear; the view then
           honestly shows what REMAINS (trust floor + sandbox — trust
           recovery is behavioural, not manual).

Run:  python demo_agent/blockers_demo.py
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


def show_blockers(d, indent="  "):
    line(f"{indent}status: {d['status'].upper()}")
    for b in d.get("blockers", []):
        ca = b.get("clear_action")
        ca_s = f"{ca['method']} {ca['endpoint']}" if ca else "advisory"
        line(f"{indent}  [{b['severity']:4}] {b['reason']}")
        line(f"{indent}          ↳ clear via: {ca_s}")


def main():
    run = int(time.time()) % 100000
    healthy_id = f"blk-demo-healthy-{run}"
    rogue_id = f"blk-demo-rogue-{run}"

    line("=" * 74)
    line("PHASE 2 DEMO — BLOCKERS (live \"why can't this agent act right now\")")
    line("=" * 74)

    # ────────────────────────────────────────────────────────────────────
    line("\nCASE 1 — NORMAL: healthy agent, nothing blocking it")
    line("-" * 74)
    _, reg = api("POST", "/agents/register", {
        "name": "Blk Demo Healthy", "agent_id": healthy_id,
        "declared_intent": "support customer queries",
        "declared_permissions": ["read_ticket", "send_email"],
        "downstream_agents": [], "blast_radius": {"score": 10, "level": "LOW"},
    })
    tok = reg["identity_token"]["token"]
    _, v = api("GET", f"/agents/{healthy_id}/blockers")
    show_blockers(v)
    assert v["status"] == "CLEAR" and not v["blockers"], "healthy agent must be CLEAR"
    _, d = api("POST", "/mcp/tools/call",
               {"tool": "read_ticket", "parameters": {"ticket": "T-42"}}, token=tok)
    line(f"\n  call read_ticket → {d['action']}")
    line(f"  decision payload blockers → {d['blockers']['status']} ({len(d['blockers']['blockers'])} active)")
    assert d["blockers"]["status"] == "CLEAR"

    # ────────────────────────────────────────────────────────────────────
    line("\nCASE 2 — EXCEPTION: rogue agent touches a planted honeypot")
    line("-" * 74)
    _, reg = api("POST", "/agents/register", {
        "name": "Blk Demo Rogue", "agent_id": rogue_id,
        "declared_intent": "analyze company financial reports",
        "declared_permissions": ["read_file", "export_data"],
        "downstream_agents": [], "blast_radius": {"score": 90, "level": "CRITICAL"},
    })
    tok_r = reg["identity_token"]["token"]
    _, d = api("POST", "/mcp/tools/call",
               {"tool": "read_file", "parameters": {"path": "/opt/finance/payroll_export_2025.csv"}},
               token=tok_r)
    line(f"  call read_file(honeypot payroll decoy) → {d['action']} "
         f"(risk {d['risk_level']}, trust {d.get('trust_score')}, isolated={d.get('agent_isolated')})")
    assert d["agent_isolated"] is True, "honeypot hit must isolate the agent"
    apr = d.get("approval") or {}
    line(f"  approval request created: {apr.get('id')} — {apr.get('reason', '')[:70]}")

    line("\n  blockers view immediately after the hit:")
    _, v = api("GET", f"/agents/{rogue_id}/blockers")
    show_blockers(v)
    kinds = {b["kind"] for b in v["blockers"]}
    assert v["status"] == "BLOCKED", "must be BLOCKED"
    assert "isolation" in kinds, "isolation blocker missing"
    assert "approval" in kinds, "pending-approval blocker missing"
    # Honesty check: the view must claim a trust-floor violation only if it is
    # actually true (and vice versa) — never theatre.
    below_floor = d["trust_score"] < 40
    assert ("trust" in kinds) == below_floor, \
        f"view inconsistent: trust_floor present={'trust' in kinds} but trust={d['trust_score']}"
    line(f"  ✓ itemized {len(v['blockers'])} blockers, every one with a clear path,")
    line("    and consistent with the actual trust state (floor claimed only if truly below it)")

    line("\n  next call by the rogue agent (403 guard response carries blockers):")
    code, g = api("POST", "/mcp/tools/call",
                  {"tool": "read_file", "parameters": {"path": "/tmp/x"}}, token=tok_r)
    line(f"  HTTP {code} — guard blockers status: {g['blockers']['status']}")
    show_blockers(g["blockers"], indent="    ")
    assert code == 403 and g["blockers"]["status"] == "BLOCKED"

    # ────────────────────────────────────────────────────────────────────
    line("\nCASE 3 — UNBLOCK FLOW: human acts, view recomputes live")
    line("-" * 74)
    line(f"  1) approve {apr.get('id')}:")
    _, r = api("POST", f"/approvals/{apr['id']}/approve", {"decided_by": "demo-human"})
    line(f"     → {r.get('status', r.get('error', '?'))}")
    line("  2) release the agent:")
    _, r = api("POST", f"/agents/release/{rogue_id}")
    if r.get("status") == "not_isolated":
        line("     → already released (granting the approval auto-releases the agent)")
    else:
        line(f"     → {r}")
    line("\n  blockers view after the human acted:")
    _, v = api("GET", f"/agents/{rogue_id}/blockers")
    show_blockers(v)
    kinds = {b["kind"] for b in v["blockers"]}
    assert "isolation" not in kinds, "isolation must be cleared"
    assert "approval" not in kinds, "pending approval must be cleared"
    line("\n  ✓ isolation + pending approval cleared by real human actions.")
    if v["blockers"]:
        line(f"  ✓ status is now {v['status'].upper()} — whatever still degrades the agent")
        line("    (e.g. degraded trust after the attack) is shown honestly; trust")
        line("    recovery is behavioural, not a button, and the view never hides it.")
    else:
        line("  ✓ no residual conditions — agent is fully clear.")

    line("\n" + "=" * 74)
    line("PHASE 2 DEMO COMPLETE — normal + exception + unblock all verified live")
    line("=" * 74)


if __name__ == "__main__":
    try:
        main()
    except AssertionError as e:
        line(f"\nDEMO ASSERTION FAILED: {e}")
        sys.exit(1)

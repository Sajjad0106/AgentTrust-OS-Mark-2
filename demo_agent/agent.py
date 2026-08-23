"""
AgentTrust OS — Demo Agent (SDK)
PDF Demo Scenario (CodeQuest 2026, §6):

    Finance Agent receives: "Export employee salary database"

    1. Agent requests payroll data.
    2. SDK captures event.
    3. Policy Engine evaluates request.
    4. Behavioral Engine detects anomaly.
    5. Honeypot file is accessed.
    6. Threat generated.
    7. Agent isolated.
    8. Approval request created.
    9. Dashboard updates live.

    Output: Threat detected / Trust score reduced / Agent isolated / Audit record created
"""

import os
import httpx
import time
from typing import Any

PROXY = os.getenv("AGENTTRUST_PROXY", "http://localhost:8000")
token: str = ""


def llm_wait_for_reviews(agent_id: str, timeout: int = 1800) -> None:
    """Wait for the real local model's verdicts on this agent's calls and
    print them as they complete (≈90-120s per verdict on CPU)."""
    st = httpx.get(f"{PROXY}/llm/status", timeout=5).json()
    if not st["llm"]["available"]:
        print("   LLM second-opinion unavailable — heuristic-only mode.")
        print(f"   ({st['llm'].get('last_error') or 'llama-server not reachable'})")
        return
    print(f"   model: {st['llm']['model']} @ {st['llm']['url']}")
    print(f"   queue: {st['queued']}/{st['max_pending']} pending (≈90-120s each on CPU)")
    deadline = time.time() + timeout
    printed: set[str] = set()
    while time.time() < deadline:
        try:
            st    = httpx.get(f"{PROXY}/llm/status", timeout=5).json()
            revs  = httpx.get(f"{PROXY}/llm/reviews?agent_id={agent_id}&limit=50",
                              timeout=5).json()["reviews"]
        except Exception:
            time.sleep(10)
            continue
        for r in revs:
            if r["review_id"] in printed:
                continue
            if r["status"] in ("completed", "failed"):
                printed.add(r["review_id"])
                v = r.get("verdict") or {}
                if r["status"] == "completed":
                    agree = "agrees" if r.get("agreement") else "DISAGREES ↑"
                    print(f"   ✓ {r['tool']:18s} {v.get('risk_level'):8s} "
                          f"{v.get('risk_score')}/100  [{r['duration_s']}s, {agree}]")
                    print(f"       LLM: {v.get('reasoning')}  ({v.get('mitre_technique')})")
                    if r.get("escalated"):
                        print(f"       ▲ ESCALATED — agent isolated + approval opened")
                else:
                    print(f"   ✗ {r['tool']:18s} review failed — {r.get('error')}")
        in_flight = st.get("queued", 0)
        done_all  = len(printed) >= st.get("completed", len(printed)) and in_flight == 0
        if in_flight == 0 and printed:
            break
        print(f"   … {in_flight} review(s) still in flight "
              f"({len(printed)} verdict(s) so far)", flush=True)
        time.sleep(15)
    if not printed:
        print("   (no verdicts within timeout — check llama-server)")


def register(agent_id: str, name: str, intent: str, permissions: list[str]) -> None:
    global token
    r = httpx.post(f"{PROXY}/agents/register", json={
        "agent_id"             : agent_id,
        "name"                 : name,
        "declared_intent"      : intent,
        "declared_permissions" : permissions
    })
    data = r.json()
    token = data["identity_token"]["token"]
    print(f"\n✅ Registered  : {name}")
    print(f"   Token       : {token[:20]}...")
    print(f"   Blast Level : {data['agent']['blast_level']} (score {data['agent']['blast_score']}/100)")


def call_tool(step: str, tool: str, parameters: dict[str, Any]) -> dict[str, Any]:
    """SDK intercept: every tool call is captured by the AgentTrust proxy (PDF step 2)."""
    print(f"\n  [{step}] {tool} {parameters}")
    r = httpx.post(
        f"{PROXY}/mcp/tools/call",
        json={"tool": tool, "parameters": parameters},
        headers={"X-Agent-Token": token},
        timeout=10
    )
    d = r.json()
    print(f"      → Action     : {d.get('action')}")
    if d.get("risk_score") is None:
        print(f"      → {d.get('reason', 'Quarantined — call rejected before the pipeline.')}")
        time.sleep(0.3)
        return d
    print(f"      → Risk       : {d.get('risk_level')} ({d.get('risk_score')}/100)")
    print(f"      → Intent Gap : {d.get('intent_gap_level')} ({d.get('intent_gap_score')}/100)")
    print(f"      → Trust      : {d.get('trust_score')}/100")
    print(f"      → DNA Drift  : {d.get('dna_drift_score')}/100")
    print(f"      → Prediction : {d.get('prediction')} ({d.get('prediction_score')}/100)")
    print(f"      → Honeypot   : {'BREACH: ' + str(d.get('honeypot_asset', {}).get('path')) if d.get('honeypot_hit') else 'intact'}")
    if d.get("approval"):
        print(f"      → Approval   : {d['approval']['id']} created ({d['approval']['status']})")
    print(f"      → {d.get('decision_summary', '')}")
    time.sleep(0.3)
    return d


if __name__ == "__main__":
    print("\n" + "="*72)
    print("   AgentTrust OS — PDF Demo Scenario: Finance Agent")
    print(f"   Live dashboard: {PROXY}/ui")
    print("="*72)

    # ── Register finance agent ───────────────────────────────────────────────
    register(
        "finance-agent-01",
        "Enterprise Finance Agent",
        "process finance queries, payroll reports and expense summaries",
        ["query_database", "read_file", "export_data"]
    )

    baseline_trust = httpx.get(f"{PROXY}/agents/finance-agent-01").json()["trust"]["trust_score"]
    print(f"   Baseline trust  : {baseline_trust}/100")

    # ── Normal behavior — trust builds, DNA baseline forms ───────────────────
    print("\n" + "─"*72)
    print("   PHASE 1 — Normal behavior (agent does its declared job)")
    print("─"*72)
    call_tool("1", "query_database", {"query": "SELECT * FROM finance.quarterly_reports WHERE quarter='Q3'"})
    call_tool("2", "read_file",      {"path": "/reports/finance_summary_q3.pdf"})
    call_tool("3", "query_database", {"query": "SELECT department, total FROM expenses GROUP BY department"})

    # ── PDF steps 1–4: the agent is told to "Export employee salary database" ─
    print("\n" + "─"*72)
    print("   PHASE 2 — Finance Agent receives: 'Export employee salary database'")
    print("              (Policy Engine evaluates → Behavioral Engine detects anomaly)")
    print("─"*72)
    call_tool("4", "export_data", {"target": "employee_salary_database", "format": "sql", "scope": "all_departments"})

    # ── PDF steps 5–6: honeypot file accessed → threat generated ─────────────
    print("\n" + "─"*72)
    print("   PHASE 3 — Agent reaches for the planted honeypot payroll file")
    print("              (Honeypot breach → Threat generated)")
    print("─"*72)
    final = call_tool("5", "read_file", {"path": "/opt/finance/payroll_export_2025.csv"})

    # ── PDF step: post-isolation calls are rejected ──────────────────────────
    print("\n" + "─"*72)
    print("   PHASE 4 — Agent is isolated; further calls are quarantined")
    print("─"*72)
    call_tool("6", "query_database", {"query": "SELECT * FROM payroll"})

    # ── PDF Output verification ───────────────────────────────────────────────
    print("\n" + "="*72)
    print("   OUTPUT VERIFICATION (PDF §6 'Output')")
    print("="*72)

    agent   = httpx.get(f"{PROXY}/agents/finance-agent-01").json()
    iso     = httpx.get(f"{PROXY}/isolation").json()["isolated"]
    appr    = httpx.get(f"{PROXY}/approvals").json()
    hp      = httpx.get(f"{PROXY}/honeypots/detections").json()
    audit   = httpx.get(f"{PROXY}/audit/log?limit=5").json()["records"]
    chain   = httpx.get(f"{PROXY}/audit/verify").json()
    feed    = httpx.get(f"{PROXY}/dashboard/threats").json()["feed"]
    stats   = httpx.get(f"{PROXY}/system/stats").json()
    now_trust = agent["trust"]["trust_score"]

    print(f"""
  1. THREAT DETECTED
     · risk level        : {final.get('risk_level')} (score {final.get('risk_score')}/100)
     · threat tags       : {final.get('threat_tags')}
     · MITRE tactic      : {final.get('mitre_tactic')} ({final.get('mitre_technique')})
     · honeypot breach   : {hp['detections'][-1]['asset']['path'] if hp['detections'] else 'none'}
     · threat center     : {sum(1 for t in feed if t.get('agent_id')=='finance-agent-01')} event(s) for this agent

  2. TRUST SCORE REDUCED
     · before            : {baseline_trust}/100
     · after             : {now_trust}/100
     · containment level : {agent['trust']['containment_level']}
     · sandboxed         : {agent['trust']['is_sandboxed']}

  3. AGENT ISOLATED
     · isolation state   : {[i['reason'][:80] + '…' for i in iso if i['agent_id']=='finance-agent-01'] or 'not isolated'}
     · quarantined calls : rejected with 403 ISOLATED (see PHASE 4)

  4. AUDIT RECORD CREATED
     · last records      : {[ (r['sequence'], r['event'].get('event_type'), r['hash'][:12]+'…') for r in audit[-4:] ]}
     · chain integrity   : {chain['message']}

  5. APPROVAL REQUEST CREATED
     · pending approvals : {[(a['id'], a['agent_id'], a['status']) for a in appr['approvals']]}
     · human actions     : POST /approvals/<id>/approve  (releases agent)
                           POST /approvals/<id>/reject   (keeps isolation)

  6. DASHBOARD
     · live dashboard    : {PROXY}/ui
     · stats             : {stats}

  7. LLM SECOND OPINION (real local model via llama.cpp)
     · endpoint          : {PROXY}/llm/reviews?agent_id=finance-agent-01
     · live panel        : dashboard → “LLM Second Opinion”
""")

    # ── LLM Second Opinion — real model verdicts on every intercepted call ────
    print("\n" + "="*72)
    print("   PHASE 5 — LLM SECOND OPINION (real Qwen3.8-27B via llama.cpp)")
    print("   every intercepted call was queued for the local model —")
    print("   printing verdicts as the model finishes them…")
    print("="*72)
    llm_wait_for_reviews("finance-agent-01")

    print("\n" + "="*72)
    print("   Demo complete. Review the live dashboard or the endpoints above.")
    print("="*72)

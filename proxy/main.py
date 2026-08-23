import sys, os, json
from contextlib import asynccontextmanager
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import asyncio
from datetime import datetime, timezone
from typing import Any

# ── Core Proxy ─────────────────────────────────────────────────────────────────
from proxy.risk_engine                          import assess_risk, get_threat_library
from proxy.logger                               import log_decision

# ── Engine Layer ───────────────────────────────────────────────────────────────
from engine.trust_score.trust_engine            import update_trust_score, get_trust_summary, get_all_profiles
from engine.intent_gap.intent_engine            import analyze_intent_gap
from engine.dna.dna_engine                      import update_dna, get_dna_summary
from engine.threat_intel.threat_engine          import correlate_threat, get_threat_feed, THREAT_FEED, AGENT_THREAT_COUNT
from engine.adaptive_policy.evolution_engine    import observe_event, get_evolved_policies
from engine.predictive.sequence_engine          import update_sequence, get_sequence_summary
from engine.forensics.session_store             import record_event, get_all_sessions
from engine.forensics.replay_engine             import replay_session
from engine.honeypot.honeypot_engine            import check_honeypot_access, get_honeypot_assets, get_detections
from engine.approval.approval_engine            import create_approval, approve as approve_request, reject as reject_request, get_approvals, get_pending_approvals
from engine.llm_review.review_engine            import LLMReviewEngine
from infrastructure.llm                         import llm_status
from engine.governance.governance_engine        import (  # noqa: E402
    register_derivation as governance_register_derivation,
    evaluate_prerequisites,
    get_profile as governance_get_profile,
    apply_edits as governance_apply_edits,
    GovernanceEditError,
    _policy_trust_floor as policy_trust_floor,
)
from engine.governance.blocker_engine           import (  # noqa: E402
    compute_blockers,
    compute_call_blockers,
)
from engine.governance.effects_engine           import (  # noqa: E402
    compute_effects,
    compute_call_effects,
)

# ── Registry, Policy, Audit, Identity ─────────────────────────────────────────
from registry.agent_registry                    import register_agent, get_agent, get_all_agents, isolate_agent, release_agent, is_isolated, get_isolated_agents
from policy.engine                              import evaluate_policies
from policy.loader                              import load_policies
from audit.chain                                import append_audit
from audit.verifier                             import verify_chain, get_audit_log
from identity.token_engine                      import create_agent_token, authenticate_request, revoke_agent


# ──────────────────────────────────────────────────────────────────────────────
# App Lifespan
# ──────────────────────────────────────────────────────────────────────────────

# ──────────────────────────────────────────────────────────────────────
# LLM Second-Opinion Review Engine (async, llama.cpp)
# ──────────────────────────────────────────────────────────────────────

def _llm_review_complete(review: dict[str, Any]) -> None:
    """Audit hook: every finished review is written to the immutable chain."""
    append_audit({
        "event_type" : "LLM_REVIEW",
        "review_id"  : review["review_id"],
        "agent_id"   : review["agent_id"],
        "tool"       : review["tool"],
        "status"     : review["status"],
        "original_action" : review["original_action"],
        "verdict"    : review.get("verdict"),
        "agreement"  : review.get("agreement"),
        "escalated"  : review.get("escalated", False),
        "duration_s" : review.get("duration_s"),
        "error"      : review.get("error"),
    })

def _llm_review_escalate(agent_id: str, verdict: dict[str, Any]) -> None:
    """Retroactive escalation: the real model found HIGH/CRITICAL danger that
    the synchronous heuristics let through. Threat detected -> isolate ->
    approval request (the PDF's prevention flow, triggered by the LLM)."""
    reason = (
        f"LLM SECOND-OPINION ({verdict.get('model', 'local')}): "
        f"{verdict['risk_level']} {verdict['risk_score']}/100 — {verdict['reasoning']}"
    )
    # Threat Center entry so the dashboard shows the LLM-detected threat
    AGENT_THREAT_COUNT[agent_id] = AGENT_THREAT_COUNT.get(agent_id, 0) + 1
    THREAT_FEED.append({
        "threat_level"      : verdict["risk_level"],
        "agent_id"          : agent_id,
        "tool"              : "llm-review-escalation",
        "intent_gap"        : 0,
        "correlated_agents" : [],
        "agent_threat_count": AGENT_THREAT_COUNT[agent_id],
        "source"            : "llm-review",
        "reasoning"         : verdict["reasoning"],
        "mitre_technique"   : verdict.get("mitre_technique", "N/A"),
        "timestamp"         : datetime.now(timezone.utc).isoformat(),
    })
    append_audit({
        "event_type" : "LLM_THREAT_DETECTED",
        "agent_id"   : agent_id,
        "risk_level" : verdict["risk_level"],
        "reasoning"  : verdict["reasoning"],
        "mitre"      : verdict.get("mitre_technique", "N/A"),
    })
    if not is_isolated(agent_id):
        isolate_agent(agent_id, reason)
        append_audit({"event_type": "AGENT_ISOLATED", "agent_id": agent_id, "reason": reason})
        # O2: push the new blocker state (isolation + approval are live now).
        # This hook runs on the event loop inside the review worker, so the
        # emit is scheduled as a task; failures are swallowed inside emit.
        try:
            asyncio.get_running_loop().create_task(emit_blockers_changed(agent_id))
        except RuntimeError:
            pass
        approval = create_approval(
            agent_id     = agent_id,
            tool         = "llm-review-escalation",
            parameters   = {},
            reason       = f"Agent isolated on LLM second opinion: {reason}",
            decision_ref = {"risk_level": verdict["risk_level"], "source": "llm-review"},
        )
        append_audit({"event_type": "APPROVAL_CREATED", "agent_id": agent_id, "approval_id": approval["id"]})
    print(f"[LLMReview] ESCALATION for {agent_id}: {verdict['risk_level']} — {verdict['reasoning'][:100]}")

llm_review_engine = LLMReviewEngine(
    on_complete   = _llm_review_complete,
    on_escalation = _llm_review_escalate,
)


# ──────────────────────────────────────────────────────────────────────────────
# App Lifespan
# ──────────────────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    load_policies()
    await llm_review_engine.start()
    llm = llm_status()
    print("\n" + "="*65)
    print("   AgentTrust OS v5.1 — All Engines Loaded. System Ready.")
    print("   7-Layer Pipeline + Honeypot + Agent Isolation + Approval Workflow.")
    if llm["available"]:
        print(f"   LLM Second-Opinion: LIVE — {llm['model']} @ {llm['url']} (async)")
    else:
        print("   LLM Second-Opinion: OFFLINE — heuristic-only mode "
              f"({llm['last_error'] or 'llama-server not reachable'})")
    print("   Live dashboard: http://localhost:8000/ui")
    print("="*65 + "\n")
    yield


# ──────────────────────────────────────────────────────────────────────────────
# Timeout Configuration - Fail-Closed: timeouts trigger BLOCK
# ──────────────────────────────────────────────────────────────────────────────

TIMEOUT_CONFIG = {
    "risk_engine": 1.0,      # Layer 1: MITRE ATT&CK
    "intent_gap": 0.5,       # Layer 2: Intent Analysis
    "policy": 0.5,           # Layer 3: Policy Evaluation
    "dna": 0.5,              # Layer 4: DNA Fingerprinting
    "trust_score": 0.5,      # Layer 5: Trust Scoring
    "sequence": 0.5,         # Layer 6: Predictive Sequence
    "threat_correlation": 0.5,  # Layer 7: Threat Correlation
    "observation": 0.3,      # Non-blocking observation layers
}


class EngineTimeoutError(Exception):
    """Raised when an engine times out - treat as BLOCK (fail-closed)."""
    pass


# ──────────────────────────────────────────────────────────────────────────────
# App Initialization
# ──────────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title       = "AgentTrust OS",
    description = (
        "Real-Time Runtime Security & Governance Platform for Agentic AI. "
        "7-layer interception pipeline with MITRE ATT&CK mapping, Zero Trust identity, "
        "behavioral DNA fingerprinting, predictive threat sequencing, "
        "forensic session replay, adaptive policy evolution, and cryptographic audit chain."
    ),
    version     = "5.0.0",
    lifespan    = lifespan,
    docs_url    = "/docs",
    redoc_url   = "/redoc",
)

# CORS configuration - use environment variable for allowed origins
ALLOWED_ORIGINS = os.getenv(
    "ALLOWED_ORIGINS",
    "http://localhost:3000,http://localhost:3001"
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins  = ALLOWED_ORIGINS,
    allow_methods  = ["*"],
    allow_headers  = ["*"],
)


# ──────────────────────────────────────────────────────────────────────────────
# WebSocket Connection Pool
# ──────────────────────────────────────────────────────────────────────────────

_ws_clients: list[WebSocket] = []


async def broadcast(event: dict[str, Any]) -> None:
    """Broadcast threat events to all connected dashboard clients in real time."""
    dead: list[WebSocket] = []
    for ws in _ws_clients:
        try:
            await ws.send_json(event)
        except Exception:
            dead.append(ws)
    for ws in dead:
        if ws in _ws_clients:
            _ws_clients.remove(ws)


async def emit_blockers_changed(agent_id: str) -> None:
    """O2 (PHASE2_Blockers_Plan §Optional stretch) — push the agent's live
    blocker status to the dashboard the moment any source of truth behind it
    changes (isolate/release, revoke/register, approve/reject, governance
    edit, trust-containment transition).

    Blockers are DERIVED (never stored), so the pushed status is recomputed
    fresh (use_cache=False) — the push can never announce a stale state.
    Telemetry only: any failure is swallowed so a state-changing action is
    never broken by a notification.
    """
    try:
        view = compute_blockers(agent_id, use_cache=False)
        await broadcast({
            "type"        : "BLOCKERS_CHANGED",
            "agent_id"    : agent_id,
            "status"      : view.get("status"),
            "blocker_ids" : [b.get("id") for b in view.get("blockers", [])],
        })
    except Exception:
        pass


def _trust_blocker_sig(score, containment, sandboxed, floor: float):
    """The three facts that create or clear trust-derived blocker rows:
    sandbox flag, containment level, policy-floor breach. Used to detect
    transitions on the intercept hot path (O2)."""
    return (bool(sandboxed), str(containment or "NONE").upper(),
            float(score or 0.0) < floor)


# ──────────────────────────────────────────────────────────────────────────────
# Health & System Info
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/", tags=["System"])
async def root():
    return {
        "service"     : "AgentTrust OS",
        "version"     : "5.0.0",
        "status"      : "running",
        "description" : "Real-Time Runtime Security & Governance Platform for Agentic AI",
        "layers"      : [
            "Layer 1 — MITRE ATT&CK Risk Engine",
            "Layer 2 — Intent Gap Analysis",
            "Layer 3 — Policy-as-Code Evaluation",
            "Layer 4 — Behavioral DNA Fingerprinting",
            "Layer 5 — Trust Score Engine",
            "Layer 6 — Predictive Sequence Analysis",
            "Layer 7 — Cross-Agent Threat Correlation",
        ],
        "docs" : "/docs",
    }


@app.get("/health", tags=["System"])
async def health():
    return {
        "status"          : "healthy",
        "timestamp"       : datetime.now(timezone.utc).isoformat(),
        "ws_clients"      : len(_ws_clients),
    }


@app.get("/system/stats", tags=["System"])
async def system_stats():
    """Live system statistics — total agents, decisions, threat counts."""
    all_agents  = get_all_agents()
    audit_log   = get_audit_log(1000)
    threat_feed = get_threat_feed()

    total        = len(audit_log)
    blocked      = sum(1 for r in audit_log if r.get("event", {}).get("decision", {}).get("action") == "BLOCKED")
    flagged      = sum(1 for r in audit_log if r.get("event", {}).get("decision", {}).get("action") == "FLAGGED")
    allowed      = sum(1 for r in audit_log if r.get("event", {}).get("decision", {}).get("action") == "ALLOWED")
    critical     = sum(1 for t in threat_feed if t.get("threat_level") == "CRITICAL")

    return {
        "total_agents"      : len(all_agents),
        "active_ws_clients" : len(_ws_clients),
        "total_decisions"   : total,
        "blocked"           : blocked,
        "flagged"           : flagged,
        "allowed"           : allowed,
        "critical_threats"  : critical,
        "sandboxed_agents"  : sum(1 for a in get_all_profiles() if a.get("is_sandboxed")),
        "isolated_agents"   : len(get_isolated_agents()),
        "pending_approvals" : len(get_pending_approvals()),
    }


# ──────────────────────────────────────────────────────────────────────────────
# WebSocket — Live Threat Stream
# ──────────────────────────────────────────────────────────────────────────────

@app.websocket("/ws/threats")
async def threat_stream(ws: WebSocket):
    """
    Real-time WebSocket stream. Connect from dashboard to receive
    every interception decision sub-100ms after it occurs.
    """
    await ws.accept()
    _ws_clients.append(ws)
    # Send connection acknowledgment
    await ws.send_json({
        "type"      : "CONNECTION_ESTABLISHED",
        "message"   : "AgentTrust OS live threat stream connected.",
        "timestamp" : datetime.now(timezone.utc).isoformat(),
    })
    try:
        while True:
            await asyncio.sleep(30)
    except WebSocketDisconnect:
        if ws in _ws_clients:
            _ws_clients.remove(ws)


# ──────────────────────────────────────────────────────────────────────────────
# Zero Trust Agent Registration & Management
# ──────────────────────────────────────────────────────────────────────────────

@app.post("/agents/register", tags=["Agent Management"])
async def register(request: Request):
    """
    Register an AI agent with AgentTrust OS.
    Returns a Zero Trust identity token — store it securely.
    Token must be passed as X-Agent-Token header on every tool call.
    """
    body     = await request.json()
    agent_id = body.get("agent_id", "unknown")

    entry = register_agent(
        agent_id             = agent_id,
        name                 = body.get("name", "Unnamed Agent"),
        declared_intent      = body.get("declared_intent", ""),
        declared_permissions = body.get("declared_permissions", []),
        downstream_agents    = body.get("downstream_agents", [])
    )

    # Issue Zero Trust identity token
    token_data = create_agent_token(agent_id)

    append_audit({
        "event_type" : "AGENT_REGISTERED",
        "agent_id"   : agent_id,
        "blast_level": entry.get("blast_level"),
        "blast_score": entry.get("blast_score"),
    })

    # ── Governance: derive default prerequisites from recorded context ──────
    # Fail-soft by design: registration must never fail because of governance.
    gov_profile = governance_register_derivation(agent_id)

    await broadcast({
        "type"  : "AGENT_REGISTERED",
        "agent" : entry,
    })
    await emit_blockers_changed(agent_id)  # O2: fresh token/gates may clear blockers

    return JSONResponse(content={
        "status"        : "registered",
        "agent"         : entry,
        "identity_token": token_data,
        "governance"    : {
            "status"        : "derived",
            "prerequisites" : len(gov_profile.get("prerequisites", [])),
            "note"          : "Default prerequisites derived from recorded context — view/adjust via GET|PUT /agents/{id}/governance",
        },
        "security_note" : "This token will not be shown again. Store it securely.",
    })


@app.post("/agents/revoke/{agent_id}", tags=["Agent Management"])
async def revoke(agent_id: str):
    """Revoke an agent's Zero Trust token. All subsequent calls will be rejected."""
    result = revoke_agent(agent_id)
    append_audit({"event_type": "AGENT_REVOKED", "agent_id": agent_id})
    await broadcast({"type": "AGENT_REVOKED", "agent_id": agent_id})
    await emit_blockers_changed(agent_id)  # O2: BLK-TOKEN now active
    return JSONResponse(content=result)


@app.get("/agents", tags=["Agent Management"])
async def list_agents():
    """List all registered agents with their blast radius and trust scores."""
    return JSONResponse(content={"agents": get_all_agents()})


@app.get("/agents/{agent_id}", tags=["Agent Management"])
async def get_single_agent(agent_id: str):
    """Get full profile for a single agent including DNA and trust summary."""
    agent       = get_agent(agent_id)
    trust       = get_trust_summary(agent_id)
    dna         = get_dna_summary(agent_id)
    sequence    = get_sequence_summary(agent_id)

    if not agent:
        return JSONResponse(status_code=404, content={"error": f"Agent '{agent_id}' not found"})

    return JSONResponse(content={
        "agent"    : agent,
        "trust"    : trust,
        "dna"      : dna,
        "sequence" : sequence,
    })


# ──────────────────────────────────────────────────────────────────────────────
# Governance — Prerequisites (derived defaults, editable, evaluated per call)
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/agents/{agent_id}/governance", tags=["Agent Management"])
async def get_governance(agent_id: str):
    """The agent's prerequisite profile: derived defaults + operator edits +
    live evaluation of the state-based prerequisites.

    Lazy-derives (and persists) a profile for agents registered before the
    governance feature existed, so every agent gets a profile.
    """
    try:
        from infrastructure import database as _db
        row = _db.get_agent_db(agent_id)
    except Exception:
        row = None
    if row is None:
        return JSONResponse(status_code=404, content={"error": f"Agent '{agent_id}' not found"})

    profile = governance_get_profile(agent_id, persist_if_missing=True)

    # Live evaluation of the state-based prerequisites (no tool in context):
    # token/isolation/sandbox/trust can be checked right now; tool-scoped
    # ones (intent/permission/blast/custom) are evaluated per intercepted call.
    live = evaluate_prerequisites(agent_id, tool="<state-only>")
    state_ids = {"PR-TOKEN", "PR-ISOLATED", "PR-SANDBOX", "PR-TRUST"}
    live_state = {
        r["id"]: {"satisfied": r["satisfied"], "reason": r["reason"]}
        for r in live.get("prerequisites", []) if r["id"] in state_ids
    }

    return JSONResponse(content={
        "profile"   : profile,
        "live_state": live_state,
        "note"      : "Tool-scoped prerequisites are evaluated on every intercepted call and included in the decision payload + audit chain.",
    })


@app.put("/agents/{agent_id}/governance", tags=["Agent Management"])
async def edit_governance(agent_id: str, request: Request):
    """Edit an agent's prerequisites (validated + audited).

    Body: {"actor": "<who>", "expected_version": <int, optional>,
           "edits": {"add_custom": [...], "remove": [ids], "update": [...]}}

    • add_custom : {label, description?, severity?, enforce?, check}
                   check ∈ param_equals | param_in | param_present (whitelist
                   interpreter — no code execution, ever)
    • remove     : custom entries only — derived defaults and security
                   invariants are locked
    • update     : severity/enforce/label/description on editable entries

    404 unknown agent · 409 version conflict · 422 validation rejection
    (rejections are audit-logged as GOVERNANCE_EDIT_REJECTED).
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Invalid JSON body"})

    try:
        from infrastructure import database as _db
        row = _db.get_agent_db(agent_id)
    except Exception:
        row = None
    if row is None:
        return JSONResponse(status_code=404, content={"error": f"Agent '{agent_id}' not found"})

    actor = body.get("actor")
    edits = body.get("edits")
    expected_version = body.get("expected_version")

    try:
        new_profile = governance_apply_edits(
            agent_id,
            edits,
            actor,
            expected_version=expected_version,
            audit=append_audit,
        )
    except GovernanceEditError as e:  # validation → 422 (checked FIRST: it subclasses ValueError)
        append_audit({
            "event_type": "GOVERNANCE_EDIT_REJECTED",
            "agent_id"  : agent_id,
            "actor"     : actor if isinstance(actor, str) else str(actor),
            "reason"    : str(e),
        })
        return JSONResponse(status_code=422, content={"error": str(e)})
    except ValueError as e:  # version conflict → 409
        append_audit({
            "event_type": "GOVERNANCE_EDIT_REJECTED",
            "agent_id"  : agent_id,
            "actor"     : actor if isinstance(actor, str) else str(actor),
            "reason"    : str(e),
        })
        return JSONResponse(status_code=409, content={"error": str(e)})

    await emit_blockers_changed(agent_id)  # O2: custom gates changed
    return JSONResponse(content={"status": "updated", "profile": new_profile})


# ──────────────────────────────────────────────────────────────────────────────
# Blockers — live "why can't this agent act right now" view (read-only)
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/agents/{agent_id}/blockers", tags=["Agent Management"])
async def get_blockers(agent_id: str):
    """The agent's LIVE blocker state — a computed, read-only view.

    Unlike /governance (the stored, editable prerequisite profile), blockers
    are never stored: they are derived on demand from the engines that
    actually enforce them, so the view can never be stale. Every hard
    blocker carries a clear_hint and, where a real endpoint exists,
    a clear_action (release / approve / re-register). Soft blockers are
    advisory degradations (restricted trust, pending approvals, standing
    custom gates).
    """
    try:
        from infrastructure import database as _db
        row = _db.get_agent_db(agent_id)
    except Exception:
        row = None
    if row is None:
        return JSONResponse(status_code=404, content={"error": f"Agent '{agent_id}' not found"})

    return JSONResponse(content=compute_blockers(agent_id, use_cache=False))


@app.get("/agents/{agent_id}/effects", tags=["Agent Management"])
async def get_effects(agent_id: str):
    """The agent's DOWNSTREAM EFFECTS — a live, computed, read-only view.

    Answers: "if this agent's actions run, who consumes the output and how
    are they affected?" The only stored input is the recorded context
    (`downstream_agents` declared at registration); consumer state is read
    live (trust store → durable row → default), always read-only.

    Consumer impact classes: HEALTHY / DEGRADED / QUARANTINED / UNKNOWN.
    Status: HEALTHY_CHAIN / DEGRADED / QUARANTINED / NO_CONSUMERS.
    """
    try:
        from infrastructure import database as _db
        row = _db.get_agent_db(agent_id)
    except Exception:
        row = None
    if row is None:
        return JSONResponse(status_code=404, content={"error": f"Agent '{agent_id}' not found"})

    return JSONResponse(content=compute_effects(agent_id, use_cache=False))


# ──────────────────────────────────────────────────────────────────────────────
# Core Interception — 7-Layer Pipeline
# ──────────────────────────────────────────────────────────────────────────────

async def _run_with_timeout(coro, timeout: float, engine_name: str) -> Any:
    """Run a coroutine with timeout. On timeout, raise EngineTimeoutError (fail-closed)."""
    try:
        return await asyncio.wait_for(coro, timeout=timeout)
    except asyncio.TimeoutError:
        raise EngineTimeoutError(f"Engine '{engine_name}' timed out after {timeout}s - BLOCKING (fail-closed)")
    except EngineTimeoutError:
        raise


@app.post("/mcp/tools/call", tags=["Interception"])
async def intercept(request: Request):
    """
    Primary interception endpoint. Every AI agent tool call routes through here.

    7-Layer Pipeline:
    1. MITRE ATT&CK Risk Engine         — Pattern + context-aware threat detection
    2. Intent Gap Analysis              — Declared intent vs actual action divergence
    3. Policy-as-Code Evaluation        — YAML-defined enterprise security policies
    4. Behavioral DNA Fingerprinting    — Agent identity drift detection
    5. Trust Score Engine               — Cumulative behavioral trust scoring
    6. Predictive Sequence Analysis     — Attack chain early detection
    7. Cross-Agent Threat Correlation   — Network-level threat propagation detection

    FAIL-CLOSED: Any timeout triggers BLOCK decision automatically.
    """

    # ── Parse Request Body ────────────────────────────────────────────────────
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Invalid JSON body"})

    # ── Zero Trust Authentication ─────────────────────────────────────────────
    try:
        identity = authenticate_request(request)
        agent_id = identity["agent_id"]
    except HTTPException as e:
        # 401 = missing credentials, 403 = invalid / expired / revoked token
        append_audit({
            "event_type" : "AUTH_FAILURE",
            "reason"     : str(e.detail),
            "ip"         : request.client.host if request.client else "unknown",
        })
        return JSONResponse(status_code=e.status_code, content={
            "error"  : str(e.detail),
            "action" : "REJECTED",
            "reason" : "Zero Trust authentication failed — request denied before pipeline entry",
        })
    except Exception as e:
        append_audit({
            "event_type" : "AUTH_FAILURE",
            "reason"     : str(e),
            "ip"         : request.client.host if request.client else "unknown",
        })
        return JSONResponse(status_code=401, content={
            "error"  : str(e),
            "action" : "REJECTED",
            "reason" : "Zero Trust authentication failed — request denied before pipeline entry",
        })

    tool   = body.get("tool", "unknown")
    params = body.get("parameters", {})

    # ── Isolation Guard — quarantined agents are rejected before the pipeline ─
    if is_isolated(agent_id):
        guard = {
            "agent_id"   : agent_id,
            "tool"       : tool,
            "parameters" : params,
            "action"     : "ISOLATED",
            "timestamp"  : datetime.now(timezone.utc).isoformat(),
            "reason"     : "Agent is ISOLATED — all tool calls rejected until a human releases the agent or grants the pending approval.",
        }
        # Governance on the rejection path too: the operator sees exactly
        # which prerequisites are unsatisfied and why the agent is blocked.
        guard["governance"] = evaluate_prerequisites(agent_id, tool, params)
        # Blockers on the rejection path: the full itemized "why" (isolation,
        # token, trust floor, pending approvals...) with how to clear each.
        # Fail-soft: a blocker-view error must never turn a 403 into a 500.
        # use_cache=False: the guard is safety-critical — an operator action
        # (isolate/release/approve) may have landed since the last compute,
        # so it must never answer from a cached snapshot.
        try:
            guard["blockers"] = compute_blockers(agent_id, use_cache=False)
        except Exception:
            guard["blockers"] = {"status": "degraded", "blockers": []}
        append_audit({"event_type": "ISOLATED_CALL_REJECTED", "agent_id": agent_id, "tool": tool, "governance": guard["governance"], "blockers": guard["blockers"]})
        await broadcast({"type": "ISOLATED_CALL_REJECTED", "agent_id": agent_id, "tool": tool})
        return JSONResponse(status_code=403, content=guard)

    # ── Honeypot Engine — decoy asset access is a confirmed threat ────────────
    honeypot = check_honeypot_access(tool, params)

    # ── Load Agent Context ────────────────────────────────────────────────────
    agent: dict[str, Any] = get_agent(agent_id)
    declared_intent = agent.get("declared_intent", "general purpose")
    trust_data: dict[str, Any] = get_trust_summary(agent_id)
    blast_level     = agent.get("blast_level", "LOW")
    blast_score     = agent.get("blast_score", 0)

    # ── LAYER 1: MITRE ATT&CK Risk Engine ────────────────────────────────────
    try:
        assessment: Any = await _run_with_timeout(
            asyncio.to_thread(assess_risk, tool, params, {"trust_score": trust_data["trust_score"]}),
            TIMEOUT_CONFIG["risk_engine"],
            "risk_engine"
        )
        risk_score, risk_level, risk_reason, mitre_technique, mitre_tactic, confidence, remediation, threat_tags = (
            assessment.risk_score, assessment.risk_level, assessment.reason,
            assessment.mitre_technique, assessment.mitre_tactic,
            assessment.confidence, assessment.remediation, assessment.tags
        )
    except EngineTimeoutError as e:
        # Fail-closed: timeout = BLOCK
        risk_score, risk_level, risk_reason, mitre_technique, mitre_tactic, confidence, remediation, threat_tags = (
            100, "CRITICAL", str(e), "TIMEOUT", "TIMEOUT", 0.0,
            "Engine timeout - fail-closed blocking", []
        )

    # ── Honeypot Breach — confirmed threat overrides risk to CRITICAL ────────
    if honeypot["hit"]:
        risk_score      = 100
        risk_level      = "CRITICAL"
        risk_reason     = honeypot["reason"]
        mitre_technique = "T1530"
        mitre_tactic    = "Exfiltration"
        confidence      = 1.0
        threat_tags     = list(dict.fromkeys([*threat_tags, "honeypot-breach", "confirmed-threat"]))

    # ── LAYER 2: Intent Gap Analysis ─────────────────────────────────────────
    # agent_id is passed so scope-creep history is tracked PER AGENT
    # (omitting it shared one global history across all agents)
    try:
        intent = await _run_with_timeout(
            asyncio.to_thread(analyze_intent_gap, declared_intent, tool, params, agent_id),
            TIMEOUT_CONFIG["intent_gap"],
            "intent_gap"
        )
    except EngineTimeoutError as e:
        # Fail-closed: timeout = BLOCK
        intent = type('obj', (object,), {
            'gap_score': 100,
            'gap_level': 'CRITICAL',
            'reason': str(e),
            'should_block': True,
            'confidence': 0.0,
            'remediation': str(e),
            'scan_surfaces': [],
        })

    # ── LAYER 3: Policy-as-Code Evaluation ───────────────────────────────────
    try:
        policy: dict[str, Any] = await _run_with_timeout(
            asyncio.to_thread(
                evaluate_policies,
                agent_id,
                tool,
                params,
                trust_data["trust_score"],
                blast_level,
                intent.gap_score,
                trust_data.get("is_sandboxed", False)
            ),
            TIMEOUT_CONFIG["policy"],
            "policy"
        )
    except EngineTimeoutError as e:
        # Fail-closed: timeout = BLOCK
        policy = {"final_action": "BLOCK", "violations": [], "policy_count": 1}

    # ── LAYER 4: Behavioral DNA Fingerprinting ────────────────────────────────
    try:
        dna = await _run_with_timeout(
            asyncio.to_thread(update_dna, agent_id, tool, params),
            TIMEOUT_CONFIG["dna"],
            "dna"
        )
    except EngineTimeoutError as e:
        # Fail-closed: timeout = BLOCK
        dna = type('obj', (object,), {
            'fingerprint': '',
            'drift_score': 100,
            'is_drifted': True,
            'unique_tools': 0,
        })

    # ── LAYER 5: Trust Score Engine ───────────────────────────────────────────
    try:
        trust = await _run_with_timeout(
            asyncio.to_thread(
                update_trust_score,
                agent_id,
                tool,
                params,
                risk_level,
                risk_score,
                intent.gap_score,
                blast_level,
                mitre_technique,
                mitre_tactic
            ),
            TIMEOUT_CONFIG["trust_score"],
            "trust_score"
        )
    except EngineTimeoutError as e:
        # Fail-closed: timeout = BLOCK
        trust = type('obj', (object,), {
            'trust_score': 0.0,
            'is_sandboxed': True,
            'total_actions': 0,
        })

    # ── O2: trust containment / policy-floor transition → live blocker push ──
    # Compare the pre-call summary (trust_data, dict) with the post-call
    # profile (TrustProfile, or the fail-closed stub). Only the three facts
    # that create or clear trust-derived blocker rows are compared (sandbox
    # flag, containment level, floor breach); no push unless a threshold was
    # crossed. Telemetry only — must never affect the pipeline.
    try:
        _floor = policy_trust_floor()
        _sig_before = _trust_blocker_sig(
            trust_data.get("trust_score", 100.0),
            trust_data.get("containment_level"),
            trust_data.get("is_sandboxed"),
            _floor,
        )
        _sig_after = _trust_blocker_sig(
            getattr(trust, "trust_score", 0.0),
            getattr(trust, "containment_level", "NONE"),
            getattr(trust, "is_sandboxed", False),
            _floor,
        )
        if _sig_before != _sig_after:
            await emit_blockers_changed(agent_id)
    except Exception:
        pass

    # ── LAYER 6: Predictive Sequence Analysis ────────────────────────────────
    try:
        sequence = await _run_with_timeout(
            asyncio.to_thread(update_sequence, agent_id, tool),
            TIMEOUT_CONFIG["sequence"],
            "sequence"
        )
    except EngineTimeoutError as e:
        # Fail-closed: timeout = BLOCK
        sequence = type('obj', (object,), {
            'prediction': 'BLOCKED',
            'prediction_score': 100,
            'matched_pattern': 'TIMEOUT',
            'actions': [],
        })

    # ── LAYER 7: Cross-Agent Threat Correlation ───────────────────────────────
    try:
        threat: dict[str, Any] = await _run_with_timeout(
            asyncio.to_thread(correlate_threat, agent_id, tool, risk_level, intent.gap_score),
            TIMEOUT_CONFIG["threat_correlation"],
            "threat_correlation"
        )
    except EngineTimeoutError as e:
        # Fail-closed: timeout = BLOCK
        threat = {"threat_level": "CRITICAL", "correlated_agents": [agent_id], "agent_threat_count": 1}

    # ── Adaptive Policy Observer (learns from every event) ───────────────────
    # Non-blocking observation - run in background
    try:
        asyncio.create_task(_run_with_timeout(
            asyncio.to_thread(
                observe_event,
                tool,
                risk_level,
                "BLOCKED" if risk_level in ("HIGH", "CRITICAL") else
                "FLAGGED" if risk_level == "MEDIUM" else "ALLOWED",
                params,
            ),
            TIMEOUT_CONFIG["observation"],
            "adaptive_policy"
        ))
    except Exception:
        pass  # Best effort - don't block on observation failures

    # ── Final Decision — Any layer can independently trigger a block ──────────
    block_reasons: list[str] = []

    if policy["final_action"] == "BLOCK":
        block_reasons.append(f"Policy violation: {[v['policy'] for v in policy['violations']]}")
    if risk_level in ("HIGH", "CRITICAL"):
        block_reasons.append(f"Risk engine: {risk_level} threat detected")
    if intent.should_block:
        block_reasons.append(f"Intent gap: critical mismatch (score {intent.gap_score}/100)")
    if trust.is_sandboxed:
        block_reasons.append(f"Agent sandboxed: trust score collapsed to {round(trust.trust_score, 1)}/100")
    if dna.is_drifted:
        block_reasons.append(f"DNA drift: behavioral fingerprint diverged (drift {dna.drift_score}/100)")
    if sequence.prediction_score >= 90:
        block_reasons.append(f"Predictive engine: {sequence.prediction} ({sequence.prediction_score}% confidence)")

    flag_reasons: list[str] = []
    if not block_reasons:
        if policy["final_action"] == "FLAG":
            flag_reasons.append("Policy flag triggered")
        if risk_level == "MEDIUM":
            flag_reasons.append("Medium risk pattern detected")
        if intent.gap_level == "MEDIUM":
            flag_reasons.append(f"Intent gap elevated (score {intent.gap_score}/100)")
        if sequence.prediction_score >= 70:
            flag_reasons.append(f"Predictive: {sequence.prediction} building ({sequence.prediction_score}%)")
        if blast_score >= 75:
            flag_reasons.append(f"Critical blast radius agent (score {blast_score}/100)")

    if honeypot["hit"]:
        block_reasons.insert(0, honeypot["reason"])

    # ── Governance: Prerequisite evaluation ─────────────────────────────────
    # In-memory, sub-millisecond, exception-safe (degrades to "degraded").
    # • Derived prerequisites (intent/permission/trust/blast/containment)
    #   surface — for explainability — the same conditions the 7 layers
    #   already enforce (enforce=false by default → no duplicate reasons).
    # • Custom operator prerequisites (enforce=true) are real gates: an
    #   unsatisfied BLOCK-severity entry adds a block reason and can escalate
    #   ALLOWED/FLAGGED → BLOCKED. Escalation is stricter-only; governance
    #   never relaxes a decision and never touches trust scores.
    gov_eval = evaluate_prerequisites(agent_id, tool, params)
    # Blockers snapshot for the decision payload — call-level view (agent
    # state + this call's failed tool-scoped prerequisites). Fail-soft: the
    # decision must never be affected by a blocker-view error.
    try:
        call_blockers = compute_call_blockers(agent_id, tool, params)
    except Exception:
        call_blockers = {"status": "degraded", "blockers": []}
    if gov_eval.get("status") == "evaluated":
        for entry in gov_eval["prerequisites"]:
            if entry["satisfied"] or not entry.get("enforce"):
                continue
            reason = f"governance prerequisite {entry['id']} unsatisfied — {entry['reason']}"
            if entry.get("severity") == "FLAG":
                flag_reasons.append(reason)
            else:
                block_reasons.append(reason)

    blocked = len(block_reasons) > 0
    flagged = not blocked and len(flag_reasons) > 0
    action  = "BLOCKED" if blocked else "FLAGGED" if flagged else "ALLOWED"

    # ── Downstream Effects (concept 3): what happens if it runs ─────────────
    # Per-call snapshot for the decision payload + audit chain. Fail-soft:
    # an effects-view error must never affect the decision.
    try:
        fx_eval = compute_call_effects(
            agent_id, tool, params, action,
            trust_score=trust.trust_score,
            correlated_agents=threat.get("correlated_agents", []),
        )
    except Exception:
        fx_eval = {"status": "degraded", "consumers": [], "effects_error": "non-fatal"}
    # D3 advisory (stricter-only): a NON-BLOCKED call flowing into a
    # QUARANTINED declared consumer carries a human-review reason. From
    # ALLOWED it escalates to FLAGGED; on an already-FLAGGED call it adds
    # the reason to the existing review. Never BLOCK, never de-escalate,
    # never touches trust. (BLOCKED/ISOLATED calls execute nothing — the
    # consumer-starvation row covers their consequence.)
    if action in ("ALLOWED", "FLAGGED") and fx_eval.get("status") != "degraded" and fx_eval.get("advisory"):
        flag_reasons.extend(fx_eval["advisory"])
        if action == "ALLOWED":
            action = "FLAGGED"
        fx_eval["advisory_applied"] = True

    # ── Prevention Escalation — CRITICAL threat / honeypot breach ────────────
    # Isolate the agent and open a human approval request
    # (Prevention Engine decisions per spec: Allow / Block / Isolate / Approval).
    isolation_triggered = False
    approval = None
    if blocked and (honeypot["hit"] or risk_level == "CRITICAL"):
        isolation_reason = (
            honeypot["reason"] if honeypot["hit"]
            else f"CRITICAL risk action '{tool}' — {risk_reason}"
        )
        isolate_agent(agent_id, isolation_reason)
        isolation_triggered = True
        action = "ISOLATED"
        approval = create_approval(
            agent_id     = agent_id,
            tool         = tool,
            parameters   = params,
            reason       = f"Agent isolated: {isolation_reason}",
            decision_ref = {"risk_level": risk_level, "honeypot_hit": honeypot["hit"]},
        )
        append_audit({"event_type": "AGENT_ISOLATED", "agent_id": agent_id, "reason": isolation_reason})
        append_audit({"event_type": "APPROVAL_CREATED", "agent_id": agent_id, "approval_id": approval["id"]})
        await emit_blockers_changed(agent_id)  # O2: auto-isolation + approval are live now

    # ── Build Full Decision Payload ───────────────────────────────────────────
    decision: dict[str, Any] = {
        # ── Identity
        "agent_id"              : agent_id,
        "tool"                  : tool,
        "parameters"            : params,
        "action"                : action,
        "timestamp"             : datetime.now(timezone.utc).isoformat(),

        # ── Layer 1: Risk Engine
        "risk_score"            : risk_score,
        "risk_level"            : risk_level,
        "risk_reason"           : risk_reason,
        "mitre_technique"       : mitre_technique,
        "mitre_tactic"          : mitre_tactic,
        "detection_confidence"  : confidence,
        "remediation"           : remediation,
        "threat_tags"           : threat_tags,

        # ── Layer 2: Intent Gap
        "intent_gap_score"      : intent.gap_score,
        "intent_gap_level"      : intent.gap_level,
        "intent_reason"         : intent.reason,
        "intent_should_block"   : intent.should_block,

        # ── Layer 3: Policy
        "policy_action"         : policy["final_action"],
        "policy_violations"     : policy["violations"],
        "policy_count"          : policy["policy_count"],

        # ── Layer 4: DNA
        "dna_fingerprint"       : dna.fingerprint,
        "dna_drift_score"       : dna.drift_score,
        "dna_drifted"           : dna.is_drifted,
        "dna_unique_tools"      : dna.unique_tools,

        # ── Layer 5: Trust Score
        "trust_score"           : round(trust.trust_score, 2),
        "trust_level"           : _trust_label(trust.trust_score),
        "is_sandboxed"          : trust.is_sandboxed,
        "total_actions"         : trust.total_actions,

        # ── Layer 6: Predictive
        "prediction"            : sequence.prediction,
        "prediction_score"      : sequence.prediction_score,
        "matched_pattern"       : sequence.matched_pattern,
        "recent_sequence"       : sequence.actions,

        # ── Layer 7: Threat Correlation
        "threat_level"          : threat.get("threat_level", "NONE"),
        "correlated_agents"     : threat.get("correlated_agents", []),
        "agent_threat_count"    : threat.get("agent_threat_count", 0),

        # ── Blast Radius Context
        "blast_score"           : blast_score,
        "blast_level"           : blast_level,

        # ── Honeypot Engine
        "honeypot_hit"          : honeypot["hit"],
        "honeypot_asset"        : honeypot["asset"],

        # ── Isolation & Approval Workflow
        "agent_isolated"        : is_isolated(agent_id),
        "isolation_triggered"   : isolation_triggered,
        "approval"              : approval,

        # ── Governance (prerequisites)
        "governance"            : gov_eval,

        # ── Blockers (live "why is this call blocked/degraded" snapshot)
        "blockers"              : call_blockers,

        # ── Downstream Effects (live "what happens if it runs" snapshot)
        "effects"               : fx_eval,

        # ── Decision Explanation
        "block_reasons"         : block_reasons,
        "flag_reasons"          : flag_reasons,
        "decision_summary"      : _build_summary(action, block_reasons, flag_reasons, risk_level),
    }

    # ── LLM Second-Opinion (async) — the real local model reviews this call
    # in the background; verdicts land in audit + dashboard, and can escalate.
    decision["llm_review"] = llm_review_engine.submit(
        agent_id, tool, params, declared_intent, action, risk_level,
    )

    # ── Forensic Session Recording ─────────────────────────────────────────────
    record_event(agent_id, decision)

    # ── Cryptographic Audit Chain ─────────────────────────────────────────────
    audit_record = append_audit({
        "event_type" : "TOOL_INTERCEPTED",
        "decision"   : decision,
    })
    decision["audit_hash"]     = audit_record.get("hash", "")
    decision["audit_sequence"] = audit_record.get("sequence", 0)

    # ── Live WebSocket Broadcast ──────────────────────────────────────────────
    log_decision(decision)
    await broadcast({"type": "THREAT_EVENT", "decision": decision})

    return JSONResponse(
        status_code = 403 if blocked else 200,
        content     = decision,
    )


# ──────────────────────────────────────────────────────────────────────────────
# Dashboard Endpoints
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/llm/status", tags=["LLM Second-Opinion"])
async def llm_status_endpoint():
    """Live status of the local llama.cpp second-opinion layer."""
    return JSONResponse(content=llm_review_engine.stats())


@app.get("/llm/reviews", tags=["LLM Second-Opinion"])
async def llm_reviews_endpoint(agent_id: str | None = None, limit: int = 50):
    """Real model verdicts (with reasoning) for reviewed tool calls."""
    return JSONResponse(content={"reviews": llm_review_engine.get_reviews(agent_id, limit)})


def _annotate_blocker_status(profiles: list) -> list:
    """O1 (PHASE2_Blockers_Plan §Optional stretch) — annotate each dashboard
    agent row with its live blocker status (CLEAR/DEGRADED/BLOCKED) so the
    agent table can render a ⛔ dot without N extra requests.
    Uses the blocker engine's 1 s TTL cache → sub-millisecond per agent;
    never 500s the panel (degrades to null per row)."""
    for a in profiles:
        try:
            a["blocker_status"] = compute_blockers(
                a.get("agent_id"), use_cache=True
            ).get("status")
        except Exception:
            a["blocker_status"] = None
    return profiles


@app.get("/dashboard/agents", tags=["Dashboard"])
async def dash_agents():
    """All agent trust profiles for dashboard overview panel."""
    return JSONResponse(content={"agents": _annotate_blocker_status(get_all_profiles())})


@app.get("/dashboard/logs", tags=["Dashboard"])
async def dash_logs(limit: int = 50):
    """Last N audit log entries for the live feed panel."""
    return JSONResponse(content={"logs": get_audit_log(limit)})


def _enrich_threat_feed(feed: list[dict]) -> list[dict]:
    """Join each threat-correlation item with its underlying decision record.

    The in-memory threat feed only carries slim correlation fields
    (level/agent/tool/intent_gap/count); the full incident context (parameters,
    risk score + reason, honeypot flag, MITRE, remediation, intent) lives in the
    persistent decision store (logs/decisions.json). Best match = same
    agent+tool with the closest timestamp (<=15 s). Never breaks: on any error
    the feed is returned unchanged.
    """
    try:
        from proxy.logger import LOG_FILE
        if not os.path.exists(LOG_FILE):
            return feed
        by_key: dict = {}
        with open(LOG_FILE) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except Exception:
                    continue
                by_key.setdefault((d.get("agent_id"), d.get("tool")), []).append(d)
        for th in feed:
            cands = by_key.get((th.get("agent_id"), th.get("tool"))) or []
            if not cands:
                continue
            try:
                t = datetime.fromisoformat(th.get("timestamp") or "")
            except Exception:
                continue
            best = None
            for d in cands:
                try:
                    dt = abs((datetime.fromisoformat(d.get("timestamp") or "") - t).total_seconds())
                except Exception:
                    continue
                if dt <= 15 and (best is None or dt < best[0]):
                    best = (dt, d)
            if best:
                d = best[1]
                th["decision"] = {
                    "agent_id": d.get("agent_id"), "tool": d.get("tool"),
                    "parameters": d.get("parameters") or {}, "action": d.get("action"),
                    "risk_score": d.get("risk_score"), "risk_level": d.get("risk_level"),
                    "risk_reason": d.get("risk_reason"),
                    "decision_summary": d.get("decision_summary") or d.get("reason") or "",
                    "honeypot_hit": bool(d.get("honeypot_hit")),
                    "mitre_technique": d.get("mitre_technique"), "mitre_tactic": d.get("mitre_tactic"),
                    "detection_confidence": d.get("detection_confidence"),
                    "remediation": d.get("remediation"), "threat_tags": d.get("threat_tags") or [],
                    "intent_gap_score": d.get("intent_gap_score"), "intent_reason": d.get("intent_reason"),
                    "timestamp": d.get("timestamp"),
                }
                th["mitre_technique"] = d.get("mitre_technique")
        return feed
    except Exception:
        return feed


@app.get("/dashboard/threats", tags=["Dashboard"])
async def dash_threats():
    """Threat intelligence feed — cross-agent correlation events."""
    return JSONResponse(content={"feed": _enrich_threat_feed(get_threat_feed())})


@app.get("/dashboard/evolved-policies", tags=["Dashboard"])
async def dash_evolved():
    """Auto-generated policies from adaptive policy evolution engine."""
    return JSONResponse(content={"policies": get_evolved_policies()})


@app.get("/dashboard/summary", tags=["Dashboard"])
async def dash_summary():
    """Single endpoint for full dashboard state — agents + stats + threats."""
    all_profiles = _annotate_blocker_status(get_all_profiles())
    threat_feed  = _enrich_threat_feed(get_threat_feed())
    audit_log    = get_audit_log(100)

    total   = len(audit_log)
    blocked = sum(1 for r in audit_log if r.get("event", {}).get("decision", {}).get("action") == "BLOCKED")
    flagged = sum(1 for r in audit_log if r.get("event", {}).get("decision", {}).get("action") == "FLAGGED")

    return JSONResponse(content={
        "agents"          : all_profiles,
        "total_decisions" : total,
        "blocked"         : blocked,
        "flagged"         : flagged,
        "allowed"         : total - blocked - flagged,
        "critical_threats": sum(1 for t in threat_feed if t.get("threat_level") == "CRITICAL"),
        "sandboxed"       : sum(1 for a in all_profiles if a.get("is_sandboxed")),
        "evolved_policies": get_evolved_policies(),
        "recent_threats"  : threat_feed[-10:],
    })


# ──────────────────────────────────────────────────────────────────────────────
# Forensics Endpoints
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/forensics/sessions", tags=["Forensics"])
async def forensic_sessions():
    """List all agent sessions with event counts for forensic investigation."""
    return JSONResponse(content={"sessions": get_all_sessions()})


@app.get("/forensics/replay/{agent_id}", tags=["Forensics"])
async def forensic_replay(agent_id: str):
    """
    Full forensic session replay for an agent.
    Returns step-by-step reconstruction of every action with state at each moment.
    """
    return JSONResponse(content=replay_session(agent_id))


@app.get("/forensics/dna/{agent_id}", tags=["Forensics"])
async def forensic_dna(agent_id: str):
    """Behavioral DNA profile for an agent — fingerprint, drift score, tool frequency."""
    return JSONResponse(content=get_dna_summary(agent_id))


# ──────────────────────────────────────────────────────────────────────────────
# Audit Chain Endpoints
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/audit/verify", tags=["Audit"])
async def audit_verify():
    """
    Cryptographically verify the entire audit chain.
    Returns tamper detection result — any modification breaks the hash chain.
    """
    return JSONResponse(content=verify_chain())


@app.get("/audit/log", tags=["Audit"])
async def audit_log(limit: int = 100):
    """Retrieve tamper-proof audit log entries with cryptographic hash chain."""
    return JSONResponse(content={"records": get_audit_log(limit)})


# ──────────────────────────────────────────────────────────────────────────────
# Threat Intelligence Endpoints
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/threat-library", tags=["Threat Intelligence"])
async def threat_library():
    """
    Full MITRE ATT&CK threat signal library.
    All detection rules with technique IDs, tactics, severity, and confidence scores.
    """
    signals: list[dict[str, Any]] = get_threat_library()
    return JSONResponse(content={
        "total"   : len(signals),
        "signals" : signals,
        "tactics" : list({s["mitre_tactic"] for s in signals}),
    })


@app.get("/sequence/{agent_id}", tags=["Threat Intelligence"])
async def sequence_summary(agent_id: str):
    """Predictive attack sequence analysis for an agent."""
    return JSONResponse(content=get_sequence_summary(agent_id))


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _trust_label(score: float) -> str:
    if score >= 80: return "TRUSTED"
    if score >= 55: return "MONITOR"
    if score >= 30: return "SUSPICIOUS"
    return "COMPROMISED"


def _build_summary(action: str, block_reasons: list[str], flag_reasons: list[str], risk_level: str) -> str:
    if action in ("BLOCKED", "ISOLATED"):
        extra = " Agent ISOLATED — approval request created." if action == "ISOLATED" else ""
        return f"Request {action}.{extra} {len(block_reasons)} condition(s) triggered: {'; '.join(block_reasons[:2])}"
    if action == "FLAGGED":
        return f"Request FLAGGED for review. {'; '.join(flag_reasons[:2])}"
    return f"Request ALLOWED. Risk level: {risk_level}. No threat conditions triggered."

@app.get("/trust/changelog/{agent_id}", tags=["Trust Engine"])
async def trust_changelog(agent_id: str, limit: int = 20):
    """
    Full mathematical trust score changelog for an agent.
    Every delta with exact reason — penalty, recovery, decay, escalation.
    """
    from engine.trust_score.trust_engine import get_trust_changelog
    return JSONResponse(content={
        "agent_id"  : agent_id,
        "changelog" : get_trust_changelog(agent_id, limit)
    })


# ──────────────────────────────────────────────────────────────────────────────
# Agent Isolation Endpoints
# ──────────────────────────────────────────────────────────────────────────────

@app.post("/agents/isolate/{agent_id}", tags=["Agent Management"])
async def isolate(agent_id: str, request: Request):
    """Manually isolate (quarantine) an agent. All its tool calls are rejected until release."""
    try:
        body = await request.json()
    except Exception:
        body = {}
    reason = body.get("reason", "Manual isolation by operator")
    isolate_agent(agent_id, reason)
    append_audit({"event_type": "AGENT_ISOLATED_MANUAL", "agent_id": agent_id, "reason": reason})
    await broadcast({"type": "AGENT_ISOLATED", "agent_id": agent_id, "reason": reason})
    await emit_blockers_changed(agent_id)  # O2: BLK-ISOLATED now active
    return JSONResponse(content={"status": "isolated", "agent_id": agent_id, "reason": reason})


@app.post("/agents/release/{agent_id}", tags=["Agent Management"])
async def release(agent_id: str):
    """Release a previously isolated agent."""
    result = release_agent(agent_id)
    append_audit({"event_type": "AGENT_RELEASED", "agent_id": agent_id, "was_isolated": result.get("was_isolated")})
    await broadcast({"type": "AGENT_RELEASED", "agent_id": agent_id})
    await emit_blockers_changed(agent_id)  # O2: BLK-ISOLATED cleared
    return JSONResponse(content=result)


@app.get("/isolation", tags=["Agent Management"])
async def isolation_status():
    """List all currently isolated (quarantined) agents."""
    return JSONResponse(content={"isolated": get_isolated_agents()})


# ──────────────────────────────────────────────────────────────────────────────
# Approval Workflow Endpoints
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/approvals", tags=["Approval Workflow"])
async def list_approvals():
    """All approval requests created by the Prevention Engine."""
    return JSONResponse(content={
        "approvals" : get_approvals(),
        "pending"   : len(get_pending_approvals()),
    })


@app.post("/approvals/{approval_id}/approve", tags=["Approval Workflow"])
async def approval_approve(approval_id: str, request: Request):
    """Human approves → agent is released from isolation and may resume."""
    try:
        body = await request.json()
    except Exception:
        body = {}
    decided_by = body.get("decided_by", "human-reviewer")
    result = approve_request(approval_id, decided_by)
    if "error" in result:
        return JSONResponse(status_code=404, content=result)
    release_agent(result["agent_id"])
    append_audit({"event_type": "APPROVAL_GRANTED", "agent_id": result["agent_id"], "approval_id": approval_id, "decided_by": decided_by})
    await broadcast({"type": "APPROVAL_DECIDED", "approval_id": approval_id, "status": "APPROVED", "agent_id": result["agent_id"]})
    await emit_blockers_changed(result["agent_id"])  # O2: approval + isolation cleared
    return JSONResponse(content={"status": "approved", "approval": result, "agent_released": True})


@app.post("/approvals/{approval_id}/reject", tags=["Approval Workflow"])
async def approval_reject(approval_id: str, request: Request):
    """Human rejects → block stands, isolation continues."""
    try:
        body = await request.json()
    except Exception:
        body = {}
    decided_by = body.get("decided_by", "human-reviewer")
    result = reject_request(approval_id, decided_by)
    if "error" in result:
        return JSONResponse(status_code=404, content=result)
    append_audit({"event_type": "APPROVAL_REJECTED", "agent_id": result["agent_id"], "approval_id": approval_id, "decided_by": decided_by})
    await broadcast({"type": "APPROVAL_DECIDED", "approval_id": approval_id, "status": "REJECTED", "agent_id": result["agent_id"]})
    await emit_blockers_changed(result["agent_id"])  # O2: BLK-APPROVAL-x cleared
    return JSONResponse(content={"status": "rejected", "approval": result})


# ──────────────────────────────────────────────────────────────────────────────
# Honeypot Engine Endpoints
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/honeypots", tags=["Honeypot Engine"])
async def honeypots():
    """All planted honeypot (decoy) assets."""
    return JSONResponse(content={"assets": get_honeypot_assets()})


@app.get("/honeypots/detections", tags=["Honeypot Engine"])
async def honeypot_detections(limit: int = 50):
    """Honeypot breach detection log."""
    detections = get_detections(limit)
    return JSONResponse(content={"detections": detections, "total": len(detections)})


# ──────────────────────────────────────────────────────────────────────────────
# Embedded Live Dashboard
# ──────────────────────────────────────────────────────────────────────────────

from fastapi.responses import HTMLResponse

DASHBOARD_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "dashboard", "index.html"
)


def _ui_response() -> HTMLResponse:
    # no-store: the dashboard JS changes often; browsers must never serve a
    # stale cached copy (a cached old version can blank sections on refresh).
    with open(DASHBOARD_FILE, "r") as f:
        html = f.read()
    return HTMLResponse(html, headers={
        "Cache-Control": "no-cache, no-store, must-revalidate",
        "Pragma": "no-cache",
        "Expires": "0",
    })


@app.get("/ui", response_class=HTMLResponse, tags=["Dashboard"])
async def dashboard_ui():
    """Live dashboard — real-time updates via WebSocket + REST polling."""
    return _ui_response()


@app.get("/dashboard", response_class=HTMLResponse, tags=["Dashboard"])
async def dashboard_ui_alias():
    """Alias for /ui."""
    return _ui_response()
# AgentTrust OS
> Real-Time Runtime Security & Governance Platform for Agentic AI

## What it does
AgentTrust OS intercepts MCP server tool calls in real-time,
scores them for risk, and blocks dangerous actions before execution.

## Status
🚧 Active Development — FAR AWAY Hackathon 2026

## Stack
- Python / FastAPI
- SQLite (persistence: agents, tokens, trust profiles, governance)
- Optional: local LLM via **llama.cpp** (`llama-server`) for the semantic
  second-opinion layer

## Setup
```bash
pip install -r requirements.txt
uvicorn proxy.main:app --reload --port 8000
```

## Dashboard UI — Neon Terminal theme (Phase 4, 2026-08-23)

The single-file dashboard at `GET /ui` was restyled from the light cream theme
to the **Neon Terminal** design tokens (source: `New UI design Idea/` design
doc + `design.css`). **Content, layout and behaviour are unchanged** — only
the visual layer:

- **Palette** (extraction tokens): surface `#050505`, near-black card layering
  `#0A0A0A/#101010` (flat design — no shadows, hairline borders `#e5e7eb`),
  neon accents: green `#39ff14` (OK/ALLOWED/live), gold `#ffd700` (HIGH/warn),
  metallic `#d4af37` (MEDIUM/focus/active), magenta `#bf00ff` (CRITICAL/danger
  — the palette has no red; magenta is its strongest alert hue), cyan
  `#00e5ff` (info), mint `#00ff9d` (positive deltas).
- **Type:** system `ui-monospace` stack for data/labels; `ui-sans-serif` for
  page title, logo and KPI values (Google-Fonts Inter link removed).
- **WCAG AA:** all 33 text/background pairs verified ≥ 4.5:1 (computed,
  incl. alpha-composited tints). Magenta *text* uses the 20% white tint
  `--red-text:#d24dff`; pure `#bf00ff` is reserved for fills, dots and glow.
- **Glow:** restrained, same-hue 6–10 px glow on live dot, active nav, ⛔
  blocker dot and CRITICAL indicators only.
- Unchanged: 5 s REST poll, WS live updates (`THREAT_EVENT`,
  `ISOLATED_CALL_REJECTED`, `BLOCKERS_CHANGED`), filters/search/range, drawer +
  actions, IST time rendering, ⛔/● dots, a11y focus, responsive breakpoints.
- No backend changes — `dashboard/index.html` only (served `no-store`, edits
  need no restart). Roadmap + acceptance: `UI_REDESIGN_Roadmap.md`.
- Evidence: `dashboard_neon_terminal.png` (1600×2400) and
  `dashboard_neon_terminal_mobile.png` (768 px).

## LLM Second-Opinion (llama.cpp)

Every intercepted tool call is also queued for an **asynchronous review by a
real local model** (the semantic layer the spec calls for). It never delays
the pipeline; verdicts land in the audit chain, the dashboard, and — if the
model finds HIGH/CRITICAL danger the heuristics let through — retroactively
trigger threat → isolation → approval.

```bash
# 1) start your llama.cpp server (any OpenAI-compatible server works)
llama-server -m /path/to/model.gguf --host 127.0.0.1 --port 8080 --jinja

# 2) point AgentTrust at it (all optional — auto-detect by default)
export AGENTTRUST_LLM_URL=http://localhost:8080/v1
export AGENTTRUST_LLM_TIMEOUT=300        # cold 27B CPU verdicts can take ~3 min

# 3) inspect
GET /llm/status                          # model availability + queue
GET /llm/reviews?agent_id=finance-agent-01   # real verdicts + reasoning
```

Notes:
- Qwen3 "thinking" models: the client sends `enable_thinking:false` so the
  model returns the JSON verdict directly instead of a long internal reasoning
  chain (order-of-magnitude faster).
- If the server is down, the system runs **heuristic-only** (circuit breaker)
  and degrades gracefully — the pipeline is never blocked by the LLM.
- Dashboard: open `http://localhost:<port>/ui` → “LLM Second Opinion” panel.

## Governance — Prerequisites

Every agent carries a **prerequisites profile**: the conditions that must hold
before its actions may proceed. It is **derived from recorded context** at
registration (declared intent → intent scope, declared permissions → permission
scope, blast radius → blast gate, plus the policy trust floor and the
Zero-Trust / isolation / sandbox invariants), and **editable** by the operator.

On **every intercepted tool call** the profile is evaluated (in-memory,
sub-millisecond, exception-safe) and attached to the decision payload, the
audit chain, and the dashboard — itemizing exactly which prerequisites are
satisfied, which are not, and why.

Safety model:
- **Security invariants** (valid token, not isolated, not sandboxed) are
  surfaced but **locked** — they can never be removed or relaxed via this API.
- **Derived defaults** (intent/permission/trust/blast) are editable for
  tuning (severity/enforce) but not removable.
- **Custom** operator prerequisites are real gates (deterministic checks only:
  `param_equals` / `param_in` / `param_present` — no code execution) and, when
  unsatisfied, escalate an ALLOWED/FLAGGED decision to BLOCK. Escalation is
  **stricter-only**; governance never relaxes a decision or touches trust.
- Every edit is **versioned and hash-chained into the audit trail**
  (`GOVERNANCE_UPDATED` / `GOVERNANCE_EDIT_REJECTED`).

```bash
GET  /agents/{id}/governance        # profile + live state evaluation
PUT  /agents/{id}/governance        # {actor, expected_version?, edits}
     # edits: add_custom[{label, severity, check}], remove[ids], update[{id,...}]
     # 404 unknown agent · 409 stale version · 422 validation rejection

python demo_agent/governance_demo.py   # live normal + exception walkthrough
```

Profiles persist in SQLite (survive restart). The hot path never writes: a
missing profile is derived in-memory and persisted lazily by the GET endpoint.
See `RESEARCH_Task_Prerequisites_Blockers_Downstream_Effects.md` for the design
and the remaining concepts (blockers, downstream effects).

## Governance — Blockers (concept 2 of 3)

The companion view to prerequisites: **"why can't agent X act right now — and
how do I fix it?"** Blockers are a **live, computed, read-only view** — never
stored, never editable. They are derived on demand from the engines that
actually enforce them, so the view can never be stale, and a blocker is only
cleared by performing the real underlying action (no override button exists).

| Blocker | Source | Severity | Cleared by |
|---|---|---|---|
| `ISOLATED` | isolation registry | hard | `POST /agents/release/{id}` |
| `TOKEN_INVALID` | token store (no/revoked/expired) | hard | re-register (fresh token) |
| `TRUST_BELOW_FLOOR` | trust < policy floor (40) | hard | behavioural trust recovery (advisory) |
| `SANDBOXED` | trust containment < 30 | hard | behavioural (automatic) |
| `RESTRICTED` | trust containment < 50 | soft | advisory |
| `PENDING_APPROVAL` | approval engine | soft | `POST /approvals/{id}/approve` |
| `CUSTOM_GATE` | standing custom prerequisites | soft (per-call hard when a call fails it) | compliant params or governance edit |

Status: `BLOCKED` (any hard) / `DEGRADED` (soft only) / `CLEAR`.

```bash
GET /agents/{id}/blockers        # itemized live view (404 unknown agent)
python demo_agent/blockers_demo.py   # live normal + exception + unblock walkthrough
```

Every intercepted decision also carries a `blockers` snapshot (agent state +
this call's failed tool-scoped prerequisites) into the decision payload and
the hash-chained audit trail; the 403 isolation-guard response carries it too
(always fresh — the guard path bypasses the 1 s view cache). The dashboard
shows a **Blockers** section in the agent drawer (with working Release/
Approve buttons) and a **Blockers at Decision Time** section in the decision
drawer. Agents with a hard blocker carry a **⛔ dot** in the agent table
(rows are annotated with live `blocker_status` by `/dashboard/agents`), and
the dashboard is updated **in real time** via a `BLOCKERS_CHANGED`
WebSocket push whenever any blocker source changes (isolate/release,
revoke/register, approve/reject, governance edits, trust transitions) — no
refresh needed. Build plan + evidence: `PHASE2_Blockers_Plan.md` (O1/O2
section, 2026-08-23).

## Governance — Downstream Effects (concept 3 of 3)

The third concept: **"what happens if it runs"** — which entities consume
the agent's output, how are they affected, and what does the system itself
record. The only stored input is the **recorded context**
(`downstream_agents` declared at registration); consumer state is read live
(trust store → durable row → default), always read-only. Like blockers,
effects are **computed, never stored, never editable**.

Consumer impact classes: `HEALTHY` / `DEGRADED` / `QUARANTINED` /
`UNKNOWN` (declared-but-unregistered consumers are surfaced honestly, never
invented). Status: `HEALTHY_CHAIN / DEGRADED / QUARANTINED / NO_CONSUMERS`.

**The single advisory (D3, stricter-only):** a non-blocked call whose
declared consumer is quarantined carries a human-review reason — from
ALLOWED it is escalated to FLAGGED (feeding a quarantined agent is a
lateral-movement red flag); on an already-FLAGGED call the reason joins the
existing review. Never BLOCK, never de-escalate, never touches trust. The
per-call snapshot is always fresh (cache bypassed, like the Phase-2 guard),
because the advisory can drive a decision.

```bash
GET /agents/{id}/effects         # consumer table + systemic effects (404 unknown)
python demo_agent/effects_demo.py   # normal + exception + unblock + blocked cases
```

Every decision payload carries an `effects` snapshot (consumer rows +
action-specific impact — "output will flow to N consumer(s)" or "consumers
starved; agent trust now X" — + systemic rows: audit trail, trust feedback,
threat correlation). The dashboard shows **Downstream Effects** in the agent
drawer and in the decision drawer (with an "advisory applied" marker when
the D3 escalation fired). Build plan + evidence:
`PHASE3_Downstream_Effects_Plan.md`.

> **Roadmap complete:** all three governance concepts are built on the same
> foundation — recorded context as the only stored input, derived +
> read-only live views, stricter-only influence on decisions, hash-chained
> audit everywhere. Total suite: 88 passing.

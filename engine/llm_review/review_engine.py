"""
AgentTrust OS — LLM Second-Opinion Review Engine (llama.cpp)

The local 27B model runs CPU-bound at ~90-120s per verdict, so it CANNOT sit
on the synchronous interception hot path. Instead it operates as an
asynchronous second-opinion layer:

    fast heuristic pipeline  ──▶  immediate decision (ms, fail-closed)
            │
            └──▶ LLM review queue (async, background)
                        │
                        ▼
              real model verdict (JSON + reasoning)
                        │
        ┌───────────────┼───────────────────────────┐
        ▼               ▼                           ▼
  audit chain       dashboard               retroactive escalation
  (LLM_REVIEW_*)   /llm/reviews            if the LLM finds HIGH/CRITICAL
                                            on a call the heuristics ALLOWED

Security contract:
  • Reviews NEVER delay, alter, or veto the original decision.
  • The LLM can only escalate AFTER the fact (threat event + isolation),
    matching the PDF's threat-detected → isolate → approval flow.
  • Queue is capped; overflow is marked "dropped" — never fabricated.
"""

import asyncio
import time
import uuid
from typing import Any, Callable, Dict, List, Optional

from infrastructure.llm import get_llm_client, llm_status

MAX_PENDING   = 10          # queue cap (server runs with --parallel 1)
MAX_STORED    = 200         # in-memory review history


class LLMReviewEngine:
    def __init__(
        self,
        on_complete: Optional[Callable[[Dict[str, Any]], None]] = None,
        on_escalation: Optional[Callable[[str, Dict[str, Any]], None]] = None,
    ):
        """
        on_complete(review)     — called for every finished review (audit hook)
        on_escalation(agent, v) — called when the LLM out-severities an
                                  ALLOWED/FLAGGED decision (isolation hook)
        """
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=MAX_PENDING)
        self._store: List[Dict[str, Any]] = []
        self._pending: Dict[str, Dict[str, Any]] = {}
        self._worker: Optional[asyncio.Task] = None
        self._on_complete   = on_complete
        self._on_escalation = on_escalation
        self.total_completed = 0
        self.total_escalated = 0
        self.total_dropped   = 0
        self.total_failed    = 0

    # ── Lifecycle ────────────────────────────────────────────────────

    async def start(self) -> None:
        if self._worker is None or self._worker.done():
            self._worker = asyncio.create_task(self._work())

    async def stop(self) -> None:
        if self._worker:
            self._worker.cancel()

    # ── Submission ───────────────────────────────────────────────────

    def submit(
        self,
        agent_id: str,
        tool: str,
        parameters: Dict[str, Any],
        declared_intent: str,
        original_action: str,
        original_risk_level: str,
    ) -> Dict[str, Any]:
        """Queue a tool call for real-model review. Returns status dict."""
        status = llm_status()
        if not status["available"]:
            return {"review_id": None, "status": "llm-unavailable",
                    "detail": status["last_error"] or "llama-server not reachable"}
        if status["circuit_breaker_open"]:
            return {"review_id": None, "status": "circuit-breaker-open",
                    "detail": "LLM failures exceeded threshold; retrying later"}

        review_id = uuid.uuid4().hex[:8]
        review = {
            "review_id": review_id,
            "agent_id": agent_id,
            "tool": tool,
            "parameters": parameters,
            "declared_intent": declared_intent,
            "original_action": original_action,
            "original_risk_level": original_risk_level,
            "status": "queued",
            "submitted_at": time.time(),
            "completed_at": None,
            "duration_s": None,
            "verdict": None,
            "agreement": None,
            "escalated": False,
        }
        self._pending[review_id] = review
        try:
            self._queue.put_nowait(review_id)
        except asyncio.QueueFull:
            self._pending.pop(review_id, None)
            self.total_dropped += 1
            return {"review_id": None, "status": "dropped-queue-full",
                    "detail": f"more than {MAX_PENDING} reviews pending — "
                              f"heuristic decision stands"}
        return {"review_id": review_id, "status": "queued"}

    # ── Worker ───────────────────────────────────────────────────────

    async def _work(self) -> None:
        client = get_llm_client()
        while True:
            review_id = await self._queue.get()
            review = self._pending.get(review_id)
            if review is None:
                continue
            try:
                # Run the blocking HTTP call off the event loop
                verdict = await asyncio.to_thread(
                    client.assess_tool_call,
                    review["tool"],
                    review["parameters"],
                    review["declared_intent"],
                )
                review["completed_at"] = time.time()
                review["duration_s"] = round(
                    review["completed_at"] - review["submitted_at"], 1)

                if verdict is None:
                    review["status"] = "failed"
                    review["error"] = client.last_error
                    self.total_failed += 1
                else:
                    review["verdict"] = verdict
                    review["status"] = "completed"
                    self.total_completed += 1
                    self._check_agreement(review)
                    self._maybe_escalate(review)
            except Exception as e:  # never kill the worker
                review["status"] = "failed"
                review["error"] = str(e)[:200]
                self.total_failed += 1
            finally:
                self._pending.pop(review_id, None)
                self._store.insert(0, review)
                self._store = self._store[:MAX_STORED]
                if self._on_complete:
                    try:
                        self._on_complete(review)
                    except Exception:
                        pass
            self._queue.task_done()

    @staticmethod
    def _check_agreement(review: Dict[str, Any]) -> None:
        """Agreement = model and heuristics on the SAME side of the danger
        line (HIGH+ = dangerous). Disagreement below the line is noted but
        never de-escalates; above the line it triggers escalation."""
        rank      = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        v_side = rank.get((review["verdict"] or {}).get("risk_level", "LOW"), 0) >= 2
        o_side = rank.get(review["original_risk_level"], 0) >= 2
        review["agreement"] = (v_side == o_side)

    def _maybe_escalate(self, review: Dict[str, Any]) -> None:
        """Retroactive escalation: LLM found HIGH/CRITICAL that the
        synchronous heuristics let through (ALLOWED/FLAGGED)."""
        review.setdefault("escalated", False)
        verdict = review.get("verdict") or {}
        if verdict.get("risk_level") not in ("HIGH", "CRITICAL"):
            return
        if review["original_action"] not in ("ALLOWED", "FLAGGED"):
            return
        review["escalated"] = True
        self.total_escalated += 1
        if self._on_escalation:
            try:
                self._on_escalation(review["agent_id"], verdict)
            except Exception as e:
                print(f"[LLMReview] escalation hook failed: {e}")

    # ── Read API ─────────────────────────────────────────────────────

    def get_reviews(self, agent_id: Optional[str] = None,
                    limit: int = 50) -> List[Dict[str, Any]]:
        reviews = self._store
        if agent_id:
            reviews = [r for r in reviews if r["agent_id"] == agent_id]
        return reviews[:limit]

    def stats(self) -> Dict[str, Any]:
        queued = len(self._pending)
        return {
            "llm": llm_status(),
            "queued": queued,
            "max_pending": MAX_PENDING,
            "completed": self.total_completed,
            "escalated": self.total_escalated,
            "failed": self.total_failed,
            "dropped": self.total_dropped,
        }

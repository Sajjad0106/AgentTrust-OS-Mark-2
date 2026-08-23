"""
AgentTrust OS — Local LLM Semantic Analyzer (llama.cpp integration)

Replaces the mocked Azure OpenAI layer from the design spec with a real
local model served by llama.cpp's OpenAI-compatible API (llama-server).

Configuration (environment variables):
    AGENTTRUST_LLM_URL      — base URL of llama-server (default http://localhost:8080/v1)
    AGENTTRUST_LLM_MODEL    — model id (default: auto-detected from /v1/models)
    AGENTTRUST_LLM_TIMEOUT  — per-call timeout in seconds (default 300.0 —
                              a local 27B CPU model needs ~3 min per cold verdict)
    AGENTTRUST_LLM_ENABLED  — "1"/"0" to force on/off (default: auto = server reachable)

Security contract:
    • The LLM verdict can only ESCALATE the heuristic risk (max of both).
      It can never lower it — a broken or tricked LLM cannot weaken
      protection (fail-safe in both directions).
    • A down/slow LLM NEVER blocks or breaks the pipeline: every call
      degrades to heuristic-only with a status marker.
    • A circuit breaker stops hammering an unavailable server:
      2 consecutive failures -> breaker open for 60s -> heuristic-only.
"""

import json
import os
import re
import time
from typing import Any, Dict, Optional

try:
    import httpx
except ImportError:  # pragma: no cover
    httpx = None

LLM_URL      = os.getenv("AGENTTRUST_LLM_URL", "http://localhost:8080/v1")
LLM_MODEL    = os.getenv("AGENTTRUST_LLM_MODEL", "")   # empty -> auto-detect
LLM_TIMEOUT  = float(os.getenv("AGENTTRUST_LLM_TIMEOUT", "300"))
LLM_ENABLED  = os.getenv("AGENTTRUST_LLM_ENABLED", "")  # "" = auto

# Kept minimal on purpose: the local 27B model processes prompt tokens at
# only a few tokens/second on CPU — every prompt token costs real seconds.
SYSTEM_PROMPT = (
    "You are the semantic security analyzer of AgentTrust OS. Judge the real "
    "semantic danger of this agent tool call (intent bypass, obfuscation, "
    "credential theft, exfiltration, destruction, lateral movement). "
    "Reply with ONLY minified JSON: {\"dangerous\":bool,\"risk_score\":0-100,"
    "\"risk_level\":\"LOW|MEDIUM|HIGH|CRITICAL\",\"reasoning\":\"max 90 chars\","
    "\"mitre_technique\":\"Txxxx|N/A\"}"
)

LEVEL_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


class LLMClient:
    """Thin, fail-safe client for a local llama-server (OpenAI-compatible)."""

    def __init__(self) -> None:
        self.model: str = LLM_MODEL
        self._available: Optional[bool] = None
        self._available_checked_at: float = 0.0
        self._fail_streak: int = 0
        self._breaker_open_until: float = 0.0
        self.last_error: str = ""

    # ── Availability / circuit breaker ──────────────────────────────

    def is_available(self) -> bool:
        """Auto-detect the local LLM server (cached 30s) + circuit breaker."""
        if LLM_ENABLED == "0":
            return False
        now = time.time()
        if self._available_checked_at and now - self._available_checked_at < 30:
            return self._available is True
        if now < self._breaker_open_until:
            return False
        ok = self._probe()
        self._available = ok
        self._available_checked_at = now
        return ok

    def _probe(self) -> bool:
        if httpx is None:
            return False
        try:
            r = httpx.get(f"{LLM_URL}/models", timeout=2.5)
            if r.status_code != 200:
                return False
            # Auto-detect model id if not pinned
            if not self.model:
                data = r.json().get("data", [])
                if data:
                    self.model = data[0].get("id", "local")
            return True
        except Exception:
            return False

    def _record_failure(self) -> None:
        self._fail_streak += 1
        if self._fail_streak >= 2:
            self._breaker_open_until = time.time() + 60
            print(f"[LLM] Circuit breaker open for 60s — heuristic-only mode "
                  f"(last error: {self.last_error[:120]})")

    def _record_success(self) -> None:
        self._fail_streak = 0

    # ── Core assessment ──────────────────────────────────────────────

    def assess_tool_call(
        self,
        tool_name: str,
        parameters: Dict[str, Any],
        declared_intent: str = "",
    ) -> Optional[Dict[str, Any]]:
        """Ask the local LLM to judge one tool call.

        Returns a normalized verdict dict, or None if the LLM is
        unavailable / timed out / returned garbage (caller falls back).
        """
        if httpx is None or not self.is_available():
            self.last_error = "llm unavailable" if not self.is_available() else "httpx missing"
            return None

        user_msg = (
            f"Intent: {declared_intent or 'unknown'} | "
            f"Call: {tool_name}({json.dumps(parameters, default=str)[:600]})"
        )
        try:
            r = httpx.post(
                f"{LLM_URL}/chat/completions",
                json={
                    "model": self.model or "local",
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": user_msg},
                    ],
                    "temperature": 0.0,
                    "max_tokens": 120,
                    # Qwen3 thinking models: suppress the internal reasoning
                    # chain — we only want the JSON verdict (saves ~90s/call).
                    "chat_template_kwargs": {"enable_thinking": False},
                },
                timeout=LLM_TIMEOUT,
            )
            if r.status_code != 200:
                self.last_error = f"llm http {r.status_code}"
                self._record_failure()
                return None
            text = r.json()["choices"][0]["message"]["content"].strip()
            verdict = self._parse_verdict(text, tool_name)
            if verdict is None:
                self.last_error = f"llm unparseable: {text[:120]}"
                self._record_failure()
                return None
            self._record_success()
            return verdict
        except httpx.TimeoutException:
            self.last_error = f"llm timeout ({LLM_TIMEOUT}s)"
            self._record_failure()
            return None
        except Exception as e:
            self.last_error = f"llm error: {str(e)[:120]}"
            self._record_failure()
            return None

    @staticmethod
    def _parse_verdict(text: str, tool_name: str) -> Optional[Dict[str, Any]]:
        """Robustly extract the JSON verdict from model output."""
        # Strip markdown fences if the model added them anyway
        text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip())
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if not match:
            return None
        try:
            raw = json.loads(match.group(0))
        except json.JSONDecodeError:
            return None

        try:
            score = max(0, min(100, int(float(raw.get("risk_score", 0)))))
        except (TypeError, ValueError):
            return None
        level = str(raw.get("risk_level", "")).upper()
        if level not in LEVEL_RANK:
            # Derive level from score if the model was inconsistent
            level = ("CRITICAL" if score >= 70 else
                     "HIGH" if score >= 45 else
                     "MEDIUM" if score >= 25 else "LOW")
        reasoning = str(raw.get("reasoning", "")).strip()[:300]
        if not reasoning:
            return None
        return {
            "dangerous": bool(raw.get("dangerous", score >= 45)),
            "risk_score": score,
            "risk_level": level,
            "reasoning": reasoning,
            "mitre_technique": str(raw.get("mitre_technique", "N/A"))[:20] or "N/A",
            "model": "local-llama.cpp",
        }


# ── Global instance ──────────────────────────────────────────────────
_llm_client: Optional[LLMClient] = None


def get_llm_client() -> LLMClient:
    global _llm_client
    if _llm_client is None:
        _llm_client = LLMClient()
    return _llm_client


def llm_status() -> Dict[str, Any]:
    """Health snapshot for dashboard / startup banner."""
    client = get_llm_client()
    client.is_available()  # refresh probe
    return {
        "enabled": LLM_ENABLED != "0",
        "available": client._available is True,
        "url": LLM_URL,
        "model": client.model or "(not detected)",
        "timeout_s": LLM_TIMEOUT,
        "circuit_breaker_open": time.time() < client._breaker_open_until,
        "last_error": client.last_error,
    }

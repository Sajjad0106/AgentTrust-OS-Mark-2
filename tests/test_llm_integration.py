"""
Offline tests for the llama.cpp LLM integration (no live server needed):
  • verdict parsing robustness (fences, clamping, level derivation, garbage)
  • review queue semantics (cap, unavailable status, agreement/escalation logic)
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from infrastructure.llm import LLMClient  # noqa: E402
from engine.llm_review.review_engine import LLMReviewEngine, MAX_PENDING  # noqa: E402


# ── Verdict parsing ──────────────────────────────────────────────────────────

def test_parse_plain_json():
    v = LLMClient._parse_verdict(
        '{"dangerous": true, "risk_score": 85, "risk_level": "HIGH", '
        '"reasoning": "credential file access", "mitre_technique": "T1078"}',
        "read_file")
    assert v and v["risk_score"] == 85 and v["risk_level"] == "HIGH"
    assert v["dangerous"] is True and v["mitre_technique"] == "T1078"


def test_parse_markdown_fenced():
    v = LLMClient._parse_verdict(
        '```json\n{"dangerous": false, "risk_score": 10, "risk_level": "LOW", '
        '"reasoning": "routine ticket read"}\n```',
        "read_ticket")
    assert v and v["risk_level"] == "LOW" and v["risk_score"] == 10


def test_parse_score_clamped():
    v = LLMClient._parse_verdict(
        '{"risk_score": 250, "risk_level": "LOW", "reasoning": "x"}', "t")
    assert v and v["risk_score"] == 100


def test_parse_bad_level_derived_from_score():
    v = LLMClient._parse_verdict(
        '{"risk_score": 72, "risk_level": "WHATEVER", "reasoning": "x"}', "t")
    assert v and v["risk_level"] == "CRITICAL"  # 72 >= 70


def test_parse_no_reasoning_rejected():
    assert LLMClient._parse_verdict('{"risk_score": 50}', "t") is None


def test_parse_garbage_rejected():
    assert LLMClient._parse_verdict("I think this is dangerous!", "t") is None
    assert LLMClient._parse_verdict("", "t") is None


def test_parse_score_out_of_range_negative():
    v = LLMClient._parse_verdict('{"risk_score": -5, "reasoning": "x"}', "t")
    assert v and v["risk_score"] == 0 and v["risk_level"] == "LOW"


# ── Review queue semantics ───────────────────────────────────────────────────

def test_queue_cap_drops_overflow():
    eng = LLMReviewEngine()
    # Force "available" so submit() enqueues instead of rejecting
    eng._client = None  # unused; we patch llm_status via monkeypatch
    import engine.llm_review.review_engine as mod
    orig = mod.llm_status
    mod.llm_status = lambda: {"available": True, "circuit_breaker_open": False,
                              "last_error": ""}
    try:
        for i in range(MAX_PENDING + 5):
            r = eng.submit("agent-x", "tool", {}, "intent", "ALLOWED", "LOW")
            if i < MAX_PENDING:
                assert r["status"] == "queued", r
            else:
                assert r["status"] == "dropped-queue-full", r
    finally:
        mod.llm_status = orig


def test_queue_unavailable_status():
    eng = LLMReviewEngine()
    import engine.llm_review.review_engine as mod
    orig = mod.llm_status
    mod.llm_status = lambda: {"available": False, "circuit_breaker_open": False,
                              "last_error": "llama-server down"}
    try:
        r = eng.submit("agent-x", "tool", {}, "intent", "ALLOWED", "LOW")
        assert r["status"] == "llm-unavailable" and r["review_id"] is None
    finally:
        mod.llm_status = orig


def test_agreement_and_escalation_logic():
    escalations = []
    eng = LLMReviewEngine(on_escalation=lambda a, v: escalations.append((a, v)))

    # LLM more severe than original + original was ALLOWED -> escalate
    r1 = {"agent_id": "a1", "original_action": "ALLOWED", "original_risk_level": "LOW",
          "verdict": {"risk_level": "CRITICAL", "risk_score": 90, "reasoning": "x"}}
    eng._check_agreement(r1)
    eng._maybe_escalate(r1)
    assert r1["agreement"] is False and r1["escalated"] is True
    assert len(escalations) == 1

    # LLM less severe than flagged original -> disagree, but no escalation
    r2 = {"agent_id": "a2", "original_action": "ALLOWED", "original_risk_level": "HIGH",
          "verdict": {"risk_level": "MEDIUM", "risk_score": 30, "reasoning": "x"}}
    eng._check_agreement(r2)
    eng._maybe_escalate(r2)
    assert r2["agreement"] is False and r2["escalated"] is False
    assert len(escalations) == 1

    # LLM severe but original already BLOCKED -> no escalation (already caught)
    r3 = {"agent_id": "a3", "original_action": "BLOCKED", "original_risk_level": "HIGH",
          "verdict": {"risk_level": "CRITICAL", "risk_score": 95, "reasoning": "x"}}
    eng._check_agreement(r3)
    eng._maybe_escalate(r3)
    assert r3["agreement"] is True and r3["escalated"] is False
    assert len(escalations) == 1


def _run_all():
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  PASS  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} LLM integration tests passed.")


if __name__ == "__main__":
    _run_all()

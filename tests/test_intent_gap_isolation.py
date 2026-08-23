"""
Regression test: Intent-Gap scope-creep history must be PER AGENT.

Bug history: proxy/main.py used to call analyze_intent_gap() WITHOUT agent_id,
so every agent accumulated into one shared "unknown" scope history. A
well-behaved agent got wrongly blocked (gap 65) because ANOTHER agent's
out-of-scope tools were counted against it.

This test pins the correct behaviour:
  • an in-scope tool passes clean (gap 5)
  • scope creep (3+ out-of-scope tools) is detected for the AGENT that did it
  • a DIFFERENT agent with the same intent is NOT contaminated by it
  • agent_id is now required (missing/empty -> error)

Run directly:   python tests/test_intent_gap_isolation.py
Or via pytest:  pytest tests/test_intent_gap_isolation.py
"""

import os
import sys

# Make the project root importable regardless of CWD
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.intent_gap.intent_engine import analyze_intent_gap  # noqa: E402


INTENT = "customer support and help desk"  # -> customer_support category

# Tools that are OUT of scope for customer_support (neither allowed nor forbidden)
OUT_OF_SCOPE = ["query_database", "read_file", "export_data"]
# A tool that IS in scope for customer_support
IN_SCOPE = ["read_ticket"]


def _gap(intent, tool, agent_id):
    return analyze_intent_gap(intent, tool, {}, agent_id).gap_score


def test_agent_id_is_required():
    """Missing agent_id must fail loudly, not fall back to shared state."""
    # Required positional arg -> calling without it raises TypeError.
    try:
        analyze_intent_gap(INTENT, "read_ticket", {})
    except TypeError:
        return
    raise AssertionError("analyze_intent_gap should require agent_id (no default)")


def test_empty_agent_id_is_rejected():
    """An empty agent_id is rejected (fail-closed), never used as a shared bucket."""
    for bad in ("", "   "):
        try:
            analyze_intent_gap(INTENT, "read_ticket", {}, bad)
        except ValueError:
            continue
        raise AssertionError(f"agent_id={bad!r} should be rejected")


def test_in_scope_tool_passes_clean():
    for agent in ("iso-agent-a", "iso-agent-b"):
        for tool in IN_SCOPE:
            assert _gap(INTENT, tool, agent) == 5, (
                f"in-scope tool {tool} should be gap 5 for {agent}"
            )


def test_scope_creep_is_per_agent_not_global():
    """
    Agent A creeps out of scope 3 times -> blocked (gap 65).
    Agent B, same intent, does the SAME out-of-scope tool ONCE -> must NOT
    inherit A's history (stays at 45, not 65).
    """
    a, b = "creep-agent-a", "creep-agent-b"

    # Agent A: three out-of-scope tools -> third triggers creep
    scores_a = [_gap(INTENT, t, a) for t in OUT_OF_SCOPE]
    assert scores_a[0] == 45, f"1st out-of-scope should be 45, got {scores_a[0]}"
    assert scores_a[1] == 45, f"2nd out-of-scope should be 45, got {scores_a[1]}"
    assert scores_a[2] == 65, f"3rd out-of-scope should trigger creep (65), got {scores_a[2]}"

    # Agent B: a fresh agent doing the same tool once must NOT be at 65
    first_b = _gap(INTENT, OUT_OF_SCOPE[0], b)
    assert first_b == 45, (
        f"Agent B contaminated by Agent A: expected 45, got {first_b} "
        f"(shared scope history — the original bug)"
    )


def test_block_flag_only_for_the_culprit():
    """Only the agent that creeps gets should_block=True.

    (Creep counts DISTINCT out-of-scope tools — same tool 3x is 1 entry.)
    """
    a, b = "block-agent-a", "block-agent-b"
    r = None
    for tool in OUT_OF_SCOPE:
        r = analyze_intent_gap(INTENT, tool, {}, a)
    assert r.should_block is True, "creeping agent A should be blocked"

    r_b = analyze_intent_gap(INTENT, OUT_OF_SCOPE[0], {}, b)
    assert r_b.should_block is False, "agent B must NOT be blocked by A's history"


def _run_all():
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for fn in fns:
        fn()
        passed += 1
        print(f"  PASS  {fn.__name__}")
    print(f"\n{passed}/{len(fns)} tests passed.")


if __name__ == "__main__":
    _run_all()

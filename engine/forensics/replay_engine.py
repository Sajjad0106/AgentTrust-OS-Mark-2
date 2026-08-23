from typing import Any
from engine.forensics.session_store import get_session


def replay_session(agent_id: str) -> dict[str, Any]:
    events = get_session(agent_id)

    if not events:
        return {"agent_id": agent_id, "total_events": 0, "replay": []}

    replay: list[dict[str, Any]] = []
    for event in events:
        d: dict[str, Any] = event.get("event", {})
        replay.append({
            "step"         : event["sequence"] + 1,
            "timestamp"    : event["timestamp"],
            "tool"         : d.get("tool", "unknown"),
            "action"       : d.get("action", "UNKNOWN"),
            "trust_score"  : d.get("trust_score", 100),
            "risk_level"   : d.get("risk_level", "LOW"),
            "intent_gap"   : d.get("intent_gap_score", 0),
            "dna_drift"    : d.get("dna_drift_score", 0),
            "prediction"   : d.get("prediction", "SAFE"),
            "policy_hits"  : len(d.get("policy_violations", [])),
            "reason"       : d.get("risk_reason", ""),
        })

    # Summarize the session
    blocked = sum(1 for r in replay if r["action"] == "BLOCKED")
    flagged = sum(1 for r in replay if r["action"] == "FLAGGED")
    trust_collapse = any(r["trust_score"] < 30 for r in replay)

    return {
        "agent_id"       : agent_id,
        "total_events"   : len(replay),
        "blocked"        : blocked,
        "flagged"        : flagged,
        "trust_collapsed": trust_collapse,
        "replay"         : replay
    }
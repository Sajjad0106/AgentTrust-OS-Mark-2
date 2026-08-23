"""
AgentTrust OS — Cross-Agent Threat Correlation Engine (Layer 7)

Maintains the live threat feed consumed by the dashboard Threat Center.
Escalated events (HIGH/CRITICAL risk or large intent gaps) are recorded;
agents performing the same escalated tool recently are correlated.
"""

from datetime import datetime, timezone
from typing import Any

THREAT_FEED: list[dict[str, Any]] = []
AGENT_THREAT_COUNT: dict[str, int] = {}
RECENT_ESCALATED_TOOLS: list[tuple[str, str]] = []  # (tool, agent_id)
FEED_LIMIT = 200
WINDOW = 50


def _escalated(risk_level: str, intent_gap: int) -> bool:
    return risk_level in ("HIGH", "CRITICAL") or intent_gap >= 70


def correlate_threat(agent_id: str, tool: str, risk_level: str, intent_gap: int) -> dict[str, Any]:
    tool_l = tool.lower()

    if _escalated(risk_level, intent_gap):
        AGENT_THREAT_COUNT[agent_id] = AGENT_THREAT_COUNT.get(agent_id, 0) + 1

        # Cross-agent correlation: other agents escalated on the same tool recently
        correlated = sorted({
            other
            for (t, other) in RECENT_ESCALATED_TOOLS
            if t == tool_l and other != agent_id
        })

        THREAT_FEED.append({
            "threat_level"      : risk_level if risk_level in ("HIGH", "CRITICAL") else "MEDIUM",
            "agent_id"          : agent_id,
            "tool"              : tool,
            "intent_gap"        : intent_gap,
            "correlated_agents" : correlated,
            "agent_threat_count": AGENT_THREAT_COUNT[agent_id],
            "timestamp"         : datetime.now(timezone.utc).isoformat(),
        })
        if len(THREAT_FEED) > FEED_LIMIT:
            del THREAT_FEED[:-FEED_LIMIT]

        RECENT_ESCALATED_TOOLS.append((tool_l, agent_id))
        if len(RECENT_ESCALATED_TOOLS) > WINDOW:
            del RECENT_ESCALATED_TOOLS[: len(RECENT_ESCALATED_TOOLS) - WINDOW]

        return {
            "threat_level"      : risk_level if risk_level in ("HIGH", "CRITICAL") else "MEDIUM",
            "correlated_agents" : correlated,
            "agent_threat_count": AGENT_THREAT_COUNT[agent_id],
        }

    return {
        "threat_level"      : "NONE",
        "correlated_agents" : [],
        "agent_threat_count": AGENT_THREAT_COUNT.get(agent_id, 0),
    }


def get_threat_feed() -> list[dict[str, Any]]:
    return list(THREAT_FEED)

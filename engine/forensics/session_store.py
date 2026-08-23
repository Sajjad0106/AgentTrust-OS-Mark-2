from datetime import datetime, timezone
from typing import Any

# agent_id → list of session events
SESSION_STORE: dict[str, list[dict[str, Any]]] = {}


def record_event(agent_id: str, event: dict[str, Any]) -> None:
    if agent_id not in SESSION_STORE:
        SESSION_STORE[agent_id] = []

    SESSION_STORE[agent_id].append({
        "sequence"  : len(SESSION_STORE[agent_id]),
        "timestamp" : datetime.now(timezone.utc).isoformat() + "Z",
        "event"     : event
    })


def get_session(agent_id: str) -> list[dict[str, Any]]:
    return SESSION_STORE.get(agent_id, [])


def get_all_sessions() -> dict[str, int]:
    return {
        aid: len(events)
        for aid, events in SESSION_STORE.items()
    }
from typing import Any
from engine.predictive.sequence_models import ActionSequence

SEQUENCE_STORE: dict[str, ActionSequence] = {}

# Known attack sequences — order matters
# Format: (pattern_name, sequence_of_tools, threat_prediction)
ATTACK_SEQUENCES = [
    (
        "credential_harvest_chain",
        ["read_file", "read_file", "send_request"],
        "EXFILTRATION_IMMINENT",
        95
    ),
    (
        "reconnaissance_pattern",
        ["list_directory", "read_file", "get_content"],
        "DATA_THEFT_BUILDING",
        75
    ),
    (
        "lateral_movement",
        ["get_contacts", "send_email", "send_request"],
        "LATERAL_MOVEMENT_DETECTED",
        85
    ),
    (
        "destructive_sequence",
        ["list_directory", "read_file", "run_command"],
        "DESTRUCTIVE_ATTACK_IMMINENT",
        98
    ),
    (
        "data_exfil_buildup",
        ["query_database", "export_data", "send_request"],
        "DATA_EXFILTRATION_IMMINENT",
        92
    ),
]

SEQUENCE_WINDOW = 5  # Look at last N actions


def update_sequence(agent_id: str, tool: str) -> ActionSequence:
    if agent_id not in SEQUENCE_STORE:
        SEQUENCE_STORE[agent_id] = ActionSequence(agent_id=agent_id)

    seq = SEQUENCE_STORE[agent_id]
    seq.actions.append(tool.lower())

    # Keep only last N actions
    if len(seq.actions) > SEQUENCE_WINDOW:
        seq.actions = seq.actions[-SEQUENCE_WINDOW:]

    # Check against known attack sequences
    seq.prediction       = "SAFE"
    seq.prediction_score = 0
    seq.matched_pattern  = ""

    for pattern_name, attack_seq, prediction, score in ATTACK_SEQUENCES:
        if _sequence_matches(seq.actions, attack_seq):
            seq.prediction       = prediction
            seq.prediction_score = score
            seq.matched_pattern  = pattern_name
            break

    SEQUENCE_STORE[agent_id] = seq
    return seq


def _sequence_matches(recent: list[str], pattern: list[str]) -> bool:
    """Check if pattern appears as subsequence in recent actions"""
    if len(pattern) > len(recent):
        return False
    # Check last N actions contain the pattern in order
    recent_str  = " ".join(recent)
    pattern_str = " ".join(pattern)
    return pattern_str in recent_str


def get_sequence_summary(agent_id: str) -> dict[str, Any]:
    seq = SEQUENCE_STORE.get(agent_id)
    if not seq:
        return {"prediction": "SAFE", "prediction_score": 0, "matched_pattern": ""}
    return {
        "prediction"      : seq.prediction,
        "prediction_score": seq.prediction_score,
        "matched_pattern" : seq.matched_pattern,
        "recent_actions"  : seq.actions
    }
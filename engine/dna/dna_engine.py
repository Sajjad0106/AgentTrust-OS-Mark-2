from __future__ import annotations

import hashlib
import json
import math
from datetime import datetime, timezone
from typing import Any, Dict, Mapping, Sequence
from engine.dna.dna_models import DNAProfile

DNA_STORE        : Dict[str, DNAProfile] = {}
DRIFT_THRESHOLD  = 55.0
BASELINE_ACTIONS = 5      # Lock baseline after N clean actions
MAX_PARAM_HISTORY = 20


def get_or_create_dna(agent_id: str) -> DNAProfile:
    if agent_id not in DNA_STORE:
        DNA_STORE[agent_id] = DNAProfile(agent_id=agent_id)
    return DNA_STORE[agent_id]


def update_dna(agent_id: str, tool: str, parameters: Mapping[str, Any]) -> DNAProfile:
    profile = get_or_create_dna(agent_id)
    now     = datetime.now(timezone.utc)

    # ── Tool frequency ────────────────────────────────────────
    profile.tool_frequency[tool] = profile.tool_frequency.get(tool, 0) + 1
    profile.action_count         += 1
    profile.unique_tools          = len(profile.tool_frequency)

    # ── Parameter length tracking ─────────────────────────────
    param_len = len(json.dumps(parameters))
    profile.param_length_history.append(param_len)
    if len(profile.param_length_history) > MAX_PARAM_HISTORY:
        profile.param_length_history = profile.param_length_history[-MAX_PARAM_HISTORY:]

    profile.avg_param_length = sum(profile.param_length_history) / len(profile.param_length_history)
    profile.param_length_stddev = _stddev(profile.param_length_history)

    # ── Shannon entropy of tool distribution ─────────────────
    profile.entropy_score = _shannon_entropy(profile.tool_frequency)

    # ── Temporal pattern tracking ─────────────────────────────
    hour = now.hour
    profile.temporal.last_action_hour = hour
    profile.temporal.hour_distribution[hour] = (
        profile.temporal.hour_distribution.get(hour, 0) + 1
    )
    # Flag unusual hours (2am–5am UTC)
    if 2 <= hour <= 5:
        profile.temporal.unusual_hour_count += 1

    # ── Compute current fingerprint ───────────────────────────
    profile.fingerprint = _compute_fingerprint(profile)

    # ── Lock baseline after enough clean actions ──────────────
    if not profile.baseline_locked and profile.action_count == BASELINE_ACTIONS:
        profile.baseline_fingerprint = profile.fingerprint
        profile.baseline_locked      = True

    # ── Compute drift ─────────────────────────────────────────
    if profile.action_count > BASELINE_ACTIONS:
        profile.drift_score = _compute_drift(profile)
        profile.drift_history.append(profile.drift_score)
        if len(profile.drift_history) > 20:
            profile.drift_history = profile.drift_history[-20:]
        profile.is_drifted = profile.drift_score >= DRIFT_THRESHOLD

    DNA_STORE[agent_id] = profile
    return profile


def _compute_fingerprint(profile: DNAProfile) -> str:
    data: Dict[str, Any] = {
        "top_3_tools"       : sorted(profile.tool_frequency.items(),
                                     key=lambda x: -x[1])[:3],
        "unique_tools"      : profile.unique_tools,
        "avg_param_length"  : round(profile.avg_param_length, 0),
        "entropy_bucket"    : round(profile.entropy_score, 1),
    }
    return hashlib.sha256(
        json.dumps(data, sort_keys=True).encode()
    ).hexdigest()[:20]


def _compute_drift(profile: DNAProfile) -> float:
    if not profile.baseline_locked:
        return 0.0

    total  = profile.action_count
    scores = []

    # Score 1: tool diversity drift
    # More unique tools than baseline → drifting
    diversity_ratio = profile.unique_tools / max(total, 1)
    scores.append(min(diversity_ratio * 60, 40.0))

    # Score 2: entropy spike
    # High entropy = agent doing too many different things
    if profile.entropy_score > 2.5:
        scores.append(min((profile.entropy_score - 2.5) * 20, 30.0))
    else:
        scores.append(0.0)

    # Score 3: unusual hours
    if profile.temporal.unusual_hour_count > 0:
        unusual_ratio = profile.temporal.unusual_hour_count / total
        scores.append(min(unusual_ratio * 50, 20.0))
    else:
        scores.append(0.0)

    # Score 4: parameter length anomaly (very large params = data staging)
    if profile.param_length_stddev > 500:
        scores.append(min(profile.param_length_stddev / 100, 10.0))
    else:
        scores.append(0.0)

    return round(sum(scores), 2)


def _shannon_entropy(freq: Dict[str, int]) -> float:
    """Shannon entropy of tool usage distribution."""
    total = sum(freq.values())
    if total == 0:
        return 0.0
    entropy = 0.0
    for count in freq.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def _stddev(values: Sequence[float | int]) -> float:
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    variance = sum((x - mean) ** 2 for x in values) / len(values)
    return round(math.sqrt(variance), 2)


def get_dna_summary(agent_id: str) -> Dict[str, Any]:
    profile = get_or_create_dna(agent_id)
    return {
        "agent_id"            : profile.agent_id,
        "fingerprint"         : profile.fingerprint,
        "baseline_fingerprint": profile.baseline_fingerprint,
        "baseline_locked"     : profile.baseline_locked,
        "drift_score"         : profile.drift_score,
        "is_drifted"          : profile.is_drifted,
        "entropy_score"       : profile.entropy_score,
        "unique_tools"        : profile.unique_tools,
        "action_count"        : profile.action_count,
        "avg_param_length"    : round(profile.avg_param_length, 1),
        "param_stddev"        : profile.param_length_stddev,
        "tool_frequency"      : profile.tool_frequency,
        "unusual_hour_count"  : profile.temporal.unusual_hour_count,
        "last_action_hour"    : profile.temporal.last_action_hour,
        "drift_trend"         : profile.drift_history[-5:],
    }
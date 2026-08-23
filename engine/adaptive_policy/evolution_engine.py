from collections import defaultdict
from typing import Any
from engine.adaptive_policy.evolution_models import EvolvedPolicy

EVOLVED_POLICIES: list[EvolvedPolicy] = []
PATTERN_TRACKER: dict[str, int] = defaultdict(int)

# Confidence threshold to auto-activate a new policy
AUTO_ACTIVATE_THRESHOLD = 3  # Seen 3 times → auto activate


def observe_event(tool: str, risk_level: str, action: str, params: dict[str, Any]) -> None:
    """
    Watch all blocked/flagged events.
    When a new pattern emerges that no policy covers — draft a new policy.
    """
    if action not in ("BLOCKED", "FLAGGED"):
        return

    param_str = str(params).lower()

    # Build pattern signature from tool + top param keywords
    keywords = _extract_keywords(param_str)
    if not keywords:
        return

    pattern_key = f"{tool.lower()}::{':'.join(sorted(keywords[:2]))}"
    PATTERN_TRACKER[pattern_key] += 1
    count = PATTERN_TRACKER[pattern_key]

    # Check if we already have a policy for this pattern
    existing = [p for p in EVOLVED_POLICIES if p.trigger_pattern == pattern_key]

    if not existing:
        # Draft a new evolved policy
        policy = EvolvedPolicy(
            name            = f"evolved-{tool.lower()}-{keywords[0]}-policy",
            trigger_pattern = pattern_key,
            tool_pattern    = [tool],
            value_pattern   = keywords[:3],
            confidence      = min(count / AUTO_ACTIVATE_THRESHOLD, 1.0),
            times_triggered = count,
            auto_activated  = False,
            status          = "DRAFT"
        )
        EVOLVED_POLICIES.append(policy)
    else:
        policy = existing[0]
        policy.times_triggered += 1
        policy.confidence = min(
            policy.times_triggered / AUTO_ACTIVATE_THRESHOLD, 1.0
        )

        # Auto activate when confidence is high enough
        if policy.times_triggered >= AUTO_ACTIVATE_THRESHOLD and not policy.auto_activated:
            policy.auto_activated = True
            policy.status         = "ACTIVE"
            print(f"[AdaptivePolicy] Auto-activated new policy: {policy.name}")


def get_evolved_policies() -> list[dict[str, Any]]:
    return [
        {
            "name"            : p.name,
            "trigger_pattern" : p.trigger_pattern,
            "tool_pattern"    : p.tool_pattern,
            "value_pattern"   : p.value_pattern,
            "confidence"      : round(p.confidence * 100, 1),
            "times_triggered" : p.times_triggered,
            "status"          : p.status,
            "auto_activated"  : p.auto_activated
        }
        for p in EVOLVED_POLICIES
    ]


def _extract_keywords(param_str: str) -> list[str]:
    stop = {"the", "a", "an", "is", "in", "on", "at", "to", "for", "of", "and", "or"}
    words = [
        w.strip("{}[]()\"',:")
        for w in param_str.split()
        if len(w) > 3 and w not in stop
    ]
    return list(dict.fromkeys(words))[:5]
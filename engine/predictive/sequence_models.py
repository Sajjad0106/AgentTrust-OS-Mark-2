from dataclasses import dataclass, field
from typing import cast

@dataclass
class ActionSequence:
    agent_id        : str
    actions         : list[str] = field(default_factory=lambda: cast(list[str], []))
    prediction      : str       = "SAFE"
    prediction_score: int       = 0
    matched_pattern : str       = ""
from dataclasses import dataclass
from typing import List

@dataclass
class EvolvedPolicy:
    name            : str
    trigger_pattern : str
    tool_pattern    : List[str]
    value_pattern   : List[str]
    confidence      : float
    times_triggered : int
    auto_activated  : bool
    status          : str   # DRAFT / ACTIVE / REJECTED
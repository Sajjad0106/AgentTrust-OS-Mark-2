from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List


def _int_int_dict() -> Dict[int, int]:
    return {}


def _str_int_dict() -> Dict[str, int]:
    return {}


def _int_list() -> List[int]:
    return []


def _float_list() -> List[float]:
    return []


@dataclass
class TemporalPattern:
    """Tracks when agent acts — unusual hours signal compromise."""
    hour_distribution : Dict[int, int] = field(default_factory=_int_int_dict)
    unusual_hour_count: int            = 0
    last_action_hour  : int            = -1

@dataclass
class DNAProfile:
    agent_id            : str
    tool_frequency      : Dict[str, int] = field(default_factory=_str_int_dict)
    param_length_history: List[int]      = field(default_factory=_int_list)
    avg_param_length    : float          = 0.0
    param_length_stddev : float          = 0.0
    unique_tools        : int            = 0
    action_count        : int            = 0
    entropy_score       : float          = 0.0   # Shannon entropy of tool distribution
    drift_score         : float          = 0.0   # 0 = stable, 100 = fully drifted
    is_drifted          : bool           = False
    fingerprint         : str            = ""
    baseline_fingerprint: str            = ""    # Set after first 5 actions
    baseline_locked     : bool           = False
    temporal            : TemporalPattern = field(default_factory=TemporalPattern)
    drift_history       : List[float]    = field(default_factory=_float_list)
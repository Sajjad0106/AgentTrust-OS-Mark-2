from dataclasses import dataclass, field
from typing import cast

@dataclass
class BlastRadiusProfile:
    agent_id             : str
    blast_score          : int        # 0-100
    blast_level          : str        # LOW / MEDIUM / HIGH / CRITICAL
    sensitive_path_count : int = 0
    network_access       : bool = False
    credential_access    : bool = False
    downstream_agents    : list[str] = field(default_factory=lambda: cast(list[str], []))
    declared_permissions : list[str] = field(default_factory=lambda: cast(list[str], []))
    reason               : str = ""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Dict


def _float_list() -> List[float]:
    return []


def _action_list() -> List["AgentAction"]:
    return []


def _event_list() -> List["TrustScoreEvent"]:
    return []


# ─────────────────────────────────────────────────────────────
# AgentAction
# Every action recorded with full context for forensic replay
# ─────────────────────────────────────────────────────────────

@dataclass
class AgentAction:
    tool              : str
    parameters        : dict
    risk_level        : str
    risk_score        : int
    intent_gap_score  : int   = 0
    mitre_technique   : str   = "N/A"
    mitre_tactic      : str   = "N/A"
    action_taken      : str   = "ALLOWED"
    blast_multiplier  : float = 1.0     # How blast radius amplified the penalty
    trust_before      : float = 100.0   # Trust score before this action
    trust_after       : float = 100.0   # Trust score after this action
    trust_delta       : float = 0.0     # Exact change caused by this action
    timestamp         : str   = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


# ─────────────────────────────────────────────────────────────
# TrustVelocity
# Tracks rate of change — rapid drops = active attack signal
# ─────────────────────────────────────────────────────────────

@dataclass
class TrustVelocity:
    last_5_scores      : List[float] = field(default_factory=_float_list)
    drop_rate          : float       = 0.0    # Avg pts lost per action (window)
    gain_rate          : float       = 0.0    # Avg pts gained per clean action
    is_in_freefall     : bool        = False  # 20+ pts drop in 3 actions
    freefall_started_at: str         = ""
    peak_drop_single   : float       = 0.0    # Worst single-action drop ever


# ─────────────────────────────────────────────────────────────
# TrustScoreEvent
# Immutable log of every trust score change with full reasoning
# This is what a CISO actually wants to see
# ─────────────────────────────────────────────────────────────

@dataclass
class TrustScoreEvent:
    sequence      : int
    event_type    : str    # PENALTY / RECOVERY / SANDBOX / ESCALATION / DECAY
    trust_before  : float
    trust_after   : float
    delta         : float
    reason        : str
    trigger       : str    # What caused this — tool name, time decay, etc.
    timestamp     : str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


# ─────────────────────────────────────────────────────────────
# ContainmentLevel
# Graduated response — not just sandboxed/not sandboxed
# ─────────────────────────────────────────────────────────────

CONTAINMENT_LEVELS = {
    "NONE"     : 0,   # Normal operation
    "WATCH"    : 1,   # Elevated monitoring, all actions logged verbosely
    "RESTRICT" : 2,   # High-risk tools require approval before execution
    "SANDBOX"  : 3,   # All actions intercepted, outputs not applied
    "ISOLATE"  : 4,   # Agent fully isolated, zero actions permitted
}


# ─────────────────────────────────────────────────────────────
# TrustProfile
# Complete behavioral trust record for one agent
# ─────────────────────────────────────────────────────────────

@dataclass
class TrustProfile:
    agent_id             : str

    # ── Core Score ────────────────────────────────────────────
    trust_score          : float = 100.0
    peak_trust           : float = 100.0   # Best score ever in this session
    floor_trust          : float = 100.0   # Worst score ever in this session
    initial_trust        : float = 100.0   # Score at session start

    # ── Action Counters ───────────────────────────────────────
    total_actions        : int   = 0
    blocked_actions      : int   = 0
    flagged_actions      : int   = 0
    allowed_actions      : int   = 0
    consecutive_clean    : int   = 0
    consecutive_risk     : int   = 0
    max_consecutive_risk : int   = 0       # Worst streak this session

    # ── Containment ───────────────────────────────────────────
    containment_level    : str   = "NONE"
    containment_reason   : str   = ""
    containment_at       : str   = ""
    is_sandboxed         : bool  = False   # True when level >= SANDBOX
    sandbox_reason       : str   = ""      # Kept for backward compatibility

    # ── Risk Distribution ─────────────────────────────────────
    risk_distribution    : Dict[str, int] = field(default_factory=lambda: {
        "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0
    })

    # ── Velocity ──────────────────────────────────────────────
    trust_velocity       : TrustVelocity = field(default_factory=TrustVelocity)

    # ── Score Changelog — every change, full detail ───────────
    score_changelog      : List[TrustScoreEvent] = field(default_factory=_event_list)

    # ── Full Action History ───────────────────────────────────
    action_history       : List[AgentAction] = field(default_factory=_action_list)

    # ── Anomaly Flags ─────────────────────────────────────────
    anomaly_spikes       : int   = 0       # Times trust dropped > 25 in one action
    total_penalty_applied: float = 0.0
    total_recovery_earned: float = 0.0

    # ── Session Meta ──────────────────────────────────────────
    session_count        : int   = 1
    created_at           : str   = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    last_action_time     : str   = ""
    last_decay_applied   : str   = ""

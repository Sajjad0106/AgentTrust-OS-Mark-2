"""
AgentTrust OS — Trust Score Engine v2.0
Industry-grade behavioral trust scoring for AI agents.

Design principles:
  - Asymmetric decay: trust drops fast, rebuilds slowly (by design)
  - Blast radius amplification: high-impact agents penalised harder
  - Graduated containment: WATCH → RESTRICT → SANDBOX → ISOLATE
  - Time-based passive decay: idle agents lose trust slowly over time
  - Anomaly spike detection: single large drops generate security events
  - Full score changelog: every delta recorded with mathematical reason
  - JSON persistence: trust survives server restarts
"""

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List

from engine.trust_score.trust_models import (
    TrustProfile,
    AgentAction,
    TrustScoreEvent,
    CONTAINMENT_LEVELS,
)
from infrastructure.database import (
    create_or_update_trust_profile,
    get_trust_profile_db,
    get_all_trust_profiles_db,
)

# ─────────────────────────────────────────────────────────────
# Configuration
# All tunable — in production these come from a config file
# ─────────────────────────────────────────────────────────────

TRUST_CONFIG: Dict[str, Any] = {

    # ── Penalty weights ───────────────────────────────────────
    # Asymmetric: one bad action costs 28-45 pts, recovery earns 1.2/action
    # This mirrors real-world: it takes 23 clean actions to recover from one HIGH
    "PENALTY_CRITICAL"          : 45.0,
    "PENALTY_HIGH"              : 28.0,
    "PENALTY_MEDIUM"            : 10.0,
    "PENALTY_LOW"               : 0.0,

    # ── Intent gap amplifiers ─────────────────────────────────
    # If agent acts outside declared scope, penalty is multiplied
    "INTENT_GAP_AMP_CRITICAL"   : 1.5,   # gap > 80
    "INTENT_GAP_AMP_HIGH"       : 1.25,  # gap > 60
    "INTENT_GAP_AMP_MEDIUM"     : 1.1,   # gap > 40

    # ── Blast radius multipliers ──────────────────────────────
    # High blast radius agents are penalised harder for the same action
    # A CRITICAL agent that does something bad = worse trust impact
    "BLAST_MULTIPLIER_CRITICAL" : 1.5,
    "BLAST_MULTIPLIER_HIGH"     : 1.25,
    "BLAST_MULTIPLIER_MEDIUM"   : 1.1,
    "BLAST_MULTIPLIER_LOW"      : 1.0,

    # ── Recovery ─────────────────────────────────────────────
    "RECOVERY_PER_CLEAN"        : 1.2,
    "CONSECUTIVE_BONUS"         : 0.3,   # Extra per consecutive clean (max 10)
    "MAX_CONSECUTIVE_BONUS"     : 10,

    # ── Time decay ────────────────────────────────────────────
    # Agents that have done bad things don't fully recover just by being idle
    # Applied once per hour of inactivity after a risky session
    "DECAY_RATE_PER_HOUR"       : 0.5,   # 0.5 pts/hr passive decay after risk
    "DECAY_APPLIES_ABOVE_SCORE" : 60.0,  # Only decay if score > 60 (punish idle bad agents)
    "DECAY_MIN_RISK_ACTIONS"    : 2,     # Only decay if agent had 2+ risk actions

    # ── Containment thresholds ────────────────────────────────
    "THRESHOLD_WATCH"           : 70.0,
    "THRESHOLD_RESTRICT"        : 50.0,
    "THRESHOLD_SANDBOX"         : 30.0,
    "THRESHOLD_ISOLATE"         : 10.0,

    # ── Anomaly spike ─────────────────────────────────────────
    "ANOMALY_SPIKE_THRESHOLD"   : 25.0,  # Single drop > 25 pts = anomaly event

    # ── Freefall detection ────────────────────────────────────
    "FREEFALL_DROP"             : 20.0,  # 20+ pts lost in last 3 actions
    "FREEFALL_WINDOW"           : 3,

    # ── History limits ────────────────────────────────────────
    "MAX_ACTION_HISTORY"        : 100,
    "MAX_CHANGELOG"             : 200,
    "VELOCITY_WINDOW"           : 5,
}

# ─────────────────────────────────────────────────────────────
# Persistence
# ─────────────────────────────────────────────────────────────

PERSIST_DIR  = "logs"
# Trust profiles persist in SQLite via infrastructure.database
# (trust_profiles table) — the JSON file is no longer used.

# In-memory store
TRUST_STORE: Dict[str, TrustProfile] = {}


def _persist_profile(profile: TrustProfile) -> None:
    """Write a single profile to the persistent store (SQLite)."""
    try:
        create_or_update_trust_profile(
            agent_id            = profile.agent_id,
            trust_score         = profile.trust_score,
            peak_trust          = profile.peak_trust,
            floor_trust         = profile.floor_trust,
            total_actions       = profile.total_actions,
            blocked_actions     = profile.blocked_actions,
            flagged_actions     = profile.flagged_actions,
            allowed_actions     = profile.allowed_actions,
            consecutive_clean   = profile.consecutive_clean,
            consecutive_risk    = profile.consecutive_risk,
            containment_level   = profile.containment_level,
            is_sandboxed        = profile.is_sandboxed,
            session_count       = profile.session_count,
        )
    except Exception as e:
        # Never break the interception pipeline on a persistence failure
        print(f"[TrustEngine] Warning: DB persist failed for {profile.agent_id}: {e}")


def _profile_from_db_row(data: Dict[str, Any], new_session: bool = False) -> TrustProfile:
    """Rebuild a TrustProfile from a trust_profiles table row.

    new_session=True (startup load) counts a fresh server session.
    """
    profile = TrustProfile(agent_id=data["agent_id"])
    profile.trust_score        = data.get("trust_score", 100.0)
    profile.peak_trust         = data.get("peak_trust", 100.0)
    profile.floor_trust        = data.get("floor_trust", 100.0)
    profile.total_actions      = data.get("total_actions", 0)
    profile.blocked_actions    = data.get("blocked_actions", 0)
    profile.flagged_actions    = data.get("flagged_actions", 0)
    profile.allowed_actions    = data.get("allowed_actions", 0)
    profile.consecutive_clean  = data.get("consecutive_clean", 0)
    profile.consecutive_risk   = data.get("consecutive_risk", 0)
    profile.containment_level  = data.get("containment_level", "NONE")
    profile.is_sandboxed       = bool(data.get("is_sandboxed", 0))
    profile.session_count      = data.get("session_count", 1) + (1 if new_session else 0)
    profile.created_at         = data.get("created_at", "")
    profile.last_action_time   = data.get("last_action_time", "")
    return profile


def _load_persisted_profiles() -> None:
    """Load all profiles from the database into memory at startup."""
    try:
        rows = get_all_trust_profiles_db()
    except Exception as e:
        print(f"[TrustEngine] Could not load persisted profiles from DB: {e}")
        return
    for data in rows:
        TRUST_STORE[data["agent_id"]] = _profile_from_db_row(data, new_session=True)
    if TRUST_STORE:
        print(f"[TrustEngine] Loaded {len(TRUST_STORE)} agent profiles from database.")


# Load on module import
_load_persisted_profiles()


# ─────────────────────────────────────────────────────────────
# Core API
# ─────────────────────────────────────────────────────────────

def get_or_create_profile(agent_id: str) -> TrustProfile:
    if agent_id in TRUST_STORE:
        return TRUST_STORE[agent_id]
    # Lazy-load from the persistent store if a profile already exists there
    try:
        row = get_trust_profile_db(agent_id)
    except Exception:
        row = None
    TRUST_STORE[agent_id] = _profile_from_db_row(row) if row else TrustProfile(agent_id=agent_id)
    return TRUST_STORE[agent_id]


def update_trust_score(
    agent_id     : str,
    tool         : str,
    parameters   : Dict[str, Any],
    risk_level   : str,
    risk_score   : int,
    intent_gap   : int   = 0,
    blast_level  : str   = "LOW",
    mitre_tech   : str   = "N/A",
    mitre_tactic : str   = "N/A",
) -> TrustProfile:

    profile      = get_or_create_profile(agent_id)
    score_before = profile.trust_score

    # ── Step 1: Apply time decay if applicable ────────────────
    _apply_time_decay(profile)

    # ── Step 2: Compute blast radius multiplier ───────────────
    blast_mult = {
        "CRITICAL": TRUST_CONFIG["BLAST_MULTIPLIER_CRITICAL"],
        "HIGH"    : TRUST_CONFIG["BLAST_MULTIPLIER_HIGH"],
        "MEDIUM"  : TRUST_CONFIG["BLAST_MULTIPLIER_MEDIUM"],
    }.get(blast_level, TRUST_CONFIG["BLAST_MULTIPLIER_LOW"])

    # ── Step 3: Compute intent gap amplifier ──────────────────
    if intent_gap > 80:
        gap_amp = TRUST_CONFIG["INTENT_GAP_AMP_CRITICAL"]
    elif intent_gap > 60:
        gap_amp = TRUST_CONFIG["INTENT_GAP_AMP_HIGH"]
    elif intent_gap > 40:
        gap_amp = TRUST_CONFIG["INTENT_GAP_AMP_MEDIUM"]
    else:
        gap_amp = 1.0

    # ── Step 4: Calculate delta ───────────────────────────────
    delta      = 0.0
    event_type = "ALLOWED"
    reason     = ""

    if risk_level in ("CRITICAL", "HIGH"):
        base_penalty = TRUST_CONFIG[f"PENALTY_{risk_level}"]
        final_penalty = base_penalty * blast_mult * gap_amp
        delta         = -final_penalty

        reason = (
            f"{risk_level} risk action '{tool}' | "
            f"Base penalty: {base_penalty} | "
            f"Blast multiplier: {blast_mult}x | "
            f"Intent gap amplifier: {gap_amp}x | "
            f"Total penalty: {round(final_penalty, 2)}"
        )
        event_type               = "PENALTY"
        profile.blocked_actions  += 1
        profile.consecutive_clean = 0
        profile.consecutive_risk += 1
        profile.max_consecutive_risk = max(
            profile.max_consecutive_risk, profile.consecutive_risk
        )
        profile.total_penalty_applied += final_penalty

    elif risk_level == "MEDIUM":
        penalty = TRUST_CONFIG["PENALTY_MEDIUM"] * blast_mult
        delta   = -penalty
        reason  = (
            f"MEDIUM risk action '{tool}' | "
            f"Penalty: {round(penalty, 2)} | "
            f"Blast multiplier: {blast_mult}x"
        )
        event_type              = "PENALTY"
        profile.flagged_actions += 1
        profile.consecutive_clean = 0
        profile.consecutive_risk += 1
        profile.max_consecutive_risk = max(
            profile.max_consecutive_risk, profile.consecutive_risk
        )
        profile.total_penalty_applied += penalty

    else:
        # Recovery — slower than penalties by design
        recovery = (
            TRUST_CONFIG["RECOVERY_PER_CLEAN"] +
            TRUST_CONFIG["CONSECUTIVE_BONUS"] *
            min(profile.consecutive_clean, TRUST_CONFIG["MAX_CONSECUTIVE_BONUS"])
        )
        delta   = recovery
        reason  = (
            f"Clean action '{tool}' | "
            f"Recovery: {round(recovery, 2)} | "
            f"Consecutive clean streak: {profile.consecutive_clean + 1}"
        )
        event_type               = "RECOVERY"
        profile.allowed_actions  += 1
        profile.consecutive_clean += 1
        profile.consecutive_risk  = 0
        profile.total_recovery_earned += recovery

    # ── Step 5: Apply delta + clamp ───────────────────────────
    profile.trust_score = max(0.0, min(100.0, profile.trust_score + delta))
    profile.peak_trust  = max(profile.peak_trust,  profile.trust_score)
    profile.floor_trust = min(profile.floor_trust, profile.trust_score)

    # ── Step 6: Detect anomaly spike ─────────────────────────
    actual_drop = score_before - profile.trust_score
    if actual_drop >= TRUST_CONFIG["ANOMALY_SPIKE_THRESHOLD"]:
        profile.anomaly_spikes += 1
        _append_changelog(profile, TrustScoreEvent(
            sequence    = len(profile.score_changelog),
            event_type  = "ANOMALY_SPIKE",
            trust_before= score_before,
            trust_after = profile.trust_score,
            delta       = -actual_drop,
            reason      = f"ANOMALY: Trust dropped {round(actual_drop, 1)} pts in single action — security event raised",
            trigger     = tool,
        ))

    # ── Step 7: Record action ─────────────────────────────────
    action = AgentAction(
        tool             = tool,
        parameters       = parameters,
        risk_level       = risk_level,
        risk_score       = risk_score,
        intent_gap_score = intent_gap,
        mitre_technique  = mitre_tech,
        mitre_tactic     = mitre_tactic,
        action_taken     = event_type,
        blast_multiplier = blast_mult,
        trust_before     = round(score_before, 2),
        trust_after      = round(profile.trust_score, 2),
        trust_delta      = round(delta, 2),
    )
    profile.action_history.append(action)
    profile.total_actions   += 1
    profile.last_action_time = action.timestamp

    if len(profile.action_history) > TRUST_CONFIG["MAX_ACTION_HISTORY"]:
        profile.action_history = profile.action_history[-TRUST_CONFIG["MAX_ACTION_HISTORY"]:]

    # ── Step 8: Update risk distribution ─────────────────────
    lvl = risk_level if risk_level in profile.risk_distribution else "LOW"
    profile.risk_distribution[lvl] += 1

    # ── Step 9: Update velocity ───────────────────────────────
    _update_velocity(profile)

    # ── Step 10: Append to changelog ─────────────────────────
    _append_changelog(profile, TrustScoreEvent(
        sequence    = len(profile.score_changelog),
        event_type  = event_type,
        trust_before= round(score_before, 2),
        trust_after = round(profile.trust_score, 2),
        delta       = round(delta, 2),
        reason      = reason,
        trigger     = tool,
    ))

    # ── Step 11: Evaluate containment level ───────────────────
    _evaluate_containment(profile)

    # ── Step 12: Persist to disk ──────────────────────────────
    TRUST_STORE[agent_id] = profile
    _persist_profile(profile)

    return profile


# ─────────────────────────────────────────────────────────────
# Time Decay
# Agents with risky history don't recover by being idle
# ─────────────────────────────────────────────────────────────

def _apply_time_decay(profile: TrustProfile) -> None:
    """
    Apply passive trust decay based on time since last action.
    Only applies when:
      - Agent has had 2+ risk actions (dirty history)
      - Current score is above floor (prevents punishing rock-bottom agents)
      - At least 1 hour since last decay
    """
    if profile.blocked_actions + profile.flagged_actions < TRUST_CONFIG["DECAY_MIN_RISK_ACTIONS"]:
        return

    if profile.trust_score <= TRUST_CONFIG["DECAY_APPLIES_ABOVE_SCORE"]:
        return

    if not profile.last_action_time:
        return

    try:
        last = datetime.fromisoformat(profile.last_action_time.replace("Z", "+00:00"))
        now  = datetime.now(timezone.utc)
        hours_elapsed = (now - last).total_seconds() / 3600

        if hours_elapsed < 1.0:
            return

        decay = TRUST_CONFIG["DECAY_RATE_PER_HOUR"] * hours_elapsed
        decay = min(decay, 5.0)  # Cap at 5 pts per decay event

        profile.trust_score = max(0.0, profile.trust_score - decay)
        profile.last_decay_applied = now.isoformat()

        _append_changelog(profile, TrustScoreEvent(
            sequence    = len(profile.score_changelog),
            event_type  = "DECAY",
            trust_before= profile.trust_score + decay,
            trust_after = profile.trust_score,
            delta       = -decay,
            reason      = (
                f"Passive time decay — {round(hours_elapsed, 1)}h inactivity "
                f"after risky session ({profile.blocked_actions} blocked actions)"
            ),
            trigger     = "time_decay",
        ))
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────
# Graduated Containment
# ─────────────────────────────────────────────────────────────

def _evaluate_containment(profile: TrustProfile) -> None:
    """
    Assign containment level based on current trust score + behavioral signals.
    Levels only escalate — never de-escalate automatically.
    De-escalation requires explicit human approval (not implemented in this version).
    """
    current_level  = CONTAINMENT_LEVELS.get(profile.containment_level, 0)
    new_level_name = profile.containment_level
    new_reason     = profile.containment_reason

    # ── ISOLATE: trust gone + sustained attack pattern ────────
    if (
        profile.trust_score <= TRUST_CONFIG["THRESHOLD_ISOLATE"] or
        profile.risk_distribution.get("CRITICAL", 0) >= 3
    ):
        if current_level < CONTAINMENT_LEVELS["ISOLATE"]:
            new_level_name = "ISOLATE"
            new_reason     = (
                f"Trust at {round(profile.trust_score, 1)}/100 — "
                f"Agent fully isolated. {profile.risk_distribution.get('CRITICAL', 0)} "
                f"CRITICAL actions in session."
            )

    # ── SANDBOX: trust collapsed ──────────────────────────────
    elif (
        profile.trust_score <= TRUST_CONFIG["THRESHOLD_SANDBOX"] or
        profile.trust_velocity.is_in_freefall or
        profile.consecutive_risk >= 4
    ):
        if current_level < CONTAINMENT_LEVELS["SANDBOX"]:
            new_level_name = "SANDBOX"
            new_reason     = (
                f"Trust at {round(profile.trust_score, 1)}/100 — "
                f"Agent sandboxed. Freefall: {profile.trust_velocity.is_in_freefall}. "
                f"Consecutive risk: {profile.consecutive_risk}."
            )

    # ── RESTRICT: trust degraded ──────────────────────────────
    elif (
        profile.trust_score <= TRUST_CONFIG["THRESHOLD_RESTRICT"] or
        profile.consecutive_risk >= 2 or
        profile.anomaly_spikes >= 1
    ):
        if current_level < CONTAINMENT_LEVELS["RESTRICT"]:
            new_level_name = "RESTRICT"
            new_reason     = (
                f"Trust at {round(profile.trust_score, 1)}/100 — "
                f"High-risk tools now require approval. "
                f"Anomaly spikes: {profile.anomaly_spikes}."
            )

    # ── WATCH: first signs of trouble ────────────────────────
    elif (
        profile.trust_score <= TRUST_CONFIG["THRESHOLD_WATCH"] or
        profile.blocked_actions >= 1
    ):
        if current_level < CONTAINMENT_LEVELS["WATCH"]:
            new_level_name = "WATCH"
            new_reason     = (
                f"Trust at {round(profile.trust_score, 1)}/100 — "
                f"Elevated monitoring activated. "
                f"Blocked actions: {profile.blocked_actions}."
            )

    # ── Apply if escalated ────────────────────────────────────
    if new_level_name != profile.containment_level:
        profile.containment_level  = new_level_name
        profile.containment_reason = new_reason
        profile.containment_at     = datetime.now(timezone.utc).isoformat()

        # Keep backward-compatible is_sandboxed flag
        profile.is_sandboxed   = CONTAINMENT_LEVELS[new_level_name] >= CONTAINMENT_LEVELS["SANDBOX"]
        profile.sandbox_reason = new_reason if profile.is_sandboxed else profile.sandbox_reason

        _append_changelog(profile, TrustScoreEvent(
            sequence    = len(profile.score_changelog),
            event_type  = "ESCALATION",
            trust_before= profile.trust_score,
            trust_after = profile.trust_score,
            delta       = 0.0,
            reason      = f"Containment escalated to {new_level_name}: {new_reason}",
            trigger     = "containment_engine",
        ))


# ─────────────────────────────────────────────────────────────
# Velocity Tracking
# ─────────────────────────────────────────────────────────────

def _update_velocity(profile: TrustProfile) -> None:
    velocity = profile.trust_velocity
    velocity.last_5_scores.append(profile.trust_score)

    if len(velocity.last_5_scores) > TRUST_CONFIG["VELOCITY_WINDOW"]:
        velocity.last_5_scores = velocity.last_5_scores[-TRUST_CONFIG["VELOCITY_WINDOW"]:]

    if len(velocity.last_5_scores) >= TRUST_CONFIG["FREEFALL_WINDOW"]:
        window      = velocity.last_5_scores[-TRUST_CONFIG["FREEFALL_WINDOW"]:]
        recent_drop = window[0] - window[-1]

        velocity.drop_rate = round(recent_drop / TRUST_CONFIG["FREEFALL_WINDOW"], 2)

        was_freefall = velocity.is_in_freefall
        velocity.is_in_freefall = recent_drop >= TRUST_CONFIG["FREEFALL_DROP"]

        if velocity.is_in_freefall and not was_freefall:
            velocity.freefall_started_at = datetime.now(timezone.utc).isoformat()

    # Track worst single drop
    if len(velocity.last_5_scores) >= 2:
        single_drop = velocity.last_5_scores[-2] - velocity.last_5_scores[-1]
        velocity.peak_drop_single = max(velocity.peak_drop_single, single_drop)


# ─────────────────────────────────────────────────────────────
# Changelog helper
# ─────────────────────────────────────────────────────────────

def _append_changelog(profile: TrustProfile, event: TrustScoreEvent) -> None:
    profile.score_changelog.append(event)
    if len(profile.score_changelog) > TRUST_CONFIG["MAX_CHANGELOG"]:
        profile.score_changelog = profile.score_changelog[-TRUST_CONFIG["MAX_CHANGELOG"]:]


# ─────────────────────────────────────────────────────────────
# Public Read API
# ─────────────────────────────────────────────────────────────

def get_trust_summary(agent_id: str) -> Dict[str, Any]:
    profile = get_or_create_profile(agent_id)

    return {
        "agent_id"              : profile.agent_id,
        "trust_score"           : round(profile.trust_score, 2),
        "trust_level"           : get_trust_label(profile.trust_score),
        "peak_trust"            : round(profile.peak_trust, 2),
        "floor_trust"           : round(profile.floor_trust, 2),

        # Containment
        "containment_level"     : profile.containment_level,
        "containment_reason"    : profile.containment_reason,
        "is_sandboxed"          : profile.is_sandboxed,
        "sandbox_reason"        : profile.sandbox_reason,

        # Counters
        "total_actions"         : profile.total_actions,
        "blocked_actions"       : profile.blocked_actions,
        "flagged_actions"       : profile.flagged_actions,
        "allowed_actions"       : profile.allowed_actions,
        "consecutive_clean"     : profile.consecutive_clean,
        "consecutive_risk"      : profile.consecutive_risk,
        "max_consecutive_risk"  : profile.max_consecutive_risk,
        "anomaly_spikes"        : profile.anomaly_spikes,

        # Risk breakdown
        "risk_distribution"     : profile.risk_distribution,
        "total_penalty_applied" : round(profile.total_penalty_applied, 2),
        "total_recovery_earned" : round(profile.total_recovery_earned, 2),

        # Velocity
        "trust_velocity"        : {
            "drop_rate"          : profile.trust_velocity.drop_rate,
            "is_in_freefall"     : profile.trust_velocity.is_in_freefall,
            "freefall_started_at": profile.trust_velocity.freefall_started_at,
            "peak_drop_single"   : profile.trust_velocity.peak_drop_single,
        },

        # Session
        "last_action_time"      : profile.last_action_time,
        "last_decay_applied"    : profile.last_decay_applied,
        "session_count"         : profile.session_count,
        "created_at"            : profile.created_at,
    }


def get_trust_changelog(agent_id: str, limit: int = 20) -> List[Dict[str, Any]]:
    """Full score changelog — every delta with mathematical reason."""
    profile = get_or_create_profile(agent_id)
    return [
        {
            "sequence"   : e.sequence,
            "event_type" : e.event_type,
            "trust_before": e.trust_before,
            "trust_after" : e.trust_after,
            "delta"      : e.delta,
            "reason"     : e.reason,
            "trigger"    : e.trigger,
            "timestamp"  : e.timestamp,
        }
        for e in profile.score_changelog[-limit:]
    ]


def get_trust_label(score: float) -> str:
    if score >= 80: return "TRUSTED"
    if score >= 55: return "MONITOR"
    if score >= 40: return "SUSPICIOUS"
    if score >= 25: return "COMPROMISED"
    return "CRITICAL_THREAT"


def get_all_profiles() -> List[Dict[str, Any]]:
    return [get_trust_summary(aid) for aid in TRUST_STORE]


def reset_trust(agent_id: str) -> TrustProfile:
    """
    Hard reset — only called when agent token is revoked and re-registered.
    Increments session count so history context is preserved in audit chain.
    """
    old_session = TRUST_STORE.get(agent_id)
    new_profile = TrustProfile(agent_id=agent_id)
    if old_session:
        new_profile.session_count = old_session.session_count + 1
    TRUST_STORE[agent_id] = new_profile
    _persist_profile(new_profile)
    return new_profile

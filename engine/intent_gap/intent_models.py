from dataclasses import dataclass, field
from typing import List, Optional


# ─────────────────────────────────────────────────────────────
# InjectionEvidence
# Structured proof of what was detected and where
# A CISO needs to see evidence, not just a flag
# ─────────────────────────────────────────────────────────────

@dataclass
class InjectionEvidence:
    injection_type    : str          # e.g. classic_override, role_hijack
    matched_pattern   : str          # The regex that fired
    matched_text      : str          # The exact text that triggered it
    found_in          : str          # WHERE it was found: tool_name / parameters / combined
    confidence        : float        # 0.0 - 1.0
    owasp_category    : str          # OWASP LLM Top 10 category
    severity          : str          # LOW / MEDIUM / HIGH / CRITICAL
    description       : str          # Human-readable explanation
    remediation       : str          # What to do right now


# ─────────────────────────────────────────────────────────────
# ScopeViolation
# When an agent acts outside its declared permission boundary
# ─────────────────────────────────────────────────────────────

@dataclass
class ScopeViolation:
    violation_type    : str          # FORBIDDEN_TOOL / OUT_OF_SCOPE / PERMISSION_BOUNDARY
    declared_scope    : List[str]    # What the agent was allowed to do
    actual_action     : str          # What it tried to do
    severity          : str
    description       : str


# ─────────────────────────────────────────────────────────────
# IntentGapResult
# Complete analysis output — everything a security system needs
# ─────────────────────────────────────────────────────────────

@dataclass
class IntentGapResult:
    # ── Core fields (backward compatible) ────────────────────
    declared_intent    : str
    actual_action      : str
    gap_score          : int          # 0 = perfect match, 100 = total mismatch
    gap_level          : str          # LOW / MEDIUM / HIGH / CRITICAL
    reason             : str          # Primary human-readable reason
    should_block       : bool

    # ── Injection analysis ────────────────────────────────────
    injection_detected : bool                      = False
    injection_type     : str                       = ""
    injection_evidence : Optional[InjectionEvidence] = None
    injection_count    : int                       = 0   # Multiple injections possible

    # ── Intent matching ───────────────────────────────────────
    matched_category   : str          = ""
    matched_intents    : List[str]    = field(default_factory=list)  # For compound intents
    allowed_tools      : List[str]    = field(default_factory=list)
    confidence         : float        = 1.0   # How confident is this analysis

    # ── Scope analysis ────────────────────────────────────────
    scope_violation    : Optional[ScopeViolation] = None
    is_scope_violation : bool         = False

    # ── Remediation ───────────────────────────────────────────
    remediation        : str          = ""
    remediation_steps  : List[str]    = field(default_factory=list)

    # ── Metadata ──────────────────────────────────────────────
    analysis_version   : str          = "2.0"
    scan_surfaces      : List[str]    = field(default_factory=list)  # What was scanned

"""
AgentTrust OS — Intent Gap Analysis Engine v2.0
Industry-grade intent vs action divergence detection for AI agents.

Design principles:
  - Multi-surface scanning: tool name + parameters + combined + nested JSON
  - Compound intent parsing: "summarize AND email" handled correctly
  - Injection confidence scoring: not all injections are equal severity
  - Scope boundary enforcement: agents stay within declared permission set
  - Full remediation guidance: every block includes actionable next steps
  - OWASP LLM Top 10 alignment: industry-standard classification
  - Historical scope tracking: detect gradual scope creep across actions
"""

import re
import json
from typing import List, Optional, Dict, Tuple
from engine.intent_gap.intent_models import (
    IntentGapResult,
    InjectionEvidence,
    ScopeViolation,
)


# ─────────────────────────────────────────────────────────────
# Intent Category Tree
# Multi-level: category → keywords + allowed tools + forbidden tools
# Each category represents a declared agent purpose
# ─────────────────────────────────────────────────────────────

INTENT_TREE: Dict = {
    "summarize": {
        "keywords"     : ["summarize", "summary", "overview", "brief",
                          "tldr", "digest", "recap", "condense"],
        "allowed_tools": ["read_file", "get_content", "fetch_document",
                          "search", "get_text", "parse_document",
                          "list_directory", "get_document"],
        "forbidden"    : ["run_command", "delete_file", "export_data",
                          "send_request", "write_file", "execute_script",
                          "drop_table", "format_disk"],
    },
    "email": {
        "keywords"     : ["email", "send mail", "compose", "reply",
                          "draft email", "send message", "mail to"],
        "allowed_tools": ["send_email", "draft_email", "reply_email",
                          "get_contacts", "read_email", "list_inbox",
                          "search_contacts", "get_email_thread"],
        "forbidden"    : ["run_command", "read_file", "export_data",
                          "delete_file", "execute_script", "drop_table"],
    },
    "search": {
        "keywords"     : ["search", "find", "look up", "query",
                          "discover", "locate", "retrieve", "fetch"],
        "allowed_tools": ["web_search", "search_files", "query_database",
                          "get_weather", "list_directory", "find_files",
                          "search_documents", "get_records"],
        "forbidden"    : ["run_command", "delete_file", "send_request",
                          "export_data", "write_credentials", "drop_table"],
    },
    "write": {
        "keywords"     : ["write", "create", "draft", "generate",
                          "compose document", "produce", "author", "prepare"],
        "allowed_tools": ["write_file", "create_file", "update_file",
                          "append_file", "create_document", "save_file"],
        "forbidden"    : ["run_command", "execute_script", "delete_file",
                          "read_credentials", "export_all", "drop_table"],
    },
    "analyze": {
        "keywords"     : ["analyze", "analyse", "inspect", "review",
                          "audit", "report", "metrics", "evaluate",
                          "assess", "examine"],
        "allowed_tools": ["read_file", "query_database", "get_metrics",
                          "fetch_logs", "get_content", "list_directory",
                          "get_reports", "calculate", "aggregate"],
        "forbidden"    : ["run_command", "delete_file", "send_request",
                          "export_all", "write_credentials", "drop_table"],
    },
    "deploy": {
        "keywords"     : ["deploy", "release", "publish", "push",
                          "ship", "rollout", "launch", "install"],
        "allowed_tools": ["run_command", "execute_script", "push_code",
                          "restart_service", "build", "run_tests",
                          "deploy_service", "update_config"],
        "forbidden"    : ["read_credentials", "export_data",
                          "delete_all", "drop_table", "format_disk"],
    },
    "monitor": {
        "keywords"     : ["monitor", "watch", "track", "observe",
                          "alert", "detect", "check", "scan"],
        "allowed_tools": ["get_metrics", "fetch_logs", "read_file",
                          "query_database", "get_alerts", "list_events",
                          "check_status", "get_health"],
        "forbidden"    : ["run_command", "delete_file", "export_all",
                          "send_request", "write_file", "drop_table"],
    },
    "schedule": {
        "keywords"     : ["schedule", "automate", "cron", "recurring",
                          "periodic", "timer", "trigger", "workflow"],
        "allowed_tools": ["create_schedule", "list_schedules",
                          "update_schedule", "get_calendar",
                          "set_reminder", "create_trigger"],
        "forbidden"    : ["run_command", "execute_script", "delete_file",
                          "read_credentials", "export_all", "drop_table"],
    },
    "data_process": {
        "keywords"     : ["process", "transform", "convert", "parse",
                          "clean", "normalize", "enrich", "pipeline"],
        "allowed_tools": ["read_file", "write_file", "transform_data",
                          "parse_csv", "convert_format", "validate_data",
                          "query_database", "update_records"],
        "forbidden"    : ["run_command", "execute_script", "delete_all",
                          "send_request", "export_all", "drop_table"],
    },
    "customer_support": {
        "keywords"     : ["support", "help desk", "ticket", "customer",
                          "resolve", "assist", "troubleshoot"],
        "allowed_tools": ["read_ticket", "update_ticket", "send_email",
                          "search_knowledge_base", "get_customer_info",
                          "create_ticket", "escalate_ticket"],
        "forbidden"    : ["run_command", "delete_file", "export_all",
                          "execute_script", "drop_table", "format_disk"],
    },
}


# ─────────────────────────────────────────────────────────────
# Injection Signature Library
# OWASP LLM Top 10 aligned + real-world attack patterns
# Each entry: (regex, injection_type, owasp_category, severity, confidence, description, remediation)
# ─────────────────────────────────────────────────────────────

INJECTION_SIGNATURES: List[Tuple] = [

    # ── LLM01: Prompt Injection — Direct ─────────────────────
    (
        r"ignore\s+(previous|prior|above|all)\s+instructions?",
        "classic_override",
        "LLM01:PromptInjection",
        "CRITICAL",
        0.97,
        "Classic prompt injection — direct instruction override attempt",
        "Block immediately. Sanitize all upstream text inputs to this agent. Audit document sources.",
    ),
    (
        r"disregard\s+(all|previous|prior|above|your)\s+(instructions?|rules?|guidelines?)",
        "instruction_disregard",
        "LLM01:PromptInjection",
        "CRITICAL",
        0.96,
        "Instruction disregard injection — agent being told to ignore its guidelines",
        "Block immediately. Flag document or input source for security review.",
    ),
    (
        r"new\s+instructions?\s*[:=]|updated\s+instructions?\s*[:=]|override\s+instructions?",
        "instruction_override",
        "LLM01:PromptInjection",
        "HIGH",
        0.91,
        "Instruction override injection — attempting to replace agent directives",
        "Block request. Treat as active attack. Review all inputs processed in this session.",
    ),

    # ── LLM01: Prompt Injection — Role Hijacking ─────────────
    (
        r"you\s+are\s+now\s+(a\s+|an\s+)?(?!helpful|assistant)",
        "role_hijack",
        "LLM01:PromptInjection",
        "CRITICAL",
        0.95,
        "Role hijacking — agent identity replacement attempt",
        "Block immediately. Agent context may be compromised. Reset session.",
    ),
    (
        r"act\s+as\s+(a\s+|an\s+)?(hacker|attacker|malicious|unrestricted|jailbroken)",
        "malicious_role_assign",
        "LLM01:PromptInjection",
        "CRITICAL",
        0.98,
        "Malicious role assignment — agent being instructed to act as threat actor",
        "Block and isolate agent. Full forensic review of session. Escalate to security team.",
    ),
    (
        r"pretend\s+(you\s+are|to\s+be)|your\s+new\s+(role|persona|identity|purpose)",
        "persona_replacement",
        "LLM01:PromptInjection",
        "HIGH",
        0.90,
        "Persona replacement injection — attempting to redefine agent identity",
        "Block request. Inspect all documents and data sources this agent has processed.",
    ),

    # ── LLM01: Prompt Injection — Memory/Context Manipulation ─
    (
        r"forget\s+(everything|all|your|previous)\s*(you\s+know|instructions?|context)?",
        "memory_wipe",
        "LLM01:PromptInjection",
        "HIGH",
        0.93,
        "Memory wipe injection — attempting to erase agent context and safety guidelines",
        "Block request. Do not process further inputs from this source without review.",
    ),
    (
        r"your\s+(memory|context|history)\s+(has\s+been\s+)?(reset|cleared|wiped|updated)",
        "false_context_reset",
        "LLM01:PromptInjection",
        "HIGH",
        0.89,
        "False context reset — deceiving agent about its own state",
        "Block request. Agent may be under active manipulation. Review session history.",
    ),

    # ── LLM01: Prompt Injection — System Prompt Exploits ─────
    (
        r"<\s*system\s*>|###\s*system\s*###|\[SYSTEM\]|<<SYS>>",
        "system_prompt_inject",
        "LLM01:PromptInjection",
        "CRITICAL",
        0.96,
        "System prompt injection via formatting exploit — attempting to inject privileged instructions",
        "Block immediately. This is a formatting-based privilege escalation. Sanitize all markup.",
    ),
    (
        r"system\s*:\s*you\s+(are|must|should|will)|system\s+prompt\s*:",
        "system_role_inject",
        "LLM01:PromptInjection",
        "CRITICAL",
        0.94,
        "System role injection — attempting to inject system-level directives",
        "Block immediately. Review all structured inputs processed by this agent.",
    ),

    # ── LLM02: Insecure Output Handling ──────────────────────
    (
        r"<\s*\/?(?:script|iframe|object|embed|link|meta)\s*",
        "html_script_inject",
        "LLM02:InsecureOutputHandling",
        "HIGH",
        0.92,
        "HTML/Script injection in parameters — possible XSS or content injection",
        "Sanitize all agent outputs. Encode HTML entities before rendering.",
    ),
    (
        r"javascript\s*:\s*|vbscript\s*:\s*|data\s*:\s*text\/html",
        "javascript_uri_inject",
        "LLM02:InsecureOutputHandling",
        "HIGH",
        0.95,
        "JavaScript URI injection — attempting to execute scripts via URI scheme",
        "Block and sanitize. Implement strict Content-Security-Policy.",
    ),

    # ── LLM06: Sensitive Information Disclosure ───────────────
    (
        r"(print|show|display|reveal|output|return|send)\s+(all\s+)?(api\s*key|password|secret|token|credential)",
        "credential_extraction",
        "LLM06:SensitiveInfoDisclosure",
        "CRITICAL",
        0.95,
        "Credential extraction attempt — agent being asked to disclose sensitive data",
        "Block immediately. Audit what credentials this agent has access to. Rotate secrets.",
    ),
    (
        r"what\s+(is|are)\s+(your\s+)?(system\s+prompt|instructions?|guidelines?|rules?)",
        "prompt_extraction",
        "LLM06:SensitiveInfoDisclosure",
        "MEDIUM",
        0.80,
        "Prompt extraction attempt — trying to reveal agent's internal instructions",
        "Flag for review. Do not allow agent to disclose system prompt contents.",
    ),

    # ── LLM07: Insecure Plugin Design ────────────────────────
    (
        r"translate\s+.{0,50}\s+and\s+(execute|run|eval)|decode\s+.{0,30}\s+and\s+(run|execute)",
        "encoded_execution",
        "LLM07:InsecurePluginDesign",
        "CRITICAL",
        0.93,
        "Encoded execution injection — obfuscated command hidden inside legitimate operation",
        "Block immediately. Audit all tool call pipelines for indirect execution paths.",
    ),
    (
        r"base64\s*(decode|encode)\s*.{0,20}\s*(run|exec|eval|execute)",
        "base64_payload",
        "LLM07:InsecurePluginDesign",
        "CRITICAL",
        0.94,
        "Base64 encoded payload injection — obfuscated malicious content",
        "Block. Decode and inspect payload. Treat as active attack.",
    ),

    # ── LLM09: Overreliance / Jailbreak ──────────────────────
    (
        r"jailbreak|jailbroken|dan\s+mode|developer\s+mode\s+enabled|god\s+mode",
        "jailbreak_attempt",
        "LLM09:Overreliance",
        "CRITICAL",
        0.97,
        "Jailbreak attempt — trying to remove agent safety constraints",
        "Block immediately. Log as active attack. Alert security team.",
    ),
    (
        r"no\s+(restrictions?|limits?|filters?|guidelines?|safety)|unrestricted\s+mode",
        "restriction_removal",
        "LLM09:Overreliance",
        "HIGH",
        0.88,
        "Restriction removal attempt — trying to operate agent without safety boundaries",
        "Block. Treat as deliberate bypass attempt. Review session context.",
    ),

    # ── Indirect Injection — Document/Data Poisoning ─────────
    (
        r"when\s+(you|the\s+agent)\s+(see|read|process|encounter)\s+.{0,30}(do|execute|run|send)",
        "indirect_injection",
        "LLM01:IndirectPromptInjection",
        "HIGH",
        0.85,
        "Indirect prompt injection — conditional trigger hidden in processed content",
        "Block. This pattern indicates poisoned document or data source. Quarantine source.",
    ),
    (
        r"if\s+(anyone\s+asks?|you\s+are\s+asked).{0,50}(say|tell|respond|claim)",
        "social_engineering_inject",
        "LLM01:IndirectPromptInjection",
        "MEDIUM",
        0.78,
        "Social engineering injection — instructing agent to deceive users",
        "Flag for review. Inspect document sources. Do not allow deceptive outputs.",
    ),
]


# ─────────────────────────────────────────────────────────────
# Unconditionally Dangerous Tools
# Blocked regardless of any declared intent
# ─────────────────────────────────────────────────────────────

UNCONDITIONALLY_DANGEROUS = {
    "drop_table"        : "Irreversible database destruction",
    "format_disk"       : "Irreversible disk format",
    "rm_rf"             : "Irreversible recursive deletion",
    "read_credentials"  : "Direct credential harvesting",
    "write_credentials" : "Credential tampering",
    "delete_all"        : "Mass data deletion",
    "export_all_users"  : "Mass user data exfiltration",
    "disable_firewall"  : "Security control bypass",
    "flush_dns"         : "Network manipulation",
    "kill_process"      : "Service disruption",
}


# ─────────────────────────────────────────────────────────────
# Scope Creep Tracker
# Tracks which tools each agent has used historically
# Detects gradual expansion beyond declared scope
# ─────────────────────────────────────────────────────────────

_SCOPE_TRACKER: Dict[str, List[str]] = {}


def _record_tool_usage(agent_id: str, tool: str) -> None:
    if agent_id not in _SCOPE_TRACKER:
        _SCOPE_TRACKER[agent_id] = []
    if tool not in _SCOPE_TRACKER[agent_id]:
        _SCOPE_TRACKER[agent_id].append(tool)


def get_scope_history(agent_id: str) -> List[str]:
    return _SCOPE_TRACKER.get(agent_id, [])


# ─────────────────────────────────────────────────────────────
# Core Analysis Function
# ─────────────────────────────────────────────────────────────

def analyze_intent_gap(
    declared_intent : str,
    tool_name       : str,
    parameters      : dict,
    agent_id        : str,
) -> IntentGapResult:
    """
    Full intent gap analysis across 6 layers:
    1. Multi-surface injection detection (tool + params + nested + combined)
    2. Unconditionally dangerous tool check
    3. Compound intent parsing (handles multi-intent declarations)
    4. Forbidden tool enforcement per intent category
    5. Scope boundary validation
    6. Ambiguity scoring with confidence

    agent_id is REQUIRED: scope-creep history is tracked per agent, and an
    anonymous caller would silently share one global history across agents.
    """

    if not agent_id or not agent_id.strip():
        raise ValueError(
            "analyze_intent_gap: agent_id is required (per-agent scope tracking)"
        )

    intent_lower = declared_intent.lower().strip()
    tool_lower   = tool_name.lower().strip()
    param_str    = _deep_stringify(parameters)
    combined     = f"{tool_lower} {param_str}"
    scan_surfaces = ["tool_name", "parameters", "combined"]

    # ── Layer 1: Multi-Surface Injection Scan ─────────────────
    # Scan tool name, parameters, and combined — separately
    # Attackers hide injections in tool names to bypass param-only scanners
    injection_hits = []

    for surface, text in [
        ("tool_name",   tool_lower),
        ("parameters",  param_str),
        ("combined",    combined),
    ]:
        hits = _scan_for_injections(text, surface)
        injection_hits.extend(hits)

    # Remove duplicates by injection_type
    seen_types = set()
    unique_hits = []
    for hit in injection_hits:
        if hit.injection_type not in seen_types:
            seen_types.add(hit.injection_type)
            unique_hits.append(hit)

    if unique_hits:
        # Pick highest confidence hit as primary
        primary = max(unique_hits, key=lambda h: h.confidence)
        return IntentGapResult(
            declared_intent    = declared_intent,
            actual_action      = tool_name,
            gap_score          = _injection_to_gap_score(primary),
            gap_level          = primary.severity,
            reason             = (
                f"[{primary.owasp_category}] {primary.description} "
                f"— Found in: {primary.found_in} | "
                f"Confidence: {int(primary.confidence * 100)}%"
            ),
            should_block       = primary.severity in ("CRITICAL", "HIGH"),
            injection_detected = True,
            injection_type     = primary.injection_type,
            injection_evidence = primary,
            injection_count    = len(unique_hits),
            confidence         = primary.confidence,
            remediation        = primary.remediation,
            remediation_steps  = _build_remediation_steps(primary, tool_name),
            scan_surfaces      = scan_surfaces,
        )

    # ── Layer 2: Unconditionally Dangerous Tool ───────────────
    if tool_lower in UNCONDITIONALLY_DANGEROUS:
        reason_text = UNCONDITIONALLY_DANGEROUS[tool_lower]
        return IntentGapResult(
            declared_intent    = declared_intent,
            actual_action      = tool_name,
            gap_score          = 95,
            gap_level          = "CRITICAL",
            reason             = (
                f"UNCONDITIONALLY BLOCKED: Tool '{tool_name}' is prohibited "
                f"regardless of intent. Reason: {reason_text}"
            ),
            should_block       = True,
            confidence         = 1.0,
            remediation        = f"Remove '{tool_name}' from agent permissions. Use a scoped alternative.",
            remediation_steps  = [
                f"Remove '{tool_name}' from agent permission set",
                "Review why agent attempted this action",
                "Check if prompt injection caused scope expansion",
                "Audit agent session history for related actions",
            ],
            scan_surfaces      = scan_surfaces,
        )

    # ── Layer 3: Compound Intent Parsing ─────────────────────
    # "summarize and email the report" → matches BOTH summarize + email
    matched_intents  : List[str] = []
    all_allowed      : List[str] = []
    all_forbidden    : List[str] = []

    for category, config in INTENT_TREE.items():
        if any(kw in intent_lower for kw in config["keywords"]):
            matched_intents.append(category)
            all_allowed.extend(config["allowed_tools"])
            all_forbidden.extend(config["forbidden"])

    # Deduplicate
    all_allowed   = list(dict.fromkeys(all_allowed))
    all_forbidden = [t for t in dict.fromkeys(all_forbidden) if t not in all_allowed]

    # ── Layer 4: No Intent Matched ────────────────────────────
    if not matched_intents:
        return IntentGapResult(
            declared_intent  = declared_intent,
            actual_action    = tool_name,
            gap_score        = 40,
            gap_level        = "MEDIUM",
            reason           = (
                f"Intent '{declared_intent}' does not match any known category. "
                f"Cannot validate tool '{tool_name}' against unknown scope."
            ),
            should_block     = False,
            matched_category = "unknown",
            matched_intents  = [],
            confidence       = 0.5,
            remediation      = "Register agent with a recognized intent category. Review agent declaration.",
            remediation_steps= [
                "Update agent registration with a clear declared_intent",
                "Supported categories: summarize, email, search, write, analyze, deploy, monitor, schedule, data_process, customer_support",
                f"Current intent '{declared_intent}' is unrecognized",
            ],
            scan_surfaces    = scan_surfaces,
        )

    primary_category = matched_intents[0]

    # ── Layer 5: Forbidden Tool Check ────────────────────────
    if tool_lower in [t.lower() for t in all_forbidden]:
        scope_v = ScopeViolation(
            violation_type = "FORBIDDEN_TOOL",
            declared_scope = all_allowed,
            actual_action  = tool_name,
            severity       = "HIGH",
            description    = (
                f"Tool '{tool_name}' is explicitly forbidden for "
                f"{' + '.join(matched_intents)} intent(s)."
            ),
        )
        return IntentGapResult(
            declared_intent    = declared_intent,
            actual_action      = tool_name,
            gap_score          = 88,
            gap_level          = "HIGH",
            reason             = (
                f"SCOPE VIOLATION: Tool '{tool_name}' is forbidden for "
                f"'{primary_category}' intent. "
                f"Matched intents: {', '.join(matched_intents)}. "
                f"Possible prompt injection or deliberate scope bypass."
            ),
            should_block       = True,
            matched_category   = primary_category,
            matched_intents    = matched_intents,
            allowed_tools      = all_allowed,
            confidence         = 0.92,
            scope_violation    = scope_v,
            is_scope_violation = True,
            remediation        = f"Remove '{tool_name}' from agent execution path. Restrict to declared scope.",
            remediation_steps  = [
                f"Block tool '{tool_name}' — not permitted for {primary_category} agent",
                "Review agent session for prior scope violations",
                "Check if a prompt injection expanded the agent's scope",
                f"Permitted tools for this intent: {', '.join(all_allowed[:5])}{'...' if len(all_allowed) > 5 else ''}",
            ],
            scan_surfaces      = scan_surfaces,
        )

    # ── Layer 6: Allowed Tool — Clean Pass ───────────────────
    if tool_lower in [t.lower() for t in all_allowed]:
        # Record usage for scope creep tracking
        _record_tool_usage(agent_id, tool_lower)

        intent_label = " + ".join(matched_intents) if len(matched_intents) > 1 else primary_category
        return IntentGapResult(
            declared_intent  = declared_intent,
            actual_action    = tool_name,
            gap_score        = 5,
            gap_level        = "LOW",
            reason           = (
                f"Tool '{tool_name}' is within declared scope for "
                f"'{intent_label}' intent."
            ),
            should_block     = False,
            matched_category = primary_category,
            matched_intents  = matched_intents,
            allowed_tools    = all_allowed,
            confidence       = 0.98,
            remediation      = "No action required.",
            scan_surfaces    = scan_surfaces,
        )

    # ── Layer 7: Ambiguous — Tool Not Explicitly Listed ───────
    # Not forbidden, not allowed — outside defined scope
    _record_tool_usage(agent_id, tool_lower)

    # Check scope creep — is agent using many out-of-scope tools?
    scope_history  = get_scope_history(agent_id)
    out_of_scope   = [t for t in scope_history if t not in all_allowed]
    creep_detected = len(out_of_scope) >= 3

    gap_score = 65 if creep_detected else 45
    gap_level = "HIGH" if creep_detected else "MEDIUM"

    scope_note = (
        f" Scope creep detected — agent has used {len(out_of_scope)} "
        f"out-of-scope tools this session."
        if creep_detected else ""
    )

    return IntentGapResult(
        declared_intent    = declared_intent,
        actual_action      = tool_name,
        gap_score          = gap_score,
        gap_level          = gap_level,
        reason             = (
            f"Tool '{tool_name}' is outside declared scope for "
            f"'{primary_category}' intent.{scope_note}"
        ),
        should_block       = creep_detected,
        matched_category   = primary_category,
        matched_intents    = matched_intents,
        allowed_tools      = all_allowed,
        confidence         = 0.75,
        is_scope_violation = creep_detected,
        remediation        = (
            f"Review whether '{tool_name}' should be in declared permissions. "
            f"If legitimate, add to agent's declared_permissions."
        ),
        remediation_steps  = [
            f"Verify '{tool_name}' is needed for this agent's purpose",
            f"If needed, add to declared_permissions during registration",
            f"If not needed, this may indicate scope creep or injection",
            f"Tools used outside scope this session: {out_of_scope[:5]}",
        ],
        scan_surfaces      = scan_surfaces,
    )


# ─────────────────────────────────────────────────────────────
# Injection Scanner
# ─────────────────────────────────────────────────────────────

def _scan_for_injections(
    text   : str,
    surface: str,
) -> List[InjectionEvidence]:
    """Scan a text surface for all matching injection signatures."""
    hits: List[InjectionEvidence] = []

    for (pattern, inj_type, owasp_cat, severity,
         confidence, description, remediation) in INJECTION_SIGNATURES:

        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            hits.append(InjectionEvidence(
                injection_type  = inj_type,
                matched_pattern = pattern,
                matched_text    = match.group(0)[:100],  # Truncate for safety
                found_in        = surface,
                confidence      = confidence,
                owasp_category  = owasp_cat,
                severity        = severity,
                description     = description,
                remediation     = remediation,
            ))

    return hits


# ─────────────────────────────────────────────────────────────
# Deep Parameter Scanner
# Handles nested JSON — attackers hide injections in nested keys
# ─────────────────────────────────────────────────────────────

def _deep_stringify(obj, depth: int = 0) -> str:
    """
    Recursively flatten any dict/list/value to a single string.
    Prevents attackers from hiding injections in nested structures.
    """
    if depth > 5:  # Prevent infinite recursion on pathological inputs
        return str(obj)

    if isinstance(obj, dict):
        parts = []
        for k, v in obj.items():
            parts.append(f"{k} {_deep_stringify(v, depth + 1)}")
        return " ".join(parts).lower()

    if isinstance(obj, list):
        return " ".join(_deep_stringify(i, depth + 1) for i in obj).lower()

    if isinstance(obj, bytes):
        try:
            return obj.decode("utf-8", errors="replace").lower()
        except Exception:
            return ""

    try:
        return str(obj).lower()
    except Exception:
        return ""


# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────

def _injection_to_gap_score(evidence: InjectionEvidence) -> int:
    """Convert injection severity + confidence to a gap score."""
    base = {"CRITICAL": 95, "HIGH": 82, "MEDIUM": 60, "LOW": 40}
    raw  = base.get(evidence.severity, 70)
    return min(100, int(raw * evidence.confidence))


def _build_remediation_steps(
    evidence : InjectionEvidence,
    tool_name: str,
) -> List[str]:
    """Build ordered remediation steps for an injection event."""
    steps = [
        f"IMMEDIATE: Block tool call '{tool_name}'",
        f"IMMEDIATE: {evidence.remediation}",
        f"INVESTIGATE: Identify source of injection — check document inputs, API payloads, user messages",
        f"CONTAIN: Review all actions taken by this agent in current session",
        f"REMEDIATE: Sanitize and re-validate all inputs before re-enabling agent",
        f"REPORT: Log as {evidence.owasp_category} security event",
    ]
    return steps


def get_intent_categories() -> dict:
    """Expose intent tree for dashboard — shows what each agent type is allowed to do."""
    return {
        category: {
            "allowed_tools": config["allowed_tools"],
            "forbidden_tools": config["forbidden"],
            "keyword_count": len(config["keywords"]),
        }
        for category, config in INTENT_TREE.items()
    }

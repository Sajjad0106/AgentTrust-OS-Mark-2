import re
import json
import base64
from dataclasses import dataclass, field
from typing import Any, List, Optional


# ─────────────────────────────────────────────────────────────
# Semantic Analyzer — Lightweight obfuscation detection
# ─────────────────────────────────────────────────────────────

class SemanticAnalyzer:
    """Lightweight semantic analyzer to detect obfuscation and intent bypasses."""

    # Common obfuscation patterns
    OBFUSCATION_PATTERNS = {
        "getattr": r"getattr\s*\(\s*[\w\.]+\s*,\s*['\"]",
        "exec_builtin": r"__import__\s*\(\s*['\"]",
        "locals_globals": r"locals\s*\(\s*\)|globals\s*\(\s*\)",
        "compile_eval": r"compile\s*\(|eval\s*\(|exec\s*\(",
        "bytecode_exec": r"exec\s*\(\s*bytes\s*\(",
        "base64_decode_exec": r"base64\.b64decode\s*\(\s*['\"]",
        "chr_concat": r"chr\s*\(\d+\)\s*\+\s*chr\s*\(\d+\)",
        "format_string": r"['\"][a-z_]+['\"]\s*\.\s*format\s*\(",
    }

    # Dangerous command aliases (after de-obfuscation)
    DANGEROUS_ALIASES = {
        "os.system": ["system", "shell", "cmd", "bash", "sh", "terminal", "console"],
        "subprocess": ["subprocess", "subproc", "sub-process", "spawn"],
        "eval/exec": ["execute", "exec", "eval", "run_code", "call_func"],
        "file_write": ["write", "create_file", "save", "dump", "output"],
        "file_read": ["read", "get_file", "load", "fetch", "import"],
    }

    def __init__(self):
        pass

    def normalize(self, text: str) -> str:
        """
        De-obfuscate text by:
        1. Decoding base64 strings
        2. Resolving common string concatenations
        3. Normalizing whitespace and quotes
        4. Expanding chr() calls
        """
        if not isinstance(text, str):
            return str(text)

        result = text

        # Decode base64 (but not in patterns that look like normal strings)
        try:
            # Look for base64-encoded strings
            b64_pattern = r"['\"]([A-Za-z0-9+/=]{20,})['\"]"
            for match in re.finditer(b64_pattern, result):
                try:
                    decoded = base64.b64decode(match.group(1)).decode('utf-8', errors='ignore')
                    # Only replace if it looks like legitimate text
                    if re.match(r"^[a-zA-Z0-9\s_\-./]+$", decoded):
                        result = result.replace(match.group(0), f"'{decoded}'")
                except Exception:
                    pass
        except Exception:
            pass

        # Resolve quoted string concatenations (e.g., 'sys' + 'tem' -> "system")
        # — needed because base64/alias checks run on the normalized text.
        for _ in range(3):  # a few passes to handle chained concatenations
            result = re.sub(
                r"['\"](\w+)['\"]\s*\+\s*['\"](\w+)['\"]",
                lambda m: '"' + m.group(1) + m.group(2) + '"',
                result,
            )

        # Resolve chr() concatenations (e.g., chr(111)+chr(115) -> "os")
        def replace_chr(match):
            try:
                chars = [chr(int(c)) for c in match.groups()]
                return '"' + ''.join(chars) + '"'
            except Exception:
                return match.group(0)

        chr_pattern = r"chr\s*\(\s*(\d+)\s*\)\s*\+\s*chr\s*\(\s*(\d+)\s*\)"
        result = re.sub(chr_pattern, replace_chr, result)

        # Normalize whitespace
        result = re.sub(r"\s+", " ", result)

        return result

    def check_obfuscation(self, text: str) -> tuple[float, List[str]]:
        """
        Check for obfuscation patterns in text.
        Returns (obfuscation_score, detected_patterns)
        """
        score = 0.0
        patterns = []

        for pattern_name, pattern in self.OBFUSCATION_PATTERNS.items():
            if re.search(pattern, text, re.IGNORECASE):
                patterns.append(pattern_name)
                score += 0.2

        return min(1.0, score), patterns

    def check_dangerous_alias(self, text: str) -> tuple[bool, str]:
        """
        Check if text contains dangerous commands even when obfuscated.
        Returns (is_dangerous, detected_command)

        Word-boundary matching so tool names like 'read_file' do not
        false-positive on the keyword 'read'.
        """
        normalized = self.normalize(text).lower()

        for alias, keywords in self.DANGEROUS_ALIASES.items():
            for kw in keywords:
                if re.search(r"\b" + re.escape(kw) + r"\b", normalized):
                    return True, alias

        return False, ""

    def analyze_intent(self, text: str) -> dict[str, Any]:
        """
        Analyze text for malicious intent.
        Returns (intent_score, intent_category, confidence)
        """
        normalized = self.normalize(text).lower()

        # Intent categories
        intent_patterns = {
            "code_execution": [
                r"os\.system|subprocess|eval|exec|compile",
                r"__import__|locals\(\)|globals\(\)",
                r"exec\s*\(\s*bytes",
            ],
            "data_theft": [
                r"export.*all|dump.*database|backup.*all|exfil",
                r"upload.*to|send.*data|transfer.*file",
            ],
            "persistence": [
                r"crontab|schtasks|systemctl.*enable|registry",
                r"start.*boot|autostart|run.*login",
            ],
            "privilege_escalation": [
                r"sudo|root|admin|administer|elevat",
                r"chmod.*777|chown.*root|setuid",
            ],
        }

        scores = {}
        for category, patterns in intent_patterns.items():
            match_count = sum(1 for p in patterns if re.search(p, normalized, re.IGNORECASE))
            scores[category] = min(1.0, match_count * 0.5)

        # Determine primary intent
        primary = max(scores.items(), key=lambda x: x[1])

        return {
            "intent_score": primary[1],
            "intent_category": primary[0] if primary[1] > 0.3 else "none",
            "confidence": primary[1],
            "all_scores": scores,
        }


# ─────────────────────────────────────────────────────────────
# MITRE ATT&CK for AI Agents — Custom Taxonomy
# Based on MITRE ATLAS + emerging agentic attack patterns
# ─────────────────────────────────────────────────────────────

@dataclass
class ThreatSignal:
    pattern         : str
    severity        : int        # 1-10
    confidence      : float      # 0.0 - 1.0
    mitre_technique : str
    mitre_tactic    : str
    description     : str
    remediation     : str
    tags            : List[str]  = field(default_factory=list)


@dataclass
class RiskAssessment:
    risk_score      : int         # 0-100
    risk_level      : str         # LOW / MEDIUM / HIGH / CRITICAL
    confidence      : float       # 0.0 - 1.0
    mitre_technique : str
    mitre_tactic    : str
    description     : str
    remediation     : str
    matched_signals : List[str]
    tags            : List[str]
    reason          : str


# ─────────────────────────────────────────────────────────────
# Threat Signal Library
# ─────────────────────────────────────────────────────────────

THREAT_SIGNALS: List[ThreatSignal] = [

    # ── Credential Access ─────────────────────────────────────
    ThreatSignal(
        pattern         = r"\/etc\/passwd|\/etc\/shadow|\/etc\/hosts",
        severity        = 10,
        confidence      = 0.97,
        mitre_technique = "T1552.001",
        mitre_tactic    = "Credential Access",
        description     = "Agent attempted to read Unix credential files",
        remediation     = "Immediately revoke agent token. Audit all prior file access. Rotate system credentials.",
        tags            = ["credential-access", "unix", "passwd"]
    ),
    ThreatSignal(
        pattern         = r"\.env|\.aws\/credentials|\.ssh\/id_rsa|\.ssh\/id_ed",
        severity        = 10,
        confidence      = 0.96,
        mitre_technique = "T1552.001",
        mitre_tactic    = "Credential Access",
        description     = "Agent attempted to access secret/credential configuration files",
        remediation     = "Revoke agent token. Rotate all exposed secrets. Enable secret scanning.",
        tags            = ["credential-access", "secrets", "env"]
    ),
    ThreatSignal(
        pattern         = r"api_key\s*=|secret_key\s*=|private_key\s*=|password\s*=|passwd\s*=|bearer\s+[a-z0-9]",
        severity        = 9,
        confidence      = 0.91,
        mitre_technique = "T1552.004",
        mitre_tactic    = "Credential Access",
        description     = "Agent request contains credential patterns in parameters — possible exfiltration attempt",
        remediation     = "Block request. Scan agent memory for credential exposure. Alert security team.",
        tags            = ["credential-exposure", "api-key", "exfiltration"]
    ),

    # ── Execution ─────────────────────────────────────────────
    ThreatSignal(
        pattern         = r"os\.system\s*\(|subprocess\.(run|call|Popen)|eval\s*\(|exec\s*\(",
        severity        = 10,
        confidence      = 0.98,
        mitre_technique = "T1059",
        mitre_tactic    = "Execution",
        description     = "Agent attempted dynamic code execution — high confidence RCE pattern",
        remediation     = "Block immediately. Sandbox agent. Full forensic review of session history.",
        tags            = ["rce", "code-execution", "critical"]
    ),
    ThreatSignal(
        pattern         = r"rm\s+-rf|del\s+\/[fqs]|format\s+[a-z]:|rd\s+\/s",
        severity        = 10,
        confidence      = 0.99,
        mitre_technique = "T1485",
        mitre_tactic    = "Impact",
        description     = "Agent attempted data destruction command",
        remediation     = "Block immediately. Snapshot affected systems. Initiate incident response.",
        tags            = ["destruction", "ransomware", "critical"]
    ),
    ThreatSignal(
        pattern         = r"curl\s+http|wget\s+http|requests\.get\s*\(.*http|fetch\s*\(.*http",
        severity        = 7,
        confidence      = 0.82,
        mitre_technique = "T1041",
        mitre_tactic    = "Exfiltration",
        description     = "Agent initiated outbound HTTP request — possible data exfiltration channel",
        remediation     = "Inspect destination URL. Block if unknown domain. Enable egress filtering.",
        tags            = ["exfiltration", "outbound", "network"]
    ),

    # ── Discovery ─────────────────────────────────────────────
    ThreatSignal(
        pattern         = r"\/proc\/\d+|\/sys\/kernel|\/sys\/class",
        severity        = 7,
        confidence      = 0.85,
        mitre_technique = "T1082",
        mitre_tactic    = "Discovery",
        description     = "Agent accessed kernel/process information — system reconnaissance detected",
        remediation     = "Flag for review. Restrict agent permissions to declared scope.",
        tags            = ["discovery", "reconnaissance", "kernel"]
    ),
    ThreatSignal(
        pattern         = r"list_all|enum\w+|get_all_users|get_all_files|scan_network",
        severity        = 6,
        confidence      = 0.78,
        mitre_technique = "T1083",
        mitre_tactic    = "Discovery",
        description     = "Agent performed broad enumeration — possible reconnaissance phase",
        remediation     = "Monitor closely. Restrict to declared permission scope.",
        tags            = ["discovery", "enumeration", "recon"]
    ),

    # ── Exfiltration ──────────────────────────────────────────
    ThreatSignal(
        pattern         = r"export.*all|dump.*database|backup.*all|extract.*users|all_records",
        severity        = 8,
        confidence      = 0.87,
        mitre_technique = "T1530",
        mitre_tactic    = "Exfiltration",
        description     = "Agent attempted bulk data export — possible data theft operation",
        remediation     = "Block export. Audit data access logs. Check for prior staging activity.",
        tags            = ["exfiltration", "data-theft", "bulk-export"]
    ),
    ThreatSignal(
        pattern         = r"base64\.encode|btoa\(|\.encode\('base64'\)",
        severity        = 6,
        confidence      = 0.72,
        mitre_technique = "T1027",
        mitre_tactic    = "Defense Evasion",
        description     = "Agent used data encoding — possible obfuscation of exfiltrated content",
        remediation     = "Decode and inspect payload. Flag agent for behavioral review.",
        tags            = ["obfuscation", "encoding", "evasion"]
    ),

    # ── Persistence ───────────────────────────────────────────
    ThreatSignal(
        pattern         = r"crontab\s+-[el]|at\s+\d|schtasks\s+\/create|systemctl\s+enable",
        severity        = 9,
        confidence      = 0.93,
        mitre_technique = "T1053",
        mitre_tactic    = "Persistence",
        description     = "Agent attempted to create scheduled task — persistence mechanism detected",
        remediation     = "Block and remove scheduled task. Full session forensic review.",
        tags            = ["persistence", "scheduled-task", "critical"]
    ),

    # ── Prompt Injection ──────────────────────────────────────
    ThreatSignal(
        pattern         = r"ignore\s+(previous|prior|above|all)\s+instructions?",
        severity        = 9,
        confidence      = 0.95,
        mitre_technique = "AML.T0051",
        mitre_tactic    = "Prompt Injection",
        description     = "Classic prompt injection pattern detected in agent parameters",
        remediation     = "Block request. Sanitize all upstream inputs to this agent.",
        tags            = ["prompt-injection", "llm-attack", "critical"]
    ),
    ThreatSignal(
        pattern         = r"you are now|act as a|pretend you are|your new (role|persona|identity)",
        severity        = 8,
        confidence      = 0.88,
        mitre_technique = "AML.T0051.001",
        mitre_tactic    = "Prompt Injection",
        description     = "Role-hijacking prompt injection pattern detected",
        remediation     = "Block request. Review all documents/inputs this agent processed.",
        tags            = ["prompt-injection", "role-hijack", "llm-attack"]
    ),

    # ── Lateral Movement ─────────────────────────────────────
    ThreatSignal(
        pattern         = r"ssh\s+\w+@|scp\s+|rsync\s+.*@|psexec|winrm",
        severity        = 9,
        confidence      = 0.92,
        mitre_technique = "T1021",
        mitre_tactic    = "Lateral Movement",
        description     = "Agent attempted remote access to another system",
        remediation     = "Block immediately. Check for unauthorized remote sessions. Network isolation.",
        tags            = ["lateral-movement", "remote-access", "critical"]
    ),
]


# ─────────────────────────────────────────────────────────────
# Medium Risk Signals — Lower severity but worth tracking
# ─────────────────────────────────────────────────────────────

MEDIUM_SIGNALS: List[ThreatSignal] = [
    ThreatSignal(
        pattern         = r"\/var\/log|\/var\/lib|\/tmp\/",
        severity        = 5,
        confidence      = 0.65,
        mitre_technique = "T1083",
        mitre_tactic    = "Discovery",
        description     = "Agent accessed system log or temp directory",
        remediation     = "Monitor. Verify this aligns with declared agent intent.",
        tags            = ["discovery", "system-access"]
    ),
    ThreatSignal(
        pattern         = r"drop\s+table|delete\s+from\s+\w+\s+where\s+1|truncate\s+table",
        severity        = 6,
        confidence      = 0.88,
        mitre_technique = "T1485",
        mitre_tactic    = "Impact",
        description     = "Potentially destructive database operation detected",
        remediation     = "Require human approval before execution. Verify with data owner.",
        tags            = ["database", "destruction", "sql"]
    ),
    ThreatSignal(
        pattern         = r"\.ssh\/|\.aws\/|\.kube\/config|\.docker\/config",
        severity        = 6,
        confidence      = 0.82,
        mitre_technique = "T1552.001",
        mitre_tactic    = "Credential Access",
        description     = "Agent accessed sensitive configuration directory",
        remediation     = "Flag for review. Verify agent has legitimate need.",
        tags            = ["config-access", "credentials"]
    ),
]


# ── Global semantic analyzer instance ───
_SEMANTIC_ANALYZER = SemanticAnalyzer()


# ─────────────────────────────────────────────────────────────
# Core Scoring Function
# ─────────────────────────────────────────────────────────────

def score_tool_call(
    tool_name     : str,
    parameters    : dict,
    agent_context : Optional[dict] = None
) -> tuple:

    assessment = assess_risk(tool_name, parameters, agent_context)
    return assessment.risk_score, assessment.risk_level, assessment.reason


def assess_risk(
    tool_name     : str,
    parameters    : dict,
    agent_context : Optional[dict] = None
) -> RiskAssessment:
    """
    Assess risk with semantic analysis to detect obfuscation bypasses.
    Uses normalization layer + regex matching for comprehensive detection.
    """

    # ── Step 1: Normalize the combined string (de-obfuscation layer) ───
    # NOTE: normalize() runs on ORIGINAL CASE — base64 decoding is
    # case-sensitive and would be destroyed by pre-lowercasing.
    raw_combined = f"{tool_name.lower()} {_stringify(parameters).lower()}"
    normalized = _SEMANTIC_ANALYZER.normalize(f"{tool_name} {_stringify(parameters)}").lower()

    # ── Step 2: Check for obfuscation patterns ───
    obs_score, obs_patterns = _SEMANTIC_ANALYZER.check_obfuscation(raw_combined)

    # ── Step 3: Check for dangerous aliases (even when obfuscated) ───
    is_dangerous, detected_alias = _SEMANTIC_ANALYZER.check_dangerous_alias(normalized)

    # ── Step 4: Analyze intent (semantic analysis) ───
    intent_result = _SEMANTIC_ANALYZER.analyze_intent(raw_combined)
    intent_score = intent_result["intent_score"]

    # ── Step 5: Check HIGH signals against normalized text ───
    combined = normalized
    matched  : List[ThreatSignal] = []

    for signal in THREAT_SIGNALS:
        if re.search(signal.pattern, combined, re.IGNORECASE):
            matched.append(signal)

    # ── Step 6: If obfuscation detected or dangerous alias found, boost score ───
    raw_score = 0
    primary = None
    confidence = 1.0

    if matched:
        primary = max(matched, key=lambda s: s.severity * s.confidence)
        raw_score = int(primary.severity * primary.confidence * 10)
    elif is_dangerous:
        # Even without regex match, dangerous alias = HIGH confidence threat
        primary = ThreatSignal(
            pattern="obfuscation_bypass",
            severity=9,
            confidence=0.90,
            mitre_technique="T1027.001",
            mitre_tactic="Defense Evasion",
            description=f"Detected obfuscated dangerous command: {detected_alias}",
            remediation="Block request. Agent attempting to bypass detection.",
            tags=["obfuscation", "evasion", detected_alias]
        )
        raw_score = int(primary.severity * primary.confidence * 10)
        confidence = 0.90

    # ── Step 7: Apply obfuscation and intent boosts ───
    if obs_score > 0:
        raw_score = min(100, raw_score + int(obs_score * 20))
        confidence = round(confidence * (1 - obs_score * 0.2), 2)

    if intent_score > 0.5:
        raw_score = min(100, raw_score + int(intent_score * 15))

    # Context boost — if agent already has low trust, score goes higher
    if agent_context:
        trust = agent_context.get("trust_score", 100)
        if trust < 50:
            raw_score = min(100, raw_score + 10)

    # ── Determine risk level ───
    risk_level = _score_to_level(raw_score)

    # Build matched signals list
    all_tags = list({tag for s in matched for tag in s.tags})
    if is_dangerous:
        all_tags.append("obfuscation_bypass")
    all_tags.extend(obs_patterns)

    # Build reason string
    reason_parts = []
    if primary:
        reason_parts.append(f"[{risk_level}] {primary.description}")
    if is_dangerous:
        reason_parts.append(f"Dangerous alias detected: {detected_alias}")
    if obs_patterns:
        reason_parts.append(f"Obfuscation patterns: {', '.join(obs_patterns)}")
    if intent_result["intent_category"] != "none":
        reason_parts.append(f"Intent: {intent_result['intent_category']} (score: {intent_result['intent_score']:.2f})")

    if not reason_parts:
        reason_parts.append(f"[LOW] No threat patterns detected — Tool: '{tool_name}'")

    reason = " | ".join(reason_parts)

    # ── Return assessment ───
    if matched or is_dangerous:
        if not primary:
            primary = ThreatSignal(
                pattern="obfuscation_bypass",
                severity=9,
                confidence=0.90,
                mitre_technique="T1027.001",
                mitre_tactic="Defense Evasion",
                description="Obfuscation detected",
                remediation="Block request. Agent attempting to bypass detection.",
                tags=["obfuscation", "evasion"]
            )

        return RiskAssessment(
            risk_score      = raw_score,
            risk_level      = risk_level,
            confidence      = confidence,
            mitre_technique = primary.mitre_technique,
            mitre_tactic    = primary.mitre_tactic,
            description     = primary.description,
            remediation     = primary.remediation,
            matched_signals = [s.mitre_technique for s in matched] + ([detected_alias] if is_dangerous else []),
            tags            = all_tags,
            reason          = reason
        )

    # Check MEDIUM signals
    for signal in MEDIUM_SIGNALS:
        if re.search(signal.pattern, combined, re.IGNORECASE):
            raw_score = int(signal.severity * signal.confidence * 10)
            return RiskAssessment(
                risk_score      = raw_score,
                risk_level      = "MEDIUM",
                confidence      = round(signal.confidence, 2),
                mitre_technique = signal.mitre_technique,
                mitre_tactic    = signal.mitre_tactic,
                description     = signal.description,
                remediation     = signal.remediation,
                matched_signals = [signal.mitre_technique],
                tags            = signal.tags,
                reason          = (
                    f"[MEDIUM] {signal.description} | "
                    f"MITRE: {signal.mitre_tactic} ({signal.mitre_technique}) | "
                    f"Confidence: {int(signal.confidence * 100)}%"
                )
            )

    # Clean
    return RiskAssessment(
        risk_score      = 5,
        risk_level      = "LOW",
        confidence      = 1.0,
        mitre_technique = "N/A",
        mitre_tactic    = "N/A",
        description     = "No threat signals detected",
        remediation     = "No action required",
        matched_signals = [],
        tags            = [],
        reason          = reason
    )

    if matched:
        # Pick highest severity signal as primary
        primary   = max(matched, key=lambda s: s.severity * s.confidence)
        raw_score = int(primary.severity * primary.confidence * 10)

        # Context boost — if agent already has low trust, score goes higher
        if agent_context:
            trust = agent_context.get("trust_score", 100)
            if trust < 50:
                raw_score = min(100, raw_score + 10)

        risk_level = _score_to_level(raw_score)
        all_tags   = list({tag for s in matched for tag in s.tags})

        return RiskAssessment(
            risk_score      = raw_score,
            risk_level      = risk_level,
            confidence      = round(primary.confidence, 2),
            mitre_technique = primary.mitre_technique,
            mitre_tactic    = primary.mitre_tactic,
            description     = primary.description,
            remediation     = primary.remediation,
            matched_signals = [s.mitre_technique for s in matched],
            tags            = all_tags,
            reason          = (
                f"[{risk_level}] {primary.description} | "
                f"MITRE: {primary.mitre_tactic} ({primary.mitre_technique}) | "
                f"Confidence: {int(primary.confidence * 100)}% | "
                f"Signals: {len(matched)}"
            )
        )

    # Check MEDIUM signals
    for signal in MEDIUM_SIGNALS:
        if re.search(signal.pattern, combined, re.IGNORECASE):
            raw_score = int(signal.severity * signal.confidence * 10)
            return RiskAssessment(
                risk_score      = raw_score,
                risk_level      = "MEDIUM",
                confidence      = round(signal.confidence, 2),
                mitre_technique = signal.mitre_technique,
                mitre_tactic    = signal.mitre_tactic,
                description     = signal.description,
                remediation     = signal.remediation,
                matched_signals = [signal.mitre_technique],
                tags            = signal.tags,
                reason          = (
                    f"[MEDIUM] {signal.description} | "
                    f"MITRE: {signal.mitre_tactic} ({signal.mitre_technique}) | "
                    f"Confidence: {int(signal.confidence * 100)}%"
                )
            )

    # Clean
    return RiskAssessment(
        risk_score      = 5,
        risk_level      = "LOW",
        confidence      = 1.0,
        mitre_technique = "N/A",
        mitre_tactic    = "N/A",
        description     = "No threat signals detected",
        remediation     = "No action required",
        matched_signals = [],
        tags            = [],
        reason          = f"[LOW] No threat patterns detected — Tool: '{tool_name}'"
    )


def get_threat_library() -> list:
    """Expose full threat library for dashboard"""
    return [
        {
            "mitre_technique": s.mitre_technique,
            "mitre_tactic"   : s.mitre_tactic,
            "severity"       : s.severity,
            "confidence"     : s.confidence,
            "description"    : s.description,
            "tags"           : s.tags
        }
        for s in THREAT_SIGNALS + MEDIUM_SIGNALS
    ]


# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────

def _score_to_level(score: int) -> str:
    if score >= 85: return "CRITICAL"
    if score >= 65: return "HIGH"
    if score >= 40: return "MEDIUM"
    return "LOW"


def _stringify(obj) -> str:
    try:
        return json.dumps(obj)
    except Exception:
        return str(obj)
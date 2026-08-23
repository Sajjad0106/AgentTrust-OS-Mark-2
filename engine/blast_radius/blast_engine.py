from engine.blast_radius.blast_models import BlastRadiusProfile
from typing import Optional

SENSITIVE_PATHS = [
    "/etc", "/root", "/.env", "/.aws", "/.ssh",
    "/credentials", "/secrets", "C:\\Windows",
    "/var/lib", "/proc", "/sys"
]

NETWORK_TOOLS = [
    "send_request", "http_call", "curl",
    "fetch_url", "webhook", "api_call"
]

CREDENTIAL_TOOLS = [
    "read_credentials", "get_secret", "fetch_token",
    "read_env", "get_api_key"
]


def calculate_blast_radius(
    agent_id            : str,
    declared_permissions: list[str],
    downstream_agents   : Optional[list[str]] = None
) -> BlastRadiusProfile:

    downstream_agents = downstream_agents or []
    score = 0
    reasons: list[str] = []

    # Check sensitive path access
    sensitive_count = sum(
        1 for p in declared_permissions
        if any(s.lower() in p.lower() for s in SENSITIVE_PATHS)
    )
    if sensitive_count > 0:
        score += sensitive_count * 15
        reasons.append(f"Access to {sensitive_count} sensitive path(s)")

    # Check network access
    has_network = any(
        t.lower() in p.lower()
        for p in declared_permissions
        for t in NETWORK_TOOLS
    )
    if has_network:
        score += 20
        reasons.append("Has outbound network access")

    # Check credential access
    has_credentials = any(
        t.lower() in p.lower()
        for p in declared_permissions
        for t in CREDENTIAL_TOOLS
    )
    if has_credentials:
        score += 30
        reasons.append("Has credential/secret access")

    # Downstream agent connections multiply risk
    if downstream_agents:
        score += len(downstream_agents) * 10
        reasons.append(f"Connected to {len(downstream_agents)} downstream agent(s)")

    # Clamp to 100
    score = min(score, 100)

    level = (
        "CRITICAL" if score >= 75 else
        "HIGH"     if score >= 50 else
        "MEDIUM"   if score >= 25 else
        "LOW"
    )

    return BlastRadiusProfile(
        agent_id             = agent_id,
        blast_score          = score,
        blast_level          = level,
        sensitive_path_count = sensitive_count,
        network_access       = has_network,
        credential_access    = has_credentials,
        downstream_agents    = downstream_agents,
        declared_permissions = declared_permissions,
        reason               = " | ".join(reasons) if reasons else "No significant blast radius detected"
    )
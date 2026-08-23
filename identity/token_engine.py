from identity.token_store import issue_token, verify_token, revoke_agent_tokens
from fastapi import Request, HTTPException
from typing import Any


def create_agent_token(agent_id: str) -> dict[str, Any]:
    token = issue_token(agent_id)
    return {
        "agent_id"   : agent_id,
        "token"      : token,
        "message"    : "Store this token securely. It will not be shown again.",
        "ttl_hours"  : 24
    }


def authenticate_request(request: Request) -> dict[str, Any]:
    auth_header = request.headers.get("X-Agent-Token")

    if not auth_header:
        raise HTTPException(
            status_code=401,
            detail="Missing X-Agent-Token header. Zero Trust policy requires agent authentication."
        )

    result = verify_token(auth_header)

    if not result["valid"]:
        raise HTTPException(
            status_code=403,
            detail=f"Token verification failed: {result['reason']}"
        )

    return result


def revoke_agent(agent_id: str) -> dict[str, str]:
    revoke_agent_tokens(agent_id)
    return {"status": "revoked", "agent_id": agent_id}
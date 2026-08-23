"""
AgentTrust OS — Token Store with Database Persistence
Uses SQLite for token storage that survives restarts.
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Optional
import sys
import os

# Add infrastructure to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from infrastructure.database import (
    issue_token_db, verify_token_db, revoke_token_db,
    get_agent_db, init_db
)


def init() -> None:
    """Initialize the database."""
    init_db()


def issue_token(agent_id: str, ttl_hours: int = 24) -> str:
    """Issue a token for an agent and store it persistently."""
    import secrets
    raw_token = secrets.token_hex(32)

    # Store token in database
    token_data = issue_token_db(agent_id, raw_token, ttl_hours)

    return raw_token  # Only returned ONCE — never stored raw


def verify_token(raw_token: str) -> dict[str, Any]:
    """Verify a token using the persistent database."""
    result = verify_token_db(raw_token)
    return result


def revoke_agent_tokens(agent_id: str) -> None:
    """Revoke all tokens for an agent from the database."""
    revoke_token_db(agent_id)


def get_token(agent_id: str) -> Optional[dict[str, Any]]:
    """Get the current valid token for an agent (for management purposes)."""
    import hashlib

    # Find the most recent non-revoked token
    result = verify_token_db("dummy")  # Just to trigger import check
    return None  # Token storage is hash-only in DB, can't retrieve raw token

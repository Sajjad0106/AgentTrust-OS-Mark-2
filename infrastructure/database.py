"""
AgentTrust OS — Persistent Identity & Trust Store
Using SQLite for durability across restarts.
"""

import sqlite3
import os
import threading
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
import hashlib

DB_PATH = "logs/agenttrust.db"

# Serialises all WRITE transactions at the Python level. Under concurrent
# load (many agents intercepting at once) this keeps each write ~sub-millisecond
# instead of letting threads pile up on SQLite's write lock and blow the
# per-engine timeouts (fail-closed BLOCK on clean traffic).
_db_write_lock = threading.Lock()


def get_connection() -> sqlite3.Connection:
    """Get a database connection with foreign keys + WAL enabled.

    WAL lets readers run concurrently with a single writer and makes write
    handoff fast; the busy timeout (10s) covers the worst-case lock wait.
    """
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def init_db() -> None:
    """Initialize the database schema."""
    conn = get_connection()
    cursor = conn.cursor()

    # ── Agents table ──
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS agents (
            agent_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            declared_intent TEXT,
            declared_permissions TEXT,
            downstream_agents TEXT,
            blast_score INTEGER DEFAULT 0,
            blast_level TEXT DEFAULT 'LOW',
            blast_reason TEXT,
            trust_score REAL DEFAULT 100.0,
            registered_at TEXT NOT NULL
        )
    """)

    # ── Tokens table ──
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS tokens (
            token_hash TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            issued_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            revoked INTEGER DEFAULT 0,
            FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE CASCADE
        )
    """)

    # ── Governance table (prerequisites profile per agent) ──
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS governance (
            agent_id TEXT PRIMARY KEY,
            prerequisites TEXT NOT NULL DEFAULT '[]',
            source TEXT NOT NULL DEFAULT 'derived',
            version INTEGER NOT NULL DEFAULT 1,
            updated_at TEXT,
            updated_by TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE CASCADE
        )
    """)

    # ── Trust profiles table ──
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS trust_profiles (
            agent_id TEXT PRIMARY KEY,
            trust_score REAL DEFAULT 100.0,
            peak_trust REAL DEFAULT 100.0,
            floor_trust REAL DEFAULT 100.0,
            total_actions INTEGER DEFAULT 0,
            blocked_actions INTEGER DEFAULT 0,
            flagged_actions INTEGER DEFAULT 0,
            allowed_actions INTEGER DEFAULT 0,
            consecutive_clean INTEGER DEFAULT 0,
            consecutive_risk INTEGER DEFAULT 0,
            max_consecutive_risk INTEGER DEFAULT 0,
            containment_level TEXT DEFAULT 'NONE',
            containment_reason TEXT,
            is_sandboxed INTEGER DEFAULT 0,
            sandbox_reason TEXT,
            session_count INTEGER DEFAULT 1,
            created_at TEXT NOT NULL,
            last_action_time TEXT,
            FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE CASCADE
        )
    """)

    conn.commit()
    conn.close()


def _hash_token(raw: str) -> str:
    """Hash a raw token for storage."""
    return hashlib.sha256(raw.encode()).hexdigest()


# ── Agent Registry Operations ───

def register_agent_db(
    agent_id: str,
    name: str,
    declared_intent: str,
    declared_permissions: List[str],
    downstream_agents: Optional[List[str]] = None,
    blast_score: int = 0,
    blast_level: str = "LOW",
    blast_reason: str = "",
    trust_score: float = 100.0
) -> dict[str, Any]:
    """Register an agent in the persistent store."""
    with _db_write_lock:
        conn = get_connection()
        cursor = conn.cursor()

        declared_permissions_json = (
            json.dumps(declared_permissions, ensure_ascii=True)
            if isinstance(declared_permissions, list) else str(declared_permissions)
        )
        downstream_agents_json = (
            json.dumps(downstream_agents or [], ensure_ascii=True)
            if isinstance(downstream_agents, list) else str(downstream_agents or [])
        )
        registered_at = datetime.now(timezone.utc).isoformat()

        cursor.execute("""
            INSERT OR REPLACE INTO agents
            (agent_id, name, declared_intent, declared_permissions, downstream_agents,
             blast_score, blast_level, blast_reason, trust_score, registered_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            agent_id, name, declared_intent, declared_permissions_json,
            downstream_agents_json, blast_score, blast_level, blast_reason,
            trust_score, registered_at
        ))

        conn.commit()
        conn.close()

    return get_agent_db(agent_id)


def get_agent_db(agent_id: str) -> Optional[dict[str, Any]]:
    """Get an agent by ID."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM agents WHERE agent_id = ?", (agent_id,))
    row = cursor.fetchone()
    conn.close()

    if row:
        return dict(row)
    return None


def get_all_agents_db() -> List[dict[str, Any]]:
    """Get all registered agents."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM agents")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def update_agent_blast(agent_id: str, blast_score: int, blast_level: str, blast_reason: str) -> None:
    """Update an agent's blast radius data."""
    with _db_write_lock:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE agents SET blast_score = ?, blast_level = ?, blast_reason = ?
            WHERE agent_id = ?
        """, (blast_score, blast_level, blast_reason, agent_id))
        conn.commit()
        conn.close()


# ── Token Operations ───

def issue_token_db(agent_id: str, raw_token: str, ttl_hours: int = 24) -> dict[str, Any]:
    """Issue a token for an agent."""
    with _db_write_lock:
        conn = get_connection()
        cursor = conn.cursor()

        token_hash = _hash_token(raw_token)
        now = datetime.now(timezone.utc)
        expires_at = (now + timedelta(hours=ttl_hours)).isoformat()
        issued_at = now.isoformat()

        # Revoke any existing tokens for this agent
        cursor.execute("UPDATE tokens SET revoked = 1 WHERE agent_id = ?", (agent_id,))

        cursor.execute("""
            INSERT INTO tokens (token_hash, agent_id, issued_at, expires_at, revoked)
            VALUES (?, ?, ?, ?, 0)
        """, (token_hash, agent_id, issued_at, expires_at))

        conn.commit()
        conn.close()

    return {
        "agent_id": agent_id,
        "token": raw_token,
        "ttl_hours": ttl_hours,
        "issued_at": issued_at,
        "expires_at": expires_at
    }


def verify_token_db(raw_token: str) -> dict[str, Any]:
    """Verify a token and return its status."""
    conn = get_connection()
    cursor = conn.cursor()

    token_hash = _hash_token(raw_token)
    now = datetime.now(timezone.utc).isoformat()

    cursor.execute("""
        SELECT t.*, a.name, a.declared_intent
        FROM tokens t
        LEFT JOIN agents a ON t.agent_id = a.agent_id
        WHERE t.token_hash = ?
    """, (token_hash,))

    row = cursor.fetchone()
    conn.close()

    if not row:
        return {"valid": False, "reason": "Token not found"}

    if row["revoked"]:
        return {"valid": False, "reason": "Token has been revoked"}

    if row["expires_at"] < now:
        return {"valid": False, "reason": "Token expired"}

    return {
        "valid": True,
        "agent_id": row["agent_id"],
        "name": row["name"],
        "declared_intent": row["declared_intent"],
        "issued_at": row["issued_at"],
        "expires_at": row["expires_at"]
    }


def revoke_token_db(agent_id: str) -> None:
    """Revoke all tokens for an agent."""
    with _db_write_lock:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE tokens SET revoked = 1 WHERE agent_id = ?", (agent_id,))
        conn.commit()
        conn.close()


# ── Trust Profile Operations ───

def create_or_update_trust_profile(
    agent_id: str,
    trust_score: float = 100.0,
    peak_trust: float = 100.0,
    floor_trust: float = 100.0,
    total_actions: int = 0,
    blocked_actions: int = 0,
    flagged_actions: int = 0,
    allowed_actions: int = 0,
    consecutive_clean: int = 0,
    consecutive_risk: int = 0,
    containment_level: str = "NONE",
    is_sandboxed: bool = False,
    session_count: Optional[int] = None
) -> None:
    """Create or update a trust profile.

    session_count=None preserves and increments the existing count
    (1 for brand-new profiles).
    """
    with _db_write_lock:
        conn = get_connection()
        cursor = conn.cursor()

        now = datetime.now(timezone.utc).isoformat()

        if session_count is None:
            # Preserve the stored session count (1 for brand-new profiles)
            cursor.execute(
                "SELECT COALESCE(MAX(session_count), 0) FROM trust_profiles WHERE agent_id = ?",
                (agent_id,)
            )
            row = cursor.fetchone()
            session_count = row[0] if row else 1

        cursor.execute("""
            INSERT OR REPLACE INTO trust_profiles
            (agent_id, trust_score, peak_trust, floor_trust, total_actions,
             blocked_actions, flagged_actions, allowed_actions,
             consecutive_clean, consecutive_risk, containment_level,
             is_sandboxed, session_count, created_at, last_action_time)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            agent_id, trust_score, peak_trust, floor_trust, total_actions,
            blocked_actions, flagged_actions, allowed_actions,
            consecutive_clean, consecutive_risk, containment_level,
            1 if is_sandboxed else 0, session_count, now, now
        ))

        conn.commit()
        conn.close()


def get_trust_profile_db(agent_id: str) -> Optional[dict[str, Any]]:
    """Get a trust profile by agent ID."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM trust_profiles WHERE agent_id = ?", (agent_id,))
    row = cursor.fetchone()
    conn.close()

    if row:
        return dict(row)
    return None


def update_trust_score_db(
    agent_id: str,
    trust_score: float,
    peak_trust: Optional[float] = None,
    floor_trust: Optional[float] = None,
    total_actions: int = 0,
    blocked_actions: int = 0,
    flagged_actions: int = 0,
    allowed_actions: int = 0,
    consecutive_clean: int = 0,
    consecutive_risk: int = 0,
    containment_level: str = "NONE",
    is_sandboxed: bool = False
) -> None:
    """Update an existing trust profile."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE trust_profiles
        SET trust_score = ?,
            peak_trust = COALESCE(?, peak_trust),
            floor_trust = COALESCE(?, floor_trust),
            total_actions = total_actions + ?,
            blocked_actions = blocked_actions + ?,
            flagged_actions = flagged_actions + ?,
            allowed_actions = allowed_actions + ?,
            consecutive_clean = ?,
            consecutive_risk = ?,
            containment_level = ?,
            is_sandboxed = ?,
            last_action_time = ?
        WHERE agent_id = ?
    """, (
        trust_score, peak_trust, floor_trust,
        total_actions, blocked_actions, flagged_actions, allowed_actions,
        consecutive_clean, consecutive_risk, containment_level,
        1 if is_sandboxed else 0, datetime.now(timezone.utc).isoformat(),
        agent_id
    ))

    conn.commit()
    conn.close()


def get_all_trust_profiles_db() -> List[dict[str, Any]]:
    """Get all trust profiles."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM trust_profiles")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


# ── Governance (prerequisites) ─────────────────────────────────────────────

def get_governance_db(agent_id: str) -> Optional[dict[str, Any]]:
    """Get the persisted governance profile for an agent (raw row or None)."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM governance WHERE agent_id = ?", (agent_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def upsert_governance_db(
    agent_id: str,
    prerequisites: List[dict[str, Any]],
    source: str = "derived",
    version: int = 1,
    updated_at: Optional[str] = None,
    updated_by: Optional[str] = None,
) -> None:
    """Persist (insert or replace) the governance profile for an agent.

    Serialised by the shared write lock; JSON is stored as text so the
    schema stays stable while prerequisite entries evolve.
    """
    with _db_write_lock:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO governance
            (agent_id, prerequisites, source, version, updated_at, updated_by, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(agent_id) DO UPDATE SET
                prerequisites = excluded.prerequisites,
                source        = excluded.source,
                version       = excluded.version,
                updated_at    = excluded.updated_at,
                updated_by    = excluded.updated_by
        """, (
            agent_id, json.dumps(prerequisites, ensure_ascii=True),
            source, version,
            updated_at or datetime.now(timezone.utc).isoformat(),
            updated_by,
            datetime.now(timezone.utc).isoformat(),
        ))
        conn.commit()
        conn.close()


def get_token_state_db(agent_id: str) -> dict[str, Any]:
    """Read-only token state for one agent (for the blockers view).

    Tokens are stored hash-only, so the per-agent state is derived from the
    agent's most recent token row:
      no_token  — never registered (or row cascaded)
      valid     — latest token is unrevoked and unexpired
      revoked   — latest token was revoked (e.g. POST /agents/revoke/{id})
      expired   — latest token's TTL lapsed

    Pure read — no writes, safe to call from the hot path.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT token_hash, issued_at, expires_at, revoked
        FROM tokens WHERE agent_id = ?
        ORDER BY issued_at DESC LIMIT 1
    """, (agent_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return {"state": "no_token", "issued_at": None, "expires_at": None}

    now = datetime.now(timezone.utc).isoformat()
    revoked = bool(row["revoked"])
    if revoked:
        state = "revoked"
    elif row["expires_at"] < now:
        state = "expired"
    else:
        state = "valid"
    return {"state": state, "issued_at": row["issued_at"], "expires_at": row["expires_at"]}


# ── Import Statements ───
import json
from datetime import datetime, timezone, timedelta

# Initialize DB on module import. init_db() is idempotent (CREATE TABLE IF
# NOT EXISTS), so calling it unconditionally also migrates pre-existing DBs
# (e.g. adding the governance table to a deployment that predates it).
init_db()

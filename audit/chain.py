import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any

AUDIT_FILE = "logs/audit_chain.jsonl"
STATE_FILE = "logs/audit_state.json"


def _compute_hash(data: dict[str, Any]) -> str:
    raw = json.dumps(data, sort_keys=True, ensure_ascii=True)
    return hashlib.sha256(raw.encode()).hexdigest()


def _load_last_hash_from_file() -> str:
    """Load the last hash from the audit file on startup for chain continuity."""
    try:
        if os.path.exists(AUDIT_FILE):
            with open(AUDIT_FILE, "r") as f:
                lines = [l for l in f if l.strip()]
                if lines:
                    last_record = json.loads(lines[-1])
                    return last_record.get("hash", "0" * 64)
    except Exception as e:
        print(f"[AuditChain] Warning: Could not load last hash: {e}")
    # Genesis hash if no file or error
    return "0" * 64


def _get_sequence() -> int:
    """Get the next sequence number using a state file to avoid O(N) counting."""
    # Ensure logs directory exists
    os.makedirs("logs", exist_ok=True)

    # Load state from file
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r") as f:
                state = json.load(f)
                seq = state.get("last_sequence", 0)
                # Increment and save
                state["last_sequence"] = seq + 1
                with open(STATE_FILE, "w") as f:
                    json.dump(state, f)
                return seq
        except Exception:
            pass

    # Initialize state file
    try:
        # Count lines once if state file doesn't exist
        count = 0
        if os.path.exists(AUDIT_FILE):
            with open(AUDIT_FILE, "r") as f:
                count = sum(1 for line in f if line.strip())

        # Save state
        with open(STATE_FILE, "w") as f:
            json.dump({"last_sequence": count + 1}, f)
        return count
    except Exception:
        return 0


def load_last_hash() -> str:
    """Public function to load and return the last hash from audit chain."""
    return _load_last_hash_from_file()


def append_audit(event: dict[str, Any]) -> dict[str, Any]:
    """Append a new audit record with cryptographic chain continuity."""
    # Load the last hash from file to maintain chain continuity across restarts
    global _last_hash
    _last_hash = _load_last_hash_from_file()

    record: dict[str, Any] = {
        "sequence"     : _get_sequence(),
        "timestamp"    : datetime.now(timezone.utc).isoformat() + "Z",
        "event"        : event,
        "previous_hash": _last_hash,
    }

    record["hash"] = _compute_hash(record)
    _last_hash     = record["hash"]

    os.makedirs("logs", exist_ok=True)
    with open(AUDIT_FILE, "a") as f:
        f.write(json.dumps(record) + "\n")

    return record


# Global state - updated by _load_last_hash_from_file on each append
_last_hash = "0" * 64

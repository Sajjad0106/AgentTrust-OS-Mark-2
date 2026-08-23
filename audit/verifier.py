import hashlib
import json
from typing import Any

AUDIT_FILE = "logs/audit_chain.jsonl"


def verify_chain() -> dict[str, Any]:
    try:
        with open(AUDIT_FILE, "r") as f:
            records = [json.loads(l) for l in f if l.strip()]
    except FileNotFoundError:
        return {"valid": True, "total": 0, "message": "No audit records yet"}

    if not records:
        return {"valid": True, "total": 0, "message": "Empty chain"}

    previous_hash = "0" * 64

    for i, record in enumerate(records):
        stored_hash  = record.get("hash")
        claimed_prev = record.get("previous_hash")

        # Verify previous hash linkage
        if claimed_prev != previous_hash:
            return {
                "valid"    : False,
                "total"    : len(records),
                "tampered_at_sequence": i,
                "message"  : f"Chain broken at sequence {i} — previous hash mismatch"
            }

        # Recompute hash to verify record integrity
        check = {k: v for k, v in record.items() if k != "hash"}
        recomputed = hashlib.sha256(
            json.dumps(check, sort_keys=True).encode()
        ).hexdigest()

        if recomputed != stored_hash:
            return {
                "valid"    : False,
                "total"    : len(records),
                "tampered_at_sequence": i,
                "message"  : f"Record tampered at sequence {i} — hash mismatch"
            }

        previous_hash = stored_hash

    return {
        "valid"  : True,
        "total"  : len(records),
        "message": f"Audit chain intact — {len(records)} records verified"
    }


def get_audit_log(limit: int = 50) -> list[dict[str, Any]]:
    try:
        with open(AUDIT_FILE, "r") as f:
            records = [json.loads(l) for l in f if l.strip()]
        return records[-limit:]
    except FileNotFoundError:
        return []
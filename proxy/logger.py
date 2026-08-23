import json
import os
from datetime import datetime, timezone
from typing import Any

LOG_FILE = "logs/decisions.json"

def log_decision(decision: dict[str, Any]) -> None:
    decision["timestamp"] = datetime.now(timezone.utc).isoformat()

    # Print to terminal with color
    color_map: dict[str, str] = {
        "HIGH": "\033[91m",    # Red
        "MEDIUM": "\033[93m",  # Yellow
        "LOW": "\033[0m"      # Green
    }

    risk_level = decision.get("risk_level")
    risk_level_str = risk_level if isinstance(risk_level, str) else ""
    color: str = color_map.get(risk_level_str, "\033[0m")

    reset = "\033[0m"
    reason = decision.get("reason") or decision.get("risk_reason", "")
    print(f"{color}[{decision['action']}] {reason} | Score: {decision.get('risk_score')}{reset}")

    # Save to file
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(decision) + "\n")
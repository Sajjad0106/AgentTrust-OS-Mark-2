"""Tests for _enrich_threat_feed — joining slim threat-correlation items with
their underlying decision records from the persistent decision store."""
import json
import os
from datetime import datetime, timezone, timedelta

from proxy import main as pm
import proxy.logger as pl


def _ts(offset_s=0.0):
    return (datetime.now(timezone.utc) + timedelta(seconds=offset_s)).isoformat()


def _write_decisions(tmp_path, rows):
    p = tmp_path / "decisions.json"
    p.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    return str(p)


def _feed_item(offset_s=0.0, agent="agent-x", tool="read_file"):
    return {"threat_level": "CRITICAL", "agent_id": agent, "tool": tool,
            "intent_gap": 5, "correlated_agents": [], "agent_threat_count": 1,
            "timestamp": _ts(offset_s)}


class TestEnrichThreatFeed:
    def test_match_attaches_decision(self, tmp_path, monkeypatch):
        dec = {"agent_id": "agent-x", "tool": "read_file", "action": "ISOLATED",
               "risk_score": 100, "risk_level": "CRITICAL",
               "risk_reason": "HONEYPOT BREACH: decoy accessed",
               "honeypot_hit": True, "parameters": {"path": "/opt/decoy.csv"},
               "mitre_technique": "T1530", "timestamp": _ts(0.006)}
        monkeypatch.setattr(pl, "LOG_FILE", _write_decisions(tmp_path, [dec]))
        feed = [_feed_item(0.0)]
        out = pm._enrich_threat_feed(feed)
        assert out is feed
        d = out[0]["decision"]
        assert d["risk_score"] == 100 and d["honeypot_hit"] is True
        assert d["risk_reason"].startswith("HONEYPOT BREACH")
        assert d["parameters"] == {"path": "/opt/decoy.csv"}
        assert out[0]["mitre_technique"] == "T1530"

    def test_no_match_leaves_item_untouched(self, tmp_path, monkeypatch):
        dec = {"agent_id": "other-agent", "tool": "read_file", "risk_score": 5,
               "risk_level": "LOW", "action": "ALLOWED", "timestamp": _ts(0)}
        monkeypatch.setattr(pl, "LOG_FILE", _write_decisions(tmp_path, [dec]))
        out = pm._enrich_threat_feed([_feed_item(0.0)])
        assert "decision" not in out[0] and "mitre_technique" not in out[0]

    def test_timestamp_mismatch_beyond_window_ignored(self, tmp_path, monkeypatch):
        dec = {"agent_id": "agent-x", "tool": "read_file", "risk_score": 100,
               "risk_level": "CRITICAL", "action": "ISOLATED",
               "timestamp": _ts(300)}  # 5 min off — too far
        monkeypatch.setattr(pl, "LOG_FILE", _write_decisions(tmp_path, [dec]))
        out = pm._enrich_threat_feed([_feed_item(0.0)])
        assert "decision" not in out[0]

    def test_closest_of_multiple_matches_wins(self, tmp_path, monkeypatch):
        far = {"agent_id": "agent-x", "tool": "read_file", "risk_score": 10,
               "risk_level": "LOW", "action": "ALLOWED", "timestamp": _ts(10)}
        near = {"agent_id": "agent-x", "tool": "read_file", "risk_score": 100,
                "risk_level": "CRITICAL", "action": "ISOLATED",
                "risk_reason": "the real one", "timestamp": _ts(1)}
        monkeypatch.setattr(pl, "LOG_FILE", _write_decisions(tmp_path, [far, near]))
        out = pm._enrich_threat_feed([_feed_item(0.0)])
        assert out[0]["decision"]["risk_score"] == 100

    def test_missing_file_never_breaks(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pl, "LOG_FILE", str(tmp_path / "nope.json"))
        feed = [_feed_item()]
        assert pm._enrich_threat_feed(feed) == feed

    def test_corrupt_file_never_breaks(self, tmp_path, monkeypatch):
        p = tmp_path / "decisions.json"
        p.write_text('{"agent_id": "agent-x", "tool": "read_file" \n NOT JSON\n')
        monkeypatch.setattr(pl, "LOG_FILE", str(p))
        feed = [_feed_item()]
        out = pm._enrich_threat_feed(feed)
        assert out[0].get("decision") is None  # valid line had no timestamp → no match, no crash

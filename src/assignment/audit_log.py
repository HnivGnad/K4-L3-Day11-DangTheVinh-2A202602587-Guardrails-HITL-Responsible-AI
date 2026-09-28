"""
Assignment 11 — Audit Log.

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
import time


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, dict] = {}

    @staticmethod
    def _key(user_id: str, request_id: str | None) -> str:
        return request_id or user_id

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Store input and start time, keyed by request ID (or user ID)."""
        key = self._key(user_id, request_id)
        self._open[key] = {
            "request_id": request_id or key,
            "user_id": user_id,
            "input": text,
            "started_at": utc_now_iso(),
            "started_perf": time.perf_counter(),
        }
        return key

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Finish an interaction and append a forensics-friendly log row."""
        key = self._key(user_id, request_id)
        started = self._open.pop(key, None)
        finished_perf = time.perf_counter()
        latency_ms = 0.0
        if started is not None:
            latency_ms = max(
                0.0, (finished_perf - started["started_perf"]) * 1000
            )

        row = {
            "request_id": request_id or key,
            "user_id": user_id,
            "input": started["input"] if started else None,
            "output": text,
            "blocked": bool(blocked),
            "layer": layer,
            "started_at": started["started_at"] if started else None,
            "completed_at": utc_now_iso(),
            "latency_ms": round(latency_ms, 3),
        }
        self.logs.append(row)
        return row

    def export_json(self, filepath: str | None = None):
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        path = Path(filepath or default_audit_log_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.logs, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return path


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

"""Posture: actionable conditions for the attention center, and a timeline of state changes. In memory only."""

from __future__ import annotations

import collections
import threading
import time
from typing import Any

SEVERITY = {"critical": 0, "warning": 1, "info": 2}


class PostureMonitor:
    def __init__(self, keep: int = 200) -> None:
        self.items: dict[str, dict[str, Any]] = {}
        self.timeline: collections.deque[dict[str, Any]] = collections.deque(maxlen=keep)
        self.state: str | None = None
        self.evaluated_at: float | None = None
        self._lock = threading.Lock()

    def update(self, conditions: list[dict[str, Any]]) -> None:
        now = round(time.time(), 3)
        with self._lock:
            current = set()
            for c in conditions:
                current.add(c["id"])
                prev = self.items.get(c["id"])
                self.items[c["id"]] = {**c, "first_seen": prev["first_seen"] if prev else now, "last_seen": now}
            for gone in [i for i in self.items if i not in current]:
                del self.items[gone]
            crit = [c for c in self.items.values() if c["severity"] == "critical"]
            warn = [c for c in self.items.values() if c["severity"] == "warning"]
            state = "critical" if crit else "degraded" if warn else "healthy"
            if state != self.state:
                top = crit[0] if crit else warn[0] if warn else None
                self.timeline.append(
                    {"ts": now, "state": state, "reason": top["title"] if top else "All checks healthy"}
                )
                self.state = state
            self.evaluated_at = now

    def view(self) -> dict[str, Any]:
        with self._lock:
            items = sorted(self.items.values(), key=lambda c: (SEVERITY[c["severity"]], -c["last_seen"]))
            return {
                "posture": self.state or "healthy",
                "evaluated_at": self.evaluated_at,
                "items": items,
                "timeline": list(reversed(self.timeline)),
            }

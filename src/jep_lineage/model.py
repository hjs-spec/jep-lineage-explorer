"""Data model for replayable JEP delegation lineage."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def parse_time(value: Any) -> datetime | None:
    """Parse common JEP timestamp values into timezone-aware datetimes."""
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    if isinstance(value, str):
        text = value.strip()
        if text.endswith("Z"):
            text = f"{text[:-1]}+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return None


def normalize_scopes(value: Any) -> frozenset[str]:
    """Normalize scope encodings into a deterministic string set."""
    if value in (None, ""):
        return frozenset()
    if isinstance(value, str):
        return frozenset(part.strip() for part in value.split(",") if part.strip())
    if isinstance(value, dict):
        return frozenset(str(key) for key, enabled in value.items() if enabled)
    try:
        return frozenset(str(item) for item in value)
    except TypeError:
        return frozenset({str(value)})


@dataclass(frozen=True)
class ReplayEvent:
    """A normalized event loaded from a JSONL replay archive."""

    line_no: int
    event_type: str
    timestamp: datetime | None
    replay_id: str
    actor: str | None
    payload: dict[str, Any]

    @classmethod
    def from_json(cls, line_no: int, payload: dict[str, Any]) -> "ReplayEvent":
        event_type = str(
            payload.get("event_type")
            or payload.get("type")
            or payload.get("action")
            or payload.get("kind")
            or "unknown"
        )
        replay_id = str(payload.get("replay_id") or payload.get("run_id") or payload.get("session_id") or "default")
        actor = payload.get("actor") or payload.get("agent") or payload.get("agent_id")
        timestamp = parse_time(payload.get("timestamp") or payload.get("time") or payload.get("ts"))
        return cls(line_no=line_no, event_type=event_type, timestamp=timestamp, replay_id=replay_id, actor=str(actor) if actor else None, payload=payload)


@dataclass
class Delegation:
    """A delegation edge in the authority propagation graph."""

    delegation_id: str
    parent_id: str | None
    replay_id: str
    delegator: str
    delegatee: str
    scopes: frozenset[str]
    issued_at: datetime | None
    expires_at: datetime | None
    source_line: int
    source_event: ReplayEvent
    revoked_at: datetime | None = None
    uses: list[ReplayEvent] = field(default_factory=list)
    children: list[str] = field(default_factory=list)

    @property
    def is_root(self) -> bool:
        return self.parent_id is None

    def active_at(self, moment: datetime | None) -> bool:
        if moment is None:
            return True
        if self.issued_at and moment < self.issued_at:
            return False
        if self.revoked_at and moment >= self.revoked_at:
            return False
        if self.expires_at and moment >= self.expires_at:
            return False
        return True


@dataclass(frozen=True)
class VerificationIssue:
    """A replay verification finding."""

    severity: str
    code: str
    message: str
    line_no: int | None = None
    delegation_id: str | None = None


@dataclass(frozen=True)
class TimelineEntry:
    """Authority timeline event for replay inspection."""

    timestamp: datetime | None
    line_no: int
    replay_id: str
    agent: str
    delegation_id: str
    event: str
    scopes: tuple[str, ...]
    detail: str

"""Replay lineage engine and delegation verification."""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

from .model import (
    Delegation,
    ReplayEvent,
    TimelineEntry,
    VerificationIssue,
    normalize_scopes,
    parse_time,
)

DELEGATION_CREATE_TYPES = {
    "delegation_created",
    "delegation.create",
    "delegate",
    "delegated",
    "authority_delegated",
    "authority.grant",
    "authority_granted",
}
DELEGATION_USE_TYPES = {
    "authority_used",
    "authority.use",
    "delegation_used",
    "tool_call",
    "agent_action",
}
DELEGATION_REVOKE_TYPES = {
    "delegation_revoked",
    "authority_revoked",
    "revoke",
    "authority.revoke",
}


def inspect_archive(path: str | Path) -> "LineageReport":
    """Load a JSONL archive and produce a replayable lineage report."""
    engine = LineageEngine.from_jsonl(path)
    return engine.build_report()


class LineageEngine:
    """Builds authority propagation, replay ancestry, and verification artifacts."""

    def __init__(self, events: Iterable[ReplayEvent]):
        self.events = sorted(
            list(events),
            key=lambda event: (event.timestamp is None, event.timestamp, event.line_no),
        )
        self.delegations: dict[tuple[str, str], Delegation] = {}
        self.orphans: list[Delegation] = []
        self.issues: list[VerificationIssue] = []
        self.timeline: list[TimelineEntry] = []
        self.lineage_edges: list[tuple[str, str, str]] = []

    @classmethod
    def from_jsonl(cls, path: str | Path) -> "LineageEngine":
        events: list[ReplayEvent] = []
        archive_path = Path(path)
        with archive_path.open("r", encoding="utf-8") as handle:
            for line_no, line in enumerate(handle, start=1):
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    payload = json.loads(stripped)
                except json.JSONDecodeError as exc:
                    events.append(
                        ReplayEvent(
                            line_no=line_no,
                            event_type="invalid_json",
                            timestamp=None,
                            replay_id="default",
                            actor=None,
                            payload={"error": str(exc), "raw": stripped},
                        )
                    )
                    continue
                if not isinstance(payload, dict):
                    payload = {"value": payload}
                events.append(ReplayEvent.from_json(line_no, payload))
        return cls(events)

    def build_report(self) -> "LineageReport":
        self.delegations.clear()
        self.orphans.clear()
        self.issues.clear()
        self.timeline.clear()
        self.lineage_edges.clear()
        self._replay()
        return LineageReport(
            delegations=self.delegations,
            issues=self.issues,
            timeline=sorted(
                self.timeline,
                key=lambda item: (item.timestamp is None, item.timestamp, item.line_no),
            ),
            lineage_edges=self.lineage_edges,
            replay_diffs=self._diff_replays(),
        )

    def _replay(self) -> None:
        for event in self.events:
            event_type = event.event_type.lower()
            if event_type == "invalid_json":
                self.issues.append(
                    VerificationIssue(
                        "error", "invalid-json", event.payload["error"], event.line_no
                    )
                )
            elif event_type in DELEGATION_CREATE_TYPES:
                self._record_delegation(event)
            elif event_type in DELEGATION_USE_TYPES:
                self._record_use(event)
            elif event_type in DELEGATION_REVOKE_TYPES:
                self._record_revocation(event)
            else:
                self._record_ancestry(event)
        self._verify_parent_links()

    def _record_delegation(self, event: ReplayEvent) -> None:
        payload = event.payload
        delegation_id = _first(
            payload, "delegation_id", "id", "edge_id", "authority_id"
        )
        if not delegation_id:
            delegation_id = f"line-{event.line_no}"
            self.issues.append(
                VerificationIssue(
                    "warning",
                    "missing-delegation-id",
                    "delegation event had no id; generated a line-based id",
                    event.line_no,
                    delegation_id,
                )
            )
        delegation_id = str(delegation_id)
        parent_id = _optional_str(
            _first(
                payload,
                "parent_delegation_id",
                "parent_id",
                "ancestor_id",
                "delegated_from",
            )
        )
        delegator = (
            _optional_str(
                _first(payload, "from_agent", "delegator", "issuer", "grantor", "actor")
            )
            or "<unknown-delegator>"
        )
        delegatee = (
            _optional_str(
                _first(payload, "to_agent", "delegatee", "subject", "grantee", "agent")
            )
            or "<unknown-delegatee>"
        )
        scopes = normalize_scopes(
            _first(payload, "scopes", "scope", "authority", "permissions")
        )
        expires_at = parse_time(
            _first(payload, "expires_at", "expiry", "expiration", "not_after")
        )

        key = (event.replay_id, delegation_id)
        if key in self.delegations:
            self.issues.append(
                VerificationIssue(
                    "error",
                    "duplicate-delegation",
                    "delegation id is defined more than once",
                    event.line_no,
                    delegation_id,
                )
            )
            return

        delegation = Delegation(
            delegation_id=delegation_id,
            parent_id=parent_id,
            replay_id=event.replay_id,
            delegator=delegator,
            delegatee=delegatee,
            scopes=scopes,
            issued_at=event.timestamp,
            expires_at=expires_at,
            source_line=event.line_no,
            source_event=event,
        )
        self.delegations[key] = delegation
        if parent_id and (event.replay_id, parent_id) in self.delegations:
            self.delegations[(event.replay_id, parent_id)].children.append(key)
        self.lineage_edges.append((delegator, delegatee, delegation_id))
        self.timeline.append(
            TimelineEntry(
                event.timestamp,
                event.line_no,
                event.replay_id,
                delegatee,
                delegation_id,
                "granted",
                tuple(sorted(scopes)),
                f"{delegator} delegated to {delegatee}",
            )
        )

        self._verify_child_delegation(delegation)

    def _record_use(self, event: ReplayEvent) -> None:
        delegation_id = _optional_str(
            _first(
                event.payload,
                "delegation_id",
                "authority_id",
                "using_delegation",
                "capability_id",
            )
        )
        if not delegation_id:
            self.issues.append(
                VerificationIssue(
                    "warning",
                    "unbound-authority-use",
                    "authority use does not reference a delegation id",
                    event.line_no,
                )
            )
            self._record_ancestry(event)
            return
        delegation = self.delegations.get((event.replay_id, delegation_id))
        if not delegation:
            self.issues.append(
                VerificationIssue(
                    "error",
                    "unknown-delegation-use",
                    "authority use references an unknown delegation",
                    event.line_no,
                    delegation_id,
                )
            )
            return
        requested_scopes = (
            normalize_scopes(
                _first(event.payload, "scopes", "scope", "authority", "permissions")
            )
            or delegation.scopes
        )
        if not requested_scopes.issubset(delegation.scopes):
            self.issues.append(
                VerificationIssue(
                    "error",
                    "scope-escalation",
                    f"requested scopes {sorted(requested_scopes - delegation.scopes)} exceed delegation",
                    event.line_no,
                    delegation_id,
                )
            )
        if not delegation.active_at(event.timestamp):
            self.issues.append(
                VerificationIssue(
                    "error",
                    "inactive-delegation-use",
                    "delegation was expired, revoked, or not yet active when used",
                    event.line_no,
                    delegation_id,
                )
            )
        actor = event.actor or _optional_str(_first(event.payload, "agent", "agent_id"))
        if actor != delegation.delegatee:
            self.issues.append(
                VerificationIssue(
                    "error",
                    "authority-actor-mismatch",
                    "authority user must match the delegatee",
                    event.line_no,
                    delegation_id,
                )
            )
        if event.timestamp is None:
            self.issues.append(
                VerificationIssue(
                    "error",
                    "missing-use-time",
                    "authority use requires a timestamp",
                    event.line_no,
                    delegation_id,
                )
            )
        ancestor, visited = delegation, set()
        while ancestor.parent_id:
            key = (ancestor.replay_id, ancestor.parent_id)
            if key in visited or key not in self.delegations:
                self.issues.append(
                    VerificationIssue(
                        "error",
                        "invalid-use-lineage",
                        "authority ancestry is missing or cyclic",
                        event.line_no,
                        delegation_id,
                    )
                )
                break
            visited.add(key)
            ancestor = self.delegations[key]
            if not ancestor.active_at(event.timestamp):
                self.issues.append(
                    VerificationIssue(
                        "error",
                        "inactive-ancestor-use",
                        "an ancestor was inactive at use time",
                        event.line_no,
                        delegation_id,
                    )
                )
                break
        delegation.uses.append(event)
        actor = actor or "<unknown-actor>"
        self.timeline.append(
            TimelineEntry(
                event.timestamp,
                event.line_no,
                event.replay_id,
                actor,
                delegation_id,
                "used",
                tuple(sorted(requested_scopes)),
                f"{actor} used authority",
            )
        )
        self._record_ancestry(event)

    def _record_revocation(self, event: ReplayEvent) -> None:
        delegation_id = _optional_str(
            _first(event.payload, "delegation_id", "authority_id", "id")
        )
        if (
            not delegation_id
            or (event.replay_id, delegation_id) not in self.delegations
        ):
            self.issues.append(
                VerificationIssue(
                    "error",
                    "unknown-delegation-revoke",
                    "revocation references an unknown delegation",
                    event.line_no,
                    delegation_id,
                )
            )
            return
        delegation = self.delegations[(event.replay_id, delegation_id)]
        if event.timestamp is None:
            self.issues.append(
                VerificationIssue(
                    "error",
                    "missing-revocation-time",
                    "revocation requires a timestamp",
                    event.line_no,
                    delegation_id,
                )
            )
            return
        if delegation.revoked_at is None or event.timestamp < delegation.revoked_at:
            delegation.revoked_at = event.timestamp
        self.timeline.append(
            TimelineEntry(
                event.timestamp,
                event.line_no,
                event.replay_id,
                delegation.delegatee,
                delegation_id,
                "revoked",
                tuple(sorted(delegation.scopes)),
                "delegation revoked",
            )
        )

    def _record_ancestry(self, event: ReplayEvent) -> None:
        parent = _optional_str(
            _first(
                event.payload,
                "parent_event_id",
                "parent_id",
                "caused_by",
                "in_reply_to",
            )
        )
        event_id = (
            _optional_str(_first(event.payload, "event_id", "id", "message_id"))
            or f"line-{event.line_no}"
        )
        if parent:
            self.lineage_edges.append((parent, event_id, event.event_type))

    def _verify_child_delegation(self, delegation: Delegation) -> None:
        if not delegation.parent_id:
            return
        parent = self.delegations.get((delegation.replay_id, delegation.parent_id))
        if not parent:
            return
        if delegation.delegator != parent.delegatee:
            self.issues.append(
                VerificationIssue(
                    "error",
                    "delegator-chain-break",
                    "child delegation delegator is not the parent delegatee",
                    delegation.source_line,
                    delegation.delegation_id,
                )
            )
        if not delegation.scopes.issubset(parent.scopes):
            self.issues.append(
                VerificationIssue(
                    "error",
                    "scope-attenuation-violation",
                    f"child scopes {sorted(delegation.scopes - parent.scopes)} exceed parent scopes",
                    delegation.source_line,
                    delegation.delegation_id,
                )
            )
        if delegation.issued_at and not parent.active_at(delegation.issued_at):
            self.issues.append(
                VerificationIssue(
                    "error",
                    "inactive-parent-delegation",
                    "parent delegation was not active when child was issued",
                    delegation.source_line,
                    delegation.delegation_id,
                )
            )
        if parent.expires_at and (
            not delegation.expires_at or delegation.expires_at > parent.expires_at
        ):
            self.issues.append(
                VerificationIssue(
                    "error",
                    "expiry-extension",
                    "child delegation expires after parent delegation",
                    delegation.source_line,
                    delegation.delegation_id,
                )
            )

    def _verify_parent_links(self) -> None:
        for key, delegation in self.delegations.items():
            parent_key = (delegation.replay_id, delegation.parent_id)
            if delegation.parent_id and parent_key not in self.delegations:
                self.issues.append(
                    VerificationIssue(
                        "error",
                        "missing-parent-delegation",
                        "parent delegation id was not present in this replay",
                        delegation.source_line,
                        delegation.delegation_id,
                    )
                )
                self.orphans.append(delegation)
                continue
            if (
                delegation.parent_id
                and key not in self.delegations[parent_key].children
            ):
                # A later declaration cannot authorize an earlier delegation/use.
                self.issues.append(
                    VerificationIssue(
                        "error",
                        "forward-parent-delegation",
                        "parent was not observed when delegation was issued",
                        delegation.source_line,
                        delegation.delegation_id,
                    )
                )
                self.delegations[parent_key].children.append(key)
                self._verify_child_delegation(delegation)
            ancestor, visited = delegation, {key}
            while ancestor.parent_id:
                next_key = (ancestor.replay_id, ancestor.parent_id)
                if next_key in visited:
                    self.issues.append(
                        VerificationIssue(
                            "error",
                            "delegation-cycle",
                            "delegation ancestry contains a cycle",
                            delegation.source_line,
                            delegation.delegation_id,
                        )
                    )
                    break
                visited.add(next_key)
                ancestor = self.delegations.get(next_key)
                if ancestor is None:
                    break

    def _diff_replays(self) -> list[dict[str, Any]]:
        by_replay: dict[str, set[tuple[str, str, tuple[str, ...]]]] = defaultdict(set)
        for delegation in self.delegations.values():
            by_replay[delegation.replay_id].add(
                (
                    delegation.delegator,
                    delegation.delegatee,
                    tuple(sorted(delegation.scopes)),
                )
            )
        replay_ids = sorted(by_replay)
        diffs: list[dict[str, Any]] = []
        for previous, current in zip(replay_ids, replay_ids[1:]):
            before = by_replay[previous]
            after = by_replay[current]
            diffs.append(
                {
                    "from": previous,
                    "to": current,
                    "added": sorted(after - before),
                    "removed": sorted(before - after),
                    "unchanged": len(before & after),
                }
            )
        return diffs


class LineageReport:
    """Computed artifacts emitted by the CLI."""

    def __init__(
        self,
        delegations: dict[tuple[str, str], Delegation],
        issues: list[VerificationIssue],
        timeline: list[TimelineEntry],
        lineage_edges: list[tuple[str, str, str]],
        replay_diffs: list[dict[str, Any]],
    ):
        self.delegations = delegations
        self.issues = issues
        self.timeline = timeline
        self.lineage_edges = lineage_edges
        self.replay_diffs = replay_diffs

    def to_dict(self) -> dict[str, Any]:
        return {
            "delegation_tree": [
                self._delegation_to_dict(delegation) for delegation in self.roots()
            ],
            "replay_lineage_graph": [
                {"from": source, "to": target, "label": label}
                for source, target, label in self.lineage_edges
            ],
            "authority_timeline": [
                self._timeline_to_dict(item) for item in self.timeline
            ],
            "verification": [issue.__dict__ for issue in self.issues],
            "lineage_diff": self.replay_diffs,
        }

    def roots(self) -> list[Delegation]:
        roots = [
            d
            for d in self.delegations.values()
            if not d.parent_id or (d.replay_id, d.parent_id) not in self.delegations
        ]
        reached = set()

        def visit(d):
            key = (d.replay_id, d.delegation_id)
            if key in reached:
                return
            reached.add(key)
            for child in d.children:
                visit(self.delegations[child])

        for root in roots:
            visit(root)
        for key, d in self.delegations.items():
            if key not in reached:
                roots.append(d)
                visit(d)
        return sorted(roots, key=lambda item: item.source_line)

    def _delegation_to_dict(
        self, delegation: Delegation, visited=None
    ) -> dict[str, Any]:
        visited = set() if visited is None else set(visited)
        key = (delegation.replay_id, delegation.delegation_id)
        if key in visited:
            return {
                "id": delegation.delegation_id,
                "replay_id": delegation.replay_id,
                "cycle": True,
                "children": [],
            }
        visited.add(key)
        return {
            "id": delegation.delegation_id,
            "replay_id": delegation.replay_id,
            "delegator": delegation.delegator,
            "delegatee": delegation.delegatee,
            "scopes": sorted(delegation.scopes),
            "issued_at": _format_time(delegation.issued_at),
            "expires_at": _format_time(delegation.expires_at),
            "revoked_at": _format_time(delegation.revoked_at),
            "uses": [event.line_no for event in delegation.uses],
            "children": [
                self._delegation_to_dict(self.delegations[child_id], visited)
                for child_id in sorted(
                    delegation.children,
                    key=lambda child: self.delegations[child].source_line,
                )
            ],
        }

    @staticmethod
    def _timeline_to_dict(item: TimelineEntry) -> dict[str, Any]:
        return {
            "timestamp": _format_time(item.timestamp),
            "line": item.line_no,
            "replay_id": item.replay_id,
            "agent": item.agent,
            "delegation_id": item.delegation_id,
            "event": item.event,
            "scopes": list(item.scopes),
            "detail": item.detail,
        }


def _first(payload: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in payload:
            return payload[key]
    return None


def _optional_str(value: Any) -> str | None:
    if value in (None, ""):
        return None
    return str(value)


def _format_time(value: Any) -> str | None:
    return value.isoformat() if value else None

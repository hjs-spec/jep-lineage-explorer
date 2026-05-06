import json

from jep_lineage.cli import main, render_text
from jep_lineage.engine import inspect_archive


def write_archive(tmp_path, rows):
    path = tmp_path / "archive.jsonl"
    path.write_text("\n".join(json.dumps(row) for row in rows), encoding="utf-8")
    return path


def test_nested_delegation_and_timeline(tmp_path):
    archive = write_archive(
        tmp_path,
        [
            {
                "event_type": "delegation_created",
                "timestamp": "2026-01-01T00:00:00Z",
                "replay_id": "r1",
                "delegation_id": "root",
                "from_agent": "owner",
                "to_agent": "planner",
                "scopes": ["read", "write"],
                "expires_at": "2026-01-02T00:00:00Z",
            },
            {
                "event_type": "delegation_created",
                "timestamp": "2026-01-01T01:00:00Z",
                "replay_id": "r1",
                "delegation_id": "child",
                "parent_delegation_id": "root",
                "from_agent": "planner",
                "to_agent": "worker",
                "scopes": ["read"],
                "expires_at": "2026-01-01T12:00:00Z",
            },
            {
                "event_type": "authority_used",
                "timestamp": "2026-01-01T02:00:00Z",
                "replay_id": "r1",
                "agent": "worker",
                "delegation_id": "child",
                "scopes": ["read"],
            },
        ],
    )

    report = inspect_archive(archive)

    assert not [issue for issue in report.issues if issue.severity == "error"]
    assert report.to_dict()["delegation_tree"][0]["children"][0]["id"] == "child"
    assert [entry.event for entry in report.timeline] == ["granted", "granted", "used"]
    assert "owner -> planner" in render_text(report)


def test_verifies_scope_attenuation_and_expiry(tmp_path):
    archive = write_archive(
        tmp_path,
        [
            {
                "type": "delegate",
                "timestamp": "2026-01-01T00:00:00Z",
                "delegation_id": "root",
                "from_agent": "owner",
                "to_agent": "planner",
                "scopes": ["read"],
                "expires_at": "2026-01-01T01:00:00Z",
            },
            {
                "type": "delegate",
                "timestamp": "2026-01-01T00:10:00Z",
                "delegation_id": "child",
                "parent_delegation_id": "root",
                "from_agent": "planner",
                "to_agent": "worker",
                "scopes": ["read", "write"],
                "expires_at": "2026-01-01T02:00:00Z",
            },
            {
                "type": "authority_used",
                "timestamp": "2026-01-01T03:00:00Z",
                "delegation_id": "root",
                "scopes": ["read"],
            },
        ],
    )

    report = inspect_archive(archive)
    codes = {issue.code for issue in report.issues}

    assert "scope-attenuation-violation" in codes
    assert "expiry-extension" in codes
    assert "inactive-delegation-use" in codes


def test_cli_strict_returns_nonzero_on_verification_errors(tmp_path, capsys):
    archive = write_archive(
        tmp_path,
        [
            {
                "type": "authority_used",
                "timestamp": "2026-01-01T00:00:00Z",
                "delegation_id": "missing",
            }
        ],
    )

    assert main(["inspect", str(archive), "--strict"]) == 2
    assert "unknown-delegation-use" in capsys.readouterr().out

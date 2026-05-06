"""Command line interface for the Delegation Lineage Explorer."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .engine import LineageReport, inspect_archive


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="jep-lineage", description="Explore and verify delegation lineage in JEP replay archives.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    inspect = subparsers.add_parser("inspect", help="inspect a JEP replay archive JSONL file")
    inspect.add_argument("archive", type=Path, help="path to a JEP replay archive in JSON Lines format")
    inspect.add_argument("--format", choices=("text", "json"), default="text", help="output format")
    inspect.add_argument("--strict", action="store_true", help="exit non-zero when verification errors are found")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "inspect":
        report = inspect_archive(args.archive)
        if args.format == "json":
            print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
        else:
            print(render_text(report))
        if args.strict and any(issue.severity == "error" for issue in report.issues):
            return 2
        return 0
    parser.error(f"unknown command: {args.command}")
    return 2


def render_text(report: LineageReport) -> str:
    lines: list[str] = []
    lines.append("Delegation Lineage Explorer")
    lines.append("===========================")
    lines.append("")
    lines.append("Delegation Tree")
    lines.append("---------------")
    roots = report.roots()
    if not roots:
        lines.append("(no delegations discovered)")
    for root in roots:
        _render_delegation(report, root.delegation_id, lines, depth=0)

    lines.append("")
    lines.append("Replay Lineage Graph")
    lines.append("--------------------")
    if report.lineage_edges:
        for source, target, label in report.lineage_edges:
            lines.append(f"- {source} -> {target} [{label}]")
    else:
        lines.append("(no replay ancestry edges discovered)")

    lines.append("")
    lines.append("Authority Timeline")
    lines.append("------------------")
    if report.timeline:
        for item in report.timeline:
            timestamp = item.timestamp.isoformat() if item.timestamp else "<no-time>"
            scopes = ",".join(item.scopes) if item.scopes else "<no-scope>"
            lines.append(f"- {timestamp} line {item.line_no}: {item.event} {item.delegation_id} agent={item.agent} scopes={scopes} ({item.detail})")
    else:
        lines.append("(no authority events discovered)")

    lines.append("")
    lines.append("Delegation Verification")
    lines.append("-----------------------")
    if report.issues:
        for issue in report.issues:
            location = f"line {issue.line_no}" if issue.line_no else "archive"
            delegation = f" delegation={issue.delegation_id}" if issue.delegation_id else ""
            lines.append(f"- {issue.severity.upper()} {issue.code} at {location}{delegation}: {issue.message}")
    else:
        lines.append("OK: replay delegation semantics verified")

    lines.append("")
    lines.append("Lineage Diff")
    lines.append("------------")
    if report.replay_diffs:
        for diff in report.replay_diffs:
            lines.append(f"- {diff['from']} -> {diff['to']}: +{len(diff['added'])} -{len(diff['removed'])} unchanged={diff['unchanged']}")
    else:
        lines.append("(single replay or no comparable replay ids)")
    return "\n".join(lines)


def _render_delegation(report: LineageReport, delegation_id: str, lines: list[str], depth: int) -> None:
    delegation = report.delegations[delegation_id]
    indent = "  " * depth
    scopes = ",".join(sorted(delegation.scopes)) if delegation.scopes else "<no-scope>"
    expires = f", expires={delegation.expires_at.isoformat()}" if delegation.expires_at else ""
    revoked = f", revoked={delegation.revoked_at.isoformat()}" if delegation.revoked_at else ""
    lines.append(f"{indent}- {delegation.delegation_id}: {delegation.delegator} -> {delegation.delegatee} scopes={scopes}{expires}{revoked}")
    for child_id in sorted(delegation.children, key=lambda child: report.delegations[child].source_line):
        _render_delegation(report, child_id, lines, depth + 1)


if __name__ == "__main__":
    sys.exit(main())

# jep-lineage-explorer

Explore replayable delegation lineage and authority propagation across AI agents and tools.

`jep-lineage-explorer` turns a JEP replay archive (`.jsonl`) into inspectable authority artifacts:

- delegation tree for authority propagation and nested delegation
- replay lineage graph for agent-to-agent responsibility chains
- authority timeline for grants, uses, expirations, and revocations
- replay lineage engine with verification for scope attenuation and expiring delegations
- lineage diff between replay ids inside the same archive
- replay ancestry inspection through parent/causal event links

## Install for local development

```bash
python -m pip install -e .
```

## CLI

```bash
jep-lineage inspect archive.jsonl
```

Useful options:

```bash
jep-lineage inspect archive.jsonl --format json
jep-lineage inspect archive.jsonl --strict
```

`--strict` exits with status `2` when verification errors are found.

## Supported JSONL event shapes

The reader accepts flexible field names so existing JEP archives can be replayed without a rigid schema.

Delegation creation event types include `delegation_created`, `delegate`, `authority_delegated`, and `authority_granted`.

Common delegation fields:

```json
{
  "event_type": "delegation_created",
  "timestamp": "2026-01-01T00:00:00Z",
  "replay_id": "run-a",
  "delegation_id": "d-root",
  "parent_delegation_id": null,
  "from_agent": "orchestrator",
  "to_agent": "planner",
  "scopes": ["read", "write"],
  "expires_at": "2026-01-01T01:00:00Z"
}
```

Authority use event types include `authority_used`, `delegation_used`, `tool_call`, and `agent_action` when they reference a `delegation_id`.

Revocation event types include `delegation_revoked`, `authority_revoked`, and `revoke`.

Replay ancestry edges are inferred from `parent_event_id`, `parent_id`, `caused_by`, or `in_reply_to` fields.

## Verification

The inspector validates that:

- child scopes are a subset of parent scopes (scope attenuation)
- child delegations do not extend parent expiration
- parent delegations are active when children are issued
- authority uses reference known, active delegations
- requested use scopes do not exceed the referenced delegation
- delegation identifiers are unique and parent links are resolvable

## Example

```jsonl
{"event_type":"delegation_created","timestamp":"2026-01-01T00:00:00Z","replay_id":"r1","delegation_id":"root","from_agent":"owner","to_agent":"planner","scopes":["read","write"],"expires_at":"2026-01-02T00:00:00Z"}
{"event_type":"delegation_created","timestamp":"2026-01-01T01:00:00Z","replay_id":"r1","delegation_id":"child","parent_delegation_id":"root","from_agent":"planner","to_agent":"worker","scopes":["read"],"expires_at":"2026-01-01T12:00:00Z"}
{"event_type":"authority_used","timestamp":"2026-01-01T02:00:00Z","replay_id":"r1","agent":"worker","delegation_id":"child","scopes":["read"]}
```

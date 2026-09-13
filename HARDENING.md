# Authority lineage checks

Authority use must identify the delegatee and provide a time. It is rejected when any ancestor is expired or revoked. Child issuer discontinuity is an error. Grants are scoped by replay_id, so identical identifiers in different replays neither overwrite nor authorize one another.

Forward or missing parents and delegation cycles produce explicit findings; cyclic archives can still be rendered safely. Building a report repeatedly is idempotent. Public report.delegations keys and Delegation.children entries are now (replay_id, delegation_id) tuples; JSON output retains separate replay_id and id fields.

These checks evaluate the declared local delegation profile. They neither verify cryptographic signatures nor infer real-world authority from an unknown root.

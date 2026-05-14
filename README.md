# alani-policy

Declarative capability, access-control, sandbox, audit, and resource policies separated from enforcement mechanisms.

| Field | Value |
|---|---|
| Tier | MVK required |
| Owner | Security and policy teams |
| Aliases | None |
| Architectural dependencies | `alani-abi`, `alani-protocol`, `alani-config` |

## Quick start

```bash
cargo fmt -- --check
cargo test --all-features
cargo test --no-default-features
```

## Public API Surface

- `capability`: capability taxonomy, principal metadata, scoped grants, attenuation, revocation, and fixed-capacity grant tables.
- `rules`: declarative policy rules, resource and operation vocabularies, default-deny rule selection, and budget limits.
- `evaluator`: static policy engine contracts, policy decisions, request validation, redaction checks, and audit-facing decision records.
- `sandbox`: agent/service sandbox profiles, resource-class gates, capability checks, budget checks, and audit-on-violation metadata.

The crate remains dependency-free while sibling repositories stabilize. Keep public API changes synchronized with `docs/repositories/alani-policy.md`, Doc 15, Doc 16, Doc 42, and Doc 43.

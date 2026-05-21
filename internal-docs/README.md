# Internal Docs

This tree preserves implementation plans, runtime iteration specs,
product-internal notes, protocol/formal corpora, prompt scratchpads, generated
proof outputs, and other non-consumer-facing material that previously lived
under `docs/`.

The forward-facing `docs/` tree should stay focused on canonical architecture,
decisions, conformance contracts, security, roadmap context, templates, and
consumer-readable references. Internal docs can inform implementation, but they
do not supersede `docs/architecture/`.

Internal files must not declare `Status: canonical...` or `Canonical owner:`.
Use `Status: internal...` plus an `Authority:` line that points back to
`docs/architecture/` and accepted ADRs. This keeps private execution context
useful without creating a second source of truth.

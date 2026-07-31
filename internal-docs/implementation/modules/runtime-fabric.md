---
module_id: runtime-fabric
module_class: method
title: One governed execution fabric
sequencer: program/sequence.v1.json
status_owner: work-item records
stage_ids: [M1, M2, M3, M4, M6, M7, M9, M10]
legacy_id: WP-RUNTIME
canon_owners:
  - docs/architecture/components/daemon-runtime/doctrine.md
  - docs/architecture/components/daemon-runtime/api.md
  - docs/architecture/components/daemon-runtime/events-receipts-delivery-bundles.md
  - docs/architecture/components/agentgres/doctrine.md
  - docs/architecture/components/agentgres/api-object-model.md
  - docs/architecture/components/wallet-network/api-authority-scopes.md
  - docs/architecture/components/connectors-tools/doctrine.md
  - docs/architecture/components/connectors-tools/contracts.md
  - docs/architecture/components/hypervisor/core-clients-surfaces.md
  - docs/architecture/foundations/invariants.md
  - docs/conformance/hypervisor-core/effect-execution.md
  - docs/conformance/hypervisor-core/intent-resolution.md
  - docs/decisions/0002-execution-authority-and-client-boundaries.md
  - docs/decisions/0010-verifiable-bounded-agency-and-execution-boundary-alignment.md
  - docs/decisions/0013-hypervisor-core-clients-surfaces-and-adapters.md
---

# One Governed Execution Fabric

## What this module owns

The reusable method for converging every externally reachable call path onto one
governed execution fabric: one classified route inventory, one admission and
final-invoker path, one accepted-truth and receipt spine, one protocol shape,
everything else demoted to a projection or protocol client. It owns the method
only — never ordering work, never carrying status, never a sequencer; order and
exit gates live in [`sequence.v1.json`](../program/sequence.v1.json), durable
status in the owning work-item record, doctrine with the canon owners.

## Pulled by

`M1`, `M2`, `M3`, `M4`, `M6`, `M7`, `M9`, `M10` — per
`modules[].applies_to_stages` in [`sequence.v1.json`](../program/sequence.v1.json).

## Canon owners

| Canon owner | What it governs here |
| --- | --- |
| [`daemon-runtime/doctrine.md`](../../../docs/architecture/components/daemon-runtime/doctrine.md) | Daemon and public runtime API families; what may be a route at all; admission and execution ownership. |
| [`daemon-runtime/api.md`](../../../docs/architecture/components/daemon-runtime/api.md), [`events-receipts-delivery-bundles.md`](../../../docs/architecture/components/daemon-runtime/events-receipts-delivery-bundles.md) | Positive Rust daemon/Core API shapes, stable protocol shape, and the receipt/event/delivery-bundle spine a converged path must not duplicate. |
| [`agentgres/doctrine.md`](../../../docs/architecture/components/agentgres/doctrine.md), [`agentgres/api-object-model.md`](../../../docs/architecture/components/agentgres/api-object-model.md) | Accepted truth: operation, exact head/root, commit object shapes, replay integrity. |
| [`wallet-network/api-authority-scopes.md`](../../../docs/architecture/components/wallet-network/api-authority-scopes.md) | `AuthorityGrant` and `CapabilityLease` shapes that extracted owner cuts must re-enter. |
| [`connectors-tools/doctrine.md`](../../../docs/architecture/components/connectors-tools/doctrine.md), [`connectors-tools/contracts.md`](../../../docs/architecture/components/connectors-tools/contracts.md) | MCP gateway as an authority-scoped surface contract, not a second host-mutation path; `RuntimeToolContract` and adapter invocation contracts. |
| [`hypervisor/core-clients-surfaces.md`](../../../docs/architecture/components/hypervisor/core-clients-surfaces.md) | Route-alias and surface registration family, projected routes, surface coverage projections. |
| [`foundations/invariants.md`](../../../docs/architecture/foundations/invariants.md) | Cross-cutting runtime invariants a converged path may not break. |
| [`effect-execution.md`](../../../docs/conformance/hypervisor-core/effect-execution.md), [`intent-resolution.md`](../../../docs/conformance/hypervisor-core/intent-resolution.md) | CEC admitted-effect boundary, deterministic execution, completion evidence, terminal-state invariants; CIRC typed intent resolution upstream of admission. |
| [ADR 0002](../../../docs/decisions/0002-execution-authority-and-client-boundaries.md), [ADR 0010](../../../docs/decisions/0010-verifiable-bounded-agency-and-execution-boundary-alignment.md), [ADR 0013](../../../docs/decisions/0013-hypervisor-core-clients-surfaces-and-adapters.md) | Daemon as canonical execution endpoint; bounded-agency execution-boundary alignment; adapter-target and surface mediation for editor, harness, and application hosts. |

## Retained obligations

Ownership boundary: the current daemon, Agentgres, wallet, contract,
connector/tool, Hypervisor-surface, and applicable domain-owner canon each own
their respective runtime facts; rail ordering belongs to
[`sequence.v1.json`](../program/sequence.v1.json). No archived guide, migration
matrix, or superseded master owns current direction, even where it still carries
imperative wording.

1. **One classified route inventory.** One hashed registry classifies every
   externally reachable native and projected route, and one authoritative
   admission/final-invoker path governs equivalent native, MCP, client, and
   adapter calls. Equivalence is by reachable effect, not by transport name.
2. **Trust-based kernel membership.** Classify `RuntimeKernelService` membership
   by required trust rather than facade size: retain a method in the trusted core
   only when moving it would weaken deterministic admission, authority/capability
   enforcement, exact-effect fencing, receipt binding, replay integrity, or the
   stable invocation contract. Line count, naming, and compatibility convenience
   are inventory signals only.
3. **Extraction discipline.** Owner-specific marketplace, workspace, coding-tool,
   model-mount, provider, and projection mechanics may leave the facade only as
   complete reviewable owner cuts whose consequential paths still re-enter the
   same applicable `AuthorityGrant` or `CapabilityLease`, policy-enforcement
   point, admission boundary, final invoker, and receipt spine. Extraction may
   not create a second authority, accepted-truth, or receipt-authoring path.
4. **Positive Rust API per live route family.** Every live route family has one
   positive Rust daemon/Core API.
5. **One path, not a chain of owners.** StepModuleRouter, workload invocation,
   policy/authority inputs, Agentgres admission, receipts/roots, projection,
   replay, and stable protocol shape form one path.
6. **Everything else is a client.** Clients, SDKs, IDEs, harnesses, MCP,
   provider adapters, and apps remain projections or protocol clients.
7. **No regressions readmitted.** Command transport, deleted bridge binaries,
   JS-authored accepted truth, fixture fallback, copied receipt authority, and
   compatibility tombstones do not return.
8. **Macro granularity.** Macro cuts retire complete authority boundaries, not
   one helper at a time; validity conditions are stated once in
   [`rules.md`](../program/rules.md) §7 and are not restated here.
9. **Terminal-ownership scope.** Selected-route terminality is required at `M9`
   per [`sequence.v1.json`](../program/sequence.v1.json); every later stage
   requires the same terminal ownership for the routes it adds.

## Applying it in a work item

- Name the in-scope route families and attach a content-bound inventory entry
  (registry digest plus classification) per reachable route, native and projected
  alike; an unclassified reachable route blocks admission.
- Record each in-scope method's obligation-2 trust classification and the canon
  owner supplying its admission, authority, truth, and receipt facts.
- Bind every consequential path to its policy-enforcement point, applicable
  `AuthorityGrant`/`CapabilityLease`, final invoker, Agentgres operation and exact
  head/root, and receipt identity — as record fields, not prose.
- Carry extraction-specific negative evidence — substitution, bypass-the-facade,
  stale-authority, retry/idempotency, crash, replay — each showing denial produces
  zero final-invoker calls.
- List old authoring paths deleted or demoted in the same cut, and the
  route/final-invoker and Hypervisor-surface coverage projections regenerated once
  at the macro boundary.
- State residual nonclaims: which reachable routes remain non-terminal after the
  cut, and which effect families were simulated rather than probed.

## Terminal evidence

The current repository's full applicable conformance aggregate; the exact
method-inventory audit verifier run against current code rather than a retained
census; extraction-specific negative tests proving the single-gateway property;
and stage-specific live probes for every selected effect family.

## Canon gaps

- **Hashed route registry has no canon owner.**
  [`core-clients-surfaces.md`](../../../docs/architecture/components/hypervisor/core-clients-surfaces.md)
  owns route-alias/surface registration and treats the daemon's in-code
  route/object registry as the shape authority, but no owner requires a
  content-hashed registry covering *every* externally reachable native and
  projected route. Resolution belongs to that file with
  [`daemon-runtime/api.md`](../../../docs/architecture/components/daemon-runtime/api.md).
- **`RuntimeKernelService` trust membership is undefined in substantive canon.**
  The term appears only in `_meta` migration matrices, one of which declares
  itself an archived non-actionable record, so obligation 2 has no doctrinal
  owner. Resolution belongs to
  [`daemon-runtime/doctrine.md`](../../../docs/architecture/components/daemon-runtime/doctrine.md).
- **`StepModuleRouter` is routed to an owner that does not define it.**
  [`implementation-matrix.md`](../../../docs/architecture/_meta/implementation-matrix.md)
  names `daemon-runtime/doctrine.md` as owner, but that file does not define the
  Step/Module invocation, result, and routing boundary; resolution belongs there.
- **Final-invoker revalidation is generalized nowhere.**
  [`physical-action-safety.md`](../../../docs/architecture/foundations/physical-action-safety.md)
  names the final-invoker boundary for one effect family; CEC governs admitted
  execution and completion evidence without defining final-invoker revalidation
  across all effect families. Resolution belongs to
  [`effect-execution.md`](../../../docs/conformance/hypervisor-core/effect-execution.md).

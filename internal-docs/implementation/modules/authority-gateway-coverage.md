---
module_id: authority-gateway-coverage
module_class: method
title: Authority Gateway attach and coverage-declaration method
sequencer: program/sequence.v1.json
status_owner: work-item records
stage_ids: [M9]
canon_owners:
  - docs/decisions/0008-ioi-authority-gateway-sidecar-adoption-wedge.md
  - docs/decisions/0002-execution-authority-and-client-boundaries.md
  - docs/architecture/components/daemon-runtime/doctrine.md
  - docs/architecture/components/daemon-runtime/api.md
  - docs/architecture/components/daemon-runtime/hypervisoros.md
  - docs/architecture/components/daemon-runtime/default-harness-profile.md
  - docs/architecture/components/daemon-runtime/events-receipts-delivery-bundles.md
  - docs/architecture/components/connectors-tools/contracts.md
  - docs/architecture/components/wallet-network/api-authority-scopes.md
  - docs/architecture/foundations/verifiable-bounded-agency.md
  - docs/architecture/foundations/invariants.md
  - docs/architecture/foundations/common-objects-and-envelopes.md
  - docs/architecture/_meta/execution-horizons.md
  - docs/conformance/hypervisor-core/effect-execution.md
---

# Authority Gateway Attach And Coverage-Declaration Method

## What this module owns

This module owns one reusable method: how a declared existing coding agent and a declared MCP server are attached to the daemon in audit mode, walked from audit to active enforcement for one selected action class, and described afterwards by a retained `EnforcementCoverageDeclaration` whose six capability facts are asserted independently and never upgraded by inference. It is a contract-pulled acceptance slice — not a new application, surface track, runtime, plane, canonical object, or peer work package — and it never orders work, never carries status, and is never a sequencer; the pulling stage orders the work and the owning work-item record holds status and the retained proof refs.

## Pulled by

[`sequence.v1.json`](../program/sequence.v1.json) is the sole binding source and its `modules[]` array carries no entry whose `id` is `authority-gateway-coverage`, so no `applies_to_stages` list is asserted here. The stage file that pulls this method is [`stages/m9.md`](../stages/m9.md) at `M9.3` and `M9.4`, where the work item `m9-authority-gateway-equivalence-and-coverage` owns the coverage and equivalence proof. Registering the `modules[]` entry and its `applies_to_stages` value is an edit to the sequencer, not to this file.

## Canon owners

| Canon owner | What it governs here |
| --- | --- |
| [ADR 0008](../../../docs/decisions/0008-ioi-authority-gateway-sidecar-adoption-wedge.md) | IOI Authority Gateway as the canonical sidecar/compatibility profile over the same daemon substrate, not a second runtime; adapter mediation must be described precisely; no full-interception claim over opaque third-party runtimes. |
| [ADR 0002](../../../docs/decisions/0002-execution-authority-and-client-boundaries.md) | Adapters, MCP servers, and clients as protocol clients that cannot become the execution authority. |
| [`daemon-runtime/doctrine.md`](../../../docs/architecture/components/daemon-runtime/doctrine.md) | Daemon doctrine for the IOI Authority Gateway: the single policy-enforcement point and admission path both selected ingress paths converge on. |
| [`daemon-runtime/api.md`](../../../docs/architecture/components/daemon-runtime/api.md) | Externally reachable route classification and the positive Rust route family the attach proof drives. |
| [`daemon-runtime/hypervisoros.md`](../../../docs/architecture/components/daemon-runtime/hypervisoros.md) | The HypervisorOS/daemon contract ownership under which `EnforcementCoverageDeclaration` is to be defined and versioned. |
| [`daemon-runtime/default-harness-profile.md`](../../../docs/architecture/components/daemon-runtime/default-harness-profile.md) | `AgentHarnessAdapter` and the harness/MCP client boundary the gateway attaches to. |
| [`daemon-runtime/events-receipts-delivery-bundles.md`](../../../docs/architecture/components/daemon-runtime/events-receipts-delivery-bundles.md) | Effect-bound success and refusal receipt shape, delivery, and the exported evidence index. |
| [`connectors-tools/contracts.md`](../../../docs/architecture/components/connectors-tools/contracts.md) | `RuntimeToolContract` for the declared MCP server and the tool/route/version facts discovery must resolve. |
| [`wallet-network/api-authority-scopes.md`](../../../docs/architecture/components/wallet-network/api-authority-scopes.md) | The `AuthorityGrant`/`CapabilityLease` crossing required when `wallet.network` portable delegation is applicable. |
| [`foundations/verifiable-bounded-agency.md`](../../../docs/architecture/foundations/verifiable-bounded-agency.md) | Exact scoped authorization plus receipt for every consequential action, and final-invoker revalidation. |
| [`foundations/invariants.md`](../../../docs/architecture/foundations/invariants.md) | Authority-provider selection and the exact-effect boundary the refusal, substitution, expiry, and revocation branches must hold. |
| [`foundations/common-objects-and-envelopes.md`](../../../docs/architecture/foundations/common-objects-and-envelopes.md) | `ReceiptEnvelope`, `AuthorityGrantEnvelope`, `AuthorityRevocationSnapshot`, `WorkResult`, and `OutcomeDelta` as the objects the journey admits. |
| [`_meta/execution-horizons.md`](../../../docs/architecture/_meta/execution-horizons.md) | Horizon 1A scope and the selected minimum-L0 profile this slice sits inside. |
| [`conformance/hypervisor-core/effect-execution.md`](../../../docs/conformance/hypervisor-core/effect-execution.md) | Exact-effect admission, fencing, and refusal conformance: allow exactly once, zero final-invoker calls on denial. |

## Retained obligations

### Activation preconditions

The method activates only after the selected M3–M5 contract paths and the applicable local-agent, MCP, tool-contract, authority, receipt, and final-invoker paths close their stage gates. Adjacent substrate does not waive the full M1–M8 verification prerequisite. Product controls are pulled into the existing Work, Developer Workspace, Developer Console, Governance, and Provenance contexts only as their owner contracts become operable. Use daemon doctrine for the IOI Authority Gateway and the current HypervisorOS/daemon contract ownership for `EnforcementCoverageDeclaration`; keep any route census, comparison manifest, or retained exit log explicitly private and non-canonical.

### The selected proof journey

```text
one declared existing coding-agent installation + one declared MCP server
  -> supported adapter/gateway attach in audit mode
  -> discover exact application, runtime, server, tool, route, and version facts
  -> attribute actor, principal, Session, GoalRun, OutcomeRoom, and request
     where evidence supports them; retain confidence, conflicts, and unknowns
  -> observe one proposed sensitive effect without granting or blocking it
  -> show the operator the exact effect, policy result, and evidence
  -> obtain the selected exact-action authorization and the authority artifact
     required by the selected profile (`CapabilityLease` when wallet.network
     portable delegation is applicable)
  -> daemon recomputes and revalidates the effect at the final invoker
  -> allow exactly once in the positive branch
  -> block before the invoker in the refusal, substitution, expiry, and
     revocation branches
  -> admit effect-bound success/refusal receipts and the resulting
     WorkResult/OutcomeDelta/room lineage
  -> export the content-bound `EnforcementCoverageDeclaration` snapshots and
     evidence index
```

### Audit, transition, and client boundary

Audit attachment grants no authority and makes no prevention claim. Moving one selected action class from audit to active enforcement requires an explicit, admitted configuration transition and receipt. The coding-agent adapter and MCP binding remain protocol clients: they may observe, attribute, propose, and transport, but cannot mint identity, policy, authority, accepted state, or receipts. Both selected ingress paths must converge on the same policy-enforcement point, applicable `AuthorityGrant`/`CapabilityLease` crossing, final invoker, and receipt spine.

### The six independent coverage facts

For every selected action class, the retained `EnforcementCoverageDeclaration` assesses six capability facts independently:

```text
discovered | observable | attributable | mediated | preventable | receipted
```

Each asserted property binds the concrete mechanism and version, privilege level, deployment scope, bypass assumptions and tested resistance, online and offline behavior, fail-open/fail-closed posture, decision source, final invoker, and evidence refs.

### Coverage-overclaim rules

- Discovery does not imply observation.
- Observation does not imply attribution.
- Attribution does not imply mediation.
- Mediation does not imply prevention.
- A receipt does not prove an unobserved external effect.
- `uncovered: true` is the mutually exclusive terminal state for an exact scope.
- Partial gaps keep unsupported facts `false` or `unknown` and record `known_gaps`.
- Opaque actions outside an admitted adapter, gateway, broker, or instrumented effect boundary remain explicitly uncovered.

### Failure conditions

The proof fails if an unclassified route starts, audit mode changes an effect, the adapter or MCP server can self-authorize, an expired/revoked/substituted request reaches the invoker, a disconnected observer is reported as preventative, a success receipt is issued without the external effect evidence required by the selected profile, or any coverage claim exceeds the retained mechanism evidence.

### Claim ceiling

Passing proves only the named agent, server, versions, action classes, deployment posture, and tested paths. It does not prove universal interception, endpoint-wide control, or coverage of opaque third-party runtimes.

### Pulled product and nonclaims

Pulled product is the first standalone Hypervisor minimum-L0 profile plus the supporting workspaces and owner applications; `ioi.ai` Goal Space participates only in the separately claimed managed-optionality overlay. Retained nonclaims are production SLA beyond closed gates, multi-node continuity, federation, physical action, public settlement, and universal correctness.

## Applying it in a work item

- Name the exact declared coding-agent installation, MCP server, versions, action classes, and deployment posture in scope, and the selected authority profile — including whether `wallet.network` portable delegation applies and therefore whether a `CapabilityLease` crossing is required.
- Retain the content-bound `EnforcementCoverageDeclaration` snapshot per selected action class as an evidence ref, with all six facts asserted independently and every asserted property carrying its nine mechanism bindings (mechanism and version, privilege level, deployment scope, bypass assumptions and tested resistance, online and offline behavior, fail-open/fail-closed posture, decision source, final invoker, evidence refs).
- Retain positive-branch evidence that the allowed effect executed exactly once, and per-branch refusal evidence — refusal, substitution, expiry, revocation, and disconnected-observer — each showing zero final-invoker calls.
- Retain the audit-mode evidence that attachment changed no effect, plus the receipt for the explicit admitted audit-to-enforcement configuration transition for the one selected action class.
- Retain the equivalence evidence that the native coding-agent path and the MCP path reached the same policy-enforcement point, authority crossing, final invoker, and receipt spine, together with complete externally reachable route classification.
- Record `uncovered: true` scopes and `known_gaps` explicitly, keep the route census, comparison manifest, and exit log marked private and non-canonical, and state the claim ceiling verbatim in the record's nonclaims.

## Terminal evidence

This method contributes to the pulling stage's exit only when the declared coding agent and MCP server complete the audit-to-enforcement journey, the allowed branch executes once, every selected refusal branch reaches zero final-invoker calls, and the exported coverage declaration names both proven and intentionally uncovered seams without upgrading either. Zero unauthorized final-invoker calls and zero duplicate effects must occur across the adversarial matrix. The stage aggregate additionally joins the conditions this slice does not own by itself: one independent operator completing every terminal step without hidden edits or unavailable one-off tools; all selected state reconstructing after restart and export; model-route replacement meeting the frozen quality, latency, cost, and custody threshold; and an evidence index linking every package, identity, authority, pursuit, verification, effect, outcome, learning, recovery, and lifecycle root. The owning work-item record holds the retained proof refs and the literal exit; this file defines the acceptance contract only.

## Canon gaps

- **`EnforcementCoverageDeclaration` has no canonical definition.** The term appears in no file under `docs/`, so its exact shape, the six independent capability facts, the per-property mechanism bindings, and the `uncovered`/`known_gaps` semantics are unowned. Owner that should resolve it: [`daemon-runtime/hypervisoros.md`](../../../docs/architecture/components/daemon-runtime/hypervisoros.md) with [ADR 0008](../../../docs/decisions/0008-ioi-authority-gateway-sidecar-adoption-wedge.md), then registration in [`architecture-contract-registry.v1.json`](../../../docs/architecture/_meta/schemas/architecture-contract-registry.v1.json).
- **The six-fact vocabulary has no canonical-enum owner.** `discovered | observable | attributable | mediated | preventable | receipted` is not enumerated as a canonical enum, so nothing prevents a divergent spelling or an added seventh fact. Owner that should resolve it: [`foundations/canonical-enums.md`](../../../docs/architecture/foundations/canonical-enums.md).
- **"Audit mode" and the audit-to-enforcement transition are undefined in canon.** No canon file names audit mode, the admitted configuration transition, or the receipt type that transition emits. Owner that should resolve it: [ADR 0008](../../../docs/decisions/0008-ioi-authority-gateway-sidecar-adoption-wedge.md) with [`daemon-runtime/doctrine.md`](../../../docs/architecture/components/daemon-runtime/doctrine.md).
- **`CapabilityLease` carries no registry entry.** The journey requires it as the authority artifact when portable delegation applies, but it appears only in prose with no schema, generated projection, or fixture set. Owner that should resolve it: [`architecture-contract-registry.v1.json`](../../../docs/architecture/_meta/schemas/architecture-contract-registry.v1.json) with [`wallet-network/api-authority-scopes.md`](../../../docs/architecture/components/wallet-network/api-authority-scopes.md).

# aiagent.xyz Vertical Ontology Packs

Status: canonical architecture authority.
Canonical owner: this file for installable domain extensions over the aiagent Digital Worker Ontology.
Supersedes: plan prose that models verticals as hardcoded categories or separate runtimes.
Superseded by: none.
Last alignment pass: 2026-09-01.
Doctrine status: canonical
Implementation status: built for M05.10 — the registered `VerticalOntologyPack` v1 and `VerticalPackWorkerBinding` v1 contracts are produced and consumed by owner-scoped Agentgres admission routes, exact owner seams, deterministic compilation, restart/replay and a blocking mutation-tested live verifier. `WorkerComposition` remains explicitly unresolved and M14-owned, and `runtime_worker_package_install_admission.rs` still treats the legacy `vertical_pack:` value as display identity rather than resolving it as this revision family.
Implementation refs:
  - `docs/architecture/_meta/schemas/vertical-ontology-pack.v1.schema.json`
  - `docs/architecture/_meta/schemas/vertical-pack-worker-binding.v1.schema.json`
  - `crates/node/src/bin/hypervisor_daemon_routes/vertical_ontology_pack_routes.rs`
  - `crates/node/src/bin/hypervisor_daemon_routes/vertical_pack_worker_binding_routes.rs`
  - `apps/hypervisor/scripts/verify-hypervisor-vertical-ontology-pack-compiler.mjs`
  - `apps/hypervisor/scripts/mutate-hypervisor-vertical-ontology-pack-compiler.mjs`
  - `crates/services/src/agentic/runtime/kernel/runtime_worker_package_install_admission.rs`
Last implementation audit: 2026-09-01

## Canonical Definition

`VerticalOntologyPack` is an installable, versioned domain extension that maps a
vertical's objects, actions, risks, policies, evidence, receipts, benchmarks,
and UI projections onto the shared aiagent worker ontology.

Vertical packs let aiagent.xyz support millions of worker profiles without
building a separate runtime, wallet, Agentgres schema, or marketplace for each
vertical.

## Owns

A pack may define:

- domain object types;
- action types;
- capability vocabulary;
- integration surfaces;
- connector mappings;
- policy profiles;
- risk mappings;
- receipt schemas;
- evidence requirements;
- benchmark rubrics;
- UI projection hints;
- forbidden actions;
- platform terms constraints;
- settlement hooks where applicable;
- safety envelopes for physical-action surfaces;
- emergency-stop and supervision requirements for embodied systems.

## Does Not Own

A pack does not own:

- daemon execution truth;
- wallet.network grants or secrets;
- Agentgres admission;
- storage backend authority;
- IOI L1 settlement by default;
- provider operations;
- model routing or model weights.

## Lifecycle

```text
draft pack
  -> validate against DigitalWorkerOntology
  -> bind integration surfaces and risk mappings
  -> attach conformance fixtures and benchmark rubrics
  -> publish pack version
  -> worker package references pack
  -> marketplace indexes capabilities/evidence
  -> managed instance applies pack policy at initialization
  -> daemon, authority providers/local governance, and Agentgres enforce during execution
```

## Minimal Implementation Objects

```yaml
VerticalOntologyPack:
  pack_id: vertical_pack:community.discord_moderation.v1
  display_name: Discord moderation
  base_ontology_ref: ontology:aiagent.base.v1
  object_types:
    - channel
    - message
    - member
  action_types:
    - message.review
    - member.timeout
    - member.ban
  integration_surface_refs:
    - integration_surface:chat_community
  connector_mappings:
    - connector:discord
  policy_profile_refs:
    - policy:moderation.default
  risk_mappings:
    external_message: high
    policy_widening: high
  receipt_schema_refs:
    - receipt_schema:moderation.action.v1
  evidence_requirement_refs:
    - evidence_requirement:moderation.audit.v1
  benchmark_profile_refs:
    - benchmark:moderation.false_positive_rate.v1
  forbidden_actions:
    - mass_ban_without_step_up
  settlement_triggers:
    - dispute
```

Example pack families:

```text
community.discord_moderation.v1
game.server_finder.v1
game.platform_coordination.v1
quant.research.v1
coding.review.v1
commerce.shopify_support.v1
finance.backoffice.v1
trading.policy_assistant.v1
robotics.carwash_prep.v1
robotics.warehouse_pick.v1
field_service.inspection.v1
```

## Admission / Settlement Boundary

Pack publication can commit package/version roots on IOI L1 only when an active
connected/secured enrollment selected that service and its marketplace-rights,
reputation, payout, dispute, or cross-domain trigger applies. Ordinary pack use
remains local/domain Agentgres truth with receipts.

## Events And Receipts

- `VerticalOntologyPackPublishedReceipt`
- `VerticalOntologyPackValidatedReceipt`
- `VerticalPackWorkerBindingReceipt`
- `VerticalPackPolicyViolationReceipt`
- `VerticalPackBenchmarkReceipt`

## Conformance Checks

- Pack actions map to declared risk classes and authority scopes.
- A pack declares its review mode per action type, and among the pack's own
  declarations that one governs: a risk class is not a review key. The review
  that actually runs follows the principal's governing policy.
- Pack connectors do not imply credential custody.
- Physical packs reference `PhysicalActionPolicy` and `SafetyEnvelope`.
- Pack UI projections are display hints, not truth.
- Unknown or stale policy/evidence coverage is explicit.

Review is keyed by action type because one risk class can hold actions that need
different review. A clean claim submission, a void of that claim and a
correction to it are all `external_message`, yet the first may go out under
sampled review while the void and the correction require exact payload
review. A mode keyed by risk class could express that only by giving all three
the strictest mode, or by weakening the void. The registered
`vertical-ontology-pack/v1` contract carries both a `review_mode` on each action
binding and a per-risk-class `declared_review_modes` list, and says neither
which one governs nor that they must agree. Its successor contract makes the
per-action mode the only review key, as a successor rather than an edit of v1.
The per-action mode stays a declaration: the review that runs follows the
principal's governing policy, and a policy that samples one action never
relaxes the review another action requires.

## Anti-Patterns

- Forking Hypervisor Daemon for a vertical.
- Treating a platform adapter as a trust root.
- Turning a pack into a broker, custodian, or cloud provider.
- Letting a pack bypass wallet.network approval because it is "domain specific."
- Creating a physical-action pack without e-stop and supervision semantics.

## Related Canon

- [`digital-worker-ontology.md`](./digital-worker-ontology.md)
- [`integration-surface-taxonomy.md`](./integration-surface-taxonomy.md)
- [`worker-marketplace.md`](./worker-marketplace.md)
- [`physical-action-safety.md`](../../foundations/physical-action-safety.md)

# aiagent.xyz Vertical Ontology Packs

Status: canonical architecture authority.
Canonical owner: this file for installable domain extensions over the aiagent Digital Worker Ontology.
Supersedes: plan prose that models verticals as hardcoded categories or separate runtimes.
Superseded by: none.
Last alignment pass: 2026-06-17.
Doctrine status: canonical
Implementation status: planned
Last implementation audit: 2026-07-05

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
- Pack connectors do not imply credential custody.
- Physical packs reference `PhysicalActionPolicy` and `SafetyEnvelope`.
- Pack UI projections are display hints, not truth.
- Unknown or stale policy/evidence coverage is explicit.

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

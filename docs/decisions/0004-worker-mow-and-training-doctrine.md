# ADR 0004: Define Worker, MoW, And Worker Training As Labor Architecture

- Status: Accepted
- Date: 2026-05-14
- Owners: IOI protocol / aiagent.xyz / sas.xyz / Hypervisor Foundry

## Context

IOI needs a protocol-visible actor for accountable machine labor, a routing
architecture for composing those actors, and a supply-creation lifecycle for
improving them. Models, agent personas, marketplace search, and fine-tuning
jobs are important, but none of them alone is the economic actor.

## Decision

The architecture adopts these protocol terms:

- `Worker` is the canonical protocol actor.
- `Agent` is product-facing or colloquial language.
- `Model` is a cognition backend mounted or invoked by a worker.
- `MoW` is protocol-level labor routing across bounded workers.
- `MoE` is model-internal or provider-side cognition routing.
- `Worker Training` is the supply-creation lifecycle for producing better
  workers.

MoW is not a fifth Web primitive. It is the labor-routing architecture made
possible once Act is bounded by identity, policy, authority scopes, receipts,
and settlement.

Worker Training is broader than fine-tuning and narrower than the whole IOI
stack. It creates or improves capability; it does not grant authority.

Hypervisor Foundry is the product lens for Worker Training. It uses the shared
builder substrate rather than defining a separate canvas environment. Training,
evaluation, benchmark, deployment, data, and outcome recipes may project into
the standard workflow compositor with lens-specific palettes, inspectors, run
panels, templates, and validation rules.

## Consequences

- aiagent.xyz ranks and routes bounded workers, not standalone model
  checkpoints.
- sas.xyz may sell Worker Training as a Service-as-Software outcome, but IOI
  does not collapse into a training platform.
- Marketplace ranking and subscription-credit distribution should be based on
  receipts, benchmarks, policy compatibility, cost, trust posture, quality, and
  contribution evidence rather than platform fiat or raw token usage.
- Model architecture claims are profile metadata; they require evaluation,
  benchmark, promotion, and regression receipts before affecting routing.
- Foundry should lead with guided product flows and expose graph editing as an
  advanced workflow-compositor projection, not as a second training-only canvas.

## Canonical References

- `docs/architecture/foundations/mixture-of-workers.md`
- `docs/architecture/foundations/worker-training-lifecycle.md`
- `docs/architecture/domains/aiagent/worker-marketplace.md`
- `docs/architecture/domains/sas/service-marketplace.md`
- `docs/architecture/domains/marketplace-neutrality.md`
- `docs/architecture/components/model-router/doctrine.md`

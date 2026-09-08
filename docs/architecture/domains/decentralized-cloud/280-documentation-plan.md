# 280 — Documentation plan: the public and internal trees, and the architecture-document decomposition

**Spec sections:** 28, 29. This tree is the `internal/architecture/` of §28; the
public developer documentation in §28 is a separate deliverable that does not exist
yet.

## 28. Documentation tree

### Public developer documentation

```text
docs/
├── start/
│   ├── what-this-cloud-is.md
│   ├── create-an-account.md
│   ├── deploy-your-first-app.md
│   ├── run-your-first-gpu-job.md
│   └── understand-your-first-bill.md
├── concepts/
│   ├── organizations-and-projects.md
│   ├── applications-services-deployments.md
│   ├── regions-and-latency-cells.md
│   ├── resource-lifecycle.md
│   ├── service-profiles.md
│   ├── resilience-and-failure-domains.md
│   └── trust-and-responsibility.md
├── applications/
│   ├── repositories-and-builds.md
│   ├── container-deployments.md
│   ├── environment-and-secrets.md
│   ├── rollouts-and-rollback.md
│   └── preview-projects.md
├── compute/
│   ├── services.md
│   ├── jobs-and-retries.md
│   ├── instances.md
│   ├── clusters.md
│   ├── reservations.md
│   └── runtime-compatibility.md
├── ai/
│   ├── inference-endpoints.md
│   ├── batch-inference.md
│   ├── model-artifacts.md
│   ├── gpu-compatibility.md
│   └── checkpoints-and-recovery.md
├── data/
│   ├── choose-storage.md
│   ├── object-api-compatibility.md
│   ├── volumes-and-attachment.md
│   ├── archives-and-retrieval.md
│   ├── databases.md
│   ├── backups-and-restores.md
│   └── deletion-and-retention.md
├── network/
│   ├── service-networks.md
│   ├── routed-networks.md
│   ├── domains-and-tls.md
│   ├── ingress-and-load-balancing.md
│   ├── egress-and-addresses.md
│   └── diagnostics.md
├── security/
│   ├── roles-and-policies.md
│   ├── workload-identity.md
│   ├── secrets-and-keys.md
│   ├── confidential-execution.md
│   └── audit-and-data-residency.md
├── operations/
│   ├── logs-metrics-traces.md
│   ├── incidents.md
│   ├── provider-failure.md
│   ├── migration.md
│   └── disaster-recovery.md
├── supply/
│   ├── provider-pools.md
│   ├── placement-policies.md
│   ├── market-and-quotes.md
│   └── provenance-and-evidence.md
├── billing/
│   ├── pricing-units.md
│   ├── budgets-and-spending-limits.md
│   ├── reservations-and-interruptions.md
│   └── invoices-refunds-and-credits.md
├── reference/
│   ├── api/
│   ├── cli/
│   ├── sdk/
│   ├── terraform/
│   ├── schemas/
│   ├── errors/
│   └── events/
└── providers/
    ├── onboarding.md
    ├── agent-installation.md
    ├── capability-qualification.md
    ├── offers-and-reservations.md
    ├── maintenance.md
    └── earnings-and-settlement.md
```

### Internal documentation

```text
internal/
├── architecture/
│   └── numbered specifications listed in Section 29
├── adr/
│   └── decisions corresponding to Section 33
├── contracts/
│   ├── openapi/
│   ├── provider-adapter/
│   ├── events/
│   ├── runtime-profiles/
│   ├── storage-compatibility/
│   └── service-level-objectives/
├── runbooks/
│   ├── provider-loss.md
│   ├── acquisition-uncertain.md
│   ├── storage-quorum-loss.md
│   ├── unsafe-database-promotion.md
│   ├── protocol-halt.md
│   ├── treasury-shortfall.md
│   ├── orphan-resources.md
│   ├── certificate-issuance-failure.md
│   └── control-plane-restore.md
├── tests/
│   ├── conformance/
│   ├── fault-injection/
│   ├── financial-reconciliation/
│   ├── tenant-isolation/
│   └── disaster-recovery/
└── operations/
    ├── release-and-schema-migration.md
    ├── on-call-ownership.md
    ├── capacity-planning.md
    └── incident-review.md
```

Public documentation explains usable contracts. Internal documentation explains implementation, invariants, and failure behavior.

## 29. Architecture-document decomposition

Each specification must include: ownership, normative interfaces, state transitions, invariants, failure handling, telemetry, security review, and acceptance tests.

Dependencies below refer to document numbers.

| Document                       | Purpose and questions answered                                                                                                         | Interfaces defined                                              | Dependencies                      | Required diagrams                                       |
| ------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------- | --------------------------------- | ------------------------------------------------------- |
| `000-system-overview.md`       | Defines system boundaries, trust domains, phases, and responsibility. What is the cloud accountable for? What is outside its contract? | Subsystem ownership and service profiles                        | None                              | Context, planes, deployment groups                      |
| `010-resource-model.md`        | Defines canonical identity and ownership. What survives migration? What cascades on deletion?                                          | Resource schemas, references, ownership rules                   | 000                               | Ownership tree, dependency graph, identity lifetimes    |
| `020-console-ux.md`            | Defines navigation, page contracts, flows, and progressive disclosure. What does each persona see?                                     | Routes, view models, status vocabulary, design components       | 010, 160                          | Shell, page maps, critical journeys                     |
| `030-control-plane.md`         | Defines desired state, plans, operations, reconcilers, retries, and finalizers. How does work resume after crashes?                    | Controller contract, operation journal, plan execution          | 010, 170, 180                     | Reconciliation loop, saga, crash boundaries             |
| `040-provider-abstraction.md`  | Defines native capability translation and uncertainty. What may an adapter claim?                                                      | Adapter API, capability manifest, normalized outcomes           | 010, 030                          | Acquisition lifecycle, native-state mapping             |
| `050-placement-market.md`      | Defines candidate discovery, constraint evaluation, delivered cost, and placement explanations                                         | Offer schema, scheduler request/result, policy compiler         | 040, 100, 190, 200, 260           | Filtering pipeline, dependency placement, optimization  |
| `060-compute.md`               | Defines services, jobs, VMs, GPU execution, packaging, and runtime compatibility                                                       | Runtime profiles, deployment bundle, attempt lifecycle          | 030, 040, 080, 090                | Four-layer mapping, rollout, checkpoint recovery        |
| `070-storage.md`               | Defines object, block, filesystem, archive, replication, and deletion semantics                                                        | Storage APIs, attachment/fencing contract, archive manifest     | 010, 040, 090, 190                | Storage cells, write path, repair, archive restore      |
| `080-network.md`               | Defines service-connect and routed profiles, tunnels, isolation, egress, and path diagnostics                                          | Connection, route, attachment, flow-meter schemas               | 010, 090, 190, 250                | Overlay, relay paths, tenant isolation                  |
| `090-identity-security.md`     | Defines principals, authorization, workload identity, secret release, and key custody                                                  | IAM APIs, credential claims, policy decisions, KMS boundary     | 010, 210                          | Authentication, authorization, credential issuance      |
| `100-metering-pricing.md`      | Defines meters, units, quote validity, rating, and cost attribution                                                                    | UsageRecord, RateCard, Quote, corrections                       | 010, 040, 080                     | Meter flow, rating, customer/supplier attribution       |
| `110-billing-ledger.md`        | Defines customer balances, commitments, journals, invoices, refunds, and hard limits                                                   | Ledger posting API, spend grants, invoice schema                | 100, 170, 180                     | Double-entry flows, holds, invoice finalization         |
| `120-settlement.md`            | Defines treasury, native transactions, escrow, finality, and reconciliation                                                            | SettlementIntent, wallet policy, native evidence                | 040, 110, 090                     | Funding, transaction uncertainty, settlement closure    |
| `130-observability.md`         | Defines logical/physical telemetry, retention, topology history, and incident evidence                                                 | OTLP conventions, query API, SLO records                        | 010, 080, 170                     | Ingestion, identity continuity, incident correlation    |
| `140-provider-runtime.md`      | Defines enrollment, inventory, local execution, maintenance, and agent upgrades                                                        | Provider agent protocol, inventory and health schemas           | 040, 060, 080, 090                | Enrollment, allocation execution, maintenance drain     |
| `150-failure-dr.md`            | Defines provider failure, quorum loss, orphan cleanup, and control-plane restore                                                       | Recovery envelopes, fencing requirements, restore checkpoints   | 030, 060, 070, 080, 110, 120      | Failure trees, rescheduling, disaster recovery          |
| `160-api-tooling.md`           | Defines API conventions, CLI/SDK/Terraform behavior, webhooks, and compatibility                                                       | OpenAPI, errors, pagination, idempotency, operation streams     | 010, 030, 090, 170                | Request lifecycle, tool-to-API mapping                  |
| `170-events.md`                | Defines event identities, ordering, replay, deduplication, and schema evolution                                                        | Event catalog, envelopes, producer/consumer ownership           | 010, 180                          | Outbox, delivery, replay, correction                    |
| `180-data-model.md`            | Defines authoritative stores, keys, constraints, retention, and materialized views                                                     | Database schemas, partitioning, consistency rules               | 010                               | Entity relationships, store boundaries, replication     |
| `190-regions-residency.md`     | Defines logical regions, latency cells, evidence, and allowed data sinks                                                               | Region contract, locality constraints, residency policy         | 010, 040, 090                     | Geographic hierarchy, data-location graph               |
| `200-sla-reputation.md`        | Defines service objectives, provider qualification, measurement confidence, and recourse                                               | Health records, qualification rules, SLO calculations           | 040, 130, 190                     | Evidence lifecycle, failure-domain coverage             |
| `210-threat-abuse.md`          | Defines adversaries, attack surfaces, tenant/provider controls, and incident authority                                                 | Threat register, abuse controls, exception process              | 000, 010                          | Trust boundaries, credential exposure paths             |
| `220-ai-operations.md`         | Defines read-only assistance, planning, approvals, execution limits, and auditability                                                  | AI tool schemas, plan/diff format, approval policy              | 030, 090, 130, 160                | Read-plan-approve-execute path                          |
| `230-managed-data.md`          | Defines database/cache/queue engine operation, backup, failover, and upgrade behavior                                                  | Managed engine profiles, promotion API, backup manifests        | 060, 070, 080, 090, 150           | Database replication, fencing, restore, maintenance     |
| `240-delivery-operations.md`   | Defines deployment groups, service ownership, releases, capacity management, and go/no-go gates                                        | Release contracts, on-call matrix, migration procedures         | All implementation specifications | Deployment topology, release waves, dependency failures |
| `250-edge-dns-certificates.md` | Defines domain ownership, stable ingress, certificate lifecycle, CDN, and edge diversity                                               | Domain/Endpoint APIs, route generations, certificate references | 080, 090, 190                     | Request path, DNS/TLS flow, edge failover               |
| `260-capacity-reservations.md` | Defines advertised versus reserved supply, overbooking prevention, gang holds, and commitments                                         | Reservation/CapacityHold APIs, cancellation and renewal terms   | 040, 050, 100, 110                | Reservation lifecycle, admission, capacity accounting   |

The first implementation sequence should be:

```text
000 / 010 / 180
→ 090 / 030 / 040
→ 100 / 110 / 120
→ 060 / 080 / 250
→ 070 / 130 / 150
→ 020 / 160 / provider onboarding
```

The UI should not be designed against resource states that the control plane cannot reliably produce.

### Where this tree stands against the decomposition

| Spec document | File here today | Not yet split out |
|---|---|---|
| 000 | `000-thesis-and-principles.md` | — |
| 010, 180, 230's state machines | `010-resource-model.md` | 180 (stores, keys, partitioning) |
| 020 | `020-console-ux.md` | — |
| 030, 170 | `030-control-plane.md` | 170 (full event catalog) |
| 040, 140 | `040-provider-abstraction.md` | 140 (agent protocol in full) |
| 050, 190, 200, 260 | `050-placement-and-supply.md` | 190, 200, 260 |
| 060 | `060-compute.md` | — |
| 070, 230 | `070-storage.md` | 230 (caches, queues, upgrades) |
| 080, 250 | `080-network.md` | 250 |
| 090, 210 | `090-identity-security.md` | 210 (threat register in full), 220 |
| 100, 110, 120 | `100-money.md` | 110, 120 |
| 130 | `130-observability.md` | — |
| 150 | `150-failure-recovery.md` | — |
| 160 | `160-api-cli-sdk.md` | — |
| 240 | `240-roadmap-and-wedge.md` | delivery operations proper |

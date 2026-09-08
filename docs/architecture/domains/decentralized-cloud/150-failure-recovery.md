# 150 — Failure and recovery: the end-to-end deployment trace, the failure/recovery trace, the hardest unresolved problems

**Spec sections:** 24, 25, 32. **Depends on:** 030, 060, 070, 080, 110, 120.
**Defines:** provider failure, quorum loss, orphan cleanup, and control-plane restore;
recovery envelopes, fencing requirements, restore checkpoints. **Required diagrams:**
failure trees, rescheduling, disaster recovery.

## 24. End-to-end deployment trace

### Scenario and explicit assumptions

The user deploys:

```text
Dockerized API
4 vCPU and 16 GiB RAM per replica
Three replicas
US-East placement
Maximum retail compute price: $0.20 per replica-hour
Private replicated persistent data
Public HTTPS endpoint
```

For this trace, persistent data means a **private Standard Object bucket** used through the application's object API. It is not a shared writable block volume. The form makes that choice explicit.

The plan selects three qualified operators in an eligible latency cell. Illustrative compute rates are `$0.17`, `$0.18`, and `$0.19` per replica-hour: `$0.54/hour` total. Storage and networking are separately itemized.

**Store abbreviations:** `Core` = authoritative resource/operation database; `Money` = financial ledger; `Market` = offer observations; `Evidence` = provider/probe evidence; `Data` = storage engine.

| Step                                 | Responsible service and action                                                                                               | State touched                                                            | Event                                                   | Failure and retry behavior                                                                                        | User-visible state                          |
| ------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ | ------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- | ------------------------------------------- |
| 1. UI interaction                    | Console collects image, resources, data semantics, location, and price ceiling; requests a plan                              | Client draft                                                             | None                                                    | Local validation preserves inputs; no external purchase                                                           | Draft                                       |
| 2. API request                       | Front Door accepts idempotent plan request                                                                                   | Request/idempotency record                                               | `request.accepted`                                      | Duplicate request returns same result; body mismatch conflicts                                                    | Reviewing                                   |
| 3. Authentication                    | Identity service verifies session or short-lived token                                                                       | Identity/session state                                                   | Audit authentication result                             | Expired credentials require renewal; no provisioning begins                                                       | Sign-in required or Reviewing               |
| 4. Authorization                     | Authorizer checks project permissions, quota, policy, and planning scope                                                     | Policy versions, quota state                                             | `authorization.evaluated`                               | Denial identifies scope/permission without leaking inaccessible resources                                         | Permission required                         |
| 5. Proposed desired-state write      | Registry stores proposed application revision and references; not yet activated                                              | Core revision, draft resource records, outbox                            | `deployment.created`                                    | Atomic transaction; retry by idempotency key                                                                      | Planning                                    |
| 6. Plan creation                     | Plan Service resolves image digest, dependencies, health checks, recovery rules, and required capabilities                   | Core Plan and dependency graph                                           | `deployment.planned`                                    | Invalid image/configuration blocks with field-level error                                                         | Planning                                    |
| 7. Pricing evaluation                | Pricing obtains applicable retail terms and cost envelope                                                                    | Quote version, rate card                                                 | `quote.created`                                         | Missing rate component or unbounded charge makes plan infeasible                                                  | Estimating cost                             |
| 8. Provider discovery                | Market Aggregator queries eligible supply feeds/adapters                                                                     | Market offer snapshots                                                   | `offers.observed`                                       | Timeouts use only still-valid observations; stale supply is labeled, not invented                                 | Finding capacity                            |
| 9. Candidate normalization           | Provider Registry/adapter converts native resources and terms into canonical units                                           | Candidate set, capability evidence                                       | `candidates.normalized`                                 | Unknown semantics or unsupported profile excludes candidate                                                       | Finding capacity                            |
| 10. Policy filtering                 | Placement Engine applies jurisdiction, trust, runtime, locality, price, and diversity constraints                            | Plan eligibility explanation                                             | `placement.filtered`                                    | No candidates produces blocking-constraint report; no silent relaxation                                           | Waiting for eligible capacity               |
| 11. Scheduling                       | Scheduler assigns three replica slots and data/network dependencies; calculates final quote                                  | Placement decision and plan hash                                         | `provider.selected`                                     | Conflicting/stale capacity triggers bounded replanning before approval                                            | Plan ready                                  |
| 12. Funds authorization and approval | User approves exact plan; Authorizer rechecks; Money creates bounded spend grants; Registry activates revision               | Approval, Money hold, Core target generation                             | `plan.approved`, `funds.authorized`                     | Expired quote or changed policy requires new review; duplicate authorization reuses hold                          | Securing capacity                           |
| 13. Resource acquisition             | Acquisition Controller persists intents; adapters acquire native leases/resources                                            | ExternalEffect, Allocation, native transaction refs, supplier obligation | `allocation.acquired`                                   | Unknown response enters acquisition-uncertain; discover outcome before retry; compensate partial acquisition      | Securing capacity                           |
| 14. Workload provisioning            | Adapter installs approved image/runtime bundle in bootstrap state                                                            | Attempt, provider observation, image evidence                            | `allocation.provisioning`                               | Pull/runtime failure retries within deadline; private pull credentials are scoped bootstrap credentials           | Provisioning                                |
| 15. Network creation                 | Network Controller establishes service connections, tunnel identity, private discovery, and inactive public route            | NetworkAttachment, endpoint generation                                   | `network.attached`                                      | Unsupported connectivity fails capability check; tunnel setup retries with bounded alternate relay selection      | Connecting network                          |
| 16. Storage provisioning             | Storage Controller creates/attaches private Standard bucket and verifies protection state                                    | Bucket policy, Data namespace, replica evidence                          | `storage.available`                                     | Insufficient independent storage domains blocks protected tier; no local-disk substitution                        | Preparing data                              |
| 17. Secret injection                 | Workload identity service verifies attempt; Secrets issues scoped bucket/application credentials                             | Identity binding, grants, secret-access audit                            | `identity.issued`, `secret.grant_issued`                | Failed identity or attestation is not bypassed; retry only after valid evidence                                   | Starting                                    |
| 18. Health verification              | Deployment Controller checks process, readiness, dependency connectivity, and resource profile                               | Health conditions, Evidence                                              | `workload.verified`                                     | Failed checks surface logs and reason; no traffic admission; bounded restart or replacement                       | Verifying                                   |
| 19. DNS                              | DNS Controller creates platform hostname or validates custom-domain binding                                                  | Domain/record intent and observed DNS                                    | `dns.configured`                                        | Ownership conflicts block custom domain; propagation remains visible and retryable                                | Preparing endpoint                          |
| 20. TLS                              | Certificate Controller obtains/installs appropriate certificate                                                              | Certificate reference, renewal schedule, gateway acknowledgement         | `certificate.ready`                                     | Challenge/issuance failure retries under rate limits; never expose false HTTPS readiness                          | Securing endpoint                           |
| 21. Observability registration       | Telemetry/Health services confirm resource labels, log flow, probes, and alert configuration; bootstrap logs already existed | Telemetry registration, monitor records                                  | `observability.registered`                              | Missing telemetry produces explicit warning or readiness block according to profile                               | Verifying                                   |
| 22. READY                            | Network Controller publishes healthy backends; external HTTPS check passes; Registry marks observed generation ready         | Endpoint generation, Service/Deployment status                           | `deployment.ready`                                      | Failed external check keeps rollout unready; previous revision remains serving when present                       | Healthy                                     |
| 23. Customer metering begins         | Metering records contract-defined billable timestamp and starts rated usage                                                  | UsageRecord, Money accrual                                               | `usage.recorded`                                        | Duplicate events deduplicated; supplier expense from step 13 remains separately recorded                          | Running; usage updating                     |
| 24. Continuous provider health       | Health Service monitors independent probes, attempt health, storage protection, and supplier observations                    | Health history, incidents                                                | `health.observed`                                       | Missing signal becomes uncertain; corroborate before broad evacuation                                             | Healthy or Investigating                    |
| 25. Provider fails                   | Health and Network Controllers remove unhealthy backend and record affected failure domain                                   | Incident, endpoint generation, attempt condition                         | `provider.unreachable`, `health.degraded`               | Distinguish provider loss from platform/probe failure; do not delete data on suspicion                            | Available; redundancy reduced               |
| 26. Replacement                      | Recovery Controller uses approved envelope, new attempt ID, fresh acquisition, existing bucket, and new credentials          | New Allocation/Attempt, old-attempt fencing state                        | `migration.started`, then `migration.completed`         | No capacity within policy gives explicit repair-blocked state; no budget/residency violation                      | Repairing, then Healthy                     |
| 27. Billing reconciliation           | Metering and Ledger reconcile old/new attempts, repair overlap, supplier obligations, and customer rate                      | Usage corrections, journal entries                                       | `usage.corrected`, `billing.updated`                    | Discrepancies enter reconciliation queue; no double charge for platform repair overlap                            | Usage reconciled                            |
| 28. User deletes deployment          | API generates/accepts authorized deletion with explicit data disposition                                                     | Core tombstone, deletion operation                                       | `deployment.deletion_requested`                         | Protected/shared data requires separate permission; repeated delete reuses operation                              | Stopping                                    |
| 29. Teardown                         | Controllers remove traffic, revoke grants, stop attempts, detach safely, release native resources, retain bucket as chosen   | Finalizers, release evidence, retained-data references                   | `allocation.released`, `deployment.deleted` when proven | Unreachable provider stays cleanup-pending; orphan reconciler continues; retained storage remains visible         | Deleted or Cleanup pending                  |
| 30. Settlement                       | Settlement Engine confirms native closure/refunds/remaining obligations; Ledger reconciles supplier cost                     | Settlement, escrow/asset/payable entries, audit                          | `settlement.completed`                                  | Protocol delay remains pending/disputed; fixed-price customer invoice does not inherit native currency volatility | Compute stopped; financial detail available |

The customer's normal experience is a short progress timeline. The complete operation journal is available through **Inspect operation**.

## 25. Failure/recovery trace

Consider loss of the operator hosting API replica 2.

### 25.1 Detect and contain

External probes and gateway observations detect failure. Provider heartbeat loss corroborates it.

Immediately remove the failed attempt from new traffic admission. Existing requests may fail; the platform must not claim that every in-flight request survives.

Create one operator-level incident and fan out impact to affected resources. Rate-limit recovery to prevent an acquisition storm.

### 25.2 Establish the safe recovery action

Read the current desired generation and approved repair envelope.

For a stateless API:

```text
Do not reuse the old attempt identity.
Do not delete the persistent bucket.
Do not wait for the old provider to acknowledge failure.
Do not allow the old attempt to rejoin automatically.
```

For stateful workloads, establish writer fencing and promotion safety before creating a new writer.

### 25.3 Replace

Select a provider outside the failed operator group, preserving:

```text
region and jurisdiction
runtime compatibility
data locality
trust profile
retail ceiling
surviving-capacity requirements
```

Acquire capacity with a new external-effect ID. Bootstrap, attach service connections, issue new credentials, verify health, then admit traffic.

The service stays `DEGRADED / REPAIRING` until required redundancy is restored.

### 25.4 Repair data protection

If the lost operator also hosted a storage replica, the Storage Controller reconstructs a new copy on a qualified replacement domain.

It reports:

```text
Data available
Protection reduced
Repair progress
Estimated transfer remaining
```

It does not label the bucket fully protected merely because reads still succeed.

### 25.5 Handle the returning provider

A returning old attempt is stale.

Its credentials are expired or revoked; its endpoint generation is obsolete. It is not allowed to overwrite current state or become an active database primary.

The platform attempts native release and reconciles the remaining supplier obligation.

### 25.6 Financial and reputation closure

Customer usage continues under the accepted managed-service rate. Platform-caused overlap is not charged twice.

Supplier expense is reconciled separately. Reputation records the observed failure with its evidence and attribution confidence. A protocol-wide outage should not automatically be recorded as an individual provider's hardware failure.

### 25.7 Proposed recovery acceptance targets

For a qualified, warm-capacity profile:

```text
Unhealthy ingress removal: target within 15 seconds
Corroborated operator-failure detection: target within 30 seconds
CPU replacement: target p95 within 5 minutes
GPU replacement with cached artifacts: target p95 within 10 minutes
```

These are launch-test targets, not universal guarantees.

Without reserved replacement capacity, the platform can promise continued service only to the extent that surviving replicas already have sufficient capacity. **Continuity and restoration of redundancy are separate promises.**

## 32. Hardest unresolved engineering problems

The ranking reflects implementation risk, not an assertion that these problems cannot be addressed.

| Rank | Problem                                                            | Classification                                 | Selected treatment / remaining work                                                                                                |
| ---: | ------------------------------------------------------------------ | ---------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
|    1 | Reliable stateful services across independent operators            | Solved with constraints                        | Qualified latency cells, engine-specific replication, fencing, restore testing; no arbitrary geographic spread                     |
|    2 | Truthful provider independence and capability evidence             | Solved with constraints                        | Operator/facility graph, evidence expiry, conservative unknowns, independent qualification; beneficial-control uncertainty remains |
|    3 | Delivered-cost advantage after networking and reliability overhead | Solved with constraints                        | Measure complete unit economics; reject supply that is cheap only before overhead                                                  |
|    4 | Stable, economical cross-provider networking                       | Requires centralized component initially       | Operated gateways/relays and qualified routed profiles; measure bandwidth and tail latency                                         |
|    5 | Replacement capacity during correlated failures                    | Solved with constraints                        | Reservations, admission limits, surviving-load headroom; unreserved market supply cannot be guaranteed                             |
|    6 | Safe recovery from unknown native acquisition outcomes             | Solved with constraints                        | Durable intents, native discovery, replay rules, orphan inventory, explicit uncertainty                                            |
|    7 | Provider access to workload plaintext                              | Solved with constraints                        | Verified-operator tiers and supported confidential profiles; ordinary execution still trusts the host                              |
|    8 | General low-overhead verification of arbitrary GPU computation     | Requires new technology for the broadest claim | Keep outside launch guarantees; investigate workload-specific verification and bounded redundant checks                            |
|    9 | GPU migration across heterogeneous machines                        | Solved with constraints                        | Application checkpoints and exact compatibility profiles; no universal transparent migration promise                               |
|   10 | Geographic placement versus actual network transit                 | Fundamental limitation of the broad guarantee  | Guarantee eligible processing/storage locations; treat transit guarantees separately                                               |
|   11 | Arbitrarily low global latency                                     | Fundamental limitation                         | Geographic locality, caching, regional service copies; no abstraction removes distance                                             |
|   12 | Availability and consistency during partitions                     | Fundamental limitation                         | Choose service-specific behavior; stateful writes stop when safe authority cannot be established                                   |
|   13 | Archive retrieval latency and provider withholding                 | Solved with constraints                        | Multiple copies, retrieval tests, hot-tier restoration, explicit retrieval objectives                                              |
|   14 | Ingress/IP mobility and DDoS                                       | Requires centralized component initially       | Managed edge and scrubbing suppliers; stable hostname, scoped address portability                                                  |
|   15 | Runtime, image, kernel, and Kubernetes heterogeneity               | Solved with constraints                        | Versioned profiles and conformance suites; unsupported combinations are excluded                                                   |
|   16 | Meter integrity and delayed settlement                             | Solved with constraints                        | Qualified meters, independent observations, financial reconciliation, operator risk reserves                                       |
|   17 | Residency and enterprise compliance across many suppliers          | Solved with constraints                        | Narrow approved pools, documented processing paths, supplier agreements, evidence, independent review                              |
|   18 | Unified navigation and protocol complexity                         | Solved by abstraction                          | Stable resource model and progressive disclosure; this is not the main technical risk                                              |

The most dangerous failure is not that one integration breaks. It is **selling a stronger abstraction than the underlying qualification, capacity, and operating model can support**.

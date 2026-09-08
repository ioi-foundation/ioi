# 030 — Control plane: system architecture, desired state, plans, reconciliation, events

**Spec sections:** 11, 12, 22. **Depends on:** 010, 170, 180. **Defines:** desired
state, plans, operations, reconcilers, retries, finalizers; how work resumes after
crashes; controller contract, operation journal, plan execution; event identities,
ordering, replay, deduplication. **Required diagrams:** reconciliation loop, saga,
crash boundaries; outbox, delivery, replay, correction.

## 11. System architecture

### 11.1 Selected architecture

Use a **cell-based, logically centralized control plane with federated data-plane foundations and decentralized/federated workload supply**.

```text
Console / CLI / SDK / Terraform / AI
                    │
             Unified Cloud API
                    │
         Project home control-plane cell
                    │
    Resource registry + plans + reconciliation
                    │
     ┌──────────────┼───────────────┐
 Provider supply   Network fabric   Data services
     │                 │                │
 Akash / direct    Gateways/relays   Hot storage cells
 GPU networks      DNS/TLS/CDN       Databases/archives
                    │
            Financial control plane
         Pricing / ledger / settlement
```

### 11.2 What remains centralized

| Subsystem              | Initial model                                            | Reason                                             |
| ---------------------- | -------------------------------------------------------- | -------------------------------------------------- |
| Public API             | Platform-operated, replicated                            | Coherent authorization and resource semantics      |
| Scheduler              | Platform-operated per cell                               | Enforce customer policy and commercial commitments |
| Identity               | Platform-operated, enterprise federation supported       | One accountable identity boundary                  |
| Resource registry      | Platform-operated                                        | Authoritative desired state                        |
| Control-plane database | Platform-operated, quorum-protected                      | Reliable mutation and recovery                     |
| Billing ledger         | Centralized authority                                    | One correct customer account and invoice           |
| Secrets/KMS            | Platform-controlled trust boundary                       | Providers must not hold platform root keys         |
| Provider reputation    | Platform-operated evidence system                        | Qualification requires accountable decisions       |
| Observability          | Federated regional pipelines, platform-controlled access | Residency and scale                                |
| DNS                    | Federated authoritative infrastructure                   | Avoid a single serving implementation              |
| Ingress                | Multiple qualified edge operators                        | Stable endpoints across compute suppliers          |
| Settlement             | Hybrid                                                   | Platform treasury interacts with native protocols  |
| Compute supply         | Decentralized/federated                                  | Open supplier participation                        |
| Storage foundations    | Federated, qualified operators                           | Stronger controls than arbitrary ephemeral supply  |

"Centralized" here means one governing authority, not one server.

### 11.3 Logical service decomposition

The following are ownership boundaries, not a requirement to launch twenty-five independently deployed microservices.

**Availability classes:** `Serving` means directly required for live requests; `Control` means required for changes; `Async` means delay is acceptable but loss is not.

| Service                     | Owned state and API                                 | Consumes → produces                                      | Consistency / availability / boundary               |
| --------------------------- | --------------------------------------------------- | -------------------------------------------------------- | --------------------------------------------------- |
| API Front Door              | Sessions, request limits; public API routing        | Requests → authenticated commands                        | Stateless replicas; Control; no treasury keys       |
| Identity & Authorization    | Principals, bindings, policy decisions              | Identity assertions → authorized scopes                  | Strong mutation checks; Control; security boundary  |
| Resource Registry           | Resource specs, versions, ownership, references     | Commands → resource events                               | Transactional per home cell; Control                |
| Plan Service                | Immutable plans, diffs, approvals                   | Resource intent → approved plan                          | Strong version binding; Control                     |
| Deployment Controller       | Rollout state, service target revisions             | Approved plans/health → workload claims                  | Durable reconciliation; Control                     |
| Placement Engine            | Placement decisions and explanations                | Claims/capacity/policy → selected candidates             | Snapshot-based planning with final revalidation     |
| Market Aggregator           | Normalized offer observations                       | Adapter feeds → offer snapshots                          | Eventual; Async; observations are not reservations  |
| Provider Registry           | Operators, facilities, capabilities, qualification  | Evidence/health → eligibility changes                    | Strong admission reads; Control                     |
| Acquisition Controller      | Allocation and external-effect journals             | Placements/grants → acquired resources                   | Durable side-effect state; Control                  |
| Provider Gateway            | Registered agents and scoped channels               | Agent reports → normalized observations                  | Untrusted-provider boundary                         |
| Protocol Adapters           | Native references and protocol observations         | Acquire/release requests → native outcomes               | Isolated credentials and bounded egress             |
| Network Controller          | Connections, routes, endpoint generations           | Resource/health changes → signed network config          | Strong intent, eventual distribution; Control       |
| Edge Gateways               | Active routing configuration                        | Traffic → responses and trusted traffic meters           | Serving; tenant isolation                           |
| Storage Controller          | Bucket/volume policy, replica intent, archive jobs  | Data requests/health → storage actions                   | Strong metadata; Control                            |
| Data Service Cells          | Object/block/database operational state             | Data requests → durable responses                        | Serving; qualified trust boundary                   |
| DNS/Certificate Controller  | Ownership checks, records, certificates             | Endpoint/domain events → DNS/TLS state                   | Durable retries; Control                            |
| Workload Identity & Secrets | Credential grants, secret versions                  | Attested or provider-bound identity → scoped credentials | Security-critical; no model access to roots         |
| Health & Incident Service   | Observations, incidents, SLO evaluations            | Probes/telemetry → health events                         | Eventual observations; bounded detection            |
| Telemetry Pipeline          | Logs, metrics, traces, retention                    | Workload/edge telemetry → queryable records              | Async ingestion; independent from billing authority |
| Pricing Service             | Rate cards, quote versions, cost models             | Requirements/offers → quotes                             | Immutable accepted quote terms                      |
| Metering Service            | Raw usage intervals and corrections                 | Trusted meters/allocation state → rated usage            | Deduplicated append-only records                    |
| Ledger & Billing            | Accounts, holds, journals, invoices                 | Usage/payments → balances and invoices                   | Strong financial transactions                       |
| Treasury & Settlement       | Wallet operations, native funds, settlement intents | Approved supplier obligations → native transactions      | HSM boundary; serialized nonce/sequence lanes       |
| Audit & Notifications       | Audit records, delivery attempts                    | Commands/events → audit and notifications                | Append-only records; Async                          |

### 11.4 Initial deployment grouping

Start with roughly eight deployable groups:

```text
console-api
core-control
identity-secrets
provider-connect
network-fabric
data-services
money
telemetry
```

Within groups, retain explicit module ownership and separate privileged credentials.

Use Go for control-plane services and provider integration, TypeScript for the console and primary SDK, PostgreSQL for authoritative relational state, and a durable event broker. Do not build a universal blockchain-based metadata database.

> **Estate note (ADR 0001 §5):** the named stack is the selected architecture where nothing existing fits. Where an existing daemon plane already satisfies a contract here, reusing it behind the adapter boundary in 040 is preferred.

## 12. Control plane

### 12.1 Authoritative state

Use PostgreSQL in each home control-plane cell.

Each resource has:

```text
id
organization_id
project_id
kind
spec
generation
resource_version
status
observed_generation
conditions[]
deletion_timestamp
finalizers[]
created_at
updated_at
```

`spec` is desired state. `status` is observed state. Controllers must never rewrite desired state merely to match a malfunctioning provider.

Use optimistic concurrency for mutations and watch-style change propagation. Kubernetes' API documentation provides a useful precedent for resource-version concurrency and resumable watches; the public API should retain those semantics without requiring customers to use Kubernetes objects. ([Kubernetes][2])

### 12.2 Plans and execution envelopes

A Plan contains:

```text
resolved resource revisions
immutable image/model digests
dependency graph
policy versions and hashes
selected placement or bounded placement alternatives
price quote and expiry
maximum customer spend
maximum permitted surge
disruption and data-movement limits
required permissions
rollback/compensation description
approval requirements
```

Execution is allowed only while the plan remains valid.

Policy changes, expired quotes, changed dependencies, or modified resources can invalidate a plan.

Automatic repair operates within a previously approved **Execution Envelope**. A repair requiring a new jurisdiction, weaker trust, higher retail ceiling, or destructive data action becomes a new approval request.

### 12.3 Reconciliation

```text
Resource change
→ enqueue resource ID
→ read current authoritative state
→ obtain short controller lease
→ compare desired and observed state
→ record next operation step
→ perform bounded external action
→ persist outcome
→ update status and outbox
→ requeue until converged
```

The queue accelerates work. Periodic sweeps recover missed messages.

Use a durable operation-step journal rather than relying on an in-memory job worker.

### 12.4 Idempotency

Public mutation rules:

* Every consequential request accepts an idempotency key.
* The key binds to a canonical request hash.
* Repeating the same request returns the original operation.
* Reusing the key with a different body returns a conflict.
* Financial and provider-effect identities survive ordinary request-cache expiry.

External action rules:

```text
Persist intent
→ derive stable external-effect ID
→ invoke provider/native transaction
→ persist or discover outcome
```

A timeout means **unknown outcome**, not "nothing happened."

Before retrying acquisition, query by native transaction hash, provider resource ID, or owned intent tag. Reuse identical signed transaction bytes where appropriate rather than creating a second purchase.

### 12.5 Events and transactions

Write the resource mutation and outbox record in one database transaction.

Publish the outbox to NATS JetStream. Consumers acknowledge only after their durable effect or deduplication record commits. JetStream provides persisted, replayable at-least-once delivery; it does not make arbitrary external side effects exactly once. ([NATS Documentation][3])

### 12.6 Partial provisioning and compensation

Provisioning is a saga:

```text
Funds held
→ capacity acquired
→ network established
→ data attached
→ workload started
→ health verified
→ traffic admitted
```

On failure, compensate in reverse dependency order where safe:

```text
remove traffic
revoke credentials
stop workload
detach data safely
release acquired capacity
release unused funds
retain data under its retention policy
```

Some charges cannot be reversed. Record them as supplier expense or customer-authorized charges according to the quote.

### 12.7 Deletion and orphans

Deletion first writes a tombstone and stops future reconciliation toward "running."

Finalizers track:

```text
traffic removed
credentials revoked
workload stopped
data disposition completed
provider allocation absent or closed
financial obligation recorded
```

An unreachable provider produces **Cleanup pending**, not a false claim that everything was deleted.

A separate inventory reconciler compares native resources with the platform registry and identifies untracked or unexpectedly retained resources.

### 12.8 Control-plane outages

Existing workloads continue using valid local routing, identity, and execution grants for their approved continuity window.

There is an explicit tradeoff between offline continuity and revocation freshness. Sensitive profiles use shorter authorization freshness limits and fail closed when necessary.

Disaster recovery restores the database, journals, and object metadata, then reconciles native inventory **before enabling new purchases or destructive cleanup**. Where an asynchronous disaster-recovery copy may have lost recent desired-state changes, the platform freezes uncertain actions rather than guessing.

## 22. Event model

Use CloudEvents-compatible envelopes. CloudEvents specifies a unique `source` plus `id` identity and permits duplicate delivery to reuse that identity, which fits the required consumer deduplication model. ([GitHub][18])

Example:

```json
{
  "specversion": "1.0",
  "id": "evt_...",
  "source": "urn:cloud:deployment-controller:cell-us1",
  "type": "cloud.allocation.ready.v1",
  "subject": "allocation/alloc_...",
  "time": "2026-09-07T18:30:00Z",
  "organizationid": "org_...",
  "projectid": "prj_...",
  "correlationid": "op_...",
  "causationid": "evt_previous",
  "aggregateversion": 17,
  "data": {
    "attemptId": "attempt_...",
    "observedGeneration": 4
  }
}
```

### Major events

| Event family                                       | Main consumers                        |
| -------------------------------------------------- | ------------------------------------- |
| `resource.created/updated/deletion_requested`      | Controllers, audit, search            |
| `plan.created/invalidated/approved`                | Operations, ledger, audit             |
| `deployment.planned/started/ready/failed`          | Console, notifications, observability |
| `placement.requested/selected/blocked`             | Acquisition, incident service         |
| `allocation.reserved/acquiring/provisioning/ready` | Deployment, networking, metering      |
| `allocation.failed/release_requested/released`     | Recovery, ledger, orphan reconciler   |
| `workload.started/stopped/checkpointed`            | Jobs, telemetry, metering             |
| `health.degraded/recovered`                        | Incident service, routing, recovery   |
| `provider.unreachable/quarantined/eligible`        | Scheduler, acquisition, incidents     |
| `migration.started/completed/blocked`              | Console, deployment, billing          |
| `storage.degraded/repair_started/protected`        | Recovery, incident service            |
| `endpoint.config_published/config_acknowledged`    | Deployment readiness                  |
| `usage.recorded/corrected/rated`                   | Ledger, billing, usage views          |
| `invoice.finalized/adjusted`                       | Payments, notifications               |
| `settlement.submitted/finalized/disputed`          | Ledger, provider statements           |
| `policy.changed/violation_detected`                | Admission, controllers, security      |

Ordering is guaranteed only within the documented aggregate or partition. Consumers compare generation and version.

A late `allocation.ready` event from an obsolete attempt must not resurrect that attempt.

Events contain references, not secret values. High-volume logs and metrics use dedicated telemetry pipelines rather than the control-event stream.

[2]: https://kubernetes.io/docs/reference/using-api/api-concepts/
[3]: https://docs.nats.io/nats-concepts/jetstream
[18]: https://github.com/cloudevents/spec/blob/main/cloudevents/spec.md

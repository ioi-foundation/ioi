# 010 — Resource model: primitives, canonical data model, state machines

Status: adopted product specification (owner, 2026-09-08); design baseline September 7, 2026.
Canonical owner: this file for the cloud primitive model, canonical data model and state machines.
Doctrine status: canonical
Implementation status: planned (the selected architecture, adopted 2026-09-08; nothing here is a claim that the product exists — what the Hypervisor daemon implements today is in `../cloud.md`)

**Spec sections:** 3, 21, 23. **Depends on:** 000. **Defines:** canonical identity and
ownership; what survives migration; what cascades on deletion; resource schemas,
references, ownership rules; lifecycle state transitions. **Required diagrams:**
ownership tree, dependency graph, identity lifetimes.

## 3. Cloud primitive model

### 3.1 Ownership hierarchy

Use this hierarchy:

```text
Organization
├── Billing Account
├── People, Teams, Service Accounts
├── Organization Policies
├── Shared Provider Pools
├── Budgets and Commitments
└── Projects
    ├── Applications
    │   ├── Services
    │   ├── Deployment Revisions
    │   └── References to project resources
    ├── Jobs and Job Runs
    ├── Compute Instances
    ├── Clusters
    ├── Data Resources
    │   ├── Databases
    │   ├── Caches
    │   ├── Queues
    │   ├── Buckets
    │   ├── Volumes
    │   └── Archives
    ├── Networks and Endpoints
    ├── Domains
    ├── Identities, Secrets, and Policies
    ├── Placement Policies
    └── Observability Configuration
```

**Organization** is the commercial and administrative boundary.

**Project** is the primary authorization, quota, resource-ownership, and residency boundary. Each project has a home control-plane cell.

Use separate projects for production and development when isolation matters. An `environment=production` label is useful for filtering, but **a label is not a security boundary**.

An application is a dependency graph over project resources. A bucket or database can be shared by several applications through explicit references. Deleting an application does not automatically delete shared data.

### 3.2 Canonical primitives

| Primitive          | Meaning                                                             | Important boundary                                      |
| ------------------ | ------------------------------------------------------------------- | ------------------------------------------------------- |
| Application        | A named, deployable system composed of services and dependencies    | Does not own every referenced resource                  |
| Service            | Stable identity for a continuously running component                | Survives rollout and provider replacement               |
| Deployment         | Immutable application/service revision plus rollout status          | Editing creates a new revision                          |
| Job                | Definition of finite work                                           | Separate from individual executions                     |
| Job Run            | One execution with attempts, results, and checkpoints               | Retries do not create a new logical job                 |
| Compute Instance   | Directly managed VM, GPU machine, or bare-metal allocation          | Exposes more infrastructure responsibility              |
| Cluster            | A supported orchestration boundary                                  | Not an arbitrary collection of Internet-connected nodes |
| Model Version      | Immutable model artifact and runtime compatibility metadata         | Not a separate storage system                           |
| Inference Endpoint | Managed service profile with model-serving controls                 | Backed by Services and allocations                      |
| Bucket             | Object namespace with a defined consistency and durability contract | Not a filesystem or block device                        |
| Volume             | Block or filesystem resource with explicit attachment semantics     | Locality and writer rules are mandatory                 |
| Database           | Managed engine, replication, backup, and failover contract          | Stronger operational responsibility than a container    |
| Network            | Connectivity and policy namespace                                   | Declares service-connect or routed capabilities         |
| Endpoint           | Stable ingress, private-service, or egress address                  | Independent of provider addresses                       |
| Placement Policy   | Hard constraints and optimization preferences                       | Versioned and explainable                               |
| Provider Pool      | Eligible supplier set selected by predicates or membership          | Does not itself reserve capacity                        |
| Reservation        | Contractually held capacity over an interval                        | Distinct from advertised availability                   |
| Plan               | Immutable proposed changes and execution limits                     | Bound to policy and price versions                      |
| Operation          | Durable execution of an approved plan                               | Contains retries and external-effect records            |

### 3.3 Internal implementation primitives

Keep these out of the default creation flow:

```text
ResourceClaim
LogicalReplicaSlot
WorkloadAttempt
Allocation
ProviderLease
CapacityHold
ExternalEffect
ExecutionGrant
NetworkAttachment
StorageReplica
SettlementIntent
```

A stable replica slot might be `api/replica-2`. Its current attempt could move from `attempt-17` on provider B to `attempt-18` on provider D.

**The service identity remains unchanged; the attempt identity must change.**

## 21. Canonical data model

All tenant-owned records carry organization, project, home-cell, ownership, and lifecycle metadata where applicable.

| Object                  | Important fields and relationships                                         | Authority                                |
| ----------------------- | -------------------------------------------------------------------------- | ---------------------------------------- |
| Organization            | ID, billing account, policy root, identity federation                      | Core                                     |
| Project                 | Organization, home cell, residency, quotas, protection flags               | Core                                     |
| Principal               | Type, external identity, status                                            | Identity                                 |
| RoleBinding             | Principal, role, scope, conditions                                         | Identity                                 |
| PolicyVersion           | Immutable content, hash, parent scope, approval                            | Policy                                   |
| Application             | Project, name, service/resource references                                 | Core                                     |
| Service                 | Desired revision, replica policy, identity, connections                    | Core                                     |
| Deployment              | Immutable revision, artifact digests, plan, rollout status                 | Core                                     |
| Job / JobRun            | Template, inputs, attempts, checkpoint/result references                   | Core                                     |
| ModelVersion            | Artifact digest, format, license metadata, runtime compatibility           | Core + object artifacts                  |
| ComputeInstance         | Runtime profile, desired state, allocation references                      | Core                                     |
| ResourceClaim           | Required capabilities, quantities, locality, policy version                | Core                                     |
| Plan                    | Resolved changes, quote, hash, expiry, approvals                           | Core                                     |
| Operation               | Plan, actor, state, step journal, result                                   | Core                                     |
| ExternalEffect          | Stable intent ID, native request/transaction references, uncertainty state | Acquisition/settlement journal           |
| LogicalReplicaSlot      | Service, slot identity, current attempt                                    | Core                                     |
| WorkloadAttempt         | Slot/run, generation, allocation, identity, start/end                      | Core                                     |
| Allocation              | Provider, physical resources, accepted terms, observed state               | Core                                     |
| ProviderLease           | Allocation, native references, lifecycle, financial obligations            | Adapter state                            |
| Provider                | Operator group, identities, facilities, qualification                      | Provider registry                        |
| OperatorGroup           | Beneficial-control evidence and related providers                          | Provider registry                        |
| Facility                | Location evidence, jurisdiction, failure-domain relationships              | Provider registry                        |
| CapabilityEvidence      | Claim, subject, issuer, method, timestamps, expiry                         | Evidence store                           |
| Offer                   | Provider, normalized resources, native price, terms, observation time      | Observed market cache                    |
| Reservation             | Capacity, interval, guarantees, cancellation, supplier obligation          | Core + ledger                            |
| Region / LatencyCell    | Contract version, boundaries, members, service classes                     | Core                                     |
| FailureDomain           | Type, membership, dependencies, confidence                                 | Core/evidence                            |
| Bucket                  | Class, storage cell, policy, encryption/retention configuration            | Core; object namespace in storage engine |
| Volume                  | Type, cell, size, writer, fencing generation, snapshots                    | Core + storage engine                    |
| ArchiveManifest         | Immutable versions, ciphertext refs, copies, proofs, retention             | Core + replicated object metadata        |
| Network                 | Mode, scope, connections, policies                                         | Core                                     |
| Endpoint                | Stable name/address, route generation, backend service                     | Core                                     |
| Domain                  | Ownership proof, DNS records, endpoint, certificate refs                   | Core                                     |
| SecretVersion           | Encrypted value reference, key version, consumer grants                    | Secrets system                           |
| UsageRecord             | Meter, interval, integer quantity, source sequence, evidence               | Metering                                 |
| Quote / RateCardVersion | Currency, units, validity, fixed/variable terms                            | Pricing                                  |
| SpendGrant              | Account, plan/allocation, ceiling, expiry, consumption                     | Ledger                                   |
| JournalEntry            | Balanced postings, source event, immutable audit identity                  | Financial ledger                         |
| Invoice                 | Period, immutable line items, credits, payment status                      | Billing                                  |
| Settlement              | Native obligation, transaction state, finality, reconciliation             | Settlement                               |
| HealthObservation       | Subject, source, measurement, time, confidence                             | Health store                             |
| AuditEvent              | Actor, action, authorization, target, result, plan/operation               | Audit                                    |
| OutboxEvent             | Aggregate, version, payload reference, publication status                  | Owning database                          |

Search indexes, dashboards, topology views, and provider rankings are materialized views. They are never authoritative for authorization, spending, or deletion.

## 23. State machines

### 23.1 Deployment revision

```text
DRAFT
  → PLANNING
  → AWAITING_APPROVAL
  → QUEUED
  → PROVISIONING
  → VERIFYING
  → READY

PLANNING / QUEUED / PROVISIONING
  → BLOCKED
  → resume previous stage after resolution

Any pre-ready stage
  → FAILED or CANCELED

READY
  → SUPERSEDED
```

A failed new revision does not necessarily make the currently serving application unavailable.

### 23.2 Service

Separate lifecycle, health, and operation:

```text
Lifecycle:
ACTIVE → DELETING → DELETED

Health:
UNKNOWN / HEALTHY / DEGRADED / UNAVAILABLE

Current operation:
NONE / UPDATING / SCALING / REPAIRING / MIGRATING
```

User presentation can therefore be:

> Healthy · Updating

or:

> Available with reduced redundancy · Repairing

### 23.3 Allocation

```text
REQUESTED
→ RESERVED, when supported
→ ACQUIRING
→ ACQUIRED
→ PROVISIONING
→ RUNNING
→ DRAINING
→ RELEASING
→ RELEASED
```

Additional states:

```text
ACQUISITION_UNCERTAIN
OBSERVATION_STALE
FAILED
RELEASE_UNVERIFIED
```

### 23.4 Jobs

```text
QUEUED → PROVISIONING → RUNNING → SUCCEEDED
                           ├→ CHECKPOINTING → RUNNING
                           ├→ RETRYING → PROVISIONING
                           ├→ FAILED
                           └→ CANCELING → CANCELED
```

Retries may repeat external application effects unless the application uses idempotent work units or transactional result publication.

### 23.5 Data

```text
CREATING → AVAILABLE
AVAILABLE → DEGRADED → REPAIRING → AVAILABLE
AVAILABLE → RESTORING
AVAILABLE → DELETING → DELETED
Any relevant state → ACTION_REQUIRED
```

For block volumes, attachment and writer ownership are separate state dimensions.

### 23.6 Financial state

```text
Customer:
AUTHORIZED → COMMITTED → ACCRUED → INVOICED → PAID
                                  └→ ADJUSTED

Supplier:
OBLIGATION_RECORDED
→ FUNDED / SUBMITTED
→ OBSERVED
→ FINALIZED
→ RECONCILED
```

Financial settlement can remain pending after a workload is running or stopped. The console must not conflate these states.

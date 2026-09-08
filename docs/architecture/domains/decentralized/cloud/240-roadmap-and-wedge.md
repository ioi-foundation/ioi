# 240 — Roadmap and wedge: MVP phases, release gates, the initial market

**Spec sections:** 30, 31. **Depends on:** all implementation specifications.
**Defines:** deployment groups, service ownership, releases, capacity management, and
go/no-go gates. **Required diagrams:** deployment topology, release waves, dependency
failures.

## 30. MVP roadmap

| Phase                                   | UX shipped                                                                                                                                                       | Backend and protocols                                                                                                                                                                       | Resource types                                                                                          | Operational burden and risks                                                                                     | Acceptance criteria                                                                                                                                                                                                                      |
| --------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **0 — End-to-end prototype**            | Account/project creation; deploy one container or GPU workload; progress timeline; endpoint; logs; placement inspector; delete                                   | Core registry, one acquisition adapter, direct-provider path, minimal gateway, payment sandbox plus bounded live supplier funding, basic ledger; small Filecoin export/retrieval experiment | Service, Job, Bucket reference, Endpoint, Allocation                                                    | Native acquisition uncertainty, networking compatibility, untracked spend                                        | Real workload runs; endpoint verified externally; every external effect tracked; deletion reconciled; crash tests around acquisition do not create untracked purchases                                                                   |
| **1 — Credible developer cloud**        | Application-first console; GPU inference/jobs; private object storage; domains/TLS; logs/metrics; USD billing; budgets; basic provider console; placement detail | Akash adapter + direct provider adapter; qualified hot storage cell; production identity/secrets; resilient gateways; treasury/reconciliation; archive integration where qualified          | Services, Jobs, Inference Endpoints, Models, Buckets, Service Networks, Domains, Policies, Reservations | 24/7 on-call; GPU supply qualification; storage operations; payment fraud; recovery capacity; real support costs | Non-crypto customer completes full lifecycle; single qualified provider-loss drill passes; no cross-tenant access; repeated usage delivery causes no double charge; all invoices reconcile to usage; sustained pilot SLO target measured |
| **2 — Serious infrastructure platform** | Direct instances, managed databases, routed networking, clusters, advanced market, topology history, enterprise IAM, Terraform, policy simulation                | More GPU networks; managed data operators; routed fabric; replicated block; multi-cell control; more edge/storage providers                                                                 | VMs, Clusters, PostgreSQL, caches, queues, volumes, shared filesystems, advanced reservations           | Stateful failover, network variability, upgrades, regional incident response, enterprise controls                | Safe fencing tests; restore tests; qualified cross-provider database topology; schema upgrade rollback procedures; verified residency paths; capacity-reservation conformance                                                            |
| **3 — Decentralized hyperscaler**       | Broader managed services, functions, workflows, enterprise portfolios, federated control options, expanded geography                                             | Many qualified networks; broader service cells; advanced scheduling and procurement; optional customer-operated control/data components                                                     | Broad cloud primitives composed from the established model                                              | Fleet-wide reliability, complex compliance, correlated supplier failures, large financial exposure               | Service-specific SLOs supported by measurements; independently exercised DR; sustainable delivered margins; no weakening of canonical contracts as supply expands                                                                        |

### Release gates

No phase advances merely because its console screens exist.

Required gates include:

```text
correctness under controller restart
unknown acquisition outcome recovery
no untracked resources
no duplicate customer charges
safe stateful fencing
independent restore
tenant isolation
policy enforcement after rescheduling
pricing under failure and low utilization
supplier and customer financial reconciliation
```

Phase 1 should omit native managed databases rather than ship a database container disguised as a resilient database service. It can support external database connections while the managed database product is qualified.

## 31. Initial wedge

**Choose managed GPU inference, with batch inference as the first workload focus.**

The initial customer is an AI team that already has a model or container and wants to run substantial inference work without sourcing machines, moving tokens, manually maintaining deployments, or rebuilding its workflow around one GPU vendor.

The first product promise:

> Submit a model and input dataset. The cloud finds eligible GPU capacity, runs the workload, preserves outputs, retries safely, and provides a predictable USD bill.

Then extend the same primitives into persistent GPU-backed endpoints.

### Why this wedge

Batch inference permits queueing, checkpointed progress, retryable units, and throughput-oriented placement. It exercises the platform's core differentiators without making interactive global latency or tightly coupled distributed training prerequisites.

The deliverable is not merely cheaper hardware. It is:

```text
qualified GPU execution
portable model and data artifacts
automatic recovery
controlled cost
consistent observability
one integration and one bill
```

### Commercial validation

Measure:

```text
cost per completed useful work unit
customer integration time
completion-time distribution
failure/retry overhead
model-transfer overhead
GPU utilization
gross margin after support, idle reserves, and settlement costs
customer willingness to repeat workloads
```

The expansion path is:

```text
Batch inference
→ persistent inference endpoints
→ supporting application services
→ managed data
→ broader infrastructure platform
```

### Genuine differentiation versus marketing

| Claim                                             | Assessment                                                                                   |
| ------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| Aggregate independent supply through one contract | Genuine architectural/product capability                                                     |
| Expose provider provenance and independence       | Genuine if evidence is maintained                                                            |
| Move logical services between operators           | Genuine within supported runtime and data contracts                                          |
| Lower total cost                                  | Must be demonstrated after overhead and failures                                             |
| Better availability than hyperscalers             | Not inherent; requires dependency diversity and operational evidence                         |
| No vendor lock-in                                 | Too strong; reduce lock-in through exportable manifests, standard APIs, and data portability |
| Trustless cloud                                   | Incorrect for this architecture                                                              |
| AWS could never build this                        | Incorrect; differentiation is also economic incentives, openness, and execution              |

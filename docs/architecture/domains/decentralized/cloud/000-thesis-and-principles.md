# 000 — System overview: thesis, principles, decisions

Status: adopted product specification (owner, 2026-09-08); design baseline September 7, 2026.
Canonical owner: this file for the thesis, product principles and critical decisions.
Doctrine status: canonical
Implementation status: planned (the selected architecture, adopted 2026-09-08; nothing here is a claim that the product exists — what the Hypervisor daemon implements today is in `../cloud.md`)

**Spec sections:** 1, 2, 33, 34. **Depends on:** none. **Defines:** system boundaries,
trust domains, phases, responsibility; the twenty critical decisions.

## 1. Executive thesis

**Build an application-first cloud whose infrastructure is purchased from an open provider market, but whose service contracts, identities, networking, data guarantees, and customer experience belong to the cloud platform.**

The product is not a collection of integrations with decentralized networks. It is a **logical cloud over replaceable physical infrastructure**.

A customer creates an application, declares its requirements, receives a deployment plan and a USD price, and deploys. The platform acquires infrastructure, establishes connectivity, provisions storage, delivers credentials, verifies health, maintains the application, and produces one bill. Provider selection and protocol settlement are implementation details unless the customer chooses to inspect them.

The central architectural separation is:

```text
Stable customer resources
    Application, Service, Endpoint, Bucket, Database, Identity
                              │
                    Desired-state control plane
                              │
Replaceable implementation resources
    Workload attempts, allocations, provider leases, tunnels, replicas
                              │
                  Heterogeneous infrastructure supply
```

**An application must not inherit the lifecycle of a provider lease.** Its identity, endpoint, deployment history, access policy, and retained data must survive replacement of that lease.

Three decisions make this practical.

**First, centralize responsibility before decentralizing control.** Initially, the company operates the API, scheduler, IAM, financial ledger, secrets service, and authoritative metadata. These services are highly available, but not permissionless. Infrastructure supply is decentralized or federated. The company remains accountable for the customer-facing service.

**Second, standardize contracts, not fictional hardware equivalence.** Providers qualify for explicit capability profiles: container execution, GPU execution, routed networking, service tunnels, replicated storage, confidential execution, and so forth. Unsupported capabilities fail admission. The platform never silently substitutes provider-local disk for resilient storage or a TCP tunnel for a full private network.

This distinction is operationally necessary. Akash's documentation explicitly describes persistent storage as provider-local and warns that it does not survive provider migration or lease termination. Conversely, current Filecoin documentation includes warm-storage, retrieval, and proof-of-data-possession components; treating Filecoin as exclusively archival would also be inaccurate. Neither fact makes the two systems interchangeable with managed block storage. ([Akash Network][1])

**Third, sell explicit service outcomes.** Customers choose between economical execution and qualified resilience, between local scratch space and replicated persistent data, and between best-effort capacity and reservations. They do not choose between twenty protocol-specific mechanisms.

The primary navigation should therefore center on **Applications, Compute, AI, Data, Network, Observe, Security, and Supply**. Applications are the default entry point. Infrastructure remains directly accessible. Supply is inspectable without dominating normal workflows.

The first market should be **managed GPU inference, initially emphasizing batch inference and portable single-node workloads**. This uses heterogeneous supply without requiring the platform to solve arbitrary distributed training, worldwide low-latency storage, or transparent GPU live migration before earning revenue.

The defensible advantage is not "blockchain makes cloud cheaper." It is a combination of qualified capacity aggregation, provider competition, portable application identities, explicit infrastructure provenance, and recovery across independent operators. These advantages must survive the cost of networking, redundancy, support, working capital, and failed allocations.

**Design baseline:** September 7, 2026. The following is the selected architecture, not a claim that the product already exists. Prices and inventory in examples are illustrative. Performance numbers are proposed acceptance targets, not measured results.

## 2. Product principles

1. **Applications come first.** Infrastructure is accessible, but not mandatory knowledge.
2. **Logical identity outlives placement.** Replacement changes allocations, not the customer's service.
3. **One cloud contract, many suppliers.** The platform owns customer-facing behavior.
4. **Capabilities are explicit.** Unsupported semantics are rejected, not approximated silently.
5. **Persistence is independent of compute leases.** Local disks are labeled local.
6. **Resilience is a dependency property.** Replica counts alone do not establish survivability.
7. **Policy precedes price.** Cost optimization never relaxes residency, security, or durability requirements.
8. **USD is the default economic language.** Protocol currencies belong behind the financial boundary.
9. **Plan before consequential change.** Show cost, placement, disruption, and permission requirements.
10. **Every external effect is recoverable or visibly unresolved.** Unknown outcomes are not treated as failures that are safe to repeat.
11. **Normal operations are provider-independent.** Logs, metrics, endpoints, and history follow the workload.
12. **Advanced detail is always available.** Provenance is inspectable, not compulsory.
13. **Claims carry evidence and scope.** "Verified," "available," and "resilient" have precise meanings.
14. **The console is an API client.** CLI, SDKs, Terraform, and AI use the same control paths.
15. **No silent central-cloud fallback.** A fallback must satisfy the customer's approved supply policy.
16. **Ship a narrow, reliable cloud before a broad service catalog.**

## 33. Critical architectural decisions

|  # | Decision                         | Selected position                                                         |
| -: | -------------------------------- | ------------------------------------------------------------------------- |
|  1 | What is the product?             | A managed logical cloud, not a protocol dashboard                         |
|  2 | Default user abstraction         | Application and stable Service                                            |
|  3 | Security and ownership boundary  | Project, with organization-level policy and billing                       |
|  4 | Logical versus physical identity | Separate Service/Slot from Attempt/Allocation/Lease                       |
|  5 | Control-plane authority          | Platform-operated initially                                               |
|  6 | Authoritative database           | Transactional relational state, not blockchain state                      |
|  7 | Provider integration boundary    | Versioned capability contracts with conformance tests                     |
|  8 | Region semantics                 | Stable logical contracts over qualified latency cells                     |
|  9 | Failure-domain model             | Graph of operator, facility, network, storage, and protocol dependencies  |
| 10 | Scheduling priority              | Hard policy first, delivered cost second                                  |
| 11 | Capacity semantics               | Advertised, held, reserved, and allocated are distinct                    |
| 12 | Persistence boundary             | Independent of compute leases                                             |
| 13 | Hot storage foundation           | Qualified platform-operated storage cells                                 |
| 14 | Archive integration              | Encrypted versioned copies, not a hidden substitute for hot/block storage |
| 15 | Network abstraction              | Service Network by default; Routed Network only where supported           |
| 16 | Customer pricing                 | Fixed USD contracts by default; operator owns underlying volatility risk  |
| 17 | Financial correctness            | Separate metering, rating, ledger, invoicing, and native settlement       |
| 18 | Recovery authority               | Preapproved bounded envelopes; no silent policy weakening                 |
| 19 | AI authority                     | Read, propose, approve, execute through the same structured API           |
| 20 | Initial market                   | Managed GPU inference, beginning with batch workloads                     |

These decisions should become explicit architectural decision records. Changing one requires reviewing its downstream effects on product claims, qualification, billing, and recovery.

## 34. Final recommended architecture

I would build an **application-first managed cloud with a centralized, cell-based control plane; federated networking and persistence foundations; and decentralized/federated compute supply behind qualified adapters**.

The implementation center is:

```text
Stable application/service identities
                +
Transactional desired state and durable operations
                +
Capability-qualified provider acquisition
                +
Platform-controlled network endpoints
                +
Persistent data independent of compute leases
                +
USD financial ledger and native settlement isolation
```

Start with managed GPU inference and batch jobs, ordinary supporting containers, private replicated object storage, domains/TLS, workload identity, logs/metrics, and one USD bill.

Use Akash and a direct-provider integration as the first compute acquisition paths. Use dedicated qualified infrastructure for the initial hot storage and network foundations. Integrate Filecoin-backed storage through an explicit archive/export contract, with warm-storage expansion only after qualification.

Do not initially build arbitrary cross-provider Kubernetes, globally synchronous databases, universal GPU live migration, or a decentralized control-plane consensus system.

### Final test: the ordinary developer

The developer signs up, adds a card, creates a project, and selects **Deploy GPU application**.

The platform produces a plan containing the GPU service, replicated object data, public endpoint, TLS, observability, and the chosen resilience profile. The developer approves a USD quote.

One provider disappears. Surviving capacity continues the admitted service, subject to the documented handling of in-flight requests. The platform replaces the failed attempt, preserves data, updates routing, and keeps the same service identity and domain.

The developer sees:

> Provider capacity failed. Your application remains available with reduced redundancy. Replacement is in progress.

They receive one monthly USD bill. They never need to acquire tokens, inspect an escrow account, or understand which protocol supplied the machine.

**This test passes only when the purchased profile includes enough independent serving capacity and persistent-data protection. A single unreserved GPU cannot honestly promise the same continuity.**

### Final test: the infrastructure expert

The expert opens **Placement** and sees:

```text
Every replica and attempt
Physical operator and facility
Jurisdiction and evidence freshness
Hardware and runtime profile
Attestation status and limitations
Underlying supply protocol
Native allocation/lease reference
Observed supplier price and allocation basis
Accepted retail rate
Settlement status
Private and public network paths
Storage replicas and recovery state
Shared failure domains
Failure-simulation result
```

They export the plan, policy, resource manifest, and evidence references through the same API used by the console.

The advanced surface does not reveal a different cloud. It reveals the implementation of the same resources.

**The architecture to build is therefore not "decentralized AWS." It is one accountable cloud service over an open infrastructure market—with stable logical resources, explicit guarantees, and replaceable physical providers.**

[1]: https://akash.network/docs/learn/core-concepts/persistent-storage/

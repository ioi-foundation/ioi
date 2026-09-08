# 050 — Placement and supply: regions, latency cells, failure domains, pools, placement contracts, scheduling, resilience claims, provenance

**Spec section:** 10. **Depends on:** 040, 100, 190, 200, 260. **Defines:** candidate
discovery, constraint evaluation, delivered cost, and placement explanations; offer
schema, scheduler request/result, policy compiler. **Required diagrams:** filtering
pipeline, dependency placement, optimization.

## 10. Decentralized-cloud abstractions

### 10.1 Logical regions

**`us-east` is a versioned service contract over eligible facilities—not a claim that the platform owns an AWS-like region.**

A Region contains:

```text
Region
  stable ID and display name
  permitted geographic boundary
  permitted jurisdictions
  available service classes
  eligible latency cells
  control-plane and data-processing constraints
  evidence requirements
  current capacity and health summaries
```

Membership may change. The region's contractual boundary may not change silently.

### 10.2 Latency cells

Within a region, define **Latency Cells**: qualified groups of facilities suitable for tightly coupled services.

Example:

```text
US East
├── Ashburn-1 latency cell
├── New York Metro-1 latency cell
└── Additional qualified cells
```

A latency cell has measured path properties, supported storage classes, and admitted failure-domain combinations.

Do not form synchronous database or storage quorums across arbitrary cities merely because they share `us-east`.

### 10.3 Failure domains

Maintain a graph rather than a single availability-zone label:

```text
Beneficial operator group
Facility
Power dependency
Rack / host
Upstream network / ASN
Metro
Storage cell
Edge operator
Control-plane cell
Protocol / settlement network
```

Two provider wallets do not establish two independent operators.

Unknown ownership relationships are treated conservatively. A "three providers" deployment may still have one effective operator or one shared facility.

### 10.4 Provider pools

A pool is an eligibility expression or explicit membership set:

```yaml
name: production-us
requirements:
  jurisdictions: [US]
  operatorVerification: independent
  facilityEvidence: current
  runtimeProfiles: [container-standard]
  networks: [akash, direct]
exclusions:
  operatorGroups: []
preferences:
  deliveredCost: minimize
  measuredReliability: preferHigher
```

"Cheapest" and "lowest latency" are optimization preferences.

"US only," "confidential compute required," and "approved operators only" are hard constraints.

A renewable-energy preference must identify whether it is based on a provider claim, contractual energy procurement, or independently verified evidence. It must not imply measured per-workload carbon accounting without such a system.

### 10.5 Placement contracts

A Placement Policy combines:

```text
Eligibility
  hardware, runtime, trust, residency, locality

Diversity
  minimum independent operators
  facility anti-affinity
  allowed shared dependencies

Service objectives
  availability profile
  latency measurement scope
  recovery and interruption policy

Economics
  retail price ceiling
  total spend envelope
  spot/reserved/on-demand terms

Mobility
  permitted destinations
  data movement policy
  maximum disruption
  approval requirements
```

"H100 or better" is expanded into an explicit accelerator compatibility set plus memory and performance requirements. It is not a lexical comparison of product names.

### 10.6 Scheduling

The scheduler:

1. Resolves required capabilities.
2. Filters hard constraints.
3. Removes stale or insufficiently evidenced offers.
4. Evaluates dependency locality.
5. Evaluates failure-domain coverage.
6. Calculates delivered cost.
7. Produces a placement and acquisition plan.
8. Revalidates before purchase.

Optimize:

$$
C_{\text{delivered}}
=
C_{\text{compute}}
+
C_{\text{data}}
+
C_{\text{network}}
+
C_{\text{redundancy}}
+
C_{\text{startup/retry}}
+
C_{\text{platform}}
$$

A migration penalty prevents unnecessary movement for small, temporary price changes.

### 10.7 Resilience claims

The UI must distinguish:

* Number of copies.
* Number of independent operators.
* Availability after a stated failure.
* Capacity after that failure.
* Durability of acknowledged data.
* Time required to restore redundancy.

For example:

> Can continue serving the admitted traffic level after loss of any one qualified compute operator. Persistent data and ingress also have independent one-operator-failure coverage. Replacement capacity is reserved.

Do not display "survives two provider failures" simply because there are three replicas.

### 10.8 Provenance

Every evidence item includes:

```text
claim
subject
issuer
method
observation time
expiry
scope
verification result
limitations
```

The expert sees actual allocations, protocol references, hardware evidence, supplier prices, settlement state, network paths, and storage placement. The ordinary developer sees the resulting service contract.

# 040 — Provider abstraction: adapter contract, acquisition, agent, qualification; provider console

**Spec sections:** 19, 9. **Depends on:** 010, 030. **Defines:** native capability
translation and uncertainty; what an adapter may claim; adapter API, capability
manifest, normalized outcomes; the provider's own surface. **Required diagrams:**
acquisition lifecycle, native-state mapping.

> **Estate note (ADR 0001 §2):** the Hypervisor daemon is one adapter target under this
> contract, beside Akash and direct providers; wallet.network is one authority backend
> behind execution grants; Agentgres is one evidence source. The adapter contract
> states what each may claim.

## 19. Provider architecture

### 19.1 Adapter contract

Use a versioned interface:

```text
DescribeCapabilities(provider)
DiscoverOffers(query, cursor)
ValidateRequest(resourceClaim)
Quote(resourceClaim, offerRef)
Reserve(resourceClaim, quoteRef, externalEffectId)
Acquire(reservationOrQuote, executionGrant, externalEffectId)
Observe(nativeResourceRef)
Update(nativeResourceRef, supportedChange, externalEffectId)
Release(nativeResourceRef, externalEffectId)
ListOwnedResources(ownerScope)
GetUsage(nativeResourceRef, interval)
GetSettlement(nativeObligationRef)
```

Optional methods:

```text
Checkpoint
Restore
Fence
AttachVolume
ConfigureRoutedNetwork
ReserveGang
VerifyAttestation
```

The capability manifest explicitly marks unsupported methods.

### 19.2 Normalized result

```json
{
  "externalEffectId": "eff_...",
  "nativeResourceRef": {
    "network": "akash",
    "provider": "provider_...",
    "resource": "opaque-native-reference"
  },
  "state": "ACQUIRED",
  "finality": "FINALIZED",
  "observedAt": "2026-09-07T18:30:00Z",
  "capabilitiesSatisfied": [
    "container-standard",
    "service-connect"
  ],
  "evidenceRefs": ["evidence_..."]
}
```

Never reduce native state to a boolean `success`.

### 19.3 Acquisition semantics

An adapter declares whether reservation is:

```text
Unsupported
Soft indication
Provider-signed hold
Contractually reserved
Already allocated
```

Market offers are not treated as capacity locks.

Gang acquisition is a bounded saga. Partial acquisitions are either completed within deadline or released with costs recorded. No fictional cross-protocol atomic transaction is assumed.

### 19.4 Provider agent

The direct-provider agent:

```text
enrolls using a one-time token
establishes mTLS
reports inventory and capability evidence
receives scoped allocation instructions
launches approved runtime bundles
reports health and usage
enforces maintenance/admission state
supports inventory reconciliation
```

It has no access to customer organization administration or platform treasury.

For protocol-native providers, the adapter uses supported native APIs. An optional workload connector may provide telemetry and service networking without requiring installation of the platform's full node agent.

### 19.5 Qualification

Qualify capabilities independently:

```text
hardware identity
runtime compatibility
tenant isolation
network behavior
storage behavior
performance envelope
geographic evidence
operational response
settlement correctness
```

Benchmarks and probes are run only on enrolled infrastructure under provider authorization.

Reputation is capability- and location-specific. Display observation window, sample size, confidence, and known incidents rather than a single unexplained score.

### 19.6 Protocol failures

Each adapter defines:

```text
finality model
transaction replacement rules
halt behavior
reorganization/invalidated-evidence behavior
escrow depletion behavior
provider termination behavior
refund and residual-obligation semantics
```

Not every blockchain has the same reorganization model. A protocol halt may block new acquisition or settlement without immediately stopping already-running workloads.

## 9. Provider-console UX

The Provider Console is a separate product surface because the provider's responsibilities differ from the customer's.

### Navigation

```text
Overview
Infrastructure
  Nodes
  Accelerators
  Local Storage
Capacity & Offers
  Available Capacity
  Offers
  Reservations
Workloads
Networking
Storage Services
Health & Maintenance
Trust
  Organization Identity
  Facilities
  Attestations
  Qualification
Earnings
  Usage
  Statements
  Payouts
  Settlements
  Disputes
API & Agents
Team & Settings
Support
```

### Provider onboarding

```text
Create provider organization
→ verify operator identity
→ register facilities
→ establish payout method or protocol identity
→ register node using one-time enrollment
→ inventory hardware and software
→ perform consented qualification tests
→ validate network capabilities
→ assign eligible service profiles
→ publish bounded offers
→ receive probationary workloads
→ expand admission limits as evidence accumulates
```

Permissionless registration does not mean immediate eligibility for sensitive production workloads.

### Key provider experiences

**Infrastructure:** hardware inventory, driver/runtime versions, allocation eligibility, attestation freshness, agent status, and quarantine reasons.

**Capacity:** advertised, held, reserved, and allocated capacity appear separately. An operator cannot represent the same physical device as independently available through several accounts without triggering inventory conflict checks.

**Offers:** exact hardware profile, interval, interruption terms, networking allowances, minimum duration, cancellation behavior, and settlement mechanism.

**Maintenance:** impact preview identifies workloads and reservations. The provider requests a maintenance window; the platform drains or relocates eligible workloads before admission closes.

**Workloads:** provider-visible resource requirements and operational state. Customer secrets, application data, and unrestricted customer logs are not exposed through the portal.

**Earnings:** accrued supplier compensation, finalized compensation, disputes, withholding under agreed terms, and actual payouts. These are not conflated with the customer's retail bill.

**Reputation:** measurements, qualification decisions, and appeal mechanisms. A provider should be able to distinguish a hardware failure from a platform-wide protocol incident.

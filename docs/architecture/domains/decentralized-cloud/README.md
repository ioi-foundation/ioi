# decentralized.cloud — product and architecture specification

**Status:** adopted by the owner on 2026-09-08 as the shaping specification for
decentralized.cloud. **Design baseline:** September 7, 2026. This is the selected
architecture, not a claim that the product already exists. Prices and inventory in
examples are illustrative. Performance numbers are proposed acceptance targets, not
measured results.

**What this tree is.** The owner's specification, split into the architecture documents
its own section 29 names, one file each, text kept verbatim. Two things are added: this
index, and [ADR 0001](adr/0001-decentralized-cloud-is-a-product.md), which records the
re-scope the specification implies for the estate's canon.

**Thesis in one line.** One accountable cloud service over an open infrastructure
market, with stable logical resources, explicit guarantees, and replaceable physical
providers. Not "decentralized AWS"; not a protocol dashboard.

## The documents

| Document | Contents (spec sections) | Depends on |
|---|---|---|
| [000-thesis-and-principles.md](000-thesis-and-principles.md) | Executive thesis · product principles · critical architectural decisions · final recommended architecture (§1, §2, §33, §34) | — |
| [010-resource-model.md](010-resource-model.md) | Cloud primitive model · canonical data model · state machines (§3, §21, §23) | 000 |
| [020-console-ux.md](020-console-ux.md) | Information architecture · global shell · page architecture · core flows · textual wireframes (§4–§8) | 010, 160 |
| [030-control-plane.md](030-control-plane.md) | System architecture · control plane · event model (§11, §12, §22) | 010, 170, 180 |
| [040-provider-abstraction.md](040-provider-abstraction.md) | Provider architecture · provider-console UX (§19, §9) | 010, 030 |
| [050-placement-and-supply.md](050-placement-and-supply.md) | Decentralized-cloud abstractions: regions, latency cells, failure domains, pools, placement contracts, scheduling, resilience claims, provenance (§10) | 040, 100, 190, 200, 260 |
| [060-compute.md](060-compute.md) | Compute (§13) | 030, 040, 080, 090 |
| [070-storage.md](070-storage.md) | Storage (§14) | 010, 040, 090, 190 |
| [080-network.md](080-network.md) | Networking (§15) | 010, 090, 190, 250 |
| [090-identity-security.md](090-identity-security.md) | IAM and security · trust and threat model (§16, §26) | 010, 210 |
| [100-money.md](100-money.md) | Metering, pricing, billing, settlement (§18) | 010, 040, 080 |
| [130-observability.md](130-observability.md) | Observability (§17) | 010, 080, 170 |
| [150-failure-recovery.md](150-failure-recovery.md) | End-to-end deployment trace · failure/recovery trace · hardest unresolved problems (§24, §25, §32) | 030, 060, 070, 080, 110, 120 |
| [160-api-cli-sdk.md](160-api-cli-sdk.md) | API, CLI, SDK, integrations (§20) | 010, 030, 090, 170 |
| [240-roadmap-and-wedge.md](240-roadmap-and-wedge.md) | MVP roadmap · release gates · initial wedge (§30, §31) | all |
| [270-diagrams.md](270-diagrams.md) | Architecture diagrams (§27) | — |
| [280-documentation-plan.md](280-documentation-plan.md) | Documentation tree · architecture-document decomposition and implementation sequence (§28, §29) | — |

Numbers follow section 29 of the specification so that later, fuller documents (110
billing-ledger, 120 settlement, 170 events, 180 data model, 190 regions, 200 SLA,
210 threat, 220 AI operations, 230 managed data, 250 edge, 260 capacity) can be split
out of the files above without renumbering.

## The implementation sequence the spec prescribes

```text
000 / 010 / 180
→ 090 / 030 / 040
→ 100 / 110 / 120
→ 060 / 080 / 250
→ 070 / 130 / 150
→ 020 / 160 / provider onboarding
```

The UI should not be designed against resource states that the control plane cannot
reliably produce.

## Relationship to the rest of the estate

decentralized.cloud is a product with its own resource model, control plane and
ledger. The estate's existing planes are consumed through the adapter boundary in
document 040: the Hypervisor as an execution and acquisition substrate (and a runtime
the cloud's own services may run on), wallet.network as one authority backend behind
spend grants, Agentgres as one evidence source behind receipts, the CAS plane behind
archive custody. For any given object exactly one plane is authoritative and the
direction of dependency is written down. See ADR 0001 for what this changes in canon
and the three owner decisions still open.

The console that exists today under `apps/decentralized-cloud/` was built as a face
over the Hypervisor daemon; its scoreboard is `apps/decentralized-cloud/docs/CONSOLE-AUDIT.md`.
It continues under this specification's rule: it iterates only against states the
control plane can produce, and draws the rest once, labelled, behind a toggle.

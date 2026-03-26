# `IOI CLI` v1.0 Product Spec

## Canonical Command Line for the Web4 L0

**Status:** Proposed revision
**Audience:** Kernel, protocol, developer tooling, publication, and ecosystem teams

## 1. Executive Summary

`IOI CLI` is the canonical command line for authoring, instantiating, publishing, upgrading, and inspecting intelligent blockchains and other sovereign autonomous domains on IOI.

It is the surface where a builder or operator can:

* scaffold a new intelligent blockchain
* define domain structure and topology
* configure policy roots and delegation rules
* define publication and receipt behavior
* publish, inspect, and upgrade sovereign domains
* formalize kernel-native execution objects

The current implementation should begin **CLI-first** and stay close to the kernel and publication layer. The present `crates/cli` surface is the natural starting point for this direction.

`forge` still matters inside this system, but it should be treated as:

* a command namespace
* a verb
* a capability family
* a tagline for domain creation

It should not be the primary product name for the whole surface.

> **`IOI CLI` is the canonical command line for the Web4 L0. `ioi forge` instantiates sovereign domains. `Autopilot` stabilizes worker systems. `sas.xyz` serves and commercializes them when they become provider products.**

---

## 2. Naming Doctrine

Use `IOI CLI` as the primary name, and use `forge` inside it.

This naming is stronger because it is:

* blunt and clear about the interface
* architecturally consistent with `Autopilot` and `sas.xyz`
* extensible as the command surface grows
* less ambiguous than spending the top-level product name on a single metaphor

`IOI CLI` should read like the canonical interface to the underlying Web4 L0 system, not like a separate semi-mythical developer brand.

That gives room for strong command families such as:

* `ioi forge`
* `ioi chain create`
* `ioi worker init`
* `ioi deploy`
* `ioi verify`

---

## 3. Product Definition

### Category

Canonical CLI surface for Web4 L0 domain authoring and intelligent blockchain instantiation.

### One sentence

`IOI CLI` is the CLI-first, kernel-adjacent surface for authoring, instantiating, publishing, upgrading, and inspecting intelligent blockchains and sovereign autonomous domains on IOI.

### One paragraph

`IOI CLI` is the builder surface for creating durable sovereign execution domains when a workflow or worker system needs more than service packaging. It owns domain scaffolding, policy roots, authority and delegation structure, publication behavior, kernel-native commitments, and upgrade semantics. It should feel closer to Ignite for Cosmos than to a consumer chat or provider dashboard: developer-grade, protocol-aware, scaffolding-heavy, and rooted in the kernel's actual publication and settlement semantics.

### Current implementation posture

`IOI CLI` should begin as:

* CLI-first
* kernel-adjacent
* publication-aware
* developer/operator facing

Later, it may grow richer IDE or visual surfaces, but the canonical first interface should stay close to `ioi` and the underlying kernel.

---

## 4. Ecosystem Role

The ecosystem becomes cleaner when the fifth distinct surface is named `IOI CLI` rather than `Forge`.

## 4.1 `Autopilot`

**Operate and stabilize**

Private/local operator shell for workers, workflows, approvals, receipts, and service candidates.

## 4.2 `IOI CLI`

**Author at the kernel boundary**

Kernel-adjacent L0 surface for intelligent blockchains, domain structure, policy roots, publication, and upgrades.

`forge` is one of its major command families, not a separate product.

## 4.3 `sas.xyz`

**Productize and serve**

Provider OS for packaging, deploying, serving, and commercializing worker services, including intelligent-blockchain-backed services when those domains are exposed as provider products.

## 4.4 `aiagent.xyz`

**Discover or procure**

Discovery and procurement surface for productized worker services and bespoke demand.

## 4.5 `ioi.ai`

**Use through hosted demand UX**

Intent ingress and hosted execution UX.

## 4.6 Boundary rules

* `Autopilot` is where worker systems are built, operated, and stabilized privately.
* `IOI CLI` is where sovereign domains and intelligent blockchains are formally instantiated.
* `forge` is a major namespace within `IOI CLI`, not the name of a separate top-level surface.
* `sas.xyz` is where services, including intelligent-blockchain-backed services, are packaged, deployed, served, and commercialized.
* Not every stabilized worker system should become an intelligent blockchain.
* Not every intelligent blockchain should be commercialized through `sas.xyz`.

**Doctrine:** `IOI CLI` creates the sovereign execution object. `Autopilot` refines the worker system. `sas.xyz` serves and commercializes it when it becomes a provider product.

---

## 5. When to Use `IOI CLI`

Use `IOI CLI` when a system needs to become a durable sovereign domain rather than just a service candidate or provider service.

Typical reasons include:

* durable sovereign state matters
* publication and continuity matter
* policy roots must be explicit and durable
* many workers or participants need coordination
* domain economics or governance are first-class
* delegation and participant semantics need durable definition
* the system is becoming a protocolized autonomous domain

Do **not** make every workflow or service candidate an intelligent blockchain by default.

---

## 6. Product Ladder and Promotion Paths

The weight of a sovereign domain should be preserved.

## 6.1 Base ladder

1. Workflow
2. Stable worker or service candidate
3. Provider service in `sas.xyz` when service packaging and commercialization are the right move
4. Intelligent blockchain / sovereign domain in `IOI CLI` when durable domain semantics are needed

## 6.2 Practical branch model

In practice, the ladder is not a strict one-way chain. A stable worker system may branch:

* into `sas.xyz` for provider-grade packaging and serving
* into `IOI CLI` for intelligent-blockchain/domain instantiation
* and, if an `IOI CLI` domain later needs provider exposure, back into `sas.xyz` as an intelligent-blockchain-backed service

## 6.3 Promotion doctrine

`Autopilot` workflows may absolutely compile toward `IOI CLI`-compatible artifacts.

That does **not** mean `Autopilot` should be the primary product for creating intelligent blockchains. `IOI CLI` is the heavier L0-native surface for that act.

---

## 7. Command Model and Why CLI-First Is Right

This surface is closer to:

* kernel semantics
* publication roots
* scaffolding
* protocol topology
* domain instantiation
* upgrade machinery

than to consumer or operator UX.

A CLI-first interface is therefore the correct first expression.

The command hierarchy should spend clarity at the top level and reserve metaphorical names for the right subcommands.

Illustrative command families include:

* `ioi forge` for creating and compiling intelligent blockchains
* `ioi chain create` for explicit domain and chain scaffolding
* `ioi worker init` for worker-native project setup
* `ioi deploy` for publication and deployment flows, including `sas.xyz`
* `ioi verify` for proofs, receipts, and execution evidence

More specific `forge` commands may still exist, such as:

* `ioi forge init`
* `ioi forge policy-root`
* `ioi forge topology`
* `ioi forge publish`
* `ioi forge receipts`
* `ioi forge inspect`
* `ioi forge upgrade`

Those commands are illustrative, not final command design.

---

## 8. Core Objects

## 8.1 Domain

A sovereign autonomous execution domain rooted in IOI semantics.

## 8.2 Intelligent blockchain

A durable sovereign domain with explicit policy, participant, publication, and continuity semantics.

## 8.3 Policy root

The durable root of what the domain is allowed to do and how it is governed.

## 8.4 Topology

The defined structure of workers, services, participants, roles, and coordination semantics inside the domain.

## 8.5 Delegation model

The durable statement of who may authorize, upgrade, operate, or participate.

## 8.6 Publication metadata

The canonical publication, identity, and upgrade-facing metadata for the domain.

## 8.7 Upgrade package

The bounded, publishable change unit for domain evolution.

## 8.8 Commitment and receipt inspector

The surface for inspecting roots, execution commitments, publication records, and kernel-native receipts.

---

## 9. Core Lifecycle

The core `IOI CLI` domain-authoring loop should be:

1. Initialize domain scaffold
2. Define policy roots and authority model
3. Define worker, service, and participant topology
4. Configure publication and receipt behavior
5. Generate kernel-native scaffolds and manifests
6. Instantiate the sovereign domain
7. Publish and inspect commitments
8. Upgrade the domain over time

This is heavier than normal serviceization and should feel heavier.

---

## 10. Relationship to `Autopilot`

`Autopilot` is the private/local shell where worker systems are:

* built
* stabilized
* supervised
* refined
* promoted into service candidates

`IOI CLI` is where those stabilized systems may be turned into sovereign domains when the weight of a real intelligent blockchain is warranted.

`Autopilot` can therefore be:

* a source surface
* a feeder
* an exporter of `IOI CLI`-compatible artifacts

But it should not be the sole home of intelligent blockchain creation.

---

## 11. Relationship to `sas.xyz`

`sas.xyz` is not just cloud routing. It is the provider-side packaging, deployment, serving, and commercialization layer.

That means the relationship is:

* `IOI CLI` creates the sovereign execution object
* `sas.xyz` serves and commercializes it when it becomes a provider product

Some intelligent blockchains will be:

* internal
* infrastructure-facing
* protocol-native
* not meant to be sold as marketplace products

Others will back:

* worker services
* APIs
* installable offerings
* enterprise deployments

Only the latter need `sas.xyz` as the provider-serving and commercial surface.

---

## 12. Definition of Done

`IOI CLI` is successful when a developer or operator can:

1. scaffold a new intelligent blockchain or sovereign domain from a CLI-first surface,
2. define policy roots, authority and delegation rules, and topology explicitly,
3. instantiate the domain as a kernel-native execution object,
4. publish, inspect, and upgrade that domain through canonical IOI semantics,
5. import or promote stabilized worker logic from `Autopilot` when relevant,
6. use `forge` and adjacent command families without needing a separate product identity,
7. and hand the resulting domain off to `sas.xyz` when it needs to become a deployable, billable, distributable provider service.

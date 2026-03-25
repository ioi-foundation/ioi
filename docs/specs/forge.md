# `Forge` v1.0 Product Spec

## Web4 L0 Domain Builder for Intelligent Blockchains on IOI

**Status:** Proposed revision
**Audience:** Kernel, protocol, developer tooling, publication, and ecosystem teams

## 1. Executive Summary

`Forge` is the Web4 L0 authoring and instantiation surface for intelligent blockchains and other sovereign autonomous domains on IOI.

It is the surface where a builder or operator can:

* scaffold a new intelligent blockchain
* define domain structure and topology
* configure policy roots and delegation rules
* define publication and receipt behavior
* publish, inspect, and upgrade sovereign domains
* formalize kernel-native execution objects

The current implementation should begin **CLI-first** and stay close to the kernel and publication layer. The present `crates/cli` surface is the natural starting point for this direction.

`Forge` should not be treated as:

* just another tab in `Autopilot`
* a thin marketplace publish form
* a vague hidden compiler artifact

It is its own leg of the ecosystem:

> **Forge instantiates sovereign domains. Autopilot stabilizes worker systems. `sas.xyz` serves and commercializes them when they become provider products.**

---

## 2. Product Definition

### Category

Web4 L0 domain builder and intelligent blockchain instantiation surface.

### One sentence

`Forge` is the CLI-first, kernel-adjacent surface for authoring, instantiating, publishing, upgrading, and inspecting intelligent blockchains and sovereign autonomous domains on IOI.

### One paragraph

`Forge` is the builder surface for creating durable sovereign execution domains when a workflow or worker system needs more than service packaging. It owns domain scaffolding, policy roots, authority and delegation structure, publication behavior, kernel-native commitments, and upgrade semantics. It should feel closer to Ignite for Cosmos than to a consumer chat or provider dashboard: developer-grade, protocol-aware, scaffolding-heavy, and rooted in the kernel’s actual publication and settlement semantics.

### Current implementation posture

`Forge` should begin as:

* CLI-first
* kernel-adjacent
* publication-aware
* developer/operator facing

Later, it may grow richer IDE or visual surfaces, but the canonical first interface should stay close to `ioi-cli` and the underlying kernel.

---

## 3. Ecosystem Role

The ecosystem becomes cleaner when `Forge` is treated as a fifth distinct surface.

## 3.1 `Autopilot`

**Operate and stabilize**

Private/local operator shell for workers, workflows, approvals, receipts, and service candidates.

## 3.2 `Forge`

**Instantiate sovereign domains**

Kernel-adjacent L0 surface for intelligent blockchains, domain structure, policy roots, publication, and upgrades.

## 3.3 `sas.xyz`

**Productize and serve**

Provider OS for packaging, deploying, serving, and commercializing worker services, including intelligent-blockchain-backed services when those domains are exposed as provider products.

## 3.4 `aiagent.xyz`

**Discover or procure**

Discovery and procurement surface for productized worker services and bespoke demand.

## 3.5 `ioi.ai`

**Use through hosted demand UX**

Intent ingress and hosted execution UX.

## 3.6 Boundary rules

* `Autopilot` is where worker systems are built, operated, and stabilized privately.
* `Forge` is where sovereign domains and intelligent blockchains are formally instantiated.
* `sas.xyz` is where services, including intelligent-blockchain-backed services, are packaged, deployed, served, and commercialized.
* Not every stabilized worker system should become an intelligent blockchain.
* Not every intelligent blockchain should be commercialized through `sas.xyz`.

**Doctrine:** `Forge` creates the sovereign execution object. `Autopilot` refines the worker system. `sas.xyz` serves and commercializes it when it becomes a provider product.

---

## 4. When to Use `Forge`

Use `Forge` when a system needs to become a durable sovereign domain rather than just a service candidate or provider service.

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

## 5. Product Ladder and Promotion Paths

The weight of a sovereign domain should be preserved.

## 5.1 Base ladder

1. Workflow
2. Stable worker or service candidate
3. Provider service in `sas.xyz` when service packaging and commercialization are the right move
4. Intelligent blockchain / sovereign domain in `Forge` when durable domain semantics are needed

## 5.2 Practical branch model

In practice, the ladder is not a strict one-way chain. A stable worker system may branch:

* into `sas.xyz` for provider-grade packaging and serving
* into `Forge` for intelligent-blockchain/domain instantiation
* and, if a `Forge` domain later needs provider exposure, back into `sas.xyz` as an intelligent-blockchain-backed service

## 5.3 Promotion doctrine

`Autopilot` workflows may absolutely compile toward `Forge`-compatible artifacts.

That does **not** mean `Autopilot` should be the primary product for creating intelligent blockchains. `Forge` is the heavier L0-native surface for that act.

---

## 6. Why CLI-First Is Right

This surface is closer to:

* kernel semantics
* publication roots
* scaffolding
* protocol topology
* domain instantiation
* upgrade machinery

than to consumer/operator UX.

A CLI-first interface is therefore the correct first expression.

It should eventually support actions such as:

* `forge init`
* `forge policy-root`
* `forge topology`
* `forge publish`
* `forge receipts`
* `forge inspect`
* `forge upgrade`

Those commands are illustrative, not final command design.

---

## 7. Core Objects

## 7.1 Domain

A sovereign autonomous execution domain rooted in IOI semantics.

## 7.2 Intelligent blockchain

A durable sovereign domain with explicit policy, participant, publication, and continuity semantics.

## 7.3 Policy root

The durable root of what the domain is allowed to do and how it is governed.

## 7.4 Topology

The defined structure of workers, services, participants, roles, and coordination semantics inside the domain.

## 7.5 Delegation model

The durable statement of who may authorize, upgrade, operate, or participate.

## 7.6 Publication metadata

The canonical publication, identity, and upgrade-facing metadata for the domain.

## 7.7 Upgrade package

The bounded, publishable change unit for domain evolution.

## 7.8 Commitment and receipt inspector

The surface for inspecting roots, execution commitments, publication records, and kernel-native receipts.

---

## 8. Core Lifecycle

The core `Forge` loop should be:

1. Initialize domain scaffold
2. Define policy roots and authority model
3. Define worker/service/participant topology
4. Configure publication and receipt behavior
5. Generate kernel-native scaffolds and manifests
6. Instantiate the sovereign domain
7. Publish and inspect commitments
8. Upgrade the domain over time

This is heavier than normal serviceization and should feel heavier.

---

## 9. Relationship to `Autopilot`

`Autopilot` is the private/local shell where worker systems are:

* built
* stabilized
* supervised
* refined
* promoted into service candidates

`Forge` is where those stabilized systems may be turned into sovereign domains when the weight of a real intelligent blockchain is warranted.

`Autopilot` can therefore be:

* a source surface
* a feeder
* an exporter of `Forge`-compatible artifacts

But it should not be the sole home of intelligent blockchain creation.

---

## 10. Relationship to `sas.xyz`

`sas.xyz` is not just cloud routing. It is the provider-side packaging, deployment, serving, and commercialization layer.

That means the relationship is:

* `Forge` creates the sovereign execution object
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

## 11. Definition of Done

`Forge` is successful when a developer or operator can:

1. scaffold a new intelligent blockchain or sovereign domain from a CLI-first surface,
2. define policy roots, authority and delegation rules, and topology explicitly,
3. instantiate the domain as a kernel-native execution object,
4. publish, inspect, and upgrade that domain through canonical IOI semantics,
5. import or promote stabilized worker logic from `Autopilot` when relevant,
6. and hand the resulting domain off to `sas.xyz` when it needs to become a deployable, billable, distributable provider service.

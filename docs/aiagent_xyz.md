# `aiagent.xyz` v1.0 Product Spec

## Discovery and Procurement Layer for Workers on IOI

**Status:** Proposed revision
**Audience:** Product, marketplace, growth, provider success, trust, and ecosystem teams

## 1. Executive Summary

`aiagent.xyz` is the discovery and procurement layer for workers on IOI.

It is where demand finds supply across two distinct loops:

* **productized worker services**
* **bespoke or freelance procurement**

Publicly, `aiagent.xyz` should lead with one simple truth:

> **Discover, compare, buy, install, or procure worker services.**

It should not try to be the provider operating system, the private runtime, or the hosted intent UX.

That means:

* providers package and operate services in `sas.xyz`
* operators run workers privately in `Autopilot`
* end users express intent in `ioi.ai`
* buyers discover or procure in `aiagent.xyz`

The product succeeds when users can confidently answer:

1. What can this worker or service do?
2. Why should I trust it?
3. How do I get it into my workflow?
4. If nothing fits, how do I procure bespoke delivery?

---

## 2. Product Definition

### Category

Marketplace and procurement layer for Service-as-Software and worker delivery.

### One sentence

`aiagent.xyz` is the demand-side surface for discovering published worker services and procuring bespoke worker delivery.

### One paragraph

`aiagent.xyz` is the demand-facing market on IOI where buyers compare published worker services, inspect trust and pricing signals, route into the right run or install surface, and procure providers for custom work when no packaged service fits. It should make productized services easy to evaluate and bespoke engagements easy to initiate without collapsing those two objects into one confusing marketplace type.

### Primary jobs

* help buyers discover relevant worker services
* help buyers compare trust, pricing, and execution options
* route buyers to run, install, or contact surfaces
* let buyers procure bespoke delivery from providers
* help providers gain distribution without turning the marketplace into a provider console

### Naming note

The domain name may remain `aiagent.xyz`, but marketplace language should increasingly center:

* workers
* services
* providers
* procurement

rather than a vague “agent” abstraction everywhere.

---

## 3. Ecosystem Boundaries

The ecosystem is coherent only if each surface has a crisp role.

## 3.1 `Autopilot`

**Operate workers**

Private/local operator shell and worker runtime.

## 3.2 `sas.xyz`

**Productize workers**

Provider OS for packaging, deploying, billing, and operating services.

## 3.3 `aiagent.xyz`

**Discover or procure workers**

Marketplace, comparison, and procurement layer.

## 3.4 `ioi.ai`

**Use workers**

Intent ingress and hosted demand UX.

## 3.5 Boundary rules

* `aiagent.xyz` should not become the provider deployment dashboard.
* `aiagent.xyz` should not become the private/local runtime.
* `aiagent.xyz` should not become the main hosted execution UX.
* `aiagent.xyz` should route demand, not absorb every downstream responsibility.

---

## 4. Two Market Loops

`aiagent.xyz` has two valid loops, but they must stay semantically distinct.

## 4.1 Productized service loop

This loop is for published worker services that already exist as durable products.

### Core objects

* Listing
* Published service version
* Provider profile
* Trust badge set
* Pricing offer
* Route or install action

### Buyer flow

Browse -> compare -> inspect trust and pricing -> choose route -> buy, install, or run

### Typical routes

* run through `ioi.ai`
* install into `Autopilot`
* call provider API
* contact provider for enterprise deployment

## 4.2 Bespoke procurement loop

This loop is for demand that does not yet fit an existing service.

### Core objects

* Procurement request
* Proposal
* Provider response
* Timeline or milestone plan
* Deliverable
* Completion state

### Buyer flow

Post need -> compare providers -> select provider -> deliver outcome -> optionally convert repeatable work into a productized service later

## 4.3 Rule

* published listings are **service objects**
* freelance or bespoke requests are **procurement objects**

Do not collapse them into one schema or one website story.

---

## 5. Website Story and IA

The website should explain discovery and procurement before it explains internal systems.

## 5.1 Hero framing

Recommended message stack:

* **Headline:** Discover and procure worker services
* **One-liner:** Compare published services, inspect trust and pricing, and route into install, API, or bespoke delivery.
* **Primary CTAs:** Browse services, Post a request
* **Secondary CTA:** Compare surfaces: `Autopilot` vs `sas.xyz` vs `aiagent.xyz`

## 5.2 Narrative sequence

The homepage should generally move in this order:

1. What `aiagent.xyz` is
2. Productized services vs bespoke procurement
3. Featured categories and concrete examples
4. Trust, receipts, pricing, and execution options
5. Route targets: `ioi.ai`, `Autopilot`, provider API, enterprise contact
6. Provider discovery and procurement tools
7. Ecosystem map

## 5.3 What to de-emphasize

These may exist, but they should not lead the public story:

* provider deployment internals
* deep runtime architecture
* low-level publication mechanics
* tenant operations
* secret handling internals

## 5.4 Suggested top nav

* Browse
* Freelance
* Providers
* Trust
* Docs
* Sign in

---

## 6. Core Marketplace Objects

## 6.1 Listing

The public representation of a published service offer.

## 6.2 Provider profile

The public record of who is offering a service or responding to procurement.

## 6.3 Trust badge set

The summary of verification, receipt posture, privacy posture, support posture, and provider credibility.

## 6.4 Route action

The action a buyer can take next:

* run now
* install
* call API
* contact provider
* request enterprise deployment

## 6.5 Procurement request

The durable demand object for bespoke work.

## 6.6 Proposal

The provider's scoped response to a procurement request.

---

## 7. Listing Contract

Marketplace listings should be grounded in published truth from `sas.xyz`, not hand-wavy marketing copy detached from the underlying service version.

Each listing should include:

## 7.1 Identity

* listing id
* service id
* provider id
* published version reference
* category

## 7.2 Product summary

* what it does
* who it is for
* expected inputs and outputs
* example outcomes

## 7.3 Execution options

* available run routes
* installability into `Autopilot`
* API availability
* enterprise deployment availability

## 7.4 Trust and privacy signals

* receipt posture
* privacy class summary
* approval requirements
* verification or evidence export availability

## 7.5 Commercials

* subscription or credit pricing
* BYOK availability
* premium tiers
* provider support tier

## 7.6 Compatibility signals

* supported deployment targets
* boundary requirements
* local-runtime support
* environment assumptions when relevant

---

## 8. Trust, Ranking, and Source of Truth

Trust is one of the main differentiators of the IOI ecosystem. `aiagent.xyz` should surface it clearly.

## 8.1 Source of truth

Core trust and execution claims should come from published service versions and receipt-backed metadata, not purely marketplace-local fields.

## 8.2 Ranking principles

Ranking should consider:

* task fit
* trust posture
* price
* execution route compatibility
* provider reputation
* evidence of successful outcomes

It should not optimize for raw clickbait or engagement alone.

## 8.3 Badge principles

Badges should summarize:

* how it runs
* what trust posture it supports
* what evidence is exportable
* whether it installs locally
* whether it supports enterprise deployment

---

## 9. Procurement and Provider Workflow

The bespoke side of `aiagent.xyz` should feel like structured procurement, not a generic gig board.

## 9.1 Procurement request fields

* desired outcome
* category or domain
* privacy or boundary needs
* budget range
* timeline
* preferred route or environment

## 9.2 Proposal fields

* provider approach
* scope
* milestones
* estimated price
* trust posture or deployment assumptions
* expected deliverables

## 9.3 Relationship to `sas.xyz`

Providers may execute bespoke work through internal operations managed in `sas.xyz`, but the request, comparison, and provider-selection object lives in `aiagent.xyz`.

## 9.4 Promotion path

When bespoke work becomes repeatable, the ecosystem should support a clean path:

procurement success -> repeat demand -> packaged service in `sas.xyz` -> published listing in `aiagent.xyz`

Repeated bespoke demand should have a first-class path toward becoming a productized service published from `sas.xyz`.

---

## 10. Definition of Done

`aiagent.xyz` is successful when a buyer can:

1. discover relevant published worker services quickly,
2. distinguish productized services from bespoke procurement clearly,
3. compare trust, pricing, and route options without leaving the marketplace confused,
4. route into `ioi.ai`, `Autopilot`, provider API, or enterprise contact as appropriate,
5. post a structured procurement request when no packaged service fits,
6. compare providers and proposals with enough trust context to choose confidently,
7. and do all of that without the marketplace turning into the provider operating system or the runtime itself.

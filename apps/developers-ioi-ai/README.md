# developers.ioi.ai

`developers.ioi.ai` is the curated developer experience surface for IOI. It is the front door for builders who want to ship with IOI products, APIs, SDKs, and execution surfaces.

This app should answer:

**How do I build with IOI?**

It should not try to be the canonical answer to:

**How does IOI work?**

## Separation Of Concerns

| Surface | Job | Typical content |
| --- | --- | --- |
| `developers.ioi.ai` | Product, onboarding, and execution-facing developer experience | Quickstarts, API and SDK onboarding, auth guides, tutorials, examples, hosted API docs, pricing, and product guides for Forge, Autopilot, and `sas.xyz` |
| `docs.ioi.network` | Canonical protocol and infrastructure reference | Protocol specs, runtime and kernel internals, consensus and AFT docs, receipts, AIIP and publication docs, coordinator and node operator docs, formal schemas |

`ioi.network` lives in a separate monorepo. For this app, we are only responsible for the `developers.ioi.ai` layer.

## What Belongs Here

- Introduction to IOI
- Quickstarts
- API and SDK getting started
- Auth, keys, and environment setup
- "Build your first worker"
- Forge guides
- Autopilot integration guides
- `sas.xyz` publishing and deployment guides
- Examples, tutorials, and walkthroughs
- Higher-level architecture overviews
- Hosted API docs
- Pricing and product comparisons
- Clear links into deeper canonical protocol docs when needed

## What Does Not Belong Here

- Canonical protocol specs
- Repo-generated raw reference material
- Runtime and kernel internals as the source of truth
- Consensus, AFT, receipt, or AIIP formal details
- Validator, coordinator, node operator, or infra runbooks
- Low-level schemas that belong in `docs.ioi.network`

## Source Of Truth Policy

- `developers.ioi.ai` is the curated DX layer.
- `docs.ioi.network` is the canonical technical reference.
- This app can summarize, teach, and organize, but it should not fork low-level truth.
- When a page needs protocol depth, it should link to `docs.ioi.network` instead of reproducing durable reference material here.
- The relationship should be explicit in the UX: quickstarts point downward to canonical reference, and canonical reference can point back here for onboarding.

## Product Posture

This surface should feel:

- Polished
- Curated
- Productized
- Onboarding-friendly

## Current Scaffold

The app is currently a docs-style shell built with Vite, React, and Tailwind. The navigation and page bodies are still placeholder content intended to be replaced with real IOI information architecture and copy.

Relevant files:

- `src/App.tsx` for the overall shell and theme state
- `src/components/Header.tsx` for top-level navigation
- `src/components/Sidebar.tsx` for docs navigation
- `src/components/MainContent.tsx` for page content variants
- `src/components/UIComponents.tsx` for shared docs UI primitives

The current scaffold does not require a live backend or API key to render locally.

## Local Development

From the monorepo root:

```bash
npm install
npm run dev --workspace=apps/developers-ioi-ai
```

The app runs on `http://localhost:3000`.

Useful workspace commands:

```bash
npm run build --workspace=apps/developers-ioi-ai
npm run lint --workspace=apps/developers-ioi-ai
```

## Editorial Guardrails

- Prefer task-oriented documentation over protocol exposition.
- Teach with examples, quickstarts, and tutorials.
- Keep onboarding concise, then link out for depth.
- Avoid duplicating canonical reference docs.
- Make the handoff to `docs.ioi.network` obvious whenever readers need low-level detail.
- Treat `developers.ioi.ai` as the front door, not the full basement of protocol internals.

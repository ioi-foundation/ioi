# Build acceptance gates — the all-surface Definition of Done

Authored 2026-08-06 from a post-close audit of the seed-mesh + ODK wiring run.
That run enriched the twenty briefs with seed, ontology, and ODK sections; it made
**no frontend changes** and did not make any canonical surface functional. This
file supplies what the briefs still lacked: **executable acceptance**, binding on
every surface build in
[`../overhaul/2026-08-05-hypervisor-bring-to-life-run.md`](../overhaul/2026-08-05-hypervisor-bring-to-life-run.md).

`apps/hypervisor/AGENTS.md:24` already requires much of this as policy. The twenty
briefs did not turn it into a gate. These eight gates do.

## G-1 · HEAD truth-refresh

Every "current state" row in a brief's §2/§3/§4 is re-verified against HEAD before
that surface's build starts, and corrections are recorded in the brief.

The mesh run's own packets prove why this is mandatory rather than advisory. Its
recipe made refresh step 1, and packet 14 still shipped two stale rows:

- `packages.md:83` asserts `_meta/schemas/` contains **zero**
  package/release/install schemas. **`hypervisor-surface-release-record.v1.schema.json`
  and `hypervisor-surface-installation-binding.v1.schema.json` both exist.**
- `packages.md:117-119` asserts canonical `/packages` does not resolve.
  **`v2-route-shell.mjs:249` registers it** (W0.1 landed after the census snapshot
  the row cites).

Both are corrected in this PR. The gate exists so the next such pair is caught by
process rather than by audit.

**Also stale by construction:** the 563-control census
(`apps/hypervisor/application-operational-depth.json`) is frozen at `19d732ff2`,
now **472 commits behind HEAD**. It covers **14 T3 surfaces**, not the current
20-surface product, and excludes the T1/T2 estates entirely. Only **12 of its 24**
`governed_receipted_action` rows are marked `implemented`. Reconciling against it —
as every mesh ledger does — proves arithmetic consistency with a frozen baseline
and **does not measure current product coverage.** Any claim of the form "all 563
controls reconciled" must carry that qualifier.

## G-2 · Request-scoped identity propagation

The module runtime drops incoming principal/tenant headers from module reads and
actions, while the serve layer's own comment warns that doing so can promote a
request to the loopback development principal
(`serve-product-ui.mjs:250`, module context `:9715`).

Thread identity through **reads, actions, authority crossings, and subscriptions**.
Ship cross-principal tests: principal A must never observe or mutate principal B's
state, and a request with no principal must not silently acquire one.

## G-3 · Mutation correctness

Descriptor and DomainApp create/patch/runtime/receipt writes discard persistence
errors and return success (`odk_routes.rs:1552`, `domain_apps_routes.rs:368` — see
`odk-extension-apps.md` §8 L-1/L-2).

Required per mutation: atomic persistence, propagated failure, rollback, CAS or
revision checks, idempotency, referential integrity, read-after-write, restart
survival, and orphan recovery. **UI deletes and runtime actions must not redirect
as success on network or daemon failure.**

The pattern to copy already exists in-tree: `finalize_ontology_persist`
(`odk_routes.rs`) persists the record first, writes the receipt second, and
restores or removes on receipt failure so no accepted mutation lacks its proof.

## G-4 · Descriptor / Studio vertical slice

Rehome the existing descriptor form (`serve-product-ui.mjs:3320`, dispatch `:9776`)
from the legacy ODK readout to Studio's canonical route, then implement the **full
canonical binding set** (`semantic-plane.md` §`OntologySurfaceDescriptorEnvelope`),
plus conformance, versioning, preview/scaffolding, and artifact generation.

**Sequencing constraint, stated because the current plan contradicts itself:**
`studio.md` §5's W2 routes descriptor writes through the CapabilityLease client,
which rejects any 2xx lacking a receipt — and the descriptor routes emit no
receipts. Either the routes gain a receipt family first, or the writes do not go
through that client. The plan cannot ship as written.

## G-5 · Complete Packages / application lifecycle

Package candidate and intake, immutable release, dependency and integrity
metadata, admission, install/uninstall, extension registration, compiler
integration, recall and revocation, affected-System impact, dynamic application
routing, and System interface bindings.

This is the gating build for the whole extension lane (`odk-extension-apps.md` §1,
`packages.md` §8). Recall must land **with** the registry, not after it.

## G-6 · Real generated runtime

Render typed object models, policy-bound and materialized data, allowed actions,
authority challenges, receipts, errors, and revocation.

Keep **inventory status** (`draft` / `admitted` / `installed` / …) separate from
**runtime state** (`mounted` / `serving` / …); they are different objects and
conflating them is how "admitted" starts reading as "running".

Owns **L-3** (`odk-extension-apps.md` §8): the runtime reads `com.objects` /
`com.actions` while the ontology plane authors `object_types` / `action_types`, so
a valid ontology renders as empty. Ruling which shape is canonical is part of this
gate.

## G-7 · Canonical routing and cutover

`/packages/marketplace` is named in the route table's `rule` string
(`v2-route-shell.mjs:252`) and is not a route. Route lookup remains exact-root-only
(`:249`, `:328`).

Add detail and deep-link grammar, `/applications/{surface_key}`, System binding
routes, `/sign-in` ownership, query/hash/embed/back-stack preservation, and typed
410s for legacy paths.

## G-8 · All-surface Definition of Done

Promote the proposed C1–C30 operational criteria
(`../audits/2026-07-30-hypervisor-surface-end-state-audit/README.md:998`) from
proposal to **mandatory build gate**. Every surface build must demonstrate:

- a primary intent → durable-result journey;
- loading, empty, missing-prerequisite, degraded, blocked, pending, denied,
  failed, recovery, and completed states;
- validation, preserved form input, cancellation, conflict, and
  timeout-as-unknown handling;
- pagination, search, sort, filter, and performance bounds;
- receipt/proof drilldowns and event reconnect/checkpoint behavior;
- keyboard, focus, screen-reader, contrast, both themes, reduced motion, narrow
  viewport, and embed behavior — **all thirteen pixel certifications currently
  record mobile as unsupported**, so narrow viewport is a build obligation, not an
  inherited pass;
- real-daemon happy, negative, fault, and restart E2E with **zero fixture
  fallback**;
- a per-control trace: visible control → handler → route → identity/authority →
  receipt → durable effect → readback/event → verifier.

## What green CI does and does not certify

Standard CI does **not** build or test `ioi-node` or the web UI. A green run
therefore cannot certify anything in this file. What is available today:

| Check | Result |
|---|---|
| Shared harness / client / event suites | 10/10, 13/13, 12/12 pass |
| Operational-depth verifier | 113/115 — the two failures are stale committed contract-wording guards |
| `cargo test -p ioi-node --bin hypervisor-daemon` | 490/491; the one failure predates this work and is unrelated |
| Interactive browser verification | **not performed** — no visual or click-through certification is claimed |

Any surface build that claims done must say which of these it ran.

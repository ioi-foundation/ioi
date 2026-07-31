---
module_id: adversarial-proof-matrix
module_class: method
title: Adversarial proof matrix
sequencer: program/sequence.v1.json
status_owner: work-item records
stage_ids: [M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, FUTURE]
canon_owners:
  - docs/architecture/_meta/source-of-truth-map.md
  - docs/architecture/foundations/invariants.md
  - docs/architecture/foundations/verifiable-bounded-agency.md
  - docs/architecture/foundations/security-privacy-policy-invariants.md
  - docs/architecture/foundations/common-objects-and-envelopes.md
  - docs/architecture/foundations/domain-ontologies-and-data-recipes.md
  - docs/architecture/foundations/institutional-learning-boundary.md
  - docs/architecture/foundations/bounded-recursive-improvement.md
  - docs/architecture/foundations/physical-action-safety.md
  - docs/architecture/foundations/economic-flywheel-and-pricing-boundaries.md
  - docs/architecture/foundations/aiip.md
  - docs/architecture/components/agentgres/doctrine.md
  - docs/architecture/components/daemon-runtime/api.md
  - docs/architecture/components/daemon-runtime/platform-operability.md
  - docs/architecture/components/daemon-runtime/events-receipts-delivery-bundles.md
  - docs/architecture/components/wallet-network/api-authority-scopes.md
  - docs/architecture/components/connectors-tools/contracts.md
  - docs/architecture/components/model-router/doctrine.md
  - docs/conformance/hypervisor-core/information-flow-propagation.md
  - docs/conformance/hypervisor-core/work-lifecycle.md
  - docs/conformance/hypervisor-core/effect-execution.md
  - docs/conformance/hypervisor-core/platform-fault-matrix.v1.json
  - docs/conformance/hypervisor-core/physical-action-safety.md
---

# Adversarial Proof Matrix

## What this module owns

This module owns one reusable method: a fixed taxonomy of failure classes and the minimum question
each puts to a claim, so a work item selects the rows its boundary is exposed to and proves the
answer rather than asserting it. It owns a method only — it never orders work, never carries status,
and is never a sequencer; the doctrine each row tests belongs to the canon owner named below.

## Pulled by

Row selection is program-wide rather than a per-stage `pulled_modules` binding:
[`program/rules.md`](../program/rules.md) §8 applies this matrix to every active stage. The
`modules[]` registry in [`program/sequence.v1.json`](../program/sequence.v1.json) carries no
`adversarial-proof-matrix` entry and therefore no `applies_to_stages` list, so the addressable set is
every stage id the sequencer declares — `M0` through `M14` and `FUTURE`, and no narrower binding may
be inferred here.

## Canon owners

| Canon owner | What it governs here |
| --- | --- |
| [`_meta/source-of-truth-map.md`](../../../docs/architecture/_meta/source-of-truth-map.md), [`foundations/invariants.md`](../../../docs/architecture/foundations/invariants.md), [`foundations/verifiable-bounded-agency.md`](../../../docs/architecture/foundations/verifiable-bounded-agency.md) | Which owner adjudicates a failure class whose doctrine is contested and the contract/fixture substrate an adversarial fixture attaches to; the estate-wide invariants each row attacks; what a bounded-agency claim may assert from observed behavior (coverage overclaim, evidence-producer conflict) |
| [`foundations/security-privacy-policy-invariants.md`](../../../docs/architecture/foundations/security-privacy-policy-invariants.md), [`wallet-network/api-authority-scopes.md`](../../../docs/architecture/components/wallet-network/api-authority-scopes.md), [`conformance/information-flow-propagation.md`](../../../docs/conformance/hypervisor-core/information-flow-propagation.md) | Identity substitution, authority bypass, cross-tenant leak, membership/claim leak, information-flow attack: principal binding, grant scope, audience/holder, expiry, revocation, declassification, and label propagation to forbidden destinations |
| [`foundations/common-objects-and-envelopes.md`](../../../docs/architecture/foundations/common-objects-and-envelopes.md), [`agentgres/doctrine.md`](../../../docs/architecture/components/agentgres/doctrine.md) | Body/ref substitution (canonical hashing, envelope identity, ref shape, version fields); stale state, writer/failover fault, truth/projection split (exact head/root and accepted-truth ordering) |
| [`daemon-runtime/api.md`](../../../docs/architecture/components/daemon-runtime/api.md), [`connectors-tools/contracts.md`](../../../docs/architecture/components/connectors-tools/contracts.md) | Route exposure and authorization fork: reachable-route classification, final-invoker identity, and the connector/MCP/adapter seams the bypass row names |
| [`daemon-runtime/platform-operability.md`](../../../docs/architecture/components/daemon-runtime/platform-operability.md), [`daemon-runtime/events-receipts-delivery-bundles.md`](../../../docs/architecture/components/daemon-runtime/events-receipts-delivery-bundles.md), [`conformance/work-lifecycle.md`](../../../docs/conformance/hypervisor-core/work-lifecycle.md), [`conformance/effect-execution.md`](../../../docs/conformance/hypervisor-core/effect-execution.md), [`conformance/platform-fault-matrix.v1.json`](../../../docs/conformance/hypervisor-core/platform-fault-matrix.v1.json) | Dependency outage, release/update substitution, restore-byte or secret substitution, activation/cleanup loss, retry/ambiguity; receipt, checkpoint, and export linkage that makes proof independently checkable; denial before invocation with zero invoker calls; fault classes injected rather than assumed |
| [`foundations/institutional-learning-boundary.md`](../../../docs/architecture/foundations/institutional-learning-boundary.md), [`model-router/doctrine.md`](../../../docs/architecture/components/model-router/doctrine.md), [`foundations/bounded-recursive-improvement.md`](../../../docs/architecture/foundations/bounded-recursive-improvement.md), [`foundations/domain-ontologies-and-data-recipes.md`](../../../docs/architecture/foundations/domain-ontologies-and-data-recipes.md) | Supply substitution across provider/model/worker/tool fallback against rights, semantics, and custody floors; verifier manipulation and budget reset (Search/Judgment/Authority separation, finite exposure); semantic escalation through mapping, compatibility, or ontology membership |
| [`foundations/physical-action-safety.md`](../../../docs/architecture/foundations/physical-action-safety.md), [`conformance/physical-action-safety.md`](../../../docs/conformance/hypervisor-core/physical-action-safety.md), [`foundations/economic-flywheel-and-pricing-boundaries.md`](../../../docs/architecture/foundations/economic-flywheel-and-pricing-boundaries.md), [`foundations/aiip.md`](../../../docs/architecture/foundations/aiip.md) | Physical safety fault (local veto, heartbeat, deterministic motion, e-stop, and its executable probes); economic theater; cross-domain replay, substitution, and membership/claim leak across sovereign boundaries |

## Retained obligations

Each row is a question, not a checklist item. A selected row is discharged only by an executed probe
against the real boundary retained with its expected-path literal; design intent, a passing positive
test, or the absence of a report does not discharge it. An unselected row is carried as an explicit
nonclaim with its out-of-boundary reason, so no row is lost by silence. The stage column names where
each class bites hardest given the sequencer's stage objectives; it is an entry point for selection,
never a restriction — any boundary that touches a row selects it regardless of the column.

| Failure class | Minimum question | Stages most exposed |
| --- | --- | --- |
| Identity substitution | Can a different principal, session, origin, factor, or device replay the action? | M1, M2, M5, M9, M12 |
| Body/ref substitution | Can the signed or admitted hash be reused with changed content, target, destination, or version? | M1, M3, M9, M12 |
| Stale state | Does a stale head, epoch, root, grant, lease, profile, or policy reach an effect? | M2, M4, M9, M10 |
| Authority bypass | Can UI, client, harness, connector, MCP, provider, or copied receipt fields mint power? | M1, M2, M5, M9, M12 |
| Route exposure / authorization fork | Is every externally reachable route classified, and can an MCP-only, adapter-only, or unregistered path reach a different policy or final-invoker path? | M3, M6, M7, M9, M14 |
| Coverage overclaim | Can discovery, observation, attribution, mediation, or receipt presence be misreported as prevention, especially after adapter loss, offline transition, version drift, or an opaque-runtime bypass? | M0, M8, M9, M13, M14 |
| Information-flow attack | Can untrusted instructions or derived data cross to a forbidden tool, model, tenant, or destination? | M7, M8, M9, M12 |
| Retry/ambiguity | Can timeout, restart, or uncertain external completion duplicate an effect? | M3, M4, M9, M10 |
| Writer/failover fault | Can an old, foreign, partitioned, or deposed writer act? | M2, M10, M11 |
| Truth/projection split | Can cache, UI, search, count, or compatibility data become accepted truth? | M4, M6, M7, M9 |
| Evidence producer conflict | Does proof require trusting the same producer whose behavior is being proved? | M0, M8, M9, M13 |
| Verifier manipulation | Can the candidate select, alter, expose, or overfit the judgment path? | M8, M9, M13 |
| Budget reset | Can branch, retry, order, account, or provider fallback evade finite limits? | M3, M8, M9, M14 |
| Cross-tenant leak | Can counts, recents, caches, routes, artifacts, memory, or exports reveal another scope? | M5, M6, M8, M12, M13 |
| Membership/claim leak | Does pairing, discovery, rank, or contribution grant membership, credit allocation, payout, or authority? | M5, M12, M13, M14 |
| Semantic escalation | Can mapping, compatibility, assertion, or ontology membership authorize an action? | M7, M8, M12 |
| Dependency outage | Are unavailable, denied, degraded, recovery, and partial-dependency states honest and safe? | M6, M9, M10, M14 |
| Supply substitution | Does provider/model/worker/tool fallback change rights or semantics without review/evidence? | M8, M9, M14 |
| Release/update substitution | Can unsigned, revoked, downgraded, digest-mismatched, or manifest-substituted install/update material execute or replace the admitted build? | M1, M2, M9, M14 |
| Restore-byte or secret substitution | Can same-size changed bytes, loose plaintext, foreign ciphertext, a stale preflight, or an incomplete manifest mutate the target before full verification and destination-local re-resolution? | M2, M9, M10 |
| Activation/cleanup loss | Can a failed, unknown, late, partial, or superseded change steal the active head, or can deleting a parent erase an unresolved resource-cleanup duty? | M2, M4, M8, M10 |
| Physical safety fault | Can remote/model/chain failure disable local veto, heartbeat, deterministic motion, or e-stop? | M11, FUTURE |
| Economic theater | Does cooperation/network value disappear after subsidy, risk, or token appreciation is removed? | M13, M14, FUTURE |

## Applying it in a work item

- Bind each selected row id to the exact boundary it attacks — route and final invoker, schema/hash,
  head/root, grant, projection, evaluator, budget, dependency, install/restore path, actuator, or
  surplus calculation — never to the estate in the abstract.
- Retain per selected row the probe's expected-path literal bound to exact artifact bytes or a
  committed artifact identity plus the denial outcome; for effect-bearing rows, retain zero-invoker
  evidence from the final invoker.
- Name the canon owner consulted per selected row and cite the conformance profile or fault-matrix
  entry the probe implements where one exists.
- Record every unselected row as an explicit nonclaim with its out-of-boundary reason, and carry a
  partially answered row as a narrowed claim, not a pass.
- Retain negative, inconclusive, and disputed results with the manual interventions, denial reasons,
  verifier disagreements, false accepts and rejects, recovery times, and cost amplification seen
  while producing them.
- Where a probe cannot run against the real boundary and a fixture or manual edit stands in, record
  the substitution and residual obligation instead of reporting the row as answered.

## Terminal evidence

The method contributes to a stage exit when every selected row has a retained, content-bound probe
carrying its denial or narrowing outcome, every unselected row is an explicit nonclaim in the owning
aggregate-exit record, and no answer rests on the producer under evaluation, a fixture standing in
for the real boundary, or a positive path alone. Answering the selected rows for one boundary bounds
that boundary only and proves nothing about rows, routes, profiles, or stages outside the probed
scope.

## Canon gaps

- The failure-class taxonomy itself has no named canon owner: [`_meta/source-of-truth-map.md`](../../../docs/architecture/_meta/source-of-truth-map.md)
  carries no subject row for adversarial failure classes, so this list has no canonical registry to
  be checked against or extended from. That map's owner should name the owner.
- The boundary between observation, mediation, or attribution and actual prevention — the
  coverage-overclaim row — is treated per profile in conformance documents but has no estate-wide
  canonical statement. [`foundations/verifiable-bounded-agency.md`](../../../docs/architecture/foundations/verifiable-bounded-agency.md)
  should resolve what a bounded-agency claim may assert from observed behavior.
- The economic-theater row requires value to survive removal of token appreciation, yet no canon file
  states a zero-appreciation viability condition. [`foundations/economic-flywheel-and-pricing-boundaries.md`](../../../docs/architecture/foundations/economic-flywheel-and-pricing-boundaries.md)
  should resolve it with the marketplace-neutrality owner.
- Sequencer-registry gap, not a canon gap: `modules[]` in [`program/sequence.v1.json`](../program/sequence.v1.json)
  has no `adversarial-proof-matrix` entry, so this module's stage reach is stated only in
  [`program/rules.md`](../program/rules.md) §8 and is resolved in the sequencer.

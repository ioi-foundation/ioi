# Private implementation-directory unification — delegated acceptance review

Document class: dated private review work-record.

Review date: 2026-07-23.

Reviewed checkout: branch `feat/estate-camera-pipeline`, commit
`a894b25054cdb45f27deb3163793773d6449dd2b`.

Authority boundary: this is an independent delegated self-review of the private
docs-and-orchestration transaction. It is not an external, cryptographically
independent, product, architecture, status, or merge approval. Architecture
meaning remains in `docs/architecture/` and accepted ADRs. The sole M0–M14
sequencer remains the
[`master guide`](../../ioi-target-end-state-master-implementation-guide.md),
and live private status remains only in work-item JSON and
[`program-state.json`](../../program-state.json).

## Verdict

**SUBSTANTIVE PASS for the bounded private implementation-directory
transaction.** The corrected estate preserves all 73 baseline bodies, applies
only the explicitly approved SA-1 through SA-9 master delta, retains all 43
historical status values, adds 79 proposed records, closes the record,
aggregate, dependency, contract, proof-gate, architecture, and Hypervisor
planning joins, and leaves every current M0–M14 aggregate exit unsatisfied.

One deterministic after-review condition remains before the transaction owner
may call the private machine transaction sealed: after these review bytes and
the execution report stop changing, create and checker-pin the post-migration
source snapshot/attestation, regenerate the ordinary source manifest, and run
the complete 22-bar `check-implementation-estate.mjs` umbrella. Immediately
before this review was written, 21 bars passed and only the intentionally
unsealed post-migration source-manifest bar failed.

**FULL PHASE-6 ACCEPTANCE IS NOT COMPLETE.** The action plan additionally
requires a clean authoritative checkout, real desktop and narrow Hypervisor
visual evidence, and user acceptance. This checkout has seven recognized
pre-existing tracked edits, the in-app browser is unavailable, and user
acceptance remains external. This review therefore does not declare the
persistent goal complete.

No runtime behavior, tracked canon, application code, conformance file, package
script, work-item status, proof gate, stage, federation, two-sovereign proof,
connected service, L1, cohort, or live embodied capability is implemented or
closed by this verdict.

## Requirement disposition

| Requirement | Review result | Evidence and boundary |
| --- | --- | --- |
| Private boundary and checkout identity | **PASS**, clean checkout **SKIP** | The private estate remains ignored. Branch/HEAD match the frozen baseline. Exactly seven pre-existing tracked paths remain modified and byte-identical to `pre-existing-tracked-changes.v1.json`; `git diff --check` exits 0. A clean-checkout proof was not obtained. |
| Source approval and closed path census | **PASS** | Revision 1 independently selects 309 exact current paths (307 files, two compatibility symlinks), with path-set SHA-256 `97e78da03f31fdb7111c35affe75aaa1a38ed10dcf93615dada48c101e848c31` and complete-row SHA-256 `c342c46e0494f3ebd1dc197fe68cec5f3137fcc4b99c8bc11a698ca3ee7455eb`. The approved snapshot and attestation are byte-pinned as `e1aa9149…c0cec` and `16a1dc1d…9870`. |
| Pre/post recoverability | **PASS before the post-seal bookkeeping condition** | The content-addressed pre snapshot is `4136450a…ca8` and records 79 pre-migration materializations. Independent digest inspection finds 73/73 exact baseline bodies. Four bodies whose repaired destinations changed bytes resolve through the checker-pinned six-row pre-link-repair manifest `688bec67…c6a17`; the other two rows preserve additional repaired history. Compatibility holds are zero. The final post snapshot must be sealed after this review/report freeze. |
| One-time source migration | **PASS** | The live bootstrap is check/refusal-only and contains no writer path. Its replay-capable predecessor is archived at `038d40c7…e343b`. A write replay exits 1. Future additions require a reviewed append-only, predecessor-bound, checker-pinned successor; filesystem discovery cannot approve a path. |
| Approved master amendments | **PASS** | Baseline master `47ce8472…beff`, current master `e2d19235…b190`, approval oracle, and applied patch all match. The exact patch SHA-256 is `f629f6bd6c2cb6eea0fbd97108f9c9a2fadcd315c09a158143b7ffa4e62966df`; the exact approved action-plan source is `9298abb5…138d`. The comparison contains SA-1 through SA-9 and no additional master change. |
| Sole sequencer and stateless guide | **PASS** | The checker sees 27 active Markdown files, exactly one M0–M14 master, zero compatibility holds, and no remaining physical legacy ordering body. Subordinate modules have no independent Phase/Cut order or status authority. |
| Status Truth Rule | **PASS** | The active-estate scan confines durable status to the 122 work-item JSON records and `program-state.json`; it reports zero held status voices. Archives, audits, pointers, evidence, modules, and projections own no current status. |
| Work-item migration and lifecycle | **PASS** | The final record-set SHA-256 is `7e156b31…752c`; the preservation ledger is `ec315b90…516`; the archived replay tool is `9fe989f5…56e7`. The finalization checker sees 122 sealed/current records and zero post-finalization chains. The live migrator permanently refuses replay even if the finalization artifact is removed. |
| Record schema and status preservation | **PASS**, historical checkout refs **SKIP** | All 122 records satisfy the complete private §4.1 contract. Status counts are 115 proposed, four historical verified, one historical scoped, one historical evidence-ready, and one historical active. All 43 pre-existing statuses are unchanged; all 79 added records are proposed; no successful exit log was created. Seven retained historical refs/anchors are absent in this older checkout and remain explicit nonclaim SKIPs. |
| Aggregates, dependencies, and conditional selection | **PASS as plan/orchestration closure** | There are 16 aggregate records: the 15 M0–M14 top-level aggregates plus the historical M1 protected-transition aggregate. Exact child/dependency/status/evidence/literal digests and selection dispositions validate. Every current top-level aggregate is proposed and every current sequencer exit is false. M9 managed optionality, M11 non-live Embodied Systems, and M14 decentralized-profile admission remain machine-readable nonselected conditional children; nonselection manufactures no proof. |
| Proof-gate ownership | **PASS** | All 58 PG definitions have exactly one non-aggregate closure owner: 57 are open and one is not applicable. `PG-1.1` remains selected/required-now, M11-targeted, open, literal-null, and owned by the amendment-gated FUTURE canonical-contract migration candidate. No plan or aggregate closes a gate. |
| Literal and program lifecycle | **PASS**, four historical literals **SKIP** | Bare/task exits are rejected. Current verification requires exactly one expected-path `ioi.program.literal_exit.v1` record binding `BAR`, repository-relative `ARTIFACT`, and `ARTIFACT_SHA256` to checkout bytes or a committed artifact. Four historical verified-record bindings are unavailable here and are not renewed. Lifecycle negatives prove aggregate status, children, dependencies, bindings, PGs, predecessor chain, and literals fail closed. |
| P0 readiness | **PASS as explicit plan coverage; not activated** | `m5-p0-readiness-verifier` joins the current M3–M5 aggregate chain, direct-path preservation, owner literal, dependency closure, and 15 applicable PGs. `program-state.json` reports `planned_not_activated`; every readiness condition is false and the claim gate remains M9. |
| Architecture A–Z coverage | **PASS as reviewed planning coverage** | The projection contains 50 obligations, 174 exact owner/fragment locators, 66 canonical/accepted owner paths, 87 source-of-truth subjects, 14 accepted ADRs, three authoritative planning inputs, 27 registered contract revisions, and 14 active conformance targets. Owner-subject, contract, conformance, ADR, and planning-input orphan counts are zero. The non-generated review ledger SHA-256 is `8f502279…6791`; owner/fragment/scope/mapping changes require a new dated review. Work-item status is excluded from admission identity. |
| Contract and authority semantics | **PASS** | Per-record allowlists distinguish registered contracts, reviewed shape owners, semantic owners, private artifacts, pending definition gaps, and rejected aliases. Product authority remains wallet grants/sealed intents, revocation/current-grant checks at the final invoker, and receipts. Unsigned workflow hash chains remain review evidence only and cannot authorize an effect. |
| Hypervisor source breadth | **PASS as source/plan breadth only** | The deterministic projection covers 20 canon-derived identities, 14 registered surfaces, 39 executable and three dormant seeds, 563 controls, 202 static routes, 76 captured SPA routes, 139 grouped/150 atomic IOI handler templates, and 179/161 source guard occurrences/unique guards. All 71 non-GET templates have one proposed authority-chain disposition covering wallet authority, sealed intent/grant, final-invoker revalidation, receipt, and negative behavior. None is operational proof. |
| Hypervisor transport survey | **PASS as retained GET-only transport evidence** | The retained supported launch records 74 safe GETs: 70 HTTP 200, four HTTP 307, zero request errors. Its command, loopback URL, GET/manual-redirect/nonmutation policy, source hashes, route set, counts, and body metadata validate. It does not independently replay the prior server process and proves no rendering or workflow. |
| Hypervisor rendered-surface evidence | **SKIP / unverified** | The retained browser result is `SKIP`, reason `Browser is not available: iab`, with desktop and narrow read-only obligations. No DOM, responsive, interaction, keyboard, focus, modal, embed, accessibility, or visual-parity result exists. |
| Runtime/schema private projections | **PASS within their named census boundaries** | The runtime-action mirror is byte-equal to canon: 2,202 bytes, SHA-256 `b1869844…c4f0`. The current private runtime census reports 198 baseline methods, 36/110/44/9 service buckets, two retired methods, 52 residual modules, 134 kernel files, and 863 scanned Rust files. Root pointer bodies are not verifier inputs; no tracked verifier hold exists. |
| Report accuracy | **PASS, with its stated future seal** | The corrected execution report's counts, hashes, five walkthroughs, SKIPs, zero-status/zero-stage claims, and unapplied-amendment list match the inspected artifacts. Its post-snapshot paragraph correctly defers that recursive seal until the report and this review stop changing. |

## Work-item and program audit

I compared the preservation ledger, immutable 43-record archive, finalized
122-record manifest, and current work-item files by ID and digest. The review
found no removed finalized identity, no changed historical status, no
non-proposed migration addition, and no current status transaction.

The checker-owned record-specific journeys cover the action-plan application
owners and later proof records. In particular:

- M9 Governance is exactly `review → approve/reject → revoke → enforce →
  appeal → export`;
- M12 federation is exactly `discovery → terms → counter/decline → admission
  → dispute → portable exit`;
- M14 service ownership is exactly `registry → order → delivery → acceptance
  → payment/dispute → suspension → exit`;
- M13 retains preregistered outside-option, cost, risk, benefit, positive-
  surplus, repeat-useful-work, independence, subsidy, and safe-decline floors;
  and
- M14 retains the literal floors for at least three unrelated organizations,
  at least two service families, a preregistered sustained period,
  willingness-to-pay/risk, independent supply, attack/security budget,
  positive safety margin, zero-appreciation viability, and the valid no-L1
  alternative.

The three FUTURE records remain proposed and amendment-gated.
`live-embodied-promotion` has the generic honest-state overlay but no ordered
live journey, no evidence, and no active M0–M14 aggregate membership. The two
contract-registry/failure-injection candidates similarly cannot enter a stage
aggregate without a later explicit master amendment.

The program projection retains historical M0 only as
`historical_pre_2026_07_22_scope`, with checkout validation `SKIP`. Its amended
current M0 aggregate is proposed and unsatisfied. All fifteen current stage
aggregate exits are unsatisfied; no historical status is allowed to satisfy a
new child, amended aggregate, or later stage.

## Five report walkthroughs cross-checked

The execution report's five canon → record → code/UI → evidence → exit
walkthroughs match the source records:

| Record | Canon/owner and anchor check | Evidence and exit check | Review conclusion |
| --- | --- | --- | --- |
| `m1-system-genesis-product-journey` | Seven current owner docs; generated architecture-contract Rust is current precedent only | no evidence refs; `M1_SYSTEM_GENESIS_PRODUCT_JOURNEY_EXIT=0`; seven ordered transitions | Proposed journey only; no System truth or activation proof. |
| `m6-applications-workspace-operational-journey` | Hypervisor core-surfaces owner; `surface-registry.mjs` is current precedent only | no evidence refs; `M6_APPLICATIONS_WORKSPACE_JOURNEY_EXIT=0`; six ordered transitions | Catalog/shell presence is not operational depth. |
| `m9-governance-operational-journey` | Hypervisor, wallet, common/domain, governed-system, invariant, security, and bounded-agency owners; product-UI server is precedent only | no evidence refs; `M9_GOVERNANCE_OPERATIONAL_JOURNEY_EXIT=0`; six ordered transitions | Workflow review evidence grants no product authority. |
| `m12-federation-product-and-operator-journey` | Hypervisor, collaborative outcome/control plane, AIIP, common objects, and ontology owners; generated Rust is precedent only | no evidence refs; `M12_FEDERATION_PRODUCT_JOURNEY_EXIT=0`; six ordered transitions | Planning does not establish federation or the M13 two-sovereign proof. |
| `live-embodied-promotion` | Embodied runtime/receipts, Foundry, common objects, assurance/liability, and physical-safety owners; physical-intent admission Rust is precedent only | no evidence refs; `LIVE_EMBODIED_PROMOTION_EXIT=0`; no ordered live journey | Conditional future only; no actuator, E1+, or M0–M14 closure claim. |

## Adversarial and tamper-negative review

All tamper fixtures were isolated temporary copies or in-memory projections;
the working records, registry, tools, statuses, canon, runtime, and app code
were not edited by these negatives.

| Tamper | Observed result |
| --- | --- |
| Mutate the approved source-disposition snapshot owner row | exit 1; rejected by checker-pinned snapshot SHA-256. |
| Add an unclassified current private path | exit 1; rejected as an unknown current path. |
| Clear `migration_finalized` in the source registry | exit 1; rejected as an unfinalized one-time migration. |
| Change a finalized work-item status without a transaction chain | exit 1; rejected as an unchained status change. |
| Change one byte of the archived replay-capable migrator | exit 1; rejected against the finalized replay-tool SHA-256. |
| Delete the work-item finalization artifact and invoke live replay | exit 1; replay remained permanently refused and all 122 records remained present. |
| Pretend the M14 aggregate is verified and treat every literal as valid in memory | still unsatisfied because current child/dependency and required PG closure fails. |
| Evaluate a nonselected conditional M14 child | it remains outside the required closure set and creates no positive proof. |
| Substitute a bare `*_EXIT=0` line | rejected; only the exact content-bound literal format is accepted. |
| Change architecture owner/fragment/mapping/scope/ADR/planning-input identities in the supplied negative suite | rejected in write and check modes; status alone is deliberately excluded. |

The private seals are checker-pinned self-review controls, not an external
signature or immutable public ledger. Their bounded value is deterministic
tamper detection inside this ignored estate; this review makes no stronger
cryptographic-independence claim.

## Exact command observations

Each PASS below means only that the named private check succeeded. No command
or process exit code is treated as a product or stage proof.

| Command | Observed result |
| --- | --- |
| `check-source-dispositions.mjs` and `bootstrap-source-registry.mjs --check` | PASS: 73 sources, 309 paths, revision 1, row SHA `c342c46e…455eb`. |
| `freeze-source-manifest.mjs --check` before review freeze | expected pre-seal failure: post-migration pins intentionally unsealed. This is the one deterministic after-review condition. |
| `check-work-item-migration-finalization.mjs` and live migrator `--check-finalization` | PASS: 122 sealed/current, zero chains, replay `9fe989f5…56e7`, final set `7e156b31…752c`. |
| Live work-item replay / live source-finalization replay | expected refusal, exit 1 in both cases; no work item, status, or source approval changed. |
| `check-work-items.mjs` | PASS: 122 records; status counts 115/4/1/1/1; seven explicit checkout SKIPs. |
| `check-single-sequencer.mjs` / `check-status-truth.mjs` | PASS: one master; zero compatibility holds or active legacy voices. |
| `generate-approved-sequencer-diff.mjs --check` | PASS: exact patch `f629f6bd…66df`. |
| `check-private-estate-boundary.mjs` | PASS: ignored estate; seven tracked bytes unchanged. |
| `check-module-headers.mjs` | PASS: four subordinate non-sequencing modules. |
| `check-internal-links.mjs` / `check-markdown-structure.mjs` | PASS: 49 physically resolved Markdown files; balanced fences/tables. |
| `check-literal-exits.mjs` | PASS contract validation with four explicit historical-checkout SKIPs. |
| `test-program-state-lifecycle.mjs` | PASS: historical audit non-freezing; aggregate/status/literal/binding/gate/P0 paths fail closed. |
| `generate-program-state.mjs --check` / root `check-program-state.mjs` | PASS: 122 records, 15 stages, historical M0 checkout SKIP; no generated status transaction, literal, or stage-close artifact. |
| Architecture review-ledger negatives / coverage check | PASS: 50 obligations, 174 exact locators, status-free admission identities. |
| Hypervisor crawl / generation / contract checks | PASS: 74 GETs and the exact current source census; visual result remains SKIP. |
| Runtime schema / residual / current trust-census checks | PASS: 2,202-byte mirror; 198 baseline methods; 52 residual modules; zero root-body inputs. |
| `check-generated.mjs` | PASS: five dedicated projections byte-current; no status or stage change. |
| `check-clean-checkout-nonclaims.mjs` | PASS as a checker invocation with machine result **SKIP** for the recognized seven-path dirty checkout. |
| `git diff --check` | PASS, exit 0. |
| `npm run check:work-items` | unavailable, exit 1: tracked package alias is missing; direct private checker used. |
| `npm run check:stateless-master-guide` | unavailable, exit 1: tracked package alias is missing; exact private oracle checker used. |
| `npm run generate:program-state` | unavailable, exit 1: tracked package alias is missing; direct private writer/checker used by the transaction owner. |
| `check-implementation-estate.mjs` immediately before this review | 21 bars PASS; one failure, exactly the intentionally unsealed post-migration source-manifest bar. |

Reviewer process disclosure: while inspecting the corrected 73/73 preservation
join, I accidentally invoked the ordinary
`freeze-source-manifest.mjs --write` once. It refreshed only the generated
ordinary source-manifest projection and emitted `73/73`; it changed no tracked
file, source approval, work item, status, program state, runtime, or app code.
The transaction owner was notified immediately. This accidental writer result
is not proof and does not replace the required ordered regeneration,
post-migration seal, and final umbrella run after this review/report freeze.

## Explicit SKIPs and Phase-6 boundary

| Open obligation | Honest disposition | Smallest next step |
| --- | --- | --- |
| Four historical verified-record literal bindings | **SKIP** in this older checkout | Validate the exact content-bound artifacts in a checkout/ref containing their bytes; do not infer renewed verification. |
| Seven historical evidence refs/anchors | **SKIP** in this incomplete checkout | Validate them in the checkout containing the merged artifacts; absence changes no status. |
| Historical M0 checkout artifact | **SKIP**; only the narrower retained committed-ref proof is described | Validate the exact historical artifact checkout binding; it still cannot satisfy the amended current M0 aggregate. |
| Desktop and narrow rendered Hypervisor surfaces | **SKIP / unverified** because `iab` is unavailable | Repeat the read-only visual crawl with the supported in-app browser and attach dated evidence. |
| Clean authoritative checkout | **SKIP** because seven frozen pre-existing tracked edits remain | Re-run the final private acceptance bar from a clean authoritative checkout. |
| Final user acceptance | pending outside this record | Review the sealed private estate, clean-checkout result, real visual evidence, and remaining amendment proposals. |

The current report correctly keeps three sequencer amendments unapplied and
approval-gated: direct private-command substitutions for absent package
aliases, M7 `OntologyActionContract` terminology normalization, and M11
`EmbodiedUnitIdentity` terminology normalization. Selecting the FUTURE
contract-registry/failure-injection candidates or live embodied promotion also
requires a later explicit sequencer amendment. This review applies none of
them.

## Post-review handoff

These review bytes are now final and must not be edited after the post snapshot
is sealed. The transaction owner must:

1. finish the execution report's delegated-review disposition without changing
   this substantive verdict;
2. regenerate the ordinary source manifest;
3. create and independently checker-pin the post-migration snapshot and
   attestation; and
4. run `freeze-source-manifest.mjs --check`, the complete 22-bar estate
   umbrella, and the final tracked-byte/worktree checks.

If any of those deterministic checks fails, the bounded PASS above is revoked
until corrected and re-reviewed. Even if all pass, full Phase-6 acceptance and
the persistent goal remain **NOT COMPLETE** until the clean checkout, real
desktop/narrow visual evidence, and user acceptance conditions are satisfied.

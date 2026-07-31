# Private implementation-directory unification — corrected execution record

Document class: dated private work record.

Cut dates: 2026-07-22 through 2026-07-23.

Authority boundary: this record reports a private docs-and-orchestration
transaction. It owns no architecture meaning, stage order, live work-item
status, activation, proof-gate closure, product authority, or public claim.
Architecture remains owned by `docs/architecture/` and accepted ADRs. The
sole M0–M14 sequence remains the
[`ioi-target-end-state-master-implementation-guide.md`](../../ioi-target-end-state-master-implementation-guide.md).
Live private status remains only in work-item JSON and the generated
[`program-state.json`](../../program-state.json).

## Result

The approved SA-1 through SA-9 transaction is implemented inside the ignored
`internal-docs/implementation/` estate. The plan-level A–Z gaps have bounded
records, current canon owners, proof definitions, exact future exit contracts,
and closed dependency/aggregate identities. Historical plan bodies are
recoverable; stable legacy paths are inert pointers; deterministic projections
and read-only checks now cover the private estate.

This is not a claim of complete Phase-6 acceptance. Two required external
acceptance conditions remain unavailable:

- the checkout contains seven pre-existing tracked edits and is therefore not
  a clean authoritative checkout; and
- the supported in-app browser returned
  `Browser is not available: iab`, so real desktop and narrow Hypervisor
  visual evidence is unverified.

The private transaction changed no tracked canon, runtime, application,
conformance, or package file. It created no successful exit log, changed no
pre-existing status value, closed no work item or stage, and opened no PR.

## Before, after, and recoverability

| Measure | Before | Corrected estate |
| --- | ---: | ---: |
| Frozen private source bodies | 73 | 73/73 retained by exact SHA-256 |
| Pre-migration materializations excluding the manifest itself | 79 | preserved in the content-addressed pre snapshot |
| Approved current private paths | not sealed | 309, including 307 regular files and two compatibility symlinks |
| Existing work-item records | 43 | 43 preserved plus 79 new proposed records |
| Total work-item records | 43 | 122 |
| Live sequencers | ambiguous-looking historical bodies | one machine-checked M0–M14 master |
| Compatibility holds | legacy premise in the prior report | zero |
| Tracked paths changed by this transaction | 0 | 0 |

The baseline is branch `feat/estate-camera-pipeline`, commit
`a894b25054cdb45f27deb3163793773d6449dd2b`. The seven pre-existing tracked
edits are byte-frozen in
[`pre-existing-tracked-changes.v1.json`](./pre-existing-tracked-changes.v1.json);
the boundary checker continues to match every byte.

The content-addressed pre-migration snapshot is
`4136450a9d07a134c6ef6c64be133d0902b6dad022a1c2d67110c6a8af64fca8`.
The source-disposition root revision seals:

- path set
  `97e78da03f31fdb7111c35affe75aaa1a38ed10dcf93615dada48c101e848c31`;
- complete disposition rows
  `c342c46e0494f3ebd1dc197fe68cec5f3137fcc4b99c8bc11a698ca3ee7455eb`;
- approval decisions
  `9494c9b55e1426a7dc869f7a327810cf10bfa42f104d31454ef16d06fcd2dea2`;
- approved snapshot
  `e1aa9149495c0d943d852265991df106ef89f2332e6d79c4954552f58a5c0cec`;
  and
- approval attestation
  `16a1dc1ddc4a7f53ac3d4f8059093fb72dae596e6452bc066082b82579b29870`.

The live source bootstrap is permanently check/refusal-only. Its exact
replay-capable predecessor remains archived at SHA-256
`038d40c75369641a9a1f2359eb31d8afc26e5d63363a6f4717339c3bf11e343b`.
Future paths require a reviewed append-only successor with predecessor and
exact row-delta binding; filesystem discovery cannot approve them.

The post-migration snapshot and attestation are deliberately sealed only after
this report and the adjacent delegated review stop changing. Their machine
identity is owned by the post-snapshot attestation and
`freeze-source-manifest.mjs --check`, not predicted in this report.

## Physical reconciliation

The first-read route is now:

`README → program-state → sole master → one work item → optional activated
module → canon/code/evidence → exact content-bound *_EXIT line`.

Reusable non-sequencing material lives in:

- `stage-guides/m0/runtime-trust-boundary.md`;
- `stage-guides/m6/product-surface-and-ux-proof.md`;
- `stage-guides/m8/campaign-experiment-method.md`; and
- `proof-gates/mechanism-gate-registry.md`.

Each module declares its activation pointer, canon owners, scope, outputs, and
`does_not_own` boundaries. Superseded bodies are inert under `_archive/`;
dated observations and transactions are under `audits/`; projections are
under `generated/`. The root runtime audit/residual paths are pointers.
The active private runtime verifier is
`tools/verify-runtime-kernel-trust-audit.mjs`; the old ignored script path is
a compatibility wrapper. No tracked verifier depended on a private legacy
body, and no compatibility hold remains.

## Approved sequencer amendments

The approved action-plan source is preserved at SHA-256
`9298abb545e85563c4cd971d2a2fc4b129b8b767bce2c82c9677aff4166f138d`.
The master baseline, current master, and exact applied/oracle patch identities
are:

| Artifact | SHA-256 |
| --- | --- |
| Baseline master | `47ce84723611ff2063c289c8c09e691ab9b61856ef8f503dccc43d4205e6beff` |
| Current master | `e2d19235be492a5aae8a3d9886ac8757ef3712cf548f1433df1d5ac1b351b190` |
| Exact SA-1…SA-9 oracle/applied patch | `f629f6bd6c2cb6eea0fbd97108f9c9a2fadcd315c09a158143b7ffa4e62966df` |

| Amendment | Applied effect |
| --- | --- |
| SA-1 | Removed stale kernel authorities and bounded subordinate modules. |
| SA-2 | Completed the private §4.1 record contract. |
| SA-3 | Made generated architecture coverage an admission/maintenance input. |
| SA-4 | Authorized recoverable archives, tombstones, and exact source-disposition delegation. |
| SA-5 | Removed proof-gate status ownership from prose. |
| SA-6 | Required one disposition for every build-relevant canon target. |
| SA-7 | Added missing aggregate/application-state obligations. |
| SA-8 | Corrected Authority Gateway and `EnforcementCoverageDeclaration` ownership. |
| SA-9 | Assigned approved A–Z contract families without pulling M9–M14 or live-embodied claims forward. |

The generator compares the current guide to a non-generated approval oracle
and refuses any unapproved semantic change. No other sequencer amendment was
applied.

## Work-item transaction and lifecycle

| Measure | Result |
| --- | ---: |
| Immutable pre-migration identities | 43 |
| Pre-existing status values changed | 0 |
| New proposed records | 79 |
| Total records | 122 |
| `proposed` | 115 |
| `verified` (historical) | 4 |
| `scoped` (historical) | 1 |
| `evidence_ready` (historical) | 1 |
| `active` (historical) | 1 |
| Successful exit logs created | 0 |

The finalized record-set SHA-256 is
`7e156b3187ec644a06494dd45e221f963150c987de25b414c1ed9e24a818752c`.
The preservation ledger is
`ec315b9054be74b99f7acbd6ad774ac603e22565631f2084540b92294116a516`.
The replay-capable migrator is archived at
`9fe989f5064604202545784de20b4c559fa067edc7cbf5567f787afd207c56e7`;
the live entry point permanently refuses replay.

Future legitimate changes are not frozen to the reconciliation statuses.
Instead, a changed or new record must carry an append-only status transaction
chain binding predecessor/current payload hashes, evidence, date, and the
strict content-bound literal for any transition to `verified`.

Aggregates bind exact child, dependency, evidence, status-at-binding, and
literal digests. Conditional children have explicit selected/not-selected
dispositions. An aggregate cannot manufacture closure from prose, an
unverified child, a stale binding, an open required proof gate, or a task exit
code.

## Architecture and program coverage

The generated architecture projection covers:

- 50 reviewed build-relevant obligations;
- 174 exact owner/fragment locators;
- 66 canonical or accepted owner paths;
- 87 source-of-truth owner subjects;
- 14 accepted ADRs;
- three authoritative planning inputs;
- 27 registered contract revisions; and
- 14 active conformance targets.

Owner-subject, contract, conformance, ADR, and planning-input orphan counts are
all zero. The non-generated reviewed ledger has SHA-256
`8f50227960a2a1b0206bcd3ccba44407ebfb5f9a85bf9dd8376e9493d93d6791`;
changed canon locators or mapping identities require a new dated review
ledger. Work-item status is deliberately excluded from the coverage join.

The regenerated program projection contains all 122 records and all 15 stage
rows. Every current M0–M14 sequencer exit is unsatisfied. P0 is
`planned_not_activated`: it requires the current M3–M5 aggregate chain,
direct-path preservation, the readiness-owner literal, dependency closure, and
15 applicable proof gates. Historical M0 evidence remains narrowly described
and does not satisfy the amended current M0 aggregate.

Strict literal validation accepts exactly one expected-path
`ioi.program.literal_exit.v1` line whose `BAR`, `ARTIFACT`, and
`ARTIFACT_SHA256` bind checkout bytes or an exact committed artifact
identity. Bare literals and task/process exit codes do not count.

## Hypervisor source and read-only survey

The supported command
`npm run serve:product-ui --workspace=@ioi/hypervisor-app` was launched on
fresh loopback ports 4273/9401 for the retained crawl and then stopped. The
pre-existing 4173/9301 process was not touched.

| Source/crawl fact | Result |
| --- | ---: |
| Canon-derived product identities | 20 |
| Registered surfaces | 14 |
| Executable parity seeds | 39 |
| Dormant seeds | 3 |
| Controls | 563 |
| Static route strings | 202 |
| Captured SPA routes | 76 |
| Grouped normalized IOI handler templates | 139 |
| Atomic normalized IOI handler templates | 150 |
| Source guard occurrences / unique guards | 179 / 161 |
| Consequential mutation dispositions | 71 |
| Safe retained GETs | 74 |
| HTTP 200 / 307 / request errors | 70 / 4 / 0 |

Every one of the 71 mutation dispositions maps the wallet/sealed-authority
requirement, final-invoker revalidation, effect receipt, and negative
behavior. This is plan/source breadth, not operational proof. A route, shell,
fixture, redirect, mock body, screenshot, or HTTP response cannot prove an
application journey or authorize an effect.

Visual verification remains machine-readable `SKIP` with desktop and narrow
obligations. No DOM, responsive, interaction, keyboard, focus, modal, embed,
accessibility, or visual-parity claim is made.

## Five canon-to-exit walkthroughs

| Subject | Canon and contracts | Current code/UI anchor | Evidence and future exit | Bounded conclusion |
| --- | --- | --- | --- | --- |
| M1 system genesis | Hypervisor surfaces, wallet authority/risk, common objects, governed systems, invariants; system manifest/genesis/profile/sequence-zero/constitution/receipt families | `crates/types/src/app/generated/architecture_contracts.rs`, current precedent only | no retained evidence; `M1_SYSTEM_GENESIS_PRODUCT_JOURNEY_EXIT=0` | Planned review → preview → admit → initialize → activate → receipt → recover/dissolve journey; proposed only. |
| M6 Applications workspace | `core-clients-surfaces.md`; surface registration/release/install/serve/projection/alias families | `apps/hypervisor/scripts/surface-registry.mjs`, current precedent only | no retained evidence; `M6_APPLICATIONS_WORKSPACE_JOURNEY_EXIT=0` | Planned catalog → search/filter → detail → open → unavailable/denied → alias/return journey; shell presence is not depth. |
| M9 Governance | Hypervisor, wallet, common/domain kernels, governed systems, invariants, security, bounded agency; constitution/amendment/lifecycle/grant/flow/receipt families | `apps/hypervisor/scripts/serve-product-ui.mjs`, current precedent only | no retained evidence; `M9_GOVERNANCE_OPERATIONAL_JOURNEY_EXIT=0` | Planned review → approve/reject → revoke → enforce → appeal → export journey; unsigned workflow hashes grant no authority. |
| M12 federation | Hypervisor, collaborative-outcome/control-plane, AIIP, common objects, ontologies; AIIP channel/envelope/binding, terms, discovery, admission, task, acceptance, settlement, mapping/action families | generated architecture-contract Rust, current precedent only | no retained evidence; `M12_FEDERATION_PRODUCT_JOURNEY_EXIT=0` | Planned discovery → terms → counter/decline → admission → dispute → portable exit; no M13 two-sovereign proof is inferred. |
| FUTURE live embodied promotion | Embodied runtime, receipts, Foundry, common objects, assurance/liability, physical safety; runtime graph/stream/supervisor/intent/receipt/assurance/lease families | physical-action-intent admission Rust, current precedent only | no retained evidence; `LIVE_EMBODIED_PROMOTION_EXIT=0` | Conditional future honest-state overlay only; no ordered live journey, actuator path, E1+, or M0–M14 closure claim. |

## Validation record

Each `PASS` below is only the bounded read/write/check result named. It is
not an exit bar, implementation proof, or status transition.

| Command or command family | Result |
| --- | --- |
| `sync-runtime-action-schema.mjs --write/--check` | PASS; 2,202-byte canonical mirror, SHA-256 `b1869844…c4f0`. |
| `generate-runtime-kernel-residual.mjs --write/--check` | PASS; 198 baseline methods, 52 residual modules, current private verifier PASS, zero root-body inputs. |
| `generate-approved-sequencer-diff.mjs --write/--check` | PASS; exact oracle/applied patch `f629f6bd…66df`. |
| Architecture ledger negative tests and `generate-architecture-coverage.mjs --write/--check` | PASS; 50 obligations and 174 reviewed exact locators. |
| Supported Hypervisor launch plus `capture-hypervisor-live-crawl.mjs --write/--check` | PASS as GET-only transport evidence; visual evidence remains SKIP. |
| `generate-hypervisor-surface-coverage.mjs --write/--check` and semantic checker | PASS; 14 surfaces, 39 seeds, 563 controls, 202 routes, 74 retained GETs. |
| Program lifecycle negative tests and `generate-program-state.mjs --write/--check` | PASS; 122 records, 15 stages, historical M0 checkout result SKIP. |
| Root `check-program-state.mjs` | PASS with the same explicit M0 checkout SKIP; no current aggregate satisfied. |
| Work-item finalization checker and live migrator `--check-finalization` | PASS; 122 sealed/current records, zero post-finalization chains. |
| Live work-item replay attempt | expected refusal, exit 1; no write occurred. |
| Work-item checker | PASS; 122 schema-valid records and seven explicit absent-checkout-reference SKIPs. |
| Literal-exit checker | PASS contract validation with four historical literal SKIPs; no task exit code inspected. |
| Source-disposition checker and live bootstrap `--check` | PASS; 73 sources, 309 approved paths, exact row seal. |
| Live source-finalization replay attempt | expected refusal, exit 1; no write occurred. |
| Source approval tamper tests | PASS as negative tests: self-authored/rehashed approvals, unknown paths, and cleared-finalization replay all rejected. |
| Single-sequencer, status-truth, private-boundary, module-header, physical-link, Markdown-structure, generated-projection, and clean-checkout-nonclaim checks | PASS within their named boundaries; clean checkout is SKIP. |
| `git diff --check` and tracked-byte comparison | PASS; only the same seven pre-existing tracked paths remain modified. |
| `npm run check:work-items` | unavailable: missing tracked package alias; direct private checker used. |
| `npm run check:stateless-master-guide` | unavailable: missing tracked package alias; exact private sequencer-oracle checker used. |
| `npm run generate:program-state` | unavailable: missing tracked package alias; direct private writer/checker used. |

The ordinary source manifest is regenerated after this report/review
transaction. The post snapshot then content-binds the final report and review,
and its checker supplies the final machine result without creating a circular
self-hash in this document.

## Explicit SKIPs and remaining acceptance boundary

| Obligation | Machine disposition | Nonclaim / smallest next step |
| --- | --- | --- |
| Four historical verified-record literal bindings | SKIP in this older checkout | Validate the retained artifacts in a checkout/ref that contains their exact bytes; preservation is not renewed verification. |
| Seven historical evidence refs/anchors | SKIP in this incomplete checkout | Validate in the checkout containing the merged artifacts; absence changes no status. |
| Hypervisor desktop and narrow rendering | SKIP: `iab` unavailable | Repeat the safe visual crawl with the supported in-app browser and attach dated M6 evidence. |
| Clean authoritative checkout | SKIP: seven pre-existing tracked edits | Repeat the final private acceptance bar in a clean authoritative checkout while preserving this private estate. |
| Final user acceptance | pending outside this work record | Review the corrected estate, visual evidence, clean-checkout run, and any remaining amendments. |

Because Phase 6 explicitly requires a clean authoritative checkout, real
desktop/narrow evidence, and user acceptance, this report does not declare the
whole action plan accepted or the persistent goal complete. All recoverable
private work is preserved at the exact external boundary.

## Delegated review

The adjacent
[`2026-07-22-delegated-self-review.md`](./2026-07-22-delegated-self-review.md)
owns the fresh independent review verdict at SHA-256
`60e12cee54bc189c9c97e34fbb865889bef274043e74a5c85f12207fcf3d0423`.
It returned **SUBSTANTIVE PASS for the bounded private transaction**, with the
post-migration seal and final 22-bar umbrella as the sole deterministic
after-review condition. It separately reports **FULL PHASE-6 / persistent goal
NOT COMPLETE** because clean-checkout, real desktop/narrow visual evidence, and
user acceptance remain external. The prior inaccurate review/report bodies
are preserved byte-exact under `_archive/pre-correction-reviews/`. This edit
does not alter the delegate's frozen substantive verdict.

## SEQUENCER AMENDMENTS — not applied

SA-1 through SA-9 were explicitly approved and applied. The following changes
remain unapplied and require the user's separate sequencer approval:

1. **Direct command-path substitutions.** Replace absent
   `npm run check:work-items` / `npm run generate:program-state` aliases
   with their direct private commands at the affected master locations.
2. **M7 contract-name normalization.** Change
   `OntologyActionContracts` to canonical `OntologyActionContract`
   terminology (wire family `OntologyActionContractEnvelope`).
3. **M11 identity-name normalization.** Change `EmbodiedUnit` to canonical
   `EmbodiedUnitIdentity`.

Later selection of the FUTURE contract-registry/failure-injection candidates
or live embodied promotion also requires an explicit sequencer amendment.
None is activated by this transaction.

## Retained nonclaims

- Product authority remains wallet grants/sealed intents, revocation,
  final-invoker equality, and receipts.
- Delegated workflow evidence is an unsigned hash chain and cannot authorize a
  product effect.
- No stage or work item is closed.
- No proof gate is closed by a plan, checker, task exit, route, shell, crawl,
  screenshot, or report.
- M9–M14 federation, two-sovereign, connected/secured-service, demand, L1,
  cohort, and public-claim language remains gated.
- Live embodied operation remains outside the active M0–M14 closure path.

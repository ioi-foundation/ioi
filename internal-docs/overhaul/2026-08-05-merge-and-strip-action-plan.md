# Merge-and-Strip Action Plan — 2026-08-05

Owner directive: merge current work to master, strip all implementation guides,
remove virtually all apparatus of proof while leaving the product untouched —
testing and proof generation that consumes iteration (evidence transcripts,
fixtures-for-checkers, context inhibitors) goes; the product and its doctrine
stay.

Status: DRAFT for owner ratification. Execution assignments in §8.
Rollback guarantee: §9 — everything stripped remains recoverable from tags.

---

## 1. Objective and non-goals

**Objective.** One merged master containing all in-flight product work, then a
single strip change that removes the proof apparatus: the sequencer estate, the
M0 program-control machinery, retained evidence, the checker/ratchet fleet, the
certification harness, and the ceremony rules that bind commits to them.

**Non-goals — explicitly untouched:**
- Product code: `crates/*`, `apps/*` (including the vendored `apps/ioi-ai`),
  `packages/*`, product-ui.
- Product tests: every `cargo test` suite (ioi-services ~3,483, ioi-node ~489,
  agentgres ~50, etc.), TS unit tests. These test the product, not the proof.
- Canon: `docs/architecture/**` (doctrine, ADRs, contract registry, schemas).
- Vendoring legality: `apps/ioi-ai/LICENSE` (MIT) and
  `IOI-ADOPTION-PROVENANCE.md` stay — legal provenance, not proof ceremony.
- Git history: nothing is rewritten; the strip is ordinary deletion commits.

## 2. Current state (measured 2026-08-05)

| Branch | Tip | Content |
|---|---|---|
| `master` | `5e1899e29` | pre-M5 baseline |
| `agent/hypervisor-m5-event-substrate` | `a4595e517` | event-substrate product code + 73 commits incl. apparatus |
| `agent/hypervisor-m5-qm-dormant-adoption` | `638841062` | contains substrate (rebased) + vendored `apps/ioi-ai` (1,224 files, blob-SHA-identical to pin `5eb33933…`) |
| `agent/canon-leg-r08-r12` | `d308ea74e` | off master; R-08 family 1/10 (registry + Rust type) |

Apparatus inventory (substrate tip): `internal-docs/implementation/` **1,530
files**; `docs/evidence/` **37 tracked files**; `scripts/` **24 check-\*, 44
verify-\*, 7 test-\*, 4 m0-program-control\***; **23 `check:` npm scripts**;
**547 schema fixture files**.

## 3. Phase 0 — freeze and tag (same day)

1. Cancel in-flight ceremony: QM packet v4.1 work stops (moot); the pending
   Codex re-review round is withdrawn; canon-leg families 2–10 pause.
2. Tags (annotated, pushed): `pre-overhaul/master`,
   `pre-overhaul/m5-event-substrate` at `a4595e517`,
   `pre-overhaul/qm-dormant-adoption` at `638841062`,
   `pre-overhaul/canon-leg` at `d308ea74e`.
3. Apparatus freeze already in force; it now covers everything until the strip
   lands.

## 4. Phase 1 — merge train (product to master, apparatus rides along and dies in Phase 2)

Merging apparatus first and stripping second keeps history linear and honest —
no cherry-pick surgery, no claim that the apparatus never existed.

- **PR-A**: `agent/hypervisor-m5-qm-dormant-adoption` → `master`.
  Brings the substrate (event-stream product code in `crates/agentgres` +
  daemon routes) AND the vendored tree in one merge, since the QM branch
  contains the substrate by rebase. No further packet/claims work required
  before merge — the vendoring is blob-SHA-proven against the pin and that
  evidence rides in the same merge for the record.
- **PR-B**: `agent/canon-leg-r08-r12` → `master` (family 1 registration:
  contract registry row + deriving Rust type + fixtures). Rebase on post-PR-A
  master; expected conflict-free.
- Merge mechanics: user merges (standing permission boundary). CI requirement
  for these two PRs: Build-and-Test only; estate gates are not required checks
  (they die next phase).

## 5. Phase 2 — the strip (single PR on merged master: `overhaul/strip-proof-apparatus`)

### 5.1 Delete outright

| Tree | Scope | Notes |
|---|---|---|
| `internal-docs/implementation/**` | all ~1,530 files | master guide, stages, modules, work-items, program/, claims-coverage/, generated/, NOW.md, all estate tools (transition, certify-stage, claims, reconcile, generate-now, regenerate wrapper, canon-map). The concepts of literal / typed transition / stage certification / claims manifests retire with it. |
| `docs/evidence/**` | all 37 tracked files | census, review epochs, anchor chain, all retained transcripts and packets (m0-program-control, m5-event-substrate, qm-dormant-adoption, M2/M4 runs). History keeps them; tags make them one command away. |
| `scripts/m0-program-control*` (4 files incl. lib model + tests) | all | effect census, epochs, discovery walk. Kills the census machinery **and with it**: the duplicated-corpora defect, the null-child walker defect, the discovery-exclusion machinery for `apps/ioi-ai` — all become moot. |
| `scripts/check-*` (24) | all except §5.2 keep-list | attestation-chain (+integration test), pre-next-leg (+pinned vectors +gate tests), shared-schema-defs, agentgres-ref-minting (+baseline), discovery-exclusions, tracked-callers, internal-architecture-headers, work-item-contract, packet-convention-baseline, etc. |
| `scripts/verify-*` (44) | all | the certification/journey harness (M4 aggregate 98-check, activation-plane 44, journey suites, harvest/rebind verifiers). Product regression safety = cargo/TS test suites, which stay. |
| `scripts/test-*` (7) | all that test the checkers | tests of deleted apparatus die with it. |
| CI | `m4_stage_proof` job; census/fingerprint refusal steps; any estate-gate required checks | Build-and-Test remains the required check. |
| `package.json` | all 23 `check:*` scripts except §5.2 | `lint`, `typecheck`, `build`, `test` remain. |
| `.cargo/config.toml` | remove `incremental = false` | evidence-stability setting; iteration speed returns. Per-run target-dir practice retires. |
| `.gitignore` | remove `docs/evidence` exception blocks | moot after deletion. |

### 5.2 Keep (explicit keep-list)

- `docs/architecture/**` in full — including `_meta/schemas/` registry +
  schemas + invariants + **fixtures (547 files, kept as inert data)**. They
  describe product contracts. Post-strip, no CI step ratchets them; the
  reassessment decides if one fast schema-validity check returns.
- `internal-docs/architecture/**` (thesis register, licensing opener, AFT
  protocol specs) and `internal-docs/audits/**`, `internal-docs/prompts/**`,
  `internal-docs/overhaul/**` (this plan) — content, not apparatus. The header
  convention survives as prose in that directory's README; its checker dies.
- `apps/ioi-ai/**` verbatim + LICENSE + adoption provenance; the root
  `package.json` workspace exclusion for it (product config, one line).
- All product test suites and the plain CI Build-and-Test workflow.
- `CLAUDE.md`, brand docs, public-site trees — out of scope.

### 5.3 Carried forward as plain work items (no ceremony attached)

Recorded at the tail of this file so nothing silently vanishes; they enter the
reassessed plan as ordinary engineering tasks:

1. M5 remaining product cuts: GoalRun thread-orchestration **seam** (re-home
   the JSONL side-spine onto the event substrate), local-agent pairing,
   participant-frontier closeout.
2. R-08 families 2–10 (registry + Rust types; owner-file reading per family 1),
   plus R-09..R-12-residual, R-01/R-02 canon items — the ratified canon agenda
   is unaffected by the strip.
3. `ioi-node` failing test `unreadable_room_never_consumes_submit_or_admit_
   recovery_intents` (fails identically on master) — product bug.
4. R-03 licensing ADR track (external counsel; unaffected).
5. QM executable rebind (M6): now needs no exclusion-drop (census is gone);
   its real obligations remain — serve-layer IOI branding, Postgres→Agentgres
   rebind, null-guard concern is moot.

## 6. Phase 3 — clean-slate scaffold

- `docs/ROADMAP.md` stub: two paragraphs — what shipped through M5-era work
  (event substrate, vendored reference shell, contract registry), and that
  implementation planning restarts from the owner's reassessment.
- Optional (owner default: yes, one page): `docs/engineering-lessons.md` — the
  defect ledger distilled to its ~10 transferable lessons (read the retained
  bytes; the resolver's view is the reachability; instrument before you aim;
  a claim of absence is a claim about the whole tree; …). One page, no
  machinery, no obligations.

## 7. Phase 4 — verify and communicate (light, by design)

- Post-strip verification is exactly three commands: `cargo build` green,
  `cargo test` workspace green (1 known pre-existing failure, item §5.3.3),
  `npm run lint && npm run typecheck` green. No other bars exist to satisfy.
- Reviewer (Codex): formally released from the M5 review program with thanks;
  future review engagements are per-request, not per-cut.
- Director memory: prune obsolete standing rules (M0 regen-in-change, epoch
  mechanics, install-estate prohibition, literal/transition rules) after the
  strip lands so future sessions don't enforce dead ceremony.

## 8. Execution assignments

| Step | Who |
|---|---|
| Phase 0 tags + freeze notices | implementer |
| PR-A, PR-B prep | implementer |
| PR merges | owner |
| Strip PR authorship (§5 tables are the spec) | implementer |
| Strip PR merge | owner |
| Phase 3 scaffold + Phase 4 verification | implementer |
| Reviewer release note, memory prune | director |

## 9. Rollback

Every deleted byte exists at the four `pre-overhaul/*` tags. Restoring any
tool, transcript, or the entire estate is `git checkout pre-overhaul/<tag> --
<path>`. No archive directories are kept in the working tree — the tags are
the archive.

## 10. Owner decision defaults (proceed unless overridden)

1. Cancel the pending Codex QM round and merge PR-A without it — **default:
   yes** (the vendoring's one real claim is blob-SHA-proven and rides along).
2. Schema fixtures kept as inert data — **default: yes**.
3. One-page distilled lessons doc — **default: yes**.
4. Delete the entire journey/certification harness (no smoke e2e kept) —
   **default: yes**; cargo/TS suites are the safety net.
5. Canon-leg families 2–10 resume after the strip as plain tasks — **default:
   yes**.

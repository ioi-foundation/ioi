# QM reference shell — dormant adoption (packet v2)

**Measured detached at `778bfda1c`** in a dedicated worktree. Both subjects were
asserted present *before* anything was measured
([`subjects-present-at-measurement.txt`](subjects-present-at-measurement.txt)):
the adopted tree at 1224 files, the gate that hides it, and the completeness bar.
Every transcript carries `IOI_MEASURED_COMMIT`, `IOI_EXPECTED_EXIT`,
`IOI_EXIT_CODE` and `IOI_VERDICT` — negatives included, because a bare `exit 1`
cannot tell a gate that refused correctly from one that broke.

## What this cut claims

**Pinned verbatim vendoring, dormant.** `apps/ioi-ai/` is upstream QM at pin
`5eb3393315b45b338b860572ab516db9f6eae6da`, byte-for-byte, minus a declared
strip list, plus one provenance file. It is not served, not rebound, not built,
and registers no route. It carries **no** parity or executable claim.

It is explicitly **not** "adoption with rebranding". There was no display-only
branding in this tree: every YC string is `@yc-software/qm` — an npm package
identity, even inside `.md` files where it sits in copy-pasteable install
commands — or `yc-software/qm` in a git-origin check. The earlier "14 files
rebranded" was 14 files of *identity rewriting* wearing a rebrand's name.

## Proofs

| proof | expected | got | verdict |
|---|---|---|---|
| [i — refusal without declaration](proofs/proof-i-refusal-without-declaration.txt) | exit 1 | 1 | as-declared |
| [ii — pass with the exclusion printed](proofs/proof-ii-pass-with-exclusion.txt) | exit 0 | 0 | as-declared |
| [iii — teeth on a tracked edge](proofs/proof-iii-teeth-on-edge.txt) | exit 1 | 1 | as-declared |
| [iv — resolver asked, workspace absent](proofs/proof-iv-workspace-unreachable.txt) | exit 1 | 1 | as-declared |

Proof iv's `exit 1` **is** the green state: npm's own resolver answers
`No workspaces found: --workspace=apps/ioi-ai`. The expectation is declared in
the transcript so the code cannot be misread as a failure.

## Gates

| gate | result |
|---|---|
| [adoption-completeness](gates/gate-adoption-completeness.log) | **PASS** — 1224 files by blob SHA, 0 discrepancies |
| [m0-program-control](gates/gate-m0.log) | PASS |
| [discovery-exclusions](gates/gate-discovery-exclusions.log) | PASS |
| [tracked-caller-census](gates/gate-tracked-callers.log) | PASS |
| [internal-architecture-headers](gates/gate-internal-architecture-headers.log) | PASS |
| [attestation-chain](gates/gate-attestation-chain.log) | PASS |
| [pre-next-leg-gate-regressions](gates/gate-pre-next-leg-regressions.log) | PASS (4/4) |
| [check-estate](gates/gate-check-estate.log) | FAIL at measurement — **closed since**, see below |
| [work-item-contract](gates/gate-work-items.log) | FAIL — **pre-existing on master**, filed, see below |
| [claims-coverage](gates/gate-claims-coverage.log) | FAIL — see below |

## The six findings, dispositioned

1. **Machine identities were forged.** 11 rewrites of `@yc-software/qm` and a
   live tarball URL — one pointing at a repository that does not exist. All 11
   restored from pinned blobs and verified by blob SHA. **Closed.**

2. **The adoption was silently incomplete.** Three upstream `.gitignore` files
   were never added, because `git add -A` honours a `.gitignore` inside the tree
   being added. The strip list was true about what was *removed* and silent about
   what git *declined to add*. Restored; upstream rebuilt from the pin
   (1277 blobs). **Closed.**

3. **Nothing checked completeness.** Now
   [`check-adoption-completeness`](../../../scripts/check-adoption-completeness.mjs)
   does, in **both** directions by blob SHA, with the upstream side rebuilt from
   the pin via `git ls-tree` against a bare clone — never from a working copy.
   An earlier pass diffed against a copy produced by the same skip mechanism it
   was meant to detect, and so reported 1222 upstream files where the pin has
   1277: *the verifier must not inherit the subject's enumeration.* It also
   refuses a **stale deviation** — an entry byte-identical to upstream — which
   caught six entries I had seeded from memory rather than measured.
   **Closed.**

4. **The tree was reachable as an npm workspace** while declared dormant. The
   teeth now ask npm's own resolver rather than `npm query`, which answers from
   the **lock** — a cached resolution that reported the tree unreachable while
   the config globbed it. Red-proven reachable first, then closed.
   **Closed.**

5. **The cut was invisible to the claims gate.** It had no manifest, so the gate
   could not see it — include-list fail-open. Manifest authored, and the
   **converse bar** added: every `docs/evidence/*/PACKET.md` must be *named* by a
   manifest, matched on an **exact path** rather than inferred from slug words,
   with teeth in both directions. The bar prints its own surface size on every
   run (1 `PACKET.md` across 52 evidence directories), so a bar inspecting one
   directory cannot read as though it inspected fifty-two. **Closed.**

6. **The rebind's obligations were prose.** They are now mechanical: M6's first
   act drops the exclusion and brings the tree into the census, which re-exposes
   the null-child crash the exclusion currently hides — so
   `m0-effect-walk-null-child-guards-successor` is a hard **dependency**, not a
   note. Branding moved to the rebind record, scoped to the **served surface** at
   the display and config layer, never to vendored identity bytes. **Closed.**

## Found while measuring — three defects the re-run surfaced

**A negative control that had stopped being negative.** Proof iii wrote its
synthetic edge as an **untracked** file. The teeth enumerate with `git ls-files`,
so the control was invisible, the gate reported PASS, and a no-op wore the shape
of evidence. Tracking the file exposed a second, real defect underneath: the
reachability regex required `import … from`, so a **bare side-effect import** —
the one form whose only purpose is to *run* a module, and the most common way to
reach a dormant tree — did not match. An earlier narrowing of that regex,
correctly aimed at killing mention-based false positives, had taken the
side-effect form with it. Six edge forms are now covered and each is red-proven
on the real excluded tree; a prose mention still does not fire. *Two defects were
stacked, and the outer one was hiding the inner one.*

**The claims gate could not read its own runners.** It recognised `PASS <label>`
and cargo's `… ok`, but not `<name>: PASS (0 error, …)` — the form every
`check-*` executable in this estate prints. And it demanded PASS bytes for
**every** claim, which makes an adversarial proof unmappable, since such a
proof's whole value is the refusal. That pushes the strongest evidence in a cut
out of the gate — the same fail-open one level down. A claim may now declare
`expected_verdict: "refusal"`, and the bar for it is **stronger**, not weaker:
the transcript must show a *pre-declared* refusal (`IOI_EXPECTED_EXIT` set to a
specific code, non-zero `IOI_EXIT_CODE`, `IOI_VERDICT=as-declared`). A proof that
merely happened to fail is indistinguishable from a broken gate — which is
exactly how the no-op above passed for evidence. Both branches red-proven: a
`FAIL` line satisfies nothing, and an undeclared refusal is refused.

**A gate that can only pass in one working copy.** `check-work-item-contract`
resolves private artifact paths under `internal-docs/prompts/`, which
`.gitignore` line 128 excludes wholesale. Confirmed **pre-existing on master** by
a detached run (FAIL, 5 error), so it is filed against its owner as
`work-item-private-artifact-paths-are-gitignored` rather than repaired inside an
adoption. The failure mode is not the detached FAIL — it is the working-copy
PASS, the one nobody investigates.

## Open, and stated rather than resolved

**The M5 substrate cut's retained evidence no longer covers this tip.** Its
manifest measures `0c92fa66e`, which **is** an ancestor of `778bfda1c`, but the
delta between them carries 1,272 non-evidence files (1224 under `apps/`, 39 under
`internal-docs/`, 7 under `scripts/`). The ancestry-plus-evidence-only-delta rule
therefore refuses it, correctly: this cut changed real bytes beneath a claim that
had been measured without them. That accounts for **all 7** remaining
claims-coverage errors. The M5 evidence is sound at its own commit; on this
branch it is stale by construction. **This packet does not re-certify it** — the
QM cut does not own the M5 substrate's claims — and the re-measurement is the
director's call, at merge or before.

**check-estate** failed at measurement time solely because the newly filed record
was not yet named in `stages/m9.md`; it is named now and the gate is green. That
green is *not* in the retained bytes above, because the bytes are honest about
the commit they measured.

## Method notes worth keeping

* I committed once over a red test, having read `tail -2` of a TAP stream — `# todo 0` and a duration, both true, neither a verdict — and a pipe had already discarded the exit status. Read `^not ok` and `# fail`; never let a pipe eat the exit code of the thing being judged.
* The `adoption-completeness` bar had **no tracked caller** on the day it was built. The census refused it immediately, which is the entire reason the census exists — the class it kills used to take three rounds and an external reviewer.
* Adding that gate broke the execution-**order** pin, which is literal data independent of the production list. That is the pin working: a new gate cannot enter the run without someone writing it down.

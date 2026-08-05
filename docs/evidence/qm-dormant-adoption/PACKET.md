# QM reference shell — dormant adoption (packet v4)

**Measured detached at `81ca7eac6`** in a dedicated worktree. Both subjects were
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
| [check-estate](gates/gate-check-estate.log) | PASS |
| [pre-next-leg-gate-regressions](gates/gate-pre-next-leg-regressions.log) | PASS (4/4) |
| [pre-next-leg **full suite**](gates/gate-pre-next-leg-full.log) | FAIL (1) — inherited from the M5 cut, filed |
| [work-item-contract](gates/gate-work-items.log) | FAIL (5) — pre-existing on master, filed |
| [claims-coverage](gates/gate-claims-coverage.log) | FAIL (13) — 7 substrate-owned stale, 6 disclosed below |

A [master baseline](gates/baseline-master-full-suite.txt) accompanies the full
suite, so "inherited" is a measurement rather than a claim: master exits **0**.

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

## Ruling A retracted — substrate suites re-measured, 13/13 green

The disclosed-stale disposition is **withdrawn by the director**, and Codex was
right: under the sole admissibility rule a red required gate cannot underwrite a
literal, disclosure or no disclosure. A scoping valve the rule does not have is
not a disposition.

So the substrate evidence was **re-measured at this commit** rather than
explained. `claims-coverage` is **PASS, 13/13**, with no scoping story and no
claim-scoping machinery built.

| substrate suite | result |
|---|---|
| [agentgres](gates/suite-agentgres.log) | **50/50 ok** |
| [injection boundary](gates/suite-boundary.log) | **ok** |
| [m5 genericity](gates/suite-m5-genericity.log) | **PASS** |
| [ioi-node](gates/suite-ioi-node.log) | 488 passed, **1 failed — pre-existing on master** |

**THE TALLY DEFECT, corrected.** The v3 transcript said `0/13` while my report
and the relay both said 7. Recorded-verdict-versus-retained-bytes — in the packet
that closed that very class, by both of us. The cause: I read the gate *after*
the evidence-only commit landed and reported that number, while the retained
bytes had been produced *before* it. **A verdict repeated from memory is not a
verdict read from bytes.** Every number in this packet is now the number in the
transcript beside it.

**TWO INVOCATIONS I COULD NOT LOOK UP, because nothing recorded them.** No
transcript under `m5-event-substrate/` carried the *command* that produced it —
only the commit. So I guessed `-p ioi-agentgres`, which does not exist, and the
suite failed on my own fabrication before the real name (`agentgres`) was read
out of `crates/agentgres/Cargo.toml`. The other two were recovered by grepping
the evidence for its own test names and PASS strings. **Every transcript in this
round therefore carries `IOI_COMMAND` and `IOI_WORKDIR`** alongside the commit,
so the next person re-measures instead of reconstructing.

**The one ioi-node failure is pre-existing**, and that is measured rather than
narrated: `unreadable_room_never_consumes_submit_or_admit_recovery_intents` fails
identically on master ([negative control](gates/negative-control-master-room-participation.log)),
which is also the R2-5 idiom applied to the work-item-contract baseline
([here](gates/negative-control-master-work-items.log)).

## Found in the v3 round (retained)

**The ratchet pinned bytes nobody else can see.** I built the pre-convention
baseline with `readdirSync` over my working copy — 51 directories. `.gitignore`
line 58 ignores `docs/evidence/*` wholesale, so the repository holds **six**.
Forty-six pins existed on one disk and in no commit. The ratchet's own stale-pin
tooth refused all 46 the first time it ran detached: the bar caught its author.
Both the baseline and the enumerator now read `git ls-files`. While only one side
did, the same gate reported 47 governed directories locally and 1 detached — a bar
that describes a different world depending on where it runs describes neither.

**Shrink-only was prose.** It was in the ruling, in the file's `monotone` field,
and asserted in my own commit message as something that "cannot be escaped by
declaring the escape". Measured: appending a directory silenced the bar entirely.
True of the design, false of the code. The baseline is now diffed against its
**committed** version; appends are refused by name, shrinks stay legal, both
red-proven.

**A comment that looked like code broke a test.** Explaining the
side-effect-import gap, I wrote the example import literally in a comment. The M0
effect walk resolves imports by scanning **text**, so it followed the example and
tried to open a file that does not exist. *A comment illustrating an import is an
import to a textual walker* — the explanation of a fix broke a test eight cases
away from anything the fix touched.

## Method notes worth keeping

* I committed once over a red test, having read `tail -2` of a TAP stream — `# todo 0` and a duration, both true, neither a verdict — and a pipe had already discarded the exit status. Read `^not ok` and `# fail`; never let a pipe eat the exit code of the thing being judged.
* The `adoption-completeness` bar had **no tracked caller** on the day it was built. The census refused it immediately, which is the entire reason the census exists — the class it kills used to take three rounds and an external reviewer.
* Adding that gate broke the execution-**order** pin, which is literal data independent of the production list. That is the pin working: a new gate cannot enter the run without someone writing it down.
* A working copy is a subject. The enumeration mistake has now landed three times in this program — the completeness bar's contaminated upstream diff, the census that vouched for its own subjects, and the ratchet built from ignored bytes. Each time the cure was the same: enumerate from tracked bytes, never from the disk you happen to be standing on.

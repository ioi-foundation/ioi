# Codex review — per-finding dispositions

Every finding from the review disposition, with the commit that closed it and
the executed check that keeps it closed. A finding is only "fixed" here if a
bar fails when the defect is reintroduced.

## Original four

| # | Finding | Disposition | Commit | Standing check |
|---|---|---|---|---|
| 1 | Record held 801 elements, 799 single characters — two assertions spread char-by-char | **Fixed.** Mine: `list += str` in Python extends element-by-character. Rejoined to 4 elements. | `e10119d7d` | `check-work-item-shape` rejects single-character elements. Proven red on the real corrupted bytes recovered from `966d2ba52` (799 caught, sample `" ", "R", "e", "j", "e", "c"`). A first attempt used a 24-char floor and fired on legitimate short entries; the predicate became the **defect signature** instead. |
| 2 | Daemon registered only three routes — no lease read, checkpoint, or revoke | **Fixed.** Seven routes: create, append, read, lease create/read/checkpoint/revoke/delivery. Lease owns no transition chain; every state change is admitted on the lease's own object key. Capability still four operations. | `e35c47588` | 11 lease-plane assertions incl. checkpoint substitution, rewind refusal, revoked/expired refusal by name |
| 3 | `classify(&body, …)` took the declaration from each append request | **Fixed.** Declaration admitted once at genesis inside an expected-absent operation; appends judged against it. Request-supplied declarations ignored. | `2cfc2dcbd` | The reviewer's live reproduction, verbatim: stream truth says admitted, request claims ephemeral, truth wins |
| 4 | `RecvError::Lagged` → silent drop | **Fixed.** The gap is an admitted typed event on the durable stream — it occupies a sequence and is replayed. | `7cf6c0823` | Structural assertion on comment-stripped source checking the silent-drop warn is **gone**, not merely that a new path exists |

## Raised during the fix pass

| # | Finding | Disposition | Commit | Standing check |
|---|---|---|---|---|
| 5 | **Ephemeral P0** — `admitted_declaration` walked full history on *every* append, including ephemeral | **Fixed.** Declaration is a steward-held in-memory lookup; a hit touches no substrate surface. | `6ce5d43f7` | Positive detection: instrument proven to read **non-zero** on an admitted append before a zero is trusted on the ephemeral one. Proven red by restoring the exact filed defect (`walks 22 → 23`, cache hits flat at 0). |
| 6 | **Hydration P1** — retained evidence was gitignored, so the coverage gate was green only on a working tree | **Fixed.** `docs/evidence/m5-event-substrate/` excepted; bytes tracked. | `b0e5f105b` | The gate reads tracked bytes; hydration proven by running green from the packet alone. |
| 7 | Census dates — review misdated / whole-set restamping | **Fixed** per the third option: appended at the actual date with the review actually performed. 1430 forced = 788 materially reviewed + 642 mechanically unchanged-confirmed; 173 baseline-identical entries keep their baseline date. | `348503942` | M0 exit verified; split recorded in the epoch's own provenance |
| 8 | Both thread-event GETs carried `not_applicable_no_effect` under a **consequential** classification | **Fixed.** Gates taken from discovery, not the template: only `engine.current_epoch` is observed, so revocation is `observed_in_handler_not_order_proven` and the rest are `not_established_at_final_invoker`. | `f34ca84cb` | M0 validates classification independently against observed effect calls |
| 9 | Wire bytes unpinned beyond status + code | **Fixed.** Exact key sets pinned for append, `admitted_head`, lease, and delivery; refusal bodies byte-exact; refusal envelope pinned across six refusals. | `2ca403bff` | Proven load-bearing: adding one harmless field turns the pin red naming the intruder |
| 10 | M0 green in tree rather than at the commit | **Fixed.** Artifacts regenerated **and committed**; all gates measured from a dedicated detached worktree at the exact commit. | `f34ca84cb`, `348503942` | Standing rule; the shared checkout is never the measurement surface |

## Re-review findings (Codex, second pass)

| # | Finding | Disposition | Commit | Standing check |
|---|---|---|---|---|
| R1 | **Ephemeral boundary failed across restart.** `lookup_declaration` lazily walked history on cache miss, so the first ephemeral append after a daemon restart traversed Agentgres — Codex measured `history_walks 0 → 1` on an exact-commit binary. | **Fixed.** The declaration projection is rebuilt at steward open, riding the existing open/replay pass; the lazy fill is deleted. After hydration a miss means undeclared, which is already a refusal. | `e08d87823` | Codex's restart reproduction, verbatim: cold-daemon ephemeral append asserts zero history walks **and** zero admissions, with open-time fills counted separately. Proven red by removing boot hydration. |
| R2 | **M0 measured at the wrong commit.** The gates table said M0 ran detached at the exact commit; the retained `m0.log` had measured `348503942`, two commits before the packet HEAD. A false report statement, and the third instance of the class. | **Fixed and mechanized.** Every retained log must carry `IOI_MEASURED_COMMIT`; the coverage gate refuses bytes that declare no commit, and bytes whose commit differs from the packet HEAD. Packet HEAD comes from git, not a file. | `c00145d60` | Three new predeclared self-test cases including the acceptance case; self-test 8 → 11 |
| R3 | **Epoch entry 29 replaced in place.** A prior attestation was destroyed — `epoch_id` changed, ten fields rewritten — while the packet claimed "appended". | **Fixed.** Entry 29 restored byte-exact from `e10119d7d` (verified by stable-stringify equality); entry 30 appended with `predecessor_entry_sha256` from the model's own hash. Chain 1..30 contiguous. Split moved to a sidecar bound by epoch id **and** entry digest. | `f6c2bcebd` | M0 exit verified; chain validated by the model's own functions |

### Two things worth stating plainly about R1 and R3

**R1's mutation result is not what I expected and is reported as measured.**
Restoring the lazy fill does *not* turn the assertion red — boot hydration makes
that line unreachable. The assertion tests the property, not that
implementation. The discriminating mutation is removing boot hydration. Saying
"proven red" against the wrong mutation would be the conditional-probe error one
level up, which is exactly what R1 was.

**R1 also contained two defects in my own fix**, both found by the probe rather
than inspection: hydration placed before `backfill` found zero domains, and
removing all substrate access from the lookup also removed the thing that used
to force steward open — so a process whose first request was ephemeral never
opened the handle at all.

**R3's asymmetry, understood firsthand:** only the head entry can be rewritten
without breaking a predecessor's hash. The chain protects everything except the
thing I edited, which is why the head must be appended past and never edited.

## Defects the gates caught in already-committed code

Redeclaration replayed as success under bare CAS · appends CAS-ing against
absence on a declared stream · admitted events not carrying `class_id`, making
a lease's class scope unenforceable against admitted truth · expiry compared
against a hardcoded zero, so no lease could expire. None found by inspection.

## Ledger additions this pass

`gate-green-in-a-working-tree` (recurred as invisible evidence) ·
`content-rejecting-floor` (a bar that rejects real content to catch corruption)
· `met-the-letter-broke-the-rule` (a structural bar satisfied by doing the
forbidden thing before the checked boundary) · **`absolute-claim-conditional-probe`**
(an unconditional claim mapped to a check that only exercises the favourable
path — 7/7 was false because the ephemeral claim rode a warm-cache-only probe) ·
**`chain-head-edited-not-appended`** (the one destructive edit a hash chain does
not resist).

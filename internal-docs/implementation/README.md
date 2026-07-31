# Implementation program

This versioned directory turns the architecture in [`docs/architecture/`](../../docs/architecture/)
into executable work. Canon and accepted ADRs own meaning; nothing here overrides them.

## Version-control classification

The default is to track a program file. A file is authoritative or retained
history when it controls sequence, scope, status, transitions, evidence,
certification, review, reproduction, or a tool's checked input. Those files
must be reviewable and must survive the machine that produced them.

Tracked:

- `work-items/`, `stages/`, `program/`, and `modules/`: program authority,
  sequencing, scope, and reusable method;
- `evidence/` and `_archive/`, including `_archive/evidence/cas/`: retained
  run evidence and historical bodies. Evidence is tracked even when stale and
  is never refreshed merely to make a current check green;
- `tools/` and `fixtures/`: the mechanisms and adversarial inputs that enforce
  the program contract;
- checked projections under `generated/` other than the two current-orientation
  outputs named below. Some are reproducible from current inputs, but other
  tools and work items consume or deliberately retain their exact historical
  bytes, so they remain auditable; and
- this README and root program inputs such as `source-dispositions.v1.json`.

Ignored:

- `worktrees/`: nested disposable checkouts. At the 2026-07-31 classification
  cut this was 9,030 files and 3.3 GB;
- `NOW.md` and `generated/program-state.v1.json`: current-orientation views
  reproduced together by `tools/generate-now.mjs` from tracked authorities.
  Their provenance is a deterministic input digest; branch names, checkout
  commits, remote refs, ancestry, caches, and stamps are forbidden inputs;
- `generated/.fast-lane-stamp`, `generated/.certify/`, `.cache/`,
  `__pycache__/`, and `node_modules/`: local caches, stamps, or dependencies.

At the classification cut, `_archive/evidence/cas/` was 791 files and 26 MB;
that is feasible to version and is therefore tracked. Size alone never moves
evidence to the ignored side silently: measure it, record the result here, and
obtain an explicit disposition first.

For a new file, ask whether losing its exact bytes would erase a past claim,
status change, review input, refusal, or proof, or prevent another tool from
checking the program as it actually ran. If yes, track it. Ignore only a nested
checkout, local dependency/cache, or a current-state view that a named tracked
tool reproduces entirely from tracked inputs. Never regenerate, restamp, or
clean a retained literal as part of changing this classification.

The classification gate is byte reproduction: from a clean worktree at the
same tracked tree, run `node internal-docs/implementation/tools/generate-now.mjs
--write` and compare both ignored outputs byte-for-byte. A difference reopens
this classification; it is never dismissed as harmless projection drift.

## Read this to start a cut

1. [`NOW.md`](./NOW.md) — generated. Open stages, the next cut, what blocks advancement.
2. [`stages/<id>.md`](./stages/) — the stage that owns the cut: canon owners, scope, exit proof, focused checks.
3. the work-item record `NOW.md` names — bounded plan and the cut's status.
4. that record's canon owners, then current code and retained evidence.

That is the whole path. Nothing else needs reading before work starts.
[`program/rules.md`](./program/rules.md) holds the rules that never change; read it once.

## What owns what

| Fact | Sole owner |
| --- | --- |
| Sequence, dependencies, exit gates, rails, claim ladder | [`program/sequence.v1.json`](./program/sequence.v1.json) |
| Stable program-wide rules | [`program/rules.md`](./program/rules.md) |
| Canon classification and its bindings | [`program/canon-map.v1.json`](./program/canon-map.v1.json) |
| Scan boundary | [`program/estate-boundary.v1.json`](./program/estate-boundary.v1.json) |
| Repo-wide guide classification | [`program/guide-registry.v1.json`](./program/guide-registry.v1.json) |
| Open, reviewed gaps | [`program/known-gaps.v1.json`](./program/known-gaps.v1.json) |
| What a `SKIP` withholds | [`program/skip-taxonomy.v1.json`](./program/skip-taxonomy.v1.json) |
| Owed, unwritten successors | [`_archive/holds/open-successor-holds.v1.json`](./_archive/holds/open-successor-holds.v1.json) |
| Stage scope and exit definition | [`stages/`](./stages/) |
| Reusable method | [`modules/`](./modules/) |
| Durable cut status | the work-item record's declared status authority |
| Current orientation | [`NOW.md`](./NOW.md) and `generated/` — derived, never authoritative |

Where a cut also exists as a merged record under
[`docs/architecture/_meta/work-items/`](../../docs/architecture/_meta/work-items/), that tracked
record is its status authority and the private record mirrors it. Everywhere else the private
record is the authority. `tools/reconcile-status.mjs` fails closed when the two disagree.

## Three commands

```text
while developing   node internal-docs/implementation/tools/check-fast.mjs
at a stage exit    node internal-docs/implementation/tools/certify-stage.mjs <STAGE> --apply
at a release gate  node internal-docs/implementation/tools/check-program.mjs
```

The fast lane validates only what changed. Stage certification is one content-bound proof that
registers evidence, moves status, and regenerates every derived view in a single transaction —
nothing downstream is hand-edited. The program audit runs everything once, at a program or
release boundary, not after every edit.

To advance one record outside a stage exit:
`tools/transition.mjs <work-item-id> <status> --result <certification.json> --apply`.

After a child transition or after retaining new aggregate evidence, refresh the
aggregate's exact child/dependency/evidence join through the owned command —
never by hand:
`tools/refresh-aggregate-verification-binding.mjs <aggregate-work-item-id> --apply`.
Stage certification and direct aggregate verification both refuse a stale,
missing, literal-invalid, or non-verified join.

## When canon changes

```text
node internal-docs/implementation/tools/canon-impact.mjs           what changed, and which stages/modules/work items must be reviewed
node internal-docs/implementation/tools/canon-impact.mjs --accept  record that the drift was reviewed
```

The canon universe is discovered from the filesystem, so a new canon file is a detected addition,
never a silent omission. A subject with no entry in `program/canon-map.v1.json` is an orphan and
fails closed. Adding a stage, module, or obligation appends one entry and renumbers nothing —
`tools/test-insertion.mjs` proves it.

A subject dispositioned `successor_required` owes an OPEN HOLD in
[`_archive/holds/open-successor-holds.v1.json`](./_archive/holds/open-successor-holds.v1.json).
While a hold is open, every predecessor closure it names projects as
`verified_historical_with_open_successor` and never as unqualified `verified`; the transition gate
refuses to re-verify it, and stage certification refuses to certify on it. The hold closes when the
named successor is admitted — never by re-running the predecessor.

```text
node internal-docs/implementation/tools/check-open-successor-holds.mjs          what is held, and what it qualifies
node internal-docs/implementation/tools/check-open-successor-holds.mjs --seed   open a hold for a disposition that has none
```

## What is not proof

A process exit code, route presence, an HTTP 200, mock data, a screenshot, a plan, or a status
declaration is not implementation proof. Proof is an expected-path literal bound to exact artifact
bytes or a committed artifact identity, plus the adversarial, denial, recovery, replay, and fault
evidence the stage requires. An exit artifact must BE a retained
`ioi.program.literal_exit.v1` log — the literal appearing somewhere inside a file of prose is not
the contract, and `tools/lib/literal-exit.mjs` is the single validator every admitting caller asks.
`SKIP` is never success: `tools/check-program.mjs` classifies every skip against
[`program/skip-taxonomy.v1.json`](./program/skip-taxonomy.v1.json) and fails while any
certification-relevant skip stands, with unclassified skips counted as certification-relevant.
Private review records and audit ledgers are workflow evidence, not product authority. See
[`program/rules.md`](./program/rules.md) §6.

## Archive

[`_archive/`](./_archive/) holds completed, superseded, and historical bodies with their
provenance, plus
[`_archive/manifests/migration-manifest.v1.json`](./_archive/manifests/migration-manifest.v1.json),
which records every path this estate moved or deleted, its digest, its reason, and — for a
deletion — its recovery source. Archived bodies are frozen: they are evidence for the commit and
canon revision they certified and are never rewritten to look current. Nothing in `_archive/`
schedules work.

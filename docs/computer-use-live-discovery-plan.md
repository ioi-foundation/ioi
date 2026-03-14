# Computer-Use Live Discovery Plan

This file is the single authoritative living spec for benchmark-driven
computer-use improvement in this repo. It is intentionally a rolling window,
not a changelog.

## Scope

- active family: `crates/cli/tests/computer_use_suite`
- active objective: improve generic computer-use capability through
  provider-backed live runs on the repo-real suite
- current frontier: remain on built-in MiniWoB until `catalog` reaches parity,
  plateaus, or hard-blocks on an honest primitive surface
- downstream objective: only after MiniWoB `catalog` is closed or honestly
  plateaued, choose the next computer-use frontier

## Method Invariants

- live-inference-first
- benchmark-driven
- no ad hoc heuristics
- no benchmark-conditioned routing
- no cheating against judges
- shared fixes only: runtime, observation, verification, recovery, bridge, or
  generic tool surfaces
- exact failing live slice first, broader family second
- cumulative sets are audit rungs, not the inner-loop dev target

## Validation Rules

- only provider-backed `computer_use_suite` agent runs count as benchmark
  progress
- required env for benchmark proof:
  - `COMPUTER_USE_SUITE_MODE=agent`
  - `COMPUTER_USE_SUITE_AGENT_BACKEND=live_http`
- allowed live inference surfaces:
  - `HttpInferenceRuntime`
  - `VerifiedHttpRuntime` if cleaner on existing wiring
- these do not count as proof of live inference:
  - `MiniwobAgentRuntime`
  - `MockInferenceRuntime`
  - `StandardInferenceRuntime`
- required live artifacts per authoritative run:
  - `agent_state.json`
  - `inference_trace.json`
  - `inference_calls.json`
- if a live run records zero provider calls, treat it as failure, not pass
- deterministic `oracle`, deterministic `runtime`, and deterministic `agent`
  runs are regression-only

## Status

Current benchmark position:

- full `smoke` is closed live
- full `core` is closed live
- full `workflow`, `workflow_rich`, `workflow_audit`, `workflow_mutation`,
  and `workflow_reorder` are closed live
- full cumulative `stress` is closed live at `19/19` on `run-1773498002`

Current frontier:

- next rung is built-in MiniWoB `catalog`
- exact live sentinel is `miniwob_catalog_copy_paste`
- reason: `stress` closed the smoke/core/stress ladder, but `catalog` is the
  remaining built-in MiniWoB family and materially widens DOM interpretation
  plus tool use through selection, clipboard, and editor-style tasks

Current blocker:

- no active benchmark blocker remains on the closed ladder
- no active infra blocker remains on the widened live path
- next required proof is the authoritative exact live rerun of
  `miniwob_catalog_copy_paste`

Decision rule:

- stay on MiniWoB until built-in `catalog` passes live or reaches an honest
  plateau
- only then choose a new benchmark family

## Rolling Window

Keep only the context needed for the next agent to continue correctly.

Latest authoritative family closure:

- `run-1773498002` closes full cumulative `stress` at judged live `19/19`
  with provider-backed inference and full artifacts present

Retained shared fixes that matter for future regressions:

- browser-launch instability is closed on the widened path:
  `run-1773489982` re-closed the first launch-blocked exact slice and
  `run-1773490053` kept full `core` green again
- MiniWoB turnover bridge accounting is closed:
  `run-1773487291` preserved terminal reward / termination across immediate
  next-episode turnover strongly enough for authoritative judgment
- visible-target grounding on tabbed / collapsible pages is closed and widened:
  `run-1773494132` and `run-1773497922` re-closed exact slices, and
  `run-1773498002` kept them green in-family
- ranked-result pagination plus planner handoff is closed and widened:
  `run-1773497374` re-closed `miniwob_search_engine_stress`, and
  `run-1773498002` kept it green in-family
- autocomplete unresolved-state recovery is closed on the widened path:
  `run-1773489181` landed the generic `ArrowDown` then `Enter` reduction, and
  later widened reruns kept the reopened `core` family green

Retention policy:

- keep the active rung
- keep the latest authoritative closure for each closed family
- keep only dormant gap notes that could plausibly reopen on the next rung
- remove date logs, narrative iteration history, and superseded local notes

## Benchmark Snapshot

| Family / rung | Status | Authoritative result | Command shape | Artifact root |
| --- | --- | --- | --- | --- |
| full `smoke` | passed | `run-1773452927`: judged live `8/8` with provider-backed inference and full artifacts | `... MODE=agent AGENT_BACKEND=live_http TASK_SET=smoke ...` | `run-1773452927/agent` |
| full `core` audit | passed | `run-1773490053`: judged live `17/17` with provider-backed inference and full artifacts | `... MODE=agent AGENT_BACKEND=live_http TASK_SET=core ...` | `run-1773490053/agent` |
| full `workflow` | passed | `run-1773456913`: judged live `2/2` with provider-backed inference and full artifacts | `... MODE=agent AGENT_BACKEND=live_http TASK_SET=workflow ...` | `run-1773456913/agent` |
| full `workflow_rich` | passed | `run-1773469571`: judged live `2/2` with provider-backed inference and full artifacts | `... MODE=agent AGENT_BACKEND=live_http TASK_SET=workflow_rich ...` | `run-1773469571/agent` |
| full `workflow_audit` | passed | `run-1773469870`: judged live `2/2` with provider-backed inference and full artifacts | `... MODE=agent AGENT_BACKEND=live_http TASK_SET=workflow_audit ...` | `run-1773469870/agent` |
| full `workflow_mutation` | passed | `run-1773479507`: judged live `2/2` with provider-backed inference and full artifacts | `... MODE=agent AGENT_BACKEND=live_http TASK_SET=workflow_mutation ...` | `run-1773479507/agent` |
| full `workflow_reorder` | passed | `run-1773483313`: judged live `2/2` with provider-backed inference and full artifacts | `... MODE=agent AGENT_BACKEND=live_http TASK_SET=workflow_reorder ...` | `run-1773483313/agent` |
| full `stress` audit | passed | `run-1773498002`: judged live `19/19` with provider-backed inference and full artifacts | `... MODE=agent AGENT_BACKEND=live_http TASK_SET=stress ...` | `run-1773498002/agent` |
| catalog sentinel: `miniwob_catalog_copy_paste` | pending | not yet run | `OPENAI_API_KEY=... OPENAI_MODEL=... COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR=/tmp/miniwob-plusplus COMPUTER_USE_SUITE_MODE=agent COMPUTER_USE_SUITE_AGENT_BACKEND=live_http COMPUTER_USE_SUITE_TASK_SET=catalog COMPUTER_USE_SUITE_CASES=miniwob_catalog_copy_paste cargo test -p ioi-cli --test computer_use_suite_e2e computer_use_suite_from_env -- --ignored --exact --nocapture` | pending |
| full `catalog` audit | pending | not yet run | `OPENAI_API_KEY=... OPENAI_MODEL=... COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR=/tmp/miniwob-plusplus COMPUTER_USE_SUITE_MODE=agent COMPUTER_USE_SUITE_AGENT_BACKEND=live_http COMPUTER_USE_SUITE_TASK_SET=catalog cargo test -p ioi-cli --test computer_use_suite_e2e computer_use_suite_from_env -- --ignored --exact --nocapture` | pending |

## Capability Gap Matrix

Only gaps exposed by live suite runs are active.

| Gap class | Current status | Handling |
| --- | --- | --- |
| `missing_pointer_primitive` | dormant | reopen only on fresh live evidence |
| `missing_selection_primitive` | dormant | next rung is designed to probe this honestly via `catalog`; reopen only on fresh live evidence |
| `missing_keyboard_primitive` | dormant | reopen only on fresh live evidence |
| `missing_clipboard_primitive` | dormant | next rung is designed to probe this honestly via `catalog`; reopen only on fresh live evidence |
| `observation_gap` | dormant | reopened transiently during stress search-engine work; exact and widened closures through `run-1773498002` keep it green |
| `verification_gap` | dormant | no current verification-red slice remains on the widened authoritative path |
| `planner_gap` | dormant | stress exact and family closures through `run-1773498002` keep the previously red planner slices green |
| `recovery_gap` | dormant | workflow mutation and reorder closures keep the last recovery reductions green |
| `infra_or_bridge_gap` | dormant | launch instability and MiniWoB turnover-accounting branches are closed on the authoritative live harness |

## Benchmark Escalation Ladder

1. Closed MiniWoB ladder
   Status: passed.
   Scope:
   - full `smoke`
   - full `core`
   - full cumulative `stress`
   Canonical closures:
   - `smoke`: `run-1773452927`
   - `core`: `run-1773490053`
   - `stress`: `run-1773498002`
   Retained meaning:
   - browser-core DOM interpretation is live-proven on the widened MiniWoB path
   - current MiniWoB follow-on work should target unproven `catalog` surfaces,
     not rerun closed smoke/core/stress families first

2. Closed workflow ladder
   Status: passed.
   Scope:
   - `workflow`
   - `workflow_rich`
   - `workflow_audit`
   - `workflow_mutation`
   - `workflow_reorder`
   Canonical closures:
   - `workflow`: `run-1773456913`
   - `workflow_rich`: `run-1773469571`
   - `workflow_audit`: `run-1773469870`
   - `workflow_mutation`: `run-1773479507`
   - `workflow_reorder`: `run-1773483313`
   Retained meaning:
   - browser-only ticket-routing / verification / audit / mutation / queue
     reorder flows are live-proven on the authoritative harness

3. Catalog selection / clipboard sentinel
   Status: pending.
   Objective:
   - stay on MiniWoB after `stress` closure and start the built-in `catalog`
     family with exact live sentinel `miniwob_catalog_copy_paste`
   Why this sentinel:
   - it is the smallest honest built-in `catalog` case that materially
     exercises the selection / clipboard tool surface under live
     provider-backed inference
   Exact command:
   - `OPENAI_API_KEY=... OPENAI_MODEL=... COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR=/tmp/miniwob-plusplus COMPUTER_USE_SUITE_MODE=agent COMPUTER_USE_SUITE_AGENT_BACKEND=live_http COMPUTER_USE_SUITE_TASK_SET=catalog COMPUTER_USE_SUITE_CASES=miniwob_catalog_copy_paste cargo test -p ioi-cli --test computer_use_suite_e2e computer_use_suite_from_env -- --ignored --exact --nocapture`
   First-pass classification rule:
   - if red, classify the smallest honest shared gap and fix only that
   - if green, record artifacts and widen only to the next catalog rung
   Exit criterion:
   - judged live pass with non-zero provider calls and full artifacts, or the
     first honest shared gap is identified for inner-loop work

4. Full MiniWoB catalog mastery
   Status: pending.
   Objective:
   - after rung 3 closes, continue exact-first through built-in MiniWoB
     `catalog` until the family reaches live parity or an honest plateau
   Immediate widening order:
   - exact `miniwob_catalog_copy_paste`
   - then exact-first on the first red `catalog` slice in family order
   - only after the current exact red slice closes, widen to full `catalog`
   Exit criterion:
   - full `catalog` passes judged live with provider-backed inference and full
     artifacts, or the remaining reds are explicitly classified as honest
     primitive-surface blockers that justify a frontier change

5. Post-catalog frontier choice
   Status: pending.
   Objective:
   - choose the next computer-use benchmark family only after rung 4 closes or
     honestly plateaus
   Decision standard:
   - prefer the next benchmark that exposes new reusable capability surfaces,
     not one that merely re-tests already closed MiniWoB DOM patterns

## Iteration Update Protocol

For every iteration:

1. Update `Status`, `Rolling Window`, `Benchmark Snapshot`, and the active rung
   first.
2. Stay on the active family until it reaches parity, plateaus, or hard-blocks.
3. Keep the inner loop simple:
   - run the current sentinel or exact failing case
   - inspect artifacts
   - classify the smallest honest shared gap
   - implement only a shared fix
   - rerun the exact same live slice
   - only then widen
4. Treat cumulative sets (`core`, `stress`, `catalog`) as audit rungs, not the
   per-fix dev loop.
5. Record for every authoritative run:
   - exact command
   - runtime / provider / model
   - task set and case ids
   - artifact root
   - judged outcome
   - smallest honest gap class
   - whether the run was diagnostic or authoritative
6. Prefer generic fixes over benchmark-local recipes.
7. Add deterministic coverage only when a live failure first proves a reusable
   gap.
8. When a rung closes, immediately define the next rung in this file.
9. Keep this file under `500` lines by preserving only the rolling window and
   canonical closure references.

## Current Next Move

Run the exact catalog sentinel:

```bash
OPENAI_API_KEY=... OPENAI_MODEL=... COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR=/tmp/miniwob-plusplus COMPUTER_USE_SUITE_MODE=agent COMPUTER_USE_SUITE_AGENT_BACKEND=live_http COMPUTER_USE_SUITE_TASK_SET=catalog COMPUTER_USE_SUITE_CASES=miniwob_catalog_copy_paste cargo test -p ioi-cli --test computer_use_suite_e2e computer_use_suite_from_env -- --ignored --exact --nocapture
```

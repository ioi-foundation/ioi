# Runtime Agent Service

The runtime under `crates/services/src/agentic/runtime` is the durable execution
engine for desktop-agent sessions. It owns:

- session lifecycle: `start@v1`, `step@v1`, `resume@v1`, `post_message@v1`
- canonical pending-action resume state
- approval, PII, and policy enforcement
- execution queue dispatch and verification evidence
- delegation and worker-result lifecycle
- transcript continuity and state persistence

The goal of the runtime is not to look simple. The goal is to keep the hard
behavior explicit, testable, and easy to trace.

## Runtime Shape

### State model

`types.rs` is the source of truth for durable runtime state.

Important invariants:

- `AgentState` remains the persisted session record.
- pending resume metadata is grouped through `PendingActionState`.
- pause legality is classified through `AgentPauseReason`.
- callers should derive wait and retry behavior from typed helpers such as:
  `pending_action_state()`, `pause_reason()`, `is_waiting_for_approval()`,
  `is_waiting_for_sudo_password()`, and related predicates.

If a new runtime feature needs more lifecycle state, prefer extending a typed
substructure or helper API instead of adding more top-level scalar fields.

### Decision loop and service lanes

`service/decision_loop/mod.rs` is the public entrypoint and should stay a thin
orchestrator.

The main phase seams are:

- `service/decision_loop/clarification.rs`
- `service/decision_loop/pending_resume.rs`
- `service/output/direct_inline.rs`
- `service/planning/playbook.rs`
- `service/decision_loop/orchestration.rs`
- `service/queue/processing/*`
- `service/tool_execution/processing/*`
- `service/recovery/*`
- `service/visual_loop/*`

The intent is that `handle_step` reads like a runtime script, while branch-heavy
behavior lives behind focused modules with seam-specific tests.

### Lifecycle path

Lifecycle responsibilities are intentionally split:

- `service/lifecycle/handlers/*` owns start, resume, post-message, and delete
  session entrypoints
- `service/lifecycle/delegation/*` owns child goal shaping, prep, and bootstrap
- `service/lifecycle/worker_results/*` owns await and merge behavior

Parent/child legality should be traceable without scanning a single monolithic
file.

## Validation

For a fast runtime-focused local gate, run:

```bash
./scripts/check-agent-runtime.sh
```

That script runs the minimum checks we expect before landing runtime cleanup
work:

- `cargo check -p ioi-api`
- `cargo check -p ioi-services`
- focused runtime seam tests
- `pii_hard_gates` integration coverage

For a fuller pass, run:

```bash
cargo test -p ioi-services --lib
cargo test -p ioi-services --test envelope_integration
cargo test -p ioi-services --test pii_hard_gates
```

The live timer-planner harness remains valuable but is intentionally separate
from the lightweight local gate:

```bash
cargo test -p ioi-services --test timer_planner_live_e2e
```

## Maintainability Guardrails

Use these as review rules for runtime changes:

- No new top-level `AgentState` scalars without a strong reason.
- No new non-test hot-path `unwrap()` in runtime lifecycle or execution code.
- New pause or resume paths must use typed pause or pending-state helpers.
- New receipt or verification markers should use typed helpers where available
  before falling back to raw strings.
- Keep public orchestration entrypoints thin and push branch-heavy logic into
  focused submodules.
- Add a seam-level test when introducing a new lifecycle branch.

Guidance budgets for hotspot entrypoints:

- `service/decision_loop/mod.rs`: target under 900 lines
- `service/queue/processing/mod.rs`: target under 800 lines
- `service/lifecycle/delegation.rs`: target under 1000 lines
- `service/lifecycle/handlers.rs`: target under 300 lines

These are not hard bans, but crossing them should trigger an explicit cleanup
conversation.

## Practical Editing Notes

- Use `timestamp_ms_now()` and `timestamp_secs_now()` instead of repeating
  `SystemTime` plumbing in hot paths.
- Prefer the typed pause helpers over matching on `AgentStatus::Paused` message
  text.
- Prefer typed receipt helpers in `service/tool_execution/support.rs` for core
  execution markers.
- Keep state persistence and transcript writes close to the lifecycle edge so
  invariants stay obvious.

When in doubt, optimize for traceability over cleverness. A runtime branch that
looks slightly repetitive but is easy to audit is often the better choice.

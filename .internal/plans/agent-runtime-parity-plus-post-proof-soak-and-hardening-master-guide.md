# Agent Runtime Parity Plus Post-Proof Master Guide

Objective: keep the Antigravity-equivalent agent IDE runtime proven under longer, messier, more realistic usage after P0 parity-plus closure.

Status baseline:

- Final verdict: `agent_runtime_parity_plus_proven`
- P0 status: `all_p0_proof_closed`
- Remaining work class: monitoring, soak, UX polish, and optional surface hardening
- Primary evidence root: `docs/evidence/autopilot-agent-runtime-parity-plus/`

## 1. Longer Integrated Sessions

Goal: prove the retry-limit fix stays stable in real runtime loops, not only focused regression tests.

Run sessions that include:

- Multi-step file read/search/edit/test loops
- Failed tool attempts followed by model repair
- Stop/resume during model or tool work
- Browser/computer session handoff and return
- Subagent delegation plus parent continuation
- Long retained shell commands with streamed output
- Weak final-answer rejection followed by a repaired answer

Watch for:

- Any `Retry limit exceeded` terminal state before a real consecutive-failure ceiling
- Runs ending while actionable repair paths still exist
- Turns stuck in active/pending state after failure recovery
- Duplicate final replies after retry/recovery
- Missing `chat__reply` after successful repair

Suggested evidence shape:

```json
{
  "sessionId": "...",
  "durationMinutes": 60,
  "scenarioMix": ["file-edit-test", "browser-session", "subagent", "stop-resume"],
  "retryLimitRegressions": 0,
  "unexpectedTerminalStates": [],
  "repairLoopsCompleted": 0,
  "notes": []
}
```

Recommended cadence:

- Short soak: 30-60 minutes before each major runtime merge
- Long soak: 2-4 hours before release candidates
- Stress soak: overnight only after short/long soaks are clean

## 2. Replay And Reconnect Durability

Goal: keep proving that durable runtime state survives reloads, restarts, and UI reconnects without duplicating side effects.

Exercise:

- Reload Agent Studio during active run
- Restart daemon between replay inspections
- Relaunch OpenVSCode/Electron against the same daemon state
- Reconnect while managed browser/computer session is waiting for user
- Replay archived runs through Stage 9 historic replay path
- Reopen trace links from replay cards into Runs/Tracing

Required invariants:

- Same thread id after reconnect
- Same runtime session id after reconnect where expected
- Same managed session id after reconnect
- No duplicate `start_thread`
- No duplicate tool side effects
- Replay cursor advances monotonically
- Historic replay must not execute live tools
- Product UI must show replayable summaries, not raw daemon payloads

Regression checks to preserve:

- `node scripts/lib/workflow-managed-session-reconnect-live-gui-proof.mjs`
- `node scripts/lib/workflow-historic-run-gui-replay-proof.mjs`
- `node --test packages/runtime-daemon/src/runtime-thread-control.test.mjs`

## 3. Product UI Leakage Watch

Goal: keep Agent Studio clean: user-facing surfaces must not expose raw trace, tool, path, daemon, receipt, or policy internals.

Forbidden in product chat/drawer/cards unless explicitly inside evidence/tracing surfaces:

- Raw tool names: `chat__reply`, `browser__inspect`, `agent__complete`, etc.
- Raw temp paths: `/tmp/...`
- Local daemon URLs: `http://127.0.0.1:...`
- Receipt or trace ids as primary copy
- Raw `daemonStateDir`
- Raw `parsed-trace`
- Raw policy payload JSON
- Secrets or token-like strings
- Stack traces in normal product copy

Allowed surfaces:

- Runs/Tracing
- Evidence artifacts
- Developer/debug proof files
- Explicit internal audit output

Add or maintain UI leak audits around:

- Assistant final answer
- Work lane rows
- Managed session cards
- Replay panels
- Policy denial text
- Error/recovery banners
- Empty/loading states

Preferred product wording:

- "assistant channel" instead of `chat__reply`
- "browser observation" instead of `browser__inspect`
- "Tracing" instead of raw receipt ids
- "workspace path" instead of raw temp paths
- "policy block" instead of raw invalid transaction/tool errors

## 4. UX Copy, Layout, And Convenience Affordances

Goal: now that the spine is proven, make it feel inevitable and calm.

Polish priorities:

- Make Agent Studio status language consistent across running, blocked, waiting, replaying, recovered, and complete states
- Keep primary user action obvious during waiting-for-user managed sessions
- Make trace/replay links visible but secondary
- Reduce noisy work-lane rows while preserving inspectability
- Improve empty states for replay, run brain, managed sessions, and policy panels
- Ensure long command output does not crowd the final answer
- Keep controls stable across reload/reconnect

Convenience affordances to consider:

- Resume latest run
- Open last trace
- Return control to agent
- Reopen managed browser
- Copy clean summary
- Show evidence
- Retry from last safe step
- Collapse completed work
- Pin active command

UX acceptance criteria:

- A non-developer can understand what happened without seeing tool names
- A developer can reach evidence/tracing in one click
- Reload/reconnect does not visually reset confidence
- Waiting-for-user state is unmistakable
- Final answer remains the center of gravity

## 5. CLI/TUI Adapter Hardening

Goal: only harden these if CLI/TUI surfaces become active product commitments.

Required parity if activated:

- Same typed stream contract as GUI
- Same product-boundary redaction rules
- Same replay cursor semantics
- Same policy lease visibility
- Same stop/resume/cancel controls
- Same managed session state projection, even if text-only
- Same trace/evidence linkability

Minimum CLI/TUI acceptance tests:

- Long command stream renders incrementally
- Final answer is distinct from work output
- Policy denial is readable and sanitized
- Stop/resume updates state correctly
- Replay after restart does not duplicate side effects
- Managed session waiting/takeover/return states are visible
- Raw tool/path/trace markers stay out of normal user output

Do not activate CLI/TUI broadly until:

- GUI parity-plus soak remains clean
- Text adapter has leak audits
- Replay/reconnect behavior is proven in terminal sessions
- Product copy has terminal-specific wording

## 6. Ongoing Release Gate

Before calling any future runtime release parity-plus clean, require:

- Retry-limit focused Rust tests pass
- Daemon reconnect tests pass
- Agent Studio static tests pass
- Stage 8 reconnect live GUI proof passes
- Stage 9 historic replay live GUI proof passes
- No product UI leak markers in audited surfaces
- Evidence manifests updated with current proof paths
- Known blockers empty or explicitly downgraded to monitoring-only

Suggested final gate checklist:

```text
[ ] No retry-limit regressions in integrated soak
[ ] Replay/reconnect survived reload, relaunch, daemon restart
[ ] Historic replay ran without live execution
[ ] Managed sessions preserved inspect/control state
[ ] Product UI leak audit clean
[ ] UX copy reviewed for raw internals
[ ] CLI/TUI unchanged or separately gated
[ ] Final manifest updated
```

## 7. Operating Principle

Treat parity-plus as a living runtime contract, not a one-time trophy.

The system is proven now. The work from here is to keep it proven under longer, less curated use: more time, more restarts, more partial failures, more UI paths, and more ordinary user behavior.

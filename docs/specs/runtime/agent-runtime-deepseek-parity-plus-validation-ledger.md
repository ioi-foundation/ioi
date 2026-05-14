# Agent Runtime DeepSeek TUI Parity Plus Validation Ledger

Status: pruned validation ledger
Source guide: `docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md`
Pruned: 2026-05-14

This ledger records the validation posture for the DeepSeek parity-plus runtime
work without carrying every historical command transcript. Exhaustive proof
output remains available through git history and local/CI artifacts.

`docs/evidence/` was emptied on 2026-05-14 and is ignored by git. New evidence
bundles should be treated as generated artifacts, not source files.

## Current Baseline

The latest completed implementation slice is slice 213,
`runtime task API and P1/P2 future-plus closure`.

Recommended regression baseline:

```bash
node --check packages/runtime-daemon/src/index.mjs
npm run build --workspace=@ioi/agent-sdk
npm run build --workspace=@ioi/agent-ide
cargo test -p ioi-cli --bin cli parses_agent_operator_surface_commands -- --nocapture
cargo test -p ioi-cli --bin cli tui_job_and_run_lifecycle_rows_preserve_daemon_routes -- --nocapture
cargo test -p ioi-cli --bin cli parses_line_mode_slash_commands -- --nocapture
node --test --test-reporter=spec --test-name-pattern "local daemon public API persists canonical Agentgres state" scripts/lib/live-runtime-daemon-contract.test.mjs
node --test --test-reporter=spec --test-name-pattern "React Flow memory, authority/tooling, doctor, skill, hook, and package node contracts remain workflow-addressable" scripts/lib/live-runtime-daemon-contract.test.mjs
node --test --test-reporter=spec scripts/lib/workflow-runtime-event-projection-contract.test.mjs
node --test --import tsx packages/agent-ide/src/WorkflowComposer/terminalCodingLoopRunActivation.test.ts packages/agent-ide/src/runtime/workflow-runtime-terminal-coding-loop-run-launch.test.ts packages/agent-ide/src/runtime/workflow-runtime-terminal-coding-loop-execution.test.ts
node --import tsx scripts/lib/workflow-terminal-coding-loop-run-button-gui-probe.mjs /tmp/workflow-terminal-coding-loop-run-button-proof.json
node --test scripts/lib/autopilot-gui-harness-contract.test.mjs
node --test --test-reporter=spec --test-name-pattern "React Flow terminal coding-loop template executes" scripts/lib/live-runtime-daemon-contract.test.mjs
npm run validate:autopilot-gui-harness
npm run validate:autopilot-gui-harness:run
```

The primary validation posture is regression guard. Credentialless P1/P2
future-plus is complete; live third-party providers, live GitHub mutation,
public marketplace catalog distribution, and hosted workers require external
credentials/providers before live validation can move beyond fail-closed proof.

## Regression Guard Matrix

| Guard | Representative checks |
| --- | --- |
| Live bridge/event truth | `scripts/lib/live-runtime-daemon-contract.test.mjs`, `scripts/lib/workflow-runtime-event-projection-contract.test.mjs` |
| React Flow runtime projection | `packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts` and focused runtime-node tests |
| Terminal coding loop | `terminalCodingLoopRunActivation.test.ts`, `workflow-runtime-terminal-coding-loop-run-launch.test.ts`, `workflow-runtime-terminal-coding-loop-execution.test.ts` |
| Coding pack | live daemon contract pattern `coding tool pack invokes`; CLI/TUI parser tests when Rust surfaces change |
| Diagnostics/rollback | diagnostics repair tests, restore gate tests, and run-inspector recovery projection checks |
| MCP | live daemon MCP discovery/search/fetch/invoke tests plus React Flow MCP authoring contracts |
| Memory | live memory manager status/validation/mutation tests plus React Flow memory node contracts |
| Subagents | SDK/TUI route wrapper tests, React Flow fan-out/child-subflow tests, and budget-block checks |
| Usage/context budgets | usage/context/compaction/coding-budget node tests plus telemetry-source chain execution proofs |
| Model routing | live daemon model-route patterns, TUI route rows, SDK route decisions, and React Flow model-router projection checks |
| Doctor/config | `/v1/doctor`, `ioi agent doctor --json`, degraded fallback, redaction, and RuntimeDoctorNode source-contract checks |
| Skills/hooks | `/v1/skills`, `/v1/hooks`, active manifest/hash trace checks, TUI skill/hook rows, and React Flow skill/hook node contracts |
| Repo/PR/tasks/jobs/a11y | governed PR dry-run/fail-closed checks, `/v1/tasks` and `/v1/jobs` live daemon checks, TUI rows, RuntimeTask/Job/Checklist node contracts, and accessibility/localization source-contract checks |
| GUI/workflow package activation | `npm run validate:autopilot-gui-harness` and `npm run validate:autopilot-gui-harness:run` |

## Recent Validation History

| Slice | Commit | Validation result |
| --- | --- | --- |
| 206 | `7ecfeaf17` | Full live GUI harness package/activation evidence path was recovered and green. |
| 207 | `3c52e5976` | Terminal coding-tool row projection passed across CLI/TUI, daemon, and React Flow checks. |
| 208 | `46cce7e96` | Terminal coding-loop creator and run-inspector materialization tests and GUI proof passed. |
| 209 | `ae97df2d8` | Live terminal coding-loop daemon execution, projection, and GUI harness checks passed. |
| 210 | `1ff517599` | Saved workflow run-launch for terminal coding-loop workflows passed unit, live daemon, build, and GUI checks. |
| 211 | `0e1ad17af` | WorkflowComposer terminal-loop activation passed unit, source-contract, build, live daemon, and full GUI harness checks. |
| 212 | `ba9dc39a7` | Terminal coding-loop Run-button GUI probe passed standalone, source-contract, GUI harness contract, focused live daemon, build, preflight GUI harness, and full live GUI harness checks. |
| 213 | final slice commit | Runtime task API and future-plus closure passed daemon syntax/build, SDK build, agent-IDE build, CLI parser/TUI task row/slash-command tests, live daemon task/job/checklist contract, workflow-node source contract, and runtime event projection contract. |

## Evidence Policy

- Keep generated screenshots, `result.json` bundles, and probe artifacts out of
  git unless a future spec explicitly requires a small golden fixture.
- Prefer `/tmp/...`, CI artifact storage, or release attachments for bulky
  validation output.
- Record commands and high-signal outcomes here; store implementation detail in
  the implementation log and current priorities in the master guide.

## Next Entry Template

```md
### Slice N. YYYY-MM-DD - Short title

- Commit:
- Commands:
- Result:
- Artifact location:
- Residual risk:
```

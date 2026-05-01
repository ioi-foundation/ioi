# Runtime Layout Refactor Validation Summary

Status: passed

## Commands

| Command | Result |
| --- | --- |
| `npm run check:runtime-layout` | passed |
| `npm run check:pre-next-leg` | passed |
| `npm run check:execution-surface-leg` | passed |
| `npm run build:agent-sdk` | passed |
| `npm test --workspace=@ioi/agent-sdk` | passed |
| `npm run build --workspace=@ioi/agent-ide` | passed |
| `npm run build --workspace=autopilot` | passed |
| `npm run typecheck` | passed |
| `npm run lint` | passed |
| `npm run test:daemon-runtime-api` | passed |
| `npm run test:runtime-events` | passed |
| `npm run test:mcp-skills-hooks` | passed |
| `npm run test:subagents` | passed |
| `npm run test:agentgres-runtime-state` | passed |
| `npm run test:workflow-compositor-dogfood` | passed |
| `npm run test:hosted-workers` | passed |
| `npm run evidence:runtime-complete-plus` | passed |
| `npm run validate:runtime-complete-plus` | passed |
| `npm run validate:architectural-improvements-broad` | passed |
| `npm run evidence:architectural-improvements-broad` | passed |
| `npm run test:cursor-sdk-parity` | passed |
| `cargo test -p autopilot agent_task_accepts_legacy_swarm_tree_payloads --lib` | passed |
| `cargo fmt --check` | passed |
| `cargo check --workspace` | passed |
| `cargo test -p ioi-api execution --lib` | passed |
| `cargo test -p ioi-services agentic::runtime::service --lib` | passed, 1446 tests |
| `cargo test -p ioi-types app::runtime_contracts::tests --lib` | passed |
| `cargo test -p ioi-services agentic::runtime::tools::builtins::tests --lib` | passed |
| `cargo test -p ioi-services agentic::runtime::tools::contracts::tests --lib` | passed |

## Evidence

- Runtime layout guardrail:
  `docs/evidence/runtime-layout-refactor/guardrail-report.json`
- Architectural complete-plus validation:
  `docs/evidence/architectural-improvements-broad/validation-summary.json`
- Architectural complete-plus evidence:
  `docs/evidence/architectural-improvements-broad/evidence-summary.json`

## Result

The physical runtime service split and active work graph vocabulary migration
are complete. `npm run check:runtime-layout` now fails if `service/step/`
returns, if production code imports `service::step`, or if active runtime/UI/API
code reintroduces non-compatibility `swarm` vocabulary. No open
runtime-layout debt remains.

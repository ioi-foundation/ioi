# Dogfooding Dashboard

This dashboard is a projection over source contracts and validation artifacts. It does not define a separate runtime.

| Surface | Substrate proof |
| --- | --- |
| CLI | crates/cli/src/commands/agent.rs |
| API/runtime | crates/services/src/agentic/runtime/substrate.rs |
| Harness | crates/types/src/app/harness.rs |
| Workflow compositor | apps/autopilot/src/windows/AutopilotShellWindow/workflowComposerWiring.test.ts |
| Benchmarks | scripts/run-agent-model-matrix.mjs |
| Desktop UI | scripts/run-autopilot-gui-harness-validation.mjs |

Import boundary: Complete

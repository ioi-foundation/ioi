#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cargo check -p ioi-api
cargo check -p ioi-services
cargo test -p ioi-types runtime_contracts --lib
cargo test -p ioi-types harness --lib
cargo test -p ioi-services tools::contracts --lib
cargo test -p ioi-services builtin_tools_project_complete_runtime_contracts --lib
cargo test -p ioi-services substrate --lib
cargo test -p ioi-cli --bin cli commands::agent::tests --no-default-features
cargo test -p ioi-services "agentic::runtime::service::step::tests::"
cargo test -p ioi-services sudo_retry_restores_install_from_incident_when_pending_tool_is_stale
cargo test -p ioi-services reset_for_new_user_goal_refreshes_target_and_intent_state
cargo test -p ioi-services --test pii_hard_gates
node apps/autopilot/src/windows/AutopilotShellWindow/harnessWorkflowWiring.test.mjs
node apps/autopilot/src/windows/AutopilotShellWindow/workflowComposerWiring.test.ts
npm run test:autopilot-gui-harness
npm run validate:autopilot-gui-harness
npm run test:agent-runtime-p3
npm run validate:agent-runtime-p3
npm run test:agent-runtime-superiority
npm run validate:agent-runtime-superiority -- --require-gui-evidence

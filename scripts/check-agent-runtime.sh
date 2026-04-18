#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cargo check -p ioi-api
cargo check -p ioi-services
cargo test -p ioi-services "agentic::runtime::service::step::tests::"
cargo test -p ioi-services sudo_retry_restores_install_from_incident_when_pending_tool_is_stale
cargo test -p ioi-services reset_for_new_user_goal_refreshes_target_and_intent_state
cargo test -p ioi-services --test pii_hard_gates

# Agent Runtime DeepSeek TUI Parity Plus Validation Ledger

Status: extracted validation ledger
Source guide: `docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md`
Reorganized: 2026-05-12

This ledger keeps proof paths and validation-command summaries out of the master
guide while preserving traceability for each completed implementation slice.

The `Source Section` column records the guide heading under which the slice
originally appeared before extraction. Use the slice title and evidence path for
the practical workstream when the source heading is broad.

## Compact Validation Index

| # | Date | Source Section | Slice | Evidence Bundle | Validation Commands |
| --- | --- | --- | --- | --- | --- |
| 1 | 2026-05-11 | P1. Model Auto-Routing And Reasoning Effort | P1. Model Auto-Routing And Reasoning Effort | docs/evidence/autopilot-gui-harness-validation/2026-05-11T00-45-58-933Z/result.json | node --test scripts/lib/live-runtime-daemon-contract.test.mjs<br>node --test packages/agent-sdk/test/sdk.test.mjs<br>node --test scripts/lib/model-mounting-daemon-contract.test.mjs |
| 2 | 2026-05-11 | P1. Memory UX | P1. Memory UX | n/a | see slice log |
| 3 | 2026-05-11 | P1. Memory UX | memory policy controls | docs/evidence/autopilot-gui-harness-validation/2026-05-11T02-51-13-357Z/result.json | node --check packages/runtime-daemon/src/index.mjs<br>node --check packages/runtime-daemon/src/memory-store.mjs<br>npm run build:agent-sdk<br>npm run build:ide<br>node --test scripts/lib/live-runtime-daemon-contract.test.mjs |
| 4 | 2026-05-11 | P1. Memory UX | workflow memory execution wiring | docs/evidence/autopilot-gui-harness-validation/2026-05-11T03-17-06-563Z/result.json | node --check packages/runtime-daemon/src/model-mounting.mjs<br>node --check packages/runtime-daemon/src/model-mounting/workflow-memory.mjs<br>node --check packages/runtime-daemon/src/model-mounting/workflow-node.mjs<br>npm run build:agent-sdk<br>npm run build:ide |
| 5 | 2026-05-11 | P1. Memory UX | workflow memory search/list | docs/evidence/autopilot-gui-harness-validation/2026-05-11T03-50-03-897Z/result.json | node --check packages/runtime-daemon/src/memory-store.mjs<br>node --check packages/runtime-daemon/src/index.mjs<br>npm run build:agent-sdk<br>npm run build:ide<br>cargo test -p autopilot workflow_model_tool_memory_parser_loop_records_lineage |
| 6 | 2026-05-11 | P1. Memory UX | subagent memory inheritance execution | docs/evidence/autopilot-gui-harness-validation/2026-05-11T04-25-14-983Z/result.json | node --check packages/runtime-daemon/src/index.mjs<br>npm run build:agent-sdk<br>npm run build:ide<br>node --test packages/agent-sdk/test/sdk.test.mjs<br>node --test scripts/lib/live-runtime-daemon-contract.test.mjs |
| 7 | 2026-05-11 | P1. Doctor, Config, And Introspection | runtime doctor preflight | docs/evidence/autopilot-gui-harness-validation/2026-05-11T04-42-38-804Z/result.json | node --check packages/runtime-daemon/src/index.mjs<br>npm run build:ide<br>cargo test -p ioi-cli --bin cli parses_agent_operator_surface_commands<br>node --test scripts/lib/live-runtime-daemon-contract.test.mjs |
| 8 | 2026-05-11 | P1. Skills And Hooks | read-only skill and hook discovery | docs/evidence/autopilot-gui-harness-validation/2026-05-11T04-51-31-990Z/result.json | node --check packages/runtime-daemon/src/index.mjs<br>npm run build:ide<br>cargo test -p ioi-cli --bin cli parses_agent_operator_surface_commands<br>node --test scripts/lib/live-runtime-daemon-contract.test.mjs |
| 9 | 2026-05-11 | P1. Skills And Hooks | active skill/hook manifest per turn | docs/evidence/autopilot-gui-harness-validation/2026-05-11T04-58-22-773Z/result.json | node --check packages/runtime-daemon/src/index.mjs<br>npm run build:ide<br>node --test scripts/lib/live-runtime-daemon-contract.test.mjs |
| 10 | 2026-05-11 | P1. Skills And Hooks | hook dry-run policy preview | docs/evidence/autopilot-gui-harness-validation/2026-05-11T05-07-33-015Z/result.json | node --check packages/runtime-daemon/src/index.mjs<br>npm run build:ide<br>node --test scripts/lib/live-runtime-daemon-contract.test.mjs |
| 11 | 2026-05-11 | P1. Skills And Hooks | HookPolicyNode activation gate | docs/evidence/autopilot-gui-harness-validation/2026-05-11T05-14-01-420Z/result.json | npm run build:ide<br>node --test scripts/lib/live-runtime-daemon-contract.test.mjs |
| 12 | 2026-05-11 | P1. Skills And Hooks | hook invocation ledger | docs/evidence/autopilot-gui-harness-validation/2026-05-11T05-19-58-078Z/result.json | node --check packages/runtime-daemon/src/index.mjs<br>npm run build:ide<br>node --test scripts/lib/live-runtime-daemon-contract.test.mjs |
| 13 | 2026-05-11 | P1. Skills And Hooks | hook escalation receipts | docs/evidence/autopilot-gui-harness-validation/2026-05-11T05-25-17-876Z/result.json | node --check packages/runtime-daemon/src/index.mjs<br>node --test scripts/lib/live-runtime-daemon-contract.test.mjs<br>npm run build:ide |
| 14 | 2026-05-11 | P2. GitHub And PR Workflow Parity Plus | repository context foundation | docs/evidence/autopilot-gui-harness-validation/2026-05-11T05-36-44-368Z/result.json | node --check packages/runtime-daemon/src/index.mjs<br>node --test scripts/lib/live-runtime-daemon-contract.test.mjs<br>npm run build:ide |
| 15 | 2026-05-11 | P2. GitHub And PR Workflow Parity Plus | branch policy gate | docs/evidence/autopilot-gui-harness-validation/2026-05-11T11-16-23-615Z/result.json | node --check packages/runtime-daemon/src/index.mjs<br>node --test scripts/lib/live-runtime-daemon-contract.test.mjs<br>npm run build:ide |
| 16 | 2026-05-11 | P2. GitHub And PR Workflow Parity Plus | GitHub context projection | docs/evidence/autopilot-gui-harness-validation/2026-05-11T11-38-48-741Z/result.json | node --check packages/runtime-daemon/src/index.mjs<br>node --test scripts/lib/live-runtime-daemon-contract.test.mjs<br>npm run build:ide |
| 17 | 2026-05-11 | P2. GitHub And PR Workflow Parity Plus | PR attempt preview ledger | docs/evidence/autopilot-gui-harness-validation/2026-05-11T11-51-00-206Z/result.json | node --check packages/runtime-daemon/src/index.mjs<br>node --test scripts/lib/live-runtime-daemon-contract.test.mjs<br>npm run build:ide |
| 18 | 2026-05-11 | P2. GitHub And PR Workflow Parity Plus | review gate decision | docs/evidence/autopilot-gui-harness-validation/2026-05-11T12-15-17-099Z/result.json | node --check packages/runtime-daemon/src/index.mjs<br>node --test scripts/lib/live-runtime-daemon-contract.test.mjs<br>npm run build:ide |
| 19 | 2026-05-11 | P2. GitHub And PR Workflow Parity Plus | issue context projection | docs/evidence/autopilot-gui-harness-validation/2026-05-11T12-25-31-750Z/result.json | node --check packages/runtime-daemon/src/index.mjs<br>node --test scripts/lib/live-runtime-daemon-contract.test.mjs<br>npm run build:ide |
| 20 | 2026-05-11 | P2. GitHub And PR Workflow Parity Plus | GitHub PR create dry-run plan | docs/evidence/autopilot-gui-harness-validation/2026-05-11T12-38-30-155Z/result.json | node --check packages/runtime-daemon/src/index.mjs<br>node --test scripts/lib/live-runtime-daemon-contract.test.mjs<br>npm run build:ide |
| 21 | 2026-05-11 | P2. Runtime Task Queue And Jobs | runtime task/job ledger spine | docs/evidence/autopilot-gui-harness-validation/2026-05-11T12-52-37-360Z/result.json | node --check packages/runtime-daemon/src/index.mjs<br>node --test scripts/lib/live-runtime-daemon-contract.test.mjs<br>npm run build:ide |
| 22 | 2026-05-11 | P2. Runtime Task Queue And Jobs | job cancellation endpoint | docs/evidence/autopilot-gui-harness-validation/2026-05-11T13-05-03-333Z/result.json | node --check packages/runtime-daemon/src/index.mjs<br>node --test scripts/lib/live-runtime-daemon-contract.test.mjs<br>npm run build:ide |
| 23 | 2026-05-11 | P2. Runtime Task Queue And Jobs | runtime checklist record | docs/evidence/autopilot-gui-harness-validation/2026-05-11T13-35-25-228Z/result.json | node --check packages/runtime-daemon/src/index.mjs<br>node --test scripts/lib/live-runtime-daemon-contract.test.mjs<br>npm run build:ide -- --pretty false |
| 24 | 2026-05-11 | P2. Localization And Accessibility | runtime chrome localization and accessible status metadata | docs/evidence/autopilot-gui-harness-validation/2026-05-11T14-03-04-311Z/result.json | node --check packages/runtime-daemon/src/index.mjs<br>node --test scripts/lib/live-runtime-daemon-contract.test.mjs<br>npm run build:ide -- --pretty false |
| 25 | 2026-05-11 | P2. Localization And Accessibility | workflow UI localization and accessible status surfaces | docs/evidence/autopilot-gui-harness-validation/2026-05-11T14-14-20-396Z/result.json | node --check packages/runtime-daemon/src/index.mjs<br>npm run build:ide -- --pretty false<br>node --test scripts/lib/live-runtime-daemon-contract.test.mjs |
| 26 | 2026-05-11 | P2. Localization And Accessibility | keyboard and focus parity | docs/evidence/autopilot-gui-harness-validation/2026-05-11T14-28-34-383Z/result.json | node --check packages/runtime-daemon/src/index.mjs<br>npm run build:ide -- --pretty false<br>node --test scripts/lib/live-runtime-daemon-contract.test.mjs |
| 27 | 2026-05-11 | P2. Localization And Accessibility | global workflow chrome locale | docs/evidence/autopilot-gui-harness-validation/2026-05-11T14-34-43-218Z/result.json | node --check packages/runtime-daemon/src/index.mjs<br>npm run build:ide -- --pretty false<br>node --test scripts/lib/live-runtime-daemon-contract.test.mjs |
| 28 | 2026-05-11 | P2. Localization And Accessibility | locale-aware portable package evidence | docs/evidence/autopilot-gui-harness-validation/2026-05-11T14-47-49-991Z/result.json | node --check packages/runtime-daemon/src/index.mjs<br>npm run build:ide -- --pretty false<br>cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_portable_package_exports_and_imports_bundle_sidecars -- --nocapture<br>node --test scripts/lib/live-runtime-daemon-contract.test.mjs |
| 29 | 2026-05-11 | P2. Localization And Accessibility | workflow-native package/import actions | docs/evidence/autopilot-gui-harness-validation/2026-05-11T15-01-34-285Z/result.json | node --check packages/runtime-daemon/src/index.mjs<br>node scripts/generate-runtime-action-contracts.mjs --check<br>npm run build:ide -- --pretty false<br>cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_portable_package_exports_and_imports_bundle_sidecars -- --nocapture<br>node --test scripts/lib/live-runtime-daemon-contract.test.mjs |
| 30 | 2026-05-11 | P2. Localization And Accessibility | package action runtime execution | docs/evidence/autopilot-gui-harness-validation/2026-05-11T15-24-53-304Z/result.json | node --check packages/runtime-daemon/src/index.mjs<br>node scripts/generate-runtime-action-contracts.mjs --check<br>npm run build:ide -- --pretty false<br>cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_package_export_and_import_nodes_execute_through_runtime -- --nocapture<br>cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_portable_package_exports_and_imports_bundle_sidecars -- --nocapture |
| 31 | 2026-05-11 | P2. Localization And Accessibility | package action run output surfaces | docs/evidence/autopilot-gui-harness-validation/2026-05-11T15-33-50-765Z/result.json | node --check packages/runtime-daemon/src/index.mjs<br>node --check scripts/lib/autopilot-gui-harness-validation/core.mjs<br>node scripts/generate-runtime-action-contracts.mjs --check<br>npm run build:ide -- --pretty false<br>cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_package_export_and_import_nodes_execute_through_runtime -- --nocapture |
| 32 | 2026-05-11 | P2. Localization And Accessibility | live shadow promotion/default dispatch binding | docs/evidence/autopilot-gui-harness-validation/2026-05-11T15-57-19-939Z/result.json | node --check scripts/lib/autopilot-gui-harness-validation/core.mjs<br>npm run build:ide -- --pretty false<br>node --test scripts/lib/live-runtime-daemon-contract.test.mjs<br>github_pr_create<br>git diff --check |
| 33 | 2026-05-11 | P2. Localization And Accessibility | direct PR-create live shadow artifact emission | docs/evidence/autopilot-gui-harness-validation/2026-05-11T16-33-52-995Z/result.json | cargo test -p ioi-types harness -- --nocapture<br>cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml default_runtime_dispatch_accepts_isolated_output_writer_staged_write_canary -- --nocapture<br>cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml save_local_task_state_exports_gui_runtime_evidence_projection -- --nocapture<br>node --check scripts/lib/autopilot-gui-harness-validation/core.mjs<br>node --test scripts/lib/autopilot-gui-harness-contract.test.mjs |
| 34 | 2026-05-11 | P2. Localization And Accessibility | PR-create workflow output surfaces | docs/evidence/autopilot-gui-harness-validation/2026-05-11T16-55-06-446Z/result.json | npm run build:ide -- --pretty false<br>node --check scripts/lib/harness-promotion-transition-gui-probe.mjs<br>node --check scripts/lib/autopilot-gui-harness-validation/core.mjs<br>node --test scripts/lib/live-runtime-daemon-contract.test.mjs<br>node --test scripts/lib/autopilot-gui-harness-contract.test.mjs |
| 35 | 2026-05-11 | P2. Localization And Accessibility | PR-create React Flow runtime execution | docs/evidence/autopilot-gui-harness-validation/2026-05-11T17-23-26-703Z/result.json | cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>node --test scripts/lib/live-runtime-daemon-contract.test.mjs<br>validation.ok === true<br>blocked === false |
| 36 | 2026-05-11 | P2. Localization And Accessibility | PR-create runtime module refactor | docs/evidence/autopilot-gui-harness-validation/2026-05-11T17-53-05-240Z/result.json | cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>node --test scripts/lib/live-runtime-daemon-contract.test.mjs<br>validation.ok === true<br>blocked === false |
| 37 | 2026-05-11 | P2. Localization And Accessibility | workflow value helper extraction | docs/evidence/autopilot-gui-harness-validation/2026-05-11T18-26-54-384Z/result.json | cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>node --test scripts/lib/live-runtime-daemon-contract.test.mjs<br>validation.ok === true<br>blocked === false |
| 38 | 2026-05-11 | P2. Localization And Accessibility | workflow package lane refactor | docs/evidence/autopilot-gui-harness-validation/2026-05-11T18-40-25-909Z/result.json | cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>node --test scripts/lib/live-runtime-daemon-contract.test.mjs<br>validation.ok === true |
| 39 | 2026-05-11 | P2. Localization And Accessibility | workflow memory lane refactor | docs/evidence/autopilot-gui-harness-validation/2026-05-11T19-05-24-252Z/result.json | cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>node --test scripts/lib/live-runtime-daemon-contract.test.mjs |
| 40 | 2026-05-11 | P2. Localization And Accessibility | authority/tooling lane refactor | docs/evidence/autopilot-gui-harness-validation/2026-05-11T19-23-09-790Z/result.json | cargo test live_mcp_provider_catalog_executes_read_only_without_mutation --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test live_mcp_tool_catalog_consumes_provider_catalog_without_tool_execution --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test live_native_tool_catalog_consumes_mcp_tool_catalog_without_tool_execution --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test live_connector_catalog_describe_consumes_mcp_tool_catalog_without_connector_execution --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test live_wallet_capability_dry_run_never_materializes_grant --manifest-path apps/autopilot/src-tauri/Cargo.toml |
| 41 | 2026-05-11 | P2. Localization And Accessibility | workflow coding-route lane refactor | docs/evidence/autopilot-gui-harness-validation/2026-05-11T19-38-33-940Z/result.json | cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml |
| 42 | 2026-05-11 | P2. Localization And Accessibility | workflow execution-results lane refactor | docs/evidence/autopilot-gui-harness-validation/2026-05-11T19-59-05-130Z/result.json | cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml |
| 43 | 2026-05-11 | P2. Localization And Accessibility | workflow harness-results lane refactor | docs/evidence/autopilot-gui-harness-validation/2026-05-11T20-14-13-182Z/result.json | cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml |
| 44 | 2026-05-11 | P2. Localization And Accessibility | workflow graph-execution lane refactor | docs/evidence/autopilot-gui-harness-validation/2026-05-11T20-27-36-131Z/result.json | cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml |
| 45 | 2026-05-11 | P2. Localization And Accessibility | workflow binding lane refactor | docs/evidence/autopilot-gui-harness-validation/2026-05-11T20-40-37-167Z/result.json | cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml |
| 46 | 2026-05-11 | P2. Localization And Accessibility | workflow output lane refactor | docs/evidence/autopilot-gui-harness-validation/2026-05-11T21-05-30-136Z/result.json | cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml |
| 47 | 2026-05-11 | P2. Localization And Accessibility | workflow approval/interrupt lane refactor | docs/evidence/autopilot-gui-harness-validation/2026-05-11T21-47-22-432Z/result.json | cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_tool_side_effect_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_output_delivery_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml |
| 48 | 2026-05-12 | P2. Localization And Accessibility | workflow checkpoint lane refactor | docs/evidence/autopilot-gui-harness-validation/2026-05-12T01-20-27-365Z/result.json | cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_failed_function_resumes_from_repaired_checkpoint --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_retry_preserves_failed_attempt_evidence --manifest-path apps/autopilot/src-tauri/Cargo.toml |
| 49 | 2026-05-12 | P2. Localization And Accessibility | workflow state/input mapping lane refactor | docs/evidence/autopilot-gui-harness-validation/2026-05-12T01-35-34-520Z/result.json | cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_expression_refs_require_connected_output_ports --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_field_mappings_require_declared_schema_paths --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_field_mappings_prepare_runtime_node_input --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml |
| 50 | 2026-05-12 | P2. Localization And Accessibility | workflow node-execution lane refactor | docs/evidence/autopilot-gui-harness-validation/2026-05-12T01-50-03-398Z/result.json | cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_expression_refs_require_connected_output_ports --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_field_mappings_prepare_runtime_node_input --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml |
| 51 | 2026-05-12 | P2. Localization And Accessibility | workflow node-contract lane refactor | docs/evidence/autopilot-gui-harness-validation/2026-05-12T02-04-17-641Z/result.json | cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_expression_refs_require_connected_output_ports --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_field_mappings_prepare_runtime_node_input --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml |
| 52 | 2026-05-12 | P2. Localization And Accessibility | workflow run-lifecycle lane refactor | docs/evidence/autopilot-gui-harness-validation/2026-05-12T02-17-52-426Z/result.json | cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_expression_refs_require_connected_output_ports --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_field_mappings_prepare_runtime_node_input --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml |
| 53 | 2026-05-12 | P2. Localization And Accessibility | workflow node-metadata lane refactor | docs/evidence/autopilot-gui-harness-validation/2026-05-12T02-30-26-185Z/result.json | cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_expression_refs_require_connected_output_ports --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_field_mappings_prepare_runtime_node_input --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml |
| 54 | 2026-05-12 | P2. Localization And Accessibility | workflow scheduler lane refactor | docs/evidence/autopilot-gui-harness-validation/2026-05-12T02-42-18-082Z/result.json | cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_expression_refs_require_connected_output_ports --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_field_mappings_prepare_runtime_node_input --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml |
| 55 | 2026-05-12 | P2. Localization And Accessibility | workflow scheduler validation lane refactor | docs/evidence/autopilot-gui-harness-validation/2026-05-12T02-55-14-162Z/result.json | cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_expression_refs_require_connected_output_ports --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_field_mappings_prepare_runtime_node_input --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml |
| 56 | 2026-05-12 | P2. Localization And Accessibility | workflow scheduler interrupt lane refactor | docs/evidence/autopilot-gui-harness-validation/2026-05-12T03-06-47-704Z/result.json | cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_expression_refs_require_connected_output_ports --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_field_mappings_prepare_runtime_node_input --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml |
| 57 | 2026-05-12 | P2. Localization And Accessibility | workflow scheduler node execution lane refactor | docs/evidence/autopilot-gui-harness-validation/2026-05-12T03-20-30-303Z/result.json | cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_expression_refs_require_connected_output_ports --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_field_mappings_prepare_runtime_node_input --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml |
| 58 | 2026-05-12 | P2. Localization And Accessibility | workflow scheduler finalization lane refactor | docs/evidence/autopilot-gui-harness-validation/2026-05-12T03-33-43-994Z/result.json | cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_expression_refs_require_connected_output_ports --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_field_mappings_prepare_runtime_node_input --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml |
| 59 | 2026-05-12 | P2. Localization And Accessibility | workflow scheduler terminal result lane refactor | docs/evidence/autopilot-gui-harness-validation/2026-05-12T03-49-14-148Z/result.json | cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_expression_refs_require_connected_output_ports --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_field_mappings_prepare_runtime_node_input --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml |
| 60 | 2026-05-12 | P2. Localization And Accessibility | workflow scheduler node outcome lane refactor | docs/evidence/autopilot-gui-harness-validation/2026-05-12T04-02-51-456Z/result.json | cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_expression_refs_require_connected_output_ports --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_field_mappings_prepare_runtime_node_input --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml |
| 61 | 2026-05-12 | P2. Localization And Accessibility | workflow scheduler node state update lane refactor | docs/evidence/autopilot-gui-harness-validation/2026-05-12T06-55-19-771Z/result.json | cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_expression_refs_require_connected_output_ports --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_field_mappings_prepare_runtime_node_input --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml |
| 62 | 2026-05-12 | P2. Localization And Accessibility | workflow scheduler node success event lane refactor | docs/evidence/autopilot-gui-harness-validation/2026-05-12T07-10-36-395Z/result.json | cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_expression_refs_require_connected_output_ports --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_field_mappings_prepare_runtime_node_input --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml |
| 63 | 2026-05-12 | P2. Localization And Accessibility | workflow scheduler node failure outcome lane refactor | docs/evidence/autopilot-gui-harness-validation/2026-05-12T10-59-14-718Z/result.json | cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_expression_refs_require_connected_output_ports --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_field_mappings_prepare_runtime_node_input --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml |
| 64 | 2026-05-12 | P2. Localization And Accessibility | React Flow scheduler lane readiness UI | docs/evidence/autopilot-gui-harness-validation/2026-05-12T11-23-50-090Z/result.json | npm run build --workspace=@ioi/agent-ide<br>node --import tsx - <<'EOF' ... scheduler lane readiness check passed<br>node --check scripts/lib/live-runtime-daemon-contract.test.mjs && node --check scripts/lib/autopilot-gui-harness-validation/core.mjs<br>node --test scripts/lib/live-runtime-daemon-contract.test.mjs<br>cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler |
| 65 | 2026-05-12 | P2. Localization And Accessibility | React Flow readiness panel extraction | docs/evidence/autopilot-gui-harness-validation/2026-05-12T11-44-32-936Z/result.json | npm run build --workspace=@ioi/agent-ide<br>node --check scripts/lib/live-runtime-daemon-contract.test.mjs && node --check scripts/lib/autopilot-gui-harness-validation/core.mjs && node --check scripts/lib/harness-refactor-shape.test.mjs<br>node --test scripts/lib/live-runtime-daemon-contract.test.mjs<br>node --test scripts/lib/harness-refactor-shape.test.mjs<br>npm run validate:autopilot-gui-harness |
| 66 | 2026-05-12 | P2. Localization And Accessibility | React Flow readiness model extraction | docs/evidence/autopilot-gui-harness-validation/2026-05-12T12-10-50-239Z/result.json | node --import tsx --test packages/agent-ide/src/runtime/workflow-readiness-model.test.ts<br>node --check scripts/lib/live-runtime-daemon-contract.test.mjs<br>node --check scripts/lib/autopilot-gui-harness-validation/core.mjs<br>node --check scripts/lib/harness-refactor-shape.test.mjs<br>npm run build --workspace=@ioi/agent-ide |
| 67 | 2026-05-12 | P2. Localization And Accessibility | React Flow unit-test readiness model extraction | docs/evidence/autopilot-gui-harness-validation/2026-05-12T12-29-29-676Z/result.json | node --import tsx --test packages/agent-ide/src/runtime/workflow-test-readiness-model.test.ts<br>node --check scripts/lib/live-runtime-daemon-contract.test.mjs<br>node --check scripts/lib/autopilot-gui-harness-validation/core.mjs<br>node --check scripts/lib/harness-refactor-shape.test.mjs<br>npm run build --workspace=@ioi/agent-ide |
| 68 | 2026-05-12 | P2. Localization And Accessibility | React Flow run-history model extraction | docs/evidence/autopilot-gui-harness-validation/2026-05-12T12-53-40-859Z/result.json | node --import tsx --test packages/agent-ide/src/runtime/workflow-run-history-model.test.ts<br>npm run build --workspace=@ioi/agent-ide<br>node --check scripts/lib/live-runtime-daemon-contract.test.mjs<br>node --check scripts/lib/autopilot-gui-harness-validation/core.mjs<br>node --check scripts/lib/harness-refactor-shape.test.mjs |
| 69 | 2026-05-12 | P2. Localization And Accessibility | React Flow search model extraction | docs/evidence/autopilot-gui-harness-validation/2026-05-12T13-15-19-853Z/result.json | node --import tsx --test packages/agent-ide/src/runtime/workflow-rail-search-model.test.ts<br>node --check scripts/lib/live-runtime-daemon-contract.test.mjs<br>node --check scripts/lib/autopilot-gui-harness-validation/core.mjs<br>node --check scripts/lib/harness-refactor-shape.test.mjs<br>node --import tsx --test packages/agent-ide/src/runtime/workflow-rail-search-model.test.ts packages/agent-ide/src/runtime/workflow-run-history-model.test.ts packages/agent-ide/src/runtime/workflow-test-readiness-model.test.ts packages/agent-ide/src/runtime/workflow-readiness-model.test.ts |
| 70 | 2026-05-12 | P2. Localization And Accessibility | React Flow entrypoints model extraction | docs/evidence/autopilot-gui-harness-validation/2026-05-12T13-32-20-984Z/result.json | node --import tsx --test packages/agent-ide/src/runtime/workflow-entrypoints-model.test.ts<br>node --check scripts/lib/live-runtime-daemon-contract.test.mjs<br>node --check scripts/lib/autopilot-gui-harness-validation/core.mjs<br>node --check scripts/lib/harness-refactor-shape.test.mjs<br>node --import tsx --test packages/agent-ide/src/runtime/workflow-entrypoints-model.test.ts packages/agent-ide/src/runtime/workflow-rail-search-model.test.ts packages/agent-ide/src/runtime/workflow-run-history-model.test.ts packages/agent-ide/src/runtime/workflow-test-readiness-model.test.ts packages/agent-ide/src/runtime/workflow-readiness-model.test.ts |
| 71 | 2026-05-12 | P2. Localization And Accessibility | React Flow file-bundle model extraction | docs/evidence/autopilot-gui-harness-validation/2026-05-12T13-48-13-986Z/result.json | node --import tsx --test packages/agent-ide/src/runtime/workflow-file-bundle-model.test.ts<br>node --check scripts/lib/live-runtime-daemon-contract.test.mjs<br>node --check scripts/lib/autopilot-gui-harness-validation/core.mjs<br>node --check scripts/lib/harness-refactor-shape.test.mjs<br>node --import tsx --test packages/agent-ide/src/runtime/workflow-file-bundle-model.test.ts packages/agent-ide/src/runtime/workflow-entrypoints-model.test.ts packages/agent-ide/src/runtime/workflow-rail-search-model.test.ts packages/agent-ide/src/runtime/workflow-run-history-model.test.ts packages/agent-ide/src/runtime/workflow-test-readiness-model.test.ts packages/agent-ide/src/runtime/workflow-readiness-model.test.ts |
| 72 | 2026-05-12 | P2. Localization And Accessibility | React Flow settings model extraction | docs/evidence/autopilot-gui-harness-validation/2026-05-12T14-16-54-801Z/result.json | node --import tsx --test packages/agent-ide/src/runtime/workflow-settings-model.test.ts<br>node --check scripts/lib/live-runtime-daemon-contract.test.mjs<br>node --check scripts/lib/autopilot-gui-harness-validation/core.mjs<br>node --check scripts/lib/harness-refactor-shape.test.mjs<br>node --import tsx --test packages/agent-ide/src/runtime/workflow-settings-model.test.ts packages/agent-ide/src/runtime/workflow-file-bundle-model.test.ts packages/agent-ide/src/runtime/workflow-entrypoints-model.test.ts packages/agent-ide/src/runtime/workflow-rail-search-model.test.ts packages/agent-ide/src/runtime/workflow-run-history-model.test.ts packages/agent-ide/src/runtime/workflow-test-readiness-model.test.ts packages/agent-ide/src/runtime/workflow-readiness-model.test.ts |
| 73 | 2026-05-12 | P2. Localization And Accessibility | React Flow settings harness extraction | docs/evidence/autopilot-gui-harness-validation/2026-05-12T14-57-39-502Z/result.json | node --check scripts/lib/autopilot-gui-harness-validation/core.mjs<br>node --test scripts/lib/harness-refactor-shape.test.mjs<br>node --test scripts/lib/live-runtime-daemon-contract.test.mjs<br>node --import tsx --test packages/agent-ide/src/runtime/workflow-settings-harness-model.test.ts packages/agent-ide/src/runtime/workflow-settings-model.test.ts packages/agent-ide/src/runtime/workflow-file-bundle-model.test.ts packages/agent-ide/src/runtime/workflow-entrypoints-model.test.ts packages/agent-ide/src/runtime/workflow-rail-search-model.test.ts packages/agent-ide/src/runtime/workflow-run-history-model.test.ts packages/agent-ide/src/runtime/workflow-test-readiness-model.test.ts packages/agent-ide/src/runtime/workflow-readiness-model.test.ts<br>npm run build --workspace=@ioi/agent-ide |
| 74 | 2026-05-12 | P2. Localization And Accessibility | React Flow settings harness typed boundary | docs/evidence/autopilot-gui-harness-validation/2026-05-12T15-19-43-946Z/result.json | npm run build --workspace=@ioi/agent-ide<br>node --test scripts/lib/harness-refactor-shape.test.mjs<br>node --test scripts/lib/live-runtime-daemon-contract.test.mjs<br>node --check scripts/lib/autopilot-gui-harness-validation/core.mjs<br>node --check scripts/lib/live-runtime-daemon-contract.test.mjs |
| 75 | 2026-05-12 | P2. Localization And Accessibility | React Flow settings harness activation panel extraction | docs/evidence/autopilot-gui-harness-validation/2026-05-12T15-42-11-524Z/result.json | npm run build --workspace=@ioi/agent-ide<br>node --test scripts/lib/harness-refactor-shape.test.mjs<br>node --check scripts/lib/autopilot-gui-harness-validation/core.mjs<br>node --test scripts/lib/live-runtime-daemon-contract.test.mjs<br>npm run validate:autopilot-gui-harness:run |
| 76 | 2026-05-12 | P2. Localization And Accessibility | React Flow settings harness worker-binding and rollback panel extraction | docs/evidence/autopilot-gui-harness-validation/2026-05-12T16-10-00-442Z/result.json | npm run build --workspace=@ioi/agent-ide<br>node --test scripts/lib/harness-refactor-shape.test.mjs<br>node --check scripts/lib/autopilot-gui-harness-validation/core.mjs<br>node --test scripts/lib/live-runtime-daemon-contract.test.mjs<br>cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler |
| 77 | 2026-05-12 | P2. Localization And Accessibility | React Flow settings harness promotion panel extraction | docs/evidence/autopilot-gui-harness-validation/2026-05-12T16-27-56-146Z/result.json | npm run build --workspace=@ioi/agent-ide<br>node --test scripts/lib/harness-refactor-shape.test.mjs<br>node --check scripts/lib/autopilot-gui-harness-validation/core.mjs<br>node --test scripts/lib/live-runtime-daemon-contract.test.mjs<br>cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler |
| 78 | 2026-05-12 | P2. Localization And Accessibility | React Flow settings harness type contract extraction | docs/evidence/autopilot-gui-harness-validation/2026-05-12T16-41-58-495Z/result.json | npm run build --workspace=@ioi/agent-ide<br>node --test scripts/lib/harness-refactor-shape.test.mjs<br>node --check scripts/lib/autopilot-gui-harness-validation/core.mjs<br>node --test scripts/lib/live-runtime-daemon-contract.test.mjs<br>cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler |
| 79 | 2026-05-12 | P2. Localization And Accessibility | React Flow settings harness active runtime rollback panel extraction | docs/evidence/autopilot-gui-harness-validation/2026-05-12T17-11-04-005Z/result.json | npm run build --workspace=@ioi/agent-ide<br>node --test scripts/lib/harness-refactor-shape.test.mjs<br>node --check scripts/lib/autopilot-gui-harness-validation/core.mjs<br>node --test scripts/lib/live-runtime-daemon-contract.test.mjs<br>cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler |
| 80 | 2026-05-12 | P2. Localization And Accessibility | React Flow settings harness rollback restore proof panel extraction | docs/evidence/autopilot-gui-harness-validation/2026-05-12T17-29-45-390Z/result.json | npm run build --workspace=@ioi/agent-ide<br>node --test scripts/lib/harness-refactor-shape.test.mjs<br>node --check scripts/lib/autopilot-gui-harness-validation/core.mjs<br>node --test scripts/lib/live-runtime-daemon-contract.test.mjs<br>cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler |
| 81 | 2026-05-12 | P2. Localization And Accessibility | React Flow settings harness active runtime binding panel extraction | docs/evidence/autopilot-gui-harness-validation/2026-05-12T17-46-33-581Z/result.json | npm run build --workspace=@ioi/agent-ide<br>node --test scripts/lib/harness-refactor-shape.test.mjs<br>node --check scripts/lib/autopilot-gui-harness-validation/core.mjs<br>node --test scripts/lib/live-runtime-daemon-contract.test.mjs<br>cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler |
| 82 | 2026-05-12 | P2. Localization And Accessibility | React Flow settings harness activation gate panel extraction | docs/evidence/autopilot-gui-harness-validation/2026-05-12T18-07-42-338Z/result.json | npm run build --workspace=@ioi/agent-ide<br>node --test scripts/lib/harness-refactor-shape.test.mjs<br>node --check scripts/lib/autopilot-gui-harness-validation/core.mjs<br>node --test scripts/lib/live-runtime-daemon-contract.test.mjs<br>cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler |
| 83 | 2026-05-12 | P2. Localization And Accessibility | React Flow settings harness promotion readiness panel extraction | docs/evidence/autopilot-gui-harness-validation/2026-05-12T18-24-22-311Z/result.json | npm run build --workspace=@ioi/agent-ide<br>node --test scripts/lib/harness-refactor-shape.test.mjs<br>node --check scripts/lib/autopilot-gui-harness-validation/core.mjs<br>node --test scripts/lib/live-runtime-daemon-contract.test.mjs<br>cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler |
| 84 | 2026-05-12 | P2. Localization And Accessibility | React Flow settings harness package evidence panel extraction | docs/evidence/autopilot-gui-harness-validation/2026-05-12T18-46-56-765Z/result.json | npm run build --workspace=@ioi/agent-ide<br>node --check scripts/lib/autopilot-gui-harness-validation/core.mjs<br>node --test scripts/lib/harness-refactor-shape.test.mjs<br>node --test scripts/lib/live-runtime-daemon-contract.test.mjs<br>cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler |
| 85 | 2026-05-12 | P2. Localization And Accessibility | React Flow settings harness activation gate refs/timeline extraction | docs/evidence/autopilot-gui-harness-validation/2026-05-12T19-05-02-607Z/result.json | npm run build --workspace=@ioi/agent-ide<br>node --check scripts/lib/autopilot-gui-harness-validation/core.mjs<br>node --test scripts/lib/harness-refactor-shape.test.mjs<br>node --test scripts/lib/live-runtime-daemon-contract.test.mjs<br>cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler |
| 86 | 2026-05-12 | P2. Localization And Accessibility | React Flow settings harness package import/rows extraction | docs/evidence/autopilot-gui-harness-validation/2026-05-12T19-30-56-229Z/result.json | npm run build --workspace=@ioi/agent-ide<br>node --check scripts/lib/autopilot-gui-harness-validation/core.mjs<br>node --test scripts/lib/harness-refactor-shape.test.mjs<br>node --test scripts/lib/live-runtime-daemon-contract.test.mjs<br>cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler |
| 87 | 2026-05-12 | P0. Live Runtime API Bridge | live bridge TTI/event contract lock | docs/specs/runtime/agent-runtime-live-bridge-tti-event-contract.md | docs integrity check<br>git diff --check |
| 104 | 2026-05-12 | P0. Live Runtime API Bridge | Live thread fork control event | /tmp/ioi-autopilot-gui-harness-thread-fork-control/2026-05-12T23-30-08-711Z/result.json | npm run build --workspace=@ioi/agent-sdk<br>npm run build --workspace=@ioi/agent-ide<br>node --test packages/agent-sdk/test/sdk.test.mjs<br>node --test --test-name-pattern "thread fork keeps one canonical source event" scripts/lib/live-runtime-daemon-contract.test.mjs |
| 105 | 2026-05-12 | P0. Live Runtime API Bridge | React Flow runtime thread fork control node | /tmp/ioi-autopilot-gui-harness-react-flow-thread-fork-control/2026-05-12T23-57-36-129Z/result.json | node --import tsx --test packages/agent-ide/src/runtime/workflow-runtime-control-nodes.test.ts packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts<br>npm run build --workspace=@ioi/agent-ide<br>cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml runtime_thread_fork_node_builds_react_flow_control_request<br>node --test --test-name-pattern "React Flow thread fork control preserves graph identity" scripts/lib/live-runtime-daemon-contract.test.mjs |
| 106 | 2026-05-13 | P0. Live Runtime API Bridge | React Flow runtime operator interrupt control node | /tmp/ioi-autopilot-gui-harness-react-flow-operator-interrupt-control/2026-05-13T00-11-09-695Z/result.json | node --import tsx --test packages/agent-ide/src/runtime/workflow-runtime-control-nodes.test.ts packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts<br>npm run build --workspace=@ioi/agent-ide<br>cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml runtime_operator_interrupt_node_builds_react_flow_control_request<br>node --test --test-name-pattern "React Flow operator interrupt control preserves graph identity" scripts/lib/live-runtime-daemon-contract.test.mjs |
| 107 | 2026-05-13 | P0. Live Runtime API Bridge | React Flow runtime operator steer control node | /tmp/ioi-autopilot-gui-harness-react-flow-operator-steer-control/2026-05-13T00-24-15-404Z/result.json | node --import tsx --test packages/agent-ide/src/runtime/workflow-runtime-control-nodes.test.ts packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts<br>npm run build --workspace=@ioi/agent-ide<br>cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml runtime_operator_steer_node_builds_react_flow_control_request<br>node --test --test-name-pattern "React Flow operator steer control preserves graph identity" scripts/lib/live-runtime-daemon-contract.test.mjs |
| 108 | 2026-05-13 | P0. Live Runtime API Bridge | React Flow runtime context compact control node | /tmp/ioi-autopilot-gui-harness-react-flow-context-compact-control/2026-05-13T00-40-20-698Z/result.json | node --import tsx --test packages/agent-ide/src/runtime/workflow-runtime-control-nodes.test.ts packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts<br>npm run build --workspace=@ioi/agent-ide<br>cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml runtime_context_compact_node_builds_react_flow_control_request<br>node --test --test-name-pattern "React Flow context compact control preserves graph identity" scripts/lib/live-runtime-daemon-contract.test.mjs |
| 109 | 2026-05-13 | P0. Live Runtime API Bridge | Shared React Flow runtime-control helper extraction | /tmp/ioi-autopilot-gui-harness-runtime-control-helper-refactor/2026-05-13T00-56-55-307Z/result.json | node --import tsx --test packages/agent-ide/src/runtime/workflow-runtime-control-nodes.test.ts packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts<br>npm run build --workspace=@ioi/agent-ide<br>cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml runtime_ -- --nocapture<br>node --test --test-name-pattern "React Flow context compact control preserves graph identity" scripts/lib/live-runtime-daemon-contract.test.mjs |
| 110 | 2026-05-13 | P2. Localization And Accessibility | React Flow settings harness active runtime binding panel split | /tmp/ioi-autopilot-gui-harness-active-runtime-binding-panel-refactor/2026-05-13T01-09-15-286Z/result.json | npm run build --workspace=@ioi/agent-ide<br>node --test scripts/lib/harness-refactor-shape.test.mjs<br>node --test --test-name-pattern "React Flow memory, authority/tooling, doctor, skill, hook, and package node contracts remain workflow-addressable" scripts/lib/live-runtime-daemon-contract.test.mjs<br>npm run validate:autopilot-gui-harness |
| 111 | 2026-05-13 | P2. Localization And Accessibility | React Flow settings harness promotion readiness panel split | /tmp/ioi-autopilot-gui-harness-promotion-readiness-panel-refactor/2026-05-13T01-18-45-520Z/result.json | npm run build --workspace=@ioi/agent-ide<br>node --test scripts/lib/harness-refactor-shape.test.mjs<br>node --test --test-name-pattern "React Flow memory, authority/tooling, doctor, skill, hook, and package node contracts remain workflow-addressable" scripts/lib/live-runtime-daemon-contract.test.mjs<br>npm run validate:autopilot-gui-harness |
| 112 | 2026-05-13 | P2. Localization And Accessibility | React Flow settings harness activation panel split | /tmp/ioi-autopilot-gui-harness-activation-panel-refactor/2026-05-13T01-27-37-008Z/result.json | npm run build --workspace=@ioi/agent-ide<br>node --test scripts/lib/harness-refactor-shape.test.mjs<br>node --test --test-name-pattern "React Flow memory, authority/tooling, doctor, skill, hook, and package node contracts remain workflow-addressable" scripts/lib/live-runtime-daemon-contract.test.mjs<br>npm run validate:autopilot-gui-harness |
| 113 | 2026-05-13 | Guide Governance | Master guide parity-gap triage cleanup | /tmp/ioi-autopilot-gui-harness-master-guide-triage/2026-05-13T01-35-47-401Z/result.json | node --check scripts/lib/autopilot-gui-harness-validation/core.mjs<br>node --test --test-name-pattern "React Flow memory, authority/tooling, doctor, skill, hook, and package node contracts remain workflow-addressable" scripts/lib/live-runtime-daemon-contract.test.mjs<br>npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-master-guide-triage<br>git diff --check |
| 114 | 2026-05-13 | P0. Terminal Coding-Agent TUI | Thin daemon-backed `ioi agent tui` shell | /tmp/ioi-autopilot-gui-harness-agent-tui-thin-shell/2026-05-13T01-47-01-001Z/result.json | cargo test -p ioi-cli --bin cli parses_agent_operator_surface_commands<br>cargo test -p ioi-cli --bin cli agent_tui<br>cargo check -p ioi-cli --bin cli<br>node --test --test-name-pattern "agent TUI thin shell starts a live thread&#124;agent TUI thin shell is daemon-backed&#124;agent CLI exposes model" scripts/lib/live-runtime-daemon-contract.test.mjs<br>npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-agent-tui-thin-shell<br>git diff --check |
| 115 | 2026-05-13 | P0. Terminal Coding-Agent TUI | React Flow/TUI runtime-event deep-link contract | /tmp/ioi-autopilot-gui-harness-agent-tui-workflow-deeplinks/2026-05-13T01-56-18-198Z/result.json | cargo test -p ioi-cli --bin cli<br>cargo check -p ioi-cli --bin cli<br>node --import tsx --test packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts packages/agent-ide/src/runtime/workflow-run-history-model.test.ts<br>npm run build --workspace=@ioi/agent-ide<br>node --test --test-name-pattern "agent TUI thin shell starts a live thread&#124;agent TUI thin shell is daemon-backed&#124;agent CLI exposes model&#124;React Flow memory, authority/tooling, doctor, skill, hook, and package node contracts remain workflow-addressable" scripts/lib/live-runtime-daemon-contract.test.mjs<br>npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-agent-tui-workflow-deeplinks |
| 116 | 2026-05-13 | P0. Terminal Coding-Agent TUI | Daemon-backed line-mode `ioi agent tui` loop | /tmp/ioi-autopilot-gui-harness-agent-tui-line-mode/2026-05-13T02-06-09-973Z/result.json | cargo test -p ioi-cli --bin cli agent_tui<br>cargo test -p ioi-cli --bin cli parses_agent_operator_surface_commands<br>cargo test -p ioi-cli --bin cli<br>cargo check -p ioi-cli --bin cli<br>node --test --test-name-pattern "agent TUI line-mode slash commands&#124;agent TUI thin shell starts a live thread&#124;agent TUI thin shell is daemon-backed&#124;agent CLI exposes model" scripts/lib/live-runtime-daemon-contract.test.mjs<br>npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-agent-tui-line-mode |
| 117 | 2026-05-13 | P0. Terminal Coding-Agent TUI | React Flow/TUI operator-control equivalence proof | /tmp/ioi-autopilot-gui-harness-tui-react-flow-control-equivalence/2026-05-13T02-12-53-211Z/result.json | node --test --test-name-pattern "React Flow and line-mode TUI .* controls share" scripts/lib/live-runtime-daemon-contract.test.mjs<br>node --test --test-name-pattern "React Flow and line-mode TUI .* controls share&#124;agent TUI line-mode slash commands&#124;React Flow operator interrupt control preserves graph identity&#124;React Flow operator steer control preserves graph identity&#124;agent CLI exposes model" scripts/lib/live-runtime-daemon-contract.test.mjs<br>node --check scripts/lib/live-runtime-daemon-contract.test.mjs<br>node --check scripts/lib/autopilot-gui-harness-validation/core.mjs<br>npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-tui-react-flow-control-equivalence |
| 118 | 2026-05-13 | P0. Terminal Coding-Agent TUI | TUI control-state projection and run-inspector rows | /tmp/ioi-autopilot-gui-harness-tui-control-state-projection/2026-05-13T02-25-01-786Z/result.json | node --import tsx --test packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts packages/agent-ide/src/runtime/workflow-run-history-model.test.ts<br>cargo test --manifest-path crates/cli/Cargo.toml --bin cli agent_tui -- --nocapture<br>npm run build --workspace=@ioi/agent-ide<br>node --test --test-name-pattern "agent CLI exposes&#124;agent TUI thin shell is daemon-backed&#124;agent TUI thin shell starts&#124;agent TUI line-mode slash commands" scripts/lib/live-runtime-daemon-contract.test.mjs<br>node --check scripts/lib/live-runtime-daemon-contract.test.mjs<br>node --check scripts/lib/autopilot-gui-harness-validation/core.mjs<br>cargo fmt -p ioi-cli -- --check<br>cargo check --manifest-path crates/cli/Cargo.toml --bin cli<br>git diff --check<br>npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-tui-control-state-projection |
| 119 | 2026-05-13 | P0. Terminal Coding-Agent TUI | TUI approval and mode-status control rows | /tmp/ioi-autopilot-gui-harness-tui-approval-mode-status/2026-05-13T02-46-20-811Z/result.json | cargo test --manifest-path crates/cli/Cargo.toml --bin cli agent_tui -- --nocapture<br>node --import tsx --test packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts packages/agent-ide/src/runtime/workflow-run-history-model.test.ts<br>npm run build --workspace=@ioi/agent-ide<br>node --test --test-name-pattern "agent CLI exposes&#124;agent TUI approval slash commands&#124;agent TUI line-mode slash commands" scripts/lib/live-runtime-daemon-contract.test.mjs<br>node --check packages/runtime-daemon/src/index.mjs && node --check scripts/lib/live-runtime-daemon-contract.test.mjs<br>cargo check --manifest-path crates/cli/Cargo.toml --bin cli<br>npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-tui-approval-mode-status |
| 120 | 2026-05-13 | P0-B. Coding Tool Pack | coding tool-pack status/diff/inspect contract | /tmp/ioi-autopilot-gui-harness-coding-tool-pack-status-diff-inspect/2026-05-13T03-05-13-000Z/result.json | node --check packages/runtime-daemon/src/index.mjs && node --check packages/runtime-daemon/src/coding-tools.mjs<br>npm run build --workspace=@ioi/agent-sdk<br>npm run build --workspace=@ioi/agent-ide<br>cargo fmt -p ioi-cli<br>cargo check -p ioi-cli<br>cargo test -p ioi-cli --bin cli parses_nested_tool_and_policy_commands -- --nocapture<br>cargo test -p ioi-cli --bin cli parses_line_mode_slash_commands -- --nocapture<br>node --test --test-name-pattern "coding tool pack invokes status" scripts/lib/live-runtime-daemon-contract.test.mjs<br>node --test --test-name-pattern "agent CLI exposes model" scripts/lib/live-runtime-daemon-contract.test.mjs<br>node --test --test-name-pattern "agent TUI thin shell is daemon-backed" scripts/lib/live-runtime-daemon-contract.test.mjs<br>npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-coding-tool-pack-status-diff-inspect |
| 121 | 2026-05-13 | P0-B. Coding Tool Pack | coding tool-pack governed apply-patch contract | /tmp/ioi-autopilot-gui-harness-coding-tool-pack-apply-patch/2026-05-13T03-24-26-739Z/result.json | node --check packages/runtime-daemon/src/coding-tools.mjs && node --check packages/runtime-daemon/src/index.mjs && node --check scripts/lib/live-runtime-daemon-contract.test.mjs<br>npm run build --workspace=@ioi/agent-sdk<br>npm run build --workspace=@ioi/agent-ide<br>cargo fmt -p ioi-cli<br>cargo check -p ioi-cli<br>cargo test -p ioi-cli --bin cli parses_nested_tool_and_policy_commands -- --nocapture<br>cargo test -p ioi-cli --bin cli parses_line_mode_slash_commands -- --nocapture<br>node --import tsx --test --test-name-pattern "projects coding tool" packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts<br>node --test --test-name-pattern "coding tool pack invokes status" scripts/lib/live-runtime-daemon-contract.test.mjs<br>npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-coding-tool-pack-apply-patch |
| 122 | 2026-05-13 | P0-B. Coding Tool Pack | coding tool-pack structured test-run contract | /tmp/ioi-autopilot-gui-harness-coding-tool-pack-test-run/2026-05-13T03-36-24-435Z/result.json | node --check packages/runtime-daemon/src/coding-tools.mjs && node --check scripts/lib/live-runtime-daemon-contract.test.mjs<br>npm run build --workspace=@ioi/agent-sdk<br>npm run build --workspace=@ioi/agent-ide<br>cargo fmt -p ioi-cli<br>cargo check -p ioi-cli<br>cargo test -p ioi-cli --bin cli parses_nested_tool_and_policy_commands -- --nocapture<br>cargo test -p ioi-cli --bin cli parses_line_mode_slash_commands -- --nocapture<br>node --import tsx --test --test-name-pattern "projects coding tool" packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts<br>node --test --test-name-pattern "coding tool pack invokes status" scripts/lib/live-runtime-daemon-contract.test.mjs<br>npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-coding-tool-pack-test-run |
| 123 | 2026-05-13 | P0-B. Coding Tool Pack | coding tool-pack artifact spillover and retrieval | /tmp/ioi-autopilot-gui-harness-coding-tool-pack-artifact-retrieval/2026-05-13T03-53-05-208Z/result.json | node --check packages/runtime-daemon/src/coding-tools.mjs && node --check packages/runtime-daemon/src/index.mjs && node --check scripts/lib/live-runtime-daemon-contract.test.mjs<br>npm run build --workspace=@ioi/agent-sdk<br>npm run build --workspace=@ioi/agent-ide<br>cargo fmt -p ioi-cli<br>cargo check -p ioi-cli<br>cargo test -p ioi-cli --bin cli parses_nested_tool_and_policy_commands -- --nocapture<br>cargo test -p ioi-cli --bin cli parses_line_mode_slash_commands -- --nocapture<br>node --import tsx --test --test-name-pattern "projects coding tool" packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts<br>node --test --test-name-pattern "coding tool pack invokes" scripts/lib/live-runtime-daemon-contract.test.mjs<br>node --test --test-name-pattern "agent CLI exposes model" scripts/lib/live-runtime-daemon-contract.test.mjs<br>node --test --test-name-pattern "agent TUI thin shell is daemon-backed" scripts/lib/live-runtime-daemon-contract.test.mjs<br>cargo fmt -p ioi-cli -- --check<br>git diff --check<br>npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-coding-tool-pack-artifact-retrieval |
| 124 | 2026-05-13 | P0-C. Post-edit LSP Diagnostics | coding tool-pack post-edit diagnostics MVP | /tmp/ioi-autopilot-gui-harness-coding-tool-pack-diagnostics/2026-05-13T04-07-29-549Z/result.json | node --check packages/runtime-daemon/src/coding-tools.mjs<br>node --check packages/runtime-daemon/src/index.mjs<br>node --check scripts/lib/live-runtime-daemon-contract.test.mjs<br>npm run build --workspace=@ioi/agent-sdk<br>npm run build --workspace=@ioi/agent-ide<br>cargo fmt -p ioi-cli<br>cargo check -p ioi-cli<br>cargo test -p ioi-cli --bin cli parses_nested_tool_and_policy_commands -- --nocapture<br>cargo test -p ioi-cli --bin cli parses_line_mode_slash_commands -- --nocapture<br>node --import tsx --test --test-name-pattern "projects coding tool" packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts<br>node --test --test-name-pattern "coding tool pack invokes" scripts/lib/live-runtime-daemon-contract.test.mjs<br>node --test --test-name-pattern "agent CLI exposes model" scripts/lib/live-runtime-daemon-contract.test.mjs<br>node --test --test-name-pattern "agent TUI thin shell is daemon-backed" scripts/lib/live-runtime-daemon-contract.test.mjs<br>cargo fmt -p ioi-cli -- --check<br>git diff --check<br>npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-coding-tool-pack-diagnostics |
| 125 | 2026-05-13 | P0-C. Post-edit LSP Diagnostics | automatic post-edit diagnostics injection loop | /tmp/ioi-autopilot-gui-harness-post-edit-diagnostics-injection/2026-05-13T04-32-30-977Z/result.json | node --check packages/runtime-daemon/src/index.mjs && node --check scripts/lib/live-runtime-daemon-contract.test.mjs<br>node --check packages/runtime-daemon/src/coding-tools.mjs<br>npm run build --workspace=@ioi/agent-sdk<br>npm run build --workspace=@ioi/agent-ide<br>node --import tsx --test --test-name-pattern "projects coding tool" packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts<br>node --test --test-name-pattern "coding tool pack invokes" scripts/lib/live-runtime-daemon-contract.test.mjs<br>node --test --test-name-pattern "RUNTIME_EVENT_SOURCES&#124;runtime event&#124;TTI" scripts/lib/live-bridge-tti-schema-contract.test.mjs<br>rustfmt --check crates/types/src/app/runtime/thread_turn_item.rs<br>cargo check -p ioi-types<br>npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-post-edit-diagnostics-injection |
| 126 | 2026-05-13 | P0-C. Post-edit LSP Diagnostics | blocking post-edit diagnostics repair gate | /tmp/ioi-autopilot-gui-harness-blocking-diagnostics-gate/2026-05-13T04-49-47-650Z/result.json | node --check packages/runtime-daemon/src/index.mjs && node --check scripts/lib/live-runtime-daemon-contract.test.mjs && node --check packages/runtime-daemon/src/coding-tools.mjs<br>npm run build --workspace=@ioi/agent-sdk<br>npm run build --workspace=@ioi/agent-ide<br>node --import tsx --test --test-name-pattern "projects coding tool&#124;approval and policy&#124;diagnostics blocking gates" packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts<br>node --test --test-name-pattern "coding tool pack invokes" scripts/lib/live-runtime-daemon-contract.test.mjs<br>node --test --test-name-pattern "RUNTIME_EVENT_SOURCES&#124;runtime event&#124;TTI" scripts/lib/live-bridge-tti-schema-contract.test.mjs<br>npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-blocking-diagnostics-gate |
| 127 | 2026-05-13 | P0-C. Post-edit LSP Diagnostics | project-aware diagnostics backend ladder | /tmp/ioi-autopilot-gui-harness-project-aware-diagnostics/2026-05-13T05-02-46-174Z/result.json | node --check packages/runtime-daemon/src/coding-tools.mjs<br>node --check packages/runtime-daemon/src/index.mjs<br>node --check scripts/lib/live-runtime-daemon-contract.test.mjs<br>node --test --test-name-pattern "coding tool pack invokes" scripts/lib/live-runtime-daemon-contract.test.mjs<br>node --import tsx --test --test-name-pattern "projects coding tool&#124;diagnostics blocking gates" packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts<br>node --test --test-name-pattern "agent CLI exposes model&#124;agent TUI thin shell is daemon-backed" scripts/lib/live-runtime-daemon-contract.test.mjs<br>node --test --test-name-pattern "RUNTIME_EVENT_SOURCES&#124;runtime event&#124;TTI" scripts/lib/live-bridge-tti-schema-contract.test.mjs<br>npm run build --workspace=@ioi/agent-sdk<br>npm run build --workspace=@ioi/agent-ide<br>cargo fmt -p ioi-cli -- --check<br>cargo check -p ioi-cli --bin cli<br>cargo test -p ioi-cli --bin cli parses_nested_tool_and_policy_commands -- --nocapture<br>cargo test -p ioi-cli --bin cli parses_line_mode_slash_commands -- --nocapture<br>git diff --check<br>npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-project-aware-diagnostics |
| 128 | 2026-05-13 | P0-D. Workspace Rollback Snapshots | workspace snapshot records for mutating coding tools | /tmp/ioi-autopilot-gui-harness-workspace-snapshots/2026-05-13T05-16-45-830Z/result.json | node --check packages/runtime-daemon/src/coding-tools.mjs<br>node --check packages/runtime-daemon/src/index.mjs<br>node --check scripts/lib/live-runtime-daemon-contract.test.mjs<br>node --import tsx --test --test-name-pattern "projects coding tool" packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts<br>node --import tsx --test --test-name-pattern "projects coding tool&#124;diagnostics blocking gates" packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts<br>node --test --test-name-pattern "coding tool pack invokes" scripts/lib/live-runtime-daemon-contract.test.mjs<br>npm run build --workspace=@ioi/agent-sdk<br>npm run build --workspace=@ioi/agent-ide<br>node --test --test-name-pattern "agent CLI exposes model&#124;agent TUI thin shell is daemon-backed" scripts/lib/live-runtime-daemon-contract.test.mjs<br>node --test --test-name-pattern "RUNTIME_EVENT_SOURCES&#124;runtime event&#124;TTI" scripts/lib/live-bridge-tti-schema-contract.test.mjs<br>git diff --check<br>npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-workspace-snapshots |
| 129 | 2026-05-13 | P0-D. Workspace Rollback Snapshots | content-backed workspace restore preview | /tmp/ioi-autopilot-gui-harness-workspace-restore-preview/2026-05-13T05-42-32-697Z/result.json | node --check packages/runtime-daemon/src/coding-tools.mjs<br>node --check packages/runtime-daemon/src/index.mjs<br>node --check scripts/lib/live-runtime-daemon-contract.test.mjs<br>npm run build --workspace=@ioi/agent-sdk<br>node --test --test-name-pattern "coding tool pack invokes" scripts/lib/live-runtime-daemon-contract.test.mjs<br>node --import tsx --test --test-name-pattern "projects coding tool&#124;diagnostics blocking gates" packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts<br>npm run build --workspace=@ioi/agent-ide<br>node --test --test-name-pattern "agent CLI exposes model&#124;agent TUI thin shell is daemon-backed" scripts/lib/live-runtime-daemon-contract.test.mjs<br>node --test --test-name-pattern "RUNTIME_EVENT_SOURCES&#124;runtime event&#124;TTI" scripts/lib/live-bridge-tti-schema-contract.test.mjs<br>npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-workspace-restore-preview |
| 130 | 2026-05-13 | P0-D. Workspace Rollback Snapshots | policy-gated workspace restore apply | /tmp/ioi-autopilot-gui-harness-workspace-restore-apply/2026-05-13T05-59-11-822Z/result.json | node --check packages/runtime-daemon/src/workspace-restore.mjs<br>node --check packages/runtime-daemon/src/index.mjs<br>node --check scripts/lib/live-runtime-daemon-contract.test.mjs<br>node --import tsx --test --test-name-pattern "projects coding tool&#124;diagnostics blocking gates" packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts<br>npm run build --workspace=@ioi/agent-sdk<br>node --test --test-name-pattern "coding tool pack invokes" scripts/lib/live-runtime-daemon-contract.test.mjs<br>npm run build --workspace=@ioi/agent-ide<br>node --test --test-name-pattern "agent CLI exposes model&#124;agent TUI thin shell is daemon-backed" scripts/lib/live-runtime-daemon-contract.test.mjs<br>node --test --test-name-pattern "RUNTIME_EVENT_SOURCES&#124;runtime event&#124;TTI" scripts/lib/live-bridge-tti-schema-contract.test.mjs<br>git diff --check<br>npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-workspace-restore-apply |
| 131 | 2026-05-13 | P0-C. Post-edit LSP Diagnostics | diagnostics rollback/repair policy | /tmp/ioi-autopilot-gui-harness-diagnostics-rollback-repair-policy/2026-05-13T06-12-33-948Z/result.json | node --check packages/runtime-daemon/src/index.mjs<br>node --check scripts/lib/live-runtime-daemon-contract.test.mjs<br>node --import tsx --test --test-name-pattern "projects coding tool&#124;diagnostics blocking gates" packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts<br>npm run build --workspace=@ioi/agent-sdk<br>node --test --test-name-pattern "coding tool pack invokes" scripts/lib/live-runtime-daemon-contract.test.mjs<br>npm run build --workspace=@ioi/agent-ide<br>node --test --test-name-pattern "agent CLI exposes model&#124;agent TUI thin shell is daemon-backed" scripts/lib/live-runtime-daemon-contract.test.mjs<br>node --test --test-name-pattern "RUNTIME_EVENT_SOURCES&#124;runtime event&#124;TTI" scripts/lib/live-bridge-tti-schema-contract.test.mjs<br>git diff --check<br>npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-diagnostics-rollback-repair-policy |
| 132 | 2026-05-13 | P0-B/P0-C/P0-D. Workflow Restore/Repair Controls | workflow restore and diagnostics repair binding controls | /tmp/ioi-autopilot-gui-harness-workflow-restore-repair-binding-controls/2026-05-13T06-25-02-908Z/result.json | node --check packages/runtime-daemon/src/index.mjs<br>node --check packages/runtime-daemon/src/coding-tools.mjs<br>node --check scripts/lib/live-runtime-daemon-contract.test.mjs<br>node --check scripts/lib/workflow-coding-tool-pack-policy-contract.test.mjs<br>node --test scripts/lib/workflow-coding-tool-pack-policy-contract.test.mjs<br>node --test --test-name-pattern "coding tool pack invokes" scripts/lib/live-runtime-daemon-contract.test.mjs<br>npm run build --workspace=@ioi/agent-ide<br>node --test --test-name-pattern "RUNTIME_EVENT_SOURCES&#124;runtime event&#124;TTI" scripts/lib/live-bridge-tti-schema-contract.test.mjs<br>git diff --check<br>npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-workflow-restore-repair-binding-controls |
| 133 | 2026-05-13 | P0-D. Workspace Rollback Snapshots | restore workflow nodes and request builders | /tmp/ioi-autopilot-gui-harness-restore-workflow-nodes/2026-05-13T06-48-16-424Z/result.json | node --import tsx --test packages/agent-ide/src/runtime/workflow-runtime-control-nodes.test.ts<br>npm run build --workspace=@ioi/agent-ide<br>cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml runtime_projection --lib<br>cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml runtime_thread_fork_node_builds_react_flow_control_request --lib<br>cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scaffolds_include_action_metadata --lib<br>node --test scripts/lib/workflow-runtime-event-projection-contract.test.mjs<br>node --test --test-name-pattern "React Flow memory, authority/tooling" scripts/lib/live-runtime-daemon-contract.test.mjs<br>git diff --check<br>npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-restore-workflow-nodes |
| 134 | 2026-05-13 | P0-D. Workspace Rollback Snapshots | keyboard-first TUI restore UX | /tmp/ioi-autopilot-gui-harness-tui-restore-ux/2026-05-13T07-12-46-679Z/result.json | cargo fmt -p ioi-cli<br>cargo test -p ioi-cli --bin cli parses_line_mode_slash_commands -- --nocapture<br>cargo test -p ioi-cli --bin cli rejects_unknown_or_incomplete_line_mode_commands -- --nocapture<br>cargo test -p ioi-cli --bin cli tui_event_route_uses_canonical_thread_stream_cursor -- --nocapture<br>cargo check -p ioi-cli --bin cli<br>node --test --test-name-pattern "agent TUI thin shell is daemon-backed" scripts/lib/live-runtime-daemon-contract.test.mjs<br>node --test --test-name-pattern "coding tool pack invokes" scripts/lib/live-runtime-daemon-contract.test.mjs<br>git diff --check<br>npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-tui-restore-ux |
| 135 | 2026-05-13 | P0-C. Post-edit LSP Diagnostics | executable diagnostics repair restore-preview | /tmp/ioi-autopilot-gui-harness-diagnostics-repair-restore-preview/2026-05-13T07-37-14-986Z/result.json | node --check packages/runtime-daemon/src/index.mjs<br>node --check scripts/lib/live-runtime-daemon-contract.test.mjs<br>node --check scripts/lib/workflow-coding-tool-pack-policy-contract.test.mjs<br>node --test scripts/lib/workflow-coding-tool-pack-policy-contract.test.mjs<br>node --import tsx --test --test-name-pattern "diagnostics repair decisions&#124;diagnostics blocking gates" packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts<br>npm run build --workspace=@ioi/agent-sdk<br>npm run build --workspace=@ioi/agent-ide<br>node --test --test-name-pattern "coding tool pack invokes" scripts/lib/live-runtime-daemon-contract.test.mjs<br>git diff --check<br>npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-diagnostics-repair-restore-preview |
| 136 | 2026-05-13 | P0-C. Post-edit LSP Diagnostics | executable diagnostics repair restore-apply | /tmp/ioi-autopilot-gui-harness-diagnostics-repair-restore-apply/2026-05-13T07-56-56-734Z/result.json | node --check packages/runtime-daemon/src/index.mjs<br>node --check scripts/lib/live-runtime-daemon-contract.test.mjs<br>node --check scripts/lib/workflow-coding-tool-pack-policy-contract.test.mjs<br>node --test scripts/lib/workflow-coding-tool-pack-policy-contract.test.mjs<br>node --import tsx --test --test-name-pattern "diagnostics repair decisions&#124;diagnostics blocking gates" packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts<br>npm run build --workspace=@ioi/agent-sdk<br>npm run build --workspace=@ioi/agent-ide<br>node --test --test-name-pattern "coding tool pack invokes" scripts/lib/live-runtime-daemon-contract.test.mjs<br>git diff --check<br>npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-diagnostics-repair-restore-apply |
| 137 | 2026-05-13 | P0-C. Post-edit LSP Diagnostics | executable diagnostics repair retry | /tmp/ioi-autopilot-gui-harness-diagnostics-repair-retry/2026-05-13T08-20-57-956Z/result.json | node --check packages/runtime-daemon/src/index.mjs<br>node --check scripts/lib/live-runtime-daemon-contract.test.mjs<br>node --check scripts/lib/workflow-coding-tool-pack-policy-contract.test.mjs<br>node --test scripts/lib/workflow-coding-tool-pack-policy-contract.test.mjs<br>node --import tsx --test --test-name-pattern "diagnostics repair decisions&#124;diagnostics repair retry&#124;diagnostics blocking gates" packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts<br>npm run build --workspace=@ioi/agent-sdk<br>npm run build --workspace=@ioi/agent-ide<br>node --test --test-name-pattern "coding tool pack invokes" scripts/lib/live-runtime-daemon-contract.test.mjs<br>git diff --check<br>npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-diagnostics-repair-retry |
| 138 | 2026-05-13 | P0-C. Post-edit LSP Diagnostics | executable diagnostics operator override | /tmp/ioi-autopilot-gui-harness-diagnostics-operator-override/2026-05-13T08-53-15-768Z/result.json | node --check packages/runtime-daemon/src/index.mjs<br>node --check scripts/lib/live-runtime-daemon-contract.test.mjs<br>node --check scripts/lib/workflow-coding-tool-pack-policy-contract.test.mjs<br>node --test scripts/lib/workflow-coding-tool-pack-policy-contract.test.mjs<br>node --import tsx --test --test-name-pattern "diagnostics repair decisions&#124;diagnostics repair retry&#124;diagnostics operator overrides&#124;diagnostics blocking gates" packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts<br>npm run build --workspace=@ioi/agent-sdk<br>npm run build --workspace=@ioi/agent-ide<br>node --test --test-name-pattern "coding tool pack invokes" scripts/lib/live-runtime-daemon-contract.test.mjs<br>npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-diagnostics-operator-override |
| 139 | 2026-05-13 | P0. Terminal Coding-Agent TUI | TUI jobs and run lifecycle parity view | /tmp/ioi-autopilot-gui-harness-tui-jobs-run-lifecycle/2026-05-13T11-39-18-945Z/result.json | cargo test -p ioi-cli --bin cli tui --quiet<br>npm run build --workspace=@ioi/agent-sdk<br>npm run build --workspace=@ioi/agent-ide<br>node --test --test-name-pattern "local daemon public API&#124;agent TUI thin shell&#124;agent TUI line-mode slash" scripts/lib/live-runtime-daemon-contract.test.mjs |
| 140 | 2026-05-13 | P1. MCP Manager Parity | daemon-owned MCP discovery/status/validation | scripts/lib/live-runtime-daemon-contract.test.mjs | node --check packages/runtime-daemon/src/index.mjs<br>node --check packages/runtime-daemon/src/mcp-manager.mjs<br>cargo test -p ioi-cli --bin cli tui --quiet<br>npm run build --workspace=@ioi/agent-sdk<br>npm run build --workspace=@ioi/agent-ide<br>node --test --test-name-pattern "daemon owns MCP&#124;agent TUI line-mode slash commands&#124;agent CLI exposes model&#124;agent TUI thin shell" scripts/lib/live-runtime-daemon-contract.test.mjs |
| 141 | 2026-05-13 | P1. Memory UX Parity | daemon-owned memory manager status/validation | scripts/lib/live-runtime-daemon-contract.test.mjs | node --check packages/runtime-daemon/src/index.mjs<br>node --check packages/runtime-daemon/src/memory-manager.mjs<br>cargo fmt -p ioi-cli -- --check<br>cargo test -p ioi-cli --bin cli tui --quiet<br>npm run build --workspace=@ioi/agent-sdk<br>npm run build --workspace=@ioi/agent-ide<br>node --test --test-name-pattern "memory writes&#124;agent CLI exposes model&#124;agent TUI thin shell&#124;agent TUI line-mode" scripts/lib/live-runtime-daemon-contract.test.mjs |
| 142 | 2026-05-13 | P1. MCP Manager Parity | MCP enable/disable/invocation controls | /tmp/ioi-autopilot-gui-harness-mcp-controls/2026-05-13T13-37-14-190Z/result.json | node --check packages/runtime-daemon/src/index.mjs<br>node --check packages/runtime-daemon/src/mcp-manager.mjs<br>node --check scripts/lib/live-runtime-daemon-contract.test.mjs<br>cargo fmt -p ioi-cli -- --check<br>cargo test -p ioi-cli --bin cli tui --quiet<br>npm run build --workspace=@ioi/agent-sdk<br>npm run build --workspace=@ioi/agent-ide<br>node --import tsx --test packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts<br>node --test --test-name-pattern "daemon owns MCP discovery&#124;agent CLI exposes model&#124;agent TUI thin shell&#124;agent TUI line-mode&#124;React Flow memory" scripts/lib/live-runtime-daemon-contract.test.mjs<br>node scripts/run-autopilot-gui-harness-validation.mjs --preflight --output-root /tmp/ioi-autopilot-gui-harness-mcp-controls |
| 143 | 2026-05-13 | P1. Memory UX Parity | memory write-side TUI/workflow controls | /tmp/ioi-autopilot-gui-harness-memory-write-controls/2026-05-13T14-00-24-781Z/result.json | node --check packages/runtime-daemon/src/index.mjs<br>node --check packages/runtime-daemon/src/memory-manager.mjs<br>node --check scripts/lib/live-runtime-daemon-contract.test.mjs<br>cargo fmt -p ioi-cli -- --check<br>cargo test -p ioi-cli --bin cli tui --quiet<br>cargo check -p autopilot<br>npm run build --workspace=@ioi/agent-sdk<br>npm run build --workspace=@ioi/agent-ide<br>node --import tsx --test packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts<br>node --test --test-name-pattern "local daemon records explicit memory writes&#124;agent CLI exposes model&#124;agent TUI line-mode&#124;React Flow memory" scripts/lib/live-runtime-daemon-contract.test.mjs<br>node scripts/run-autopilot-gui-harness-validation.mjs --preflight --output-root /tmp/ioi-autopilot-gui-harness-memory-write-controls |
| 144 | 2026-05-13 | P1. MCP Manager Parity | live MCP stdio transport invocation | /tmp/ioi-autopilot-gui-harness-mcp-live-stdio/2026-05-13T14-11-08-493Z/result.json | node --check packages/runtime-daemon/src/index.mjs<br>node --check packages/runtime-daemon/src/mcp-manager.mjs<br>node --check scripts/fixtures/mcp-stdio-echo-server.mjs<br>node --check scripts/lib/live-runtime-daemon-contract.test.mjs<br>cargo test -p ioi-cli --bin cli tui --quiet<br>npm run build --workspace=@ioi/agent-sdk<br>node --test --test-name-pattern "daemon owns MCP discovery&#124;agent CLI exposes model&#124;agent TUI line-mode&#124;React Flow memory" scripts/lib/live-runtime-daemon-contract.test.mjs<br>node scripts/run-autopilot-gui-harness-validation.mjs --preflight --output-root /tmp/ioi-autopilot-gui-harness-mcp-live-stdio<br>git diff --check |
| 145 | 2026-05-13 | P1. MCP Manager Parity | MCP resources/prompts discovery | /tmp/ioi-autopilot-gui-harness-mcp-resources-prompts/2026-05-13T14-30-00-293Z/result.json | node --check packages/runtime-daemon/src/mcp-manager.mjs<br>node --check packages/runtime-daemon/src/index.mjs<br>node --check scripts/fixtures/mcp-stdio-echo-server.mjs<br>node --check scripts/lib/live-runtime-daemon-contract.test.mjs<br>node --import tsx --test packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts<br>npm run build --workspace=@ioi/agent-sdk<br>npm run build --workspace=@ioi/agent-ide<br>cargo fmt -p ioi-cli -- --check<br>cargo test -p ioi-cli --bin cli tui --quiet<br>node --test --test-name-pattern "daemon owns MCP discovery&#124;agent CLI exposes model&#124;agent TUI line-mode&#124;React Flow memory" scripts/lib/live-runtime-daemon-contract.test.mjs<br>node scripts/run-autopilot-gui-harness-validation.mjs --preflight --output-root /tmp/ioi-autopilot-gui-harness-mcp-resources-prompts |
| 146 | 2026-05-13 | P1. MCP Manager Parity | MCP import/add/remove registry writes | /tmp/ioi-autopilot-gui-harness-mcp-config-writes/2026-05-13T14-48-32-036Z/result.json | node --check packages/runtime-daemon/src/index.mjs<br>node --check scripts/lib/live-runtime-daemon-contract.test.mjs<br>npm run build --workspace=@ioi/agent-sdk<br>cargo fmt -p ioi-cli -- --check<br>cargo test -p ioi-cli --bin cli tui --quiet<br>npm run build --workspace=@ioi/agent-ide<br>node --import tsx --test packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts<br>node --test --test-name-pattern "daemon owns MCP discovery&#124;agent CLI exposes model&#124;agent TUI line-mode&#124;React Flow memory" scripts/lib/live-runtime-daemon-contract.test.mjs<br>node scripts/run-autopilot-gui-harness-validation.mjs --preflight --output-root /tmp/ioi-autopilot-gui-harness-mcp-config-writes |
| 147 | 2026-05-13 | P1. MCP Manager Parity | live MCP HTTP/SSE transport | /tmp/ioi-autopilot-gui-harness-mcp-http-sse/2026-05-13T15-06-56-740Z/result.json | node --check packages/runtime-daemon/src/mcp-manager.mjs<br>node --check packages/runtime-daemon/src/index.mjs<br>node --check scripts/lib/live-runtime-daemon-contract.test.mjs<br>npm run build --workspace=@ioi/agent-sdk<br>npm run build --workspace=@ioi/agent-ide<br>node --import tsx --test packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts<br>node --test --test-name-pattern "daemon owns MCP discovery&#124;agent CLI exposes model&#124;agent TUI line-mode&#124;React Flow memory" scripts/lib/live-runtime-daemon-contract.test.mjs<br>cargo fmt -p ioi-cli -- --check<br>cargo test -p ioi-cli --bin cli tui --quiet<br>node scripts/run-autopilot-gui-harness-validation.mjs --preflight --output-root /tmp/ioi-autopilot-gui-harness-mcp-http-sse |
| 148 | 2026-05-13 | P1. MCP Manager Parity | self-hosted MCP serve mode | /tmp/ioi-autopilot-gui-harness-mcp-serve/2026-05-13T15-29-48-332Z/result.json | node --check packages/runtime-daemon/src/index.mjs<br>node --check packages/runtime-daemon/src/mcp-manager.mjs<br>node --check scripts/lib/live-runtime-daemon-contract.test.mjs<br>npm run build --workspace=@ioi/agent-sdk<br>npm run build --workspace=@ioi/agent-ide<br>node --import tsx --test packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts<br>node --test --test-name-pattern "daemon owns MCP discovery&#124;agent CLI exposes model&#124;agent TUI line-mode&#124;React Flow memory" scripts/lib/live-runtime-daemon-contract.test.mjs<br>cargo fmt -p ioi-cli -- --check<br>cargo test -p ioi-cli --bin cli tui --quiet<br>git diff --check<br>node scripts/run-autopilot-gui-harness-validation.mjs --preflight --output-root /tmp/ioi-autopilot-gui-harness-mcp-serve |
| 149 | 2026-05-13 | P1. MCP Manager Parity | remote MCP auth/vault header hardening | /tmp/ioi-autopilot-gui-harness-mcp-auth-vault/2026-05-13T15-45-08-787Z/result.json | node --check packages/runtime-daemon/src/mcp-manager.mjs<br>node --check packages/runtime-daemon/src/index.mjs<br>node --check scripts/lib/live-runtime-daemon-contract.test.mjs<br>npm run build --workspace=@ioi/agent-sdk<br>npm run build --workspace=@ioi/agent-ide<br>node --import tsx --test packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts<br>node --test --test-name-pattern "daemon owns MCP discovery&#124;agent CLI exposes model&#124;agent TUI line-mode&#124;React Flow memory" scripts/lib/live-runtime-daemon-contract.test.mjs<br>cargo fmt -p ioi-cli -- --check<br>cargo test -p ioi-cli --bin cli tui --quiet<br>node scripts/run-autopilot-gui-harness-validation.mjs --preflight --output-root /tmp/ioi-autopilot-gui-harness-mcp-auth-vault |
| 150 | 2026-05-13 | P1. MCP Manager Parity | large MCP catalog deferred search/fetch | /tmp/ioi-autopilot-gui-harness-mcp-large-catalog-search/2026-05-13T16-02-41-899Z/result.json | node --check packages/runtime-daemon/src/index.mjs<br>node --check scripts/lib/live-runtime-daemon-contract.test.mjs<br>npm run build --workspace=@ioi/agent-sdk<br>npm run build --workspace=@ioi/agent-ide<br>node --import tsx --test packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts<br>node --test --test-name-pattern "daemon owns MCP discovery&#124;agent CLI exposes model&#124;agent TUI line-mode&#124;React Flow memory" scripts/lib/live-runtime-daemon-contract.test.mjs<br>cargo fmt -p ioi-cli -- --check<br>cargo test -p ioi-cli --bin cli tui --quiet<br>git diff --check<br>node scripts/run-autopilot-gui-harness-validation.mjs --preflight --output-root /tmp/ioi-autopilot-gui-harness-mcp-large-catalog-search |
| 151 | 2026-05-13 | P1. MCP Manager Parity | global IOI MCP config discovery | /tmp/ioi-autopilot-gui-harness-mcp-global-config/2026-05-13T16-20-04-651Z/result.json | node --check packages/runtime-daemon/src/mcp-manager.mjs<br>node --check packages/runtime-daemon/src/index.mjs<br>node --check scripts/lib/live-runtime-daemon-contract.test.mjs<br>npm run build --workspace=@ioi/agent-sdk<br>npm run build --workspace=@ioi/agent-ide<br>node --import tsx --test packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts<br>node --test --test-name-pattern "daemon owns MCP discovery" scripts/lib/live-runtime-daemon-contract.test.mjs<br>node --test --test-name-pattern "agent CLI exposes model&#124;React Flow memory" scripts/lib/live-runtime-daemon-contract.test.mjs<br>cargo fmt -p ioi-cli -- --check<br>cargo test -p ioi-cli --bin cli tui --quiet<br>node scripts/run-autopilot-gui-harness-validation.mjs --preflight --output-root /tmp/ioi-autopilot-gui-harness-mcp-global-config<br>git diff --check |
| 152 | 2026-05-13 | P0. Terminal Coding-Agent TUI / P1. MCP Manager Parity | TUI MCP search/fetch source-mode UX | /tmp/ioi-autopilot-gui-harness-mcp-tui-search-fetch/2026-05-13T16-35-16-836Z/result.json | node --check packages/runtime-daemon/src/index.mjs<br>node --check scripts/lib/live-runtime-daemon-contract.test.mjs<br>cargo fmt -p ioi-cli<br>cargo fmt -p ioi-cli -- --check<br>cargo test -p ioi-cli --bin cli tui --quiet<br>node --test --test-name-pattern "agent TUI line-mode slash commands" scripts/lib/live-runtime-daemon-contract.test.mjs<br>node --test --test-name-pattern "agent CLI exposes model" scripts/lib/live-runtime-daemon-contract.test.mjs<br>node scripts/run-autopilot-gui-harness-validation.mjs --preflight --output-root /tmp/ioi-autopilot-gui-harness-mcp-tui-search-fetch<br>git diff --check |
| 153 | 2026-05-13 | P0. Terminal Coding-Agent TUI / P0-C. Post-edit LSP Diagnostics | TUI diagnostics repair decision controls | /tmp/ioi-autopilot-gui-harness-diagnostics-repair-tui/2026-05-13T16-45-07-095Z/result.json | node --check packages/runtime-daemon/src/index.mjs<br>node --check scripts/lib/live-runtime-daemon-contract.test.mjs<br>cargo fmt -p ioi-cli<br>cargo fmt -p ioi-cli -- --check<br>cargo test -p ioi-cli --bin cli tui --quiet<br>node --test --test-name-pattern "agent CLI exposes model" scripts/lib/live-runtime-daemon-contract.test.mjs<br>node --test --test-name-pattern "agent TUI thin shell is daemon-backed" scripts/lib/live-runtime-daemon-contract.test.mjs<br>node --test --test-name-pattern "agent TUI line-mode slash commands" scripts/lib/live-runtime-daemon-contract.test.mjs<br>node --test --test-name-pattern "coding tool pack invokes status" scripts/lib/live-runtime-daemon-contract.test.mjs<br>node scripts/run-autopilot-gui-harness-validation.mjs --preflight --output-root /tmp/ioi-autopilot-gui-harness-diagnostics-repair-tui<br>git diff --check |
| 154 | 2026-05-13 | P0. Terminal Coding-Agent TUI / P0-C. Post-edit LSP Diagnostics | React Flow diagnostics repair action node | /tmp/ioi-autopilot-gui-harness-diagnostics-repair-react-flow/2026-05-13T16-59-53-289Z/result.json | rustfmt --check apps/autopilot/src-tauri/src/runtime_projection.rs apps/autopilot/src-tauri/src/project/workflow_node_execution_lane.rs apps/autopilot/src-tauri/src/generated/runtime_action_schema.rs<br>cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml substrate_classifies_workflow_node_kinds -- --nocapture<br>node --import tsx --test packages/agent-ide/src/runtime/workflow-runtime-control-nodes.test.ts<br>npm run build --workspace=@ioi/agent-ide<br>node --test --test-name-pattern "React Flow memory, authority" scripts/lib/live-runtime-daemon-contract.test.mjs<br>node scripts/run-autopilot-gui-harness-validation.mjs --preflight --output-root /tmp/ioi-autopilot-gui-harness-diagnostics-repair-react-flow<br>git diff --check |
| 155 | 2026-05-13 | P0. Terminal Coding-Agent TUI / P0-C. Post-edit LSP Diagnostics | React Flow run-inspector diagnostics repair actions | /tmp/ioi-autopilot-gui-harness-diagnostics-repair-run-inspector/2026-05-13T17-22-14-924Z/result.json | node --import tsx --test --test-name-pattern "diagnostics blocking gates" packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts<br>node --check scripts/lib/live-runtime-daemon-contract.test.mjs<br>npm run build --workspace=@ioi/agent-ide<br>rustfmt --check apps/autopilot/src-tauri/src/kernel/artifacts/mod.rs apps/autopilot/src-tauri/src/lib.rs<br>node --test --test-name-pattern "React Flow memory, authority" scripts/lib/live-runtime-daemon-contract.test.mjs<br>cargo check --manifest-path apps/autopilot/src-tauri/Cargo.toml<br>npm run build --workspace=autopilot<br>node scripts/run-autopilot-gui-harness-validation.mjs --preflight --output-root /tmp/ioi-autopilot-gui-harness-diagnostics-repair-run-inspector<br>git diff --check |
| 156 | 2026-05-13 | P0. Terminal Coding-Agent TUI / P0-C. Post-edit LSP Diagnostics | run-inspector diagnostics repair full recovery loop | /tmp/ioi-autopilot-gui-harness-diagnostics-repair-full-loop/2026-05-13T17-40-50-387Z/result.json | node --check scripts/lib/live-runtime-daemon-contract.test.mjs<br>npm run build --workspace=@ioi/agent-ide<br>node --test --test-name-pattern "run-inspector diagnostics repair action" scripts/lib/live-runtime-daemon-contract.test.mjs<br>node --test --test-name-pattern "coding tool pack invokes" scripts/lib/live-runtime-daemon-contract.test.mjs<br>node --import tsx --test --test-name-pattern "diagnostics blocking gates" packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts<br>node --test --test-name-pattern "React Flow memory, authority" scripts/lib/live-runtime-daemon-contract.test.mjs<br>node scripts/run-autopilot-gui-harness-validation.mjs --preflight --output-root /tmp/ioi-autopilot-gui-harness-diagnostics-repair-full-loop |

## Slice 1. 2026-05-11 - P1. Model Auto-Routing And Reasoning Effort

Guide section: P1. Model Auto-Routing And Reasoning Effort

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-11T00-45-58-933Z/result.json

Validation evidence:

- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test packages/agent-sdk/test/sdk.test.mjs`
- `node --test scripts/lib/model-mounting-daemon-contract.test.mjs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T00-45-58-933Z/result.json`

## Slice 2. 2026-05-11 - P1. Memory UX

Guide section: P1. Memory UX

Evidence bundles:

- n/a

No standalone validation evidence block was present in the source slice.

## Slice 3. 2026-05-11 - memory policy controls

Guide section: P1. Memory UX

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-11T02-51-13-357Z/result.json

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `node --check packages/runtime-daemon/src/memory-store.mjs`
- `npm run build:agent-sdk`
- `npm run build:ide`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test packages/agent-sdk/test/sdk.test.mjs`
- `node --test scripts/lib/model-mounting-daemon-contract.test.mjs`
- `cargo test -p ioi-cli --bin cli parses_agent_operator_surface_commands`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T02-51-13-357Z/result.json`

## Slice 4. 2026-05-11 - workflow memory execution wiring

Guide section: P1. Memory UX

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-11T03-17-06-563Z/result.json

Validation evidence:

- `node --check packages/runtime-daemon/src/model-mounting.mjs`
- `node --check packages/runtime-daemon/src/model-mounting/workflow-memory.mjs`
- `node --check packages/runtime-daemon/src/model-mounting/workflow-node.mjs`
- `npm run build:agent-sdk`
- `npm run build:ide`
- `cargo test -p autopilot workflow_model_tool_memory_parser_loop_records_lineage`
- `node --test scripts/lib/model-mounting-daemon-contract.test.mjs`
- `git diff --check`

- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T03-17-06-563Z/result.json`

## Slice 5. 2026-05-11 - workflow memory search/list

Guide section: P1. Memory UX

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-11T03-50-03-897Z/result.json

Validation evidence:

- `node --check packages/runtime-daemon/src/memory-store.mjs`
- `node --check packages/runtime-daemon/src/index.mjs`
- `npm run build:agent-sdk`
- `npm run build:ide`
- `cargo test -p autopilot workflow_model_tool_memory_parser_loop_records_lineage`
- `node --test packages/agent-sdk/test/sdk.test.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `git diff --check`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T03-50-03-897Z/result.json`

## Slice 6. 2026-05-11 - subagent memory inheritance execution

Guide section: P1. Memory UX

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-11T04-25-14-983Z/result.json

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `npm run build:agent-sdk`
- `npm run build:ide`
- `node --test packages/agent-sdk/test/sdk.test.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `cargo test -p autopilot workflow_model_tool_memory_parser_loop_records_lineage`
- `git diff --check`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T04-25-14-983Z/result.json`

## Slice 7. 2026-05-11 - runtime doctor preflight

Guide section: P1. Doctor, Config, And Introspection

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-11T04-42-38-804Z/result.json

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `npm run build:ide`
- `cargo test -p ioi-cli --bin cli parses_agent_operator_surface_commands`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T04-42-38-804Z/result.json`

## Slice 8. 2026-05-11 - read-only skill and hook discovery

Guide section: P1. Skills And Hooks

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-11T04-51-31-990Z/result.json

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `npm run build:ide`
- `cargo test -p ioi-cli --bin cli parses_agent_operator_surface_commands`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T04-51-31-990Z/result.json`

## Slice 9. 2026-05-11 - active skill/hook manifest per turn

Guide section: P1. Skills And Hooks

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-11T04-58-22-773Z/result.json

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `npm run build:ide`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T04-58-22-773Z/result.json`

## Slice 10. 2026-05-11 - hook dry-run policy preview

Guide section: P1. Skills And Hooks

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-11T05-07-33-015Z/result.json

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `npm run build:ide`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T05-07-33-015Z/result.json`

## Slice 11. 2026-05-11 - HookPolicyNode activation gate

Guide section: P1. Skills And Hooks

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-11T05-14-01-420Z/result.json

Validation evidence:

- `npm run build:ide`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T05-14-01-420Z/result.json`

## Slice 12. 2026-05-11 - hook invocation ledger

Guide section: P1. Skills And Hooks

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-11T05-19-58-078Z/result.json

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `npm run build:ide`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T05-19-58-078Z/result.json`

## Slice 13. 2026-05-11 - hook escalation receipts

Guide section: P1. Skills And Hooks

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-11T05-25-17-876Z/result.json

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run build:ide`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T05-25-17-876Z/result.json`

## Slice 14. 2026-05-11 - repository context foundation

Guide section: P2. GitHub And PR Workflow Parity Plus

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-11T05-36-44-368Z/result.json

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run build:ide`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T05-36-44-368Z/result.json`

## Slice 15. 2026-05-11 - branch policy gate

Guide section: P2. GitHub And PR Workflow Parity Plus

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-11T11-16-23-615Z/result.json

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run build:ide`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T11-16-23-615Z/result.json`

## Slice 16. 2026-05-11 - GitHub context projection

Guide section: P2. GitHub And PR Workflow Parity Plus

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-11T11-38-48-741Z/result.json

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run build:ide`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T11-38-48-741Z/result.json`

## Slice 17. 2026-05-11 - PR attempt preview ledger

Guide section: P2. GitHub And PR Workflow Parity Plus

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-11T11-51-00-206Z/result.json

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run build:ide`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T11-51-00-206Z/result.json`

## Slice 18. 2026-05-11 - review gate decision

Guide section: P2. GitHub And PR Workflow Parity Plus

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-11T12-15-17-099Z/result.json

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run build:ide`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T12-15-17-099Z/result.json`

## Slice 19. 2026-05-11 - issue context projection

Guide section: P2. GitHub And PR Workflow Parity Plus

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-11T12-25-31-750Z/result.json

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run build:ide`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T12-25-31-750Z/result.json`

## Slice 20. 2026-05-11 - GitHub PR create dry-run plan

Guide section: P2. GitHub And PR Workflow Parity Plus

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-11T12-38-30-155Z/result.json

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run build:ide`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T12-38-30-155Z/result.json`

## Slice 21. 2026-05-11 - runtime task/job ledger spine

Guide section: P2. Runtime Task Queue And Jobs

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-11T12-52-37-360Z/result.json

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run build:ide`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T12-52-37-360Z/result.json`

## Slice 22. 2026-05-11 - job cancellation endpoint

Guide section: P2. Runtime Task Queue And Jobs

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-11T13-05-03-333Z/result.json

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run build:ide`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T13-05-03-333Z/result.json`

## Slice 23. 2026-05-11 - runtime checklist record

Guide section: P2. Runtime Task Queue And Jobs

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-11T13-35-25-228Z/result.json

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run build:ide -- --pretty false`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T13-35-25-228Z/result.json`

## Slice 24. 2026-05-11 - runtime chrome localization and accessible status metadata

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-11T14-03-04-311Z/result.json

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run build:ide -- --pretty false`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T14-03-04-311Z/result.json`

## Slice 25. 2026-05-11 - workflow UI localization and accessible status surfaces

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-11T14-14-20-396Z/result.json

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `npm run build:ide -- --pretty false`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T14-14-20-396Z/result.json`

## Slice 26. 2026-05-11 - keyboard and focus parity

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-11T14-28-34-383Z/result.json

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `npm run build:ide -- --pretty false`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T14-28-34-383Z/result.json`

## Slice 27. 2026-05-11 - global workflow chrome locale

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-11T14-34-43-218Z/result.json

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `npm run build:ide -- --pretty false`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T14-34-43-218Z/result.json`

## Slice 28. 2026-05-11 - locale-aware portable package evidence

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-11T14-47-49-991Z/result.json

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `npm run build:ide -- --pretty false`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_portable_package_exports_and_imports_bundle_sidecars -- --nocapture`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T14-47-49-991Z/result.json`

## Slice 29. 2026-05-11 - workflow-native package/import actions

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-11T15-01-34-285Z/result.json

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `node scripts/generate-runtime-action-contracts.mjs --check`
- `npm run build:ide -- --pretty false`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_portable_package_exports_and_imports_bundle_sidecars -- --nocapture`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `git diff --check`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T15-01-34-285Z/result.json`

## Slice 30. 2026-05-11 - package action runtime execution

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-11T15-24-53-304Z/result.json

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `node scripts/generate-runtime-action-contracts.mjs --check`
- `npm run build:ide -- --pretty false`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_package_export_and_import_nodes_execute_through_runtime -- --nocapture`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_portable_package_exports_and_imports_bundle_sidecars -- --nocapture`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml substrate_classifies_workflow_node_kinds -- --nocapture`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `git diff --check`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T15-24-53-304Z/result.json`

## Slice 31. 2026-05-11 - package action run output surfaces

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-11T15-33-50-765Z/result.json

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node scripts/generate-runtime-action-contracts.mjs --check`
- `npm run build:ide -- --pretty false`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_package_export_and_import_nodes_execute_through_runtime -- --nocapture`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `git diff --check`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T15-33-50-765Z/result.json`
  - all retained chat scenarios passed;
  - per-slice package-output proof passed:
    `rollback-restore-canary-ui-proof.json` has
    `checks.workflowPackageRunOutputSurfaces === true`;
  - full harness validation remains red on unrelated promotion-live/default
    dispatch bindings:
    `harness_promotion_transition_live_gui_interaction`,
    `harness_live_promotion_readiness`, and
    `harness_live_shadow_comparison_gate`.

## Slice 32. 2026-05-11 - live shadow promotion/default dispatch binding

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-11T15-57-19-939Z/result.json

Validation evidence:

- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `npm run build:ide -- --pretty false`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- focused default dispatch proof: live mode, 21/21 shadow comparisons,
  `github_pr_create` present, no live promotion blockers.
- `git diff --check`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T15-57-19-939Z/result.json`
  - `validation.ok === true`;
  - no false artifacts;
  - `harness_live_promotion_readiness_present === true`;
  - `harness_live_shadow_comparison_gate_present === true`;
  - proof gate has `comparisonCount === 21`, `requiredComparisonCount === 21`,
    and includes `github_pr_create`.

## Slice 33. 2026-05-11 - direct PR-create live shadow artifact emission

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-11T16-33-52-995Z/result.json

Validation evidence:

- `cargo test -p ioi-types harness -- --nocapture`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml default_runtime_dispatch_accepts_isolated_output_writer_staged_write_canary -- --nocapture`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml save_local_task_state_exports_gui_runtime_evidence_projection -- --nocapture`
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/autopilot-gui-harness-contract.test.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run build:ide -- --pretty false`
- `git diff --check`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T16-33-52-995Z/result.json`
  - `validation.ok === true`;
  - runtime consistency includes
    `harness_authority_tooling_github_pr_create_dry_run_present === true`;
  - `runtime-artifacts.json` has the direct 21/21 component set with
    `github_pr_create`.

## Slice 34. 2026-05-11 - PR-create workflow output surfaces

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-11T16-55-06-446Z/result.json

Validation evidence:

- `npm run build:ide -- --pretty false`
- `node --check scripts/lib/harness-promotion-transition-gui-probe.mjs`
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test scripts/lib/autopilot-gui-harness-contract.test.mjs`
- `TSX_TSCONFIG_PATH=packages/agent-ide/tsconfig.json node --import tsx packages/agent-ide/src/runtime/workflow-rail-receipts.test.ts`
- targeted React render proof:
  `node --import tsx scripts/lib/harness-promotion-transition-gui-probe.mjs /tmp/github-pr-create-workflow-node-probe.json`
- `git diff --check`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T16-55-06-446Z/result.json`
  - `validation.ok === true`;
  - `rollback-restore-canary-ui-proof.json` has
    `checks.workflowGithubPrCreateRunOutputSurfaces === true`;
  - `promotion-transition-gui-behavior-proof.json` has
    `checks.githubPrCreateNodeOutputInspector === true`;
  - `runtime-artifacts.json` retains the direct 21/21 live shadow component set
    with `github_pr_create` and
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

## Slice 35. 2026-05-11 - PR-create React Flow runtime execution

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-11T17-23-26-703Z/result.json

Validation evidence:

- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T17-23-26-703Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` source-contract proof now includes
    `ActionKind::GithubPrCreate`,
    `workflow_github_pr_create_output`, and
    `github_pr_create_dry_run_node_executes_through_runtime`.

## Slice 36. 2026-05-11 - PR-create runtime module refactor

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-11T17-53-05-240Z/result.json

Validation evidence:

- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T17-53-05-240Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has
    `checks.workflowGithubPrCreateRunOutputSurfaces === true`;
  - `runtime-artifacts.json` keeps the 21-kind live shadow component set with
    `github_pr_create` and `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

## Slice 37. 2026-05-11 - workflow value helper extraction

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-11T18-26-54-384Z/result.json

Validation evidence:

- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T18-26-54-384Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has
    `checks.workflowGithubPrCreateRunOutputSurfaces === true`;
  - `runtime-artifacts.json` keeps the 21-kind live shadow component set with
    `github_pr_create` and `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

## Slice 38. 2026-05-11 - workflow package lane refactor

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-11T18-40-25-909Z/result.json

Validation evidence:

- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T18-40-25-909Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has
    `checks.workflowPackageRunOutputSurfaces === true` and
    `checks.workflowGithubPrCreateRunOutputSurfaces === true`;
  - `runtime-artifacts.json` keeps the 21-kind live shadow component set with
    `github_pr_create` and `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

## Slice 39. 2026-05-11 - workflow memory lane refactor

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-11T19-05-24-252Z/result.json

Validation evidence:

- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_memory_lane.rs apps/autopilot/src-tauri/src/project/workflow_value_helpers.rs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T19-05-24-252Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has
    `checks.workflowMemoryRuntimeLane === true`,
    `checks.workflowPackageRunOutputSurfaces === true`, and
    `checks.workflowGithubPrCreateRunOutputSurfaces === true`;
  - `runtime-artifacts.json` keeps the 21-kind live shadow component set with
    `github_pr_create` and `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

## Slice 40. 2026-05-11 - authority/tooling lane refactor

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-11T19-23-09-790Z/result.json

Validation evidence:

- `cargo test live_mcp_provider_catalog_executes_read_only_without_mutation --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_mcp_tool_catalog_consumes_provider_catalog_without_tool_execution --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_native_tool_catalog_consumes_mcp_tool_catalog_without_tool_execution --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_connector_catalog_describe_consumes_mcp_tool_catalog_without_connector_execution --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_wallet_capability_dry_run_never_materializes_grant --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_destructive_denial_blocks_without_side_effect --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_approval_gate_denies_without_authority_transfer --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/validation.rs apps/autopilot/src-tauri/src/project/workflow_authority_tooling_lane.rs apps/autopilot/src-tauri/src/project/workflow_value_helpers.rs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T19-23-09-790Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has
    `checks.workflowAuthorityToolingRuntimeLane === true`,
    `checks.workflowMemoryRuntimeLane === true`,
    `checks.workflowPackageRunOutputSurfaces === true`, and
    `checks.workflowGithubPrCreateRunOutputSurfaces === true`;
  - `runtime-artifacts.json` keeps the 21-kind live shadow component set with
    `approval_gate`, `policy_gate`, `connector_call`, `mcp_provider`,
    `mcp_tool_call`, `tool_call`, `wallet_capability`, and `github_pr_create`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingProviderCatalogLiveCount === 5`,
    `harnessAuthorityToolingMcpToolCatalogLiveCount === 5`,
    `harnessAuthorityToolingNativeToolCatalogLiveCount === 5`,
    `harnessAuthorityToolingConnectorCatalogLiveCount === 5`,
    `harnessAuthorityToolingWalletCapabilityLiveDryRunCount === 5`, and
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

## Slice 41. 2026-05-11 - workflow coding-route lane refactor

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-11T19-38-33-940Z/result.json

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/commands.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_coding_route_lane.rs apps/autopilot/src-tauri/src/project/workflow_value_helpers.rs`
- `git diff --check -- apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/commands.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_coding_route_lane.rs scripts/lib/live-runtime-daemon-contract.test.mjs scripts/lib/autopilot-gui-harness-validation/core.mjs docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T19-38-33-940Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `workflow-skill-context-proof.json` has `passed === true` with
    `checks.resolverExecution === true`;
  - `workflow-coding-route-proof.json` has `passed === true` with
    `checks.classifierAndEvidence === true`;
  - `workflow-coding-route-promotion-loop-proof.json` has `passed === true`
    with `checks.draftBenchmarkSelection === true` and
    `checks.promotionRuntime === true`.

## Slice 42. 2026-05-11 - workflow execution-results lane refactor

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-11T19-59-05-130Z/result.json

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/commands.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_coding_route_lane.rs apps/autopilot/src-tauri/src/project/workflow_execution_results_lane.rs apps/autopilot/src-tauri/src/project/workflow_value_helpers.rs`
- `git diff --check -- apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_execution_results_lane.rs scripts/lib/live-runtime-daemon-contract.test.mjs scripts/lib/autopilot-gui-harness-validation/core.mjs docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T19-59-05-130Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowExecutionResultsRuntimeLane === true`;
  - `rollback-restore-canary-ui-proof.json` also keeps
    `checks.workflowAuthorityToolingRuntimeLane === true`,
    `checks.workflowMemoryRuntimeLane === true`,
    `checks.workflowPackageRunOutputSurfaces === true`, and
    `checks.workflowGithubPrCreateRunOutputSurfaces === true`;
  - `workflow-coding-route-proof.json` has `passed === true` with
    `checks.classifierAndEvidence === true`;
  - `workflow-coding-route-promotion-loop-proof.json` has `passed === true`
    with `checks.promotionRuntime === true`.

## Slice 43. 2026-05-11 - workflow harness-results lane refactor

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-11T20-14-13-182Z/result.json

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/commands.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_coding_route_lane.rs apps/autopilot/src-tauri/src/project/workflow_execution_results_lane.rs apps/autopilot/src-tauri/src/project/workflow_harness_results_lane.rs apps/autopilot/src-tauri/src/project/workflow_value_helpers.rs`
- `git diff --check -- apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_harness_results_lane.rs scripts/lib/live-runtime-daemon-contract.test.mjs scripts/lib/autopilot-gui-harness-validation/core.mjs docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T20-14-13-182Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowHarnessResultsRuntimeLane === true`;
  - `rollback-restore-canary-ui-proof.json` also keeps
    `checks.workflowExecutionResultsRuntimeLane === true`,
    `checks.workflowAuthorityToolingRuntimeLane === true`,
    `checks.workflowMemoryRuntimeLane === true`,
    `checks.workflowPackageRunOutputSurfaces === true`, and
    `checks.workflowGithubPrCreateRunOutputSurfaces === true`;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

## Slice 44. 2026-05-11 - workflow graph-execution lane refactor

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-11T20-27-36-131Z/result.json

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/commands.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_coding_route_lane.rs apps/autopilot/src-tauri/src/project/workflow_execution_results_lane.rs apps/autopilot/src-tauri/src/project/workflow_graph_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_harness_results_lane.rs apps/autopilot/src-tauri/src/project/workflow_value_helpers.rs`
- `git diff --check -- apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_graph_execution_lane.rs scripts/lib/live-runtime-daemon-contract.test.mjs scripts/lib/autopilot-gui-harness-validation/core.mjs docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T20-27-36-131Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowGraphExecutionRuntimeLane === true`;
  - `rollback-restore-canary-ui-proof.json` also keeps
    `checks.workflowHarnessResultsRuntimeLane === true`,
    `checks.workflowExecutionResultsRuntimeLane === true`,
    `checks.workflowAuthorityToolingRuntimeLane === true`,
    `checks.workflowMemoryRuntimeLane === true`,
    `checks.workflowPackageRunOutputSurfaces === true`, and
    `checks.workflowGithubPrCreateRunOutputSurfaces === true`;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

## Slice 45. 2026-05-11 - workflow binding lane refactor

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-11T20-40-37-167Z/result.json

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/commands.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_binding_lane.rs apps/autopilot/src-tauri/src/project/workflow_coding_route_lane.rs apps/autopilot/src-tauri/src/project/workflow_execution_results_lane.rs apps/autopilot/src-tauri/src/project/workflow_graph_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_harness_results_lane.rs apps/autopilot/src-tauri/src/project/workflow_value_helpers.rs`
- `git diff --check -- apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_binding_lane.rs scripts/lib/live-runtime-daemon-contract.test.mjs scripts/lib/autopilot-gui-harness-validation/core.mjs docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T20-40-37-167Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowBindingRuntimeLane === true`;
  - `rollback-restore-canary-ui-proof.json` also keeps
    `checks.workflowGraphExecutionRuntimeLane === true`,
    `checks.workflowHarnessResultsRuntimeLane === true`,
    `checks.workflowExecutionResultsRuntimeLane === true`,
    `checks.workflowAuthorityToolingRuntimeLane === true`,
    `checks.workflowMemoryRuntimeLane === true`,
    `checks.workflowPackageRunOutputSurfaces === true`, and
    `checks.workflowGithubPrCreateRunOutputSurfaces === true`;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

## Slice 46. 2026-05-11 - workflow output lane refactor

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-11T21-05-30-136Z/result.json

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/commands.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_binding_lane.rs apps/autopilot/src-tauri/src/project/workflow_coding_route_lane.rs apps/autopilot/src-tauri/src/project/workflow_execution_results_lane.rs apps/autopilot/src-tauri/src/project/workflow_graph_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_harness_results_lane.rs apps/autopilot/src-tauri/src/project/workflow_output_lane.rs apps/autopilot/src-tauri/src/project/workflow_value_helpers.rs`
- `git diff --check -- apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_output_lane.rs scripts/lib/live-runtime-daemon-contract.test.mjs scripts/lib/autopilot-gui-harness-validation/core.mjs docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T21-05-30-136Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowOutputRuntimeLane === true`;
  - `rollback-restore-canary-ui-proof.json` also keeps
    `checks.workflowBindingRuntimeLane === true`,
    `checks.workflowGraphExecutionRuntimeLane === true`,
    `checks.workflowHarnessResultsRuntimeLane === true`,
    `checks.workflowExecutionResultsRuntimeLane === true`,
    `checks.workflowAuthorityToolingRuntimeLane === true`,
    `checks.workflowMemoryRuntimeLane === true`,
    `checks.workflowPackageRunOutputSurfaces === true`, and
    `checks.workflowGithubPrCreateRunOutputSurfaces === true`;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

## Slice 47. 2026-05-11 - workflow approval/interrupt lane refactor

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-11T21-47-22-432Z/result.json

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_side_effect_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_output_delivery_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tests_can_pass_target_outputs_before_downstream_interrupt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/commands.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_approval_interrupt_lane.rs apps/autopilot/src-tauri/src/project/workflow_binding_lane.rs apps/autopilot/src-tauri/src/project/workflow_coding_route_lane.rs apps/autopilot/src-tauri/src/project/workflow_execution_results_lane.rs apps/autopilot/src-tauri/src/project/workflow_graph_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_harness_results_lane.rs apps/autopilot/src-tauri/src/project/workflow_output_lane.rs apps/autopilot/src-tauri/src/project/workflow_value_helpers.rs`
- `git diff --check -- apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_approval_interrupt_lane.rs scripts/lib/live-runtime-daemon-contract.test.mjs scripts/lib/autopilot-gui-harness-validation/core.mjs docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-11T21-47-22-432Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowApprovalInterruptRuntimeLane === true`;
  - `rollback-restore-canary-ui-proof.json` also keeps
    `checks.workflowOutputRuntimeLane === true`,
    `checks.workflowBindingRuntimeLane === true`,
    `checks.workflowGraphExecutionRuntimeLane === true`,
    `checks.workflowHarnessResultsRuntimeLane === true`,
    `checks.workflowExecutionResultsRuntimeLane === true`,
    `checks.workflowAuthorityToolingRuntimeLane === true`,
    `checks.workflowMemoryRuntimeLane === true`,
    `checks.workflowPackageRunOutputSurfaces === true`, and
    `checks.workflowGithubPrCreateRunOutputSurfaces === true`;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

## Slice 48. 2026-05-12 - workflow checkpoint lane refactor

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-12T01-20-27-365Z/result.json

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_failed_function_resumes_from_repaired_checkpoint --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_retry_preserves_failed_attempt_evidence --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_binding_requires_schema_and_retry_contract --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_side_effect_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_output_delivery_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tests_can_pass_target_outputs_before_downstream_interrupt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/commands.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_approval_interrupt_lane.rs apps/autopilot/src-tauri/src/project/workflow_binding_lane.rs apps/autopilot/src-tauri/src/project/workflow_checkpoint_lane.rs apps/autopilot/src-tauri/src/project/workflow_coding_route_lane.rs apps/autopilot/src-tauri/src/project/workflow_execution_results_lane.rs apps/autopilot/src-tauri/src/project/workflow_graph_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_harness_results_lane.rs apps/autopilot/src-tauri/src/project/workflow_output_lane.rs apps/autopilot/src-tauri/src/project/workflow_value_helpers.rs`
- `git diff --check -- apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_checkpoint_lane.rs scripts/lib/live-runtime-daemon-contract.test.mjs scripts/lib/autopilot-gui-harness-validation/core.mjs docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T01-20-27-365Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowCheckpointRuntimeLane === true`;
  - `rollback-restore-canary-ui-proof.json` also keeps
    `checks.workflowApprovalInterruptRuntimeLane === true`,
    `checks.workflowOutputRuntimeLane === true`,
    `checks.workflowBindingRuntimeLane === true`,
    `checks.workflowGraphExecutionRuntimeLane === true`,
    `checks.workflowHarnessResultsRuntimeLane === true`,
    `checks.workflowExecutionResultsRuntimeLane === true`,
    `checks.workflowAuthorityToolingRuntimeLane === true`,
    `checks.workflowMemoryRuntimeLane === true`,
    `checks.workflowPackageRunOutputSurfaces === true`, and
    `checks.workflowGithubPrCreateRunOutputSurfaces === true`;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

## Slice 49. 2026-05-12 - workflow state/input mapping lane refactor

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-12T01-35-34-520Z/result.json

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_expression_refs_require_connected_output_ports --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_field_mappings_require_declared_schema_paths --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_field_mappings_prepare_runtime_node_input --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_failed_function_resumes_from_repaired_checkpoint --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_retry_preserves_failed_attempt_evidence --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_binding_requires_schema_and_retry_contract --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_side_effect_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_output_delivery_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tests_can_pass_target_outputs_before_downstream_interrupt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/commands.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_approval_interrupt_lane.rs apps/autopilot/src-tauri/src/project/workflow_binding_lane.rs apps/autopilot/src-tauri/src/project/workflow_checkpoint_lane.rs apps/autopilot/src-tauri/src/project/workflow_coding_route_lane.rs apps/autopilot/src-tauri/src/project/workflow_execution_results_lane.rs apps/autopilot/src-tauri/src/project/workflow_graph_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_harness_results_lane.rs apps/autopilot/src-tauri/src/project/workflow_output_lane.rs apps/autopilot/src-tauri/src/project/workflow_state_lane.rs apps/autopilot/src-tauri/src/project/workflow_value_helpers.rs`
- `git diff --check -- apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_state_lane.rs scripts/lib/live-runtime-daemon-contract.test.mjs scripts/lib/autopilot-gui-harness-validation/core.mjs docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T01-35-34-520Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowStateRuntimeLane === true`;
  - `rollback-restore-canary-ui-proof.json` also keeps
    `checks.workflowCheckpointRuntimeLane === true`,
    `checks.workflowApprovalInterruptRuntimeLane === true`,
    `checks.workflowOutputRuntimeLane === true`,
    `checks.workflowBindingRuntimeLane === true`,
    `checks.workflowGraphExecutionRuntimeLane === true`,
    `checks.workflowHarnessResultsRuntimeLane === true`,
    `checks.workflowExecutionResultsRuntimeLane === true`,
    `checks.workflowAuthorityToolingRuntimeLane === true`,
    `checks.workflowMemoryRuntimeLane === true`,
    `checks.workflowPackageRunOutputSurfaces === true`, and
    `checks.workflowGithubPrCreateRunOutputSurfaces === true`;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

## Slice 50. 2026-05-12 - workflow node-execution lane refactor

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-12T01-50-03-398Z/result.json

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_expression_refs_require_connected_output_ports --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_field_mappings_prepare_runtime_node_input --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_failed_function_resumes_from_repaired_checkpoint --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_retry_preserves_failed_attempt_evidence --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_binding_requires_schema_and_retry_contract --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_side_effect_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_output_delivery_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tests_can_pass_target_outputs_before_downstream_interrupt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/commands.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_node_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_approval_interrupt_lane.rs apps/autopilot/src-tauri/src/project/workflow_binding_lane.rs apps/autopilot/src-tauri/src/project/workflow_checkpoint_lane.rs apps/autopilot/src-tauri/src/project/workflow_coding_route_lane.rs apps/autopilot/src-tauri/src/project/workflow_execution_results_lane.rs apps/autopilot/src-tauri/src/project/workflow_graph_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_harness_results_lane.rs apps/autopilot/src-tauri/src/project/workflow_output_lane.rs apps/autopilot/src-tauri/src/project/workflow_state_lane.rs apps/autopilot/src-tauri/src/project/workflow_value_helpers.rs`
- `git diff --check -- apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_node_execution_lane.rs scripts/lib/live-runtime-daemon-contract.test.mjs scripts/lib/autopilot-gui-harness-validation/core.mjs docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T01-50-03-398Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowNodeExecutionRuntimeLane === true`;
  - `rollback-restore-canary-ui-proof.json` also keeps
    `checks.workflowStateRuntimeLane === true`,
    `checks.workflowCheckpointRuntimeLane === true`,
    `checks.workflowApprovalInterruptRuntimeLane === true`,
    `checks.workflowOutputRuntimeLane === true`,
    `checks.workflowBindingRuntimeLane === true`,
    `checks.workflowGraphExecutionRuntimeLane === true`,
    `checks.workflowHarnessResultsRuntimeLane === true`,
    `checks.workflowExecutionResultsRuntimeLane === true`,
    `checks.workflowAuthorityToolingRuntimeLane === true`,
    `checks.workflowMemoryRuntimeLane === true`,
    `checks.workflowPackageRunOutputSurfaces === true`, and
    `checks.workflowGithubPrCreateRunOutputSurfaces === true`;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

## Slice 51. 2026-05-12 - workflow node-contract lane refactor

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-12T02-04-17-641Z/result.json

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_expression_refs_require_connected_output_ports --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_field_mappings_prepare_runtime_node_input --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_failed_function_resumes_from_repaired_checkpoint --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_retry_preserves_failed_attempt_evidence --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_binding_requires_schema_and_retry_contract --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_side_effect_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_output_delivery_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tests_can_pass_target_outputs_before_downstream_interrupt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/commands.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_node_contract_lane.rs apps/autopilot/src-tauri/src/project/workflow_node_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_approval_interrupt_lane.rs apps/autopilot/src-tauri/src/project/workflow_binding_lane.rs apps/autopilot/src-tauri/src/project/workflow_checkpoint_lane.rs apps/autopilot/src-tauri/src/project/workflow_coding_route_lane.rs apps/autopilot/src-tauri/src/project/workflow_execution_results_lane.rs apps/autopilot/src-tauri/src/project/workflow_graph_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_harness_results_lane.rs apps/autopilot/src-tauri/src/project/workflow_output_lane.rs apps/autopilot/src-tauri/src/project/workflow_state_lane.rs apps/autopilot/src-tauri/src/project/workflow_value_helpers.rs`
- `git diff --check -- apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_node_contract_lane.rs scripts/lib/live-runtime-daemon-contract.test.mjs scripts/lib/autopilot-gui-harness-validation/core.mjs docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T02-04-17-641Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowNodeContractRuntimeLane === true`;
  - `rollback-restore-canary-ui-proof.json` also keeps
    `checks.workflowNodeExecutionRuntimeLane === true`,
    `checks.workflowStateRuntimeLane === true`,
    `checks.workflowCheckpointRuntimeLane === true`,
    `checks.workflowApprovalInterruptRuntimeLane === true`,
    `checks.workflowOutputRuntimeLane === true`,
    `checks.workflowBindingRuntimeLane === true`,
    `checks.workflowGraphExecutionRuntimeLane === true`,
    `checks.workflowHarnessResultsRuntimeLane === true`,
    `checks.workflowExecutionResultsRuntimeLane === true`,
    `checks.workflowAuthorityToolingRuntimeLane === true`,
    `checks.workflowMemoryRuntimeLane === true`,
    `checks.workflowPackageRunOutputSurfaces === true`, and
    `checks.workflowGithubPrCreateRunOutputSurfaces === true`;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

## Slice 52. 2026-05-12 - workflow run-lifecycle lane refactor

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-12T02-17-52-426Z/result.json

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_expression_refs_require_connected_output_ports --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_field_mappings_prepare_runtime_node_input --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_failed_function_resumes_from_repaired_checkpoint --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_retry_preserves_failed_attempt_evidence --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_binding_requires_schema_and_retry_contract --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_side_effect_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_output_delivery_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tests_can_pass_target_outputs_before_downstream_interrupt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_run_lifecycle_lane.rs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T02-17-52-426Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowRunLifecycleRuntimeLane === true`;
  - `rollback-restore-canary-ui-proof.json` also keeps
    `checks.workflowNodeContractRuntimeLane === true`,
    `checks.workflowNodeExecutionRuntimeLane === true`,
    `checks.workflowStateRuntimeLane === true`,
    `checks.workflowCheckpointRuntimeLane === true`,
    `checks.workflowApprovalInterruptRuntimeLane === true`,
    `checks.workflowOutputRuntimeLane === true`,
    `checks.workflowBindingRuntimeLane === true`,
    `checks.workflowGraphExecutionRuntimeLane === true`,
    `checks.workflowHarnessResultsRuntimeLane === true`,
    `checks.workflowExecutionResultsRuntimeLane === true`,
    `checks.workflowAuthorityToolingRuntimeLane === true`,
    `checks.workflowMemoryRuntimeLane === true`,
    `checks.workflowPackageRunOutputSurfaces === true`, and
    `checks.workflowGithubPrCreateRunOutputSurfaces === true`;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

## Slice 53. 2026-05-12 - workflow node-metadata lane refactor

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-12T02-30-26-185Z/result.json

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_expression_refs_require_connected_output_ports --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_field_mappings_prepare_runtime_node_input --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_failed_function_resumes_from_repaired_checkpoint --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_retry_preserves_failed_attempt_evidence --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_binding_requires_schema_and_retry_contract --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_side_effect_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_output_delivery_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tests_can_pass_target_outputs_before_downstream_interrupt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_node_metadata_lane.rs apps/autopilot/src-tauri/src/project/workflow_run_lifecycle_lane.rs apps/autopilot/src-tauri/src/project/workflow_node_contract_lane.rs apps/autopilot/src-tauri/src/project/workflow_node_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_state_lane.rs apps/autopilot/src-tauri/src/project/workflow_approval_interrupt_lane.rs apps/autopilot/src-tauri/src/project/validation.rs apps/autopilot/src-tauri/src/project/package.rs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T02-30-26-185Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowNodeMetadataRuntimeLane === true`;
  - `rollback-restore-canary-ui-proof.json` also keeps
    `checks.workflowRunLifecycleRuntimeLane === true`,
    `checks.workflowNodeContractRuntimeLane === true`,
    `checks.workflowNodeExecutionRuntimeLane === true`,
    `checks.workflowStateRuntimeLane === true`,
    `checks.workflowCheckpointRuntimeLane === true`,
    `checks.workflowApprovalInterruptRuntimeLane === true`,
    `checks.workflowOutputRuntimeLane === true`,
    `checks.workflowBindingRuntimeLane === true`,
    `checks.workflowGraphExecutionRuntimeLane === true`,
    `checks.workflowHarnessResultsRuntimeLane === true`,
    `checks.workflowExecutionResultsRuntimeLane === true`,
    `checks.workflowAuthorityToolingRuntimeLane === true`,
    `checks.workflowMemoryRuntimeLane === true`,
    `checks.workflowPackageRunOutputSurfaces === true`, and
    `checks.workflowGithubPrCreateRunOutputSurfaces === true`;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

## Slice 54. 2026-05-12 - workflow scheduler lane refactor

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-12T02-42-18-082Z/result.json

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_expression_refs_require_connected_output_ports --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_field_mappings_prepare_runtime_node_input --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_failed_function_resumes_from_repaired_checkpoint --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_retry_preserves_failed_attempt_evidence --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_binding_requires_schema_and_retry_contract --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_side_effect_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_output_delivery_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tests_can_pass_target_outputs_before_downstream_interrupt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/runtime.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_lane.rs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T02-42-18-082Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowSchedulerRuntimeLane === true`;
  - `rollback-restore-canary-ui-proof.json` also keeps
    `checks.workflowNodeMetadataRuntimeLane === true`,
    `checks.workflowRunLifecycleRuntimeLane === true`,
    `checks.workflowNodeContractRuntimeLane === true`,
    `checks.workflowNodeExecutionRuntimeLane === true`,
    `checks.workflowStateRuntimeLane === true`,
    `checks.workflowCheckpointRuntimeLane === true`,
    `checks.workflowApprovalInterruptRuntimeLane === true`,
    `checks.workflowOutputRuntimeLane === true`,
    `checks.workflowBindingRuntimeLane === true`,
    `checks.workflowGraphExecutionRuntimeLane === true`,
    `checks.workflowHarnessResultsRuntimeLane === true`,
    `checks.workflowExecutionResultsRuntimeLane === true`,
    `checks.workflowAuthorityToolingRuntimeLane === true`,
    `checks.workflowMemoryRuntimeLane === true`,
    `checks.workflowPackageRunOutputSurfaces === true`, and
    `checks.workflowGithubPrCreateRunOutputSurfaces === true`;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

## Slice 55. 2026-05-12 - workflow scheduler validation lane refactor

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-12T02-55-14-162Z/result.json

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_expression_refs_require_connected_output_ports --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_field_mappings_prepare_runtime_node_input --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_failed_function_resumes_from_repaired_checkpoint --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_retry_preserves_failed_attempt_evidence --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_binding_requires_schema_and_retry_contract --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_side_effect_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_output_delivery_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tests_can_pass_target_outputs_before_downstream_interrupt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs && node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_validation_lane.rs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T02-55-14-162Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowSchedulerRuntimeLane === true` and
    `checks.workflowSchedulerValidationRuntimeLane === true`;
  - all prior runtime lane checks remain true, including node metadata, run
    lifecycle, node contract, node execution, state, checkpoint, approval,
    output, binding, graph execution, harness results, execution results,
    authority/tooling, memory, package run output, and GitHub PR create output;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

## Slice 56. 2026-05-12 - workflow scheduler interrupt lane refactor

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-12T03-06-47-704Z/result.json

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_expression_refs_require_connected_output_ports --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_field_mappings_prepare_runtime_node_input --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_failed_function_resumes_from_repaired_checkpoint --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_retry_preserves_failed_attempt_evidence --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_binding_requires_schema_and_retry_contract --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_side_effect_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_output_delivery_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tests_can_pass_target_outputs_before_downstream_interrupt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs && node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_interrupt_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_validation_lane.rs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T03-06-47-704Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowSchedulerRuntimeLane === true`,
    `checks.workflowSchedulerInterruptRuntimeLane === true`, and
    `checks.workflowSchedulerValidationRuntimeLane === true`;
  - all prior runtime lane checks remain true, including node metadata, run
    lifecycle, node contract, node execution, state, checkpoint, approval,
    output, binding, graph execution, harness results, execution results,
    authority/tooling, memory, package run output, and GitHub PR create output;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

## Slice 57. 2026-05-12 - workflow scheduler node execution lane refactor

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-12T03-20-30-303Z/result.json

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_expression_refs_require_connected_output_ports --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_field_mappings_prepare_runtime_node_input --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_failed_function_resumes_from_repaired_checkpoint --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_retry_preserves_failed_attempt_evidence --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_binding_requires_schema_and_retry_contract --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_side_effect_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_output_delivery_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tests_can_pass_target_outputs_before_downstream_interrupt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs && node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_execution_lane.rs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T03-20-30-303Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowSchedulerRuntimeLane === true`,
    `checks.workflowSchedulerNodeExecutionRuntimeLane === true`,
    `checks.workflowSchedulerInterruptRuntimeLane === true`, and
    `checks.workflowSchedulerValidationRuntimeLane === true`;
  - all prior runtime lane checks remain true, including node metadata, run
    lifecycle, node contract, node execution, state, checkpoint, approval,
    output, binding, graph execution, harness results, execution results,
    authority/tooling, memory, package run output, and GitHub PR create output;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

## Slice 58. 2026-05-12 - workflow scheduler finalization lane refactor

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-12T03-33-43-994Z/result.json

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_expression_refs_require_connected_output_ports --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_field_mappings_prepare_runtime_node_input --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_failed_function_resumes_from_repaired_checkpoint --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_retry_preserves_failed_attempt_evidence --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_binding_requires_schema_and_retry_contract --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_side_effect_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_output_delivery_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tests_can_pass_target_outputs_before_downstream_interrupt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs && node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_finalization_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_interrupt_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_validation_lane.rs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T03-33-43-994Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowSchedulerRuntimeLane === true`,
    `checks.workflowSchedulerFinalizationRuntimeLane === true`,
    `checks.workflowSchedulerNodeExecutionRuntimeLane === true`,
    `checks.workflowSchedulerInterruptRuntimeLane === true`, and
    `checks.workflowSchedulerValidationRuntimeLane === true`;
  - all prior runtime lane checks remain true, including node metadata, run
    lifecycle, node contract, node execution, state, checkpoint, approval,
    output, binding, graph execution, harness results, execution results,
    authority/tooling, memory, package run output, and GitHub PR create output;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

## Slice 59. 2026-05-12 - workflow scheduler terminal result lane refactor

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-12T03-49-14-148Z/result.json

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_expression_refs_require_connected_output_ports --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_field_mappings_prepare_runtime_node_input --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_failed_function_resumes_from_repaired_checkpoint --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_retry_preserves_failed_attempt_evidence --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_binding_requires_schema_and_retry_contract --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_side_effect_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_output_delivery_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tests_can_pass_target_outputs_before_downstream_interrupt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs && node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_finalization_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_terminal_result_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_interrupt_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_validation_lane.rs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T03-49-14-148Z/result.json`
  - `validation.ok === true`;
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowSchedulerRuntimeLane === true`,
    `checks.workflowSchedulerFinalizationRuntimeLane === true`,
    `checks.workflowSchedulerTerminalResultRuntimeLane === true`,
    `checks.workflowSchedulerNodeExecutionRuntimeLane === true`,
    `checks.workflowSchedulerInterruptRuntimeLane === true`, and
    `checks.workflowSchedulerValidationRuntimeLane === true`;
  - all prior runtime lane checks remain true, including node metadata, run
    lifecycle, node contract, node execution, state, checkpoint, approval,
    output, binding, graph execution, harness results, execution results,
    authority/tooling, memory, package run output, and GitHub PR create output;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

## Slice 60. 2026-05-12 - workflow scheduler node outcome lane refactor

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-12T04-02-51-456Z/result.json

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_expression_refs_require_connected_output_ports --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_field_mappings_prepare_runtime_node_input --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_failed_function_resumes_from_repaired_checkpoint --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_retry_preserves_failed_attempt_evidence --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_binding_requires_schema_and_retry_contract --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_side_effect_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_output_delivery_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tests_can_pass_target_outputs_before_downstream_interrupt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs && node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_finalization_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_terminal_result_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_outcome_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_interrupt_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_validation_lane.rs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T04-02-51-456Z/result.json`
  - `blocked === false`;
  - all chat query scenarios have `passed === true`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowSchedulerRuntimeLane === true`,
    `checks.workflowSchedulerFinalizationRuntimeLane === true`,
    `checks.workflowSchedulerTerminalResultRuntimeLane === true`,
    `checks.workflowSchedulerNodeExecutionRuntimeLane === true`,
    `checks.workflowSchedulerNodeOutcomeRuntimeLane === true`,
    `checks.workflowSchedulerInterruptRuntimeLane === true`, and
    `checks.workflowSchedulerValidationRuntimeLane === true`;
  - all prior runtime lane checks remain true, including node metadata, run
    lifecycle, node contract, node execution, state, checkpoint, approval,
    output, binding, graph execution, harness results, execution results,
    authority/tooling, memory, package run output, and GitHub PR create output;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

## Slice 61. 2026-05-12 - workflow scheduler node state update lane refactor

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-12T06-55-19-771Z/result.json

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_expression_refs_require_connected_output_ports --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_field_mappings_prepare_runtime_node_input --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_failed_function_resumes_from_repaired_checkpoint --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_retry_preserves_failed_attempt_evidence --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_binding_requires_schema_and_retry_contract --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_side_effect_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_output_delivery_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tests_can_pass_target_outputs_before_downstream_interrupt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs && node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_finalization_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_terminal_result_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_outcome_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_state_update_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_interrupt_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_validation_lane.rs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T06-55-19-771Z/result.json`
  - `blocked === false`;
  - all chat query scenarios have `passed === true`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowSchedulerRuntimeLane === true`,
    `checks.workflowSchedulerFinalizationRuntimeLane === true`,
    `checks.workflowSchedulerTerminalResultRuntimeLane === true`,
    `checks.workflowSchedulerNodeExecutionRuntimeLane === true`,
    `checks.workflowSchedulerNodeOutcomeRuntimeLane === true`,
    `checks.workflowSchedulerNodeStateUpdateRuntimeLane === true`,
    `checks.workflowSchedulerInterruptRuntimeLane === true`, and
    `checks.workflowSchedulerValidationRuntimeLane === true`;
  - all prior runtime lane checks remain true, including node metadata, run
    lifecycle, node contract, node execution, state, checkpoint, approval,
    output, binding, graph execution, harness results, execution results,
    authority/tooling, memory, package run output, and GitHub PR create output;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

## Slice 62. 2026-05-12 - workflow scheduler node success event lane refactor

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-12T07-10-36-395Z/result.json

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_expression_refs_require_connected_output_ports --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_field_mappings_prepare_runtime_node_input --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_failed_function_resumes_from_repaired_checkpoint --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_retry_preserves_failed_attempt_evidence --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_binding_requires_schema_and_retry_contract --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_side_effect_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_output_delivery_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tests_can_pass_target_outputs_before_downstream_interrupt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs && node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_finalization_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_terminal_result_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_outcome_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_state_update_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_success_event_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_interrupt_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_validation_lane.rs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T07-10-36-395Z/result.json`
  - `blocked === false`;
  - all chat query scenarios have `passed === true`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowSchedulerRuntimeLane === true`,
    `checks.workflowSchedulerFinalizationRuntimeLane === true`,
    `checks.workflowSchedulerTerminalResultRuntimeLane === true`,
    `checks.workflowSchedulerNodeExecutionRuntimeLane === true`,
    `checks.workflowSchedulerNodeOutcomeRuntimeLane === true`,
    `checks.workflowSchedulerNodeStateUpdateRuntimeLane === true`,
    `checks.workflowSchedulerNodeSuccessEventRuntimeLane === true`,
    `checks.workflowSchedulerInterruptRuntimeLane === true`, and
    `checks.workflowSchedulerValidationRuntimeLane === true`;
  - all prior runtime lane checks remain true, including node metadata, run
    lifecycle, node contract, node execution, state, checkpoint, approval,
    output, binding, graph execution, harness results, execution results,
    authority/tooling, memory, package run output, and GitHub PR create output;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

## Slice 63. 2026-05-12 - workflow scheduler node failure outcome lane refactor

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-12T10-59-14-718Z/result.json

Validation evidence:

- `cargo test workflow_skill_context --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_expression_refs_require_connected_output_ports --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_field_mappings_prepare_runtime_node_input --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test coding_route --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_run_interrupt_resume_and_checkpoint_fork_are_durable --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_failed_function_resumes_from_repaired_checkpoint --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_retry_preserves_failed_attempt_evidence --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_binding_requires_schema_and_retry_contract --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tool_side_effect_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_output_delivery_pauses_for_contextual_approval --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_tests_can_pass_target_outputs_before_downstream_interrupt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_package_export_and_import_nodes_execute_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test github_pr_create_dry_run_node_executes_through_runtime --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test workflow_model_tool_memory_parser_loop_records_lineage --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test live_authority_policy_gate_emits_non_mutating_decision_receipt --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo test substrate_classifies_workflow_node_kinds --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs && node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_finalization_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_terminal_result_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_outcome_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_state_update_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_success_event_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_failure_outcome_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_interrupt_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_validation_lane.rs`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T10-59-14-718Z/result.json`
  - `blocked === false`;
  - all chat query scenarios have `passed === true`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true` with
    `checks.workflowSchedulerRuntimeLane === true`,
    `checks.workflowSchedulerFinalizationRuntimeLane === true`,
    `checks.workflowSchedulerTerminalResultRuntimeLane === true`,
    `checks.workflowSchedulerNodeExecutionRuntimeLane === true`,
    `checks.workflowSchedulerNodeOutcomeRuntimeLane === true`,
    `checks.workflowSchedulerNodeStateUpdateRuntimeLane === true`,
    `checks.workflowSchedulerNodeSuccessEventRuntimeLane === true`,
    `checks.workflowSchedulerNodeFailureOutcomeRuntimeLane === true`,
    `checks.workflowSchedulerInterruptRuntimeLane === true`, and
    `checks.workflowSchedulerValidationRuntimeLane === true`;
  - all prior runtime lane checks remain true, including node metadata, run
    lifecycle, node contract, node execution, state, checkpoint, approval,
    output, binding, graph execution, harness results, execution results,
    authority/tooling, memory, package run output, and GitHub PR create output;
  - `runtime-artifacts.json` keeps the 21-kind live shadow comparison component
    set with `github_pr_create`, `approval_gate`, `policy_gate`,
    `connector_call`, `mcp_provider`, `mcp_tool_call`, `tool_call`, and
    `wallet_capability`;
  - `runtime-artifacts.json` reports
    `harnessAuthorityToolingGithubPrCreateDryRunCount === 5`.

## Slice 64. 2026-05-12 - React Flow scheduler lane readiness UI

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-12T11-23-50-090Z/result.json

Validation evidence:

- `npm run build --workspace=@ioi/agent-ide`
- focused runtime import check:
  `node --import tsx - <<'EOF' ... scheduler lane readiness check passed`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs && node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler`
- `rustfmt --edition 2021 --check apps/autopilot/src-tauri/src/project.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_finalization_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_terminal_result_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_outcome_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_state_update_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_success_event_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_node_failure_outcome_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_interrupt_lane.rs apps/autopilot/src-tauri/src/project/workflow_scheduler_validation_lane.rs`
- `npm run validate:autopilot-gui-harness`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T11-23-50-090Z/result.json`
  - `rollback-restore-canary-ui-proof.json` has `passed === true`;
  - `checks.workflowSchedulerLaneReadinessManifest === true`;
  - `checks.workflowSchedulerLaneReadinessActivationUi === true`;
  - all scheduler runtime lane checks remain true, including failure outcome,
    success event, state update, node outcome, node execution, terminal result,
    finalization, interrupt, validation, and the main scheduler lane.

## Slice 65. 2026-05-12 - React Flow readiness panel extraction

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-12T11-44-32-936Z/result.json

Validation evidence:

- `npm run build --workspace=@ioi/agent-ide`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs && node --check scripts/lib/autopilot-gui-harness-validation/core.mjs && node --check scripts/lib/harness-refactor-shape.test.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test scripts/lib/harness-refactor-shape.test.mjs`
- `npm run validate:autopilot-gui-harness`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T11-44-32-936Z/result.json`
  - `blocked === false`;
  - `rollback-restore-canary-ui-proof.json` has `passed === true`;
  - `checks.workflowSchedulerLaneReadinessManifest === true`;
  - `checks.workflowSchedulerLaneReadinessActivationUi === true`;
  - `checks.workflowSchedulerRuntimeLane === true`;
  - `checks.workflowSchedulerNodeFailureOutcomeRuntimeLane === true`.

## Slice 66. 2026-05-12 - React Flow readiness model extraction

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-12T12-10-50-239Z/result.json

Validation evidence:

- `node --import tsx --test packages/agent-ide/src/runtime/workflow-readiness-model.test.ts`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --check scripts/lib/harness-refactor-shape.test.mjs`
- `npm run build --workspace=@ioi/agent-ide`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test scripts/lib/harness-refactor-shape.test.mjs`
- `npm run validate:autopilot-gui-harness`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T12-10-50-239Z/result.json`
  - `validation.ok === true`;
  - `validation.failures` is empty;
  - `rollback-restore-canary-ui-proof.json` has `passed === true`;
  - `checks.workflowSchedulerLaneReadinessManifest === true`;
  - `checks.workflowSchedulerLaneReadinessActivationUi === true`;
  - `checks.workflowSchedulerRuntimeLane === true`;
  - `checks.workflowSchedulerNodeFailureOutcomeRuntimeLane === true`;
  - `sourceRefs` include both
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/readinessPanel.tsx`
    and `packages/agent-ide/src/runtime/workflow-readiness-model.ts`.

## Slice 67. 2026-05-12 - React Flow unit-test readiness model extraction

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-12T12-29-29-676Z/result.json

Validation evidence:

- `node --import tsx --test packages/agent-ide/src/runtime/workflow-test-readiness-model.test.ts`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --check scripts/lib/harness-refactor-shape.test.mjs`
- `npm run build --workspace=@ioi/agent-ide`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test scripts/lib/harness-refactor-shape.test.mjs`
- `node --import tsx --test packages/agent-ide/src/runtime/workflow-test-readiness-model.test.ts packages/agent-ide/src/runtime/workflow-readiness-model.test.ts`
- `npm run validate:autopilot-gui-harness`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T12-29-29-676Z/result.json`
  - `validation.ok === true`;
  - `validation.failures` is empty;
  - `rollback-restore-canary-ui-proof.json` has `passed === true`;
  - `checks.workflowUnitTestReadinessModelUi === true`;
  - `checks.workflowSchedulerLaneReadinessActivationUi === true`;
  - `checks.workflowSchedulerRuntimeLane === true`;
  - `sourceRefs` include both
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/unitTestsPanel.tsx`
    and `packages/agent-ide/src/runtime/workflow-test-readiness-model.ts`.

## Slice 68. 2026-05-12 - React Flow run-history model extraction

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-12T12-53-40-859Z/result.json

Validation evidence:

- `node --import tsx --test packages/agent-ide/src/runtime/workflow-run-history-model.test.ts`
- `npm run build --workspace=@ioi/agent-ide`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --check scripts/lib/harness-refactor-shape.test.mjs`
- `node --import tsx --test packages/agent-ide/src/runtime/workflow-run-history-model.test.ts packages/agent-ide/src/runtime/workflow-test-readiness-model.test.ts packages/agent-ide/src/runtime/workflow-readiness-model.test.ts`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test scripts/lib/harness-refactor-shape.test.mjs`
- `npm run validate:autopilot-gui-harness`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T12-53-40-859Z/result.json`
  - `validation.ok === true`;
  - `validation.failures` is empty;
  - `rollback-restore-canary-ui-proof.json` has `passed === true`;
  - `checks.workflowRunHistoryModelUi === true`;
  - `checks.workflowUnitTestReadinessModelUi === true`;
  - `checks.workflowSchedulerLaneReadinessActivationUi === true`;
  - `checks.workflowSchedulerRuntimeLane === true`;
  - `sourceRefs` include both
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/runsPanel.tsx`
    and `packages/agent-ide/src/runtime/workflow-run-history-model.ts`.

## Slice 69. 2026-05-12 - React Flow search model extraction

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-12T13-15-19-853Z/result.json

Validation evidence:

- `node --import tsx --test packages/agent-ide/src/runtime/workflow-rail-search-model.test.ts`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --check scripts/lib/harness-refactor-shape.test.mjs`
- `node --import tsx --test packages/agent-ide/src/runtime/workflow-rail-search-model.test.ts packages/agent-ide/src/runtime/workflow-run-history-model.test.ts packages/agent-ide/src/runtime/workflow-test-readiness-model.test.ts packages/agent-ide/src/runtime/workflow-readiness-model.test.ts`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test scripts/lib/harness-refactor-shape.test.mjs`
- `npm run build --workspace=@ioi/agent-ide`
- `npm run validate:autopilot-gui-harness`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T13-15-19-853Z/result.json`
  - `validation.ok === true`;
  - `validation.failures` is empty;
  - `rollback-restore-canary-ui-proof.json` has `passed === true`;
  - `checks.workflowRailSearchModelUi === true`;
  - `checks.workflowRunHistoryModelUi === true`;
  - `checks.workflowUnitTestReadinessModelUi === true`;
  - `checks.workflowSchedulerLaneReadinessActivationUi === true`;
  - `checks.workflowSchedulerRuntimeLane === true`;
  - `sourceRefs` include both
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/searchPanel.tsx`
    and `packages/agent-ide/src/runtime/workflow-rail-search-model.ts`.

## Slice 70. 2026-05-12 - React Flow entrypoints model extraction

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-12T13-32-20-984Z/result.json

Validation evidence:

- `node --import tsx --test packages/agent-ide/src/runtime/workflow-entrypoints-model.test.ts`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --check scripts/lib/harness-refactor-shape.test.mjs`
- `node --import tsx --test packages/agent-ide/src/runtime/workflow-entrypoints-model.test.ts packages/agent-ide/src/runtime/workflow-rail-search-model.test.ts packages/agent-ide/src/runtime/workflow-run-history-model.test.ts packages/agent-ide/src/runtime/workflow-test-readiness-model.test.ts packages/agent-ide/src/runtime/workflow-readiness-model.test.ts`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test scripts/lib/harness-refactor-shape.test.mjs`
- `npm run build --workspace=@ioi/agent-ide`
- `npm run validate:autopilot-gui-harness`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T13-32-20-984Z/result.json`
  - `validation.ok === true`;
  - `validation.failures` is empty;
  - `rollback-restore-canary-ui-proof.json` has `passed === true`;
  - `checks.workflowEntrypointsModelUi === true`;
  - `checks.workflowRailSearchModelUi === true`;
  - `checks.workflowRunHistoryModelUi === true`;
  - `checks.workflowUnitTestReadinessModelUi === true`;
  - `checks.workflowSchedulerLaneReadinessActivationUi === true`;
  - `checks.workflowSchedulerRuntimeLane === true`;
  - `sourceRefs` include both
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/entrypointsPanel.tsx`
    and `packages/agent-ide/src/runtime/workflow-entrypoints-model.ts`.

## Slice 71. 2026-05-12 - React Flow file-bundle model extraction

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-12T13-48-13-986Z/result.json

Validation evidence:

- `node --import tsx --test packages/agent-ide/src/runtime/workflow-file-bundle-model.test.ts`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --check scripts/lib/harness-refactor-shape.test.mjs`
- `node --import tsx --test packages/agent-ide/src/runtime/workflow-file-bundle-model.test.ts packages/agent-ide/src/runtime/workflow-entrypoints-model.test.ts packages/agent-ide/src/runtime/workflow-rail-search-model.test.ts packages/agent-ide/src/runtime/workflow-run-history-model.test.ts packages/agent-ide/src/runtime/workflow-test-readiness-model.test.ts packages/agent-ide/src/runtime/workflow-readiness-model.test.ts`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test scripts/lib/harness-refactor-shape.test.mjs`
- `npm run build --workspace=@ioi/agent-ide`
- `npm run validate:autopilot-gui-harness`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T13-48-13-986Z/result.json`
  - `validation.ok === true`;
  - `validation.failures` is empty;
  - `rollback-restore-canary-ui-proof.json` has `passed === true`;
  - `checks.workflowFileBundleModelUi === true`;
  - `checks.workflowEntrypointsModelUi === true`;
  - `checks.workflowRailSearchModelUi === true`;
  - `checks.workflowRunHistoryModelUi === true`;
  - `checks.workflowUnitTestReadinessModelUi === true`;
  - `checks.workflowSchedulerLaneReadinessActivationUi === true`;
  - `checks.workflowSchedulerRuntimeLane === true`;
  - `sourceRefs` include both
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/filesPanel.tsx`
    and `packages/agent-ide/src/runtime/workflow-file-bundle-model.ts`.

## Slice 72. 2026-05-12 - React Flow settings model extraction

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-12T14-16-54-801Z/result.json

Validation evidence:

- `node --import tsx --test packages/agent-ide/src/runtime/workflow-settings-model.test.ts`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --check scripts/lib/harness-refactor-shape.test.mjs`
- `node --import tsx --test packages/agent-ide/src/runtime/workflow-settings-model.test.ts packages/agent-ide/src/runtime/workflow-file-bundle-model.test.ts packages/agent-ide/src/runtime/workflow-entrypoints-model.test.ts packages/agent-ide/src/runtime/workflow-rail-search-model.test.ts packages/agent-ide/src/runtime/workflow-run-history-model.test.ts packages/agent-ide/src/runtime/workflow-test-readiness-model.test.ts packages/agent-ide/src/runtime/workflow-readiness-model.test.ts`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test scripts/lib/harness-refactor-shape.test.mjs`
- `npm run build --workspace=@ioi/agent-ide`
- `npm run validate:autopilot-gui-harness`
- `npm run validate:autopilot-gui-harness:run`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T14-16-54-801Z/result.json`
  - `validation.ok === true`;
  - `validation.failures` is empty;
  - `rollback-restore-canary-ui-proof.json` has `passed === true`;
  - `checks.workflowSettingsModelUi === true`;
  - `checks.workflowFileBundleModelUi === true`;
  - `checks.workflowEntrypointsModelUi === true`;
  - `checks.workflowRailSearchModelUi === true`;
  - `checks.workflowRunHistoryModelUi === true`;
  - `checks.workflowUnitTestReadinessModelUi === true`;
  - `checks.workflowSchedulerLaneReadinessActivationUi === true`;
  - `checks.workflowSchedulerRuntimeLane === true`;
  - `sourceRefs` include both
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsPanel.tsx`
    and `packages/agent-ide/src/runtime/workflow-settings-model.ts`.

## Slice 73. 2026-05-12 - React Flow settings harness extraction

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-12T14-57-39-502Z/result.json

Validation evidence:

- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/harness-refactor-shape.test.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --import tsx --test packages/agent-ide/src/runtime/workflow-settings-harness-model.test.ts packages/agent-ide/src/runtime/workflow-settings-model.test.ts packages/agent-ide/src/runtime/workflow-file-bundle-model.test.ts packages/agent-ide/src/runtime/workflow-entrypoints-model.test.ts packages/agent-ide/src/runtime/workflow-rail-search-model.test.ts packages/agent-ide/src/runtime/workflow-run-history-model.test.ts packages/agent-ide/src/runtime/workflow-test-readiness-model.test.ts packages/agent-ide/src/runtime/workflow-readiness-model.test.ts`
- `npm run build --workspace=@ioi/agent-ide`
- `npm run validate:autopilot-gui-harness:run`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T14-57-39-502Z/result.json`
  - `validation.ok === true`;
  - `validation.failures` is empty;
  - `rollback-restore-canary-ui-proof.json` has `passed === true`;
  - `checks.workflowSettingsHarnessModelUi === true`;
  - `checks.workflowSettingsModelUi === true`;
  - `checks.workflowFileBundleModelUi === true`;
  - `checks.workflowEntrypointsModelUi === true`;
  - `checks.workflowRailSearchModelUi === true`;
  - `checks.workflowRunHistoryModelUi === true`;
  - `checks.workflowUnitTestReadinessModelUi === true`;
  - `checks.workflowSchedulerLaneReadinessActivationUi === true`;
  - `checks.workflowSchedulerRuntimeLane === true`;
  - `sourceRefs` include
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPanel.tsx`
    and
    `packages/agent-ide/src/runtime/workflow-settings-harness-model.ts`.

## Slice 74. 2026-05-12 - React Flow settings harness typed boundary

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-12T15-19-43-946Z/result.json

Validation evidence:

- `npm run build --workspace=@ioi/agent-ide`
- `node --test scripts/lib/harness-refactor-shape.test.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --import tsx --test packages/agent-ide/src/runtime/workflow-settings-harness-model.test.ts packages/agent-ide/src/runtime/workflow-settings-model.test.ts packages/agent-ide/src/runtime/workflow-file-bundle-model.test.ts packages/agent-ide/src/runtime/workflow-entrypoints-model.test.ts packages/agent-ide/src/runtime/workflow-rail-search-model.test.ts packages/agent-ide/src/runtime/workflow-run-history-model.test.ts packages/agent-ide/src/runtime/workflow-test-readiness-model.test.ts packages/agent-ide/src/runtime/workflow-readiness-model.test.ts`
- `npm run validate:autopilot-gui-harness:run`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T15-19-43-946Z/result.json`
  - `validation.ok === true`;
  - `validation.failures` is empty;
  - `rollback-restore-canary-ui-proof.json` has `passed === true`;
  - `checks.workflowSettingsHarnessModelUi === true`;
  - `checks.workflowSettingsModelUi === true`;
  - `sourceRefs` include
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPanel.tsx`
    and
    `packages/agent-ide/src/runtime/workflow-settings-harness-model.ts`.

## Slice 75. 2026-05-12 - React Flow settings harness activation panel extraction

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-12T15-42-11-524Z/result.json

Validation evidence:

- `npm run build --workspace=@ioi/agent-ide`
- `node --test scripts/lib/harness-refactor-shape.test.mjs`
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm run validate:autopilot-gui-harness:run`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T15-42-11-524Z/result.json`
  - `rollback-restore-canary-ui-proof.json` has `passed === true`;
  - `checks.workflowSettingsHarnessModelUi === true`;
  - `checks.activationGateEvidenceInspector === true`;
  - `promotion-transition-live-gui-interaction-proof.json` has
    `passed === true`;
  - `checks.activationGateEvidenceInspectable === true`;
  - `checks.activationGateActionWorkbench === true`;
  - `checks.activationGateActionClickProof === true`;
  - `sourceRefs` include both
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPanel.tsx`
    and
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationPanel.tsx`.

## Slice 76. 2026-05-12 - React Flow settings harness worker-binding and rollback panel extraction

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-12T16-10-00-442Z/result.json

Validation evidence:

- `npm run build --workspace=@ioi/agent-ide`
- `node --test scripts/lib/harness-refactor-shape.test.mjs`
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler`
- `npm run validate:autopilot-gui-harness:run`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T16-10-00-442Z/result.json`
  - `validation.ok === true`;
  - `validation.failures` is empty;
  - `rollback-restore-canary-ui-proof.json` has `passed === true`;
  - `checks.workflowSettingsHarnessModelUi === true`;
  - `checks.workerSessionCheckpointUi === true`;
  - `checks.rollbackExecutionReceiptRefs === true`;
  - `promotion-transition-live-gui-interaction-proof.json` has
    `passed === true`;
  - `checks.activeWorkerBinding === true`;
  - `checks.workerBindingRegistryBound === true`;
  - `checks.workerRollbackLiveShadowGateBound === true`;
  - `checks.activeRuntimeRollbackProofWorkbench === true`;
  - `checks.activeRuntimeRollbackExecutionWorkbench === true`;
  - `checks.activeRuntimeRollbackApplyExecution === true`;
  - `sourceRefs` include
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessWorkerBindingPanel.tsx`,
    and
    `packages/agent-ide/src/runtime/workflow-settings-harness-model.ts`.

## Slice 77. 2026-05-12 - React Flow settings harness promotion panel extraction

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-12T16-27-56-146Z/result.json

Validation evidence:

- `npm run build --workspace=@ioi/agent-ide`
- `node --test scripts/lib/harness-refactor-shape.test.mjs`
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler`
- `npm run validate:autopilot-gui-harness:run`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T16-27-56-146Z/result.json`
  - `validation.ok === true`;
  - `validation.failures` is empty;
  - `rollback-restore-canary-ui-proof.json` has `passed === true`;
  - `checks.workflowSettingsHarnessModelUi === true`;
  - `checks.promotionTransitionControls === true`;
  - `checks.workerSessionCheckpointUi === true`;
  - `promotion-transition-live-gui-interaction-proof.json` has
    `passed === true`;
  - `checks.livePromotionReadinessBound === true`;
  - `checks.activeWorkerBinding === true`;
  - `checks.workerBindingRegistryBound === true`;
  - `checks.activeRuntimeRollbackProofWorkbench === true`;
  - `checks.activeRuntimeRollbackApplyExecution === true`;
  - `sourceRefs` include
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessWorkerBindingPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPromotionPanel.tsx`,
    and
    `packages/agent-ide/src/runtime/workflow-settings-harness-model.ts`.

## Slice 78. 2026-05-12 - React Flow settings harness type contract extraction

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-12T16-41-58-495Z/result.json

Validation evidence:

- `npm run build --workspace=@ioi/agent-ide`
- `node --test scripts/lib/harness-refactor-shape.test.mjs`
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler`
- `npm run validate:autopilot-gui-harness:run`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T16-41-58-495Z/result.json`
  - `validation.ok === true`;
  - `validation.failures` is empty;
  - `rollback-restore-canary-ui-proof.json` has `passed === true`;
  - `checks.workflowSettingsHarnessModelUi === true`;
  - `checks.promotionTransitionControls === true`;
  - `checks.workerSessionCheckpointUi === true`;
  - `promotion-transition-live-gui-interaction-proof.json` has
    `passed === true`;
  - `checks.livePromotionReadinessBound === true`;
  - `checks.activeWorkerBinding === true`;
  - `checks.workerBindingRegistryBound === true`;
  - `checks.activeRuntimeRollbackProofWorkbench === true`;
  - `checks.activeRuntimeRollbackApplyExecution === true`;
  - `sourceRefs` include
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessTypes.ts`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessWorkerBindingPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPromotionPanel.tsx`,
    and
    `packages/agent-ide/src/runtime/workflow-settings-harness-model.ts`.

## Slice 79. 2026-05-12 - React Flow settings harness active runtime rollback panel extraction

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-12T17-11-04-005Z/result.json

Validation evidence:

- `npm run build --workspace=@ioi/agent-ide`
- `node --test scripts/lib/harness-refactor-shape.test.mjs`
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler`
- `npm run validate:autopilot-gui-harness:run`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T17-11-04-005Z/result.json`
  - `validation.ok === true`;
  - `validation.failures` is empty;
  - `rollback-restore-canary-ui-proof.json` has `passed === true`;
  - `checks.workflowSettingsHarnessModelUi === true`;
  - `checks.workerSessionCheckpointUi === true`;
  - `checks.rollbackExecutionReceiptRefs === true`;
  - `checks.promotionTransitionControls === true`;
  - `promotion-transition-live-gui-interaction-proof.json` has
    `passed === true`;
  - `checks.livePromotionReadinessBound === true`;
  - `checks.activeWorkerBinding === true`;
  - `checks.workerBindingRegistryBound === true`;
  - `checks.activeRuntimeRollbackProofWorkbench === true`;
  - `checks.activeRuntimeRollbackExecutionWorkbench === true`;
  - `checks.activeRuntimeRollbackApplyExecution === true`;
  - `checks.activeRuntimeRollbackNegativeApply === true`;
  - rollback/restore and promotion live proof `sourceRefs` include
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessTypes.ts`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessWorkerBindingPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActiveRuntimeRollbackPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPromotionPanel.tsx`,
    and
    `packages/agent-ide/src/runtime/workflow-settings-harness-model.ts`.

## Slice 80. 2026-05-12 - React Flow settings harness rollback restore proof panel extraction

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-12T17-29-45-390Z/result.json

Validation evidence:

- `npm run build --workspace=@ioi/agent-ide`
- `node --test scripts/lib/harness-refactor-shape.test.mjs`
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler`
- `npm run validate:autopilot-gui-harness:run`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T17-29-45-390Z/result.json`
  - `validation.ok === true`;
  - `validation.failures` is empty;
  - `rollback-restore-canary-ui-proof.json` has `passed === true`;
  - `checks.workflowSettingsHarnessModelUi === true`;
  - `checks.workerSessionCheckpointUi === true`;
  - `checks.rollbackExecutionReceiptRefs === true`;
  - `checks.promotionTransitionControls === true`;
  - `promotion-transition-live-gui-interaction-proof.json` has
    `passed === true`;
  - `checks.livePromotionReadinessBound === true`;
  - `checks.activeWorkerBinding === true`;
  - `checks.workerBindingRegistryBound === true`;
  - `checks.activeRuntimeRollbackProofWorkbench === true`;
  - `checks.activeRuntimeRollbackExecutionWorkbench === true`;
  - `checks.activeRuntimeRollbackApplyExecution === true`;
  - `checks.activeRuntimeRollbackNegativeApply === true`;
  - rollback/restore and promotion live proof `sourceRefs` include
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessTypes.ts`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessWorkerBindingPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActiveRuntimeRollbackPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessRollbackRestoreProofPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPromotionPanel.tsx`,
    and
    `packages/agent-ide/src/runtime/workflow-settings-harness-model.ts`.

## Slice 81. 2026-05-12 - React Flow settings harness active runtime binding panel extraction

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-12T17-46-33-581Z/result.json

Validation evidence:

- `npm run build --workspace=@ioi/agent-ide`
- `node --test scripts/lib/harness-refactor-shape.test.mjs`
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler`
- `npm run validate:autopilot-gui-harness:run`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T17-46-33-581Z/result.json`
  - `validation.ok === true`;
  - `validation.failures` is empty;
  - `rollback-restore-canary-ui-proof.json` has `passed === true`;
  - `checks.workflowSettingsHarnessModelUi === true`;
  - `checks.workerSessionCheckpointUi === true`;
  - `checks.rollbackExecutionReceiptRefs === true`;
  - `checks.promotionTransitionControls === true`;
  - `promotion-transition-live-gui-interaction-proof.json` has
    `passed === true`;
  - `checks.livePromotionReadinessBound === true`;
  - `checks.activeWorkerBinding === true`;
  - `checks.workerBindingRegistryBound === true`;
  - `checks.activeRuntimeRollbackProofWorkbench === true`;
  - `checks.activeRuntimeRollbackExecutionWorkbench === true`;
  - `checks.activeRuntimeRollbackApplyExecution === true`;
  - `checks.activeRuntimeRollbackNegativeApply === true`;
  - rollback/restore and promotion live proof `sourceRefs` include
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessTypes.ts`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessWorkerBindingPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActiveRuntimeBindingPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActiveRuntimeRollbackPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessRollbackRestoreProofPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPromotionPanel.tsx`,
    and
    `packages/agent-ide/src/runtime/workflow-settings-harness-model.ts`.

## Slice 82. 2026-05-12 - React Flow settings harness activation gate panel extraction

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-12T18-07-42-338Z/result.json

Validation evidence:

- `npm run build --workspace=@ioi/agent-ide`
- `node --test scripts/lib/harness-refactor-shape.test.mjs`
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler`
- `npm run validate:autopilot-gui-harness:run`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T18-07-42-338Z/result.json`
  - `validation.ok === true`;
  - `validation.failures` is empty;
  - `rollback-restore-canary-ui-proof.json` has `passed === true`;
  - `checks.workflowSettingsHarnessModelUi === true`;
  - `checks.activationGateEvidenceInspector === true`;
  - `checks.workerSessionCheckpointUi === true`;
  - `checks.rollbackExecutionReceiptRefs === true`;
  - `checks.promotionTransitionControls === true`;
  - `promotion-transition-live-gui-interaction-proof.json` has
    `passed === true`;
  - `checks.livePromotionReadinessBound === true`;
  - `checks.activeWorkerBinding === true`;
  - `checks.workerBindingRegistryBound === true`;
  - `checks.activeRuntimeRollbackProofWorkbench === true`;
  - `checks.activeRuntimeRollbackExecutionWorkbench === true`;
  - `checks.activeRuntimeRollbackApplyExecution === true`;
  - `checks.activeRuntimeRollbackNegativeApply === true`;
  - rollback/restore and promotion live proof `sourceRefs` include
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessTypes.ts`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationGatePanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessWorkerBindingPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActiveRuntimeBindingPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActiveRuntimeRollbackPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessRollbackRestoreProofPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPromotionPanel.tsx`,
    and
    `packages/agent-ide/src/runtime/workflow-settings-harness-model.ts`.

## Slice 83. 2026-05-12 - React Flow settings harness promotion readiness panel extraction

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-12T18-24-22-311Z/result.json

Validation evidence:

- `npm run build --workspace=@ioi/agent-ide`
- `node --test scripts/lib/harness-refactor-shape.test.mjs`
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler`
- `npm run validate:autopilot-gui-harness:run`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T18-24-22-311Z/result.json`
  - `validation.ok === true`;
  - `validation.failures` is empty;
  - `rollback-restore-canary-ui-proof.json` has `passed === true`;
  - `checks.workflowSettingsHarnessModelUi === true`;
  - `checks.activationGateEvidenceInspector === true`;
  - `checks.workerSessionCheckpointUi === true`;
  - `checks.rollbackExecutionReceiptRefs === true`;
  - `checks.promotionTransitionControls === true`;
  - `promotion-transition-live-gui-interaction-proof.json` has
    `passed === true`;
  - `checks.livePromotionReadinessBound === true`;
  - `checks.activeWorkerBinding === true`;
  - `checks.workerBindingRegistryBound === true`;
  - `checks.activeRuntimeRollbackProofWorkbench === true`;
  - `checks.activeRuntimeRollbackExecutionWorkbench === true`;
  - `checks.activeRuntimeRollbackApplyExecution === true`;
  - `checks.activeRuntimeRollbackNegativeApply === true`;
  - rollback/restore and promotion live proof `sourceRefs` include
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessTypes.ts`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationGatePanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessWorkerBindingPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActiveRuntimeBindingPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActiveRuntimeRollbackPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessRollbackRestoreProofPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPromotionPanel.tsx`,
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPromotionReadinessPanel.tsx`,
    and
    `packages/agent-ide/src/runtime/workflow-settings-harness-model.ts`.

## Slice 84. 2026-05-12 - React Flow settings harness package evidence panel extraction

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-12T18-46-56-765Z/result.json

Validation evidence:

- `npm run build --workspace=@ioi/agent-ide`
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/harness-refactor-shape.test.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler`
- `npm run validate:autopilot-gui-harness:run`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T18-46-56-765Z/result.json`
  - `validation.ok === true`;
  - `validation.failures` is empty;
  - `rollback-restore-canary-ui-proof.json` has `passed === true`;
  - `checks.workflowSettingsHarnessModelUi === true`;
  - `checks.activationGateEvidenceInspector === true`;
  - `checks.workerSessionCheckpointUi === true`;
  - `checks.rollbackExecutionReceiptRefs === true`;
  - `checks.promotionTransitionControls === true`;
  - rollback proof `sourceRefs` include
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPackageEvidencePanel.tsx`;
  - `promotion-transition-live-gui-interaction-proof.json` has
    `passed === true`;
  - `checks.packageEvidenceGateClickProof === true`;
  - `checks.packageEvidenceImportRoundTripProof === true`;
  - `checks.packageImportReviewProof === true`;
  - `checks.packageImportActivationHandoffProof === true`;
  - `checks.packageImportActivationApplyProof === true`;
  - `checks.packageImportActivationReplayIntegrityProof === true`;
  - `checks.livePromotionReadinessBound === true`;
  - `checks.activeWorkerBinding === true`;
  - `checks.workerBindingRegistryBound === true`;
  - `checks.activeRuntimeRollbackProofWorkbench === true`;
  - `checks.activeRuntimeRollbackExecutionWorkbench === true`;
  - `checks.activeRuntimeRollbackApplyExecution === true`;
  - `checks.activeRuntimeRollbackNegativeApply === true`;
  - promotion live proof `sourceRefs` include
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPackageEvidencePanel.tsx`.

## Slice 85. 2026-05-12 - React Flow settings harness activation gate refs/timeline extraction

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-12T19-05-02-607Z/result.json

Validation evidence:

- `npm run build --workspace=@ioi/agent-ide`
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/harness-refactor-shape.test.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler`
- `npm run validate:autopilot-gui-harness:run`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T19-05-02-607Z/result.json`
  - `validation.ok === true`;
  - `validation.failures` is empty;
  - `rollback-restore-canary-ui-proof.json` has `passed === true`;
  - `checks.workflowSettingsHarnessModelUi === true`;
  - `checks.activationGateEvidenceInspector === true`;
  - `checks.workerSessionCheckpointUi === true`;
  - `checks.rollbackExecutionReceiptRefs === true`;
  - `checks.promotionTransitionControls === true`;
  - rollback proof `sourceRefs` include
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationGateRefsPanel.tsx`
    and
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationGateTimelinePanel.tsx`;
  - `promotion-transition-live-gui-interaction-proof.json` has
    `passed === true`;
  - `checks.routeStatefulActivationGateReferenceDeepLinks === true`;
  - `checks.activationGateMutationCanaryNodeInspectorDeepLink === true`;
  - `checks.activationGateNodeTimelineDeepLink === true`;
  - `checks.livePromotionReadinessBound === true`;
  - `checks.activeWorkerBinding === true`;
  - `checks.workerBindingRegistryBound === true`;
  - `checks.activeRuntimeRollbackProofWorkbench === true`;
  - `checks.activeRuntimeRollbackExecutionWorkbench === true`;
  - `checks.activeRuntimeRollbackApplyExecution === true`;
  - `checks.activeRuntimeRollbackNegativeApply === true`;
  - promotion live proof `sourceRefs` include
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationGateRefsPanel.tsx`
    and
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationGateTimelinePanel.tsx`.

## Slice 86. 2026-05-12 - React Flow settings harness package import/rows extraction

Guide section: P2. Localization And Accessibility

Evidence bundles:

- docs/evidence/autopilot-gui-harness-validation/2026-05-12T19-30-56-229Z/result.json

Validation evidence:

- `npm run build --workspace=@ioi/agent-ide`
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
- `node --test scripts/lib/harness-refactor-shape.test.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scheduler`
- `npm run validate:autopilot-gui-harness:run`
- live GUI/workflow harness:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-12T19-30-56-229Z/result.json`
  - `validation.ok === true`;
  - `validation.failures` is empty;
  - `rollback-restore-canary-ui-proof.json` has `passed === true`;
  - `checks.workflowSettingsHarnessModelUi === true`;
  - `checks.activationGateEvidenceInspector === true`;
  - `checks.workerSessionCheckpointUi === true`;
  - `checks.rollbackExecutionReceiptRefs === true`;
  - `checks.promotionTransitionControls === true`;
  - rollback proof `sourceRefs` include
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPackageImportReviewPanel.tsx`
    and
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPackageEvidenceRowsPanel.tsx`;
  - `promotion-transition-live-gui-interaction-proof.json` has
    `passed === true`;
  - `checks.packageEvidenceGateClickProof === true`;
  - `checks.packageEvidenceImportRoundTripProof === true`;
  - `checks.packageImportReviewProof === true`;
  - `checks.packageImportActivationHandoffProof === true`;
  - `checks.packageImportActivationApplyProof === true`;
  - `checks.packageImportActivationReplayIntegrityProof === true`;
  - `checks.coldStartDeepLinkRestore === true`;
  - `checks.livePromotionReadinessBound === true`;
  - `checks.activeWorkerBinding === true`;
  - `checks.workerBindingRegistryBound === true`;
  - `checks.activeRuntimeRollbackProofWorkbench === true`;
  - `checks.activeRuntimeRollbackExecutionWorkbench === true`;
  - `checks.activeRuntimeRollbackApplyExecution === true`;
  - `checks.activeRuntimeRollbackNegativeApply === true`;
  - promotion live proof `sourceRefs` include
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPackageImportReviewPanel.tsx`
    and
    `packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPackageEvidenceRowsPanel.tsx`.

## Slice 87. 2026-05-12 - live bridge TTI/event contract lock

Guide section: P0. Live Runtime API Bridge

Evidence bundles:

- docs/specs/runtime/agent-runtime-live-bridge-tti-event-contract.md

Validation evidence:

- docs integrity check:
  - master guide has no inline completed-slice blocks;
  - master guide has no inline validation evidence blocks;
  - implementation and validation ledgers have matching slice counts;
  - referenced evidence result paths exist.
- `git diff --check`

## Slice 88. 2026-05-12 - live bridge TTI schema snapshots

Guide section: P0. Live Runtime API Bridge

Evidence bundles:

- scripts/lib/live-bridge-tti-schema-contract.test.mjs

Validation evidence:

- `node --test scripts/lib/live-bridge-tti-schema-contract.test.mjs`
  - Rust and TypeScript schema literals match for thread, turn, item, and event
    records;
  - literal arrays match for modes, approval modes, statuses, item kinds,
    actors, and event sources;
  - `RuntimeThreadRecord`, `RuntimeTurnRecord`, `RuntimeItemRecord`, and
    `RuntimeEventEnvelope` required fields match across Rust and TypeScript;
  - `runtime_contracts.rs` and the SDK root export the locked contracts.
- `npm run build:agent-sdk`
- `cargo test -p ioi-types thread_turn_item --lib`
- `cargo check -p ioi-types`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
  - 11 daemon/API contract subtests passed, including the existing
    Agentgres-backed thread/turn/event projection smoke.
- `git diff --check`

## Slice 89. 2026-05-12 - daemon runtime event-store spine

Guide section: P0. Live Runtime API Bridge

Evidence bundles:

- scripts/lib/live-runtime-daemon-contract.test.mjs

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `node --test scripts/lib/live-bridge-tti-schema-contract.test.mjs`
  - 4 schema snapshot contract subtests passed.
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
  - 12 daemon/API contract subtests passed;
  - append-only event-store subtest proved seq `1, 2`, duplicate idempotency
    returning seq `1`, `since_seq=1` replay returning seq `2`, and restart
    persistence preserving the original payload;
  - thread event replay emits `ioi.runtime.event.v1` rows and returns
    `event_cursor_out_of_range` for a future cursor.
- `git diff --check`

## Slice 90. 2026-05-12 - runtime event replay alias parity

Guide section: P0. Live Runtime API Bridge

Evidence bundles:

- scripts/lib/live-runtime-daemon-contract.test.mjs
- packages/agent-sdk/test/sdk.test.mjs

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
- `npm run build:agent-sdk`
- `npm test --workspace=@ioi/agent-sdk`
  - 10 SDK subtests passed, including stream reconnect cursor behavior and
    daemon-backed public substrate HTTP usage.
- `node --test scripts/lib/live-bridge-tti-schema-contract.test.mjs`
  - 4 schema snapshot contract subtests passed.
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
  - 12 daemon/API contract subtests passed;
  - thread replay accepts `since_seq`, `Last-Event-ID` sequence cursors, and
    `Last-Event-ID` event-id cursors;
  - `/v1/threads/{id}/events/stream` returns the same stored event ids as
    `/events`;
  - `/v1/runs/{id}/events` and `/v1/runs/{id}/replay` return the owning turn's
    stored event ids;
  - future cursors return `event_cursor_out_of_range` with `latestSeq`.

## Slice 91. 2026-05-12 - RuntimeApiBridge boundary and turn projection

Guide section: P0. Live Runtime API Bridge

Evidence bundles:

- scripts/lib/live-runtime-daemon-contract.test.mjs
- packages/runtime-daemon/src/runtime-api-bridge.mjs

Validation evidence:

- `node --check packages/runtime-daemon/src/runtime-api-bridge.mjs`
- `node --check packages/runtime-daemon/src/index.mjs`
- `npm test --workspace=@ioi/agent-sdk`
  - 10 SDK subtests passed.
- `node --test scripts/lib/live-bridge-tti-schema-contract.test.mjs`
  - 4 schema snapshot contract subtests passed.
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
  - 13 daemon/API contract subtests passed;
  - `runtime_profile=runtime_service` fails closed without `RuntimeApiBridge`;
  - injected bridge thread start persists a `thread.started` event with
    `fixture_profile: null`;
  - injected bridge turn submission persists `turn.started` and
    `turn.completed` rows and returns a locked `RuntimeTurnRecord`;
  - `/v1/runs/{id}/events` returns the bridge-backed owning turn event ids.

## Slice 92. 2026-05-12 - RuntimeAgentService command bridge adapter

Guide section: P0. Live Runtime API Bridge

Evidence bundles:

- scripts/lib/live-runtime-daemon-contract.test.mjs
- packages/runtime-daemon/src/runtime-agent-service-adapter.mjs

Validation evidence:

- `node --check packages/runtime-daemon/src/runtime-agent-service-adapter.mjs`
- `node --check packages/runtime-daemon/src/runtime-api-bridge.mjs`
- `node --check packages/runtime-daemon/src/index.mjs`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
- `npm test --workspace=@ioi/agent-sdk`
  - 10 SDK subtests passed.
- `node --test scripts/lib/live-bridge-tti-schema-contract.test.mjs`
  - 4 schema snapshot contract subtests passed.
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
  - 14 daemon/API contract subtests passed;
  - `runtime_profile=runtime_service` still fails closed without a bridge;
  - env-configured `IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND` starts a
    command bridge using `ioi.runtime.bridge.command.v1`;
  - command bridge `start_thread` persists `thread.started` with
    `source_event_kind=RuntimeAgentService.handle_service_call.start@v1`;
  - command bridge `submit_turn` persists `turn.started` and `turn.completed`
    over the same stored event stream with `fixture_profile: null`;
  - command bridge trace proves `start_thread` and `submit_turn` both received
    the schema version, bridge id, runtime profile, thread id, and runtime
    session id expected by the adapter boundary.
- `git diff --check`

## Slice 93. 2026-05-12 - Rust RuntimeAgentService bridge executable

Guide section: P0. Live Runtime API Bridge

Evidence bundles:

- crates/node/src/bin/ioi-runtime-bridge.rs
- crates/node/Cargo.toml

Validation evidence:

- `cargo check -p ioi-node --bin ioi-runtime-bridge --features local-mode`
  - targeted local-mode bridge binary compiled successfully.
- `cargo build -p ioi-node --bin ioi-runtime-bridge --features local-mode`
  - produced `target/debug/ioi-runtime-bridge` for live command-protocol smoke.
- `cargo test -p ioi-node --bin ioi-runtime-bridge --features local-mode`
  - 2 unit tests passed:
    - bridge request accepts `schemaVersion`/`bridgeId` aliases;
    - TTI events preserve `source=runtime_service`, `fixture_profile=null`, and
      the thread event stream id.
- Two-invocation command smoke using `target/debug/ioi-runtime-bridge`
  - `start_thread` returned a runtime session id and `thread.started`;
  - a second process invocation called `submit_turn` with that session id and
    returned `turn.started` plus terminal `turn.completed`;
  - the terminal event came from the Rust runtime-owned step path rather than a
    daemon fixture projection.
- Daemon env-adapter smoke with
  `IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND=target/debug/ioi-runtime-bridge`
  - `POST /v1/threads` returned a Rust-backed runtime session with
    `fixture_profile: null`;
  - `POST /v1/threads/{id}/turns` returned a Rust-backed turn;
  - `/v1/threads/{id}/events?since_seq=0` replayed
    `thread.started`, `turn.started`, and `turn.completed` from
    `source=runtime_service`.
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
  - 14 daemon/API contract subtests passed after the Rust bridge executable
    landed.
- `git diff --check`

## Slice 94. 2026-05-12 - Daemon Rust bridge executable contract

Guide section: P0. Live Runtime API Bridge

Evidence bundles:

- scripts/lib/live-runtime-daemon-contract.test.mjs
- crates/node/src/bin/ioi-runtime-bridge.rs

Validation evidence:

- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
- `cargo check -p ioi-node --bin ioi-runtime-bridge --features local-mode`
- `cargo test -p ioi-node --bin ioi-runtime-bridge --features local-mode`
  - 2 bridge executable unit tests passed.
- `node --test scripts/lib/live-bridge-tti-schema-contract.test.mjs`
  - 4 TTI schema snapshot subtests passed.
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
  - 15 daemon/API contract subtests passed;
  - the new Rust executable contract builds or uses
    `IOI_RUNTIME_BRIDGE_RUST_BIN`, then wires
    `IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND` to the real
    `ioi-runtime-bridge` binary;
  - `POST /v1/threads` with `runtime_profile=runtime_service` returns a
    Rust-backed session id, `runtime_bridge_id`, and `fixture_profile: null`;
  - `POST /v1/threads/{id}/turns` returns a Rust-backed turn with
    runtime-owned `run_runtime_service_*` and `turn_runtime_service_*` ids;
  - replay returns `thread.started`, `turn.started`, and a terminal runtime
    event from `RuntimeAgentService.handle_service_call.*` source kinds, all
    from `source=runtime_service` and `fixture_profile: null`;
  - `/v1/runs/{id}/events` aliases the same stored turn event ids.
- `npm test --workspace=@ioi/agent-sdk`
  - 10 SDK subtests passed.
- `node --test scripts/lib/autopilot-gui-harness-contract.test.mjs`
  - 10 GUI harness contract subtests passed.
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-preflight`
  - preflight passed and wrote a temporary result bundle outside the worktree.
- `git diff --check`

## Slice 95. 2026-05-12 - KernelEvent bridge mapper foundation

Guide section: P0. Live Runtime API Bridge

Evidence bundles:

- crates/node/src/runtime_bridge_events.rs
- crates/node/src/bin/ioi-runtime-bridge.rs
- scripts/lib/live-runtime-daemon-contract.test.mjs

Validation evidence:

- `cargo fmt --package ioi-node`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
- `cargo check -p ioi-node --bin ioi-runtime-bridge --features local-mode`
- `cargo test -p ioi-node --bin ioi-runtime-bridge --features local-mode`
  - 6 bridge executable and mapper unit tests passed;
  - mapper coverage locks `KernelEvent::AgentThought` to
    `reasoning.delta`, `KernelEvent::AgentActionResult` to
    `tool.completed` or `tool.failed`, `KernelEvent::FirewallInterception`
    to `approval.required` or `policy.blocked`, and
    `KernelEvent::WorkloadReceipt` to `receipt.emitted`.
- `node --test scripts/lib/live-bridge-tti-schema-contract.test.mjs`
  - 4 TTI schema snapshot subtests passed.
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
  - 15 daemon/API contract subtests passed;
  - the Rust bridge contract now observes a live
    `KernelEvent::AgentActionResult` from `RuntimeAgentService`, maps it to
    `tool.completed` with `component_kind=tool_result`, and replays it between
    `turn.started` and the terminal runtime-service turn event;
  - `/v1/runs/{id}/events` aliases the same stored mapped KernelEvent row.
- `npm test --workspace=@ioi/agent-sdk`
  - 10 SDK subtests passed.
- `node --test scripts/lib/autopilot-gui-harness-contract.test.mjs`
  - 10 GUI harness contract subtests passed.
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-preflight`
  - GUI harness preflight passed outside the worktree.
- `git diff --check`

## Slice 96. 2026-05-12 - SDK Thread/Turn canonical event projection

Guide section: P0. Live Runtime API Bridge

Evidence bundles:

- packages/agent-sdk/src/thread.ts
- packages/agent-sdk/src/runtime-events.ts
- packages/agent-sdk/src/substrate-client.ts
- packages/agent-sdk/test/sdk.test.mjs
- scripts/lib/live-runtime-daemon-contract.test.mjs

Validation evidence:

- `npm run typecheck --workspace=@ioi/agent-sdk`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test scripts/lib/live-bridge-tti-schema-contract.test.mjs`
  - 4 TTI schema snapshot subtests passed after keeping
    `RuntimeEventEnvelope` exact and moving daemon convenience fields into
    projection-only parsing.
- `npm test --workspace=@ioi/agent-sdk`
  - 11 SDK subtests passed;
  - the new Thread/Turn wrapper test proves canonical daemon
    `RuntimeEventEnvelope` rows become typed SDK runtime events, including
    mapped `KernelEvent::AgentActionResult` metadata.
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live daemon contract validates `Thread.open(...).events({ sinceSeq: 0 })`
    over a Rust runtime-service thread and confirms the mapped KernelEvent row
    projects to `tool_completed` or `tool_failed` with
    `componentKind=tool_result`, `workflowNodeId=runtime.tool-result`,
    `toolName=system::intent_clarification`, `agentStatus=Paused`, and
    `stepIndex=0`.
- `node --test scripts/lib/autopilot-gui-harness-contract.test.mjs`
  - 10 GUI harness contract subtests passed.
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-sdk-thread-turn-final`
  - preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-sdk-thread-turn-final/2026-05-12T21-56-13-739Z/result.json`.

## Slice 97. 2026-05-12 - React Flow runtime event projection over Thread.events

Guide section: P0. Live Runtime API Bridge

Evidence bundles:

- packages/agent-ide/src/runtime/workflow-runtime-event-projection.ts
- packages/agent-ide/src/runtime/workflow-runtime-diagnostics-repair-actions.ts
- packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts
- scripts/lib/workflow-runtime-event-projection-contract.test.mjs
- docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md

Validation evidence:

- `npm run build --workspace=@ioi/agent-ide`
  - TypeScript and Vite build passed after proving the projection compiles
    under the package's ES2020 target.
- `node --test scripts/lib/workflow-runtime-event-projection-contract.test.mjs`
  - Source contract passed, locking the schema id, canonical event fields,
    React Flow node/edge outputs, and reasoning/tool/approval/policy/receipt/
    router event families.
- Built-bundle smoke import of
  `projectRuntimeThreadEventsToWorkflowProjection`
  - projected a reasoning-to-tool event sample as 2 React Flow nodes, 1 edge,
    and `latestEventId=e2`.
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
  - 15 daemon/API contract subtests passed, preserving the live
    runtime-service replay path that supplies the canonical thread events.
- `node --test scripts/lib/autopilot-gui-harness-contract.test.mjs`
  - 10 GUI harness contract subtests passed.
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-reactflow-runtime-event-projection`
  - preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-reactflow-runtime-event-projection/2026-05-12T22-04-30-270Z/result.json`.

## Slice 98. 2026-05-12 - Workflow run inspector runtime event graph

Guide section: P0. Live Runtime API Bridge

Evidence bundles:

- packages/agent-ide/src/runtime/workflow-run-history-model.ts
- packages/agent-ide/src/features/Workflows/WorkflowRailPanel/runsPanel.tsx
- packages/agent-ide/src/WorkflowComposer/controller.tsx
- apps/autopilot/src/services/TauriRuntime.ts
- scripts/lib/workflow-runtime-event-projection-contract.test.mjs

Validation evidence:

- `npm run build --workspace=@ioi/agent-ide`
  - TypeScript and Vite build passed with the run inspector projection,
    controller loader, graph runtime type, and CSS updates.
- `node --test scripts/lib/workflow-runtime-event-projection-contract.test.mjs`
  - Source contract passed, locking the controller loader, runtime event model
    projection, run inspector graph test ids, and evidence-ref data attributes.
- Built-bundle smoke import of
  `projectRuntimeThreadEventsToWorkflowProjection`
  - projected policy/receipt canonical events as 2 React Flow nodes with
    `latestCursor=events_thread:5`.
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
  - 15 daemon/API contract subtests passed, including the React Flow source
    contract checks for runtime event graph inspector wiring.
- `node --test scripts/lib/autopilot-gui-harness-contract.test.mjs`
  - 10 GUI harness contract subtests passed.
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-runtime-event-inspector`
  - preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-runtime-event-inspector/2026-05-12T22-17-29-609Z/result.json`.

## Slice 99. 2026-05-12 - CLI/TUI runtime event stream command

Guide section: P0. Live Runtime API Bridge

Evidence bundles:

- crates/cli/src/commands/agent_event_stream.rs
- crates/cli/src/commands/agent.rs
- crates/cli/src/commands/mod.rs
- scripts/lib/live-runtime-daemon-contract.test.mjs
- docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md

Validation evidence:

- `cargo fmt --package ioi-cli`
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
- `cargo test -p ioi-cli --bin cli commands::agent`
  - 7 CLI binary unit tests passed;
  - coverage includes `agent stream` argument parsing, canonical thread/run
    route construction, `since_seq`, `Last-Event-ID`, SSE parsing, and compact
    mapped KernelEvent row formatting.
- `cargo check -p ioi-cli --bin cli`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
  - 15 daemon/API contract subtests passed;
  - the source contract now locks `AgentCommands::Stream`,
    `AgentEventStreamArgs`, `/v1/threads/{id}/events`,
    `/v1/threads/{id}/events/stream`, `/v1/runs/{id}/events`, cursor support,
    SSE parsing, and the event evidence fields consumed by CLI/TUI.
- `cargo build -p ioi-cli --bin cli`
- Ad hoc live daemon CLI replay:
  - started a runtime daemon, appended a mapped
    `KernelEvent::AgentActionResult`-shaped row, and verified
    `target/debug/cli agent stream` read the stored event by JSON and compact
    output;
  - compact output included `source=KernelEvent::AgentActionResult`,
    `component=tool_result`, `node=runtime.tool-result`,
    `receipts=[receipt_cli_stream_validation]`, and
    `policies=[policy_cli_stream_validation]`;
  - mapped event id:
    `thread_4e6cec3d-c755-4a17-b1bd-432b84e347f1:events:seq:00000002`.
- `node --test scripts/lib/workflow-runtime-event-projection-contract.test.mjs`
  - React Flow canonical Thread.events projection contract passed.
- `node --test scripts/lib/autopilot-gui-harness-contract.test.mjs`
  - 10 GUI harness contract subtests passed.
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-cli-event-stream`
  - preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-cli-event-stream/2026-05-12T22-34-03-536Z/result.json`.
- `git diff --check`

Known validation note:

- `cargo test -p ioi-cli commands::agent` is not a valid scoped signal for this
  slice because Cargo still compiles unrelated CLI integration tests first; the
  current integration fixtures fail on pre-existing `StartAgentParams`
  initializers missing `runtime_route_frame`. The passing binary-only tests and
  `cargo check -p ioi-cli --bin cli` validate the changed command surface.

## Slice 100. 2026-05-12 - Cross-surface same-sequence KernelEvent proof

Guide section: P0. Live Runtime API Bridge

Evidence bundles:

- scripts/lib/live-runtime-daemon-contract.test.mjs
- docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md
- docs/specs/runtime/agent-runtime-deepseek-parity-plus-implementation-log.md

Validation evidence:

- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
- `node --test scripts/lib/live-runtime-daemon-contract.test.mjs`
  - 16 daemon/API contract subtests passed;
  - `runtime_service` mode used the Rust `ioi-runtime-bridge`;
  - one mapped `KernelEvent::AgentActionResult` row was captured from daemon
    SSE replay and found by exact `event_id` through SDK `Thread.events()`,
    CLI/TUI `agent stream --json`, and the React Flow
    `projectRuntimeThreadEventsToWorkflowProjection(...)` output;
  - the proof locked identical `seq`, cursor, `event_kind`,
    `source_event_kind`, `component_kind`, `workflow_node_id`, payload schema,
    receipt refs, policy refs, artifact refs, and rollback refs.
- `cargo check -p ioi-cli --bin cli`
- `node --test scripts/lib/workflow-runtime-event-projection-contract.test.mjs`
  - React Flow canonical Thread.events projection source contract passed.
- `node --test scripts/lib/autopilot-gui-harness-contract.test.mjs`
  - 10 GUI harness contract subtests passed.
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-cross-surface-event-seq`
  - preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-cross-surface-event-seq/2026-05-12T22-40-35-479Z/result.json`.

## Slice 101. 2026-05-12 - Live operator interrupt turn-control event

Guide section: P0. Live Runtime API Bridge

Evidence bundles:

- packages/runtime-daemon/src/index.mjs
- packages/agent-sdk/src/thread.ts
- crates/cli/src/commands/agent.rs
- packages/agent-ide/src/runtime/workflow-runtime-event-projection.ts
- scripts/lib/live-runtime-daemon-contract.test.mjs
- docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md
- docs/specs/runtime/agent-runtime-deepseek-parity-plus-implementation-log.md

Validation evidence:

- `npm run build --workspace=@ioi/agent-sdk`
  - SDK declarations and dist bundle rebuilt with `Turn.interrupt(...)` and
    `turn_interrupted` event typing.
- `npm run build --workspace=@ioi/agent-ide`
  - React Flow projection bundle rebuilt with `turn_interrupted` support.
- `cargo test -p ioi-cli --bin cli parses_agent_operator_surface_commands`
  - CLI parser accepted `agent interrupt --thread-id ... --turn-id ...`.
- `node --test packages/agent-sdk/test/sdk.test.mjs`
  - 11 SDK subtests passed, including the daemon HTTP wrapper proof for
    `Turn.interrupt(...)`.
- `node --test scripts/lib/workflow-runtime-event-projection-contract.test.mjs`
  - React Flow source contract passed with `turn_interrupted`.
- `node --test --test-name-pattern "operator interrupt keeps one canonical control event" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live Rust runtime-service proof passed;
  - CLI/TUI `agent interrupt` appended one canonical `turn.interrupted` event;
  - SDK and React Flow found the same `event_id`, `seq`, cursor,
    `source_event_kind`, `component_kind`, `workflow_node_id`, payload schema,
    receipt refs, and policy refs;
  - repeated SDK interrupt stayed idempotent.
- `node --test --test-name-pattern "local daemon projects Agentgres runs" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - existing thread/turn/event projection contract still passed after adding
    turn-status override handling.
- `node --test --test-name-pattern "agent CLI exposes model" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - CLI source contract passed with the interrupt endpoint and operator-control
    event constants.
- `node --check packages/runtime-daemon/src/index.mjs`
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-operator-interrupt-control`
  - preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-operator-interrupt-control/2026-05-12T22-55-37-243Z/result.json`.

Known validation note:

- `cargo test -p ioi-cli parses_agent_operator_surface_commands` still compiles
  unrelated integration tests and fails before the targeted unit because
  existing e2e fixtures construct `StartAgentParams` without
  `runtime_route_frame`. The passing binary-only unit test is the scoped CLI
  signal for this slice.

## Slice 102. 2026-05-12 - Live operator steer turn-control event

Guide section: P0. Live Runtime API Bridge

Evidence bundles:

- packages/runtime-daemon/src/index.mjs
- packages/agent-sdk/src/thread.ts
- crates/cli/src/commands/agent.rs
- packages/agent-ide/src/runtime/workflow-runtime-event-projection.ts
- scripts/lib/live-runtime-daemon-contract.test.mjs
- docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md
- docs/specs/runtime/agent-runtime-deepseek-parity-plus-implementation-log.md

Validation evidence:

- `npm run build --workspace=@ioi/agent-sdk`
  - SDK declarations and dist bundle rebuilt with `Turn.steer(...)` and
    `turn_steered` event typing.
- `npm run build --workspace=@ioi/agent-ide`
  - React Flow projection bundle rebuilt with `turn_steered` support.
- `node --check packages/runtime-daemon/src/index.mjs`
- `cargo fmt --package ioi-cli`
- `cargo test -p ioi-cli --bin cli parses_agent_operator_surface_commands`
  - CLI parser accepted `agent steer --thread-id ... --turn-id ...`.
- `node --test packages/agent-sdk/test/sdk.test.mjs`
  - 11 SDK subtests passed, including the daemon HTTP wrapper proof for
    `Turn.steer(...)`.
- `node --test scripts/lib/workflow-runtime-event-projection-contract.test.mjs`
  - React Flow source contract passed with `turn_steered`.
- `node --test --test-name-pattern "operator steer keeps one canonical guidance event" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live Rust runtime-service proof passed;
  - CLI/TUI `agent steer` appended one canonical `turn.steered` event;
  - SDK and React Flow found the same `event_id`, `seq`, cursor,
    `source_event_kind`, `component_kind`, `workflow_node_id`, payload schema,
    receipt refs, and policy refs;
  - repeated SDK steer with the same guidance stayed idempotent.
- `node --test --test-name-pattern "operator interrupt keeps one canonical control event" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - prior interrupt control proof stayed green after sharing the
    operator-control evidence helper.
- `node --test --test-name-pattern "local daemon projects Agentgres runs" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - existing thread/turn/event projection contract still passed.
- `node --test --test-name-pattern "agent CLI exposes model" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - CLI source contract passed with the steer endpoint and operator-control
    event constants.
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-operator-steer-control`
  - preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-operator-steer-control/2026-05-12T23-06-03-227Z/result.json`.

Known validation note:

- `cargo test -p ioi-cli parses_agent_operator_surface_commands` still compiles
  unrelated integration tests and fails before the targeted unit because
  existing e2e fixtures construct `StartAgentParams` without
  `runtime_route_frame`. The passing binary-only unit test is the scoped CLI
  signal for this slice.

## Slice 103. 2026-05-12 - Live context compact control event

Guide section: P0. Live Runtime API Bridge

Evidence bundles:

- packages/runtime-daemon/src/index.mjs
- packages/agent-sdk/src/thread.ts
- crates/cli/src/commands/agent.rs
- packages/agent-ide/src/runtime/workflow-runtime-event-projection.ts
- scripts/lib/live-runtime-daemon-contract.test.mjs
- docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md
- docs/specs/runtime/agent-runtime-deepseek-parity-plus-implementation-log.md

Validation evidence:

- `npm run build --workspace=@ioi/agent-sdk`
  - SDK declarations and dist bundle rebuilt with `Thread.compact(...)` and
    `context_compacted` event typing.
- `node --check packages/runtime-daemon/src/index.mjs`
- `cargo fmt --package ioi-cli`
- `npm run build --workspace=@ioi/agent-ide`
  - React Flow projection bundle rebuilt with `context_compacted` support.
- `cargo test -p ioi-cli --bin cli parses_agent_operator_surface_commands`
  - CLI parser accepted `agent compact --thread-id ...`.
- `node --test packages/agent-sdk/test/sdk.test.mjs`
  - 11 SDK subtests passed, including the daemon HTTP wrapper proof for
    `Thread.compact(...)`.
- `node --test scripts/lib/workflow-runtime-event-projection-contract.test.mjs`
  - React Flow source contract passed with `context_compacted`.
- `node --test --test-name-pattern "context compact keeps one canonical compaction event" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live Rust runtime-service proof passed;
  - CLI/TUI `agent compact` appended one canonical `context.compacted` event;
  - SDK and React Flow found the same `event_id`, `seq`, cursor,
    `source_event_kind`, `component_kind`, `workflow_node_id`, payload schema,
    receipt refs, and policy refs;
  - repeated SDK compact with the same reason/scope stayed idempotent.
- `node --test --test-name-pattern "agent CLI exposes model" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - CLI source contract passed with the compact endpoint and context-compaction
    event constants.
- `node --test --test-name-pattern "operator steer keeps one canonical guidance event" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - prior steer control proof stayed green.
- `node --test --test-name-pattern "operator interrupt keeps one canonical control event" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - prior interrupt control proof stayed green.
- `node --test --test-name-pattern "local daemon projects Agentgres runs" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - existing thread/turn/event projection contract still passed.
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-context-compact-control`
  - preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-context-compact-control/2026-05-12T23-14-55-807Z/result.json`.

Known validation note:

- `cargo test -p ioi-cli parses_agent_operator_surface_commands` still compiles
  unrelated integration tests and fails before the targeted unit because
  existing e2e fixtures construct `StartAgentParams` without
  `runtime_route_frame`. The passing binary-only unit test is the scoped CLI
  signal for this slice.

## Slice 104. 2026-05-12 - Live thread fork control event

Guide section: P0. Live Runtime API Bridge

Evidence bundles:

- packages/runtime-daemon/src/index.mjs
- packages/agent-sdk/src/messages.ts
- packages/agent-sdk/src/runtime-events.ts
- packages/agent-sdk/src/substrate-client.ts
- crates/cli/src/commands/agent.rs
- packages/agent-ide/src/runtime/workflow-runtime-event-projection.ts
- scripts/lib/live-runtime-daemon-contract.test.mjs
- docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md
- docs/specs/runtime/agent-runtime-deepseek-parity-plus-implementation-log.md

Validation evidence:

- `cargo fmt --package ioi-cli`
- `node --check packages/runtime-daemon/src/index.mjs`
- `npm run build --workspace=@ioi/agent-sdk`
  - SDK declarations and dist bundle rebuilt with `thread_forked` typing and
    daemon fork input defaults.
- `npm run build --workspace=@ioi/agent-ide`
  - React Flow projection bundle rebuilt with `thread_forked` support.
- `cargo test -p ioi-cli --bin cli parses_agent_operator_surface_commands`
  - CLI parser accepted `agent fork --thread-id ...`.
- `node --test packages/agent-sdk/test/sdk.test.mjs`
  - 11 SDK subtests passed, including the daemon HTTP wrapper proof for
    `Thread.fork(...)`.
- `node --test scripts/lib/workflow-runtime-event-projection-contract.test.mjs`
  - React Flow source contract passed with `thread_forked`.
- `node --test --test-name-pattern "thread fork keeps one canonical source event" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live Rust runtime-service proof passed;
  - CLI/TUI `agent fork` appended one canonical source-thread `thread.forked`
    event;
  - SDK and React Flow found the same `event_id`, `seq`, cursor,
    `source_event_kind`, `component_kind`, `workflow_node_id`, payload schema,
    receipt refs, and policy refs;
  - the forked thread opened through the SDK as the returned branch.
- `node --test --test-name-pattern "agent CLI exposes model" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - CLI source contract passed with the fork endpoint and thread-fork event
    constants.
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-thread-fork-control`
  - preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-thread-fork-control/2026-05-12T23-30-08-711Z/result.json`.

Known validation note:

- Direct `node --test packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts`
  is not a valid repo test command because Node does not load extensionless TS
  imports for that source file. `npm run build --workspace=@ioi/agent-ide` and
  `node --test scripts/lib/workflow-runtime-event-projection-contract.test.mjs`
  are the scoped React Flow validation signals for this slice.

## Slice 105. 2026-05-12 - React Flow runtime thread fork control node

Guide section: P0. Live Runtime API Bridge

Evidence bundles:

- packages/agent-ide/src/runtime/workflow-runtime-control-nodes.ts
- packages/agent-ide/src/runtime/workflow-node-registry.ts
- packages/agent-ide/src/runtime/workflow-runtime-event-projection.ts
- apps/autopilot/src-tauri/src/project/workflow_node_execution_lane.rs
- apps/autopilot/src-tauri/src/project/templates.rs
- scripts/lib/live-runtime-daemon-contract.test.mjs
- /tmp/ioi-autopilot-gui-harness-react-flow-thread-fork-control/2026-05-12T23-57-36-129Z/result.json

Validation evidence:

- `node --import tsx --test packages/agent-ide/src/runtime/workflow-runtime-control-nodes.test.ts packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts`
  - 8 React Flow runtime-control/projection subtests passed.
- `node --test scripts/lib/workflow-runtime-event-projection-contract.test.mjs`
  - React Flow source contract passed with the runtime-control request builder.
- `npm run generate:runtime-action-contracts -- --check`
  - generated TS/Rust action schema files are current.
- `npm run build --workspace=@ioi/agent-ide`
  - agent-ide declarations and bundles rebuilt with `runtime_thread_fork`.
- `rustfmt --check apps/autopilot/src-tauri/src/runtime_projection.rs apps/autopilot/src-tauri/src/project/templates.rs apps/autopilot/src-tauri/src/project/validation.rs apps/autopilot/src-tauri/src/project/workflow_node_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_project_tests/runtime_and_graph_contracts.rs apps/autopilot/src-tauri/src/project/workflow_project_tests/scaffolds_and_bindings.rs apps/autopilot/src-tauri/src/generated/runtime_action_schema.rs`
  - slice-touched Rust files passed formatting.
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml runtime_thread_fork_node_builds_react_flow_control_request`
  - local workflow execution produced a React Flow fork control descriptor with
    graph id, node id, endpoint, request body, and `source=react_flow`.
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scaffolds_include_action_metadata`
  - scaffold action metadata exposes `runtime_thread_fork` with write side
    effect class, dry-run support, schema requirement, and state connection
    class.
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml substrate_classifies_workflow_node_kinds`
  - Rust `ActionKind` classifies `runtime_thread_fork`.
- `node --test --test-name-pattern "React Flow thread fork control preserves graph identity" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live Rust runtime-service proof passed;
  - React Flow request builder produced the daemon fork request;
  - daemon SSE, SDK `Thread.events()`, and React Flow projection preserved
    `source=react_flow`, `workflow_graph_id`, `workflow_node_id`,
    `component_kind`, payload schema, receipt refs, and policy refs.
- `node --test --test-name-pattern "thread fork keeps one canonical source event" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - prior CLI/TUI fork source-event proof stayed green.
- `node --test --test-name-pattern "React Flow memory, authority/tooling, doctor, skill, hook, and package node contracts remain workflow-addressable" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - workflow-addressability source contract passed with the new runtime control
    node.
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-react-flow-thread-fork-control`
  - preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-react-flow-thread-fork-control/2026-05-12T23-57-36-129Z/result.json`.

Known validation note:

- Repo-wide `cargo fmt --manifest-path apps/autopilot/src-tauri/Cargo.toml --check`
  still reports pre-existing formatting diffs in unrelated orchestrator store
  modules. The scoped `rustfmt --check` over this slice's touched Rust files
  passed.

## Slice 106. 2026-05-13 - React Flow runtime operator interrupt control node

Guide section: P0. Live Runtime API Bridge

Evidence bundles:

- packages/agent-ide/src/runtime/workflow-runtime-control-nodes.ts
- packages/agent-ide/src/runtime/workflow-node-registry.ts
- packages/agent-ide/src/runtime/workflow-runtime-event-projection.ts
- apps/autopilot/src-tauri/src/project/workflow_node_execution_lane.rs
- apps/autopilot/src-tauri/src/project/templates.rs
- scripts/lib/live-runtime-daemon-contract.test.mjs
- /tmp/ioi-autopilot-gui-harness-react-flow-operator-interrupt-control/2026-05-13T00-11-09-695Z/result.json

Validation evidence:

- `node --import tsx --test packages/agent-ide/src/runtime/workflow-runtime-control-nodes.test.ts packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts`
  - 10 React Flow runtime-control/projection subtests passed.
- `node --test scripts/lib/workflow-runtime-event-projection-contract.test.mjs`
  - React Flow source contract passed with the interrupt control request
    builder and projection node kind.
- `npm run generate:runtime-action-contracts -- --check`
  - generated TS/Rust action schema files are current.
- `npm run build --workspace=@ioi/agent-ide`
  - agent-ide declarations and bundles rebuilt with
    `runtime_operator_interrupt`.
- `rustfmt --check apps/autopilot/src-tauri/src/runtime_projection.rs apps/autopilot/src-tauri/src/project/templates.rs apps/autopilot/src-tauri/src/project/validation.rs apps/autopilot/src-tauri/src/project/workflow_node_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_project_tests/runtime_and_graph_contracts.rs apps/autopilot/src-tauri/src/project/workflow_project_tests/scaffolds_and_bindings.rs apps/autopilot/src-tauri/src/generated/runtime_action_schema.rs`
  - slice-touched Rust files passed formatting.
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml runtime_operator_interrupt_node_builds_react_flow_control_request`
  - local workflow execution produced a React Flow interrupt control
    descriptor with graph id, node id, endpoint, request body, thread id,
    turn id, and `source=react_flow`.
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scaffolds_include_action_metadata`
  - scaffold action metadata exposes `runtime_operator_interrupt` with write
    side effect class, dry-run support, schema requirement, and control
    connection class.
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml substrate_classifies_workflow_node_kinds`
  - Rust `ActionKind` classifies `runtime_operator_interrupt`.
- `node --test --test-name-pattern "React Flow operator interrupt control preserves graph identity" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live Rust runtime-service proof passed;
  - React Flow request builder produced the daemon interrupt request;
  - daemon SSE, SDK `Thread.events()`, and React Flow projection preserved
    `source=react_flow`, `workflow_graph_id`, `workflow_node_id`,
    `component_kind`, payload schema, receipt refs, and policy refs.
- `node --test --test-name-pattern "operator interrupt keeps one canonical control event" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - prior CLI/TUI operator interrupt source-event proof stayed green.
- `node --test --test-name-pattern "React Flow memory, authority/tooling, doctor, skill, hook, and package node contracts remain workflow-addressable" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - workflow-addressability source contract passed with the new runtime control
    node.
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-react-flow-operator-interrupt-control`
  - preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-react-flow-operator-interrupt-control/2026-05-13T00-11-09-695Z/result.json`.

Known validation note:

- Repo-wide `cargo fmt --manifest-path apps/autopilot/src-tauri/Cargo.toml --check`
  still reports pre-existing formatting diffs in unrelated orchestrator store
  modules. The scoped `rustfmt --check` over this slice's touched Rust files
  passed.

## Slice 107. 2026-05-13 - React Flow runtime operator steer control node

Guide section: P0. Live Runtime API Bridge

Evidence bundles:

- packages/agent-ide/src/runtime/workflow-runtime-control-nodes.ts
- packages/agent-ide/src/runtime/workflow-node-registry.ts
- packages/agent-ide/src/runtime/workflow-runtime-event-projection.ts
- apps/autopilot/src-tauri/src/project/workflow_node_execution_lane.rs
- apps/autopilot/src-tauri/src/project/templates.rs
- scripts/lib/live-runtime-daemon-contract.test.mjs
- /tmp/ioi-autopilot-gui-harness-react-flow-operator-steer-control/2026-05-13T00-24-15-404Z/result.json

Validation evidence:

- `node --import tsx --test packages/agent-ide/src/runtime/workflow-runtime-control-nodes.test.ts packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts`
  - 12 React Flow runtime-control/projection subtests passed.
- `node --test scripts/lib/workflow-runtime-event-projection-contract.test.mjs`
  - React Flow source contract passed with the steer control request builder
    and projection node kind.
- `npm run generate:runtime-action-contracts -- --check`
  - generated TS/Rust action schema files are current.
- `npm run build --workspace=@ioi/agent-ide`
  - agent-ide declarations and bundles rebuilt with `runtime_operator_steer`.
- `rustfmt --check apps/autopilot/src-tauri/src/runtime_projection.rs apps/autopilot/src-tauri/src/project/templates.rs apps/autopilot/src-tauri/src/project/validation.rs apps/autopilot/src-tauri/src/project/workflow_node_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_project_tests/runtime_and_graph_contracts.rs apps/autopilot/src-tauri/src/project/workflow_project_tests/scaffolds_and_bindings.rs apps/autopilot/src-tauri/src/generated/runtime_action_schema.rs`
  - slice-touched Rust files passed formatting.
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml runtime_operator_steer_node_builds_react_flow_control_request`
  - local workflow execution produced a React Flow steer control descriptor
    with graph id, node id, endpoint, request body, thread id, turn id,
    guidance, and `source=react_flow`.
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scaffolds_include_action_metadata`
  - scaffold action metadata exposes `runtime_operator_steer` with write side
    effect class, dry-run support, schema requirement, and control connection
    class.
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml substrate_classifies_workflow_node_kinds`
  - Rust `ActionKind` classifies `runtime_operator_steer`.
- `node --test --test-name-pattern "React Flow operator steer control preserves graph identity" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live Rust runtime-service proof passed;
  - React Flow request builder produced the daemon steer request;
  - daemon SSE, SDK `Thread.events()`, and React Flow projection preserved
    `source=react_flow`, `workflow_graph_id`, `workflow_node_id`,
    `component_kind`, payload schema, receipt refs, and policy refs while the
    turn terminal state stayed unchanged.
- `node --test --test-name-pattern "operator steer keeps one canonical guidance event" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - prior CLI/TUI operator steer source-event proof stayed green.
- `node --test --test-name-pattern "React Flow memory, authority/tooling, doctor, skill, hook, and package node contracts remain workflow-addressable" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - workflow-addressability source contract passed with the new runtime control
    node.
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-react-flow-operator-steer-control`
  - preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-react-flow-operator-steer-control/2026-05-13T00-24-15-404Z/result.json`.

Known validation note:

- Repo-wide `cargo fmt --manifest-path apps/autopilot/src-tauri/Cargo.toml --check`
  still reports pre-existing formatting diffs in unrelated orchestrator store
  modules. The scoped `rustfmt --check` over this slice's touched Rust files
  passed.

## Slice 108. 2026-05-13 - React Flow runtime context compact control node

Guide section: P0. Live Runtime API Bridge

Evidence bundles:

- packages/agent-ide/src/runtime/workflow-runtime-control-nodes.ts
- packages/agent-ide/src/runtime/workflow-node-registry.ts
- packages/agent-ide/src/runtime/workflow-runtime-event-projection.ts
- apps/autopilot/src-tauri/src/project/workflow_node_execution_lane.rs
- apps/autopilot/src-tauri/src/project/templates.rs
- scripts/lib/live-runtime-daemon-contract.test.mjs
- /tmp/ioi-autopilot-gui-harness-react-flow-context-compact-control/2026-05-13T00-40-20-698Z/result.json

Validation evidence:

- `node --import tsx --test packages/agent-ide/src/runtime/workflow-runtime-control-nodes.test.ts packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts`
  - 14 React Flow runtime-control/projection subtests passed.
- `node --test scripts/lib/workflow-runtime-event-projection-contract.test.mjs`
  - React Flow source contract passed with the compact control request builder
    and projection node kind.
- `npm run generate:runtime-action-contracts -- --check`
  - generated TS/Rust action schema files are current.
- `npm run build --workspace=@ioi/agent-ide`
  - agent-ide declarations and bundles rebuilt with
    `runtime_context_compact`.
- `rustfmt --check apps/autopilot/src-tauri/src/runtime_projection.rs apps/autopilot/src-tauri/src/project/templates.rs apps/autopilot/src-tauri/src/project/validation.rs apps/autopilot/src-tauri/src/project/workflow_node_execution_lane.rs apps/autopilot/src-tauri/src/project/workflow_project_tests/runtime_and_graph_contracts.rs apps/autopilot/src-tauri/src/project/workflow_project_tests/scaffolds_and_bindings.rs apps/autopilot/src-tauri/src/generated/runtime_action_schema.rs`
  - slice-touched Rust files passed formatting.
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml runtime_context_compact_node_builds_react_flow_control_request`
  - local workflow execution produced a React Flow compact control descriptor
    with graph id, node id, endpoint, request body, thread id, turn id,
    reason, scope, and `source=react_flow`.
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scaffolds_include_action_metadata`
  - scaffold action metadata exposes `runtime_context_compact` with write side
    effect class, dry-run support, schema requirement, and control connection
    class.
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml substrate_classifies_workflow_node_kinds`
  - Rust `ActionKind` classifies `runtime_context_compact`.
- `node --test --test-name-pattern "React Flow context compact control preserves graph identity" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live Rust runtime-service proof passed;
  - React Flow request builder produced the daemon compact request;
  - daemon SSE, SDK `Thread.events()`, and React Flow projection preserved
    `source=react_flow`, `workflow_graph_id`, `workflow_node_id`,
    `component_kind`, payload schema, receipt refs, policy refs, reason, and
    scope while retaining one canonical `context.compacted` event.
- `node --test --test-name-pattern "context compact keeps one canonical compaction event" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - prior CLI/TUI context compact source-event proof stayed green.
- `node --test --test-name-pattern "React Flow memory, authority/tooling, doctor, skill, hook, and package node contracts remain workflow-addressable" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - workflow-addressability source contract passed with the new runtime control
    node.
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-react-flow-context-compact-control`
  - preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-react-flow-context-compact-control/2026-05-13T00-40-20-698Z/result.json`.

Known validation note:

- Repo-wide `cargo fmt --manifest-path apps/autopilot/src-tauri/Cargo.toml --check`
  still reports pre-existing formatting diffs in unrelated orchestrator store
  modules. The scoped `rustfmt --check` over this slice's touched Rust files
  passed.

## Slice 109. 2026-05-13 - Shared React Flow runtime-control helper extraction

Guide section: P0. Live Runtime API Bridge

Evidence bundles:

- packages/agent-ide/src/runtime/workflow-runtime-control-nodes.ts
- packages/agent-ide/src/runtime/workflow-runtime-control-nodes.test.ts
- apps/autopilot/src-tauri/src/project/workflow_node_execution_lane.rs
- scripts/lib/workflow-runtime-event-projection-contract.test.mjs
- scripts/lib/live-runtime-daemon-contract.test.mjs
- /tmp/ioi-autopilot-gui-harness-runtime-control-helper-refactor/2026-05-13T00-56-55-307Z/result.json

Validation evidence:

- `node --import tsx --test packages/agent-ide/src/runtime/workflow-runtime-control-nodes.test.ts packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts`
  - 15 React Flow runtime-control/projection subtests passed, including the
    shared envelope metadata test across fork, interrupt, steer, and compact.
- `node --test scripts/lib/workflow-runtime-event-projection-contract.test.mjs`
  - React Flow source contract stayed green after the helper extraction.
- `npm run generate:runtime-action-contracts -- --check`
  - generated TS/Rust action schema files are current.
- `npm run build --workspace=@ioi/agent-ide`
  - agent-ide declarations and bundles rebuilt with the shared TS helper.
- `rustfmt --check apps/autopilot/src-tauri/src/project/workflow_node_execution_lane.rs`
  - refactored Rust workflow execution lane passed formatting.
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml runtime_ -- --nocapture`
  - broad runtime filter passed 51 active tests, ignored one Chromium-only
    probe, and included all four React Flow runtime-control workflow-node
    output tests.
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scaffolds_include_action_metadata`
  - scaffold action metadata stayed green after the descriptor helper
    extraction.
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml substrate_classifies_workflow_node_kinds`
  - Rust `ActionKind` classification stayed green.
- `node --test --test-name-pattern "React Flow context compact control preserves graph identity" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live Rust runtime-service proof stayed green through daemon SSE, SDK
    `Thread.events()`, and React Flow projection.
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-runtime-control-helper-refactor`
  - preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-runtime-control-helper-refactor/2026-05-13T00-56-55-307Z/result.json`.

Known validation note:

- This was a behavior-preserving refactor slice; no runtime action schema
  change was expected, and `generate:runtime-action-contracts -- --check`
  confirmed no generated contract drift.

## Slice 110. 2026-05-13 - React Flow settings harness active runtime binding panel split

Guide section: P2. Localization And Accessibility

Evidence bundles:

- packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActiveRuntimeBindingPanel.tsx
- packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActiveRuntimeBindingSummary.tsx
- packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActiveRuntimeBindingDeepLinks.tsx
- scripts/lib/harness-refactor-shape.test.mjs
- /tmp/ioi-autopilot-gui-harness-active-runtime-binding-panel-refactor/2026-05-13T01-09-15-286Z/result.json

Validation evidence:

- `npm run build --workspace=@ioi/agent-ide`
  - agent-ide TypeScript and Vite build passed with the extracted components.
- `node --test scripts/lib/harness-refactor-shape.test.mjs`
  - harness refactor shape passed and now covers the active runtime binding
    summary/deep-link modules.
- `node --check scripts/lib/harness-refactor-shape.test.mjs`
  - harness refactor shape syntax check passed.
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
  - GUI harness validation core syntax check passed.
- `node --test --test-name-pattern "React Flow memory, authority/tooling, doctor, skill, hook, and package node contracts remain workflow-addressable" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - source contract passed with the parent panel preserving
    `data-worker-binding-registry-bound` and
    `workflow-harness-active-runtime-binding-deep-links`.
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-active-runtime-binding-panel-refactor`
  - preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-active-runtime-binding-panel-refactor/2026-05-13T01-09-15-286Z/result.json`.

Known validation note:

- The first harness refactor shape run failed on a stale line-count checkpoint
  for `scripts/lib/autopilot-gui-harness-validation/core.mjs`, which this slice
  did not edit. The checkpoint now matches the current committed baseline and
  the suite passes.

## Slice 111. 2026-05-13 - React Flow settings harness promotion readiness panel split

Guide section: P2. Localization And Accessibility

Evidence bundles:

- packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPromotionReadinessPanel.tsx
- packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPromotionReadinessSummary.tsx
- packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPromotionReadinessAuthorityGates.tsx
- packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPromotionReadinessRoutingCanary.tsx
- scripts/lib/harness-refactor-shape.test.mjs
- /tmp/ioi-autopilot-gui-harness-promotion-readiness-panel-refactor/2026-05-13T01-18-45-520Z/result.json

Validation evidence:

- `npm run build --workspace=@ioi/agent-ide`
  - agent-ide TypeScript and Vite build passed with the extracted promotion
    readiness components.
- `node --test scripts/lib/harness-refactor-shape.test.mjs`
  - harness refactor shape passed and now covers the promotion readiness
    summary, authority gates, and routing/canary modules.
- `node --check scripts/lib/harness-refactor-shape.test.mjs`
  - harness refactor shape syntax check passed.
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
  - GUI harness validation core syntax check passed.
- `node --test --test-name-pattern "React Flow memory, authority/tooling, doctor, skill, hook, and package node contracts remain workflow-addressable" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - source contract passed with the parent panel preserving
    `workflow-harness-selector-live-promotion-readiness` and
    `workflow-harness-authority-gate-live`.
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-promotion-readiness-panel-refactor`
  - preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-promotion-readiness-panel-refactor/2026-05-13T01-18-45-520Z/result.json`.

Known validation note:

- The first harness refactor shape run failed because the summary and authority
  child components intentionally receive parent-routed test ids. The guard now
  checks each child module's owned implementation surface while the parent
  continues to preserve the source-contract literals.

## Slice 112. 2026-05-13 - React Flow settings harness activation panel split

Guide section: P2. Localization And Accessibility

Evidence bundles:

- packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationPanel.tsx
- packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationWizardDetails.tsx
- packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationActions.tsx
- scripts/lib/harness-refactor-shape.test.mjs
- /tmp/ioi-autopilot-gui-harness-activation-panel-refactor/2026-05-13T01-27-37-008Z/result.json

Validation evidence:

- `npm run build --workspace=@ioi/agent-ide`
  - agent-ide TypeScript and Vite build passed with the extracted activation
    wizard details and action controls.
- `node --test scripts/lib/harness-refactor-shape.test.mjs`
  - harness refactor shape passed and now covers the activation wizard details
    and activation actions modules.
- `node --check scripts/lib/harness-refactor-shape.test.mjs`
  - harness refactor shape syntax check passed.
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
  - GUI harness validation core syntax check passed.
- `node --test --test-name-pattern "React Flow memory, authority/tooling, doctor, skill, hook, and package node contracts remain workflow-addressable" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - source contract passed with the parent panel preserving
    `WorkflowSettingsHarnessActivationGatePanel` delegation and activation
    wizard source markers.
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-activation-panel-refactor`
  - preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-activation-panel-refactor/2026-05-13T01-27-37-008Z/result.json`.

Known validation note:

- The parent keeps activation step and candidate-gate source marker templates
  and passes them to the wizard detail component so source-contract probes can
  still bind to the existing React Flow workflow hooks after extraction.

## Slice 113. 2026-05-13 - Master guide parity-gap triage cleanup

Guide section: Current Implementation State / Next Implementation Slices

Evidence bundles:

- docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md
- docs/specs/runtime/agent-runtime-deepseek-parity-plus-implementation-log.md
- docs/specs/runtime/agent-runtime-deepseek-parity-plus-validation-ledger.md
- /tmp/ioi-autopilot-gui-harness-master-guide-triage/2026-05-13T01-35-47-401Z/result.json

Validation evidence:

- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
  - GUI harness validation core syntax check passed.
- `node --test --test-name-pattern "React Flow memory, authority/tooling, doctor, skill, hook, and package node contracts remain workflow-addressable" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - source contract remained green while the guide queue pivoted back to P0 TUI
    parity work.
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-master-guide-triage`
  - live GUI/workflow preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-master-guide-triage/2026-05-13T01-35-47-401Z/result.json`.
- `git diff --check`
  - whitespace check passed.

## Slice 114. 2026-05-13 - Thin daemon-backed `ioi agent tui` shell

Guide section: P0. Terminal Coding-Agent TUI

Evidence bundles:

- crates/cli/src/commands/agent_tui.rs
- crates/cli/src/commands/agent.rs
- crates/cli/src/commands/agent_event_stream.rs
- scripts/lib/live-runtime-daemon-contract.test.mjs
- /tmp/ioi-autopilot-gui-harness-agent-tui-thin-shell/2026-05-13T01-47-01-001Z/result.json

Validation evidence:

- `cargo test -p ioi-cli --bin cli parses_agent_operator_surface_commands`
  - CLI parser accepts `agent tui` with daemon endpoint, goal, message,
    runtime profile, model route, interrupt, cursor, and JSON flags.
- `cargo test -p ioi-cli --bin cli agent_tui`
  - TUI route, turn-selection, and start-option unit tests passed.
- `cargo check -p ioi-cli --bin cli`
  - CLI binary type-check passed with the new command module.
- `cargo fmt -p ioi-cli -- --check`
  - Rust formatting check passed.
- `node --test --test-name-pattern "agent TUI thin shell starts a live thread|agent TUI thin shell is daemon-backed|agent CLI exposes model" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live daemon contract passed: `agent tui` started a runtime-service thread,
    submitted a turn, interrupted via daemon control route, rendered canonical
    events, and replayed by `Last-Event-ID` with no private runtime loop.
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live runtime daemon contract syntax check passed.
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
  - GUI harness validation core syntax check passed.
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-agent-tui-thin-shell`
  - live GUI/workflow preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-agent-tui-thin-shell/2026-05-13T01-47-01-001Z/result.json`.
- `git diff --check`
  - whitespace check passed.

## Slice 115. 2026-05-13 - React Flow/TUI runtime-event deep-link contract

Guide section: P0. Terminal Coding-Agent TUI

Evidence bundles:

- crates/cli/src/commands/agent_tui.rs
- packages/agent-ide/src/runtime/workflow-runtime-event-projection.ts
- packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts
- packages/agent-ide/src/features/Workflows/WorkflowRailPanel/runsPanel.tsx
- scripts/lib/live-runtime-daemon-contract.test.mjs
- /tmp/ioi-autopilot-gui-harness-agent-tui-workflow-deeplinks/2026-05-13T01-56-18-198Z/result.json

Validation evidence:

- `cargo test -p ioi-cli --bin cli`
  - full CLI binary test suite passed with TUI event-row deep-link coverage.
- `cargo check -p ioi-cli --bin cli`
  - CLI binary type-check passed.
- `cargo fmt -p ioi-cli -- --check`
  - Rust formatting check passed.
- `node --import tsx --test packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts packages/agent-ide/src/runtime/workflow-run-history-model.test.ts`
  - React Flow runtime-event projection and run-history model tests passed with
    the TUI reopen descriptor on projected nodes.
- `npm run build --workspace=@ioi/agent-ide`
  - agent-ide TypeScript and Vite build passed.
- `node --test --test-name-pattern "agent TUI thin shell starts a live thread|agent TUI thin shell is daemon-backed|agent CLI exposes model|React Flow memory, authority/tooling, doctor, skill, hook, and package node contracts remain workflow-addressable" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live daemon contract passed: the operator-interrupt event kept the same
    event id, cursor, workflow node id, and `ioi agent tui --thread-id ...`
    reopen args across daemon SSE, SDK `Thread.events()`, TUI JSON event rows,
    and React Flow projection.
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live runtime daemon contract syntax check passed.
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
  - GUI harness validation core syntax check passed.
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-agent-tui-workflow-deeplinks`
  - live GUI/workflow preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-agent-tui-workflow-deeplinks/2026-05-13T01-56-18-198Z/result.json`.

## Slice 116. 2026-05-13 - Daemon-backed line-mode `ioi agent tui` loop

Guide section: P0. Terminal Coding-Agent TUI

Evidence bundles:

- crates/cli/src/commands/agent_tui.rs
- crates/cli/src/commands/agent_tui_loop.rs
- crates/cli/src/commands/mod.rs
- crates/cli/src/commands/agent.rs
- scripts/lib/live-runtime-daemon-contract.test.mjs
- /tmp/ioi-autopilot-gui-harness-agent-tui-line-mode/2026-05-13T02-06-09-973Z/result.json

Validation evidence:

- `cargo test -p ioi-cli --bin cli agent_tui`
  - TUI route, event-row, line-mode parser, and slash-command validation tests
    passed.
- `cargo test -p ioi-cli --bin cli parses_agent_operator_surface_commands`
  - CLI parser accepts `agent tui --interactive` alongside the existing daemon
    endpoint and runtime profile flags.
- `cargo test -p ioi-cli --bin cli`
  - full CLI binary test suite passed.
- `cargo check -p ioi-cli --bin cli`
  - CLI binary type-check passed.
- `cargo fmt -p ioi-cli -- --check`
  - Rust formatting check passed.
- `node --test --test-name-pattern "agent TUI line-mode slash commands|agent TUI thin shell starts a live thread|agent TUI thin shell is daemon-backed|agent CLI exposes model" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live daemon contract passed: stdin drove `/interrupt`, `/events 0`, and
    `/quit`; the line-mode interrupt emitted the same daemon event identity,
    cursor, workflow node id, and TUI reopen args through SDK and React Flow.
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live runtime daemon contract syntax check passed.
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
  - GUI harness validation core syntax check passed.
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-agent-tui-line-mode`
  - live GUI/workflow preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-agent-tui-line-mode/2026-05-13T02-06-09-973Z/result.json`.

## Slice 117. 2026-05-13 - React Flow/TUI operator-control equivalence proof

Guide section: P0. Terminal Coding-Agent TUI

Evidence bundles:

- scripts/lib/live-runtime-daemon-contract.test.mjs
- docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md
- docs/specs/runtime/agent-runtime-deepseek-parity-plus-implementation-log.md
- docs/specs/runtime/agent-runtime-deepseek-parity-plus-validation-ledger.md
- /tmp/ioi-autopilot-gui-harness-tui-react-flow-control-equivalence/2026-05-13T02-12-53-211Z/result.json

Validation evidence:

- `node --test --test-name-pattern "React Flow and line-mode TUI .* controls share" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live interrupt and steer equivalence proofs passed.
- `node --test --test-name-pattern "React Flow and line-mode TUI .* controls share|agent TUI line-mode slash commands|React Flow operator interrupt control preserves graph identity|React Flow operator steer control preserves graph identity|agent CLI exposes model" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - broader source/live contract passed with the existing React Flow control
    proofs, TUI line-mode proof, and the new equivalence proofs together.
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live runtime daemon contract syntax check passed.
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
  - GUI harness validation core syntax check passed.
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-tui-react-flow-control-equivalence`
  - live GUI/workflow preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-tui-react-flow-control-equivalence/2026-05-13T02-12-53-211Z/result.json`.

## Slice 118. 2026-05-13 - TUI control-state projection and run-inspector rows

Guide section: P0. Terminal Coding-Agent TUI

Evidence bundles:

- crates/cli/src/commands/agent_tui.rs
- crates/cli/src/commands/agent_tui_loop.rs
- packages/agent-ide/src/runtime/workflow-runtime-event-projection.ts
- packages/agent-ide/src/runtime/workflow-run-history-model.ts
- packages/agent-ide/src/features/Workflows/WorkflowRailPanel/runsPanel.tsx
- scripts/lib/live-runtime-daemon-contract.test.mjs
- /tmp/ioi-autopilot-gui-harness-tui-control-state-projection/2026-05-13T02-25-01-786Z/result.json

Validation evidence:

- `node --import tsx --test packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts packages/agent-ide/src/runtime/workflow-run-history-model.test.ts`
  - React Flow TUI control-state projection and run-history model tests passed.
- `cargo test --manifest-path crates/cli/Cargo.toml --bin cli agent_tui -- --nocapture`
  - CLI TUI route, event-row, control-state, line-mode parser, and
    validation-error tests passed.
- `npm run build --workspace=@ioi/agent-ide`
  - agent-ide TypeScript and Vite build passed.
- `node --test --test-name-pattern "agent CLI exposes|agent TUI thin shell is daemon-backed|agent TUI thin shell starts|agent TUI line-mode slash commands" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live daemon contract passed for JSON and line-mode TUI control-state
    projection.
- `node --import tsx --test --test-name-pattern "projects TUI control state|workflow run history model projects TUI control state" packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts packages/agent-ide/src/runtime/workflow-run-history-model.test.ts`
  - focused TUI control-state projection tests passed.
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live runtime daemon contract syntax check passed.
- `node --check scripts/lib/autopilot-gui-harness-validation/core.mjs`
  - GUI harness validation core syntax check passed.
- `cargo fmt -p ioi-cli -- --check`
  - Rust formatting check passed.
- `cargo check --manifest-path crates/cli/Cargo.toml --bin cli`
  - CLI binary type-check passed.
- `git diff --check`
  - whitespace check passed.
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-tui-control-state-projection`
  - live GUI/workflow preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-tui-control-state-projection/2026-05-13T02-25-01-786Z/result.json`.

Known validation note:

- Broad `cargo test --manifest-path crates/cli/Cargo.toml agent_tui -- --nocapture`
  remains blocked by unrelated CLI integration tests that need
  `StartAgentParams.runtime_route_frame` initializers.
- Broad
  `node --import tsx --test apps/autopilot/src/windows/AutopilotShellWindow/workflowComposerWiring.test.ts`
  remains blocked by an existing readiness-label source-contract assertion
  before it reaches this slice's run-inspector additions.

## Slice 120. 2026-05-13 - Coding tool-pack status/diff/inspect contract

Guide section: P0-B. Coding Tool Pack

Evidence bundles:

- packages/runtime-daemon/src/index.mjs
- packages/runtime-daemon/src/coding-tools.mjs
- packages/agent-sdk/src/substrate-client.ts
- crates/cli/src/commands/agent.rs
- crates/cli/src/commands/agent_tui.rs
- crates/cli/src/commands/agent_tui_loop.rs
- packages/agent-ide/src/types/graph.ts
- packages/agent-ide/src/runtime/workflow-node-registry.ts
- packages/agent-ide/src/runtime/workflow-runtime-event-projection.ts
- scripts/lib/live-runtime-daemon-contract.test.mjs
- /tmp/ioi-autopilot-gui-harness-coding-tool-pack-status-diff-inspect/2026-05-13T03-05-13-000Z/result.json

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs && node --check packages/runtime-daemon/src/coding-tools.mjs`
  - daemon syntax checks passed.
- `npm run build --workspace=@ioi/agent-sdk`
  - SDK declaration and bundle build passed.
- `npm run build --workspace=@ioi/agent-ide`
  - agent-ide TypeScript and Vite build passed.
- `cargo fmt -p ioi-cli`
  - Rust formatting completed.
- `cargo check -p ioi-cli`
  - CLI package check passed.
- `cargo test -p ioi-cli --bin cli parses_nested_tool_and_policy_commands -- --nocapture`
  - CLI coding-tool parser test passed.
- `cargo test -p ioi-cli --bin cli parses_line_mode_slash_commands -- --nocapture`
  - TUI coding-tool slash command parser test passed.
- `node --test --test-name-pattern "coding tool pack invokes status" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live daemon/SDK/CLI/TUI/React Flow coding tool-pack proof passed.
- `node --test --test-name-pattern "agent CLI exposes model" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - CLI/TUI source-contract guard passed.
- `node --test --test-name-pattern "agent TUI thin shell is daemon-backed" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - TUI source-contract guard passed.
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-coding-tool-pack-status-diff-inspect`
  - live GUI/workflow preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-coding-tool-pack-status-diff-inspect/2026-05-13T03-05-13-000Z/result.json`.

Known validation note:

- Broad `cargo test -p ioi-cli ...` remains blocked by unrelated CLI
  integration tests that need `StartAgentParams.runtime_route_frame`
  initializers.

## Slice 139. 2026-05-13 - TUI jobs and run lifecycle parity view

Guide section: P0-A. Terminal Coding-Agent TUI

Evidence bundles:

- crates/cli/src/commands/agent_tui.rs
- crates/cli/src/commands/agent_tui_loop.rs
- packages/agent-sdk/src/substrate-client.ts
- packages/agent-ide/src/runtime/workflow-runtime-event-projection.ts
- packages/agent-ide/src/features/Workflows/WorkflowRailPanel/runsPanel.tsx
- scripts/lib/live-runtime-daemon-contract.test.mjs
- /tmp/ioi-autopilot-gui-harness-tui-jobs-run-lifecycle/2026-05-13T11-39-18-945Z/result.json

Validation evidence:

- `cargo test -p ioi-cli --bin cli tui --quiet`
  - Rust TUI route, parser, control-state, job-row, and lifecycle-row tests
    passed.
- `npm run typecheck --workspace=@ioi/agent-sdk`
  - SDK job-handle typecheck passed.
- `npm run build --workspace=@ioi/agent-ide -- --emptyOutDir=false`
  - React Flow control-state projection and run-panel build passed.
- `node --import tsx --test --test-name-pattern "projects TUI control state" packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts`
  - React Flow TUI control-state rows passed for job and run-lifecycle counts.
- `node --import tsx --test --test-name-pattern "workflow run history model projects TUI control state" packages/agent-ide/src/runtime/workflow-run-history-model.test.ts`
  - run-inspector model projection stayed compatible with the expanded
    control-state schema.
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live daemon contract syntax check passed.
- `node --test --test-name-pattern "local daemon public API|agent TUI thin shell|agent TUI line-mode slash" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live daemon, SDK job handles, JSON TUI job rows, line-mode `/jobs`, `/job`,
    and `/run replay`, and React Flow projection proof passed.
- `cargo fmt -p ioi-cli -- --check`
  - Rust formatting check passed.
- `git diff --check`
  - whitespace check passed.
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-tui-jobs-run-lifecycle`
  - live GUI/workflow preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-tui-jobs-run-lifecycle/2026-05-13T11-39-18-945Z/result.json`.

## Slice 140. 2026-05-13 - Daemon-owned MCP discovery/status/validation

Guide section: P1. MCP Manager Parity

Evidence bundles:

- packages/runtime-daemon/src/index.mjs
- packages/runtime-daemon/src/mcp-manager.mjs
- packages/agent-sdk/src/messages.ts
- packages/agent-sdk/src/substrate-client.ts
- packages/agent-sdk/src/thread.ts
- crates/cli/src/commands/agent_tui.rs
- crates/cli/src/commands/agent_tui_loop.rs
- packages/agent-ide/src/runtime/workflow-runtime-event-projection.ts
- packages/agent-ide/src/features/Workflows/WorkflowNodeBindingEditor/sections.tsx
- scripts/lib/live-runtime-daemon-contract.test.mjs

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
  - daemon MCP manager syntax check passed.
- `node --check packages/runtime-daemon/src/mcp-manager.mjs`
  - daemon MCP catalog helper syntax check passed.
- `cargo test -p ioi-cli --bin cli tui --quiet`
  - Rust TUI command parser and TUI unit slice passed.
- `npm run build --workspace=@ioi/agent-sdk`
  - SDK declaration and bundle build passed.
- `npm run build --workspace=@ioi/agent-ide`
  - Agent IDE TypeScript and Vite build passed.
- `node --test --test-name-pattern "daemon owns MCP|agent TUI line-mode slash commands|agent CLI exposes model|agent TUI thin shell" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live daemon/SDK/TUI/React Flow MCP discovery/status/validation proof and
    source-contract guards passed.

## Slice 141. 2026-05-13 - Daemon-owned memory manager status/validation

Guide section: P1. Memory UX Parity

Evidence bundles:

- packages/runtime-daemon/src/index.mjs
- packages/runtime-daemon/src/memory-manager.mjs
- packages/agent-sdk/src/messages.ts
- packages/agent-sdk/src/substrate-client.ts
- packages/agent-sdk/src/thread.ts
- crates/cli/src/commands/agent_tui.rs
- crates/cli/src/commands/agent_tui_loop.rs
- packages/agent-ide/src/runtime/workflow-runtime-event-projection.ts
- packages/agent-ide/src/runtime/workflow-node-registry.ts
- packages/agent-ide/src/features/Workflows/WorkflowNodeBindingEditor/sections.tsx
- packages/agent-ide/src/features/Workflows/WorkflowRailPanel/runsPanel.tsx
- scripts/lib/live-runtime-daemon-contract.test.mjs

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
  - daemon memory manager route wiring syntax check passed.
- `node --check packages/runtime-daemon/src/memory-manager.mjs`
  - memory manager status/validation helper syntax check passed.
- `cargo fmt -p ioi-cli -- --check`
  - Rust TUI formatting check passed.
- `cargo test -p ioi-cli --bin cli tui --quiet`
  - Rust TUI parser/control tests passed with `/memory validate` coverage.
- `npm run build --workspace=@ioi/agent-sdk`
  - SDK declaration and bundle build passed with memory status/validation helpers.
- `npm run build --workspace=@ioi/agent-ide`
  - Agent IDE TypeScript and Vite build passed with memory rows/state-node ops.
- `node --test --test-name-pattern "memory writes|agent CLI exposes model|agent TUI thin shell|agent TUI line-mode" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live daemon memory status/validation endpoints, SDK `Thread.memory`,
    TUI `/memory`, and React Flow control-state projection proof passed.

## Slice 142. 2026-05-13 - MCP enable/disable/invocation controls

Guide section: P1. MCP Manager Parity

Evidence bundles:

- packages/runtime-daemon/src/index.mjs
- packages/runtime-daemon/src/mcp-manager.mjs
- packages/agent-sdk/src/messages.ts
- packages/agent-sdk/src/substrate-client.ts
- packages/agent-sdk/src/thread.ts
- crates/cli/src/commands/agent_tui.rs
- crates/cli/src/commands/agent_tui_loop.rs
- packages/agent-ide/src/runtime/workflow-runtime-event-projection.ts
- packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts
- packages/agent-ide/src/runtime/workflow-node-registry.ts
- packages/agent-ide/src/types/graph.ts
- packages/agent-ide/src/features/Workflows/WorkflowNodeBindingEditor/sections.tsx
- packages/agent-ide/src/features/Workflows/WorkflowRailPanel/runsPanel.tsx
- scripts/lib/live-runtime-daemon-contract.test.mjs

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
  - daemon MCP control route wiring syntax check passed.
- `node --check packages/runtime-daemon/src/mcp-manager.mjs`
  - daemon MCP manager helper syntax check passed.
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live contract test harness syntax check passed.
- `cargo fmt -p ioi-cli -- --check`
  - Rust TUI formatting check passed.
- `cargo test -p ioi-cli --bin cli tui --quiet`
  - Rust TUI parser/control tests passed with MCP enable/disable/invoke
    coverage.
- `npm run build --workspace=@ioi/agent-sdk`
  - SDK declaration and bundle build passed with MCP toggle/invoke helpers.
- `npm run build --workspace=@ioi/agent-ide`
  - Agent IDE TypeScript and Vite build passed with MCP rows/state-node ops.
- `node --import tsx --test packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts`
  - React Flow runtime event projection tests passed with MCP invocation row
    coverage.
- `node --test --test-name-pattern "daemon owns MCP discovery|agent CLI exposes model|agent TUI thin shell|agent TUI line-mode|React Flow memory" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live daemon, SDK, TUI line-mode, source-contract, and React Flow projection
    proof passed for MCP enable/disable/invoke controls.
- `node scripts/run-autopilot-gui-harness-validation.mjs --preflight --output-root /tmp/ioi-autopilot-gui-harness-mcp-controls`
  - live autopilot GUI/workflow preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-mcp-controls/2026-05-13T13-37-14-190Z/result.json`.

## Slice 143. 2026-05-13 - Memory write-side TUI/workflow controls

Guide section: P1. Memory UX Parity

Evidence bundles:

- packages/runtime-daemon/src/index.mjs
- packages/runtime-daemon/src/memory-manager.mjs
- packages/agent-sdk/src/index.ts
- packages/agent-sdk/src/substrate-client.ts
- packages/agent-sdk/src/thread.ts
- crates/cli/src/commands/agent_tui.rs
- crates/cli/src/commands/agent_tui_loop.rs
- packages/agent-ide/src/types/graph.ts
- packages/agent-ide/src/runtime/workflow-node-registry.ts
- packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts
- packages/agent-ide/src/features/Workflows/WorkflowNodeBindingEditor/sections.tsx
- apps/autopilot/src-tauri/src/project/workflow_memory_lane.rs
- apps/autopilot/src-tauri/src/project/workflow_node_execution_lane.rs
- scripts/lib/live-runtime-daemon-contract.test.mjs
- /tmp/ioi-autopilot-gui-harness-memory-write-controls/2026-05-13T14-00-24-781Z/result.json

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
  - daemon memory mutation control route syntax check passed.
- `node --check packages/runtime-daemon/src/memory-manager.mjs`
  - daemon memory manager syntax check passed.
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live contract test harness syntax check passed.
- `cargo fmt -p ioi-cli -- --check`
  - Rust TUI formatting check passed.
- `cargo test -p ioi-cli --bin cli tui --quiet`
  - Rust TUI parser/control tests passed with memory remember/edit/delete
    coverage.
- `cargo check -p autopilot`
  - Autopilot workflow execution lane compiled with memory mutation nodes.
- `npm run build --workspace=@ioi/agent-sdk`
  - SDK declaration and bundle build passed with thread memory mutation helpers.
- `npm run build --workspace=@ioi/agent-ide`
  - Agent IDE TypeScript and Vite build passed with memory mutation node
    controls.
- `node --import tsx --test packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts`
  - React Flow runtime event projection tests passed with memory mutation row
    coverage.
- `node --test --test-name-pattern "local daemon records explicit memory writes|agent CLI exposes model|agent TUI line-mode|React Flow memory" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live daemon, SDK, TUI line-mode, source-contract, and React Flow projection
    proof passed for memory write/edit/delete controls.
- `node scripts/run-autopilot-gui-harness-validation.mjs --preflight --output-root /tmp/ioi-autopilot-gui-harness-memory-write-controls`
  - live autopilot GUI/workflow preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-memory-write-controls/2026-05-13T14-00-24-781Z/result.json`.

## Slice 144. 2026-05-13 - Live MCP stdio transport invocation

Guide section: P1. MCP Manager Parity

Evidence bundles:

- packages/runtime-daemon/src/index.mjs
- packages/runtime-daemon/src/mcp-manager.mjs
- packages/agent-sdk/src/messages.ts
- packages/agent-sdk/src/substrate-client.ts
- scripts/fixtures/mcp-stdio-echo-server.mjs
- scripts/lib/live-runtime-daemon-contract.test.mjs
- /tmp/ioi-autopilot-gui-harness-mcp-live-stdio/2026-05-13T14-11-08-493Z/result.json

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
  - daemon MCP invoke route syntax check passed with async live stdio calls.
- `node --check packages/runtime-daemon/src/mcp-manager.mjs`
  - daemon MCP manager syntax check passed with stdio transport helper.
- `node --check scripts/fixtures/mcp-stdio-echo-server.mjs`
  - deterministic MCP stdio fixture syntax check passed.
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live contract test harness syntax check passed.
- `cargo test -p ioi-cli --bin cli tui --quiet`
  - Rust TUI parser/control tests remained green for MCP line-mode commands.
- `npm run build --workspace=@ioi/agent-sdk`
  - SDK declaration and bundle build passed with transport execution metadata.
- `node --test --test-name-pattern "daemon owns MCP discovery|agent CLI exposes model|agent TUI line-mode|React Flow memory" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live daemon, SDK, TUI line-mode, source-contract, and React Flow projection
    proof passed with an actual stdio MCP server invocation.
- `node scripts/run-autopilot-gui-harness-validation.mjs --preflight --output-root /tmp/ioi-autopilot-gui-harness-mcp-live-stdio`
  - live autopilot GUI/workflow preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-mcp-live-stdio/2026-05-13T14-11-08-493Z/result.json`.
- `git diff --check`
  - whitespace check passed.

## Slice 145. 2026-05-13 - MCP resources/prompts discovery

Guide section: P1. MCP Manager Parity

Evidence bundles:

- packages/runtime-daemon/src/mcp-manager.mjs
- packages/runtime-daemon/src/index.mjs
- scripts/fixtures/mcp-stdio-echo-server.mjs
- packages/agent-sdk/src/messages.ts
- packages/agent-sdk/src/substrate-client.ts
- crates/cli/src/commands/agent_tui.rs
- crates/cli/src/commands/agent_tui_loop.rs
- packages/agent-ide/src/runtime/workflow-runtime-event-projection.ts
- packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts
- scripts/lib/live-runtime-daemon-contract.test.mjs
- /tmp/ioi-autopilot-gui-harness-mcp-resources-prompts/2026-05-13T14-30-00-293Z/result.json

Validation evidence:

- `node --check packages/runtime-daemon/src/mcp-manager.mjs`
  - daemon MCP catalog helper syntax check passed with stdio resource/prompt
    discovery.
- `node --check packages/runtime-daemon/src/index.mjs`
  - daemon route/control syntax check passed with resource/prompt endpoints.
- `node --check scripts/fixtures/mcp-stdio-echo-server.mjs`
  - deterministic MCP stdio fixture syntax check passed.
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live contract syntax check passed.
- `node --import tsx --test packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts`
  - React Flow TUI control-state projection tests passed with MCP
    resource/prompt rows.
- `npm run build --workspace=@ioi/agent-sdk`
  - SDK declaration and bundle build passed with resource/prompt list helpers.
- `npm run build --workspace=@ioi/agent-ide`
  - Agent IDE TypeScript and Vite build passed with MCP resource/prompt row
    projection.
- `cargo fmt -p ioi-cli -- --check`
  - Rust formatting check passed.
- `cargo test -p ioi-cli --bin cli tui --quiet`
  - Rust TUI parser/control tests remained green.
- `node --test --test-name-pattern "daemon owns MCP discovery|agent CLI exposes model|agent TUI line-mode|React Flow memory" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - focused live daemon/SDK/TUI/React Flow proof passed with MCP
    resources/prompts discovered from a stdio server.
- `node scripts/run-autopilot-gui-harness-validation.mjs --preflight --output-root /tmp/ioi-autopilot-gui-harness-mcp-resources-prompts`
  - GUI/workflow preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-mcp-resources-prompts/2026-05-13T14-30-00-293Z/result.json`.

## Slice 146. 2026-05-13 - MCP import/add/remove registry writes

Guide section: P1. MCP Manager Parity

Evidence bundles:

- packages/runtime-daemon/src/index.mjs
- packages/agent-sdk/src/messages.ts
- packages/agent-sdk/src/substrate-client.ts
- packages/agent-sdk/src/thread.ts
- crates/cli/src/commands/agent_tui.rs
- crates/cli/src/commands/agent_tui_loop.rs
- packages/agent-ide/src/types/graph.ts
- packages/agent-ide/src/features/Workflows/WorkflowNodeBindingEditor/sections.tsx
- packages/agent-ide/src/runtime/workflow-node-registry.ts
- scripts/lib/live-runtime-daemon-contract.test.mjs
- /tmp/ioi-autopilot-gui-harness-mcp-config-writes/2026-05-13T14-48-32-036Z/result.json

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
  - daemon MCP registry mutation route/control syntax check passed.
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live contract syntax check passed.
- `npm run build --workspace=@ioi/agent-sdk`
  - SDK declaration and bundle build passed with MCP import/add/remove helpers.
- `cargo fmt -p ioi-cli -- --check`
  - Rust formatting check passed.
- `cargo test -p ioi-cli --bin cli tui --quiet`
  - Rust TUI parser/control tests passed with MCP import/add/remove commands.
- `npm run build --workspace=@ioi/agent-ide`
  - Agent IDE TypeScript and Vite build passed with MCP registry mutation state
    operations.
- `node --import tsx --test packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts`
  - React Flow runtime event projection tests remained green.
- `node --test --test-name-pattern "daemon owns MCP discovery|agent CLI exposes model|agent TUI line-mode|React Flow memory" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - focused live daemon/SDK/TUI/React Flow proof passed with MCP registry
    import/add/remove writes.
- `node scripts/run-autopilot-gui-harness-validation.mjs --preflight --output-root /tmp/ioi-autopilot-gui-harness-mcp-config-writes`
  - GUI/workflow preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-mcp-config-writes/2026-05-13T14-48-32-036Z/result.json`.

## Slice 147. 2026-05-13 - Live MCP HTTP/SSE transport

Guide section: P1. MCP Manager Parity

Evidence bundles:

- packages/runtime-daemon/src/mcp-manager.mjs
- packages/runtime-daemon/src/index.mjs
- packages/agent-sdk/src/messages.ts
- packages/agent-sdk/src/substrate-client.ts
- packages/agent-ide/src/types/graph.ts
- packages/agent-ide/src/features/Workflows/WorkflowNodeBindingEditor/sections.tsx
- packages/agent-ide/src/runtime/workflow-node-registry.ts
- scripts/lib/live-runtime-daemon-contract.test.mjs
- /tmp/ioi-autopilot-gui-harness-mcp-http-sse/2026-05-13T15-06-56-740Z/result.json

Validation evidence:

- `node --check packages/runtime-daemon/src/mcp-manager.mjs`
  - daemon MCP manager syntax check passed with remote HTTP/SSE helpers.
- `node --check packages/runtime-daemon/src/index.mjs`
  - daemon route/control syntax check passed with live transport dispatch.
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live contract syntax check passed with deterministic HTTP/SSE MCP fixture.
- `npm run build --workspace=@ioi/agent-sdk`
  - SDK declaration and bundle build passed with remote transport typing.
- `npm run build --workspace=@ioi/agent-ide`
  - Agent IDE TypeScript and Vite build passed with MCP transport/URL/header
    workflow config fields.
- `node --import tsx --test packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts`
  - React Flow runtime event projection tests remained green.
- `node --test --test-name-pattern "daemon owns MCP discovery|agent CLI exposes model|agent TUI line-mode|React Flow memory" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - focused live daemon/SDK/TUI/React Flow proof passed with stdio, HTTP, and
    SSE MCP discovery/invocation receipts.
- `cargo fmt -p ioi-cli -- --check`
  - Rust formatting check passed.
- `cargo test -p ioi-cli --bin cli tui --quiet`
  - Rust TUI parser/control tests remained green.
- `node scripts/run-autopilot-gui-harness-validation.mjs --preflight --output-root /tmp/ioi-autopilot-gui-harness-mcp-http-sse`
  - GUI/workflow preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-mcp-http-sse/2026-05-13T15-06-56-740Z/result.json`.

## Slice 148. 2026-05-13 - Self-hosted MCP serve mode

Guide section: P1. MCP Manager Parity

Evidence bundles:

- packages/runtime-daemon/src/index.mjs
- packages/agent-sdk/src/substrate-client.ts
- packages/agent-sdk/src/thread.ts
- packages/agent-sdk/src/index.ts
- packages/agent-ide/src/types/graph.ts
- packages/agent-ide/src/runtime/workflow-node-registry.ts
- packages/agent-ide/src/features/Workflows/WorkflowNodeBindingEditor/sections.tsx
- scripts/lib/live-runtime-daemon-contract.test.mjs
- docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md
- docs/specs/runtime/agent-runtime-deepseek-parity-plus-implementation-log.md
- /tmp/ioi-autopilot-gui-harness-mcp-serve/2026-05-13T15-29-48-332Z/result.json

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
  - daemon MCP serve route/control syntax check passed.
- `node --check packages/runtime-daemon/src/mcp-manager.mjs`
  - daemon MCP manager syntax check remained green.
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live contract syntax check passed with MCP serve-mode coverage.
- `npm run build --workspace=@ioi/agent-sdk`
  - SDK declaration and bundle build passed with MCP serve RPC helpers.
- `npm run build --workspace=@ioi/agent-ide`
  - Agent IDE TypeScript and Vite build passed with MCP serve state-node
    configuration fields.
- `node --import tsx --test packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts`
  - React Flow runtime event projection tests remained green.
- `node --test --test-name-pattern "daemon owns MCP discovery|agent CLI exposes model|agent TUI line-mode|React Flow memory" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - focused live daemon/SDK/TUI/React Flow proof passed with MCP serve
    initialize, tools/list, tools/call, receipt, and workflow projection
    coverage.
- `cargo fmt -p ioi-cli -- --check`
  - Rust formatting check passed.
- `cargo test -p ioi-cli --bin cli tui --quiet`
  - Rust TUI parser/control tests remained green.
- `git diff --check`
  - whitespace check passed.
- `node scripts/run-autopilot-gui-harness-validation.mjs --preflight --output-root /tmp/ioi-autopilot-gui-harness-mcp-serve`
  - GUI/workflow preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-mcp-serve/2026-05-13T15-29-48-332Z/result.json`.

## Slice 149. 2026-05-13 - Remote MCP auth/vault header hardening

Guide section: P1. MCP Manager Parity

Evidence bundles:

- packages/runtime-daemon/src/mcp-manager.mjs
- packages/runtime-daemon/src/index.mjs
- packages/agent-ide/src/types/graph.ts
- packages/agent-ide/src/features/Workflows/WorkflowNodeBindingEditor/sections.tsx
- scripts/lib/live-runtime-daemon-contract.test.mjs
- docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md
- docs/specs/runtime/agent-runtime-deepseek-parity-plus-implementation-log.md
- /tmp/ioi-autopilot-gui-harness-mcp-auth-vault/2026-05-13T15-45-08-787Z/result.json

Validation evidence:

- `node --check packages/runtime-daemon/src/mcp-manager.mjs`
  - MCP manager syntax check passed with vault-backed remote header
    resolution.
- `node --check packages/runtime-daemon/src/index.mjs`
  - daemon route/control syntax check passed with VaultPort passed to live MCP
    discovery and invocation.
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live contract syntax check passed with secure HTTP/SSE fixture coverage.
- `npm run build --workspace=@ioi/agent-sdk`
  - SDK declaration and bundle build remained green.
- `npm run build --workspace=@ioi/agent-ide`
  - Agent IDE TypeScript and Vite build passed with vault-header UI wording.
- `node --import tsx --test packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts`
  - React Flow runtime event projection tests remained green.
- `node --test --test-name-pattern "daemon owns MCP discovery|agent CLI exposes model|agent TUI line-mode|React Flow memory" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - focused live daemon/SDK/TUI/React Flow proof passed with vault-backed
    remote HTTP/SSE headers, fail-closed raw auth validation, redacted status,
    and remote-only material observation.
- `cargo fmt -p ioi-cli -- --check`
  - Rust formatting check passed.
- `cargo test -p ioi-cli --bin cli tui --quiet`
  - Rust TUI parser/control tests remained green.
- `node scripts/run-autopilot-gui-harness-validation.mjs --preflight --output-root /tmp/ioi-autopilot-gui-harness-mcp-auth-vault`
  - GUI/workflow preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-mcp-auth-vault/2026-05-13T15-45-08-787Z/result.json`.

## Slice 150. 2026-05-13 - Large MCP catalog deferred search/fetch

Guide section: P1. MCP Manager Parity

Evidence bundles:

- packages/runtime-daemon/src/index.mjs
- packages/agent-sdk/src/messages.ts
- packages/agent-sdk/src/substrate-client.ts
- packages/agent-sdk/src/thread.ts
- packages/agent-sdk/src/index.ts
- packages/agent-ide/src/types/graph.ts
- packages/agent-ide/src/features/Workflows/WorkflowNodeBindingEditor/sections.tsx
- packages/agent-ide/src/runtime/workflow-node-registry.ts
- scripts/lib/live-runtime-daemon-contract.test.mjs
- docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md
- docs/specs/runtime/agent-runtime-deepseek-parity-plus-implementation-log.md
- /tmp/ioi-autopilot-gui-harness-mcp-large-catalog-search/2026-05-13T16-02-41-899Z/result.json

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
  - daemon route/control syntax check passed with MCP catalog search/fetch
    routes and bounded live catalog status exposure.
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live contract syntax check passed with the 80-tool MCP fixture.
- `npm run build --workspace=@ioi/agent-sdk`
  - SDK declaration and bundle build passed with MCP search/fetch helpers and
    catalog summary types.
- `npm run build --workspace=@ioi/agent-ide`
  - Agent IDE TypeScript and Vite build passed with MCP search/fetch workflow
    node metadata and binding controls.
- `node --import tsx --test packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts`
  - React Flow runtime event projection tests remained green.
- `node --test --test-name-pattern "daemon owns MCP discovery" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - focused live MCP proof passed with large-catalog summaries, preview limits,
    exact tool search, exact tool fetch, and root status payload bounding.
- `node --test --test-name-pattern "daemon owns MCP discovery|agent CLI exposes model|agent TUI line-mode|React Flow memory" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - focused daemon/SDK/TUI/React Flow source-contract proof remained green.
- `cargo fmt -p ioi-cli -- --check`
  - Rust formatting check passed.
- `cargo test -p ioi-cli --bin cli tui --quiet`
  - Rust TUI parser/control tests remained green.
- `node scripts/run-autopilot-gui-harness-validation.mjs --preflight --output-root /tmp/ioi-autopilot-gui-harness-mcp-large-catalog-search`
  - GUI/workflow preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-mcp-large-catalog-search/2026-05-13T16-02-41-899Z/result.json`.
- `git diff --check`
  - whitespace check passed.

## Slice 156. 2026-05-13 - Run-inspector diagnostics repair full recovery loop

Guide section: P0. Terminal Coding-Agent TUI / P0-C. Post-edit LSP Diagnostics

Evidence bundles:

- scripts/lib/live-runtime-daemon-contract.test.mjs
- docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md
- docs/specs/runtime/agent-runtime-deepseek-parity-plus-implementation-log.md
- docs/specs/runtime/agent-runtime-deepseek-parity-plus-validation-ledger.md
- /tmp/ioi-autopilot-gui-harness-diagnostics-repair-full-loop/2026-05-13T17-40-50-387Z/result.json

Validation evidence:

- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live daemon contract syntax check passed with the focused recovery-loop
    fixture.
- `npm run build --workspace=@ioi/agent-ide`
  - Agent IDE TypeScript and Vite build passed after adding diagnostics repair
    action/control-node sources to the live import freshness check.
- `node --test --test-name-pattern "run-inspector diagnostics repair action" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - focused live proof passed: projected React Flow row action compiled into a
    daemon repair request, emitted operator-override and repair-decision
    events, completed the blocked turn, refreshed React Flow projection, and
    replayed through `ioi agent tui --json`.
- `node --test --test-name-pattern "coding tool pack invokes" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - broad coding-pack SDK/CLI/TUI/React Flow regression remained green after
    moving the row-action proof into a clean fixture.
- `node --import tsx --test --test-name-pattern "diagnostics blocking gates" packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts`
  - blocking-gate projection regression passed.
- `node --test --test-name-pattern "React Flow memory, authority" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - workflow source-contract proof passed.
- `node scripts/run-autopilot-gui-harness-validation.mjs --preflight --output-root /tmp/ioi-autopilot-gui-harness-diagnostics-repair-full-loop`
  - GUI/workflow preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-diagnostics-repair-full-loop/2026-05-13T17-40-50-387Z/result.json`.

## Slice 155. 2026-05-13 - React Flow run-inspector diagnostics repair actions

Guide section: P0. Terminal Coding-Agent TUI / P0-C. Post-edit LSP Diagnostics

Evidence bundles:

- packages/agent-ide/src/runtime/workflow-runtime-event-projection.ts
- packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts
- packages/agent-ide/src/features/Workflows/WorkflowRailPanel/runsPanel.tsx
- packages/agent-ide/src/features/Workflows/WorkflowRailPanel/core.tsx
- packages/agent-ide/src/WorkflowComposer/controller.tsx
- packages/agent-ide/src/WorkflowComposer/view.tsx
- packages/agent-ide/src/WorkflowComposer/styles/composer-panels.css
- packages/agent-ide/src/runtime/graph-runtime-types.ts
- packages/agent-ide/src/index.ts
- apps/autopilot/src/services/TauriRuntime.ts
- apps/autopilot/src-tauri/src/kernel/artifacts/mod.rs
- apps/autopilot/src-tauri/src/lib.rs
- scripts/lib/live-runtime-daemon-contract.test.mjs
- docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md
- docs/specs/runtime/agent-runtime-deepseek-parity-plus-implementation-log.md
- docs/specs/runtime/agent-runtime-deepseek-parity-plus-validation-ledger.md
- /tmp/ioi-autopilot-gui-harness-diagnostics-repair-run-inspector/2026-05-13T17-22-14-924Z/result.json

Validation evidence:

- `node --import tsx --test --test-name-pattern "diagnostics blocking gates" packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts`
  - focused projection test passed for blocking-gate diagnostics repair action
    descriptors.
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
  - source-contract syntax check passed.
- `npm run build --workspace=@ioi/agent-ide`
  - Agent IDE TypeScript and Vite build passed with run-inspector action
    descriptors and public exports.
- `rustfmt --check apps/autopilot/src-tauri/src/kernel/artifacts/mod.rs apps/autopilot/src-tauri/src/lib.rs`
  - Rust formatting check passed for the Tauri daemon bridge command.
- `node --test --test-name-pattern "React Flow memory, authority" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - focused source-contract proof passed for row-action controls,
    projection parsing, controller dispatch, graph runtime types, and Tauri
    command registration.
- `cargo check --manifest-path apps/autopilot/src-tauri/Cargo.toml`
  - Tauri crate compiled with the new runtime-control bridge.
- `npm run build --workspace=autopilot`
  - Autopilot app TypeScript and Vite build passed.
- `node scripts/run-autopilot-gui-harness-validation.mjs --preflight --output-root /tmp/ioi-autopilot-gui-harness-diagnostics-repair-run-inspector`
  - GUI/workflow preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-diagnostics-repair-run-inspector/2026-05-13T17-22-14-924Z/result.json`.
- `git diff --check`
  - whitespace check passed.

## Slice 154. 2026-05-13 - React Flow diagnostics repair action node

Guide section: P0. Terminal Coding-Agent TUI / P0-C. Post-edit LSP Diagnostics

Evidence bundles:

- packages/agent-ide/src/runtime/workflow-runtime-control-nodes.ts
- packages/agent-ide/src/runtime/workflow-runtime-control-nodes.test.ts
- packages/agent-ide/src/runtime/workflow-node-registry.ts
- packages/agent-ide/src/runtime/workflow-schema.ts
- packages/agent-ide/src/types/graph.ts
- apps/autopilot/src-tauri/src/project/workflow_node_execution_lane.rs
- apps/autopilot/src-tauri/src/runtime_projection.rs
- scripts/lib/live-runtime-daemon-contract.test.mjs
- docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md
- docs/specs/runtime/agent-runtime-deepseek-parity-plus-implementation-log.md
- docs/specs/runtime/agent-runtime-deepseek-parity-plus-validation-ledger.md
- /tmp/ioi-autopilot-gui-harness-diagnostics-repair-react-flow/2026-05-13T16-59-53-289Z/result.json

Validation evidence:

- `rustfmt --check apps/autopilot/src-tauri/src/runtime_projection.rs apps/autopilot/src-tauri/src/project/workflow_node_execution_lane.rs apps/autopilot/src-tauri/src/generated/runtime_action_schema.rs`
  - Rust formatting check passed for the touched Tauri projection/generated
    files.
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml substrate_classifies_workflow_node_kinds -- --nocapture`
  - focused Rust substrate classification proof passed with the new
    `RuntimeDiagnosticsRepair` action kind.
- `node --import tsx --test packages/agent-ide/src/runtime/workflow-runtime-control-nodes.test.ts`
  - runtime-control request-builder tests passed, including diagnostics repair
    graph identity, action normalization, approval, and conflict fields.
- `npm run build --workspace=@ioi/agent-ide`
  - Agent IDE TypeScript and Vite build passed with the new workflow node,
    schema, localization, and canvas metadata.
- `node --test --test-name-pattern "React Flow memory, authority" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - focused source-contract proof passed for the workflow node registry, graph
    types, request builder, runtime projection adapter, and generated action
    schema additions.
- `node scripts/run-autopilot-gui-harness-validation.mjs --preflight --output-root /tmp/ioi-autopilot-gui-harness-diagnostics-repair-react-flow`
  - GUI/workflow preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-diagnostics-repair-react-flow/2026-05-13T16-59-53-289Z/result.json`.
- `git diff --check`
  - whitespace check passed.

## Slice 153. 2026-05-13 - TUI diagnostics repair decision controls

Guide section: P0. Terminal Coding-Agent TUI / P0-C. Post-edit LSP Diagnostics

Evidence bundles:

- crates/cli/src/commands/agent_tui.rs
- crates/cli/src/commands/agent_tui_loop.rs
- scripts/lib/live-runtime-daemon-contract.test.mjs
- docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md
- docs/specs/runtime/agent-runtime-deepseek-parity-plus-implementation-log.md
- docs/specs/runtime/agent-runtime-deepseek-parity-plus-validation-ledger.md
- /tmp/ioi-autopilot-gui-harness-diagnostics-repair-tui/2026-05-13T16-45-07-095Z/result.json

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
  - daemon syntax stayed green for the existing diagnostics repair endpoint.
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live contract syntax check passed with the new TUI diagnostics repair
    source-contract assertions.
- `cargo fmt -p ioi-cli`
  - Rust formatting applied to the TUI command parser and helper changes.
- `cargo fmt -p ioi-cli -- --check`
  - CLI formatting check passed.
- `cargo test -p ioi-cli --bin cli tui --quiet`
  - focused TUI test target passed with 10 tests, including repair command
    parsing and approval guards.
- `node --test --test-name-pattern "agent CLI exposes model" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - source-contract proof passed for the diagnostics repair execute route, TUI
    helper, slash command, and line-mode output.
- `node --test --test-name-pattern "agent TUI thin shell is daemon-backed" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - thin-shell guard passed with the repair route and helper still
    daemon-backed.
- `node --test --test-name-pattern "agent TUI line-mode slash commands" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live line-mode proof stayed green after expanding the help/parser surface.
- `node --test --test-name-pattern "coding tool pack invokes status" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live daemon/SDK/CLI/TUI/React Flow coding tool-pack proof passed, including
    existing SDK diagnostics repair retry, restore preview/apply, and operator
    override execution.
- `node scripts/run-autopilot-gui-harness-validation.mjs --preflight --output-root /tmp/ioi-autopilot-gui-harness-diagnostics-repair-tui`
  - GUI/workflow preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-diagnostics-repair-tui/2026-05-13T16-45-07-095Z/result.json`.
- `git diff --check`
  - whitespace check passed.

## Slice 152. 2026-05-13 - TUI MCP search/fetch source-mode UX

Guide section: P0. Terminal Coding-Agent TUI / P1. MCP Manager Parity

Evidence bundles:

- crates/cli/src/commands/agent_tui.rs
- crates/cli/src/commands/agent_tui_loop.rs
- packages/runtime-daemon/src/index.mjs
- scripts/lib/live-runtime-daemon-contract.test.mjs
- docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md
- docs/specs/runtime/agent-runtime-deepseek-parity-plus-implementation-log.md
- docs/specs/runtime/agent-runtime-deepseek-parity-plus-validation-ledger.md
- /tmp/ioi-autopilot-gui-harness-mcp-tui-search-fetch/2026-05-13T16-35-16-836Z/result.json

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
  - daemon syntax check passed with thread-scoped MCP search/fetch
    source-mode filtering.
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live contract syntax check passed with TUI search/fetch assertions.
- `cargo fmt -p ioi-cli`
  - Rust formatting applied to TUI changes.
- `cargo fmt -p ioi-cli -- --check`
  - CLI formatting check passed.
- `cargo test -p ioi-cli --bin cli tui --quiet`
  - focused TUI test target passed with 10 tests.
- `node --test --test-name-pattern "agent TUI line-mode slash commands" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live line-mode proof passed for `/mcp search`, `/mcp fetch`, source-mode
    flags, and MCP search/fetch rows.
- `node --test --test-name-pattern "agent CLI exposes model" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - source-contract proof passed for the TUI MCP search/fetch routes and
    source-mode wiring.
- `node scripts/run-autopilot-gui-harness-validation.mjs --preflight --output-root /tmp/ioi-autopilot-gui-harness-mcp-tui-search-fetch`
  - GUI/workflow preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-mcp-tui-search-fetch/2026-05-13T16-35-16-836Z/result.json`.
- `git diff --check`
  - whitespace check passed.

## Slice 151. 2026-05-13 - Global IOI MCP config discovery

Guide section: P1. MCP Manager Parity

Evidence bundles:

- packages/runtime-daemon/src/mcp-manager.mjs
- packages/runtime-daemon/src/index.mjs
- packages/agent-sdk/src/messages.ts
- packages/agent-ide/src/types/graph.ts
- packages/agent-ide/src/features/Workflows/WorkflowNodeBindingEditor/sections.tsx
- packages/agent-ide/src/runtime/workflow-node-registry.ts
- scripts/lib/live-runtime-daemon-contract.test.mjs
- docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md
- docs/specs/runtime/agent-runtime-deepseek-parity-plus-implementation-log.md
- docs/specs/runtime/agent-runtime-deepseek-parity-plus-validation-ledger.md
- /tmp/ioi-autopilot-gui-harness-mcp-global-config/2026-05-13T16-20-04-651Z/result.json

Validation evidence:

- `node --check packages/runtime-daemon/src/mcp-manager.mjs`
  - MCP manager syntax check passed with `$HOME/.ioi/mcp.json` global source
    loading and source-mode normalization.
- `node --check packages/runtime-daemon/src/index.mjs`
  - daemon route/control syntax check passed with source-mode filtering and
    validation provenance.
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live contract syntax check passed with global home MCP fixture coverage.
- `npm run build --workspace=@ioi/agent-sdk`
  - SDK declaration and bundle build passed with MCP source provenance fields.
- `npm run build --workspace=@ioi/agent-ide`
  - Agent IDE TypeScript and Vite build passed with MCP source-mode authoring
    controls.
- `node --test --test-name-pattern "daemon owns MCP discovery" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - focused live MCP proof passed with global IOI config discovery, source
    filtering, redacted global vault refs, and existing live transport and
    large-catalog regression coverage.
- `node --import tsx --test packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts`
  - React Flow runtime event projection tests remained green.
- `node --test --test-name-pattern "agent CLI exposes model|React Flow memory" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - source-contract proof passed for runtime source provenance and React Flow
    config-source controls.
- `cargo fmt -p ioi-cli -- --check`
  - CLI formatting check passed.
- `cargo test -p ioi-cli --bin cli tui --quiet`
  - focused TUI test target passed with 10 tests.
- `node scripts/run-autopilot-gui-harness-validation.mjs --preflight --output-root /tmp/ioi-autopilot-gui-harness-mcp-global-config`
  - GUI/workflow preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-mcp-global-config/2026-05-13T16-20-04-651Z/result.json`.
- `git diff --check`
  - whitespace check passed.

## Slice 137. 2026-05-13 - Executable diagnostics repair retry

Guide section: P0-C. Post-edit LSP Diagnostics

Evidence bundles:

- packages/runtime-daemon/src/index.mjs
- packages/agent-sdk/src/substrate-client.ts
- packages/agent-ide/src/runtime/workflow-runtime-event-projection.ts
- packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts
- scripts/lib/live-runtime-daemon-contract.test.mjs
- scripts/lib/workflow-coding-tool-pack-policy-contract.test.mjs
- /tmp/ioi-autopilot-gui-harness-diagnostics-repair-retry/2026-05-13T08-20-57-956Z/result.json

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
  - daemon syntax check passed after adding repair retry execution.
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live contract syntax check passed.
- `node --check scripts/lib/workflow-coding-tool-pack-policy-contract.test.mjs`
  - workflow source-contract syntax check passed.
- `node --test scripts/lib/workflow-coding-tool-pack-policy-contract.test.mjs`
  - source contract passed for repair retry runtime/SDK/projection markers.
- `node --import tsx --test --test-name-pattern "diagnostics repair decisions|diagnostics repair retry|diagnostics blocking gates" packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts`
  - React Flow projection passed for blocking gates, repair decisions, and
    repair retry rows.
- `npm run build --workspace=@ioi/agent-sdk`
  - SDK declaration and bundle build passed with repair retry result typing.
- `npm run build --workspace=@ioi/agent-ide`
  - agent-ide TypeScript and Vite build passed.
- `node --test --test-name-pattern "coding tool pack invokes" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live daemon/SDK/CLI/TUI/React Flow proof passed with `repair_retry`
    execution, retry turn context injection, daemon SSE, SDK events, and React
    Flow projection.
- `git diff --check`
  - whitespace check passed.
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-diagnostics-repair-retry`
  - live GUI/workflow preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-diagnostics-repair-retry/2026-05-13T08-20-57-956Z/result.json`.

## Slice 138. 2026-05-13 - Executable diagnostics operator override

Guide section: P0-C. Post-edit LSP Diagnostics

Evidence bundles:

- packages/runtime-daemon/src/index.mjs
- packages/agent-sdk/src/substrate-client.ts
- packages/agent-ide/src/runtime/workflow-runtime-event-projection.ts
- packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts
- scripts/lib/live-runtime-daemon-contract.test.mjs
- scripts/lib/workflow-coding-tool-pack-policy-contract.test.mjs
- /tmp/ioi-autopilot-gui-harness-diagnostics-operator-override/2026-05-13T08-53-15-768Z/result.json

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
  - daemon syntax check passed after adding operator override execution.
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live contract syntax check passed.
- `node --check scripts/lib/workflow-coding-tool-pack-policy-contract.test.mjs`
  - workflow source-contract syntax check passed.
- `node --test scripts/lib/workflow-coding-tool-pack-policy-contract.test.mjs`
  - source contract passed for operator override runtime/SDK/projection markers.
- `node --import tsx --test --test-name-pattern "diagnostics repair decisions|diagnostics repair retry|diagnostics operator overrides|diagnostics blocking gates" packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts`
  - React Flow projection passed for blocking gates, repair decisions, repair
    retry rows, and operator override rows.
- `npm run build --workspace=@ioi/agent-sdk`
  - SDK declaration and bundle build passed with operator override result
    typing.
- `npm run build --workspace=@ioi/agent-ide`
  - agent-ide TypeScript and Vite build passed.
- `node --test --test-name-pattern "coding tool pack invokes" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live daemon/SDK/CLI/TUI/React Flow proof passed with `operator_override`
    execution, approval-required blocking, approval-granted continuation,
    daemon SSE, SDK events, and React Flow projection.
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-diagnostics-operator-override`
  - live GUI/workflow preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-diagnostics-operator-override/2026-05-13T08-53-15-768Z/result.json`.

## Slice 125. 2026-05-13 - Automatic post-edit diagnostics injection loop

Guide section: P0-C. Post-edit LSP Diagnostics

Evidence bundles:

- packages/runtime-daemon/src/index.mjs
- packages/runtime-daemon/src/coding-tools.mjs
- packages/agent-sdk/src/messages.ts
- packages/agent-sdk/src/substrate-client.ts
- crates/types/src/app/runtime/thread_turn_item.rs
- packages/agent-ide/src/types/graph.ts
- packages/agent-ide/src/features/Workflows/WorkflowNodeBindingEditor/sections.tsx
- packages/agent-ide/src/runtime/workflow-node-registry.ts
- packages/agent-ide/src/runtime/workflow-runtime-event-projection.ts
- packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts
- scripts/lib/live-runtime-daemon-contract.test.mjs
- /tmp/ioi-autopilot-gui-harness-post-edit-diagnostics-injection/2026-05-13T04-32-30-977Z/result.json

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs && node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
  - daemon index and live contract syntax checks passed.
- `node --check packages/runtime-daemon/src/coding-tools.mjs`
  - daemon coding-tools syntax check passed.
- `npm run build --workspace=@ioi/agent-sdk`
  - SDK declaration and bundle build passed.
- `npm run build --workspace=@ioi/agent-ide`
  - agent-ide TypeScript and Vite build passed.
- `node --import tsx --test --test-name-pattern "projects coding tool" packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts`
  - React Flow projection test passed for injected diagnostics rows.
- `node --test --test-name-pattern "coding tool pack invokes" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live daemon/SDK/CLI/TUI/React Flow coding tool-pack proof passed for
    automatic diagnostics, next-turn compact injection, and nested React Flow
    diagnostics `skip` config.
- `node --test --test-name-pattern "RUNTIME_EVENT_SOURCES|runtime event|TTI" scripts/lib/live-bridge-tti-schema-contract.test.mjs`
  - Rust/TypeScript live bridge TTI schema literal guard passed with
    `runtime_auto`.
- `rustfmt --check crates/types/src/app/runtime/thread_turn_item.rs`
  - touched Rust schema file formatting check passed.
- `cargo check -p ioi-types`
  - Rust types package check passed.
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-post-edit-diagnostics-injection`
  - live GUI/workflow preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-post-edit-diagnostics-injection/2026-05-13T04-32-30-977Z/result.json`.

Known validation note:

- Broad `cargo fmt --all -- --check` remains blocked by unrelated formatting
  drift in `apps/autopilot/src-tauri/src/orchestrator/store/*.rs`; this slice's
  touched Rust file passed direct `rustfmt --check`.

## Slice 126. 2026-05-13 - Blocking post-edit diagnostics repair gate

Guide section: P0-C. Post-edit LSP Diagnostics

Evidence bundles:

- packages/runtime-daemon/src/index.mjs
- packages/agent-ide/src/runtime/workflow-runtime-event-projection.ts
- packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts
- scripts/lib/live-runtime-daemon-contract.test.mjs
- /tmp/ioi-autopilot-gui-harness-blocking-diagnostics-gate/2026-05-13T04-49-47-650Z/result.json

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs && node --check scripts/lib/live-runtime-daemon-contract.test.mjs && node --check packages/runtime-daemon/src/coding-tools.mjs`
  - runtime daemon, live contract, and coding-tools syntax checks passed.
- `npm run build --workspace=@ioi/agent-sdk`
  - SDK declaration and bundle build passed.
- `npm run build --workspace=@ioi/agent-ide`
  - agent-ide TypeScript and Vite build passed.
- `node --import tsx --test --test-name-pattern "projects coding tool|approval and policy|diagnostics blocking gates" packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts`
  - React Flow projection passed for coding-tool rows, generic policy gates,
    and diagnostics blocking-gate nodes.
- `node --test --test-name-pattern "coding tool pack invokes" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live daemon/SDK/CLI/TUI/React Flow coding tool-pack proof passed for
    advisory diagnostics injection, blocking diagnostics repair gate,
    `policy.blocked` TTI projection, SDK normalization, and React Flow gate
    rows.
- `node --test --test-name-pattern "RUNTIME_EVENT_SOURCES|runtime event|TTI" scripts/lib/live-bridge-tti-schema-contract.test.mjs`
  - Rust/TypeScript live bridge TTI schema literal guard passed.
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-blocking-diagnostics-gate`
  - live GUI/workflow preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-blocking-diagnostics-gate/2026-05-13T04-49-47-650Z/result.json`.

## Slice 127. 2026-05-13 - Project-aware diagnostics backend ladder

Guide section: P0-C. Post-edit LSP Diagnostics

Evidence bundles:

- packages/runtime-daemon/src/coding-tools.mjs
- packages/runtime-daemon/src/index.mjs
- packages/agent-sdk/src/substrate-client.ts
- packages/agent-ide/src/features/Workflows/WorkflowNodeBindingEditor/sections.tsx
- packages/agent-ide/src/runtime/workflow-node-registry.ts
- crates/cli/src/commands/agent.rs
- crates/cli/src/commands/agent_tui_loop.rs
- scripts/lib/live-runtime-daemon-contract.test.mjs
- /tmp/ioi-autopilot-gui-harness-project-aware-diagnostics/2026-05-13T05-02-46-174Z/result.json

Validation evidence:

- `node --check packages/runtime-daemon/src/coding-tools.mjs`
  - coding-tools syntax check passed after adding the diagnostics planner and
    workspace-safe path walking.
- `node --check packages/runtime-daemon/src/index.mjs`
  - runtime daemon syntax check passed with `auto` as the post-edit diagnostics
    default.
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live contract syntax check passed.
- `node --test --test-name-pattern "coding tool pack invokes" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live daemon/SDK/CLI/TUI/React Flow coding tool-pack proof passed for
    project-aware `auto` TypeScript diagnostics, post-edit runtime-auto
    findings, and degraded/fallback receipts when local `tsc` is unavailable.
- `node --import tsx --test --test-name-pattern "projects coding tool|diagnostics blocking gates" packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts`
  - React Flow projection passed for coding-tool rows and diagnostics
    blocking-gate nodes.
- `node --test --test-name-pattern "agent CLI exposes model|agent TUI thin shell is daemon-backed" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - CLI/TUI source-contract guards passed after the `/diagnostics` default moved
    to `auto`.
- `node --test --test-name-pattern "RUNTIME_EVENT_SOURCES|runtime event|TTI" scripts/lib/live-bridge-tti-schema-contract.test.mjs`
  - live bridge TTI schema guards passed.
- `npm run build --workspace=@ioi/agent-sdk`
  - SDK declaration and bundle build passed.
- `npm run build --workspace=@ioi/agent-ide`
  - agent-ide TypeScript and Vite build passed.
- `cargo fmt -p ioi-cli -- --check`
  - CLI formatting check passed.
- `cargo check -p ioi-cli --bin cli`
  - CLI binary check passed.
- `cargo test -p ioi-cli --bin cli parses_nested_tool_and_policy_commands -- --nocapture`
  - CLI coding-tool parser test passed.
- `cargo test -p ioi-cli --bin cli parses_line_mode_slash_commands -- --nocapture`
  - TUI slash-command parser test passed.
- `git diff --check`
  - diff whitespace check passed.
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-project-aware-diagnostics`
  - live GUI/workflow preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-project-aware-diagnostics/2026-05-13T05-02-46-174Z/result.json`.

## Slice 128. 2026-05-13 - Workspace snapshot records for mutating coding tools

Guide section: P0-D. Workspace Rollback Snapshots

Evidence bundles:

- packages/runtime-daemon/src/coding-tools.mjs
- packages/runtime-daemon/src/index.mjs
- packages/agent-sdk/src/substrate-client.ts
- packages/agent-ide/src/runtime/workflow-runtime-event-projection.ts
- packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts
- scripts/lib/live-runtime-daemon-contract.test.mjs
- docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md
- docs/specs/runtime/agent-runtime-deepseek-parity-plus-implementation-log.md
- docs/specs/runtime/agent-runtime-deepseek-parity-plus-validation-ledger.md
- /tmp/ioi-autopilot-gui-harness-workspace-snapshots/2026-05-13T05-16-45-830Z/result.json

Validation evidence:

- `node --check packages/runtime-daemon/src/coding-tools.mjs`
  - coding-tools syntax check passed after adding changed-file stat metadata and
    workspace snapshot receipt requirements.
- `node --check packages/runtime-daemon/src/index.mjs`
  - runtime daemon syntax check passed after adding snapshot record creation,
    artifact materialization, and `workspace.snapshot.created` event emission.
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live contract syntax check passed.
- `node --import tsx --test --test-name-pattern "projects coding tool" packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts`
  - React Flow coding-tool projection test passed with workspace snapshot rows.
- `node --import tsx --test --test-name-pattern "projects coding tool|diagnostics blocking gates" packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts`
  - React Flow projection test passed for coding-tool and diagnostics gate rows.
- `node --test --test-name-pattern "coding tool pack invokes" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live daemon/SDK/CLI/TUI/React Flow coding tool-pack proof passed for
    metadata-only workspace snapshots, rollback refs, snapshot artifacts, and
    snapshot event projection.
- `npm run build --workspace=@ioi/agent-sdk`
  - SDK declaration and bundle build passed with workspace snapshot result
    fields.
- `npm run build --workspace=@ioi/agent-ide`
  - agent-ide TypeScript and Vite build passed.
- `node --test --test-name-pattern "agent CLI exposes model|agent TUI thin shell is daemon-backed" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - CLI/TUI source-contract guards passed.
- `node --test --test-name-pattern "RUNTIME_EVENT_SOURCES|runtime event|TTI" scripts/lib/live-bridge-tti-schema-contract.test.mjs`
  - live bridge TTI schema guards passed.
- `git diff --check`
  - diff whitespace check passed.
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-workspace-snapshots`
  - live GUI/workflow preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-workspace-snapshots/2026-05-13T05-16-45-830Z/result.json`.

## Slice 129. 2026-05-13 - Content-backed workspace restore preview

Guide section: P0-D. Workspace Rollback Snapshots

Evidence bundles:

- packages/runtime-daemon/src/coding-tools.mjs
- packages/runtime-daemon/src/index.mjs
- packages/agent-sdk/src/substrate-client.ts
- packages/agent-ide/src/runtime/workflow-runtime-event-projection.ts
- packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts
- scripts/lib/live-runtime-daemon-contract.test.mjs
- docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md
- docs/specs/runtime/agent-runtime-deepseek-parity-plus-implementation-log.md
- docs/specs/runtime/agent-runtime-deepseek-parity-plus-validation-ledger.md
- /tmp/ioi-autopilot-gui-harness-workspace-restore-preview/2026-05-13T05-42-32-697Z/result.json

Validation evidence:

- `node --check packages/runtime-daemon/src/coding-tools.mjs`
  - coding-tools syntax check passed after adding private snapshot content drafts
    for applied patches.
- `node --check packages/runtime-daemon/src/index.mjs`
  - runtime daemon syntax check passed after adding snapshot content artifacts,
    snapshot listing, restore preview routing, and restore preview events.
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live contract syntax check passed.
- `npm run build --workspace=@ioi/agent-sdk`
  - SDK declaration and bundle build passed with snapshot listing and restore
    preview helpers.
- `node --test --test-name-pattern "coding tool pack invokes" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live daemon/SDK/CLI/TUI/React Flow coding tool-pack proof passed for
    content-backed snapshot artifact readback, restore preview, SDK helper,
    restore preview events, and React Flow restore-gate projection. The first
    run failed only because the test selected the new snapshot `artifact.read`
    event instead of the existing test-output `artifact.read` event; the lookup
    was narrowed to the intended workflow node and the suite passed.
- `node --import tsx --test --test-name-pattern "projects coding tool|diagnostics blocking gates" packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts`
  - React Flow projection tests passed for coding-tool, workspace snapshot,
    restore preview, and diagnostics gate rows.
- `npm run build --workspace=@ioi/agent-ide`
  - agent-ide TypeScript and Vite build passed.
- `node --test --test-name-pattern "agent CLI exposes model|agent TUI thin shell is daemon-backed" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - CLI/TUI source-contract guards passed.
- `node --test --test-name-pattern "RUNTIME_EVENT_SOURCES|runtime event|TTI" scripts/lib/live-bridge-tti-schema-contract.test.mjs`
  - live bridge TTI schema guards passed.
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-workspace-restore-preview`
  - live GUI/workflow preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-workspace-restore-preview/2026-05-13T05-42-32-697Z/result.json`.

## Slice 130. 2026-05-13 - Policy-gated workspace restore apply

Guide section: P0-D. Workspace Rollback Snapshots

Evidence bundles:

- packages/runtime-daemon/src/workspace-restore.mjs
- packages/runtime-daemon/src/index.mjs
- packages/agent-sdk/src/substrate-client.ts
- packages/agent-ide/src/runtime/workflow-runtime-event-projection.ts
- packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts
- scripts/lib/live-runtime-daemon-contract.test.mjs
- docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md
- docs/specs/runtime/agent-runtime-deepseek-parity-plus-implementation-log.md
- docs/specs/runtime/agent-runtime-deepseek-parity-plus-validation-ledger.md
- /tmp/ioi-autopilot-gui-harness-workspace-restore-apply/2026-05-13T05-59-11-822Z/result.json

Validation evidence:

- `node --check packages/runtime-daemon/src/workspace-restore.mjs`
  - workspace restore helper syntax check passed.
- `node --check packages/runtime-daemon/src/index.mjs`
  - runtime daemon syntax check passed after adding restore-apply routing,
    artifact materialization, and restore apply events.
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live contract syntax check passed.
- `node --import tsx --test --test-name-pattern "projects coding tool|diagnostics blocking gates" packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts`
  - React Flow projection tests passed for coding-tool, workspace snapshot,
    restore preview, restore apply, and diagnostics gate rows.
- `npm run build --workspace=@ioi/agent-sdk`
  - SDK declaration and bundle build passed with restore apply request/result
    helpers.
- `node --test --test-name-pattern "coding tool pack invokes" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live daemon/SDK/CLI/TUI/React Flow coding tool-pack proof passed for
    blocked-without-approval restore apply, approved apply, SDK noop replay,
    restore apply events, and React Flow restore-gate projection.
- `npm run build --workspace=@ioi/agent-ide`
  - agent-ide TypeScript and Vite build passed.
- `node --test --test-name-pattern "agent CLI exposes model|agent TUI thin shell is daemon-backed" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - CLI/TUI source-contract guards passed.
- `node --test --test-name-pattern "RUNTIME_EVENT_SOURCES|runtime event|TTI" scripts/lib/live-bridge-tti-schema-contract.test.mjs`
  - live bridge TTI schema guards passed.
- `git diff --check`
  - diff whitespace check passed.
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-workspace-restore-apply`
  - live GUI/workflow preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-workspace-restore-apply/2026-05-13T05-59-11-822Z/result.json`.

## Slice 131. 2026-05-13 - Diagnostics rollback/repair policy

Guide section: P0-C. Post-edit LSP Diagnostics

Evidence bundles:

- packages/runtime-daemon/src/index.mjs
- packages/agent-sdk/src/runtime-events.ts
- packages/agent-sdk/src/substrate-client.ts
- packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts
- scripts/lib/live-runtime-daemon-contract.test.mjs
- docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md
- docs/specs/runtime/agent-runtime-deepseek-parity-plus-implementation-log.md
- docs/specs/runtime/agent-runtime-deepseek-parity-plus-validation-ledger.md
- /tmp/ioi-autopilot-gui-harness-diagnostics-rollback-repair-policy/2026-05-13T06-12-33-948Z/result.json

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
  - runtime daemon syntax check passed after adding diagnostics rollback/repair
    context and policy decision metadata.
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live contract syntax check passed.
- `node --import tsx --test --test-name-pattern "projects coding tool|diagnostics blocking gates" packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts`
  - React Flow projection tests passed for diagnostics gate rollback refs and
    policy decision refs.
- `npm run build --workspace=@ioi/agent-sdk`
  - SDK declaration and bundle build passed with runtime event rollback refs in
    mock envelopes.
- `node --test --test-name-pattern "coding tool pack invokes" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live daemon/SDK/CLI/TUI/React Flow coding tool-pack proof passed for
    blocking diagnostics carrying workspace snapshot refs, rollback refs,
    repair/restore decision refs, SDK projection, and React Flow projection.
- `npm run build --workspace=@ioi/agent-ide`
  - agent-ide TypeScript and Vite build passed.
- `node --test --test-name-pattern "agent CLI exposes model|agent TUI thin shell is daemon-backed" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - CLI/TUI source-contract guards passed.
- `node --test --test-name-pattern "RUNTIME_EVENT_SOURCES|runtime event|TTI" scripts/lib/live-bridge-tti-schema-contract.test.mjs`
  - live bridge TTI schema guards passed.
- `git diff --check`
  - diff whitespace check passed.
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-diagnostics-rollback-repair-policy`
  - live GUI/workflow preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-diagnostics-rollback-repair-policy/2026-05-13T06-12-33-948Z/result.json`.

## Slice 132. 2026-05-13 - Workflow restore and diagnostics repair binding controls

Guide section: P0-B/P0-C/P0-D. Workflow Restore/Repair Controls

Evidence bundles:

- packages/agent-ide/src/types/graph.ts
- packages/agent-ide/src/features/Workflows/WorkflowNodeBindingEditor/sections.tsx
- packages/agent-ide/src/runtime/workflow-node-registry.ts
- packages/runtime-daemon/src/coding-tools.mjs
- packages/runtime-daemon/src/index.mjs
- scripts/lib/live-runtime-daemon-contract.test.mjs
- scripts/lib/workflow-coding-tool-pack-policy-contract.test.mjs
- docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md
- docs/specs/runtime/agent-runtime-deepseek-parity-plus-implementation-log.md
- docs/specs/runtime/agent-runtime-deepseek-parity-plus-validation-ledger.md
- /tmp/ioi-autopilot-gui-harness-workflow-restore-repair-binding-controls/2026-05-13T06-25-02-908Z/result.json

Validation evidence:

- `node --check packages/runtime-daemon/src/index.mjs`
  - runtime daemon syntax check passed after adding workflow-authored restore
    and diagnostics repair policy parsing.
- `node --check packages/runtime-daemon/src/coding-tools.mjs`
  - coding-tool catalog syntax check passed after adding workflow config fields.
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live contract syntax check passed.
- `node --check scripts/lib/workflow-coding-tool-pack-policy-contract.test.mjs`
  - React Flow policy-control source-contract syntax check passed.
- `node --test scripts/lib/workflow-coding-tool-pack-policy-contract.test.mjs`
  - React Flow source-contract guard passed for typed config, editor controls,
    creator defaults, daemon catalog fields, and runtime policy parsing hooks.
- `node --test --test-name-pattern "coding tool pack invokes" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live daemon/SDK/CLI/TUI/React Flow coding tool-pack proof passed with
    workflow-authored `preview_only`, `require_approval`, `restore_preview`,
    and operator-override approval settings reflected in diagnostics repair
    context, injection policy, and blocking gate.
- `npm run build --workspace=@ioi/agent-ide`
  - agent-ide TypeScript and Vite build passed.
- `node --test --test-name-pattern "RUNTIME_EVENT_SOURCES|runtime event|TTI" scripts/lib/live-bridge-tti-schema-contract.test.mjs`
  - live bridge TTI schema guards passed.
- `git diff --check`
  - diff whitespace check passed.
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-workflow-restore-repair-binding-controls`
  - live GUI/workflow preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-workflow-restore-repair-binding-controls/2026-05-13T06-25-02-908Z/result.json`.

## Slice 133. 2026-05-13 - Restore workflow nodes and request builders

Guide section: P0-D. Workspace Rollback Snapshots

Evidence bundles:

- packages/agent-ide/src/runtime/workflow-runtime-control-nodes.ts
- packages/agent-ide/src/runtime/workflow-runtime-control-nodes.test.ts
- packages/agent-ide/src/runtime/workflow-node-registry.ts
- packages/agent-ide/src/runtime/workflow-schema.ts
- packages/agent-ide/src/runtime/runtime-projection-adapter.ts
- packages/agent-ide/src/types/graph.ts
- apps/autopilot/src-tauri/src/runtime_projection.rs
- apps/autopilot/src-tauri/src/project/templates.rs
- apps/autopilot/src-tauri/src/project/workflow_node_execution_lane.rs
- apps/autopilot/src-tauri/src/project/validation.rs
- docs/implementation/runtime-action-schema.json
- scripts/lib/live-runtime-daemon-contract.test.mjs
- scripts/lib/workflow-runtime-event-projection-contract.test.mjs
- /tmp/ioi-autopilot-gui-harness-restore-workflow-nodes/2026-05-13T06-48-16-424Z/result.json

Validation evidence:

- `node --import tsx --test packages/agent-ide/src/runtime/workflow-runtime-control-nodes.test.ts`
  - React Flow request-builder tests passed for thread fork, interrupt, steer,
    context compact, rollback snapshot list, and restore gate preview/apply.
- `npm run build --workspace=@ioi/agent-ide`
  - agent-ide TypeScript and Vite build passed.
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml runtime_projection --lib`
  - Tauri runtime projection enum and edge-rule tests passed.
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml runtime_thread_fork_node_builds_react_flow_control_request --lib`
  - existing local runtime-control execution lane contract passed after adding
    restore node action kinds.
- `cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_scaffolds_include_action_metadata --lib`
  - project scaffold action metadata contract passed.
- `node --test scripts/lib/workflow-runtime-event-projection-contract.test.mjs`
  - React Flow runtime event/control source contract passed.
- `node --test --test-name-pattern "React Flow memory, authority/tooling" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - workflow-addressability source contract passed for the new restore node
    registry, UI chrome, generated schemas, Tauri templates, and execution lane.
- `git diff --check`
  - whitespace check passed.
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-restore-workflow-nodes`
  - live GUI/workflow preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-restore-workflow-nodes/2026-05-13T06-48-16-424Z/result.json`.

Known validation note:

- Full `cargo fmt --manifest-path apps/autopilot/src-tauri/Cargo.toml --check`
  still reports unrelated formatting drift in existing orchestrator store files;
  this slice's changed Rust files were formatted directly with `rustfmt`.

## Slice 134. 2026-05-13 - Keyboard-first TUI restore UX

Guide section: P0-D. Workspace Rollback Snapshots

Evidence bundles:

- crates/cli/src/commands/agent_tui.rs
- crates/cli/src/commands/agent_tui_loop.rs
- scripts/lib/live-runtime-daemon-contract.test.mjs
- docs/specs/runtime/agent-runtime-deepseek-parity-plus-master-guide.md
- docs/specs/runtime/agent-runtime-deepseek-parity-plus-implementation-log.md
- docs/specs/runtime/agent-runtime-deepseek-parity-plus-validation-ledger.md
- /tmp/ioi-autopilot-gui-harness-tui-restore-ux/2026-05-13T07-12-46-679Z/result.json

Validation evidence:

- `cargo fmt -p ioi-cli`
  - Rust formatting completed.
- `cargo test -p ioi-cli --bin cli parses_line_mode_slash_commands -- --nocapture`
  - TUI slash command parser test passed for `/restore` list, preview, apply,
    and conflict-override forms.
- `cargo test -p ioi-cli --bin cli rejects_unknown_or_incomplete_line_mode_commands -- --nocapture`
  - TUI parser rejects restore preview without a snapshot id, restore apply
    without `--approve`, and unknown restore flags.
- `cargo test -p ioi-cli --bin cli tui_event_route_uses_canonical_thread_stream_cursor -- --nocapture`
  - TUI route helper test passed for snapshot restore route expansion.
- `cargo check -p ioi-cli --bin cli`
  - CLI package check passed.
- `node --test --test-name-pattern "agent TUI thin shell is daemon-backed" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - TUI source-contract guard passed for daemon-owned restore routes and
    line-mode command output.
- `node --test --test-name-pattern "coding tool pack invokes" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live daemon/SDK/CLI/TUI/React Flow proof passed for TUI snapshot listing,
    restore preview, approval-safe restore apply, workspace restoration, and
    TUI restore-gate workflow node projection.
- `node --test --test-name-pattern "agent CLI exposes model" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - broader CLI/TUI source-contract guard passed with `/restore` in the
    slash-command inventory.
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live contract syntax check passed.
- `cargo fmt -p ioi-cli -- --check`
  - Rust formatting check passed.
- `git diff --check`
  - whitespace check passed.
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-tui-restore-ux`
  - live GUI/workflow preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-tui-restore-ux/2026-05-13T07-12-46-679Z/result.json`.

## Slice 121. 2026-05-13 - Coding tool-pack governed apply-patch contract

Guide section: P0-B. Coding Tool Pack

Evidence bundles:

- packages/runtime-daemon/src/index.mjs
- packages/runtime-daemon/src/coding-tools.mjs
- packages/agent-sdk/src/substrate-client.ts
- crates/cli/src/commands/agent.rs
- crates/cli/src/commands/agent_tui.rs
- crates/cli/src/commands/agent_tui_loop.rs
- packages/agent-ide/src/types/graph.ts
- packages/agent-ide/src/runtime/workflow-node-registry.ts
- packages/agent-ide/src/runtime/workflow-runtime-event-projection.ts
- packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts
- scripts/lib/live-runtime-daemon-contract.test.mjs
- /tmp/ioi-autopilot-gui-harness-coding-tool-pack-apply-patch/2026-05-13T03-24-26-739Z/result.json

Validation evidence:

- `node --check packages/runtime-daemon/src/coding-tools.mjs && node --check packages/runtime-daemon/src/index.mjs && node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
  - daemon and live contract syntax checks passed.
- `npm run build --workspace=@ioi/agent-sdk`
  - SDK declaration and bundle build passed.
- `npm run build --workspace=@ioi/agent-ide`
  - agent-ide TypeScript and Vite build passed.
- `cargo fmt -p ioi-cli`
  - Rust formatting completed.
- `cargo check -p ioi-cli`
  - CLI package check passed.
- `cargo test -p ioi-cli --bin cli parses_nested_tool_and_policy_commands -- --nocapture`
  - CLI coding-tool parser test passed for apply-patch flags.
- `cargo test -p ioi-cli --bin cli parses_line_mode_slash_commands -- --nocapture`
  - TUI slash command parser test passed for `/patch` and `/patch-dry-run`.
- `node --import tsx --test --test-name-pattern "projects coding tool" packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts`
  - React Flow coding-tool projection test passed for status and apply-patch rows.
- `node --test --test-name-pattern "coding tool pack invokes status" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live daemon/SDK/CLI/TUI/React Flow coding tool-pack proof passed for
    status, diff, inspect, dry-run apply-patch, and mutating apply-patch.
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-coding-tool-pack-apply-patch`
  - live GUI/workflow preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-coding-tool-pack-apply-patch/2026-05-13T03-24-26-739Z/result.json`.

Known validation note:

- Broad `cargo test -p ioi-cli ...` remains blocked by unrelated CLI
  integration tests that need `StartAgentParams.runtime_route_frame`
  initializers.

## Slice 122. 2026-05-13 - Coding tool-pack structured test-run contract

Guide section: P0-B. Coding Tool Pack

Evidence bundles:

- packages/runtime-daemon/src/index.mjs
- packages/runtime-daemon/src/coding-tools.mjs
- packages/agent-sdk/src/substrate-client.ts
- crates/cli/src/commands/agent.rs
- crates/cli/src/commands/agent_tui.rs
- crates/cli/src/commands/agent_tui_loop.rs
- packages/agent-ide/src/types/graph.ts
- packages/agent-ide/src/runtime/workflow-node-registry.ts
- packages/agent-ide/src/runtime/workflow-runtime-event-projection.ts
- packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts
- scripts/lib/live-runtime-daemon-contract.test.mjs
- /tmp/ioi-autopilot-gui-harness-coding-tool-pack-test-run/2026-05-13T03-36-24-435Z/result.json

Validation evidence:

- `node --check packages/runtime-daemon/src/coding-tools.mjs && node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
  - daemon and live contract syntax checks passed.
- `npm run build --workspace=@ioi/agent-sdk`
  - SDK declaration and bundle build passed.
- `npm run build --workspace=@ioi/agent-ide`
  - agent-ide TypeScript and Vite build passed.
- `cargo fmt -p ioi-cli`
  - Rust formatting completed.
- `cargo check -p ioi-cli`
  - CLI package check passed.
- `cargo test -p ioi-cli --bin cli parses_nested_tool_and_policy_commands -- --nocapture`
  - CLI coding-tool parser test passed for test-run flags.
- `cargo test -p ioi-cli --bin cli parses_line_mode_slash_commands -- --nocapture`
  - TUI slash command parser test passed for `/test`.
- `node --import tsx --test --test-name-pattern "projects coding tool" packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts`
  - React Flow coding-tool projection test passed for status, apply-patch, and test-run rows.
- `node --test --test-name-pattern "coding tool pack invokes status" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live daemon/SDK/CLI/TUI/React Flow coding tool-pack proof passed for
    status, diff, inspect, apply-patch, and test-run.
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-coding-tool-pack-test-run`
  - live GUI/workflow preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-coding-tool-pack-test-run/2026-05-13T03-36-24-435Z/result.json`.

Known validation note:

- Broad `cargo test -p ioi-cli ...` remains blocked by unrelated CLI
  integration tests that need `StartAgentParams.runtime_route_frame`
  initializers.

## Slice 123. 2026-05-13 - Coding tool-pack artifact spillover and retrieval

Guide section: P0-B. Coding Tool Pack

Evidence bundles:

- packages/runtime-daemon/src/index.mjs
- packages/runtime-daemon/src/coding-tools.mjs
- packages/agent-sdk/src/substrate-client.ts
- crates/cli/src/commands/agent.rs
- crates/cli/src/commands/agent_tui.rs
- crates/cli/src/commands/agent_tui_loop.rs
- packages/agent-ide/src/types/graph.ts
- packages/agent-ide/src/runtime/workflow-node-registry.ts
- packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts
- scripts/lib/live-runtime-daemon-contract.test.mjs
- /tmp/ioi-autopilot-gui-harness-coding-tool-pack-artifact-retrieval/2026-05-13T03-53-05-208Z/result.json

Validation evidence:

- `node --check packages/runtime-daemon/src/coding-tools.mjs && node --check packages/runtime-daemon/src/index.mjs && node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
  - daemon and live contract syntax checks passed.
- `npm run build --workspace=@ioi/agent-sdk`
  - SDK declaration and bundle build passed.
- `npm run build --workspace=@ioi/agent-ide`
  - agent-ide TypeScript and Vite build passed.
- `cargo fmt -p ioi-cli`
  - Rust formatting completed.
- `cargo check -p ioi-cli`
  - CLI package check passed.
- `cargo test -p ioi-cli --bin cli parses_nested_tool_and_policy_commands -- --nocapture`
  - CLI coding-tool parser test passed for artifact/retrieve flags.
- `cargo test -p ioi-cli --bin cli parses_line_mode_slash_commands -- --nocapture`
  - TUI slash command parser test passed for `/artifact` and `/retrieve`.
- `node --import tsx --test --test-name-pattern "projects coding tool" packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts`
  - React Flow coding-tool projection test passed for artifact refs and
    retrieval rows.
- `node --test --test-name-pattern "coding tool pack invokes" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live daemon/SDK/CLI/TUI/React Flow coding tool-pack proof passed for
    status, diff, inspect, apply-patch, test-run, artifact read, and
    retrieve-result.
- `node --test --test-name-pattern "agent CLI exposes model" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - CLI/TUI source-contract guard passed.
- `node --test --test-name-pattern "agent TUI thin shell is daemon-backed" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - TUI source-contract guard passed.
- `cargo fmt -p ioi-cli -- --check`
  - Rust formatting check passed.
- `git diff --check`
  - whitespace check passed.
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-coding-tool-pack-artifact-retrieval`
  - live GUI/workflow preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-coding-tool-pack-artifact-retrieval/2026-05-13T03-53-05-208Z/result.json`.

Known validation note:

- Broad `cargo test -p ioi-cli ...` remains blocked by unrelated CLI
  integration tests that need `StartAgentParams.runtime_route_frame`
  initializers.

## Slice 124. 2026-05-13 - Coding tool-pack post-edit diagnostics MVP

Guide section: P0-C. Post-edit LSP Diagnostics

Evidence bundles:

- packages/runtime-daemon/src/coding-tools.mjs
- packages/agent-sdk/src/substrate-client.ts
- crates/cli/src/commands/agent.rs
- crates/cli/src/commands/agent_tui_loop.rs
- packages/agent-ide/src/types/graph.ts
- packages/agent-ide/src/features/Workflows/WorkflowNodeBindingEditor/sections.tsx
- packages/agent-ide/src/runtime/workflow-node-registry.ts
- packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts
- scripts/lib/live-runtime-daemon-contract.test.mjs
- /tmp/ioi-autopilot-gui-harness-coding-tool-pack-diagnostics/2026-05-13T04-07-29-549Z/result.json

Validation evidence:

- `node --check packages/runtime-daemon/src/coding-tools.mjs`
  - daemon coding-tools syntax check passed.
- `node --check packages/runtime-daemon/src/index.mjs`
  - daemon index syntax check passed.
- `node --check scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live contract syntax check passed.
- `npm run build --workspace=@ioi/agent-sdk`
  - SDK declaration and bundle build passed.
- `npm run build --workspace=@ioi/agent-ide`
  - agent-ide TypeScript and Vite build passed.
- `cargo fmt -p ioi-cli`
  - Rust formatting completed.
- `cargo check -p ioi-cli`
  - CLI package check passed.
- `cargo test -p ioi-cli --bin cli parses_nested_tool_and_policy_commands -- --nocapture`
  - CLI coding-tool parser test passed for diagnostics flags.
- `cargo test -p ioi-cli --bin cli parses_line_mode_slash_commands -- --nocapture`
  - TUI slash command parser test passed for `/diagnostics`.
- `node --import tsx --test --test-name-pattern "projects coding tool" packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts`
  - React Flow coding-tool projection test passed for diagnostics rows.
- `node --test --test-name-pattern "coding tool pack invokes" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - live daemon/SDK/CLI/TUI/React Flow coding tool-pack proof passed for
    status, diff, inspect, apply-patch, diagnostics, test-run, artifact read,
    and retrieve-result.
- `node --test --test-name-pattern "agent CLI exposes model" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - CLI/TUI source-contract guard passed.
- `node --test --test-name-pattern "agent TUI thin shell is daemon-backed" scripts/lib/live-runtime-daemon-contract.test.mjs`
  - TUI source-contract guard passed.
- `cargo fmt -p ioi-cli -- --check`
  - Rust formatting check passed.
- `git diff --check`
  - whitespace check passed.
- `npm run validate:autopilot-gui-harness -- --output-root /tmp/ioi-autopilot-gui-harness-coding-tool-pack-diagnostics`
  - live GUI/workflow preflight passed and wrote
    `/tmp/ioi-autopilot-gui-harness-coding-tool-pack-diagnostics/2026-05-13T04-07-29-549Z/result.json`.

Known validation note:

- Broad `cargo test -p ioi-cli ...` remains blocked by unrelated CLI
  integration tests that need `StartAgentParams.runtime_route_frame`
  initializers.

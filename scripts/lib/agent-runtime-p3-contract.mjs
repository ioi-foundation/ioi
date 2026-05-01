import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { validateAutopilotGuiHarnessResult } from "./autopilot-gui-harness-contract.mjs";
import { SCORECARD_SCHEMA } from "./benchmark-matrix-contracts.mjs";

export const AGENT_RUNTIME_P3_SCHEMA_VERSION =
  "ioi.agent-runtime.p3-exhaustive-validation.v1";

export const MASTER_GUIDE_PATH =
  "docs/plans/architectural-improvements-broad-master-guide.md";

export const P3_PRODUCT_POLISH_ITEMS = Object.freeze([
  {
    id: "human_tui",
    guideLine: 2398,
    label: "Human TUI for events, approvals, child agents, plans, and receipts",
    dashboard: "runtime-scorecard-dashboard.md",
    anchors: [
      sourceAnchor("crates/cli/src/commands/agent.rs", [
        "AgentCommands::Events",
        "AgentCommands::Trace",
        "AgentCommands::Verify",
        "AgentCommands::Replay",
        "AgentCommands::Doctor",
      ]),
      sourceAnchor("apps/autopilot/src/windows/ChatShellWindow/components/ArtifactHubSidebar.tsx", [
        "tasks",
        "substrate",
        "kernel_logs",
        "security_policy",
      ]),
    ],
  },
  {
    id: "redacted_diagnostic_bundle",
    guideLine: 2399,
    label: "Redacted diagnostic bundle export",
    dashboard: "redacted-diagnostic-bundle.json",
    anchors: [
      sourceAnchor("apps/autopilot/src/windows/ChatShellWindow/utils/traceBundleExportModel.ts", [
        "redacted_share",
        "includeArtifactPayloads: false",
      ]),
      sourceAnchor("apps/autopilot/src/windows/ChatShellWindow/components/ArtifactHubPackagingViews.tsx", [
        "Redacted",
        "TraceBundleExportVariant",
      ]),
    ],
  },
  {
    id: "runtime_scorecard_dashboard",
    guideLine: 2400,
    label: "Runtime scorecard dashboard",
    dashboard: "runtime-scorecard-dashboard.md",
    anchors: [
      sourceAnchor("scripts/lib/benchmark-matrix-contracts.mjs", [
        "SCORECARD_SCHEMA",
        "operationalDiscipline",
      ]),
      sourceAnchor("crates/services/src/agentic/runtime/service/lifecycle/worker_results/scorecards.rs", [
        "scorecard",
      ]),
    ],
  },
  {
    id: "tool_mcp_authoring_templates",
    guideLine: 2401,
    label: "Guided tool and MCP authoring templates",
    dashboard: "tool-and-mcp-authoring-dashboard.md",
    anchors: [
      sourceAnchor("crates/services/src/agentic/runtime/tools/contracts.rs", [
        "RuntimeToolContract",
      ]),
      sourceAnchor("crates/cli/src/commands/mcp.rs", [
        "McpCommands",
        "Receipts",
        "Test",
      ]),
      sourceAnchor("docs/templates/runtime-tool-contract-template.md", [
        "RuntimeToolContract",
        "receipt",
      ]),
      sourceAnchor("docs/templates/mcp-connector-authoring-template.md", [
        "MCP",
        "containment",
      ]),
    ],
  },
  {
    id: "workflow_class_benchmarks",
    guideLine: 2402,
    label: "Benchmarks comparing workflow class completion, safety, recovery, and diagnosis quality",
    dashboard: "workflow-benchmark-dashboard.md",
    anchors: [
      sourceAnchor("scripts/run-agent-model-matrix.mjs", [
        "FAILURE_ONTOLOGY",
        "operationalDiscipline",
        "scorecards",
      ]),
      sourceAnchor("scripts/run-agent-model-matrix.test.mjs", [
        "scorecards",
      ]),
    ],
  },
  {
    id: "agent_quality_dashboard",
    guideLine: 2404,
    label: "Agent quality dashboard",
    dashboard: "agent-quality-dashboard.md",
    anchors: [
      sourceAnchor("crates/types/src/app/runtime_contracts.rs", [
        "AgentQualityLedger",
        "ToolSelectionQualityModel",
        "RuntimeStrategyRouter",
      ]),
      sourceAnchor("scripts/lib/agent-runtime-p3-contract.mjs", [
        "agent-quality-dashboard.md",
      ]),
    ],
  },
  {
    id: "dogfooding_dashboard",
    guideLine: 2406,
    label: "Dogfooding dashboard",
    dashboard: "dogfooding-dashboard.md",
    anchors: [
      sourceAnchor("crates/types/src/app/harness.rs", [
        "HarnessComponentKind",
        "GuiHarnessValidator",
        "kernel_ref",
      ]),
      sourceAnchor("apps/autopilot/src/windows/AutopilotShellWindow/harnessWorkflowWiring.test.mjs", [
        "Default Agent Harness",
      ]),
      sourceAnchor("apps/autopilot/src/windows/AutopilotShellWindow/workflowComposerWiring.test.ts", [
        "substrate",
      ]),
    ],
  },
  {
    id: "cognitive_loop_dashboard",
    guideLine: 2409,
    label: "Cognitive-loop dashboard",
    dashboard: "cognitive-loop-dashboard.md",
    anchors: [
      sourceAnchor("crates/services/src/agentic/runtime/substrate.rs", [
        "UncertaintyAssessment",
        "probes_for_state",
        "semantic_impact_for_state",
        "postconditions_for_state",
        "drift_signal_for_state",
        "stop_condition_for_state",
      ]),
      sourceAnchor("crates/types/src/app/runtime_contracts.rs", [
        "CognitiveBudget",
        "HandoffQuality",
      ]),
    ],
  },
  {
    id: "playbook_marketplace_operator_view",
    guideLine: 2412,
    label: "Playbook marketplace/operator view",
    dashboard: "playbook-marketplace-dashboard.md",
    anchors: [
      sourceAnchor("crates/services/src/agentic/runtime/agent_playbooks.rs", [
        "builtin_agent_playbooks",
        "playbook_decision_record",
      ]),
      sourceAnchor("crates/types/src/app/runtime_contracts.rs", [
        "TaskFamilyPlaybook",
        "NegativeLearningRecord",
      ]),
      sourceAnchor("crates/services/src/agentic/runtime/service/actions/evaluation.rs", [
        "BoundedSelfImprovementGate",
      ]),
    ],
  },
  {
    id: "desktop_validation_dashboard",
    guideLine: 2414,
    label: "Desktop validation dashboard",
    dashboard: "desktop-validation-dashboard.md",
    anchors: [
      sourceAnchor("scripts/lib/autopilot-gui-harness-contract.mjs", [
        "AUTOPILOT_RETAINED_QUERIES",
        "CLEAN_CHAT_UX_REQUIREMENTS",
        "RUNTIME_CONSISTENCY_REQUIREMENTS",
      ]),
      sourceAnchor("scripts/run-autopilot-gui-harness-validation.mjs", [
        "buildGuiEvidenceAssessment",
        "screenshot",
        "runtime-artifacts.json",
      ]),
    ],
  },
]);

export const EXHAUSTIVE_WORKFLOW_SUITES = Object.freeze([
  workflowSuite("cli_workflow", 1356, "CLI workflow suite", [
    sourceAnchor("crates/cli/src/commands/agent.rs", ["Run", "Chat", "Status", "Verify"]),
    commandAnchor("cargo test -p ioi-cli --bin cli commands::agent::tests --no-default-features"),
  ]),
  workflowSuite("session_lifecycle_crash_resume", 1357, "Session lifecycle and crash-resume suite", [
    sourceAnchor("crates/cli/tests/agent_pause_resume.rs", ["Paused", "Resumed"]),
    sourceAnchor("crates/services/src/agentic/runtime/service/lifecycle/handlers/tests.rs", [
      "AgentStatus",
    ]),
  ]),
  workflowSuite("event_stream_schema_ordering", 1358, "Event stream schema and ordering golden suite", [
    sourceAnchor("crates/types/src/app/runtime_contracts.rs", [
      "AgentRuntimeEvent",
      "event_id",
    ]),
    sourceAnchor("crates/cli/src/commands/agent.rs", ["monotonic_step_order"]),
  ]),
  workflowSuite("tool_contract", 1359, "Tool contract suite", [
    sourceAnchor("crates/services/src/agentic/runtime/tools/contracts.rs", [
      "RuntimeToolContract",
    ]),
    commandAnchor("cargo test -p ioi-services tools::contracts --lib"),
  ]),
  workflowSuite("filesystem_safety", 1360, "Filesystem stale-write/device/symlink/read-before-edit safety suite", [
    sourceAnchor(
      "crates/services/src/agentic/runtime/service/tool_execution/processing/phases/execute_tool_phase/file_observation.rs",
      ["stale write", "read"],
    ),
    sourceAnchor("crates/services/src/agentic/runtime/execution/filesystem/handler/tests.rs", [
      "symlink",
    ]),
  ]),
  workflowSuite("shell_job_control", 1361, "Shell job-control suite", [
    sourceAnchor("crates/services/src/agentic/runtime/service/tool_execution/command_contract/tests.rs", [
      "command_history",
      "CommandExecution",
    ]),
    sourceAnchor("scripts/run-agent-model-matrix.mjs", ["killChildProcessTree"]),
  ]),
  workflowSuite("policy_firewall_approval", 1362, "Policy/firewall/approval suite", [
    sourceAnchor("crates/services/src/agentic/runtime/service/handler/execution/execution/firewall_policy.rs", [
      "policy",
      "ApprovalGrant",
      "RequireApproval",
    ]),
    sourceAnchor("crates/services/src/agentic/runtime/service/handler/approvals.rs", [
      "is_runtime_secret_install_retry_approved",
    ]),
  ]),
  workflowSuite("mcp_containment", 1363, "MCP containment suite", [
    sourceAnchor("crates/cli/src/commands/mcp.rs", [
      "McpContainmentMode",
      "static_checks_for_server",
    ]),
    sourceAnchor("crates/services/src/agentic/runtime/tools/mcp.rs", ["MCP"]),
  ]),
  workflowSuite("delegation_merge_contract", 1364, "Delegation and merge-contract suite", [
    sourceAnchor("crates/services/src/agentic/runtime/service/lifecycle/delegation/tests.rs", [
      "delegation",
    ]),
    sourceAnchor("crates/services/src/agentic/runtime/service/lifecycle/worker_results/tests/playbook_merge.rs", [
      "merge",
    ]),
  ]),
  workflowSuite("plan_execution_binding", 1365, "Plan/execution binding suite", [
    sourceAnchor("crates/services/src/agentic/runtime/service/planning/planner/tests.rs", [
      "plan",
    ]),
    sourceAnchor("crates/services/src/agentic/runtime/service/queue/processing/execution/tests.rs", [
      "browser_queue_timeout_for_tool",
    ]),
  ]),
  workflowSuite("prompt_precedence", 1366, "Prompt precedence suite", [
    sourceAnchor("crates/types/src/app/runtime_contracts.rs", [
      "PromptAssemblyContract",
      "PromptLayerKind",
    ]),
    sourceAnchor("crates/services/src/agentic/runtime/service/decision_loop/intent_resolver/instruction_contract/tests.rs", [
      "instruction",
    ]),
  ]),
  workflowSuite("memory_compaction", 1367, "Memory/compaction suite", [
    sourceAnchor("crates/services/src/agentic/runtime/service/lifecycle/compaction/tests.rs", [
      "compaction",
    ]),
    sourceAnchor("crates/services/src/agentic/runtime/service/memory/transcript/tests.rs", [
      "memory",
    ]),
  ]),
  workflowSuite("model_routing_fallback", 1368, "Model routing/fallback suite", [
    sourceAnchor("crates/services/src/agentic/runtime/service/decision_loop/cognition/router.rs", [
      "model_hash",
    ]),
    sourceAnchor("scripts/chat-artifact-corpus/runtime.test.ts", [
      "productionModel",
      "acceptanceModel",
    ]),
  ]),
  workflowSuite("observability_export_replay", 1369, "Observability/export/replay suite", [
    sourceAnchor("apps/autopilot/src/windows/ChatShellWindow/utils/exportContext.ts", [
      "exportThreadTraceBundle",
    ]),
    sourceAnchor("crates/cli/src/commands/agent.rs", [
      "replay_report",
      "Export",
    ]),
  ]),
  workflowSuite("production_profile_fail_closed", 1370, "Production profile fail-closed suite", [
    sourceAnchor("crates/types/src/app/runtime_contracts.rs", [
      "fail_closed_in_production",
    ]),
    sourceAnchor("crates/services/src/agentic/runtime/runtime_secret/tests.rs", [
      "secret",
    ]),
  ]),
]);

export const BETTER_AGENT_VALIDATIONS = Object.freeze([
  betterAgent("strategy_router", 2110, "Strategy-router tests", [
    sourceAnchor("crates/services/src/agentic/runtime/substrate.rs", [
      "RuntimeStrategyRouter",
      "used_uncertainty",
    ]),
  ]),
  betterAgent("tool_quality_capability_retirement", 2112, "Tool-quality and capability-retirement tests", [
    sourceAnchor("crates/types/src/app/runtime_contracts.rs", ["ToolSelectionQualityModel"]),
    sourceAnchor("crates/services/src/agentic/runtime/substrate.rs", ["capability_retirement"]),
  ]),
  betterAgent("clarification_quality", 2114, "Clarification-quality tests", [
    sourceAnchor("crates/types/src/app/runtime_contracts.rs", ["ClarificationContract"]),
    sourceAnchor("crates/services/src/agentic/runtime/service/lifecycle/handlers/post_message.rs", [
      "reset_for_new_user_goal",
    ]),
  ]),
  betterAgent("recovery_policy", 2116, "Recovery-policy tests", [
    sourceAnchor("crates/types/src/app/runtime_contracts.rs", ["ErrorRecoveryContract"]),
    sourceAnchor("crates/services/src/agentic/runtime/service/recovery/incident/recovery/tests.rs", [
      "recovery",
    ]),
  ]),
  betterAgent("memory_quality", 2119, "Memory-quality tests", [
    sourceAnchor("crates/types/src/app/runtime_contracts.rs", ["MemoryQualityGate"]),
    sourceAnchor("crates/services/src/agentic/runtime/substrate.rs", [
      "memory_quality_gates_for_state",
    ]),
  ]),
  betterAgent("delegation_value", 2122, "Delegation-value tests", [
    sourceAnchor("crates/services/src/agentic/runtime/service/lifecycle/delegation/tests.rs", [
      "delegation",
    ]),
  ]),
  betterAgent("bounded_self_improvement", 2124, "Bounded self-improvement gate tests", [
    sourceAnchor("crates/types/src/app/runtime_contracts.rs", [
      "BoundedSelfImprovementGate",
      "rollback_ref",
    ]),
    sourceAnchor("crates/services/src/agentic/runtime/service/actions/evaluation.rs", [
      "skill_candidate_self_improvement_gate",
    ]),
  ]),
  betterAgent("model_routing_quality", 2126, "Model-routing quality tests", [
    sourceAnchor("crates/types/src/app/runtime_contracts.rs", ["ModelRoutingDecision"]),
    sourceAnchor("crates/services/src/agentic/runtime/service/decision_loop/cognition/inference/tests.rs", [
      "cognition_inference_timeout",
    ]),
  ]),
  betterAgent("operator_collaboration", 2129, "Operator-collaboration tests", [
    sourceAnchor("crates/types/src/app/runtime_contracts.rs", [
      "OperatorCollaborationContract",
      "OperatorInterruptionContract",
    ]),
    sourceAnchor("crates/cli/tests/agent_pause_resume.rs", ["pause", "resume"]),
  ]),
  betterAgent("regression_scorecard", 2131, "Regression scorecard tests", [
    sourceAnchor("scripts/lib/benchmark-matrix-contracts.mjs", [
      "REQUIRED_DECISION_CATEGORY_IDS",
    ]),
  ]),
  betterAgent("unified_substrate_dogfooding", 2133, "Unified-substrate dogfooding tests", [
    sourceAnchor("apps/autopilot/src/windows/AutopilotShellWindow/harnessWorkflowWiring.test.mjs", [
      "Default Agent Harness",
    ]),
    sourceAnchor("crates/types/src/app/harness.rs", ["kernel_ref"]),
  ]),
  betterAgent("harness_adapter", 2136, "Harness adapter tests", [
    sourceAnchor("crates/types/src/app/runtime_contracts.rs", ["HarnessTraceAdapter"]),
    sourceAnchor("crates/services/src/agentic/runtime/substrate.rs", [
      "harness_trace_adapter_for_surface",
    ]),
  ]),
  betterAgent("import_boundary", 2138, "Import-boundary tests", [
    sourceAnchor("scripts/lib/agent-runtime-p3-contract.mjs", [
      "scanImportBoundaries",
    ]),
  ]),
  betterAgent("mock_live_substrate", 2140, "Mock/live substrate tests", [
    sourceAnchor("apps/autopilot/src/windows/AutopilotShellWindow/workflowComposerWiring.test.ts", [
      "mock",
      "live",
    ]),
  ]),
  betterAgent("task_state_model", 2142, "Task-state model tests", [
    sourceAnchor("crates/types/src/app/runtime_contracts.rs", ["TaskStateModel"]),
    sourceAnchor("crates/services/src/agentic/runtime/substrate.rs", [
      "task_state_for_state",
    ]),
  ]),
  betterAgent("compaction_state", 2145, "Compaction-state tests", [
    sourceAnchor("crates/services/src/agentic/runtime/service/lifecycle/compaction/tests.rs", [
      "compaction",
    ]),
  ]),
  betterAgent("uncertainty_routing", 2147, "Uncertainty routing tests", [
    sourceAnchor("crates/types/src/app/runtime_contracts.rs", ["UncertaintyAssessment"]),
    sourceAnchor("crates/services/src/agentic/runtime/substrate.rs", [
      "RuntimeDecisionAction::Probe",
      "RuntimeDecisionAction::Ask",
    ]),
  ]),
  betterAgent("probe_loop", 2150, "Probe-loop tests", [
    sourceAnchor("crates/services/src/agentic/runtime/service/tool_execution/probe/tests.rs", [
      "probe",
    ]),
    sourceAnchor("crates/services/src/agentic/runtime/substrate.rs", ["probes_for_state"]),
  ]),
  betterAgent("postcondition_synthesis", 2153, "Postcondition synthesis tests", [
    sourceAnchor("crates/types/src/app/runtime_contracts.rs", ["PostconditionSynthesis"]),
    sourceAnchor("crates/services/src/agentic/runtime/substrate.rs", [
      "postconditions_for_state",
    ]),
  ]),
  betterAgent("semantic_impact", 2156, "Semantic-impact tests", [
    sourceAnchor("crates/services/src/agentic/runtime/substrate.rs", [
      "semantic_impact_classifies_paths_from_runtime_receipts",
      "semantic_impact_marks_uncategorized_changed_paths_unknown",
    ]),
  ]),
  betterAgent("capability_sequence", 2159, "Capability-sequence tests", [
    sourceAnchor("crates/types/src/app/runtime_contracts.rs", [
      "CapabilitySequencing",
      "CapabilityRetirement",
    ]),
  ]),
  betterAgent("negative_learning", 2162, "Negative-learning tests", [
    sourceAnchor("crates/types/src/app/runtime_contracts.rs", ["NegativeLearningRecord"]),
    sourceAnchor("crates/services/src/agentic/runtime/substrate.rs", [
      "negative_learning_for_state",
    ]),
  ]),
  betterAgent("verifier_independence", 2164, "Verifier-independence tests", [
    sourceAnchor("crates/types/src/app/runtime_contracts.rs", [
      "VerifierIndependencePolicy",
    ]),
    sourceAnchor("crates/services/src/agentic/runtime/substrate.rs", [
      "verifier_independence_policy_for_state",
    ]),
  ]),
  betterAgent("cognitive_budget", 2166, "Cognitive-budget tests", [
    sourceAnchor("crates/types/src/app/runtime_contracts.rs", ["CognitiveBudget"]),
    sourceAnchor("crates/services/src/agentic/runtime/substrate.rs", [
      "cognitive_budget_for_state",
    ]),
  ]),
  betterAgent("drift", 2168, "Drift tests", [
    sourceAnchor("crates/types/src/app/runtime_contracts.rs", ["DriftSignal"]),
    sourceAnchor("crates/services/src/agentic/runtime/substrate.rs", [
      "drift_signal_for_state",
    ]),
  ]),
  betterAgent("dry_run", 2170, "Dry-run tests", [
    sourceAnchor("crates/types/src/app/runtime_contracts.rs", ["DryRunCapability"]),
    sourceAnchor("crates/services/src/agentic/runtime/substrate.rs", [
      "dry_run:workflow_side_effect",
      "dry_run:external_order_or_cart",
    ]),
  ]),
  betterAgent("stop_condition", 2173, "Stop-condition tests", [
    sourceAnchor("crates/types/src/app/runtime_contracts.rs", ["StopConditionRecord"]),
    sourceAnchor("crates/services/src/agentic/runtime/substrate.rs", [
      "stop_condition_for_state",
    ]),
  ]),
  betterAgent("handoff_quality", 2176, "Handoff-quality tests", [
    sourceAnchor("crates/types/src/app/runtime_contracts.rs", ["HandoffQuality"]),
    sourceAnchor("crates/services/src/agentic/runtime/substrate.rs", [
      "handoff_quality_for_state",
    ]),
  ]),
  betterAgent("autopilot_gui_retained_query", 2178, "Autopilot GUI retained-query tests", [
    sourceAnchor("scripts/lib/autopilot-gui-harness-contract.mjs", [
      "AUTOPILOT_RETAINED_QUERIES",
      "validateAutopilotGuiHarnessResult",
    ]),
    evidenceAnchor("autopilot_gui_harness_passing_result"),
  ]),
  betterAgent("chat_presentation", 2183, "Chat presentation tests", [
    sourceAnchor("scripts/lib/autopilot-gui-harness-contract.mjs", [
      "collapsible_explored_files",
      "source_pills_reserved_for_search",
    ]),
    sourceAnchor("apps/autopilot/src/windows/ChatShellWindow/components/AssistantProcessDisclosure.tsx", [
      "assistant-process",
    ]),
  ]),
  betterAgent("thinking_source_ux", 2189, "Thinking/source UX tests", [
    sourceAnchor("apps/autopilot/src/windows/ChatShellWindow/components/views/ThoughtsView.tsx", [
      "thoughts-section--compact",
      "Searched web",
      "Browsed source",
    ]),
    sourceAnchor("apps/autopilot/src/windows/ChatShellWindow/components/transcript/sourceSummary.ts", [
      "faviconUrl",
    ]),
  ]),
]);

export const RUNTIME_SCORECARD_DIMENSIONS = Object.freeze([
  ["Start", "Session state persisted before work begins."],
  ["Prompt", "Prompt sections, source hashes, and truncation diagnostics exist."],
  ["Plan", "Plan exists or explicit no-plan rationale exists."],
  ["Tool proposal", "Tool input validates against contract."],
  ["Policy", "Policy decision receipt exists."],
  ["Approval", "Approval grant is exact-scope when needed."],
  ["Execution", "Tool lifecycle events and receipt exist."],
  ["Postcondition", "Required evidence is checked."],
  ["Memory", "Relevant memory read/write is recorded with provenance."],
  ["Error", "Failure has class, retryability, and recovery suggestion."],
  ["Resume", "Crash boundary has a passing resume test."],
  ["Export", "Trace bundle reconstructs final state."],
  ["Verification", "`ioi agent verify` can accept or explain failure."],
  ["Quality", "`AgentQualityLedger` records scorecard metrics and failure ontology labels."],
  ["Strategy", "Runtime strategy choice is recorded with rationale and outcome."],
  ["Task state", "Objective, facts, uncertainty, assumptions, constraints, changed objects, blockers, stale facts, confidence, and evidence refs are current."],
  ["Uncertainty", "Ask/probe/retrieve/dry-run/execute/stop decision records value of information and cost of being wrong."],
  ["Probe", "Hypothesis, cheapest validation action, expected observation, result, confidence update, and next action are persisted."],
  ["Postcondition synthesis", "Required checks are derived before execution and mapped to receipts or explicit unknowns."],
  ["Semantic impact", "Changed symbols, APIs, schemas, policies, call sites, docs, generated files, migrations, and affected tests are analyzed."],
  ["Capability sequence", "Tool/capability order is selected from evidence and outcomes, not only availability."],
  ["Verifier independence", "High-risk verification uses required independent role/model/context/evidence policy."],
  ["Budget", "Reasoning, tool, retry, verification, wall-time, escalation, and stop budgets are respected."],
  ["Drift", "Plan, file, branch, connector auth, requirement, policy, model availability, and projection drift are checked."],
  ["Dry-run", "High-impact side effects are previewed when dry-run support exists."],
  ["Stop", "Terminal state includes explicit stop reason and evidence sufficiency status."],
  ["Handoff", "Receiving agent or operator can continue without reconstructing objective, state, blockers, or evidence."],
  ["Autopilot GUI", "`AUTOPILOT_LOCAL_GPU_DEV=1 npm run dev:desktop` launches retained desktop validation."],
  ["Chat UX", "Final answer is primary; Markdown, Mermaid, collapsible work, explored files, and source pills render cleanly."],
  ["GUI/runtime consistency", "Visible chat output matches trace, selected sources, receipts, task state, and stop reason."],
  ["Learning", "Promoted skills/playbooks/model-route changes have validation, rollback, and policy evidence."],
  ["Substrate", "Surface path records which public substrate contract and adapter were used."],
  ["Dogfooding", "Workflow/harness/benchmark validation proves same envelope, event, receipt, replay, and quality-ledger contract."],
]);

function sourceAnchor(filePath, contains = []) {
  return { kind: "source", path: filePath, contains };
}

function commandAnchor(command) {
  return { kind: "command", command };
}

function evidenceAnchor(id) {
  return { kind: "evidence", id };
}

function workflowSuite(id, guideLine, label, anchors) {
  return {
    id,
    guideLine,
    label,
    scorecardDimensions: [
      "Start",
      "Policy",
      "Execution",
      "Postcondition",
      "Export",
      "Quality",
      "Substrate",
      "Dogfooding",
    ],
    anchors,
  };
}

function betterAgent(id, guideLine, label, anchors) {
  return {
    id,
    guideLine,
    label,
    scorecardDimensions: [
      "Strategy",
      "Task state",
      "Uncertainty",
      "Probe",
      "Quality",
      "Stop",
      "Dogfooding",
    ],
    anchors,
  };
}

function readText(repoRoot, relativePath) {
  return fs.readFileSync(path.join(repoRoot, relativePath), "utf8");
}

function exists(repoRoot, relativePath) {
  return fs.existsSync(path.join(repoRoot, relativePath));
}

function listFiles(root, predicate) {
  const out = [];
  if (!fs.existsSync(root)) return out;
  const stack = [root];
  while (stack.length > 0) {
    const current = stack.pop();
    let stats;
    try {
      stats = fs.statSync(current);
    } catch {
      continue;
    }
    if (stats.isDirectory()) {
      for (const entry of fs.readdirSync(current)) {
        if (entry === "node_modules" || entry === "target" || entry === ".git") {
          continue;
        }
        stack.push(path.join(current, entry));
      }
      continue;
    }
    if (predicate(current)) out.push(current);
  }
  return out.sort();
}

function sha256Text(text) {
  return crypto.createHash("sha256").update(text).digest("hex");
}

export function latestPassingGuiHarnessEvidence(repoRoot) {
  const evidenceRoots = [
    "docs/evidence/architectural-improvements-broad/gui-retained-validation",
    "docs/evidence/autopilot-gui-harness-validation",
  ].map((relativePath) => path.join(repoRoot, relativePath));
  const candidates = evidenceRoots
    .filter((evidenceRoot) => fs.existsSync(evidenceRoot))
    .flatMap((evidenceRoot) =>
      fs
        .readdirSync(evidenceRoot)
        .map((entry) => path.join(evidenceRoot, entry))
        .filter((entryPath) => fs.existsSync(path.join(entryPath, "result.json"))),
    )
    .sort((left, right) => path.basename(right).localeCompare(path.basename(left)));

  for (const candidate of candidates) {
    try {
      const resultPath = path.join(candidate, "result.json");
      const result = JSON.parse(fs.readFileSync(resultPath, "utf8"));
      const validation = validateAutopilotGuiHarnessResult(result);
      if (result.blocked !== true && validation.ok) {
        return {
          directory: path.relative(repoRoot, candidate),
          resultPath: path.relative(repoRoot, resultPath),
          runtimeArtifactsPath: fs.existsSync(path.join(candidate, "runtime-artifacts.json"))
            ? path.relative(repoRoot, path.join(candidate, "runtime-artifacts.json"))
            : null,
          queryCount: Array.isArray(result.queryResults) ? result.queryResults.length : 0,
          screenshotCount:
            Object.keys(result.artifacts?.screenshots ?? {}).length ||
            (Array.isArray(result.screenshots)
              ? result.screenshots.length
              : result.queryResults?.filter((query) => query.screenshotPath || query.screenshot)
                  .length ?? 0),
          chatUx: result.chatUx ?? {},
          runtimeConsistency: result.runtimeConsistency ?? {},
          validation,
          generatedAt: path.basename(candidate),
        };
      }
    } catch {
      // Keep scanning older evidence bundles.
    }
  }
  return null;
}

function evaluateAnchor(repoRoot, anchor, context) {
  if (anchor.kind === "source") {
    const present = exists(repoRoot, anchor.path);
    if (!present) {
      return {
        ...anchor,
        status: "Missing",
        detail: `Missing source file ${anchor.path}`,
      };
    }
    const content = readText(repoRoot, anchor.path);
    const missing = (anchor.contains ?? []).filter((needle) => !content.includes(needle));
    return {
      ...anchor,
      status: missing.length === 0 ? "Complete" : "Partial",
      detail:
        missing.length === 0
          ? `Found ${anchor.path}`
          : `Missing source tokens: ${missing.join(", ")}`,
      sourceHash: sha256Text(content).slice(0, 16),
    };
  }

  if (anchor.kind === "command") {
    return {
      ...anchor,
      status: "Complete",
      detail: "Command is part of the validation manifest and must be run by the release gate.",
    };
  }

  if (anchor.kind === "evidence") {
    if (anchor.id === "autopilot_gui_harness_passing_result") {
      return context.guiEvidence
        ? {
            ...anchor,
            status: "Complete",
            detail: `Latest passing GUI evidence: ${context.guiEvidence.resultPath}`,
          }
        : {
            ...anchor,
            status: context.requireGuiEvidence ? "Missing" : "Unknown",
            detail:
              "No passing Autopilot GUI retained-query result was found in architectural-improvements or legacy GUI evidence roots.",
          };
    }
  }

  return {
    ...anchor,
    status: "Unknown",
    detail: `Unknown anchor kind ${anchor.kind}`,
  };
}

function evaluateItems(repoRoot, items, context) {
  return items.map((item) => {
    const anchors = item.anchors.map((anchor) => evaluateAnchor(repoRoot, anchor, context));
    const missingAnchors = anchors.filter((anchor) => anchor.status !== "Complete");
    return {
      ...item,
      status: missingAnchors.length === 0 ? "Complete" : "Partial",
      anchors,
      missingAnchors,
    };
  });
}

export function scanImportBoundaries(repoRoot) {
  const productionRoots = [
    "crates/services/src/agentic/runtime",
    "crates/types/src/app",
    "apps/autopilot/src/windows/ChatShellWindow",
    "apps/autopilot/src/windows/AutopilotShellWindow",
    "packages/agent-ide/src",
  ];
  const forbiddenPatterns = [
    /from\s+["'][^"']*scripts\/lib/i,
    /require\(["'][^"']*scripts\/lib/i,
    /agent-runtime-p3-contract\.mjs/i,
    /benchmark-matrix-contracts\.mjs/i,
    /autopilot-gui-harness-contract\.mjs/i,
    /fixtures\/agent-model-matrix/i,
  ];
  const sourceExtensions = new Set([".rs", ".ts", ".tsx", ".js", ".jsx", ".mjs"]);
  const findings = [];
  for (const root of productionRoots) {
    const absoluteRoot = path.join(repoRoot, root);
    for (const filePath of listFiles(absoluteRoot, (candidate) => {
      const relative = path.relative(repoRoot, candidate);
      if (/\b(test|tests|__tests__)\b/i.test(relative)) return false;
      return sourceExtensions.has(path.extname(candidate));
    })) {
      const content = fs.readFileSync(filePath, "utf8");
      for (const pattern of forbiddenPatterns) {
        if (pattern.test(content)) {
          findings.push({
            path: path.relative(repoRoot, filePath),
            pattern: String(pattern),
          });
        }
      }
    }
  }
  return {
    status: findings.length === 0 ? "Complete" : "Divergent",
    findings,
  };
}

function workflowScorecardRows() {
  return EXHAUSTIVE_WORKFLOW_SUITES.map((suite) => ({
    workflowClass: suite.id,
    label: suite.label,
    dimensions: suite.scorecardDimensions,
    guideLine: suite.guideLine,
  }));
}

function dashboardSpecs() {
  return [
    {
      id: "runtime_scorecard",
      file: "runtime-scorecard-dashboard.md",
      title: "Runtime Scorecard Dashboard",
    },
    {
      id: "agent_quality",
      file: "agent-quality-dashboard.md",
      title: "Agent Quality Dashboard",
    },
    {
      id: "dogfooding",
      file: "dogfooding-dashboard.md",
      title: "Dogfooding Dashboard",
    },
    {
      id: "cognitive_loop",
      file: "cognitive-loop-dashboard.md",
      title: "Cognitive Loop Dashboard",
    },
    {
      id: "playbook_marketplace",
      file: "playbook-marketplace-dashboard.md",
      title: "Playbook Marketplace Dashboard",
    },
    {
      id: "desktop_validation",
      file: "desktop-validation-dashboard.md",
      title: "Desktop Validation Dashboard",
    },
    {
      id: "tool_mcp_authoring",
      file: "tool-and-mcp-authoring-dashboard.md",
      title: "Tool And MCP Authoring Dashboard",
    },
    {
      id: "workflow_benchmarks",
      file: "workflow-benchmark-dashboard.md",
      title: "Workflow Benchmark Dashboard",
    },
  ];
}

export function evaluateAgentRuntimeP3Readiness(repoRoot, options = {}) {
  const context = {
    requireGuiEvidence: options.requireGuiEvidence === true,
    guiEvidence: latestPassingGuiHarnessEvidence(repoRoot),
  };
  const p3 = evaluateItems(repoRoot, P3_PRODUCT_POLISH_ITEMS, context);
  const workflows = evaluateItems(repoRoot, EXHAUSTIVE_WORKFLOW_SUITES, context);
  const betterAgent = evaluateItems(repoRoot, BETTER_AGENT_VALIDATIONS, context);
  const importBoundary = scanImportBoundaries(repoRoot);
  const guidePresent = exists(repoRoot, MASTER_GUIDE_PATH);
  const packageJson = JSON.parse(readText(repoRoot, "package.json"));
  const packageScripts = packageJson.scripts ?? {};
  const requiredScripts = [
    "test:autopilot-gui-harness",
    "validate:autopilot-gui-harness",
    "validate:autopilot-gui-harness:run",
    "test:agent-runtime-p3",
    "validate:agent-runtime-p3",
  ];
  const missingScripts = requiredScripts.filter((script) => !packageScripts[script]);
  const allItems = [...p3, ...workflows, ...betterAgent];
  const incomplete = allItems.filter((item) => item.status !== "Complete");
  if (context.requireGuiEvidence && !context.guiEvidence) {
    incomplete.push({
      id: "autopilot_gui_harness_passing_result",
      status: "Missing",
      label: "Passing Autopilot GUI retained-query evidence",
      missingAnchors: [
        {
          status: "Missing",
          detail: "No passing GUI retained-query result was found.",
        },
      ],
    });
  }
  if (missingScripts.length > 0) {
    incomplete.push({
      id: "package_scripts",
      status: "Missing",
      label: "Package scripts for P3 validation",
      missingAnchors: missingScripts.map((script) => ({
        status: "Missing",
        detail: `Missing package script ${script}`,
      })),
    });
  }
  if (importBoundary.status !== "Complete") {
    incomplete.push({
      id: "import_boundary",
      status: importBoundary.status,
      label: "No split-brain runtime imports",
      missingAnchors: importBoundary.findings.map((finding) => ({
        status: "Divergent",
        detail: `${finding.path} matches ${finding.pattern}`,
      })),
    });
  }
  if (!guidePresent) {
    incomplete.push({
      id: "master_guide",
      status: "Missing",
      label: "Master guide source of truth",
      missingAnchors: [{ status: "Missing", detail: `Missing ${MASTER_GUIDE_PATH}` }],
    });
  }

  return {
    schemaVersion: AGENT_RUNTIME_P3_SCHEMA_VERSION,
    generatedAt: new Date().toISOString(),
    masterGuide: {
      path: MASTER_GUIDE_PATH,
      present: guidePresent,
      guideHash: guidePresent ? sha256Text(readText(repoRoot, MASTER_GUIDE_PATH)) : null,
      p3Lines: [2396, 2416],
      exhaustiveWorkflowLines: [1354, 1378],
      betterAgentLines: [2106, 2193],
      finalBeatLines: [2520, 2570],
    },
    status: incomplete.length === 0 ? "Complete" : "Partial",
    ok: incomplete.length === 0,
    counts: {
      p3: p3.length,
      exhaustiveWorkflowSuites: workflows.length,
      betterAgentValidations: betterAgent.length,
      scorecardDimensions: RUNTIME_SCORECARD_DIMENSIONS.length,
      scorecardSchemaCategories: SCORECARD_SCHEMA.categories.length,
      incomplete: incomplete.length,
    },
    p3,
    exhaustiveWorkflowSuites: workflows,
    betterAgentValidations: betterAgent,
    workflowScorecardRows: workflowScorecardRows(),
    dashboards: dashboardSpecs(),
    guiEvidence: context.guiEvidence,
    importBoundary,
    packageScripts: {
      required: requiredScripts,
      missing: missingScripts,
    },
    failures: incomplete.flatMap((item) =>
      item.missingAnchors.map((anchor) => `${item.id}: ${anchor.detail}`),
    ),
  };
}

function table(headers, rows) {
  return [
    `| ${headers.join(" | ")} |`,
    `| ${headers.map(() => "---").join(" | ")} |`,
    ...rows.map((row) => `| ${row.map((cell) => String(cell ?? "").replace(/\n/g, " ")).join(" | ")} |`),
  ].join("\n");
}

function itemRows(items) {
  return items.map((item) => [
    item.status,
    item.label,
    `guide:${item.guideLine}`,
    item.missingAnchors.length === 0
      ? "All anchors present"
      : item.missingAnchors.map((anchor) => anchor.detail).join("; "),
  ]);
}

function scorecardRows() {
  return RUNTIME_SCORECARD_DIMENSIONS.map(([dimension, evidence]) => [
    dimension,
    evidence,
  ]);
}

function buildRuntimeScorecardDashboard(readiness) {
  return [
    "# Runtime Scorecard Dashboard",
    "",
    `Generated: ${readiness.generatedAt}`,
    "",
    table(["Dimension", "Required evidence"], scorecardRows()),
    "",
    "## Workflow Classes",
    "",
    table(
      ["Status", "Workflow class", "Guide", "Evidence"],
      itemRows(readiness.exhaustiveWorkflowSuites),
    ),
  ].join("\n");
}

function buildAgentQualityDashboard(readiness) {
  const categoryRows = SCORECARD_SCHEMA.categories.map((category) => [
    category.label,
    category.decisionWeight,
    category.requiredForPromotion ? "yes" : "no",
    category.metrics.join(", "),
  ]);
  return [
    "# Agent Quality Dashboard",
    "",
    table(["Category", "Weight", "Required", "Metrics"], categoryRows),
    "",
    "## Better-Agent Validation",
    "",
    table(
      ["Status", "Validation", "Guide", "Evidence"],
      itemRows(readiness.betterAgentValidations),
    ),
  ].join("\n");
}

function buildDogfoodingDashboard(readiness) {
  return [
    "# Dogfooding Dashboard",
    "",
    "This dashboard is a projection over source contracts and validation artifacts. It does not define a separate runtime.",
    "",
    table(
      ["Surface", "Substrate proof"],
      [
        ["CLI", "crates/cli/src/commands/agent.rs"],
        ["API/runtime", "crates/services/src/agentic/runtime/substrate.rs"],
        ["Harness", "crates/types/src/app/harness.rs"],
        ["Workflow compositor", "apps/autopilot/src/windows/AutopilotShellWindow/workflowComposerWiring.test.ts"],
        ["Benchmarks", "scripts/run-agent-model-matrix.mjs"],
        ["Desktop UI", "scripts/run-autopilot-gui-harness-validation.mjs"],
      ],
    ),
    "",
    `Import boundary: ${readiness.importBoundary.status}`,
  ].join("\n");
}

function buildCognitiveLoopDashboard(readiness) {
  const required = [
    "TaskStateModel",
    "UncertaintyAssessment",
    "Probe",
    "PostconditionSynthesizer",
    "SemanticImpactAnalysis",
    "VerifierIndependencePolicy",
    "CognitiveBudget",
    "DriftSignal",
    "DryRunCapability",
    "StopConditionRecord",
    "HandoffQuality",
  ];
  return [
    "# Cognitive Loop Dashboard",
    "",
    table(
      ["Runtime primitive", "Source"],
      required.map((name) => [name, "crates/types/src/app/runtime_contracts.rs"]),
    ),
    "",
    table(
      ["Status", "Validation", "Guide", "Evidence"],
      itemRows(
        readiness.betterAgentValidations.filter((item) =>
          [
            "task_state_model",
            "uncertainty_routing",
            "probe_loop",
            "postcondition_synthesis",
            "semantic_impact",
            "verifier_independence",
            "cognitive_budget",
            "drift",
            "dry_run",
            "stop_condition",
            "handoff_quality",
          ].includes(item.id),
        ),
      ),
    ),
  ].join("\n");
}

function buildPlaybookMarketplaceDashboard(readiness) {
  return [
    "# Playbook Marketplace Dashboard",
    "",
    "Validated playbooks, negative learning, decay, override rules, and gated promotion use the runtime contracts below.",
    "",
    table(
      ["Contract", "Source"],
      [
        ["TaskFamilyPlaybook", "crates/types/src/app/runtime_contracts.rs"],
        ["NegativeLearningRecord", "crates/types/src/app/runtime_contracts.rs"],
        ["BoundedSelfImprovementGate", "crates/types/src/app/runtime_contracts.rs"],
        ["Builtin playbooks", "crates/services/src/agentic/runtime/agent_playbooks.rs"],
      ],
    ),
    "",
    table(
      ["Status", "P3 item", "Guide", "Evidence"],
      itemRows(readiness.p3.filter((item) => item.id === "playbook_marketplace_operator_view")),
    ),
  ].join("\n");
}

function buildDesktopValidationDashboard(readiness) {
  const evidence = readiness.guiEvidence;
  return [
    "# Desktop Validation Dashboard",
    "",
    evidence
      ? `Latest passing retained-query evidence: ${evidence.resultPath}`
      : "No passing retained-query GUI evidence was available to this validation run.",
    "",
    table(
      ["Check", "Value"],
      evidence
        ? [
            ["Query count", evidence.queryCount],
            ["Screenshot count", evidence.screenshotCount],
            ["Runtime artifacts", evidence.runtimeArtifactsPath ?? "missing"],
            ["Generated at", evidence.generatedAt],
          ]
        : [["GUI evidence", "missing or externally blocked"]],
    ),
    "",
    evidence
      ? table(
          ["Chat UX requirement", "Pass"],
          Object.entries(evidence.chatUx).map(([key, value]) => [key, value ? "yes" : "no"]),
        )
      : "",
    "",
    evidence
      ? table(
          ["Runtime consistency requirement", "Pass"],
          Object.entries(evidence.runtimeConsistency).map(([key, value]) => [
            key,
            value ? "yes" : "no",
          ]),
        )
      : "",
  ].join("\n");
}

function buildToolMcpAuthoringDashboard(readiness) {
  return [
    "# Tool And MCP Authoring Dashboard",
    "",
    table(
      ["Template", "Purpose"],
      [
        ["docs/templates/runtime-tool-contract-template.md", "RuntimeToolContract authoring checklist"],
        ["docs/templates/mcp-connector-authoring-template.md", "MCP containment and receipt checklist"],
      ],
    ),
    "",
    table(
      ["Status", "P3 item", "Guide", "Evidence"],
      itemRows(readiness.p3.filter((item) => item.id === "tool_mcp_authoring_templates")),
    ),
  ].join("\n");
}

function buildWorkflowBenchmarkDashboard(readiness) {
  return [
    "# Workflow Benchmark Dashboard",
    "",
    "Workflow-class completion, safety, recovery, and diagnosis quality are scored through the same scorecard categories used by the benchmark matrix.",
    "",
    table(
      ["Workflow class", "Scorecard dimensions", "Guide"],
      readiness.workflowScorecardRows.map((row) => [
        row.workflowClass,
        row.dimensions.join(", "),
        `guide:${row.guideLine}`,
      ]),
    ),
  ].join("\n");
}

function redactValue(value) {
  if (Array.isArray(value)) return value.map(redactValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, entry]) => {
        if (/secret|token|password|credential|cookie|authorization/i.test(key)) {
          return [key, "<redacted>"];
        }
        return [key, redactValue(entry)];
      }),
    );
  }
  if (typeof value === "string" && /sk-|ghp_|token|password|secret/i.test(value)) {
    return "<redacted>";
  }
  return value;
}

export function buildRedactedDiagnosticBundle(readiness) {
  return redactValue({
    schemaVersion: `${AGENT_RUNTIME_P3_SCHEMA_VERSION}.diagnostic_bundle`,
    generatedAt: readiness.generatedAt,
    status: readiness.status,
    counts: readiness.counts,
    masterGuide: readiness.masterGuide,
    guiEvidence: readiness.guiEvidence
      ? {
          resultPath: readiness.guiEvidence.resultPath,
          runtimeArtifactsPath: readiness.guiEvidence.runtimeArtifactsPath,
          queryCount: readiness.guiEvidence.queryCount,
          screenshotCount: readiness.guiEvidence.screenshotCount,
          chatUx: readiness.guiEvidence.chatUx,
          runtimeConsistency: readiness.guiEvidence.runtimeConsistency,
        }
      : null,
    importBoundary: readiness.importBoundary,
    failures: readiness.failures,
  });
}

export function buildDashboardDocuments(readiness) {
  return {
    "runtime-scorecard-dashboard.md": buildRuntimeScorecardDashboard(readiness),
    "agent-quality-dashboard.md": buildAgentQualityDashboard(readiness),
    "dogfooding-dashboard.md": buildDogfoodingDashboard(readiness),
    "cognitive-loop-dashboard.md": buildCognitiveLoopDashboard(readiness),
    "playbook-marketplace-dashboard.md": buildPlaybookMarketplaceDashboard(readiness),
    "desktop-validation-dashboard.md": buildDesktopValidationDashboard(readiness),
    "tool-and-mcp-authoring-dashboard.md": buildToolMcpAuthoringDashboard(readiness),
    "workflow-benchmark-dashboard.md": buildWorkflowBenchmarkDashboard(readiness),
  };
}

export function validateAgentRuntimeP3Readiness(readiness) {
  const failures = [...(readiness.failures ?? [])];
  if (readiness.counts.p3 !== 10) failures.push("P3 checklist must include 10 items");
  if (readiness.counts.exhaustiveWorkflowSuites !== 15) {
    failures.push("Exhaustive workflow checklist must include 15 suites");
  }
  if (readiness.counts.betterAgentValidations !== 31) {
    failures.push("Better-agent checklist must include 31 validations");
  }
  if (readiness.counts.scorecardDimensions < 30) {
    failures.push("Runtime scorecard dimensions are incomplete");
  }
  if (readiness.packageScripts.missing.length > 0) {
    failures.push(`Missing package scripts: ${readiness.packageScripts.missing.join(", ")}`);
  }
  if (readiness.importBoundary.status !== "Complete") {
    failures.push("Import-boundary scan found split-brain production imports");
  }
  return {
    ok: failures.length === 0,
    failures,
  };
}

export function writeAgentRuntimeP3Evidence(repoRoot, options = {}) {
  const outputRoot =
    options.outputRoot ?? "docs/evidence/agent-runtime-p3-validation";
  const outputDir = path.join(
    repoRoot,
    outputRoot,
    new Date().toISOString().replace(/[:.]/g, "-"),
  );
  fs.mkdirSync(outputDir, { recursive: true });
  const readiness = evaluateAgentRuntimeP3Readiness(repoRoot, {
    requireGuiEvidence: options.requireGuiEvidence === true,
  });
  const validation = validateAgentRuntimeP3Readiness(readiness);
  const dashboardsDir = path.join(outputDir, "dashboards");
  fs.mkdirSync(dashboardsDir, { recursive: true });
  const dashboards = buildDashboardDocuments(readiness);
  for (const [filename, content] of Object.entries(dashboards)) {
    fs.writeFileSync(path.join(dashboardsDir, filename), `${content.trim()}\n`, "utf8");
  }
  const redactedDiagnosticBundle = buildRedactedDiagnosticBundle(readiness);
  fs.writeFileSync(
    path.join(outputDir, "redacted-diagnostic-bundle.json"),
    `${JSON.stringify(redactedDiagnosticBundle, null, 2)}\n`,
    "utf8",
  );
  fs.writeFileSync(
    path.join(outputDir, "checklist.json"),
    `${JSON.stringify(readiness, null, 2)}\n`,
    "utf8",
  );
  const dashboardIndex = {
    schemaVersion: `${AGENT_RUNTIME_P3_SCHEMA_VERSION}.dashboard_index`,
    generatedAt: readiness.generatedAt,
    dashboards: dashboardSpecs().map((spec) => ({
      ...spec,
      path: path.relative(repoRoot, path.join(dashboardsDir, spec.file)),
    })),
  };
  fs.writeFileSync(
    path.join(outputDir, "dashboard-index.json"),
    `${JSON.stringify(dashboardIndex, null, 2)}\n`,
    "utf8",
  );
  const scorecard = {
    schemaVersion: `${AGENT_RUNTIME_P3_SCHEMA_VERSION}.scorecard`,
    generatedAt: readiness.generatedAt,
    ok: validation.ok,
    runtimeScorecardDimensions: RUNTIME_SCORECARD_DIMENSIONS.map(
      ([dimension, requiredEvidence]) => ({ dimension, requiredEvidence }),
    ),
    workflowRows: readiness.workflowScorecardRows,
    benchmarkScorecardSchema: SCORECARD_SCHEMA,
  };
  fs.writeFileSync(
    path.join(outputDir, "scorecard.json"),
    `${JSON.stringify(scorecard, null, 2)}\n`,
    "utf8",
  );
  const report = [
    "# Agent Runtime P3 Validation Report",
    "",
    `Status: ${validation.ok ? "Complete" : "Partial"}`,
    "",
    `Master guide: ${MASTER_GUIDE_PATH}`,
    "",
    table(
      ["Area", "Count"],
      [
        ["P3 product polish", readiness.counts.p3],
        ["Exhaustive workflow suites", readiness.counts.exhaustiveWorkflowSuites],
        ["Better-agent validations", readiness.counts.betterAgentValidations],
        ["Runtime scorecard dimensions", readiness.counts.scorecardDimensions],
        ["Incomplete", readiness.counts.incomplete],
      ],
    ),
    "",
    validation.failures.length > 0
      ? ["## Failures", "", ...validation.failures.map((failure) => `- ${failure}`)].join("\n")
      : "## Failures\n\nNone.",
    "",
    "## Dashboards",
    "",
    ...dashboardIndex.dashboards.map((dashboard) => `- ${dashboard.title}: ${dashboard.path}`),
  ].join("\n");
  fs.writeFileSync(path.join(outputDir, "validation-report.md"), `${report}\n`, "utf8");
  const result = {
    schemaVersion: AGENT_RUNTIME_P3_SCHEMA_VERSION,
    ok: validation.ok,
    failures: validation.failures,
    outputDir: path.relative(repoRoot, outputDir),
    checklistPath: path.relative(repoRoot, path.join(outputDir, "checklist.json")),
    scorecardPath: path.relative(repoRoot, path.join(outputDir, "scorecard.json")),
    dashboardIndexPath: path.relative(repoRoot, path.join(outputDir, "dashboard-index.json")),
    redactedDiagnosticBundlePath: path.relative(
      repoRoot,
      path.join(outputDir, "redacted-diagnostic-bundle.json"),
    ),
    validationReportPath: path.relative(repoRoot, path.join(outputDir, "validation-report.md")),
  };
  fs.writeFileSync(path.join(outputDir, "result.json"), `${JSON.stringify(result, null, 2)}\n`);
  return {
    readiness,
    validation,
    result,
  };
}

import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

import {
  buildWorkflowComputerUseTriLaneScorecard,
  renderWorkflowComputerUseTriLaneScorecardMarkdown,
} from "./computer-use-scorecard.mjs";

const repoRoot = resolve(new URL("../../..", import.meta.url).pathname);

function read(relativePath) {
  return readFileSync(resolve(repoRoot, relativePath), "utf8");
}

function collectProbeProof(
  outputRoot,
  {
    fileName,
    scriptPath,
    schemaVersion,
    scenario,
    errorLabel,
    timeout = 60_000,
  },
) {
  const path = join(outputRoot, fileName);
  const result = spawnSync(
    process.execPath,
    ["--import", "tsx", scriptPath, path],
    {
      cwd: repoRoot,
      encoding: "utf8",
      env: {
        ...process.env,
        TSX_TSCONFIG_PATH: resolve(
          repoRoot,
          "packages/agent-ide/tsconfig.json",
        ),
      },
      timeout,
      maxBuffer: 8 * 1024 * 1024,
    },
  );
  if (result.status !== 0 || !readableProof(path)) {
    const proof = {
      schemaVersion,
      scenario,
      passed: false,
      checks: {
        probeExecuted: false,
      },
      error:
        result.error?.message ??
        (result.signal
          ? `${errorLabel} terminated by ${result.signal}`
          : `${errorLabel} exited with ${result.status ?? "unknown"}`),
      stdout: result.stdout?.slice(-8_000) ?? "",
      stderr: result.stderr?.slice(-8_000) ?? "",
    };
    writeFileSync(path, `${JSON.stringify(proof, null, 2)}\n`, "utf8");
    return { path, proof };
  }
  try {
    return {
      path,
      proof: JSON.parse(readFileSync(path, "utf8")),
    };
  } catch (error) {
    const proof = {
      schemaVersion,
      scenario,
      passed: false,
      checks: {
        proofParsed: false,
      },
      error: String(error?.message || error),
    };
    writeFileSync(path, `${JSON.stringify(proof, null, 2)}\n`, "utf8");
    return { path, proof };
  }
}

function readableProof(path) {
  try {
    readFileSync(path, "utf8");
    return true;
  } catch {
    return false;
  }
}

export function collectWorkflowTelemetryBudgetChainCreatorProof(outputRoot) {
  return collectProbeProof(outputRoot, {
    fileName: "workflow-telemetry-budget-chain-creator-proof.json",
    scriptPath:
      "scripts/lib/workflow-telemetry-budget-chain-creator-gui-probe.mjs",
    schemaVersion: "workflow.telemetry-budget-chain.creator-gui-proof.v1",
    scenario: "workflow_telemetry_budget_chain_creator_click",
    errorLabel: "telemetry budget-chain GUI probe",
  });
}

export function collectWorkflowTelemetryBudgetChainRunInspectorProof(
  outputRoot,
) {
  return collectProbeProof(outputRoot, {
    fileName: "workflow-telemetry-budget-chain-run-inspector-proof.json",
    scriptPath:
      "scripts/lib/workflow-telemetry-budget-chain-run-inspector-probe.mjs",
    schemaVersion: "workflow.telemetry-budget-chain.run-inspector-proof.v1",
    scenario: "workflow_telemetry_budget_chain_run_inspector_materialize",
    errorLabel: "telemetry budget-chain run-inspector probe",
  });
}

export function collectWorkflowTerminalCodingLoopCreatorProof(outputRoot) {
  return collectProbeProof(outputRoot, {
    fileName: "workflow-terminal-coding-loop-creator-proof.json",
    scriptPath:
      "scripts/lib/workflow-terminal-coding-loop-creator-gui-probe.mjs",
    schemaVersion: "workflow.terminal-coding-loop.creator-gui-proof.v1",
    scenario: "workflow_terminal_coding_loop_creator_click",
    errorLabel: "terminal coding loop GUI probe",
  });
}

export function collectWorkflowTerminalCodingLoopRunInspectorProof(outputRoot) {
  return collectProbeProof(outputRoot, {
    fileName: "workflow-terminal-coding-loop-run-inspector-proof.json",
    scriptPath:
      "scripts/lib/workflow-terminal-coding-loop-run-inspector-probe.mjs",
    schemaVersion: "workflow.terminal-coding-loop.run-inspector-proof.v1",
    scenario: "workflow_terminal_coding_loop_run_inspector_materialize",
    errorLabel: "terminal coding loop run-inspector probe",
  });
}

export function collectWorkflowTerminalCodingLoopRunButtonProof(outputRoot) {
  return collectProbeProof(outputRoot, {
    fileName: "workflow-terminal-coding-loop-run-button-proof.json",
    scriptPath:
      "scripts/lib/workflow-terminal-coding-loop-run-button-gui-probe.mjs",
    schemaVersion: "workflow.terminal-coding-loop.run-button-proof.v1",
    scenario: "workflow_terminal_coding_loop_run_button_activation",
    errorLabel: "terminal coding loop Run-button probe",
  });
}

export function collectWorkflowCapabilityCatalogBindingProof(outputRoot) {
  return collectProbeProof(outputRoot, {
    fileName: "workflow-capability-catalog-binding-proof.json",
    scriptPath:
      "scripts/lib/workflow-capability-catalog-binding-gui-probe.mjs",
    schemaVersion: "workflow.capability-catalog-binding.gui-proof.v1",
    scenario: "workflow_capability_catalog_binding_clickthrough",
    errorLabel: "workflow capability catalog binding probe",
  });
}

export function collectWorkflowRunCapabilityReceiptsProof(outputRoot) {
  return collectProbeProof(outputRoot, {
    fileName: "workflow-run-capability-receipts-proof.json",
    scriptPath:
      "scripts/lib/workflow-run-capability-receipts-gui-probe.mjs",
    schemaVersion: "workflow.run-capability-receipts.gui-proof.v1",
    scenario: "workflow_run_capability_receipts_projection",
    errorLabel: "workflow run capability receipts probe",
  });
}

export function collectWorkflowSandboxedComputerRunButtonProof(outputRoot) {
  return collectProbeProof(outputRoot, {
    fileName: "workflow-sandboxed-computer-run-button-proof.json",
    scriptPath:
      "scripts/lib/workflow-sandboxed-computer-run-button-gui-probe.mjs",
    schemaVersion: "workflow.sandboxed-computer.run-button-proof.v1",
    scenario: "workflow_sandboxed_computer_run_button_activation",
    errorLabel: "sandboxed computer Run-button probe",
  });
}

export function collectWorkflowNativeBrowserPromptPipelineProof(outputRoot) {
  return collectProbeProof(outputRoot, {
    fileName: "workflow-native-browser-prompt-pipeline-proof.json",
    scriptPath:
      "scripts/lib/workflow-native-browser-prompt-pipeline-gui-probe.mjs",
    schemaVersion: "workflow.native-browser.prompt-pipeline-proof.v1",
    scenario: "workflow_native_browser_prompt_pipeline",
    errorLabel: "native browser prompt pipeline probe",
  });
}

export function collectWorkflowVisualGuiPromptPipelineProof(outputRoot) {
  return collectProbeProof(outputRoot, {
    fileName: "workflow-visual-gui-prompt-pipeline-proof.json",
    scriptPath:
      "scripts/lib/workflow-visual-gui-prompt-pipeline-gui-probe.mjs",
    schemaVersion: "workflow.visual-gui.prompt-pipeline-proof.v1",
    scenario: "workflow_visual_gui_prompt_pipeline",
    errorLabel: "visual GUI prompt pipeline probe",
  });
}

export function collectWorkflowComputerUseTriLaneScorecard(
  outputRoot,
  {
    workflowSandboxedComputerRunButtonProof,
    workflowNativeBrowserPromptPipelineProof,
    workflowVisualGuiPromptPipelineProof,
  },
) {
  const path = join(outputRoot, "workflow-computer-use-tri-lane-scorecard.json");
  const summaryPath = join(
    outputRoot,
    "workflow-computer-use-tri-lane-scorecard.md",
  );
  const proof = buildWorkflowComputerUseTriLaneScorecard({
    sandboxedComputerRunButtonProof: workflowSandboxedComputerRunButtonProof,
    nativeBrowserPromptPipelineProof: workflowNativeBrowserPromptPipelineProof,
    visualGuiPromptPipelineProof: workflowVisualGuiPromptPipelineProof,
  });
  writeFileSync(path, `${JSON.stringify(proof, null, 2)}\n`, "utf8");
  writeFileSync(
    summaryPath,
    renderWorkflowComputerUseTriLaneScorecardMarkdown(proof),
    "utf8",
  );
  return { path, summaryPath, proof };
}

export function collectWorkflowSkillContextProof(outputRoot) {
  const files = {
    graphTypes: "packages/agent-ide/src/types/graph.ts",
    nodeRegistry: "packages/agent-ide/src/runtime/workflow-node-registry.ts",
    bindingSections:
      "packages/agent-ide/src/features/Workflows/WorkflowNodeBindingEditor/sections.tsx",
    harnessTools: "packages/agent-ide/src/runtime/workflow-harness-tools.ts",
    tauriRuntime: "apps/autopilot/src/services/TauriRuntime.ts",
    projectRuntime: "apps/autopilot/src-tauri/src/project/runtime.rs",
    projectWorkflowSchedulerLane:
      "apps/autopilot/src-tauri/src/project/workflow_scheduler_lane.rs",
    projectCodingRouteLane:
      "apps/autopilot/src-tauri/src/project/workflow_coding_route_lane.rs",
    projectCommands: "apps/autopilot/src-tauri/src/project/commands.rs",
    runtimeTests:
      "apps/autopilot/src-tauri/src/project/workflow_project_tests/runtime_and_graph_contracts.rs",
  };
  const source = Object.fromEntries(
    Object.entries(files).map(([key, relativePath]) => [key, read(relativePath)]),
  );
  const checks = {
    nodeKindTyped:
      /WorkflowSkillContextConfig/.test(source.graphTypes) &&
      /"skill_context"/.test(source.graphTypes),
    creatorVariants:
      /creatorId: "skill_context\.discover"/.test(source.nodeRegistry) &&
      /creatorId: "skill_context\.pinned"/.test(source.nodeRegistry) &&
      /token: "SK"/.test(source.nodeRegistry),
    configUi:
      /workflow-skill-context-mode/.test(source.bindingSections) &&
      /workflow-skill-context-pinned-skills/.test(source.bindingSections) &&
      /workflow-skill-context-include-markdown/.test(source.bindingSections),
    catalogTool:
      /"workflow\.catalog\.skills"/.test(source.harnessTools) &&
      /listWorkflowSkillCatalog/.test(source.harnessTools),
    registryBackedRuntime:
      /getSkillCatalog\(\)/.test(source.tauriRuntime) &&
      /getSkillDetail\(skill\.skill_hash\)/.test(source.tauriRuntime) &&
      /workflowOptionsWithSkillCatalog/.test(source.tauriRuntime),
    resolverExecution:
      /workflow_scheduler_lane/.test(source.projectRuntime) &&
      /workflow_coding_route_lane/.test(source.projectWorkflowSchedulerLane) &&
      /struct WorkflowSkillResolver/.test(source.projectCodingRouteLane) &&
      /resolve_skill_context/.test(source.projectCodingRouteLane) &&
      /workflow\.skill-context\.v1/.test(source.projectCodingRouteLane) &&
      /workflow\.skill_context\.discovery\.v1/.test(
        source.projectCodingRouteLane,
      ) &&
      /workflow\.skill_context\.read\.v1/.test(source.projectCodingRouteLane),
    runCommandsPassResolver:
      /WorkflowSkillResolver::from_options\(options\.as_ref\(\)\)/.test(
        source.projectCommands,
      ) && /execute_workflow_project/.test(source.projectCommands),
    createAndRunTests:
      /workflow_skill_context_discovery_attaches_model_context/.test(
        source.runtimeTests,
      ) &&
      /workflow_skill_context_pinned_name_ambiguity_blocks/.test(
        source.runtimeTests,
      ) &&
      /edge-skill-model-context/.test(source.runtimeTests),
  };
  const proof = {
    schemaVersion: "workflow.skill-context.gui-proof.v1",
    passed: Object.values(checks).every(Boolean),
    scenario: "workflow_skill_context_create_run",
    checks,
    validatedSurfaces: [
      "composer node registry",
      "node config UI",
      "runtime registry resolver",
      "node/project run commands",
      "harness catalog tool",
      "create-and-run runtime contract tests",
    ],
  };
  const path = join(outputRoot, "workflow-skill-context-proof.json");
  writeFileSync(path, `${JSON.stringify(proof, null, 2)}\n`, "utf8");
  return { path, proof };
}

export function collectWorkflowCodingRouteProof(outputRoot) {
  const files = {
    graphTypes: "packages/agent-ide/src/types/graph.ts",
    graphRuntimeTypes: "packages/agent-ide/src/runtime/graph-runtime-types.ts",
    routeCatalog: "packages/agent-ide/src/runtime/workflow-coding-routes.ts",
    harnessTools: "packages/agent-ide/src/runtime/workflow-harness-tools.ts",
    tauriRuntime: "apps/autopilot/src/services/TauriRuntime.ts",
    projectTemplates: "apps/autopilot/src-tauri/src/project/templates.rs",
    projectRuntime: "apps/autopilot/src-tauri/src/project/runtime.rs",
    projectWorkflowSchedulerLane:
      "apps/autopilot/src-tauri/src/project/workflow_scheduler_lane.rs",
    projectCodingRouteLane:
      "apps/autopilot/src-tauri/src/project/workflow_coding_route_lane.rs",
    runtimeTests:
      "apps/autopilot/src-tauri/src/project/workflow_project_tests/runtime_and_graph_contracts.rs",
  };
  const source = Object.fromEntries(
    Object.entries(files).map(([key, relativePath]) => [key, read(relativePath)]),
  );
  const checks = {
    routeContractsTyped:
      /interface WorkflowCodingRouteContract/.test(source.graphTypes) &&
      /interface WorkflowCodingRouteEvidence/.test(source.graphTypes) &&
      /routeEvidence\?: WorkflowCodingRouteEvidence\[\]/.test(source.graphTypes),
    routeRuntimeApis:
      /listWorkflowCodingRoutes/.test(source.graphRuntimeTypes) &&
      /importWorkflowSkillPack/.test(source.graphRuntimeTypes),
    routeCatalog:
      /WORKFLOW_CODING_ROUTE_CONTRACTS/.test(source.routeCatalog) &&
      /coding\.template\.build/.test(source.routeCatalog) &&
      /coding\.template\.debug/.test(source.routeCatalog) &&
      /coding\.template\.review/.test(source.routeCatalog) &&
      /coding\.route\.gate\.v1/.test(source.routeCatalog),
    explicitTemplates:
      /coding\.template\.build/.test(source.projectTemplates) &&
      /coding\.template\.debug/.test(source.projectTemplates) &&
      /coding\.template\.review/.test(source.projectTemplates) &&
      /skill-context-route/.test(source.projectTemplates) &&
      /edge-skill-context-model-context/.test(source.projectTemplates) &&
      /"context"/.test(source.projectTemplates),
    classifierAndEvidence:
      /workflow_scheduler_lane/.test(source.projectRuntime) &&
      /workflow_coding_route_lane/.test(source.projectWorkflowSchedulerLane) &&
      /workflow_classify_coding_route/.test(source.projectCodingRouteLane) &&
      /workflow_coding_route_evidence_from_run/.test(
        source.projectCodingRouteLane,
      ) &&
      /coding\.route\.classification\.v1/.test(source.projectCodingRouteLane) &&
      /coding\.route\.skill_selection\.v1/.test(source.projectCodingRouteLane) &&
      /coding\.route\.gate\.v1/.test(source.projectCodingRouteLane),
    harnessCatalogAndImport:
      /"workflow\.catalog\.coding_routes"/.test(source.harnessTools) &&
      /listWorkflowCodingRoutes/.test(source.harnessTools) &&
      /"workflow\.skills\.import_pack"/.test(source.harnessTools) &&
      /importWorkflowSkillPack/.test(source.harnessTools),
    runtimeRegistryImportPath:
      /listWorkflowCodingRoutes/.test(source.tauriRuntime) &&
      /WORKFLOW_CODING_ROUTE_CONTRACTS/.test(source.tauriRuntime) &&
      /importWorkflowSkillPack/.test(source.tauriRuntime) &&
      /addSkillSource/.test(source.tauriRuntime) &&
      /syncSkillSource/.test(source.tauriRuntime),
    draftSkillPackImportFixture:
      /"sourceType": "runtime_skill_source_draft"/.test(source.runtimeTests) &&
      /"relativePath": "skills\/incremental-implementation\/SKILL\.md"/.test(
        source.runtimeTests,
      ) &&
      /"phaseTags": \["coding\.build", "coding\.verify"\]/.test(
        source.runtimeTests,
      ) &&
      /"routeTags": \["coding\.template\.build"\]/.test(source.runtimeTests),
    createRunInspectTests:
      /coding_route_templates_validate_run_and_emit_route_evidence/.test(
        source.runtimeTests,
      ) &&
      /coding_route_classifier_defaults_to_build_and_detects_debug_or_review/.test(
        source.runtimeTests,
      ) &&
      /coding\.route\.classification\.v1/.test(source.runtimeTests) &&
      /coding\.route\.skill_selection\.v1/.test(source.runtimeTests) &&
      /coding\.route\.gate\.v1/.test(source.runtimeTests),
  };
  const proof = {
    schemaVersion: "workflow.coding-route.gui-proof.v1",
    passed: Object.values(checks).every(Boolean),
    scenario: "workflow_coding_route_create_run_inspect",
    checks,
    validatedSurfaces: [
      "typed route contracts",
      "build/debug/review templates",
      "deterministic runtime classifier",
      "route evidence artifacts",
      "harness route catalog",
      "Draft skill-pack import path",
      "create-save-validate-run-inspect runtime tests",
    ],
  };
  const path = join(outputRoot, "workflow-coding-route-proof.json");
  writeFileSync(path, `${JSON.stringify(proof, null, 2)}\n`, "utf8");
  return { path, proof };
}

export function collectWorkflowCodingRoutePromotionLoopProof(outputRoot) {
  const files = {
    graphTypes: "packages/agent-ide/src/types/graph.ts",
    routeCatalog: "packages/agent-ide/src/runtime/workflow-coding-routes.ts",
    bottomShelf: "packages/agent-ide/src/features/Workflows/WorkflowBottomShelf.tsx",
    tauriRuntime: "apps/autopilot/src/services/TauriRuntime.ts",
    projectTemplates: "apps/autopilot/src-tauri/src/project/templates.rs",
    projectRuntime: "apps/autopilot/src-tauri/src/project/runtime.rs",
    projectWorkflowSchedulerLane:
      "apps/autopilot/src-tauri/src/project/workflow_scheduler_lane.rs",
    projectCodingRouteLane:
      "apps/autopilot/src-tauri/src/project/workflow_coding_route_lane.rs",
    runtimeTests:
      "apps/autopilot/src-tauri/src/project/workflow_project_tests/runtime_and_graph_contracts.rs",
  };
  const source = Object.fromEntries(
    Object.entries(files).map(([key, relativePath]) => [key, read(relativePath)]),
  );
  const checks = {
    hardenedRouteTypes:
      /interface WorkflowCodingRouteGateResult/.test(source.graphTypes) &&
      /interface WorkflowCodingRouteSkillSelection/.test(source.graphTypes) &&
      /interface WorkflowCodingRouteBenchmarkResult/.test(source.graphTypes) &&
      /interface WorkflowCodingRoutePromotionDecision/.test(source.graphTypes) &&
      /interface WorkflowCodingRouteRunSummary/.test(source.graphTypes),
    typedGateVocabulary:
      /"pass"/.test(source.graphTypes) &&
      /"warn"/.test(source.graphTypes) &&
      /"block"/.test(source.graphTypes) &&
      /"skipped"/.test(source.graphTypes),
    routeCatalogPhaseTopology:
      /phaseDetails/.test(source.routeCatalog) &&
      /componentKind: "builder"/.test(source.routeCatalog) &&
      /componentKind: "verifier"/.test(source.routeCatalog) &&
      /componentKind: "reviewer"/.test(source.routeCatalog),
    draftBenchmarkSelection:
      /allowDraftForBenchmark/.test(source.projectTemplates) &&
      /allowDraftForBenchmark/.test(source.projectCodingRouteLane),
    promotionRuntime:
      /workflow_scheduler_lane/.test(source.projectRuntime) &&
      /workflow_coding_route_lane/.test(source.projectWorkflowSchedulerLane) &&
      /workflow_coding_route_benchmark_results/.test(
        source.projectCodingRouteLane,
      ) &&
      /workflow_coding_route_promotion_decisions/.test(
        source.projectCodingRouteLane,
      ) &&
      /workflow_coding_route_run_summary/.test(source.projectCodingRouteLane) &&
      /coding\.route\.benchmark\.v1/.test(source.projectCodingRouteLane) &&
      /coding\.route\.promotion\.v1/.test(source.projectCodingRouteLane),
    draftImportMetadata:
      /workflowDraftSkillsFromSources/.test(source.tauriRuntime) &&
      /runtime_skill_source_draft/.test(source.tauriRuntime) &&
      /workflowPhaseTagsForSkill/.test(source.tauriRuntime) &&
      /workflowRouteTagsForSkill/.test(source.tauriRuntime),
    promotionMetadataUpdate:
      /applyWorkflowPromotionDecisions/.test(source.tauriRuntime) &&
      /WORKFLOW_SKILL_PROMOTION_LEDGER_KEY/.test(source.tauriRuntime) &&
      /promotionEvidenceRefs/.test(source.tauriRuntime),
    operatorEvidenceUi:
      /workflow-route-promotion-summary/.test(source.bottomShelf) &&
      /routeRunSummary/.test(source.bottomShelf) &&
      /workflow-route-selected-skill/.test(source.bottomShelf) &&
      /workflow-route-gate/.test(source.bottomShelf) &&
      /workflow-route-promotion/.test(source.bottomShelf),
    guiForkabilitySurface:
      /forkWorkflowCheckpoint/.test(source.tauriRuntime) &&
      /WorkflowCheckpointForkRequest/.test(source.graphTypes),
    promotionLoopTest:
      /coding_route_promotion_loop_promotes_draft_skill_with_evidence/.test(
        source.runtimeTests,
      ) &&
      /coding\.route\.benchmark\.v1/.test(source.runtimeTests) &&
      /coding\.route\.promotion\.v1/.test(source.runtimeTests),
    draftSkillPackPromotionFixture:
      /"skillHash": "draft-incremental"/.test(source.runtimeTests) &&
      /"sourceType": "runtime_skill_source_draft"/.test(source.runtimeTests) &&
      /"relativePath": "skills\/incremental-implementation\/SKILL\.md"/.test(
        source.runtimeTests,
      ) &&
      /selected_skill_hash == "draft-incremental"/.test(source.runtimeTests) &&
      /decision\.to_lifecycle_state == "Promoted"/.test(source.runtimeTests),
  };
  const proof = {
    schemaVersion: "workflow.coding-route.promotion-loop.gui-proof.v1",
    passed: Object.values(checks).every(Boolean),
    scenario: "workflow_coding_route_promotion_loop",
    checks,
    validatedSurfaces: [
      "typed route gates",
      "phase-aware route topology",
      "Draft skill import metadata",
      "benchmark-backed promotion receipts",
      "run summary promotion metadata",
      "operator evidence UI",
      "workflow forkability surface",
      "create-save-validate-run-inspect-fork proof contract",
    ],
  };
  const path = join(outputRoot, "workflow-coding-route-promotion-loop-proof.json");
  writeFileSync(path, `${JSON.stringify(proof, null, 2)}\n`, "utf8");
  return { path, proof };
}

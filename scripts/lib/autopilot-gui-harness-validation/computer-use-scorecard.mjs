export const WORKFLOW_COMPUTER_USE_TRI_LANE_SCORECARD_SCHEMA_VERSION =
  "workflow.computer-use.tri-lane-scorecard.v1";

const REQUIRED_MODEL_TRACE_PHASES = [
  "input",
  "binding",
  "prompt",
  "model",
  "tool_selection",
];

export function buildWorkflowComputerUseTriLaneScorecard({
  sandboxedComputerRunButtonProof,
  nativeBrowserPromptPipelineProof,
  visualGuiPromptPipelineProof,
}) {
  const laneReports = [
    laneReport({
      laneId: "native_browser",
      proof: nativeBrowserPromptPipelineProof?.proof,
      proofPath: nativeBrowserPromptPipelineProof?.path,
      requiredModelTrace: true,
      requiredScenario: "workflow_native_browser_prompt_pipeline",
      traceNodeCountKey: "browserTraceNodeCount",
    }),
    laneReport({
      laneId: "visual_gui",
      proof: visualGuiPromptPipelineProof?.proof,
      proofPath: visualGuiPromptPipelineProof?.path,
      requiredModelTrace: true,
      requiredScenario: "workflow_visual_gui_prompt_pipeline",
      traceNodeCountKey: "visualTraceNodeCount",
    }),
    laneReport({
      laneId: "sandboxed_hosted",
      proof: sandboxedComputerRunButtonProof?.proof,
      proofPath: sandboxedComputerRunButtonProof?.path,
      requiredModelTrace: false,
      requiredScenario: "workflow_sandboxed_computer_run_button_activation",
      traceNodeCountKey: "projectedNodeCount",
    }),
  ];
  const laneIds = new Set(laneReports.map((lane) => lane.lane));
  const checks = {
    nativeBrowserProofPassed:
      laneById(laneReports, "native_browser")?.proofPassed === true,
    visualGuiProofPassed:
      laneById(laneReports, "visual_gui")?.proofPassed === true,
    sandboxedHostedProofPassed:
      laneById(laneReports, "sandboxed_hosted")?.proofPassed === true,
    laneCoverageComplete:
      laneIds.has("native_browser") &&
      laneIds.has("visual_gui") &&
      laneIds.has("sandboxed_hosted"),
    runButtonCoverage: laneReports.every((lane) => lane.runButtonWired),
    modelPromptTraceCoverage: laneReports
      .filter((lane) => lane.requiredModelTrace)
      .every((lane) => lane.modelPromptTracePresent),
    runtimeTraceCoverage: laneReports.every(
      (lane) => (lane.runtimeEventCount ?? 0) >= 10,
    ),
    environmentSelectionCoverage: laneReports.every(
      (lane) => lane.environmentSelectionPresent,
    ),
    observationAndTargetCoverage: laneReports.every(
      (lane) => lane.targetCount > 0,
    ),
    affordanceProposalPolicyCoverage: laneReports.every(
      (lane) =>
        lane.affordanceCount > 0 &&
        Boolean(lane.workbench.proposalRef) &&
        Boolean(lane.workbench.policyOutcome),
    ),
    actionVerificationCleanupCoverage: laneReports.every(
      (lane) =>
        Boolean(lane.workbench.actionRef) &&
        lane.workbench.verificationStatus === "passed" &&
        lane.workbench.cleanupStatus === "completed",
    ),
    approvalOrFailClosedCoverage: laneReports.every(
      (lane) =>
        Boolean(lane.workbench.commitGateStatus) &&
        (lane.lane !== "visual_gui" ||
          lane.workbench.policyApprovalRef ===
            "approval-visual-gui-run-button" ||
          lane.workbench.commitGateStatus === "approved") &&
        (lane.lane !== "sandboxed_hosted" ||
          lane.workbench.policyFailClosed === true),
    ),
    projectionIdentityCoverage: laneReports.every(
      (lane) => lane.projectionIdentityPreserved,
    ),
    noReactFlowShadowRuntimeTruth: laneReports.every(
      (lane) => lane.noCanvasLocalRuntimeTruth,
    ),
  };
  const passed = Object.values(checks).every(Boolean);
  return {
    schemaVersion: WORKFLOW_COMPUTER_USE_TRI_LANE_SCORECARD_SCHEMA_VERSION,
    scenario: "workflow_computer_use_tri_lane_scorecard",
    passed,
    promotionStatus: passed ? "passed" : "blocked",
    checks,
    laneReports,
    scorecard: {
      laneCoverage: countTrue([
        checks.nativeBrowserProofPassed,
        checks.visualGuiProofPassed,
        checks.sandboxedHostedProofPassed,
      ]),
      laneCoverageRequired: 3,
      promptTraceLanesCovered: laneReports.filter(
        (lane) => lane.requiredModelTrace && lane.modelPromptTracePresent,
      ).length,
      promptTraceLanesRequired: laneReports.filter(
        (lane) => lane.requiredModelTrace,
      ).length,
      totalRuntimeEvents: laneReports.reduce(
        (count, lane) => count + (lane.runtimeEventCount ?? 0),
        0,
      ),
      totalTargetCount: laneReports.reduce(
        (count, lane) => count + lane.targetCount,
        0,
      ),
      totalAffordanceCount: laneReports.reduce(
        (count, lane) => count + lane.affordanceCount,
        0,
      ),
    },
    externalDeferrals: [
      {
        id: "hosted_provider_backends",
        status: "external_provider_deferral",
        reason:
          "Concrete VM/container/mobile hosted providers still require selected provider credentials, isolation policy, and retention policy; the deterministic local fixture covers runtime truth and fail-closed posture.",
      },
      {
        id: "external_eval_ingestion",
        status: "external_provider_deferral",
        reason:
          "OSWorld/ScreenSpot/WorkArena scorecard ingestion remains provider-backed; this scorecard gates IOI's retained tri-lane runtime/workflow proof artifacts.",
      },
    ],
  };
}

function laneReport({
  laneId,
  proof,
  proofPath,
  requiredModelTrace,
  requiredScenario,
  traceNodeCountKey,
}) {
  const requestSummary = proof?.requestSummary ?? {};
  const checks = proof?.checks ?? {};
  const workbench = requestSummary.workbench ?? {};
  const projectionLabels = new Set(requestSummary.projectionLabels ?? []);
  const projectionSteps = requestSummary.projectionSteps ?? [];
  const modelTracePhases = requestSummary.modelTracePhases ?? [];
  return {
    lane: requestSummary.lane ?? laneId,
    requiredScenario,
    proofPath: proofPath ?? null,
    proofScenario: proof?.scenario ?? null,
    proofPassed: proof?.passed === true,
    sessionMode: requestSummary.sessionMode ?? null,
    actionKind: requestSummary.actionKind ?? null,
    requiredModelTrace,
    modelId: requestSummary.modelId ?? null,
    modelPromptTracePresent:
      requiredModelTrace === false
        ? null
        : REQUIRED_MODEL_TRACE_PHASES.every((phase) =>
            modelTracePhases.includes(phase),
          ),
    runtimeEventCount: requestSummary.runtimeEventCount ?? 0,
    projectedNodeCount:
      requestSummary[traceNodeCountKey] ??
      requestSummary.projectedNodeCount ??
      requestSummary.browserTraceNodeCount ??
      requestSummary.visualTraceNodeCount ??
      0,
    targetCount: requestSummary.targetCount ?? 0,
    affordanceCount: requestSummary.affordanceCount ?? 0,
    environmentSelectionPresent:
      projectionLabels.has("Computer use: select environment") ||
      projectionSteps.some((step) => step.step === "select_environment"),
    runButtonWired:
      checks.realRunButtonRendered === true &&
      checks.realRunButtonClickWired === true &&
      checks.genericRunButtonUsesRuntimeProjectBridge === true,
    projectionIdentityPreserved: checks.graphNodeIdentityPreserved === true,
    noCanvasLocalRuntimeTruth: checks.noCanvasLocalRuntimeTruth === true,
    workbench: {
      proposalRef: workbench.proposalRef ?? null,
      actionRef: workbench.actionRef ?? null,
      actionKind: workbench.actionKind ?? requestSummary.actionKind ?? null,
      executionStatus: workbench.executionStatus ?? null,
      executionAdapterId: workbench.executionAdapterId ?? null,
      executionProviderId: workbench.executionProviderId ?? null,
      executionPreflightStatus: workbench.executionPreflightStatus ?? null,
      executionRequiresReobserve:
        workbench.executionRequiresReobserve ?? null,
      verificationStatus: workbench.verificationStatus ?? null,
      commitGateStatus: workbench.commitGateStatus ?? null,
      cleanupStatus: workbench.cleanupStatus ?? null,
      policyOutcome: workbench.policyOutcome ?? null,
      policyApprovalRef: workbench.policyApprovalRef ?? null,
      policyFailClosed: workbench.policyFailClosed ?? null,
      retentionMode: workbench.retentionMode ?? null,
    },
  };
}

function laneById(lanes, laneId) {
  return lanes.find((lane) => lane.lane === laneId);
}

function countTrue(values) {
  return values.filter(Boolean).length;
}

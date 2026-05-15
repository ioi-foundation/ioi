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
      laneIds.has("sandboxed_hosted") &&
      laneReports.every((lane) => lane.proofScenario === lane.requiredScenario),
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
  const externalDeferrals = [
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
  ];
  const summaryRows = laneReports.map(operatorSummaryRow);
  const blockers = blockingRowsForChecks(checks, laneReports);
  return {
    schemaVersion: WORKFLOW_COMPUTER_USE_TRI_LANE_SCORECARD_SCHEMA_VERSION,
    scenario: "workflow_computer_use_tri_lane_scorecard",
    passed,
    promotionStatus: passed ? "passed" : "blocked",
    checks,
    laneReports,
    operatorSummary: {
      status: passed ? "passed" : "blocked",
      headline: passed
        ? "Computer-use tri-lane retained gate passed."
        : `${blockers.length} computer-use tri-lane blocker${blockers.length === 1 ? "" : "s"} detected.`,
      summaryRows,
      blockers,
      externalDeferrals,
    },
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
    externalDeferrals,
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

function operatorSummaryRow(lane) {
  const blockers = laneBlockers(lane);
  return {
    id: `lane:${lane.lane}`,
    lane: lane.lane,
    status: blockers.length === 0 ? "passed" : "blocked",
    label: laneLabel(lane.lane),
    sessionMode: lane.sessionMode,
    actionKind: lane.workbench.actionKind ?? lane.actionKind,
    modelPromptTrace:
      lane.requiredModelTrace === false
        ? "not_required"
        : lane.modelPromptTracePresent
          ? "present"
          : "missing",
    runtimeEvents: lane.runtimeEventCount,
    projectedNodes: lane.projectedNodeCount,
    targets: lane.targetCount,
    affordances: lane.affordanceCount,
    policy:
      lane.workbench.policyApprovalRef ??
      lane.workbench.policyOutcome ??
      (lane.workbench.policyFailClosed === true ? "fail_closed" : null),
    verification: lane.workbench.verificationStatus,
    cleanup: lane.workbench.cleanupStatus,
    proofPath: lane.proofPath,
    blockers,
  };
}

function laneBlockers(lane) {
  const blockers = [];
  if (!lane.proofPassed) blockers.push("proof_failed_or_missing");
  if (lane.proofScenario !== lane.requiredScenario) {
    blockers.push("required_scenario_missing");
  }
  if (!lane.runButtonWired) blockers.push("composer_run_not_wired");
  if (lane.requiredModelTrace && !lane.modelPromptTracePresent) {
    blockers.push("model_prompt_trace_missing");
  }
  if ((lane.runtimeEventCount ?? 0) < 10) blockers.push("runtime_trace_short");
  if (!lane.environmentSelectionPresent) {
    blockers.push("environment_selection_missing");
  }
  if (lane.targetCount <= 0) blockers.push("target_index_missing");
  if (lane.affordanceCount <= 0) blockers.push("affordance_graph_missing");
  if (!lane.workbench.proposalRef) blockers.push("proposal_missing");
  if (!lane.workbench.policyOutcome) blockers.push("policy_outcome_missing");
  if (!lane.workbench.actionRef) blockers.push("action_missing");
  if (lane.workbench.verificationStatus !== "passed") {
    blockers.push("verification_not_passed");
  }
  if (lane.workbench.cleanupStatus !== "completed") {
    blockers.push("cleanup_not_completed");
  }
  if (!lane.workbench.commitGateStatus) blockers.push("commit_gate_missing");
  if (
    lane.lane === "visual_gui" &&
    lane.workbench.policyApprovalRef !== "approval-visual-gui-run-button" &&
    lane.workbench.commitGateStatus !== "approved"
  ) {
    blockers.push("visual_approval_missing");
  }
  if (lane.lane === "sandboxed_hosted" && lane.workbench.policyFailClosed !== true) {
    blockers.push("sandbox_fail_closed_missing");
  }
  if (!lane.projectionIdentityPreserved) {
    blockers.push("projection_identity_missing");
  }
  if (!lane.noCanvasLocalRuntimeTruth) {
    blockers.push("react_flow_shadow_truth_detected");
  }
  return blockers;
}

function blockingRowsForChecks(checks, laneReports) {
  return Object.entries(checks)
    .filter(([, passed]) => passed !== true)
    .map(([check]) => ({
      id: `blocker:${check}`,
      severity: "blocking",
      check,
      title: blockerTitle(check),
      detail: blockerDetail(check),
      lanes: blockedLanesForCheck(check, laneReports),
    }));
}

function blockedLanesForCheck(check, laneReports) {
  switch (check) {
    case "nativeBrowserProofPassed":
      return ["native_browser"];
    case "visualGuiProofPassed":
      return ["visual_gui"];
    case "sandboxedHostedProofPassed":
      return ["sandboxed_hosted"];
    case "laneCoverageComplete":
      return laneReports
        .filter((lane) => lane.proofScenario !== lane.requiredScenario)
        .map((lane) => lane.lane);
    case "runButtonCoverage":
      return laneReports.filter((lane) => !lane.runButtonWired).map((lane) => lane.lane);
    case "modelPromptTraceCoverage":
      return laneReports
        .filter((lane) => lane.requiredModelTrace && !lane.modelPromptTracePresent)
        .map((lane) => lane.lane);
    case "runtimeTraceCoverage":
      return laneReports
        .filter((lane) => (lane.runtimeEventCount ?? 0) < 10)
        .map((lane) => lane.lane);
    case "environmentSelectionCoverage":
      return laneReports
        .filter((lane) => !lane.environmentSelectionPresent)
        .map((lane) => lane.lane);
    case "observationAndTargetCoverage":
      return laneReports.filter((lane) => lane.targetCount <= 0).map((lane) => lane.lane);
    case "affordanceProposalPolicyCoverage":
      return laneReports
        .filter(
          (lane) =>
            lane.affordanceCount <= 0 ||
            !lane.workbench.proposalRef ||
            !lane.workbench.policyOutcome,
        )
        .map((lane) => lane.lane);
    case "actionVerificationCleanupCoverage":
      return laneReports
        .filter(
          (lane) =>
            !lane.workbench.actionRef ||
            lane.workbench.verificationStatus !== "passed" ||
            lane.workbench.cleanupStatus !== "completed",
        )
        .map((lane) => lane.lane);
    case "approvalOrFailClosedCoverage":
      return laneReports
        .filter(
          (lane) =>
            !lane.workbench.commitGateStatus ||
            (lane.lane === "visual_gui" &&
              lane.workbench.policyApprovalRef !==
                "approval-visual-gui-run-button" &&
              lane.workbench.commitGateStatus !== "approved") ||
            (lane.lane === "sandboxed_hosted" &&
              lane.workbench.policyFailClosed !== true),
        )
        .map((lane) => lane.lane);
    case "projectionIdentityCoverage":
      return laneReports
        .filter((lane) => !lane.projectionIdentityPreserved)
        .map((lane) => lane.lane);
    case "noReactFlowShadowRuntimeTruth":
      return laneReports
        .filter((lane) => !lane.noCanvasLocalRuntimeTruth)
        .map((lane) => lane.lane);
    default:
      return [];
  }
}

function blockerTitle(check) {
  return (
    {
      nativeBrowserProofPassed: "Native browser proof did not pass.",
      visualGuiProofPassed: "Visual GUI proof did not pass.",
      sandboxedHostedProofPassed: "Sandboxed hosted proof did not pass.",
      laneCoverageComplete: "Required lane proof is missing or mismatched.",
      runButtonCoverage: "Composer Run wiring evidence is incomplete.",
      modelPromptTraceCoverage: "Mounted model prompt trace coverage is incomplete.",
      runtimeTraceCoverage: "Runtime trace coverage is incomplete.",
      environmentSelectionCoverage:
        "Environment selection evidence is incomplete.",
      observationAndTargetCoverage: "Observation or target evidence is incomplete.",
      affordanceProposalPolicyCoverage:
        "Affordance, proposal, or policy evidence is incomplete.",
      actionVerificationCleanupCoverage:
        "Action, verification, or cleanup evidence is incomplete.",
      approvalOrFailClosedCoverage:
        "Approval or fail-closed posture is incomplete.",
      projectionIdentityCoverage:
        "Workflow projection identity evidence is incomplete.",
      noReactFlowShadowRuntimeTruth:
        "React Flow shadow runtime truth regression detected.",
    }[check] ?? `Computer-use scorecard check failed: ${check}`
  );
}

function blockerDetail(check) {
  return (
    {
      laneCoverageComplete:
        "Every retained lane must have the expected proof scenario before promotion.",
      modelPromptTraceCoverage:
        "Composed model lanes must show input, binding, prompt, model, and tool-selection phases.",
      approvalOrFailClosedCoverage:
        "Visual coordinate actions need approval evidence and sandboxed lanes need fail-closed posture.",
      noReactFlowShadowRuntimeTruth:
        "React Flow may project and configure runtime truth, but must not own a second runtime state.",
    }[check] ?? "Inspect the lane summary rows for the missing evidence class."
  );
}

function laneLabel(lane) {
  return (
    {
      native_browser: "Native Browser",
      visual_gui: "Visual GUI",
      sandboxed_hosted: "Sandboxed Hosted",
    }[lane] ?? lane
  );
}

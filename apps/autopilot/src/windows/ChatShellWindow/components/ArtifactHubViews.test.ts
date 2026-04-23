import assert from "node:assert/strict";
import type { PlanSummary, ThoughtAgentSummary } from "../../../types";
import { workerInsightForPlanSummary } from "./artifactHubWorkerInsight";

function basePlanSummary(): PlanSummary {
  return {
    selectedRoute: "route",
    routeFamily: "general",
    topology: "single_agent",
    plannerAuthority: "primary_agent",
    status: "running",
    currentStage: null,
    progressSummary: null,
    pauseSummary: null,
    workerCount: 0,
    branchCount: 0,
    evidenceCount: 0,
    activeWorkerLabel: null,
    activeWorkerRole: null,
    verifierState: "not_engaged",
    verifierRole: null,
    verifierOutcome: null,
    approvalState: "clear",
    selectedSkills: [],
    prepSummary: null,
    artifactGeneration: null,
    computerUsePerception: null,
    researchVerification: null,
    artifactQuality: null,
    computerUseVerification: null,
    codingVerification: null,
    patchSynthesis: null,
    artifactRepair: null,
    computerUseRecovery: null,
    policyBindings: [],
  };
}

function thoughtAgent(
  overrides: Partial<ThoughtAgentSummary>,
): ThoughtAgentSummary {
  return {
    agentLabel: "Worker",
    agentRole: null,
    agentKind: "worker",
    stepIndex: 1,
    notes: [],
    ...overrides,
  };
}

function workerInsightUsesTypedVerifierKind(): void {
  const planSummary: PlanSummary = {
    ...basePlanSummary(),
    routeFamily: "research",
    topology: "planner_specialist_verifier",
    plannerAuthority: "kernel",
    verifierState: "passed",
    verifierRole: "citation_verifier",
    verifierOutcome: "pass",
    researchVerification: {
      verdict: "passed",
      sourceCount: 2,
      distinctDomainCount: 2,
      sourceCountFloorMet: true,
      sourceIndependenceFloorMet: true,
      freshnessStatus: "passed",
      quoteGroundingStatus: "passed",
      notes: "Typed verifier worker surfaced the research scorecard.",
    },
  };

  const insight = workerInsightForPlanSummary(
    thoughtAgent({
      agentLabel: "Grounding Specialist",
      agentRole: "Source Review",
      agentKind: "verifier",
    }),
    planSummary,
  );

  assert.deepEqual(insight, {
    label: "Verifier finding",
    text: "Typed verifier worker surfaced the research scorecard.",
  });
}

function workerInsightDoesNotInferVerifierFromJudgeLikeLabel(): void {
  const planSummary: PlanSummary = {
    ...basePlanSummary(),
    routeFamily: "artifacts",
    topology: "planner_specialist_verifier",
    plannerAuthority: "kernel",
    verifierState: "passed",
    verifierRole: "artifact_validation_verifier",
    verifierOutcome: "warning",
    artifactQuality: {
      verdict: "needs_attention",
      fidelityStatus: "faithful",
      presentationStatus: "needs_repair",
      repairStatus: "required",
      notes: "Artifact validation still has feedback.",
    },
  };

  const insight = workerInsightForPlanSummary(
    thoughtAgent({
      agentLabel: "Validator Violet",
      agentRole: "Source Notes",
      agentKind: "worker",
    }),
    planSummary,
  );

  assert.equal(insight, null);
}

function workerInsightUsesTypedArtifactGeneratorKind(): void {
  const planSummary: PlanSummary = {
    ...basePlanSummary(),
    routeFamily: "artifacts",
    topology: "planner_specialist_verifier",
    plannerAuthority: "kernel",
    artifactGeneration: {
      status: "ready",
      producedFileCount: 3,
      verificationSignalStatus: "retained",
      presentationStatus: "ready",
      notes: "Generated three retained artifact files.",
    },
  };

  const insight = workerInsightForPlanSummary(
    thoughtAgent({
      agentLabel: "Artifact Builder",
      agentRole: "Generate Artifact",
      agentKind: "artifact_generator",
    }),
    planSummary,
  );

  assert.deepEqual(insight, {
    label: "Output",
    text: "Generated three retained artifact files.",
  });
}

workerInsightUsesTypedVerifierKind();
workerInsightDoesNotInferVerifierFromJudgeLikeLabel();
workerInsightUsesTypedArtifactGeneratorKind();

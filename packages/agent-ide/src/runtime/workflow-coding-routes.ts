import type { WorkflowCodingRouteContract } from "../types/graph";

export const WORKFLOW_CODING_ROUTE_EVIDENCE_KINDS = [
  "coding.route.classification.v1",
  "coding.route.phase.start.v1",
  "coding.route.phase.complete.v1",
  "coding.route.skill_selection.v1",
  "coding.route.gate.v1",
  "coding.route.benchmark.v1",
  "coding.route.promotion.v1",
] as const;

const BUILD_PHASE_DETAILS = [
  { phaseId: "coding.intake", label: "Intake", componentKind: "context", required: true, gateIds: [] },
  { phaseId: "coding.context", label: "Context", componentKind: "context", required: true, gateIds: [] },
  { phaseId: "coding.plan", label: "Plan", componentKind: "planner", required: true, gateIds: ["route.build.plan"] },
  { phaseId: "coding.build", label: "Build", componentKind: "builder", required: true, gateIds: [] },
  { phaseId: "coding.verify", label: "Verify", componentKind: "verifier", required: true, gateIds: ["route.verify.execution"] },
  { phaseId: "coding.closeout", label: "Closeout", componentKind: "merge_verdict", required: true, gateIds: [] },
] satisfies WorkflowCodingRouteContract["phaseDetails"];

const DEBUG_PHASE_DETAILS = [
  { phaseId: "coding.intake", label: "Intake", componentKind: "context", required: true, gateIds: [] },
  { phaseId: "coding.context", label: "Context", componentKind: "context", required: true, gateIds: [] },
  { phaseId: "coding.define", label: "Define", componentKind: "planner", required: true, gateIds: ["route.debug.repro"] },
  { phaseId: "coding.verify", label: "Verify", componentKind: "verifier", required: true, gateIds: ["route.verify.execution"] },
  { phaseId: "coding.review", label: "Review", componentKind: "reviewer", required: true, gateIds: [] },
  { phaseId: "coding.closeout", label: "Closeout", componentKind: "merge_verdict", required: true, gateIds: [] },
] satisfies WorkflowCodingRouteContract["phaseDetails"];

const REVIEW_PHASE_DETAILS = [
  { phaseId: "coding.intake", label: "Intake", componentKind: "context", required: true, gateIds: [] },
  { phaseId: "coding.context", label: "Context", componentKind: "context", required: true, gateIds: [] },
  { phaseId: "coding.review", label: "Review", componentKind: "reviewer", required: true, gateIds: ["route.review.findings"] },
  { phaseId: "coding.verify", label: "Verify", componentKind: "verifier", required: true, gateIds: ["route.verify.execution"] },
  { phaseId: "coding.closeout", label: "Closeout", componentKind: "merge_verdict", required: true, gateIds: [] },
] satisfies WorkflowCodingRouteContract["phaseDetails"];

export const WORKFLOW_CODING_ROUTE_CONTRACTS = [
  {
    schemaVersion: "workflow.coding-route.v1",
    routeId: "coding.template.build",
    label: "Build",
    taskClass: "build",
    riskLevel: "normal",
    phases: [
      "coding.intake",
      "coding.context",
      "coding.plan",
      "coding.build",
      "coding.verify",
      "coding.closeout",
    ],
    phaseDetails: BUILD_PHASE_DETAILS,
    requiredSkillSelectors: [
      {
        mode: "discover",
        names: ["incremental-implementation", "test-driven-development"],
        required: false,
      },
    ],
    optionalSkillSelectors: [
      { mode: "discover", names: ["code-review"], required: false },
    ],
    evidenceRequirements: [...WORKFLOW_CODING_ROUTE_EVIDENCE_KINDS],
    gates: [
      {
        gateId: "route.build.plan",
        label: "Implementation plan",
        phaseId: "coding.plan",
        evidenceKind: "execution",
        required: true,
        status: "skipped",
        operatorOverrideAllowed: false,
        blockingRequirements: ["planning evidence"],
      },
      {
        gateId: "route.verify.execution",
        label: "Verification evidence",
        phaseId: "coding.verify",
        evidenceKind: "execution",
        required: true,
        status: "skipped",
        operatorOverrideAllowed: false,
        blockingRequirements: ["node execution evidence"],
      },
    ],
    skipRules: ["Do not bypass explicit skill_context attachment for model context."],
    failureBehavior: "block",
  },
  {
    schemaVersion: "workflow.coding-route.v1",
    routeId: "coding.template.debug",
    label: "Debug",
    taskClass: "debug",
    riskLevel: "normal",
    phases: [
      "coding.intake",
      "coding.context",
      "coding.define",
      "coding.verify",
      "coding.review",
      "coding.closeout",
    ],
    phaseDetails: DEBUG_PHASE_DETAILS,
    requiredSkillSelectors: [
      {
        mode: "discover",
        names: ["debugging", "regression", "test-driven-development"],
        required: false,
      },
    ],
    optionalSkillSelectors: [
      { mode: "discover", names: ["incremental-implementation"], required: false },
    ],
    evidenceRequirements: [...WORKFLOW_CODING_ROUTE_EVIDENCE_KINDS],
    gates: [
      {
        gateId: "route.debug.repro",
        label: "Failure reproduction",
        phaseId: "coding.define",
        evidenceKind: "execution",
        required: true,
        status: "skipped",
        operatorOverrideAllowed: false,
        blockingRequirements: ["reproduction or diagnostic evidence"],
      },
      {
        gateId: "route.verify.execution",
        label: "Verification evidence",
        phaseId: "coding.verify",
        evidenceKind: "execution",
        required: true,
        status: "skipped",
        operatorOverrideAllowed: false,
        blockingRequirements: ["node execution evidence"],
      },
    ],
    skipRules: ["Do not ship without a verified repro or equivalent diagnostic evidence."],
    failureBehavior: "block",
  },
  {
    schemaVersion: "workflow.coding-route.v1",
    routeId: "coding.template.review",
    label: "Review",
    taskClass: "review",
    riskLevel: "normal",
    phases: [
      "coding.intake",
      "coding.context",
      "coding.review",
      "coding.verify",
      "coding.closeout",
    ],
    phaseDetails: REVIEW_PHASE_DETAILS,
    requiredSkillSelectors: [
      {
        mode: "discover",
        names: ["code-review", "security-review", "test-review"],
        required: false,
      },
    ],
    optionalSkillSelectors: [
      { mode: "discover", names: ["incremental-implementation"], required: false },
    ],
    evidenceRequirements: [...WORKFLOW_CODING_ROUTE_EVIDENCE_KINDS],
    gates: [
      {
        gateId: "route.review.findings",
        label: "Finding evidence",
        phaseId: "coding.review",
        evidenceKind: "execution",
        required: true,
        status: "skipped",
        operatorOverrideAllowed: false,
        blockingRequirements: ["findings or explicit no-findings evidence"],
      },
      {
        gateId: "route.verify.execution",
        label: "Verification evidence",
        phaseId: "coding.verify",
        evidenceKind: "execution",
        required: true,
        status: "skipped",
        operatorOverrideAllowed: false,
        blockingRequirements: ["node execution evidence"],
      },
    ],
    skipRules: ["Do not treat skill guidance as review findings without runtime evidence."],
    failureBehavior: "block",
  },
] satisfies WorkflowCodingRouteContract[];

export function workflowCodingRouteContract(
  routeId: string,
): WorkflowCodingRouteContract | null {
  return (
    WORKFLOW_CODING_ROUTE_CONTRACTS.find((route) => route.routeId === routeId) ?? null
  );
}

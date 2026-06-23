import type {
  WorkflowSchedulerLaneCapabilityId,
  WorkflowSchedulerLaneReadiness,
  WorkflowValidationIssue,
} from "../types/graph";

export type WorkflowSchedulerLaneCapabilitySpec = Omit<
  WorkflowSchedulerLaneReadiness,
  "status"
> & {
  id: WorkflowSchedulerLaneCapabilityId;
};

export const EXPECTED_WORKFLOW_SCHEDULER_LANE_CAPABILITY_IDS = [
  "scheduler",
  "scheduler.finalization",
  "terminalResult",
  "nodeExecution",
  "nodeOutcome",
  "nodeStateUpdate",
  "nodeSuccessEvent",
  "nodeFailureOutcome",
  "interrupt",
  "validation",
] as const satisfies readonly WorkflowSchedulerLaneCapabilityId[];

const HYPERVISOR_WORKFLOW_SCHEDULER_EVIDENCE: string[] = [
  "crates/services/src/agentic/automation.rs",
  "crates/node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs",
  "apps/hypervisor/src/services/HypervisorClientRuntime.ts",
];

export const WORKFLOW_SCHEDULER_LANE_CAPABILITIES = [
  {
    id: "scheduler",
    label: "Scheduler",
    capabilityScope: "runtime.workflow.scheduler",
    proofCheckKey: "workflowSchedulerRuntimeLane",
    detail:
      "Main workflow execution loop delegates validation, node execution, interruptions, and finalization to scheduler lanes.",
    evidenceRefs: HYPERVISOR_WORKFLOW_SCHEDULER_EVIDENCE,
    blockerCode: "scheduler_lane_capability_missing",
  },
  {
    id: "scheduler.finalization",
    label: "Scheduler finalization",
    capabilityScope: "runtime.workflow.scheduler.finalization",
    proofCheckKey: "workflowSchedulerFinalizationRuntimeLane",
    detail:
      "Completion requirements, missing-output checks, and terminal result routing are isolated in the finalization lane.",
    evidenceRefs: [
      "crates/services/src/agentic/automation.rs",
    ],
    blockerCode: "scheduler_lane_capability_missing",
  },
  {
    id: "terminalResult",
    label: "Terminal result",
    capabilityScope: "runtime.workflow.scheduler.terminal_result",
    proofCheckKey: "workflowSchedulerTerminalResultRuntimeLane",
    detail:
      "Run completion summaries, thread persistence, harness artifacts, and final result assembly live in the terminal result lane.",
    evidenceRefs: [
      "crates/services/src/agentic/automation.rs",
    ],
    blockerCode: "scheduler_lane_capability_missing",
  },
  {
    id: "nodeExecution",
    label: "Node execution",
    capabilityScope: "runtime.workflow.scheduler.node_execution",
    proofCheckKey: "workflowSchedulerNodeExecutionRuntimeLane",
    detail:
      "Ready-node attempts, retry lifecycle events, and node execution handoff are isolated from graph state mutation.",
    evidenceRefs: [
      "crates/services/src/agentic/automation.rs",
    ],
    blockerCode: "scheduler_lane_capability_missing",
  },
  {
    id: "nodeOutcome",
    label: "Node outcome",
    capabilityScope: "runtime.workflow.scheduler.node_outcome",
    proofCheckKey: "workflowSchedulerNodeOutcomeRuntimeLane",
    detail:
      "Node execution results route into state updates, success events, or failure outcomes through a dedicated outcome lane.",
    evidenceRefs: [
      "crates/services/src/agentic/automation.rs",
    ],
    blockerCode: "scheduler_lane_capability_missing",
  },
  {
    id: "nodeStateUpdate",
    label: "Node state update",
    capabilityScope: "runtime.workflow.scheduler.node_state_update",
    proofCheckKey: "workflowSchedulerNodeStateUpdateRuntimeLane",
    detail:
      "Branch decisions, pending writes, selected output, and next-ready-node projection stay in the state update lane.",
    evidenceRefs: [
      "crates/services/src/agentic/automation.rs",
    ],
    blockerCode: "scheduler_lane_capability_missing",
  },
  {
    id: "nodeSuccessEvent",
    label: "Node success event",
    capabilityScope: "runtime.workflow.scheduler.node_success_event",
    proofCheckKey: "workflowSchedulerNodeSuccessEventRuntimeLane",
    detail:
      "Success, child-run, output, and asset materialization events are emitted from the success event lane.",
    evidenceRefs: [
      "crates/services/src/agentic/automation.rs",
    ],
    blockerCode: "scheduler_lane_capability_missing",
  },
  {
    id: "nodeFailureOutcome",
    label: "Node failure outcome",
    capabilityScope: "runtime.workflow.scheduler.node_failure_outcome",
    proofCheckKey: "workflowSchedulerNodeFailureOutcomeRuntimeLane",
    detail:
      "Failed attempts, blocked node ids, and failure lifecycle events are isolated in the failure outcome lane.",
    evidenceRefs: [
      "crates/services/src/agentic/automation.rs",
    ],
    blockerCode: "scheduler_lane_capability_missing",
  },
  {
    id: "interrupt",
    label: "Interrupt",
    capabilityScope: "runtime.workflow.scheduler.interrupt",
    proofCheckKey: "workflowSchedulerInterruptRuntimeLane",
    detail:
      "Runtime interrupt prompts, notices, checkpoint state, and terminal summaries are handled in the interrupt lane.",
    evidenceRefs: [
      "crates/services/src/agentic/automation.rs",
    ],
    blockerCode: "scheduler_lane_capability_missing",
  },
  {
    id: "validation",
    label: "Validation",
    capabilityScope: "runtime.workflow.scheduler.validation",
    proofCheckKey: "workflowSchedulerValidationRuntimeLane",
    detail:
      "Validation-blocked runs produce terminal summaries without attaching finalization-only artifacts.",
    evidenceRefs: [
      "crates/services/src/agentic/automation.rs",
    ],
    blockerCode: "scheduler_lane_capability_missing",
  },
] as const satisfies readonly WorkflowSchedulerLaneCapabilitySpec[];

const schedulerLaneFallbackLabels: Record<
  WorkflowSchedulerLaneCapabilityId,
  string
> = {
  scheduler: "Scheduler",
  "scheduler.finalization": "Scheduler finalization",
  terminalResult: "Terminal result",
  nodeExecution: "Node execution",
  nodeOutcome: "Node outcome",
  nodeStateUpdate: "Node state update",
  nodeSuccessEvent: "Node success event",
  nodeFailureOutcome: "Node failure outcome",
  interrupt: "Interrupt",
  validation: "Validation",
};

export function workflowSchedulerLaneReadiness(
  specs: readonly WorkflowSchedulerLaneCapabilitySpec[] =
    WORKFLOW_SCHEDULER_LANE_CAPABILITIES,
): WorkflowSchedulerLaneReadiness[] {
  const specById = new Map(specs.map((spec) => [spec.id, spec]));
  return EXPECTED_WORKFLOW_SCHEDULER_LANE_CAPABILITY_IDS.map((id) => {
    const spec = specById.get(id);
    if (spec) {
      return {
        ...spec,
        status: "ready",
      };
    }
    return {
      id,
      label: schedulerLaneFallbackLabels[id],
      capabilityScope: `runtime.workflow.scheduler.${id}`,
      proofCheckKey: `missing:${id}`,
      status: "blocked",
      detail:
        "Scheduler lane capability is missing from the React Flow readiness manifest.",
      evidenceRefs: [],
      blockerCode: "scheduler_lane_capability_missing",
    };
  });
}

export function workflowSchedulerLaneReadinessIssues(
  lanes: readonly WorkflowSchedulerLaneReadiness[],
): WorkflowValidationIssue[] {
  return lanes
    .filter((lane) => lane.status !== "ready")
    .map((lane) => ({
      code: lane.blockerCode ?? "scheduler_lane_capability_missing",
      message: `${lane.label} lane capability is ${lane.status}; ${lane.detail}`,
      repairActionId: "open-harness-readiness",
      repairLabel: "Review scheduler lanes",
      configSection: "advanced",
    }));
}

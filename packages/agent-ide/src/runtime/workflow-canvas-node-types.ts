import type { WorkflowNodeKind } from "../types/graph";
import { WORKFLOW_NODE_DEFINITIONS } from "./workflow-node-registry";

export const WORKFLOW_CANVAS_RUNTIME_PROJECTION_NODE_TYPE_IDS = Object.freeze([
  "task_state",
  "uncertainty_gate",
  "probe",
  "budget_gate",
  "capability_sequence",
  "dry_run",
  "semantic_impact",
  "postcondition_synthesis",
  "verifier",
  "drift_detector",
  "quality_ledger",
  "handoff",
  "gui_harness_validation",
] satisfies WorkflowNodeKind[]);

export const WORKFLOW_CANVAS_NODE_TYPE_IDS = Object.freeze(
  Array.from(
    new Set([
      ...WORKFLOW_NODE_DEFINITIONS.map((definition) => definition.type),
      ...WORKFLOW_CANVAS_RUNTIME_PROJECTION_NODE_TYPE_IDS,
    ]),
  ).sort(),
);

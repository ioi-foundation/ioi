import { WORKFLOW_NODE_DEFINITIONS } from "./workflow-node-registry";

export const WORKFLOW_CANVAS_NODE_TYPE_IDS = Object.freeze(
  Array.from(
    new Set(WORKFLOW_NODE_DEFINITIONS.map((definition) => definition.type)),
  ).sort(),
);

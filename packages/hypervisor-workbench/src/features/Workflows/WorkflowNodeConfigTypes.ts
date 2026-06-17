import type {
  WorkflowConnectionClass,
  WorkflowPortDefinition,
} from "../../types/graph";
import type {
  WorkflowNodeCreatorDefinition,
  WorkflowNodeDefinition,
} from "../../runtime/workflow-node-registry";

export interface WorkflowUpstreamReference {
  nodeId: string;
  nodeName: string;
  nodeType: string;
  portId: string;
  connectionClass: WorkflowConnectionClass;
  expression: string;
  schema: unknown;
  latestOutput: unknown;
}

export interface WorkflowCompatibleNodeHint {
  definition: WorkflowNodeDefinition | WorkflowNodeCreatorDefinition;
  sourcePort: WorkflowPortDefinition;
  targetPort: WorkflowPortDefinition;
  connectionClass: WorkflowConnectionClass;
  direction: "downstream" | "attachment";
  recommended: boolean;
}

export interface WorkflowNodeConnectionReference {
  edgeId: string;
  peerNodeId: string;
  peerNodeName: string;
  peerNodeType: string;
  localPortId: string;
  peerPortId: string;
  connectionClass: WorkflowConnectionClass;
  label?: string;
}

export type WorkflowNodeConfigSectionId =
  | "settings"
  | "connections"
  | "inputs"
  | "mapping"
  | "outputs"
  | "schema"
  | "bindings"
  | "policy"
  | "fixtures"
  | "run-data"
  | "tests"
  | "advanced";

export interface WorkflowNodeDetailSection {
  id: WorkflowNodeConfigSectionId;
  label: string;
}

export const WORKFLOW_NODE_DETAIL_SECTIONS: WorkflowNodeDetailSection[] = [
  { id: "settings", label: "Settings" },
  { id: "connections", label: "Connections" },
  { id: "inputs", label: "Inputs" },
  { id: "mapping", label: "Mapping" },
  { id: "outputs", label: "Outputs" },
  { id: "schema", label: "Schema" },
  { id: "bindings", label: "Bindings" },
  { id: "policy", label: "Policy" },
  { id: "fixtures", label: "Fixtures" },
  { id: "run-data", label: "Run data" },
  { id: "tests", label: "Tests" },
  { id: "advanced", label: "Advanced" },
];

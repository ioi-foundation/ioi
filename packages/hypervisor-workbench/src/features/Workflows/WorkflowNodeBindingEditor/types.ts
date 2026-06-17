import type {
  FirewallPolicy,
  Node,
  NodeLogic,
} from "../../../types/graph";
export interface WorkflowNodeBindingEditorProps {
  node: Node;
  logic: NodeLogic;
  law: FirewallPolicy;
  sectionStatus: string;
  sectionDetail: string;
  modelAttachmentCounts: {
    model: number;
    memory: number;
    tool: number;
    parser: number;
  };
  dryRunView: {
    status: string;
    nodeRun?: { attempt?: number } | null;
    sandbox: Record<string, unknown>;
    resultPayload: unknown;
    stdout?: string;
    stderr?: string;
    error?: string;
  } | null;
  onUpdate: (updates: Partial<Node>) => void;
  updateLogic: (nextLogic: NodeLogic) => void;
  onDryRun: () => void;
}
export type WorkflowNodeBindingSectionsProps = Omit<WorkflowNodeBindingEditorProps, "sectionStatus" | "sectionDetail">;

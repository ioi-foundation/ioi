import type {
  WorkflowNodeRun,
  WorkflowProject,
  WorkflowProposal,
  WorkflowRunResult,
  WorkflowTestCase,
  WorkflowValidationIssue,
  WorkflowValidationResult,
} from "../types/graph";
import { workflowNodeName } from "./workflow-rail-model";

export interface WorkflowInterruptPreview {
  binding?: {
    bindingKind?: string;
    ref?: string;
    sideEffectClass?: string;
  };
  reason?: string;
}

export interface WorkflowBottomValidationIssueItem {
  category: string;
  issue: WorkflowValidationIssue;
  status: "blocked" | "warning";
}

export interface WorkflowBottomSuggestion {
  id: string;
  title: string;
  message: string;
  nodeId?: string;
  status: "ready" | "warning" | "blocked";
}

export function workflowInterruptPreview(result: WorkflowRunResult | null): WorkflowInterruptPreview | undefined {
  return result?.interrupt?.response as WorkflowInterruptPreview | undefined;
}

export function workflowBottomValidationIssueItems(
  validationResult: WorkflowValidationResult | null,
): WorkflowBottomValidationIssueItem[] {
  return validationResult
    ? [
        ...validationResult.errors.map((issue) => ({ category: "Error", issue, status: "blocked" as const })),
        ...validationResult.missingConfig.map((issue) => ({ category: "Missing config", issue, status: "blocked" as const })),
        ...validationResult.connectorBindingIssues.map((issue) => ({ category: "Binding", issue, status: "blocked" as const })),
        ...(validationResult.executionReadinessIssues ?? []).map((issue) => ({
          category: "Readiness",
          issue,
          status: "blocked" as const,
        })),
        ...(validationResult.verificationIssues ?? []).map((issue) => ({
          category: "Verification",
          issue,
          status: "blocked" as const,
        })),
        ...validationResult.warnings.map((issue) => ({ category: "Warning", issue, status: "warning" as const })),
      ]
    : [];
}

export function workflowBottomSuggestions({
  workflow,
  tests,
  proposals,
  validationResult,
  validationIssueItems,
}: {
  workflow: WorkflowProject;
  tests: WorkflowTestCase[];
  proposals: WorkflowProposal[];
  validationResult: WorkflowValidationResult | null;
  validationIssueItems?: WorkflowBottomValidationIssueItem[];
}): WorkflowBottomSuggestion[] {
  const issueItems = validationIssueItems ?? workflowBottomValidationIssueItems(validationResult);
  const uncoveredNodes = validationResult
    ? workflow.nodes.filter((nodeItem) => (validationResult.coverageByNodeId[nodeItem.id] ?? []).length === 0)
    : [];
  const outputNodes = workflow.nodes.filter((nodeItem) => nodeItem.type === "output");
  const suggestions: WorkflowBottomSuggestion[] = [];

  if (!validationResult) {
    suggestions.push({
      id: "run-validation",
      title: "Validate executable readiness",
      message: "Run validation to surface configuration, binding, policy, and output blockers.",
      status: "warning",
    });
  }

  issueItems.slice(0, 6).forEach(({ category, issue, status }, index) => {
    suggestions.push({
      id: `issue-${issue.code}-${index}`,
      title: `${category}: ${issue.nodeId ? workflowNodeName(workflow, issue.nodeId) : "Workflow"}`,
      message: issue.message,
      nodeId: issue.nodeId,
      status,
    });
  });

  if (tests.length === 0) {
    suggestions.push({
      id: "add-tests",
      title: "Add unit tests",
      message: "Attach tests to critical nodes so runs can prove behavior before activation.",
      status: "warning",
    });
  } else if (uncoveredNodes.length > 0) {
    suggestions.push({
      id: "cover-nodes",
      title: "Expand test coverage",
      message: `${uncoveredNodes.length} node${uncoveredNodes.length === 1 ? "" : "s"} have no unit-test target.`,
      nodeId: uncoveredNodes[0]?.id,
      status: "warning",
    });
  }

  if (outputNodes.length === 0) {
    suggestions.push({
      id: "add-output",
      title: "Define workflow output",
      message: "Add an Output primitive so the workflow has an explicit product and completion target.",
      status: "blocked",
    });
  }

  const openProposalCount = proposals.filter((proposal) => proposal.status === "open").length;
  if (openProposalCount > 0) {
    suggestions.push({
      id: "review-proposals",
      title: "Review bounded proposals",
      message: `${openProposalCount} open proposal${openProposalCount === 1 ? "" : "s"} can be previewed before apply.`,
      status: "ready",
    });
  }

  if (suggestions.length === 0) {
    suggestions.push({
      id: "ready",
      title: "No local suggestions",
      message: "This workflow has no current local suggestions. Formal graph changes should still go through proposals.",
      status: "ready",
    });
  }

  return suggestions;
}

export function workflowSelectedNodeValidationIssues(
  selectedNodeRun: WorkflowNodeRun | null,
  selectedNodeId: string | undefined,
  issueItems: WorkflowBottomValidationIssueItem[],
): WorkflowBottomValidationIssueItem[] {
  const nodeId = selectedNodeId ?? selectedNodeRun?.nodeId;
  return nodeId ? issueItems.filter(({ issue }) => issue.nodeId === nodeId) : [];
}

import type {
  WorkflowProject,
  WorkflowValidationIssue,
  WorkflowValidationResult,
} from "../types/graph";

export type WorkflowRunLaunchGuard =
  | {
      status: "ready";
      validation: WorkflowValidationResult;
      message: null;
    }
  | {
      status: "blocked";
      validation: WorkflowValidationResult;
      message: string;
    };

function firstValidationMessage(result: WorkflowValidationResult): string {
  return (
    result.errors[0]?.message ??
    result.missingConfig[0]?.message ??
    result.connectorBindingIssues[0]?.message ??
    result.executionReadinessIssues?.[0]?.message ??
    result.verificationIssues?.[0]?.message ??
    result.warnings[0]?.message ??
    `Workflow run blocked by ${result.status} validation.`
  );
}

function runLaunchIssue(
  code: string,
  message: string,
): WorkflowValidationIssue {
  return { code, message };
}

function uniqueStrings(values: string[]): string[] {
  return Array.from(new Set(values.filter(Boolean)));
}

function withRunLaunchIssues(
  validation: WorkflowValidationResult,
  issues: WorkflowValidationIssue[],
): WorkflowValidationResult {
  return {
    ...validation,
    status: "blocked",
    errors: [...issues, ...validation.errors],
    warnings: [...validation.warnings],
    blockedNodes: uniqueStrings([
      ...validation.blockedNodes,
      ...issues.map((issue) => issue.nodeId ?? ""),
    ]),
    executionReadinessIssues: [
      ...(validation.executionReadinessIssues ?? []),
      ...issues,
    ],
  };
}

export function workflowRunLaunchGuard(
  workflow: WorkflowProject,
  validation: WorkflowValidationResult,
): WorkflowRunLaunchGuard {
  if (validation.status !== "passed") {
    return {
      status: "blocked",
      validation,
      message: firstValidationMessage(validation),
    };
  }

  const issues: WorkflowValidationIssue[] = [];
  const hasStart = workflow.nodes.some(
    (node) => node.type === "trigger" || node.type === "source",
  );
  const hasOutput = workflow.nodes.some((node) => node.type === "output");

  if (workflow.nodes.length === 0) {
    issues.push(
      runLaunchIssue(
        "empty_workflow_run_blocked",
        "Run needs at least one workflow node before activation.",
      ),
    );
  }
  if (!hasStart) {
    issues.push(
      runLaunchIssue(
        "missing_start_node",
        "Run needs a trigger or source/input node before activation.",
      ),
    );
  }
  if (!hasOutput) {
    issues.push(
      runLaunchIssue(
        "missing_output_node",
        "Run needs at least one output node before activation.",
      ),
    );
  }

  if (issues.length === 0) {
    return {
      status: "ready",
      validation,
      message: null,
    };
  }

  const blockedValidation = withRunLaunchIssues(validation, issues);
  return {
    status: "blocked",
    validation: blockedValidation,
    message: issues[0]?.message ?? "Workflow run blocked before activation.",
  };
}

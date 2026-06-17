import { objectRecord, optionalString } from "./runtime-value-helpers.mjs";

const REPOSITORY_PROJECTIONS = {
  listRepositories: {
    operation: "repository_workflow_repository_list",
    operation_kind: "repository_workflow.projection.repository_list",
    projection_kind: "repository_list",
  },
  repositoryContext: {
    operation: "repository_workflow_repository_context",
    operation_kind: "repository_workflow.projection.repository_context",
    projection_kind: "repository_context",
  },
  branchPolicy: {
    operation: "repository_workflow_branch_policy",
    operation_kind: "repository_workflow.projection.branch_policy",
    projection_kind: "branch_policy",
  },
  githubContext: {
    operation: "repository_workflow_github_context",
    operation_kind: "repository_workflow.projection.github_context",
    projection_kind: "github_context",
  },
  prAttempts: {
    operation: "repository_workflow_pr_attempts",
    operation_kind: "repository_workflow.projection.pr_attempts",
    projection_kind: "pr_attempts",
  },
  issueContext: {
    operation: "repository_workflow_issue_context",
    operation_kind: "repository_workflow.projection.issue_context",
    projection_kind: "issue_context",
  },
  reviewGate: {
    operation: "repository_workflow_review_gate",
    operation_kind: "repository_workflow.projection.review_gate",
    projection_kind: "review_gate",
  },
  githubPrCreatePlan: {
    operation: "repository_workflow_github_pr_create_plan",
    operation_kind: "repository_workflow.projection.github_pr_create_plan",
    projection_kind: "github_pr_create_plan",
  },
};

export function createRuntimeRepositoryApi({
  contextPolicyCore = null,
} = {}) {
  const project = (store, projection) =>
    projectRepositoryWorkflow({
      contextPolicyCore,
      workspace_root: store?.defaultCwd,
      ...projection,
    });

  return {
    listRepositories(store) {
      return project(store, REPOSITORY_PROJECTIONS.listRepositories);
    },
    repositoryContext(store) {
      return project(store, REPOSITORY_PROJECTIONS.repositoryContext);
    },
    branchPolicy(store) {
      return project(store, REPOSITORY_PROJECTIONS.branchPolicy);
    },
    githubContext(store) {
      return project(store, REPOSITORY_PROJECTIONS.githubContext);
    },
    prAttempts(store) {
      return project(store, REPOSITORY_PROJECTIONS.prAttempts);
    },
    issueContext(store) {
      return project(store, REPOSITORY_PROJECTIONS.issueContext);
    },
    reviewGate(store) {
      return project(store, REPOSITORY_PROJECTIONS.reviewGate);
    },
    githubPrCreatePlan(store) {
      return project(store, REPOSITORY_PROJECTIONS.githubPrCreatePlan);
    },
  };
}

function projectRepositoryWorkflow(details = {}) {
  const { contextPolicyCore = null, ...errorDetails } = details;
  const evidence_refs = [
    "runtime_repository_workflow_rust_projection",
    "agentgres_repository_workflow_truth_required",
  ];

  if (!contextPolicyCore?.projectRepositoryWorkflow) {
    throw createRepositoryWorkflowProjectionError(null, {
      ...errorDetails,
      source: "runtime.repository_api",
      evidence_refs,
    });
  }

  const result = contextPolicyCore.projectRepositoryWorkflow({
    ...errorDetails,
    source: "runtime.repository_api",
    evidence_refs,
  });
  if (result?.projection_kind !== errorDetails.projection_kind) {
    throw createRepositoryWorkflowProjectionMismatchError(result, errorDetails);
  }
  const projection = result?.projection;
  if (["repository_list", "pr_attempts"].includes(errorDetails.projection_kind)) {
    if (Array.isArray(projection)) return projection;
  } else if (objectRecord(projection)) {
    return projection;
  }
  throw createRepositoryWorkflowProjectionMismatchError(result, errorDetails);
}

function createRepositoryWorkflowProjectionError(record, fallbackDetails) {
  const error = new Error(
    optionalString(record?.message) ??
      "Repository workflow projection requires Rust daemon-core projection over Agentgres-admitted repository workflow truth.",
  );
  error.status = Number(record?.status_code ?? 501);
  error.code =
    optionalString(record?.code) ??
    "runtime_repository_workflow_rust_projection_missing";
  error.details = record?.details ?? {
    rust_core_boundary: "runtime.repository_workflow_projection",
    ...fallbackDetails,
  };
  return error;
}

function createRepositoryWorkflowProjectionMismatchError(result, fallbackDetails) {
  const error = new Error(
    "Rust repository workflow projection returned an invalid route projection.",
  );
  error.status = 502;
  error.code = "runtime_repository_workflow_rust_projection_invalid";
  error.details = {
    rust_core_boundary: "runtime.repository_workflow_projection",
    expected_projection_kind: fallbackDetails.projection_kind,
    actual_projection_kind: result?.projection_kind ?? null,
    operation: fallbackDetails.operation,
    operation_kind: fallbackDetails.operation_kind,
    source: "runtime.repository_api",
  };
  return error;
}

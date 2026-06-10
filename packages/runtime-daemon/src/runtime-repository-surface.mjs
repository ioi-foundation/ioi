import { optionalString } from "./runtime-value-helpers.mjs";

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

export function createRuntimeRepositorySurface({
  repositoryRunner = null,
} = {}) {
  const fail = (store, projection) =>
    throwRepositoryWorkflowProjectionRustCoreRequired({
      repositoryRunner,
      workspace_root: store?.defaultCwd,
      ...projection,
    });

  return {
    listRepositories(store) {
      fail(store, REPOSITORY_PROJECTIONS.listRepositories);
    },
    repositoryContext(store) {
      fail(store, REPOSITORY_PROJECTIONS.repositoryContext);
    },
    branchPolicy(store) {
      fail(store, REPOSITORY_PROJECTIONS.branchPolicy);
    },
    githubContext(store) {
      fail(store, REPOSITORY_PROJECTIONS.githubContext);
    },
    prAttempts(store) {
      fail(store, REPOSITORY_PROJECTIONS.prAttempts);
    },
    issueContext(store) {
      fail(store, REPOSITORY_PROJECTIONS.issueContext);
    },
    reviewGate(store) {
      fail(store, REPOSITORY_PROJECTIONS.reviewGate);
    },
    githubPrCreatePlan(store) {
      fail(store, REPOSITORY_PROJECTIONS.githubPrCreatePlan);
    },
  };
}

function throwRepositoryWorkflowProjectionRustCoreRequired(details = {}) {
  const { repositoryRunner = null, ...errorDetails } = details;
  const evidence_refs = [
    "runtime_repository_workflow_js_projection_retired",
    "rust_daemon_core_repository_workflow_projection_required",
    "agentgres_repository_workflow_truth_required",
  ];

  if (repositoryRunner?.planRepositoryWorkflowProjectionRequired) {
    const record = repositoryRunner.planRepositoryWorkflowProjectionRequired({
      ...errorDetails,
      source: "runtime.repository_surface",
      evidence_refs,
    });
    const planned = record?.record ?? record;
    throw createRepositoryWorkflowProjectionError(planned ?? record, {
      ...errorDetails,
      source: "runtime.repository_surface",
      evidence_refs,
    });
  }

  throw createRepositoryWorkflowProjectionError(null, {
    ...errorDetails,
    source: "runtime.repository_surface",
    evidence_refs,
  });
}

function createRepositoryWorkflowProjectionError(record, fallbackDetails) {
  const error = new Error(
    optionalString(record?.message) ??
      "Repository workflow projection requires direct Rust daemon-core projection over Agentgres-admitted repository workflow truth.",
  );
  error.status = Number(record?.status_code ?? 501);
  error.code =
    optionalString(record?.code) ??
    "runtime_repository_workflow_projection_rust_core_required";
  error.details = record?.details ?? {
    rust_core_boundary: "runtime.repository_workflow_projection",
    ...fallbackDetails,
  };
  return error;
}

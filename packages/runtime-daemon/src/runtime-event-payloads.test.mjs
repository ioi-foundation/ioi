import assert from "node:assert/strict";
import test from "node:test";

import { createRuntimeEventPayloadHelpers } from "./runtime-event-payloads.mjs";

function normalizeArray(value) {
  return Array.isArray(value) ? value : [];
}

function uniqueStrings(values) {
  return [...new Set(normalizeArray(values).filter(Boolean).map(String))];
}

const retiredPayloadKeys = ["id", "type"].map((suffix) => ["legacy", "event", suffix].join("_"));

const retiredComputerUseSummaryAliasKeys = [
  "eventKind",
  "schemaVersion",
  "workflowGraphId",
  "workflowNodeId",
  "workflowNodeIds",
  "toolRef",
  "authorityScopes",
];

const retiredMemorySummaryAliasKeys = [
  "eventKind",
  "memoryRecordId",
  "memoryPolicyId",
  "workflowNodeId",
];

const retiredRepositoryContextSummaryAliasKeys = [
  "eventKind",
  "contextId",
  "isGitRepository",
  "repoRootHash",
  "detachedHead",
  "headShortSha",
  "remoteCount",
  "mutationExecuted",
  "workflowNodeId",
];

const retiredBranchPolicySummaryAliasKeys = [
  "eventKind",
  "policyId",
  "repositoryContextId",
  "defaultBranch",
  "protectedBranch",
  "detachedHead",
  "mutationAllowed",
  "prCreationAllowed",
  "reviewRequired",
  "mutationExecuted",
  "workflowNodeId",
];

const retiredGithubContextSummaryAliasKeys = [
  "eventKind",
  "contextId",
  "repositoryContextId",
  "branchPolicyId",
  "githubRemotePresent",
  "defaultRemoteName",
  "repoFullName",
  "defaultBranch",
  "branchPolicyStatus",
  "prCreationEligible",
  "networkLookupPerformed",
  "mutationExecuted",
  "workflowNodeId",
];

const retiredIssueContextSummaryAliasKeys = [
  "eventKind",
  "contextId",
  "repositoryContextId",
  "githubContextId",
  "prAttemptId",
  "reviewGateId",
  "repoFullName",
  "issueProvided",
  "issueNumber",
  "sourceKind",
  "networkLookupPerformed",
  "mutationExecuted",
  "workflowNodeId",
];

const retiredPrAttemptSummaryAliasKeys = [
  "eventKind",
  "attemptId",
  "repositoryContextId",
  "branchPolicyId",
  "githubContextId",
  "repoFullName",
  "defaultBranch",
  "headShortSha",
  "branchArtifact",
  "diffArtifact",
  "mutationAttempted",
  "mutationExecuted",
  "networkLookupPerformed",
  "workflowNodeId",
];

const retiredRuntimeTaskSummaryAliasKeys = [
  "eventKind",
  "taskId",
  "runId",
  "agentId",
  "threadId",
  "turnId",
  "taskFamily",
  "selectedStrategy",
  "promptIncluded",
  "workflowNodeId",
];

const retiredRuntimeChecklistSummaryAliasKeys = [
  "eventKind",
  "checklistId",
  "taskId",
  "jobId",
  "runId",
  "itemCount",
  "completedItemCount",
  "failedItemCount",
  "canceledItemCount",
  "blockedItemCount",
  "requiredItemIds",
  "workflowNodeId",
];

const retiredRuntimeJobSummaryAliasKeys = [
  "eventKind",
  "jobId",
  "taskId",
  "runId",
  "agentId",
  "threadId",
  "turnId",
  "lifecycleStatus",
  "queueName",
  "jobType",
  "queuedAt",
  "startedAt",
  "completedAt",
  "workflowNodeId",
];

const retiredUsageSummaryReaderAliasKeys = [
  "eventKind",
  "schemaVersion",
  "runId",
  "threadId",
  "turnId",
  "totalTokens",
  "inputTokens",
  "outputTokens",
  "estimatedCostUsd",
  "contextPressure",
  "contextPressureStatus",
  "workflowNodeId",
  "componentKind",
];

const retiredContextPressureDeltaSummaryReaderAliasKeys = [
  "eventKind",
  "schemaVersion",
  "runId",
  "threadId",
  "turnId",
  "usageTotalTokens",
  "usageCostEstimateUsd",
  "usageContextPressure",
  "usageContextPressureStatus",
  "workflowNodeId",
  "componentKind",
];

const retiredContextPressureAlertSummaryReaderAliasKeys = [
  "eventKind",
  "schemaVersion",
  "alertId",
  "alertLevel",
  "pressureStatus",
  "recommendedAction",
  "runId",
  "threadId",
  "turnId",
  "workflowNodeId",
  "componentKind",
];

const retiredUsageFinalSummaryReaderAliasKeys = [
  "eventKind",
  "schemaVersion",
  "threadId",
  "turnId",
  "totalTokens",
  "inputTokens",
  "outputTokens",
  "estimatedCostUsd",
  "contextPressure",
  "contextPressureStatus",
  "workflowNodeId",
];

function legacyDataFor(keys) {
  return Object.fromEntries(keys.map((key) => [key, "legacy"]));
}

function helpers() {
  return createRuntimeEventPayloadHelpers({
    COMPUTER_USE_CONTRACT_SCHEMA_VERSION: "computer.v1",
    LSP_DIAGNOSTICS_INJECTION_NODE_ID: "runtime.lsp-diagnostics.inject",
    RUNTIME_CONTEXT_PRESSURE_ALERT_SCHEMA_VERSION: "context.alert.v1",
    RUNTIME_CONTEXT_PRESSURE_DELTA_SCHEMA_VERSION: "context.delta.v1",
    RUNTIME_USAGE_DELTA_SCHEMA_VERSION: "usage.delta.v1",
    RUNTIME_USAGE_TELEMETRY_SCHEMA_VERSION: "usage.final.v1",
    computerUseSourceEventKind: (type) => `ComputerUse.${type}`,
    isComputerUseRunEventType: (type) => type.startsWith("computer_use_"),
    memoryEventKind: (operation = "write") =>
      operation === "policy_update" ? "MemoryPolicy" : "AgentMemory",
    normalizeArray,
    uniqueStrings,
  });
}

test("runtime event payloads preserve computer-use and memory summaries", () => {
  const runtime = helpers();

  const computerUse = runtime.payloadSummaryForRunEvent({
    id: "event-one",
    type: "computer_use_observation",
    runId: "run-one",
    agentId: "agent-one",
    summary: "Observed page",
    data: {
      event_kind: "ComputerUse.Observation",
      eventKind: "RetiredComputerUseEventKind",
      schema_version: "computer.v1",
      schemaVersion: "retired.computer.v1",
      computer_use_step: "observe",
      computer_use_observation_ref: "observation-one",
      workflow_graph_id: "workflow-one",
      workflowGraphId: "retired-workflow",
      workflow_node_id: "node-one",
      workflowNodeId: "retired-node",
      workflow_node_ids: ["node-one"],
      workflowNodeIds: ["retired-node"],
      tool_ref: "computer_use.observe",
      toolRef: "retired-tool",
      authority_scopes: ["computer_use.read"],
      authorityScopes: ["retired.scope"],
      fail_closed_when_unavailable: true,
    },
  });

  assert.equal(computerUse.event_kind, "ComputerUse.Observation");
  assert.equal(computerUse.schema_version, "computer.v1");
  assert.equal(computerUse.computer_use_step, "observe");
  assert.equal(computerUse.computer_use_observation_ref, "observation-one");
  assert.equal(computerUse.workflow_graph_id, "workflow-one");
  assert.equal(computerUse.workflow_node_id, "node-one");
  assert.deepEqual(computerUse.workflow_node_ids, ["node-one"]);
  assert.equal(computerUse.tool_ref, "computer_use.observe");
  assert.deepEqual(computerUse.authority_scopes, ["computer_use.read"]);
  assert.equal(computerUse.fail_closed_when_unavailable, true);
  assert.equal(computerUse.redaction, "computer_use_trace_safe");
  for (const key of retiredPayloadKeys) {
    assert.equal(Object.hasOwn(computerUse, key), false);
  }
  assert.equal(computerUse.workflow_node_ids.includes("retired-node"), false);
  assert.equal(computerUse.authority_scopes.includes("retired.scope"), false);
  for (const key of retiredComputerUseSummaryAliasKeys) {
    assert.equal(Object.hasOwn(computerUse, key), false);
  }

  const memory = runtime.payloadSummaryForRunEvent({
    id: "event-two",
    type: "memory_update",
    runId: "run-one",
    agentId: "agent-one",
    data: {
      event_kind: "MemoryPolicy.Canonical",
      eventKind: "RetiredMemoryEventKind",
      operation: "policy_update",
      object: "ioi.agent_memory_policy",
      id: "policy-one",
      memory_record_id: "memory-one",
      memoryRecordId: "retired-memory",
      memory_policy_id: "policy-one",
      memoryPolicyId: "retired-policy",
      inherited_record_ids: ["memory-one", "memory-two"],
      write_allowed: false,
      write_block_reason: "approval_required",
      workflow_node_id: "memory.node",
      workflowNodeId: "retired.memory.node",
    },
  });

  assert.equal(memory.event_kind, "MemoryPolicy.Canonical");
  assert.equal(memory.memory_operation, "policy_update");
  assert.equal(memory.memory_record_id, "memory-one");
  assert.equal(memory.memory_policy_id, "policy-one");
  assert.equal(memory.workflow_node_id, "memory.node");
  assert.equal(memory.inherited_memory_count, 2);
  assert.equal(memory.write_allowed, false);
  assert.equal(memory.write_block_reason, "approval_required");
  assert.notEqual(memory.event_kind, "RetiredMemoryEventKind");
  assert.notEqual(memory.memory_record_id, "retired-memory");
  assert.notEqual(memory.memory_policy_id, "retired-policy");
  assert.notEqual(memory.workflow_node_id, "retired.memory.node");
  for (const key of retiredMemorySummaryAliasKeys) {
    assert.equal(Object.hasOwn(memory, key), false);
  }
});

test("runtime event payloads consume canonical diagnostics injection and blocking gate fields", () => {
  const runtime = helpers();

  const injected = runtime.payloadSummaryForRunEvent({
    id: "event-one",
    type: "lsp_diagnostics_injected",
    runId: "run-one",
    agentId: "agent-one",
    data: {
      injection_id: "injection-one",
      diagnostic_status: "findings",
      diagnostic_count: 3,
      injected_finding_count: 2,
      omitted_finding_count: 1,
      diagnostic_event_ids: ["diag-one"],
      rollback_refs: ["rollback-one"],
      workspace_snapshot_refs: ["snapshot-one"],
      source_tool_call_ids: ["tool-call-one"],
      findings: [{ message: "broken" }],
    },
  });

  assert.equal(injected.event_kind, "LspDiagnosticsInjected");
  assert.equal(injected.injection_id, "injection-one");
  assert.equal(injected.diagnostic_count, 3);
  assert.equal(injected.injected_finding_count, 2);
  assert.deepEqual(injected.rollback_refs, ["rollback-one"]);
  assert.deepEqual(injected.workspace_snapshot_refs, ["snapshot-one"]);
  assert.deepEqual(injected.source_tool_call_ids, ["tool-call-one"]);
  assert.equal(injected.workflow_node_id, "runtime.lsp-diagnostics.inject");
  assert.equal(injected.redaction, "lsp_diagnostics_safe");

  const blocked = runtime.payloadSummaryForRunEvent({
    id: "event-two",
    type: "policy_blocked",
    runId: "run-one",
    agentId: "agent-one",
    data: {
      gate_id: "gate-one",
      policy_decision_id: "policy-one",
      policy_decision_refs: ["policy-one", "policy-two"],
      reason: "post_edit_diagnostics_findings",
      requires_input: true,
      recommended_next_actions: ["repair_retry"],
      repair_decisions: [{ action: "repair_retry" }],
    },
  });

  assert.equal(blocked.event_kind, "PolicyBlocked");
  assert.equal(blocked.gate_id, "gate-one");
  assert.deepEqual(blocked.policy_decision_refs, ["policy-one", "policy-two"]);
  assert.equal(blocked.requires_input, true);
  assert.deepEqual(blocked.recommended_next_actions, ["repair_retry"]);
  assert.deepEqual(blocked.repair_decisions, [{ action: "repair_retry" }]);
});

test("runtime event payloads preserve repository and runtime record summaries", () => {
  const runtime = helpers();

  const repo = runtime.payloadSummaryForRunEvent({
    id: "event-one",
    type: "repository_context",
    runId: "run-one",
    agentId: "agent-one",
    data: {
      event_kind: "RepositoryContext.Canonical",
      eventKind: "RetiredRepositoryContext",
      context_id: "repo-context-one",
      contextId: "retired-repo-context",
      is_git_repository: true,
      isGitRepository: false,
      repo_root_hash: "repo-root-hash",
      repoRootHash: "retired-repo-root-hash",
      branch: "main",
      detached_head: false,
      detachedHead: true,
      head_short_sha: "abc123",
      headShortSha: "retired-head",
      remote_count: 2,
      remoteCount: 99,
      status: {
        is_dirty: true,
        isDirty: false,
        counts: { staged: 1, unstaged: 2, untracked: 3 },
      },
      mutation_executed: false,
      mutationExecuted: true,
      workflow_node_id: "runtime.repository-context",
      workflowNodeId: "retired.repository-context",
      redaction: { profile: "repository_context_safe" },
    },
  });

  assert.equal(repo.event_kind, "RepositoryContext.Canonical");
  assert.equal(repo.context_id, "repo-context-one");
  assert.equal(repo.is_git_repository, true);
  assert.equal(repo.repo_root_hash, "repo-root-hash");
  assert.equal(repo.detached_head, false);
  assert.equal(repo.head_short_sha, "abc123");
  assert.equal(repo.remote_count, 2);
  assert.equal(repo.is_dirty, true);
  assert.equal(repo.staged_count, 1);
  assert.equal(repo.unstaged_count, 2);
  assert.equal(repo.untracked_count, 3);
  assert.equal(repo.mutation_executed, false);
  assert.equal(repo.workflow_node_id, "runtime.repository-context");
  assert.notEqual(repo.context_id, "retired-repo-context");
  assert.notEqual(repo.repo_root_hash, "retired-repo-root-hash");
  assert.notEqual(repo.head_short_sha, "retired-head");
  assert.notEqual(repo.remote_count, 99);
  assert.notEqual(repo.workflow_node_id, "retired.repository-context");
  for (const key of retiredRepositoryContextSummaryAliasKeys) {
    assert.equal(Object.hasOwn(repo, key), false);
  }

  const branchPolicy = runtime.payloadSummaryForRunEvent({
    id: "event-branch-policy",
    type: "branch_policy",
    runId: "run-one",
    agentId: "agent-one",
    data: {
      event_kind: "BranchPolicyDecision.Canonical",
      eventKind: "RetiredBranchPolicyDecision",
      policy_id: "policy-one",
      policyId: "retired-policy",
      repository_context_id: "repo-context-one",
      repositoryContextId: "retired-repo-context",
      status: "warning",
      branch: "feature/canonical",
      default_branch: "main",
      defaultBranch: "retired-main",
      protected_branch: false,
      protectedBranch: true,
      detached_head: false,
      detachedHead: true,
      dirty: true,
      upstream: "origin/main",
      ahead: 1,
      behind: 2,
      blockers: ["missing_head"],
      warnings: ["dirty_worktree", "untracked_files"],
      mutation_allowed: false,
      mutationAllowed: true,
      pr_creation_allowed: false,
      prCreationAllowed: true,
      review_required: true,
      reviewRequired: false,
      mutation_executed: false,
      mutationExecuted: true,
      workflow_node_id: "runtime.branch-policy",
      workflowNodeId: "retired.branch-policy",
      redaction: { profile: "branch_policy_safe" },
    },
  });

  assert.equal(branchPolicy.event_kind, "BranchPolicyDecision.Canonical");
  assert.equal(branchPolicy.policy_id, "policy-one");
  assert.equal(branchPolicy.repository_context_id, "repo-context-one");
  assert.equal(branchPolicy.default_branch, "main");
  assert.equal(branchPolicy.protected_branch, false);
  assert.equal(branchPolicy.detached_head, false);
  assert.equal(branchPolicy.blocker_count, 1);
  assert.equal(branchPolicy.warning_count, 2);
  assert.equal(branchPolicy.mutation_allowed, false);
  assert.equal(branchPolicy.pr_creation_allowed, false);
  assert.equal(branchPolicy.review_required, true);
  assert.equal(branchPolicy.mutation_executed, false);
  assert.equal(branchPolicy.workflow_node_id, "runtime.branch-policy");
  assert.notEqual(branchPolicy.policy_id, "retired-policy");
  assert.notEqual(branchPolicy.workflow_node_id, "retired.branch-policy");
  for (const key of retiredBranchPolicySummaryAliasKeys) {
    assert.equal(Object.hasOwn(branchPolicy, key), false);
  }

  const github = runtime.payloadSummaryForRunEvent({
    id: "event-github-context",
    type: "github_context",
    runId: "run-one",
    agentId: "agent-one",
    data: {
      event_kind: "GitHubContext.Canonical",
      eventKind: "RetiredGitHubContext",
      context_id: "github-context-one",
      contextId: "retired-github-context",
      repository_context_id: "repo-context-one",
      repositoryContextId: "retired-repo-context",
      branch_policy_id: "policy-one",
      branchPolicyId: "retired-policy",
      status: "available",
      github_remote_present: true,
      githubRemotePresent: false,
      default_remote_name: "origin",
      defaultRemoteName: "retired-origin",
      owner: "ioi-foundation",
      repo: "ioi",
      repo_full_name: "ioi-foundation/ioi",
      repoFullName: "retired/repo",
      branch: "feature/canonical",
      default_branch: "main",
      defaultBranch: "retired-main",
      branch_policy_status: "warning",
      branchPolicyStatus: "retired-warning",
      credentials: {
        token_available: true,
        tokenAvailable: false,
      },
      pr_creation_eligible: true,
      prCreationEligible: false,
      network_lookup_performed: false,
      networkLookupPerformed: true,
      mutation_executed: false,
      mutationExecuted: true,
      workflow_node_id: "runtime.github-context",
      workflowNodeId: "retired.github-context",
      redaction: { profile: "github_context_safe" },
    },
  });

  assert.equal(github.event_kind, "GitHubContext.Canonical");
  assert.equal(github.context_id, "github-context-one");
  assert.equal(github.repository_context_id, "repo-context-one");
  assert.equal(github.branch_policy_id, "policy-one");
  assert.equal(github.github_remote_present, true);
  assert.equal(github.default_remote_name, "origin");
  assert.equal(github.repo_full_name, "ioi-foundation/ioi");
  assert.equal(github.default_branch, "main");
  assert.equal(github.branch_policy_status, "warning");
  assert.equal(github.token_available, true);
  assert.equal(github.pr_creation_eligible, true);
  assert.equal(github.network_lookup_performed, false);
  assert.equal(github.mutation_executed, false);
  assert.equal(github.workflow_node_id, "runtime.github-context");
  assert.notEqual(github.context_id, "retired-github-context");
  assert.notEqual(github.repo_full_name, "retired/repo");
  assert.notEqual(github.workflow_node_id, "retired.github-context");
  for (const key of retiredGithubContextSummaryAliasKeys) {
    assert.equal(Object.hasOwn(github, key), false);
  }

  const issue = runtime.payloadSummaryForRunEvent({
    id: "event-issue-context",
    type: "issue_context",
    runId: "run-one",
    agentId: "agent-one",
    data: {
      event_kind: "IssueContext.Canonical",
      eventKind: "RetiredIssueContext",
      context_id: "issue-context-one",
      contextId: "retired-issue-context",
      repository_context_id: "repo-context-one",
      repositoryContextId: "retired-repo-context",
      github_context_id: "github-context-one",
      githubContextId: "retired-github-context",
      pr_attempt_id: "pr-attempt-one",
      prAttemptId: "retired-pr-attempt",
      review_gate_id: "review-gate-one",
      reviewGateId: "retired-review-gate",
      status: "bound",
      repo_full_name: "ioi-foundation/ioi",
      repoFullName: "retired/repo",
      bound: true,
      issue_provided: true,
      issueProvided: false,
      issue_number: 42,
      issueNumber: 404,
      source_kind: "github_issue",
      sourceKind: "retired_source",
      warnings: ["needs_triage"],
      network_lookup_performed: false,
      networkLookupPerformed: true,
      mutation_executed: false,
      mutationExecuted: true,
      workflow_node_id: "runtime.issue-context",
      workflowNodeId: "retired.issue-context",
      redaction: { profile: "issue_context_safe" },
    },
  });

  assert.equal(issue.event_kind, "IssueContext.Canonical");
  assert.equal(issue.context_id, "issue-context-one");
  assert.equal(issue.repository_context_id, "repo-context-one");
  assert.equal(issue.github_context_id, "github-context-one");
  assert.equal(issue.pr_attempt_id, "pr-attempt-one");
  assert.equal(issue.review_gate_id, "review-gate-one");
  assert.equal(issue.repo_full_name, "ioi-foundation/ioi");
  assert.equal(issue.issue_provided, true);
  assert.equal(issue.issue_number, 42);
  assert.equal(issue.source_kind, "github_issue");
  assert.equal(issue.warning_count, 1);
  assert.equal(issue.network_lookup_performed, false);
  assert.equal(issue.mutation_executed, false);
  assert.equal(issue.workflow_node_id, "runtime.issue-context");
  assert.notEqual(issue.context_id, "retired-issue-context");
  assert.notEqual(issue.issue_number, 404);
  assert.notEqual(issue.workflow_node_id, "retired.issue-context");
  for (const key of retiredIssueContextSummaryAliasKeys) {
    assert.equal(Object.hasOwn(issue, key), false);
  }

  const prAttempt = runtime.payloadSummaryForRunEvent({
    id: "event-pr-attempt",
    type: "pr_attempt",
    runId: "run-one",
    agentId: "agent-one",
    data: {
      event_kind: "PrAttemptRecord.Canonical",
      eventKind: "RetiredPrAttemptRecord",
      attempt_id: "pr-attempt-one",
      attemptId: "retired-pr-attempt",
      repository_context_id: "repo-context-one",
      repositoryContextId: "retired-repo-context",
      branch_policy_id: "branch-policy-one",
      branchPolicyId: "retired-branch-policy",
      github_context_id: "github-context-one",
      githubContextId: "retired-github-context",
      status: "blocked",
      outcome: "failed_precondition",
      repo_full_name: "ioi-foundation/ioi",
      repoFullName: "retired/repo",
      branch: "feature/substrate",
      default_branch: "main",
      defaultBranch: "retired-main",
      head_short_sha: "abc1234",
      headShortSha: "fffffff",
      blockers: ["missing_authority_scope:github.pr.create"],
      warnings: ["pr_attempt_preview_only"],
      authority: {
        required_scopes: ["github.pr.create"],
        requiredScopes: ["retired.scope"],
        missing_scopes: ["github.pr.create"],
        missingScopes: ["retired.scope"],
        scope_granted: false,
        scopeGranted: true,
      },
      branch_artifact: {
        artifact_name: "pr-branch.json",
      },
      branchArtifact: {
        artifactName: "retired-branch.json",
      },
      diff_artifact: {
        artifact_name: "pr-diff.patch",
        diff_hash: "diff-hash-one",
        file_count: 2,
      },
      diffArtifact: {
        artifactName: "retired-diff.patch",
        diffHash: "retired-diff-hash",
        fileCount: 404,
      },
      mutation_attempted: false,
      mutationAttempted: true,
      mutation_executed: false,
      mutationExecuted: true,
      network_lookup_performed: false,
      networkLookupPerformed: true,
      workflow_node_id: "runtime.pr-attempt",
      workflowNodeId: "retired.pr-attempt",
      redaction: { profile: "pr_attempt_safe" },
    },
  });

  assert.equal(prAttempt.event_kind, "PrAttemptRecord.Canonical");
  assert.equal(prAttempt.attempt_id, "pr-attempt-one");
  assert.equal(prAttempt.repository_context_id, "repo-context-one");
  assert.equal(prAttempt.branch_policy_id, "branch-policy-one");
  assert.equal(prAttempt.github_context_id, "github-context-one");
  assert.equal(prAttempt.repo_full_name, "ioi-foundation/ioi");
  assert.equal(prAttempt.default_branch, "main");
  assert.equal(prAttempt.head_short_sha, "abc1234");
  assert.deepEqual(prAttempt.required_authority_scopes, ["github.pr.create"]);
  assert.deepEqual(prAttempt.missing_authority_scopes, ["github.pr.create"]);
  assert.equal(prAttempt.authority_scope_granted, false);
  assert.equal(prAttempt.branch_artifact_name, "pr-branch.json");
  assert.equal(prAttempt.diff_artifact_name, "pr-diff.patch");
  assert.equal(prAttempt.diff_hash, "diff-hash-one");
  assert.equal(prAttempt.diff_file_count, 2);
  assert.equal(prAttempt.mutation_attempted, false);
  assert.equal(prAttempt.mutation_executed, false);
  assert.equal(prAttempt.network_lookup_performed, false);
  assert.equal(prAttempt.workflow_node_id, "runtime.pr-attempt");
  assert.notEqual(prAttempt.attempt_id, "retired-pr-attempt");
  assert.notEqual(prAttempt.diff_hash, "retired-diff-hash");
  assert.notEqual(prAttempt.workflow_node_id, "retired.pr-attempt");
  for (const key of retiredPrAttemptSummaryAliasKeys) {
    assert.equal(Object.hasOwn(prAttempt, key), false);
  }

  const task = runtime.payloadSummaryForRunEvent({
    id: "event-two",
    type: "runtime_task",
    runId: "run-one",
    agentId: "agent-one",
    data: {
      event_kind: "RuntimeTaskRecord.Canonical",
      eventKind: "RetiredRuntimeTaskRecord",
      task_id: "task-one",
      taskId: "retired-task",
      run_id: "run-one",
      runId: "retired-run",
      agent_id: "agent-one",
      agentId: "retired-agent",
      thread_id: "thread-one",
      threadId: "retired-thread",
      turn_id: "turn-one",
      turnId: "retired-turn",
      status: "running",
      task_family: "coding",
      taskFamily: "retired-family",
      selected_strategy: "agent",
      selectedStrategy: "retired-strategy",
      durable: true,
      replayable: true,
      prompt_included: false,
      promptIncluded: true,
      workflow_node_id: "runtime.runtime-task",
      workflowNodeId: "retired.runtime-task",
    },
  });

  assert.equal(task.event_kind, "RuntimeTaskRecord.Canonical");
  assert.equal(task.task_id, "task-one");
  assert.equal(task.run_id, "run-one");
  assert.equal(task.agent_id, "agent-one");
  assert.equal(task.thread_id, "thread-one");
  assert.equal(task.turn_id, "turn-one");
  assert.equal(task.task_family, "coding");
  assert.equal(task.selected_strategy, "agent");
  assert.equal(task.durable, true);
  assert.equal(task.replayable, true);
  assert.equal(task.prompt_included, false);
  assert.equal(task.workflow_node_id, "runtime.runtime-task");
  assert.notEqual(task.task_id, "retired-task");
  assert.notEqual(task.workflow_node_id, "retired.runtime-task");
  for (const key of retiredRuntimeTaskSummaryAliasKeys) {
    assert.equal(Object.hasOwn(task, key), false);
  }

  const checklist = runtime.payloadSummaryForRunEvent({
    id: "event-three",
    type: "runtime_checklist",
    runId: "run-one",
    agentId: "agent-one",
    data: {
      event_kind: "RuntimeChecklistRecord.Canonical",
      eventKind: "RetiredRuntimeChecklistRecord",
      checklist_id: "checklist-one",
      checklistId: "retired-checklist",
      task_id: "task-one",
      taskId: "retired-task",
      job_id: "job-one",
      jobId: "retired-job",
      run_id: "run-one",
      runId: "retired-run",
      status: "completed",
      item_count: 4,
      itemCount: 99,
      completed_item_count: 3,
      completedItemCount: 88,
      failed_item_count: 1,
      failedItemCount: 77,
      canceled_item_count: 0,
      canceledItemCount: 66,
      blocked_item_count: 0,
      blockedItemCount: 55,
      required_item_ids: ["item-one"],
      requiredItemIds: ["retired-item"],
      durable: true,
      replayable: true,
      workflow_node_id: "runtime.runtime-checklist",
      workflowNodeId: "retired.runtime-checklist",
    },
  });

  assert.equal(checklist.event_kind, "RuntimeChecklistRecord.Canonical");
  assert.equal(checklist.checklist_id, "checklist-one");
  assert.equal(checklist.task_id, "task-one");
  assert.equal(checklist.job_id, "job-one");
  assert.equal(checklist.item_count, 4);
  assert.equal(checklist.completed_item_count, 3);
  assert.equal(checklist.failed_item_count, 1);
  assert.deepEqual(checklist.required_item_ids, ["item-one"]);
  assert.notDeepEqual(checklist.required_item_ids, ["retired-item"]);
  assert.equal(checklist.workflow_node_id, "runtime.runtime-checklist");
  for (const key of retiredRuntimeChecklistSummaryAliasKeys) {
    assert.equal(Object.hasOwn(checklist, key), false);
  }

  const job = runtime.payloadSummaryForRunEvent({
    id: "event-four",
    type: "job_completed",
    runId: "run-one",
    agentId: "agent-one",
    data: {
      event_kind: "JobCompleted.Canonical",
      eventKind: "RetiredJobCompleted",
      job_id: "job-one",
      jobId: "retired-job",
      task_id: "task-one",
      taskId: "retired-task",
      run_id: "run-one",
      runId: "retired-run",
      agent_id: "agent-one",
      agentId: "retired-agent",
      thread_id: "thread-one",
      threadId: "retired-thread",
      turn_id: "turn-one",
      turnId: "retired-turn",
      status: "completed",
      lifecycle_status: "completed",
      lifecycleStatus: "retired-completed",
      queue_name: "local-agentgres",
      queueName: "retired-queue",
      runner: "local-daemon-agentgres",
      job_type: "agent_run",
      jobType: "retired-job-type",
      queued_at: "2026-06-06T00:00:00.000Z",
      queuedAt: "retired-queued",
      started_at: "2026-06-06T00:00:01.000Z",
      startedAt: "retired-started",
      completed_at: "2026-06-06T00:00:02.000Z",
      completedAt: "retired-completed-at",
      progress: { percent: 100 },
      workflow_node_id: "runtime.runtime-job",
      workflowNodeId: "retired.runtime-job",
    },
  });

  assert.equal(job.event_kind, "JobCompleted.Canonical");
  assert.equal(job.job_id, "job-one");
  assert.equal(job.lifecycle_status, "completed");
  assert.equal(job.queue_name, "local-agentgres");
  assert.equal(job.job_type, "agent_run");
  assert.equal(job.queued_at, "2026-06-06T00:00:00.000Z");
  assert.equal(job.progress_percent, 100);
  assert.equal(job.workflow_node_id, "runtime.runtime-job");
  assert.notEqual(job.job_id, "retired-job");
  assert.notEqual(job.lifecycle_status, "retired-completed");
  assert.notEqual(job.workflow_node_id, "retired.runtime-job");
  for (const key of retiredRuntimeJobSummaryAliasKeys) {
    assert.equal(Object.hasOwn(job, key), false);
  }
});

test("runtime event payloads preserve usage and model route summaries", () => {
  const runtime = helpers();

  const usage = runtime.payloadSummaryForRunEvent({
    id: "event-one",
    type: "usage_delta",
    runId: "run-one",
    agentId: "agent-one",
    data: {
      stage: "completion_streamed",
      total_tokens: 42,
      input_tokens: 30,
      output_tokens: 12,
      context_pressure: 0.4,
      workflow_node_id: "runtime.usage-telemetry",
    },
  });

  assert.equal(usage.event_kind, "RuntimeUsageTelemetry.Delta");
  assert.equal(usage.schema_version, "usage.delta.v1");
  assert.equal(usage.stage, "completion_streamed");
  assert.equal(usage.total_tokens, 42);
  assert.equal(usage.context_pressure, 0.4);
  assert.equal(usage.redaction, "usage_telemetry_safe");
  assert.equal(Object.hasOwn(usage, "eventKind"), false);

  const legacyUsage = runtime.payloadSummaryForRunEvent({
    id: "event-legacy-usage",
    type: "usage_delta",
    runId: "run-one",
    agentId: "agent-one",
    data: legacyDataFor(retiredUsageSummaryReaderAliasKeys),
  });

  assert.equal(legacyUsage.event_kind, "RuntimeUsageTelemetry.Delta");
  assert.equal(legacyUsage.schema_version, "usage.delta.v1");
  assert.equal(legacyUsage.run_id, null);
  assert.equal(legacyUsage.total_tokens, 0);
  assert.equal(legacyUsage.context_pressure, 0);
  assert.equal(legacyUsage.workflow_node_id, "runtime.usage-telemetry");

  const contextDelta = runtime.payloadSummaryForRunEvent({
    id: "event-context-delta",
    type: "context_pressure_delta",
    runId: "run-one",
    agentId: "agent-one",
    data: {
      usage_total_tokens: 42,
      usage_context_pressure: 0.4,
    },
  });

  assert.equal(contextDelta.event_kind, "RuntimeContextPressure.Delta");
  assert.equal(contextDelta.schema_version, "context.delta.v1");
  assert.equal(contextDelta.usage_total_tokens, 42);
  assert.equal(Object.hasOwn(contextDelta, "eventKind"), false);

  const legacyContextDelta = runtime.payloadSummaryForRunEvent({
    id: "event-legacy-context-delta",
    type: "context_pressure_delta",
    runId: "run-one",
    agentId: "agent-one",
    data: legacyDataFor(retiredContextPressureDeltaSummaryReaderAliasKeys),
  });

  assert.equal(legacyContextDelta.event_kind, "RuntimeContextPressure.Delta");
  assert.equal(legacyContextDelta.schema_version, "context.delta.v1");
  assert.equal(legacyContextDelta.run_id, null);
  assert.equal(legacyContextDelta.usage_total_tokens, 0);
  assert.equal(legacyContextDelta.usage_context_pressure, 0);
  assert.equal(legacyContextDelta.workflow_node_id, "runtime.context-budget");

  const alert = runtime.payloadSummaryForRunEvent({
    id: "event-two",
    type: "context_pressure_alert",
    runId: "run-one",
    agentId: "agent-one",
    data: {
      alert_id: "alert-one",
      alert_level: "warning",
      actions: ["compact"],
    },
  });

  assert.equal(alert.schema_version, "context.alert.v1");
  assert.equal(alert.alert_id, "alert-one");
  assert.deepEqual(alert.actions, ["compact"]);
  assert.equal(Object.hasOwn(alert, "eventKind"), false);

  const legacyAlert = runtime.payloadSummaryForRunEvent({
    id: "event-legacy-alert",
    type: "context_pressure_alert",
    runId: "run-one",
    agentId: "agent-one",
    data: legacyDataFor(retiredContextPressureAlertSummaryReaderAliasKeys),
  });

  assert.equal(legacyAlert.event_kind, "RuntimeContextPressure.Alert");
  assert.equal(legacyAlert.schema_version, "context.alert.v1");
  assert.equal(legacyAlert.alert_id, null);
  assert.equal(legacyAlert.pressure_status, null);
  assert.equal(legacyAlert.recommended_action, null);
  assert.equal(legacyAlert.workflow_node_id, "runtime.context-pressure-alert");

  const usageFinal = runtime.payloadSummaryForRunEvent({
    id: "event-usage-final",
    type: "usage_final",
    runId: "run-one",
    agentId: "agent-one",
    data: {
      total_tokens: 42,
      input_tokens: 30,
      output_tokens: 12,
    },
  });

  assert.equal(usageFinal.event_kind, "RuntimeUsageTelemetry");
  assert.equal(usageFinal.schema_version, "usage.final.v1");
  assert.equal(usageFinal.total_tokens, 42);
  assert.equal(Object.hasOwn(usageFinal, "eventKind"), false);

  const legacyUsageFinal = runtime.payloadSummaryForRunEvent({
    id: "event-legacy-usage-final",
    type: "usage_final",
    runId: "run-one",
    agentId: "agent-one",
    data: legacyDataFor(retiredUsageFinalSummaryReaderAliasKeys),
  });

  assert.equal(legacyUsageFinal.event_kind, "RuntimeUsageTelemetry");
  assert.equal(legacyUsageFinal.schema_version, "usage.final.v1");
  assert.equal(legacyUsageFinal.thread_id, null);
  assert.equal(legacyUsageFinal.total_tokens, 0);
  assert.equal(legacyUsageFinal.context_pressure, null);
  assert.equal(legacyUsageFinal.workflow_node_id, "runtime.usage-telemetry");

  const route = runtime.payloadSummaryForRunEvent({
    id: "event-three",
    type: "model_route_decision",
    runId: "run-one",
    agentId: "agent-one",
    data: {
      decision_id: "decision-one",
      route_id: "route.local-first",
      requested_model: "qwen",
      selected_model: "qwen",
      provider_kind: "llama.cpp",
      fallback_triggered: true,
    },
  });

  assert.equal(route.event_kind, "ModelRouteDecision");
  assert.equal(route.model_route_decision_id, "decision-one");
  assert.equal(route.route_id, "route.local-first");
  assert.equal(route.provider_kind, "llama.cpp");
  assert.equal(route.fallback_triggered, true);
  for (const key of retiredPayloadKeys) {
    assert.equal(Object.hasOwn(route, key), false);
  }

  const legacyRoute = runtime.payloadSummaryForRunEvent({
    id: "event-legacy-route",
    type: "model_route_decision",
    runId: "run-one",
    agentId: "agent-one",
    data: {
      eventKind: "LegacyModelRouteDecision",
      decisionId: "decision-legacy",
      routeId: "route.legacy",
      requestedModel: "legacy-model",
      selectedModel: "legacy-selected",
      providerKind: "legacy-provider",
      fallbackTriggered: true,
    },
  });

  assert.equal(legacyRoute.event_kind, "ModelRouteDecision");
  assert.equal(legacyRoute.model_route_decision_id, null);
  assert.equal(legacyRoute.route_id, null);
  assert.equal(legacyRoute.provider_kind, null);
  assert.equal(legacyRoute.fallback_triggered, false);
});

import assert from "node:assert/strict";
import { test } from "node:test";

import {
  branchPolicyProjection,
  githubContextProjection,
  githubPrCreatePlanProjection,
  issueContextProjection,
  prAttemptsProjection,
  repositoryContextProjection,
  repositoryListProjection,
  reviewGateProjection,
} from "./repository-projections.mjs";

function deps(calls = []) {
  return {
    branchPolicyForRepositoryContext({ repositoryContext, policyId }) {
      calls.push({ fn: "branchPolicyForRepositoryContext", policyId });
      return { policyId, status: "passed", repositoryContextId: repositoryContext.contextId };
    },
    doctorHash(value) {
      assert.equal(typeof value, "string");
      return "abcdef1234567890";
    },
    githubContextForRepository({ repositoryContext, branchPolicy, contextId }) {
      calls.push({ fn: "githubContextForRepository", contextId });
      return {
        contextId,
        status: "available",
        githubRemotePresent: true,
        repoFullName: "ioi/example",
        repositoryContextId: repositoryContext.contextId,
        branchPolicyId: branchPolicy.policyId,
      };
    },
    githubPrCreatePlanForReviewGate(input) {
      calls.push({ fn: "githubPrCreatePlanForReviewGate", planId: input.planId });
      return { planId: input.planId, prAttemptId: input.prAttempt.attemptId, reviewGateId: input.reviewGate.gateId, issueContextId: input.issueContext.contextId };
    },
    issueContextForGithub(input) {
      calls.push({ fn: "issueContextForGithub", contextId: input.contextId });
      return { contextId: input.contextId, prAttemptId: input.prAttempt.attemptId, reviewGateId: input.reviewGate.gateId };
    },
    prAttemptForRepository(input) {
      calls.push({ fn: "prAttemptForRepository", attemptId: input.attemptId });
      return { attemptId: input.attemptId, status: "ready" };
    },
    repositoryContextForWorkspace({ cwd, contextId }) {
      calls.push({ fn: "repositoryContextForWorkspace", contextId });
      return {
        contextId,
        isGitRepository: true,
        repoRoot: cwd,
        branch: "feature/refactor",
        headSha: "abc123",
        upstream: "origin/feature/refactor",
        remoteCount: 1,
        remotes: [{ name: "origin", urlHash: "remote_hash" }],
        status: { isDirty: false, counts: { modified: 0 } },
        redaction: { remoteCredentialsIncluded: false },
      };
    },
    reviewGateForPrAttempt(input) {
      calls.push({ fn: "reviewGateForPrAttempt", gateId: input.gateId });
      return { gateId: input.gateId, prAttemptId: input.prAttempt.attemptId, status: "passed" };
    },
  };
}

test("repository projections use stable ids and preserve repository list shape", () => {
  const calls = [];
  const context = repositoryContextProjection({ cwd: "/workspace" }, deps(calls));
  assert.equal(context.contextId, "repoctx_abcdef123456");

  const repositories = repositoryListProjection({ cwd: "/workspace" }, deps([]));
  assert.deepEqual(repositories, [
    {
      url: "/workspace",
      source: "local_git",
      status: "available",
      contextId: "repoctx_abcdef123456",
      repoRoot: "/workspace",
      branch: "feature/refactor",
      headSha: "abc123",
      upstream: "origin/feature/refactor",
      remoteCount: 1,
      remotes: [{ name: "origin", urlHash: "remote_hash" }],
      isDirty: false,
      dirtyCounts: { modified: 0 },
      redaction: { remoteCredentialsIncluded: false },
    },
  ]);
});

test("repository projections compose branch and github contexts", () => {
  const calls = [];
  const branchPolicy = branchPolicyProjection({ cwd: "/workspace" }, deps(calls));
  const githubContext = githubContextProjection({ cwd: "/workspace" }, deps(calls));

  assert.equal(branchPolicy.policyId, "branch_policy_abcdef123456");
  assert.equal(githubContext.contextId, "github_context_abcdef123456");
  assert.deepEqual(calls.map((call) => call.fn), [
    "repositoryContextForWorkspace",
    "branchPolicyForRepositoryContext",
    "repositoryContextForWorkspace",
    "branchPolicyForRepositoryContext",
    "githubContextForRepository",
  ]);
});

test("repository projections compose PR, issue, review, and create-plan records", () => {
  assert.deepEqual(prAttemptsProjection({ cwd: "/workspace" }, deps([])), [
    { attemptId: "pr_attempt_abcdef123456", status: "ready" },
  ]);
  assert.deepEqual(reviewGateProjection({ cwd: "/workspace" }, deps([])), {
    gateId: "review_gate_abcdef123456",
    prAttemptId: "pr_attempt_abcdef123456",
    status: "passed",
  });
  assert.deepEqual(issueContextProjection({ cwd: "/workspace" }, deps([])), {
    contextId: "issue_context_abcdef123456",
    prAttemptId: "pr_attempt_abcdef123456",
    reviewGateId: "review_gate_abcdef123456",
  });
  assert.deepEqual(githubPrCreatePlanProjection({ cwd: "/workspace" }, deps([])), {
    planId: "github_pr_create_plan_abcdef123456",
    prAttemptId: "pr_attempt_abcdef123456",
    reviewGateId: "review_gate_abcdef123456",
    issueContextId: "issue_context_abcdef123456",
  });
});

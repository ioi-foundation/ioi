import assert from "node:assert/strict";
import test from "node:test";

import { createRuntimeRepositorySurface } from "./runtime-repository-surface.mjs";

function helper(name) {
  return (...args) => ({ name, args });
}

test("runtime repository surface delegates public projections with store cwd", () => {
  const calls = [];
  const projection = (name) => (input, deps) => {
    calls.push({ name, input, depKeys: Object.keys(deps).sort() });
    return { name, cwd: input.cwd };
  };
  const workflowCalls = [];
  const surface = createRuntimeRepositorySurface({
    branchPolicyForRepositoryContext: helper("branchPolicyForRepositoryContext"),
    branchPolicyProjection: projection("branchPolicy"),
    createRepositoryWorkflowProjections(deps) {
      workflowCalls.push(Object.keys(deps).sort());
      return {
        githubPrCreatePlanForReviewGate: helper("githubPrCreatePlanForReviewGate"),
        issueContextForGithub: helper("issueContextForGithub"),
        prAttemptForRepository: helper("prAttemptForRepository"),
        reviewGateForPrAttempt: helper("reviewGateForPrAttempt"),
      };
    },
    doctorHash: helper("doctorHash"),
    githubContextForRepository: helper("githubContextForRepository"),
    githubContextProjection: projection("githubContext"),
    githubPrCreatePlanProjection: projection("githubPrCreatePlan"),
    issueContextProjection: projection("issueContext"),
    prAttemptsProjection: projection("prAttempts"),
    repositoryContextForWorkspace: helper("repositoryContextForWorkspace"),
    repositoryContextProjection: projection("repositoryContext"),
    repositoryListProjection: projection("listRepositories"),
    reviewGateProjection: projection("reviewGate"),
  });
  const store = { defaultCwd: "/workspace/project" };

  assert.equal(surface.listRepositories(store).cwd, "/workspace/project");
  assert.equal(surface.repositoryContext(store).cwd, "/workspace/project");
  assert.equal(surface.branchPolicy(store).cwd, "/workspace/project");
  assert.equal(surface.githubContext(store).cwd, "/workspace/project");
  assert.equal(surface.prAttempts(store).cwd, "/workspace/project");
  assert.equal(surface.issueContext(store).cwd, "/workspace/project");
  assert.equal(surface.reviewGate(store).cwd, "/workspace/project");
  assert.equal(surface.githubPrCreatePlan(store).cwd, "/workspace/project");

  assert.deepEqual(calls.map((call) => call.name), [
    "listRepositories",
    "repositoryContext",
    "branchPolicy",
    "githubContext",
    "prAttempts",
    "issueContext",
    "reviewGate",
    "githubPrCreatePlan",
  ]);
  assert.deepEqual(Object.fromEntries(calls.map((call) => [call.name, call.depKeys])), {
    listRepositories: ["doctorHash", "repositoryContextForWorkspace"],
    repositoryContext: ["doctorHash", "repositoryContextForWorkspace"],
    branchPolicy: [
      "branchPolicyForRepositoryContext",
      "doctorHash",
      "repositoryContextForWorkspace",
    ],
    githubContext: [
      "branchPolicyForRepositoryContext",
      "doctorHash",
      "githubContextForRepository",
      "repositoryContextForWorkspace",
    ],
    prAttempts: [
      "branchPolicyForRepositoryContext",
      "doctorHash",
      "githubContextForRepository",
      "prAttemptForRepository",
      "repositoryContextForWorkspace",
    ],
    issueContext: [
      "branchPolicyForRepositoryContext",
      "doctorHash",
      "githubContextForRepository",
      "issueContextForGithub",
      "prAttemptForRepository",
      "repositoryContextForWorkspace",
      "reviewGateForPrAttempt",
    ],
    reviewGate: [
      "branchPolicyForRepositoryContext",
      "doctorHash",
      "githubContextForRepository",
      "prAttemptForRepository",
      "repositoryContextForWorkspace",
      "reviewGateForPrAttempt",
    ],
    githubPrCreatePlan: [
      "branchPolicyForRepositoryContext",
      "doctorHash",
      "githubContextForRepository",
      "githubPrCreatePlanForReviewGate",
      "issueContextForGithub",
      "prAttemptForRepository",
      "repositoryContextForWorkspace",
      "reviewGateForPrAttempt",
    ],
  });
  assert.deepEqual(workflowCalls, [
    [
      "branchPolicyForRepositoryContext",
      "doctorHash",
      "emptyToNull",
      "gitOutput",
      "githubContextForRepository",
      "normalizeArray",
      "repositoryContextForWorkspace",
      "uniqueStrings",
    ],
  ]);
});

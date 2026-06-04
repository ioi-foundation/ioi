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
import {
  branchPolicyForRepositoryContext,
  emptyToNull,
  githubContextForRepository,
  gitOutput,
  repositoryContextForWorkspace,
} from "./repository-context.mjs";
import { createRepositoryWorkflowProjections } from "./repository-workflow-projections.mjs";
import {
  doctorHash,
  normalizeArray,
  uniqueStrings,
} from "./runtime-value-helpers.mjs";

export function createRuntimeRepositorySurface({
  branchPolicyForRepositoryContext: branchPolicyForRepositoryContextDep = branchPolicyForRepositoryContext,
  branchPolicyProjection: branchPolicyProjectionDep = branchPolicyProjection,
  createRepositoryWorkflowProjections: createRepositoryWorkflowProjectionsDep = createRepositoryWorkflowProjections,
  doctorHash: doctorHashDep = doctorHash,
  emptyToNull: emptyToNullDep = emptyToNull,
  githubContextForRepository: githubContextForRepositoryDep = githubContextForRepository,
  githubContextProjection: githubContextProjectionDep = githubContextProjection,
  githubPrCreatePlanProjection: githubPrCreatePlanProjectionDep = githubPrCreatePlanProjection,
  issueContextProjection: issueContextProjectionDep = issueContextProjection,
  gitOutput: gitOutputDep = gitOutput,
  normalizeArray: normalizeArrayDep = normalizeArray,
  prAttemptsProjection: prAttemptsProjectionDep = prAttemptsProjection,
  repositoryContextForWorkspace: repositoryContextForWorkspaceDep = repositoryContextForWorkspace,
  repositoryContextProjection: repositoryContextProjectionDep = repositoryContextProjection,
  repositoryListProjection: repositoryListProjectionDep = repositoryListProjection,
  reviewGateProjection: reviewGateProjectionDep = reviewGateProjection,
  uniqueStrings: uniqueStringsDep = uniqueStrings,
} = {}) {
  const workflowProjections = createRepositoryWorkflowProjectionsDep({
    branchPolicyForRepositoryContext: branchPolicyForRepositoryContextDep,
    doctorHash: doctorHashDep,
    emptyToNull: emptyToNullDep,
    githubContextForRepository: githubContextForRepositoryDep,
    gitOutput: gitOutputDep,
    normalizeArray: normalizeArrayDep,
    repositoryContextForWorkspace: repositoryContextForWorkspaceDep,
    uniqueStrings: uniqueStringsDep,
  });
  const {
    githubPrCreatePlanForReviewGate,
    issueContextForGithub,
    prAttemptForRepository,
    reviewGateForPrAttempt,
  } = workflowProjections;
  const baseDeps = {
    doctorHash: doctorHashDep,
    repositoryContextForWorkspace: repositoryContextForWorkspaceDep,
  };
  const branchDeps = {
    ...baseDeps,
    branchPolicyForRepositoryContext: branchPolicyForRepositoryContextDep,
  };
  const githubDeps = {
    ...branchDeps,
    githubContextForRepository: githubContextForRepositoryDep,
  };
  const prDeps = {
    ...githubDeps,
    prAttemptForRepository,
  };
  const reviewDeps = {
    ...prDeps,
    reviewGateForPrAttempt,
  };
  return {
    listRepositories(store) {
      return repositoryListProjectionDep({ cwd: store.defaultCwd }, baseDeps);
    },
    repositoryContext(store) {
      return repositoryContextProjectionDep({ cwd: store.defaultCwd }, baseDeps);
    },
    branchPolicy(store) {
      return branchPolicyProjectionDep({ cwd: store.defaultCwd }, branchDeps);
    },
    githubContext(store) {
      return githubContextProjectionDep({ cwd: store.defaultCwd }, githubDeps);
    },
    prAttempts(store) {
      return prAttemptsProjectionDep({ cwd: store.defaultCwd }, prDeps);
    },
    issueContext(store) {
      return issueContextProjectionDep({ cwd: store.defaultCwd }, {
        ...reviewDeps,
        issueContextForGithub,
      });
    },
    reviewGate(store) {
      return reviewGateProjectionDep({ cwd: store.defaultCwd }, reviewDeps);
    },
    githubPrCreatePlan(store) {
      return githubPrCreatePlanProjectionDep({ cwd: store.defaultCwd }, {
        ...reviewDeps,
        githubPrCreatePlanForReviewGate,
        issueContextForGithub,
      });
    },
  };
}

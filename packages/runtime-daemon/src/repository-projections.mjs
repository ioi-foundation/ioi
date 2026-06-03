export function repositoryContextId(cwd, deps = {}) {
  const { doctorHash } = deps;
  return `repoctx_${doctorHash(cwd).slice(0, 12)}`;
}

export function branchPolicyId(cwd, deps = {}) {
  const { doctorHash } = deps;
  return `branch_policy_${doctorHash(cwd).slice(0, 12)}`;
}

export function githubContextId(cwd, deps = {}) {
  const { doctorHash } = deps;
  return `github_context_${doctorHash(cwd).slice(0, 12)}`;
}

export function prAttemptId(cwd, deps = {}) {
  const { doctorHash } = deps;
  return `pr_attempt_${doctorHash(cwd).slice(0, 12)}`;
}

export function reviewGateId(cwd, deps = {}) {
  const { doctorHash } = deps;
  return `review_gate_${doctorHash(cwd).slice(0, 12)}`;
}

export function issueContextId(cwd, deps = {}) {
  const { doctorHash } = deps;
  return `issue_context_${doctorHash(cwd).slice(0, 12)}`;
}

export function githubPrCreatePlanId(cwd, deps = {}) {
  const { doctorHash } = deps;
  return `github_pr_create_plan_${doctorHash(cwd).slice(0, 12)}`;
}

export function repositoryContextProjection({ cwd }, deps = {}) {
  const {
    doctorHash,
    repositoryContextForWorkspace,
  } = deps;
  return repositoryContextForWorkspace({
    cwd,
    contextId: repositoryContextId(cwd, { doctorHash }),
  });
}

export function repositoryListProjection({ cwd }, deps = {}) {
  const context = repositoryContextProjection({ cwd }, deps);
  return [
    {
      url: cwd,
      source: context.isGitRepository ? "local_git" : "local_workspace",
      status: context.isGitRepository ? "available" : "not_a_git_repository",
      contextId: context.contextId,
      repoRoot: context.repoRoot,
      branch: context.branch,
      headSha: context.headSha,
      upstream: context.upstream,
      remoteCount: context.remoteCount,
      remotes: context.remotes,
      isDirty: context.status.isDirty,
      dirtyCounts: context.status.counts,
      redaction: context.redaction,
    },
  ];
}

export function branchPolicyProjection({ cwd }, deps = {}) {
  const {
    branchPolicyForRepositoryContext,
    doctorHash,
  } = deps;
  const repositoryContext = repositoryContextProjection({ cwd }, deps);
  return branchPolicyForRepositoryContext({
    repositoryContext,
    policyId: branchPolicyId(cwd, { doctorHash }),
  });
}

export function githubContextProjection({ cwd }, deps = {}) {
  const {
    branchPolicyForRepositoryContext,
    doctorHash,
    githubContextForRepository,
  } = deps;
  const repositoryContext = repositoryContextProjection({ cwd }, deps);
  const branchPolicy = branchPolicyForRepositoryContext({
    repositoryContext,
    policyId: branchPolicyId(cwd, { doctorHash }),
  });
  return githubContextForRepository({
    repositoryContext,
    branchPolicy,
    contextId: githubContextId(cwd, { doctorHash }),
  });
}

export function prAttemptsProjection({ cwd }, deps = {}) {
  const {
    branchPolicyForRepositoryContext,
    doctorHash,
    githubContextForRepository,
    prAttemptForRepository,
  } = deps;
  const repositoryContext = repositoryContextProjection({ cwd }, deps);
  const branchPolicy = branchPolicyForRepositoryContext({
    repositoryContext,
    policyId: branchPolicyId(cwd, { doctorHash }),
  });
  const githubContext = githubContextForRepository({
    repositoryContext,
    branchPolicy,
    contextId: githubContextId(cwd, { doctorHash }),
  });
  return [
    prAttemptForRepository({
      repositoryContext,
      branchPolicy,
      githubContext,
      attemptId: prAttemptId(cwd, { doctorHash }),
    }),
  ];
}

export function issueContextProjection({ cwd }, deps = {}) {
  const {
    branchPolicyForRepositoryContext,
    doctorHash,
    githubContextForRepository,
    issueContextForGithub,
    prAttemptForRepository,
    reviewGateForPrAttempt,
  } = deps;
  const repositoryContext = repositoryContextProjection({ cwd }, deps);
  const branchPolicy = branchPolicyForRepositoryContext({
    repositoryContext,
    policyId: branchPolicyId(cwd, { doctorHash }),
  });
  const githubContext = githubContextForRepository({
    repositoryContext,
    branchPolicy,
    contextId: githubContextId(cwd, { doctorHash }),
  });
  const prAttempt = prAttemptForRepository({
    repositoryContext,
    branchPolicy,
    githubContext,
    attemptId: prAttemptId(cwd, { doctorHash }),
  });
  const reviewGate = reviewGateForPrAttempt({
    repositoryContext,
    branchPolicy,
    githubContext,
    prAttempt,
    gateId: reviewGateId(cwd, { doctorHash }),
  });
  return issueContextForGithub({
    repositoryContext,
    githubContext,
    prAttempt,
    reviewGate,
    contextId: issueContextId(cwd, { doctorHash }),
  });
}

export function reviewGateProjection({ cwd }, deps = {}) {
  const {
    branchPolicyForRepositoryContext,
    doctorHash,
    githubContextForRepository,
    prAttemptForRepository,
    reviewGateForPrAttempt,
  } = deps;
  const repositoryContext = repositoryContextProjection({ cwd }, deps);
  const branchPolicy = branchPolicyForRepositoryContext({
    repositoryContext,
    policyId: branchPolicyId(cwd, { doctorHash }),
  });
  const githubContext = githubContextForRepository({
    repositoryContext,
    branchPolicy,
    contextId: githubContextId(cwd, { doctorHash }),
  });
  const prAttempt = prAttemptForRepository({
    repositoryContext,
    branchPolicy,
    githubContext,
    attemptId: prAttemptId(cwd, { doctorHash }),
  });
  return reviewGateForPrAttempt({
    repositoryContext,
    branchPolicy,
    githubContext,
    prAttempt,
    gateId: reviewGateId(cwd, { doctorHash }),
  });
}

export function githubPrCreatePlanProjection({ cwd }, deps = {}) {
  const {
    branchPolicyForRepositoryContext,
    doctorHash,
    githubContextForRepository,
    githubPrCreatePlanForReviewGate,
    issueContextForGithub,
    prAttemptForRepository,
    reviewGateForPrAttempt,
  } = deps;
  const repositoryContext = repositoryContextProjection({ cwd }, deps);
  const branchPolicy = branchPolicyForRepositoryContext({
    repositoryContext,
    policyId: branchPolicyId(cwd, { doctorHash }),
  });
  const githubContext = githubContextForRepository({
    repositoryContext,
    branchPolicy,
    contextId: githubContextId(cwd, { doctorHash }),
  });
  const prAttempt = prAttemptForRepository({
    repositoryContext,
    branchPolicy,
    githubContext,
    attemptId: prAttemptId(cwd, { doctorHash }),
  });
  const reviewGate = reviewGateForPrAttempt({
    repositoryContext,
    branchPolicy,
    githubContext,
    prAttempt,
    gateId: reviewGateId(cwd, { doctorHash }),
  });
  const issueContext = issueContextForGithub({
    repositoryContext,
    githubContext,
    prAttempt,
    reviewGate,
    contextId: issueContextId(cwd, { doctorHash }),
  });
  return githubPrCreatePlanForReviewGate({
    repositoryContext,
    branchPolicy,
    githubContext,
    issueContext,
    prAttempt,
    reviewGate,
    planId: githubPrCreatePlanId(cwd, { doctorHash }),
  });
}

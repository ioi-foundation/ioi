export function createRepositoryWorkflowProjections(deps = {}) {
  const {
    branchPolicyForRepositoryContext,
    doctorHash,
    emptyToNull,
    githubContextForRepository,
    gitOutput,
    normalizeArray,
    repositoryContextForWorkspace,
    uniqueStrings,
  } = deps;

  function issueContextForGithub({
    runId,
    contextId,
    repositoryContext,
    githubContext,
    prAttempt,
    reviewGate,
    issue,
    generatedAt,
  } = {}) {
    const context = repositoryContext ?? repositoryContextForWorkspace({});
    const github = githubContext ?? githubContextForRepository({ repositoryContext: context });
    const issueNumber = normalizeIssueNumber(issue?.number ?? issue?.issueNumber);
    const title = emptyToNull(issue?.title);
    const sourceUrl = emptyToNull(issue?.url ?? issue?.sourceUrl);
    const bound = Boolean(issueNumber || title || sourceUrl);
    const status = !github.githubRemotePresent ? "unavailable" : bound ? "bound" : "unbound";
    const warnings = uniqueStrings([
      ...(!bound ? ["issue_context_unbound"] : []),
      ...(!github.githubRemotePresent ? ["missing_github_remote"] : []),
    ]);
    const id = contextId ?? (runId ? `issue_context_${runId}` : `issue_context_${doctorHash(github.contextId ?? context.contextId ?? "workspace").slice(0, 12)}`);
    return {
      schemaVersion: "ioi.agent-runtime.issue-context.v1",
      object: "ioi.issue_context",
      contextId: id,
      runId: runId ?? null,
      generatedAt: generatedAt ?? new Date().toISOString(),
      repositoryContextId: context.contextId ?? null,
      githubContextId: github.contextId ?? null,
      prAttemptId: prAttempt?.attemptId ?? null,
      reviewGateId: reviewGate?.gateId ?? null,
      status,
      summary: issueContextSummary({ status, repoFullName: github.repoFullName, issueNumber, title }),
      readOnly: true,
      provider: "github",
      repoFullName: github.repoFullName ?? null,
      htmlUrl: github.htmlUrl ?? null,
      bound,
      issueProvided: bound,
      issueNumber,
      title,
      sourceUrl,
      sourceKind: bound ? "github_issue" : "unbound",
      labels: normalizeArray(issue?.labels),
      assignees: [],
      blockers: [],
      warnings,
      noIssuePolicy: {
        allowed: true,
        reason: "Issue context is optional for local PR previews until a task source is supplied.",
      },
      networkLookupPerformed: false,
      mutationExecuted: false,
      redaction: {
        profile: "issue_context_safe",
        tokenValueIncluded: false,
        remoteCredentialsIncluded: false,
        networkResponseIncluded: false,
        bodyIncluded: false,
        reviewerIdentityIncluded: false,
      },
      evidenceRefs: [
        "issue_context",
        "IssueContextNode",
        "github.issue_context.read_only",
        context.contextId,
        github.contextId,
        prAttempt?.attemptId,
        reviewGate?.gateId,
      ].filter(Boolean),
    };
  }

  function issueContextSummary({ status, repoFullName, issueNumber, title }) {
    const target = repoFullName ?? "unknown GitHub repository";
    if (status === "bound") {
      const issueRef = issueNumber ? `#${issueNumber}` : title ?? "provided issue";
      return `Issue context ${issueRef} is bound for ${target} without network reads.`;
    }
    if (status === "unavailable") return "Issue context is unavailable because no GitHub remote was detected.";
    return `No issue is bound for ${target}; PR workflow may continue with an unbound issue context.`;
  }

  function normalizeIssueNumber(value) {
    const number = Number(value);
    return Number.isInteger(number) && number > 0 ? number : null;
  }

  function prAttemptForRepository({
    runId,
    attemptId,
    repositoryContext,
    branchPolicy,
    githubContext,
    generatedAt,
    prompt,
  } = {}) {
    const context = repositoryContext ?? repositoryContextForWorkspace({});
    const policy = branchPolicy ?? branchPolicyForRepositoryContext({ repositoryContext: context });
    const github = githubContext ?? githubContextForRepository({ repositoryContext: context, branchPolicy: policy });
    const diffArtifact = prDiffArtifactForRepository(context);
    const branchArtifact = prBranchArtifactForRepository({ repositoryContext: context, branchPolicy: policy, githubContext: github });
    const missingAuthorityScopes = ["github.pr.create"];
    const branchPolicyBlockers = normalizeArray(policy.blockers);
    const githubPreconditions = github.prCreationPreconditions ?? {};
    const blockers = uniqueStrings([
      ...branchPolicyBlockers,
      ...(!context.isGitRepository ? ["not_git_repository"] : []),
      ...(!github.githubRemotePresent ? ["missing_github_remote"] : []),
      ...(!githubPreconditions.tokenAvailable ? ["missing_github_token"] : []),
      ...(!githubPreconditions.branchPolicyAllowsPr ? ["branch_policy_not_passed"] : []),
      ...missingAuthorityScopes.map((scope) => `missing_authority_scope:${scope}`),
    ]);
    const warnings = uniqueStrings([
      ...normalizeArray(policy.warnings),
      ...normalizeArray(github.branchPolicyWarnings),
      "pr_attempt_preview_only",
    ]);
    const status = blockers.length > 0 ? "blocked" : "ready";
    const outcome = blockers.length > 0 ? "failed_precondition" : "preview_ready";
    const id = attemptId ?? (runId ? `pr_attempt_${runId}` : `pr_attempt_${doctorHash(context.contextId ?? "workspace").slice(0, 12)}`);
    const record = {
      schemaVersion: "ioi.agent-runtime.pr-attempt.v1",
      object: "ioi.pr_attempt",
      attemptId: id,
      runId: runId ?? null,
      generatedAt: generatedAt ?? new Date().toISOString(),
      repositoryContextId: context.contextId ?? null,
      branchPolicyId: policy.policyId ?? null,
      githubContextId: github.contextId ?? null,
      status,
      outcome,
      summary: prAttemptSummary({ status, outcome, repoFullName: github.repoFullName, blockers }),
      previewOnly: true,
      readOnly: true,
      provider: "github",
      action: "pr_create",
      title: prompt ? `Draft PR for: ${String(prompt).slice(0, 96)}` : null,
      bodyIncluded: false,
      repoFullName: github.repoFullName ?? null,
      htmlUrl: github.htmlUrl ?? null,
      branch: context.branch ?? null,
      defaultBranch: context.defaultBranch ?? null,
      headSha: context.headSha ?? null,
      headShortSha: context.headShortSha ?? null,
      upstream: context.upstream ?? null,
      dirty: Boolean(context.status?.isDirty),
      counts: context.status?.counts ?? {},
      blockers,
      warnings,
      failure: blockers.length
        ? {
            reason: blockers[0],
            message: "PR creation was not attempted because preview preconditions or authority requirements were not satisfied.",
          }
        : null,
      authority: {
        requiredScopes: ["github.pr.create"],
        grantedScopes: [],
        missingScopes: missingAuthorityScopes,
        scopeGranted: false,
        approvalRequired: true,
        approvalSatisfied: false,
      },
      preconditions: {
        gitRepositoryPresent: Boolean(context.isGitRepository),
        githubRemotePresent: Boolean(github.githubRemotePresent),
        branchPolicyAllowsPr: Boolean(githubPreconditions.branchPolicyAllowsPr),
        tokenAvailable: Boolean(githubPreconditions.tokenAvailable),
        authorityScopeGranted: false,
        diffCaptured: true,
        branchArtifactAttached: true,
        diffArtifactAttached: true,
        networkLookupPerformed: false,
        mutationExecuted: false,
      },
      mutationAttempted: false,
      mutationExecuted: false,
      networkLookupPerformed: false,
      prNumber: null,
      prUrl: null,
      branchArtifact: prArtifactMetadata(branchArtifact),
      diffArtifact: prArtifactMetadata(diffArtifact),
      artifacts: [
        { name: "pr-attempt.json", mediaType: "application/json" },
        prArtifactMetadata(branchArtifact),
        prArtifactMetadata(diffArtifact),
      ],
      redaction: {
        profile: "pr_attempt_safe",
        tokenValueIncluded: false,
        remoteCredentialsIncluded: false,
        networkResponseIncluded: false,
        diffContentInProjection: false,
      },
      evidenceRefs: [
        "pr_attempt",
        "pr_attempt_preview_only",
        "PrAttemptNode",
        context.contextId,
        policy.policyId,
        github.contextId,
        branchArtifact.artifactName,
        diffArtifact.artifactName,
      ].filter(Boolean),
    };
    Object.defineProperty(record, "artifactContents", {
      enumerable: false,
      value: {
        branch: branchArtifact.content,
        diff: diffArtifact.content,
      },
    });
    return record;
  }

  function prAttemptSummary({ status, outcome, repoFullName, blockers }) {
    const target = repoFullName ?? "unknown GitHub repository";
    if (status === "blocked") {
      return `PR attempt for ${target} recorded as ${outcome}; blockers: ${normalizeArray(blockers).join(", ")}.`;
    }
    return `PR attempt for ${target} recorded as preview-ready; mutation remains disabled.`;
  }

  function prBranchArtifactForRepository({ repositoryContext, branchPolicy, githubContext }) {
    const value = {
      schemaVersion: "ioi.agent-runtime.pr-branch-artifact.v1",
      object: "ioi.pr_branch_artifact",
      repositoryContextId: repositoryContext.contextId ?? null,
      branchPolicyId: branchPolicy.policyId ?? null,
      githubContextId: githubContext.contextId ?? null,
      repoFullName: githubContext.repoFullName ?? null,
      branch: repositoryContext.branch ?? null,
      defaultBranch: repositoryContext.defaultBranch ?? null,
      headSha: repositoryContext.headSha ?? null,
      headShortSha: repositoryContext.headShortSha ?? null,
      upstream: repositoryContext.upstream ?? null,
      dirty: Boolean(repositoryContext.status?.isDirty),
      counts: repositoryContext.status?.counts ?? {},
      branchPolicyStatus: branchPolicy.status ?? null,
      redaction: {
        profile: "pr_branch_artifact_safe",
        statusPathsIncluded: false,
        remoteCredentialsIncluded: false,
      },
    };
    return {
      artifactName: "pr-branch.json",
      mediaType: "application/json",
      artifactHash: doctorHash(JSON.stringify(value)),
      content: value,
    };
  }

  function prDiffArtifactForRepository(repositoryContext) {
    const rawPatch = repositoryContext.isGitRepository && repositoryContext.repoRoot
      ? gitOutput(repositoryContext.repoRoot, ["diff", "--no-ext-diff", "--binary", "HEAD", "--"]) ?? ""
      : "";
    const maxBytes = 512 * 1024;
    const rawBytes = Buffer.byteLength(rawPatch, "utf8");
    const truncated = rawBytes > maxBytes;
    const retainedPatch = truncated
      ? `${rawPatch.slice(0, maxBytes)}\n\n[ioi pr diff truncated: ${rawBytes - maxBytes} byte(s) omitted]\n`
      : rawPatch;
    return {
      artifactName: "pr-diff.patch",
      mediaType: "text/x-diff",
      artifactHash: doctorHash(rawPatch),
      diffHash: doctorHash(rawPatch),
      byteLength: rawBytes,
      retainedByteLength: Buffer.byteLength(retainedPatch, "utf8"),
      truncated,
      fileCount: prDiffFileCount(rawPatch),
      hasDiff: rawPatch.length > 0,
      untrackedCount: repositoryContext.status?.counts?.untracked ?? 0,
      content: retainedPatch,
    };
  }

  function prArtifactMetadata(artifactProjection) {
    const { content: _content, ...metadata } = artifactProjection;
    return metadata;
  }

  function prDiffFileCount(patch) {
    return String(patch).split(/\r?\n/).filter((line) => line.startsWith("diff --git ")).length;
  }

  function reviewGateForPrAttempt({
    runId,
    gateId,
    repositoryContext,
    branchPolicy,
    githubContext,
    prAttempt,
    generatedAt,
  } = {}) {
    const context = repositoryContext ?? repositoryContextForWorkspace({});
    const policy = branchPolicy ?? branchPolicyForRepositoryContext({ repositoryContext: context });
    const github = githubContext ?? githubContextForRepository({ repositoryContext: context, branchPolicy: policy });
    const attempt = prAttempt ?? prAttemptForRepository({ repositoryContext: context, branchPolicy: policy, githubContext: github });
    const requiredReviewers = ["code-owner"];
    const requiredChecks = [
      "branch_policy_passed",
      "github_context_available",
      "pr_attempt_ready",
      "diff_artifact_attached",
      "human_review_satisfied",
    ];
    const prAttemptReady = attempt.status === "ready";
    const reviewSatisfied = false;
    const blockers = uniqueStrings([
      ...normalizeArray(attempt.blockers),
      ...(policy.status !== "passed" ? ["branch_policy_not_passed"] : []),
      ...(github.status !== "available" ? ["github_context_not_available"] : []),
      ...(!prAttemptReady ? ["pr_attempt_not_ready"] : []),
      ...(!reviewSatisfied ? ["review_not_satisfied"] : []),
    ]);
    const warnings = uniqueStrings([
      ...normalizeArray(policy.warnings),
      ...normalizeArray(attempt.warnings),
      "review_gate_preview_only",
    ]);
    const status = blockers.length > 0 ? "blocked" : "passed";
    const decision = status;
    const id = gateId ?? (runId ? `review_gate_${runId}` : `review_gate_${doctorHash(attempt.attemptId ?? context.contextId ?? "workspace").slice(0, 12)}`);
    return {
      schemaVersion: "ioi.agent-runtime.review-gate.v1",
      object: "ioi.review_gate_decision",
      gateId: id,
      runId: runId ?? null,
      generatedAt: generatedAt ?? new Date().toISOString(),
      repositoryContextId: context.contextId ?? null,
      branchPolicyId: policy.policyId ?? null,
      githubContextId: github.contextId ?? null,
      prAttemptId: attempt.attemptId ?? null,
      status,
      decision,
      summary: reviewGateSummary({ status, repoFullName: github.repoFullName, blockers }),
      readOnly: true,
      previewOnly: true,
      reviewRequired: true,
      approvalRequired: true,
      reviewSatisfied,
      approvalSatisfied: false,
      mutationAllowed: false,
      prCreationAllowed: false,
      mutationExecuted: false,
      networkLookupPerformed: false,
      provider: "github",
      repoFullName: github.repoFullName ?? null,
      branch: context.branch ?? null,
      defaultBranch: context.defaultBranch ?? null,
      prAttemptStatus: attempt.status ?? null,
      prAttemptOutcome: attempt.outcome ?? null,
      requiredReviewers,
      satisfiedReviewers: [],
      requiredChecks,
      passedChecks: [],
      blockers,
      warnings,
      authority: {
        requiredScopes: ["github.pr.create"],
        grantedScopes: [],
        missingScopes: ["github.pr.create"],
        scopeGranted: false,
        approvalRequired: true,
        approvalSatisfied: false,
      },
      preconditions: {
        repositoryContextPresent: Boolean(context.contextId),
        branchPolicyPassed: policy.status === "passed",
        githubContextAvailable: github.status === "available",
        prAttemptPresent: Boolean(attempt.attemptId),
        prAttemptReady,
        diffArtifactAttached: Boolean(attempt.diffArtifact?.artifactName),
        branchArtifactAttached: Boolean(attempt.branchArtifact?.artifactName),
        reviewPolicySatisfied: reviewSatisfied,
        networkLookupPerformed: false,
        mutationExecuted: false,
      },
      redaction: {
        profile: "review_gate_safe",
        reviewerIdentityIncluded: false,
        tokenValueIncluded: false,
        networkResponseIncluded: false,
      },
      evidenceRefs: [
        "review_gate",
        "review_gate_preview_only",
        "ReviewGateNode",
        context.contextId,
        policy.policyId,
        github.contextId,
        attempt.attemptId,
      ].filter(Boolean),
    };
  }

  function reviewGateSummary({ status, repoFullName, blockers }) {
    const target = repoFullName ?? "unknown GitHub repository";
    if (status === "passed") {
      return `Review gate passed for ${target}; PR creation may proceed to authority checks.`;
    }
    return `Review gate blocked PR creation for ${target}: ${normalizeArray(blockers).join(", ")}.`;
  }

  function githubPrCreatePlanForReviewGate({
    runId,
    planId,
    repositoryContext,
    branchPolicy,
    githubContext,
    issueContext,
    prAttempt,
    reviewGate,
    generatedAt,
  } = {}) {
    const context = repositoryContext ?? repositoryContextForWorkspace({});
    const policy = branchPolicy ?? branchPolicyForRepositoryContext({ repositoryContext: context });
    const github = githubContext ?? githubContextForRepository({ repositoryContext: context, branchPolicy: policy });
    const attempt = prAttempt ?? prAttemptForRepository({ repositoryContext: context, branchPolicy: policy, githubContext: github });
    const gate = reviewGate ?? reviewGateForPrAttempt({ repositoryContext: context, branchPolicy: policy, githubContext: github, prAttempt: attempt });
    const issue = issueContext ?? issueContextForGithub({ repositoryContext: context, githubContext: github, prAttempt: attempt, reviewGate: gate });
    const title = attempt.title ?? `Draft PR for ${context.branch ?? "working branch"}`;
    const payloadPreview = {
      owner: github.owner ?? null,
      repo: github.repo ?? null,
      base: context.defaultBranch ?? null,
      head: context.branch ?? null,
      title,
      bodyIncluded: false,
      draft: true,
      maintainerCanModify: true,
      issueNumber: issue.issueNumber ?? null,
    };
    const requestPayloadHash = doctorHash(JSON.stringify(payloadPreview));
    const blockers = uniqueStrings([
      ...normalizeArray(gate.blockers),
      ...normalizeArray(attempt.blockers),
      ...(github.status !== "available" ? ["github_context_not_available"] : []),
      ...(policy.status !== "passed" ? ["branch_policy_not_passed"] : []),
      ...(attempt.status !== "ready" ? ["pr_attempt_not_ready"] : []),
      ...(gate.status !== "passed" ? ["review_gate_not_passed"] : []),
      ...(!gate.reviewSatisfied ? ["review_not_satisfied"] : []),
      ...(!github.credentials?.tokenAvailable ? ["missing_github_token"] : []),
      "missing_authority_scope:github.pr.create",
      "dry_run_only",
    ]);
    const warnings = uniqueStrings([
      ...normalizeArray(issue.warnings),
      ...normalizeArray(gate.warnings),
      "github_pr_create_plan_dry_run",
    ]);
    const status = blockers.length > 0 ? "blocked" : "ready";
    const id = planId ?? (runId ? `github_pr_create_plan_${runId}` : `github_pr_create_plan_${doctorHash(gate.gateId ?? attempt.attemptId ?? "workspace").slice(0, 12)}`);
    return {
      schemaVersion: "ioi.agent-runtime.github-pr-create-plan.v1",
      object: "ioi.github_pr_create_plan",
      planId: id,
      runId: runId ?? null,
      generatedAt: generatedAt ?? new Date().toISOString(),
      repositoryContextId: context.contextId ?? null,
      branchPolicyId: policy.policyId ?? null,
      githubContextId: github.contextId ?? null,
      issueContextId: issue.contextId ?? null,
      prAttemptId: attempt.attemptId ?? null,
      reviewGateId: gate.gateId ?? null,
      status,
      decision: status,
      summary: githubPrCreatePlanSummary({ status, repoFullName: github.repoFullName, blockers }),
      dryRun: true,
      previewOnly: true,
      provider: "github",
      toolName: "github__pr_create",
      action: "pr_create",
      repoFullName: github.repoFullName ?? null,
      owner: github.owner ?? null,
      repo: github.repo ?? null,
      baseBranch: context.defaultBranch ?? null,
      headBranch: context.branch ?? null,
      title,
      bodyPlan: {
        included: false,
        source: issue.bound ? "issue_context" : "runtime_template",
        redaction: "body_not_included_in_projection",
      },
      issueNumber: issue.issueNumber ?? null,
      reviewGateStatus: gate.status ?? null,
      reviewSatisfied: Boolean(gate.reviewSatisfied),
      authority: {
        requiredScopes: ["github.pr.create"],
        grantedScopes: [],
        missingScopes: ["github.pr.create"],
        scopeGranted: false,
        approvalRequired: true,
        approvalSatisfied: false,
      },
      request: {
        method: "POST",
        path: github.repoFullName ? `/repos/${github.repoFullName}/pulls` : null,
        payloadHash: requestPayloadHash,
        payloadPreview,
        bodyIncluded: false,
        tokenIncluded: false,
      },
      blockers,
      warnings,
      networkLookupPerformed: false,
      mutationAttempted: false,
      mutationExecuted: false,
      prNumber: null,
      prUrl: null,
      redaction: {
        profile: "github_pr_create_plan_safe",
        tokenValueIncluded: false,
        authorizationHeaderIncluded: false,
        requestBodyIncluded: false,
        responseBodyIncluded: false,
        networkResponseIncluded: false,
      },
      evidenceRefs: [
        "github_pr_create_plan",
        "github.pr_create.request_hash",
        "github.pr_create.authority_scope",
        "github.pr_create.dry_run",
        "GitHubPrCreateNode",
        context.contextId,
        policy.policyId,
        github.contextId,
        issue.contextId,
        attempt.attemptId,
        gate.gateId,
      ].filter(Boolean),
    };
  }

  function githubPrCreatePlanSummary({ status, repoFullName, blockers }) {
    const target = repoFullName ?? "unknown GitHub repository";
    if (status === "ready") {
      return `GitHub PR create dry-run plan is ready for ${target}; mutation remains disabled pending authority approval.`;
    }
    return `GitHub PR create dry-run plan is blocked for ${target}: ${normalizeArray(blockers).join(", ")}.`;
  }

  return {
    githubPrCreatePlanForReviewGate,
    issueContextForGithub,
    prAttemptForRepository,
    reviewGateForPrAttempt,
  };
}

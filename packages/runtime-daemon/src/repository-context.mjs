import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import path from "node:path";

import { WORKSPACE_TRUST_WARNING_SCHEMA_VERSION } from "./runtime-contract-constants.mjs";
import { approvalModeForThreadMode } from "./threads/thread-runtime-controls.mjs";

export function repositoryContextForWorkspace({ cwd, contextId, generatedAt } = {}) {
  const workspaceRoot = path.resolve(cwd ?? process.cwd());
  const rootOutput = gitOutput(workspaceRoot, ["rev-parse", "--show-toplevel"]);
  const baseContext = {
    schemaVersion: "ioi.agent-runtime.repository-context.v1",
    object: "ioi.repository_context",
    contextId: contextId ?? `repoctx_${doctorHash(workspaceRoot).slice(0, 12)}`,
    generatedAt: generatedAt ?? new Date().toISOString(),
    workspaceRoot,
    workspaceRootHash: doctorHash(workspaceRoot),
    provider: "git",
    readOnly: true,
    mutationExecuted: false,
    evidenceRefs: ["repository_context", "repository.context.read_only", "RepositoryContextNode"],
  };
  if (!rootOutput) {
    return {
      ...baseContext,
      status: repositoryStatusProjection("not_a_git_repository"),
      isGitRepository: false,
      repoRoot: null,
      repoRootHash: null,
      workspaceRelativePath: null,
      branch: null,
      detachedHead: false,
      headSha: null,
      headShortSha: null,
      upstream: null,
      remoteCount: 0,
      remotes: [],
      redaction: repositoryContextRedaction(),
    };
  }

  const repoRoot = path.resolve(rootOutput);
  const branchName = emptyToNull(gitOutput(repoRoot, ["branch", "--show-current"]));
  const abbrevRef = emptyToNull(gitOutput(repoRoot, ["rev-parse", "--abbrev-ref", "HEAD"]));
  const detachedHead = !branchName && abbrevRef === "HEAD";
  const headSha = emptyToNull(gitOutput(repoRoot, ["rev-parse", "HEAD"]));
  const upstream = emptyToNull(
    gitOutput(repoRoot, ["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"]),
  );
  const porcelain = gitOutput(repoRoot, ["status", "--porcelain=v1", "--untracked-files=normal"]) ?? "";
  const branchStatus = gitOutput(repoRoot, ["status", "--porcelain=v2", "--branch", "--untracked-files=no"]) ?? "";
  const aheadBehind = repositoryAheadBehind(branchStatus);
  const counts = repositoryStatusCounts(porcelain);
  const remotes = parseGitRemotes(gitOutput(repoRoot, ["remote", "-v"]) ?? "");
  const defaultBranch = repositoryDefaultBranch(repoRoot);
  return {
    ...baseContext,
    status: repositoryStatusProjection("available", counts, aheadBehind, porcelain),
    isGitRepository: true,
    repoRoot,
    repoRootHash: doctorHash(repoRoot),
    workspaceRelativePath: relative(repoRoot, workspaceRoot),
    branch: branchName ?? (detachedHead ? null : abbrevRef),
    defaultBranch,
    detachedHead,
    headSha,
    headShortSha: headSha ? headSha.slice(0, 12) : null,
    upstream,
    remoteCount: remotes.length,
    remotes,
    redaction: repositoryContextRedaction(),
  };
}

export function branchPolicyForRepositoryContext({
  runId,
  policyId,
  repositoryContext,
  generatedAt,
} = {}) {
  const context = repositoryContext ?? repositoryContextForWorkspace({});
  const counts = context.status?.counts ?? repositoryStatusCounts("");
  const protectedBranchNames = uniqueStrings([
    context.defaultBranch,
    "main",
    "master",
    "trunk",
    "production",
    "release",
    "stable",
  ]);
  const branch = context.branch ?? null;
  const protectedBranch = Boolean(branch && protectedBranchNames.includes(branch));
  const blockers = [];
  const warnings = [];
  if (!context.isGitRepository) blockers.push("not_a_git_repository");
  if (!context.headSha && context.isGitRepository) blockers.push("missing_head");
  if (context.detachedHead || !branch) blockers.push("detached_head");
  if ((counts.conflicted ?? 0) > 0) blockers.push("conflicted_worktree");
  if (protectedBranch) blockers.push("protected_branch");
  if (context.status?.isDirty) warnings.push("dirty_worktree");
  if ((counts.untracked ?? 0) > 0) warnings.push("untracked_files");
  if (!context.upstream && context.isGitRepository) warnings.push("missing_upstream");
  if ((context.status?.ahead ?? 0) > 0) warnings.push("ahead_of_upstream");
  if ((context.status?.behind ?? 0) > 0) warnings.push("behind_upstream");

  const status = blockers.length > 0 ? "blocked" : warnings.length > 0 ? "warning" : "passed";
  const mutationAllowed = status === "passed";
  const summary = branchPolicySummary({ status, branch, protectedBranch, blockers, warnings });
  const id = policyId ?? (runId ? `branch_policy_${runId}` : `branch_policy_${doctorHash(context.contextId ?? "workspace").slice(0, 12)}`);
  return {
    schemaVersion: "ioi.agent-runtime.branch-policy.v1",
    object: "ioi.branch_policy_decision",
    policyId: id,
    generatedAt: generatedAt ?? new Date().toISOString(),
    repositoryContextId: context.contextId ?? null,
    status,
    decision: status,
    summary,
    readOnly: true,
    mutationExecuted: false,
    mutationAllowed,
    prCreationAllowed: mutationAllowed,
    reviewRequired: warnings.length > 0 || blockers.length > 0,
    approvalRequired: warnings.length > 0 || blockers.length > 0,
    branch,
    defaultBranch: context.defaultBranch ?? null,
    protectedBranch,
    protectedBranchNames,
    detachedHead: Boolean(context.detachedHead),
    headSha: context.headSha ?? null,
    headShortSha: context.headShortSha ?? null,
    upstream: context.upstream ?? null,
    ahead: context.status?.ahead ?? 0,
    behind: context.status?.behind ?? 0,
    dirty: Boolean(context.status?.isDirty),
    counts,
    blockers: uniqueStrings(blockers),
    warnings: uniqueStrings(warnings),
    recommendedNextAction: branchPolicyRecommendedNextAction({ status, blockers, warnings }),
    redaction: {
      profile: "branch_policy_safe",
      remoteCredentialsIncluded: false,
      statusPathsIncluded: false,
    },
    evidenceRefs: [
      "branch_policy",
      "repository.branch_policy.read_only",
      "BranchPolicyNode",
      context.contextId,
    ].filter(Boolean),
  };
}

export function workspaceTrustWarningRecordForMode({
  agent,
  threadId,
  controls,
  request,
  source,
  requestedBy,
  workflowGraphId,
  workflowNodeId,
  modeWorkflowNodeId,
  modeEvent,
  now,
} = {}) {
  const generatedAt = now ?? new Date().toISOString();
  const workspaceRoot = path.resolve(agent?.cwd ?? process.cwd());
  const repositoryContext = repositoryContextForWorkspace({
    cwd: workspaceRoot,
    contextId: `repoctx_${doctorHash(workspaceRoot).slice(0, 12)}`,
    generatedAt,
  });
  const branchPolicy = branchPolicyForRepositoryContext({
    repositoryContext,
    policyId: `branch_policy_${doctorHash(`${threadId ?? "thread"}:${repositoryContext.contextId}`).slice(0, 12)}`,
    generatedAt,
  });
  const mode = controls?.mode ?? "agent";
  const approvalMode = controls?.approvalMode ?? approvalModeForThreadMode(mode);
  const ignoredUiFields = workspaceTrustIgnoredUiFields(request);
  const modeReasons =
    mode === "yolo"
      ? ["thread_yolo_mode_never_prompts"]
      : ["thread_review_mode_requires_visible_review"];
  const branchReasons = [
    ...normalizeArray(branchPolicy.blockers),
    ...normalizeArray(branchPolicy.warnings),
  ];
  const warningReasons = uniqueStrings([
    ...modeReasons,
    ...branchReasons,
    ...(ignoredUiFields.length ? ["canvas_local_trust_override_ignored"] : []),
  ]);
  const severity =
    mode === "yolo" || branchPolicy.status === "blocked"
      ? "high"
      : branchPolicy.status === "warning"
        ? "medium"
        : "notice";
  const warningId = `workspace_trust_${doctorHash([
    threadId ?? "thread",
    mode,
    approvalMode,
    repositoryContext.workspaceRootHash,
    branchPolicy.status,
    workflowGraphId ?? "",
    workflowNodeId ?? "",
  ].join(":")).slice(0, 16)}`;
  const summary = workspaceTrustWarningSummary({
    mode,
    approvalMode,
    severity,
    branchPolicy,
    ignoredUiFields,
  });
  return {
    schemaVersion: WORKSPACE_TRUST_WARNING_SCHEMA_VERSION,
    schema_version: WORKSPACE_TRUST_WARNING_SCHEMA_VERSION,
    object: "ioi.workspace_trust_warning",
    warningId,
    warning_id: warningId,
    generatedAt,
    generated_at: generatedAt,
    status: "warning",
    severity,
    summary,
    message: summary,
    mode,
    thread_mode: mode,
    approvalMode,
    approval_mode: approvalMode,
    trustProfile: "local_private",
    trust_profile: "local_private",
    daemonTrustSource: "thread_mode_and_read_only_repository_context",
    daemon_trust_source: "thread_mode_and_read_only_repository_context",
    canvasLocalTrustStateAccepted: false,
    canvas_local_trust_state_accepted: false,
    uiOverrideIgnored: ignoredUiFields.length > 0,
    ui_override_ignored: ignoredUiFields.length > 0,
    ignoredUiFields,
    ignored_ui_fields: ignoredUiFields,
    requestedBy,
    requested_by: requestedBy,
    controlSurface: source,
    control_surface: source,
    agentId: agent?.id ?? null,
    agent_id: agent?.id ?? null,
    threadId: threadId ?? null,
    thread_id: threadId ?? null,
    sessionId: agent ? runtimeSessionIdForAgent(agent) : null,
    session_id: agent ? runtimeSessionIdForAgent(agent) : null,
    workflowGraphId: workflowGraphId ?? null,
    workflow_graph_id: workflowGraphId ?? null,
    workflowNodeId: workflowNodeId ?? null,
    workflow_node_id: workflowNodeId ?? null,
    modeWorkflowNodeId: modeWorkflowNodeId ?? null,
    mode_workflow_node_id: modeWorkflowNodeId ?? null,
    sourceModeEventId: modeEvent?.event_id ?? null,
    source_mode_event_id: modeEvent?.event_id ?? null,
    sourceModeSeq: modeEvent?.seq ?? null,
    source_mode_seq: modeEvent?.seq ?? null,
    workspaceRoot,
    workspace_root: workspaceRoot,
    workspaceRootHash: repositoryContext.workspaceRootHash,
    workspace_root_hash: repositoryContext.workspaceRootHash,
    repositoryContextId: repositoryContext.contextId ?? null,
    repository_context_id: repositoryContext.contextId ?? null,
    branchPolicyId: branchPolicy.policyId ?? null,
    branch_policy_id: branchPolicy.policyId ?? null,
    branchPolicyStatus: branchPolicy.status ?? null,
    branch_policy_status: branchPolicy.status ?? null,
    isGitRepository: Boolean(repositoryContext.isGitRepository),
    is_git_repository: Boolean(repositoryContext.isGitRepository),
    branch: repositoryContext.branch ?? null,
    defaultBranch: repositoryContext.defaultBranch ?? null,
    default_branch: repositoryContext.defaultBranch ?? null,
    upstream: repositoryContext.upstream ?? null,
    dirty: Boolean(branchPolicy.dirty),
    counts: branchPolicy.counts ?? {},
    ahead: branchPolicy.ahead ?? 0,
    behind: branchPolicy.behind ?? 0,
    protectedBranch: Boolean(branchPolicy.protectedBranch),
    protected_branch: Boolean(branchPolicy.protectedBranch),
    detachedHead: Boolean(branchPolicy.detachedHead),
    detached_head: Boolean(branchPolicy.detachedHead),
    warningReasons,
    warning_reasons: warningReasons,
    branchPolicyWarnings: normalizeArray(branchPolicy.warnings),
    branch_policy_warnings: normalizeArray(branchPolicy.warnings),
    branchPolicyBlockers: normalizeArray(branchPolicy.blockers),
    branch_policy_blockers: normalizeArray(branchPolicy.blockers),
    recommendedNextAction: branchPolicy.recommendedNextAction,
    recommended_next_action: branchPolicy.recommendedNextAction,
    readOnly: true,
    read_only: true,
    mutationExecuted: false,
    mutation_executed: false,
    evidenceRefs: uniqueStrings([
      "workspace_trust_warning",
      "daemon_owned_workspace_trust",
      "thread_mode_review_yolo_warning",
      "repository_context",
      repositoryContext.contextId,
      branchPolicy.policyId,
    ]),
    evidence_refs: uniqueStrings([
      "workspace_trust_warning",
      "daemon_owned_workspace_trust",
      "thread_mode_review_yolo_warning",
      "repository_context",
      repositoryContext.contextId,
      branchPolicy.policyId,
    ]),
  };
}

export function githubContextForRepository({
  runId,
  contextId,
  repositoryContext,
  branchPolicy,
  generatedAt,
} = {}) {
  const context = repositoryContext ?? repositoryContextForWorkspace({});
  const policy = branchPolicy ?? branchPolicyForRepositoryContext({ repositoryContext: context });
  const githubRemotes = normalizeArray(context.remotes).filter((remote) => remote.provider === "github");
  const defaultRemote =
    githubRemotes.find((remote) => remote.name === "origin") ??
    githubRemotes[0] ??
    null;
  const owner = defaultRemote?.owner ?? null;
  const repo = defaultRemote?.repo ?? null;
  const repoFullName = owner && repo ? `${owner}/${repo}` : null;
  const tokenSources = githubTokenSources();
  const githubRemotePresent = Boolean(defaultRemote && repoFullName);
  const branchPolicyAllowsPr = policy.prCreationAllowed === true;
  const prCreationEligible = githubRemotePresent && branchPolicyAllowsPr && tokenSources.length > 0;
  const status = !githubRemotePresent
    ? "unavailable"
    : policy.status === "blocked"
      ? "blocked"
      : policy.status === "warning"
        ? "warning"
        : "available";
  const id = contextId ?? (runId ? `github_context_${runId}` : `github_context_${doctorHash(context.contextId ?? "workspace").slice(0, 12)}`);
  return {
    schemaVersion: "ioi.agent-runtime.github-context.v1",
    object: "ioi.github_context",
    contextId: id,
    generatedAt: generatedAt ?? new Date().toISOString(),
    repositoryContextId: context.contextId ?? null,
    branchPolicyId: policy.policyId ?? null,
    status,
    summary: githubContextSummary({ status, repoFullName, policy }),
    readOnly: true,
    networkLookupPerformed: false,
    mutationExecuted: false,
    provider: "github",
    githubRemotePresent,
    defaultRemoteName: defaultRemote?.name ?? null,
    owner,
    repo,
    repoFullName,
    htmlUrl: repoFullName ? `https://github.com/${repoFullName}` : null,
    defaultBranch: context.defaultBranch ?? null,
    branch: context.branch ?? null,
    branchPolicyStatus: policy.status ?? null,
    branchPolicyBlockers: normalizeArray(policy.blockers),
    branchPolicyWarnings: normalizeArray(policy.warnings),
    prCreationEligible,
    prCreationPreconditions: {
      githubRemotePresent,
      branchPolicyAllowsPr,
      tokenAvailable: tokenSources.length > 0,
      networkLookupPerformed: false,
      mutationExecuted: false,
    },
    remotes: githubRemotes.map((remote) => ({
      name: remote.name,
      host: remote.host,
      owner: remote.owner,
      repo: remote.repo,
      repoFullName: remote.repoFullName,
      fetchUrl: remote.fetchUrl,
      fetchUrlHash: remote.fetchUrlHash,
      pushUrl: remote.pushUrl,
      pushUrlHash: remote.pushUrlHash,
    })),
    credentials: {
      tokenAvailable: tokenSources.length > 0,
      tokenSources,
      tokenValueIncluded: false,
      authorizationHeaderIncluded: false,
    },
    redaction: {
      profile: "github_context_safe",
      tokenValueIncluded: false,
      remoteCredentialsIncluded: false,
      networkResponseIncluded: false,
    },
    evidenceRefs: [
      "github_context",
      "github.context.read_only",
      "GitHubContextNode",
      context.contextId,
      policy.policyId,
    ].filter(Boolean),
  };
}

export function gitOutput(cwd, args) {
  try {
    return execFileSync("git", ["-C", cwd, ...args], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
      timeout: 1500,
      maxBuffer: 4 * 1024 * 1024,
    }).trimEnd();
  } catch {
    return null;
  }
}

export function emptyToNull(value) {
  const text = typeof value === "string" ? value.trim() : "";
  return text ? text : null;
}

export function repositoryStatusCounts(porcelain) {
  const counts = {
    staged: 0,
    unstaged: 0,
    untracked: 0,
    ignored: 0,
    conflicted: 0,
  };
  for (const line of String(porcelain).split(/\r?\n/).filter(Boolean)) {
    const status = line.slice(0, 2);
    const x = status[0];
    const y = status[1];
    if (status === "??") {
      counts.untracked += 1;
      continue;
    }
    if (status === "!!") {
      counts.ignored += 1;
      continue;
    }
    if (repositoryStatusIsConflict(status)) counts.conflicted += 1;
    if (x && x !== " " && x !== "?" && x !== "!") counts.staged += 1;
    if (y && y !== " " && y !== "?" && y !== "!") counts.unstaged += 1;
  }
  return counts;
}

export function parseGitRemotes(remoteOutput) {
  const byName = new Map();
  for (const line of String(remoteOutput).split(/\r?\n/).filter(Boolean)) {
    const match = line.match(/^(\S+)\s+(.+?)\s+\((fetch|push)\)$/);
    if (!match) continue;
    const [, name, url, kind] = match;
    const metadata = parseRemoteMetadata(url);
    const current = byName.get(name) ?? { name };
    current[`${kind}Url`] = redactRemoteUrl(url);
    current[`${kind}UrlHash`] = doctorHash(url);
    current.provider ??= metadata.provider;
    current.host ??= metadata.host;
    current.owner ??= metadata.owner;
    current.repo ??= metadata.repo;
    current.repoFullName ??= metadata.repoFullName;
    byName.set(name, current);
  }
  return [...byName.values()].sort((left, right) => left.name.localeCompare(right.name));
}

function branchPolicySummary({ status, branch, protectedBranch, blockers, warnings }) {
  if (status === "passed") {
    return `Branch policy passed for ${branch ?? "detached HEAD"}; mutation and PR workflows may proceed.`;
  }
  if (status === "blocked") {
    return `Branch policy blocked ${branch ?? "detached HEAD"}${protectedBranch ? " because it is protected/default" : ""}: ${blockers.join(", ")}.`;
  }
  return `Branch policy warning for ${branch ?? "detached HEAD"}: ${warnings.join(", ")}.`;
}

function branchPolicyRecommendedNextAction({ status, blockers, warnings }) {
  if (status === "passed") return "Proceed to review or PR workflow gates.";
  if (blockers.includes("protected_branch")) {
    return "Create or switch to a feature branch before requesting branch mutation or PR creation.";
  }
  if (blockers.includes("conflicted_worktree")) {
    return "Resolve merge conflicts before requesting branch mutation or PR creation.";
  }
  if (blockers.includes("detached_head")) {
    return "Check out a named feature branch before requesting branch mutation or PR creation.";
  }
  if (warnings.includes("dirty_worktree")) {
    return "Review, stage, or commit local worktree changes before requesting PR creation.";
  }
  if (warnings.includes("missing_upstream")) {
    return "Configure an upstream branch or accept a review gate before PR creation.";
  }
  return "Review branch policy warnings before requesting mutation.";
}

function workspaceTrustIgnoredUiFields(request = {}) {
  const aliases = [
    ["trust_profile", "trustProfile"],
    ["workspace_trust", "workspaceTrust"],
    ["workspace_trust_profile", "workspaceTrustProfile"],
    ["workspace_trust_status", "workspaceTrustStatus"],
    ["workspace_trust_warning", "workspaceTrustWarning"],
    ["workspace_trust_idempotency_key", "workspaceTrustIdempotencyKey"],
    ["workspace_trust_suppressed", "workspaceTrustSuppressed"],
    ["suppress_workspace_trust_warning", "suppressWorkspaceTrustWarning"],
    ["hide_workspace_trust_warning", "hideWorkspaceTrustWarning"],
    ["suppressWarnings", "suppress_warnings"],
    ["hideWarnings", "hide_warnings"],
    ["trusted", "isTrusted"],
  ];
  return aliases
    .filter(([left, right]) => Object.hasOwn(request, left) || Object.hasOwn(request, right))
    .map(([left, right]) => (Object.hasOwn(request, left) ? left : right));
}

function workspaceTrustWarningSummary({
  mode,
  approvalMode,
  severity,
  branchPolicy,
  ignoredUiFields,
} = {}) {
  const modeText =
    mode === "yolo"
      ? "YOLO mode can run without further prompts"
      : "Review mode requires visible operator review";
  const branchText =
    branchPolicy?.status === "passed"
      ? "repository context is clean"
      : `branch policy is ${branchPolicy?.status ?? "unknown"} (${[
          ...normalizeArray(branchPolicy?.blockers),
          ...normalizeArray(branchPolicy?.warnings),
        ].join(", ")})`;
  const overrideText = ignoredUiFields?.length
    ? "; canvas-local trust override fields were ignored"
    : "";
  return `${modeText}; approval=${approvalMode ?? "suggest"}; severity=${severity}; ${branchText}${overrideText}.`;
}

function githubContextSummary({ status, repoFullName, policy }) {
  if (!repoFullName) return "No GitHub remote was detected in repository context.";
  if (status === "blocked") {
    return `GitHub context resolved ${repoFullName}, but branch policy is blocked: ${normalizeArray(policy.blockers).join(", ")}.`;
  }
  if (status === "warning") {
    return `GitHub context resolved ${repoFullName} with branch policy warnings: ${normalizeArray(policy.warnings).join(", ")}.`;
  }
  return `GitHub context resolved ${repoFullName} without network calls.`;
}

function githubTokenSources() {
  return ["GITHUB_TOKEN", "GH_TOKEN"].filter((name) => Boolean(process.env[name]));
}

function repositoryDefaultBranch(repoRoot) {
  const remoteHead = emptyToNull(gitOutput(repoRoot, ["symbolic-ref", "--short", "refs/remotes/origin/HEAD"]));
  if (remoteHead?.startsWith("origin/")) return remoteHead.slice("origin/".length);
  return remoteHead;
}

function repositoryStatusProjection(availability, counts = repositoryStatusCounts(""), aheadBehind = {}, porcelain = "") {
  const isDirty =
    counts.staged > 0 ||
    counts.unstaged > 0 ||
    counts.untracked > 0 ||
    counts.conflicted > 0;
  return {
    availability,
    clean: availability === "available" ? !isDirty : null,
    isDirty,
    counts,
    ahead: aheadBehind.ahead ?? 0,
    behind: aheadBehind.behind ?? 0,
    porcelainHash: porcelain ? doctorHash(porcelain) : null,
    untrackedMode: availability === "available" ? "normal" : "none",
  };
}

function repositoryStatusIsConflict(status) {
  return ["DD", "AU", "UD", "UA", "DU", "AA", "UU"].includes(status);
}

function repositoryAheadBehind(branchStatus) {
  const line = String(branchStatus)
    .split(/\r?\n/)
    .find((item) => item.startsWith("# branch.ab "));
  const match = line?.match(/\+(\d+)\s+-(\d+)/);
  return {
    ahead: match ? Number(match[1]) : 0,
    behind: match ? Number(match[2]) : 0,
  };
}

function parseRemoteMetadata(remoteUrl) {
  const normalized = {
    provider: null,
    host: null,
    owner: null,
    repo: null,
    repoFullName: null,
  };
  const fromParts = (host, remotePath) => {
    const parts = String(remotePath ?? "")
      .replace(/^\/+/, "")
      .replace(/\.git$/, "")
      .split("/")
      .filter(Boolean);
    const owner = parts[0] ?? null;
    const repo = parts[1] ?? null;
    const lowerHost = host ? String(host).toLowerCase() : null;
    return {
      provider: lowerHost === "github.com" ? "github" : null,
      host: lowerHost,
      owner,
      repo,
      repoFullName: owner && repo ? `${owner}/${repo}` : null,
    };
  };
  try {
    const parsed = new URL(remoteUrl);
    return fromParts(parsed.hostname, parsed.pathname);
  } catch {
    const scpLike = String(remoteUrl).match(/^(?:[^@]+@)?([^:]+):(.+)$/);
    if (scpLike) return fromParts(scpLike[1], scpLike[2]);
  }
  return normalized;
}

function redactRemoteUrl(remoteUrl) {
  try {
    const parsed = new URL(remoteUrl);
    parsed.username = "";
    parsed.password = "";
    return parsed.toString();
  } catch {
    return remoteUrl.includes("@")
      ? `redacted:${doctorHash(remoteUrl).slice(0, 12)}`
      : remoteUrl;
  }
}

function repositoryContextRedaction() {
  return {
    profile: "repository_context_safe",
    pathIncluded: true,
    remoteUrlsHashed: true,
    remoteCredentialsIncluded: false,
    statusPathsIncluded: false,
  };
}

function runtimeSessionIdForAgent(agent) {
  return agent.runtime_session_id ?? agent.id;
}

function doctorHash(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

function normalizeArray(value) {
  return Array.isArray(value) ? value : [];
}

function uniqueStrings(values) {
  return [...new Set(normalizeArray(values).filter((value) => typeof value === "string" && value.length > 0))];
}

function relative(from, to) {
  return path.relative(from, to) || ".";
}

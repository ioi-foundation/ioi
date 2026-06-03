import assert from "node:assert/strict";
import test from "node:test";

import {
  branchPolicyForRepositoryContext,
  githubContextForRepository,
  parseGitRemotes,
  repositoryStatusCounts,
  workspaceTrustWarningRecordForMode,
} from "./repository-context.mjs";
import { WORKSPACE_TRUST_WARNING_SCHEMA_VERSION } from "./runtime-contract-constants.mjs";

test("repository status counts classify porcelain states", () => {
  assert.deepEqual(
    repositoryStatusCounts([
      "M  staged.txt",
      " M unstaged.txt",
      "MM both.txt",
      "?? new.txt",
      "!! ignored.txt",
      "UU conflict.txt",
    ].join("\n")),
    {
      staged: 3,
      unstaged: 3,
      untracked: 1,
      ignored: 1,
      conflicted: 1,
    },
  );
});

test("git remote parsing redacts credentials and detects GitHub metadata", () => {
  const remotes = parseGitRemotes([
    "origin\thttps://token:secret@github.com/ioi-foundation/ioi.git (fetch)",
    "origin\tgit@github.com:ioi-foundation/ioi.git (push)",
    "backup\thttps://example.com/plain/repo.git (fetch)",
  ].join("\n"));

  assert.equal(remotes.length, 2);
  const origin = remotes.find((remote) => remote.name === "origin");
  assert.equal(origin.provider, "github");
  assert.equal(origin.host, "github.com");
  assert.equal(origin.owner, "ioi-foundation");
  assert.equal(origin.repo, "ioi");
  assert.equal(origin.repoFullName, "ioi-foundation/ioi");
  assert.equal(origin.fetchUrl, "https://github.com/ioi-foundation/ioi.git");
  assert.match(origin.pushUrl, /^redacted:/);
  assert.equal(origin.fetchUrl.includes("secret"), false);
  assert.equal(origin.pushUrl.includes("git@"), false);
});

test("branch and GitHub projections remain read-only policy records", () => {
  const repositoryContext = {
    contextId: "repoctx_test",
    isGitRepository: true,
    defaultBranch: "main",
    branch: "feature/runtime-split",
    detachedHead: false,
    headSha: "abc123abc123",
    headShortSha: "abc123abc123",
    upstream: "origin/feature/runtime-split",
    status: {
      isDirty: false,
      counts: repositoryStatusCounts(""),
      ahead: 0,
      behind: 0,
    },
    remotes: parseGitRemotes("origin\tgit@github.com:ioi-foundation/ioi.git (fetch)"),
  };
  const branchPolicy = branchPolicyForRepositoryContext({
    repositoryContext,
    policyId: "branch_policy_test",
    generatedAt: "2026-06-03T00:00:00.000Z",
  });
  const previousGithubToken = process.env.GITHUB_TOKEN;
  process.env.GITHUB_TOKEN = "test-token";
  try {
    const githubContext = githubContextForRepository({
      repositoryContext,
      branchPolicy,
      contextId: "github_context_test",
      generatedAt: "2026-06-03T00:00:00.000Z",
    });

    assert.equal(branchPolicy.status, "passed");
    assert.equal(branchPolicy.mutationAllowed, true);
    assert.equal(branchPolicy.readOnly, true);
    assert.equal(githubContext.status, "available");
    assert.equal(githubContext.repoFullName, "ioi-foundation/ioi");
    assert.equal(githubContext.credentials.tokenAvailable, true);
    assert.equal(githubContext.credentials.tokenValueIncluded, false);
    assert.equal(githubContext.networkLookupPerformed, false);
    assert.equal(githubContext.mutationExecuted, false);
  } finally {
    if (previousGithubToken === undefined) {
      delete process.env.GITHUB_TOKEN;
    } else {
      process.env.GITHUB_TOKEN = previousGithubToken;
    }
  }
});

test("workspace trust warning ignores UI-provided trust overrides", () => {
  const warning = workspaceTrustWarningRecordForMode({
    agent: {
      id: "agent_test",
      cwd: "/tmp/not-a-git-repository-for-ioi-test",
      runtimeSessionId: "session_test",
    },
    threadId: "thread_test",
    controls: { mode: "yolo" },
    request: { trust_profile: "trusted", hideWarnings: true },
    source: "studio",
    requestedBy: "operator",
    now: "2026-06-03T00:00:00.000Z",
  });

  assert.equal(warning.schemaVersion, WORKSPACE_TRUST_WARNING_SCHEMA_VERSION);
  assert.equal(warning.severity, "high");
  assert.equal(warning.sessionId, "session_test");
  assert.equal(warning.uiOverrideIgnored, true);
  assert.deepEqual(warning.ignoredUiFields, ["trust_profile", "hideWarnings"]);
  assert.equal(warning.readOnly, true);
  assert.equal(warning.mutationExecuted, false);
  assert.equal(warning.branchPolicyBlockers.includes("not_a_git_repository"), true);
});

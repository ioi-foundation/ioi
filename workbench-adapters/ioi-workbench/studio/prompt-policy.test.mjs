import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);
const { createStudioPromptPolicy } = require("./prompt-policy.js");

function createPolicy() {
  return createStudioPromptPolicy({
    normalizeStudioExecutionMode: (value) => value || "agent",
    stringValue: (value, fallback = "") => {
      if (typeof value !== "string") return fallback;
      const trimmed = value.trim();
      return trimmed || fallback;
    },
    studioModeAgent: "agent",
  });
}

test("prompt policy normalizes whitespace and auto model selectors", () => {
  const policy = createPolicy();

  assert.equal(policy.compactStudioWhitespace("  hello\n\n world\t "), "hello world");
  assert.equal(policy.isAutoStudioModelSelector("auto"), true);
  assert.equal(policy.isAutoStudioModelSelector("local:auto"), true);
  assert.equal(policy.isAutoStudioModelSelector("default"), true);
  assert.equal(policy.isAutoStudioModelSelector("route.local-first"), false);
});

test("prompt policy distinguishes workspace prompts from current external retrieval", () => {
  const policy = createPolicy();

  assert.equal(policy.promptTargetsLocalWorkspace("review workbench-adapters/ioi-workbench"), true);
  assert.equal(policy.promptRequiresWorkspaceContext("audit the current workspace and explain packages/runtime-daemon", "agent"), true);
  assert.equal(policy.promptRequiresWorkspaceContext("audit the current workspace", "ask"), false);
  assert.equal(policy.promptRequiresRetrieval("review packages/runtime-daemon/src/index.mjs"), false);
  assert.equal(policy.promptRequiresRetrieval("what is the latest Filecoin market price today?"), true);
  assert.equal(policy.promptRequiresRetrieval("cite public sources for this online claim"), true);
});

test("prompt policy keeps internal harness probes out of retrieval and workspace-context routing", () => {
  const policy = createPolicy();

  for (const prompt of [
    "TOOLCAT_SINGLE_TOOL shell__run",
    "workspace_fixture_123 run this proof",
    "daemon_endpoint=http://127.0.0.1:1",
    "live IDE Rust/provider tool row",
  ]) {
    assert.equal(policy.promptIsInternalHarnessProbe(prompt), true);
    assert.equal(policy.promptRequiresRetrieval(prompt), false);
    assert.equal(policy.promptRequiresWorkspaceContext(prompt, "agent"), false);
  }
});

test("prompt policy extracts workspace targets from prompts", () => {
  const policy = createPolicy();

  assert.deepEqual(
    policy.workspaceTargetsForPrompt("review workbench-adapters/ioi-workbench and workbench-adapters/ioi-workbench."),
    [{ kind: "path", path: "workbench-adapters/ioi-workbench", reason: "explicit_workspace_path" }],
  );
  assert.deepEqual(
    policy.workspaceTargetsForPrompt("inspect packages/runtime-daemon/src/index.mjs, then summarize docs/architecture/runtime.md"),
    [
      { kind: "path", path: "packages/runtime-daemon/src/index.mjs", reason: "explicit_workspace_path" },
      { kind: "path", path: "docs/architecture/runtime.md", reason: "explicit_workspace_path" },
    ],
  );
  assert.deepEqual(
    policy.workspaceTargetsForPrompt("explain retry limit behavior in the current workspace"),
    [{ kind: "search", query: "retry limit behavior current", reason: "workspace_context_query" }],
  );
});

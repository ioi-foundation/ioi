import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { createRuntimeAgentOptionsHelpers } from "./runtime-agent-options.mjs";

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function makeHelpers(env = {}) {
  return createRuntimeAgentOptionsHelpers({
    env,
    readJson,
    doctorHash: (value) => crypto.createHash("sha256").update(String(value)).digest("hex"),
    externalBlocker: (message, details) => {
      const error = new Error(message);
      error.code = "external_blocker";
      error.details = details;
      return error;
    },
  });
}

test("runtime agent options summarize explicit and Cursor-compatible config", () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-agent-options-"));
  fs.mkdirSync(path.join(cwd, ".cursor", "skills"), { recursive: true });
  fs.writeFileSync(
    path.join(cwd, ".cursor", "mcp.json"),
    JSON.stringify({ mcpServers: { cursorServer: {} } }),
  );
  fs.writeFileSync(path.join(cwd, ".cursor", "hooks.json"), JSON.stringify({ preRun: {} }));
  fs.writeFileSync(path.join(cwd, ".cursor", "skills", "code-review.md"), "# skill");
  fs.writeFileSync(path.join(cwd, ".cursor", "skills", ".ignored"), "# hidden");

  const { summarizeAgentOptions, loadCursorCompatibilityConfig } = makeHelpers();

  assert.deepEqual(loadCursorCompatibilityConfig(cwd), {
    mcpServers: { cursorServer: {} },
    hookNames: ["preRun"],
    skillNames: ["code-review.md"],
  });
  assert.deepEqual(summarizeAgentOptions(cwd, {
    local: { cwd: "/workspace" },
    hosted: {},
    mcp_servers: { explicitServer: {}, cursorServer: {} },
    mcpServers: { retiredServer: {} },
    agents: { reviewer: {} },
    sandboxOptions: { profile: "locked" },
  }), {
    localCwd: "/workspace",
    cloudConfigured: true,
    selfHostedConfigured: false,
    mcpServerNames: ["explicitServer", "cursorServer"],
    skillNames: ["code-review.md"],
    hookNames: ["preRun"],
    subagentNames: ["reviewer"],
    sandboxProfile: "locked",
  });
});

test("runtime agent options preserve runtime mode and provider availability behavior", () => {
  const { runtimeModeForOptions, ensureProviderAvailable } = makeHelpers({
    IOI_AGENT_SDK_HOSTED_ENDPOINT: "https://hosted.example",
  });

  assert.equal(runtimeModeForOptions({ cloud: {} }), "cloud");
  assert.equal(runtimeModeForOptions({ hosted: {} }), "hosted");
  assert.equal(runtimeModeForOptions({ selfHosted: {} }), "selfHosted");
  assert.equal(runtimeModeForOptions({}), "local");
  assert.doesNotThrow(() => ensureProviderAvailable("local", {}));
  assert.doesNotThrow(() => ensureProviderAvailable("hosted", {}));

  const unavailable = makeHelpers().ensureProviderAvailable;
  assert.throws(
    () => unavailable("cloud", {}),
    (error) =>
      error.code === "external_blocker" &&
      error.details.runtime === "cloud" &&
      error.details.requiredEnvironment.includes("IOI_AGENT_SDK_HOSTED_ENDPOINT"),
  );
});

test("runtime agent options preserve memory merge and provider key doctor report", () => {
  const { memoryOptionsForRequest, doctorProviderKeyReport } = makeHelpers({
    OPENAI_API_KEY: "secret",
    IOI_AGENT_SDK_SELF_HOSTED_ENDPOINT: "https://worker.example",
  });

  assert.deepEqual(memoryOptionsForRequest({
    memory: { scope: "thread", limit: 3 },
    options: { memory: { limit: 5, query: "recent" } },
  }), {
    scope: "thread",
    limit: 5,
    query: "recent",
  });

  const rows = doctorProviderKeyReport();
  const openAi = rows.find((row) => row.name === "OPENAI_API_KEY");
  const anthropic = rows.find((row) => row.name === "ANTHROPIC_API_KEY");
  assert.equal(openAi.configured, true);
  assert.equal(openAi.valueRedacted, true);
  assert.equal(openAi.valueHash.length, 64);
  assert.equal(anthropic.configured, false);
  assert.equal(anthropic.valueHash, null);
});

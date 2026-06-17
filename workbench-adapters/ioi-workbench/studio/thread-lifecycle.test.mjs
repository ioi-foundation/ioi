import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);

const { createStudioThreadLifecycle } = require("./thread-lifecycle.js");

function createHarness({ projection = {}, requestJson } = {}) {
  const receipts = [];
  const output = { lines: [], appendLine(line) { this.lines.push(line); } };
  let resetCount = 0;
  const state = {
    threadId: "",
    sessionId: "",
    modelRoute: "",
    selectedModel: "",
    reasoningEffort: "none",
    approvalMode: "default",
    executionMode: "ask",
    runtimeProfile: "fixture",
    status: "idle",
    history: [],
    timeline: [],
    ...projection,
  };
  const lifecycle = createStudioThreadLifecycle({
    appendStudioReceipts: (items) => receipts.push(...items),
    daemonEndpoint: () => "http://daemon.test",
    daemonRequestToken: () => "token",
    firstArray: (value) => (Array.isArray(value) ? value : []),
    getStudioRuntimeProjection: () => state,
    isAutoStudioModelSelector: (value) => value === "auto",
    normalizeStudioExecutionMode: (value) => value === "agent" ? "agent" : "ask",
    normalizeStudioPermissionMode: (value) => value === "full_access" ? "full_access" : "default",
    normalizeStudioReasoningEffort: (value) => value || "none",
    requestJson,
    resetStudioDaemonThreadProjection: () => {
      resetCount += 1;
      state.threadId = "";
    },
    STUDIO_AGENT_RUNTIME_PROFILE: "runtime_service",
    STUDIO_DIRECT_MODEL_RUNTIME_PROFILE: "fixture",
    STUDIO_MODE_AGENT: "agent",
    studioIntentFramePayload: (frame) => frame ? { ...frame, projected: true } : null,
    studioPermissionDaemonMapping: (mode) => ({
      approvalMode: mode,
      approval_mode: mode,
      threadMode: mode === "full_access" ? "battle" : "safe",
      thread_mode: mode === "full_access" ? "battle" : "safe",
    }),
    stringValue: (value, fallback = "") => (typeof value === "string" ? value : value === null || value === undefined ? fallback : String(value)),
    uniqueStrings: (values = []) => [...new Set(values.filter(Boolean))],
    workspaceSummary: () => ({ path: "/workspace/repo" }),
  });
  return { lifecycle, output, receipts, state, get resetCount() { return resetCount; } };
}

test("thread lifecycle switches mode and resets incompatible daemon thread", () => {
  const harness = createHarness({
    projection: {
      threadId: "thread-old",
      executionMode: "ask",
      runtimeProfile: "fixture",
    },
  });

  const result = harness.lifecycle.applyStudioAgentModeSelection({ executionMode: "agent" });

  assert.deepEqual(result, { executionMode: "agent", runtimeProfile: "runtime_service" });
  assert.equal(harness.resetCount, 1);
  assert.equal(harness.state.threadId, "");
});

test("thread lifecycle creates daemon thread with stable envelope and projection", async () => {
  const requests = [];
  const harness = createHarness({
    requestJson: async (endpoint, route, options) => {
      requests.push({ endpoint, route, options });
      return {
        thread_id: "thread-one",
        session_id: "session-one",
        model_route_id: "route.local-first",
        selected_model: "auto",
        status: "active",
        model_route_receipt_id: "receipt-route",
      };
    },
  });

  const projection = await harness.lifecycle.ensureStudioDaemonThread({
    model: "route.local-first",
    selectedModelId: "auto",
    executionMode: "agent",
    reasoningEffort: "low",
    approvalMode: "full_access",
    intentFrame: { runtimeAction: "chat" },
  }, harness.output);

  assert.equal(projection.threadId, "thread-one");
  assert.equal(harness.state.sessionId, "session-one");
  assert.equal(harness.state.runtimeProfile, "runtime_service");
  assert.equal(harness.state.approvalMode, "full_access");
  assert.equal(harness.state.history[0].title, "Daemon Studio session");
  assert.equal(harness.state.timeline[0].label, "Daemon session created");
  assert.equal(harness.receipts[0].id, "receipt-route");
  assert.equal(harness.output.lines[0], "[ioi-studio] daemon session ready: thread-one");
  assert.equal(requests[0].route, "/v1/threads");
  assert.equal(requests[0].options.payload.mode, "battle");
  assert.equal(requests[0].options.payload.runtime_profile, "runtime_service");
  assert.equal(requests[0].options.payload.options.local.cwd, "/workspace/repo");
  assert.equal(requests[0].options.payload.options.model.id, "auto");
  assert.deepEqual(requests[0].options.payload.options.intentFrame, { runtimeAction: "chat", projected: true });
});

test("thread lifecycle updates permission mode and reports unavailable daemon route", async () => {
  const requests = [];
  const harness = createHarness({
    projection: { threadId: "thread-one" },
    requestJson: async (endpoint, route, options) => {
      requests.push({ endpoint, route, options });
      throw new Error("route unavailable");
    },
  });

  const mapping = await harness.lifecycle.applyStudioPermissionModeSelection({ approvalMode: "full_access" }, harness.output);

  assert.equal(mapping.threadMode, "battle");
  assert.equal(harness.state.approvalMode, "full_access");
  assert.equal(requests[0].route, "/v1/threads/thread-one/mode");
  assert.equal(requests[0].options.payload.mode, "battle");
  assert.equal(requests[0].options.payload.source, "agent-studio-permissions-menu");
  assert.match(harness.output.lines[0], /permission mode update unavailable: route unavailable/);
});

test("thread lifecycle derives assistant run result text with fallback", () => {
  const harness = createHarness();

  assert.equal(
    harness.lifecycle.studioRunResultText({
      prompt: "hello",
      conversation: [{ role: "assistant", content: "older" }, { role: "assistant", message: "newer" }],
      run: { result: "run result" },
    }),
    "newer",
  );
  assert.equal(
    harness.lifecycle.studioRunResultText({ prompt: "hello", run: { output: "run output" }, conversation: [] }),
    "run output",
  );
  assert.equal(
    harness.lifecycle.studioRunResultText({ prompt: "hello", run: {}, conversation: [] }),
    "Daemon turn completed for: hello",
  );
});

import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { test } from "node:test";

const require = createRequire(import.meta.url);
const { createStudioArtifactIntent } = require("./artifact-intent.js");

function stringValue(value, fallback = "") {
  if (typeof value !== "string") {
    return fallback;
  }
  const normalized = value.trim();
  return normalized || fallback;
}

function createIntent(overrides = {}) {
  return createStudioArtifactIntent({
    stringValue,
    firstArray: (value) => Array.isArray(value) ? value : [],
    promptRequiresRetrieval: () => false,
    promptRequiresWorkspaceContext: () => false,
    workspaceTargetsForPrompt: () => [],
    normalizeStudioExecutionMode: (value) => value === "ask" ? "ask" : "agent",
    studioArtifactShouldGatherResearch: () => false,
    modeAgent: "agent",
    modeAsk: "ask",
    ...overrides,
  });
}

test("artifact intent helpers recognize generated website prompts without authoring intent frames", () => {
  const intent = createIntent();
  const prompt = "Create a website about local-first agent runtime observability.";

  assert.equal(intent.studioPromptRequestsGeneratedWebArtifact(prompt), true);
  assert.equal(intent.shouldProjectConversationArtifactCanvas(prompt), true);
  assert.equal(intent.studioArtifactClassFromPrompt(prompt), "static_html_js");
  assert.equal(intent.studioArtifactTitleFromClass("static_html_js", prompt), "Local-first agent runtime observability website");
  assert.equal(Object.hasOwn(intent, "fallbackStudioPromptIntentFrame"), false);
});

test("artifact intent recognizes browser observation capture artifacts", () => {
  const intent = createIntent();
  const prompt = "Capture the browser session result as an artifact.";

  assert.equal(intent.studioPromptRequestsBrowserObservationArtifact(prompt), true);
  assert.equal(intent.studioArtifactClassFromPrompt(prompt), "browser_observation");
  assert.equal(intent.studioArtifactTitleFromClass("browser_observation", prompt), "Browser session capture");
});

test("artifact intent consumes daemon-owned Ask intent frames", () => {
  const intent = createIntent();
  const frame = {
    schema_version: "ioi.studio.intent-frame.v1",
    object: "ioi.studio_intent_frame",
    route_directive: "ask",
    intent_id: "conversation.reply",
    execution_mode: "ask",
    required_capabilities: ["prim:conversation.reply"],
    decision_material: { source: "rust_studio_intent_frame_projection" },
  };
  const payload = intent.studioIntentFramePayload(frame);

  assert.equal(intent.studioIntentFrameRouteDirective(frame), "ask");
  assert.equal(payload.intentId, "conversation.reply");
  assert.equal(payload.executionMode, "ask");
  assert.deepEqual(payload.requiredCapabilities, ["prim:conversation.reply"]);
});

test("artifact intent consumes daemon-owned runtime cockpit intent frames", () => {
  const intent = createIntent();
  const frame = {
    schema_version: "ioi.studio.intent-frame.v1",
    object: "ioi.studio_intent_frame",
    route_directive: "runtime_cockpit",
    intent_id: "runtime.inspect",
    required_capabilities: ["prim:runtime.trace.read"],
    decision_material: {
      source: "rust_studio_intent_frame_projection",
      matched_features: ["runtime_inspection"],
    },
  };

  assert.equal(intent.shouldProjectStudioRuntimeCockpit("Show replay state"), true);
  assert.equal(intent.studioIntentFrameProjectsRuntimeCockpit(frame), true);
  assert.equal(intent.studioIntentFramePayload(frame).intentId, "runtime.inspect");
  assert.ok(intent.studioIntentFramePayload(frame).requiredCapabilities.includes("prim:runtime.trace.read"));
});

test("artifact intent does not recover route truth from injected local predicates", () => {
  const intent = createIntent({
    promptRequiresRetrieval: (prompt) => /latest/i.test(prompt),
    promptRequiresWorkspaceContext: (prompt) => /workspace/i.test(prompt),
    workspaceTargetsForPrompt: () => [{ kind: "path", path: "apps/hypervisor", reason: "test" }],
  });

  assert.equal(intent.studioIntentFrameRequiresRetrieval({}, "What is the latest release status?"), false);
  assert.equal(intent.studioIntentFrameProjectsArtifact({ route_directive: "agent" }), false);
  assert.equal(intent.studioIntentFrameArtifactClass({}, "Create a website"), "");
  assert.equal(
    intent.studioIntentFrameRequiresRetrieval({ retrieval: { required: true } }, "What is the latest release status?"),
    true,
  );
});

test("artifact intent normalizes snake and camel intent-frame payload fields", () => {
  const intent = createIntent();
  const payload = intent.studioIntentFramePayload({
    schema_version: "schema.v1",
    intent_id: "runtime.inspect",
    route_directive: "runtime_cockpit",
    execution_mode: "agent",
    required_capabilities: ["prim:runtime.trace.read"],
    runtime_action: { kind: "inspect" },
    effect_contract: { effectLevel: "read_only" },
    decisionMaterial: {
      source: "daemon",
      matchedFeatures: ["runtime_inspection"],
      promptHash: "hash",
      promptPreview: "preview",
    },
  });

  assert.equal(payload.schemaVersion, "schema.v1");
  assert.equal(payload.intentId, "runtime.inspect");
  assert.equal(payload.routeDirective, "runtime_cockpit");
  assert.deepEqual(payload.requiredCapabilities, ["prim:runtime.trace.read"]);
  assert.deepEqual(payload.runtimeAction, { kind: "inspect" });
  assert.deepEqual(payload.runtime_action, { kind: "inspect" });
  assert.deepEqual(payload.effectContract, { effectLevel: "read_only" });
  assert.deepEqual(payload.decisionMaterial.matchedFeatures, ["runtime_inspection"]);
});

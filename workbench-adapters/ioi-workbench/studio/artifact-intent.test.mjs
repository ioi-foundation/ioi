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

test("artifact intent routes generated website prompts to static HTML artifacts", () => {
  const intent = createIntent();
  const prompt = "Create a website about local-first agent runtime observability.";
  const frame = intent.fallbackStudioPromptIntentFrame(prompt);

  assert.equal(intent.studioPromptRequestsGeneratedWebArtifact(prompt), true);
  assert.equal(intent.shouldProjectConversationArtifactCanvas(prompt), true);
  assert.equal(frame.routeDirective, "artifact");
  assert.equal(frame.intentId, "artifact.create");
  assert.equal(frame.artifact.artifactClass, "static_html_js");
  assert.equal(frame.artifact.title, "Local-first agent runtime observability website");
  assert.deepEqual(frame.effectContract.receiptsRequired, ["artifact_record", "artifact_revision", "artifact_policy"]);
});

test("artifact intent recognizes browser observation capture artifacts", () => {
  const intent = createIntent();
  const prompt = "Capture the browser session result as an artifact.";

  assert.equal(intent.studioPromptRequestsBrowserObservationArtifact(prompt), true);
  assert.equal(intent.studioArtifactClassFromPrompt(prompt), "browser_observation");
  assert.equal(intent.studioArtifactTitleFromClass("browser_observation", prompt), "Browser session capture");
});

test("artifact intent keeps Ask mode on direct answer route", () => {
  const intent = createIntent();
  const frame = intent.fallbackStudioPromptIntentFrame("Explain the current plan", { executionMode: "ask" });

  assert.equal(frame.routeDirective, "ask");
  assert.equal(frame.intentId, "conversation.reply");
  assert.equal(frame.executionMode, "ask");
  assert.deepEqual(frame.requiredCapabilities, ["prim:conversation.reply"]);
});

test("artifact intent routes runtime cockpit prompts to runtime inspection", () => {
  const intent = createIntent();
  const frame = intent.fallbackStudioPromptIntentFrame("Show the runtime cockpit receipt timeline and replay state.");

  assert.equal(intent.shouldProjectStudioRuntimeCockpit("Show replay state"), true);
  assert.equal(frame.routeDirective, "runtime_cockpit");
  assert.equal(frame.intentId, "runtime.inspect");
  assert.ok(frame.requiredCapabilities.includes("prim:runtime.trace.read"));
  assert.deepEqual(frame.decisionMaterial.matchedFeatures, ["runtime_inspection"]);
});

test("artifact intent uses injected retrieval and workspace predicates", () => {
  const intent = createIntent({
    promptRequiresRetrieval: (prompt) => /latest/i.test(prompt),
    promptRequiresWorkspaceContext: (prompt) => /workspace/i.test(prompt),
    workspaceTargetsForPrompt: () => [{ kind: "path", path: "apps/hypervisor", reason: "test" }],
  });

  const retrieval = intent.fallbackStudioPromptIntentFrame("What is the latest release status?");
  assert.equal(retrieval.intentId, "retrieval.answer");
  assert.equal(retrieval.retrieval.required, true);
  assert.ok(retrieval.requiredCapabilities.includes("prim:web.search"));

  const workspace = intent.fallbackStudioPromptIntentFrame("Inspect the workspace for runtime modules.");
  assert.equal(workspace.intentId, "workspace.context");
  assert.equal(workspace.workspace.required, true);
  assert.deepEqual(workspace.workspace.targets, [{ kind: "path", path: "apps/hypervisor", reason: "test" }]);
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

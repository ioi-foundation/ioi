import assert from "node:assert/strict";
import test from "node:test";

import { resolveStudioIntentFrame } from "./studio-intent-frame.mjs";

test("routes natural website creation prompts to static artifact creation", () => {
  const frame = resolveStudioIntentFrame({
    prompt: "Create a website that explains post-quantum computers",
    executionMode: "agent",
  });

  assert.equal(frame.intentId, "artifact.create");
  assert.equal(frame.routeDirective, "artifact");
  assert.equal(frame.artifact.required, true);
  assert.equal(frame.artifact.class, "static_html_js");
  assert.equal(frame.artifact.title, "Post-quantum computers website");
  assert.equal(frame.retrieval.required, true);
  assert.ok(frame.retrieval.requirements.includes("source_grounding"));
  assert.ok(frame.requiredCapabilities.includes("prim:web.search"));
  assert.ok(frame.requiredCapabilities.includes("prim:web.read"));
  assert.equal(frame.effectContract.sandbox, "artifact_renderer");
});

test("routes generated app prompts to React/Vite artifacts", () => {
  const frame = resolveStudioIntentFrame({
    prompt: "Build a small React dashboard artifact from this CSV, then make the sidebar denser.",
  });

  assert.equal(frame.intentId, "artifact.create");
  assert.equal(frame.routeDirective, "artifact");
  assert.equal(frame.artifact.class, "react_vite_app");
  assert.ok(frame.requiredCapabilities.includes("prim:artifact.write"));
});

test("routes imported document prompts to editable document artifacts", () => {
  const frame = resolveStudioIntentFrame({
    prompt: "Turn this ODT into an artifact, tighten the intro, compare changes, and export a clean copy.",
  });

  assert.equal(frame.routeDirective, "artifact");
  assert.equal(frame.artifact.class, "imported_document");
  assert.equal(frame.retrieval.required, false);
});

test("marks current external questions as retrieval-required", () => {
  const frame = resolveStudioIntentFrame({
    prompt: "Which is a better investment right now, Akash or Filecoin?",
  });

  assert.equal(frame.intentId, "retrieval.answer");
  assert.equal(frame.routeDirective, "agent");
  assert.equal(frame.retrieval.required, true);
  assert.ok(frame.retrieval.requirements.includes("current_external_state"));
});

test("routes local repository questions to workspace context", () => {
  const frame = resolveStudioIntentFrame({
    prompt: "Where are local/native model providers registered in this repo?",
    executionMode: "agent",
  });

  assert.equal(frame.intentId, "workspace.context");
  assert.equal(frame.routeDirective, "agent");
  assert.equal(frame.workspace.required, true);
  assert.ok(frame.workspace.requirements.includes("workspace_context"));
  assert.deepEqual(frame.workspace.targets, [
    {
      kind: "search",
      query: "local native model providers registered",
      reason: "workspace_context_query",
    },
  ]);
  assert.ok(frame.requiredCapabilities.includes("prim:file.search"));
  assert.ok(frame.requiredCapabilities.includes("prim:file.read"));
  assert.equal(frame.effectContract.effectLevel, "read_only_workspace");
});

test("routes explicit local plan paths to workspace context", () => {
  const frame = resolveStudioIntentFrame({
    prompt: "What does progress look like per .internal/plans/example-master-guide.md?",
    executionMode: "agent",
  });

  assert.equal(frame.intentId, "workspace.context");
  assert.equal(frame.workspace.required, true);
  assert.deepEqual(frame.workspace.targets, [
    {
      kind: "path",
      path: ".internal/plans/example-master-guide.md",
      reason: "explicit_workspace_path",
    },
  ]);
  assert.equal(frame.retrieval.required, false);
});

test("routes explicit inline command prompts to local runtime action", () => {
  const frame = resolveStudioIntentFrame({
    prompt: "Run `node --check scripts/lib/autopilot-agent-studio-chat-scenarios.mjs` and summarize the exit code.",
    executionMode: "agent",
  });

  assert.equal(frame.intentId, "command.exec");
  assert.equal(frame.routeDirective, "runtime_action");
  assert.deepEqual(frame.runtimeAction, {
    required: true,
    intentClass: "local_runtime_action",
    intent_class: "local_runtime_action",
    actionFamily: "shell",
    action_family: "shell",
    targetKind: "shell_command",
    target_kind: "shell_command",
    targetCommand: "node --check scripts/lib/autopilot-agent-studio-chat-scenarios.mjs",
    target_command: "node --check scripts/lib/autopilot-agent-studio-chat-scenarios.mjs",
    hostMutation: true,
    host_mutation: true,
  });
  assert.equal(frame.workspace.required, false);
  assert.equal(frame.retrieval.required, false);
  assert.ok(frame.requiredCapabilities.includes("command.exec"));
  assert.equal(frame.effectContract.effectLevel, "command_execution");
});

test("does not collapse retained shell stdin lifecycle prompts into one-shot command plans", () => {
  const frame = resolveStudioIntentFrame({
    prompt: [
      "Start a disposable retained Node.js helper that waits for stdin and echoes a status line.",
      "Check the helper status, send the input `compile-once`, terminate the helper, reset retained shell state, and then answer.",
    ].join(" "),
    executionMode: "agent",
  });

  assert.notEqual(frame.intentId, "command.exec");
  assert.notEqual(frame.routeDirective, "runtime_action");
  assert.equal(frame.runtimeAction, null);
});

test("does not treat inline code symbols as local runtime actions", () => {
  const frame = resolveStudioIntentFrame({
    prompt: "Explain how `formatOrderTotal` is used in this repo.",
    executionMode: "agent",
  });

  assert.notEqual(frame.intentId, "command.exec");
  assert.equal(frame.runtimeAction, null);
});

test("routes runtime inspection prompts to the runtime cockpit projection", () => {
  const frame = resolveStudioIntentFrame({
    prompt: "Show runtime cockpit policy lease and worker status for this run.",
  });

  assert.equal(frame.intentId, "runtime.inspect");
  assert.equal(frame.routeDirective, "runtime_cockpit");
  assert.ok(frame.requiredCapabilities.includes("prim:runtime.trace.read"));
});

test("keeps browser automation prompts in the governed agent route", () => {
  const frame = resolveStudioIntentFrame({
    prompt:
      "Open the local browser fixture at http://127.0.0.1:45235/. Inspect the page, click the blue canvas target, and report whether the browser session stayed observable.",
    executionMode: "agent",
  });

  assert.equal(frame.routeDirective, "agent");
  assert.equal(frame.artifact.required, false);
  assert.notEqual(frame.artifact.class, "browser_observation");
});

test("routes explicit browser capture prompts to browser observation artifacts", () => {
  const frame = resolveStudioIntentFrame({
    prompt: "Capture this browser session result as an artifact and let me ask a follow-up question.",
    executionMode: "agent",
  });

  assert.equal(frame.intentId, "artifact.create");
  assert.equal(frame.routeDirective, "artifact");
  assert.equal(frame.artifact.required, true);
  assert.equal(frame.artifact.class, "browser_observation");
});

test("keeps simple conversational turns cheap and direct", () => {
  const frame = resolveStudioIntentFrame({ prompt: "hiya bot" });

  assert.equal(frame.intentId, "conversation.reply");
  assert.equal(frame.routeDirective, "agent");
  assert.equal(frame.retrieval.required, false);
  assert.equal(frame.artifact.required, false);
});

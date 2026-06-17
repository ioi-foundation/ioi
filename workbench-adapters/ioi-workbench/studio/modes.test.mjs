import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { test } from "node:test";

const require = createRequire(import.meta.url);
const {
  STUDIO_MODE_AGENT,
  STUDIO_MODE_ASK,
  STUDIO_PERMISSION_MODE_AUTO_REVIEW,
  STUDIO_PERMISSION_MODE_DEFAULT,
  STUDIO_PERMISSION_MODE_FULL_ACCESS,
  normalizeStudioExecutionMode,
  normalizeStudioPermissionMode,
  studioExecutionModeLabel,
  studioPermissionDaemonMapping,
  studioPermissionModeLabel,
  studioPermissionModeOptions,
  studioPermissionThreadMode,
} = require("./modes.js");

test("studio modes normalize execution aliases", () => {
  assert.equal(normalizeStudioExecutionMode("direct chat"), STUDIO_MODE_ASK);
  assert.equal(normalizeStudioExecutionMode("chat_only"), STUDIO_MODE_ASK);
  assert.equal(normalizeStudioExecutionMode("agent"), STUDIO_MODE_AGENT);
  assert.equal(studioExecutionModeLabel("ask"), "Ask");
  assert.equal(studioExecutionModeLabel("agent"), "Agent");
});

test("studio modes normalize permission aliases and labels", () => {
  assert.equal(normalizeStudioPermissionMode("auto review"), STUDIO_PERMISSION_MODE_AUTO_REVIEW);
  assert.equal(normalizeStudioPermissionMode("yolo"), STUDIO_PERMISSION_MODE_FULL_ACCESS);
  assert.equal(normalizeStudioPermissionMode("suggest"), STUDIO_PERMISSION_MODE_DEFAULT);
  assert.equal(studioPermissionModeLabel("auto"), "Auto-review");
  assert.equal(studioPermissionModeLabel("neverprompt"), "Full access");
  assert.equal(studioPermissionModeLabel("suggest"), "Default permissions");
});

test("studio modes map permission controls to daemon thread controls", () => {
  assert.equal(studioPermissionThreadMode("never_prompt"), "yolo");
  assert.equal(studioPermissionThreadMode("suggest"), STUDIO_MODE_AGENT);
  assert.deepEqual(studioPermissionDaemonMapping("full access"), {
    approvalMode: STUDIO_PERMISSION_MODE_FULL_ACCESS,
    approval_mode: STUDIO_PERMISSION_MODE_FULL_ACCESS,
    threadMode: "yolo",
    thread_mode: "yolo",
  });
});

test("studio modes expose picked permission option", () => {
  const options = studioPermissionModeOptions("auto");
  assert.equal(options.length, 3);
  assert.equal(options.find((option) => option.id === STUDIO_PERMISSION_MODE_AUTO_REVIEW).picked, true);
  assert.equal(options.find((option) => option.id === STUDIO_PERMISSION_MODE_DEFAULT).picked, false);
});

import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { nativeFixtureStage5StopHookRepairResponse } from "./native-fixture-stage5-stop-hook-repair.mjs";

const HELPER_PATH = ".tmp/autopilot-stage5-stop-hook-repair/run-1/status-labels.mjs";
const TEST_PATH = ".tmp/autopilot-stage5-stop-hook-repair/run-1/status-labels.test.mjs";
const QUERY = [
  `Stage 5 stop-hook proof: fix the failing normalizeStatusLabel helper at ${HELPER_PATH}.`,
  "Run the focused test, do not finish while validation is failing, repair with a hunk edit, rerun validation, and then answer.",
].join(" ");

function parseToolCall(response) {
  assert.equal(typeof response, "string");
  return JSON.parse(response);
}

function withProofEnv(fn) {
  const previousEnabled = process.env.IOI_STAGE5_STOP_HOOK_REPAIR_PROOF;
  const previousStateDir = process.env.IOI_STAGE5_STOP_HOOK_REPAIR_STATE_DIR;
  const stateDir = mkdtempSync(join(tmpdir(), "ioi-stage5-stop-hook-fixture-test-"));
  process.env.IOI_STAGE5_STOP_HOOK_REPAIR_PROOF = "1";
  process.env.IOI_STAGE5_STOP_HOOK_REPAIR_STATE_DIR = stateDir;
  try {
    return fn();
  } finally {
    if (previousEnabled === undefined) {
      delete process.env.IOI_STAGE5_STOP_HOOK_REPAIR_PROOF;
    } else {
      process.env.IOI_STAGE5_STOP_HOOK_REPAIR_PROOF = previousEnabled;
    }
    if (previousStateDir === undefined) {
      delete process.env.IOI_STAGE5_STOP_HOOK_REPAIR_STATE_DIR;
    } else {
      process.env.IOI_STAGE5_STOP_HOOK_REPAIR_STATE_DIR = previousStateDir;
    }
    rmSync(stateDir, { recursive: true, force: true });
  }
}

async function withProofEnvAsync(fn) {
  const previousEnabled = process.env.IOI_STAGE5_STOP_HOOK_REPAIR_PROOF;
  const previousStateDir = process.env.IOI_STAGE5_STOP_HOOK_REPAIR_STATE_DIR;
  const stateDir = mkdtempSync(join(tmpdir(), "ioi-stage5-stop-hook-fixture-test-"));
  process.env.IOI_STAGE5_STOP_HOOK_REPAIR_PROOF = "1";
  process.env.IOI_STAGE5_STOP_HOOK_REPAIR_STATE_DIR = stateDir;
  try {
    return await fn();
  } finally {
    if (previousEnabled === undefined) {
      delete process.env.IOI_STAGE5_STOP_HOOK_REPAIR_PROOF;
    } else {
      process.env.IOI_STAGE5_STOP_HOOK_REPAIR_PROOF = previousEnabled;
    }
    if (previousStateDir === undefined) {
      delete process.env.IOI_STAGE5_STOP_HOOK_REPAIR_STATE_DIR;
    } else {
      process.env.IOI_STAGE5_STOP_HOOK_REPAIR_STATE_DIR = previousStateDir;
    }
    rmSync(stateDir, { recursive: true, force: true });
  }
}

function responseFor(inputText, calledTools = []) {
  return nativeFixtureStage5StopHookRepairResponse({
    queryText: QUERY,
    promptContextText: QUERY,
    inputText,
    expectsJsonToolCall: true,
    hasToolCalled: (toolName) => calledTools.includes(toolName),
  });
}

test("stage5 stop-hook repair fixture is disabled unless proof env is enabled", () => {
  const previousEnabled = process.env.IOI_STAGE5_STOP_HOOK_REPAIR_PROOF;
  delete process.env.IOI_STAGE5_STOP_HOOK_REPAIR_PROOF;
  try {
    assert.equal(responseFor(QUERY), null);
  } finally {
    if (previousEnabled !== undefined) {
      process.env.IOI_STAGE5_STOP_HOOK_REPAIR_PROOF = previousEnabled;
    }
  }
});

test("stage5 stop-hook repair fixture walks failing validation, blocked reply, hunk edit, rerun, and final reply", () => withProofEnv(() => {
  const first = parseToolCall(responseFor(QUERY));
  assert.equal(first.name, "shell__run");
  assert.equal(first.arguments.command, "node");
  assert.deepEqual(first.arguments.args, ["--test", TEST_PATH]);

  const weakReply = parseToolCall(responseFor(
    [
      QUERY,
      "tool.completed shell__run exit_code=1",
      "# Subtest: normalizes run statuses",
      "not ok 1 - normalizes run statuses",
      "actual: 'waiting_for_input'",
      "expected: 'Waiting for input'",
      "# pass 0",
      "# fail 1",
    ].join("\n"),
    ["shell__run"],
  ));
  assert.equal(weakReply.name, "chat__reply");
  assert.match(weakReply.arguments.message, /complete/);

  const read = parseToolCall(responseFor(
    [
      QUERY,
      "tool.failed chat__reply ERROR_CLASS=StopHookBlocked Latest validation command failed (exit_code=1): node --test .tmp/autopilot-stage5-stop-hook-repair/run-1/status-labels.test.mjs.",
      "Continue the model -> tool -> typed result -> model loop: inspect the failure, repair the cause, and rerun validation.",
    ].join("\n"),
    ["shell__run", "chat__reply"],
  ));
  assert.equal(read.name, "file__read");
  assert.equal(read.arguments.path, HELPER_PATH);

  const edit = parseToolCall(responseFor(
    [
      QUERY,
      "tool.failed chat__reply ERROR_CLASS=StopHookBlocked Latest validation command failed (exit_code=1): node --test .tmp/autopilot-stage5-stop-hook-repair/run-1/status-labels.test.mjs.",
      `tool.completed file__read path=${HELPER_PATH}`,
      "export function normalizeStatusLabel(status) {",
      "  return String(status || \"\").trim();",
      "}",
    ].join("\n"),
    ["shell__run", "chat__reply", "file__read"],
  ));
  assert.equal(edit.name, "file__edit");
  assert.equal(edit.arguments.path, HELPER_PATH);
  assert.match(edit.arguments.search, /return String/);
  assert.match(edit.arguments.replace, /split/);
  assert.match(edit.arguments.replace, /toUpperCase/);

  const rerun = parseToolCall(responseFor(
    `${QUERY}\ntool.completed file__read path=${HELPER_PATH}\ntool.completed file__edit applied=true`,
    ["shell__run", "chat__reply", "file__read", "file__edit"],
  ));
  assert.equal(rerun.name, "shell__run");
  assert.deepEqual(rerun.arguments.args, ["--test", TEST_PATH]);

  const finalReply = parseToolCall(responseFor(
    [
      QUERY,
      `tool.completed file__read path=${HELPER_PATH}`,
      "tool.completed file__edit applied=true",
      "tool.completed shell__run exit_code=0",
      "# pass 1",
      "# fail 0",
    ].join("\n"),
    ["shell__run", "chat__reply", "file__read", "file__edit"],
  ));
  assert.equal(finalReply.name, "chat__reply");
  assert.match(finalReply.arguments.message, /validation[\s\S]*now passes/);
  assert.doesNotMatch(finalReply.arguments.message, /ERROR_CLASS|StopHookBlocked|tool\.completed|status-labels\.mjs/);

  const done = responseFor(
    [
      QUERY,
      `tool.completed file__read path=${HELPER_PATH}`,
      "tool.completed file__edit applied=true",
      "tool.completed shell__run exit_code=0",
      "# pass 1",
      "# fail 0",
      "tool.completed chat__reply",
    ].join("\n"),
    ["shell__run", "chat__reply", "file__read", "file__edit"],
  );
  assert.equal(done, "I repaired the disposable status-label helper and reran the focused validation. It now passes.");
}));

test("stage5 stop-hook repair proof emits tool calls even without JSON prompt markers", () => withProofEnv(() => {
  const helperPath = ".tmp/autopilot-stage5-stop-hook-repair/run-no-json/status-labels.mjs";
  const testPath = ".tmp/autopilot-stage5-stop-hook-repair/run-no-json/status-labels.test.mjs";
  const query = `Stage 5 stop-hook proof: fix the failing normalizeStatusLabel helper at ${helperPath}.`;
  const response = nativeFixtureStage5StopHookRepairResponse({
    queryText: query,
    promptContextText: query,
    inputText: query,
    expectsJsonToolCall: false,
  });
  const first = parseToolCall(response);
  assert.equal(first.name, "shell__run");
  assert.deepEqual(first.arguments.args, ["--test", testPath]);
}));

test("stage5 stop-hook repair fixture advances duplicate read replay to edit", () => withProofEnv(() => {
  const edit = parseToolCall(responseFor(
    [
      QUERY,
      "tool.failed chat__reply ERROR_CLASS=StopHookBlocked Latest validation command failed.",
      "no matching read observation. Use `file__read` before editing the governed file.",
      "Skipped immediate replay of 'the governed file read' because the identical action already succeeded on the previous step.",
      "Do not repeat it. Verify the updated state or choose a different action.",
    ].join("\n"),
    ["shell__run", "chat__reply"],
  ));
  assert.equal(edit.name, "file__edit");
  assert.equal(edit.arguments.path, HELPER_PATH);
}));

test("stage5 stop-hook repair replacement satisfies focused status-label validation", () => withProofEnvAsync(async () => {
  const edit = parseToolCall(responseFor(
    [
      QUERY,
      "tool.failed chat__reply ERROR_CLASS=StopHookBlocked Latest validation command failed.",
      `tool.completed file__read path=${HELPER_PATH}`,
      "export function normalizeStatusLabel(status) {",
      "  return String(status || \"\").trim();",
      "}",
    ].join("\n"),
    ["shell__run", "chat__reply", "file__read"],
  ));
  assert.equal(edit.name, "file__edit");

  const moduleUrl = `data:text/javascript;charset=utf-8,${encodeURIComponent(edit.arguments.replace)}`;
  const mod = await import(moduleUrl);
  assert.equal(mod.normalizeStatusLabel("waiting_for_input"), "Waiting for input");
  assert.equal(mod.normalizeStatusLabel("completed"), "Completed");
  assert.equal(mod.normalizeStatusLabel(""), "");
}));

test("stage5 stop-hook repair fixture treats post-edit shell completion as green validation", () => withProofEnv(() => {
  const finalReply = parseToolCall(responseFor(
    [
      QUERY,
      `tool.completed file__read path=${HELPER_PATH}`,
      "tool.completed file__edit applied=true",
      "tool.completed shell__run",
      "Ran command",
    ].join("\n"),
    ["shell__run", "chat__reply", "file__read", "file__edit"],
  ));
  assert.equal(finalReply.name, "chat__reply");
  assert.match(finalReply.arguments.message, /now passes/);
}));

test("stage5 stop-hook repair fixture ignores shell completion before the edit", () => withProofEnv(() => {
  const rerun = parseToolCall(responseFor(
    [
      QUERY,
      "tool.output completed shell__run",
      "tool.failed shell__run",
      "# pass 0",
      "# fail 1",
      `tool.completed file__read path=${HELPER_PATH}`,
      "tool.completed file__edit applied=true",
    ].join("\n"),
    ["shell__run", "chat__reply", "file__read", "file__edit"],
  ));
  assert.equal(rerun.name, "shell__run");
  assert.deepEqual(rerun.arguments.args, ["--test", TEST_PATH]);
}));

test("stage5 stop-hook repair fixture proves stop hook before read guidance", () => withProofEnv(() => {
  const weakReply = parseToolCall(responseFor(
    [
      QUERY,
      "tool.failed shell__run exit_code=1",
      "# pass 0",
      "# fail 1",
      "no matching read observation. Use `file__read` before editing the governed file.",
    ].join("\n"),
    ["shell__run"],
  ));
  assert.equal(weakReply.name, "chat__reply");
  assert.match(weakReply.arguments.message, /complete/);
}));

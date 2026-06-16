import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

const repoRoot = process.cwd();

function read(relativePath) {
  return fs.readFileSync(path.join(repoRoot, relativePath), "utf8");
}

test("runtime daemon entrypoint delegates constants and HTTP helpers to focused modules", () => {
  const index = read("packages/runtime-daemon/src/index.mjs");
  const constants = read("packages/runtime-daemon/src/runtime-contract-constants.mjs");
  const httpUtils = read("packages/runtime-daemon/src/runtime-http-utils.mjs");
  const openAiCompat = read("packages/runtime-daemon/src/openai-compat-routes.mjs");
  const routeHandlers = read("packages/runtime-daemon/src/runtime-route-handlers.mjs");
  const recordProjections = read("packages/runtime-daemon/src/runtime-record-projections.mjs");

  assert.match(index, /from "\.\/runtime-contract-constants\.mjs"/);
  assert.match(index, /from "\.\/runtime-http-utils\.mjs"/);
  assert.match(index, /from "\.\/openai-compat-routes\.mjs"/);
  assert.match(index, /from "\.\/runtime-route-handlers\.mjs"/);
  assert.match(index, /from "\.\/runtime-record-projections\.mjs"/);
  assert.doesNotMatch(index, /const RUN_EVENT_TO_TTI_EVENT = \{/);
  assert.doesNotMatch(index, /async function readBody\(request\)/);
  assert.doesNotMatch(index, /async function handleOpenAiCompatibilityRoute/);
  assert.doesNotMatch(index, /async function handleModelMountingNativeRoute/);
  assert.doesNotMatch(index, /async function handleThreadRoute/);
  assert.doesNotMatch(index, /async function handleRunRoute/);
  assert.doesNotMatch(index, /function runtimeTaskRecord\(\{/);
  assert.doesNotMatch(index, /function runtimeBridgeRunRecord/);
  assert.doesNotMatch(index, /function runtimeChecklistRecord/);
  assert.match(constants, /export const RUN_EVENT_TO_TTI_EVENT = \{/);
  assert.match(constants, /export const COMPUTER_USE_CONTROL_TOOL_IDS = new Set/);
  assert.match(httpUtils, /export async function readBody/);
  assert.match(httpUtils, /export function writeError/);
  assert.match(openAiCompat, /export async function handleOpenAiCompatibilityRoute/);
  assert.doesNotMatch(openAiCompat, /nativeInvocationResponse/);
  assert.match(routeHandlers, /export function createRuntimeRouteHandlers/);
  assert.match(routeHandlers, /async function handleModelMountingNativeRoute/);
  assert.match(routeHandlers, /async function handleThreadRoute/);
  assert.match(routeHandlers, /async function handleRunRoute/);
  assert.match(recordProjections, /export function createRuntimeRecordProjections/);
  assert.match(recordProjections, /function runtimeTaskRecord\(\{/);
  assert.doesNotMatch(recordProjections, /function runtimeBridgeRunRecord/);
  assert.match(recordProjections, /function runtimeChecklistRecord/);
});

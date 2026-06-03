import { createRequire } from "node:module";
import test from "node:test";
import assert from "node:assert/strict";

const require = createRequire(import.meta.url);
const { createInitialStudioRuntimeProjection } = require("./projection-state.js");

test("initial Studio projection keeps daemon-owned product defaults", () => {
  const projection = createInitialStudioRuntimeProjection({
    approvalId: "approval.inline",
    executionMode: "agent",
    permissionMode: "suggest",
    policyLeaseId: "approval.policy",
    runtimeProfile: "runtime_service",
  });

  assert.equal(projection.schemaVersion, "ioi.agent-studio.operational-chat.projection.v1");
  assert.equal(projection.status, "idle");
  assert.equal(projection.executionMode, "agent");
  assert.equal(projection.runtimeProfile, "runtime_service");
  assert.equal(projection.modelRoute, "route.local-first");
  assert.equal(projection.approvalId, "approval.inline");
  assert.equal(projection.hunkApprovalId, "approval.inline");
  assert.equal(projection.policyLeaseId, "approval.policy");
  assert.equal(projection.runtimeCockpit.projectionOnlyRuntimeRejected, true);
  assert.equal(projection.runtimeUx.tracingSeparationAchieved, true);
  assert.match(projection.turns[0].content, /daemon-owned sessions/);
  assert.equal(projection.timeline[0].label, "Studio surface opened");
  assert.equal(projection.terminal[0].label, "No terminal job running");
});

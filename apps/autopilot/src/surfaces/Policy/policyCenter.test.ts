import assert from "node:assert/strict";
import test from "node:test";

import {
  buildAuthorityProfileProjection,
  createDefaultShieldPolicyState,
  updateConnectorOverride,
  type ShieldPolicyState,
} from "./policyCenter";

test("authority profile projection summarizes the default policy matrix", () => {
  const projection = buildAuthorityProfileProjection(
    createDefaultShieldPolicyState(),
  );

  assert.equal(projection.profileId, "guided_default");
  assert.equal(projection.label, "Guided default");
  assert.equal(projection.tone, "ready");
  assert.deepEqual(
    projection.allowedFamilies.map((family) => family.id),
    ["reads"],
  );
  assert.deepEqual(
    projection.gatedFamilies.map((family) => family.id),
    ["writes", "admin", "automations"],
  );
  assert.deepEqual(
    projection.deniedFamilies.map((family) => family.id),
    ["expert"],
  );
  assert.equal(projection.receipts.retention, "local_only");
});

test("authority profile projection flags broad expert posture as warning", () => {
  const state: ShieldPolicyState = {
    ...createDefaultShieldPolicyState(),
    global: {
      reads: "auto",
      writes: "auto",
      admin: "auto",
      expert: "auto",
      automations: "confirm_on_create",
      dataHandling: "local_redacted",
    },
  };

  const projection = buildAuthorityProfileProjection(state);

  assert.equal(projection.profileId, "expert");
  assert.equal(projection.tone, "warning");
  assert.deepEqual(
    projection.allowedFamilies.map((family) => family.id),
    ["reads", "writes", "admin", "expert"],
  );
  assert.equal(projection.receipts.label, "Local with redacted export");
});

test("authority profile projection respects connector override state", () => {
  const state = updateConnectorOverride(
    createDefaultShieldPolicyState(),
    "google-workspace",
    {
      inheritGlobal: false,
      writes: "auto",
      admin: "block",
      dataHandling: "local_redacted",
    },
  );

  const projection = buildAuthorityProfileProjection(state, "google-workspace");

  assert.equal(projection.profileId, "custom");
  assert.equal(projection.scopeLabel, "Connector override projection");
  assert.deepEqual(
    projection.allowedFamilies.map((family) => family.id),
    ["reads", "writes"],
  );
  assert.deepEqual(
    projection.deniedFamilies.map((family) => family.id),
    ["admin", "expert"],
  );
  assert.equal(projection.receipts.retention, "local_redacted");
});

console.log("policyCenter.test.ts: ok");

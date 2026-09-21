"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { SCHEMA, renderChallengeNotification } = require("./challenge-notification.js");

const notification = {
  schema_version: SCHEMA, run_id: "pop_x1", kind: "provider_operation", state: "awaiting_operator_decision", byte_derived: true,
  policy_hash: `sha256:${"a".repeat(64)}`, request_hash: `sha256:${"b".repeat(64)}`, audience: "ab".repeat(32), target_scope: "scope:hypervisor.live-route.hypervisor-provider-op",
  required_scopes: ["provider.provision"], receipt_ref: "agentgres://provider-receipt/prc_x", preimage_sha256: `sha256:${"c".repeat(64)}`,
  operation: { op: "create", environment_ref: "env-x", provider_id: "pacc_x" },
  source_adapter: { adapter_kind: "ide_extension", editor_service_ref: "environment_service:editor_x", access_lease_ref: "lease_x", session_ref: null },
  decision: { card_url: "http://127.0.0.1:4173/work/sessions", approve_url: "http://127.0.0.1:4173/__ioi/runs/pop_x1/approve", deny_url: "http://127.0.0.1:4173/__ioi/runs/pop_x1/deny", timeline_url: "http://127.0.0.1:4173/__ioi/agent-runs/pop_x1/timeline" },
  message: "Hypervisor blocked create on env-x pending your approval — decide on the App's approval card",
};

test("a notification renders one message and the actions that open the App's decision, never an in-editor approval", () => {
  const r = renderChallengeNotification(notification);
  assert.equal(r.ok, true);
  assert.equal(r.message, notification.message);
  assert.deepEqual(r.actions.map((a) => a.title), ["Open approval", "View timeline"]);
  assert.equal(r.actions[0].url, notification.decision.card_url);
  assert.ok(!r.actions.some((a) => /approve|deny/iu.test(a.title)), "no approve/deny action lives in the editor");
  assert.equal(r.detail.request_hash, notification.request_hash);
  assert.equal(r.detail.byte_derived, true);
});

test("a notification of another schema, or none, renders nothing actionable", () => {
  assert.deepEqual(renderChallengeNotification({ schema_version: "other" }).actions, []);
  assert.equal(renderChallengeNotification(null).ok, false);
});

test("the renderer carries no facet, grant or key even when a malformed notification tries to smuggle one", () => {
  const smuggled = { ...notification, facets: [{ key: "deposit_usd", raw: "1.0" }], wallet_approval_grant: { approver_sig: "x" } };
  const r = renderChallengeNotification(smuggled);
  const text = JSON.stringify(r);
  assert.ok(!text.includes("deposit_usd") && !text.includes("approver_sig") && !text.includes("wallet_approval_grant"));
});

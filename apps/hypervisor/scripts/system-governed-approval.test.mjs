// R-240 journey WP-A: the governed ladder's typed forms and the Limits tab, as pure renders.
//
//   node --test apps/hypervisor/scripts/system-governed-approval.test.mjs
import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { ladderExpectations, TYPED_LADDER_FIELDS, TYPED_LIFECYCLE_GAP } from "./system-genesis-surfaces.mjs";
import { renderGovernanceLimits } from "./governance-limits.mjs";

// The daemon's own JCS-sha256 domains (system_sequence_zero_routes.rs / the journey gate's helpers).
function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(",")}}`;
  return JSON.stringify(value);
}
const sha = (material) => `sha256:${createHash("sha256").update(canonicalJson(material)).digest("hex")}`;

test("each ladder step's expected roots come from the daemon's read of the step before, under the daemon's own domains", () => {
  const record = { system_id: "system://acme/one", proposal_root: "sha256:1", nested: { b: 2, a: [1, "x"] } };
  const receipt = { receipt_ref: "receipt://asgr_1", z: true, a: null };
  const materialization = { materialization_id: "m1", roots: { y: 1, x: 2 } };
  const materializationReceipt = { receipt_ref: "receipt://aszm_1" };
  const init = {
    lifecycle_receipt: { bound_facts: { proposal_root: "sha256:p", decision_root: "sha256:d" } },
    autonomous_system_activation_state: { activation_state_root: "sha256:s", transition_root: "sha256:t", transition_receipt_root: "sha256:r" },
  };
  const e = ladderExpectations({
    admission: { status: 200, body: { autonomous_system_genesis_admission: record, autonomous_system_genesis_receipt: receipt } },
    sequenceZero: { status: 200, body: { autonomous_system_sequence_zero_materialization: materialization, autonomous_system_sequence_zero_materialization_receipt: materializationReceipt } },
    initialize: { status: 200, body: init },
  });
  assert.deepEqual(Object.keys(e["sequence-zero-materialization"]), TYPED_LADDER_FIELDS["sequence-zero-materialization"]);
  assert.equal(e["sequence-zero-materialization"].expected_genesis_admission_record_root, sha({ domain: "ioi.autonomous-system-genesis-admission-record-jcs-sha256.v1", value: record }));
  assert.equal(e["sequence-zero-materialization"].expected_genesis_admission_receipt_root, sha({ domain: "ioi.autonomous-system-genesis-admission-receipt-jcs-sha256.v1", value: receipt }));
  assert.equal(e.initialize.expected_sequence_zero_materialization_root, sha({ domain: "ioi.autonomous-system-sequence-zero-materialization-artifact-jcs-sha256.v1", artifact: materialization }));
  assert.equal(e.initialize.expected_sequence_zero_materialization_receipt_root, sha({ domain: "ioi.autonomous-system-sequence-zero-materialization-receipt-artifact-jcs-sha256.v1", artifact: materializationReceipt }));
  assert.deepEqual(e.activate, {
    expected_initialize_proposal_root: "sha256:p", expected_initialize_decision_root: "sha256:d", expected_initialize_state_root: "sha256:s",
    expected_initialize_transition_root: "sha256:t", expected_initialize_receipt_root: "sha256:r",
  });
});

test("a step whose predecessor is not admitted has no expected roots — the field stays empty, never guessed", () => {
  const refused = { status: 404, body: { error: { code: "system_lifecycle_not_found" } } };
  const e = ladderExpectations({ admission: refused, sequenceZero: refused, initialize: refused });
  for (const step of Object.keys(TYPED_LADDER_FIELDS)) for (const name of TYPED_LADDER_FIELDS[step]) assert.equal(e[step][name], null, `${step}.${name}`);
  assert.match(TYPED_LIFECYCLE_GAP, /^typed lifecycle forms \(/u);
});

const limitsTab = (limits) => renderGovernanceLimits({ checkpoints: [], records: [], owner: "org://acme", signedOut: false, readError: null, limits }, { query: new URLSearchParams("tab=limits") });

test("the Limits tab names the authority-node gap only on a deployment whose daemon can record no limit", () => {
  const none = limitsTab({ connectors: [{ connector_id: "conn_a", name: "A" }], decidable: false });
  assert.match(none, /data-named-gap="system_limits_authority_node_absent"/u);
  assert.doesNotMatch(none, /data-limits-standing-list/u);
  const deployment = limitsTab({
    decidable: true,
    connectors: [
      { connector_id: "conn_a", name: "A", standing_lease: { status: "active", bounds: { max_usages: 5, max_cumulative_spend_microusd: 1_000_000, operations: ["session_execute"], expires_at_ms: 1_790_000_000_000 } } },
      { connector_id: "conn_b", name: "B" },
    ],
  });
  assert.doesNotMatch(deployment, /system_limits_authority_node_absent/u);
  assert.match(deployment, /data-limits-standing="deployment"/u);
  assert.match(deployment, /data-limits-connection="connector:conn_a" data-standing-lease-status="active"/u);
  assert.match(deployment, /5 uses · budget \$1\.0000 · session_execute/u);
  assert.match(deployment, /data-limits-connection="connector:conn_b" data-standing-lease-status="none"/u);
  const unread = limitsTab({ readError: { code: "request_principal_required", message: "whether this deployment can record limits could not be read" } });
  assert.match(unread, /data-limits-standing-unavailable="request_principal_required"/u);
  assert.doesNotMatch(unread, /system_limits_authority_node_absent/u, "an unread posture is never claimed");
});

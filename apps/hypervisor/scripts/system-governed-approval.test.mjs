// R-240 journey WP-A: the governed ladder's typed forms, the Limits tab and a System's limits, as pure renders (the last over a stub daemon).
//
//   node --test apps/hypervisor/scripts/system-governed-approval.test.mjs
import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import http from "node:http";
import { headExpectations, ladderExpectations, PROTECTED_TRANSITION_OPS, renderOutcome, systemLimits, SYSTEM_DATA_ATTACHMENT_CONTRACT, SYSTEM_DATA_ATTACHMENT_CONTRACT_V1, TYPED_HEAD_FIELDS, TYPED_LADDER_FIELDS, TYPED_LIFECYCLE_GAP } from "./system-genesis-surfaces.mjs";
import { readFileSync } from "node:fs";
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

// A stub daemon answering the four reads Govern mode's limits make, as the caller: the System's
// attachments under each contract generation, the connectors plane and the standing-envelope posture.
async function withStubDaemon(routes, run) {
  const server = http.createServer((req, res) => {
    const body = routes[req.url];
    res.writeHead(body ? 200 : 404, { "content-type": "application/json" });
    res.end(JSON.stringify(body || { ok: false, error: { code: "not_found" } }));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try { return await run(`http://127.0.0.1:${server.address().port}`); } finally { server.close(); }
}

test("a System's limits read both attachment generations: a v2 connector subject maps to its own connector's standing envelope", async () => {
  const system = "system://acme/one";
  const records = (contract) => `/v1/hypervisor/autonomous-systems/${encodeURIComponent(system)}/records?contract_id=${encodeURIComponent(contract)}`;
  const attached = (kind, ref, version) => ({ head: "sha256:h", current: { schema_version: `ioi.hypervisor.system-data-attachment.${version}`, subject_kind: kind, subject_ref: ref, status: "attached", system_binding: { system_id: system } } });
  const html = await withStubDaemon({
    [records(SYSTEM_DATA_ATTACHMENT_CONTRACT)]: { ok: true, records: [attached("connector", "connector:conn_walk", "v2")] },
    [records(SYSTEM_DATA_ATTACHMENT_CONTRACT_V1)]: { ok: true, records: [attached("connection", "connection://provider/conn_gh/user:1", "v1"), attached("ontology", "ontology://acme/x", "v1")] },
    "/v1/hypervisor/connectors": { ok: true, connectors: [
      { connector_id: "conn_walk", name: "cx-walk", standing_lease: { status: "active", bounds: { max_usages: 5, max_cumulative_spend_microusd: 1_000_000, operations: ["session_execute"], expires_at_ms: 1_790_000_000_000 } } },
      { connector_id: "conn_gh", name: "GitHub" },
    ] },
    "/v1/hypervisor/authority/standing-envelopes": { ok: true, decidable: true, envelopes: [] },
  }, (url) => systemLimits(url, system, "acme/one"));
  assert.equal(SYSTEM_DATA_ATTACHMENT_CONTRACT, "schema://ioi/components/hypervisor/system-data-attachment/v2");
  assert.match(html, /data-system-limit-connection="connector:conn_walk" data-standing-lease-status="active"/u);
  assert.match(html, /cx-walk[\s\S]*5 uses · budget \$1\.0000 · session_execute/u);
  assert.match(html, /data-system-limit-connection="connection:\/\/provider\/conn_gh\/user:1" data-standing-lease-status="none"/u, "v1's records still count");
  assert.doesNotMatch(html, /ontology:\/\/acme\/x/u, "only connections carry limits");
  assert.match(html, /data-system-limits-authority="deployment"/u);
  assert.match(html, /data-system-limits-bound-runs="absent"/u);
  assert.doesNotMatch(html, /SystemDataAttachment v2\)/u, "the connector gap is closed");
});

// ---- R-240, authority follow-ups: re-ask, a pasted grant's settlement, a grant for other coordinates ----
const OLD = "wac_" + "0".repeat(32);
const NEXT = "wac_" + "1".repeat(32);
const OTHER = "wac_" + "2".repeat(32);
const RESUBMIT = { action: "/__ioi/systems/asg_x/initialize", declaration: "{}", declarationField: "declaration" };

test("a resume refused because its approval's grant expired unused offers the operator's card for the challenge the daemon asked again — nothing ran", () => {
  const out = renderOutcome({ status: 410, body: { error: {
    code: "approval_ref_expired", message: "this approval's one-use grant expired unused …",
    approval_ref: `wallet-approval-challenge://${OLD}`,
    approval_challenge: { challenge_id: NEXT, challenge_state: "pending", supersedes: OLD, decidable: true, request_hash: "sha256:" + "d".repeat(64) },
  } } }, { resubmit: RESUBMIT, actionLabel: "initialize" });
  assert.match(out, /<h2>Asked again — approve the new challenge<\/h2>/u);
  assert.match(out, new RegExp(`data-approval-reasked="${NEXT}"`, "u"));
  assert.match(out, new RegExp(`which supersedes <code data-approval-supersedes>${OLD}</code>`, "u"));
  assert.match(out, new RegExp(`data-approval-card="1" data-approval-challenge="${NEXT}"`, "u"), "the card is the successor's");
  assert.match(out, new RegExp(`name="approval_challenge_id" value="${NEXT}"`, "u"));
  assert.match(out, /Nothing ran\./u);
  // A refusal with no parked challenge stays the verbatim refusal.
  const plain = renderOutcome({ status: 410, body: { error: { code: "approval_ref_expired", message: "expired" } } }, { resubmit: RESUBMIT });
  assert.match(plain, /<h2>Daemon refusal \(HTTP 410\)<\/h2>/u);
  assert.doesNotMatch(plain, /data-approval-card=/u);
});

test("a grant for other coordinates: the refusal names the challenge parked for this step as left pending, with its card", () => {
  const out = renderOutcome({ status: 403, body: { error: {
    code: "system_lifecycle_host_authority_required", message: "grant binding mismatch",
    approval: { policy_hash: "sha256:" + "a".repeat(64), request_hash: "sha256:" + "b".repeat(64), effect_hash: "sha256:" + "c".repeat(64) },
    approval_challenge_pending: { challenge: { challenge_id: OLD, challenge_state: "pending", decidable: true }, reason: "the presented grant does not bind this step's coordinates, so the challenge parked for them is left pending" },
  } } }, { resubmit: RESUBMIT });
  assert.match(out, new RegExp(`data-approval-challenge-pending="${OLD}">the presented grant does not bind this step's coordinates, so the challenge parked for them is left pending\\.`, "u"));
  assert.match(out, new RegExp(`data-approval-card="1" data-approval-challenge="${OLD}"`, "u"));
});

test("a committed step lists what it did with this step's parked challenges: completed by the grant it ran under, or left pending — each linked, with the daemon's reason", () => {
  const out = renderOutcome({ status: 200, body: {
    operation: "initialize", autonomous_system_chain: { status: "initialized", latest_sequence: 1 },
    approval_challenges: [
      { challenge_id: OLD, challenge_state: "consumed", settled: true, reason: "this step ran under the presented grant g for exactly the coordinates this challenge was parked for" },
      { challenge_id: OTHER, challenge_state: "pending", settled: false, reason: "this challenge was parked for this step with other coordinates" },
      { challenge_id: "not-a-challenge", settled: true },
    ],
  } });
  assert.match(out, /data-approval-challenges="1"/u);
  assert.match(out, new RegExp(`data-approval-challenge-note="${OLD}" data-approval-challenge-settled="1"><a href="/__ioi/authority/challenges/${OLD}"><code>${OLD}</code></a> — completed by the grant this step ran under: this step ran under the presented grant g`, "u"));
  assert.match(out, new RegExp(`data-approval-challenge-note="${OTHER}" data-approval-challenge-settled="0">.*— left pending: this challenge was parked for this step with other coordinates`, "u"));
  assert.doesNotMatch(out, /not-a-challenge<\/code><\/a>/u, "only daemon challenge ids are linked");
  const none = renderOutcome({ status: 200, body: { operation: "initialize", autonomous_system_chain: { status: "initialized", latest_sequence: 1 } } });
  assert.doesNotMatch(none, /data-approval-challenges=/u);
});

test("the protected transitions are typed: their request is exactly the two head roots, prefilled from the daemon's projection; an absent or malformed root stays empty, never guessed", () => {
  assert.deepEqual(TYPED_HEAD_FIELDS.transitions, ["expected_chain_head_root", "expected_predecessor_state_root"]);
  const chain = "sha256:" + "a".repeat(64), state = "sha256:" + "b".repeat(64);
  assert.deepEqual(headExpectations({ canonical_roots: { chain_root: chain, latest_state_root: state } }), { expected_chain_head_root: chain, expected_predecessor_state_root: state });
  assert.deepEqual(headExpectations(null), { expected_chain_head_root: null, expected_predecessor_state_root: null });
  assert.deepEqual(headExpectations({ canonical_roots: { chain_root: "sha256:short", latest_state_root: 7 } }), { expected_chain_head_root: null, expected_predecessor_state_root: null });
  // The daemon's own request shape (validate_protected_request) admits exactly these two roots and the grant.
  const rust = readFileSync(new URL("../../../crates/node/src/bin/hypervisor_daemon_routes/system_protected_transition_routes.rs", import.meta.url), "utf8");
  const allowed = /fn validate_protected_request[\s\S]*?const ALLOWED: &\[&str\] = &\[([\s\S]*?)\];/u.exec(rust)[1].match(/"([a-z_]+)"/gu).map((q) => q.slice(1, -1));
  assert.deepEqual(allowed.filter((name) => name !== "wallet_approval_grant"), TYPED_HEAD_FIELDS.transitions);
  // The op list is the daemon's canonical table (ProtectedTransitionOp::ALL), in order.
  const types = readFileSync(new URL("../../../crates/types/src/app/system_lifecycle_transitions.rs", import.meta.url), "utf8");
  const table = /impl ProtectedTransitionOp \{[\s\S]*?pub fn as_str\(self\) -> &'static str \{\s*match self \{([\s\S]*?)\}/u.exec(types)[1].match(/=> "([a-z_]+)"/gu).map((m) => m.slice(4, -1));
  assert.deepEqual([...PROTECTED_TRANSITION_OPS], table);
});

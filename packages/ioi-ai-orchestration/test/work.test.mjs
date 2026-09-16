// R-177 S4b — work objects composed over the orchestration: the pure coordinate helpers are pinned
// against the registered v4 fixtures, and the actor rules are driven over a fake orchestration.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { WORK_CONTRACTS, Work, coordinateOf, delegationActor, delegationRef, parseDelegationRef, participationActor, verifyFrozenCoordinates } from "../dist/index.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const schemas = path.resolve(here, "../../../docs/architecture/_meta/schemas");
const readJson = (rel) => JSON.parse(fs.readFileSync(path.join(schemas, rel), "utf8"));

test("delegation refs round-trip and a malformed one parses to null", () => {
  assert.equal(delegationRef("thread_1", "agent_2"), "delegation://thread_1/agent_2");
  assert.deepEqual(parseDelegationRef("delegation://thread_1/agent_2"), { thread_id: "thread_1", subagent_id: "agent_2" });
  assert.equal(parseDelegationRef("delegation://thread_1"), null);
  assert.equal(parseDelegationRef("participant-lease://x"), null);
  assert.deepEqual(delegationActor("t", "a"), { participation_ref: null, delegation_ref: "delegation://t/a" });
  assert.deepEqual(participationActor("participation-request://x/1"), { participation_ref: "participation-request://x/1", delegation_ref: null });
});

test("a frozen coordinate is the served record's binding: ref, orchestration and payload root; verification catches every drift", () => {
  const claim = readJson("fixtures/work-claim-v4/positive-delegation-claim.json");
  const coordinate = coordinateOf(claim, claim.work_claim_id);
  assert.deepEqual(coordinate, { record_ref: claim.work_claim_id, orchestration_ref: claim.system_binding.parent_scope_ref, control_hash: claim.system_binding.payload_root });
  assert.throws(() => coordinateOf({ work_claim_id: "x" }, "x"), (e) => e.code === "work_coordinate_unbound");
  const attempt = readJson("fixtures/attempt-v4/positive-delegation-attempt.json");
  const record = { ...attempt, bound_coordinates: { goal_run: null, frontier_item: null, work_claim: coordinate } };
  assert.deepEqual(verifyFrozenCoordinates({ ...record, orchestration_ref: claim.system_binding.parent_scope_ref }, { work_claim: { record: claim, ref: claim.work_claim_id } }), { ok: true, findings: [] });
  assert.ok(verifyFrozenCoordinates({ ...record, orchestration_ref: claim.system_binding.parent_scope_ref, bound_coordinates: { work_claim: { ...coordinate, control_hash: `sha256:${"9".repeat(64)}` } } }, { work_claim: { record: claim, ref: claim.work_claim_id } }).findings.some((f) => /payload root/u.test(f)));
  assert.ok(verifyFrozenCoordinates({ ...record, orchestration_ref: "app-scope://other" }, { work_claim: { record: claim, ref: claim.work_claim_id } }).findings.some((f) => /another orchestration/u.test(f)));
  assert.ok(verifyFrozenCoordinates({ ...record, orchestration_ref: claim.system_binding.parent_scope_ref }, {}).findings.some((f) => /no served record/u.test(f)));
});

test("the actor rules: one actor exactly, a delegation of THIS thread the kernel lists, a participation accepted and not exited", async () => {
  const accepted = readJson("fixtures/orchestration-participation-request-v2/positive-accepted-hosted.json");
  const exited = readJson("fixtures/orchestration-participation-request-v2/positive-exited.json");
  const submitted = readJson("fixtures/orchestration-participation-request-v2/positive-submitted.json");
  const chains = { [accepted.participation_request_id]: accepted, "participation-request://x/exited": exited, "participation-request://x/submitted": submitted };
  const fake = {
    thread_id: "thread_root", scope_ref: "app-scope://ioi-ai/objective/demo", system_id: "system://ioi/orchestration/demo",
    async delegations() { return { subagents: [{ subagent_id: "agent_listed" }] }; },
    async recordChain(contract, id) { const c = chains[id]; if (!c) { const e = new Error("scope"); e.status = 403; throw e; } return { current: c, head: "sha256:h", revisions: [c], admissions: [] }; },
  };
  const work = new Work(fake);
  assert.equal(WORK_CONTRACTS.claim, "schema://ioi/applications/ioi-ai/work-claim/v4");
  await assert.rejects(work.resolveActor({ participation_ref: null, delegation_ref: null }), (e) => e.code === "work_actor_required");
  await assert.rejects(work.resolveActor({ participation_ref: accepted.participation_request_id, delegation_ref: "delegation://thread_root/agent_listed" }), (e) => e.code === "work_actor_ambiguous");
  await assert.rejects(work.resolveActor(delegationActor("thread_other", "agent_listed")), (e) => e.code === "work_actor_delegation_foreign_thread");
  await assert.rejects(work.resolveActor(delegationActor("thread_root", "agent_unlisted")), (e) => e.code === "work_actor_delegation_unknown");
  await assert.rejects(work.resolveActor({ participation_ref: null, delegation_ref: "delegation://broken" }), (e) => e.code === "work_actor_delegation_malformed");
  assert.deepEqual(await work.resolveActor(delegationActor("thread_root", "agent_listed")), delegationActor("thread_root", "agent_listed"));
  assert.deepEqual(await work.resolveActor(participationActor(accepted.participation_request_id)), participationActor(accepted.participation_request_id));
  await assert.rejects(work.resolveActor(participationActor("participation-request://x/exited")), (e) => e.code === "work_actor_participation_exited");
  await assert.rejects(work.resolveActor(participationActor("participation-request://x/submitted")), (e) => e.code === "work_actor_participation_not_accepted");
  await assert.rejects(work.resolveActor(participationActor("participation-request://x/absent")), (e) => e.code === "work_actor_participation_unknown");
});

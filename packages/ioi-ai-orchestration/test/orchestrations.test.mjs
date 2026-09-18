// R-185 S4c-1 — the ioi.ai application's orchestrations recorded under a System: the composer is
// driven over a fake substrate that behaves like the seam (exact heads, derived binding, chain,
// list) and the kernel's thread routes, and the record it admits is pinned against the REGISTERED
// contract's member set so the composer and the schema cannot drift apart unnoticed.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import {
  GOVERNANCE_LIST_REFS,
  GOVERNANCE_NULLABLE_REFS,
  GOVERNANCE_SCALAR_REFS,
  ORCHESTRATION_CONTRACT,
  ORCHESTRATION_MEMBER_BOUND,
  ORCHESTRATION_SCOPE_PREFIX,
  Orchestrations,
  orchestrationIdTail,
  orchestrationScope,
  threadIdOf,
} from "../dist/index.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const schemas = path.resolve(here, "../../../docs/architecture/_meta/schemas");
const readJson = (rel) => JSON.parse(fs.readFileSync(path.join(schemas, rel), "utf8"));
const schema = readJson("orchestration.v1.schema.json");
const registry = readJson("architecture-contract-registry.v1.json");

const SYSTEM = "system://ioi/orchestration/test";
const OWNER = "org://local";
const NOW = "2026-09-17T12:00:00Z";

function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(",")}}`;
}
const sha = (text) => `sha256:${createHash("sha256").update(text).digest("hex")}`;

function refusal(status, code) {
  const error = new Error(code);
  error.status = status;
  error.details = { daemon: { error: { code } } };
  return error;
}

/** A fake of exactly what the composer drives: /v1/threads, subagents, and the S1 seam's three routes. */
function fakeSubstrate() {
  const threads = new Map();
  const subagents = new Map();
  const chains = new Map(); // resource_ref -> [{ record, head, admission }]
  const calls = [];
  const resource = (systemId, contract, object) => `${systemId}/${contract}/${object}`;
  const goalRuns = new Map([["gr_one", { goal_run_id: "gr_one", goal_ref: "goal://gr_one", orchestration_ref: null }], ["gr_two", { goal_run_id: "gr_two", goal_ref: "goal://gr_two", orchestration_ref: null }]]);
  return {
    calls,
    threads,
    chains,
    async createThread(input) {
      calls.push(["createThread", input]);
      const thread = { thread_id: `thread_${threads.size + 1}`, status: "active", title: input.goal ?? "" };
      threads.set(thread.thread_id, thread);
      subagents.set(thread.thread_id, []);
      return thread;
    },
    async getThread(id) {
      calls.push(["getThread", id]);
      const thread = threads.get(id);
      if (!thread) throw refusal(404, "thread_not_found");
      return thread;
    },
    async spawnSubagent(threadId, input) {
      const record = { subagent_id: `agent_${(subagents.get(threadId) ?? []).length + 1}`, parent_thread_id: threadId, role: input.role ?? null, run_id: null, lifecycle_status: "queued" };
      subagents.get(threadId).push(record);
      return record;
    },
    async listSubagents(threadId) {
      calls.push(["listSubagents", threadId]);
      return { subagents: [...(subagents.get(threadId) ?? [])] };
    },
    async admitSystemRecord(systemId, input) {
      calls.push(["admitSystemRecord", systemId, input]);
      if (systemId !== SYSTEM) throw refusal(404, "system_record_system_absent");
      if ("system_binding" in input.record) throw refusal(422, "system_record_binding_authored");
      const carriers = Object.entries(input.record).filter(([k, v]) => k.endsWith("_id") && v === input.object_id);
      if (carriers.length !== 1) throw refusal(422, "system_record_identity_not_carried");
      const key = resource(systemId, input.contract_id, input.object_id);
      const chain = chains.get(key) ?? [];
      const head = chain.at(-1)?.head ?? null;
      if ((input.expected_head ?? null) !== head) throw refusal(409, "system_record_expected_head_conflict");
      const payload_root = sha(canonical(input.record));
      const record = {
        ...input.record,
        system_binding: { schema_version: "ioi.foundations.system-scoped-object-binding.v1", system_id: systemId, parent_scope_ref: input.parent_scope_ref, proposed_or_issued_by_ref: "user://stub", payload_root, created_at: NOW, updated_at: chain.length ? NOW : null },
      };
      const nextHead = sha(`${head ?? "genesis"}|${payload_root}`);
      const admission = { seq: chain.length, head: nextHead, contract_id: input.contract_id, idempotency_key: input.idempotency_key, receipt_ref: `receipt://event-stream/${chain.length}`, operation_ref: `agentgres://event-stream/${chain.length}` };
      chain.push({ record, head: nextHead, admission });
      chains.set(key, chain);
      return { ok: true, replayed: false, system_id: systemId, contract_id: input.contract_id, resource_ref: key, record, admission, expected_head_for_successor: nextHead, receipt_ref: admission.receipt_ref, operation_ref: admission.operation_ref };
    },
    async listSystemRecords(systemId, contractId) {
      calls.push(["listSystemRecords", systemId, contractId]);
      const records = [...chains.entries()]
        .filter(([key]) => key.startsWith(`${systemId}/`) && (!contractId || key.startsWith(`${systemId}/${contractId}/`)))
        .map(([key, chain]) => ({ resource_ref: key, contract_id: chain.at(-1).admission.contract_id, current: chain.at(-1).record, head: chain.at(-1).head, revisions: chain.length }));
      return { ok: true, system_id: systemId, records, count: records.length };
    },
    async getSystemRecord(systemId, contractId, objectId) {
      calls.push(["getSystemRecord", systemId, contractId, objectId]);
      const chain = chains.get(resource(systemId, contractId, objectId));
      if (!chain) throw refusal(404, "system_record_absent");
      return { ok: true, current: chain.at(-1).record, revisions: chain.map((e) => e.record), admissions: chain.map((e) => e.admission), head: chain.at(-1).head };
    },
    async admitWorkReservation() {
      throw new Error("the orchestrations composer reserves nothing");
    },
    goalRuns,
    async stampGoalRunOrchestrationMembership(goalRunId, input) {
      calls.push(["stampGoalRunOrchestrationMembership", goalRunId, input]);
      if (goalRunId === "gr_absent") throw refusal(404, "goal_run_not_found");
      const run = goalRuns.get(goalRunId) ?? { goal_run_id: goalRunId, goal_ref: `goal://${goalRunId}`, orchestration_ref: null };
      goalRuns.set(goalRunId, run);
      if (run.orchestration_ref && input.orchestration_ref && run.orchestration_ref !== input.orchestration_ref) throw refusal(409, "goal_run_orchestration_membership_conflict");
      run.orchestration_ref = input.orchestration_ref;
      return { ok: true, goal_run: { ...run }, durable: true };
    },
  };
}

const governance = {
  stop_policy_ref: "policy://t/stop",
  visibility_policy_ref: "policy://t/visibility",
  participation_policy_ref: "policy://t/participation",
  privacy_policy_ref: "policy://t/privacy",
  contribution_policy_ref: "policy://t/contribution",
  cooperation_surplus_policy_ref: "policy://t/surplus",
  coordination_policy_ref: "policy://t/coordination",
  ordering_and_merge_policy_ref: "policy://t/ordering",
  conflict_and_failover_policy_ref: "policy://t/failover",
  constraint_refs: ["budget://t/monthly"],
  acceptance_criteria_refs: [],
  collaboration_terms_refs: [],
  artifact_license_rights_retention_and_export_policy_refs: [],
  ontology_profile_refs: [],
  scorecard_and_guardrail_refs: [],
  verifier_path_refs: [],
  resource_and_budget_refs: [],
  settlement_policy_ref: null,
  multi_party_collaboration_ref: null,
  not_a_governance_member: "dropped before admission",
};

function composer(substrate, ids = ["orc_one", "orc_two", "orc_three"]) {
  const queue = [...ids];
  return new Orchestrations(substrate, { system_id: SYSTEM, owner_ref: OWNER }, { now: () => NOW, mintId: () => queue.shift() ?? "orc_extra" });
}

test("the governance members the composer copies are exactly the registered contract's governance members", () => {
  const declared = [...GOVERNANCE_SCALAR_REFS, ...GOVERNANCE_LIST_REFS, ...GOVERNANCE_NULLABLE_REFS].sort();
  const identity = ["schema_version", "orchestration_id", "orchestration_ref", "system_binding", "owner_ref", "composed_by_ref", "thread_ref", "objective", "objective_ref", "mode", "coordination_topology", "member_goal_run_refs", "composed_at", "status"];
  const contractGovernance = schema.required.filter((member) => !identity.includes(member)).sort();
  assert.deepEqual(declared, contractGovernance);
  const row = registry.contracts.find((c) => c.contract_id === ORCHESTRATION_CONTRACT);
  assert.ok(row, "the orchestration contract is registered");
  assert.equal(row.evolution.successor_of, "schema://ioi/applications/ioi-ai/outcome-room/v2");
  assert.equal(ORCHESTRATION_MEMBER_BOUND, schema.properties.member_goal_run_refs.maxItems);
});

test("coordinates: the id tail, the scope derived from it, and the thread read from the record", () => {
  assert.equal(orchestrationIdTail("orchestration://orc_abc"), "orc_abc");
  assert.equal(orchestrationIdTail("orc_abc"), "orc_abc");
  assert.equal(orchestrationIdTail("outcome-room://or_abc"), null);
  assert.equal(orchestrationIdTail("orc_bad/path"), null);
  assert.equal(orchestrationScope("orc_abc"), `${ORCHESTRATION_SCOPE_PREFIX}orc_abc`);
  assert.equal(threadIdOf({ thread_ref: "thread://thread_9" }), "thread_9");
  assert.equal(threadIdOf({ thread_ref: "session://x" }), null);
});

test("compose creates the coordinating thread first, then admits the one record that makes the handle durable, shaped exactly as the contract requires", async () => {
  const substrate = fakeSubstrate();
  const orchestrations = composer(substrate);
  const composed = await orchestrations.compose({ objective: "  Coordinate one bounded outcome  ", objective_ref: "goal://gr_1", mode: "private_goal", composed_by_ref: "user://alice", governance });
  assert.equal(substrate.calls[0][0], "createThread");
  assert.equal(substrate.calls[0][1].goal, "Coordinate one bounded outcome");
  assert.equal(substrate.calls[1][0], "admitSystemRecord");
  const admit = substrate.calls[1][2];
  assert.equal(admit.owner_ref, OWNER);
  assert.equal(admit.contract_id, ORCHESTRATION_CONTRACT);
  assert.equal(admit.object_id, "orchestration://orc_one");
  assert.equal(admit.parent_scope_ref, `${ORCHESTRATION_SCOPE_PREFIX}orc_one`);
  assert.equal(admit.expected_head, null);
  assert.equal("not_a_governance_member" in admit.record, false, "only the contract's governance members are copied");
  const record = composed.orchestration;
  assert.deepEqual(Object.keys(record).sort(), [...schema.required].sort(), "the served record carries exactly the contract's required members");
  assert.equal(record.orchestration_ref, record.system_binding.parent_scope_ref);
  assert.equal(record.thread_ref, `thread://${composed.handle.thread_id}`);
  assert.equal(record.status, "open");
  assert.deepEqual(record.member_goal_run_refs, []);
  assert.equal(record.composed_at, NOW);
  assert.equal(record.coordination_topology, "hosted_admission");
  assert.match(composed.head, /^sha256:[0-9a-f]{64}$/u);
  await assert.rejects(orchestrations.compose({ objective: "   ", mode: "private_goal", composed_by_ref: "user://alice", governance }), (e) => e.code === "orchestration_objective_required");
  await assert.rejects(orchestrations.compose({ objective: "x", mode: "chat_room", composed_by_ref: "user://alice", governance }), (e) => e.code === "orchestration_mode_invalid");
});

test("list is the seam's list under the contract; open re-attaches a handle on the coordinates the record carries; the graph roots at that thread and scopes records to the orchestration", async () => {
  const substrate = fakeSubstrate();
  const orchestrations = composer(substrate);
  const first = await orchestrations.compose({ objective: "first", mode: "private_goal", composed_by_ref: "user://alice", governance });
  await orchestrations.compose({ objective: "second", mode: "permissioned_team", composed_by_ref: "user://alice", governance });
  const listed = await orchestrations.list();
  assert.deepEqual(listed.map((e) => e.orchestration.orchestration_id).sort(), ["orchestration://orc_one", "orchestration://orc_two"]);
  assert.ok(listed.every((e) => e.revisions === 1 && typeof e.head === "string"));
  const opened = await orchestrations.open("orc_one");
  assert.equal(opened.handle.thread_id, first.handle.thread_id);
  assert.equal(opened.handle.scope_ref, first.orchestration.orchestration_ref);
  assert.equal(opened.handle.owner_ref, OWNER);
  assert.equal(opened.head, first.head);
  assert.equal(opened.revisions.length, 1);
  assert.equal(opened.admissions.length, 1);
  await opened.handle.delegate({ prompt: "carry one unit", role: "worker" });
  const graph = await orchestrations.graph("orchestration://orc_one");
  assert.equal(graph.root, `thread:${first.handle.thread_id}`);
  assert.equal(graph.scope_ref, first.orchestration.orchestration_ref);
  assert.deepEqual(graph.nodes.map((n) => n.kind).sort(), ["record", "subagent", "system", "thread"]);
  assert.equal(graph.nodes.find((n) => n.kind === "record").detail.parent_scope_ref, first.orchestration.orchestration_ref, "the second orchestration's record is outside this scope and is not projected");
  const delegations = await orchestrations.delegations("orc_one");
  assert.equal(delegations.subagents.length, 1);
  await assert.rejects(orchestrations.open("orc_absent"), (e) => e.code === "orchestration_absent");
  await assert.rejects(orchestrations.open("or_room"), (e) => e.code === "orchestration_id_malformed");
});

test("membership is a revision on the exact head: attach and detach move the head, a stale head is the seam's refusal passed through untouched, and the composer's own rules refuse by name", async () => {
  const substrate = fakeSubstrate();
  const orchestrations = composer(substrate);
  const composed = await orchestrations.compose({ objective: "members", mode: "private_goal", composed_by_ref: "user://alice", governance });
  const attached = await orchestrations.attachGoalRun("orc_one", "goal://gr_1", composed.head);
  assert.deepEqual(attached.member_stamp, { goal_run_ref: "goal://gr_1", orchestration_ref: "app-scope://ioi-ai/orchestration/orc_one", stamped: true, durable: true, refusal: null });
  assert.equal(substrate.goalRuns.get("gr_1").orchestration_ref, "app-scope://ioi-ai/orchestration/orc_one");
  assert.equal(attached.action, "attach");
  assert.deepEqual(attached.orchestration.member_goal_run_refs, ["goal://gr_1"]);
  assert.notEqual(attached.head, composed.head);
  assert.equal(attached.orchestration.system_binding.parent_scope_ref, composed.orchestration.orchestration_ref, "a revision keeps the composition scope");
  await assert.rejects(orchestrations.attachGoalRun("orc_one", "goal://gr_2", composed.head), (e) => e.status === 409 && e.details.daemon.error.code === "system_record_expected_head_conflict");
  await assert.rejects(orchestrations.attachGoalRun("orc_one", "goal://gr_1", attached.head), (e) => e.code === "orchestration_goal_run_already_attached");
  await assert.rejects(orchestrations.attachGoalRun("orc_one", "outcome-room://or_1", attached.head), (e) => e.code === "orchestration_goal_run_ref_malformed");
  await assert.rejects(orchestrations.attachGoalRun("orc_one", "goal://gr_2", "latest"), (e) => e.code === "orchestration_expected_head_required");
  await assert.rejects(orchestrations.detachGoalRun("orc_one", "goal://gr_2", attached.head), (e) => e.code === "orchestration_goal_run_not_attached");
  const detached = await orchestrations.detachGoalRun("orc_one", "goal://gr_1", attached.head);
  assert.equal(detached.member_stamp.stamped, true);
  assert.equal(substrate.goalRuns.get("gr_1").orchestration_ref, null);
  assert.equal(detached.action, "detach");
  assert.deepEqual(detached.orchestration.member_goal_run_refs, []);
  const opened = await orchestrations.open("orc_one");
  assert.equal(opened.revisions.length, 3);
  assert.equal(opened.head, detached.head);
  assert.ok(substrate.calls.every(([name]) => name !== "admitWorkReservation"));
  const pending = await orchestrations.attachGoalRun("orc_one", "goal://gr_absent", detached.head);
  assert.deepEqual(pending.orchestration.member_goal_run_refs, ["goal://gr_absent"]);
  assert.equal(pending.member_stamp.stamped, false);
  assert.equal(pending.member_stamp.refusal.code, "goal_run_not_found");
  assert.equal(pending.member_stamp.refusal.status, 404);
  const cleared = await orchestrations.detachGoalRun("orc_one", "goal://gr_absent", pending.head);
  assert.equal(cleared.member_stamp.stamped, false);
  const reopened = await orchestrations.open("orc_one");
  assert.equal(reopened.revisions.length, 5);
  assert.deepEqual(reopened.orchestration.member_goal_run_refs, []);
});

test("the members bound is the contract's: the sixty-fifth attach is refused before the daemon", async () => {
  const substrate = fakeSubstrate();
  const orchestrations = composer(substrate);
  let { head } = await orchestrations.compose({ objective: "bound", mode: "private_goal", composed_by_ref: "user://alice", governance });
  for (let i = 0; i < ORCHESTRATION_MEMBER_BOUND; i += 1) ({ head } = await orchestrations.attachGoalRun("orc_one", `goal://gr_${i}`, head));
  const writes = substrate.calls.filter(([name]) => name === "admitSystemRecord").length;
  await assert.rejects(orchestrations.attachGoalRun("orc_one", "goal://gr_over", head), (e) => e.code === "orchestration_members_over_bound");
  assert.equal(substrate.calls.filter(([name]) => name === "admitSystemRecord").length, writes, "no admission was attempted");
});

test("status transitions: open and paused alternate, closed is terminal and refuses membership", async () => {
  const substrate = fakeSubstrate();
  const orchestrations = composer(substrate);
  let { head } = await orchestrations.compose({ objective: "status", mode: "private_goal", composed_by_ref: "user://alice", governance });
  await assert.rejects(orchestrations.transition("orc_one", "open", head), (e) => e.code === "orchestration_transition_noop");
  await assert.rejects(orchestrations.transition("orc_one", "archived", head), (e) => e.code === "orchestration_status_invalid");
  ({ head } = await orchestrations.transition("orc_one", "paused", head));
  ({ head } = await orchestrations.transition("orc_one", "open", head));
  const closed = await orchestrations.transition("orc_one", "closed", head);
  assert.equal(closed.orchestration.status, "closed");
  await assert.rejects(orchestrations.transition("orc_one", "open", closed.head), (e) => e.code === "orchestration_closed");
  await assert.rejects(orchestrations.attachGoalRun("orc_one", "goal://gr_1", closed.head), (e) => e.code === "orchestration_closed");
});

test("a served record whose root is not a thread cannot be re-attached", async () => {
  const substrate = fakeSubstrate();
  const orchestrations = composer(substrate);
  await orchestrations.compose({ objective: "broken root", mode: "private_goal", composed_by_ref: "user://alice", governance });
  const key = [...substrate.chains.keys()][0];
  substrate.chains.get(key).at(-1).record.thread_ref = "session://sess_1";
  await assert.rejects(orchestrations.open("orc_one"), (e) => e.code === "orchestration_root_unbound");
});

test("a seam reply that is not shaped as an admission is refused, never read as success", async () => {
  const substrate = fakeSubstrate();
  const honest = substrate.admitSystemRecord.bind(substrate);
  let calls = 0;
  substrate.admitSystemRecord = async (systemId, input) => {
    calls += 1;
    if (calls === 1) return honest(systemId, input);
    return { error: { code: "answered_two_hundred_with_a_refusal_body" } };
  };
  const orchestrations = composer(substrate);
  const composed = await orchestrations.compose({ objective: "unreadable", mode: "private_goal", composed_by_ref: "user://alice", governance });
  await assert.rejects(orchestrations.attachGoalRun("orc_one", "goal://gr_1", composed.head), (e) => e.code === "orchestration_admission_unreadable");
  const reopened = await orchestrations.open("orc_one");
  assert.deepEqual(reopened.orchestration.member_goal_run_refs, [], "nothing was claimed for the unreadable reply");
});

test("the registered positive fixtures are exactly the member set the composer serves", () => {
  for (const rel of ["fixtures/orchestration-v1/positive-open-hosted.json", "fixtures/orchestration-v1/positive-closed-with-member.json"]) {
    const fixture = readJson(rel);
    assert.deepEqual(Object.keys(fixture).sort(), [...schema.required].sort(), rel);
    assert.equal(fixture.orchestration_ref, fixture.system_binding.parent_scope_ref, rel);
    assert.equal(fixture.orchestration_ref, orchestrationScope(orchestrationIdTail(fixture.orchestration_id)), rel);
  }
});

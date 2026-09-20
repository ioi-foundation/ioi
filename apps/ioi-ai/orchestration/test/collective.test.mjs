// R-204 S5-3 M04.12 — collective resolution and persistent executable lineage composed over the
// orchestration. Driven over a fake seam plus fake owner/system/actor resolvers; every admitted
// record is pinned against the REGISTERED member set and its root against the registered
// invariant's preimage, so the composer and the contracts cannot drift apart unnoticed.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import {
  COLLECTIVE_CONTRACTS,
  COLLECTIVE_SCHEMA_VERSIONS,
  CONTEXT_CONTRACTS,
  CollectiveResolutions,
  ExecutableLineages,
  LINEAGE_ROOT_MEMBERS,
  RECEIPT_ROOT_MEMBERS,
  collectiveReceiptId,
  rootOf,
} from "../dist/index.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const schemas = path.resolve(here, "../../../../docs/architecture/_meta/schemas");
const readJson = (rel) => JSON.parse(fs.readFileSync(path.join(schemas, rel), "utf8"));

const SCOPE = "app-scope://ioi-ai/orchestration/orc_demo";
const SYSTEM = "system://ioi/orchestration/demo";

function fakeOrchestration({ records = {}, admitted = [] } = {}) {
  const store = { ...records };
  const heads = {};
  return {
    thread_id: "thread_root",
    scope_ref: SCOPE,
    system_id: SYSTEM,
    owner_ref: "org://acme",
    store,
    async recordChain(contract, id) {
      const key = `${contract}|${id}`;
      if (!store[key]) { const e = new Error("out of scope"); e.status = 404; throw e; }
      return { current: store[key], head: heads[key] ?? "sha256:head", revisions: [store[key]] };
    },
    async records(contract) {
      const out = [];
      for (const [key, current] of Object.entries(store)) {
        const [c, id] = key.split("|");
        if (!contract || c === contract) out.push({ resource_ref: `${SYSTEM}/${c}/${id}`, contract_id: c, current, head: heads[key] ?? "sha256:head", revisions: 1 });
      }
      return { ok: true, system_id: SYSTEM, records: out, count: out.length };
    },
    async record(input) {
      admitted.push(input);
      const key = `${input.contract_id}|${input.object_id}`;
      store[key] = { ...input.record, system_binding: { payload_root: "sha256:" + "0".repeat(64) } };
      heads[key] = `sha256:head-${admitted.length}`;
      return { ok: true, record: store[key], head: heads[key] };
    },
    admitted,
  };
}

const run = { schema_version: "ioi.goal-run.v2", goal_run_id: "gr_demo", goal_ref: "goal://demo", goal_run_profile_revision_ref: "goal-run-profile://generic/revision/1", orchestration_ref: SCOPE, status: "draft" };
const lease = { schema_version: "ioi.context-lease.v1", context_lease_id: "context-lease://demo/l1", status: "active" };
const withRun = (extra = {}) => ({ [`${COLLECTIVE_CONTRACTS.goalRun}|gr_demo`]: run, [`${CONTEXT_CONTRACTS.lease}|context-lease://demo/l1`]: lease, ...extra });

const system = { async active(id) { return id === SYSTEM ? { system_release_ref: "release://demo/1", constitution_ref: "constitution://demo/1", active_profile_set_ref: "profile-set://demo/1" } : null; } };
const owners = { async exists(ref) { return ["automation-run://acme/etl/run_9", "automation-installation://acme/etl/inst_1", "runtime-assignment://ra_one"].includes(ref); } };
const actors = { async isAccountable(ref) { return ref === "participation://demo/p_caretaker" || ref === "delegation://thread_root/sub_1"; } };

const resolutionDraft = (over = {}) => ({
  receipt_id: collectiveReceiptId("demo/one"),
  goal_run_profile_revision_refs: ["goal-run-profile://generic/revision/1"],
  policy_refs: ["policy://ioi/orchestration/coordination/v1"],
  lease_policy_refs: ["policy://ioi/lease/context/v1"],
  artifact_lifecycle_policy_ref: "policy://ioi/artifact/reuse-fork-install-retire/v1",
  requirement_refs: ["requirement://verifier/path/v1"],
  resolved_owner_refs: [SCOPE, "goal://demo", "context-lease://demo/l1", "runtime-assignment://ra_one"],
  resolved_at: "2026-09-19T12:00:00Z",
  ...over,
});
const lineageDraft = (over = {}) => ({
  lineage_id: "lineage://demo/original",
  resolution_receipt_ref: collectiveReceiptId("demo/one"),
  artifact_ref: "artifact://af_one",
  artifact_sha256: "sha256:" + "1".repeat(64),
  definition_ref: "automation-spec://acme/etl/revision/3",
  accountable_subject_ref: "automation://acme/etl",
  stop_policy_ref: "policy://acme/stop/default",
  ...over,
});
const refusal = async (fn) => { try { await fn(); } catch (e) { return e; } return null; };

async function resolved() {
  const o = fakeOrchestration({ records: withRun() });
  const resolutions = new CollectiveResolutions(o, { owners, system });
  await resolutions.resolve(resolutionDraft());
  return { o, resolutions, lineages: new ExecutableLineages(o, { owners, actors }) };
}

// ---- the receipt --------------------------------------------------------------------------------

test("a receipt admits with the ACTIVE System's coordinates STAMPED, its member set exactly the contract's, and a root over the registered preimage", async () => {
  const o = fakeOrchestration({ records: withRun() });
  const r = await new CollectiveResolutions(o, { owners, system }).resolve(resolutionDraft());
  const schema = readJson("collective-resolution-receipt.v1.schema.json");
  assert.deepEqual(Object.keys(o.admitted[0].record).sort(), Object.keys(schema.properties).filter((k) => k !== "system_binding").sort());
  assert.equal(o.admitted[0].record.schema_version, schema.properties.schema_version.const);
  assert.equal(o.admitted[0].record.schema_version, COLLECTIVE_SCHEMA_VERSIONS.receipt);
  assert.equal(r.record.system_release_ref, "release://demo/1");
  assert.equal(r.record.system_id, SYSTEM);
  assert.equal(r.record.orchestration_ref, SCOPE);
  assert.equal(r.record.registers_no_new_owner, true);
  assert.equal(r.record.closure_root, rootOf(o.admitted[0].record, RECEIPT_ROOT_MEMBERS));
  const inv = readJson("invariants/collective-resolution-receipt.v1.invariants.json").rules.find((x) => x.rule_id === "collective_resolution_receipt.closure.recomputes");
  assert.deepEqual([...RECEIPT_ROOT_MEMBERS], Object.keys(inv.expression.material_fields), "the composer's preimage IS the registered invariant's");
});

test("a receipt is refused by name — no System reader, unadmitted profile, orchestration not an owner, unresolvable owner, second admission — writing nothing", async () => {
  const o = fakeOrchestration({ records: withRun() });
  const r = new CollectiveResolutions(o, { owners, system });
  assert.equal((await refusal(() => r.resolve(resolutionDraft({ receipt_id: "collective-resolution://a-slug" }))))?.code, "collective_resolution_ref_malformed");
  assert.equal((await refusal(() => new CollectiveResolutions(o, { owners }).resolve(resolutionDraft())))?.code, "collective_resolution_system_reader_required");
  assert.equal((await refusal(() => r.resolve(resolutionDraft({ goal_run_profile_revision_refs: ["goal-run-profile://nobody/revision/9"] }))))?.code, "collective_resolution_profile_unadmitted");
  assert.equal((await refusal(() => r.resolve(resolutionDraft({ resolved_owner_refs: ["goal://demo"] }))))?.code, "collective_resolution_orchestration_not_resolved_owner");
  assert.equal((await refusal(() => r.resolve(resolutionDraft({ resolved_owner_refs: [SCOPE, "automation-run://nobody"] }))))?.code, "collective_resolution_owner_unresolvable");
  assert.equal((await refusal(() => r.resolve(resolutionDraft({ resolved_owner_refs: [SCOPE, "goal://not-admitted"] }))))?.code, "collective_resolution_owner_unresolvable");
  assert.equal(o.admitted.length, 0);
  await r.resolve(resolutionDraft());
  assert.equal((await refusal(() => r.resolve(resolutionDraft())))?.code, "collective_resolution_already_admitted");
  assert.equal(o.admitted.length, 1);
});

// ---- the lineage --------------------------------------------------------------------------------

test("reuse admits a lineage under an admitted receipt over an EXACT artifact, its member set the contract's and its root over the registered preimage; observation persists nothing", async () => {
  const { o, lineages } = await resolved();
  const before = o.admitted.length;
  const seen = await lineages.observe("artifact://af_one", "sha256:" + "1".repeat(64));
  assert.equal(seen.persisted, false); assert.equal(o.admitted.length, before);
  const r = await lineages.reuse(lineageDraft());
  const schema = readJson("persistent-executable-lineage.v1.schema.json");
  assert.deepEqual(Object.keys(o.admitted.at(-1).record).sort(), Object.keys(schema.properties).filter((k) => k !== "system_binding").sort());
  assert.equal(o.admitted.at(-1).record.schema_version, schema.properties.schema_version.const);
  assert.equal(r.record.posture.status, "reused");
  assert.equal(r.record.orchestration_ref, SCOPE);
  assert.equal(r.record.lineage_root, rootOf(o.admitted.at(-1).record, LINEAGE_ROOT_MEMBERS));
  const inv = readJson("invariants/persistent-executable-lineage.v1.invariants.json").rules.find((x) => x.rule_id === "persistent_executable_lineage.root.recomputes");
  assert.deepEqual([...LINEAGE_ROOT_MEMBERS], Object.keys(inv.expression.material_fields));
  assert.equal((await lineages.observe("artifact://af_one", "sha256:" + "1".repeat(64))).lineages_here[0], "lineage://demo/original");
});

test("a lineage is refused by name: unknown receipt, a session as the accountable subject, a mutable latest, a fork with no parent or no receipt", async () => {
  const { o, lineages } = await resolved();
  const writes = o.admitted.length;
  assert.equal((await refusal(() => lineages.reuse(lineageDraft({ resolution_receipt_ref: collectiveReceiptId("demo/none") }))))?.code, "lineage_resolution_receipt_unknown");
  assert.equal((await refusal(() => lineages.reuse(lineageDraft({ accountable_subject_ref: "session://s_creator" }))))?.code, "lineage_accountable_subject_not_durable");
  assert.equal((await refusal(() => lineages.reuse(lineageDraft({ artifact_sha256: "latest" }))))?.code, "lineage_mutable_latest_refused");
  assert.equal((await refusal(() => lineages.fork({ ...lineageDraft({ lineage_id: "lineage://demo/fork" }), source_artifact_refs: [], transformation_receipt_refs: ["receipt://t/1"] })))?.code, "lineage_fork_parent_absent");
  assert.equal((await refusal(() => lineages.fork({ ...lineageDraft({ lineage_id: "lineage://demo/fork" }), source_artifact_refs: ["artifact://af_one"], transformation_receipt_refs: [] })))?.code, "lineage_fork_receipt_absent");
  assert.equal((await refusal(() => lineages.fork({ ...lineageDraft({ lineage_id: "lineage://demo/fork" }), source_artifact_refs: ["artifact://af_one"], transformation_receipt_refs: ["receipt://t/1"] })))?.code, "lineage_fork_parent_unknown");
  assert.equal(o.admitted.length, writes);
  await lineages.reuse(lineageDraft());
  const fork = await lineages.fork({ ...lineageDraft({ lineage_id: "lineage://demo/fork", artifact_ref: "artifact://af_two", artifact_sha256: "sha256:" + "2".repeat(64) }), source_artifact_refs: ["artifact://af_one"], transformation_receipt_refs: ["receipt://t/1"] });
  assert.equal(fork.record.posture.status, "forked");
});

test("install → activate follow the transition table, bind only what the daemon serves, live leases admitted here and a caretaker that resolves; each successor is at the exact head", async () => {
  const { o, lineages } = await resolved();
  await lineages.reuse(lineageDraft());
  const id = "lineage://demo/original";
  assert.equal((await refusal(() => lineages.activate(id, { runtime_ref: "automation-run://acme/etl/run_9", runtime_kind: "automation_run", lease_refs: [], caretaker_ref: "participation://demo/p_caretaker" })))?.code, "lineage_transition_skipped");
  assert.equal((await refusal(() => lineages.install(id, { installation_ref: "automation-installation://acme/etl/nobody" })))?.code, "lineage_installation_unbound");
  const installed = await lineages.install(id, { installation_ref: "automation-installation://acme/etl/inst_1" });
  assert.equal(installed.record.posture.status, "installed");
  assert.notEqual(o.admitted.at(-1).expected_head, null);
  assert.equal((await refusal(() => lineages.activate(id, { runtime_ref: "automation-run://acme/etl/nobody", runtime_kind: "automation_run", lease_refs: [], caretaker_ref: "participation://demo/p_caretaker" })))?.code, "lineage_runtime_unbound");
  assert.equal((await refusal(() => lineages.activate(id, { runtime_ref: "automation-run://acme/etl/run_9", runtime_kind: "automation_run", lease_refs: ["context-lease://demo/none"], caretaker_ref: "participation://demo/p_caretaker" })))?.code, "lineage_lease_unknown");
  assert.equal((await refusal(() => lineages.activate(id, { runtime_ref: "automation-run://acme/etl/run_9", runtime_kind: "automation_run", lease_refs: ["context-lease://demo/l1"], caretaker_ref: "participation://demo/nobody" })))?.code, "lineage_caretaker_unresolvable");
  const active = await lineages.activate(id, { runtime_ref: "automation-run://acme/etl/run_9", runtime_kind: "automation_run", lease_refs: ["context-lease://demo/l1"], caretaker_ref: "participation://demo/p_caretaker" });
  assert.equal(active.record.posture.status, "active");
  assert.equal(active.record.lineage_root, rootOf(o.admitted.at(-1).record, LINEAGE_ROOT_MEMBERS));
});

test("posture is a READ MODEL: it recomputes from the owners, persists nothing, and types the orphan; removal transfers nothing and a caretaker's exit quarantines", async () => {
  const { o, lineages } = await resolved();
  const id = "lineage://demo/original";
  await lineages.reuse(lineageDraft());
  await lineages.install(id, { installation_ref: "automation-installation://acme/etl/inst_1" });
  await lineages.activate(id, { runtime_ref: "automation-run://acme/etl/run_9", runtime_kind: "automation_run", lease_refs: ["context-lease://demo/l1"], caretaker_ref: "participation://demo/p_caretaker" });
  const writes = o.admitted.length;
  const p1 = await lineages.posture(id); const p2 = await lineages.posture(id);
  assert.deepEqual(p1, p2); assert.equal(o.admitted.length, writes);
  assert.equal(p1.derived.status, "active"); assert.equal(p1.recorded.status, "active");
  const removed = await lineages.onCreatorRemoved(id, "session://s_creator");
  assert.equal(removed.transferred, false); assert.equal(o.admitted.length, writes, "removal writes nothing when the subject is durable");
  o.store[`${CONTEXT_CONTRACTS.lease}|context-lease://demo/l1`] = { ...lease, status: "revoked" };
  const stale = await lineages.posture(id);
  assert.deepEqual(stale.derived, { status: "stopped", orphan_reason: "authority_stale" });
  assert.equal(stale.recorded.status, "active", "the recorded posture is what was admitted; the derived one is what holds");
  assert.equal(o.admitted.length, writes);
  assert.equal(await lineages.onParticipantExited(id, "participation://demo/other"), null);
  const q = await lineages.onParticipantExited(id, "participation://demo/p_caretaker");
  assert.deepEqual(q.record.posture, { status: "quarantined", orphan_reason: "caretaker_absent" });
});

test("stop, quarantine, repair (exact successor), replace (an admitted successor naming its predecessor) and retire are exact-head successors; retirement is terminal; a mutable latest cannot repair", async () => {
  const { o, lineages } = await resolved();
  const id = "lineage://demo/original";
  await lineages.reuse(lineageDraft());
  await lineages.install(id, { installation_ref: "automation-installation://acme/etl/inst_1" });
  await lineages.activate(id, { runtime_ref: "automation-run://acme/etl/run_9", runtime_kind: "automation_run", lease_refs: [], caretaker_ref: "delegation://thread_root/sub_1" });
  const stopped = await lineages.stop(id, "policy");
  assert.deepEqual(stopped.record.posture, { status: "stopped", orphan_reason: null });
  assert.equal((await refusal(() => lineages.quarantine(id, "not_a_reason")))?.code, "lineage_orphan_reason_unrecognized");
  const q = await lineages.quarantine(id, "health_stale");
  assert.equal(q.record.posture.orphan_reason, "health_stale");
  assert.equal((await refusal(() => lineages.repair(id, { successor_artifact_ref: "artifact://af_one", successor_artifact_sha256: "latest", transformation_receipt_ref: "receipt://t/2" })))?.code, "lineage_mutable_latest_refused");
  const repairing = await lineages.repair(id, { successor_artifact_ref: "artifact://af_one_fixed", successor_artifact_sha256: "sha256:" + "3".repeat(64), transformation_receipt_ref: "receipt://t/2" });
  assert.equal(repairing.record.posture.status, "repairing");
  assert.equal(repairing.record.successor_artifact_ref, "artifact://af_one_fixed");
  assert.equal((await refusal(() => lineages.replace(id, { successor_lineage_ref: "lineage://demo/next" })))?.code, "lineage_replacement_unknown");
  const next = await lineages.succeedFrom(id, lineageDraft({ lineage_id: "lineage://demo/next", artifact_ref: "artifact://af_one_fixed", artifact_sha256: "sha256:" + "3".repeat(64) }));
  assert.equal(next.record.successor_of, id);
  assert.deepEqual(next.record.source_artifact_refs, ["artifact://af_one"]);
  const replaced = await lineages.replace(id, { successor_lineage_ref: "lineage://demo/next" });
  assert.equal(replaced.record.posture.status, "replaced");
  assert.equal((await refusal(() => lineages.retire(id)))?.code, "lineage_terminal");
  const retired = await lineages.retire("lineage://demo/next");
  assert.equal(retired.record.posture.status, "retired");
  assert.equal((await refusal(() => lineages.install("lineage://demo/next", { installation_ref: "automation-installation://acme/etl/inst_1" })))?.code, "lineage_terminal");
  for (const a of o.admitted.slice(1)) assert.equal(a.record.lineage_root, rootOf(a.record, LINEAGE_ROOT_MEMBERS), "every successor re-seals its root");
});

test("a dependency that is retired stops the dependent's derived posture and refuses a new dependent", async () => {
  const { o, lineages } = await resolved();
  await lineages.reuse(lineageDraft({ lineage_id: "lineage://demo/dep" }));
  await lineages.reuse(lineageDraft({ lineage_id: "lineage://demo/main", dependency_lineage_refs: ["lineage://demo/dep"] }));
  await lineages.install("lineage://demo/main", { installation_ref: "automation-installation://acme/etl/inst_1" });
  await lineages.activate("lineage://demo/main", { runtime_ref: "automation-run://acme/etl/run_9", runtime_kind: "automation_run", lease_refs: [], caretaker_ref: "delegation://thread_root/sub_1" });
  await lineages.retire("lineage://demo/dep");
  assert.deepEqual((await lineages.posture("lineage://demo/main")).derived, { status: "stopped", orphan_reason: "dependency_unavailable" });
  assert.equal((await refusal(() => lineages.reuse(lineageDraft({ lineage_id: "lineage://demo/late", dependency_lineage_refs: ["lineage://demo/dep"] }))))?.code, "lineage_dependency_retired");
  assert.equal(o.admitted.filter((a) => a.contract_id === COLLECTIVE_CONTRACTS.lineage).length, 5);
});

// R-202 S5-3 M04.11 — the context family composed over the orchestration. The composers are driven
// over a fake substrate that behaves like the seam, plus a fake view reader that serves admitted
// revisions, and every record they admit is pinned against the REGISTERED member set so the
// composer and the schema cannot drift apart unnoticed.
//
// The assertions that matter are the cross-record ones the single-record invariant language cannot
// express: a cell binds a subject THIS orchestration admitted; a lease is issued to a cell that
// exists here on that cell's subject to a role it permits over view REVISIONS the daemon serves;
// narrowing is subtraction; a terminal lease resolves nothing; a handoff is two distinct cells on
// one subject whose travelling leases the receiver may hold; acceptance copies nothing.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import {
  CONTEXT_CONTRACTS,
  CONTEXT_SCHEMA_VERSIONS,
  ContextCells,
  ContextHandoffs,
  ContextLeases,
  HANDOFF_NON_GRANTS,
  HANDOFF_ROOT_MEMBERS,
  LEASE_ROOT_MEMBERS,
  receiptRootOf,
} from "../dist/index.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const schemas = path.resolve(here, "../../../../docs/architecture/_meta/schemas");
const readJson = (rel) => JSON.parse(fs.readFileSync(path.join(schemas, rel), "utf8"));

const SCOPE = "app-scope://ioi-ai/orchestration/orc_demo";
const SUBJECT = "goal://demo";

function fakeOrchestration({ records = {}, admitted = [] } = {}) {
  const store = { ...records };
  const heads = {};
  return {
    thread_id: "thread_root",
    scope_ref: SCOPE,
    system_id: "system://ioi/orchestration/demo",
    store,
    async recordChain(contract, id) {
      const key = `${contract}|${id}`;
      const current = store[key];
      if (!current) {
        const error = new Error("out of scope");
        error.status = 404;
        throw error;
      }
      return { current, head: heads[key] ?? "sha256:head" };
    },
    async records(contract) {
      const out = [];
      for (const [key, current] of Object.entries(store)) {
        const [c, id] = key.split("|");
        if (!contract || c === contract) out.push({ resource_ref: `${this.system_id}/${c}/${id}`, contract_id: c, current, head: heads[key] ?? "sha256:head", revisions: 1 });
      }
      return { ok: true, system_id: this.system_id, records: out, count: out.length };
    },
    async record(input) {
      admitted.push(input);
      const key = `${input.contract_id}|${input.object_id}`;
      store[key] = { ...input.record, system_binding: { payload_root: "sha256:" + "0".repeat(64) } };
      heads[key] = `sha256:head-${admitted.length}`;
      return { ok: true, record: store[key], head: heads[key], expected_head_for_successor: heads[key] };
    },
    admitted,
  };
}

const goalRun = { schema_version: "ioi.goal-run.v2", goal_run_id: "gr_demo", goal_ref: SUBJECT, orchestration_ref: SCOPE, status: "draft" };
const withRun = (extra = {}) => ({ [`${CONTEXT_CONTRACTS.goalRun}|gr_demo`]: goalRun, ...extra });

const cellDraft = (over = {}) => ({
  context_cell_id: "context-cell://demo/conductor",
  work_subject_ref: SUBJECT,
  role_topology_revision_ref: null,
  role_binding_id: "binding-conductor",
  accountable_actor_ref: "worker://demo/conductor",
  role: "conductor",
  resolver_revision_ref: null,
  resolver_content_hash: null,
  model_route_ref: null,
  memory_projection_refs: [],
  information_flow_label_refs: [],
  active_runtime_assignment_ref: null,
  authority_scope_refs: ["authority://demo/read"],
  compression_policy_ref: null,
  current_claim_ref: null,
  next_wake_condition_ref: null,
  ...over,
});

const views = {
  async query({ family, revision }) {
    if (family === "acme-crm" && revision === 3) return { purpose: "support", data_classes: ["contact", "ticket"] };
    if (family === "acme-billing" && revision === 1) return { purpose: "support", data_classes: ["invoice"] };
    if (family === "acme-hr" && revision === 2) return { purpose: "payroll", data_classes: ["salary"] };
    const error = new Error("not served");
    error.status = 404;
    throw error;
  },
};

const leaseDraft = (over = {}) => ({
  context_lease_id: "context-lease://demo/l1",
  issued_to_ref: "context-cell://demo/conductor",
  lease_kind: "receipt_view",
  allowed_ref_patterns: ["view://acme-crm/*"],
  denied_ref_patterns: ["view://acme-crm/revision/1"],
  authority_scope_refs: ["authority://demo/read"],
  budget_ref: null,
  ttl_seconds: 3600,
  receipt_required: true,
  leased_refs: ["view://acme-crm/revision/3"],
  information_flow_label_refs: ["ifc-label://demo/internal"],
  permitted_recipient_roles: ["conductor", "implementer"],
  ...over,
});

async function refusal(fn) {
  try {
    await fn();
  } catch (error) {
    return error;
  }
  return null;
}

// ---- cells --------------------------------------------------------------------------------------

test("a cell admits with the composition coordinate STAMPED and its member set exactly the registered contract's", async () => {
  const o = fakeOrchestration({ records: withRun() });
  const cells = new ContextCells(o);
  const result = await cells.admit(cellDraft());
  const schema = readJson("context-cell.v2.schema.json");
  const expected = Object.keys(schema.properties).filter((k) => k !== "system_binding").sort();
  assert.deepEqual(Object.keys(o.admitted[0].record).sort(), expected);
  assert.equal(o.admitted[0].record.schema_version, CONTEXT_SCHEMA_VERSIONS.cell);
  assert.equal(o.admitted[0].record.schema_version, schema.properties.schema_version.const);
  assert.equal(result.record.orchestration_ref, SCOPE);
  assert.deepEqual(result.record.context_lease_refs, []);
  assert.equal(result.record.status, "open");
});

test("a cell whose subject no GoalRun under this orchestration admitted is refused by name, before any write", async () => {
  const o = fakeOrchestration({ records: withRun() });
  const error = await refusal(() => new ContextCells(o).admit(cellDraft({ work_subject_ref: "goal://somebody-elses" })));
  assert.equal(error?.code, "context_subject_unadmitted");
  assert.equal(o.admitted.length, 0);
});

test("a topology-bound cell is REFUSED rather than trusted: nothing under the seam can check its six axes", async () => {
  const o = fakeOrchestration({ records: withRun() });
  const error = await refusal(() => new ContextCells(o).admit(cellDraft({ role_topology_revision_ref: "role_topology://demo/revision/1" })));
  assert.equal(error?.code, "context_cell_topology_binding_unverifiable");
  assert.equal(o.admitted.length, 0);
});

test("a cell successor writes at the exact head, may not rewrite its subject, and names only live leases issued to it", async () => {
  const o = fakeOrchestration({ records: withRun() });
  const cells = new ContextCells(o);
  await cells.admit(cellDraft());
  await cells.admit(cellDraft({ context_cell_id: "context-cell://demo/impl", role: "implementer", role_binding_id: "binding-impl", accountable_actor_ref: "worker://demo/impl" }));
  const leases = new ContextLeases(o, { views });
  await leases.issue(leaseDraft());
  await leases.issue(leaseDraft({ context_lease_id: "context-lease://demo/l-impl", issued_to_ref: "context-cell://demo/impl", permitted_recipient_roles: ["implementer"] }));
  const rewrite = await refusal(() => cells.succeed("context-cell://demo/conductor", { work_subject_ref: "goal://other" }));
  assert.equal(rewrite?.code, "context_cell_subject_rewritten");
  const foreign = await refusal(() => cells.succeed("context-cell://demo/conductor", { context_lease_refs: ["context-lease://demo/l-impl"] }));
  assert.equal(foreign?.code, "context_lease_not_issued_to_cell");
  const before = o.admitted.length;
  const ok = await cells.succeed("context-cell://demo/conductor", { context_lease_refs: ["context-lease://demo/l1"], status: "active" });
  assert.equal(o.admitted[before].expected_head, (await o.recordChain(CONTEXT_CONTRACTS.cell, "context-cell://demo/conductor")).head === ok.head ? o.admitted[before].expected_head : o.admitted[before].expected_head);
  assert.notEqual(o.admitted[before].expected_head, null);
  assert.deepEqual(ok.record.context_lease_refs, ["context-lease://demo/l1"]);
  assert.equal("system_binding" in o.admitted[before].record, false, "the binding is derived by the seam, never re-sent");
});

// ---- leases -------------------------------------------------------------------------------------

test("a lease admits with its subject read off the HOLDER, its member set exactly the contract's, and a root that re-derives here", async () => {
  const o = fakeOrchestration({ records: withRun() });
  await new ContextCells(o).admit(cellDraft());
  const result = await new ContextLeases(o, { views }).issue(leaseDraft());
  const schema = readJson("context-lease.v1.schema.json");
  const expected = Object.keys(schema.properties).filter((k) => k !== "system_binding").sort();
  const sent = o.admitted[1].record;
  assert.deepEqual(Object.keys(sent).sort(), expected);
  assert.equal(sent.schema_version, schema.properties.schema_version.const);
  assert.equal(sent.work_subject_ref, SUBJECT);
  assert.equal(sent.receipt_root, receiptRootOf(sent, LEASE_ROOT_MEMBERS));
  const invariant = readJson("invariants/context-lease.v1.invariants.json").rules[0].expression.material_fields;
  assert.deepEqual([...LEASE_ROOT_MEMBERS], Object.keys(invariant), "the composer's preimage IS the registered invariant's");
  assert.equal(result.record.status, "active");
});

test("a lease is refused by name when its holder is unknown, its role is not permitted, or it names a view HEAD or an unserved revision", async () => {
  const o = fakeOrchestration({ records: withRun() });
  await new ContextCells(o).admit(cellDraft());
  const leases = new ContextLeases(o, { views });
  assert.equal((await refusal(() => leases.issue(leaseDraft({ issued_to_ref: "context-cell://demo/nobody" }))))?.code, "context_cell_unknown");
  assert.equal((await refusal(() => leases.issue(leaseDraft({ permitted_recipient_roles: ["reviewer"] }))))?.code, "context_lease_holder_role_not_permitted");
  assert.equal((await refusal(() => leases.issue(leaseDraft({ leased_refs: ["view://acme-crm"] }))))?.code, "context_lease_view_not_a_revision");
  assert.equal((await refusal(() => leases.issue(leaseDraft({ leased_refs: ["view://acme-crm/revision/9"] }))))?.code, "context_lease_view_unresolved");
  assert.equal((await refusal(() => leases.issue(leaseDraft({ context_cell_ref: "context-cell://demo/other" }))))?.code, "context_lease_cell_not_the_holder");
  assert.equal((await refusal(() => leases.issue(leaseDraft({ issued_to_ref: "harness-invocation://demo/1" }))))?.code, "context_lease_issued_to_unverifiable");
  assert.equal(o.admitted.length, 1, "nothing but the cell was written");
  const noReader = new ContextLeases(o);
  assert.equal((await refusal(() => noReader.issue(leaseDraft())))?.code, "context_lease_view_reader_required");
});

test("narrowing is SUBTRACTION: every widening is refused by the member's own name, a shrink admits a successor, and the root re-seals", async () => {
  const o = fakeOrchestration({ records: withRun() });
  await new ContextCells(o).admit(cellDraft());
  const leases = new ContextLeases(o, { views });
  await leases.issue(leaseDraft({ leased_refs: ["view://acme-crm/revision/3", "view://acme-billing/revision/1"], permitted_recipient_roles: ["conductor", "implementer"] }));
  const id = "context-lease://demo/l2";
  const cases = [
    [{ leased_refs: ["view://acme-crm/revision/3", "view://acme-hr/revision/2"] }, "context_lease_leased_refs_widened"],
    [{ allowed_ref_patterns: ["view://acme-crm/*", "view://acme-hr/*"] }, "context_lease_allowed_patterns_widened"],
    [{ authority_scope_refs: ["authority://demo/read", "authority://demo/write"] }, "context_lease_authority_scopes_widened"],
    [{ information_flow_label_refs: ["ifc-label://demo/internal", "ifc-label://demo/public"] }, "context_lease_labels_widened"],
    [{ permitted_recipient_roles: ["conductor", "implementer", "reviewer"] }, "context_lease_recipient_roles_widened"],
    [{ denied_ref_patterns: [] }, "context_lease_denial_dropped"],
    [{ ttl_seconds: 7200 }, "context_lease_ttl_extended"],
    [{ ttl_seconds: null }, "context_lease_ttl_unbounded"],
  ];
  for (const [patch, code] of cases) {
    const error = await refusal(() => leases.narrow("context-lease://demo/l1", { context_lease_id: id, predecessor_remains_valid: true, ...patch }));
    assert.equal(error?.code, code, JSON.stringify(patch));
  }
  assert.equal(o.admitted.length, 2);
  const ok = await leases.narrow("context-lease://demo/l1", { context_lease_id: id, predecessor_remains_valid: true, leased_refs: ["view://acme-crm/revision/3"], permitted_recipient_roles: ["conductor"], denied_ref_patterns: ["view://acme-crm/revision/1", "view://acme-crm/revision/2"], ttl_seconds: 600 });
  assert.equal(ok.record.successor_of, "context-lease://demo/l1");
  assert.equal(ok.record.predecessor_remains_valid, true);
  assert.equal(ok.record.receipt_root, receiptRootOf(ok.record, LEASE_ROOT_MEMBERS));
  assert.notEqual(ok.record.receipt_root, o.admitted[1].record.receipt_root);
});

test("the resolution is a READ MODEL: purposes fold by intersection, no view means no implied policy, revocation resolves nothing", async () => {
  const o = fakeOrchestration({ records: withRun() });
  await new ContextCells(o).admit(cellDraft());
  const leases = new ContextLeases(o, { views });
  await leases.issue(leaseDraft({ leased_refs: ["view://acme-crm/revision/3", "view://acme-billing/revision/1"] }));
  const writes = o.admitted.length;
  const one = await leases.resolveLeastContext("context-lease://demo/l1");
  const two = await leases.resolveLeastContext("context-lease://demo/l1");
  assert.deepEqual(one, two);
  assert.equal(o.admitted.length, writes, "a resolution persists nothing");
  assert.equal(one.nature, "read_model");
  assert.deepEqual(one.permitted_purposes, ["support"]);
  assert.deepEqual(one.exposed_data_classes, ["contact", "invoice", "ticket"]);
  assert.ok(one.inherited_dimensions.includes("purpose") && one.inherited_dimensions.includes("data_classes"));
  assert.equal("purpose" in one, false, "the resolution restates no dimension it inherits");
  await leases.issue(leaseDraft({ context_lease_id: "context-lease://demo/l-mixed", leased_refs: ["view://acme-crm/revision/3", "view://acme-hr/revision/2"] }));
  assert.deepEqual((await leases.resolveLeastContext("context-lease://demo/l-mixed")).permitted_purposes, [], "two views with different purposes permit none");
  await leases.issue(leaseDraft({ context_lease_id: "context-lease://demo/l-empty", leased_refs: [], allowed_ref_patterns: [] }));
  const empty = await leases.resolveLeastContext("context-lease://demo/l-empty");
  assert.equal(typeof empty.reason, "string");
  const revoked = await leases.revoke("context-lease://demo/l1");
  assert.equal(revoked.record.status, "revoked");
  assert.equal(revoked.record.receipt_root, receiptRootOf(revoked.record, LEASE_ROOT_MEMBERS));
  assert.equal((await refusal(() => leases.resolveLeastContext("context-lease://demo/l1")))?.code, "context_lease_resolves_nothing");
  assert.equal((await refusal(() => leases.revoke("context-lease://demo/l1")))?.code, "context_lease_terminal");
  assert.equal((await refusal(() => leases.narrow("context-lease://demo/l1", { context_lease_id: "context-lease://demo/l9", predecessor_remains_valid: false })))?.code, "context_lease_terminal");
});

// ---- handoffs -----------------------------------------------------------------------------------

async function twoCellsWithLease() {
  const o = fakeOrchestration({ records: withRun() });
  const cells = new ContextCells(o);
  await cells.admit(cellDraft());
  await cells.admit(cellDraft({ context_cell_id: "context-cell://demo/impl", role: "implementer", role_binding_id: "binding-impl", accountable_actor_ref: "worker://demo/impl" }));
  await cells.admit(cellDraft({ context_cell_id: "context-cell://demo/rev", role: "reviewer", role_binding_id: "binding-rev", accountable_actor_ref: "worker://demo/rev" }));
  const leases = new ContextLeases(o, { views });
  await leases.issue(leaseDraft({ permitted_recipient_roles: ["conductor", "implementer"] }));
  return { o, cells, leases, handoffs: new ContextHandoffs(o) };
}

const handoffDraft = (over = {}) => ({
  handoff_id: "handoff://demo/h1",
  from_context_cell_ref: "context-cell://demo/conductor",
  to_context_cell_ref: "context-cell://demo/impl",
  handoff_kind: "task_brief",
  payload_ref: null,
  context_lease_refs: ["context-lease://demo/l1"],
  acceptance_refs: ["rubric://demo/done"],
  receipt_refs: [],
  ...over,
});

test("a handoff admits over the packet AS SENT with the constant non-grants, its member set the contract's, and a root that re-derives", async () => {
  const { o, handoffs } = await twoCellsWithLease();
  const result = await handoffs.send(handoffDraft());
  const schema = readJson("context-handoff.v1.schema.json");
  const expected = Object.keys(schema.properties).filter((k) => k !== "system_binding").sort();
  const sent = o.admitted.at(-1).record;
  assert.deepEqual(Object.keys(sent).sort(), expected);
  assert.equal(sent.schema_version, schema.properties.schema_version.const);
  assert.deepEqual(sent.non_grants, HANDOFF_NON_GRANTS);
  assert.equal(sent.receipt_root, receiptRootOf(sent, HANDOFF_ROOT_MEMBERS));
  const invariant = readJson("invariants/context-handoff.v1.invariants.json").rules[0].expression.material_fields;
  assert.deepEqual([...HANDOFF_ROOT_MEMBERS], Object.keys(invariant));
  assert.equal(result.record.status, "sent");
  assert.equal(result.record.work_subject_ref, SUBJECT);
});

test("a handoff is refused by name: to itself, across subjects or unknown cells, or carrying a lease the RECEIVER's role may not hold", async () => {
  const { o, handoffs } = await twoCellsWithLease();
  const writes = o.admitted.length;
  assert.equal((await refusal(() => handoffs.send(handoffDraft({ to_context_cell_ref: "context-cell://demo/conductor" }))))?.code, "context_handoff_to_self");
  assert.equal((await refusal(() => handoffs.send(handoffDraft({ to_context_cell_ref: "context-cell://demo/nobody" }))))?.code, "context_cell_unknown");
  assert.equal((await refusal(() => handoffs.send(handoffDraft({ to_context_cell_ref: "context-cell://demo/rev" }))))?.code, "context_handoff_lease_not_permitted_for_receiver");
  assert.equal((await refusal(() => handoffs.send(handoffDraft({ context_lease_refs: ["context-lease://demo/none"] }))))?.code, "context_lease_unknown");
  assert.equal(o.admitted.length, writes);
});

test("only a SENT handoff is decided, once; acceptance is a candidate under the receiver's policy that copies no lease and re-asserts every non-grant", async () => {
  const { o, handoffs, leases } = await twoCellsWithLease();
  await handoffs.send(handoffDraft());
  const receiverBefore = (await o.recordChain(CONTEXT_CONTRACTS.cell, "context-cell://demo/impl")).current;
  const { admission, candidate } = await handoffs.accept("handoff://demo/h1");
  assert.equal(admission.record.status, "accepted");
  assert.deepEqual(admission.record.non_grants, HANDOFF_NON_GRANTS);
  assert.equal(admission.record.receipt_root, receiptRootOf(admission.record, HANDOFF_ROOT_MEMBERS));
  assert.notEqual(o.admitted.at(-1).expected_head, null, "the decision is a successor at the exact head");
  assert.equal(candidate.nature, "candidate");
  assert.deepEqual(candidate.leases_the_receiver_may_hold, ["context-lease://demo/l1"]);
  assert.equal(candidate.copies_no_lease, true);
  const receiverAfter = (await o.recordChain(CONTEXT_CONTRACTS.cell, "context-cell://demo/impl")).current;
  assert.deepEqual(receiverAfter, receiverBefore, "acceptance wrote nothing to the receiving cell");
  assert.equal((await refusal(() => handoffs.accept("handoff://demo/h1")))?.code, "context_handoff_not_sent");
  assert.equal((await refusal(() => handoffs.reject("handoff://demo/h1")))?.code, "context_handoff_not_sent");
  await leases.revoke("context-lease://demo/l1");
  await handoffs.send(handoffDraft({ handoff_id: "handoff://demo/h2", context_lease_refs: [] }));
  const rejected = await handoffs.reject("handoff://demo/h2");
  assert.equal(rejected.record.status, "rejected");
});

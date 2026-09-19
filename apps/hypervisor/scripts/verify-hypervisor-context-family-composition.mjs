#!/usr/bin/env node
// R-202 S5-3 M04.11 — the context family COMPOSED by ioi.ai over the orchestration, driven end to
// end against an isolated daemon and the REAL wallet.network fixture.
//
// What this proves: ContextCell, ContextLease and ContextHandoff are records of a bounded System
// admitted through the generic record seam by `apps/ioi-ai/orchestration/src/context.ts`, and every
// obligation that spans two records — the ones the single-record invariant language cannot say —
// is refused by the composer BY NAME before any write: a cell binds a subject THIS orchestration
// admitted; a lease is issued to a cell that exists here, on its subject, to a role it permits, over
// view REVISIONS the daemon serves; narrowing is subtraction; a terminal lease resolves nothing; a
// handoff is two distinct cells on one subject whose travelling leases the receiver may hold;
// acceptance is a candidate that copies nothing. The single-record half — each receipt_root
// re-deriving over its members — is refused by the REGISTERED INVARIANT'S OWN NAME at the seam, and
// the gate re-derives every root itself, independently of both the composer and the daemon.
//
// What it does NOT prove, said here: the fold over ADMITTED view revisions (purposes by
// intersection) is proven by the package's unit tests with a stub reader; minting a v2 view
// revision needs the intake fixture `verify-hypervisor-policy-bound-data-view-runtime.mjs` owns, so
// here the live reader is exercised on the refusal side only (an unserved revision is refused after
// asking the daemon). Restart re-derivation is the orchestration-records gate's claim, not this one's.
//
// The daemon serves no context route: the plane those lived on was deleted in S5-1 (R-192).
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { isIsolatedDaemonLogName, sanitizedVerifierBaseEnv, startIsolatedPlane } from "./lib/isolated-daemon.mjs";
import { startRealWalletNetworkPrincipalAuthorityFixture } from "./lib/wallet-network-principal-authority-fixture.mjs";
import { bootstrapActiveSystem, exactGenesisBody, rebindGenesisBodySystem, recomputeReleaseHashes } from "./verify-hypervisor-system-sequence-zero-materialization.mjs";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";

const SYSTEM_ID = "system://ioi/context/s5-3-proof";
const GENESIS_ID = "genesis://ioi/context/s5-3-proof/genesis";
const CONSTITUTION_REF = "constitution://ioi/context/s5-3-proof/v1";
const PACKAGE = "package://ioi/outcome-room";
const DEPLOYMENT_AUTHORITY = "domain://acme-host";
const SCOPE_REF = "app-scope://ioi-ai/orchestration/orc_s5_3_ctx";
const SUBJECT = "goal://s5_3_ctx";
const RECEIPT_CONTRACT = "schema://ioi/applications/ioi-ai/goal-run-profile-resolution-receipt/v1";
const CLOSURE_RULE_ID = "goal_run_profile_resolution_receipt.closure.recomputes";
const LEASE_RULE_ID = "context_lease.receipt_root.recomputes";
const HANDOFF_RULE_ID = "context_handoff.receipt_root.recomputes";
const MUTATION = process.argv.includes("--mutation");
const results = [];
const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
process.chdir(REPO);

const ok = (name, pass, detail = "") => { results.push({ name, pass: Boolean(pass), detail }); console.log(`${pass ? "PASS" : "FAIL"}  ${name}${pass ? "" : `  (${detail})`}`); };
const requireValue = (value, message) => { if (!value) throw new Error(message); return value; };
const daemonCode = (error) => error?.details?.daemon?.error?.code ?? error?.details?.daemon?.code ?? "";
const refused = async (fn) => { try { return { ok: true, value: await fn() }; } catch (error) { return { ok: false, status: error?.status, code: daemonCode(error) || error?.code, composer: error?.name === "ContextRefusal", message: error?.message }; } };
const namesRule = (r, ruleId) => !r.ok && r.code === "system_record_not_registered_valid" && String(r.message ?? "").includes(`invariant:${ruleId}`);

/** The canonicalisation the registered invariants use, implemented HERE so the gate's oracle is its own. */
function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(",")}}`;
}
function deriveRoot(record, members) {
  const material = {};
  for (const m of members) material[m] = record[m];
  return `sha256:${createHash("sha256").update(canonical(material)).digest("hex")}`;
}
/** THE PREDICATE the narrowing assertions are made with, extracted so DRILL D3 can feed it a widened successor. */
function narrowsOnly(prior, next) {
  const sub = (a, b) => a.every((x) => b.includes(x));
  return sub(next.leased_refs, prior.leased_refs) && sub(next.allowed_ref_patterns, prior.allowed_ref_patterns)
    && sub(next.authority_scope_refs, prior.authority_scope_refs) && sub(next.information_flow_label_refs, prior.information_flow_label_refs)
    && sub(next.permitted_recipient_roles, prior.permitted_recipient_roles) && sub(prior.denied_ref_patterns, next.denied_ref_patterns)
    && !(prior.ttl_seconds !== null && next.ttl_seconds === null) && !(prior.ttl_seconds !== null && next.ttl_seconds !== null && next.ttl_seconds > prior.ttl_seconds);
}
function materialFieldsOf(invariantPath, ruleId) {
  const rule = JSON.parse(readFileSync(join(REPO, "docs/architecture/_meta/schemas/invariants", invariantPath), "utf8")).rules.find((r) => r.rule_id === ruleId);
  return Object.keys(requireValue(rule?.expression?.material_fields, `${ruleId} is missing from the registry`));
}

async function jsonCall(base, method, path, body, headers = {}) {
  const payload = body === undefined ? undefined : JSON.stringify(body);
  return await new Promise((resolve, reject) => {
    const request = httpRequest(new URL(path, base), { method, headers: { "content-type": "application/json", ...(payload === undefined ? {} : { "content-length": Buffer.byteLength(payload) }), ...headers } }, (response) => {
      const chunks = []; response.on("data", (c) => chunks.push(c));
      response.on("end", () => { clearTimeout(deadline); const raw = Buffer.concat(chunks).toString("utf8"); let parsed = {}; try { parsed = raw ? JSON.parse(raw) : {}; } catch { parsed = { raw }; } resolve({ status: response.statusCode, body: parsed }); });
    });
    const deadline = setTimeout(() => request.destroy(new Error(`HTTP timeout at ${method} ${path}`)), 1_800_000);
    request.on("error", (error) => { clearTimeout(deadline); reject(error); });
    if (payload !== undefined) request.write(payload);
    request.end();
  });
}

function genesisBody() {
  const body = exactGenesisBody();
  body.release.package_id = PACKAGE;
  body.release.manifest_id = `${PACKAGE}/release/sha256:${"7".repeat(64)}`;
  body.release.display_name = "Context family composition S5-3 verifier package";
  body.release.description = "ContextCell, ContextLease and ContextHandoff composed by ioi.ai over the System-record seam.";
  body.proposed_instantiation.candidate.package_id = PACKAGE;
  body.proposed_instantiation.candidate.manifest_ref = body.release.manifest_id;
  body.proposed_instantiation.candidate.instantiation.proposed_by = "project://ioi/context";
  recomputeReleaseHashes(body.release);
  return rebindGenesisBodySystem(body, {
    systemId: SYSTEM_ID,
    genesisId: GENESIS_ID,
    constitutionRef: CONSTITUTION_REF,
    deploymentProfileRef: `deployment-profile://ioi/context/s5-3-proof/local/revision/sha256:${"8".repeat(64)}`,
    orderingProfileRef: "ordering-profile://ioi/context/s5-3-proof/hosted",
    oracleProfileRef: "oracle-evidence-profile://ioi/context/s5-3-proof/fail-closed",
    lifecycleProfileRef: "lifecycle-profile://ioi/context/s5-3-proof/default",
  });
}

async function loadModules() {
  const sdk = join(REPO, "packages", "agent-sdk", "dist", "index.js");
  const composer = join(REPO, "apps", "ioi-ai", "orchestration", "dist", "index.js");
  requireValue(existsSync(sdk), "BLOCKED: build packages/agent-sdk first");
  requireValue(existsSync(composer), "BLOCKED: build apps/ioi-ai/orchestration first");
  return { sdk: await import(pathToFileURL(sdk).href), composer: await import(pathToFileURL(composer).href) };
}

const cellDraft = (id, role, over = {}) => ({
  context_cell_id: id, work_subject_ref: SUBJECT, role_topology_revision_ref: null, role_binding_id: `binding-${role}`,
  accountable_actor_ref: `worker://s5-3-ctx/${role}`, role, resolver_revision_ref: null, resolver_content_hash: null, model_route_ref: null,
  memory_projection_refs: [], information_flow_label_refs: [], active_runtime_assignment_ref: null, authority_scope_refs: ["authority://s5-3-ctx/read"],
  compression_policy_ref: null, current_claim_ref: null, next_wake_condition_ref: null, ...over,
});
const leaseDraft = (id, holder, over = {}) => ({
  context_lease_id: id, issued_to_ref: holder, lease_kind: "repo_slice", allowed_ref_patterns: ["worktree://s5-3-ctx/*"], denied_ref_patterns: ["worktree://s5-3-ctx/secrets/*"],
  authority_scope_refs: ["authority://s5-3-ctx/read"], budget_ref: null, ttl_seconds: 3600, receipt_required: true, leased_refs: [],
  information_flow_label_refs: ["ifc-label://s5-3-ctx/internal"], permitted_recipient_roles: ["conductor", "implementer"], ...over,
});

async function run() {
  const dataDir = mkdtempSync(join(tmpdir(), "ioi-context-family-composition-"));
  let resolver; let plane;
  try {
    const { sdk, composer } = await loadModules();
    const { Orchestration, createRuntimeSubstrateClient, createPolicyBoundDataViewClient } = sdk;
    const { CONTEXT_CONTRACTS, ContextCells, ContextHandoffs, ContextLeases, GoalRuns, HANDOFF_NON_GRANTS } = composer;
    const baseEnv = { ...sanitizedVerifierBaseEnv() };
    resolver = await startRealWalletNetworkPrincipalAuthorityFixture({ baseEnv });
    const env = { ...resolver.env, IOI_HYPERVISOR_AUTHORITY_PRINCIPAL_REF: DEPLOYMENT_AUTHORITY, IOI_HYPERVISOR_SESSIONS_ROOT: join(dataDir, "verifier-session-workspaces") };
    plane = await startIsolatedPlane({ dataDir, baseEnv, env, serve: true });
    requireValue(plane, "BLOCKED: build target/debug/hypervisor-daemon first");
    const bootstrapLog = readdirSync(dataDir).filter(isIsolatedDaemonLogName).map((n) => readFileSync(join(dataDir, n), "utf8")).join("\n");
    const token = requireValue(bootstrapLog.match(/\b(ioi_bootstrap_[0-9a-f]+)\b/u)?.[1], "isolated daemon did not expose its bootstrap token");
    const operator = await jsonCall(plane.daemonUrl, "POST", "/v1/hypervisor/auth/bootstrap", { token, password: "context-family-composition-password", email: "context@ioi.local" });
    const sessionToken = requireValue(operator.status === 200 && operator.body?.session_token, `operator bootstrap failed ${operator.status}`);
    const operatorHeaders = { authorization: `Bearer ${sessionToken}` };
    const call = (method, path, body) => jsonCall(plane.daemonUrl, method, path, body, operatorHeaders);
    const whoami = await call("GET", "/v1/hypervisor/auth/whoami", undefined);
    const OWNER = `user://${requireValue(operator.body?.principal?.principal_id, "operator identity missing")}`;
    const TENANT = whoami.body?.principal?.tenant_refs?.[0] ?? OWNER;
    const client = createRuntimeSubstrateClient({ endpoint: plane.daemonUrl, headers: operatorHeaders });
    const views = createPolicyBoundDataViewClient({ endpoint: plane.daemonUrl, headers: operatorHeaders });

    const active = await bootstrapActiveSystem(call, resolver, dataDir, genesisBody());
    ok("PRECONDITION: the bounded System is admitted and activated through its governed genesis on the real wallet fixture", active.status === "active" || Boolean(active.source), JSON.stringify(active).slice(0, 200));
    const orchestration = await Orchestration.compose(client, { system_id: SYSTEM_ID, owner_ref: TENANT, scope_ref: SCOPE_REF, objective: "S5-3 proof: the context family composed over the seam" });
    ok("[root] the composition is a coordinating thread and a record scope, exactly as the orchestration gate already proves; this gate builds on it rather than re-proving it", typeof orchestration.thread_id === "string" && orchestration.scope_ref === SCOPE_REF, `${orchestration.thread_id}/${orchestration.scope_ref}`);

    // -- the SUBJECT: a GoalRun this orchestration admitted, resolved from a receipt whose root re-derives ----
    const closureFields = materialFieldsOf("goal-run-profile-resolution-receipt.v1.invariants.json", CLOSURE_RULE_ID);
    const receipt = { ...JSON.parse(readFileSync(join(REPO, "docs/architecture/_meta/schemas/fixtures/goal-run-profile-resolution-receipt-v1/positive-minimal.json"), "utf8")), receipt_id: "receipt://context/s5-3/profile-resolution", goal_ref: SUBJECT };
    receipt.receipt_root = deriveRoot(receipt, closureFields);
    const admittedReceipt = await refused(() => orchestration.record({ contract_id: RECEIPT_CONTRACT, object_id: receipt.receipt_id, record: receipt, expected_head: null }));
    const runs = new GoalRuns(orchestration);
    const run = await refused(() => runs.admit({ goal_run_id: "gr_s5_3_ctx", goal_ref: SUBJECT, owner_ref: OWNER, profile_resolution_receipt_ref: receipt.receipt_id, origin_surface: "api", normalized_goal: "hold one bounded context family", source_context_binding: { target_session_ref: null, project_ref: null }, receipt_obligations: [], admitted_state_root_ref: "artifact://context/s5-3/admitted-state", authority_scope_refs: ["scope:goal.run.create"] }));
    ok("[subject] the family's subject is a GoalRun THIS orchestration admitted through the M04.4 composition, over a receipt whose closure root re-derives here", admittedReceipt.ok && run.ok && run.value?.record?.goal_ref === SUBJECT, `${admittedReceipt.code ?? ""}/${run.code ?? ""}`);

    // -- cells ----------------------------------------------------------------------------------------------
    const cells = new ContextCells(orchestration);
    const conductor = await refused(() => cells.admit(cellDraft("context-cell://s5-3-ctx/conductor", "conductor")));
    ok("[cell] a ContextCell admits as a RECORD of this orchestration through the seam, its composition coordinate STAMPED by the composer, its binding derived by the seam, its lease set empty because a lease is issued TO a cell and cannot precede it",
      conductor.ok && conductor.value?.record?.orchestration_ref === SCOPE_REF && conductor.value?.record?.system_binding?.system_id === SYSTEM_ID && Array.isArray(conductor.value?.record?.context_lease_refs) && conductor.value.record.context_lease_refs.length === 0 && conductor.value?.record?.status === "open",
      `${conductor.ok}/${conductor.code ?? ""}/${conductor.value?.record?.orchestration_ref}`);
    const stray = await refused(() => cells.admit(cellDraft("context-cell://s5-3-ctx/stray", "operator", { work_subject_ref: "goal://nobody_admitted_this" })));
    const strayRead = await cells.read("context-cell://s5-3-ctx/stray");
    ok("[cell] a cell naming a work subject no GoalRun under this orchestration admitted is refused by the composer BY NAME, before any record is written — the subject is read off the seam, never taken from the caller",
      !stray.ok && stray.composer && stray.code === "context_subject_unadmitted" && strayRead === null, `${stray.code}/${strayRead === null}`);
    const bound = await refused(() => cells.admit(cellDraft("context-cell://s5-3-ctx/bound", "implementer", { role_topology_revision_ref: "role_topology://s5-3-ctx/revision/1" })));
    ok("[cell] a topology-bound cell is REFUSED rather than trusted: canon says its six role-binding axes must equal that exact topology role, and nothing under the seam can check them, so the composer refuses by name instead of copying the caller's word",
      !bound.ok && bound.composer && bound.code === "context_cell_topology_binding_unverifiable", `${bound.code}`);
    const implementer = await refused(() => cells.admit(cellDraft("context-cell://s5-3-ctx/implementer", "implementer")));
    const reviewer = await refused(() => cells.admit(cellDraft("context-cell://s5-3-ctx/reviewer", "reviewer")));
    const cellsListed = await orchestration.records(CONTEXT_CONTRACTS.cell);
    ok("[cell] three cells of three roles on one subject are served back by the seam under the cell contract, and nothing else is", implementer.ok && reviewer.ok && cellsListed.count === 3, `${cellsListed.count}`);

    // -- leases ---------------------------------------------------------------------------------------------
    const leaseFields = materialFieldsOf("context-lease.v1.invariants.json", LEASE_RULE_ID);
    const leases = new ContextLeases(orchestration, { views });
    const l1 = await refused(() => leases.issue(leaseDraft("context-lease://s5-3-ctx/l1", "context-cell://s5-3-ctx/conductor")));
    ok("[lease] a lease issued to the conductor admits through the seam, its subject READ off the holder, and its receipt_root RE-DERIVES here over the seventeen registered members — the root the composer sealed, re-derived by this gate, never read back",
      l1.ok && l1.value?.record?.work_subject_ref === SUBJECT && l1.value?.record?.receipt_root === deriveRoot(l1.value.record, leaseFields) && leaseFields.length === 17,
      `${l1.ok}/${l1.code ?? ""}/${leaseFields.length}`);
    const staleLease = { ...l1.value.record, context_lease_id: "context-lease://s5-3-ctx/stale", denied_ref_patterns: [] };
    delete staleLease.system_binding;
    const staleLeaseAdmission = await refused(() => orchestration.record({ contract_id: CONTEXT_CONTRACTS.lease, object_id: staleLease.context_lease_id, record: staleLease, expected_head: null }));
    ok("[lease] a lease whose root is stale by a SINGLE member — a denial dropped after the root was taken — is refused at the seam BY THE REGISTERED INVARIANT'S OWN NAME, not merely refused: the composer is not the only thing standing between a decorative root and the chain",
      namesRule(staleLeaseAdmission, LEASE_RULE_ID), `${staleLeaseAdmission.status}/${staleLeaseAdmission.code}/${String(staleLeaseAdmission.message ?? "").slice(0, 140)}`);
    const head = await refused(() => leases.issue(leaseDraft("context-lease://s5-3-ctx/head", "context-cell://s5-3-ctx/conductor", { leased_refs: ["view://acme-crm"] })));
    ok("[lease] a lease naming a view FAMILY HEAD is refused by the composer by name — a lease that resolves through a moving head cannot reproduce the same least-context view after a restart",
      !head.ok && head.composer && head.code === "context_lease_view_not_a_revision", `${head.code}`);
    const unserved = await refused(() => leases.issue(leaseDraft("context-lease://s5-3-ctx/unserved", "context-cell://s5-3-ctx/conductor", { leased_refs: ["view://acme-crm/revision/3"] })));
    ok("[lease] a lease naming a well-formed view REVISION the daemon does not serve is refused by name AFTER ASKING THE DAEMON through the SDK's own view reader under the operator's identity — the grammar cannot know whether a revision exists, so the composer asks rather than assumes",
      !unserved.ok && unserved.composer && unserved.code === "context_lease_view_unresolved", `${unserved.code}`);
    const wrongRole = await refused(() => leases.issue(leaseDraft("context-lease://s5-3-ctx/wrong-role", "context-cell://s5-3-ctx/reviewer")));
    ok("[lease] a lease whose holder's role is outside its own permitted_recipient_roles is refused by name — the one dimension the lease owns rather than inherits",
      !wrongRole.ok && wrongRole.composer && wrongRole.code === "context_lease_holder_role_not_permitted", `${wrongRole.code}`);
    const nobody = await refused(() => leases.issue(leaseDraft("context-lease://s5-3-ctx/nobody", "context-cell://s5-3-ctx/nobody")));
    ok("[lease] a lease issued to a cell that was never admitted under this orchestration is refused by name, before any record is written",
      !nobody.ok && nobody.composer && nobody.code === "context_cell_unknown", `${nobody.code}`);
    const leasesWritten = (await orchestration.records(CONTEXT_CONTRACTS.lease)).count;
    ok("[lease] every refusal above wrote nothing: the seam serves exactly the one admitted lease", leasesWritten === 1, `${leasesWritten}`);

    // -- narrowing ------------------------------------------------------------------------------------------
    const prior = l1.value.record;
    const widenings = [
      ["leased_refs", { leased_refs: ["view://acme-crm/revision/3"] }, "context_lease_leased_refs_widened"],
      ["allowed_ref_patterns", { allowed_ref_patterns: ["worktree://s5-3-ctx/*", "worktree://other/*"] }, "context_lease_allowed_patterns_widened"],
      ["authority_scope_refs", { authority_scope_refs: ["authority://s5-3-ctx/read", "authority://s5-3-ctx/write"] }, "context_lease_authority_scopes_widened"],
      ["information_flow_label_refs", { information_flow_label_refs: ["ifc-label://s5-3-ctx/internal", "ifc-label://s5-3-ctx/public"] }, "context_lease_labels_widened"],
      ["permitted_recipient_roles", { permitted_recipient_roles: ["conductor", "implementer", "reviewer"] }, "context_lease_recipient_roles_widened"],
    ];
    for (const [member, patch, code] of widenings) {
      const r = await refused(() => leases.narrow("context-lease://s5-3-ctx/l1", { context_lease_id: `context-lease://s5-3-ctx/wide-${member}`, predecessor_remains_valid: true, ...patch }));
      ok(`[narrow] widening ${member} through a narrowing is refused by the member's own name — widening is a NEW binding on record, never a successor of this one`, !r.ok && r.composer && r.code === code, `${r.code}`);
    }
    const dropped = await refused(() => leases.narrow("context-lease://s5-3-ctx/l1", { context_lease_id: "context-lease://s5-3-ctx/dropped", predecessor_remains_valid: true, denied_ref_patterns: [] }));
    ok("[narrow] dropping a DENIAL is a widening too — reach grows by removal, not only by addition — and is refused by name", !dropped.ok && dropped.composer && dropped.code === "context_lease_denial_dropped", `${dropped.code}`);
    const longer = await refused(() => leases.narrow("context-lease://s5-3-ctx/l1", { context_lease_id: "context-lease://s5-3-ctx/longer", predecessor_remains_valid: true, ttl_seconds: 7200 }));
    const forever = await refused(() => leases.narrow("context-lease://s5-3-ctx/l1", { context_lease_id: "context-lease://s5-3-ctx/forever", predecessor_remains_valid: true, ttl_seconds: null }));
    ok("[narrow] a narrowing cannot EXTEND the lease's ttl, and a bounded lease cannot become UNBOUNDED through one — each refused by its own name",
      !longer.ok && longer.code === "context_lease_ttl_extended" && !forever.ok && forever.code === "context_lease_ttl_unbounded", `${longer.code}/${forever.code}`);
    const l2 = await refused(() => leases.narrow("context-lease://s5-3-ctx/l1", { context_lease_id: "context-lease://s5-3-ctx/l2", predecessor_remains_valid: true, permitted_recipient_roles: ["conductor"], denied_ref_patterns: ["worktree://s5-3-ctx/secrets/*", "worktree://s5-3-ctx/keys/*"], ttl_seconds: 600 }));
    ok("[narrow] a shrink admits a SUCCESSOR through the seam that names its predecessor, carries predecessor_remains_valid, only subtracts, and re-seals a root that re-derives here",
      l2.ok && l2.value?.record?.successor_of === "context-lease://s5-3-ctx/l1" && l2.value?.record?.predecessor_remains_valid === true && narrowsOnly(prior, l2.value.record) && l2.value?.record?.receipt_root === deriveRoot(l2.value.record, leaseFields) && l2.value.record.receipt_root !== prior.receipt_root,
      `${l2.ok}/${l2.code ?? ""}`);

    // -- resolution, expiry, reach --------------------------------------------------------------------------
    const before = (await orchestration.records()).count;
    const one = await leases.resolveLeastContext("context-lease://s5-3-ctx/l2");
    const two = await leases.resolveLeastContext("context-lease://s5-3-ctx/l2");
    const after = (await orchestration.records()).count;
    ok("[resolve] the resolution is a READ MODEL that states its own nature and persists nothing: two reads of one lease return the same answer, write no record, name the dimensions they INHERIT from the bound views and labels, and restate none of them; a lease binding NO view resolves with a typed reason rather than a policy nobody asserted",
      one.nature === "read_model" && JSON.stringify(one) === JSON.stringify(two) && before === after && one.inherited_dimensions.includes("purpose") && !("purpose" in one) && !("data_class" in one) && typeof one.reason === "string" && one.denied_ref_patterns.length === 2,
      `${one.nature}/${before}->${after}/${one.reason}`);
    const revoked = await refused(() => leases.revoke("context-lease://s5-3-ctx/l2"));
    const resolvesNothing = await refused(() => leases.resolveLeastContext("context-lease://s5-3-ctx/l2"));
    const noSuccessor = await refused(() => leases.narrow("context-lease://s5-3-ctx/l2", { context_lease_id: "context-lease://s5-3-ctx/l3", predecessor_remains_valid: false }));
    ok("[revoke] revocation admits a successor at the predecessor's EXACT head whose status is revoked and whose root re-seals; a REVOKED lease then resolves nothing — the fence is on the read — and admits no further successor",
      revoked.ok && revoked.value?.record?.status === "revoked" && revoked.value?.record?.receipt_root === deriveRoot(revoked.value.record, leaseFields) && !resolvesNothing.ok && resolvesNothing.code === "context_lease_resolves_nothing" && !noSuccessor.ok && noSuccessor.code === "context_lease_terminal",
      `${revoked.ok}/${resolvesNothing.code}/${noSuccessor.code}`);

    // -- cell successor -------------------------------------------------------------------------------------
    const lImpl = await refused(() => leases.issue(leaseDraft("context-lease://s5-3-ctx/l-impl", "context-cell://s5-3-ctx/implementer", { permitted_recipient_roles: ["implementer"] })));
    const foreignLease = await refused(() => cells.succeed("context-cell://s5-3-ctx/conductor", { context_lease_refs: ["context-lease://s5-3-ctx/l-impl"] }));
    const rewritten = await refused(() => cells.succeed("context-cell://s5-3-ctx/conductor", { work_subject_ref: "goal://other" }));
    const succeeded = await refused(() => cells.succeed("context-cell://s5-3-ctx/conductor", { context_lease_refs: ["context-lease://s5-3-ctx/l1"], status: "active" }));
    const chain = await cells.read("context-cell://s5-3-ctx/conductor");
    ok("[cell-successor] a cell succeeds at its predecessor's EXACT head on its own identity — canon gives the cell no successor_of, so the seam's compare-and-swap is the only succession it has — naming its own live lease; naming a lease issued to ANOTHER cell, or rewriting its subject, is refused by name",
      lImpl.ok && !foreignLease.ok && foreignLease.code === "context_lease_not_issued_to_cell" && !rewritten.ok && rewritten.code === "context_cell_subject_rewritten" && succeeded.ok && chain?.revisions?.length === 2 && chain?.current?.status === "active" && chain?.current?.context_lease_refs?.[0] === "context-lease://s5-3-ctx/l1",
      `${foreignLease.code}/${rewritten.code}/${succeeded.ok}/${chain?.revisions?.length}`);

    // -- handoffs -------------------------------------------------------------------------------------------
    const handoffFields = materialFieldsOf("context-handoff.v1.invariants.json", HANDOFF_RULE_ID);
    const handoffs = new ContextHandoffs(orchestration);
    const h1 = await refused(() => handoffs.send({ handoff_id: "handoff://s5-3-ctx/h1", from_context_cell_ref: "context-cell://s5-3-ctx/conductor", to_context_cell_ref: "context-cell://s5-3-ctx/implementer", handoff_kind: "task_brief", payload_ref: null, context_lease_refs: ["context-lease://s5-3-ctx/l1"], acceptance_refs: ["rubric://s5-3-ctx/done"], receipt_refs: [] }));
    ok("[handoff] a handoff admits through the seam over the packet AS SENT — its five non-grants constant and inspectable, its subject read off the sender — and its receipt_root re-derives here over the twelve registered members",
      h1.ok && h1.value?.record?.status === "sent" && canonical(h1.value?.record?.non_grants ?? null) === canonical(HANDOFF_NON_GRANTS) && h1.value?.record?.work_subject_ref === SUBJECT && h1.value?.record?.receipt_root === deriveRoot(h1.value.record, handoffFields) && handoffFields.length === 12,
      `${h1.ok}/${h1.code ?? ""}/${handoffFields.length}`);
    const staleHandoff = { ...h1.value.record, handoff_id: "handoff://s5-3-ctx/stale", context_lease_refs: ["context-lease://s5-3-ctx/l1", "context-lease://s5-3-ctx/l-impl"] };
    delete staleHandoff.system_binding;
    const staleHandoffAdmission = await refused(() => orchestration.record({ contract_id: CONTEXT_CONTRACTS.handoff, object_id: staleHandoff.handoff_id, record: staleHandoff, expected_head: null }));
    ok("[handoff] a lease added to the packet after the root was taken is refused at the seam by invariant:context_handoff.receipt_root.recomputes — the lease set a receiver re-evaluates on acceptance is exactly what a decorative root would fail to commit",
      namesRule(staleHandoffAdmission, HANDOFF_RULE_ID), `${staleHandoffAdmission.status}/${staleHandoffAdmission.code}`);
    const self = await refused(() => handoffs.send({ handoff_id: "handoff://s5-3-ctx/self", from_context_cell_ref: "context-cell://s5-3-ctx/conductor", to_context_cell_ref: "context-cell://s5-3-ctx/conductor", handoff_kind: "continuation_summary", payload_ref: null, context_lease_refs: [], acceptance_refs: [], receipt_refs: [] }));
    const notPermitted = await refused(() => handoffs.send({ handoff_id: "handoff://s5-3-ctx/to-reviewer", from_context_cell_ref: "context-cell://s5-3-ctx/conductor", to_context_cell_ref: "context-cell://s5-3-ctx/reviewer", handoff_kind: "review_request", payload_ref: null, context_lease_refs: ["context-lease://s5-3-ctx/l1"], acceptance_refs: [], receipt_refs: [] }));
    ok("[handoff] a cell handing off to ITSELF is refused — that is a summarisation, not a handoff between cells — and a travelling lease not permitted for the RECEIVING cell's role is refused by name at send, not discovered at acceptance",
      !self.ok && self.code === "context_handoff_to_self" && !notPermitted.ok && notPermitted.code === "context_handoff_lease_not_permitted_for_receiver", `${self.code}/${notPermitted.code}`);
    const receiverBefore = JSON.stringify((await cells.read("context-cell://s5-3-ctx/implementer"))?.current);
    const accepted = await refused(() => handoffs.accept("handoff://s5-3-ctx/h1"));
    const receiverAfter = JSON.stringify((await cells.read("context-cell://s5-3-ctx/implementer"))?.current);
    const again = await refused(() => handoffs.accept("handoff://s5-3-ctx/h1"));
    const rejectAfter = await refused(() => handoffs.reject("handoff://s5-3-ctx/h1"));
    ok("[handoff] acceptance mints a successor at the exact head that is a CANDIDATE under the RECEIVER's policy — it names the leases the receiver's role may hold, copies no lease and transfers no authority (the receiving cell's record is byte-identical before and after), re-asserts the non-grants — and only a SENT handoff can be decided, once",
      accepted.ok && accepted.value?.admission?.record?.status === "accepted" && canonical(accepted.value?.admission?.record?.non_grants ?? null) === canonical(HANDOFF_NON_GRANTS) && accepted.value?.candidate?.copies_no_lease === true && accepted.value?.candidate?.leases_the_receiver_may_hold?.[0] === "context-lease://s5-3-ctx/l1" && receiverBefore === receiverAfter && !again.ok && again.code === "context_handoff_not_sent" && !rejectAfter.ok && rejectAfter.code === "context_handoff_not_sent",
      `${accepted.ok}/${accepted.code ?? ""}/${again.code}/${receiverBefore === receiverAfter}`);

    // -- the namespace this composition replaced ------------------------------------------------------------
    const retired = await Promise.all(["context-cells", "context-leases", "handoffs"].map((tail) => call("POST", `/v1/goal-orchestration/goal-runs/${encodeURIComponent(SUBJECT)}/${tail}`, { through: "the retired plane" })));
    ok("[retirement] and the daemon serves NOTHING under /v1/goal-orchestration/goal-runs/*/context-cells, /context-leases or /handoffs for the operator's own session: the composition above is not an alternative to that plane, it is what replaced it",
      retired.every((r) => r.status === 404 || r.status === 405), retired.map((r) => r.status).join("/"));

    // -- structure ------------------------------------------------------------------------------------------
    const composerSource = readFileSync(join(REPO, "apps/ioi-ai/orchestration/src/context.ts"), "utf8");
    const routerSource = readFileSync(join(REPO, "crates/node/src/bin/hypervisor-daemon.rs"), "utf8");
    ok("[structure] the composer is application-layer code over the primitives: it names no room or participant, holds no store, computes every root itself and drives only the seam's record, records and recordChain; the daemon's router registers nothing for context cells, leases or handoffs",
      !/\b(room|rooms|participant|participants)\b/iu.test(composerSource) && !/localStorage|writeFileSync|mkdirSync/u.test(composerSource) && /receiptRootOf\(/u.test(composerSource) && /\.record\(\{/u.test(composerSource) && /\.recordChain\(/u.test(composerSource) && /\.records\(/u.test(composerSource) && !/"\/v1\/[^"]*\/(?:context-cells|context-leases|handoffs)\b/u.test(routerSource),
      "");

    if (MUTATION) {
      const reLease = deriveRoot(l1.value.record, leaseFields);
      const movedLease = deriveRoot({ ...l1.value.record, ttl_seconds: 1 }, leaseFields);
      const reHandoff = deriveRoot(h1.value.record, handoffFields);
      const movedHandoff = deriveRoot({ ...h1.value.record, payload_ref: "task-brief://moved" }, handoffFields);
      ok("DRILL D1 — the payload oracle: the gate re-derives the ADMITTED lease's and handoff's roots from their own members, and a single moved member changes each",
        reLease === l1.value.record.receipt_root && movedLease !== reLease && reHandoff === h1.value.record.receipt_root && movedHandoff !== reHandoff, `${reLease === l1.value.record.receipt_root}/${reHandoff === h1.value.record.receipt_root}`);
      const removed = { ...l1.value.record }; delete removed.status;
      ok("DRILL D2 — and the same oracle rejects a record with a member REMOVED, not only one changed", deriveRoot(removed, leaseFields) !== l1.value.record.receipt_root, "");
      const widened = { ...l2.value.record, leased_refs: ["view://acme-crm/revision/3"] };
      const admits = await refused(() => Promise.resolve({ record: {} }));
      const rejects = await refused(() => Promise.reject(Object.assign(new Error("x"), { status: 422, details: { daemon: { error: { code: "system_record_not_registered_valid" } } } })));
      ok("DRILL D3 — the subtraction claim is FALSIFIABLE: the same predicate the shrink assertion uses goes RED on a successor built the way a composer that trusted its caller would build it; and the refusal predicate reads an admitted reply as ok and a typed refusal as refused with its daemon code",
        narrowsOnly(prior, l2.value.record) && !narrowsOnly(prior, widened) && admits.ok && !rejects.ok && rejects.status === 422 && rejects.code === "system_record_not_registered_valid", "");
    }
  } finally {
    if (plane) await plane.stop();
    if (resolver) await resolver.stop();
    rmSync(dataDir, { recursive: true, force: true });
  }
}

try {
  await run();
} catch (error) {
  ok("the verifier completed", false, String(error?.message ?? error));
}
if (!MUTATION) emitVerifierCensus({ verifierId: "context-family-composition", sourceUrl: import.meta.url, results });
const failed = results.filter((r) => !r.pass);
console.log(`\n${results.length - failed.length}/${results.length} passed`);
if (failed.length) process.exitCode = 1;

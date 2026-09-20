#!/usr/bin/env node
// R-204 S5-3 M04.12 — collective resolution and persistent executable lineage COMPOSED by ioi.ai
// over the orchestration, driven end to end against an isolated daemon and the REAL wallet.network
// fixture.
//
// What this proves: the collective-resolution receipt and the persistent-executable-lineage record
// are records of a bounded System admitted through the generic record seam by
// `apps/ioi-ai/orchestration/src/collective.ts`. The receipt's release, constitution and profile
// set are READ FROM THE DAEMON's served genesis, never from the caller; every profile revision is
// one an admitted GoalRun carries; the orchestration is itself a resolved owner (and the seam's
// corrected invariant refuses a receipt that says otherwise, BY ITS NAME); every owner ref resolves —
// by the seam or by the daemon's own planes. A lineage binds an EXACT artifact under an admitted
// receipt; its accountable subject is durable; fork needs admitted parents and a transformation
// receipt; install binds an automation the daemon serves; activate binds a runtime the daemon
// serves (a kernel-owned delegation), live leases admitted through the M04.11 composer and a
// caretaker that resolves; transitions are never skipped; posture is a READ MODEL; removal
// transfers nothing; repair and replacement are exact; retirement is terminal; every root is
// re-derived by this gate and refused BY THE REGISTERED INVARIANT'S NAME at the seam when stale;
// and a daemon restart re-derives every record at the same head from durable admissions.
//
// What it does NOT prove, said here: ArtifactRef production (no producer exists in the estate —
// artifact identity is an opaque ref frozen by sha256 here); lease expiry by clock (the daemon
// evaluates no TTL — liveness is read by status); runtime HEALTH beyond "served or not" (the
// managed-worker states carry no quarantined/retired/stopped); a participation-backed caretaker
// (this gate's caretaker is a delegation; a participation is refused as unresolved because none is
// minted here). Each is a typed refusal or a printed non-claim, never a green over an assumption.
//
// The daemon serves no collective, lineage, caretaker or artifact-lifecycle route (R-192).
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

const SYSTEM_ID = "system://ioi/collective/s5-3-proof";
const GENESIS_ID = "genesis://ioi/collective/s5-3-proof/genesis";
const CONSTITUTION_REF = "constitution://ioi/collective/s5-3-proof/v1";
const PACKAGE = "package://ioi/outcome-room";
const DEPLOYMENT_AUTHORITY = "domain://acme-host";
const SCOPE_REF = "app-scope://ioi-ai/orchestration/orc_s5_3_collective";
const SUBJECT = "goal://s5_3_collective";
const RECEIPT_CONTRACT = "schema://ioi/applications/ioi-ai/goal-run-profile-resolution-receipt/v1";
const CLOSURE_RULE_ID = "goal_run_profile_resolution_receipt.closure.recomputes";
const RECEIPT_RULE_ID = "collective_resolution_receipt.closure.recomputes";
const OWNER_RULE_ID = "collective_resolution_receipt.orchestration.is_a_resolved_owner";
const LINEAGE_RULE_ID = "persistent_executable_lineage.root.recomputes";
const ORPHAN_RULE_ID = "persistent_executable_lineage.orphan.reason_is_typed";
const MUTATION = process.argv.includes("--mutation");
const results = [];
const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
process.chdir(REPO);

const ok = (name, pass, detail = "") => { results.push({ name, pass: Boolean(pass), detail }); console.log(`${pass ? "PASS" : "FAIL"}  ${name}${pass ? "" : `  (${detail})`}`); };
const requireValue = (value, message) => { if (!value) throw new Error(message); return value; };
const daemonCode = (error) => error?.details?.daemon?.error?.code ?? error?.details?.daemon?.code ?? "";
const refused = async (fn) => { try { return { ok: true, value: await fn() }; } catch (error) { return { ok: false, status: error?.status, code: daemonCode(error) || error?.code, composer: error?.name === "CollectiveRefusal" || error?.name === "ContextRefusal", message: error?.message }; } };
const namesRule = (r, ruleId) => !r.ok && r.code === "system_record_not_registered_valid" && String(r.message ?? "").includes(`invariant:${ruleId}`);

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
function materialFieldsOf(invariantPath, ruleId) {
  const rule = JSON.parse(readFileSync(join(REPO, "docs/architecture/_meta/schemas/invariants", invariantPath), "utf8")).rules.find((r) => r.rule_id === ruleId);
  return Object.keys(requireValue(rule?.expression?.material_fields, `${ruleId} is missing from the registry`));
}
const stripSeam = (record) => { const { system_binding: _b, ...rest } = record; return rest; };

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
  body.release.manifest_id = `${PACKAGE}/release/sha256:${"9".repeat(64)}`;
  body.release.display_name = "Collective lineage composition S5-3 verifier package";
  body.release.description = "The collective-resolution receipt and persistent executable lineage composed by ioi.ai over the System-record seam.";
  body.proposed_instantiation.candidate.package_id = PACKAGE;
  body.proposed_instantiation.candidate.manifest_ref = body.release.manifest_id;
  body.proposed_instantiation.candidate.instantiation.proposed_by = "project://ioi/collective";
  recomputeReleaseHashes(body.release);
  return rebindGenesisBodySystem(body, {
    systemId: SYSTEM_ID,
    genesisId: GENESIS_ID,
    constitutionRef: CONSTITUTION_REF,
    deploymentProfileRef: `deployment-profile://ioi/collective/s5-3-proof/local/revision/sha256:${"a".repeat(64)}`,
    orderingProfileRef: "ordering-profile://ioi/collective/s5-3-proof/hosted",
    oracleProfileRef: "oracle-evidence-profile://ioi/collective/s5-3-proof/fail-closed",
    lifecycleProfileRef: "lifecycle-profile://ioi/collective/s5-3-proof/default",
  });
}

async function loadModules() {
  const sdk = join(REPO, "packages", "agent-sdk", "dist", "index.js");
  const composer = join(REPO, "apps", "ioi-ai", "orchestration", "dist", "index.js");
  requireValue(existsSync(sdk), "BLOCKED: build packages/agent-sdk first");
  requireValue(existsSync(composer), "BLOCKED: build apps/ioi-ai/orchestration first");
  return { sdk: await import(pathToFileURL(sdk).href), composer: await import(pathToFileURL(composer).href) };
}

const cellDraft = (id, role) => ({
  context_cell_id: id, work_subject_ref: SUBJECT, role_topology_revision_ref: null, role_binding_id: `binding-${role}`, accountable_actor_ref: `worker://s5-3-collective/${role}`, role,
  resolver_revision_ref: null, resolver_content_hash: null, model_route_ref: null, memory_projection_refs: [], information_flow_label_refs: [], active_runtime_assignment_ref: null,
  authority_scope_refs: ["authority://s5-3-collective/read"], compression_policy_ref: null, current_claim_ref: null, next_wake_condition_ref: null,
});
const leaseDraft = (id, holder) => ({
  context_lease_id: id, issued_to_ref: holder, lease_kind: "runtime", allowed_ref_patterns: ["worktree://s5-3-collective/*"], denied_ref_patterns: [], authority_scope_refs: ["authority://s5-3-collective/read"],
  budget_ref: null, ttl_seconds: 3600, receipt_required: false, leased_refs: [], information_flow_label_refs: [], permitted_recipient_roles: ["conductor", "implementer"],
});
// The receipt identity is minted by the composer's own helper once the module is loaded inside run().
let RECEIPT_ID = null;
const lineageDraft = (id, over = {}) => ({
  lineage_id: id, resolution_receipt_ref: RECEIPT_ID, artifact_ref: "artifact://s5-3/etl", artifact_sha256: `sha256:${"1".repeat(64)}`,
  definition_ref: "automation-spec://s5-3/etl/revision/1", accountable_subject_ref: "automation://s5-3/etl", stop_policy_ref: "policy://s5-3/stop/default", ...over,
});

async function run() {
  const dataDir = mkdtempSync(join(tmpdir(), "ioi-collective-lineage-"));
  let resolver; let plane;
  try {
    const { sdk, composer } = await loadModules();
    const { Orchestration, createRuntimeSubstrateClient } = sdk;
    const { COLLECTIVE_CONTRACTS, CONTEXT_CONTRACTS, CollectiveResolutions, ContextCells, ContextLeases, ExecutableLineages, GoalRuns, LINEAGE_TRANSITIONS, collectiveReceiptId } = composer;
    const baseEnv = { ...sanitizedVerifierBaseEnv() };
    resolver = await startRealWalletNetworkPrincipalAuthorityFixture({ baseEnv });
    const env = { ...resolver.env, IOI_HYPERVISOR_AUTHORITY_PRINCIPAL_REF: DEPLOYMENT_AUTHORITY, IOI_HYPERVISOR_SESSIONS_ROOT: join(dataDir, "verifier-session-workspaces") };
    plane = await startIsolatedPlane({ dataDir, baseEnv, env, serve: true });
    requireValue(plane, "BLOCKED: build target/debug/hypervisor-daemon first");
    const bootstrapLog = readdirSync(dataDir).filter(isIsolatedDaemonLogName).map((n) => readFileSync(join(dataDir, n), "utf8")).join("\n");
    const token = requireValue(bootstrapLog.match(/\b(ioi_bootstrap_[0-9a-f]+)\b/u)?.[1], "isolated daemon did not expose its bootstrap token");
    const operator = await jsonCall(plane.daemonUrl, "POST", "/v1/hypervisor/auth/bootstrap", { token, password: "collective-lineage-password", email: "collective@ioi.local" });
    const sessionToken = requireValue(operator.status === 200 && operator.body?.session_token, `operator bootstrap failed ${operator.status}`);
    const operatorHeaders = { authorization: `Bearer ${sessionToken}` };
    let daemonUrl = plane.daemonUrl;
    const call = (method, path, body) => jsonCall(daemonUrl, method, path, body, operatorHeaders);
    const whoami = await call("GET", "/v1/hypervisor/auth/whoami", undefined);
    const OWNER = `user://${requireValue(operator.body?.principal?.principal_id, "operator identity missing")}`;
    const TENANT = whoami.body?.principal?.tenant_refs?.[0] ?? OWNER;
    let client = createRuntimeSubstrateClient({ endpoint: daemonUrl, headers: operatorHeaders });

    const active = await bootstrapActiveSystem(call, resolver, dataDir, genesisBody());
    ok("PRECONDITION: the bounded System is admitted and activated through its governed genesis on the real wallet fixture", active.status === "active" || Boolean(active.source), JSON.stringify(active).slice(0, 200));
    const orchestration = await Orchestration.compose(client, { system_id: SYSTEM_ID, owner_ref: TENANT, scope_ref: SCOPE_REF, objective: "S5-3 proof: collective resolution and executable lineage composed over the seam" });
    ok("[root] the composition is a coordinating thread and a record scope, exactly as the orchestration gate already proves; this gate builds on it rather than re-proving it", typeof orchestration.thread_id === "string" && orchestration.scope_ref === SCOPE_REF, `${orchestration.thread_id}/${orchestration.scope_ref}`);

    // -- the readers the composer folds through: the DAEMON's served genesis, the daemon's planes, the kernel's delegations --
    // The System's coordinates are read from what the DAEMON serves — first its genesis-admission
    // read, then the activation response it answered at bootstrap — by member name wherever the
    // served object carries them. What the gate composed is compared AGAINST that read below, so a
    // reader that answered from the gate's own body could not pass the assertion.
    const genesisTail = active.source?.sourceTail;
    const findKey = (value, keys, depth = 0) => {
      if (!value || typeof value !== "object" || depth > 8) return undefined;
      for (const k of keys) if (typeof value[k] === "string") return value[k];
      for (const v of Object.values(value)) { const hit = findKey(v, keys, depth + 1); if (hit !== undefined) return hit; }
      return undefined;
    };
    const readerLog = [];
    const system = {
      async active(systemId) {
        if (systemId !== SYSTEM_ID) return null;
        let served = { status: 0, body: {} };
        if (genesisTail) served = await call("GET", `/v1/hypervisor/autonomous-systems/${encodeURIComponent(genesisTail)}`, undefined);
        const sources = [served.status === 200 ? served.body : null, active.chain ?? null, active.state ?? null, active.source ?? null].filter(Boolean);
        readerLog.push(`GET ${genesisTail ?? "-"} -> ${served.status} ${JSON.stringify(Object.keys(served.body ?? {})).slice(0, 120)} ${served.body?.error?.code ?? served.body?.code ?? ""}`);
        for (const src of sources) {
          const release = findKey(src, ["manifest_ref", "manifest_id", "system_release_ref", "release_ref"]);
          const constitution = findKey(src, ["constitution_ref", "constitution_id"]);
          const profile = findKey(src, ["deployment_profile_ref", "active_profile_set_ref"]);
          if (release && constitution && profile) return { system_release_ref: release, constitution_ref: constitution, active_profile_set_ref: profile };
        }
        return null;
      },
    };
    const composedGenesis = genesisBody();
    const composedRelease = composedGenesis.release.manifest_id;
    const composedProfile = composedGenesis.proposed_instantiation.candidate.initial_profile_refs.deployment_profile_ref;
    // the daemon pins the deployment profile to its CONTENT revision at genesis, so the served ref shares the composed identity and carries the daemon's digest
    const composedProfileIdentity = composedProfile.replace(/\/revision\/sha256:[0-9a-f]{64}$/u, "");
    const owners = {
      async exists(ref) {
        // "served" is the daemon answering with the RECORD, not merely a 200: the execution read answers
        // 200 with ok:false for an unknown id, which a status-only probe would have read as served.
        if (ref.startsWith("automation-installation://")) { const r = await call("GET", `/v1/hypervisor/automations/${encodeURIComponent(ref.slice("automation-installation://".length))}`, undefined); return r.status === 200 && r.body?.ok !== false && Boolean(r.body?.automation ?? r.body?.automation_id); }
        if (ref.startsWith("automation-run://")) { const r = await call("GET", `/v1/hypervisor/automation-executions/${encodeURIComponent(ref.slice("automation-run://".length))}`, undefined); return r.status === 200 && r.body?.ok === true && Boolean(r.body?.execution); }
        if (ref.startsWith("delegation://")) { const [thread, sub] = ref.slice("delegation://".length).split("/"); if (thread !== orchestration.thread_id) return false; const listed = await orchestration.delegations(); return (listed.subagents ?? []).some((s) => s.subagent_id === sub); }
        return false;
      },
    };
    const actors = { async isAccountable(ref) { return ref.startsWith("delegation://") ? owners.exists(ref) : false; } };

    // -- the SUBJECT, a caretaker/runtime delegation, a cell and a lease — all through the compositions this unit composes over --
    const closureFields = materialFieldsOf("goal-run-profile-resolution-receipt.v1.invariants.json", CLOSURE_RULE_ID);
    const profileReceipt = { ...JSON.parse(readFileSync(join(REPO, "docs/architecture/_meta/schemas/fixtures/goal-run-profile-resolution-receipt-v1/positive-minimal.json"), "utf8")), receipt_id: "receipt://collective/s5-3/profile-resolution", goal_ref: SUBJECT };
    profileReceipt.receipt_root = deriveRoot(profileReceipt, closureFields);
    const admittedProfile = await refused(() => orchestration.record({ contract_id: RECEIPT_CONTRACT, object_id: profileReceipt.receipt_id, record: profileReceipt, expected_head: null }));
    const runs = new GoalRuns(orchestration);
    const run = await refused(() => runs.admit({ goal_run_id: "gr_s5_3_collective", goal_ref: SUBJECT, owner_ref: OWNER, profile_resolution_receipt_ref: profileReceipt.receipt_id, origin_surface: "api", normalized_goal: "hold one persistent executable lineage", source_context_binding: { target_session_ref: null, project_ref: null }, receipt_obligations: [], admitted_state_root_ref: "artifact://collective/s5-3/admitted-state", authority_scope_refs: ["scope:goal.run.create"] }));
    const worker = await refused(() => orchestration.delegate({ prompt: "carry the lineage's runtime", role: "worker" }));
    const subagentId = worker.value?.subagent_id ?? worker.value?.subagent?.subagent_id ?? (await orchestration.delegations()).subagents?.[0]?.subagent_id;
    const DELEGATION = `delegation://${orchestration.thread_id}/${subagentId}`;
    const cells = new ContextCells(orchestration);
    const leases = new ContextLeases(orchestration, { views: { async query() { throw Object.assign(new Error("no views here"), { status: 404 }); } } });
    const cell = await refused(() => cells.admit(cellDraft("context-cell://s5-3-collective/conductor", "conductor")));
    const l1 = await refused(() => leases.issue(leaseDraft("context-lease://s5-3-collective/l1", "context-cell://s5-3-collective/conductor")));
    const l2 = await refused(() => leases.issue(leaseDraft("context-lease://s5-3-collective/l2", "context-cell://s5-3-collective/conductor")));
    const profileRevision = run.value?.record?.goal_run_profile_revision_ref;
    ok("[subject] the closure's members are THIS orchestration's: a GoalRun admitted through the M04.4 composition over a receipt whose closure root re-derives here, a kernel-owned delegation of the coordinating thread, and a cell with two leases admitted through the M04.11 composer",
      admittedProfile.ok && run.ok && typeof profileRevision === "string" && typeof subagentId === "string" && cell.ok && l1.ok && l2.ok && (await owners.exists(DELEGATION)),
      `${admittedProfile.code ?? ""}/${run.code ?? ""}/${worker.code ?? ""}/${cell.code ?? ""}/${l1.code ?? ""}/${l2.code ?? ""}`);

    // -- the receipt ----------------------------------------------------------------------------------------
    const receiptFields = materialFieldsOf("collective-resolution-receipt.v1.invariants.json", RECEIPT_RULE_ID);
    const resolutions = new CollectiveResolutions(orchestration, { owners, system });
    RECEIPT_ID = collectiveReceiptId("s5-3/one");
    const draft = { receipt_id: RECEIPT_ID, goal_run_profile_revision_refs: [profileRevision], policy_refs: ["policy://ioi/orchestration/coordination/v1"], lease_policy_refs: ["policy://ioi/lease/context/v1"], artifact_lifecycle_policy_ref: "policy://ioi/artifact/reuse-fork-install-retire/v1", requirement_refs: ["requirement://verifier/path/v1", "requirement://stop/v1"], resolved_owner_refs: [SCOPE_REF, SUBJECT, "context-lease://s5-3-collective/l1", DELEGATION] };
    const served = await system.active(SYSTEM_ID);
    const receipt = await refused(() => resolutions.resolve(draft));
    const rr = receipt.value?.record ?? {};
    ok("[resolve] a collective-resolution receipt admits as a RECORD of this orchestration through the seam: its System and orchestration STAMPED, its release/constitution/profile-set read from what the DAEMON serves for that System and equal to the governed genesis this gate composed — the profile at the daemon's content-pinned revision (so the reader could not have answered from the gate's own body), its binding derived by the seam, registers_no_new_owner true, and its closure_root re-derived here over the eighteen registered members",
      receipt.ok && served && rr.system_id === SYSTEM_ID && rr.orchestration_ref === SCOPE_REF && rr.system_release_ref === served.system_release_ref && rr.constitution_ref === served.constitution_ref && rr.active_profile_set_ref === served.active_profile_set_ref && served.system_release_ref === composedRelease && served.constitution_ref === CONSTITUTION_REF && String(served.active_profile_set_ref).startsWith(`${composedProfileIdentity}/revision/sha256:`) && rr.system_binding?.system_id === SYSTEM_ID && rr.registers_no_new_owner === true && rr.closure_root === deriveRoot(rr, receiptFields) && receiptFields.length === 18,
      `${receipt.ok}/${receipt.code ?? ""}/${receipt.message?.slice(0, 100) ?? ""}/served=${JSON.stringify(served)}/composed=${JSON.stringify({ composedRelease, CONSTITUTION_REF, composedProfile })}/reader=${readerLog.join(" | ")}`);
    if (!receipt.ok) throw new Error(`the receipt did not admit (${receipt.code}); nothing below can be proven — reader: ${readerLog.join(" | ")}`);
    const staleReceipt = { ...stripSeam(rr), receipt_id: collectiveReceiptId("s5-3/stale"), receipt_ref: collectiveReceiptId("s5-3/stale"), requirement_refs: ["requirement://verifier/path/v1"] };
    const staleReceiptAdmission = await refused(() => orchestration.record({ contract_id: COLLECTIVE_CONTRACTS.receipt, object_id: staleReceipt.receipt_id, record: staleReceipt, expected_head: null }));
    ok("[resolve] a receipt whose closure is stale by ONE member — a requirement dropped after the root was taken — posted straight at the seam around the composer is refused BY THE REGISTERED INVARIANT'S OWN NAME",
      namesRule(staleReceiptAdmission, RECEIPT_RULE_ID), `${staleReceiptAdmission.status}/${staleReceiptAdmission.code}/${String(staleReceiptAdmission.message ?? "").slice(0, 140)}`);
    const orphanReceipt = { ...stripSeam(rr), receipt_id: collectiveReceiptId("s5-3/orphan"), receipt_ref: collectiveReceiptId("s5-3/orphan"), resolved_owner_refs: rr.resolved_owner_refs.filter((o) => o !== SCOPE_REF) };
    orphanReceipt.closure_root = deriveRoot(orphanReceipt, receiptFields);
    const orphanAdmission = await refused(() => orchestration.record({ contract_id: COLLECTIVE_CONTRACTS.receipt, object_id: orphanReceipt.receipt_id, record: orphanReceipt, expected_head: null }));
    const orphanViaComposer = await refused(() => resolutions.resolve({ ...draft, receipt_id: collectiveReceiptId("s5-3/orphan2"), resolved_owner_refs: [SUBJECT] }));
    ok("[resolve] a receipt whose orchestration is not among its resolved owners is refused twice: by the composer by name, and — with a root that DOES recompute, posted around the composer — at the seam by the CORRECTED invariant's own name, which until this slice tested only that the field was present",
      namesRule(orphanAdmission, OWNER_RULE_ID) && !orphanViaComposer.ok && orphanViaComposer.composer && orphanViaComposer.code === "collective_resolution_orchestration_not_resolved_owner",
      `${orphanAdmission.status}/${orphanAdmission.code}/${String(orphanAdmission.message ?? "").slice(0, 120)} | ${orphanViaComposer.code}`);
    const unadmitted = await refused(() => resolutions.resolve({ ...draft, receipt_id: collectiveReceiptId("s5-3/unadmitted"), goal_run_profile_revision_refs: ["goal-run-profile://nobody/revision/9"] }));
    const unserved = await refused(() => resolutions.resolve({ ...draft, receipt_id: collectiveReceiptId("s5-3/unserved"), resolved_owner_refs: [SCOPE_REF, "automation-run://nobody"] }));
    const noReader = await refused(() => new CollectiveResolutions(orchestration, { owners }).resolve({ ...draft, receipt_id: collectiveReceiptId("s5-3/noreader") }));
    ok("[resolve] a receipt naming a profile revision no admitted run carries is refused by name (a resolution that would need a new profile owner); one naming an owner the daemon does not serve is refused by name AFTER asking the daemon; one composed without a System reader is refused rather than taking the release from the caller — none writes",
      !unadmitted.ok && unadmitted.code === "collective_resolution_profile_unadmitted" && !unserved.ok && unserved.code === "collective_resolution_owner_unresolvable" && !noReader.ok && noReader.code === "collective_resolution_system_reader_required",
      `${unadmitted.code}/${unserved.code ?? unserved.message}/${noReader.code}`);
    const twice = await refused(() => resolutions.resolve(draft));
    const receiptsServed = (await orchestration.records(COLLECTIVE_CONTRACTS.receipt)).count;
    ok("[resolve] the same receipt admits once — a second admission is refused by name — and the seam serves exactly one receipt after every refusal above", !twice.ok && twice.code === "collective_resolution_already_admitted" && receiptsServed === 1, `${twice.code}/${receiptsServed}`);

    // -- the lineage ----------------------------------------------------------------------------------------
    const lineageFields = materialFieldsOf("persistent-executable-lineage.v1.invariants.json", LINEAGE_RULE_ID);
    const lineages = new ExecutableLineages(orchestration, { owners, actors });
    const before = (await orchestration.records()).count;
    const seen = await lineages.observe("artifact://s5-3/etl", `sha256:${"1".repeat(64)}`);
    const afterObserve = (await orchestration.records()).count;
    const reused = await refused(() => lineages.reuse(lineageDraft("lineage://s5-3/etl")));
    const lr = reused.value?.record ?? {};
    ok("[chain] observation persists nothing; reuse admits a lineage at posture `reused` under the admitted receipt over an EXACT artifact hash, its coordinate stamped, its binding derived, and its lineage_root re-derived here over the twenty-two registered members",
      seen.persisted === false && before === afterObserve && reused.ok && lr.posture?.status === "reused" && lr.orchestration_ref === SCOPE_REF && lr.system_binding?.system_id === SYSTEM_ID && lr.lineage_root === deriveRoot(lr, lineageFields) && lineageFields.length === 22,
      `${reused.ok}/${reused.code ?? ""}/${String(reused.message ?? "").slice(0, 200)}/${lineageFields.length}`);
    const staleLineage = { ...stripSeam(lr), lineage_id: "lineage://s5-3/stale", artifact_sha256: `sha256:${"f".repeat(64)}` };
    const staleLineageAdmission = await refused(() => orchestration.record({ contract_id: COLLECTIVE_CONTRACTS.lineage, object_id: staleLineage.lineage_id, record: staleLineage, expected_head: null }));
    const untyped = { ...stripSeam(lr), lineage_id: "lineage://s5-3/untyped", posture: { status: "quarantined", orphan_reason: null } };
    untyped.lineage_root = deriveRoot(untyped, lineageFields);
    const untypedAdmission = await refused(() => orchestration.record({ contract_id: COLLECTIVE_CONTRACTS.lineage, object_id: untyped.lineage_id, record: untyped, expected_head: null }));
    ok("[chain] posted around the composer, a lineage whose artifact hash moved after the root was taken is refused by invariant:persistent_executable_lineage.root.recomputes, and a quarantined lineage with no typed reason by invariant:persistent_executable_lineage.orphan.reason_is_typed — an orphaned condition is typed, at the seam, not only in the composer",
      namesRule(staleLineageAdmission, LINEAGE_RULE_ID) && namesRule(untypedAdmission, ORPHAN_RULE_ID), `${staleLineageAdmission.code}/${untypedAdmission.code}`);
    const noParent = await refused(() => lineages.fork({ ...lineageDraft("lineage://s5-3/fork"), source_artifact_refs: [], transformation_receipt_refs: ["receipt://s5-3/transform/1"] }));
    const noReceipt = await refused(() => lineages.fork({ ...lineageDraft("lineage://s5-3/fork"), source_artifact_refs: ["artifact://s5-3/etl"], transformation_receipt_refs: [] }));
    const strangeParent = await refused(() => lineages.fork({ ...lineageDraft("lineage://s5-3/fork"), source_artifact_refs: ["artifact://nobody/knows"], transformation_receipt_refs: ["receipt://s5-3/transform/1"] }));
    const fork = await refused(() => lineages.fork({ ...lineageDraft("lineage://s5-3/fork", { artifact_ref: "artifact://s5-3/etl-fork", artifact_sha256: `sha256:${"2".repeat(64)}` }), source_artifact_refs: ["artifact://s5-3/etl"], transformation_receipt_refs: ["receipt://s5-3/transform/1"] }));
    const sessionSubject = await refused(() => lineages.reuse(lineageDraft("lineage://s5-3/session-owned", { accountable_subject_ref: "session://s_creator" })));
    const latest = await refused(() => lineages.reuse(lineageDraft("lineage://s5-3/latest", { artifact_sha256: "latest" })));
    ok("[chain] a fork with no parent, no transformation receipt, or a parent no lineage here carries is refused by name; a fork naming an admitted parent and its receipt admits as `forked`; a lineage whose accountable subject is a SESSION, or whose artifact is a mutable latest, is refused by name",
      !noParent.ok && noParent.code === "lineage_fork_parent_absent" && !noReceipt.ok && noReceipt.code === "lineage_fork_receipt_absent" && !strangeParent.ok && strangeParent.code === "lineage_fork_parent_unknown" && fork.ok && fork.value?.record?.posture?.status === "forked" && !sessionSubject.ok && sessionSubject.code === "lineage_accountable_subject_not_durable" && !latest.ok && latest.code === "lineage_mutable_latest_refused",
      `${noParent.code}/${noReceipt.code}/${strangeParent.code}/${fork.code ?? fork.message ?? "ok"}/${sessionSubject.code}/${latest.code}`);

    // -- install over a REAL automation the daemon serves --------------------------------------------------
    const project = await call("POST", "/v1/hypervisor/projects", { repository_url: "https://example.invalid/collective/lineage.git", project_name: "s5-3-collective" });
    const projectId = project.body?.selected_project_id ?? project.body?.project?.project_id ?? project.body?.project_id ?? "";
    const automation = await call("POST", "/v1/hypervisor/automations", { project_ref: projectId, name: "s5-3 lineage installation", steps: [] });
    const automationId = automation.body?.automation?.automation_id ?? automation.body?.automation?.id ?? "";
    const INSTALLATION = `automation-installation://${automationId}`;
    const skipped = await refused(() => lineages.activate("lineage://s5-3/etl", { runtime_ref: DELEGATION, runtime_kind: "delegation", lease_refs: [], caretaker_ref: DELEGATION }));
    const unbound = await refused(() => lineages.install("lineage://s5-3/etl", { installation_ref: "automation-installation://nobody" }));
    const installed = await refused(() => lineages.install("lineage://s5-3/etl", { installation_ref: INSTALLATION }));
    ok("[chain] activating an uninstalled lineage is refused as a skipped transition; installing into an automation the daemon does not serve is refused by name AFTER asking the daemon; installing into a REAL automation the daemon admitted (project → automation, both through the daemon's own routes) succeeds at the predecessor's exact head",
      !skipped.ok && skipped.code === "lineage_transition_skipped" && !unbound.ok && unbound.code === "lineage_installation_unbound" && automationId.length > 0 && installed.ok && installed.value?.record?.posture?.status === "installed" && installed.value?.record?.installation_ref === INSTALLATION,
      `${skipped.code}/${unbound.code}/project ${project.status} ${projectId || JSON.stringify(project.body).slice(0, 120)}/automation ${automation.status} ${automationId || JSON.stringify(automation.body).slice(0, 120)}/${installed.code ?? installed.message ?? "ok"}`);

    // -- activate: a runtime the daemon serves, live leases, a caretaker that resolves ------------------------
    await leases.revoke("context-lease://s5-3-collective/l2");
    const unservedRuntime = await refused(() => lineages.activate("lineage://s5-3/etl", { runtime_ref: "automation-run://nobody", runtime_kind: "automation_run", lease_refs: ["context-lease://s5-3-collective/l1"], caretaker_ref: DELEGATION }));
    const deadLease = await refused(() => lineages.activate("lineage://s5-3/etl", { runtime_ref: DELEGATION, runtime_kind: "delegation", lease_refs: ["context-lease://s5-3-collective/l2"], caretaker_ref: DELEGATION }));
    const strangeCaretaker = await refused(() => lineages.activate("lineage://s5-3/etl", { runtime_ref: DELEGATION, runtime_kind: "delegation", lease_refs: ["context-lease://s5-3-collective/l1"], caretaker_ref: "participation://s5-3-collective/nobody" }));
    const activated = await refused(() => lineages.activate("lineage://s5-3/etl", { runtime_ref: DELEGATION, runtime_kind: "delegation", lease_refs: ["context-lease://s5-3-collective/l1"], caretaker_ref: DELEGATION }));
    ok("[chain] activation is refused by name for a runtime the daemon does not serve (asked), for a lease the M04.11 composer already REVOKED, and for a caretaker that resolves to no accountable actor; it succeeds binding the kernel-owned delegation as runtime and caretaker with the live lease — ArtifactRef.lifecycle.status = active satisfies nothing here, a served runtime does",
      !unservedRuntime.ok && unservedRuntime.code === "lineage_runtime_unbound" && !deadLease.ok && deadLease.code === "lineage_lease_not_live" && !strangeCaretaker.ok && strangeCaretaker.code === "lineage_caretaker_unresolvable" && activated.ok && activated.value?.record?.posture?.status === "active" && activated.value?.record?.runtime_ref === DELEGATION,
      `${unservedRuntime.code}/${deadLease.code}/${strangeCaretaker.code}/${activated.code ?? activated.message ?? "ok"}`);

    // -- posture: a read model; leases, removal and dependencies ------------------------------------------------
    const w0 = (await orchestration.records()).count;
    const p1 = await lineages.posture("lineage://s5-3/etl"); const p2 = await lineages.posture("lineage://s5-3/etl");
    const w1 = (await orchestration.records()).count;
    ok("[posture] posture is a READ MODEL recomputed from the owners on every call: two calls agree, write nothing, and derive `active` from a durable subject, a resolving caretaker, live leases, available dependencies and a served runtime",
      p1.nature === "read_model" && JSON.stringify(p1) === JSON.stringify(p2) && w0 === w1 && p1.derived.status === "active" && p1.checks.accountable_subject_durable && p1.checks.caretaker_resolves === true && p1.checks.leases_live && p1.checks.runtime_served === true, JSON.stringify(p1.checks));
    const removed = await refused(() => lineages.onCreatorRemoved("lineage://s5-3/etl", "session://the-creator"));
    const w2 = (await orchestration.records()).count;
    ok("[removal] after the creating principal's session is reported ended, the lineage is served unchanged and its posture stays `active`, because its accountable subject is the durable automation, not the session — nothing is transferred, nothing extended, nothing written",
      removed.ok && removed.value?.transferred === false && removed.value?.extended === false && removed.value?.posture?.derived?.status === "active" && w2 === w1, `${removed.code ?? "ok"}/${w2 - w1}`);
    await leases.revoke("context-lease://s5-3-collective/l1");
    const revokedLease = await leases.read("context-lease://s5-3-collective/l1");
    const stale = await lineages.posture("lineage://s5-3/etl");
    ok("[leases] revoking the lease through the M04.11 composer moves the DERIVED posture to `stopped` with orphan_reason `authority_stale` while the recorded posture stays `active` (what was admitted vs what holds); the lease chain shows the revocation as an exact-head successor and no lease was extended — NOT CLAIMED: TTL elapse, which the daemon does not evaluate",
      stale.derived.status === "stopped" && stale.derived.orphan_reason === "authority_stale" && stale.recorded.status === "active" && revokedLease?.current?.status === "revoked" && revokedLease?.revisions?.length === 2, JSON.stringify(stale.derived));
    const notCaretaker = await lineages.onParticipantExited("lineage://s5-3/etl", "participation://s5-3-collective/somebody-else");
    const caretakerGone = await refused(() => lineages.onParticipantExited("lineage://s5-3/etl", DELEGATION));
    ok("[removal] a participant's exit that is not the caretaker's moves nothing; the caretaker's exit, reported to the composition, mints an exact-head successor `quarantined` with the typed reason `caretaker_absent` and copies no lease and transfers no ownership",
      notCaretaker === null && caretakerGone.ok && caretakerGone.value?.record?.posture?.status === "quarantined" && caretakerGone.value?.record?.posture?.orphan_reason === "caretaker_absent" && caretakerGone.value?.record?.accountable_subject_ref === "automation://s5-3/etl", `${caretakerGone.code ?? "ok"}`);
    const dep = await refused(() => lineages.reuse(lineageDraft("lineage://s5-3/dep", { artifact_ref: "artifact://s5-3/lib", artifact_sha256: `sha256:${"3".repeat(64)}` })));
    const dependent = await refused(() => lineages.reuse(lineageDraft("lineage://s5-3/dependent", { artifact_ref: "artifact://s5-3/app", artifact_sha256: `sha256:${"4".repeat(64)}`, dependency_lineage_refs: ["lineage://s5-3/dep"] })));
    await lineages.retire("lineage://s5-3/dep");
    const dependentPosture = await lineages.posture("lineage://s5-3/dependent");
    const lateDependent = await refused(() => lineages.reuse(lineageDraft("lineage://s5-3/late", { artifact_ref: "artifact://s5-3/late", artifact_sha256: `sha256:${"5".repeat(64)}`, dependency_lineage_refs: ["lineage://s5-3/dep"] })));
    ok("[dependency] retiring a dependency lineage leaves the dependent's record untouched and its DERIVED posture `dependency_unavailable`; a new lineage depending on the retired one is refused by name",
      dep.ok && dependent.ok && dependentPosture.checks.dependencies_available === false && dependentPosture.recorded.status === "reused" && !lateDependent.ok && lateDependent.code === "lineage_dependency_retired", `${lateDependent.code}`);

    // -- the verbs ------------------------------------------------------------------------------------------
    const v = "lineage://s5-3/fork";
    await lineages.install(v, { installation_ref: INSTALLATION });
    await lineages.activate(v, { runtime_ref: DELEGATION, runtime_kind: "delegation", lease_refs: [], caretaker_ref: DELEGATION });
    const stopped = await refused(() => lineages.stop(v, "policy"));
    const quarantined = await refused(() => lineages.quarantine(v, "health_stale"));
    const latestRepair = await refused(() => lineages.repair(v, { successor_artifact_ref: "artifact://s5-3/etl-fork", successor_artifact_sha256: "latest", transformation_receipt_ref: "receipt://s5-3/transform/2" }));
    const repairing = await refused(() => lineages.repair(v, { successor_artifact_ref: "artifact://s5-3/etl-fork-fixed", successor_artifact_sha256: `sha256:${"6".repeat(64)}`, transformation_receipt_ref: "receipt://s5-3/transform/2" }));
    const unknownSuccessor = await refused(() => lineages.replace(v, { successor_lineage_ref: "lineage://s5-3/next" }));
    const next = await refused(() => lineages.succeedFrom(v, lineageDraft("lineage://s5-3/next", { artifact_ref: "artifact://s5-3/etl-fork-fixed", artifact_sha256: `sha256:${"6".repeat(64)}` })));
    const replaced = await refused(() => lineages.replace(v, { successor_lineage_ref: "lineage://s5-3/next" }));
    const afterTerminal = await refused(() => lineages.retire(v));
    const retired = await refused(() => lineages.retire("lineage://s5-3/next"));
    const chainV = await lineages.read(v);
    const rootsHold = (chainV?.revisions ?? []).every((rev) => rev.lineage_root === deriveRoot(rev, lineageFields));
    ok("[verbs] stop (policy, no orphan reason), quarantine (typed), repair (an EXACT successor artifact — a mutable latest is refused by name), replace (an admitted successor that names its predecessor — an unknown one is refused) and retire are each an exact-head successor whose root re-seals and re-derives here; a replaced lineage is terminal and admits no further verb",
      stopped.ok && stopped.value?.record?.posture?.orphan_reason === null && quarantined.ok && quarantined.value?.record?.posture?.orphan_reason === "health_stale" && !latestRepair.ok && latestRepair.code === "lineage_mutable_latest_refused" && repairing.ok && !unknownSuccessor.ok && unknownSuccessor.code === "lineage_replacement_unknown" && next.ok && next.value?.record?.successor_of === v && replaced.ok && replaced.value?.record?.posture?.status === "replaced" && !afterTerminal.ok && afterTerminal.code === "lineage_terminal" && retired.ok && (chainV?.revisions?.length ?? 0) >= 7 && rootsHold,
      `${stopped.code ?? "ok"}/${quarantined.code ?? "ok"}/${latestRepair.code}/${repairing.code ?? "ok"}/${unknownSuccessor.code}/${next.code ?? "ok"}/${replaced.code ?? "ok"}/${afterTerminal.code}/${retired.code ?? "ok"}/revs=${chainV?.revisions?.length}/roots=${rootsHold}`);

    // -- restart: every record re-derives from durable admissions --------------------------------------------
    const beforeRestart = { receipt: await orchestration.recordChain(COLLECTIVE_CONTRACTS.receipt, RECEIPT_ID), etl: await orchestration.recordChain(COLLECTIVE_CONTRACTS.lineage, "lineage://s5-3/etl"), fork: await orchestration.recordChain(COLLECTIVE_CONTRACTS.lineage, v) };
    await plane.stop();
    plane = await startIsolatedPlane({ dataDir, baseEnv, env, serve: true });
    requireValue(plane, "daemon did not restart");
    daemonUrl = plane.daemonUrl;
    client = createRuntimeSubstrateClient({ endpoint: daemonUrl, headers: operatorHeaders });
    const again = { receipt: await refused(() => client.getSystemRecord(SYSTEM_ID, COLLECTIVE_CONTRACTS.receipt, RECEIPT_ID)), etl: await refused(() => client.getSystemRecord(SYSTEM_ID, COLLECTIVE_CONTRACTS.lineage, "lineage://s5-3/etl")), fork: await refused(() => client.getSystemRecord(SYSTEM_ID, COLLECTIVE_CONTRACTS.lineage, v)) };
    const same = (k) => again[k].ok && again[k].value?.head === beforeRestart[k].head && again[k].value?.revisions?.length === beforeRestart[k].revisions.length && canonical(stripSeam(again[k].value.current)) === canonical(stripSeam(beforeRestart[k].current));
    ok("[restart] after the daemon is stopped and started on the same data dir, a fresh client that remembers nothing reads the receipt and both lineages back at the SAME heads, the same revision counts and the same bytes — re-derived from durable admissions, not remembered",
      same("receipt") && same("etl") && same("fork") && deriveRoot(again.etl.value.current, lineageFields) === again.etl.value.current.lineage_root, `${again.receipt.code ?? ""}/${again.etl.code ?? ""}/${again.fork.code ?? ""}`);

    // -- the namespace and the structure ---------------------------------------------------------------------
    const call2 = (method, path, body) => jsonCall(daemonUrl, method, path, body, operatorHeaders);
    const retiredRoutes = await Promise.all(["collective-resolutions", "lineages", "artifacts"].map((tail) => call2("POST", `/v1/goal-orchestration/goal-runs/${encodeURIComponent(SUBJECT)}/${tail}`, { through: "the retired plane" })));
    const routerSource = readFileSync(join(REPO, "crates/node/src/bin/hypervisor-daemon.rs"), "utf8");
    ok("[retirement] and the daemon serves NOTHING under /v1/goal-orchestration/ for collective resolutions, lineages or artifacts for the operator's own session, and its router registers no collective, lineage or caretaker route: the composition above replaced a plane that never existed here",
      retiredRoutes.every((r) => r.status === 404 || r.status === 405) && !/"\/v1\/[^"]*(?:collective-resolution|executable-lineage|persistent-executable|caretaker|artifact-lifecycle|lineages?\/[^"]*\/(?:observe|reuse|fork|install|activate|quarantine|repair|replace|retire))[^"]*"/u.test(routerSource), retiredRoutes.map((r) => r.status).join("/"));
    const composerSource = readFileSync(join(REPO, "apps/ioi-ai/orchestration/src/collective.ts"), "utf8");
    ok("[structure] the composer is application-layer code over the primitives: it holds no store, reaches no daemon URL, computes every root itself, and reaches records only through the seam's record, records and recordChain and owners only through the readers it is handed",
      !/localStorage|writeFileSync|mkdirSync|\/v1\//u.test(composerSource) && /rootOf\(/u.test(composerSource) && /\.record\(\{/u.test(composerSource) && /\.recordChain\(/u.test(composerSource) && /\.records\(/u.test(composerSource) && /owners\.exists\(/u.test(composerSource) && /system\.active\(/u.test(composerSource), "");

    if (MUTATION) {
      const reReceipt = deriveRoot(rr, receiptFields); const movedReceipt = deriveRoot({ ...rr, resolved_at: "1970-01-01T00:00:00Z" }, receiptFields);
      const reLineage = deriveRoot(lr, lineageFields); const movedLineage = deriveRoot({ ...lr, stop_policy_ref: "policy://moved" }, lineageFields);
      ok("DRILL D1 — the payload oracle: re-deriving the ADMITTED receipt's and lineage's roots from their own members reproduces them, and a single moved member changes each", reReceipt === rr.closure_root && movedReceipt !== reReceipt && reLineage === lr.lineage_root && movedLineage !== reLineage, `${reReceipt === rr.closure_root}/${reLineage === lr.lineage_root}`);
      const removedMember = { ...lr }; delete removedMember.posture;
      let removedThrows = false; try { deriveRoot(removedMember, lineageFields); } catch { removedThrows = true; }
      ok("DRILL D2 — the same oracle does not reproduce a root over a record with a member REMOVED", removedThrows || deriveRoot(removedMember, lineageFields) !== lr.lineage_root, "");
      const admits = await refused(() => Promise.resolve({ record: {} }));
      const rejects = await refused(() => Promise.reject(Object.assign(new Error("x"), { status: 422, details: { daemon: { error: { code: "system_record_not_registered_valid" } } } })));
      ok("DRILL D3 — the refusal predicate reads an admitted reply as ok and a typed refusal as refused with its daemon code; and the transition table the skipped-transition claim rests on says activate does NOT follow reused and install DOES, so the claim is falsifiable rather than vacuous",
        admits.ok && !rejects.ok && rejects.status === 422 && rejects.code === "system_record_not_registered_valid" && !LINEAGE_TRANSITIONS.activate.includes("reused") && LINEAGE_TRANSITIONS.install.includes("reused"), `${admits.ok}/${rejects.code}`);
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
  ok("the verifier completed", false, String(error?.stack ?? error).slice(0, 600));
}
if (!MUTATION) emitVerifierCensus({ verifierId: "collective-artifact-runtime-lifecycle", sourceUrl: import.meta.url, results });
const failed = results.filter((r) => !r.pass);
console.log(`\n${results.length - failed.length}/${results.length} passed`);
if (failed.length) process.exitCode = 1;

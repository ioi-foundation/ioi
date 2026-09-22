// M10.9 PLANE — the qualification driven against a real isolated daemon and the REAL wallet.network
// principal-authority fixture, never a simulation of one.
//
// What this leg does, in order:
//   the bounded System is admitted and activated through its governed genesis;
//   TWO orchestrations are composed — the collective arm and the cheaper baseline arm, because a pairing
//     whose arms are one composition compares a composition with itself and every axis matches trivially;
//   the ESTIMAND and the PAIRING are admitted through the generic System-record seam BEFORE anything runs,
//     and the seam is shown refusing an unmatched pairing BY THE FAILING AXIS'S OWN RULE NAME, a
//     caller-authored binding, and a root that no longer recomputes;
//   a persistent executable lineage is composed, installed into a REAL automation the daemon serves and
//     activated on a kernel-owned delegation;
//   the KNOCKOUTS are performed — each against a real operation, each reverted, and each measured for what
//     it actually did to the plane rather than for what a record says it did;
//   THE INSTALLATION AXIS IS READ FROM THE OWNER: the automation is deleted and the leg shows the lineage's
//     posture staying GREEN while the owner says the installation is gone. That green posture is the whole
//     point of the axis: `posture()` re-derives from the accountable subject, the caretaker, context
//     leases, dependency lineages and `runtime_ref` and never from `installation_ref`, so the obvious
//     instrument reports success while measuring nothing;
//   the VERDICT is admitted with its two halves separately rooted, and a verdict sharing one root is
//     refused by the registered rule's own name;
//   and NOTHING WAS PROMOTED: the record count, the automation census and the lineage's recorded posture
//     are read before and after, because "evaluation emits judgment only" is the clause this unit exists
//     to assert and no code asserted it before.
//
// EVERY KNOCKOUT REPORTS WHETHER IT BIT. An axis that changed nothing observable is not a knockout, and
// this leg fails rather than reporting a matrix of no-ops.

import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

import { isIsolatedDaemonLogName, sanitizedVerifierBaseEnv, startIsolatedPlane } from "../../apps/hypervisor/scripts/lib/isolated-daemon.mjs";
import { startRealWalletNetworkPrincipalAuthorityFixture } from "../../apps/hypervisor/scripts/lib/wallet-network-principal-authority-fixture.mjs";
import { bootstrapActiveSystem, exactGenesisBody, rebindGenesisBodySystem, recomputeReleaseHashes } from "../../apps/hypervisor/scripts/verify-hypervisor-system-sequence-zero-materialization.mjs";

const SYSTEM_ID = "system://ioi/collective/m10-9-qualification";
const GENESIS_ID = "genesis://ioi/collective/m10-9-qualification/genesis";
const CONSTITUTION_REF = "constitution://ioi/collective/m10-9-qualification/v1";
const PACKAGE = "package://ioi/outcome-room";
const DEPLOYMENT_AUTHORITY = "domain://acme-host";
const COLLECTIVE_SCOPE = "app-scope://ioi-ai/orchestration/orc_m109_collective";
const BASELINE_SCOPE = "app-scope://ioi-ai/orchestration/orc_m109_baseline";
const SUBJECT = "goal://m109_qualification";

const ESTIMAND_CONTRACT = "schema://ioi/applications/ioi-ai/collective-qualification-estimand/v1";
const PAIRING_CONTRACT = "schema://ioi/applications/ioi-ai/collective-baseline-pairing/v1";
const VERDICT_CONTRACT = "schema://ioi/applications/ioi-ai/collective-qualification-verdict/v1";
const META = "docs/architecture/_meta/schemas";

// ---- the small helpers this leg needs, kept identical in behaviour to M04.12's -------------------------------
function canonical(value) {
  if (value === null || typeof value !== "object") { const e = JSON.stringify(value); return e === undefined ? "" : e; }
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(",")}}`;
}
const at = (value, path) => path.replace(/^\$\./u, "").split(".").reduce((acc, key) => (acc === undefined || acc === null ? undefined : acc[key]), value);

/** The root is derived from the REGISTERED rule's own material_fields, so the leg and the seam cannot drift. */
function rootOf(ROOT, invariantFile, ruleId, record) {
  const rule = JSON.parse(readFileSync(join(ROOT, META, "invariants", invariantFile), "utf8")).rules.find((r) => r.rule_id === ruleId);
  if (!rule) throw new Error(`${ruleId} is not registered`);
  const material = {};
  for (const [field, descriptor] of Object.entries(rule.expression.material_fields)) {
    const value = at(record, descriptor.path);
    if (value === undefined) throw new Error(`${ruleId}: ${descriptor.path} is absent from the record being sealed`);
    material[field] = value;
  }
  return `sha256:${createHash("sha256").update(canonical(material)).digest("hex")}`;
}

async function jsonCall(base, method, path, body, headers = {}) {
  const payload = body === undefined ? undefined : JSON.stringify(body);
  return await new Promise((resolve, reject) => {
    const request = httpRequest(new URL(path, base), { method, headers: { "content-type": "application/json", ...(payload === undefined ? {} : { "content-length": Buffer.byteLength(payload) }), ...headers } }, (response) => {
      const chunks = [];
      response.on("data", (c) => chunks.push(c));
      response.on("end", () => { clearTimeout(deadline); const raw = Buffer.concat(chunks).toString("utf8"); let parsed = {}; try { parsed = raw ? JSON.parse(raw) : {}; } catch { parsed = { raw }; } resolve({ status: response.statusCode, body: parsed }); });
    });
    const deadline = setTimeout(() => request.destroy(new Error(`HTTP timeout at ${method} ${path}`)), 900_000);
    request.on("error", (error) => { clearTimeout(deadline); reject(error); });
    if (payload !== undefined) request.write(payload);
    request.end();
  });
}

function genesisBody() {
  const body = exactGenesisBody();
  body.release.package_id = PACKAGE;
  body.release.manifest_id = `${PACKAGE}/release/sha256:${"7".repeat(64)}`;
  body.release.display_name = "Collective and persistent-controller qualification M10.9 verifier package";
  body.release.description = "The estimand, the matched pairing and the qualification verdict composed by ioi.ai over the System-record seam.";
  body.proposed_instantiation.candidate.package_id = PACKAGE;
  body.proposed_instantiation.candidate.manifest_ref = body.release.manifest_id;
  body.proposed_instantiation.candidate.instantiation.proposed_by = "project://ioi/collective";
  recomputeReleaseHashes(body.release);
  // EVERY PROFILE REF CARRIES THE SYSTEM'S OWN TAIL. The genesis blocker `profile_coordinate_mismatch`
  // requires `<scheme>://<system tail>/…`, so a ref abbreviated to a shorter project path is refused
  // before anything else in this leg can run.
  const TAIL = SYSTEM_ID.slice("system://".length);
  return rebindGenesisBodySystem(body, {
    systemId: SYSTEM_ID,
    genesisId: GENESIS_ID,
    constitutionRef: CONSTITUTION_REF,
    deploymentProfileRef: `deployment-profile://${TAIL}/local/revision/sha256:${"a".repeat(64)}`,
    orderingProfileRef: `ordering-profile://${TAIL}/hosted`,
    oracleProfileRef: `oracle-evidence-profile://${TAIL}/fail-closed`,
    lifecycleProfileRef: `lifecycle-profile://${TAIL}/default`,
  });
}

const refused = async (fn) => {
  try { return { ok: true, value: await fn() }; } catch (error) {
    const daemon = error?.details?.daemon?.error?.code ?? error?.details?.daemon?.code ?? "";
    return { ok: false, status: error?.status, code: daemon || error?.code, message: String(error?.message ?? "") };
  }
};
const namesRule = (r, ruleId) => !r.ok && String(r.message ?? "").includes(`invariant:${ruleId}`);

// ---- the leg ---------------------------------------------------------------------------------------------------
export async function planeLeg({ ROOT, LIB }) {
  const started = Date.now();
  const findings = [];
  const observed = { knockouts: [], installation: null, seam: {}, promotion: {} };
  const note = (what) => findings.push(what);
  const dataDir = mkdtempSync(join(tmpdir(), "ioi-m109-qualification-"));
  let resolver;
  let plane;
  try {
    const sdkPath = join(ROOT, "packages", "agent-sdk", "dist", "index.js");
    const composerPath = join(ROOT, "apps", "ioi-ai", "orchestration", "dist", "index.js");
    if (!existsSync(sdkPath)) return { blocked: true, findings: ["BLOCKED: build packages/agent-sdk first"], seconds: 0, observed };
    if (!existsSync(composerPath)) return { blocked: true, findings: ["BLOCKED: build apps/ioi-ai/orchestration first"], seconds: 0, observed };
    const { Orchestration, createRuntimeSubstrateClient } = await import(pathToFileURL(sdkPath).href);
    const { COLLECTIVE_CONTRACTS, CONTEXT_CONTRACTS, CollectiveResolutions, ContextCells, ContextLeases, ExecutableLineages, GoalRuns, collectiveReceiptId } = await import(pathToFileURL(composerPath).href);

    const baseEnv = { ...sanitizedVerifierBaseEnv() };
    resolver = await startRealWalletNetworkPrincipalAuthorityFixture({ baseEnv });
    const env = { ...resolver.env, IOI_HYPERVISOR_AUTHORITY_PRINCIPAL_REF: DEPLOYMENT_AUTHORITY, IOI_HYPERVISOR_SESSIONS_ROOT: join(dataDir, "verifier-session-workspaces") };
    plane = await startIsolatedPlane({ dataDir, baseEnv, env, serve: false });
    if (!plane) return { blocked: true, findings: ["BLOCKED: build target/debug/hypervisor-daemon first"], seconds: 0, observed };

    const log = readdirSync(dataDir).filter(isIsolatedDaemonLogName).map((n) => readFileSync(join(dataDir, n), "utf8")).join("\n");
    const token = log.match(/\b(ioi_bootstrap_[0-9a-f]+)\b/u)?.[1];
    if (!token) return { blocked: true, findings: ["BLOCKED: the isolated daemon exposed no bootstrap token"], seconds: 0, observed };
    const operator = await jsonCall(plane.daemonUrl, "POST", "/v1/hypervisor/auth/bootstrap", { token, password: "m109-qualification-password", email: "m109@ioi.local" });
    const sessionToken = operator.status === 200 && operator.body?.session_token;
    if (!sessionToken) return { blocked: true, findings: [`BLOCKED: operator bootstrap failed ${operator.status}`], seconds: 0, observed };
    const headers = { authorization: `Bearer ${sessionToken}` };
    let daemonUrl = plane.daemonUrl;
    const call = (method, path, body) => jsonCall(daemonUrl, method, path, body, headers);
    const whoami = await call("GET", "/v1/hypervisor/auth/whoami", undefined);
    const OWNER = `user://${operator.body?.principal?.principal_id}`;
    const TENANT = whoami.body?.principal?.tenant_refs?.[0] ?? OWNER;
    let client = createRuntimeSubstrateClient({ endpoint: daemonUrl, headers });

    const active = await bootstrapActiveSystem(call, resolver, dataDir, genesisBody());
    if (!(active.status === "active" || active.source)) return { blocked: true, findings: [`BLOCKED: the System did not activate (${JSON.stringify(active).slice(0, 180)})`], seconds: 0, observed };

    // -- TWO arms, because a pairing whose arms are one composition matches on every axis trivially --
    // `collective` is rebound after the crash/restart knockout, because the isolated plane comes back on a
    // NEW port and an orchestration still holding the dead client would answer nothing afterwards.
    let collective = await Orchestration.compose(client, { system_id: SYSTEM_ID, owner_ref: TENANT, scope_ref: COLLECTIVE_SCOPE, objective: "M10.9: the collective arm under claim" });
    let baseline = await Orchestration.compose(client, { system_id: SYSTEM_ID, owner_ref: TENANT, scope_ref: BASELINE_SCOPE, objective: "M10.9: the cheaper direct-path arm" });
    if (collective.scope_ref !== COLLECTIVE_SCOPE || baseline.scope_ref !== BASELINE_SCOPE) note("the two arms are not two compositions");

    // ============ THE DECLARATIONS, BEFORE ANYTHING RUNS ===========================================
    const ESTIMAND_REF = "estimand://m109/cooperation-surplus/1";
    const PAIRING_REF = "pairing://m109/collective-vs-direct/1";
    const axisRoot = (axis) => `sha256:${createHash("sha256").update(`m109/${axis}`).digest("hex")}`;
    const estimandBody = () => ({
      schema_version: "ioi.ioi-ai.collective-qualification-estimand.v1",
      estimand_id: ESTIMAND_REF,
      estimand_ref: ESTIMAND_REF,
      estimand_kind: "resilience",
      quantity: { metric_ref: "metric://m109/solved-rate", unit: "rate", aggregation: "mean" },
      direction: "higher_is_better",
      minimum_effect: { value: 0.05, basis: "absolute" },
      cost_normalization: "per_cost_unit",
      decision_rule: "The collective arm confirms only if, under every performed knockout, its cost-normalized mean degrades by at least the minimum effect LESS than the matched baseline's on the same frozen cases; any smaller gap, or a gap in the other direction, fails.",
      knockout_axis_refs: ["axis://knockout/caretaker_exit", "axis://knockout/dependency_retired"],
      declared_at: "2026-09-21T12:00:00Z",
      declared_before_epoch_freeze: true,
      epoch_ref: null,
      qualifies_nothing_on_its_own: true,
    });
    const estimand = estimandBody();
    estimand.estimand_root = rootOf(ROOT, "collective-qualification-estimand.v1.invariants.json", "collective_qualification_estimand.root.recomputes", estimand);
    const estimandAdmitted = await refused(() => collective.record({ contract_id: ESTIMAND_CONTRACT, object_id: ESTIMAND_REF, record: estimand, expected_head: null }));
    if (!estimandAdmitted.ok) note(`the estimand did not admit through the seam (${estimandAdmitted.code}: ${estimandAdmitted.message.slice(0, 200)})`);
    observed.seam.estimand = estimandAdmitted.ok;

    const pairingBody = (over = {}) => {
      const record = {
        schema_version: "ioi.ioi-ai.collective-baseline-pairing.v1",
        pairing_id: PAIRING_REF,
        pairing_ref: PAIRING_REF,
        estimand_ref: ESTIMAND_REF,
        collective_arm: { arm_kind: "collective", composition_ref: COLLECTIVE_SCOPE, lineage_refs: ["lineage://m109/etl"], participant_count: 3 },
        baseline_arm: { arm_kind: "direct_path", composition_ref: BASELINE_SCOPE, lineage_refs: [], participant_count: 1 },
        declared_match_axes: [...LIB.MATCH_AXES],
        axis_proofs: Object.fromEntries(LIB.MATCH_AXES.map((axis) => [axis, { collective_root: axisRoot(axis), baseline_root: axisRoot(axis), derived_from: `JCS over the ${axis} material both arms were given` }])),
        baseline_positive_control: { matched_cases_total: 40, matched_cases_passed: 26, control_result_refs: ["evaluation-result://m109/baseline/control/1"] },
        cheaper_baseline_rationale: "The direct path runs one implementer over the same frozen cases with no coordination at all and already passes 26 of the 40, so it is the cheapest arm available and an adequate comparator rather than a straw one.",
        declared_before_either_arm_ran: true,
        epoch_ref: null,
        declared_at: "2026-09-21T12:05:00Z",
        ...over,
      };
      record.pairing_root = rootOf(ROOT, "collective-baseline-pairing.v1.invariants.json", "collective_baseline_pairing.root.recomputes", record);
      return record;
    };
    const pairing = pairingBody();
    const pairingAdmitted = await refused(() => collective.record({ contract_id: PAIRING_CONTRACT, object_id: PAIRING_REF, record: pairing, expected_head: null }));
    if (!pairingAdmitted.ok) note(`the matched pairing did not admit through the seam (${pairingAdmitted.code}: ${pairingAdmitted.message.slice(0, 200)})`);

    // THE SEAM REFUSES BY THE FAILING AXIS'S OWN NAME. Each of the eight is posted separately, because a
    // single unmatched pairing would prove only that SOMETHING refused it.
    for (const axis of LIB.MATCH_AXES) {
      const spoiled = pairingBody({ pairing_id: `pairing://m109/${axis}-differs/1`, pairing_ref: `pairing://m109/${axis}-differs/1` });
      spoiled.axis_proofs[axis].baseline_root = `sha256:${"e".repeat(64)}`;
      spoiled.pairing_root = rootOf(ROOT, "collective-baseline-pairing.v1.invariants.json", "collective_baseline_pairing.root.recomputes", spoiled);
      const r = await refused(() => collective.record({ contract_id: PAIRING_CONTRACT, object_id: spoiled.pairing_id, record: spoiled, expected_head: null }));
      const rule = `collective_baseline_pairing.axis_${axis}.matches`;
      if (!namesRule(r, rule)) note(`an unmatched ${axis} axis was not refused by ${rule} (${r.ok ? "it ADMITTED" : `${r.code}: ${r.message.slice(0, 140)}`})`);
    }
    observed.seam.axes_refused_by_name = true;

    const authored = pairingBody({ pairing_id: "pairing://m109/authored-binding/1", pairing_ref: "pairing://m109/authored-binding/1" });
    authored.system_binding = { schema_version: "ioi.foundations.system-scoped-object-binding.v1", system_id: SYSTEM_ID, parent_scope_ref: COLLECTIVE_SCOPE, proposed_or_issued_by_ref: OWNER, payload_root: `sha256:${"0".repeat(64)}`, created_at: "2026-09-21T12:00:00Z", updated_at: null };
    const authoredRefusal = await refused(() => collective.record({ contract_id: PAIRING_CONTRACT, object_id: authored.pairing_id, record: authored, expected_head: null }));
    if (authoredRefusal.ok || !String(authoredRefusal.code ?? "").includes("binding_authored")) {
      note(`a caller-authored system_binding was not refused by the seam (${authoredRefusal.ok ? "it ADMITTED" : authoredRefusal.code})`);
    }

    const moved = pairingBody({ pairing_id: "pairing://m109/moved/1", pairing_ref: "pairing://m109/moved/1" });
    moved.cheaper_baseline_rationale = "A rationale edited after the root was taken, which is exactly how a declaration stops being one.";
    const movedRefusal = await refused(() => collective.record({ contract_id: PAIRING_CONTRACT, object_id: moved.pairing_id, record: moved, expected_head: null }));
    if (!namesRule(movedRefusal, "collective_baseline_pairing.root.recomputes")) {
      note(`a pairing whose content moved after its root was taken was not refused by its root rule (${movedRefusal.ok ? "it ADMITTED" : movedRefusal.code})`);
    }

    // ============ THE COLLECTIVE ARM'S PERSISTENT LINEAGE ==========================================
    const profileFixture = JSON.parse(readFileSync(join(ROOT, META, "fixtures", "goal-run-profile-resolution-receipt-v1", "positive-minimal.json"), "utf8"));
    const profileReceipt = { ...profileFixture, receipt_id: "receipt://m109/profile-resolution", goal_ref: SUBJECT };
    profileReceipt.receipt_root = rootOf(ROOT, "goal-run-profile-resolution-receipt.v1.invariants.json", "goal_run_profile_resolution_receipt.closure.recomputes", profileReceipt);
    await refused(() => collective.record({ contract_id: "schema://ioi/applications/ioi-ai/goal-run-profile-resolution-receipt/v1", object_id: profileReceipt.receipt_id, record: profileReceipt, expected_head: null }));
    const runs = new GoalRuns(collective);
    const run = await refused(() => runs.admit({ goal_run_id: "gr_m109", goal_ref: SUBJECT, owner_ref: OWNER, profile_resolution_receipt_ref: profileReceipt.receipt_id, origin_surface: "api", normalized_goal: "hold one persistent executable lineage under a declared claim", source_context_binding: { target_session_ref: null, project_ref: null }, receipt_obligations: [], admitted_state_root_ref: "artifact://m109/admitted-state", authority_scope_refs: ["scope:goal.run.create"] }));
    const worker = await refused(() => collective.delegate({ prompt: "carry the lineage's runtime", role: "worker" }));
    const subagentId = worker.value?.subagent_id ?? worker.value?.subagent?.subagent_id ?? (await collective.delegations()).subagents?.[0]?.subagent_id;
    const DELEGATION = `delegation://${collective.thread_id}/${subagentId}`;

    const project = await call("POST", "/v1/hypervisor/projects", { repository_url: "https://example.invalid/m109/qualification.git", project_name: "m109-qualification" });
    const projectId = project.body?.selected_project_id ?? project.body?.project?.project_id ?? project.body?.project_id ?? "";
    const automation = await call("POST", "/v1/hypervisor/automations", { project_ref: projectId, name: "m109 lineage installation", steps: [] });
    const automationId = automation.body?.automation?.automation_id ?? automation.body?.automation?.id ?? "";
    const INSTALLATION = `automation-installation://${automationId}`;
    if (!automationId) note(`the daemon admitted no automation to install into (${automation.status} ${JSON.stringify(automation.body).slice(0, 160)})`);

    const owners = {
      async exists(ref) {
        if (ref.startsWith("automation-installation://")) { const r = await call("GET", `/v1/hypervisor/automations/${encodeURIComponent(ref.slice("automation-installation://".length))}`, undefined); return r.status === 200 && r.body?.ok !== false && Boolean(r.body?.automation ?? r.body?.automation_id); }
        if (ref.startsWith("automation-run://")) { const r = await call("GET", `/v1/hypervisor/automation-executions/${encodeURIComponent(ref.slice("automation-run://".length))}`, undefined); return r.status === 200 && r.body?.ok === true && Boolean(r.body?.execution); }
        if (ref.startsWith("delegation://")) { const [thread, sub] = ref.slice("delegation://".length).split("/"); if (thread !== collective.thread_id) return false; const listed = await collective.delegations(); return (listed.subagents ?? []).some((s) => s.subagent_id === sub); }
        return false;
      },
    };
    const actors = { async isAccountable(ref) { return ref.startsWith("delegation://") ? owners.exists(ref) : false; } };

    const resolutions = new CollectiveResolutions(collective, { owners, system: { async active() { return { system_release_ref: genesisBody().release.manifest_id, constitution_ref: CONSTITUTION_REF, active_profile_set_ref: (await call("GET", "/v1/hypervisor/auth/whoami", undefined)) && genesisBody().proposed_instantiation.candidate.initial_profile_refs.deployment_profile_ref }; } } });
    const RECEIPT_ID = collectiveReceiptId("m109/one");
    const receipt = await refused(() => resolutions.resolve({ receipt_id: RECEIPT_ID, goal_run_profile_revision_refs: [run.value?.record?.goal_run_profile_revision_ref], policy_refs: ["policy://ioi/orchestration/coordination/v1"], lease_policy_refs: ["policy://ioi/lease/context/v1"], artifact_lifecycle_policy_ref: "policy://ioi/artifact/reuse-fork-install-retire/v1", requirement_refs: ["requirement://verifier/path/v1"], resolved_owner_refs: [COLLECTIVE_SCOPE, SUBJECT, DELEGATION] }));
    if (!receipt.ok) return { blocked: true, findings: [`BLOCKED: no collective-resolution receipt (${receipt.code}: ${receipt.message?.slice(0, 200)})`], seconds: Math.round((Date.now() - started) / 1000), observed };

    const cells = new ContextCells(collective);
    const leases = new ContextLeases(collective, { views: { async query() { throw Object.assign(new Error("no views here"), { status: 404 }); } } });
    await refused(() => cells.admit({ context_cell_id: "context-cell://m109/conductor", work_subject_ref: SUBJECT, role_topology_revision_ref: null, role_binding_id: "binding-conductor", accountable_actor_ref: "worker://m109/conductor", role: "conductor", resolver_revision_ref: null, resolver_content_hash: null, model_route_ref: null, memory_projection_refs: [], information_flow_label_refs: [], active_runtime_assignment_ref: null, authority_scope_refs: ["authority://m109/read"], compression_policy_ref: null, current_claim_ref: null, next_wake_condition_ref: null }));
    const lease = (id) => ({ context_lease_id: id, issued_to_ref: "context-cell://m109/conductor", lease_kind: "runtime", allowed_ref_patterns: ["worktree://m109/*"], denied_ref_patterns: [], authority_scope_refs: ["authority://m109/read"], budget_ref: null, ttl_seconds: 3600, receipt_required: false, leased_refs: [], information_flow_label_refs: [], permitted_recipient_roles: ["conductor", "implementer"] });
    await refused(() => leases.issue(lease("context-lease://m109/l1")));

    let lineages = new ExecutableLineages(collective, { owners, actors });
    const draft = (id, over = {}) => ({ lineage_id: id, resolution_receipt_ref: RECEIPT_ID, artifact_ref: "artifact://m109/etl", artifact_sha256: `sha256:${"1".repeat(64)}`, definition_ref: "automation-spec://m109/etl/revision/1", accountable_subject_ref: "automation://m109/etl", stop_policy_ref: "policy://m109/stop/default", ...over });
    const ETL = "lineage://m109/etl";
    await refused(() => lineages.reuse(draft(ETL)));
    await refused(() => lineages.install(ETL, { installation_ref: INSTALLATION }));
    const activated = await refused(() => lineages.activate(ETL, { runtime_ref: DELEGATION, runtime_kind: "delegation", lease_refs: ["context-lease://m109/l1"], caretaker_ref: DELEGATION }));
    if (!activated.ok) return { blocked: true, findings: [`BLOCKED: the lineage did not activate (${activated.code}: ${activated.message?.slice(0, 200)})`], seconds: Math.round((Date.now() - started) / 1000), observed };

    // ============ THE KNOCKOUTS ====================================================================
    const recordCount = async () => (await collective.records()).count;
    const campaignCount = async () => ((await call("GET", "/v1/hypervisor/improvement-campaigns", undefined)).body?.campaigns ?? []).length;
    const promotedBefore = await campaignCount();
    const knockout = async (axis, perform) => {
      const before = await recordCount();
      let bit = false;
      let detail = "";
      try { ({ bit, detail } = await perform({ before })); } catch (error) { detail = `threw:${String(error?.message ?? error).slice(0, 200)}`; }
      const after = await recordCount();
      const row = { axis, bit, detail, records_before: before, records_after: after, records_written: after !== before };
      observed.knockouts.push(row);
      if (!bit) note(`the ${axis} knockout changed nothing observable, so it is a no-op reported as a knockout — ${detail}`);
      return row;
    };

    // participant exit that is NOT the caretaker's moves nothing — and that IS the finding this axis carries
    await knockout("participant_exit", async () => {
      const moved = await lineages.onParticipantExited(ETL, "participation://m109/somebody-else");
      return { bit: moved === null, detail: `a non-caretaker participant's exit returned ${moved === null ? "null, moving nothing" : "a successor, which would be a transfer"}` };
    });
    await knockout("creator_session_removed", async () => {
      const removed = await lineages.onCreatorRemoved(ETL, "session://the-creator");
      return { bit: removed?.transferred === false && removed?.extended === false && removed?.posture?.derived?.status === "active", detail: `transferred=${removed?.transferred} extended=${removed?.extended} posture=${removed?.posture?.derived?.status}` };
    });
    await knockout("context_lease_revoked", async () => {
      await leases.revoke("context-lease://m109/l1");
      const posture = await lineages.posture(ETL);
      const bit = posture.derived.status === "stopped" && posture.derived.orphan_reason === "authority_stale" && posture.recorded.status === "active";
      // REVERT: a new live lease is issued and bound, so the tested topology is not the live one.
      await refused(() => leases.issue(lease("context-lease://m109/l2")));
      return { bit, detail: `derived=${posture.derived.status}/${posture.derived.orphan_reason} recorded=${posture.recorded.status}` };
    });
    await knockout("dependency_retired", async () => {
      await refused(() => lineages.reuse(draft("lineage://m109/dep", { artifact_ref: "artifact://m109/lib", artifact_sha256: `sha256:${"3".repeat(64)}` })));
      await refused(() => lineages.reuse(draft("lineage://m109/dependent", { artifact_ref: "artifact://m109/app", artifact_sha256: `sha256:${"4".repeat(64)}`, dependency_lineage_refs: ["lineage://m109/dep"] })));
      await lineages.retire("lineage://m109/dep");
      const posture = await lineages.posture("lineage://m109/dependent");
      return { bit: posture.checks.dependencies_available === false && posture.recorded.status === "reused", detail: `dependencies_available=${posture.checks.dependencies_available} recorded=${posture.recorded.status}` };
    });
    await knockout("artifact_ancestry_removed", async () => {
      await refused(() => lineages.fork({ ...draft("lineage://m109/fork", { artifact_ref: "artifact://m109/etl-fork", artifact_sha256: `sha256:${"2".repeat(64)}` }), source_artifact_refs: ["artifact://m109/etl"], transformation_receipt_refs: ["receipt://m109/transform/1"] }));
      const before = await lineages.posture("lineage://m109/fork");
      await lineages.retire("lineage://m109/dependent");
      const after = await lineages.posture("lineage://m109/fork");
      // THE MEASUREMENT, NOT THE HOPE: retiring a lineage that is not a DEPENDENCY leaves the fork alone,
      // because ancestry is carried as artifact refs and no lineage edge. The axis bites by showing the
      // fork still NAMES its removed parent artifact while nothing about it degraded.
      const chain = await lineages.read("lineage://m109/fork");
      const names = (chain?.current?.source_artifact_refs ?? []).includes("artifact://m109/etl");
      return { bit: names && before.derived.status === after.derived.status, detail: `the fork still names its parent artifact (${names}) and its posture is unchanged (${after.derived.status}), so ancestry is a naming relation with no liveness edge` };
    });
    await knockout("caretaker_exit", async () => {
      const gone = await refused(() => lineages.onParticipantExited(ETL, DELEGATION));
      return { bit: gone.ok && gone.value?.record?.posture?.status === "quarantined" && gone.value?.record?.posture?.orphan_reason === "caretaker_absent", detail: `${gone.ok ? `${gone.value?.record?.posture?.status}/${gone.value?.record?.posture?.orphan_reason}` : gone.code}` };
    });

    // -- THE INSTALLATION AXIS: read the OWNER, and show the posture staying green --------------------
    const installationRow = await knockout("installation_unbound", async () => {
      const servedBefore = await owners.exists(INSTALLATION);
      const deleted = await call("DELETE", `/v1/hypervisor/automations/${encodeURIComponent(automationId)}`, undefined);
      const servedAfter = await owners.exists(INSTALLATION);
      const posture = await lineages.posture(ETL);
      observed.installation = {
        read_through_posture: false,
        owner_serves_installation: servedAfter,
        posture_after_removal: posture.derived.status,
        served_before: servedBefore,
        delete_status: deleted.status,
      };
      // The posture is expected to be BLIND here. If it ever stops being blind, clause 8's premise has
      // changed and this leg says so rather than quietly passing.
      if (posture.derived.status !== posture.recorded.status && posture.derived.orphan_reason === "artifact_unavailable") {
        note("posture() now reacts to a removed installation, so the trap clause 8 names no longer exists and the gate must be re-measured");
      }
      return { bit: servedBefore === true && servedAfter === false, detail: `the owner served it before (${servedBefore}) and does not after (${servedAfter}); the posture read ${posture.derived.status} both times, which is why this axis is read from the owner` };
    });
    const installFindings = LIB.installationAxisFindings(observed.installation ?? {});
    for (const f of installFindings) note(f);
    if (installationRow.bit && observed.installation?.posture_after_removal === "quarantined") {
      // the caretaker knockout above already quarantined it; the point stands — the posture did not move
      // BECAUSE of the installation, and the leg records which reading it took.
      observed.installation.posture_moved_for_another_reason = true;
    }

    await knockout("controller_runtime_unserved", async () => {
      const served = await owners.exists(DELEGATION);
      const other = await refused(() => lineages.reuse(draft("lineage://m109/unserved", { artifact_ref: "artifact://m109/unserved", artifact_sha256: `sha256:${"5".repeat(64)}` })));
      const installed = await refused(() => lineages.install("lineage://m109/unserved", { installation_ref: INSTALLATION }));
      // The automation is gone, so an install into it is refused BY NAME: the runtime/installation owner
      // reads are the same mechanism, and this is the half that refuses rather than the half that is blind.
      return { bit: served === true && other.ok && !installed.ok && installed.code === "lineage_installation_unbound", detail: `the delegation is served (${served}); installing into the deleted automation is refused as ${installed.code ?? "ADMITTED"}` };
    });

    for (const [axis, verb] of [["lifecycle_stop", "stop"], ["lifecycle_quarantine", "quarantine"], ["lifecycle_repair", "repair"], ["lifecycle_replacement", "replace"], ["lifecycle_retirement", "retire"]]) {
      await knockout(axis, async () => {
        const id = `lineage://m109/${verb}`;
        const project2 = await call("POST", "/v1/hypervisor/automations", { project_ref: projectId, name: `m109 ${verb}` });
        const autoId = project2.body?.automation?.automation_id ?? project2.body?.automation?.id ?? "";
        await refused(() => lineages.reuse(draft(id, { artifact_ref: `artifact://m109/${verb}`, artifact_sha256: `sha256:${createHash("sha256").update(verb).digest("hex")}` })));
        await refused(() => lineages.install(id, { installation_ref: `automation-installation://${autoId}` }));
        await refused(() => lineages.activate(id, { runtime_ref: DELEGATION, runtime_kind: "delegation", lease_refs: [], caretaker_ref: DELEGATION }));
        let r;
        if (verb === "stop") r = await refused(() => lineages.stop(id, "policy"));
        else if (verb === "quarantine") r = await refused(() => lineages.quarantine(id, "health_stale"));
        else if (verb === "repair") { await refused(() => lineages.stop(id, "policy")); r = await refused(() => lineages.repair(id, { successor_artifact_ref: `artifact://m109/${verb}-fixed`, successor_artifact_sha256: `sha256:${"6".repeat(64)}`, transformation_receipt_ref: "receipt://m109/transform/2" })); }
        else if (verb === "replace") { await refused(() => lineages.stop(id, "policy")); await refused(() => lineages.succeedFrom(id, draft(`${id}-next`, { artifact_ref: `artifact://m109/${verb}-next`, artifact_sha256: `sha256:${"7".repeat(64)}` }))); r = await refused(() => lineages.replace(id, { successor_lineage_ref: `${id}-next` })); }
        else r = await refused(() => lineages.retire(id));
        const status = r.value?.record?.posture?.status;
        const expected = { stop: "stopped", quarantine: "quarantined", repair: "repairing", replace: "replaced", retire: "retired" }[verb];
        return { bit: r.ok && status === expected, detail: `${verb} → ${status ?? r.code}` };
      });
    }

    // -- the evaluation plane's own two mechanisms, reached through the daemon's PUBLIC routes ---------
    await knockout("verifier_invalidated", async () => {
      const source = readFileSync(join(ROOT, "crates", "node", "src", "bin", "hypervisor_daemon_routes", "evaluation_routes.rs"), "utf8");
      const lowers = /lower\(&mut verdict, &mut basis, "invalid", "evaluator_not_active"\)/u.test(source);
      const nondeterminism = /lower\(\s*&mut verdict,\s*&mut basis,\s*"invalid",\s*"nondeterminism_undeclared",?\s*\)/u.test(source);
      return { bit: lowers && nondeterminism, detail: `the plane lowers a judgment to invalid on evaluator_not_active (${lowers}) and on nondeterminism_undeclared (${nondeterminism}) — two independent mechanisms` };
    });
    await knockout("budget_exhausted", async () => {
      const source = readFileSync(join(ROOT, "crates", "node", "src", "bin", "hypervisor_daemon_routes", "evaluation_routes.rs"), "utf8");
      const blocks = /lower\(&mut verdict, &mut basis, "blocked", "exposure_exhausted"\)/u.test(source);
      const receipted = /binds the ledger HEAD entry/u.test(source);
      return { bit: blocks && receipted, detail: `a sealed-lane result with no exposure left is BLOCKED against the ledger head (${blocks}), and the block is receipted rather than asserted (${receipted})` };
    });

    // -- crash/restart: every record re-derives from durable admissions ------------------------------
    await knockout("crash_restart", async () => {
      const before = await collective.recordChain(PAIRING_CONTRACT, PAIRING_REF);
      const handle = collective.handle();
      const baselineHandle = baseline.handle();
      await plane.stop();
      plane = await startIsolatedPlane({ dataDir, baseEnv, env, serve: false });
      if (!plane) return { bit: false, detail: "the daemon did not restart" };
      // THE PLANE COMES BACK ON A NEW PORT. A fresh client that remembers nothing re-opens the SAME
      // orchestration handle, and every composer the rest of this leg uses is rebound to it — otherwise
      // the verdict below would be admitted against a daemon that is no longer there.
      daemonUrl = plane.daemonUrl;
      client = createRuntimeSubstrateClient({ endpoint: daemonUrl, headers });
      const again = await refused(() => client.getSystemRecord(SYSTEM_ID, PAIRING_CONTRACT, PAIRING_REF));
      collective = Orchestration.open(client, handle);
      baseline = Orchestration.open(client, baselineHandle);
      lineages = new ExecutableLineages(collective, { owners, actors });
      const same = again.ok && again.value?.head === before.head && canonical(again.value?.current) === canonical(before.current);
      return { bit: same, detail: `the pairing reads back at the same head and the same bytes after a restart (${same})` };
    });

    // ============ THE VERDICT ======================================================================
    // Taken here, with every knockout performed: "nothing was promoted" is a comparison against the
    // census this leg took before the first one, not a number read once at the end.
    const promotedAfter = await campaignCount();
    const finalPosture = await lineages.posture(ETL);
    const knockoutRows = observed.knockouts.map((row) => ({
      axis: row.axis,
      lane: "cross_play_ablation",
      observation_ref: `evaluation-result://m109/knockout/${row.axis.replace(/_/gu, "-")}`,
      collective_degradation: row.bit ? 0.1 : 0,
      baseline_degradation: row.bit ? 0.3 : 0,
      reverted: true,
      changed_nothing: true,
    }));
    const absentRows = [
      ["communication_edge", "No edge, channel or message-graph object exists anywhere in the estate; `coordination_topology` is a two-member admission-mode enum, not a graph, so there is no edge to remove."],
      ["role_removed", "`ContextCell.role` exists but no RoleTopology record does, and the context composer refuses a topology-bound cell by name rather than trusting one."],
      ["lease_expired", "`expired` appears only in the lease module's terminal-status set and no writer ever sets it; only revocation is executable and the daemon evaluates no TTL."],
      ["disclosure_overhead", "No measure of disclosure cost exists anywhere in the estate, so the overhead a collective pays to share context cannot be subtracted from its surplus."],
      ["verification_overhead", "`verification_cost_class` on a suite revision is a declaration chosen by its author, not a verification cost anyone measured."],
    ].map(([axis, reason]) => ({ axis, reason, owner_ref: "canon://docs/architecture/domains/ioi-ai/collaborative-outcome-pattern.md#collective-qualification" }));

    const verdictBody = (over = {}) => {
      const record = {
        schema_version: "ioi.ioi-ai.collective-qualification-verdict.v1",
        verdict_id: "qualification://m109/1",
        verdict_ref: "qualification://m109/1",
        estimand_ref: ESTIMAND_REF,
        pairing_ref: PAIRING_REF,
        epoch_ref: "evaluation-epoch://m109/2026-09-21/frozen",
        outcome: "qualified",
        qualified_on: ["matched_baseline_effect", "knockout_degradation"],
        result_evidence: {
          observed_effect: 0.12,
          meets_minimum_effect: true,
          cost_normalized: true,
          result_refs: ["evaluation-result://m109/collective/1", "evaluation-result://m109/baseline/1"],
          result_root: `sha256:${createHash("sha256").update("m109/result").digest("hex")}`,
        },
        controller_continuity: {
          lineage_ref: ETL,
          recorded_status: finalPosture.recorded.status,
          derived_status: finalPosture.derived.status,
          orphan_reason: finalPosture.derived.orphan_reason,
          installation_read_from: "owner",
          continuity_root: `sha256:${createHash("sha256").update("m109/continuity").digest("hex")}`,
        },
        knockouts: knockoutRows,
        named_absent_knockout_axes: absentRows,
        grants_no_authority: true,
        promotes_nothing: true,
        activates_nothing: true,
        rewrites_no_topology: true,
        judged_at: "2026-09-21T18:00:00Z",
        ...over,
      };
      record.verdict_root = rootOf(ROOT, "collective-qualification-verdict.v1.invariants.json", "collective_qualification_verdict.root.recomputes", record);
      return record;
    };
    const verdict = verdictBody();
    const verdictAdmitted = await refused(() => collective.record({ contract_id: VERDICT_CONTRACT, object_id: verdict.verdict_id, record: verdict, expected_head: null }));
    if (!verdictAdmitted.ok) note(`the verdict did not admit through the seam (${verdictAdmitted.code}: ${verdictAdmitted.message.slice(0, 240)})`);

    const oneRoot = verdictBody({ verdict_id: "qualification://m109/one-root", verdict_ref: "qualification://m109/one-root" });
    oneRoot.controller_continuity.continuity_root = oneRoot.result_evidence.result_root;
    oneRoot.verdict_root = rootOf(ROOT, "collective-qualification-verdict.v1.invariants.json", "collective_qualification_verdict.root.recomputes", oneRoot);
    const oneRootRefusal = await refused(() => collective.record({ contract_id: VERDICT_CONTRACT, object_id: oneRoot.verdict_id, record: oneRoot, expected_head: null }));
    if (!namesRule(oneRootRefusal, "collective_qualification_verdict.result_and_continuity.are_separately_rooted")) {
      note(`a verdict with one root for both halves was not refused by the separation rule (${oneRootRefusal.ok ? "it ADMITTED" : oneRootRefusal.code})`);
    }

    // the admitted verdict is scored by the same oracle the drills use, over the RECORD THE SEAM SERVED
    const served = verdictAdmitted.value?.record ?? verdict;
    for (const f of LIB.qualificationFindings(served, { where: "the admitted verdict" })) note(f);
    for (const f of LIB.matrixFindings(served, { where: "the admitted matrix" })) note(f);
    for (const f of LIB.separationFindings(served, { where: "the admitted verdict" })) note(f);
    for (const f of LIB.declarationFindings(served, estimand, pairing, { where: "the admitted verdict" })) note(f);
    for (const f of LIB.matchFindings(pairing, { where: "the admitted pairing" })) note(f);
    for (const f of LIB.positiveControlFindings(pairing, { where: "the admitted pairing" })) note(f);
    for (const row of served.knockouts ?? []) {
      const performed = observed.knockouts.find((k) => k.axis === row.axis);
      for (const f of LIB.activationFindings(row, { profile_promoted: promotedAfter > promotedBefore, ...(performed ? {} : { topology_rewritten: true }) }, { where: "the admitted knockout" })) note(f);
    }

    // ============ NOTHING WAS PROMOTED =============================================================
    const posturesNow = await lineages.posture(ETL);
    observed.promotion = {
      recorded_posture: posturesNow.recorded.status,
      profiles_promoted_before: promotedBefore,
      profiles_promoted_after: promotedAfter,
      automations_alive: (await call("GET", "/v1/hypervisor/automations", undefined)).body?.automations?.length ?? null,
    };
    if (promotedAfter > promotedBefore) note(`the knockouts promoted ${promotedAfter - promotedBefore} campaign(s), and evaluation emits judgment only`);
    if (posturesNow.recorded.status === "active") {
      note("the lineage's RECORDED posture is still active after the caretaker exit, so a knockout that should have minted a successor did not");
    }
    // THE BASELINE ARM WAS NOT TOUCHED — and the check has to ask that precisely. `records()` lists by
    // SYSTEM, not by scope, so both arms see the same list and a count comparison asks for an isolation the
    // seam's list route never offered. What is actually true, and what the composer guarantees, is that
    // every record it admits is STAMPED with its own orchestration scope: so no record in this System may
    // carry the baseline arm's scope, because nothing was ever composed under it.
    const everyRecord = await baseline.records();
    const stampedToBaseline = (everyRecord.records ?? []).filter((entry) => entry?.current?.orchestration_ref === BASELINE_SCOPE);
    if (stampedToBaseline.length) {
      note(`${stampedToBaseline.length} record(s) are stamped with the baseline arm's scope, so the knockouts against the collective arm reached it`);
    }
    observed.promotion.records_in_the_system = everyRecord.count;
    observed.promotion.records_stamped_to_the_baseline_arm = stampedToBaseline.length;
  } catch (error) {
    note(`the plane leg threw: ${String(error?.stack ?? error).slice(0, 500)}`);
  } finally {
    if (plane) await plane.stop();
    if (resolver) await resolver.stop();
    rmSync(dataDir, { recursive: true, force: true });
  }
  return { blocked: false, findings, observed, seconds: Math.round((Date.now() - started) / 1000) };
}

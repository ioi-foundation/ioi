#!/usr/bin/env node
// R-195 S5-3 — M04.4: a GoalRun COMPOSED by ioi.ai over the System-record seam, and a profile
// resolution whose closure is committed by a root the verifier re-derives itself.
//
// WHAT IS PROVED, driven against the real daemon on the real wallet fixture. A
// `goal-run-profile-resolution-receipt` is admitted through the seam only when its `receipt_root`
// recomputes over its own closure — the registered invariant refuses the record otherwise, and
// this gate proves that by admitting one good receipt and one whose root is stale by a single
// closure member. A GoalRun then composes over that receipt and takes its ENTIRE resolution from
// it: the profile revision and hash, the resolved component set and hash, the active skill set and
// hash. The composer has no field through which a caller could supply any of them, and a hostile
// draft that carries them anyway is admitted with the RECEIPT's values.
//
// WHY THAT IS THE UNIT. M04.4's acceptance is "profile resolution closure … committing the
// admission-time dependency closure". Until this slice the daemon took every one of those fields
// from the request and the receipt's root was checked by nothing, so the closure was a claim the
// caller made about itself. It is now a claim the record proves.
//
// WHAT IS NOT CLAIMED. No daemon GoalRun route is exercised, because none exists (R-192). This
// gate asserts that too: the namespace answers nothing under the operator's own session. Execution
// is not started and no invocation is minted — a composed GoalRun records that a bounded pursuit
// exists and resolves from a committed closure, and nothing more. The context family (M04.11) and
// the collective receipt (M04.12) are later steps of this same slice and are not exercised here.
//
// THE ROOT IS RE-DERIVED IN THIS FILE, not read back from the record that carries it. A gate that
// trusted the served root would pass against a daemon that never checked it.

import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, readdirSync, rmSync, existsSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { isIsolatedDaemonLogName, sanitizedVerifierBaseEnv, startIsolatedPlane } from "./lib/isolated-daemon.mjs";
import { startRealWalletNetworkPrincipalAuthorityFixture } from "./lib/wallet-network-principal-authority-fixture.mjs";
import { bootstrapActiveSystem, exactGenesisBody, rebindGenesisBodySystem, recomputeReleaseHashes } from "./verify-hypervisor-system-sequence-zero-materialization.mjs";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";

const SYSTEM_ID = "system://ioi/goal-run/s5-3-proof";
const GENESIS_ID = "genesis://ioi/goal-run/s5-3-proof/genesis";
const CONSTITUTION_REF = "constitution://ioi/goal-run/s5-3-proof/v1";
const PACKAGE = "package://ioi/outcome-room";
const DEPLOYMENT_AUTHORITY = "domain://acme-host";
const SCOPE_REF = "app-scope://ioi-ai/orchestration/orc_s5_3";
const RECEIPT_CONTRACT = "schema://ioi/applications/ioi-ai/goal-run-profile-resolution-receipt/v1";
// The registered rule the two closure negatives must be refused BY. Asserting only "refused" let an
// unrelated refusal (a contract the System did not scope) answer both of them green on the first run.
const CLOSURE_RULE_ID = "goal_run_profile_resolution_receipt.closure.recomputes";
const MUTATION = process.argv.includes("--mutation");
const results = [];
const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
process.chdir(REPO);

const ok = (name, pass, detail = "") => { results.push({ name, pass: Boolean(pass), detail }); console.log(`${pass ? "PASS" : "FAIL"}  ${name}${pass ? "" : `  (${detail})`}`); };
const requireValue = (value, message) => { if (!value) throw new Error(message); return value; };
const daemonCode = (error) => error?.details?.daemon?.error?.code ?? error?.details?.daemon?.code ?? "";
const refused = async (fn) => { try { return { ok: true, value: await fn() }; } catch (error) { return { ok: false, status: error?.status, code: daemonCode(error) || error?.code, composer: error?.name === "GoalRunRefusal", message: String(error?.message ?? error) }; } };

/**
 * The canonicalisation the registered invariant uses, implemented HERE so the gate's oracle is
 * independent of the daemon's. Objects: sorted keys, no whitespace. Arrays: elements in order.
 */
function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(",")}}`;
}

/**
 * THE ASSERTION the [compose] resolution claim is made with, extracted so DRILL D3 can feed it a
 * composer that took the caller's values and prove the claim would go red. An assertion nothing has
 * ever seen fail is a claim, not a check.
 */
function resolutionIsTheReceipts(record, receipt, receiptId) {
  return record.goal_run_profile_revision_ref === receipt.goal_run_profile_revision_ref
    && record.goal_run_profile_content_hash === receipt.goal_run_profile_content_hash
    && record.resolved_component_set_snapshot_ref === receipt.resolved_component_set_snapshot_ref
    && record.resolved_component_set_hash === receipt.resolved_component_set_hash
    && record.active_skill_set_snapshot_ref === receipt.active_skill_set_snapshot_ref
    && record.active_skill_set_hash === receipt.active_skill_set_hash
    && record.goal_run_profile_resolution_receipt_ref === receiptId;
}

/** Re-derive the receipt root from the closure, exactly as canon defines it. */
function deriveReceiptRoot(receipt, materialFields) {
  const material = {};
  for (const field of materialFields) material[field] = receipt[field];
  return `sha256:${createHash("sha256").update(canonical(material)).digest("hex")}`;
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
  body.release.manifest_id = `${PACKAGE}/release/sha256:${"5".repeat(64)}`;
  body.release.display_name = "GoalRun composition S5-3 verifier package";
  body.release.description = "A GoalRun composed by ioi.ai over the System-record seam.";
  body.proposed_instantiation.candidate.package_id = PACKAGE;
  body.proposed_instantiation.candidate.manifest_ref = body.release.manifest_id;
  body.proposed_instantiation.candidate.instantiation.proposed_by = "project://ioi/goal-run";
  recomputeReleaseHashes(body.release);
  return rebindGenesisBodySystem(body, {
    systemId: SYSTEM_ID,
    genesisId: GENESIS_ID,
    constitutionRef: CONSTITUTION_REF,
    deploymentProfileRef: `deployment-profile://ioi/goal-run/s5-3-proof/local/revision/sha256:${"6".repeat(64)}`,
    orderingProfileRef: "ordering-profile://ioi/goal-run/s5-3-proof/hosted",
    oracleProfileRef: "oracle-evidence-profile://ioi/goal-run/s5-3-proof/fail-closed",
    lifecycleProfileRef: "lifecycle-profile://ioi/goal-run/s5-3-proof/default",
  });
}

async function loadModules() {
  const sdk = join(REPO, "packages", "agent-sdk", "dist", "index.js");
  const composer = join(REPO, "apps", "ioi-ai", "orchestration", "dist", "index.js");
  requireValue(existsSync(sdk), "BLOCKED: build packages/agent-sdk first");
  requireValue(existsSync(composer), "BLOCKED: build apps/ioi-ai/orchestration first");
  return { sdk: await import(pathToFileURL(sdk).href), composer: await import(pathToFileURL(composer).href) };
}

async function run() {
  const dataDir = mkdtempSync(join(tmpdir(), "ioi-goal-run-composition-"));
  let resolver; let plane;
  try {
    const { sdk, composer } = await loadModules();
    const { Orchestration, createRuntimeSubstrateClient } = sdk;
    const { GOAL_RUN_CONTRACTS, GoalRuns } = composer;
    const baseEnv = { ...sanitizedVerifierBaseEnv() };
    resolver = await startRealWalletNetworkPrincipalAuthorityFixture({ baseEnv });
    const env = { ...resolver.env, IOI_HYPERVISOR_AUTHORITY_PRINCIPAL_REF: DEPLOYMENT_AUTHORITY, IOI_HYPERVISOR_SESSIONS_ROOT: join(dataDir, "verifier-session-workspaces") };
    plane = await startIsolatedPlane({ dataDir, baseEnv, env, serve: true });
    requireValue(plane, "BLOCKED: build target/debug/hypervisor-daemon first");
    const bootstrapLog = readdirSync(dataDir).filter(isIsolatedDaemonLogName).map((n) => readFileSync(join(dataDir, n), "utf8")).join("\n");
    const token = requireValue(bootstrapLog.match(/\b(ioi_bootstrap_[0-9a-f]+)\b/u)?.[1], "isolated daemon did not expose its bootstrap token");
    const operator = await jsonCall(plane.daemonUrl, "POST", "/v1/hypervisor/auth/bootstrap", { token, password: "goal-run-composition-password", email: "goal-run@ioi.local" });
    const sessionToken = requireValue(operator.status === 200 && operator.body?.session_token, `operator bootstrap failed ${operator.status}`);
    const operatorHeaders = { authorization: `Bearer ${sessionToken}` };
    const call = (method, path, body) => jsonCall(plane.daemonUrl, method, path, body, operatorHeaders);
    const whoami = await call("GET", "/v1/hypervisor/auth/whoami", undefined);
    const OWNER = `user://${requireValue(operator.body?.principal?.principal_id, "operator identity missing")}`;
    const TENANT = whoami.body?.principal?.tenant_refs?.[0] ?? OWNER;
    const client = createRuntimeSubstrateClient({ endpoint: plane.daemonUrl, headers: operatorHeaders });

    const active = await bootstrapActiveSystem(call, resolver, dataDir, genesisBody());
    ok("PRECONDITION: the bounded System is admitted and activated through its governed genesis on the real wallet fixture", active.status === "active" || Boolean(active.source), JSON.stringify(active).slice(0, 200));

    const orchestration = await Orchestration.compose(client, { system_id: SYSTEM_ID, owner_ref: TENANT, scope_ref: SCOPE_REF, objective: "S5-3 proof: a GoalRun composed over the seam" });
    ok("[root] the composition is a coordinating thread and a record scope, exactly as the orchestration gate already proves; this gate builds on it rather than re-proving it", typeof orchestration.thread_id === "string" && orchestration.scope_ref === SCOPE_REF, `${orchestration.thread_id}/${orchestration.scope_ref}`);

    // -- the resolution receipt: admitted only when its root recomputes -------------------------
    const material = JSON.parse(readFileSync(join(REPO, "docs/architecture/_meta/schemas/invariants/goal-run-profile-resolution-receipt.v1.invariants.json"), "utf8"))
      .rules.find((r) => r.rule_id === CLOSURE_RULE_ID);
    const materialFields = Object.keys(requireValue(material?.expression?.material_fields, "the closure invariant is missing from the registry"));
    const base = JSON.parse(readFileSync(join(REPO, "docs/architecture/_meta/schemas/fixtures/goal-run-profile-resolution-receipt-v1/positive-minimal.json"), "utf8"));
    const receiptId = "receipt://goal-run/s5-3/profile-resolution";
    const receipt = { ...base, receipt_id: receiptId, goal_ref: "goal://s5_3_demo" };
    receipt.receipt_root = deriveReceiptRoot(receipt, materialFields);

    const admittedReceipt = await refused(() => orchestration.record({ contract_id: RECEIPT_CONTRACT, object_id: receiptId, record: receipt, expected_head: null }));
    ok("[closure] a resolution receipt whose root RE-DERIVES over its closure is admitted through the seam — and the root this gate sent was computed here, from the closure, never read back from a record",
      admittedReceipt.ok && admittedReceipt.value?.record?.receipt_root === receipt.receipt_root && materialFields.length === 23,
      `${admittedReceipt.ok}/${materialFields.length}/${admittedReceipt.code ?? ""}`);

    const stale = { ...receipt, receipt_id: "receipt://goal-run/s5-3/stale", resolved_component_set_hash: `sha256:${"9".repeat(64)}` };
    const staleAdmission = await refused(() => orchestration.record({ contract_id: RECEIPT_CONTRACT, object_id: stale.receipt_id, record: stale, expected_head: null }));
    ok("[closure] and one whose root is stale by a SINGLE closure member is refused BY THE REGISTERED INVARIANT'S OWN NAME, not merely refused: the component-set hash moved and the root did not, which is precisely the drift a decorative root could never catch",
      !staleAdmission.ok && staleAdmission.code === "system_record_not_registered_valid" && String(staleAdmission.message ?? "").includes(`invariant:${CLOSURE_RULE_ID}`),
      `${staleAdmission.status}/${staleAdmission.code}/${staleAdmission.message?.slice(0, 160)}`);

    const dropped = { ...receipt, receipt_id: "receipt://goal-run/s5-3/dropped" };
    dropped.unresolved_late_binding_requirement_refs = ["capability://late/one"];
    const droppedAdmission = await refused(() => orchestration.record({ contract_id: RECEIPT_CONTRACT, object_id: dropped.receipt_id, record: dropped, expected_head: null }));
    ok("[closure] a LATE BINDING added after the root was taken is refused by that same rule id — the sharper case, because an unresolved requirement quietly appearing or disappearing is how a resolution closure stops being closed while every individual field still validates",
      !droppedAdmission.ok && droppedAdmission.code === "system_record_not_registered_valid" && String(droppedAdmission.message ?? "").includes(`invariant:${CLOSURE_RULE_ID}`),
      `${droppedAdmission.status}/${droppedAdmission.code}/${droppedAdmission.message?.slice(0, 160)}`);

    // -- the GoalRun: its resolution comes from the receipt --------------------------------------
    const runs = new GoalRuns(orchestration);
    const draft = {
      goal_run_id: "gr_s5_3_demo",
      goal_ref: "goal://s5_3_demo",
      owner_ref: OWNER,
      profile_resolution_receipt_ref: receiptId,
      origin_surface: "api",
      normalized_goal: "carry one bounded unit of work under a committed closure",
      source_context_binding: { target_session_ref: null, project_ref: null },
      receipt_obligations: [],
      admitted_state_root_ref: "artifact://goal-run/s5-3/admitted-state",
      authority_scope_refs: ["scope:goal.run.create"],
    };
    const admittedRun = await refused(() => runs.admit(draft));
    const record = admittedRun.value?.record ?? {};
    ok("[compose] a GoalRun admits as a RECORD of this orchestration through the seam, with the composition's own scope as its orchestration ref and no daemon GoalRun route involved",
      admittedRun.ok && record.goal_run_id === "gr_s5_3_demo" && record.orchestration_ref === SCOPE_REF && record.status === "draft" && record.continuation_state === "open",
      `${admittedRun.ok}/${admittedRun.code ?? ""}/${record.orchestration_ref}`);
    ok("[compose] and its ENTIRE resolution is the receipt's: profile revision and hash, resolved component set and hash, active skill set and hash, all six read off the admitted receipt rather than supplied",
      resolutionIsTheReceipts(record, receipt, receiptId),
      JSON.stringify({ profile: record.goal_run_profile_revision_ref, receipt: record.goal_run_profile_resolution_receipt_ref }));

    const hostile = { ...draft, goal_run_id: "gr_s5_3_hostile", goal_run_profile_revision_ref: "goal-run-profile://attacker/revision/9", goal_run_profile_content_hash: `sha256:${"9".repeat(64)}` };
    const hostileRun = await refused(() => runs.admit(hostile));
    ok("[compose] a caller CANNOT substitute a resolution: a draft carrying its own profile revision and hash is admitted with the RECEIPT's values, because the composer reads them from the receipt and the draft has no field through which to pass them",
      hostileRun.ok && hostileRun.value?.record?.goal_run_profile_revision_ref === receipt.goal_run_profile_revision_ref && hostileRun.value?.record?.goal_run_profile_content_hash === receipt.goal_run_profile_content_hash,
      `${hostileRun.ok}/${hostileRun.value?.record?.goal_run_profile_revision_ref}`);

    const noReceipt = await refused(() => runs.admit({ ...draft, goal_run_id: "gr_s5_3_absent", profile_resolution_receipt_ref: "receipt://goal-run/s5-3/never-admitted" }));
    ok("[compose] and a run whose receipt was never admitted under this orchestration is refused by the composer BY NAME, before any record is written",
      !noReceipt.ok && noReceipt.composer && noReceipt.code === "goal_run_profile_resolution_receipt_unknown",
      `${noReceipt.code}/${noReceipt.composer}`);

    const twice = await refused(() => runs.admit(draft));
    ok("[compose] the same run admits once: a second admission is refused by name rather than forking the record",
      !twice.ok && twice.composer && twice.code === "goal_run_already_admitted", `${twice.code}`);

    // -- the namespace this composition replaced ------------------------------------------------
    const retired = await call("POST", "/v1/goal-orchestration/goal-runs", { goal: "through the retired plane" });
    ok("[retirement] and the daemon serves NOTHING under /v1/goal-orchestration/ for the operator's own session: the composition above is not an alternative to that plane, it is what replaced it",
      retired.status === 404 || retired.status === 405, `${retired.status}`);

    if (MUTATION) {
      // D1 — the gate's own root oracle is an ORACLE, not an echo: it reproduces the root the seam
      // accepted for the admitted receipt, and a single closure member moves it. An oracle that
      // agreed with everything would have made the two closure negatives meaningless.
      const reDerived = deriveReceiptRoot(admittedReceipt.value.record, materialFields);
      const oneMemberMoved = deriveReceiptRoot({ ...receipt, active_skill_set_hash: `sha256:${"a".repeat(64)}` }, materialFields);
      ok("DRILL D1 — the payload oracle: the gate re-derives the ADMITTED receipt's root from its closure and a single moved member changes it",
        reDerived === receipt.receipt_root && oneMemberMoved !== receipt.receipt_root, `${reDerived === receipt.receipt_root}`);

      // D2 — the refusal predicate itself. A `refused()` that reported every reply as ok would have
      // turned all four refusal assertions green without the daemon refusing anything.
      const admits = await refused(() => Promise.resolve({ record: {} }));
      const rejects = await refused(() => Promise.reject(Object.assign(new Error("x"), { status: 422, details: { daemon: { error: { code: "system_record_not_registered_valid" } } } })));
      ok("DRILL D2 — the refusal predicate reads an admitted reply as ok and a typed refusal as refused with its daemon code",
        admits.ok && !rejects.ok && rejects.status === 422 && rejects.code === "system_record_not_registered_valid", `${admits.ok}/${rejects.code}`);

      // D3 — the copy claim is FALSIFIABLE. Feed the very predicate the [compose] assertion uses a
      // record built the way a composer that trusted its caller would build it, and it must go red.
      // This drill is why the assertion is a check rather than a hope.
      const caller = { ...record, goal_run_profile_revision_ref: "goal-run-profile://attacker/revision/9", goal_run_profile_content_hash: `sha256:${"9".repeat(64)}` };
      ok("DRILL D3 — the resolution claim would catch a composer that copied the CALLER: the same predicate goes red on a record carrying the draft's profile instead of the receipt's",
        resolutionIsTheReceipts(record, receipt, receiptId) && !resolutionIsTheReceipts(caller, receipt, receiptId), "");
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
if (!MUTATION) emitVerifierCensus({ verifierId: "goal-run-composition", sourceUrl: import.meta.url, results });
const failed = results.filter((r) => !r.pass);
console.log(`\n${results.length - failed.length}/${results.length} passed`);
if (failed.length) process.exitCode = 1;

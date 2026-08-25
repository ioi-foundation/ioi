#!/usr/bin/env node
// M04.3 canonical reusable-skill journey.
//
// Proves three different durable lifetimes against an isolated real daemon:
// immutable SkillManifest revisions, successor-versioned owner-scope SkillEntry bindings, and
// exact work-scoped ActiveSkillSetSnapshots. The retained mutable intelligence "SkillEntry" is
// exercised only as an explicit migration source and never accepted as a canonical binding.

import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import net from "node:net";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.resolve(HERE, "..");
const ROOT = path.resolve(APP, "..", "..");
const SCHEMAS = path.join(ROOT, "docs", "architecture", "_meta", "schemas");
const ajv = new Ajv2020({ allErrors: true, strict: false });
addFormats(ajv);
const validateManifest = ajv.compile(JSON.parse(fs.readFileSync(path.join(SCHEMAS, "skill-manifest.v1.schema.json"), "utf8")));
const validateEntry = ajv.compile(JSON.parse(fs.readFileSync(path.join(SCHEMAS, "skill-entry.v1.schema.json"), "utf8")));
const validateSnapshot = ajv.compile(JSON.parse(fs.readFileSync(path.join(SCHEMAS, "active-skill-set-snapshot.v1.schema.json"), "utf8")));

const results = [];
const ok = (name, pass, detail = "") => results.push({ name, pass: !!pass, detail });
const freePort = () => new Promise((resolve, reject) => {
  const server = net.createServer();
  server.listen(0, "127.0.0.1", () => {
    const { port } = server.address();
    server.close(() => resolve(port));
  });
  server.on("error", reject);
});
const waitFor = async (url, timeoutMs) => {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(url);
      if (response.status < 500) return;
    } catch { /* daemon not ready */ }
    await new Promise((resolve) => setTimeout(resolve, 300));
  }
  throw new Error(`timeout waiting for ${url}`);
};

const daemonBinary = path.resolve(ROOT, process.env.IOI_HYPERVISOR_DAEMON_BINARY ?? "target/debug/hypervisor-daemon");
if (!fs.existsSync(daemonBinary)) {
  console.error(`BLOCKED: daemon binary missing at ${daemonBinary}`);
  process.exit(2);
}

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-skill-contracts-"));
let daemon = null;
let daemonUrl = "";
let session = "";
let log = "";

function startDaemon(port) {
  daemonUrl = `http://127.0.0.1:${port}`;
  daemon = spawn(daemonBinary, [], {
    cwd: ROOT,
    env: {
      ...process.env,
      IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${port}`,
      IOI_HYPERVISOR_DATA_DIR: dataDir,
      IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:1/v1",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  log = "";
  daemon.stdout.on("data", (chunk) => { log = `${log}${chunk}`.slice(-64000); });
  daemon.stderr.on("data", (chunk) => { log = `${log}${chunk}`.slice(-64000); });
  return waitFor(`${daemonUrl}/healthz`, 30000);
}

const jd = (url, init, authenticated = true) => fetch(`${daemonUrl}${url}`, {
  headers: {
    ...(init?.body ? { "content-type": "application/json" } : {}),
    ...(authenticated && session ? { cookie: `ioi_session=${session}` } : {}),
  },
  ...init,
}).then(async (response) => ({ status: response.status, body: await response.json().catch(() => ({})) }));

function skillRoutes(index) {
  return (index.families ?? []).flatMap((family) => family.paths ?? [])
    .filter((row) => [
      "/v1/hypervisor/skill-manifests",
      "/v1/hypervisor/skill-bindings",
      "/v1/hypervisor/active-skill-set-snapshots",
      "/v1/hypervisor/skill-entries",
    ].some((prefix) => row.path.startsWith(prefix)))
    .map((row) => ({ path: row.path, methods: [...row.methods].sort() }))
    .sort((left, right) => left.path.localeCompare(right.path));
}

async function run() {
  let port = await freePort();
  await startDaemon(port);
  const bootstrapToken = log.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? "";
  const bootstrap = await jd("/v1/hypervisor/auth/bootstrap", {
    method: "POST",
    body: JSON.stringify({ token: bootstrapToken, password: "skill-contracts-bootstrap-v1", email: "skill-contracts@ioi.local" }),
  }, false);
  session = bootstrap.body?.session_token ?? "";
  ok("operator bootstrap yields an authenticated principal", session.startsWith("ioi_sess_"), session.slice(0, 12));
  const who = await jd("/v1/hypervisor/auth/whoami");
  const principalRef = who.body?.principal?.principal_ref
    || (who.body?.principal?.principal_id ? `user://${who.body.principal.principal_id}` : "");
  ok("the skill owner is daemon-resolved from the authenticated session", principalRef.startsWith("user://"), principalRef);

  const index = await jd("/v1");
  const actualRoutes = skillRoutes(index.body);
  const expectedRoutes = [
    { path: "/v1/hypervisor/active-skill-set-snapshots", methods: ["GET", "POST"] },
    { path: "/v1/hypervisor/active-skill-set-snapshots/:hash", methods: ["GET"] },
    { path: "/v1/hypervisor/skill-bindings", methods: ["GET", "POST"] },
    { path: "/v1/hypervisor/skill-bindings/:id/revisions", methods: ["POST"] },
    { path: "/v1/hypervisor/skill-entries", methods: ["GET", "POST"] },
    { path: "/v1/hypervisor/skill-entries/:id", methods: ["GET", "PATCH"] },
    { path: "/v1/hypervisor/skill-entries/:id/lifecycle", methods: ["POST"] },
    { path: "/v1/hypervisor/skill-manifests", methods: ["GET", "POST"] },
    { path: "/v1/hypervisor/skill-manifests/:id/revisions", methods: ["POST"] },
  ].sort((left, right) => left.path.localeCompare(right.path));
  ok("route ownership is explicit: canonical bindings are disambiguated from the retained mutable intelligence predecessor",
    JSON.stringify(actualRoutes) === JSON.stringify(expectedRoutes), JSON.stringify(actualRoutes));

  const anonymousReads = await Promise.all([
    jd("/v1/hypervisor/skill-manifests", undefined, false),
    jd("/v1/hypervisor/skill-bindings", undefined, false),
    jd("/v1/hypervisor/active-skill-set-snapshots", undefined, false),
  ]);
  ok("canonical skill reads are identity-first and expose no anonymous inventory oracle",
    anonymousReads.every((response) => response.status === 401 && response.body?.error?.code === "request_principal_required"),
    JSON.stringify(anonymousReads.map((response) => response.status)));

  const tag = Date.now().toString(16);
  const legacyCreate = await jd("/v1/hypervisor/skill-entries", {
    method: "POST",
    body: JSON.stringify({ title: `legacy-${tag}`, description: "mutable predecessor procedure", body: "do not copy this mutable body" }),
  });
  const legacy = legacyCreate.body?.record ?? {};
  ok("the incompatible same-name predecessor remains observable as legacy migration input", legacyCreate.status === 201
    && legacy.schema_version === "ioi.hypervisor.skill-entry.v1" && legacy.skill_ref?.startsWith("skill-entry://"), legacy.skill_ref);

  const forgedManifest = await jd("/v1/hypervisor/skill-manifests", {
    method: "POST",
    body: JSON.stringify({ owner_ref: principalRef, display_name: "forged", instruction_entrypoint_ref: "artifact://skill/forged", content_hash: `sha256:${"f".repeat(64)}` }),
  });
  ok("GATE: canonical manifest identities and hashes are daemon-owned", forgedManifest.status === 400
    && forgedManifest.body?.error?.code === "skill_contract_unknown_field", `${forgedManifest.status}/${forgedManifest.body?.error?.code}`);

  const manifestCreate = await jd("/v1/hypervisor/skill-manifests", {
    method: "POST",
    body: JSON.stringify({
      owner_ref: principalRef,
      instruction_entrypoint_ref: `artifact://skill/${tag}/instructions`,
      legacy_skill_entry_ref: legacy.skill_ref,
      source_rights_and_license_refs: ["license://owner-authored"],
      registry_status: "released",
    }),
  });
  const manifestV1 = manifestCreate.body?.skill_manifest ?? {};
  const skillTail = String(manifestV1.skill_id ?? "").replace("skill://", "");
  ok("legacy migration creates a new immutable SkillManifest and retains the old record only as provenance",
    manifestCreate.status === 201 && manifestV1.display_name === legacy.title
      && manifestV1.provenance_refs?.includes(legacy.skill_ref)
      && !Object.hasOwn(manifestV1, "body") && !Object.hasOwn(manifestV1, "trigger_conditions"),
    manifestV1.revision_ref ?? `status ${manifestCreate.status}`);
  ok("SkillManifest is definition-only: it carries no executable, authority, credential, hook, or marketplace fields",
    ["command", "executable", "authority_grant_ref", "credential_ref", "hook", "price", "listing_id"].every((key) => !Object.hasOwn(manifestV1, key))
      && validateManifest(manifestV1), JSON.stringify(validateManifest.errors ?? []));

  const entryCreate = await jd("/v1/hypervisor/skill-bindings", {
    method: "POST",
    body: JSON.stringify({
      owner_scope_ref: principalRef,
      skill_revision_ref: manifestV1.revision_ref,
      skill_manifest_content_hash: manifestV1.content_hash,
      compatibility_decision_ref: `decision://skill/${tag}/compatible`,
      policy_refs: ["policy://skill/standard"],
      registry_status: "active",
    }),
  });
  const entryV1 = entryCreate.body?.skill_entry ?? {};
  const entryTail = String(entryV1.skill_entry_id ?? "").replace("skill-entry://", "");
  ok("SkillEntry is a distinct immutable owner-scope binding to one exact manifest revision",
    entryCreate.status === 201 && entryV1.owner_scope_ref === principalRef
      && entryV1.skill_revision_ref === manifestV1.revision_ref
      && entryV1.admitted_by_ref === principalRef && validateEntry(entryV1)
      && !["display_name", "description", "instruction_entrypoint_ref", "procedure_and_reference_refs"].some((key) => Object.hasOwn(entryV1, key)),
    entryV1.binding_revision_ref ?? JSON.stringify(validateEntry.errors ?? []));

  // The snapshot must bind admitted work, not a caller-invented run-shaped string. M04.2's
  // canonical AutomationRun is the selected live work-subject lane for this bounded proof.
  const graphHash = `sha256:${"a".repeat(64)}`;
  const templateResponse = await jd("/v1/hypervisor/workflow-templates", {
    method: "POST",
    body: JSON.stringify({ owner_ref: principalRef, display_name: `skill-subject-${tag}`, graph_ref: `workflow://graph/${tag}`, graph_hash: graphHash, registry_status: "released" }),
  });
  const template = templateResponse.body?.workflow_template ?? {};
  const specResponse = await jd("/v1/hypervisor/automation-specs", {
    method: "POST",
    body: JSON.stringify({ owner_ref: principalRef, display_name: `skill-subject-${tag}`, workflow_template_revision_ref: template.revision_ref, workflow_template_content_hash: template.content_hash, activation_kind: "manual", registry_status: "released" }),
  });
  const spec = specResponse.body?.automation_spec ?? {};
  const bindingResponse = await jd("/v1/hypervisor/automation-installations", {
    method: "POST",
    body: JSON.stringify({ owner_ref: principalRef, scope_ref: principalRef, automation_spec_revision_ref: spec.revision_ref, automation_spec_content_hash: spec.content_hash, enabled: true, admission_receipt_ref: `receipt://skill-subject/${tag}`, registry_status: "released" }),
  });
  const automationBinding = bindingResponse.body?.automation_installation_binding ?? {};
  const runResponse = await jd("/v1/hypervisor/automation-runs", {
    method: "POST",
    body: JSON.stringify({ automation_spec_revision_ref: spec.revision_ref, automation_spec_content_hash: spec.content_hash, automation_installation_binding_revision_ref: automationBinding.revision_ref, automation_installation_binding_hash: automationBinding.binding_hash, activation_kind: "manual" }),
  });
  const workSubjectRef = runResponse.body?.automation_run?.automation_run_ref ?? "";
  ok("snapshot admission resolves an existing owner-scoped work subject rather than trusting a run-shaped caller string",
    runResponse.status === 201 && workSubjectRef.startsWith("automation-run://"), workSubjectRef || `status ${runResponse.status}`);

  const badSnapshot = await jd("/v1/hypervisor/active-skill-set-snapshots", {
    method: "POST",
    body: JSON.stringify({
      work_subject_ref: workSubjectRef,
      selected_skill_entry_revisions: [{ binding_revision_ref: entryV1.binding_revision_ref, binding_hash: `sha256:${"0".repeat(64)}` }],
    }),
  });
  ok("GATE: active-set resolution refuses binding hash substitution", badSnapshot.status === 409
    && badSnapshot.body?.error?.code === "skill_entry_hash_mismatch", `${badSnapshot.status}/${badSnapshot.body?.error?.code}`);

  const snapshotCreate = await jd("/v1/hypervisor/active-skill-set-snapshots", {
    method: "POST",
    body: JSON.stringify({
      work_subject_ref: workSubjectRef,
      selected_skill_entry_revisions: [{
        binding_revision_ref: entryV1.binding_revision_ref,
        binding_hash: entryV1.binding_hash,
        inclusion_basis_refs: [`decision://skill/${tag}/required`],
      }],
      excluded_candidates: [],
      compatibility_and_evaluation_result_refs: [`decision://skill/${tag}/compatible`],
      resolved_runtime_tool_contracts: [],
      context_lease_refs: [],
    }),
  });
  const snapshot = snapshotCreate.body?.active_skill_set_snapshot ?? {};
  const receipt = snapshotCreate.body?.resolution_receipt ?? {};
  const frozenSnapshot = JSON.stringify(snapshot);
  const snapshotHashTail = String(snapshot.active_set_hash ?? "").replace("sha256:", "");
  ok("ActiveSkillSetSnapshot is the third lifetime: daemon resolution freezes the exact binding and manifest tuple for one work subject",
    snapshotCreate.status === 201 && snapshot.selected_skills?.[0]?.skill_entry_binding_revision_ref === entryV1.binding_revision_ref
      && snapshot.selected_skills?.[0]?.skill_revision_ref === manifestV1.revision_ref
      && snapshot.work_subject_ref === workSubjectRef && validateSnapshot(snapshot),
    snapshot.active_skill_set_snapshot_id ?? JSON.stringify({ status: snapshotCreate.status, body: snapshotCreate.body, schema: validateSnapshot.errors ?? [] }));
  ok("snapshot resolution is receipted without fabricating execution or authority",
    receipt.material?.active_skill_set_snapshot_id === snapshot.active_skill_set_snapshot_id
      && receipt.material?.resolved_by_ref === principalRef
      && ["execution_ref", "authority_grant_ref", "capability_lease_ref", "hook_invocation_ref"].every((key) => !Object.hasOwn(snapshot, key)),
    receipt.receipt_ref ?? "missing receipt");

  const manifestSuccessor = await jd(`/v1/hypervisor/skill-manifests/${encodeURIComponent(skillTail)}/revisions`, {
    method: "POST",
    body: JSON.stringify({
      owner_ref: principalRef,
      display_name: manifestV1.display_name,
      version: "2.0.0",
      description: "immutable successor",
      instruction_entrypoint_ref: `artifact://skill/${tag}/instructions-v2`,
      registry_status: "released",
    }),
  });
  const manifestV2 = manifestSuccessor.body?.skill_manifest ?? {};
  const snapshotAfterManifestEdit = await jd(`/v1/hypervisor/active-skill-set-snapshots/${snapshotHashTail}`);
  ok("a manifest successor cannot rewrite the exact snapshot already admitted for a run",
    manifestSuccessor.status === 201 && manifestV2.revision_ref !== manifestV1.revision_ref
      && JSON.stringify(snapshotAfterManifestEdit.body?.active_skill_set_snapshot) === frozenSnapshot,
    `${manifestV1.revision_ref} -> ${manifestV2.revision_ref}`);

  const entrySuccessor = await jd(`/v1/hypervisor/skill-bindings/${encodeURIComponent(entryTail)}/revisions`, {
    method: "POST",
    body: JSON.stringify({
      owner_scope_ref: principalRef,
      skill_revision_ref: manifestV2.revision_ref,
      skill_manifest_content_hash: manifestV2.content_hash,
      compatibility_decision_ref: `decision://skill/${tag}/suspended`,
      registry_status: "suspended",
    }),
  });
  const entryV2 = entrySuccessor.body?.skill_entry ?? {};
  const snapshotAttempt = async (binding) => jd("/v1/hypervisor/active-skill-set-snapshots", {
    method: "POST",
    body: JSON.stringify({ work_subject_ref: workSubjectRef, selected_skill_entry_revisions: [{ binding_revision_ref: binding.binding_revision_ref, binding_hash: binding.binding_hash }] }),
  });
  const [staleAttempt, suspendedAttempt] = await Promise.all([snapshotAttempt(entryV1), snapshotAttempt(entryV2)]);
  ok("successor-only binding lifecycle is effective: the stale active revision and current suspended revision both refuse new snapshots",
    staleAttempt.body?.error?.code === "skill_entry_superseded" && suspendedAttempt.body?.error?.code === "skill_entry_ineligible",
    `${staleAttempt.body?.error?.code}/${suspendedAttempt.body?.error?.code}`);

  daemon.kill("SIGTERM");
  await new Promise((resolve) => daemon.once("exit", resolve));
  port = await freePort();
  await startDaemon(port);
  const afterRestart = await jd(`/v1/hypervisor/active-skill-set-snapshots/${snapshotHashTail}`);
  ok("the run-scoped snapshot replays byte-for-byte after daemon restart, independent of today's binding head",
    afterRestart.status === 200 && JSON.stringify(afterRestart.body?.active_skill_set_snapshot) === frozenSnapshot,
    String(afterRestart.status));

  const anonymousExact = await jd(`/v1/hypervisor/active-skill-set-snapshots/${snapshotHashTail}`, undefined, false);
  ok("an anonymous exact-snapshot read reveals no existence oracle", anonymousExact.status === 401
    && anonymousExact.body?.error?.code === "request_principal_required", `${anonymousExact.status}/${anonymousExact.body?.error?.code}`);
}

try {
  await run();
} catch (error) {
  ok("journey completes without infrastructure failure", false, error?.stack ?? String(error));
} finally {
  if (daemon && daemon.exitCode === null) daemon.kill("SIGTERM");
  fs.rmSync(dataDir, { recursive: true, force: true });
}

for (const result of results) {
  console.log(`${result.pass ? "PASS" : "FAIL"}  ${result.name}${result.detail ? ` — ${result.detail}` : ""}`);
}
const failed = results.filter((result) => !result.pass);
emitVerifierCensus({ verifierId: "skill-contracts", sourceUrl: import.meta.url, results });
console.log(`\n${results.length - failed.length}/${results.length} passed`);
process.exit(failed.length ? 1 : 0);

#!/usr/bin/env node
// M04.4 reusable GoalRunProfile and AgentHarnessAdapter definition journey.

import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..", "..", "..");
const SCHEMAS = path.join(ROOT, "docs", "architecture", "_meta", "schemas");
const ajv = new Ajv2020({ allErrors: true, strict: false });
addFormats(ajv);
const validateProfile = ajv.compile(JSON.parse(fs.readFileSync(path.join(SCHEMAS, "goal-run-profile.v1.schema.json"), "utf8")));
const validateAdapter = ajv.compile(JSON.parse(fs.readFileSync(path.join(SCHEMAS, "agent-harness-adapter.v1.schema.json"), "utf8")));

const results = [];
const ok = (name, pass, detail = "") => results.push({ name, pass: !!pass, detail });
const canonical = (value) => {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
};
const sha256 = (value) => `sha256:${createHash("sha256").update(canonical(value)).digest("hex")}`;
const releaseHash = (record, domain, kind) => {
  const body = structuredClone(record);
  for (const field of ["revision_ref", "content_hash", "registry_lifecycle_ref", "registry_status"]) delete body[field];
  return sha256({ domain, kind, body });
};
const freePort = () => new Promise((resolve, reject) => {
  const server = net.createServer();
  server.listen(0, "127.0.0.1", () => {
    const { port } = server.address();
    server.close(() => resolve(port));
  });
  server.on("error", reject);
});
const waitFor = async (url) => {
  const deadline = Date.now() + 30000;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(url);
      if (response.status < 500) return;
    } catch { /* booting */ }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error(`timeout waiting for ${url}`);
};

const binary = path.resolve(ROOT, process.env.IOI_HYPERVISOR_DAEMON_BINARY ?? "target/debug/hypervisor-daemon");
if (!fs.existsSync(binary)) {
  console.error(`BLOCKED: daemon binary missing at ${binary}`);
  process.exit(2);
}
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-goal-profile-contracts-"));
let daemon = null;
let daemonUrl = "";
let session = "";
let log = "";

async function startDaemon(port) {
  daemonUrl = `http://127.0.0.1:${port}`;
  daemon = spawn(binary, [], {
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
  await waitFor(`${daemonUrl}/healthz`);
}

const jd = (url, init, authenticated = true) => fetch(`${daemonUrl}${url}`, {
  headers: {
    ...(init?.body ? { "content-type": "application/json" } : {}),
    ...(authenticated && session ? { cookie: `ioi_session=${session}` } : {}),
  },
  ...init,
}).then(async (response) => ({ status: response.status, body: await response.json().catch(() => ({})) }));

function routeInventory(index) {
  const selected = new Set([
    "/v1/goal-orchestration/goal-run-profiles",
    "/v1/goal-orchestration/goal-run-profiles/:id/revisions",
    "/v1/hypervisor/agent-harness-adapters",
    "/v1/hypervisor/agent-harness-adapters/:id/revisions",
  ]);
  return (index.families ?? []).flatMap((family) => family.paths ?? [])
    .filter((row) => selected.has(row.path))
    .map((row) => ({ path: row.path, methods: [...row.methods].sort() }))
    .sort((left, right) => left.path.localeCompare(right.path));
}

const profileBody = (ownerRef, version, description) => ({
  owner_ref: ownerRef,
  display_name: "Portable bounded pursuit",
  description,
  version,
  applicable_goal_class_refs: ["schema://ioi/ioi-ai/goal-draft/v1"],
  compatible_domain_object_schema_refs: ["schema://ioi/foundations/work-result/v3"],
  orchestration_policy_ref: "orchestration-policy://bounded-general",
  input_contract_ref: "schema://ioi/ioi-ai/goal-draft/v1",
  output_contract_ref: "schema://ioi/foundations/work-result/v3",
  stop_policy_ref: "policy://ioi/goal-run/bounded-stop/v1",
  recovery_policy_ref: "policy://ioi/goal-run/bounded-recovery/v1",
  escalation_policy_ref: "policy://ioi/goal-run/bounded-escalation/v1",
  registry_status: "released",
});

const adapterBody = (ownerRef, status, provenance) => ({
  owner_ref: ownerRef,
  adapter_family: "remote_agent_api",
  transport_kind: "remote_api",
  supported_task_brief_schema_refs: ["schema://ioi/agentic/task-brief/v1"],
  supported_event_and_result_schema_refs: ["schema://ioi/foundations/work-result/v3"],
  provenance_evaluation_and_conformance_refs: [provenance],
  registry_status: status,
});

async function run() {
  let port = await freePort();
  await startDaemon(port);
  const token = log.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? "";
  const bootstrap = await jd("/v1/hypervisor/auth/bootstrap", {
    method: "POST",
    body: JSON.stringify({ token, password: "goal-profile-contracts-v1", email: "goal-profile@ioi.local" }),
  }, false);
  session = bootstrap.body?.session_token ?? "";
  const who = await jd("/v1/hypervisor/auth/whoami");
  const principalRef = who.body?.principal?.principal_ref
    || (who.body?.principal?.principal_id ? `user://${who.body.principal.principal_id}` : "");
  ok("operator bootstrap resolves the definition owner from authenticated daemon identity",
    session.startsWith("ioi_sess_") && principalRef.startsWith("user://"), principalRef);

  const index = await jd("/v1");
  const actual = routeInventory(index.body);
  const expected = [
    { path: "/v1/goal-orchestration/goal-run-profiles", methods: ["GET", "POST"] },
    { path: "/v1/goal-orchestration/goal-run-profiles/:id/revisions", methods: ["POST"] },
    { path: "/v1/hypervisor/agent-harness-adapters", methods: ["GET", "POST"] },
    { path: "/v1/hypervisor/agent-harness-adapters/:id/revisions", methods: ["POST"] },
  ].sort((left, right) => left.path.localeCompare(right.path));
  ok("portable profile and concrete adapter routes have explicit distinct owners",
    JSON.stringify(actual) === JSON.stringify(expected), JSON.stringify(actual));

  const anonymous = await Promise.all([
    jd("/v1/goal-orchestration/goal-run-profiles", undefined, false),
    jd("/v1/hypervisor/agent-harness-adapters", undefined, false),
  ]);
  ok("definition inventory is identity-first and exposes no anonymous oracle",
    anonymous.every((response) => response.status === 401), JSON.stringify(anonymous.map((response) => response.status)));

  const forged = await jd("/v1/goal-orchestration/goal-run-profiles", {
    method: "POST",
    body: JSON.stringify({ ...profileBody(principalRef, "1.0.0", "forged"), content_hash: `sha256:${"f".repeat(64)}` }),
  });
  ok("GATE: profile identity and content hash are daemon-owned",
    forged.status === 400 && forged.body?.error?.code === "goal_profile_unknown_field",
    `${forged.status}/${forged.body?.error?.code}`);

  const createdProfileResponse = await jd("/v1/goal-orchestration/goal-run-profiles", {
    method: "POST", body: JSON.stringify(profileBody(principalRef, "1.0.0", "first immutable revision")),
  });
  const profileV1 = createdProfileResponse.body?.goal_run_profile ?? {};
  const profileTail = String(profileV1.goal_run_profile_id ?? "").replace("goal-run-profile://", "");
  ok("GoalRunProfile admission derives an exact canonical revision and validates the generated contract",
    createdProfileResponse.status === 201 && validateProfile(profileV1)
      && profileV1.revision_ref === `${profileV1.goal_run_profile_id}/revision/${profileV1.content_hash}`,
    profileV1.revision_ref ?? JSON.stringify(validateProfile.errors ?? []));
  ok("GoalRunProfile content identity covers the complete immutable reusable definition",
    profileV1.content_hash === releaseHash(profileV1, "ioi.goal-run-profile-release-jcs-sha256.v1", "goal_run_profile"),
    profileV1.content_hash);

  const createdAdapterResponse = await jd("/v1/hypervisor/agent-harness-adapters", {
    method: "POST", body: JSON.stringify(adapterBody(principalRef, "released", "evidence://adapter/initial")),
  });
  const adapterV1 = createdAdapterResponse.body?.agent_harness_adapter ?? {};
  const adapterTail = String(adapterV1.adapter_id ?? "").replace("agent-harness-adapter://", "");
  ok("AgentHarnessAdapter admission derives a separate exact concrete-transport revision",
    createdAdapterResponse.status === 201 && validateAdapter(adapterV1)
      && adapterV1.revision_ref === `${adapterV1.adapter_id}/revision/${adapterV1.content_hash}`,
    adapterV1.revision_ref ?? JSON.stringify(validateAdapter.errors ?? []));
  ok("adapter content identity is independently domain-separated from profile identity",
    adapterV1.content_hash === releaseHash(adapterV1, "ioi.agent-harness-adapter-release-jcs-sha256.v1", "agent_harness_adapter")
      && adapterV1.content_hash !== profileV1.content_hash, adapterV1.content_hash);
  ok("reusable definitions contain no GoalRun, execution, authority, credential, or receipt claims",
    [profileV1, adapterV1].every((record) => ["goal_ref", "execution_ref", "authority_grant_ref", "credential_ref", "receipt_ref"].every((field) => !Object.hasOwn(record, field))));

  const profileV2Response = await jd(`/v1/goal-orchestration/goal-run-profiles/${encodeURIComponent(profileTail)}/revisions`, {
    method: "POST", body: JSON.stringify(profileBody(principalRef, "2.0.0", "successor revision")),
  });
  const profileV2 = profileV2Response.body?.goal_run_profile ?? {};
  const adapterV2Response = await jd(`/v1/hypervisor/agent-harness-adapters/${encodeURIComponent(adapterTail)}/revisions`, {
    method: "POST", body: JSON.stringify(adapterBody(principalRef, "deprecated", "evidence://adapter/successor")),
  });
  const adapterV2 = adapterV2Response.body?.agent_harness_adapter ?? {};
  ok("both definition families advance only by exact immutable successor lineage",
    profileV2.predecessor_revision_ref === profileV1.revision_ref
      && adapterV2.predecessor_revision_ref === adapterV1.revision_ref
      && profileV2.content_hash !== profileV1.content_hash && adapterV2.content_hash !== adapterV1.content_hash,
    `${profileV2.predecessor_revision_ref}/${adapterV2.predecessor_revision_ref}`);

  const [profilesBefore, adaptersBefore] = await Promise.all([
    jd("/v1/goal-orchestration/goal-run-profiles"),
    jd("/v1/hypervisor/agent-harness-adapters"),
  ]);
  const frozenProfiles = JSON.stringify(profilesBefore.body?.goal_run_profiles ?? []);
  const frozenAdapters = JSON.stringify(adaptersBefore.body?.agent_harness_adapters ?? []);
  ok("owner-scoped inventory retains every immutable revision without conflating profile and adapter lifetimes",
    profilesBefore.body?.goal_run_profiles?.length === 2 && adaptersBefore.body?.agent_harness_adapters?.length === 2
      && profilesBefore.body.goal_run_profiles.every((record) => record.schema_version === "ioi.goal-run-profile.v1")
      && adaptersBefore.body.agent_harness_adapters.every((record) => record.schema_version === "ioi.agent-harness-adapter.v1"));

  const profileFamily = path.join(dataDir, "goal-run-profile-revisions");
  const profileSlot = path.join(profileFamily, `${profileTail}--${profileV1.content_hash.replace("sha256:", "")}.json`);
  const profileBytes = fs.readFileSync(profileSlot);
  const relocatedSlot = path.join(profileFamily, `relocated--${profileV1.content_hash.replace("sha256:", "")}.json`);
  fs.copyFileSync(profileSlot, relocatedSlot);
  const relocated = await jd("/v1/goal-orchestration/goal-run-profiles");
  fs.unlinkSync(relocatedSlot);
  const tamperedProfile = JSON.parse(profileBytes.toString("utf8"));
  tamperedProfile.description = "content changed without changing its release hash";
  fs.writeFileSync(profileSlot, JSON.stringify(tamperedProfile));
  const tampered = await jd("/v1/goal-orchestration/goal-run-profiles");
  fs.writeFileSync(profileSlot, profileBytes);
  ok("whole-family reads refuse relocated slots and content that does not recompute to its release hash",
    [relocated, tampered].every((response) => response.status === 409
      && response.body?.error?.code === "goal_profile_registry_unreadable"),
    JSON.stringify([relocated.status, tampered.status]));

  daemon.kill("SIGTERM");
  await new Promise((resolve) => daemon.once("exit", resolve));
  port = await freePort();
  await startDaemon(port);
  const [profilesAfter, adaptersAfter] = await Promise.all([
    jd("/v1/goal-orchestration/goal-run-profiles"),
    jd("/v1/hypervisor/agent-harness-adapters"),
  ]);
  ok("portable profile and adapter revision histories replay byte-for-byte after daemon restart",
    JSON.stringify(profilesAfter.body?.goal_run_profiles ?? []) === frozenProfiles
      && JSON.stringify(adaptersAfter.body?.agent_harness_adapters ?? []) === frozenAdapters);
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
emitVerifierCensus({ verifierId: "goal-profile-contracts", sourceUrl: import.meta.url, results });
console.log(`\n${results.length - failed.length}/${results.length} passed`);
process.exit(failed.length ? 1 : 0);

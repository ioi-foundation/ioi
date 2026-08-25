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
const gatewayProfileTemplate = JSON.parse(fs.readFileSync(path.join(
  SCHEMAS,
  "fixtures",
  "authority-gateway-profile-v1",
  "positive-active-pre-effect.json",
), "utf8"));

const results = [];
const ok = (name, pass, detail = "") => results.push({ name, pass: !!pass, detail });
const H1 = `sha256:${"1".repeat(64)}`;
const H2 = `sha256:${"2".repeat(64)}`;
const familyCount = (family) => {
  try { return fs.readdirSync(path.join(dataDir, family)).filter((name) => name.endsWith(".json")).length; } catch { return 0; }
};
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
const gatewayProfileHash = (profile) => sha256({
  domain: "ioi.authority-gateway-profile-hash-jcs-sha256.v1",
  profile_ref: profile.profile_ref,
  profile_revision: profile.profile_revision,
  predecessor_profile_hash: profile.predecessor_profile_hash,
  declaration: profile.declaration,
  created_at: profile.created_at,
  valid_until: profile.valid_until,
});
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

const profileBody = (
  ownerRef,
  version,
  description,
  workflowTemplateRevisionRefs = [],
  skillRequirementRefs = [],
) => ({
  owner_ref: ownerRef,
  display_name: "Portable bounded pursuit",
  description,
  version,
  applicable_goal_class_refs: ["schema://ioi/ioi-ai/goal-draft/v1"],
  compatible_domain_object_schema_refs: ["schema://ioi/foundations/work-result/v3"],
  orchestration_policy_ref: "orchestration-policy://bounded-general",
  workflow_template_revision_refs: workflowTemplateRevisionRefs,
  harness_requirement_refs: ["harness://hypervisor_worker"],
  skill_requirement_refs: skillRequirementRefs,
  runtime_tool_contract_requirement_refs: ["tool://ioi/runtime/file__read"],
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
  const tenantOwner = (who.body?.principal?.tenant_refs ?? []).find((ref) => ref === "org://local") ?? "";
  ok("operator bootstrap resolves the definition owner from authenticated daemon identity",
    session.startsWith("ioi_sess_") && principalRef.startsWith("user://") && tenantOwner === "org://local",
    `${principalRef}/${tenantOwner}`);

  const workflowResponse = await jd("/v1/hypervisor/workflow-templates", {
    method: "POST",
    body: JSON.stringify({
      owner_ref: principalRef,
      display_name: "Goal profile bounded workflow",
      version: "1.0.0",
      graph_ref: "workflow://graph/goal-profile-bounded-v1",
      graph_hash: H1,
      registry_status: "released",
    }),
  });
  const workflowTemplate = workflowResponse.body?.workflow_template ?? {};
  ok("the automation owner admits the exact released WorkflowTemplate used by the portable profile",
    workflowResponse.status === 201
      && workflowTemplate.revision_ref === `${workflowTemplate.workflow_template_id}/revision/${workflowTemplate.content_hash}`,
    `${workflowResponse.status}/${workflowTemplate.revision_ref ?? ""}`);

  const skillDependencyManifestResponse = await jd("/v1/hypervisor/skill-manifests", {
    method: "POST",
    body: JSON.stringify({
      owner_ref: principalRef,
      display_name: "Goal profile evidence inventory dependency",
      instruction_entrypoint_ref: "artifact://skill/goal-profile-evidence-inventory/instructions",
      runtime_tool_contract_requirement_refs: ["tool://ioi/runtime/file__list"],
      registry_status: "released",
    }),
  });
  const skillDependencyManifest = skillDependencyManifestResponse.body?.skill_manifest ?? {};
  const skillDependencyBindingResponse = await jd("/v1/hypervisor/skill-bindings", {
    method: "POST",
    body: JSON.stringify({
      owner_scope_ref: principalRef,
      skill_revision_ref: skillDependencyManifest.revision_ref,
      skill_manifest_content_hash: skillDependencyManifest.content_hash,
      compatibility_decision_ref: "decision://skill/goal-profile-evidence-inventory/compatible",
      registry_status: "active",
    }),
  });
  const skillDependencyBinding = skillDependencyBindingResponse.body?.skill_entry ?? {};
  const skillManifestResponse = await jd("/v1/hypervisor/skill-manifests", {
    method: "POST",
    body: JSON.stringify({
      owner_ref: principalRef,
      display_name: "Goal profile evidence reader",
      instruction_entrypoint_ref: "artifact://skill/goal-profile-evidence-reader/instructions",
      dependency_skill_revision_refs: [skillDependencyManifest.revision_ref],
      registry_status: "released",
    }),
  });
  const skillManifest = skillManifestResponse.body?.skill_manifest ?? {};
  const skillBindingResponse = await jd("/v1/hypervisor/skill-bindings", {
    method: "POST",
    body: JSON.stringify({
      owner_scope_ref: principalRef,
      skill_revision_ref: skillManifest.revision_ref,
      skill_manifest_content_hash: skillManifest.content_hash,
      compatibility_decision_ref: "decision://skill/goal-profile-evidence-reader/compatible",
      registry_status: "active",
    }),
  });
  const skillBinding = skillBindingResponse.body?.skill_entry ?? {};
  ok("the skill owner admits released dependency closure and current active bindings for profile resolution",
    skillDependencyManifestResponse.status === 201
      && skillDependencyBindingResponse.status === 201
      && skillManifestResponse.status === 201
      && skillBindingResponse.status === 201
      && skillDependencyBinding.skill_revision_ref === skillDependencyManifest.revision_ref
      && skillBinding.skill_revision_ref === skillManifest.revision_ref,
    `${skillDependencyManifestResponse.status}/${skillDependencyBindingResponse.status}/${skillManifestResponse.status}/${skillBindingResponse.status}`);

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
    body: JSON.stringify({ ...profileBody(principalRef, "1.0.0", "forged", [workflowTemplate.revision_ref], [skillManifest.skill_id]), content_hash: `sha256:${"f".repeat(64)}` }),
  });
  ok("GATE: profile identity and content hash are daemon-owned",
    forged.status === 400 && forged.body?.error?.code === "goal_profile_unknown_field",
    `${forged.status}/${forged.body?.error?.code}`);

  const createdProfileResponse = await jd("/v1/goal-orchestration/goal-run-profiles", {
    method: "POST", body: JSON.stringify(profileBody(principalRef, "1.0.0", "first immutable revision", [workflowTemplate.revision_ref], [skillManifest.skill_id])),
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
    method: "POST", body: JSON.stringify(profileBody(principalRef, "2.0.0", "successor revision", [workflowTemplate.revision_ref], [skillManifest.skill_id])),
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

  const tenantAdapterResponse = await jd("/v1/hypervisor/agent-harness-adapters", {
    method: "POST",
    body: JSON.stringify(adapterBody(tenantOwner, "released", "evidence://adapter/tenant-gateway")),
  });
  const tenantAdapter = tenantAdapterResponse.body?.agent_harness_adapter ?? {};
  ok("an authenticated tenant principal can admit an organization-owned released adapter",
    tenantAdapterResponse.status === 201 && tenantAdapter.owner_ref === tenantOwner
      && tenantAdapter.registry_status === "released" && validateAdapter(tenantAdapter),
    `${tenantAdapterResponse.status}/${tenantAdapter.owner_ref ?? ""}`);

  const gatewayProfile = structuredClone(gatewayProfileTemplate);
  gatewayProfile.profile_ref = "authority-gateway://local/goal-profile-contracts/revision/1";
  gatewayProfile.declaration.adapter.adapter_ref = "adapter://local/goal-profile-contracts";
  gatewayProfile.declaration.adapter.implementation_ref = "artifact://local/goal-profile-contracts/1.0.0";
  gatewayProfile.declaration.adapter.deployment_profile_ref = "deployment-profile://local/goal-profile-contracts";
  gatewayProfile.declaration.run_on_graduation.agent_harness_adapter_revision_ref = tenantAdapter.revision_ref;
  gatewayProfile.declaration.run_on_graduation.agent_harness_adapter_content_hash = `sha256:${"f".repeat(64)}`;
  gatewayProfile.profile_hash = gatewayProfileHash(gatewayProfile);
  const forgedGateway = await jd("/v1/authority-gateway/profiles", {
    method: "POST",
    body: JSON.stringify({
      owner_ref: tenantOwner,
      idempotency_key: "goal-profile-contracts-forged-gateway-v1",
      profile: gatewayProfile,
    }),
  });
  ok("GATE: a gateway profile cannot cite an unresolvable or hash-mismatched run-on adapter",
    forgedGateway.status === 409
      && forgedGateway.body?.error?.code === "gateway_run_on_adapter_unresolved"
      && !fs.existsSync(path.join(dataDir, "authority-gateway-profiles")),
    `${forgedGateway.status}/${forgedGateway.body?.error?.code}`);

  gatewayProfile.declaration.run_on_graduation.agent_harness_adapter_content_hash = tenantAdapter.content_hash;
  gatewayProfile.profile_hash = gatewayProfileHash(gatewayProfile);
  const exactGateway = await jd("/v1/authority-gateway/profiles", {
    method: "POST",
    body: JSON.stringify({
      owner_ref: tenantOwner,
      idempotency_key: "goal-profile-contracts-exact-gateway-v1",
      profile: gatewayProfile,
    }),
  });
  const retainedGateway = exactGateway.body?.profile?.profile ?? {};
  const graduation = retainedGateway.declaration?.run_on_graduation ?? {};
  const persistedGateways = fs.readdirSync(path.join(dataDir, "authority-gateway-profiles"))
    .filter((name) => name.endsWith(".json"))
    .map((name) => JSON.parse(fs.readFileSync(path.join(dataDir, "authority-gateway-profiles", name), "utf8")));
  ok("current gateway admission durably binds the exact released adapter and carries no ambient authority",
    exactGateway.status === 201 && persistedGateways.length === 1
      && graduation.agent_harness_adapter_revision_ref === tenantAdapter.revision_ref
      && graduation.agent_harness_adapter_content_hash === tenantAdapter.content_hash
      && graduation.implicit_approval_carryover === false
      && graduation.implicit_grant_carryover === false
      && graduation.implicit_credential_carryover === false
      && graduation.implicit_scope_carryover === false,
    `${exactGateway.status}/${graduation.agent_harness_adapter_revision_ref ?? ""}`);

  const definitionResolution = {
    workflow_template_revision_refs: [workflowTemplate.revision_ref],
    component_hashes: {},
  };
  const pathRequest = {
    requested_path: "direct_non_system",
    goal_run_profile_revision_ref: profileV2.revision_ref,
    goal_run_profile_content_hash: `sha256:${"f".repeat(64)}`,
    result_profile: "research",
    capability_requirement_refs: [],
  };
  const goalRunsBefore = familyCount("goal-runs");
  const unresolvedToolProfileResponse = await jd("/v1/goal-orchestration/goal-run-profiles", {
    method: "POST",
    body: JSON.stringify({
      ...profileBody(principalRef, "1.0.0", "unresolvable runtime-tool requirement", [workflowTemplate.revision_ref], [skillManifest.skill_id]),
      runtime_tool_contract_requirement_refs: ["tool://ioi/runtime/unregistered_goal_profile_tool"],
    }),
  });
  const unresolvedToolProfile = unresolvedToolProfileResponse.body?.goal_run_profile ?? {};
  const unresolvedToolPath = {
    ...pathRequest,
    goal_run_profile_revision_ref: unresolvedToolProfile.revision_ref,
    goal_run_profile_content_hash: unresolvedToolProfile.content_hash,
  };
  const unresolvedTool = await jd("/v1/goal-orchestration/goal-runs", {
    method: "POST",
    body: JSON.stringify({
      goal: "Refuse an unresolvable runtime-tool requirement",
      admission_path_request: unresolvedToolPath,
      definition_resolution: definitionResolution,
    }),
  });
  ok("GATE: a profile runtime-tool requirement must resolve from the current released owner registry before persistence",
    unresolvedToolProfileResponse.status === 201
      && unresolvedTool.status === 409
      && unresolvedTool.body?.error?.code === "goal_run_runtime_tool_resolution_unavailable"
      && familyCount("goal-runs") === goalRunsBefore,
    `${unresolvedTool.status}/${unresolvedTool.body?.error?.code}`);

  const unresolvedSkillProfileResponse = await jd("/v1/goal-orchestration/goal-run-profiles", {
    method: "POST",
    body: JSON.stringify({
      ...profileBody(principalRef, "1.0.0", "unresolvable skill requirement", [workflowTemplate.revision_ref]),
      skill_requirement_refs: ["skill://unregistered_goal_profile_skill"],
    }),
  });
  const unresolvedSkillProfile = unresolvedSkillProfileResponse.body?.goal_run_profile ?? {};
  const unresolvedSkillPath = {
    ...pathRequest,
    goal_run_profile_revision_ref: unresolvedSkillProfile.revision_ref,
    goal_run_profile_content_hash: unresolvedSkillProfile.content_hash,
  };
  const unresolvedSkill = await jd("/v1/goal-orchestration/goal-runs", {
    method: "POST",
    body: JSON.stringify({
      goal: "Refuse an unresolvable skill requirement",
      admission_path_request: unresolvedSkillPath,
      definition_resolution: definitionResolution,
    }),
  });
  ok("GATE: a profile skill requirement must resolve through a current active owner binding before persistence",
    unresolvedSkillProfileResponse.status === 201
      && unresolvedSkill.status === 409
      && unresolvedSkill.body?.error?.code === "goal_run_skill_resolution_unavailable"
      && familyCount("goal-runs") === goalRunsBefore,
    `${unresolvedSkill.status}/${unresolvedSkill.body?.error?.code}`);

  const unsupportedPolicyProfileResponse = await jd("/v1/goal-orchestration/goal-run-profiles", {
    method: "POST",
    body: JSON.stringify({
      ...profileBody(principalRef, "1.0.0", "unsupported orchestration policy", [workflowTemplate.revision_ref], [skillManifest.skill_id]),
      orchestration_policy_ref: "orchestration-policy://unregistered-portable-policy",
    }),
  });
  const unsupportedPolicyProfile = unsupportedPolicyProfileResponse.body?.goal_run_profile ?? {};
  const unsupportedPolicy = await jd("/v1/goal-orchestration/goal-runs", {
    method: "POST",
    body: JSON.stringify({
      goal: "Refuse an unowned orchestration policy",
      admission_path_request: {
        ...pathRequest,
        goal_run_profile_revision_ref: unsupportedPolicyProfile.revision_ref,
        goal_run_profile_content_hash: unsupportedPolicyProfile.content_hash,
      },
      definition_resolution: definitionResolution,
    }),
  });
  ok("GATE: general admission refuses a profile policy with no canonical runtime owner",
    unsupportedPolicyProfileResponse.status === 201
      && unsupportedPolicy.status === 409
      && unsupportedPolicy.body?.error?.code === "goal_run_orchestration_policy_resolution_unavailable"
      && familyCount("goal-runs") === goalRunsBefore,
    `${unsupportedPolicy.status}/${unsupportedPolicy.body?.error?.code}`);

  const unsupportedRequirementProfileResponse = await jd("/v1/goal-orchestration/goal-run-profiles", {
    method: "POST",
    body: JSON.stringify({
      ...profileBody(principalRef, "1.0.0", "unsupported primitive requirement", [workflowTemplate.revision_ref], [skillManifest.skill_id]),
      primitive_capability_requirements: ["prim:network.egress"],
    }),
  });
  const unsupportedRequirementProfile = unsupportedRequirementProfileResponse.body?.goal_run_profile ?? {};
  const unsupportedRequirement = await jd("/v1/goal-orchestration/goal-runs", {
    method: "POST",
    body: JSON.stringify({
      goal: "Refuse an unresolved primitive requirement",
      admission_path_request: {
        ...pathRequest,
        goal_run_profile_revision_ref: unsupportedRequirementProfile.revision_ref,
        goal_run_profile_content_hash: unsupportedRequirementProfile.content_hash,
      },
      definition_resolution: definitionResolution,
    }),
  });
  ok("GATE: unsupported nonempty profile requirement families fail closed before persistence",
    unsupportedRequirementProfileResponse.status === 201
      && unsupportedRequirement.status === 409
      && unsupportedRequirement.body?.error?.code === "goal_run_profile_requirement_resolution_unavailable"
      && familyCount("goal-runs") === goalRunsBefore,
    `${unsupportedRequirement.status}/${unsupportedRequirement.body?.error?.code}`);

  const substitutedConstraintResolution = structuredClone(definitionResolution);
  substitutedConstraintResolution.effective_constraint_envelope_hash = H2;
  const substitutedConstraint = await jd("/v1/goal-orchestration/goal-runs", {
    method: "POST",
    body: JSON.stringify({
      goal: "Refuse a caller constraint commitment",
      admission_path_request: {
        ...pathRequest,
        goal_run_profile_revision_ref: profileV2.revision_ref,
        goal_run_profile_content_hash: profileV2.content_hash,
      },
      definition_resolution: substitutedConstraintResolution,
    }),
  });
  ok("GATE: caller-substituted effective constraints refuse before GoalRun persistence",
    substitutedConstraint.status === 409
      && substitutedConstraint.body?.error?.code === "goal_run_admission_material_substitution"
      && familyCount("goal-runs") === goalRunsBefore,
    `${substitutedConstraint.status}/${substitutedConstraint.body?.error?.code}`);

  const substitutedLateBindingResolution = structuredClone(definitionResolution);
  substitutedLateBindingResolution.unresolved_late_binding_requirement_refs = ["worker://caller-forged"];
  const substitutedLateBinding = await jd("/v1/goal-orchestration/goal-runs", {
    method: "POST",
    body: JSON.stringify({
      goal: "Refuse caller late-binding material",
      admission_path_request: {
        ...pathRequest,
        goal_run_profile_revision_ref: profileV2.revision_ref,
        goal_run_profile_content_hash: profileV2.content_hash,
      },
      definition_resolution: substitutedLateBindingResolution,
    }),
  });
  ok("GATE: caller-authored late-binding requirements refuse before GoalRun persistence",
    substitutedLateBinding.status === 409
      && substitutedLateBinding.body?.error?.code === "goal_run_admission_material_substitution"
      && familyCount("goal-runs") === goalRunsBefore,
    `${substitutedLateBinding.status}/${substitutedLateBinding.body?.error?.code}`);

  const substitutedOverrideResolution = structuredClone(definitionResolution);
  substitutedOverrideResolution.admitted_override_set_ref = "artifact://caller/override-set";
  substitutedOverrideResolution.admitted_override_set_hash = H1;
  const substitutedOverride = await jd("/v1/goal-orchestration/goal-runs", {
    method: "POST",
    body: JSON.stringify({
      goal: "Refuse a caller override set",
      admission_path_request: {
        ...pathRequest,
        goal_run_profile_revision_ref: profileV2.revision_ref,
        goal_run_profile_content_hash: profileV2.content_hash,
      },
      definition_resolution: substitutedOverrideResolution,
    }),
  });
  ok("GATE: a null-override profile refuses caller-authored override coordinates",
    substitutedOverride.status === 409
      && substitutedOverride.body?.error?.code === "goal_run_override_substitution"
      && familyCount("goal-runs") === goalRunsBefore,
    `${substitutedOverride.status}/${substitutedOverride.body?.error?.code}`);

  const skillManifestTail = String(skillManifest.skill_id ?? "").replace("skill://", "");
  const skillManifestSlot = path.join(
    dataDir,
    "canonical-skill-manifest-revisions",
    `${skillManifestTail}--${String(skillManifest.content_hash).replace("sha256:", "")}.json`,
  );
  const skillManifestBytes = fs.readFileSync(skillManifestSlot);
  const changedSkillManifest = JSON.parse(skillManifestBytes.toString("utf8"));
  changedSkillManifest.description = "changed without a successor revision";
  fs.writeFileSync(skillManifestSlot, JSON.stringify(changedSkillManifest));
  const changedSkill = await jd("/v1/goal-orchestration/goal-runs", {
    method: "POST",
    body: JSON.stringify({
      goal: "Refuse changed skill-manifest bytes",
      admission_path_request: {
        ...pathRequest,
        goal_run_profile_revision_ref: profileV2.revision_ref,
        goal_run_profile_content_hash: profileV2.content_hash,
      },
      definition_resolution: definitionResolution,
    }),
  });
  fs.writeFileSync(skillManifestSlot, skillManifestBytes);
  ok("GATE: changed canonical SkillManifest bytes refuse before GoalRun persistence",
    changedSkill.status === 409
      && changedSkill.body?.error?.code === "goal_run_skill_resolution_unavailable"
      && familyCount("goal-runs") === goalRunsBefore,
    `${changedSkill.status}/${changedSkill.body?.error?.code}`);

  const forgedGoalRun = await jd("/v1/goal-orchestration/goal-runs", {
    method: "POST",
    body: JSON.stringify({
      goal: "Resolve an exact portable profile before admission",
      admission_path_request: pathRequest,
      definition_resolution: definitionResolution,
    }),
  });
  ok("GATE: the general GoalRun surface refuses an unregistered profile hash before any run write",
    forgedGoalRun.status === 409
      && forgedGoalRun.body?.error?.code === "goal_run_profile_resolution_unavailable"
      && familyCount("goal-runs") === goalRunsBefore,
    `${forgedGoalRun.status}/${forgedGoalRun.body?.error?.code}`);

  pathRequest.goal_run_profile_content_hash = profileV2.content_hash;
  const workflowTail = String(workflowTemplate.workflow_template_id).replace("workflow-template://", "");
  const workflowSlot = path.join(dataDir, "workflow-template-revisions", `${workflowTail}--${workflowTemplate.content_hash.replace("sha256:", "")}.json`);
  const workflowBytes = fs.readFileSync(workflowSlot);
  const changedWorkflow = JSON.parse(workflowBytes.toString("utf8"));
  changedWorkflow.description = "changed after immutable WorkflowTemplate admission";
  fs.writeFileSync(workflowSlot, JSON.stringify(changedWorkflow));
  const changedWorkflowRun = await jd("/v1/goal-orchestration/goal-runs", {
    method: "POST",
    body: JSON.stringify({
      goal: "Refuse changed WorkflowTemplate registry truth",
      admission_path_request: pathRequest,
      definition_resolution: definitionResolution,
    }),
  });
  fs.writeFileSync(workflowSlot, workflowBytes);
  ok("GATE: general GoalRun admission refuses changed WorkflowTemplate registry bytes before persistence",
    changedWorkflowRun.status === 409
      && changedWorkflowRun.body?.error?.code === "goal_run_workflow_resolution_unavailable"
      && familyCount("goal-runs") === goalRunsBefore,
    `${changedWorkflowRun.status}/${changedWorkflowRun.body?.error?.code}`);

  const substitutedResolution = structuredClone(definitionResolution);
  substitutedResolution.workflow_template_revision_refs = ["workflow-template://substituted/revision/sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"];
  delete substitutedResolution.component_hashes[workflowTemplate.revision_ref];
  substitutedResolution.component_hashes[substitutedResolution.workflow_template_revision_refs[0]] = H1;
  const substitutedWorkflow = await jd("/v1/goal-orchestration/goal-runs", {
    method: "POST",
    body: JSON.stringify({
      goal: "Refuse a substituted WorkflowTemplate selection",
      admission_path_request: pathRequest,
      definition_resolution: substitutedResolution,
    }),
  });
  ok("GATE: general GoalRun admission refuses a caller-substituted WorkflowTemplate before persistence",
    substitutedWorkflow.status === 409
      && substitutedWorkflow.body?.error?.code === "goal_run_workflow_resolution_substitution"
      && familyCount("goal-runs") === goalRunsBefore,
    `${substitutedWorkflow.status}/${substitutedWorkflow.body?.error?.code}`);

  const substitutedHarnessResolution = structuredClone(definitionResolution);
  const substitutedHarnessRef = "harness-profile://substituted/revision/sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
  substitutedHarnessResolution.harness_profile_revision_refs = [substitutedHarnessRef];
  substitutedHarnessResolution.component_hashes[substitutedHarnessRef] = H1;
  const substitutedHarness = await jd("/v1/goal-orchestration/goal-runs", {
    method: "POST",
    body: JSON.stringify({
      goal: "Refuse a substituted harness-profile selection",
      admission_path_request: pathRequest,
      definition_resolution: substitutedHarnessResolution,
    }),
  });
  ok("GATE: general GoalRun admission refuses a caller-substituted harness profile before persistence",
    substitutedHarness.status === 409
      && substitutedHarness.body?.error?.code === "goal_run_harness_resolution_substitution"
      && familyCount("goal-runs") === goalRunsBefore,
    `${substitutedHarness.status}/${substitutedHarness.body?.error?.code}`);

  const substitutedSkillResolution = structuredClone(definitionResolution);
  const substitutedSkillRef = "skill://substituted/revision/sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
  substitutedSkillResolution.skill_manifest_revision_refs = [substitutedSkillRef];
  substitutedSkillResolution.component_hashes[substitutedSkillRef] = H1;
  const substitutedSkill = await jd("/v1/goal-orchestration/goal-runs", {
    method: "POST",
    body: JSON.stringify({
      goal: "Refuse a substituted skill selection",
      admission_path_request: pathRequest,
      definition_resolution: substitutedSkillResolution,
    }),
  });
  ok("GATE: general GoalRun admission refuses caller-substituted skill bindings before persistence",
    substitutedSkill.status === 409
      && substitutedSkill.body?.error?.code === "goal_run_skill_resolution_substitution"
      && familyCount("goal-runs") === goalRunsBefore,
    `${substitutedSkill.status}/${substitutedSkill.body?.error?.code}`);

  const substitutedToolResolution = structuredClone(definitionResolution);
  const substitutedToolRef = "tool://substituted/revision/sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
  substitutedToolResolution.runtime_tool_contract_refs = [substitutedToolRef];
  substitutedToolResolution.component_hashes[substitutedToolRef] = H1;
  const substitutedTool = await jd("/v1/goal-orchestration/goal-runs", {
    method: "POST",
    body: JSON.stringify({
      goal: "Refuse a substituted runtime-tool selection",
      admission_path_request: pathRequest,
      definition_resolution: substitutedToolResolution,
    }),
  });
  ok("GATE: general GoalRun admission refuses a caller-substituted runtime-tool contract before persistence",
    substitutedTool.status === 409
      && substitutedTool.body?.error?.code === "goal_run_runtime_tool_resolution_substitution"
      && familyCount("goal-runs") === goalRunsBefore,
    `${substitutedTool.status}/${substitutedTool.body?.error?.code}`);

  const directPolicyDir = path.join(dataDir, "goal-run-admission-policy-revisions");
  const directPolicySlot = path.join(
    directPolicyDir,
    fs.readdirSync(directPolicyDir).find((name) => name.startsWith("direct_") && name.endsWith(".json")),
  );
  const directPolicyBytes = fs.readFileSync(directPolicySlot);
  const changedDirectPolicy = JSON.parse(directPolicyBytes.toString("utf8"));
  changedDirectPolicy.allowed_result_profiles = ["custom"];
  fs.writeFileSync(directPolicySlot, JSON.stringify(changedDirectPolicy));
  const changedDirectPolicyRun = await jd("/v1/goal-orchestration/goal-runs", {
    method: "POST",
    body: JSON.stringify({
      goal: "Refuse changed direct policy registry bytes",
      admission_path_request: pathRequest,
      definition_resolution: definitionResolution,
    }),
  });
  fs.writeFileSync(directPolicySlot, directPolicyBytes);
  ok("GATE: changed daemon-owned direct policy bytes refuse before GoalRun persistence",
    changedDirectPolicyRun.status === 409
      && changedDirectPolicyRun.body?.error?.code === "goal_run_activation_immutable_release_conflict"
      && familyCount("goal-runs") === goalRunsBefore,
    `${changedDirectPolicyRun.status}/${changedDirectPolicyRun.body?.error?.code}`);

  const exactGoalRun = await jd("/v1/goal-orchestration/goal-runs", {
    method: "POST",
    body: JSON.stringify({
      goal: "Resolve an exact portable profile before admission",
      admission_path_request: pathRequest,
      definition_resolution: definitionResolution,
    }),
  });
  const exactResolution = exactGoalRun.body?.definition_resolution ?? {};
  const exactReceipt = exactResolution.resolution_receipt ?? {};
  const exactSnapshot = exactResolution.resolved_component_set ?? {};
  ok("the general GoalRun surface consumes exact daemon-resolved workflow, harness, skill, and transitive runtime-tool tuples",
    exactGoalRun.status === 201
      && exactGoalRun.body?.goal_run?.goal_run_profile_revision_ref === profileV2.revision_ref
      && exactGoalRun.body?.goal_run?.goal_run_profile_content_hash === profileV2.content_hash
      && exactGoalRun.body?.definition_resolution?.resolution_receipt?.goal_run_profile_content_hash === profileV2.content_hash
      && exactGoalRun.body?.definition_resolution?.resolution_receipt?.workflow_template_resolutions?.[0]?.revision_ref === workflowTemplate.revision_ref
      && exactGoalRun.body?.definition_resolution?.resolution_receipt?.workflow_template_resolutions?.[0]?.content_hash === workflowTemplate.content_hash
      && exactGoalRun.body?.definition_resolution?.resolution_receipt?.resolved_harness_profile_revisions?.[0]?.revision_ref?.startsWith("harness-profile://daemon-resolved/hypervisor_worker/revision/sha256:")
      && exactGoalRun.body?.definition_resolution?.resolution_receipt?.resolved_harness_profile_revisions?.[0]?.content_hash?.startsWith("sha256:")
      && exactGoalRun.body?.definition_resolution?.resolution_receipt?.resolved_skill_bindings?.length === 2
      && exactGoalRun.body?.definition_resolution?.resolution_receipt?.resolved_skill_bindings?.some((binding) => binding.skill_manifest_revision_ref === skillManifest.revision_ref && binding.skill_entry_binding_revision_ref === skillBinding.binding_revision_ref)
      && exactGoalRun.body?.definition_resolution?.resolution_receipt?.resolved_skill_bindings?.some((binding) => binding.skill_manifest_revision_ref === skillDependencyManifest.revision_ref && binding.skill_entry_binding_revision_ref === skillDependencyBinding.binding_revision_ref)
      && exactGoalRun.body?.definition_resolution?.resolution_receipt?.resolved_runtime_tool_contracts?.some((contract) => contract.revision_ref?.startsWith("tool://ioi/runtime/file__read/revision/") && contract.content_hash?.startsWith("sha256:"))
      && exactGoalRun.body?.definition_resolution?.resolution_receipt?.resolved_runtime_tool_contracts?.some((contract) => contract.revision_ref?.startsWith("tool://ioi/runtime/file__list/revision/") && contract.content_hash?.startsWith("sha256:")),
    `${exactGoalRun.status}/${exactGoalRun.body?.error?.code ?? ""}`);
  ok("the direct closure freezes daemon-owned policy, constraints, null overrides, and empty unresolved requirements into the snapshot hash",
    exactReceipt.orchestration_policy_ref?.startsWith("orchestration-policy://bounded-general/revision/sha256:")
      && exactReceipt.orchestration_policy_version_or_hash?.startsWith("sha256:")
      && exactReceipt.effective_constraint_envelope_ref?.startsWith("constraint://goal-run/")
      && exactReceipt.effective_constraint_envelope_hash?.startsWith("sha256:")
      && exactReceipt.admitted_override_set_ref === null
      && exactReceipt.admitted_override_set_hash === null
      && exactReceipt.unresolved_late_binding_requirement_refs?.length === 0
      && exactSnapshot.orchestration_policy_ref === exactReceipt.orchestration_policy_ref
      && exactSnapshot.effective_constraint_envelope_hash === exactReceipt.effective_constraint_envelope_hash
      && exactSnapshot.effective_constraint_envelope?.requester_ref === principalRef
      && exactSnapshot.admitted_override_set_ref === null
      && exactGoalRun.body?.goal_run?.constraint_refs?.[0] === exactReceipt.effective_constraint_envelope_ref
      && exactGoalRun.body?.goal_run?.authority_scope_refs?.length === 0
      && familyCount("goal-run-admission-policy-revisions") === 1,
    `${exactGoalRun.status}/${exactReceipt.orchestration_policy_ref ?? ""}`);
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

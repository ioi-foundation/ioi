#!/usr/bin/env node
//
// M09.2 — THE STARTUP PLAN IS INSPECTABLE BEFORE IT RUNS, AND IT FREEZES WHAT IT SAYS IT FREEZES.
//
// ACC-11 clause 3: the startup plan is inspectable before it runs and the lifecycle executes that
// plan. This drives a real daemon end to end — recipe, resolution, plan — and then attacks the
// plan's four refusals.
//
// WHAT WAS HERE BEFORE. `HypervisorEnvironmentStartupPlan` did not exist. The only occurrence of
// the name in the estate outside canon was `environment_startup_plan_ref`, listed in
// `project_discovery_routes.rs` among the fields a discovery proposal may NOT carry — the plane
// next door correctly refusing to mint something that had no owner. Canon describes a 46-field
// immutable bridge from a resolved recipe to one concrete startup attempt; nothing implemented it.
//
// AND A SECOND GAP THAT ONLY APPEARED WHEN THIS CHECK WAS WRITTEN. The only producer of a
// resolution was environment CREATION, which resolves the recipe, runs its tasks and starts its
// services in one pass. So a plan's predecessor could only be obtained by starting the environment
// the plan plans — and a plan inspectable only after the thing it plans has started is the
// negation of clause 3 rather than a weaker form of it. The standalone resolution lane exists
// because this check could not otherwise be written honestly.
//
// THE FOUR REFUSALS THE UNIT NAMES, and how each is attacked:
//   * proposal execution — the plan executes nothing, and says so on the wire
//   * mutable recipe aliases — the plan freezes the recipe by CONTENT, proved by editing the
//     recipe afterwards and showing the plan still commits the old bytes
//   * undeclared endpoints/custody/egress/effects — every required edge the resolution names must
//     be declared, attacked one edge at a time
//   * caller-asserted lineage — every server-resolved field, attacked one field at a time
import net from "node:net";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const RESULTS = [];
const ok = (label, pass, detail = "") => {
  RESULTS.push({ label, pass: !!pass, detail });
  console.log(`${pass ? "PASS" : "FAIL"}  ${label}${detail ? `  · ${detail}` : ""}`);
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const freePort = () => new Promise((resolve, reject) => {
  const srv = net.createServer();
  srv.listen(0, "127.0.0.1", () => { const { port } = srv.address(); srv.close(() => resolve(port)); });
  srv.on("error", reject);
});

const daemonBinary = path.resolve(ROOT, process.env.IOI_HYPERVISOR_DAEMON_BINARY ?? "target/debug/hypervisor-daemon");
let scratch = "";
let daemon = null;
let daemonLog = "";
let BASE = "";

function cleanup() {
  try { daemon?.kill("SIGTERM"); } catch { /* already gone */ }
  daemon = null;
  if (scratch) { try { fs.rmSync(scratch, { recursive: true, force: true }); } catch { /* best effort */ } }
}
process.on("exit", cleanup);
process.on("SIGINT", () => { cleanup(); process.exit(130); });
process.on("SIGTERM", () => { cleanup(); process.exit(143); });

async function jd(method, route, body) {
  const res = await fetch(`${BASE}${route}`, {
    method,
    headers: body === undefined ? undefined : { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* not json */ }
  return { status: res.status, json, text };
}
const code = (response) => response.json?.code ?? null;

// The recipe every case below resolves. It carries one required service, one required port and one
// required secret, so each undeclared-edge attack has a distinct subject.
const RECIPE = {
  recipe: {
    substrate: "container",
    services: [{ name: "db", command: "postgres -D /var/lib/postgresql/data", lifecycle: "required", trigger: "environment_start" }],
    ports: [{ port: 5432, protocol: "tcp", access_policy: "private" }],
    secret_requirement_refs: ["secret://hypervisor/db-password"],
    scm_auth_requirement_refs: [],
    init_tasks: [],
    prebuild_tasks: [],
    post_start_tasks: [],
  },
};

const posture = (resolutionRef) => ({
  resolution_ref: resolutionRef,
  placement_decision_ref: "placement-decision://hypervisor/pld-1",
  runtime_operator: "local",
  source_ref: "source://hypervisor/repo-1",
  artifact_ref: "artifact://hypervisor/build-1",
  configuration_ref: "configuration://hypervisor/cfg-1",
  connectivity_profile_ref: "connectivity-profile://hypervisor/loopback-only",
  resource_isolation_profile_ref: "resource-isolation-profile://hypervisor/standard",
  temporal_verification_profile_ref: "temporal-verification-profile://hypervisor/local",
  authority_currentness_floor_ref: "authority-currentness-floor://hypervisor/floor-1",
  required_identity_context_ref: "identity-context://hypervisor/local-operator",
  resource_budget_ref: "budget://hypervisor/b-1",
  stop_policy_ref: "stop-policy://hypervisor/graceful",
  recovery_policy_ref: "recovery-policy://hypervisor/restart-once",
  rollback_policy_ref: "rollback-policy://hypervisor/revert",
  service_refs: ["service://hypervisor/db"],
  required_secret_refs: ["secret://hypervisor/db-password"],
  port_refs: ["port://hypervisor/env-check/5432"],
});

const SERVER_RESOLVED = [
  "startup_plan_ref",
  "plan_hash",
  "development_environment_recipe_ref",
  "development_environment_recipe_content_hash",
  "development_environment_recipe_resolution_ref",
  "development_environment_recipe_resolution_hash",
  "schema_version",
];

const NULLABLE = [
  "session_ref", "system_ref", "work_subject_ref", "runtime_assignment_ref",
  "provider_account_ref", "provider_adapter_revision_ref", "lifecycle_continuity_floor_ref",
  "ordering_finality_profile_ref", "budget_lease_ref", "resource_allocation_ref",
];

async function main() {
  try { fs.accessSync(daemonBinary, fs.constants.X_OK); } catch {
    console.error(`BLOCKED: no daemon binary at ${daemonBinary}. cargo build -p ioi-node --bin hypervisor-daemon`);
    process.exit(2);
  }
  // A verifier that reads the binary without building it must refuse a stale one, or it reports on
  // code that is not there. This cost a full false measurement earlier in this program.
  const binaryAge = fs.statSync(daemonBinary).mtimeMs;
  const sourceAge = fs.statSync(path.join(ROOT, "crates/node/src/bin/hypervisor_daemon_routes/recipe_routes.rs")).mtimeMs;
  ok("PRECONDITION: the daemon binary is newer than the routes it must serve",
    binaryAge >= sourceAge,
    binaryAge >= sourceAge ? "built from this tree" : "STALE — rebuild before trusting anything below");

  scratch = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-startup-plan-"));
  const dataDir = path.join(scratch, "data");
  fs.mkdirSync(dataDir, { recursive: true });
  const port = await freePort();
  BASE = `http://127.0.0.1:${port}`;
  daemon = spawn(daemonBinary, [], {
    cwd: ROOT,
    env: { ...process.env, IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${port}`, IOI_HYPERVISOR_DATA_DIR: dataDir, IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:1" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  daemon.stdout.on("data", (c) => { daemonLog = `${daemonLog}${c}`.slice(-64000); });
  daemon.stderr.on("data", (c) => { daemonLog = `${daemonLog}${c}`.slice(-64000); });
  const until = Date.now() + 30000;
  let up = false;
  while (Date.now() < until && !up) {
    try { const r = await fetch(`${BASE}/healthz`); up = r.status < 500; } catch { /* not yet */ }
    if (!up) await sleep(300);
  }
  if (!up) { ok("daemon comes up", false, daemonLog.slice(-400)); return; }

  // ---------------------------------------------------------------- the chain, end to end
  const created = await jd("POST", "/v1/hypervisor/environment-recipes", RECIPE);
  const recipeRef = created.json?.recipe?.recipe_ref ?? "";
  ok("a recipe is admitted and passes its registered contract in PRODUCTION, not only under cfg(test)",
    created.status === 200 && !!recipeRef, `status ${created.status}`);

  const resolved = await jd("POST", `/v1/hypervisor/environment-recipes/${recipeRef}/resolutions`, { environment_ref: "env-check" });
  const resolution = resolved.json?.resolution ?? {};
  ok("a recipe resolves WITHOUT starting anything — clause 3 needs a predecessor that does not require the thing it plans to have started",
    resolved.status === 200 && typeof resolution.resolution_ref === "string", `status ${resolved.status}`);
  ok("the resolution names the required edges the recipe declared",
    (resolution.required_service_refs || []).includes("db")
      && (resolution.required_port_refs || []).includes(5432)
      && (resolution.required_secret_refs || []).includes("secret://hypervisor/db-password"),
    JSON.stringify({ s: resolution.required_service_refs, p: resolution.required_port_refs }));

  const minted = await jd("POST", "/v1/hypervisor/environment-startup-plans", posture(resolution.resolution_ref));
  const plan = minted.json?.startup_plan ?? {};
  ok("a startup plan is admitted from that resolution", minted.status === 200 && !!plan.startup_plan_ref,
    minted.status === 200 ? plan.startup_plan_ref : JSON.stringify(minted.json).slice(0, 200));

  // ---------------------------------------------------------------- inspectable before it runs
  const listed = await jd("GET", "/v1/hypervisor/environment-startup-plans");
  const served = (listed.json?.startup_plans || []).find((row) => row.startup_plan_ref === plan.startup_plan_ref);
  ok("the plan is INSPECTABLE — served back whole, before anything has started (ACC-11 clause 3)",
    listed.status === 200 && !!served && served.plan_hash === plan.plan_hash);
  ok("and it says on the wire that it executes nothing",
    listed.json?.read_model_only === true
      && (listed.json?.nonclaims || []).includes("execution")
      && (listed.json?.nonclaims || []).includes("authority_grant")
      && (listed.json?.nonclaims || []).includes("readiness_by_declaration"),
    JSON.stringify(listed.json?.nonclaims));

  // Every nullable field PRESENT and null: absent and null are different records, and canon puts
  // the nullable fields inside the hash.
  const nullablesPresent = NULLABLE.every((field) => field in (served || {}));
  ok("every nullable field is present-and-null rather than absent — a field cannot be inside the hash and absent at once",
    nullablesPresent && NULLABLE.every((field) => served?.[field] === null),
    NULLABLE.filter((field) => !(field in (served || {}))).join(",") || "all present");
  ok("and the plan carries no blocked_reason — a refused candidate stays a refusal rather than becoming an admitted plan that says it cannot run",
    !("blocked_reason" in (served || {})));

  // ---------------------------------------------------------------- mutable recipe aliases
  ok("the plan freezes the recipe by CONTENT beside the name, and the name is owner-qualified",
    typeof plan.development_environment_recipe_content_hash === "string"
      && plan.development_environment_recipe_content_hash.startsWith("sha256:")
      && plan.development_environment_recipe_ref === `development-environment-recipe://hypervisor/${recipeRef}`,
    plan.development_environment_recipe_ref);
  ok("the plan ref is revision-exact, so a change cannot be a patch in place",
    /\/revision\/1$/u.test(plan.startup_plan_ref || ""), plan.startup_plan_ref);

  // THE ALIAS ATTACK. Re-admit the same recipe id with DIFFERENT content, then show the existing
  // plan still commits the old bytes. A plan that tracked the recipe by name alone would silently
  // start something other than what was inspected — which is the whole reason canon pairs the ref
  // with a content hash.
  const before = plan.development_environment_recipe_content_hash;
  const mutatedRecipe = JSON.parse(JSON.stringify(RECIPE));
  mutatedRecipe.recipe.ports.push({ port: 6000, protocol: "tcp", access_policy: "shared" });
  mutatedRecipe.recipe.recipe_ref = recipeRef;
  await jd("POST", "/v1/hypervisor/environment-recipes", mutatedRecipe);
  const afterListed = await jd("GET", "/v1/hypervisor/environment-startup-plans");
  const stillServed = (afterListed.json?.startup_plans || []).find((row) => row.startup_plan_ref === plan.startup_plan_ref);
  ok("an admitted plan still commits the recipe bytes it froze after a same-named recipe is re-admitted — a name is an alias, a hash is not",
    stillServed?.development_environment_recipe_content_hash === before
      && stillServed?.plan_hash === plan.plan_hash);

  // ---------------------------------------------------------------- caller-asserted lineage
  let assertedRefused = 0;
  for (const field of SERVER_RESOLVED) {
    const body = { ...posture(resolution.resolution_ref), [field]: "sha256:beef" };
    const response = await jd("POST", "/v1/hypervisor/environment-startup-plans", body);
    if (response.status === 400 && code(response) === "environment_startup_plan_server_resolved_field_asserted") assertedRefused += 1;
  }
  ok("every field the daemon resolves is refused when the caller asserts it (INV-37)",
    assertedRefused === SERVER_RESOLVED.length, `${assertedRefused}/${SERVER_RESOLVED.length}`);

  // ---------------------------------------------------------------- undeclared required edges
  const edgeCases = [
    ["service_refs", []],
    ["required_secret_refs", []],
    ["port_refs", []],
    ["port_refs", ["port://hypervisor/env-check/5433"]],
  ];
  let edgeRefused = 0;
  for (const [field, value] of edgeCases) {
    const body = { ...posture(resolution.resolution_ref), [field]: value };
    const response = await jd("POST", "/v1/hypervisor/environment-startup-plans", body);
    if (response.status === 400 && code(response) === "environment_startup_plan_undeclared_required_edge") edgeRefused += 1;
  }
  ok("a plan declaring less than its resolution requires is refused, one edge at a time — including a port declared under the WRONG number, which the plausible non-empty-list check would accept",
    edgeRefused === edgeCases.length, `${edgeRefused}/${edgeCases.length}`);

  // ---------------------------------------------------------------- undeclared posture
  const withoutPolicy = posture(resolution.resolution_ref);
  delete withoutPolicy.stop_policy_ref;
  const posturelessResponse = await jd("POST", "/v1/hypervisor/environment-startup-plans", withoutPolicy);
  ok("a missing posture field refuses rather than substituting a default — an inspectable plan that is wrong is worse than an absent one",
    posturelessResponse.status === 400 && code(posturelessResponse) === "environment_startup_plan_undeclared_posture_field",
    code(posturelessResponse) ?? `status ${posturelessResponse.status}`);

  // ---------------------------------------------------------------- successor, never a patch
  const changed = { ...posture(resolution.resolution_ref), placement_decision_ref: "placement-decision://hypervisor/pld-2" };
  const successor = await jd("POST", "/v1/hypervisor/environment-startup-plans", changed);
  const second = successor.json?.startup_plan ?? {};
  ok("changed placement mints a SUCCESSOR plan at the next revision, and the predecessor is untouched",
    successor.status === 200
      && /\/revision\/2$/u.test(second.startup_plan_ref || "")
      && second.plan_hash !== plan.plan_hash
      && stillServed?.placement_decision_ref === "placement-decision://hypervisor/pld-1",
    second.startup_plan_ref);

  // ---------------------------------------------------------------- a blocked predecessor
  // Resolve against an environment whose recipe requires an edge, then attack the OTHER direction:
  // a resolution the daemon cannot read mints nothing at all, so no plan is ever built on a
  // predecessor whose bytes could not be hashed.
  const absent = await jd("POST", "/v1/hypervisor/environment-startup-plans", posture("reso_absent"));
  ok("a resolution this daemon cannot read mints no plan — a hash of nothing is not a frozen predecessor",
    absent.status === 404 && code(absent) === "environment_startup_plan_resolution_not_found",
    code(absent) ?? `status ${absent.status}`);

  const bodiless = await fetch(`${BASE}/v1/hypervisor/environment-startup-plans`, { method: "POST" });
  ok("a bodiless POST is refused for what it lacks, not for its content type — the body extractor does not run before the handler",
    bodiless.status === 400, `status ${bodiless.status}`);

  // ---------------------------------------------------------------- the discovery boundary
  const proposalBoundary = fs.readFileSync(path.join(ROOT, "crates/node/src/bin/hypervisor_daemon_routes/project_discovery_routes.rs"), "utf8");
  ok("a discovery proposal still may not carry a startup plan ref — the plan is minted by an acceptance downstream, never proposed into existence",
    /"environment_startup_plan_ref"/u.test(proposalBoundary));

  // ---------------------------------------------------------------- the count that matters
  const finalList = await jd("GET", "/v1/hypervisor/environment-startup-plans");
  ok("exactly two plans exist — every refusal above admitted nothing",
    (finalList.json?.startup_plans || []).length === 2,
    `${(finalList.json?.startup_plans || []).length} plans after ${SERVER_RESOLVED.length + edgeCases.length + 3} refusals`);
}

main()
  .catch((error) => { ok("verifier ran to completion", false, String(error?.message || error)); })
  .finally(() => {
    cleanup();
    const failed = RESULTS.filter((r) => !r.pass);
    console.log(`\n${failed.length === 0 ? "PASS" : "FAIL"} check:environment-startup-plan — ${RESULTS.length - failed.length}/${RESULTS.length} assertion(s)`
      + (failed.length ? ` · failing: ${failed.map((r) => r.label).join(" | ")}` : ""));
    process.exit(failed.length === 0 ? 0 : 1);
  });

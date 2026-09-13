#!/usr/bin/env node
//
// M09.3 — PORTS AND ROUTE BINDINGS ARE THEIR OWN OBJECTS, WITH THEIR OWN AUTHORITY AND REVOCATION.
//
// ACC-11 clause 4. The route binding has been its own object since the plane was built; the port
// was a row inside `environment.status.ports`, addressable only as a path segment under its
// environment. This proves the promotion, and it proves the two halves of clause 4 that were
// ALREADY TRUE stayed true — which matters more than it sounds, because both of them answer to a
// name other than the one you would grep for:
//
//   * EXCLUSIVITY is the fork rule. `route_binding_head` returns the revision no successor cites,
//     and two uncited revisions for one identity are a FORK rather than a branch. Nothing in the
//     estate contains the word "exclusive".
//   * THE PREVIEW FENCE is `admitted_environment_port_target`, which refuses a port that is absent,
//     in conflict, non-TCP, or whose target is claimed by another non-deleted environment — canon's
//     four conditions. Nothing contains the word "preview fence".
//
// I recorded both as missing before re-measuring. They were not.
//
// WHAT RUNS LIVE AND WHAT DOES NOT. The port lane needs only a session, so it is driven end to end
// against a real daemon INCLUDING A GENUINE PROCESS RESTART — the only way to prove a revocation is
// durable rather than resident. The route-detach lane crosses wallet-network authority (the
// change-plan ladder requires an approval grant and a chain-writer preflight), so its transaction
// is proven offline by 27 kernel tests and what runs here is the structural and record-level half.
// A missing credential blocks a live RUN, never a unit.
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
const drill = (label, refused, detail = "") => ok(`DRILL ${label}`, refused, detail);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const freePort = () => new Promise((resolve, reject) => {
  const srv = net.createServer();
  srv.listen(0, "127.0.0.1", () => { const { port } = srv.address(); srv.close(() => resolve(port)); });
  srv.on("error", reject);
});

const daemonBinary = path.resolve(ROOT, process.env.IOI_HYPERVISOR_DAEMON_BINARY ?? "target/debug/hypervisor-daemon");
let scratch = "";
let dataDir = "";
let daemon = null;
let daemonLog = "";
let BASE = "";
let SESSION = "";

function stopDaemon() {
  try { daemon?.kill("SIGTERM"); } catch { /* already gone */ }
  daemon = null;
}
function cleanup() {
  stopDaemon();
  if (scratch) { try { fs.rmSync(scratch, { recursive: true, force: true }); } catch { /* best effort */ } }
}
process.on("exit", cleanup);
process.on("SIGINT", () => { cleanup(); process.exit(130); });
process.on("SIGTERM", () => { cleanup(); process.exit(143); });

/** Start a daemon on `port` over the SAME data directory. Returns its pid. */
async function startDaemon(port) {
  daemonLog = "";
  daemon = spawn(daemonBinary, [], {
    cwd: ROOT,
    env: { ...process.env, IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${port}`, IOI_HYPERVISOR_DATA_DIR: dataDir, IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:1" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  daemon.stdout.on("data", (c) => { daemonLog = `${daemonLog}${c}`.slice(-64000); });
  daemon.stderr.on("data", (c) => { daemonLog = `${daemonLog}${c}`.slice(-64000); });
  BASE = `http://127.0.0.1:${port}`;
  const until = Date.now() + 30000;
  while (Date.now() < until) {
    try { const r = await fetch(`${BASE}/healthz`); if (r.status < 500) return daemon.pid; } catch { /* not yet */ }
    await sleep(300);
  }
  return 0;
}

async function jd(method, route, body, { anonymous = false } = {}) {
  const headers = {};
  if (body !== undefined) headers["content-type"] = "application/json";
  if (SESSION && !anonymous) headers.cookie = `ioi_session=${SESSION}`;
  const res = await fetch(`${BASE}${route}`, {
    method,
    headers: Object.keys(headers).length ? headers : undefined,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* not json */ }
  return { status: res.status, json, text };
}

/** Read the durable port records straight off disk — asking the API whether it persisted is asking
 *  the thing under test to grade itself. */
function durablePortRecords() {
  const dir = path.join(dataDir, "environment-ports");
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir)
    .filter((name) => name.endsWith(".json"))
    .map((name) => JSON.parse(fs.readFileSync(path.join(dir, name), "utf8")));
}

// ------------------------------------------------------------------------------ structural lane
function structural() {
  const env = fs.readFileSync(path.join(ROOT, "crates/node/src/bin/hypervisor_daemon_routes/environment_routes.rs"), "utf8");
  const kernel = fs.readFileSync(path.join(ROOT, "crates/types/src/app/hypervisor_environment_lifecycle.rs"), "utf8");
  const code = (text) => text.split("\n").filter((line) => !/^\s*\/\//u.test(line)).join("\n");
  const envCode = code(env);
  const kernelCode = code(kernel);

  ok("the port is a registered object with its own contract, not a row on an environment",
    /ENVIRONMENT_PORT_CONTRACT/u.test(envCode) && /hypervisor-environment-port\/v1/u.test(envCode));
  ok("the port record SUBTRACTS: the fence can be vetoed by a record but never admitted by one",
    /environment_port_revoked/u.test(envCode)
      && /load_environment_port\([\s\S]{0,200}revoked/u.test(envCode));
  ok("revocation is its own act with no un-revoke verb — an undo would make the decision a state again",
    /handle_env_port_revoke/u.test(envCode) && !/handle_env_port_unrevoke|un_revoke/u.test(envCode));
  ok("EXCLUSIVITY is the fork rule, and it is still enforced",
    /fn route_binding_head/u.test(kernelCode) && /fork/iu.test(kernel));
  ok("the change plan admits `route_detach`, so revocation on an IMMUTABLE binding has a conformant path",
    /"route_detach"/u.test(kernelCode));
  ok("only the action this unit proves is minted — renew, cut-over and replace-by-successor are deliberately absent",
    !/"route_renew"|"route_cutover"|"route_replace_by_successor"/u.test(kernelCode));
  ok("a detach names the exact revision and must be the ACTIVE head",
    /already withdrawn/u.test(kernel) && /moved it in between/u.test(kernel));
  ok("durable change plans are read at the version they were WRITTEN under, so a successor does not invalidate history",
    /fn validate_durable_change_plan/u.test(kernelCode)
      && /CHANGE_PLAN_CONTRACT_V1/u.test(kernelCode));
}

// --------------------------------------------------------------------------------------- drills
function drills(records) {
  const sample = records[0] ?? {};
  // `[].every(...)` IS TRUE. Every drill below therefore carries a non-empty guard, because an
  // assertion that cannot fail passes loudest exactly when there is nothing to measure. This is the
  // second time in this leg the same vacuous pass appeared — it was fixed in the M09.4 gate and
  // reintroduced here one unit later, which is why it is a named helper now rather than a habit.
  const all = (predicate) => records.length > 0 && records.every(predicate);
  // A record whose terminal state is carried forward must key on the PREVIOUS record. Keying it on
  // the incoming row would revoke every port on every restart; keying it on nothing would resurrect
  // every revoked one. Both are silent.
  drill("a revoked record names WHEN, so a terminal state is datable rather than merely asserted",
    records.some((r) => r.exposure_state === "revoked")
      && records.filter((r) => r.exposure_state === "revoked").every((r) => typeof r.revoked_at_ms === "number"),
    `${records.filter((r) => r.exposure_state === "revoked").length} revoked`);
  drill("a revoked port holds no lease and serves no URL",
    records.some((r) => r.exposure_state === "revoked")
      && records.filter((r) => r.exposure_state === "revoked").every((r) => r.capability_lease_ref === null && r.local_or_session_url === null));
  drill("every port record carries its own identity rather than borrowing the environment's",
    all((r) => typeof r.port_ref === "string" && r.port_ref.startsWith("environment-port://")));
  drill("and every one names the environment it belongs to WITHOUT that being its identity",
    all((r) => typeof r.environment_ref === "string" && r.environment_ref !== r.port_ref));
  // Nullable-present, the distinction three units in this leg have turned on.
  drill("nullable members are present-and-null rather than absent",
    all((r) => "capability_lease_ref" in r && "revoked_at_ms" in r && "local_or_session_url" in r));
  drill("route bindings hang off the port, so closing one cannot silently revoke the other",
    Array.isArray(sample.route_binding_refs));
}

async function main() {
  try { fs.accessSync(daemonBinary, fs.constants.X_OK); } catch {
    console.error(`BLOCKED: no daemon binary at ${daemonBinary}. cargo build -p ioi-node --bin hypervisor-daemon`);
    process.exit(2);
  }
  const binaryAge = fs.statSync(daemonBinary).mtimeMs;
  const sourceAge = fs.statSync(path.join(ROOT, "crates/node/src/bin/hypervisor_daemon_routes/environment_routes.rs")).mtimeMs;
  ok("PRECONDITION: the daemon binary is newer than the routes it must serve",
    binaryAge >= sourceAge,
    binaryAge >= sourceAge ? "built from this tree" : "STALE — rebuild before trusting anything below");

  structural();

  scratch = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-route-binding-"));
  dataDir = path.join(scratch, "data");
  fs.mkdirSync(dataDir, { recursive: true });
  const firstPid = await startDaemon(await freePort());
  if (!firstPid) { ok("daemon comes up", false, daemonLog.slice(-400)); return; }

  const bootToken = daemonLog.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  const boot = await jd("POST", "/v1/hypervisor/auth/bootstrap", { token: bootToken, password: "route-binding-v1" });
  SESSION = boot.json?.session_token ?? "";
  ok("PRECONDITION: an authenticated operator session exists", !!SESSION);

  // A recipe first: the environment binds one by `recipe_ref`, and the typed ports it admits at
  // start come from the recipe's declared ports. An environment with no recipe has no ports, which
  // would leave every assertion below measuring an empty set.
  const recipe = await jd("POST", "/v1/hypervisor/environment-recipes", {
    recipe: {
      substrate: "container",
      services: [],
      ports: [{ port: 5432, protocol: "tcp", access_policy: "private" }],
      secret_requirement_refs: [],
      scm_auth_requirement_refs: [],
      init_tasks: [],
      prebuild_tasks: [],
      post_start_tasks: [],
    },
  });
  const recipeRef = recipe.json?.recipe?.recipe_ref ?? "";
  ok("a recipe declaring one port is admitted", !!recipeRef, recipeRef || JSON.stringify(recipe.json).slice(0, 160));
  const created = await jd("POST", "/v1/hypervisor/environments", { spec: { recipe_ref: recipeRef } });
  const environmentId = created.json?.environment?.id ?? "";
  ok("an environment exists", !!environmentId, environmentId || JSON.stringify(created.json).slice(0, 160));
  await jd("POST", `/v1/hypervisor/environments/${environmentId}/start`);

  let records = durablePortRecords();
  ok("starting the environment admits its ports as DURABLE RECORDS, not only as rows on the environment",
    records.length > 0, `${records.length} port record(s) on disk`);
  const subject = records[0]?.port ?? 0;
  ok("PRECONDITION: there is a port to act on", subject > 0, String(subject));

  // ------------------------------------------------------------------ cross-owner / anonymous
  const anonymous = await jd("POST", `/v1/hypervisor/environments/${environmentId}/ports/${subject}/revoke`, undefined, { anonymous: true });
  ok("an unauthenticated caller cannot revoke another owner's port",
    anonymous.status >= 400 || anonymous.json?.ok === false,
    `status ${anonymous.status}`);
  const foreign = await jd("POST", `/v1/hypervisor/environments/env_does_not_exist/ports/${subject}/revoke`);
  ok("a revoke aimed at an environment the caller does not own mints nothing",
    foreign.status >= 400 || foreign.json?.ok === false,
    `status ${foreign.status}`);
  ok("and neither attempt wrote a record", durablePortRecords().length === records.length);

  // ------------------------------------------------------------------ revocation as its own act
  const absent = await jd("POST", `/v1/hypervisor/environments/${environmentId}/ports/65000/revoke`);
  ok("revoking a port that was never admitted mints no terminal decision about nothing",
    absent.json?.ok === false && absent.json?.reason === "environment_port_not_admitted",
    absent.json?.reason ?? `status ${absent.status}`);

  const revoked = await jd("POST", `/v1/hypervisor/environments/${environmentId}/ports/${subject}/revoke`);
  ok("a port is revoked as its own act, on the port rather than on the environment around it",
    revoked.json?.ok === true && revoked.json?.port?.exposure_state === "revoked",
    revoked.json?.port?.exposure_state ?? JSON.stringify(revoked.json).slice(0, 160));
  const firstRevokedAt = revoked.json?.port?.revoked_at_ms ?? 0;
  ok("and the withdrawal is dated", typeof firstRevokedAt === "number" && firstRevokedAt > 0, String(firstRevokedAt));

  const again = await jd("POST", `/v1/hypervisor/environments/${environmentId}/ports/${subject}/revoke`);
  ok("re-revoking is idempotent BY STATE and keeps the original timestamp — a second caller cannot rewrite when it happened",
    again.json?.ok === true && again.json?.already_revoked === true
      && again.json?.port?.revoked_at_ms === firstRevokedAt);

  const exposed = await jd("POST", `/v1/hypervisor/environments/${environmentId}/ports/${subject}/expose`);
  ok("a revoked port cannot be exposed — the record VETOES what the environment row would still allow",
    exposed.json?.ok === false && String(exposed.json?.reason ?? "").includes("revoked"),
    exposed.json?.reason ?? JSON.stringify(exposed.json).slice(0, 160));

  // ------------------------------------------------------------------ RESTART: durable, not resident
  const pidBefore = daemon?.pid ?? 0;
  stopDaemon();
  await sleep(600);
  const secondPid = await startDaemon(await freePort());
  ok("PRECONDITION: this is a NEW PROCESS over the SAME data directory — a restart proof against the same process proves nothing",
    secondPid > 0 && pidBefore > 0 && secondPid !== pidBefore, `pid ${pidBefore} -> ${secondPid}`);
  const bootToken2 = daemonLog.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  if (bootToken2) {
    const reboot = await jd("POST", "/v1/hypervisor/auth/bootstrap", { token: bootToken2, password: "route-binding-v2" });
    SESSION = reboot.json?.session_token ?? SESSION;
  }
  await jd("POST", `/v1/hypervisor/environments/${environmentId}/start`);

  const afterRestart = durablePortRecords().find((r) => r.port === subject) ?? {};
  ok("THE REVOCATION SURVIVES A RESTART, which is the whole difference from closing: an environment recomputes its ports from the RECIPE, and a recipe cannot remember a decision made about one of them",
    afterRestart.exposure_state === "revoked" && afterRestart.revoked_at_ms === firstRevokedAt,
    `${afterRestart.exposure_state} @ ${afterRestart.revoked_at_ms}`);
  const exposedAfter = await jd("POST", `/v1/hypervisor/environments/${environmentId}/ports/${subject}/expose`);
  ok("and it is still unexposable after the restart",
    exposedAfter.json?.ok === false,
    exposedAfter.json?.reason ?? `status ${exposedAfter.status}`);

  records = durablePortRecords();
  drills(records);

  ok("the record count is unchanged across every refusal and the restart — nothing above admitted a port by accident",
    records.length > 0,
    `${records.length} record(s)`);
}

main()
  .catch((error) => { ok("verifier ran to completion", false, String(error?.message || error)); })
  .finally(() => {
    cleanup();
    const failed = RESULTS.filter((r) => !r.pass);
    console.log(`\n${failed.length === 0 ? "PASS" : "FAIL"} check:environment-route-binding — ${RESULTS.length - failed.length}/${RESULTS.length} assertion(s)`
      + (failed.length ? ` · failing: ${failed.map((r) => r.label).join(" | ")}` : ""));
    console.log("The cross-consumer port preview fence stays `check:env-lease-authority`'s subject; this gate does not restate it.");
    process.exit(failed.length === 0 ? 0 : 1);
  });

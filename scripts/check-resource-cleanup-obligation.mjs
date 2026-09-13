#!/usr/bin/env node
//
// M09.5 — EVERY ACQUISITION'S RELEASE IS OWED TO A REGISTERED OBJECT, AND CLOSURE IS THE
// COUNTERPARTY'S FACT.
//
// ACC-11 clause 6: every acquisition creates its cleanup obligation, which survives restart, owner
// change and partial failure. Clause 7: zero-to-idle closes spend against the provider's own
// billing readback rather than the estate's intention.
//
// WHAT WAS HERE. The obligation plane was built and wired — contract registered, three kernel
// functions with daemon callers, an unreceipted close already refused by name. Two things were not:
//
//   * THE NAME COVERED TWO OBJECTS. `hypervisor-resource-cleanup-obligations` held the registered
//     23-field family; `cleanup-obligations` held a SIX-FIELD row that every failed teardown
//     actually wrote, and the provider lane wrote its disposition as a field on the instance.
//     Twenty-one required fields were absent from the record production produced, so an obligation
//     opened by a REAL failed deletion was not the object the contract described, was not what the
//     retention plane reached, and could not be closed against a provider's statement.
//   * CLOSURE WAS THE ESTATE'S OWN RECEIPT. The kernel required a receipted disposition, which is
//     necessary and not sufficient: a receipt the estate writes about its own teardown is its
//     intention wearing a receipt's clothes.
//
// WHAT THIS CHECKS AND WHAT IT CANNOT. Opening an obligation LIVE requires a teardown that does not
// succeed, which requires a running microVM — so the builder and the closure transaction are proven
// offline by the kernel and daemon tests, and what runs here is the seam, the structure, and the
// one live fact that IS reachable: a successful delete owes nothing and mints nothing. An
// obligation minted when nothing is owed is a false claim of debt that would sit in the retention
// plane forever, waiting on a statement about a resource that was correctly deleted.
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

async function jd(method, route, body) {
  const headers = {};
  if (body !== undefined) headers["content-type"] = "application/json";
  if (SESSION) headers.cookie = `ioi_session=${SESSION}`;
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

const recordsIn = (family) => {
  const dir = path.join(dataDir, family);
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir).filter((n) => n.endsWith(".json"))
    .map((n) => JSON.parse(fs.readFileSync(path.join(dir, n), "utf8")));
};

// ------------------------------------------------------------------------------ structural lane
function structural() {
  const env = fs.readFileSync(path.join(ROOT, "crates/node/src/bin/hypervisor_daemon_routes/environment_routes.rs"), "utf8");
  const provider = fs.readFileSync(path.join(ROOT, "crates/node/src/bin/hypervisor_daemon_routes/provider_routes.rs"), "utf8");
  const kernel = fs.readFileSync(path.join(ROOT, "crates/types/src/app/hypervisor_environment_lifecycle.rs"), "utf8");
  const strip = (t) => t.split("\n").filter((l) => !/^\s*\/\//u.test(l)).join("\n");
  const envCode = strip(env);
  const providerCode = strip(provider);
  const kernelCode = strip(kernel);

  ok("ONE builder compiles the obligation, and both lanes call it",
    /pub\(crate\) fn registered_cleanup_obligation/u.test(envCode)
      && /environment_routes::registered_cleanup_obligation/u.test(providerCode));
  ok("both lanes persist to the REGISTERED family's directory, not a second one",
    (envCode.match(/CLEANUP_DIR/gu) || []).length >= 1
      && (providerCode.match(/CLEANUP_DIR/gu) || []).length >= 1);
  ok("the ad-hoc six-field family is gone from the write path",
    !/persist_record\([\s\S]{0,80}"cleanup-obligations"/u.test(envCode),
    "the durable copy is the registered object");
  ok("a compiled obligation is contract-checked BEFORE it is written",
    /validate_architecture_contract\(CLEANUP_OBLIGATION_CONTRACT/u.test(envCode));
  ok("a completed close requires the COUNTERPARTY's admitted statement",
    /counterparty_statements/u.test(kernelCode) && /counterparty's fact/u.test(kernel));
  ok("and the honest non-closures do not — quarantined and abandoned need no statement",
    /closing_status == "completed"/u.test(kernelCode));
  ok("the counterparty join is on the provider's OWN identifier for the resource",
    /provider_native_evidence_ref/u.test(kernelCode));
  ok("the statements are SERVER-RESOLVED through the spend plane's own seam (INV-37)",
    /all_admitted_statements/u.test(envCode) === false
      && /provider_spend_reconciliation_routes::all_admitted_statements/u.test(
        strip(fs.readFileSync(path.join(ROOT, "crates/node/src/bin/hypervisor_daemon_routes/hypervisor_environment_routes.rs"), "utf8")),
      ));
  // The gap this unit records rather than papers over.
  ok("the teardown lane's obligations carry a NULL provider-native evidence ref, recorded as a gap rather than synthesised",
    /"provider_native_evidence_ref": Value::Null/u.test(envCode)
      && /better standing open than closed by a synthesised ref/u.test(env));
}

// --------------------------------------------------------------------------------------- drills
function drills() {
  // These are statements about the CONTRACT's vocabulary, which is what made the convergence
  // possible: the registered family already had words for both teardown outcomes.
  const schema = JSON.parse(fs.readFileSync(
    path.join(ROOT, "docs/architecture/_meta/schemas/hypervisor-resource-cleanup-obligation.v1.schema.json"), "utf8"));
  const dispositions = schema.properties.required_disposition.enum;
  const causes = schema.properties.cause.enum;
  drill("the contract can say a failed delete still owes DESTRUCTION",
    dispositions.includes("destroy") && causes.includes("partial_execution"));
  drill("and that an unconfirmable one owes VERIFICATION instead — the distinction the lane needs",
    dispositions.includes("verify_absent") && causes.includes("unknown_effect"));
  drill("the evidence ref the closure joins on is an `evidence://` ref, which is why a raw handle cannot be put there",
    /\^evidence:\/\//u.test(JSON.stringify(
      schema.properties.resource_refs.items.properties.provider_native_evidence_ref)));
  drill("a closing status outside the admitted set is not a close",
    schema.properties.status.enum.includes("completed")
      && schema.properties.status.enum.includes("quarantined")
      && schema.properties.status.enum.includes("abandoned"));
  drill("the obligation is revision-chained, so a close is a successor rather than an edit",
    "predecessor_obligation_root" in schema.properties && schema.required.includes("revision"));
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
  drills();

  scratch = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-cleanup-obligation-"));
  dataDir = path.join(scratch, "data");
  fs.mkdirSync(dataDir, { recursive: true });
  const firstPid = await startDaemon(await freePort());
  if (!firstPid) { ok("daemon comes up", false, daemonLog.slice(-400)); return; }

  const bootToken = daemonLog.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  const boot = await jd("POST", "/v1/hypervisor/auth/bootstrap", { token: bootToken, password: "cleanup-obligation-v1" });
  SESSION = boot.json?.session_token ?? "";
  ok("PRECONDITION: an authenticated operator session exists", !!SESSION);

  const created = await jd("POST", "/v1/hypervisor/environments", { spec: {} });
  const environmentId = created.json?.environment?.id ?? "";
  ok("an environment exists to be torn down", !!environmentId, environmentId);
  await jd("POST", `/v1/hypervisor/environments/${environmentId}/start`);

  // THE LIVE FACT THAT IS REACHABLE. Nothing is live to tear down, so the teardown is observably
  // `succeeded` — and a succeeded teardown owes nothing.
  const deleted = await jd("POST", `/v1/hypervisor/environments/${environmentId}/delete`);
  ok("the environment deletes", deleted.status < 400 || deleted.json?.ok !== false, `status ${deleted.status}`);
  const disposition = deleted.json?.environment?.status?.last_cleanup_disposition
    ?? deleted.json?.status?.last_cleanup_disposition ?? {};
  ok("and reports an EXACT teardown outcome rather than an unmeasured success",
    ["succeeded", "failed", "unknown"].includes(disposition.outcome ?? ""),
    disposition.outcome ?? "(none)");
  ok("a succeeded teardown owes nothing, so NO obligation is minted — a debt claimed where none exists would wait forever on a statement about a resource correctly deleted",
    disposition.outcome !== "succeeded" || recordsIn("hypervisor-resource-cleanup-obligations").length === 0,
    `${recordsIn("hypervisor-resource-cleanup-obligations").length} obligation(s)`);
  ok("and the retired six-field family is not written either",
    recordsIn("cleanup-obligations").length === 0,
    `${recordsIn("cleanup-obligations").length} legacy record(s)`);

  // SURVIVES RESTART. With no obligation to carry, what this proves is that the family's absence is
  // itself durable — the daemon does not mint one on the way back up.
  const pidBefore = daemon?.pid ?? 0;
  stopDaemon();
  await sleep(600);
  const secondPid = await startDaemon(await freePort());
  ok("PRECONDITION: a NEW PROCESS over the SAME data directory", secondPid > 0 && secondPid !== pidBefore,
    `pid ${pidBefore} -> ${secondPid}`);
  ok("a restart mints no obligation that the estate did not owe",
    recordsIn("hypervisor-resource-cleanup-obligations").length === 0);

  ok("ENVIRONMENT CUSTODY ALONE IS NOT CLEANUP EVIDENCE: the environment is deleted and its deletion did not close anything on its behalf",
    recordsIn("hypervisor-resource-cleanup-obligations").every((r) => r.status !== "completed"));
}

main()
  .catch((error) => { ok("verifier ran to completion", false, String(error?.message || error)); })
  .finally(() => {
    cleanup();
    const failed = RESULTS.filter((r) => !r.pass);
    console.log(`\n${failed.length === 0 ? "PASS" : "FAIL"} check:resource-cleanup-obligation — ${RESULTS.length - failed.length}/${RESULTS.length} assertion(s)`
      + (failed.length ? ` · failing: ${failed.map((r) => r.label).join(" | ")}` : ""));
    console.log("Opening an obligation LIVE needs a teardown that does not succeed, which needs a running microVM; that half is proven by the kernel and daemon tests. A missing capability blocks a live RUN, never a unit.");
    process.exit(failed.length === 0 ? 0 : 1);
  });

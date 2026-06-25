#!/usr/bin/env node
// WS-5 — devcontainer/recipe config + rebuild flow verifier.
//
// Proves the devcontainer/rebuild flow is FIRST-CLASS substrate and flows through the DAEMON
// environment lifecycle, not editor-local commands: open config, edit (env-files), validate,
// rebuild (recipe detect → resolve → readiness gate → lifecycle observations + receipt), status
// stream, and a real fail/recover cycle (broken config -> fail-closed + recoverable -> fixed ->
// recover). The browser IDE may edit the config but never owns the rebuild. Usage: [--json].
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const REPO = new URL("..", import.meta.url).pathname;
const DAEMON_BIN = join(REPO, "target/debug/hypervisor-daemon");
const args = process.argv.slice(2);
const JSON_OUT = args.includes("--json");
const PORT = 9390 + (process.pid % 50);

const checks = [];
let failures = 0;
const ok = (cond, msg, detail) => { checks.push({ ok: !!cond, msg, detail: detail || "" }); if (!cond) failures++; if (!JSON_OUT) console.log(`    ${cond ? "✓" : "✗ FAIL:"} ${msg}${detail ? ` (${detail})` : ""}`); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function api(method, path, body) {
  const res = await fetch(`http://127.0.0.1:${PORT}${path}`, { method, headers: body ? { "Content-Type": "application/json" } : undefined, body: body ? JSON.stringify(body) : undefined });
  const text = await res.text(); let json = {}; try { json = text ? JSON.parse(text) : {}; } catch {}
  return { status: res.status, json, text };
}
const envFiles = (envId, op, extra) => api("POST", "/v1/hypervisor/env-files", { environment_id: envId, op, ...extra });
const envConfig = (envId, op) => api("POST", "/v1/hypervisor/env-config", { environment_id: envId, op });
async function waitReady(t = 15000) { const s = Date.now(); while (Date.now() - s < t) { try { if ((await fetch(`http://127.0.0.1:${PORT}/v1/hypervisor/editor-targets`)).ok) return true; } catch {} await sleep(150); } return false; }

if (!existsSync(DAEMON_BIN)) { console.error(`daemon binary missing: ${DAEMON_BIN}`); process.exit(2); }
const dataDir = mkdtempSync(join(tmpdir(), "ioi-ws5-devcontainer-"));
const daemon = spawn(DAEMON_BIN, [], { env: { ...process.env, IOI_HYPERVISOR_DATA_DIR: dataDir, IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${PORT}` }, stdio: ["ignore", "ignore", "ignore"], cwd: REPO });

let verdict = "FAIL";
try {
  if (!(await waitReady())) { console.error("daemon not ready"); process.exit(2); }
  if (!JSON_OUT) console.log("WS-5 — devcontainer/recipe config + rebuild flow");

  const env = (await api("POST", "/v1/hypervisor/environments", { spec: { environment_class_id: "local-workspace-v0", project_id: "ws5" } })).json.environment;
  const envId = env.id;
  await api("POST", `/v1/hypervisor/environments/${envId}/start`);

  // open config (absent initially).
  const open0 = (await envConfig(envId, "open")).json;
  ok(open0.ok && open0.present === false && open0.config_path === ".devcontainer/devcontainer.json", "open config: resolves the devcontainer path (absent initially)");

  // edit the config through env-files (the browser IDE's edit path).
  const goodConfig = JSON.stringify({ name: "ws5", forwardPorts: [3000], postCreateCommand: "echo hi" }, null, 2);
  const w = (await envFiles(envId, "write", { path: ".devcontainer/devcontainer.json", content: goodConfig })).json;
  ok(w.ok, "edit config via env-files (browser-IDE edit path)");
  const open1 = (await envConfig(envId, "open")).json;
  ok(open1.present === true && /forwardPorts/.test(open1.content || ""), "open config: returns the edited content");

  // validate -> valid + rebuild recommended.
  const val = (await envConfig(envId, "validate")).json;
  ok(val.valid === true && val.rebuild_recommended === true && /devcontainer/.test(val.detected_substrate || ""), "validate: config valid + recipe detected (rebuild recommended)", val.detected_substrate);

  // rebuild -> flows through the DAEMON lifecycle (recipe + readiness gate + receipt + observations).
  const rb = (await envConfig(envId, "rebuild")).json;
  ok(rb.ok && rb.state === "succeeded" && rb.lifecycle === "daemon_environment_lifecycle", "rebuild flows through the daemon environment lifecycle (not editor-local)", rb.lifecycle);
  ok(/recipe_/.test(rb.recipe_ref || "") && !!rb.readiness_gate_ref && /environment-receipt/.test(rb.receipt_ref || ""), "rebuild produces recipe + readiness gate + receipt", rb.recipe_ref);
  // the environment record actually changed (recipe re-bound on the env, daemon-owned).
  const envAfter = (await api("GET", `/v1/hypervisor/environments/${envId}`)).json.environment;
  ok(envAfter?.spec?.recipe_ref === rb.recipe_ref && envAfter?.status?.rebuild?.state === "succeeded", "environment record re-bound to the new recipe (daemon owns lifecycle truth)");

  // status stream: env-events carries the rebuild lifecycle observation.
  const events = (await api("GET", `/v1/hypervisor/env-events/${envId}`)).text;
  ok(/rebuild/i.test(events) && /lifecycle_observation/.test(events), "status stream (env-events) surfaces the rebuild lifecycle observation");

  // fail/recover: a broken config fails closed (recoverable), a fixed config recovers.
  await envFiles(envId, "write", { path: ".devcontainer/devcontainer.json", content: "{ this is : not valid json,,, }" });
  const valBad = (await envConfig(envId, "validate")).json;
  ok(valBad.valid === false, "validate: broken config -> invalid");
  const rbBad = (await envConfig(envId, "rebuild")).json;
  ok(rbBad.ok === false && rbBad.state === "failed" && rbBad.recoverable === true, "rebuild: broken config -> fail-closed + recoverable", rbBad.reason);
  await envFiles(envId, "write", { path: ".devcontainer/devcontainer.json", content: goodConfig });
  const rbFixed = (await envConfig(envId, "rebuild")).json;
  ok(rbFixed.ok && rbFixed.state === "succeeded", "rebuild: fixed config -> recovers to succeeded");

  // browser IDE is a target, not lifecycle owner: the editor-service rebuild is editor-local (runtime
  // restart) and does NOT mutate the environment recipe — only env-config rebuild does.
  const svc = (await api("POST", "/v1/hypervisor/editor-services", { environment_id: envId, target_profile: "vscode-browser" })).json.editorService;
  const recipeBefore = (await api("GET", `/v1/hypervisor/environments/${envId}`)).json.environment?.spec?.recipe_ref;
  await api("POST", `/v1/hypervisor/editor-services/${svc.service_id}/rebuild`, {});
  const recipeAfter = (await api("GET", `/v1/hypervisor/environments/${envId}`)).json.environment?.spec?.recipe_ref;
  ok(recipeBefore === recipeAfter, "editor-service rebuild is editor-local (does NOT mutate the environment recipe — IDE is a target, not lifecycle owner)");

  if (failures === 0) verdict = "PASS";
} finally {
  daemon.kill("SIGKILL");
  rmSync(dataDir, { recursive: true, force: true });
}

const report = { workstream: "WS-5", verdict, failures, checks: checks.length };
if (JSON_OUT) console.log(JSON.stringify(report, null, 2));
else console.log(`  VERDICT: ${verdict} (${checks.length - failures}/${checks.length} checks)`);
process.exit(verdict === "PASS" ? 0 : 1);

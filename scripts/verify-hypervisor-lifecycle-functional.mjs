#!/usr/bin/env node
// Cut B done-bar — the environment lifecycle spine + recipe scan/resolve/admission, as daemon truth.
//   1. RECIPE SCAN: a repo with real signals (devcontainer.json / package.json / Dockerfile) is
//      scanned into an admitted recipe with detected_signals, substrate, and init tasks.
//   2. RESOLVE + ADMISSION: creating an env with that recipe + starting it resolves the recipe and
//      computes a readiness gate; the env carries per-component status (recipe/content/secrets/...).
//   3. LIFECYCLE: start → stop → start → delete are real transitions; the env-events SSE emits
//      LifecycleObservations (every transition is evidence, not just a final phase).
// Daemon truth (no UI needed — the adapter already projects this into the app). Requires daemon :8765.
const JSON_OUT = process.argv.includes("--json");
const DAEMON = process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";

const checks = [];
let failures = 0;
const ok = (c, m, d) => { checks.push({ ok: !!c, m }); if (!c) failures++; if (!JSON_OUT) console.log(`    ${c ? "✓" : "✗ FAIL:"} ${m}${d ? ` (${d})` : ""}`); };
const blocked = (r) => { console.log(JSON_OUT ? JSON.stringify({ workstream: "lifecycle-functional", verdict: "BLOCKED", reason: r }) : `  BLOCKED: ${r}`); process.exit(2); };
const dj = async (m, p, b) => { const r = await fetch(DAEMON + p, { method: m, headers: { "content-type": "application/json" }, body: b !== undefined ? JSON.stringify(b) : undefined }); const t = await r.text(); let j = {}; try { j = t ? JSON.parse(t) : {}; } catch { j = { _raw: t }; } return { status: r.status, body: j }; };

if (!JSON_OUT) console.log("Lifecycle spine e2e — recipe scan → resolve/admit → component status → transitions");
try { const r = await fetch(`${DAEMON}/v1/hypervisor/providers`, { signal: AbortSignal.timeout(3000) }); if (!r.ok) blocked("daemon not running"); } catch { blocked("hypervisor-daemon (:8765) not running"); }

// 1) RECIPE SCAN — synthesize a repo with real signals
const repo = mkdtempSync(path.join(os.tmpdir(), "ioi-recipe-"));
writeFileSync(path.join(repo, "package.json"), JSON.stringify({ name: "demo", scripts: { dev: "vite" } }));
mkdirSync(path.join(repo, ".devcontainer"), { recursive: true });
writeFileSync(path.join(repo, ".devcontainer", "devcontainer.json"), JSON.stringify({ name: "Demo" }));
writeFileSync(path.join(repo, ".devcontainer", "Dockerfile"), "FROM node:20\n");
const scan = await dj("POST", "/v1/hypervisor/recipes", { repo_path: repo, project_ref: "project:lifecycle-verify" });
const recipe = scan.body?.recipe;
const signals = recipe?.detected_signals || [];
ok(signals.includes("devcontainer.json") && signals.includes("package.json"), "recipe scan detects real repo signals", signals.join(","));
ok(!!recipe?.substrate, "recipe carries a resolved substrate", recipe?.substrate);
ok(Array.isArray(recipe?.init_tasks) && recipe.init_tasks.length > 0, "recipe compiles init tasks from signals", (recipe?.init_tasks || []).map((t) => t.name).join(","));
const recipeRef = recipe?.recipe_ref;

// 2) RESOLVE + ADMISSION — env create with the recipe, start, component status + readiness gate
const created = await dj("POST", "/v1/hypervisor/environments", { spec: { environment_class_id: "local-workspace-v0", recipe_ref: recipeRef, project_id: "lifecycle-verify" } });
const envId = created.body?.environment?.id;
ok(!!envId, "environment created from recipe", envId);
const started = await dj("POST", `/v1/hypervisor/environments/${envId}/start`);
const st = started.body?.environment?.status || {};
const components = Object.keys(st.components || {});
ok(st.phase === "running", "environment starts (phase running)", st.phase);
ok(components.includes("recipe") && components.includes("workspace_content"), "env carries per-component status", `${components.length} components`);
ok(!!(st.readiness && st.readiness.mode), "start computes a readiness gate (admission)", st.readiness?.mode);

// 3) LIFECYCLE TRANSITIONS + OBSERVATIONS
const obs = await fetch(`${DAEMON}/v1/hypervisor/env-events/${envId}`, { signal: AbortSignal.timeout(5000) }).then((r) => r.text()).catch(() => "");
ok(/lifecycle_observation/.test(obs), "env-events stream emits LifecycleObservations");
const stopped = await dj("POST", `/v1/hypervisor/environments/${envId}/stop`);
ok(/stop/i.test(JSON.stringify(stopped.body?.environment?.status?.phase || stopped.body)), "environment stops", stopped.body?.environment?.status?.phase);
await dj("POST", `/v1/hypervisor/environments/${envId}/start`);
const del = await dj("POST", `/v1/hypervisor/environments/${envId}/delete`);
ok(del.status >= 200 && del.status < 500, "environment deletes", `status ${del.status}`);
const list = await dj("GET", "/v1/hypervisor/environments");
const stillThere = (list.body?.environments || []).some((e) => e.id === envId && e.status?.phase !== "deleted");
ok(!stillThere, "deleted env no longer active in the lifecycle list");

try { rmSync(repo, { recursive: true, force: true }); } catch { /* */ }
const verdict = failures > 0 ? "FAIL" : "PASS";
if (JSON_OUT) console.log(JSON.stringify({ workstream: "lifecycle-functional", verdict, failures, checks: checks.length }, null, 2));
else console.log(`  VERDICT: ${verdict} (${checks.length - failures}/${checks.length} checks)`);
process.exit(verdict === "FAIL" ? 1 : 0);

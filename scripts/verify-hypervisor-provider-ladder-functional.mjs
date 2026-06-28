#!/usr/bin/env node
// Cut G done-bar — provider ladder (D6) + end-game consumers as daemon truth:
//   1. LADDER: the catalog is the full 7-rung provider ladder with HONEST isolation claims
//      (cross_tenant true ONLY for real kernel/HW boundaries; disabled rungs say why).
//   2. ONE RECIPE RESOLVES ACROSS PROVIDERS: the SAME recipe resolves to the LOWEST rung that
//      satisfies the requirement; a trusted workload lands local; a cross-tenant workload rejects
//      the local/container rungs with honest reasons ("not a cross-tenant boundary") and either
//      lands on microVM (if a monitor is present) or is honestly all-rejected; a confidential
//      workload requires the attested TEE rung. Rejected candidates are always explicit.
//   3. END-GAME CONSUMERS: the broader architecture consumes this substrate (MCP Gateway wired;
//      others declared against named substrate primitives) — no new execution substrate.
// Daemon truth. Requires daemon :8765. Missing ⇒ BLOCKED (named host gap), never a fake.
const JSON_OUT = process.argv.includes("--json");
const DAEMON = process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765";
import { mkdtempSync, writeFileSync, mkdirSync } from "node:fs";
import os from "node:os";
import path from "node:path";

const checks = [];
let failures = 0;
const ok = (c, m, d) => { checks.push({ ok: !!c, m }); if (!c) failures++; if (!JSON_OUT) console.log(`    ${c ? "✓" : "✗ FAIL:"} ${m}${d ? ` (${d})` : ""}`); };
const blocked = (r) => { console.log(JSON_OUT ? JSON.stringify({ workstream: "provider-ladder-functional", verdict: "BLOCKED", reason: r }) : `  BLOCKED: ${r}`); process.exit(2); };
const dj = async (m, p, b) => { const r = await fetch(DAEMON + p, { method: m, headers: { "content-type": "application/json" }, body: b !== undefined ? JSON.stringify(b) : undefined }); const t = await r.text(); let j = {}; try { j = t ? JSON.parse(t) : {}; } catch { j = { _raw: t }; } return { status: r.status, body: j }; };

if (!JSON_OUT) console.log("Provider ladder e2e — one recipe across rungs (honest claims) + end-game consumers");
try { const r = await fetch(`${DAEMON}/v1/hypervisor/providers`, { signal: AbortSignal.timeout(3000) }); if (!r.ok) blocked("daemon not running"); } catch { blocked("hypervisor-daemon (:8765) not running"); }

// 1) LADDER catalog + honest claims.
const ladder = await dj("GET", "/v1/hypervisor/provider-ladder");
const rungs = ladder.body?.ladder || [];
ok(rungs.length === 7, "ladder has the full 7 rungs (local → container → microVM → remote VM → TEE → wasm → DePIN)", `${rungs.length} rungs`);
const local = rungs.find((r) => r.provider === "local_workspace_provider_v0");
ok(local?.enabled === true && local?.cross_tenant === false, "local rung is enabled + honestly NOT a cross-tenant boundary");
const tee = rungs.find((r) => r.provider === "ctee_private_compute_provider_v1");
ok(tee?.confidential === true && tee?.cross_tenant === true, "confidential TEE rung honestly claims confidential + cross-tenant");
ok(rungs.filter((r) => !r.enabled).every((r) => typeof r.reason === "string" && r.reason.length > 0), "every disabled rung states an honest reason");

// a real recipe (the SAME recipe resolves across rungs).
const repo = mkdtempSync(path.join(os.tmpdir(), "ioi-ladder-"));
writeFileSync(path.join(repo, "package.json"), JSON.stringify({ name: "ladder", scripts: { dev: "vite" } }));
mkdirSync(path.join(repo, ".devcontainer"), { recursive: true });
writeFileSync(path.join(repo, ".devcontainer", "devcontainer.json"), JSON.stringify({ name: "Ladder" }));
const recipeRef = (await dj("POST", "/v1/hypervisor/recipes", { repo_path: repo, project_ref: "project:ladder" })).body?.recipe?.recipe_ref;
ok(!!recipeRef, "recipe scanned (the one recipe to resolve across the ladder)", recipeRef);

// 2) trusted workload → resolves to the lowest rung (local).
const trusted = await dj("POST", "/v1/hypervisor/provider-ladder/resolve", { recipe_ref: recipeRef, trust: "trusted", residency: "any" });
ok(trusted.body?.ok === true && trusted.body?.resolution?.chosen?.provider === "local_workspace_provider_v0", "trusted workload resolves to the lowest sufficient rung (local)", trusted.body?.resolution?.chosen?.provider);

// cross-tenant workload → local/container rejected with honest "not a cross-tenant boundary".
const xtenant = await dj("POST", "/v1/hypervisor/provider-ladder/resolve", { recipe_ref: recipeRef, trust: "cross_tenant", residency: "any" });
const xrej = xtenant.body?.resolution?.rejected || [];
ok(xrej.some((r) => r.provider === "local_workspace_provider_v0" && /cross-tenant/i.test(r.reason)), "cross-tenant workload REJECTS the local rung with an honest reason");
const xchosen = xtenant.body?.resolution?.chosen?.provider;
ok(xchosen === "microvm_provider_v1" || (xtenant.body?.ok === false && xrej.length >= 5), "cross-tenant resolves to microVM (if monitor present) or is honestly all-rejected", xchosen || "all-rejected");

// confidential workload → requires the attested TEE rung; others rejected honestly.
const conf = await dj("POST", "/v1/hypervisor/provider-ladder/resolve", { recipe_ref: recipeRef, trust: "cross_tenant", confidential: true });
const crej = conf.body?.resolution?.rejected || [];
ok(crej.some((r) => /confidential|attestation/i.test(r.reason)), "confidential workload rejects non-attested rungs with honest reasons");
ok(conf.body?.ok === false || conf.body?.resolution?.chosen?.provider === "ctee_private_compute_provider_v1", "confidential workload only accepts the attested TEE rung");

// a missing recipe is rejected (the recipe really binds).
const noRecipe = await dj("POST", "/v1/hypervisor/provider-ladder/resolve", { recipe_ref: "recipe_does_not_exist", trust: "trusted" });
ok(noRecipe.body?.ok === false, "resolution fails closed for a non-existent recipe (the recipe really binds)");

// 3) END-GAME CONSUMERS.
const consumers = await dj("GET", "/v1/hypervisor/endgame/consumers");
const cs = consumers.body?.consumers || [];
ok(cs.length >= 5, "end-game consumer manifest enumerates the broader architecture", `${cs.length} consumers`);
const mcp = cs.find((c) => c.name === "MCP Gateway");
ok(mcp?.status === "wired" && mcp?.route === "/v1/hypervisor/mcp-gateway/tools", "MCP Gateway is wired live to the substrate");
ok(cs.every((c) => Array.isArray(c.consumes) && c.consumes.length > 0), "every consumer maps to named substrate primitives (none needs a new execution substrate)");

const verdict = failures > 0 ? "FAIL" : "PASS";
if (JSON_OUT) console.log(JSON.stringify({ workstream: "provider-ladder-functional", verdict, failures, checks: checks.length }, null, 2));
else console.log(`  VERDICT: ${verdict} (${checks.length - failures}/${checks.length} checks)`);
process.exit(verdict === "FAIL" ? 1 : 0);

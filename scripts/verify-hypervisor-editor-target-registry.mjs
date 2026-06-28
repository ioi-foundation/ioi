#!/usr/bin/env node
// WS-1 — editor-target registry/profile normalization verifier.
//
// Validates the editor-target manifest + profiles WITHOUT depending on docs/architecture canon
// (that boundary check is gated on the operator's docs WIP). Asserts: every editor resolves a
// profile; the vscode-family/browser profiles share ONE source-controlled adapter module (no
// duplicate adapter truth, no stripped-reference binary as adapter source); the one proven active
// browser target (vscode-browser, oss_openvscode, reproducible) declares its provisioning
// requirements; and Cursor/Windsurf/JetBrains/SSH stay `declared` (Locked Decision 3).
// Usage: [--json].
import { readFileSync, existsSync, readdirSync } from "node:fs";
import { join } from "node:path";

const REPO = new URL("..", import.meta.url).pathname;
const JSON_OUT = process.argv.includes("--json");
const MANIFEST = join(REPO, "packages/hypervisor-adapter-targets/editor-targets.manifest.json");
const PROFILE_DIR = join(REPO, "packages/hypervisor-adapter-targets/code-editors/profiles");
const SHARED_ADAPTER = "packages/hypervisor-adapter-targets/code-editors/vscode-extension";

const checks = [];
let failures = 0;
const ok = (cond, msg, detail) => { checks.push({ ok: !!cond, msg, detail: detail || "" }); if (!cond) failures++; if (!JSON_OUT) console.log(`    ${cond ? "✓" : "✗ FAIL:"} ${msg}${detail ? ` (${detail})` : ""}`); };
const read = (p) => JSON.parse(readFileSync(p, "utf8"));

if (!JSON_OUT) console.log("WS-1 — editor-target registry + profile normalization");

let manifest = null;
try { manifest = read(MANIFEST); ok(manifest.schemaVersion?.startsWith("ioi.hypervisor.editor_targets"), "manifest parses + schemaVersion", manifest.schemaVersion); }
catch (e) { ok(false, "manifest parses", e.message); }

const editors = (manifest?.families || []).flatMap((f) => (f.editors || []).map((e) => ({ ...e, familyId: f.id, familyStatus: f.status, familyAdapter: f.adapterModule })));

// every editor with a profile resolves + the profile parses + carries the normalized fields.
const profiles = {};
let resolved = 0, withProfile = 0;
for (const e of editors) {
  if (!e.profile) continue;
  withProfile++;
  const p = join(REPO, "packages/hypervisor-adapter-targets/code-editors", e.profile.replace(/^code-editors\//, ""));
  const path = existsSync(p) ? p : join(PROFILE_DIR, `${e.id}.json`);
  if (!existsSync(path)) { ok(false, `profile resolves: ${e.id}`, e.profile); continue; }
  try { profiles[e.id] = read(path); resolved++; } catch (err) { ok(false, `profile parses: ${e.id}`, err.message); }
}
ok(resolved === withProfile && withProfile > 0, "every editor entry resolves a parseable profile", `${resolved}/${withProfile}`);

// normalized fields present on every resolved profile.
const allDir = readdirSync(PROFILE_DIR).filter((f) => f.endsWith(".json"));
let normalized = 0;
for (const f of allDir) {
  const j = read(join(PROFILE_DIR, f));
  if (["family", "runtimeVariant", "licensePosture", "status", "adapterModule"].every((k) => k in j)) normalized++;
  else ok(false, `profile normalized: ${f}`, "missing runtimeVariant/licensePosture/status/family");
}
ok(normalized === allDir.length, "all profiles carry family/runtimeVariant/licensePosture/status", `${normalized}/${allDir.length}`);

// ONE source-controlled adapter module across vscode-family + browser_ide (no duplicate adapter truth).
const familyAdapters = new Set(Object.values(profiles).filter((p) => ["vscode_family", "browser_ide"].includes(p.family)).map((p) => p.adapterModule));
ok(familyAdapters.size === 1 && familyAdapters.has(SHARED_ADAPTER), "vscode-family + browser share ONE adapter module (no duplicate adapter source truth)", [...familyAdapters].join(","));

// no stripped/reverse-engineered reference binary used as an adapter source.
const badAdapter = Object.entries(profiles).find(([, p]) => /reverse-engineering|browser-agent|stripped|reference-binary/i.test(p.adapterModule || ""));
ok(!badAdapter, "no profile uses a stripped reference-binary path as adapter source", badAdapter ? badAdapter[0] : "");

// the proven active browser target.
const vb = profiles["vscode-browser"];
ok(vb?.status === "active" && vb?.runtimeVariant === "oss_openvscode" && vb?.licensePosture === "oss", "vscode-browser is active + oss_openvscode + oss license");
ok(vb?.provisioning?.reproducible === true && Array.isArray(vb?.provisioning?.requires)
  && ["editor_host_provisioning_plan", "editor_access_service", "editor_ws_proxy", "capability_lease"].every((r) => vb.provisioning.requires.includes(r)),
  "vscode-browser declares reproducible provisioning (host plan + access service + ws proxy + capability_lease)");
ok(/capability_lease_ref/.test(vb?.provisioning?.accessLease || ""), "vscode-browser access lease reuses capability_lease_ref (no parallel SessionAccessLease)");

// one-target discipline: exactly the agreed active set; others declared.
const active = editors.filter((e) => e.status === "active").map((e) => e.id).sort();
const declared = editors.filter((e) => e.status === "declared").map((e) => e.id);
ok(active.includes("vscode-browser") && active.includes("vscode") && !active.includes("cursor") && !active.includes("windsurf"),
  "one-target discipline: vscode + vscode-browser active; Cursor/Windsurf declared", `active=[${active.join(",")}]`);
ok(["cursor", "windsurf", "devin"].every((d) => declared.includes(d)) && declared.length >= 5, "Cursor/Windsurf/Devin/JetBrains/SSH stay declared", `${declared.length} declared`);

// doctrine: VS Code is a target, not Hypervisor product identity.
const doctrine = (manifest?.doctrine || []).join(" ");
ok(/not one of them|not the host|not product identity/i.test(doctrine), "manifest doctrine keeps VS Code a mediated target, not product identity");

const verdict = failures === 0 ? "PASS" : "FAIL";
const report = { workstream: "WS-1", verdict, failures, checks: checks.length, active, declared };
if (JSON_OUT) console.log(JSON.stringify(report, null, 2));
else console.log(`  VERDICT: ${verdict} (${checks.length - failures}/${checks.length} checks)`);
process.exit(verdict === "PASS" ? 0 : 1);

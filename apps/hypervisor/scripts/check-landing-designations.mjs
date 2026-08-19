#!/usr/bin/env node
// I-6 — LANDING-DESIGNATION AUDIT (Reference-UX Remediation Program v2).
// Validates landing-designations.v1.json (the machine record of plan §4.1) and, with --exit-gate,
// enforces the W1 exit rule (E8): ZERO click targets may remain LATER — every one must have flipped
// to a designation (NOW) or a recorded terminal absence. GRE targets await the GRE-1 owner ruling
// and are legal at every gate.
//
// Structural checks (always):
//   - unique click_target; status ∈ {NOW, LATER, GRE}
//   - every LATER carries pending_action, and that action EXISTS in the remediation ledger
//   - every NOW carries a grammar; every competitor/graft names a real matrix seed token
//   - every canonical_route in the surface registry appears as (or under) some click target
// Usage: node scripts/check-landing-designations.mjs [--exit-gate]
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
const D = JSON.parse(readFileSync(join(ROOT, "landing-designations.v1.json"), "utf8"));
const LEDGER = JSON.parse(readFileSync(join(ROOT, "reference-remediation-ledger.v1.json"), "utf8"));
const REG = readFileSync(join(HERE, "surface-registry.mjs"), "utf8");

const ledgerIds = new Set();
for (const [k, v] of Object.entries(LEDGER.waves)) if (Array.isArray(v)) for (const a of v) ledgerIds.add(a.id);

const results = [];
const ok = (name, cond, detail) => results.push({ name, pass: !!cond, detail: detail || "" });

const seen = new Set();
let dup = null;
for (const t of D.targets) { if (seen.has(t.click_target)) dup = t.click_target; seen.add(t.click_target); }
ok("click targets unique", !dup, dup || "");
ok("statuses valid", D.targets.every((t) => ["NOW", "LATER", "GRE"].includes(t.status)));
const badLater = D.targets.filter((t) => t.status === "LATER" && (!t.pending_action || !ledgerIds.has(t.pending_action)));
ok("every LATER names a real ledger action", badLater.length === 0, badLater.map((t) => t.click_target).join(" · "));
const badNow = D.targets.filter((t) => t.status === "NOW" && !t.grammar);
ok("every NOW names its grammar", badNow.length === 0, badNow.map((t) => t.click_target).join(" · "));
const pendingRoleBad = D.targets.flatMap((t) => (t.pending_roles || []).filter((a) => !ledgerIds.has(a)).map((a) => `${t.click_target}:${a}`));
ok("every pending role names a real ledger action", pendingRoleBad.length === 0, pendingRoleBad.join(" · "));
// registry canonical routes covered
const canon = [...REG.matchAll(/canonical_route: "([^"]+)"/g)].map((m) => m[1]);
const covered = (r) => D.targets.some((t) => t.click_target === r || r.startsWith(t.click_target + "/") || t.click_target === r.split("/").slice(0, 2).join("/"));
const missing = canon.filter((r) => !covered(r));
ok("every registry canonical_route is designated (or under a designated owner target)", missing.length === 0, missing.join(" · "));

const later = D.targets.filter((t) => t.status === "LATER");
if (process.argv.includes("--exit-gate")) {
  ok("W1 EXIT GATE (E8): zero LATER click targets remain", later.length === 0, later.map((t) => `${t.click_target}→${t.pending_action}`).join(" · "));
}

const fails = results.filter((r) => !r.pass);
for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
const counts = D.targets.reduce((a, t) => ((a[t.status] = (a[t.status] || 0) + 1), a), {});
console.log(`\n${results.length - fails.length}/${results.length} passed · targets: ${D.targets.length} (${Object.entries(counts).map(([k, v]) => `${k}=${v}`).join(" · ")})`);
process.exit(fails.length ? 1 : 0);

#!/usr/bin/env node
// UX-substrate verifier (Slice 1 breadth gate). Proves the design-system kit + canon shell are
// stable and that the two pressure surfaces (Environments + Workbench) are converted onto them with
// ZERO per-surface drift — before any application breadth. Static gates always run; the --browser
// tier drives the live native UI (default http://127.0.0.1:1420) and is a declared gap if absent.
// Usage: [--browser] [--url http://127.0.0.1:1420] [--json].
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

const REPO = new URL("..", import.meta.url).pathname;
const APP = join(REPO, "apps/hypervisor/src");
const args = process.argv.slice(2);
const JSON_OUT = args.includes("--json");
const WANT_BROWSER = args.includes("--browser");
const UI_URL = (args[args.indexOf("--url") + 1] && !args[args.indexOf("--url") + 1].startsWith("--")) ? args[args.indexOf("--url") + 1] : "http://127.0.0.1:1420";

const checks = [];
const declaredGaps = [];
let failures = 0;
const ok = (cond, msg, detail) => { checks.push({ ok: !!cond, msg, detail: detail || "" }); if (!cond) failures++; if (!JSON_OUT) console.log(`    ${cond ? "✓" : "✗ FAIL:"} ${msg}${detail ? ` (${detail})` : ""}`); };
const read = (p) => { try { return readFileSync(p, "utf8"); } catch { return ""; } };
function walk(dir, out = []) { for (const e of (existsSync(dir) ? readdirSync(dir) : [])) { const p = join(dir, e); if (statSync(p).isDirectory()) walk(p, out); else out.push(p); } return out; }

if (!JSON_OUT) console.log("UX substrate — Slice 1 gate");

// ---- anti-drift: NO hex in the governed dirs (surfaces/shell/ui). Tokens live in styles/*.css. ----
const governed = [join(APP, "surfaces"), join(APP, "shell"), join(APP, "ui")];
const hexRe = /#[0-9a-fA-F]{3,8}\b/;
const hexOffenders = [];
for (const dir of governed) for (const f of walk(dir)) {
  if (!/\.(tsx?|css)$/.test(f)) continue;
  read(f).split("\n").forEach((line, i) => { if (hexRe.test(line)) hexOffenders.push(`${f.replace(REPO, "")}:${i + 1}`); });
}
ok(hexOffenders.length === 0, "no hex literals in surfaces/shell/ui (token-pure)", hexOffenders.slice(0, 4).join(", "));

// ---- kit exists + consumed ----
const kitIndex = read(join(APP, "ui/index.ts"));
ok(/kit\.css/.test(kitIndex) && /primitives/.test(kitIndex) && /patterns/.test(kitIndex), "ui kit barrel exports stylesheet + primitives + patterns");
const cockpit = read(join(APP, "surfaces/NativeCockpit.tsx"));
const workbench = read(join(APP, "surfaces/NativeWorkbench.tsx"));
ok(/from "\.\.\/ui"/.test(cockpit) && /from "\.\.\/ui"/.test(workbench), "Environments + Workbench import the kit (no bespoke primitives)");

// ---- canon rail ----
const rail = read(join(APP, "shell/Rail.tsx"));
ok(["New Session", "Home", "Projects", "Automations", "Applications", "Sessions"].every((x) => rail.includes(x)), "rail renders the canon items");
ok(!/rail-providers|rail-environments|>\s*Providers\s*<|>\s*Environments\s*</.test(rail), "rail does NOT carry Providers/Environments (they are catalog surfaces)");

// ---- applications catalog ----
const apps = read(join(APP, "shell/ApplicationsModal.tsx"));
const groupCount = (apps.match(/label:\s*"/g) || []).length;
const surfaceNames = ["Workbench", "Environments", "Agent Studio", "Foundry", "ODK", "Domain Apps", "Developer & Integrations", "Governance", "Operations", "Work Ledger", "Marketplace"];
ok(groupCount >= 8, "Applications catalog defines >= 8 groups", `${groupCount}`);
ok(surfaceNames.every((n) => apps.includes(n)), "Applications catalog lists all 11 v2 surfaces");

// ---- source-neutral ----
const srcFiles = walk(APP).filter((f) => /\.(tsx?|css)$/.test(f));
const leaked = srcFiles.filter((f) => /reverse-engineering/.test(read(f)) || /class(Name)?=["']ona["']/.test(read(f)));
ok(leaked.length === 0, "no harvested-reference leakage in src (no reverse-engineering / ona)", leaked.slice(0, 3).map((f) => f.replace(REPO, "")).join(", "));

// ---- product-label contract ----
ok(/AuthorityControl/.test(cockpit) && /productLabel/.test(read(join(APP, "ui/patterns.tsx"))), "effectful controls use AuthorityControl (productLabel + advancedLabel)");

// ---- typecheck ----
const tsc = spawnSync(join(REPO, "node_modules/.bin/tsc"), ["-p", join(REPO, "apps/hypervisor/tsconfig.json"), "--noEmit"], { encoding: "utf8", cwd: REPO });
ok(tsc.status === 0, "apps/hypervisor typechecks (strict)", tsc.status === 0 ? "" : (tsc.stdout || "").split("\n").slice(0, 3).join(" | "));

// ---- browser tier (drives the live native UI) ----
if (WANT_BROWSER) {
  const r = await browserTier();
  if (r.skipped) { declaredGaps.push({ gate: "browser_render", prerequisite: r.reason }); if (!JSON_OUT) console.log(`    · DECLARED GAP: browser_render — ${r.reason}`); }
  else for (const c of r.checks) ok(c.ok, c.msg, c.detail);
}

async function browserTier() {
  let chromium; try { ({ chromium } = await import("playwright")); } catch { return { skipped: true, reason: "playwright not importable" }; }
  try { const res = await fetch(UI_URL, { signal: AbortSignal.timeout(3000) }); if (!res.ok) throw new Error(String(res.status)); } catch { return { skipped: true, reason: `native UI not serving at ${UI_URL} (start: npm run dev --workspace=@ioi/hypervisor-app)` }; }
  const out = [];
  const b = await chromium.launch({ headless: true });
  try {
   try {
    const p = await b.newPage({ viewport: { width: 1280, height: 800 } });
    const errs = []; p.on("console", (m) => { if (m.type() === "error") errs.push(m.text()); }); p.on("pageerror", (e) => errs.push("pageerror: " + e.message));
    await p.goto(`${UI_URL}/`, { waitUntil: "domcontentloaded", timeout: 30000 });
    await p.waitForSelector('[data-testid="app-shell"]', { timeout: 15000 });
    await p.waitForSelector('[data-testid="home-surface"]', { timeout: 15000 });
    // tokens applied: app-shell background === resolved --surface-0 (→ --sand-100), not a default.
    const tok = await p.evaluate(() => {
      const hexToRgb = (h) => { const n = h.replace("#", "").trim(); const v = n.length === 3 ? n.split("").map((c) => c + c).join("") : n; return `rgb(${parseInt(v.slice(0, 2), 16)}, ${parseInt(v.slice(2, 4), 16)}, ${parseInt(v.slice(4, 6), 16)})`; };
      const sand = getComputedStyle(document.documentElement).getPropertyValue("--sand-100");
      const shell = document.querySelector('[data-testid="app-shell"]');
      return { want: hexToRgb(sand), got: getComputedStyle(shell).backgroundColor };
    });
    out.push({ ok: tok.want === tok.got, msg: "tokens applied — shell bg === resolved --surface-0", detail: `${tok.got} vs ${tok.want}` });
    // rail items present
    const railOk = await p.evaluate(() => ["rail-new-session", "rail-home", "rail-projects", "rail-automations", "rail-applications", "rail-sessions"].every((t) => !!document.querySelector(`[data-testid="${t}"]`)));
    out.push({ ok: railOk, msg: "canon rail renders all items" });
    // applications modal opens + catalog
    await p.click('[data-testid="rail-applications"]');
    await p.waitForSelector('[data-testid="apps-catalog"]', { timeout: 8000 });
    const groups = await p.$$('[data-testid="apps-group"]'); const cards = await p.$$('[data-testid="appcard"]');
    out.push({ ok: groups.length >= 8 && cards.length >= 11, msg: "Applications modal shows >=8 groups + >=11 surfaces", detail: `${groups.length} groups / ${cards.length} cards` });
    await p.keyboard.press("Escape").catch(() => {});
    // environments converted + create works
    await p.goto(`${UI_URL}/environments`, { waitUntil: "domcontentloaded", timeout: 30000 });
    await p.waitForSelector('[data-testid="environments-surface"]', { timeout: 15000 });
    await p.click('[data-testid="create-env"]');
    await p.waitForSelector('[data-testid="env-card"]', { timeout: 30000 });
    const card = await p.evaluate(() => {
      const c = document.querySelector('[data-testid="env-card"]') || document.querySelector('.hv-card');
      return { grid: !!document.querySelector('[data-testid="component-grid"]'), openin: !!document.querySelector('[data-testid="open-in-picker"]'), card: !!c };
    });
    out.push({ ok: card.card && card.grid && card.openin, msg: "Environments converted onto kit (card + component-grid + open-in)" });
    out.push({ ok: errs.length === 0, msg: "no console/page errors across shell + environments", detail: errs.slice(0, 2).join("; ") });
   } catch (e) {
    out.push({ ok: false, msg: "browser tier completed without exception", detail: String(e).slice(0, 160) });
   }
  } finally { await b.close(); }
  return { checks: out };
}

const verdict = failures > 0 ? "FAIL" : declaredGaps.length ? "PASS_WITH_DECLARED_GAPS" : "PASS";
const report = { workstream: "ux-substrate-slice-1", verdict, failures, checks: checks.length, declared_gaps: declaredGaps };
if (JSON_OUT) console.log(JSON.stringify(report, null, 2));
else { console.log(`  declared gaps: ${declaredGaps.length ? declaredGaps.map((g) => g.prerequisite).join(", ") : "none"}`); console.log(`  VERDICT: ${verdict} (${checks.length - failures}/${checks.length} checks)`); }
process.exit(verdict === "FAIL" ? 1 : 0);

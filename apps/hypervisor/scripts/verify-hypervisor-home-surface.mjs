#!/usr/bin/env node
// Home surface readiness verifier (03-home port · 02-new-session identity — the P0 front door).
//
// THE Home is an augmentation-rendered EXPLORER at /ai (welcome / get-started / governed work /
// recents / applications, SPA design tokens, live daemon truth). The SPA's polished composer page
// is New Session, at /ai#new-session (create-session button + Ctrl+O land there; Advanced launch
// opens the owned governed modal). /__ioi/home stays the full readout the explorer links to.
// Asserts all three against the running daemon (:8765) + serve (:4173): explorer mounts as the
// /ai default and cites live blocked/pending truth with token-resolved styles (Playwright); the
// create-session button routes to the composer and the owned modal stays one click away; the
// readout's four strips render bound to REAL daemon truth with honest empty states; NO second
// "Home" exists in the launcher modal; existing estate surfaces stay 200; fallthrough stays
// empty; and the degraded lane names the daemon outage (checked on an ISOLATED second serve
// pointed at a dead daemon port so the live processes are never touched).
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-home-surface.mjs
// Exit 0 = all assertions pass; exit 1 = one or more failed.

import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
const SERVE = (process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173").replace(/\/$/, "");
const HERE = dirname(fileURLToPath(import.meta.url));
const DEGRADED_PORT = 4599;
const DEGRADED_UI_PORT = 9399;

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
async function jget(path) {
  return fetch(`${DAEMON}${path}`).then((r) => r.json()).catch(() => null);
}
async function sGet(path, base = SERVE) {
  const r = await fetch(`${base}${path}`);
  return { status: r.status, text: await r.text() };
}

async function run() {
  // 1. Surface renders with the full strip anatomy.
  const home = await sGet("/__ioi/home");
  ok("home renders 200", home.status === 200, `status ${home.status}`);
  for (const id of ["home-decisions", "home-blocked", "home-resume", "home-proof"]) {
    ok(`strip ${id} present`, home.text.includes(`id="${id}"`));
  }
  ok("counts chips render", /decisions \d+|decisions \?/.test(home.text) && /blocked \d+|blocked \?/.test(home.text));
  ok("no degraded banner while daemon is up", !home.text.includes("home-degraded"));
  ok("read-only: no effectful forms on Home", !/<form[^>]*method="post"/i.test(home.text), "Home links to owning surfaces; it never mutates");

  // 2. Decisions strip ⇔ governance approval-requests truth.
  const appr = await jget("/v1/hypervisor/governance/approval-requests");
  const pending = ((appr && appr.approval_requests) || []).filter((a) => a.status === "pending");
  if (pending.length === 0) {
    ok("decisions empty state honest", home.text.includes("no pending approval requests"), "daemon reports 0 pending");
  } else {
    ok("decisions rows bound to daemon truth", pending.slice(0, 8).every((a) => home.text.includes(a.subject_ref || "__missing_subject_ref__")), `${pending.length} pending`);
  }

  // 3. Blocked strip ⇔ failover runs parked at a wallet gate (awaiting_authority_*).
  const fo = await jget("/v1/hypervisor/failover/runs");
  const parked = ((fo && fo.runs) || []).filter((r) => String(r.status || "").startsWith("awaiting_authority"));
  if (parked.length === 0) {
    ok("blocked strip honest when nothing parked", home.text.includes("No runs are parked or failing") || home.text.includes("failed"), "0 parked; failures may still render");
  } else {
    ok("parked failover runs cited verbatim", parked.slice(0, 6).every((r) => home.text.includes(r.run_ref || "__missing_run_ref__")), `${parked.length} parked at a gate`);
    ok("gate named on parked rows", parked.slice(0, 6).every((r) => home.text.includes(`wallet gate: ${String(r.status).replace("awaiting_authority_", "")}`)));
  }

  // 4. Resume strip ⇔ sessions truth.
  const sess = await jget("/v1/hypervisor/sessions");
  const sessions = (sess && sess.sessions) || [];
  if (sessions.length === 0) {
    ok("resume empty state honest", home.text.includes("No sessions yet"), "daemon reports 0 sessions");
  } else {
    const newest = sessions.slice().sort((a, b) => String(b.created_at || "").localeCompare(String(a.created_at || "")))[0];
    ok("newest session cited", home.text.includes(newest.session_ref || "__missing_session_ref__"), newest.session_ref);
  }

  // 5. Proof strip ⇔ work-ledger head entries (newest-first from the daemon).
  const led = await jget("/v1/hypervisor/work-ledger");
  const entries = (led && led.entries) || [];
  if (entries.length === 0) {
    ok("proof empty state honest", home.text.includes("the proof stream is empty"), "daemon reports 0 entries");
  } else {
    ok("proof head entries rendered", entries.slice(0, 3).every((e) => home.text.includes(e.kind || "__missing_entry_kind__")), `${entries.length} ledger entries`);
    ok("proof links to Work Ledger", home.text.includes('href="/__ioi/work-ledger"'));
  }

  // 6. Reachability — Applications page links the readout; launcher modal carries no rival Home.
  const apps = await sGet("/__ioi/applications");
  ok("Applications cross-links the readout", apps.status === 200 && apps.text.includes('href="/__ioi/home"'));
  const aug = await sGet("/ioi-augmentation.js");
  ok("launcher modal does NOT list a second Home", aug.status === 200 && !/name: "Home"/.test(aug.text), "the explorer IS Home; no rival catalog entry");
  ok("explorer + view router ship in the augmentation", aug.text.includes("ioi-home-explorer") && aug.text.includes("applyAiViews") && aug.text.includes("renderExplorer"));
  ok("composer band retired", !aug.text.includes("ioi-home-band"), "governed-work strips live on the explorer now");

  // 6c. App catalog — every pixel-certified port in the parity matrix is discoverable from /ai.
  // Membership is matrix truth (shell_pixel_certified seeds), so this assertion self-extends as
  // the certification wave lands new ports; the launcher lanes must carry each one.
  const matrix = JSON.parse(readFileSync(join(HERE, "..", "harvest-app-parity-matrix.json"), "utf8"));
  const portedSeeds = (matrix.seeds || []).filter((s) => s.shell_pixel_certified && s.candidate_surface);
  const catRes = await sGet("/__ioi/api/applications");
  let catalog = null; try { catalog = JSON.parse(catRes.text); } catch { /* non-json */ }
  ok("app catalog endpoint serves the matrix projection", catRes.status === 200 && catalog && catalog.schema === "ioi.hypervisor.app-catalog.v1", `status ${catRes.status}`);
  const catRoutes = [...new Set(((catalog && catalog.apps) || []).map((a) => a.route))];
  ok("catalog lists every certified seed", portedSeeds.length > 0 && portedSeeds.every((s) => catRoutes.includes(s.candidate_surface.split("?")[0])), `${catRoutes.length} catalog apps vs ${portedSeeds.length} certified seeds`);
  // The catalog is DERIVED truth: certified matrix seeds ⊕ contract-admitted registry surfaces
  // (read_only_by_contract with verified operational-depth evidence — the #65+ lane that admitted
  // missions). Rebuild it from the same inputs and require the served projection to match exactly —
  // an app beyond that derivation is an invention, a missing one is a dropped port.
  const { buildAppCatalog } = await import("./app-catalog.mjs");
  const atlas = JSON.parse(readFileSync(join(HERE, "..", "application-operational-depth.json"), "utf8"));
  const expectedApps = buildAppCatalog({ matrix, atlas }).apps.map((a) => `${a.slug}|${a.route}`).sort();
  const servedApps = ((catalog && catalog.apps) || []).map((a) => `${a.slug}|${a.route}`).sort();
  ok("catalog invents no apps beyond the matrix + verified contract evidence (served == derived, both directions)", JSON.stringify(servedApps) === JSON.stringify(expectedApps), `served ${servedApps.length} vs derived ${expectedApps.length}`);
  ok("catalog apps carry title + family", ((catalog && catalog.apps) || []).every((a) => a.title && a.family && a.slug));
  ok("estate page lists every catalog app", catRoutes.every((r) => apps.text.includes(`href="${r}"`)), "/__ioi/applications renders the same projection");
  const aiHtml = await sGet("/ai");
  ok("/ai serves the augmented shell", aiHtml.status === 200 && aiHtml.text.includes('src="/ioi-augmentation.js"'), "requires the owned tree (IOI_PRODUCT_UI_PUBLIC) or the injected tag");
  ok("augmentation ships the catalog lane", aug.text.includes("fetchAppCatalog") && aug.text.includes("/__ioi/api/applications"));

  // 6b. The explorer Home + New Session composer identities on the REAL shell (Playwright — both
  // views are client-routed by the augmentation, so static HTML checks cannot see them).
  {
    const { chromium } = await import("playwright");
    const b = await chromium.launch();
    try {
      const page = await b.newPage({ viewport: { width: 1440, height: 1000 } });
      const visible = (sel) => page.evaluate((s) => { const e = document.querySelector(s); return !!e && e.offsetParent !== null && getComputedStyle(e).display !== "none"; }, sel);
      // Explorer = the /ai default view (what the rail's Home opens).
      await page.goto(`${SERVE}/ai`, { waitUntil: "networkidle" });
      const exp = page.locator('[data-testid="ioi-home-explorer"]');
      await exp.waitFor({ state: "attached", timeout: 15000 }).catch(() => {});
      ok("explorer mounts as the /ai default view", await exp.count() === 1);
      ok("native composer hidden behind the explorer", !(await visible('[data-testid="prompt-input-textarea"]')));
      await page.waitForFunction(() => {
        const el = document.getElementById("ioi-home-explorer");
        return el && el.textContent && el.textContent.includes("Welcome back");
      }, { timeout: 15000 }).catch(() => {});
      const expText = (await exp.textContent().catch(() => "")) || "";
      ok("welcome hero renders", expText.includes("Welcome back"));
      ok("explorer sections render", expText.includes("Governed work") && expText.includes("Recent") && expText.includes("Applications") && expText.includes("Full readout"));
      const parkedNow = ((await jget("/v1/hypervisor/failover/runs"))?.runs || []).filter((r) => String(r.status || "").startsWith("awaiting_authority"));
      const pendNow = ((await jget("/v1/hypervisor/governance/approval-requests"))?.approval_requests || []).filter((a) => a.status === "pending");
      if (parkedNow.length || pendNow.length) {
        ok("explorer cites live blocked/pending truth", (parkedNow.length === 0 || expText.includes("wallet gate")) && (pendNow.length === 0 || expText.includes("Approval waiting")), `${parkedNow.length} parked · ${pendNow.length} pending`);
      } else {
        ok("explorer all-clear line honest when quiet", expText.includes("All clear"), "daemon reports nothing parked/pending");
      }
      const sessNow = ((await jget("/v1/hypervisor/sessions"))?.sessions || []);
      ok("recent tab honest vs sessions truth", sessNow.length === 0 ? expText.includes("No sessions yet") : expText.includes(sessNow[0].session_ref || "@"), `${sessNow.length} sessions`);
      const appTiles = await page.locator('#ioi-home-explorer a[href^="/__ioi/"]').count();
      ok("applications grid renders the estate", appTiles >= 11, `${appTiles} estate links`);
      const tokened = await page.evaluate(() => {
        const row = document.querySelector("#ioi-home-explorer a.rounded-xl, #ioi-home-explorer div.rounded-xl");
        if (!row) return false;
        const cs = getComputedStyle(row);
        return cs.borderRadius !== "0px" && cs.backgroundColor !== "rgba(0, 0, 0, 0)";
      });
      ok("explorer styled by the SPA design tokens", tokened, "token classes resolved to real computed styles");
      // App catalog on the live shell — every ported app is a tile in the explorer grid, a row in
      // the launcher modal, and opens in the Open Application slot (in-shell, rail intact).
      await page.waitForFunction((n) => document.querySelectorAll("#ioi-home-explorer a[data-ioi-app]").length >= n, catRoutes.length, { timeout: 15000 }).catch(() => {});
      const missingTiles = [];
      for (const r of catRoutes) if ((await page.locator(`#ioi-home-explorer a[href="${r}"]`).count()) === 0) missingTiles.push(r);
      ok("explorer grid lists every ported app", catRoutes.length > 0 && missingTiles.length === 0, missingTiles.length ? `missing: ${missingTiles.join(" ")}` : `${catRoutes.length} ported tiles`);
      await page.click('#ioi-home-explorer a[href="#applications"]');
      const launcherOpen = await page.waitForSelector("#ioi-apps-modal.open", { timeout: 10000 }).then(() => true).catch(() => false);
      const missingRows = [];
      if (launcherOpen) for (const r of catRoutes) if ((await page.locator(`#ioi-apps-modal .ioi-mrow[data-href="${r}"]`).count()) === 0) missingRows.push(r);
      ok("launcher modal lists every ported app", launcherOpen && missingRows.length === 0, missingRows.length ? `missing: ${missingRows.join(" ")}` : "modal carries the catalog");
      await page.click("#ioi-apps-modal .ioi-mh button").catch(() => {});
      if (catRoutes.length) {
        await page.click(`#ioi-home-explorer a[href="${catRoutes[0]}"]`);
        await page.waitForTimeout(400);
        const portedSlot = await page.evaluate(() => {
          const el = document.getElementById("ioi-open-app");
          if (!el || el.style.display === "none") return null;
          const f = el.querySelector("iframe");
          return f ? f.getAttribute("src") : null;
        });
        ok("ported tile opens in the Open Application slot EMBEDDED (native container contract #65)", portedSlot === `${catRoutes[0]}?embed=1`, `slot iframe → ${portedSlot}`);
        await page.evaluate(() => { const x = document.querySelector("#ioi-open-app .ioi-oa-close"); if (x) x.click(); });
      }
      // New Session = the composer, at #new-session, reached from the rail button.
      await page.click('[data-testid="create-session-button"]');
      await page.waitForTimeout(600);
      ok("create-session routes to the composer", (await page.evaluate(() => location.hash)) === "#new-session" && (await visible('[data-testid="prompt-input-textarea"]')));
      ok("explorer hidden on the composer view", !(await visible('[data-testid="ioi-home-explorer"]')));
      await page.waitForSelector("#ioi-ns-advanced", { timeout: 10000 }).catch(() => {});
      await page.click("#ioi-ns-advanced").catch(() => {});
      const modalOpen = await page.waitForSelector("#ioi-ns-modal.open", { timeout: 10000 }).then(() => true).catch(() => false);
      ok("Advanced launch opens the owned governed modal", modalOpen, "one daemon-backed launch lane preserved");
      // Governed row click-through — back on the explorer, a row opens the owning surface in-slot.
      await page.goto(`${SERVE}/ai`, { waitUntil: "networkidle" });
      await exp.waitFor({ state: "attached", timeout: 15000 }).catch(() => {});
      const itemRow = page.locator("#ioi-home-explorer a.ioi-hb-row").first();
      if (await itemRow.count()) {
        await itemRow.click();
        await page.waitForTimeout(400);
        const slotSrc = await page.evaluate(() => {
          const el = document.getElementById("ioi-open-app");
          if (!el || el.style.display === "none") return null;
          const f = el.querySelector("iframe");
          return f ? f.getAttribute("src") : null;
        });
        ok("governed row opens the owning surface in the Open Application slot", !!slotSrc && slotSrc.startsWith("/__ioi/"), `slot iframe → ${slotSrc}`);
      } else {
        ok("governed row click-through (skipped — all clear, no rows)", true, "nothing parked/pending/failed right now");
      }
    } finally {
      await b.close();
    }
  }

  // 7. Existing estate surfaces stay reachable.
  for (const p of ["/__ioi/applications", "/__ioi/workbench", "/__ioi/environments", "/__ioi/agent-studio", "/__ioi/foundry", "/__ioi/odk", "/__ioi/domain-apps", "/__ioi/connections", "/__ioi/governance", "/__ioi/operations", "/__ioi/work-ledger", "/__ioi/marketplace"]) {
    ok(`surface ${p} still 200`, (await sGet(p)).status === 200);
  }

  // 8. Fallthrough stays empty after exercising the new surface.
  const ft = await sGet("/__ioi/fallthrough");
  let ftJson = null; try { ftJson = JSON.parse(ft.text); } catch { /* non-json */ }
  const ftCount = ftJson ? (Array.isArray(ftJson) ? ftJson.length : (ftJson.entries || []).length) : -1;
  ok("fallthrough empty", ftCount === 0, `entries: ${ftCount}`);

  // 9. Degraded lane — isolated serve pointed at a dead daemon port shows the named outage banner.
  const child = spawn(process.execPath, [join(HERE, "serve-product-ui.mjs")], {
    env: { ...process.env, PORT: String(DEGRADED_PORT), PRODUCT_UI_PORT: String(DEGRADED_UI_PORT), IOI_HYPERVISOR_DAEMON_URL: "http://127.0.0.1:1" },
    stdio: "ignore",
  });
  try {
    let deg = null;
    for (let i = 0; i < 30 && !deg; i++) {
      await new Promise((r) => setTimeout(r, 500));
      deg = await sGet("/__ioi/home", `http://127.0.0.1:${DEGRADED_PORT}`).catch(() => null);
    }
    ok("degraded serve reachable", !!deg && deg.status === 200, deg ? `status ${deg.status}` : "never came up");
    ok("degraded banner names the outage", !!deg && deg.text.includes("home-degraded") && deg.text.includes("Daemon unreachable"));
    ok("degraded page fabricates nothing", !!deg && deg.text.includes("nothing rather than fixtures"));
  } finally {
    child.kill("SIGTERM");
  }
}

run().then(() => {
  const fails = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${results.length - fails.length}/${results.length} passed`);
  if (fails.length) process.exit(1);
  console.log("home-surface readiness: OK");
}).catch((e) => {
  console.error("verifier crashed:", e);
  process.exit(1);
});

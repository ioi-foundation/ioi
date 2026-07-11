#!/usr/bin/env node
// Native-shell integration verifier (operational wave PR61 — Native Ontology Integration,
// AMENDED by the #70 stack correction: Ontology is CATALOG-LAUNCHED, not a permanent rail item).
//
// Proves the product architecture the wave stands on:
//   1. NATIVE RAIL — the permanent rail is EXACTLY the native five (Home · Projects ·
//      Automations · Applications · Sessions); NO permanent Ontology rail entry exists and no
//      other permanent item is injected (the only injected rail row is the contextual
//      Open Application row).
//   2. CATALOG LAUNCH / SINGLE SLOT / SINGLE RAIL — Ontology launches from the REAL
//      Applications catalog into the existing singular Open Application slot in EMBEDDED mode
//      (openApplication forces embed=1 at the funnel): the native rail stays visible, the app's
//      duplicated reference global rail is NOT visible inside the iframe, app-LOCAL navigation
//      IS, and in-app navigation never creates a second slot. Close → reopen from the catalog
//      preserves normal launcher behavior.
//   3. EMBED PERSISTENCE — embed=1 survives in-app links, row onclicks, and GET forms.
//   4. STANDALONE UNTOUCHED — direct routes render the complete certified reference shell
//      (no embed style, global rail present); certification artifacts stay byte-identical.
//   5. SUITE — the Applications estate + launcher catalogs route Ontology to the Manager
//      (owner surface), never to the /__ioi/odk substrate (which stays linked from within).
//   6. CAPABILITY MODEL — every registry surface declares authority-derived capabilities +
//      operational_state from the allowed vocabularies (fail-fast invariants also boot-guard).
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-native-shell-integration.mjs
// Exit 0 = all assertions pass; exit 1 = one or more failed.

import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { SURFACES, CAPABILITIES, OPERATIONAL_STATES, boundSurface } from "./surface-registry.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));

const SERVE = (process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173").replace(/\/$/, "");

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
const page = (url) => fetch(url).then(async (r) => ({ status: r.status, text: await r.text() })).catch(() => ({ status: 0, text: "" }));

async function run() {
  // 6 (static first). Capability model invariants.
  ok("every surface declares capabilities + operational_state from the allowed vocabularies", SURFACES.every((s) => Array.isArray(s.capabilities) && s.capabilities.length > 0 && s.capabilities.every((c) => CAPABILITIES.includes(c)) && OPERATIONAL_STATES.includes(s.operational_state)), `${SURFACES.length} surfaces`);
  ok("extracted interactive modules declare their earned state (pipeline/explorer=inspect, schema=act since #63)", SURFACES.find((s) => s.slug === "pipeline").operational_state === "inspect" && SURFACES.find((s) => s.slug === "explorer").operational_state === "inspect" && SURFACES.find((s) => s.slug === "schema").operational_state === "act");
  ok("operational state is not inferred from parity: certified non-extracted surfaces stay browse/act, never inspect+", SURFACES.filter((s) => !boundSurface(s.route, "GET")).every((s) => ["shell", "browse", "act"].includes(s.operational_state)));

  // 4. Standalone routes keep the complete certified shell.
  for (const r of ["/__ioi/ontology/manager", "/__ioi/ontology/explorer", "/__ioi/pipeline"]) {
    const p = await page(`${SERVE}${r}`);
    ok(`standalone ${r} keeps the certified reference shell (global rail present, no embed style)`, p.status === 200 && p.text.includes('class="og-grail') && !p.text.includes(".og-grail{display:none"));
  }
  // 3 (static). Embedded routes hide ONLY the global rail and thread embed=1 everywhere.
  const em = await page(`${SERVE}/__ioi/ontology/manager?embed=1`);
  ok("embedded manager hides the duplicated global rail (CSS only) and keeps the app-LOCAL rail", em.status === 200 && em.text.includes(".og-grail{display:none") && em.text.includes('class="og-arail"'), "app-local nav preserved");
  ok("embedded manager threads embed=1 through its Explorer cross-link", /href="\/__ioi\/ontology\/explorer\?embed=1"/.test(em.text));
  const ee = await page(`${SERVE}/__ioi/ontology/explorer?embed=1`);
  ok("embedded explorer threads embed=1 through row onclicks AND the filter form", /location\.href='\/__ioi\/ontology\/explorer\?[^']*embed=1'/.test(ee.text) && ee.text.includes('<input type="hidden" name="embed" value="1">'));
  const ep = await page(`${SERVE}/__ioi/pipeline?embed=1`);
  ok("embedded pipeline threads embed=1 through node/preview links", /href="\/__ioi\/pipeline\?[^"]*embed=1[^"]*"/.test(ep.text) && ep.text.includes(".og-grail{display:none"));

  // 5. Suite catalogs route Ontology to the Manager, never the substrate.
  const apps = await page(`${SERVE}/__ioi/applications`);
  ok("the Applications estate routes Ontology to the Manager (owner surface)", apps.status === 200 && /Ontology[\s\S]{0,400}?href="\/__ioi\/ontology\/manager"/.test(apps.text.replace(/\n/g, " ")) || apps.text.includes('href="/__ioi/ontology/manager"'));
  const aug = await page(`${SERVE}/ioi-augmentation.js`);
  ok("the launcher catalog routes Ontology to the Manager; the substrate stays a Data-lane link", /name: "Ontology"[^}]*href: "\/__ioi\/ontology\/manager"/.test(aug.text) && /name: "Data"[^}]*href: "\/__ioi\/odk#data-planes"/.test(aug.text));
  ok("the Manager keeps the substrate linked from within (odk stays the advanced contract surface)", em.text.includes("/__ioi/odk"));
  ok("NO rail injection ships in the augmentation (#70 stack correction) — Ontology is catalog-launched", !aug.text.includes("mountOntologyNav") && !aug.text.includes("ioi-ontology-rail"));
  ok("openApplication forces embed=1 for /__ioi/ applications at the funnel (embeddedAppSrc)", aug.text.includes("embeddedAppSrc") && /searchParams\.set\("embed", "1"\)/.test(aug.text));
  ok("certification artifacts are byte-identical (git-clean)", (spawnSync("git", ["status", "--porcelain", "--", "pixel-certifications"], { cwd: join(HERE, ".."), encoding: "utf8" }).stdout || "").trim() === "");

  // 1+2+3 (live). The native shell journey, driven in a real browser.
  {
    const { chromium } = await import("playwright");
    const b = await chromium.launch();
    try {
      const pg = await b.newPage({ viewport: { width: 1440, height: 1000 } });
      await pg.goto(`${SERVE}/ai`, { waitUntil: "networkidle" });
      const rail = pg.locator('[data-testid="sidebar"]');
      await pg.waitForSelector('[data-testid="sidebar"] a[href="#applications"]', { timeout: 15000 });
      await pg.waitForTimeout(1200); // augmentation ticks settle (React re-renders the rail)
      ok("NO permanent Ontology rail entry exists (#70 stack correction)", await pg.locator("#ioi-ontology-rail").count() === 0);
      const railState = await pg.evaluate(() => {
        const sb = document.querySelector('[data-testid="sidebar"]');
        const anchors = [...sb.querySelectorAll("a")];
        const texts = anchors.map((a) => (a.textContent || "").trim());
        const idx = (href) => anchors.findIndex((a) => a.getAttribute("href") === href && (a.textContent || "").trim());
        return {
          home: idx("/ai"), projects: idx("/projects"), automations: idx("/automations"), applications: idx("#applications"),
          sessions: !!sb.querySelector('[data-testid="sessions-filter-button"]'),
          ontologyText: texts.some((t) => /^\S?Ontology$/.test(t)),
          injected: [...sb.querySelectorAll('[id^="ioi-"]')].map((e) => e.id).filter((id) => id !== "ioi-openapp-rail").join(","),
        };
      });
      ok("the permanent rail is EXACTLY the native five: Home → Projects → Automations → Applications, with the Sessions region", railState.home >= 0 && railState.projects > railState.home && railState.automations > railState.projects && railState.applications > railState.automations && railState.sessions === true, JSON.stringify(railState));
      ok("no Ontology rail label and no injected permanent nav id (the Open Application row is the only injected rail row)", railState.ontologyText === false && railState.injected === "");
      // Launch Ontology from the REAL Applications catalog → the singular slot, embedded.
      await pg.click('[data-testid="sidebar"] a[href="#applications"]');
      await pg.waitForSelector("#ioi-apps-modal.open", { timeout: 15000 });
      await pg.click('#ioi-apps-modal .ioi-mrow[data-name="Ontology"]');
      await pg.waitForSelector("#ioi-open-app iframe", { timeout: 15000 });
      ok("Ontology launches FROM THE CATALOG into the singular Open Application slot (embedded Manager — the funnel forced embed=1)", await pg.locator("#ioi-open-app").count() === 1 && ((await pg.locator("#ioi-open-app iframe").getAttribute("src")) || "").includes("/__ioi/ontology/manager?embed=1"));
      ok("the native rail stays visible while the app is open", await rail.isVisible());
      // Poll for the manager iframe to commit + render its app rail (the module makes several
      // daemon round-trips, so frames()/DOM aren't ready the instant the iframe element appears).
      let frame = null;
      for (let i = 0; i < 40 && !frame; i++) {
        await pg.waitForTimeout(500);
        const f = pg.frames().find((x) => x.url().includes("/__ioi/ontology/manager"));
        if (f && await f.locator(".og-arail").count().catch(() => 0)) frame = f;
      }
      ok("inside the app: the duplicated global rail is NOT visible, the app-LOCAL rail IS", !!frame && !(await frame.locator(".og-grail").isVisible().catch(() => true)) && (await frame.locator(".og-arail").isVisible().catch(() => false)));
      // In-app navigation stays embedded, stays single-slot.
      await frame.click('a[href="/__ioi/ontology/explorer?embed=1"]');
      let frame2 = null;
      for (let i = 0; i < 40 && !frame2; i++) {
        await pg.waitForTimeout(500);
        const f2 = pg.frames().find((f) => f.url().includes("/__ioi/ontology/explorer"));
        if (f2 && await f2.locator(".oe-content").count().catch(() => 0)) frame2 = f2;
      }
      ok("in-app navigation stays in the SAME slot and stays embedded", await pg.locator("#ioi-open-app").count() === 1 && !!frame2 && frame2.url().includes("embed=1"));
      ok("embedded explorer keeps ITS app-local chrome (hero + catalog)", !!frame2 && (await frame2.locator(".oe-content").isVisible().catch(() => false)) && !(await frame2.locator(".og-grail").isVisible().catch(() => true)));
      // Close → native navigation intact → reopen.
      await pg.click("#ioi-open-app .ioi-oa-close");
      await pg.waitForTimeout(400);
      ok("closing the app preserves native navigation (rail + Home explorer intact; still no Ontology rail item)", await rail.isVisible() && await pg.locator("#ioi-ontology-rail").count() === 0 && await pg.locator('[data-testid="ioi-home-explorer"]').count() === 1);
      // Reopen from the catalog — normal launcher behavior preserved.
      await pg.click('[data-testid="sidebar"] a[href="#applications"]');
      await pg.waitForSelector("#ioi-apps-modal.open", { timeout: 15000 });
      await pg.click('#ioi-apps-modal .ioi-mrow[data-name="Ontology"]');
      await pg.waitForSelector("#ioi-open-app iframe", { timeout: 15000 });
      ok("reopening uses the same singular slot (never a second one)", await pg.locator("#ioi-open-app").count() === 1 && await pg.locator("#ioi-open-app iframe").count() === 1);
    } finally {
      await b.close();
    }
  }
}

run().then(() => {
  const fails = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${results.length - fails.length}/${results.length} passed`);
  if (fails.length) process.exit(1);
  console.log("native-shell integration: OK");
}).catch((e) => {
  console.error("verifier crashed:", e);
  process.exit(1);
});

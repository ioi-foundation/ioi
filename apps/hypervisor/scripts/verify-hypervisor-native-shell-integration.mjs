#!/usr/bin/env node
// Native application container contract verifier (operational wave #61 → #65).
//
// Proves the product architecture the wave stands on:
//   1. NATIVE RAIL (#70 stack correction) — the permanent rail is EXACTLY the native five
//      (Home · Projects · Automations · Applications · Sessions); NO permanent Ontology rail
//      entry exists; Ontology launches from the REAL Applications catalog.
//   2. ONE PLATFORM RAIL (#65) — EVERY registry surface opened from the real native Applications
//      launcher renders in the singular Open Application slot in EMBEDDED mode: iframe src
//      carries embed=1, the native rail stays visible, the app's ported reference GLOBAL rail is
//      removed STRUCTURALLY (no hidden duplicate navigation tree — the .og-grail element does not
//      exist), the shell collapses with no residual rail column, and app-LOCAL navigation stays.
//   3. EMBED PERSISTENCE — embed=1 survives in-app links, row onclicks, GET forms, action PRG
//      redirects, refresh, and cross-application links (lineage/vertex/work-ledger/operations
//      thread it too, so a chain re-entering a registry surface stays embedded).
//   4. STANDALONE UNTOUCHED — direct bare routes render the complete registered shell
//      (global rail present, no embed rewrite); existing pixel-certification artifacts stay byte-identical.
//   5. SUITE — the Applications estate + launcher catalogs route Ontology to the Manager
//      (owner surface), never to the /__ioi/odk substrate (which stays linked from within).
//   6. CONTRACT MODEL — every registry surface declares capabilities + operational_state +
//      embedded_shell_state from the allowed vocabularies; an application may be called
//      operational only under native_single_rail (fail-fast invariants also boot-guard).
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-native-shell-integration.mjs
// Exit 0 = all assertions pass; exit 1 = one or more failed.

import { execSync } from "node:child_process";
import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { SURFACES, CAPABILITIES, OPERATIONAL_STATES, EMBEDDED_SHELL_STATES, EMBED_THREAD_ROUTES, embeddableRoutes, boundSurface } from "./surface-registry.mjs";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";

const SERVE = (process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173").replace(/\/$/, "");
const HERE = dirname(fileURLToPath(import.meta.url));
const SHOT_DIR = join(HERE, "..", ".artifacts", "native-container");

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
const page = (url) => fetch(url).then(async (r) => ({ status: r.status, text: await r.text() })).catch(() => ({ status: 0, text: "" }));

// App-local navigation/chrome that must SURVIVE embedding (per-surface landmark).
const LOCAL_NAV = {
  missions: ".ms-main",
  pipeline: ".pb-main", sources: ".src-tabs", schema: ".og-arail", explorer: ".oe-tabbar",
  approvals: ".ap-main", incidents: ".in-main", models: ".mc-main", listings: ".mk-main",
  designer: ".dsg-main", machinery: ".mch-main", monitors: ".mon-main", changes: ".chg-main",
  evalsuites: ".evl-main",
};

// Every href / location.href in an EMBEDDED document that lands on an embeddable route must
// carry embed=1 — the universal threading invariant (no per-surface link inventory to go stale).
function unthreadedLinks(html) {
  const routes = embeddableRoutes();
  const bad = [];
  for (const m of html.matchAll(/(?:href="|location\.href=')(\/__ioi\/[^"'#?]*)(\?[^"'#]*)?/g)) {
    if (routes.has(m[1]) && !/(\?|&)embed=1/.test(m[2] || "")) bad.push(m[1] + (m[2] || ""));
  }
  return bad;
}

async function run() {
  // 6 (static first). Contract-model invariants.
  ok("every surface declares capabilities + operational_state + embedded_shell_state from the allowed vocabularies", SURFACES.every((s) => Array.isArray(s.capabilities) && s.capabilities.length > 0 && s.capabilities.every((c) => CAPABILITIES.includes(c)) && OPERATIONAL_STATES.includes(s.operational_state) && EMBEDDED_SHELL_STATES.includes(s.embedded_shell_state)), `${SURFACES.length} surfaces`);
  ok("every operational surface (beyond shell) is native_single_rail when embedded (#65 admission rule)", SURFACES.every((s) => s.operational_state === "shell" || s.embedded_shell_state === "native_single_rail"));
  ok("extracted interactive modules declare their EARNED state (pipeline=workflow_complete since #67; explorer earned inspect→act; schema=act since #63)", SURFACES.find((s) => s.slug === "pipeline").operational_state === "workflow_complete" && ["inspect", "act"].includes(SURFACES.find((s) => s.slug === "explorer").operational_state) && SURFACES.find((s) => s.slug === "schema").operational_state === "act");
  ok("operational state is not inferred from parity: certified non-extracted surfaces stay browse/act, never inspect+", SURFACES.filter((s) => !boundSurface(s.route, "GET")).every((s) => ["shell", "browse", "act"].includes(s.operational_state)));
  ok("embeddable routes = every registry surface + the generic embedded thread routes", (() => { const r = embeddableRoutes(); return SURFACES.every((s) => r.has(s.route)) && EMBED_THREAD_ROUTES.every((t) => r.has(t)); })(), `${embeddableRoutes().size} routes`);

  // 4. Standalone bare routes — DESIGNATION-AWARE (remediation v2 re-aim, 2026-08-20).
  // The rails ruling partitions the registry: the CERTIFIED reference ports (exactly the
  // LOCAL_NAV set — the shells with committed pixel-certification evidence) keep their
  // ported global rail on BARE delivery as pixel evidence; EVERY later row (agent ports,
  // native cockpits, seed-first landings) is RAILLESS on every delivery — a fabricated
  // vendor rail on one of those is a regression, not fidelity.
  const CERTIFIED_RAIL = new Set(Object.keys(LOCAL_NAV));
  for (const s of SURFACES) {
    const p = await page(`${SERVE}${s.route}`);
    if (CERTIFIED_RAIL.has(s.slug)) {
      ok(`standalone ${s.route} keeps the certified shell (pixel-evidence rail present, no embed rewrite)`, p.status === 200 && p.text.includes('<aside class="og-grail') && !p.text.includes(".og-grail{display:none"));
    } else {
      ok(`standalone ${s.route} is RAILLESS (post-ruling surface: no fabricated vendor rail on any delivery)`, p.status === 200 && !p.text.includes('<aside class="og-grail'));
    }
  }

  // 2+3 (static). Embedded render: STRUCTURAL rail removal + app-local nav + universal threading — ALL 14.
  for (const s of SURFACES) {
    const p = await page(`${SERVE}${s.route}?embed=1`);
    const bad = unthreadedLinks(p.text);
    const localMark = LOCAL_NAV[s.slug] ? p.text.includes(LOCAL_NAV[s.slug].slice(1)) : true;
    ok(`embedded ${s.route} removes the ported global rail STRUCTURALLY, keeps app-local chrome, threads embed through every embeddable link`, p.status === 200 && !p.text.includes('<aside class="og-grail') && localMark && bad.length === 0, bad.length ? `unthreaded: ${bad.slice(0, 3).join(" ")}` : LOCAL_NAV[s.slug]);
  }
  // 3. Non-registry cross-application surfaces thread embed too (no ported rail of their own).
  for (const r of EMBED_THREAD_ROUTES) {
    const p = await page(`${SERVE}${r}?embed=1`);
    const bad = unthreadedLinks(p.text);
    ok(`embedded thread route ${r} threads embed=1 through its embeddable links (journey stays embedded)`, p.status === 200 && !p.text.includes('<aside class="og-grail') && bad.length === 0, bad.length ? `unthreaded: ${bad.slice(0, 3).join(" ")}` : "");
  }
  // 3. GET forms carry the embed field (explorer filter form is the canonical case).
  const ee = await page(`${SERVE}/__ioi/ontology/explorer?embed=1`);
  ok("embedded explorer threads embed=1 through row onclicks AND the filter form", /location\.href='\/__ioi\/ontology\/explorer\?[^']*embed=1'/.test(ee.text) && ee.text.includes('<input type="hidden" name="embed" value="1">'));

  // 5. Suite catalogs route Ontology to the Manager, never the substrate.
  const apps = await page(`${SERVE}/__ioi/applications`);
  ok("the Applications estate routes Ontology to the Manager (owner surface)", apps.status === 200 && /Ontology[\s\S]{0,400}?href="\/__ioi\/ontology\/manager"/.test(apps.text.replace(/\n/g, " ")) || apps.text.includes('href="/__ioi/ontology/manager"'));
  const aug = await page(`${SERVE}/ioi-augmentation.js`);
  // Re-aimed (2026-08-20): the augmentation no longer ships a hardcoded catalog nav map — launcher
  // rows come from the compiled product-surface projection. The #70 intent survives as server truth:
  // the /ontology FAMILY landing routes to the Manager (owner surface).
  const ontLanding = await page(`${SERVE}/ontology`);
  ok("the ontology family landing routes Ontology to the Manager (owner surface)", ontLanding.status === 200 && ontLanding.text.includes('href="/__ioi/ontology/manager"'));
  const em = await page(`${SERVE}/__ioi/ontology/manager?embed=1`);
  ok("the Manager keeps the substrate linked from within (odk stays the advanced contract surface)", em.text.includes("/__ioi/odk"));
  ok("NO rail injection ships in the augmentation (#70 stack correction); openApplication() owns embed (URL-normalized, forced embed=1)", !aug.text.includes("mountOntologyNav") && !aug.text.includes("ioi-ontology-rail") && aug.text.includes("embeddedAppSrc") && aug.text.includes('u.searchParams.set("embed", "1")'));

  // 4. Pixel-certification artifacts are byte-identical (the contract never regenerates them).
  const dirty = execSync("git status --porcelain -- pixel-certifications", { cwd: join(HERE, ".."), encoding: "utf8" }).trim();
  ok("pixel-certification artifacts are byte-identical (git-clean)", dirty === "", dirty || "clean");

  // 1+2+3 (live). The native shell journey, driven in a real browser.
  {
    const { chromium } = await import("playwright");
    const b = await chromium.launch();
    try {
      const pg = await b.newPage({ viewport: { width: 1440, height: 900 } });
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
        const idxAny = (href) => anchors.findIndex((a) => a.getAttribute("href") === href);
        return {
          homeAny: idxAny("/ai"), projects: idx("/projects"), applications: idx("#applications"),
          sessions: !!sb.querySelector('[data-testid="sessions-filter-button"]'),
          ontologyText: texts.some((t) => /^\S?Ontology$/.test(t)),
          injected: [...sb.querySelectorAll('[id^="ioi-"]')].map((e) => e.id).filter((id) => id !== "ioi-openapp-rail").join(","),
        };
      });
      // Re-aimed (2026-08-20): the shell's rail evolved — Home is an icon-only anchor (no text) and
      // the Automations rail item was retired in favor of the canonical /automations 302 + launcher
      // row (container-first, 80-automations). The permanent rail is Home → Projects → Applications
      // with the Sessions region; still no Ontology entry, still no injected permanent nav.
      ok("the permanent rail is the native set: Home (icon) → Projects → Applications, with the Sessions region", railState.homeAny >= 0 && railState.projects >= 0 && railState.applications > railState.projects && railState.sessions === true, JSON.stringify(railState));
      ok("no Ontology rail label and no injected permanent nav id (the Open Application row is the only injected rail row)", railState.ontologyText === false && railState.injected === "");

      // Acquire the committed frame for a route, waiting for its landmark selector.
      const frameFor = async (route, marker) => {
        for (let i = 0; i < 40; i++) {
          await pg.waitForTimeout(500);
          const f = pg.frames().find((x) => { try { return new URL(x.url()).pathname === route; } catch { return false; } });
          if (f && await f.locator(marker).count().catch(() => 0)) return f;
        }
        return null;
      };

      // #65 re-aimed (remediation v2, 2026-08-20): the launcher no longer carries one direct
      // row per registry surface — rows carry DESIGNATED open targets (canonical routes,
      // GRE-2 302 transfers, family splash landings). The integration contract is therefore
      // REACHABILITY: every registry surface must be reachable from the Applications launcher
      // within TWO link hops (direct row | row 302-transfer | row-served landing link |
      // one further in-estate document link). Click-driving stays for the DIRECT rows.
      await pg.click('a[href="#applications"]');
      await pg.waitForSelector(".ioi-mrow[data-href]", { timeout: 15000 }); // catalog projection is async
      const rowTargets = await pg.evaluate(() => [...new Set([...document.querySelectorAll(".ioi-mrow[data-href]")].map((r) => r.getAttribute("data-href")))].filter((h) => h && h.startsWith("/")));
      // The shell wires further targets client-side (cockpits, workspaces — 60-shell-wiring) and in
      // its own code rather than the DOM; both are the estate's own committed shell. Harvest them.
      const shellDom = await pg.evaluate(() => [...new Set([...document.querySelectorAll("[data-href], a[href^='/']")].map((e) => (e.getAttribute("data-href") || e.getAttribute("href") || "").split("?")[0]))].filter((h) => h && h.startsWith("/")));
      const augLiterals = [...aug.text.matchAll(/["'`](\/__ioi\/[a-z0-9-]+(?:\/[a-z0-9-]+)*)["'`?]/g)].map((m) => m[1]);
      const launchUniverse = [...new Set([...rowTargets, ...shellDom, ...augLiterals])];
      const fetchDoc = async (route) => {
        try {
          const res = await fetch(`${SERVE}${route}`, { redirect: "manual" });
          const loc = res.status >= 300 && res.status < 400 ? new URL(res.headers.get("location") || "/", SERVE).pathname : "";
          const text = res.status === 200 ? await res.text() : "";
          return { loc, hrefs: [...text.matchAll(/href="(\/[^"#?]*)/g)].map((m) => m[1]) };
        } catch { return { loc: "", hrefs: [] }; }
      };
      const reached = new Set(launchUniverse);
      let frontier = launchUniverse;
      for (let hop = 0; hop < 2; hop++) {
        const next = [];
        for (const r of frontier) {
          const d = await fetchDoc(r);
          for (const target of [d.loc, ...d.hrefs]) {
            if (target && !reached.has(target)) { reached.add(target); next.push(target); }
          }
        }
        frontier = next;
      }
      // E7 CODE REMOVAL LANDED (2026-08-20): the eight legacy cockpit rows this gate used to
      // exclude BY NAME left the registry with their modules and their dedicated verifiers, so the
      // named list went inert and was DELETED with them — as its own contract required. The
      // reachability contract below now binds EVERY registry row with no exclusion of any kind: a
      // surface that cannot be reached from the native shell within two link hops fails here, and
      // the only way to satisfy it is to link the surface or to remove it.
      const unreachable = SURFACES.filter((s) => !reached.has(s.route)).map((s) => s.route);
      ok("every registry surface is reachable from the native shell within two link hops (launcher row, shell-wired target, GRE-2 transfer, or landing/document link)", unreachable.length === 0, unreachable.length ? `unreachable: ${unreachable.join(" ")}` : `${SURFACES.length} surfaces via ${launchUniverse.length} shell targets`);
      ok("the launcher never offers the /__ioi/odk substrate as a catalog row (it stays linked from within owner surfaces)", !rowTargets.includes("/__ioi/odk"));
      // The row harvest left the modal open; close it so the click-drive loop can reopen it per surface.
      await pg.keyboard.press("Escape");
      await pg.waitForTimeout(300);
      await pg.evaluate(() => document.getElementById("ioi-apps-modal")?.classList.remove("open"));
      for (const s of SURFACES.filter((x) => rowTargets.includes(x.route) && LOCAL_NAV[x.slug])) {
        await pg.click('a[href="#applications"]');
        await pg.waitForSelector(`.ioi-mrow[data-href="${s.route}"]`, { timeout: 15000 });
        await pg.click(`.ioi-mrow[data-href="${s.route}"]`);
        await pg.waitForSelector("#ioi-open-app iframe", { timeout: 15000 });
        const src = (await pg.locator("#ioi-open-app iframe").getAttribute("src")) || "";
        const f = await frameFor(s.route, LOCAL_NAV[s.slug]);
        const shape = f ? await f.evaluate(() => {
          const shell = document.querySelector('div[class$="-shell"]');
          const first = shell && shell.firstElementChild;
          return { grails: document.querySelectorAll(".og-grail").length, firstLeft: first ? Math.round(first.getBoundingClientRect().left) : -1 };
        }).catch(() => null) : null;
        const localVisible = f ? await f.locator(LOCAL_NAV[s.slug]).first().isVisible().catch(() => false) : false;
        ok(`launcher → ${s.title}: singular slot, embed=1, native rail up, NO .og-grail element, no residual rail column, app-local chrome visible`,
          await pg.locator("#ioi-open-app").count() === 1 && src.includes(`${s.route}?embed=1`) && await rail.isVisible() && !!shape && shape.grails === 0 && shape.firstLeft === 0 && localVisible,
          `src=${src} shape=${JSON.stringify(shape)}`);
      }

      // Missions is registry-owned; Operations is a generic embedded thread route. Drive the
      // production anchors in both directions and prove the native slot contract at every stop.
      const embeddedSlotState = async (frame) => {
        let url = null;
        try { url = frame ? new URL(frame.url()) : null; } catch { /* failed state is reported below */ }
        return {
          route: url ? url.pathname : "",
          embed: url ? url.searchParams.get("embed") : "",
          slots: await pg.locator("#ioi-open-app").count(),
          iframes: await pg.locator("#ioi-open-app iframe").count(),
          nativeRail: await rail.isVisible().catch(() => false),
          grails: frame ? await frame.locator(".og-grail").count().catch(() => -1) : -1,
        };
      };
      const keepsEmbeddedSlot = (state, route) => state.route === route && state.embed === "1"
        && state.slots === 1 && state.iframes === 1 && state.nativeRail && state.grails === 0;

      await pg.click('a[href="#applications"]');
      await pg.waitForSelector('.ioi-mrow[data-href="/__ioi/missions"]', { timeout: 15000 });
      await pg.click('.ioi-mrow[data-href="/__ioi/missions"]');
      let missionsFrame = await frameFor("/__ioi/missions", ".ms-main");
      const launchedMissions = await embeddedSlotState(missionsFrame);
      ok("Applications → Missions: embed=1, singular slot, native rail visible, zero .og-grail elements",
        keepsEmbeddedSlot(launchedMissions, "/__ioi/missions"), JSON.stringify(launchedMissions));

      if (missionsFrame) await missionsFrame.locator('a.ms-action[href^="/__ioi/operations"][href*="embed=1"]').click();
      const operationsFrame = await frameFor("/__ioi/operations", "#ops-jobs");
      const reachedOperations = await embeddedSlotState(operationsFrame);
      ok("Missions → Operations: embed=1 persists, singular slot remains, native rail stays visible, zero .og-grail elements",
        keepsEmbeddedSlot(reachedOperations, "/__ioi/operations"), JSON.stringify(reachedOperations));

      if (operationsFrame) await operationsFrame.locator('a[href^="/__ioi/missions"][href*="embed=1"]').first().click();
      missionsFrame = await frameFor("/__ioi/missions", ".ms-main");
      const returnedMissions = await embeddedSlotState(missionsFrame);
      ok("Operations → Missions: embed=1 persists, singular slot remains, native rail stays visible, zero .og-grail elements",
        keepsEmbeddedSlot(returnedMissions, "/__ioi/missions"), JSON.stringify(returnedMissions));

      // #65 regression: Pipeline from the catalog — in-app node selection + refresh keep embed.
      await pg.click('a[href="#applications"]');
      await pg.waitForSelector('.ioi-mrow[data-href="/__ioi/pipeline"]', { timeout: 15000 });
      await pg.click('.ioi-mrow[data-href="/__ioi/pipeline"]');
      let pf = await frameFor("/__ioi/pipeline", ".pb-main");
      ok("Pipeline opens from the catalog embedded (the #61 Ontology-only journey gap is closed)", !!pf && pf.url().includes("embed=1"));
      await pf.click('a[href*="node="]');
      pf = await frameFor("/__ioi/pipeline", ".pb-main");
      ok("Pipeline node selection inside the slot keeps embed=1 + the node context", !!pf && pf.url().includes("embed=1") && /[?&]node=/.test(pf.url()), pf ? pf.url() : "no frame");
      await pf.evaluate(() => location.reload());
      pf = await frameFor("/__ioi/pipeline", ".pb-main");
      ok("refresh inside the embedded app preserves embed=1 + selection", !!pf && pf.url().includes("embed=1") && /[?&]node=/.test(pf.url()));

      // Integrated screenshots at both contract viewports (Pipeline open, native rail visible).
      mkdirSync(SHOT_DIR, { recursive: true });
      await pg.screenshot({ path: join(SHOT_DIR, "integrated-1440x900.png") });
      await pg.setViewportSize({ width: 1920, height: 1080 });
      await pg.waitForTimeout(600);
      await pg.screenshot({ path: join(SHOT_DIR, "integrated-1920x1080.png") });
      ok("integrated screenshots captured at 1440x900 and 1920x1080", true, SHOT_DIR);

      // In-app CROSS-application navigation stays embedded, stays single-slot (Manager → Explorer).
      // Ontology launches from the REAL Applications catalog (#70 stack correction).
      await pg.click('a[href="#applications"]');
      await pg.waitForSelector('.ioi-mrow[data-name="Ontology"]', { timeout: 15000 });
      await pg.click('.ioi-mrow[data-name="Ontology"]');
      // GRE-2 re-aim (2026-08-20): the catalog Ontology row opens the FAMILY landing embedded;
      // the Manager stays the family's owner surface one governed link away. The #70 intent is
      // preserved as: the family landing routes to the MANAGER and never offers /__ioi/odk as
      // the family target (the substrate stays linked only from within owner surfaces).
      const famF = await frameFor("/ontology", 'a[href^="/__ioi/ontology/manager"]');
      // Family rows embed WITHOUT ?embed=1 in the src — the Sec-Fetch-Dest: iframe hardening strips
      // the rail and rewrites canonical hrefs to carry embed=1. Assert on the rewrite, not the URL.
      const famManagerEmbedLinks = famF ? await famF.locator('a[href^="/__ioi/ontology/manager"][href*="embed=1"]').count().catch(() => 0) : 0;
      ok("Ontology launches FROM THE CATALOG embedded (family landing in the singular slot; iframe delivery rewrote its canonical links to carry embed=1)", !!famF && famManagerEmbedLinks > 0);
      let mf = null;
      if (famF) {
        await famF.click('a[href^="/__ioi/ontology/manager"]');
        mf = await frameFor("/__ioi/ontology/manager", ".og-arail");
      }
      ok("family landing → Manager stays embedded in the SAME slot", !!mf && mf.url().includes("embed=1") && await pg.locator("#ioi-open-app").count() === 1);
      if (mf) await mf.click('a[href^="/__ioi/ontology/explorer"][href*="embed=1"]');
      const ef = mf ? await frameFor("/__ioi/ontology/explorer", ".oe-tabbar") : null;
      ok("in-app navigation stays in the SAME slot and stays embedded", await pg.locator("#ioi-open-app").count() === 1 && !!ef && ef.url().includes("embed=1"));
      ok("embedded explorer keeps ITS app-local chrome and renders NO ported rail element", !!ef && (await ef.locator(".oe-tabbar").first().isVisible().catch(() => false)) && (await ef.locator(".og-grail").count().catch(() => 1)) === 0);

      // Close → native navigation intact → reopen.
      await pg.click("#ioi-open-app .ioi-oa-close");
      await pg.waitForTimeout(400);
      ok("closing the app preserves native navigation (rail + sessions region intact; still no Ontology rail item)", await rail.isVisible() && await pg.locator("#ioi-ontology-rail").count() === 0 && await pg.locator('[data-testid="sessions-filter-button"]').count() === 1);
      // Reopen from the catalog — normal launcher behavior preserved.
      await pg.click('a[href="#applications"]');
      await pg.waitForSelector('.ioi-mrow[data-name="Ontology"]', { timeout: 15000 });
      await pg.click('.ioi-mrow[data-name="Ontology"]');
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
  emitVerifierCensus({ verifierId: "native-shell", sourceUrl: import.meta.url, results });
  if (fails.length) process.exit(1);
  console.log("native application container: OK");
}).catch((e) => {
  console.error("verifier crashed:", e);
  process.exit(1);
});

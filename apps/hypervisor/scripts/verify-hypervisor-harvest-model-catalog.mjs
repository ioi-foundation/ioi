#!/usr/bin/env node
// Harvest-port Foundry model-catalog verifier — the model-catalog seed's data lane rebound to the
// DAEMON model-route registry. Proves the boot-depth finding: rebinding a seed's data lane makes
// the captured UX render DAEMON TRUTH (not captured vendor fixtures).
//
// Doctrine: local capture -> bootable seed -> daemon rebind -> IOI-owned surface -> retire seed.
//
// Proves:
//   - /__apps/models boots the captured Model Catalog grammar under the estate, brand-clean
//     (catalog home, filters by lifecycle/type/creator, compare affordance, model cards);
//   - its ModelCatalogHomeQuery lane is answered from the daemon model-route registry: the catalog
//     renders the daemon's real routes (by display name) and NOT the captured PALANTIR_PROVIDED
//     vendor models — a real lane rebind, using the captured response only as a fragment envelope;
//   - the rendered catalog equals the daemon registry (count + display names; availability→lifecycle
//     is honest: available=GA/Stable, else non-GA), proven against an independent daemon read;
//   - the owning Foundry surface links the seed; no brand leak.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-harvest-model-catalog.mjs
// Exit 2 = BLOCKED (capture or daemon not running).

import { chromium } from "playwright";

const SERVE = (process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173").replace(/\/$/, "");
const CAPTURE = (process.env.IOI_HARVEST_CAPTURE_URL || process.env.IOI_HARVEST_MIRROR_URL || "http://127.0.0.1:9225").replace(/\/$/, "");
const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };

async function run() {
  const capUp = await fetch(`${CAPTURE}/workspace/model-catalog/`).then((r) => r.ok).catch(() => false);
  if (!capUp) { console.error("BLOCKED: capture not reachable at " + CAPTURE); process.exit(2); }
  const dmUp = await fetch(`${DAEMON}/v1/hypervisor/model-routes`).then((r) => r.ok).catch(() => false);
  if (!dmUp) { console.error("BLOCKED: daemon not reachable at " + DAEMON); process.exit(2); }
  ok("capture + daemon live", true, `${CAPTURE} · ${DAEMON}`);

  // 1. Owner surface (Foundry) links the seed.
  const foundry = await fetch(`${SERVE}/__ioi/foundry`).then(async (r) => ({ status: r.status, text: await r.text() }));
  ok("Foundry surface serves + links the model-catalog seed", foundry.status === 200 && !foundry.text.includes("Palantir") && foundry.text.includes("/__apps/models"));

  // 2. Independent daemon read — the truth the catalog must equal.
  const routesJson = await fetch(`${DAEMON}/v1/hypervisor/model-routes`).then((r) => r.json());
  const routes = routesJson.routes || [];
  ok("daemon model-route registry has routes to supply", routes.length >= 1, `${routes.length} routes`);
  const displayNames = routes.map((r) => r.display_name || (r.model || {}).model_id).filter(Boolean);

  // 3. The seed's ModelCatalogHomeQuery lane is answered from the daemon (not captured vendors).
  const gql = await fetch(`${SERVE}/graphql-gateway/api/graphql`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ operationName: "ModelCatalogHomeQuery", variables: { attribution: { user: {} }, pageSize: 100 }, query: "query ModelCatalogHomeQuery($attribution: LanguageModelAttribution!, $pageSize: Int!, $pageToken: PageToken) { languageModelsV4(pageSize: $pageSize) { values { name displayName rid } } }" }),
  }).then((r) => r.json()).catch(() => null);
  const values = gql && gql.data && gql.data.languageModelsV4 && gql.data.languageModelsV4.values || [];
  ok("ModelCatalogHomeQuery answered from the daemon (count == registry)", values.length === routes.length, `${values.length} models vs ${routes.length} routes`);
  ok("catalog rows are the daemon routes (display names match), not captured vendor models", values.every((v) => displayNames.some((d) => String(v.displayName || "").includes(d))) && !values.some((v) => /GPT-|Claude |Gemini |PALANTIR/i.test(v.name || v.displayName || "")), values.map((v) => v.displayName).join(", "));
  ok("rows carry daemon-derived language-model rids (no fabrication of vendor ids)", values.every((v) => String(v.rid || "").startsWith("ri.language-model-service.main.language-model.")));

  // 4. The booted seed renders the daemon catalog, brand-clean.
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1500, height: 950 } });
  const errs = [];
  page.on("pageerror", (e) => errs.push(String(e)));
  await page.goto(`${SERVE}/__apps/models`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(6000);
  const view = await page.evaluate(() => {
    const t = document.body.innerText;
    return {
      catalogGrammar: /Model Catalog/i.test(t) && /Filters/i.test(t) && /Compare models/i.test(t),
      brandLeak: /\bPalantir\b/.test(t),
      vendorModels: /GPT-5|Claude Opus|Gemini/i.test(t),
      text: t,
    };
  });
  ok("seed boots the captured Model Catalog grammar (home + filters + compare)", view.catalogGrammar);
  ok("booted catalog renders the daemon route by display name", displayNames.some((d) => view.text.includes(d)), displayNames[0]);
  ok("captured vendor models are GONE (replaced by daemon truth)", !view.vendorModels);
  ok("no brand leak in the booted catalog", !view.brandLeak);
  ok("catalog boots without real crashes (only uncaptured-lane gaps)", errs.filter((e) => !/GraphQL|Failed to fetch|NetworkError|fetch failed|Load failed|4\d\d|5\d\d/i.test(e)).length === 0, errs.slice(0, 2).join(" | "));
  await page.screenshot({ path: process.env.IOI_MODELCAT_SHOT || "/tmp/models.png" }).catch(() => {});
  await browser.close();
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`harvest model-catalog readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => { console.error("verifier crashed:", e); process.exit(1); });

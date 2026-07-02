#!/usr/bin/env node
// Source-grafted surface parity done-bar.
//
// Asserts the fidelity grafts from the Palantir crosswalk parity pass are live and daemon-backed,
// and that no estate surface whose source shape is a console/cockpit/catalog remains a bare table:
//   - Environments: master-detail LIFECYCLE CONSOLE — rows select into a detail drawer that loads
//     the real daemon env record (component phases, observations, ports/services/tasks, isolation).
//   - Work Ledger: EXECUTABLE CROSS-REFERENCE MAP — drawer renders cross-object refs as navigable
//     backlinks so the governed lifecycle is traversable from one proof.
//   - Operations: OPERATE CONSOLE — run rows select into a drawer joining the run to its scheduler
//     record, with in-surface proof ref + remediation (re-run / pause) on the existing lanes.
//   - Connections: REGISTRY WITH DRILLDOWN — connector cards select into a drawer with the tool/
//     scope contract table and the actual capability leases issued (sealed secrets never serialized).
//   - Workbench: MASTER-DETAIL WORKING SHELL — env rows select into a pane composing bound sessions
//     (admitted harness bindings) + the probed editor-target open matrix.
//   - Agent Studio: EDITOR-WITH-TABS shell (Configuration / Harness profiles / Model routes /
//     Activity) with #hash deep-links (Work Ledger backlinks land on their tab).
//   - ODK: BIDIRECTIONAL LINEAGE — detail pages render "Referenced by" (reverse refs), proven on a
//     self-created + self-deleted draft fixture chain.
//   - Marketplace: listing detail carries LISTING-LEVEL admission readiness before any candidate.
//
// Playwright-driven against the live app. Usage:
//   node apps/hypervisor/scripts/verify-hypervisor-surface-parity.mjs
// Optional: IOI_PARITY_SHOTS_DIR=/path → writes a screenshot per estate surface.

import { chromium } from "playwright";
import { mkdirSync } from "node:fs";

const SHELL = (process.env.IOI_HYPERVISOR_APP_URL || "http://127.0.0.1:4173").replace(/\/$/, "");
const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };

async function run() {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1500, height: 950 } });
  const consoleErrors = [];
  const failedUrls = [];
  page.on("requestfailed", (r) => failedUrls.push(r.url()));
  page.on("console", (m) => {
    if (m.type() !== "error") return;
    if (/Failed to load resource/.test(m.text()) && failedUrls.every((u) => u.startsWith("https://docs.ioi.com/"))) return;
    consoleErrors.push(m.text());
  });
  page.on("pageerror", (e) => consoleErrors.push(String(e)));

  // ── Environments: lifecycle console master-detail ──
  await page.goto(`${SHELL}/__ioi/environments`, { waitUntil: "domcontentloaded" });
  await page.waitForSelector(".envrow", { timeout: 20000 });
  ok("Environments is a master-detail console (selectable rows + detail drawer)", await page.locator("#env-drawer").count() === 1 && await page.locator(".envrow").count() >= 1);
  await page.evaluate(() => document.querySelector(".envrow").click());
  await page.waitForSelector("#env-drawer .envd-k", { timeout: 15000 });
  const sections = await page.locator("#env-drawer .envd-k").allTextContents();
  ok("detail drawer loads the real daemon lifecycle record", sections.some((s) => /Component phases/.test(s)) && sections.some((s) => /Lifecycle observations/.test(s)) && sections.some((s) => /Ports/.test(s)), sections.join(" | "));
  const compPills = await page.locator("#env-drawer .envd-comp .pill").count();
  ok("component phase pills rendered from the daemon record (not fabricated)", compPills >= 4, `${compPills} components`);
  const obsCount = await page.locator("#env-drawer .envd-obs").count();
  ok("lifecycle observations timeline rendered", obsCount >= 1, `${obsCount} observations`);
  ok("substrate posture chips present (resource substrate honesty)", await page.locator(".chips .pill").count() >= 1);

  // ── Work Ledger: executable cross-reference map (navigable backlinks) ──
  await page.goto(`${SHELL}/__ioi/work-ledger`, { waitUntil: "domcontentloaded" });
  await page.waitForSelector(".wlrow", { timeout: 20000 });
  ok("Work Ledger renders the multi-kind proof stream (runs + harness + lifecycle)", (await page.locator(".wlrow").count()) >= 1 && (await page.locator('.chip[data-val="harness_execution"]').count()) === 1);
  // Prefer a harness_execution row (rich backlinks); else the first row.
  const hx = page.locator('.wlrow[data-kind="harness_execution"]').first();
  const target = (await hx.count()) ? hx : page.locator(".wlrow").first();
  await target.click();
  await page.waitForFunction(() => /Backlinks|State root/.test(document.getElementById("wl-drawer")?.textContent || ""), null, { timeout: 10000 });
  const drawerText = await page.locator("#wl-drawer").innerText();
  ok("drawer names the state_root proof", /State root/.test(drawerText) && /(fnv:|sha256:)/.test(drawerText));
  if (await hx.count()) {
    const links = await page.locator("#wl-drawer .wlbl a").count();
    ok("harness run drawer exposes navigable backlinks (cross-reference map)", /backlinks/i.test(drawerText) && links >= 2, `${links} backlinks`);
    const sessionLink = await page.locator('#wl-drawer .wlbl a[href="/__ioi/agent-studio#harness-profiles"], #wl-drawer .wlbl a[href="/__ioi/workbench#sessions"]').count();
    ok("backlinks route into the owning estate surfaces", sessionLink >= 1);
  } else {
    ok("harness run backlinks lane skipped (no harness_execution entry yet)", true);
    ok("(skipped) backlink routing", true);
  }

  // ── Operations: operate console (run row → drawer join + remediation + in-surface proof) ──
  await page.goto(`${SHELL}/__ioi/operations`, { waitUntil: "domcontentloaded" });
  ok("Operations is a master-detail operate console (drawer present)", await page.locator("#ops-drawer").count() === 1);
  if (await page.locator(".oprow").count()) {
    await page.locator(".oprow").first().click();
    await page.waitForFunction(() => /Scheduler posture|Remediation/.test(document.getElementById("ops-drawer")?.textContent || ""), null, { timeout: 10000 });
    const opsText = await page.locator("#ops-drawer").innerText();
    ok("run drawer joins the scheduler record in-payload", /Scheduler posture/i.test(opsText));
    ok("run drawer carries the proof ref (Run Timeline)", /Proof/i.test(opsText) && (await page.locator('#ops-drawer a[href^="/__ioi/run-timeline/"]').count()) >= 1);
    ok("remediation acts on the existing automation lanes (re-run, back=ops)", (await page.locator('#ops-drawer form[action*="/run?back=ops"]').count()) === 1);
  } else {
    ok("(skipped) run drawer join — no runs recorded yet", true);
    ok("(skipped) proof ref", true);
    ok("(skipped) remediation lane", true);
  }

  // ── Connections: registry with per-connector drilldown ──
  await page.goto(`${SHELL}/__ioi/connections`, { waitUntil: "domcontentloaded" });
  ok("Connections has a drilldown drawer (registry, not a flat card list)", await page.locator("#cn-drawer").count() === 1);
  if (await page.locator(".cncard").count()) {
    await page.locator(".cncard").first().click();
    await page.waitForFunction(() => /Tool contracts/.test(document.getElementById("cn-drawer")?.textContent || ""), null, { timeout: 10000 });
    const cnText = await page.locator("#cn-drawer").innerText();
    ok("connector drawer exposes the tool/scope contract table", /Tool contracts/i.test(cnText));
    ok("connector drawer lists the capability leases issued against it", /Capability leases issued/i.test(cnText));
    const html = await page.content();
    ok("sealed credentials are never serialized to the cockpit", !html.includes("sealed_client_secret"));
  } else {
    ok("(skipped) connector drilldown — no connectors registered", true);
    ok("(skipped) lease rows", true);
    ok("(skipped) secret-serialization guard", true);
  }

  // ── Workbench: master-detail working shell over env + sessions + editor matrix ──
  await page.goto(`${SHELL}/__ioi/workbench`, { waitUntil: "domcontentloaded" });
  ok("Workbench is a master-detail shell (selection pane present)", await page.locator("#wb-drawer").count() === 1);
  if (await page.locator(".wbrow").count()) {
    await page.locator(".wbrow").first().click();
    await page.waitForFunction(() => /Open with/.test(document.getElementById("wb-drawer")?.textContent || ""), null, { timeout: 10000 });
    const wbText = await page.locator("#wb-drawer").innerText();
    ok("selected env composes bound sessions (admitted harness bindings)", /Sessions bound/i.test(wbText));
    ok("selected env composes the probed editor-target open matrix", /Open with/i.test(wbText) && (await page.locator('#wb-drawer a[href^="/workspaces/"]').count()) >= 1);
  } else {
    ok("(skipped) env selection — no active environments", true);
    ok("(skipped) editor matrix", true);
  }

  // ── Agent Studio: editor-with-tabs shell + hash deep-links ──
  await page.goto(`${SHELL}/__ioi/agent-studio`, { waitUntil: "domcontentloaded" });
  const tabCount = await page.locator("#astabs .tab").count();
  if (tabCount) {
    ok("Agent Studio detail is an editor-with-tabs shell", tabCount === 4, `${tabCount} tabs`);
    ok("default tab shows configuration", await page.locator('.aspanel.on[data-aspanel="config"]').count() === 1);
    await page.locator('#astabs .tab[data-astab="harness-profiles"]').click();
    ok("harness-profiles tab activates its registry panel", await page.locator('.aspanel.on[data-aspanel="harness-profiles"]').count() === 1);
    await page.goto(`${SHELL}/__ioi/agent-studio#model-routes`, { waitUntil: "domcontentloaded" });
    await page.waitForFunction(() => document.querySelector('.aspanel.on')?.getAttribute("data-aspanel") === "model-routes", null, { timeout: 10000 });
    ok("Work Ledger backlink hash (#model-routes) deep-links onto its tab", true);
  } else {
    ok("(skipped) Agent Studio tabs — no agents yet (registry-only view)", true);
    ok("(skipped) default tab", true);
    ok("(skipped) tab activation", true);
    ok("(skipped) hash deep-link", true);
  }

  // ── ODK: bidirectional lineage, proven on a self-created draft fixture chain ──
  const J = (p, init) => fetch(`${DAEMON}${p}`, init).then((r) => r.json()).catch(() => ({}));
  const POST = (p, bodyObj) => J(p, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(bodyObj) });
  const DEL = (p) => fetch(`${DAEMON}${p}`, { method: "DELETE" }).catch(() => {});
  const sfx = `parity-${process.pid}-${Math.floor(Math.random() * 1e6)}`;
  const ontR = await POST("/v1/hypervisor/odk/domain-ontologies", { domain: sfx, version: "0.1.0", description: "parity verifier fixture", canonical_object_model: { objects: ["run"], actions: ["inspect"], events: [], states: ["draft"], roles: ["operator"] } });
  const ont = ontR.ontology || {};
  let listingId = "", manifestId = "", descriptorId = "", recipeId = "";
  if (ont.id) {
    const recR = await POST("/v1/hypervisor/odk/data-recipes", { name: `${sfx}-recipe`, description: "fixture", ontology_ref: ont.ref, output_kind: "ontology_objects", source_refs: [], connector_mappings: [], policy_bound_views: [] });
    recipeId = recR.data_recipe?.id || "";
    const desR = await POST("/v1/hypervisor/odk/surface-descriptors", { name: `${sfx}-surface`, description: "fixture", ontology_ref: ont.ref, composition_pattern: "list_detail", recipe_refs: recR.data_recipe ? [recR.data_recipe.ref] : [] });
    descriptorId = desR.surface_descriptor?.id || "";
    const manR = await POST("/v1/hypervisor/odk/manifests", { name: `${sfx}-manifest`, description: "fixture", ontology_refs: [ont.ref], recipe_refs: recR.data_recipe ? [recR.data_recipe.ref] : [], surface_descriptor_refs: desR.surface_descriptor ? [desR.surface_descriptor.ref] : [], eval_refs: [], worker_plan_refs: [], mcp_operator_contracts: [] });
    manifestId = manR.manifest?.id || "";
    await page.goto(`${SHELL}/__ioi/odk/ontologies/${encodeURIComponent(ont.id)}`, { waitUntil: "domcontentloaded" });
    const odkText = await page.locator("body").innerText();
    ok("ODK ontology detail renders reverse lineage (Referenced by)", /Referenced by \(3\)/i.test(odkText), (odkText.match(/Referenced by \(\d+\)/i) || [])[0]);
    ok("reverse-lineage hits link back into their owning family pages", (await page.locator('a.card[href^="/__ioi/odk/manifests/"]').count()) >= 1 && (await page.locator('a.card[href^="/__ioi/odk/data-recipes/"]').count()) >= 1);
    // ── Marketplace: listing-level admission readiness (pre-candidate) ──
    const listR = await POST("/v1/hypervisor/marketplace/listings", { name: `${sfx}-listing`, description: "parity verifier fixture", listing_kind: "ontology_pack", subject_ref: manR.manifest?.ref || "", evidence_refs: [] });
    listingId = listR.listing?.id || "";
    if (listingId) {
      await page.goto(`${SHELL}/__ioi/marketplace/listings/${encodeURIComponent(listingId)}`, { waitUntil: "domcontentloaded" });
      const mpText = await page.locator("body").innerText();
      ok("listing detail carries listing-level admission readiness before any candidate", /Admission readiness/i.test(mpText) && /auth (enforced|not enforced)/i.test(mpText) && /gaps: \d+/.test(mpText));
    } else {
      ok("marketplace listing fixture creation failed (daemon rejected)", false, JSON.stringify(listR.error || {}));
    }
  } else {
    ok("ODK fixture creation failed (daemon rejected)", false, JSON.stringify(ontR.error || {}));
    ok("(skipped) reverse-lineage links", false);
    ok("(skipped) marketplace readiness", false);
  }
  // Fixture teardown — the verifier leaves no draft debris.
  if (listingId) await DEL(`/v1/hypervisor/marketplace/listings/${encodeURIComponent(listingId)}`);
  if (manifestId) await DEL(`/v1/hypervisor/odk/manifests/${encodeURIComponent(manifestId)}`);
  if (descriptorId) await DEL(`/v1/hypervisor/odk/surface-descriptors/${encodeURIComponent(descriptorId)}`);
  if (recipeId) await DEL(`/v1/hypervisor/odk/data-recipes/${encodeURIComponent(recipeId)}`);
  if (ont.id) await DEL(`/v1/hypervisor/odk/domain-ontologies/${encodeURIComponent(ont.id)}`);

  // ── Screenshots: one per estate surface (acceptance evidence) ──
  const shotsDir = process.env.IOI_PARITY_SHOTS_DIR || "";
  if (shotsDir) {
    mkdirSync(shotsDir, { recursive: true });
    const surfaces = ["workbench", "environments", "agent-studio", "foundry", "odk", "domain-apps", "connections", "governance", "operations", "work-ledger", "marketplace"];
    for (const s of surfaces) {
      await page.goto(`${SHELL}/__ioi/${s}`, { waitUntil: "networkidle" }).catch(() => {});
      await page.screenshot({ path: `${shotsDir}/${s}.png`, fullPage: false }).catch(() => {});
    }
    ok("estate screenshots captured", true, `${surfaces.length} surfaces → ${shotsDir}`);
  }

  await page.screenshot({ path: process.env.IOI_PARITY_SHOT || "/tmp/parity.png", fullPage: false }).catch(() => {});
  ok("no console errors across the grafted surfaces", consoleErrors.length === 0, consoleErrors.slice(0, 2).join(" | "));
  await browser.close();
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`surface parity readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => {
  console.error("verifier crashed:", e);
  process.exit(1);
});

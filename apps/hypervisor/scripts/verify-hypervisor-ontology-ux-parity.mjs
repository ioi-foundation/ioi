#!/usr/bin/env node
// Ontology-manager UX-GRAMMAR PARITY done-bar (Playwright).
//
// The product goal is "Palantir-familiar UX first, then re-authored underneath": the primary ODK
// surface must begin from the recognizable Ontology Manager grammar, backed by IOI daemon truth, with
// unsupported lanes shown HONESTLY empty. This verifier compares the LOCAL reference Ontology Manager
// against the Hypervisor owner surface at the UX-GRAMMAR level (headings / panes / core flow / empty
// states / no brand-or-reference leak) — NOT byte parity (byte parity is explicitly not the goal).
//
// Reference:  http://127.0.0.1:9225/workspace/ontology/   (the local Palantir capture)
// Hypervisor: http://127.0.0.1:4173/__ioi/odk             (the re-authored owner surface)
//
// Asserts:
//   1. The reference exposes the manager grammar (object/link/action types, properties, functions,
//      health, configuration) — so we are measuring against the real reference IA.
//   2. Hypervisor MIRRORS that grammar as its primary surface (same panes), titled "Ontology Manager".
//   3. Each pane is backed by DAEMON TRUTH (a created fixture's object/link/value/action/function
//      render; readiness is honest).
//   4. Unsupported lanes are HONEST: 0 objects boundary, Groups/Interfaces/Explorer unavailable, and
//      the four missing authority contracts are named (ConnectorMapping, PolicyBoundDataView,
//      TransformationRun, OntologyProjection).
//   5. IOI authority is threaded in (daemon truth, receipts, substrate readiness, conformance gap).
//   6. Captures stay secondary; NO brand/reference leak (no "Palantir"/"Foundry") on our surface; no
//      request failures on the owner surface.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-ontology-ux-parity.mjs
// Exit 2 = BLOCKED (a server or the browser is unavailable — never a silent pass).

import { chromium } from "playwright";

const SHELL = (process.env.IOI_HYPERVISOR_APP_URL || "http://127.0.0.1:4173").replace(/\/$/, "");
const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
const REFERENCE = (process.env.IOI_HARVEST_CAPTURE_URL || process.env.IOI_HARVEST_MIRROR_URL || "http://127.0.0.1:9225").replace(/\/$/, "");

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
const has = (text, ...needles) => needles.every((n) => new RegExp(n, "i").test(text));

// The reference Ontology Manager grammar (stable tokens from the local capture nav).
const GRAMMAR = ["Object types", "Properties", "Link types", "Action types", "Functions", "Health", "configuration"];

const READY_ONTOLOGY = {
  domain: "ux-parity-lending",
  canonical_object_model: {
    value_types: [{ id: "money", name: "Money", base: "double" }],
    object_types: [
      { id: "loan", name: "Loan", title_property: "title", properties: [
        { id: "title", name: "Title", value_type: "string" }, { id: "amount", name: "Amount", value_type: "money" },
      ] },
      { id: "borrower", name: "Borrower", title_property: "name", properties: [{ id: "name", name: "Name", value_type: "string" }] },
    ],
    link_types: [{ id: "held_by", name: "Held by", from: "loan", to: "borrower", cardinality: "one_to_many" }],
    action_types: [{ id: "approve", name: "Approve", kind: "modify_object", applies_to: "loan" }, { id: "score", name: "Score", kind: "function" }],
  },
};

async function daemonUp() {
  return fetch(`${DAEMON}/v1/hypervisor/odk/overview`).then((r) => r.ok).catch(() => false);
}
async function innerTextOf(page, url, waitMs = 1200) {
  await page.goto(url, { waitUntil: "domcontentloaded", timeout: 20000 });
  await page.waitForTimeout(waitMs); // let the reference SPA hydrate its nav
  return page.locator("body").innerText().catch(() => "");
}

async function run() {
  if (!(await daemonUp())) { console.error("BLOCKED: daemon not reachable at " + DAEMON); process.exit(2); }
  const refUp = await fetch(`${REFERENCE}/workspace/ontology/`).then((r) => r.ok).catch(() => false);
  if (!refUp) { console.error("BLOCKED: reference capture not reachable at " + REFERENCE); process.exit(2); }

  // Fixture: a ready ontology so the manager panes have daemon-backed content.
  const created = await fetch(`${DAEMON}/v1/hypervisor/odk/domain-ontologies`, {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(READY_ONTOLOGY),
  }).then((r) => r.json()).catch(() => ({}));
  const ontId = created?.ontology?.id;
  if (!ontId) { console.error("BLOCKED: could not create the ontology fixture"); process.exit(2); }

  let browser;
  try {
    browser = await chromium.launch();
  } catch (e) {
    console.error("BLOCKED: chromium unavailable — " + (e && e.message));
    await fetch(`${DAEMON}/v1/hypervisor/odk/domain-ontologies/${ontId}`, { method: "DELETE" }).catch(() => {});
    process.exit(2);
  }

  try {
    const page = await browser.newPage({ viewport: { width: 1500, height: 950 } });
    const ownerFailures = [];
    let recording = false;
    page.on("requestfailed", (r) => { if (recording && r.url().includes("/__ioi/")) ownerFailures.push(r.url()); });

    // 1. The reference exposes the manager grammar.
    const refText = await innerTextOf(page, `${REFERENCE}/workspace/ontology/`, 1800);
    ok("reference loads as an Ontology Manager", /Ontology Manager/i.test(refText));
    ok("reference exposes the manager grammar (object/link/action types, properties, functions, health, config)", has(refText, ...GRAMMAR), GRAMMAR.filter((g) => !new RegExp(g, "i").test(refText)).join(",") || "all present");

    // 2. Hypervisor mirrors the grammar as its PRIMARY surface, backed by daemon truth.
    recording = true;
    const mgr = await innerTextOf(page, `${SHELL}/__ioi/odk?ontology=${encodeURIComponent(ontId)}`, 400);
    recording = false;
    ok("Hypervisor primary ODK surface is titled 'Ontology Manager'", /Ontology Manager/.test(await page.title()) || /Ontology Manager/.test(mgr));
    const missingGrammar = GRAMMAR.filter((g) => !new RegExp(g, "i").test(mgr));
    ok("Hypervisor mirrors the full reference grammar (same manager panes)", missingGrammar.length === 0, missingGrammar.join(",") || "all present");
    ok("Hypervisor adds the richer typed panes (Value types + Interfaces)", has(mgr, "Value types", "Interfaces"));

    // 3. Panes backed by daemon truth (the fixture's typed model renders).
    ok("object-types pane renders the fixture object type", has(mgr, "Loan"));
    ok("link-types pane renders the fixture link", has(mgr, "Held by"));
    ok("value-types pane renders the fixture value type", has(mgr, "Money"));
    ok("action + function panes render the fixture members", has(mgr, "Approve") && has(mgr, "Score"));
    ok("health pane is honest daemon readiness (fixture is ready)", /ready/i.test(mgr));

    // 4. Honest empty / unavailable lanes + named missing contracts.
    ok("object-instance boundary is stated (0 objects)", /0 objects/i.test(mgr));
    ok("Groups + Interfaces shown but unavailable", has(mgr, "Groups") && has(mgr, "Interfaces") && /unavailable/i.test(mgr));
    ok("Object data / Explorer is honestly unavailable", has(mgr, "Object data", "Explorer") && /unavailable/i.test(mgr));
    ok("all four missing authority contracts are named", has(mgr, "ConnectorMapping", "PolicyBoundDataView", "TransformationRun", "OntologyProjection"));

    // 5. IOI authority threaded sideways.
    ok("IOI authority: daemon truth + receipts", has(mgr, "daemon truth") && /receipt/i.test(mgr));
    ok("IOI authority: substrate readiness + conformance gap named", has(mgr, "Substrate readiness") && /Conformance/i.test(mgr));

    // 6. Captures secondary; no brand/reference leak; no owner-surface request failures.
    // (hrefs live in attributes, not innerText — check the DOM on the still-current manager page.)
    const schemaLinks = await page.locator('a[href="/__apps/schema"]').count().catch(() => 0);
    const explorerLinks = await page.locator('a[href^="/__apps/explorer"]').count().catch(() => 0);
    ok("reference captures kept secondary (schema + explorer links present)", schemaLinks >= 1 && explorerLinks >= 1, `schema ${schemaLinks} · explorer ${explorerLinks}`);
    ok("no brand/reference leak on the owner surface (no Palantir/Foundry)", !/\bPalantir\b/i.test(mgr) && !/\bFoundry\b/i.test(mgr));
    ok("owner surface makes no failed requests", ownerFailures.length === 0, ownerFailures.slice(0, 2).join(" "));

    // Core flow: the switcher offers ontology selection (deep-linkable).
    const switcher = await page.locator(`a[href*="/__ioi/odk?ontology="]`).count().catch(() => 0);
    ok("core flow: ontology switcher is present (deep-linkable selection)", switcher >= 1, `${switcher} chips`);
  } finally {
    await browser.close().catch(() => {});
    await fetch(`${DAEMON}/v1/hypervisor/odk/domain-ontologies/${ontId}`, { method: "DELETE" }).catch(() => {});
  }
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`ontology-ux-parity: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => { console.error("verifier crashed:", e); process.exit(1); });

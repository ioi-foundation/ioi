#!/usr/bin/env node
// Harvest-port Marketplace verifier — REBIND phase: the store-browse seed's data lanes are
// answered with the DAEMON marketplace plane, not capture fixtures.
//
// Proves: /__apps/listings (marketplace seed) browses stores/products through GraphQL
// (searchMarketplaceProducts values + aggregates, searchResources LOCAL_MARKETPLACE,
// remoteMarketplaces) and the serve answers with the daemon plane: ONE local store (the
// estate's governed listing plane), product rows = daemon listings verbatim (name,
// description, kind, subject, timestamps), status by the plane's own semantics —
// public_state "published" (admitted review + open release + serving runtime, receipted) →
// INSTALLABLE; drafts are UNPUBLISHED_DRAFT and NEVER installable. A draft-listing fixture
// over a REAL agent round-trips through the wire and the store table renders honest counts
// in the booted UI. The zip-upload affordance is disabled at the wire (the estate has no
// upload lane). Store/product drill-down documents are NOT in the capture cache — NAMED GAP
// (live re-harvest target); nothing is faked for them.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-harvest-marketplace.mjs
// Exit 2 = BLOCKED (harvest capture or daemon not running) — named, not failed.

import { chromium } from "playwright";

const SERVE = (process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173").replace(/\/$/, "");
const CAPTURE = (process.env.IOI_HARVEST_CAPTURE_URL || process.env.IOI_HARVEST_MIRROR_URL || "http://127.0.0.1:9225").replace(/\/$/, "");
const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };

const gql = (operationName, variables, query) => fetch(`${SERVE}/graphql-gateway/api/graphql?q=${operationName}`, {
  method: "POST", headers: { "content-type": "application/json" },
  body: JSON.stringify({ operationName, variables, query }),
}).then((r) => r.json());

const PRODUCTS_QUERY = "query SearchMarketplaceProducts($productMetadataQuery: String, $marketplaceRids: [RID!], $productStatus: [MarketplaceProductStatus!], $pageToken: String, $pageSize: Int!) { searchMarketplaceProducts(filter: {type: AND, clauses: [{productMetadataQuery: $productMetadataQuery, marketplaceRids: $marketplaceRids, productStatus: $productStatus}]}, pageToken: $pageToken, pageSize: $pageSize) { values { id status } nextPageToken } }";
const STORE_TABLE_QUERY = "query StoreTableQuery($pageSize: Int!) { searchMarketplaceProducts(filter: {type: AND, clauses: [{productStatus: INSTALLABLE}]}, sort: {direction: ASCENDING, field: NAME}, pageSize: $pageSize) { aggregates { marketplaceCounts { marketplace { rid } productCount } } } }";

async function run() {
  // 0. Liveness.
  const captureUp = await fetch(`${CAPTURE}/workspace/marketplace/`).then((r) => r.ok).catch(() => false);
  if (!captureUp) { console.error("BLOCKED: harvest capture not reachable at " + CAPTURE); process.exit(2); }
  const daemonUp = await fetch(`${DAEMON}/v1/hypervisor/marketplace/listings`).then((r) => r.ok).catch(() => false);
  if (!daemonUp) { console.error("BLOCKED: daemon not reachable at " + DAEMON); process.exit(2); }
  ok("harvest capture + daemon live", true, `${CAPTURE} · ${DAEMON}`);

  // 1. Seed serves under the estate, rebranded at the wire.
  const page1 = await fetch(`${SERVE}/__apps/listings`).then(async (r) => ({ status: r.status, text: await r.text() }));
  ok("seed serves under the estate", page1.status === 200 && !page1.text.includes("Palantir"));

  // 2. Fixture: a draft listing over a REAL agent (subject must resolve or the daemon rejects).
  const agents = await fetch(`${DAEMON}/v1/agents`).then((r) => r.json()).catch(() => []);
  const agentId = Array.isArray(agents) && agents[0] && agents[0].id;
  ok("a real agent exists to list", !!agentId, agentId);
  const marker = `verify-marketplace-rebind ${Date.now().toString(36)}`;
  const created = await fetch(`${DAEMON}/v1/hypervisor/marketplace/listings`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ listing_kind: "agent", subject_ref: agentId, name: marker, description: "draft listing fixture for the rebind verifier" }),
  }).then((r) => r.json()).catch(() => null);
  const fixtureId = created && created.listing && created.listing.id;
  ok("daemon draft-listing fixture created over the real agent", !!fixtureId, fixtureId);

  let uiText = "";
  try {
    // 3. REBOUND WIRE — stores and products are the daemon plane.
    const stores = await gql("StoreTableQuery", { pageSize: 1 }, STORE_TABLE_QUERY);
    const counts = stores?.data?.searchMarketplaceProducts?.aggregates?.marketplaceCounts || [];
    ok("exactly ONE store — the estate's own listing plane", counts.length === 1 && String(counts[0].marketplace?.rid || "").startsWith("ri.marketplace.main.local-store."), counts.length + " stores");
    const lj = await fetch(`${DAEMON}/v1/hypervisor/marketplace/listings`).then((r) => r.json());
    const published = (lj.listings || []).filter((l) => l.public_state === "published").length;
    ok("store table counts ONLY published (installable) listings", counts[0]?.productCount === published, `${counts[0]?.productCount} vs ${published} published`);

    const all = await gql("SearchMarketplaceProducts", { productMetadataQuery: null, marketplaceRids: null, productStatus: null, pageSize: 100 }, PRODUCTS_QUERY);
    const rows = all?.data?.searchMarketplaceProducts?.values || [];
    const ids = new Set(rows.map((r) => r.id));
    ok("every daemon listing on the wire", (lj.listings || []).every((l) => ids.has(l.id)), `${(lj.listings || []).length} listings`);
    ok("products lane fabricates NOTHING", rows.every((r) => (lj.listings || []).some((l) => l.id === r.id)), `${rows.length} wire rows`);
    const fixtureRow = rows.find((r) => r.id === fixtureId);
    ok("fixture draft is UNPUBLISHED_DRAFT — a draft is NEVER installable", !!fixtureRow && fixtureRow.status === "UNPUBLISHED_DRAFT");
    const installable = await gql("SearchMarketplaceProducts", { productMetadataQuery: null, marketplaceRids: null, productStatus: ["INSTALLABLE"], pageSize: 100 }, PRODUCTS_QUERY);
    const instRows = installable?.data?.searchMarketplaceProducts?.values || [];
    ok("INSTALLABLE view carries only receipted published listings", instRows.length === published && instRows.every((r) => (lj.listings || []).some((l) => l.id === r.id && l.public_state === "published")));
    const search = await gql("SearchMarketplaceProducts", { productMetadataQuery: marker.split(" ")[0], marketplaceRids: null, productStatus: null, pageSize: 100 }, PRODUCTS_QUERY);
    ok("text search honors the seed's grammar (finds the fixture by name)", (search?.data?.searchMarketplaceProducts?.values || []).some((r) => r.id === fixtureId));

    // 4. Upload honesty — no zip-upload lane exists in the estate.
    const quota = await fetch(`${SERVE}/marketplace/api/block-set-transport/permissions/user-upload-quota`).then((r) => r.json());
    ok("zip-upload affordance disabled at the wire (no such lane)", quota.isUploadFromMarketplaceEnabled === false);

    // 5. BOOTED UI — the store table is daemon truth on the glass.
    const b = await chromium.launch();
    try {
      const page = await b.newPage({ viewport: { width: 1700, height: 1000 } });
      await page.goto(`${SERVE}/__apps/listings`, { waitUntil: "networkidle", timeout: 60000 }).catch(() => {});
      await page.waitForTimeout(8000);
      uiText = await page.evaluate(() => (document.body.innerText || "").replace(/\s+/g, " "));
    } finally {
      await b.close();
    }
    ok("booted store table renders the estate plane", uiText.includes("Estate Marketplace"));
    ok("no reference-org stores leak through", !uiText.includes("Learning Store") && !uiText.includes("Machinery Store"));
    ok("published count on the glass is daemon truth", uiText.includes(`${published} product`));
    ok("no brand-cased strings in rendered text", !/Palantir/.test(uiText));
  } finally {
    // 6. Fixture cleanup (the plane supports honest deletion of drafts).
    if (fixtureId) {
      const del = await fetch(`${DAEMON}/v1/hypervisor/marketplace/listings/${encodeURIComponent(fixtureId)}`, { method: "DELETE" }).then((r) => r.json()).catch(() => null);
      ok("fixture draft removed after the round-trip", !!(del && del.removed));
    }
  }
}

run().then(() => {
  const fails = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${results.length - fails.length}/${results.length} passed`);
  if (fails.length) process.exit(1);
  console.log("harvest-marketplace REBIND readiness: OK");
}).catch((e) => { console.error("verifier crashed:", e); process.exit(1); });

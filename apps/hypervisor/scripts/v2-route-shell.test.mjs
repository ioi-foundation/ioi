// W1.3 contract test — the canonical route table's deep-link grammar, the marketplace mode
// route (DEF-ROUTE-1), retired-subtree 410 semantics, and the shell renderer's deep-link /
// embed behavior. Run: npm run test:hypervisor-route-shell
import test from "node:test";
import assert from "node:assert/strict";
import {
  V2_ROUTE_TABLE,
  RETIRED_UI_ROUTES,
  v2RouteFor,
  resolveV2Route,
  retiredUiRouteFor,
  renderV2RouteShellPage,
  retiredUiRouteRefusal,
} from "./v2-route-shell.mjs";

// ------------------------------ DEF-ROUTE-1 ------------------------------

test("DEF-ROUTE-1: /packages/marketplace IS a route, carrying the ledger rule verbatim", () => {
  const row = v2RouteFor("/packages/marketplace");
  assert.ok(row, "the route named in the ledger rule string must resolve");
  assert.equal(row.rule, "Marketplace is the optional mode at /packages/marketplace");
  assert.ok(row.serving_today.length > 0, "the marketplace object plane serves it today");
});

// ------------------------------ deep-link grammar ------------------------------

test("deep-link: exact rows resolve with an empty subpath (unchanged behavior)", () => {
  const hit = resolveV2Route("/ontology");
  assert.equal(hit.row.route, "/ontology");
  assert.equal(hit.subpath, "");
});

test("deep-link: a subpath resolves to its owning surface with the remainder carried", () => {
  const hit = resolveV2Route("/ontology/objects/obj_123");
  assert.equal(hit.row.route, "/ontology");
  assert.equal(hit.subpath, "objects/obj_123");
});

test("deep-link: longest prefix wins — /work/sessions/<id> belongs to the Sessions view, not Work", () => {
  const hit = resolveV2Route("/work/sessions/sess_9");
  assert.equal(hit.row.route, "/work/sessions");
  assert.equal(hit.subpath, "sess_9");
});

test("deep-link: /packages/marketplace/<listing> resolves under the marketplace mode row", () => {
  const hit = resolveV2Route("/packages/marketplace/mlist_1");
  assert.equal(hit.row.route, "/packages/marketplace");
  assert.equal(hit.subpath, "mlist_1");
});

test("deep-link: segment boundaries only — /database never matches /data", () => {
  assert.equal(resolveV2Route("/database"), null);
  assert.equal(resolveV2Route("/database/x"), null);
});

test("deep-link: vendored subtrees fall through — the SPA keeps /projects/* and /settings/<section>", () => {
  assert.equal(resolveV2Route("/projects"), null, "vendor_spa root falls through");
  assert.equal(resolveV2Route("/projects/proj_1"), null, "vendor_spa subtree falls through");
  assert.equal(resolveV2Route("/settings/members"), null, "passthrough subtree falls through");
  assert.ok(resolveV2Route("/settings"), "the /settings ROOT itself still renders the shell");
});

test("deep-link: unknown roots resolve to nothing — the grammar claims only canonical surfaces", () => {
  assert.equal(resolveV2Route("/definitely-not-a-surface/x/y"), null);
});

// ------------------------------ retired subtree ------------------------------

test("410: a retired root retires its subtree, and the replacement carries the deep link", () => {
  assert.deepEqual(retiredUiRouteFor("/sessions"), {
    requested: "/sessions",
    replacement: "/work/sessions",
  });
  assert.deepEqual(retiredUiRouteFor("/sessions/sess_42"), {
    requested: "/sessions/sess_42",
    replacement: "/work/sessions/sess_42",
  });
  assert.equal(retiredUiRouteFor("/sessionsx"), null, "segment boundary holds for retirement too");
});

test("410: the refusal record keeps the daemon's exact shape and performs nothing", () => {
  const refusal = retiredUiRouteRefusal("/sessions/s1", "/work/sessions/s1");
  assert.equal(refusal.code, "hypervisor.route_retired");
  assert.equal(refusal.canonical_replacement_route, "/work/sessions/s1");
  assert.equal(refusal.read_performed, false);
  assert.equal(refusal.mutation_performed, false);
});

// ------------------------------ renderer ------------------------------

const compiledStub = {
  daemon: { available: true },
  workspaces: [{ route: "/home", name: "Home", launchable: true }],
  applications: [{ route: "/ontology", name: "Ontology", launchable: true }],
};

test("render: a deep link is named honestly on the page and in the data attributes", () => {
  const row = v2RouteFor("/ontology");
  const html = renderV2RouteShellPage(row, compiledStub, { subpath: "objects/obj_1", query: "tab=schema" });
  assert.match(html, /Requested deep link/);
  assert.match(html, /\/ontology\/objects\/obj_1\?tab=schema/);
  assert.match(html, /data-ioi-surface-subpath="objects\/obj_1"/);
  assert.match(html, /Deep-link state/);
});

test("render: embed omits estate chrome but keeps the same truth — no nav band, no footer", () => {
  const row = v2RouteFor("/ontology");
  const full = renderV2RouteShellPage(row, compiledStub, {});
  const embedded = renderV2RouteShellPage(row, null, { embed: true });
  assert.match(full, /Estate navigation/);
  assert.doesNotMatch(embedded, /Estate navigation/);
  assert.doesNotMatch(embedded, /v2 route shell \(W0\.1\)/);
  assert.match(embedded, /data-ioi-embed="1"/);
  assert.match(embedded, /Registration/, "the honest registration grid survives embedding");
});

test("render: no fabricated serving lanes — an empty serving_today renders honest absence", () => {
  const reserved = V2_ROUTE_TABLE.find((r) => r.disposition === "reserved");
  const html = renderV2RouteShellPage(reserved, compiledStub, {});
  assert.match(html, /Nothing serves this surface today/);
  assert.match(html, /nonlaunchable/);
});

// ------------------------------ table integrity ------------------------------

test("table: every row keeps the required registration fields; retired roots never collide with rows", () => {
  for (const row of V2_ROUTE_TABLE) {
    for (const field of ["route", "surface", "kind", "rule", "waves", "build_state", "serving_today"]) {
      assert.ok(field in row, `${row.route} missing ${field}`);
    }
    assert.ok(row.route.startsWith("/"), row.route);
  }
  for (const retired of Object.keys(RETIRED_UI_ROUTES)) {
    assert.equal(v2RouteFor(retired), null, `${retired} is retired AND registered — contradiction`);
  }
});

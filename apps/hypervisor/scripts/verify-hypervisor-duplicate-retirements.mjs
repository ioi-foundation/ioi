#!/usr/bin/env node
// DUPLICATE RETIREMENT verifier (ADR 0056 M6, 2026-09-25) — a duplicate surface retires INTO the canon
// owner that already carries its lane, and this proves each merge from both sides:
//   1. TYPED RETIREMENT — the duplicate's route answers 410 with the registered refusal record (JSON:
//      nothing read, nothing written; the refusal contract admits no successor outside Work, so its
//      replacement is null) or the retired-route page (HTML) that NAMES AND LINKS the survivor. A link,
//      never a redirect alias (ADR 0022 D2).
//   2. NO FALLBACK — no registry row, no bound module, no canonical yield; the route shell carries the
//      successor; the parity matrix no longer claims the port and adjudicates the merge.
//   3. THE SURVIVOR CARRIES THE LANE — the surface named as successor renders the lane the duplicate
//      showed (the rule the merge was allowed under: nothing a user could reach is lost).
//   4. NOTHING LEADS THERE — the pages that linked the duplicate link the survivor instead.
//   5. THE SEED IS PRESERVED — the duplicate's rendering code stays in the serve, bound to nothing.
//
// Run against a sign-in-off serve (the census posture): IOI_HYPERVISOR_SERVE_URL=http://127.0.0.1:<port>
// Exit: 0 pass · 1 fail · 2 blocked (serve unreachable).
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { SURFACES, boundSurface, canonicalSurfaceRoute } from "./surface-registry.mjs";
import { retiredUiRouteFor } from "./v2-route-shell.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.resolve(HERE, "..");
// Its own isolated daemon + serve, the operator signed in (R-240, verifier auth sweep, 2026-09-29). This verifier read
// `IOI_HYPERVISOR_SERVE_URL || :4173` — the OWNER's development serve — with no session; since 2026-09-26 a serve requires
// sign-in, and the ontology/data-source reads behind its pages are caller-scoped. An explicit URL naming the owner's stack
// is refused (verifier-stack.mjs).
import { verifierStack } from "./lib/verifier-stack.mjs";
const STACK = await verifierStack({ serve: true });
const SERVE = STACK.serveUrl;
const results = [];
const ok = (name, cond, detail = "") => results.push({ name, pass: !!cond, detail: String(detail).slice(0, 220) });
const get = (p, accept) => fetch(`${SERVE}${p}`, { headers: { accept }, redirect: "manual" })
  .then(async (r) => ({ status: r.status, text: await r.text() })).catch(() => ({ status: 0, text: "" }));
const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

const reachable = await get("/", "text/html");
if (!reachable.status) { console.error(`BLOCKED: no serve at ${SERVE}`); process.exit(2); }

const matrix = JSON.parse(fs.readFileSync(path.join(APP, "harvest-app-parity-matrix.json"), "utf8"));
const bySeed = Object.fromEntries((matrix.seeds || []).map((s) => [s.slug, s]));
const serveSrc = fs.readFileSync(path.join(HERE, "serve-product-ui.mjs"), "utf8");
const packagesSrc = fs.readFileSync(path.join(APP, "surfaces", "packages", "index.mjs"), "utf8");
const artifactsSrc = fs.readFileSync(path.join(APP, "surfaces", "packages", "artifacts.mjs"), "utf8");
// A duplicate served by a flat serve branch keeps that branch; one served by a module keeps its code there.
const flatSeed = (route) => serveSrc.includes(`if (pathname === "${route}" && req.method === "GET")`);

// One row per merge. `lane` is what the duplicate showed; `carries` proves the survivor renders it;
// `linkers` are the pages that linked the duplicate before the merge.
const MERGED = [
  {
    slug: "modelstudio", seed: "modelstudio", route: "/__ioi/foundry/model-studio",
    successor: "/__ioi/foundry/specs/new", label: "the Foundry spec builder",
    lane: "create a model file (a draft FoundrySpec) — Model Studio's one verb, a declared gap there",
    carries: (t) => /<h1>New FoundrySpec/.test(t) && /<form method="post" action="\/__ioi\/foundry\/specs">/.test(t) && /name="name"/.test(t),
    linkers: ["/__ioi/foundry", "/__ioi/foundry/models", "/__ioi/foundry/inference"],
  },
  {
    slug: "insight", seed: "analysis", route: "/__ioi/evaluations/insight",
    successor: "/__ioi/ontology/explorer", label: "Object Explorer",
    lane: "materialized object sets with their provenance, and saved object sets (rows, or the plane's refusal)",
    carries: (t) => /materialized/.test(t) && /Saved object sets/.test(t) && (/class="oe-ssname"/.test(t) || /class="[^"]*\boe-ssrefused\b[^"]*">[^<]*<code>[a-z_]+<\/code>/.test(t) || /No saved object sets yet/.test(t)),
    linkers: ["/__ioi/evaluations", "/__ioi/evaluations/quiver", "/__ioi/evaluations/evalsuites"],
  },
  {
    slug: "map", seed: "map", route: "/__ioi/environments/map",
    successor: "/__ioi/environments", label: "Environments",
    lane: "where governed work is placed — venues, regions and placement decisions (the world map itself is Embodied Systems' lane, P12)",
    carries: (t) => /id="env-placement-venues"/.test(t) && /<h2>Placement<\/h2>/.test(t),
    linkers: ["/__ioi/environments", "/__ioi/environments/machines"],
  },
  {
    // ADR 0056 M6b: the Packages module's Marketplace MODE duplicated the certified Marketplace port.
    // It had no parity-matrix row of its own (a module mount, not a harvested seed), so the matrix
    // check asks only that no row claims the mount.
    slug: "packages-marketplace", seed: null, route: "/__ioi/packages/marketplace",
    successor: "/packages/marketplace", label: "the Marketplace",
    lane: "the listing plane (search, stores, listing rows) as the certified Marketplace port, stamped with the canonical route and the Packages owner, one hop from the counts readout",
    carries: (t) => t.includes('data-ioi-surface-route="/packages/marketplace"') && t.includes('data-ioi-surface-owner="Packages"') && /<h1 class="mk-htitle">Marketplace/.test(t) && /class="mk-search/.test(t) && t.includes('href="/__ioi/marketplace"'),
    linkers: ["/__ioi/marketplace", "/packages", "/__ioi/packages/registry"],
    preserved: () => /function marketplaceView\(/.test(packagesSrc) && packagesSrc.includes('LEGACY_MARKETPLACE_ROUTE = "/__ioi/packages/marketplace"'),
  },
  {
    // ADR 0056 M6c: the one merge that needed a PORT first. Packages lacked most of the Artifacts page, so
    // the page's rendering code MOVED verbatim into surfaces/packages/artifacts.mjs as a Packages tab, and
    // only then did the route retire. The seed is that adopted code, now reading as the caller.
    slug: "registry", seed: "registry", route: "/__ioi/marketplace/artifacts",
    successor: "/packages?tab=artifacts", label: "the Packages Artifacts tab",
    lane: "the registry ladder — ten planes each classified from its own answer, the cross-plane record table, the package-registry panel, the taxonomy and substrate lanes and the route-counted cards",
    carries: (t) => (t.match(/data-ioi-plane="/g) || []).length === 10 && (t.match(/data-ioi-plane-state="(live|empty|refused|write_only|unreadable)"/g) || []).length === 10
      && t.includes("Registry records") && t.includes("Publishable material") && t.includes("Learn about artifacts") && t.includes('data-ioi-surface-owner="Packages"'),
    linkers: ["/__ioi/marketplace", "/packages", "/__ioi/packages/registry"],
    preserved: () => artifactsSrc.includes("const rgyClassify = (pr) => {") && artifactsSrc.includes("export function renderArtifactsTab(") && !serveSrc.includes('pathname === "/__ioi/marketplace/artifacts"'),
  },
];

for (const m of MERGED) {
  // 1. Typed retirement.
  const json = await get(m.route, "application/json");
  let refusal = {};
  try { refusal = JSON.parse(json.text); } catch { /* reported below */ }
  ok(`${m.slug}: TYPED RETIREMENT (JSON) — ${m.route} answers 410 with the registered refusal record, nothing read, nothing written`,
    json.status === 410 && refusal.schema_version === "ioi.hypervisor.route_retirement_refusal.v1" && refusal.code === "hypervisor.route_retired"
      && refusal.requested_route === m.route && refusal.canonical_replacement_route === null
      && refusal.read_performed === false && refusal.mutation_performed === false && refusal.final_invocation_performed === false,
    `${json.status} ${json.text.slice(0, 160)}`);
  const html = await get(m.route, "text/html");
  ok(`${m.slug}: TYPED RETIREMENT (HTML) — a browser gets the 410 page that names and links ${m.label}, never a redirect`,
    html.status === 410 && html.text.includes(`href="${m.successor}"`) && html.text.includes(m.label), `${html.status}`);

  // 2. No fallback.
  const retired = retiredUiRouteFor(m.route);
  ok(`${m.slug}: NO FALLBACK — no registry row, no bound module, no canonical yield; the route shell names ${m.successor} as the successor`,
    !SURFACES.some((s) => s.slug === m.slug || s.route === m.route) && !boundSurface(m.route, "GET") && !canonicalSurfaceRoute(m.route)
      && retired?.replacement === null && retired?.successor === m.successor);
  if (m.seed) {
    const row = bySeed[m.seed];
    ok(`${m.slug}: NO FALLBACK — the parity matrix no longer claims the port (seed \`${m.seed}\`) and adjudicates the merge`,
      row && row.parity_class !== "reference_ported" && row.candidate_surface !== m.route && /ADR 0056 M6/.test(row.adjudication_ref || ""),
      `${row?.parity_class} ${row?.candidate_surface || ""}`);
  } else {
    ok(`${m.slug}: NO FALLBACK — no parity-matrix row claims the retired mount`, !(matrix.seeds || []).some((s) => (s.candidate_surface || "").split("?")[0] === m.route));
  }

  // 3. The survivor carries the lane.
  const surv = await get(m.successor, "text/html");
  ok(`${m.slug}: THE SURVIVOR CARRIES THE LANE — ${m.successor} renders ${m.lane}`, surv.status === 200 && m.carries(surv.text), `${surv.status}`);

  // 4. Nothing leads there.
  const linking = [];
  for (const p of [...new Set([...m.linkers, m.successor])]) {
    const r = await get(p, "text/html");
    if (new RegExp(`href="${esc(m.route)}(?:[?"#])`).test(r.text)) linking.push(p);
  }
  ok(`${m.slug}: NOTHING LEADS THERE — no page that linked ${m.route} still does`, linking.length === 0, linking.join(" "));

  // 5. The seed is preserved.
  ok(`${m.slug}: THE SEED IS PRESERVED — its rendering code stays where it was (the serve, or its module), bound to nothing (seeds are never mass-deleted)`,
    m.preserved ? m.preserved() : flatSeed(m.route));
}

const passed = results.filter((r) => r.pass).length;
for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.pass || !r.detail ? "" : `  (${r.detail})`}`);
console.log(`${passed}/${results.length} passed`);
process.exit(passed === results.length ? 0 : 1);

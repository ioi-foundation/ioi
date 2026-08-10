// Applications — the canonical /applications greenfield launcher (next-legs III Leg 3).
//
// GREENFIELD, TYPED NON-PARITY: no provenance-qualified seed exists for this surface — two
// recovery passes promoted zero candidates — so this build rides the owner-authorized
// greenfield-authorized-non-parity lane recorded in apps/hypervisor/seed-ux-provenance.v1.json.
// It claims no seed preservation and no parity; it is canon-first over
// docs/architecture/components/hypervisor/core-clients-surfaces.md ("one catalog/compiler
// projection", § Product-Surface Compiler, § Hypervisor Applications).
//
// READ-ONLY BY CONTRACT: launch is NAVIGATION over a compiled projection, never a mutation.
// The module declares zero actions; every admission-class verb (install / enable / recall /
// mount / serve) is authority-crossing and lives with its owner (Packages, Governance) — this
// surface renders their consequences, it never performs them.
//
// ONE truth source, two reads, both through the shared read client on the REQUEST-scoped
// daemon capability (typed degradation, no caching, refusals verbatim):
//
//   1. POST /v1/hypervisor/product-surface-projections — THE compiler projection
//      (lifecycle_routes.rs handle_product_surface_projection). Its application_entries are
//      the launcher's ONLY membership authority: the compiled first-party registrations
//      (registration → admitted+active release → installed+enabled installation for the
//      request org → serving binding; `launchable` requires all three) JOINED live with the
//      package-registry namespace (installed, non-uninstalled bindings on non-recalled
//      releases, org-scoped, `entry_source: "hypervisor-package-registry"`). A recalled or
//      uninstalled surface is ABSENT by derivation on every read — recall removes the row
//      immediately, and after restart, because there is no row state to clean up. Registry
//      unreadability is the daemon's typed 503 (hypervisor.package_registry_projection_
//      unavailable) and renders verbatim — never a silently thinner catalog.
//   2. GET /v1/hypervisor/core-taxonomy — the compiler-owned registration source. The
//      projection entry deliberately carries no availability field, so the reserved/planned
//      typing of a registration (Embodied Systems: `surface_availability: "planned"`) is read
//      from the taxonomy's application_registrations and joined by surface_ref. That is stated
//      on the page: the reservation TYPING comes from the registration source; the
//      nonlaunchability itself is projection truth (no release exists, so `launchable: false`
//      with the projection's own typed reason).
//
// HONESTY RULES this module holds:
//   - Rows render EXACTLY the projection truth: launchable rows link the projection's own
//     resolved_launch_route (with the caller's ?org= scope carried through — launch and deep
//     link preserve context); ineligible rows are disabled with the exact
//     disabled_reason_codes verbatim; reserved registrations render declared-nonlaunchable,
//     never hidden, never a coming-soon tile.
//   - Daemon outage → a typed unavailability page with ZERO rows. This launcher deliberately
//     renders NO static fallback inventory: a launcher row implies launch adjudication and an
//     outage never fabricates launchability (the W0.2 shell navigation band separately keeps
//     its safe static NAV inventory — navigation is not launchability).
//   - Folded owners never reappear as peers. The estate's retired owner names (Missions →
//     Work; the storefront owner → the Packages optional mode; the old workbench and
//     agent-studio owner names → Developer Workspace / Studio) are a refusal set: a projection
//     entry carrying one would render as a typed defect refusal, never as a peer row.
import { escHtml } from "../kit.mjs";

const esc = escHtml;
const LEGACY_ROUTE = "/__ioi/applications-launcher";
const CANONICAL_ROUTE = "/applications";
const PROJECTION_PATH = "/v1/hypervisor/product-surface-projections";
const TAXONOMY_PATH = "/v1/hypervisor/core-taxonomy";
const PROJECTION_SCHEMA = "ioi.hypervisor.product_surface_projection.v1";
const TAXONOMY_SCHEMA = "ioi.runtime.hypervisor_core_taxonomy.v2";
const REGISTRY_ENTRY_SOURCE = "hypervisor-package-registry";

export const meta = {
  slug: "applications",
  route: LEGACY_ROUTE,
  verifier: "scripts/verify-hypervisor-applications-journey.mjs",
  certification: "n/a",
};

// The folded-owner refusal set. These names owned surfaces once and were folded into canonical
// owners (taxonomy retired_routes; canon § Hypervisor Applications: Missions → Work,
// Marketplace → the Packages optional mode, Workbench → Developer Workspace, Agent Studio →
// Studio); they survive in the estate only as tool-surface EVIDENCE rows (surface-registry.mjs
// `owner` strings), never as catalog peers. This module renders server-side, so these constants
// never reach the served page: a retired name appears in launcher HTML only if the projection
// emits one — and then only inside the typed defect refusal below, never as a peer row.
const RETIRED_OWNER_NAMES = new Set(["Missions", "Marketplace", "Workbench", "Agent Studio"]);

// ---------------------------------------------------------------------------------------------
// load — both reads ride the caller's own identity envelope when the runtime supplies the
// request-scoped capability; anonymous stays anonymous (the daemon adjudicates scope, the
// module never re-implements policy). The ?org= query parameter IS the live scope selector:
// it rides the projection request as org_ref, the daemon adjudicates membership (a caller
// outside the org gets the typed hypervisor.organization_membership_required refusal,
// rendered verbatim), and every launch href carries it forward so launch and direct deep
// link preserve the same context.
export async function load(ctx) {
  const { createReadClient } = await import("../read-client.mjs");
  const client = typeof ctx.daemonFetch === "function"
    ? createReadClient({ daemon: "", fetchImpl: ctx.daemonFetch })
    : createReadClient({ daemon: ctx.daemon });
  const org = (ctx.url.searchParams.get("org") || "").trim();
  const body = { context: { launcher: "applications" } };
  if (org) body.org_ref = org;
  const projection = await client.read(PROJECTION_PATH, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
    expectSchema: PROJECTION_SCHEMA,
  });
  const taxonomy = await client.read(TAXONOMY_PATH, { expectSchema: TAXONOMY_SCHEMA });
  return { projection, taxonomy, org };
}

// No actions, deliberately: launch is navigation. Admission-class verbs are authority-crossing
// and belong to their owners; declaring one here would mint a second mutation path.
export const actions = [];

// ---------------------------------------------------------------------------------------------
const pill = (cls, label) => `<span class="pill ${cls}">${esc(label)}</span>`;
const reasonCodes = (codes) => (Array.isArray(codes) && codes.length
  ? codes.map((c) => `<code>${esc(String(c))}</code>`).join(" ")
  : "—");

function withOrg(route, org) {
  return org ? `${route}${route.includes("?") ? "&" : "?"}org=${encodeURIComponent(org)}` : route;
}

// Availability join over the compiler-owned registration source (see header note 2).
function availabilityBySurfaceRef(taxonomy) {
  if (!taxonomy?.ok) return null;
  const rows = Array.isArray(taxonomy.payload?.application_registrations)
    ? taxonomy.payload.application_registrations
    : [];
  const map = new Map();
  for (const row of rows) {
    if (typeof row?.surface_ref === "string") map.set(row.surface_ref, row);
  }
  return map;
}

// The typed zero-row outage page. `result` is the read client's degraded result for the
// projection read — its code/message (and the daemon's own refusal body, when one exists)
// render verbatim. Nothing else renders: no rows, no static inventory, no launch state.
function unavailableView(result) {
  const refusal = result?.refusal && typeof result.refusal === "object"
    ? `<pre>${esc(JSON.stringify(result.refusal, null, 2))}</pre>`
    : "";
  return `<div class="empty" data-ioi-degraded="${esc(result?.code || "daemon_unavailable")}">
      <b>The compiled projection is unavailable</b> — <code>${esc(result?.code || "daemon_unavailable")}</code>
      <div style="margin-top:6px">${esc(result?.message || "the daemon did not answer")}</div>
    </div>
    ${refusal}
    <p class="sub" style="margin-top:14px">Zero rows are rendered. A launcher row implies launch adjudication, and this surface never fabricates launchability: membership and launch state come only from <code>POST ${esc(PROJECTION_PATH)}</code>. The catalog returns when the compiler answers.</p>`;
}

function workspaceBand(entries, org) {
  const links = (entries || []).map((w) => {
    const route = typeof w.canonical_route === "string" ? w.canonical_route : "";
    const label = w.display_name || route;
    if (!route) return pill("muted", label);
    return `<a class="pill muted" style="text-decoration:none" data-ioi-workspace-name="${esc(label)}" href="${esc(withOrg(route, org))}">${esc(label)}</a>`;
  });
  return `<div class="band" aria-label="Core workspaces">
      <span class="bandlabel">Core workspaces</span>
      <div class="pills">${links.join("")}</div>
    </div>`;
}

// One catalog row, rendered with its exact projection truth. `registration` is the taxonomy
// registration row for this surface_ref (or undefined), `taxonomyDegraded` names the
// registration-source outage when the availability join could not be read.
function entryRow(entry, { org, registration, taxonomyDegraded }) {
  const name = String(entry.display_name || entry.identity_ref || "");
  if (RETIRED_OWNER_NAMES.has(name)) {
    // Folded owners never reappear as peers — a typed refusal row, never a launch link.
    return `<div class="card defect" data-ioi-retired-owner-defect="${esc(name)}">
        <div class="main"><div class="name">retired owner name refused</div>
        <div class="meta">the projection emitted a folded owner name as a peer entry — this launcher refuses to render it as an application; the canonical owner carries this surface (defect: report against the compiler feed)</div></div>
      </div>`;
  }
  const fromRegistry = entry.entry_source === REGISTRY_ENTRY_SOURCE;
  const reserved = registration?.surface_availability === "planned";
  const launchRoute = typeof entry.resolved_launch_route === "string" && entry.resolved_launch_route.startsWith("/")
    ? entry.resolved_launch_route
    : null;
  const launchable = entry.launchable === true && launchRoute !== null;
  const sourcePill = fromRegistry ? pill("muted", "package registry") : pill("muted", "compiled registration");
  const identity = `<div class="meta"><code>${esc(String(entry.identity_ref || ""))}</code>${entry.canonical_route ? ` · <code>${esc(String(entry.canonical_route))}</code>` : ""}</div>`;
  if (launchable) {
    const href = withOrg(launchRoute, org);
    return `<a class="card launch" data-ioi-entry-name="${esc(name)}" data-ioi-launchable="true" href="${esc(href)}">
        <div class="main"><div class="name">${esc(name)}${sourcePill}</div>${identity}
        <div class="meta">launch → <code>${esc(href)}</code>${entry.surface_capability_depth ? ` · depth ${esc(String(entry.surface_capability_depth))}` : ""}${entry.surface_operational_state ? ` · ${esc(String(entry.surface_operational_state))}` : ""}</div></div>
        <span class="pill ok">launchable</span>
      </a>`;
  }
  if (reserved) {
    return `<div class="card" data-ioi-entry-name="${esc(name)}" data-ioi-launchable="false" data-ioi-reserved="planned">
        <div class="main"><div class="name">${esc(name)}${sourcePill}${pill("warn", "reserved · planned")}</div>${identity}
        <div class="meta">declared nonlaunchable — a reserved registration row, rendered so it is never hidden and never a coming-soon tile. The <code>surface_availability: "planned"</code> typing is read from the compiler-owned registration source (<code>GET ${esc(TAXONOMY_PATH)}</code> · application_registrations); the projection entry itself carries no availability field — its own truth is <code>launchable: false</code> with the typed reason below, because no release exists for this registration.</div>
        <div class="meta">reasons: ${reasonCodes(entry.disabled_reason_codes)}</div></div>
        <span class="pill warn">nonlaunchable</span>
      </div>`;
  }
  // Ineligible row — the projection's exact typed reasons, verbatim. Registry-sourced entries
  // additionally carry their eligibility facts (installation/release refs, enablement,
  // disposition) so the row states WHY it is inventory without being launchable.
  const registryFacts = fromRegistry
    ? `<div class="meta">${pill("muted", `installation ${String(entry.surface_installation_state || "—")}`)}${pill("warn", String(entry.surface_enablement_state || "—"))}${entry.release_disposition ? pill(entry.release_disposition === "active" ? "ok" : "warn", `release ${String(entry.release_disposition)}`) : ""}</div>
       <div class="meta"><code>${esc(String(entry.installation_ref || ""))}</code> · <code>${esc(String(entry.release_ref || ""))}</code></div>`
    : "";
  const typingNote = taxonomyDegraded && !fromRegistry
    ? `<div class="meta">registration-source read unavailable (<code>${esc(taxonomyDegraded)}</code>) — reservation typing unknown for this render; the reasons above are projection truth</div>`
    : "";
  return `<div class="card" data-ioi-entry-name="${esc(name)}" data-ioi-launchable="false">
      <div class="main"><div class="name">${esc(name)}${sourcePill}</div>${identity}
      <div class="meta">reasons: ${reasonCodes(entry.disabled_reason_codes)}</div>${registryFacts}${typingNote}</div>
      <span class="pill warn">not launchable</span>
    </div>`;
}

// ---------------------------------------------------------------------------------------------
export function render(model, ctx) {
  const onLegacyMount = ctx.url.pathname.startsWith("/__ioi/");
  const base = onLegacyMount ? LEGACY_ROUTE : CANONICAL_ROUTE;
  const org = model.org || "";
  const projection = model.projection;
  let bodyHtml;
  if (!projection?.ok) {
    bodyHtml = unavailableView(projection);
  } else {
    const payload = projection.payload || {};
    const availability = availabilityBySurfaceRef(model.taxonomy);
    const taxonomyDegraded = availability === null ? (model.taxonomy?.code || "daemon_unavailable") : null;
    const entries = Array.isArray(payload.application_entries) ? payload.application_entries : [];
    const rows = entries.map((entry) => entryRow(entry, {
      org,
      registration: availability?.get(String(entry.identity_ref || "")),
      taxonomyDegraded,
    })).join("");
    const scope = `<div class="band" aria-label="Scope">
        <span class="bandlabel">Scope</span>
        <div class="pills">${pill("muted", `org ${payload.org_ref || "—"}`)}${pill("muted", `principal ${payload.principal_ref || "—"}`)}${org ? `<a class="pill muted" style="text-decoration:none" href="${esc(base)}">clear org scope</a>` : ""}</div>
      </div>`;
    const catalog = entries.length
      ? rows
      : `<div class="empty">The compiled projection returned zero application entries — honest absence, nothing is substituted.</div>`;
    bodyHtml = `${workspaceBand(payload.workspace_entries, org)}${scope}
      <h2 id="catalog">Application catalog</h2>
      ${catalog}
      <div class="foot">Membership and launch state: <code>POST ${esc(PROJECTION_PATH)}</code> (projection <code>${esc(String(payload.projection_id || "—"))}</code>, read-model-only). Reservation typing: <code>GET ${esc(TAXONOMY_PATH)}</code>${taxonomyDegraded ? ` — unavailable this render (<code>${esc(taxonomyDegraded)}</code>)` : ""}. Registry-sourced rows are inventory truth, never launchability; a recalled or uninstalled surface is absent by derivation on every read.</div>`;
  }
  const head = `<h1>Applications</h1>
    <p class="sub">The one catalog/compiler projection. Every row below is compiler truth for this exact request — launchable rows navigate to their surface (launch is navigation, never a mutation); ineligible rows state their exact typed reasons; reserved registrations render declared-nonlaunchable. This surface is a greenfield build on the typed non-parity lane (<code>seed-ux-provenance.v1.json</code>): it claims no seed preservation and no parity.</p>`;
  const css = `:root{color-scheme:dark}
  body{margin:0;background:#0c0d10;color:#e6e7ea;font:14px/1.55 -apple-system,Segoe UI,Roboto,sans-serif}
  .wrap{max-width:980px;margin:0 auto;padding:32px 24px 80px}
  a{color:#8ab4ff}
  h1{font-size:26px;margin:0 0 6px;letter-spacing:-.02em}
  .sub{color:#9a9da6;margin:0 0 22px;max-width:820px}
  h2{font-size:13px;letter-spacing:.04em;text-transform:uppercase;color:#878a93;margin:26px 0 10px;font-weight:600}
  .band{display:flex;align-items:baseline;gap:12px;margin:0 0 10px;flex-wrap:wrap}
  .bandlabel{font-size:11.5px;letter-spacing:.04em;text-transform:uppercase;color:#6f7280;white-space:nowrap}
  .pills{display:flex;flex-wrap:wrap;gap:6px}
  .card{display:flex;align-items:center;gap:14px;padding:13px 16px;border:1px solid #24262d;border-radius:12px;background:#15171c;margin-bottom:8px;text-decoration:none;color:inherit}
  a.card.launch:hover{border-color:#3a82f6;background:#191b21}
  .card.defect{border-color:#5c2323;background:#221111}
  .card .main{flex:1;min-width:0}
  .card .name{font-weight:600;color:#fff}
  .card .meta{color:#878a93;font-size:12.5px;margin-top:3px;overflow-wrap:anywhere}
  .pill{display:inline-block;padding:2px 9px;border-radius:999px;font-size:11px;border:1px solid;white-space:nowrap;margin-left:6px}
  .ok{color:#46c277;border-color:#235c3b;background:#11281b}
  .warn{color:#d6a13a;border-color:#5c4a23;background:#28220f}
  .muted{color:#9a9da6;border-color:#2a2c33}
  .empty{color:#6f7280;padding:18px;border:1px dashed #24262d;border-radius:12px}
  code{font-size:11.5px;color:#aab;background:#0e0f13;padding:1px 5px;border-radius:4px}
  pre{background:#0e0f13;border:1px solid #24262d;border-radius:8px;padding:12px;overflow:auto;font:11.5px/1.5 ui-monospace,monospace;color:#cdd1d8;white-space:pre-wrap;word-break:break-all}
  .foot{color:#6f7280;font-size:12.5px;margin-top:28px;border-top:1px solid #1b1d23;padding-top:14px}
  @media(max-width:700px){.wrap{padding:24px 14px 56px}.card{align-items:flex-start}}`;
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Applications · Hypervisor</title><style>${css}</style></head>
<body><div class="wrap">${head}${bodyHtml}</div></body></html>`;
}

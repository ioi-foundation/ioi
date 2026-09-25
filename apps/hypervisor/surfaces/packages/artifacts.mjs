// ADR 0056 M6c (2026-09-25): the ARTIFACTS registry port (REG-1), ADOPTED into Packages as its Artifacts
// tab. Moved VERBATIM from the /__ioi/marketplace/artifacts handler in serve-product-ui.mjs — the plane
// census, the record table, the package-registry panel, the taxonomy and substrate lanes and the
// route-counted cards — with three changes a module needs and nothing else:
//   1. the probes ride the caller's identity (ctx.daemonFetch), like every other module read, instead of
//      the serve's ambient fetch — canon filters collections by principal before it counts them, so a
//      plane's state here is the state THIS caller sees;
//   2. owner links name canonical routes (Packages on its own mount, the Marketplace at
//      /packages/marketplace since M6b);
//   3. the page shell (its own header, task-tray counters and Help chip — typed absences for reference
//      chrome) is the Packages page's now; the Create-repository link moves into the hero.
//
// The handler's own introduction, kept:
// ---- Marketplace · Artifacts — REG-1 (remediation v2): the REGISTRY port, and the leg where
// the honest move is a FOUR-WAY read-state census. The reference capture of `registry` was
// blocked_missing_capture, so the replay-scoped verdict was absent_confirmed (#registry, MAR-1
// — "the reference Artifacts seed expresses no IA to carry it"). The owner-authorized
// live-tenant sweep OVERTURNED it: the click target boots a real artifact-registry landing —
// title "Artifacts", headings "Explore artifacts" + "Learn about artifacts", 14 controls, one
// search input, an ecosystem scope selector, a three-counter task tray and a four-card
// documentation band, over ZERO repository rows.
//
// ADJUDICATED BEFORE BUILDING (#registry-port). Unlike map, the estate HAS registry planes —
// several of them — so the question was never "is there anything" but "which plane backs WHICH
// lane, and what does each plane actually answer to THIS surface's identity". Probing them
// returned FOUR distinct non-fabricable states, and blurring any two of them would be the lie
// this port exists to refuse:
//   LIVE       — the plane answers and holds records (rendered verbatim, rows == the plane)
//   EMPTY      — the plane answers and holds none (the reference's own state: 0 repositories)
//   REFUSED    — the plane is IDENTITY-FIRST and refuses this read with a typed code. A
//                refusal is NOT a zero: printing "0 packages" here would convert a refusal
//                into a measurement, which is exactly the defect class this program hunts.
//   NO READ ROUTE — the daemon publishes the plane as POST-only. Nothing can be read, which is
//                not the same as reading nothing.
// Every plane's state is CLASSIFIED FROM ITS OWN LIVE RESPONSE ON EVERY RENDER and stamped on
// the row as data-ioi-plane-state, so a state can never be pasted and can never rot.
//
// This is a READ-ONLY PROJECTION. The estate's registry verbs (admit a package candidate,
// create a release, recall a release, draft/publish a listing) are owned by Packages and
// Marketplace and are NOT re-minted here — the reference's "Create artifact repository" is a
// typed absence whose reason names the owner surface, and the surface links there.

export async function loadArtifacts(daemonFetch, registryOwner = "/packages") {
  // Probe each candidate registry plane EXACTLY as this surface's own identity sees it. The
  // probe keeps the raw status so a 405 (write-only) can never be confused with a 401
  // (refused) and neither can be confused with a 200 that carried an empty collection.
  const rgyProbe = async (p) => {
    try {
      const r = await daemonFetch(p);
      const text = await r.text();
      let body = null;
      try { body = JSON.parse(text); } catch { body = null; }
      return { path: p, status: r.status, ok: r.ok, body };
    } catch { return { path: p, status: 0, ok: false, body: null }; }
  };
  // The estate's registry planes, in the order the ladder actually runs: what material exists,
  // what is proposed, what is admitted, what is published, what is recorded afterwards.
  const RGY_PLANES = [
    { key: "packages", path: "/v1/hypervisor/packages", label: "Package registry",
      role: "THE artifact registry: a candidate freezes exact source bytes, a release is immutable and content-addressed by DIGEST (the estate's version), an installation binding is born disabled",
      owner: registryOwner, ownerLabel: "Packages" },
    { key: "publish_candidates", path: "/v1/hypervisor/marketplace/publish-candidates", label: "Publish candidates",
      role: "the frozen publish intent a listing must pass through before any review can admit it",
      owner: "/__ioi/marketplace", ownerLabel: "Marketplace substrate" },
    { key: "admission_reviews", path: "/v1/hypervisor/marketplace/admission-reviews", label: "Admission reviews",
      role: "the governed decision that ADMITS a candidate — admission is not publication and grants no runtime",
      owner: "/__ioi/marketplace", ownerLabel: "Marketplace substrate" },
    { key: "listings", path: "/v1/hypervisor/marketplace/listings", label: "Marketplace listings",
      role: "read-only, runtime-backed distribution metadata — the closest thing the estate has to a published artifact",
      owner: "/packages/marketplace", ownerLabel: "Marketplace" },
    { key: "instance_offers", path: "/v1/hypervisor/marketplace/instance-offers", label: "Managed instance offers",
      role: "managed offerings hung off agent / domain_app listings",
      owner: "/__ioi/marketplace", ownerLabel: "Marketplace substrate" },
    { key: "release_controls", path: "/v1/hypervisor/governance/release-controls", label: "Release controls",
      role: "the OPEN-RELEASE gate a publish must clear — governance truth, not registry inventory",
      owner: "/__ioi/governance/approvals", ownerLabel: "Governance" },
    { key: "scm_publication_effects", path: "/v1/hypervisor/scm-publication-effects", label: "SCM publication effects (publish receipts)",
      role: "the RECORDED OUTCOME of a governed publish out to an external SCM destination — the estate's publish receipt",
      owner: "/__ioi/connections", ownerLabel: "Connections" },
    { key: "scm_publication_proposals", path: "/v1/hypervisor/scm-publication-proposals", label: "SCM publication proposals",
      role: "the proposal a publish is raised as before its effect is recorded",
      owner: "/__ioi/connections", ownerLabel: "Connections" },
    { key: "worker_package_install_admissions", path: "/v1/hypervisor/worker-package-install-admissions", label: "Worker package-install admissions",
      role: "the admission a worker needs before a package may be installed into it",
      owner: "/__ioi/operations", ownerLabel: "Operations" },
    { key: "artifact_availability_incidents", path: "/v1/hypervisor/artifact-availability-incidents", label: "Artifact availability incidents",
      role: "recorded artifact-availability failures",
      owner: "/__ioi/operations", ownerLabel: "Operations" },
  ];
  const [rgyProbes, rgyOverview, rgyIndexJson] = await Promise.all([
    Promise.all(RGY_PLANES.map((pl) => rgyProbe(pl.path))),
    rgyProbe(`/v1/hypervisor/marketplace/overview`),
    daemonFetch(`/v1`).then((r) => r.json()).catch(() => ({})),
  ]);
  return { RGY_PLANES, rgyProbes, rgyOverview, rgyIndexJson };
}

export function renderArtifactsTab(model, { esc, registryBase }) {
  const { RGY_PLANES, rgyProbes, rgyOverview, rgyIndexJson } = model;
  // FOUR states, classified from the live response and never from a constant. The order of the
  // tests IS the contract: a write-only plane is decided by its status before anything reads a
  // body, a refusal is decided before any collection is looked for, and only a 200 that
  // actually carried a collection may be called live-or-empty.
  const rgyClassify = (pr) => {
    if (pr.status === 405) return { state: "write_only", code: "", rows: [] };
    if (!pr.ok) {
      const b = pr.body || {};
      const code = (b.error && b.error.code) || b.reason || b.code || `http_${pr.status}`;
      return { state: "refused", code: String(code), message: String((b.error && b.error.message) || b.message || ""), rows: [] };
    }
    const arr = Object.values(pr.body || {}).find((v) => Array.isArray(v));
    if (!Array.isArray(arr)) return { state: "unreadable", code: `http_${pr.status}`, rows: [] };
    return { state: arr.length ? "live" : "empty", code: "", rows: arr };
  };
  const rgyRead = RGY_PLANES.map((pl, i) => ({ ...pl, ...rgyClassify(rgyProbes[i]), status: rgyProbes[i].status }));
  const rgyBy = Object.fromEntries(rgyRead.map((r) => [r.key, r]));
  const rgyCount = (s) => rgyRead.filter((r) => r.state === s).length;
  const rgyRecords = rgyRead.filter((r) => r.state === "live");
  const rgyRecordTotal = rgyRecords.reduce((n, r) => n + r.rows.length, 0);
  // ONE gap contract for every named absence (aria + title + data-ioi reason). rgy-gap marks a
  // CHROME control the reference offers and the estate cannot honour; rgy-dash marks a FIELD
  // the record itself does not carry. Every chrome reason is written for ITS control — a
  // reused boilerplate reason is a decorative assertion, and the verifier fails on one.
  const rgap = (cls, label, reason) => `<span class="${cls} rgy-gap" aria-disabled="true" title="${esc(reason)}" data-ioi-disabled-reason="${esc(reason)}">${esc(label)}</span>`;
  const rdash = (reason) => `<span class="rgy-dash" aria-disabled="true" title="${esc(reason)}" data-ioi-disabled-reason="${esc(reason)}">—</span>`;
  const rdt = (iso) => { const d2 = new Date(iso || 0); return isNaN(d2) ? "—" : d2.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" }); };
  const rstr = (v) => (typeof v === "string" && v.trim() !== "" ? v : "");
  // ---- the ROUTE census, re-counted from the daemon's own index on every render. Two claims
  // on this surface rest on route arithmetic — that the package family is CLOSED at exactly
  // eight routes, and that NOTHING in the estate indexes artifacts for search — so both are
  // derived here rather than pasted, and a gate fails the day either drifts.
  const rgyRoutes = (Array.isArray(rgyIndexJson.families) ? rgyIndexJson.families : []).flatMap((f) => (Array.isArray(f.paths) ? f.paths : []));
  const rgyPkgRoutes = rgyRoutes.filter((r) => String(r.path || "").startsWith("/v1/hypervisor/packages"));
  const rgyMktRoutes = rgyRoutes.filter((r) => String(r.path || "").startsWith("/v1/hypervisor/marketplace"));
  const rgySearchRoutes = rgyRoutes.filter((r) => /(search|\/query|index)/i.test(String(r.path || "")));
  const rgyArtifactSearchRoutes = rgySearchRoutes.filter((r) => /(package|artifact|release|listing|registry|marketplace)/i.test(String(r.path || "")));
  // ---- the TAXONOMY lane: the estate's own registry kinds, read live from the daemon's
  // overview. This is what the reference's ecosystem scope selector would scope BY if the
  // estate had one — it does not, because these are estate object kinds, not package
  // ecosystems, and nothing scopes a search that does not exist.
  const rgyOv = (rgyOverview.ok && rgyOverview.body) ? rgyOverview.body : {};
  const rgyKinds = Array.isArray(rgyOv.listing_kinds) ? rgyOv.listing_kinds : [];
  const rgyByKind = rgyOv.listings_by_kind && typeof rgyOv.listings_by_kind === "object" ? rgyOv.listings_by_kind : {};
  const rgyKindRows = rgyKinds.map((k) => `<span class="rgy-kind" data-ioi-registry-kind="${esc(k)}"><b>${esc(k)}</b><span class="rgy-kindn">${esc(String(rgyByKind[k] ?? 0))}</span></span>`).join("");
  // ---- the SUBSTRATE lane: the daemon's own census of PUBLISHABLE MATERIAL. This is never
  // rendered as artifact rows — material that COULD be published is not a published artifact,
  // and the daemon's own key names carry that distinction, so they render verbatim.
  const rgySubstrate = rgyOv.substrate && typeof rgyOv.substrate === "object" ? rgyOv.substrate : {};
  const rgySubKeys = Object.keys(rgySubstrate).sort();
  const rgySubRows = rgySubKeys.map((k) => `<span class="rgy-sub" data-ioi-substrate-key="${esc(k)}"><code>${esc(k)}</code><b>${esc(String(rgySubstrate[k]))}</b></span>`).join("");
  // ---- the PLANE CENSUS table: one row per plane, its state classified live and stamped.
  const rgyStateLabel = {
    live: "LIVE",
    empty: "EMPTY",
    refused: "REFUSED",
    write_only: "NO READ ROUTE",
    unreadable: "UNREADABLE",
  };
  const rgyStateCopy = (r) => {
    if (r.state === "live") return `${r.rows.length} record${r.rows.length === 1 ? "" : "s"} — rendered below verbatim`;
    if (r.state === "empty") return `the plane answered and holds none — an EMPTY plane, not a missing one`;
    if (r.state === "refused") return `identity-first: <code>${esc(r.code)}</code> — a REFUSAL, never a zero`;
    if (r.state === "write_only") return `the daemon publishes this plane POST-only (HTTP ${esc(String(r.status))} on GET) — nothing to read, which is not the same as reading nothing`;
    return `the plane did not answer readably (<code>${esc(r.code)}</code>) — stated, never guessed`;
  };
  const rgyPlaneRows = rgyRead.map((r) => `<div class="rgy-prow" data-ioi-plane="${esc(r.path)}" data-ioi-plane-state="${esc(r.state)}">`
    + `<span><b>${esc(r.label)}</b><span class="rgy-role">${esc(r.role)}</span></span>`
    + `<span><code class="rgy-ref">${esc(r.path)}</code></span>`
    + `<span class="rgy-state rgy-state-${esc(r.state)}">${esc(rgyStateLabel[r.state] || r.state)}</span>`
    + `<span class="rgy-scopy">${rgyStateCopy(r)}</span>`
    + `<span><a href="${esc(r.owner)}">${esc(r.ownerLabel)} →</a></span></div>`).join("");
  // ---- the RECORD lane: the reference's repository list, rendered as what the estate's
  // readable registry planes actually hold. Every row NAMES which plane it came from, so a
  // record is never shown under a header it does not belong to, and every field the record
  // does not carry is a typed dash rather than a blank or an invented value.
  const RGY_RECORD_CAP = 50;
  const rgyAllRecords = rgyRecords.flatMap((r) => r.rows.map((rec) => ({ plane: r, rec })));
  const rgyShown = rgyAllRecords.slice(0, RGY_RECORD_CAP);
  const rgyRecordRows = rgyShown.map(({ plane, rec }) => {
    const id = rstr(rec.id) || rstr(rec.listing_id) || rstr(rec.candidate_id) || rstr(rec.package_id) || rstr(rec.offer_id);
    const name = rstr(rec.name) || rstr(rec.display_name);
    const ref = rstr(rec.ref) || rstr(rec.candidate_ref) || rstr(rec.subject_ref) || rstr(rec.listing_ref);
    const kind = rstr(rec.listing_kind) || rstr(rec.decision) || rstr(rec.kind);
    const state = rstr(rec.status);
    const ver = rstr(rec.schema_version);
    return `<a class="rgy-row" href="${esc(plane.owner)}" title="a REAL record on ${esc(plane.label)} (${esc(plane.path)}) — owner surface: ${esc(plane.ownerLabel)}">`
      + `<span><b>${name ? esc(name) : esc(id || "record")}</b>${name ? `<code class="rgy-ref">${esc(id)}</code>` : rdash(`This ${plane.label} record carries no name or display_name — the plane records none on it, so the record id above is the only identity it has and nothing here supplies a friendlier one (typed absence)`)}</span>`
      + `<span>${esc(plane.label)}<code class="rgy-ref">${esc(plane.path)}</code></span>`
      + `<span>${kind ? esc(kind) : rdash(`This ${plane.label} record carries no listing_kind, decision or kind field — the plane records none on it (typed absence, not an unread field)`)}</span>`
      + `<span>${state ? esc(state) : rdash(`This ${plane.label} record carries no status field — the plane records none on it (typed absence, not an unread field)`)}</span>`
      + `<span>${ver ? `<code class="rgy-ref">${esc(ver)}</code>` : rdash(`This ${plane.label} record carries no schema_version — the estate versions releases by content DIGEST and records schema_version on the record; neither is supplied by this surface (typed absence)`)}</span>`
      + `<span>${ref ? `<code class="rgy-ref">${esc(ref)}</code>` : rdash(`This ${plane.label} record binds no subject/candidate ref — the plane records none on it (typed absence)`)}</span>`
      + `<span>${esc(rdt(rec.created_at || rec.updated_at))}</span></a>`;
  }).join("");
  // ---- the reference's "Learn about artifacts" band, ported as WHAT THE ESTATE'S REGISTRY
  // ACTUALLY IS: each of the reference's four topics named against the real route that owns it
  // (or against the absence, where there is none). Live counts, no prose standing in for a plane.
  const rgyCards = [
    {
      title: "Core concepts",
      body: `A package <b>candidate</b> freezes exact source bytes; a <b>release</b> is immutable and content-addressed by digest — that digest IS the estate's version, there is no version string to name; an <b>installation binding</b> is born <code>disabled</code> and admission grants no runtime and no launch eligibility. The family is CLOSED: <b>${rgyPkgRoutes.length}</b> routes under <code>/v1/hypervisor/packages</code>, counted from the daemon's route index on this render.`,
      link: { href: registryBase, label: "Packages — the owner surface →" },
    },
    {
      title: "Publish an artifact",
      body: `Publication is a governed ladder, not a button: draft listing → publish candidate → admission review → publish, gated on an OPEN release control, across <b>${rgyMktRoutes.length}</b> marketplace routes. Outward publication to an external SCM destination records its own effect (the estate's publish receipt). Right now the estate holds <b>${rgyRecordTotal}</b> readable record${rgyRecordTotal === 1 ? "" : "s"} across <b>${rgyCount("live")}</b> live plane${rgyCount("live") === 1 ? "" : "s"}.`,
      link: { href: "/packages/marketplace", label: "Marketplace — the owner surface →" },
    },
    {
      title: "Search an artifact",
      body: `The estate cannot. Counted from the daemon's route index on this render: <b>${rgySearchRoutes.length}</b> search/query routes are published and <b>${rgyArtifactSearchRoutes.length}</b> of them index packages, releases or listings. There is no artifact index to query, so this surface offers no search box that would quietly return nothing.`,
      gap: ["Search artifacts", "The reference's per-artifact search resolves against an artifact INDEX; the estate publishes no route that indexes packages, releases or listings, so a search affordance here could only ever return an empty result that looked like an answer (typed absence)"],
    },
    {
      title: "Recall an artifact",
      body: `Recall is REAL and it is the family's <b>one</b> disposition successor: <code>POST /v1/hypervisor/packages/:package_id/releases/:release_digest/recall</code> appends an immutable successor revision under exact-head CAS with a bounded reason, and every binding read afterwards resolves the recalled head. <b>deprecate</b>, <b>supersede</b> and <b>revoke</b> are named by the registered enum and no route can set them. The verb lives on its owner surface and is never re-minted on a read landing.`,
      link: { href: registryBase, label: "Packages — the owner surface →" },
    },
  ].map((c) => `<div class="rgy-card"><b class="rgy-cardh">${esc(c.title)}</b><p class="rgy-cardb">${c.body}</p>`
    + (c.link ? `<a class="rgy-cardl" href="${esc(c.link.href)}">${esc(c.link.label)}</a>` : rgap("rgy-cardl", c.gap[0], c.gap[1]))
    + `</div>`).join("");
  const rgyFoot = `REG-1 (remediation v2): the REGISTRY port — the leg where honesty is a FOUR-WAY read-state census. The reference capture was blocked_missing_capture (replay-scoped verdict: absent_confirmed, MAR-1 "expresses no IA"); the owner-authorized live sweep OVERTURNED it and recorded a real artifact-registry landing (title "Artifacts" · headings "Explore artifacts" + "Learn about artifacts" · <b>14 controls</b> · 1 search input · 0 repository rows). Of those 14, <b>9 are the vendor global rail</b> (railless here — estate chrome is never re-minted on a ported landing) and the <b>5 app controls</b> plus the search input are ported and every one of them is a typed absence with a reason written for it. Unlike the map leg, the estate HAS registry planes: <b>${rgyRead.length}</b> were probed live on this render and they answered in FOUR distinct states — <b>${rgyCount("live")} LIVE</b> · <b>${rgyCount("empty")} EMPTY</b> · <b>${rgyCount("refused")} REFUSED</b> · <b>${rgyCount("write_only")} NO READ ROUTE</b>. Every state is classified from that plane's own live response and stamped on its row, so none can be pasted and none can rot. READ-ONLY: the estate's registry verbs (admit a candidate · create a release · recall a release · draft or publish a listing) stay on <a href="${esc(registryBase)}">Packages</a> and <a href="/packages/marketplace">Marketplace</a> and are not duplicated here. Evidence: reference-seed-adjudications.v1.json#registry-port · reference-live-tenant-deep-atlas.v1.json#registry (landing) · reference-live-tenant-atlas.v1.json#registry. Owner: <a href="/packages/marketplace">Marketplace</a> · truth: <a href="${esc(registryBase)}">package registry</a> · <a href="/__ioi/marketplace">marketplace substrate</a> · <a href="/__ioi/governance/approvals">release controls</a> · <a href="/__ioi/connections">SCM publication</a>.`;
  const html = `<div class="rgy-tab">
    <section class="rgy-hero">
          <h2 class="rgy-h1">Explore artifacts</h2>
          <p class="rgy-lede">The estate's registry is not one plane but a LADDER, and this is a read-only projection of it: what material exists, what has been proposed, what has been admitted, what has been published, and what was recorded afterwards. ${rgyRead.length} planes were probed live on this render and they came back in four different states — and this surface refuses to blur them, because <b>REFUSED is not EMPTY, EMPTY is not MISSING</b>, and a plane with no read route is none of the three.</p>
          <div class="rgy-searchbar">
            <span class="rgy-scope">${rgap("rgy-chip", "Ecosystem scope ▾", "The reference scopes its search by third-party PACKAGE ECOSYSTEM (its live capture had one selected); the estate binds no package ecosystem at all — its registry holds estate object kinds, not ecosystem packages — so naming one here would imply a binding that does not exist (typed absence)")}</span>
            <span class="rgy-sinput">${rgap("rgy-chip", "Search artifacts…", `No artifact search index exists on the estate: counted from the daemon's route index on this render, ${rgySearchRoutes.length} search/query routes are published and ${rgyArtifactSearchRoutes.length} of them index packages, releases or listings. A search box here could only return an empty result that read like an answer (typed absence)`)}</span>
          </div>
          <p class="rgy-lede" style="margin-top:18px">The estate's registry taxonomy, read live from the daemon's own overview — <b>${rgyKinds.length}</b> kind${rgyKinds.length === 1 ? "" : "s"} with their current listing counts. These are estate OBJECT kinds, not package ecosystems, and they scope nothing here: the selector above is absent because there is no artifact search to scope.</p>
          <div class="rgy-kinds">${rgyKindRows || `<span class="rgy-kind">${rdash("The marketplace overview returned no listing-kind enum on this render — the taxonomy is read from the daemon and never supplied by this surface (typed absence)")}</span>`}</div>
          <p class="rgy-lede" style="margin-top:14px"><a class="rgy-create" href="${esc(registryBase)}#catalog" title="Repository creation is candidate admission on Packages, the owner surface — this opens it">+ Create artifact repository</a></p>
        </section>
    <div class="rgy-body">
          <h2 class="rgy-h">Registry planes — read live, classified into four states</h2>
          <p class="rgy-note">Every row is a REAL daemon plane and its state was classified from that plane's own response on this render, then stamped on the row (<code>data-ioi-plane-state</code>) so it can never be pasted and never rot. <b>LIVE</b> = the plane answered and holds records. <b>EMPTY</b> = it answered and holds none (this is the reference's own state: its Artifacts landing rendered 0 repositories). <b>REFUSED</b> = the plane is identity-first and refused this read with a typed code — <b>a refusal is not a zero</b>, and rendering it as one would convert a closed door into a measurement. <b>NO READ ROUTE</b> = the daemon publishes the plane POST-only; there is nothing to read, which is not the same as reading nothing. Rows open the owner surface that holds the verbs.</p>
          <div class="rgy-phead"><span>Plane</span><span>Route</span><span>State</span><span>What that state means here</span><span>Owner</span></div>
          ${rgyPlaneRows}
          <h2 class="rgy-h">Registry records — every record the readable planes actually hold</h2>
          <p class="rgy-note">${rgyRecordTotal} REAL record${rgyRecordTotal === 1 ? "" : "s"} across ${rgyCount("live")} live plane${rgyCount("live") === 1 ? "" : "s"}${rgyAllRecords.length > RGY_RECORD_CAP ? ` — the first ${RGY_RECORD_CAP} of ${rgyAllRecords.length} render below (cap NAMED, never silent)` : ""}. Every row NAMES which plane it came from and carries the record's own id, ref and schema_version verbatim; a field the record does not carry is a typed dash, never a blank and never an invented value. The estate versions a release by content DIGEST — there is no version string on these records to print, and none is invented.</p>
          <div class="rgy-thead"><span>Record</span><span>Plane</span><span>Kind / decision</span><span>State</span><span>Schema version</span><span>Bound ref</span><span>Created</span></div>
          ${rgyRecordRows || `<div class="rgy-empty">No records on any readable plane — this table renders the real registry planes and never fabricates rows.</div>`}
          <h3 class="rgy-h">The package registry itself — ${esc(rgyStateLabel[rgyBy.packages.state] || rgyBy.packages.state)}</h3>
          <div class="rgy-absent">
            <h3>${rgyBy.packages.state === "refused" ? `The estate's real artifact registry REFUSED this read — that is not an empty registry` : `The estate's real artifact registry answered — ${esc(String(rgyBy.packages.rows.length))} candidate${rgyBy.packages.rows.length === 1 ? "" : "s"}`}</h3>
            ${rgyBy.packages.state === "refused"
              ? `<p><code>/v1/hypervisor/packages</code> is IDENTITY-FIRST: it resolves the caller's principal before it reads a single field, and this projection's own identity got <code>${esc(rgyBy.packages.code)}</code> back. So this surface prints no candidate count, no release list and no installation binding — because it does not have one. <b>A refusal is not a zero.</b> The reference's landing shows an EMPTY registry (0 repositories over a plane that answered); this lane shows a plane that would not answer, and the difference is exactly the one a fabricated "0 packages" would erase.</p>`
              : `<p><code>/v1/hypervisor/packages</code> answered for this projection's identity, and the candidates it returned render in the record table above with the plane named on every row. Admission grants no runtime: an installation binding is born <code>disabled</code> and this surface never reads a binding as launchable.</p>`}
            <p>Either way the VERBS stay where they are owned. Admitting a candidate, cutting a release, recalling one, and uninstalling a binding are the Packages family's own authority-crossing writes; this landing links to them and re-mints none of them. <a href="${esc(registryBase)}">Open Packages →</a></p>
          </div>
          <h2 class="rgy-h">Publishable material — NOT published artifacts</h2>
          <p class="rgy-note">The daemon's own substrate census, read verbatim from <code>/v1/hypervisor/marketplace/overview</code> with its own key names: this is material that COULD be published, and none of it is a published artifact. It is deliberately NOT rendered as registry rows — counting candidate material as inventory is the same class of error as reading a refusal as a zero.</p>
          <div class="rgy-subs">${rgySubRows || `<span class="rgy-sub">${rdash("The marketplace overview returned no substrate census on this render — stated, never filled in with a guess")}</span>`}</div>
        </div>
    </div>
    <section class="rgy-learn"><div class="rgy-lwrap">
          <div class="rgy-ltop"><h2 class="rgy-lh">Learn about artifacts</h2>${rgap("rgy-chip", "Go to documentation ↗", "The reference links out to vendor-hosted artifact documentation; the estate serves no documentation plane and has no binding to that vendor's docs, so this control names its absence instead of sending an operator somewhere this estate does not own (typed absence)")}</div>
          <div class="rgy-cards">${rgyCards}</div>
        </div></section>
    <p class="rgy-foot">${rgyFoot}</p>
  </div>`;
  return { css: RGY_CSS, html };
}

const RGY_CSS = `
  /* The Packages page styles h2 as a small uppercase label; the port's headings keep the case, spacing
     and colour they had on their own page. */
  .rgy-tab h2,.rgy-tab h3{text-transform:none;letter-spacing:normal;color:#1c2127}
  .rgy-create{display:inline-flex;align-items:center;height:30px;padding:0 12px;border-radius:4px;background:#2d72d2;color:#fff;font-size:14px}
  .rgy-chip{display:inline-flex;align-items:center;height:30px;padding:0 10px;border-radius:4px;border:1px solid #d1d1d1;font-size:13px;color:#404854}
  .rgy-gap{opacity:.62;cursor:not-allowed}
  .rgy-dash{color:#a8b2be;cursor:not-allowed}
  .rgy-hero{padding:52px 24px 40px;text-align:center}
  .rgy-h1{font-size:28px;font-weight:600;margin:0 0 10px;color:#1c2127}
  .rgy-lede{font-size:14px;color:#5f6b7c;max-width:820px;margin:0 auto 22px;line-height:1.65}
  .rgy-searchbar{display:flex;max-width:880px;margin:0 auto;border:1px solid #d1d1d1;border-radius:4px;overflow:hidden}
  .rgy-scope{flex:0 0 210px;display:flex;align-items:center;justify-content:center;height:38px;border-right:1px solid #d1d1d1;background:#f6f7f9;font-size:13px}
  .rgy-sinput{flex:1;display:flex;align-items:center;height:38px;padding:0 12px;font-size:13px;color:#8a94a2}
  .rgy-kinds{display:flex;flex-wrap:wrap;gap:8px;justify-content:center;margin:16px auto 0;max-width:880px}
  .rgy-kind{display:inline-flex;align-items:center;gap:6px;border:1px solid #e5e8eb;border-radius:999px;padding:3px 11px;font-size:12px;color:#404854}
  .rgy-kindn{background:#e8eef7;color:#215db0;border-radius:999px;padding:0 7px;font-size:11px;font-weight:600}
  .rgy-body{padding:0 24px 44px;max-width:1240px;margin:0 auto;width:100%;overflow-x:auto}
  .rgy-h{font-size:18px;font-weight:600;margin:26px 0 4px}
  .rgy-note{font-size:12px;color:#5f6b7c;margin:0 0 12px;line-height:1.65}
  .rgy-phead,.rgy-prow{display:grid;grid-template-columns:2.4fr 1.6fr .9fr 2.2fr .9fr;gap:8px;padding:9px 8px;min-width:680px}
  .rgy-thead,.rgy-row{display:grid;grid-template-columns:1.7fr 1.7fr .9fr .8fr 1.5fr 1.6fr .8fr;gap:8px;padding:8px;min-width:760px}
  .rgy-phead,.rgy-thead{font-size:11px;font-weight:600;letter-spacing:.04em;text-transform:uppercase;color:#5f6b7c;border-bottom:1px solid #e5e8eb}
  .rgy-prow,.rgy-row{align-items:center;border-bottom:1px solid #f0f2f5;font-size:13px;color:#1c2127}
  .rgy-prow:hover,.rgy-row:hover{background:#f6f7f9}
  .rgy-role{display:block;font-size:11px;color:#5f6b7c;line-height:1.5;margin-top:2px}
  .rgy-ref{display:block;font-size:11px;color:#5f6b7c;word-break:break-all}
  .rgy-scopy{font-size:12px;color:#5f6b7c;line-height:1.5}
  .rgy-state{font-size:11px;font-weight:600;letter-spacing:.03em;border-radius:3px;padding:2px 7px;text-align:center;border:1px solid}
  .rgy-state-live{color:#1c6e42;border-color:#9bc4ab;background:#eef8f2}
  .rgy-state-empty{color:#5f6b7c;border-color:#d1d1d1;background:#f6f7f9}
  .rgy-state-refused{color:#946638;border-color:#f0dca6;background:#fff8e6}
  .rgy-state-write_only{color:#7961db;border-color:#cfc4f5;background:#f3f0fd}
  .rgy-state-unreadable{color:#a82a2a;border-color:#eab8b8;background:#fdf0f0}
  .rgy-absent{border:1px solid #f0dca6;background:#fff8e6;border-radius:4px;padding:20px 22px;color:#5f6b7c;font-size:14px;line-height:1.65;margin:0 0 16px}
  .rgy-absent h3{font-size:16px;color:#1c2127;margin:0 0 8px}
  .rgy-absent p{margin:0 0 8px}
  .rgy-subs{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 8px}
  .rgy-sub{display:inline-flex;align-items:center;gap:8px;border:1px solid #e5e8eb;border-radius:4px;padding:5px 10px;font-size:12px;color:#404854}
  .rgy-empty{padding:22px 10px;color:#5f6b7c;font-size:14px;line-height:1.6}
  .rgy-learn{background:#f6f7f9;border-top:1px solid #e5e8eb;padding:30px 24px 44px}
  .rgy-lwrap{max-width:1240px;margin:0 auto}
  .rgy-ltop{display:flex;align-items:center;justify-content:space-between;margin:0 0 12px}
  .rgy-lh{font-size:18px;font-weight:600;margin:0}
  .rgy-cards{display:grid;grid-template-columns:repeat(2,1fr);gap:12px}
  .rgy-card{background:#fff;border:1px solid #e5e8eb;border-radius:4px;padding:14px 16px}
  .rgy-cardh{font-size:14px;color:#1c2127}
  .rgy-cardb{font-size:12.5px;color:#5f6b7c;line-height:1.65;margin:6px 0 10px}
  .rgy-cardl{font-size:12.5px}
  .rgy-foot{font-size:12px;color:#7b8494;line-height:1.65;margin:0 auto;padding:18px 24px 40px;max-width:1240px}
  @media(max-width:900px){.rgy-cards{grid-template-columns:1fr}
  @media(max-width:700px){.rgy-thead,.rgy-phead{display:none}.rgy-row,.rgy-prow{grid-template-columns:1fr;min-width:0;gap:2px;padding:10px 8px}.rgy-row *,.rgy-prow *,.rgy-note,.rgy-sub{overflow-wrap:break-word}.rgy-body{overflow-x:hidden}.rgy-cards{grid-template-columns:1fr}.rgy-card{min-width:0}.rgy-card *{overflow-wrap:anywhere}}}
`;

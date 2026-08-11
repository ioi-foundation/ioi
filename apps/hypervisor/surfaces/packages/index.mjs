// Packages — the canonical /packages surface packet (W2.3 bar, next-legs II Leg 2; recall +
// launcher join, next-legs III Leg 2).
//
// One module, two mounts, over the CLOSED daemon package family (MEF-CLOSED-003 — exactly eight
// /v1/hypervisor/packages/* routes: candidate create/list/get, release create/list/get, release
// recall, installation create/list/get, uninstall):
//
//   registry     — /packages (+ fresh legacy lane /__ioi/packages/registry): the package
//                  lifecycle projection. Candidates (frozen ODK source meshes), immutable
//                  content-addressed HypervisorSurfaceReleaseRecords, and installation bindings
//                  rendered with their FORCED-DISABLED truth verbatim: surface_enablement_state
//                  "disabled", launch_eligible:false, and the daemon's exact
//                  disabled_reason_codes — never a launchability claim.
//   marketplace  — /packages/marketplace (+ /__ioi/packages/marketplace): the OPTIONAL Packages
//                  mode (canon: a Marketplace entry point resolves to "Packages / Marketplace"
//                  and never becomes a second package owner). READ-FIRST in this packet: the
//                  daemon's marketplace overview + listing plane rendered honestly (honest-empty
//                  when the substrate has no listings); the governed draft→candidate→review→
//                  publish ladder keeps operating on its legacy owner lane until the
//                  marketplace-actions leg, and its controls render DISABLED here with the
//                  machine-readable reason.
//
// The family's admission contract, derived from the Rust (package_registry_routes.rs) + the
// package-registry smoke — the module speaks it exactly:
//   - identity-first: EVERY route (reads included) resolves the caller's principal before any
//     field is read; an anonymous call is a typed 401 request_principal_required. Module reads
//     therefore ride the request-scoped daemon capability (ctx.daemonFetch) so the caller's own
//     session is the read identity; an anonymous page render shows the typed refusal band, never
//     fabricated rows.
//   - owner-scoped: candidate create carries owner_ref (org://…); release + installation writes
//     derive the owner from the admitted candidate/release.
//   - caller idempotency: every mutation carries idempotency_key; an exact retry REPLAYS
//     (replayed:true, same head, same receipt_ref); the same key over different bytes refuses.
//   - exact-head CAS: release create carries expected_package_head, installation create
//     expected_release_head, uninstall expected_installation_head — a stale head is a typed 409
//     package_expected_head_conflict.
//   - admission evidence or nothing: a 2xx is believed only when the reply carries the family
//     record under its declared schema_version PLUS agentgres.receipt_ref. Anything less fails
//     CLOSED. Typed refusals render verbatim.
//
// RECALL landed WITH the registry (W2.3): POST .../releases/:digest/recall appends the immutable
// disposition successor (active → recalled) under exact-head CAS with a bounded reason. The
// cascade is DERIVED AT READ TIME — bindings keep their admitted bytes and every binding read
// resolves the current release head, so a recalled release reads back on its bindings as
// launch_eligible:false with the surface_release_recalled reason, immediately and after restart.
// The product-surface projection consumes the registry namespace live (W2.4 join): installed
// bindings on active releases appear in the launcher feed as honest ineligible entries; recalled
// and uninstalled surfaces are absent by derivation.
//
// NAMED GAPS this module still states instead of faking:
//   - deprecate / supersede / revoke: no daemon verb exists — recall is the family's ONE
//     disposition successor. The other enum values render disabled with
//     data-ioi-disabled-reason, never wired to an invented path.
//   - enable / registration / serving: installs are born disabled and the family owns no verb to
//     change that; the missing extension_application registration is named by the daemon's own
//     disabled_reason_codes, rendered verbatim. A launcher-feed entry is INVENTORY presence,
//     never launchability.
import { escHtml } from "../kit.mjs";

const esc = escHtml;
const enc = encodeURIComponent;
const LEGACY_ROUTE = "/__ioi/packages/registry";
const LEGACY_MARKETPLACE_ROUTE = "/__ioi/packages/marketplace";
const CANONICAL_ROUTE = "/packages";
const CANONICAL_MARKETPLACE_ROUTE = "/packages/marketplace";

export const meta = {
  slug: "packages",
  route: LEGACY_ROUTE,
  verifier: "scripts/verify-hypervisor-packages-journey.mjs",
  certification: "n/a",
};

const CANDIDATE_SCHEMA = "ioi.hypervisor.package_candidate.v1";
const RELEASE_SCHEMA = "ioi.hypervisor.surface_release_record.v1";
const INSTALLATION_SCHEMA = "ioi.hypervisor.surface_installation_binding.v1";
const PACKAGES_PLANE = "/v1/hypervisor/packages";

const DISPOSITION_GAP_REASON = "no daemon verb exists — recall is the family's one disposition successor (active → recalled); the registered enum also names 'deprecated' and 'superseded' but no route can set them, so these controls stay disabled instead of pretending";
const ENABLE_GAP_REASON = "no daemon verb exists — installation bindings are born surface_enablement_state 'disabled' (extension_application registration absent) and the family owns no enable/registration/serving route";
const LAUNCHER_JOIN_NOTE = "Launcher feed (live join): the product-surface projection consumes the package registry namespace on every read — an installed binding on an active release appears in application_entries as an honest INELIGIBLE entry (launchable:false with the exact derived reasons); a recalled or uninstalled surface is absent by derivation, immediately and after restart. Feed presence is inventory truth, never launchability.";
const MARKETPLACE_LADDER_REASON = "marketplace ladder actions (draft/patch/delete, publish candidate, review decide, publish, offer) operate on the /__ioi/marketplace legacy owner lane until the marketplace-actions leg — this mode is read-first";

// ---------------------------------------------------------------------------------------------
// load — every read is a typed-degradation projection through the shared read client, carried on
// the REQUEST-scoped daemon capability when the runtime supplies one (the packages family is
// identity-first on reads; a plain unauthenticated fetch would render every pane as a 401 band
// even for a signed-in operator). Anonymous stays anonymous: the capability forwards only the
// caller's own envelope, so a signed-out render shows the typed refusal, never another caller's truth.
export async function load(ctx) {
  const { createReadClient } = await import("../read-client.mjs");
  const client = typeof ctx.daemonFetch === "function"
    ? createReadClient({ daemon: "", fetchImpl: ctx.daemonFetch })
    : createReadClient({ daemon: ctx.daemon });
  const sp = ctx.url.searchParams;
  if (isMarketplaceMount(ctx.url.pathname)) {
    const results = await client.readMany({
      overview: "/v1/hypervisor/marketplace/overview",
      listings: "/v1/hypervisor/marketplace/listings",
    });
    return { mode: "marketplace", results };
  }
  const results = await client.readMany({
    packages: PACKAGES_PLANE,
    domain_apps: "/v1/hypervisor/domain-apps",
  });
  const model = { mode: "registry", results };
  const pkg = (sp.get("pkg") || "").trim();
  const rel = (sp.get("rel") || "").trim();
  const inst = (sp.get("inst") || "").trim();
  if (pkg) {
    model.candidate = await client.read(`${PACKAGES_PLANE}/${enc(pkg)}`);
    model.releases = await client.read(`${PACKAGES_PLANE}/${enc(pkg)}/releases`);
  }
  if (pkg && rel) {
    model.release = await client.read(`${PACKAGES_PLANE}/${enc(pkg)}/releases/${enc(rel)}`);
    model.installations = await client.read(`${PACKAGES_PLANE}/${enc(pkg)}/releases/${enc(rel)}/installations`);
  }
  if (pkg && rel && inst) {
    model.installation = await client.read(`${PACKAGES_PLANE}/${enc(pkg)}/releases/${enc(rel)}/installations/${enc(inst)}`);
  }
  return model;
}

function isMarketplaceMount(pathname) {
  return pathname === CANONICAL_MARKETPLACE_ROUTE || pathname === LEGACY_MARKETPLACE_ROUTE;
}

// ---------------------------------------------------------------------------------------------
// actions — ONLY the lifecycle verbs the daemon actually owns. There is deliberately no
// deprecate/supersede/revoke/enable action here: declaring one would invent an authority
// path the daemon refuses to own (the named gaps render disabled in the views instead).
const PKG_AUTHORITY = { plane: "hypervisor.packages", operation: "POST /v1/hypervisor/packages" };
const REL_AUTHORITY = { plane: "hypervisor.packages", operation: "POST /v1/hypervisor/packages/:package_id/releases (expected_package_head CAS)" };
const RECALL_AUTHORITY = { plane: "hypervisor.packages", operation: "POST /v1/hypervisor/packages/:package_id/releases/:release_digest/recall (expected_release_head CAS, idempotent replay)" };
const INST_AUTHORITY = { plane: "hypervisor.packages", operation: "POST /v1/hypervisor/packages/:package_id/releases/:release_digest/installations (expected_release_head CAS)" };
const UNINST_AUTHORITY = { plane: "hypervisor.packages", operation: "POST .../installations/:installation_id/uninstall (expected_installation_head CAS, idempotent replay)" };
export const actions = [
  { id: "admit-candidate", method: "POST", route: "/actions/admit-candidate", fields: ["owner_ref", "package_id", "domain_app_ref", "idempotency_key"], context: [], authority: PKG_AUTHORITY, receipt: CANDIDATE_SCHEMA, confirm: false, success: "return-to-surface", refusal: "typed-banner" },
  { id: "cut-release", method: "POST", route: "/:id/cut-release", fields: ["idempotency_key", "expected_package_head", "surface_distribution", "surface_capability_depth", "object_contract_refs", "action_contract_refs", "evidence_refs"], fieldMax: 4096, context: ["id"], authority: REL_AUTHORITY, receipt: RELEASE_SCHEMA, confirm: false, success: "return-to-surface", refusal: "typed-banner" },
  { id: "recall-release", method: "POST", route: "/:id/recall", fields: ["idempotency_key", "release_digest", "expected_release_head", "reason"], fieldMax: 600, context: ["id"], authority: RECALL_AUTHORITY, receipt: RELEASE_SCHEMA, confirm: false, success: "return-to-surface", refusal: "typed-banner" },
  { id: "install-release", method: "POST", route: "/:id/install", fields: ["idempotency_key", "release_digest", "expected_release_head", "installation_id", "project_ref", "visibility", "allowed_object_contract_refs", "allowed_action_refs"], fieldMax: 4096, context: ["id"], authority: INST_AUTHORITY, receipt: INSTALLATION_SCHEMA, confirm: false, success: "return-to-surface", refusal: "typed-banner" },
  { id: "uninstall", method: "POST", route: "/:id/uninstall", fields: ["idempotency_key", "release_digest", "installation_id", "expected_installation_head"], context: ["id"], authority: UNINST_AUTHORITY, receipt: INSTALLATION_SCHEMA, confirm: false, success: "return-to-surface", refusal: "typed-banner" },
];

// The authored ref-list fields arrive as one text blob; the daemon wants exact JSON arrays.
// Splitting on whitespace/commas is SHAPE only — uniqueness, prefixes, and subset-of-release
// narrowing are the daemon's judgments and its typed refusals render verbatim.
const refList = (value) => String(value ?? "").split(/[\s,]+/u).map((part) => part.trim()).filter(Boolean);

export async function handleAction({ action, id, fields, daemonFetch }) {
  if (typeof daemonFetch !== "function") {
    return { kind: "failure", http: 500, code: "identity_capability_missing", message: "the action runtime supplied no request-scoped daemon capability — refusing to mutate without the caller's identity" };
  }
  let path = "";
  const body = { idempotency_key: fields.idempotency_key };
  let redirect = `${LEGACY_ROUTE}`;
  if (action.id === "admit-candidate") {
    path = PACKAGES_PLANE;
    body.package_id = fields.package_id;
    body.owner_ref = fields.owner_ref;
    body.domain_app_ref = fields.domain_app_ref;
    redirect = `${LEGACY_ROUTE}?pkg=${enc(fields.package_id || "")}`;
  } else if (action.id === "cut-release") {
    path = `${PACKAGES_PLANE}/${enc(id)}/releases`;
    body.expected_package_head = fields.expected_package_head;
    body.surface_distribution = fields.surface_distribution;
    body.surface_capability_depth = fields.surface_capability_depth;
    body.object_contract_refs = refList(fields.object_contract_refs);
    body.action_contract_refs = refList(fields.action_contract_refs);
    body.evidence_refs = refList(fields.evidence_refs);
    redirect = `${LEGACY_ROUTE}?pkg=${enc(id)}`;
  } else if (action.id === "recall-release") {
    path = `${PACKAGES_PLANE}/${enc(id)}/releases/${enc(fields.release_digest || "")}/recall`;
    body.expected_release_head = fields.expected_release_head;
    body.reason = fields.reason;
    redirect = `${LEGACY_ROUTE}?pkg=${enc(id)}&rel=${enc(fields.release_digest || "")}`;
  } else if (action.id === "install-release") {
    path = `${PACKAGES_PLANE}/${enc(id)}/releases/${enc(fields.release_digest || "")}/installations`;
    body.installation_id = fields.installation_id;
    body.expected_release_head = fields.expected_release_head;
    body.project_ref = fields.project_ref ? fields.project_ref : null;
    body.visibility = fields.visibility;
    body.allowed_object_contract_refs = refList(fields.allowed_object_contract_refs);
    body.allowed_action_refs = refList(fields.allowed_action_refs);
    redirect = `${LEGACY_ROUTE}?pkg=${enc(id)}&rel=${enc(fields.release_digest || "")}&inst=${enc(fields.installation_id || "")}`;
  } else if (action.id === "uninstall") {
    path = `${PACKAGES_PLANE}/${enc(id)}/releases/${enc(fields.release_digest || "")}/installations/${enc(fields.installation_id || "")}/uninstall`;
    body.expected_installation_head = fields.expected_installation_head;
    redirect = `${LEGACY_ROUTE}?pkg=${enc(id)}&rel=${enc(fields.release_digest || "")}&inst=${enc(fields.installation_id || "")}`;
  } else {
    return { kind: "failure", http: 500, code: "action_unknown", message: `undeclared action '${action.id}'` };
  }
  const response = await daemonFetch(path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  }).catch(() => null);
  if (!response) return { kind: "failure", http: 502, code: "daemon_unavailable", message: "the daemon did not answer — nothing was changed" };
  const payload = await response.json().catch(() => null);
  if (!payload) return { kind: "failure", http: 502, code: "daemon_reply_unreadable", message: `the daemon answered ${response.status} without a readable body — do not trust the mutation` };
  if (payload.ok !== true) {
    // The daemon's typed refusal, VERBATIM — {error:{code,message}} on this family's validation
    // and scope refusals; flat {code,message} kept for shared-foundation shapes.
    const code = payload.error?.code || payload.code || `http_${response.status}`;
    let message = payload.error?.message || payload.message || payload.reason || "refused — state unchanged";
    if (code === "package_expected_head_conflict" || code === "event_stream_expected_head_conflict") {
      message = `${message} — the record moved; re-open it to get the fresh admitted head, then re-submit`;
    }
    return { kind: "refusal", http: response.status || 409, code, message };
  }
  // Admission evidence or nothing: the family envelope ({package|release|installation}) must
  // carry the record under the DECLARED schema plus agentgres.receipt_ref. Fail closed otherwise.
  const envelope = payload.package || payload.release || payload.installation || null;
  const record = envelope?.record || null;
  const receiptRef = typeof envelope?.agentgres?.receipt_ref === "string" ? envelope.agentgres.receipt_ref : "";
  if (!record || record.schema_version !== action.receipt || !receiptRef.startsWith("receipt://")) {
    return { kind: "failure", http: 502, code: "receipt_missing", message: `the mutation answered 2xx without the ${action.receipt} record + agentgres receipt_ref admission evidence — failing closed (do not trust the mutation)` };
  }
  const replayed = envelope.agentgres?.replayed === true;
  let created = "";
  let status = "";
  if (action.id === "admit-candidate") {
    created = record.package_id || "";
    status = replayed ? "replayed" : (record.status || "candidate");
    redirect = `${LEGACY_ROUTE}?pkg=${enc(created)}`;
  } else if (action.id === "cut-release" || action.id === "recall-release") {
    const digest = String(record.release_ref || "").split("/release/").at(-1) || "";
    created = digest;
    status = replayed
      ? "replayed"
      : (action.id === "recall-release"
        ? (record.surface_package_disposition || "recalled")
        : `${record.surface_admission_state || ""}/${record.surface_package_disposition || ""}`);
    redirect = `${LEGACY_ROUTE}?pkg=${enc(id)}&rel=${enc(digest)}`;
  } else {
    created = fields.installation_id || String(record.installation_ref || "").split("/").at(-1) || "";
    status = replayed ? "replayed" : (record.surface_installation_state || "");
  }
  return { kind: "success", status, created, receipt_ref: receiptRef, redirect };
}

// ---------------------------------------------------------------------------------------------
// render helpers (the studio module's grammar — pills, typed degradation, disabled named gaps)
const pill = (cls, label) => `<span class="pill ${cls}">${esc(label)}</span>`;
const code = (v) => (v ? `<code>${esc(String(v))}</code>` : "—");
const shortHash = (h) => { const s = String(h || ""); return s.length > 22 ? `${s.slice(0, 22)}…` : s; };
const degraded = (result) => `<div class="empty">unavailable — <code>${esc(result?.code || "daemon_unavailable")}</code> (${esc(result?.message || "the plane did not answer")})</div>`;
const rowsOf = (result, key) => (result?.ok ? (Array.isArray(result.payload?.[key]) ? result.payload[key] : []) : null);
const disabledCtl = (label, reason) => `<button class="act ghost" type="button" disabled data-ioi-disabled-reason="${esc(reason)}">${esc(label)}</button>`;
const mintKey = () => `packages-ui-${globalThis.crypto.randomUUID()}`;
const reasonCodes = (codes) => (Array.isArray(codes) && codes.length ? codes.map((c) => `<code>${esc(c)}</code>`).join(" ") : "—");

function banner(sp) {
  const acted = sp.get("acted") || "";
  const receipt = sp.get("receipt") || "";
  const refused = sp.get("refused") || "";
  const reason = sp.get("reason") || "";
  const result = sp.get("result") || "";
  const record = sp.get("record") || "";
  if (acted && receipt) {
    return `<div id="ap-result" class="banner ok-banner" tabindex="-1"><b>${esc(acted)}</b> recorded${result ? ` — <b>${esc(result)}</b>` : ""}${record ? ` · record <code>${esc(record)}</code>` : ""} · receipt <code>${esc(receipt)}</code> · <a href="/__ioi/work-ledger">proof stream</a></div>`;
  }
  if (refused) {
    return `<div id="ap-result" class="banner no-banner" tabindex="-1">refused: <code>${esc(refused)}</code>${reason ? ` — ${esc(reason)}` : ""} · <b>state unchanged</b></div>`;
  }
  return "";
}

// One installation binding row/grid fragment — the FORCED-DISABLED truth rendered verbatim:
// the daemon's own enablement state, launch_eligible, the DERIVED release disposition (the
// recall cascade reads it from the current release head on every request), and the exact
// derived disabled_reason_codes — including surface_release_recalled when the release was
// recalled, with the bounded recall reason verbatim.
function bindingTruth(entry) {
  const record = entry.record || {};
  const recalled = entry.release_disposition === "recalled";
  return `${pill(record.surface_installation_state === "installed" ? "ok" : "muted", record.surface_installation_state || "—")}
    ${pill("warn", record.surface_enablement_state || "—")}
    ${entry.release_disposition ? pill(recalled ? "warn" : "ok", `release ${entry.release_disposition}`) : ""}
    ${pill(entry.launch_eligible === false ? "warn" : "muted", `launch_eligible: ${String(entry.launch_eligible)}`)}
    <div class="sub" style="margin:4px 0 0;text-transform:none;letter-spacing:0">reasons: ${reasonCodes(entry.disabled_reason_codes)}</div>
    ${recalled && entry.release_recall_reason ? `<div class="sub" style="margin:4px 0 0;text-transform:none;letter-spacing:0">recall reason: ${esc(String(entry.release_recall_reason))}</div>` : ""}`;
}

// ---- Registry landing ---------------------------------------------------------------------------
function catalogView(model, base) {
  const rows = rowsOf(model.results.packages, "packages");
  const domainApps = rowsOf(model.results.domain_apps, "domain_apps");
  const list = rows === null
    ? degraded(model.results.packages)
    : (rows.length
      ? `<table><thead><tr><th>Package</th><th>Owner</th><th>Status</th><th>Registration</th><th>Candidate hash</th></tr></thead><tbody>${rows.map((p) => {
        const r = p.record || {};
        return `<tr>
          <td><a href="${base}?pkg=${enc(r.package_id || "")}"><b>${esc(r.package_id || "—")}</b></a><div style="color:#878a93;font-size:11.5px"><code>${esc(r.package_ref || "")}</code></div></td>
          <td>${code(r.owner_ref)}</td>
          <td>${pill("muted", r.status || "—")}</td>
          <td>${pill("warn", `registration ${r.registration_state || "absent"}`)}</td>
          <td><code title="${esc(r.candidate_content_hash || "")}">${esc(shortHash(r.candidate_content_hash))}</code></td>
        </tr>`;
      }).join("")}</tbody></table>`
      : `<div class="empty">No package candidates yet — freeze one below. A candidate snapshots one draft DomainApp + its ODK manifest + surface descriptor content-addressed; it creates no registration, route, process, or launch eligibility.</div>`);
  const appOptions = domainApps === null
    ? null
    : domainApps.filter((d) => (d.status || "") === "draft" && d.odk_manifest_ref && d.surface_descriptor_ref);
  const form = appOptions === null
    ? `<div class="empty">${model.results.domain_apps?.ok === false ? `The DomainApp plane is unavailable (<code>${esc(model.results.domain_apps?.code || "daemon_unavailable")}</code>) — admission is disabled rather than guessed.` : "unavailable"}</div>`
    : (appOptions.length
      ? `<form class="aform" method="post" action="${LEGACY_ROUTE}/actions/admit-candidate">
          <input type="hidden" name="idempotency_key" value="${esc(mintKey())}">
          <input type="hidden" name="return" value="${esc(LEGACY_ROUTE)}">
          <label class="fl">Owner (org://…)<input name="owner_ref" placeholder="org://…" required title="The single org:// that owns this package. The daemon admits the candidate under it and refuses a caller who holds no authority over it."></label>
          <label class="fl">Package id (globally unique, lowercase)<input name="package_id" maxlength="128" pattern="[a-z0-9][a-z0-9._-]*" required></label>
          <label class="fl">DomainApp (draft, with ODK manifest + descriptor bound)<select name="domain_app_ref">${appOptions.map((d) => `<option value="${esc(d.domain_app_ref || "")}">${esc(d.name || d.domain_app_ref || "")}</option>`).join("")}</select></label>
          <button class="act" type="submit">Admit candidate</button>
          <span class="sub" style="margin:0;text-transform:none;letter-spacing:0">idempotent: an exact retry replays the original admission (same head, same receipt)</span>
        </form>`
      : `<div class="empty">Candidate admission needs a <b>draft</b> DomainApp with a bound ODK manifest and a <code>domain_app</code> surface descriptor — none exists yet. Author the source mesh in the <a href="/__ioi/odk">ODK workbench</a> first.</div>`);
  return `<h2 id="catalog">Package candidates</h2>
    <p class="sub" style="margin:-4px 0 12px">The daemon's owner-filtered package inventory, reconstructed from admitted Agentgres truth on every read. A candidate freezes exact DomainApp/manifest/descriptor bytes; releases and installs hang off it below.</p>
    ${list}
    <h3 style="margin:18px 0 6px;font-size:13px">Admit a package candidate</h3>${form}
    <h2 id="lifecycle-ceiling">Lifecycle ceiling</h2>
    <div class="gapcard">
      <p class="sub" style="margin:0 0 8px;text-transform:none;letter-spacing:0">The closed daemon family ends at its two successor verbs — <b>recall</b> (on the release detail, active → recalled with a bounded reason) and <b>uninstall</b>. What does NOT exist yet, stated rather than faked:</p>
      ${disabledCtl("Deprecate", DISPOSITION_GAP_REASON)} ${disabledCtl("Supersede", DISPOSITION_GAP_REASON)} ${disabledCtl("Revoke", DISPOSITION_GAP_REASON)} ${disabledCtl("Enable", ENABLE_GAP_REASON)}
      <p class="sub" style="margin:8px 0 0;text-transform:none;letter-spacing:0">${esc(LAUNCHER_JOIN_NOTE)}</p>
    </div>`;
}

// ---- Candidate detail + releases ---------------------------------------------------------------
function candidateView(model, base, pkg) {
  const d = model.candidate;
  if (!d?.ok || d.payload?.ok !== true || !d.payload.package) {
    return `<h2>Package ${esc(pkg)}</h2>${d?.ok && d.payload?.ok === false ? `<div class="empty">not found — <code>${esc(d.payload?.error?.code || "package_candidate_not_found")}</code></div>` : degraded(d)}`;
  }
  const p = d.payload.package;
  const r = p.record || {};
  const head = p.agentgres?.head || "";
  const snaps = r.source_snapshots || {};
  const releases = rowsOf(model.releases, "releases");
  const relList = releases === null
    ? degraded(model.releases)
    : (releases.length
      ? `<table><thead><tr><th>Release</th><th>Distribution</th><th>Depth</th><th>Admission</th><th>Disposition</th><th>Evidence</th></tr></thead><tbody>${releases.map((rel) => {
        const rr = rel.record || {};
        const digest = String(rr.release_ref || "").split("/release/").at(-1) || "";
        return `<tr>
          <td><a href="${base}?pkg=${enc(pkg)}&rel=${enc(digest)}"><code>${esc(shortHash(digest))}</code></a></td>
          <td>${pill("muted", rr.surface_distribution || "—")}</td>
          <td>${pill("muted", rr.surface_capability_depth || "—")}</td>
          <td>${pill(rr.surface_admission_state === "admitted" ? "ok" : "muted", rr.surface_admission_state || "—")}</td>
          <td>${pill(rr.surface_package_disposition === "active" ? "ok" : "warn", rr.surface_package_disposition || "—")}</td>
          <td>${(rr.evidence_refs || []).length} ref(s)</td>
        </tr>`;
      }).join("")}</tbody></table>`
      : `<div class="empty">No releases yet — cut one below against the exact candidate head. A release is immutable and content-addressed; admitting it registers, installs, serves, and authorizes nothing.</div>`);
  const casNote = head
    ? `<span class="sub" style="margin:0;text-transform:none;letter-spacing:0">compare-and-swap against admitted candidate head <code>${esc(shortHash(head))}</code></span>`
    : `<span class="sub" style="margin:0;text-transform:none;letter-spacing:0">no admitted head is readable — release admission is disabled rather than guessed</span>`;
  const dis = head ? "" : " disabled";
  return `<h2 id="candidate-detail">Package detail</h2>
    <dl class="grid">
      <dt>Package</dt><dd><b>${esc(r.package_id || "—")}</b> · ${code(r.package_ref)}</dd>
      <dt>Candidate ref</dt><dd>${code(r.package_candidate_ref)}</dd>
      <dt>Owner</dt><dd>${code(r.owner_ref)}</dd>
      <dt>Surface</dt><dd>${code(r.surface_ref)} ${pill("muted", r.surface_class || "—")}</dd>
      <dt>Status</dt><dd>${pill("muted", r.status || "—")} ${pill("warn", `registration ${r.registration_state || "absent"}`)}</dd>
      <dt>Source snapshots</dt><dd>
        domain-app <code title="${esc(snaps.domain_app_content_hash || "")}">${esc(shortHash(snaps.domain_app_content_hash))}</code><br>
        odk-manifest <code title="${esc(snaps.odk_manifest_content_hash || "")}">${esc(shortHash(snaps.odk_manifest_content_hash))}</code><br>
        descriptor <code title="${esc(snaps.surface_descriptor_content_hash || "")}">${esc(shortHash(snaps.surface_descriptor_content_hash))}</code></dd>
      <dt>Candidate hash</dt><dd><code data-testid="pkg-candidate-hash">${esc(r.candidate_content_hash || "—")}</code></dd>
      <dt>Admitted head</dt><dd><code data-testid="pkg-admitted-head">${esc(head || "—")}</code></dd>
      <dt>Receipt</dt><dd>${code(p.agentgres?.receipt_ref)}</dd>
      <dt>Nonclaim</dt><dd class="sub" style="text-transform:none;letter-spacing:0;margin:0">${esc(r.nonclaim || "—")}</dd>
    </dl>
    <h3 style="margin:16px 0 6px;font-size:13px">Releases</h3>${relList}
    <h3 style="margin:16px 0 6px;font-size:13px">Cut an immutable release</h3>
    <form class="aform" method="post" action="${LEGACY_ROUTE}/${enc(pkg)}/cut-release">
      <input type="hidden" name="idempotency_key" value="${esc(mintKey())}">
      <input type="hidden" name="return" value="${esc(`${LEGACY_ROUTE}?pkg=${enc(pkg)}`)}">
      ${head ? `<input type="hidden" name="expected_package_head" value="${esc(head)}">` : ""}
      <label class="fl">Distribution<select name="surface_distribution"${dis}>${["private_registry", "organization_catalog", "direct_package", "marketplace", "bundled"].map((v) => `<option value="${v}">${v.replace(/_/g, " ")}</option>`).join("")}</select></label>
      <label class="fl">Capability depth<select name="surface_capability_depth"${dis}>${["browse", "inspect", "propose", "act", "workflow_complete"].map((v) => `<option value="${v}"${v === "propose" ? " selected" : ""}>${v.replace(/_/g, " ")}</option>`).join("")}</select></label>
      <label class="fl">Object contract refs (whitespace/comma separated)<textarea name="object_contract_refs" rows="2" placeholder="object-model://…"${dis}></textarea></label>
      <label class="fl">Action contract refs<textarea name="action_contract_refs" rows="2" placeholder="action://…"${dis}></textarea></label>
      <label class="fl">Evidence refs (artifact:// evidence:// receipt:// — the candidate's own receipt is bound automatically)<textarea name="evidence_refs" rows="2" placeholder="artifact://…"${dis}></textarea></label>
      <button class="act" type="submit"${dis}>Cut release</button> ${casNote}
    </form>`;
}

// ---- Release detail + installations ------------------------------------------------------------
function releaseView(model, base, pkg, rel) {
  const d = model.release;
  if (!d?.ok || d.payload?.ok !== true || !d.payload.release) {
    return `<h2>Release ${esc(shortHash(rel))}</h2>${d?.ok && d.payload?.ok === false ? `<div class="empty">not found — <code>${esc(d.payload?.error?.code || "package_release_not_found")}</code></div>` : degraded(d)}`;
  }
  const envelope = d.payload.release;
  const rr = envelope.record || {};
  const head = envelope.agentgres?.head || "";
  const recalled = rr.surface_package_disposition === "recalled";
  const installations = rowsOf(model.installations, "installations");
  const instList = installations === null
    ? degraded(model.installations)
    : (installations.length
      ? `<table><thead><tr><th>Installation</th><th>Binding truth</th><th>Visibility</th><th>Rev</th></tr></thead><tbody>${installations.map((entry) => {
        const ir = entry.record || {};
        const iid = String(ir.installation_ref || "").split("/").at(-1) || "";
        return `<tr>
          <td><a href="${base}?pkg=${enc(pkg)}&rel=${enc(rel)}&inst=${enc(iid)}"><b>${esc(iid)}</b></a><div style="color:#878a93;font-size:11.5px"><code>${esc(ir.installation_ref || "")}</code></div></td>
          <td>${bindingTruth(entry)}</td>
          <td>${pill("muted", ir.visibility || "—")}</td>
          <td>${esc(String(ir.revision ?? "—"))}</td>
        </tr>`;
      }).join("")}</tbody></table>`
      : `<div class="empty">No installation bindings for this release yet — bind one below. An installation is REAL and immediately <b>disabled</b>: the daemon refuses to claim launchability it does not own.</div>`);
  const casNote = head
    ? `<span class="sub" style="margin:0;text-transform:none;letter-spacing:0">compare-and-swap against admitted release head <code>${esc(shortHash(head))}</code></span>`
    : `<span class="sub" style="margin:0;text-transform:none;letter-spacing:0">no admitted head is readable — installation is disabled rather than guessed</span>`;
  const dis = head ? "" : " disabled";
  return `<h2 id="release-detail">Release detail <span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">— immutable, content-addressed</span></h2>
    <dl class="grid">
      <dt>Release ref</dt><dd><code data-testid="rel-ref">${esc(rr.release_ref || "—")}</code></dd>
      <dt>Package</dt><dd><a href="${base}?pkg=${enc(pkg)}">${code(rr.package_ref)}</a></dd>
      <dt>Surface</dt><dd>${code(rr.surface_ref)}</dd>
      <dt>Distribution · depth</dt><dd>${pill("muted", rr.surface_distribution || "—")} ${pill("muted", rr.surface_capability_depth || "—")}</dd>
      <dt>Admission</dt><dd>${pill(rr.surface_admission_state === "admitted" ? "ok" : "muted", rr.surface_admission_state || "—")} ${pill(rr.surface_package_disposition === "active" ? "ok" : "warn", rr.surface_package_disposition || "—")} <span class="sub" style="margin:0;text-transform:none;letter-spacing:0">recall (below) is the one disposition successor the daemon owns — an immutable revision on this stream, never an edit</span></dd>
      ${recalled ? `<dt>Recall reason</dt><dd data-testid="rel-recall-reason">${esc(String(envelope.recall_reason ?? "—"))}</dd>` : ""}
      <dt>Object contracts</dt><dd>${(rr.object_contract_refs || []).map((v) => code(v)).join("<br>") || "—"}</dd>
      <dt>Action contracts</dt><dd>${(rr.action_contract_refs || []).map((v) => code(v)).join("<br>") || "—"}</dd>
      <dt>Evidence</dt><dd>${(rr.evidence_refs || []).map((v) => code(v)).join("<br>") || "—"}</dd>
      <dt>Candidate binding</dt><dd>${code(envelope.package_candidate_ref)}<br><span class="sub" style="margin:0;text-transform:none;letter-spacing:0">admitted against candidate head</span> ${code(envelope.package_candidate_head)}</dd>
      <dt>Admitted head</dt><dd><code data-testid="rel-admitted-head">${esc(head || "—")}</code></dd>
      <dt>Registration</dt><dd>${pill("warn", `registration ${envelope.registration_state || "absent"}`)}</dd>
    </dl>
    <h3 style="margin:16px 0 6px;font-size:13px">Recall this release</h3>
    ${recalled ? `<div class="empty">Already recalled — the disposition successor is immutable history; re-submitting the original recall replays it. Bindings over this release read back <code>launch_eligible: false</code> with <code>surface_release_recalled</code>, and the launcher feed no longer carries the surface.</div>` : `<form class="aform" method="post" action="${LEGACY_ROUTE}/${enc(pkg)}/recall">
      <input type="hidden" name="idempotency_key" value="${esc(mintKey())}">
      <input type="hidden" name="return" value="${esc(`${LEGACY_ROUTE}?pkg=${enc(pkg)}&rel=${enc(rel)}`)}">
      <input type="hidden" name="release_digest" value="${esc(rel)}">
      ${head ? `<input type="hidden" name="expected_release_head" value="${esc(head)}">` : ""}
      <label class="fl">Reason (required, bounded — recorded verbatim on the admitted successor)<textarea name="reason" rows="2" maxlength="500" required${dis}></textarea></label>
      <button class="act" type="submit"${dis}>Recall (active → recalled, immutable successor)</button> ${casNote}
      <span class="sub" style="margin:0;text-transform:none;letter-spacing:0">the cascade is derived at read: every binding over this release immediately reads back ineligible with the recall named, and the surface leaves the launcher feed — no binding bytes are mutated</span>
    </form>`}
    <div class="gapcard">
      ${disabledCtl("Deprecate", DISPOSITION_GAP_REASON)} ${disabledCtl("Supersede", DISPOSITION_GAP_REASON)} ${disabledCtl("Revoke", DISPOSITION_GAP_REASON)}
      <p class="sub" style="margin:8px 0 0;text-transform:none;letter-spacing:0">${esc(LAUNCHER_JOIN_NOTE)}</p>
    </div>
    <h3 style="margin:16px 0 6px;font-size:13px">Installation bindings</h3>${instList}
    <h3 style="margin:16px 0 6px;font-size:13px">Install this exact release</h3>
    ${recalled ? `<div class="empty">Installation is closed: the daemon refuses a binding over a recalled release (<code>package_release_not_installable</code>) — the form is withheld rather than submitted to fail.</div>` : `<form class="aform" method="post" action="${LEGACY_ROUTE}/${enc(pkg)}/install">
      <input type="hidden" name="idempotency_key" value="${esc(mintKey())}">
      <input type="hidden" name="return" value="${esc(`${LEGACY_ROUTE}?pkg=${enc(pkg)}&rel=${enc(rel)}`)}">
      <input type="hidden" name="release_digest" value="${esc(rel)}">
      ${head ? `<input type="hidden" name="expected_release_head" value="${esc(head)}">` : ""}
      <label class="fl">Installation id (lowercase)<input name="installation_id" maxlength="128" pattern="[a-z0-9][a-z0-9._-]*" required${dis}></label>
      <label class="fl">Visibility<select name="visibility"${dis}>${["private", "organization", "permissioned", "public"].map((v) => `<option value="${v}"${v === "organization" ? " selected" : ""}>${v}</option>`).join("")}</select></label>
      <label class="fl">Project (project://…, optional)<input name="project_ref" maxlength="300" placeholder="project://…"${dis}></label>
      <label class="fl">Allowed object contracts (may only NARROW the release set)<textarea name="allowed_object_contract_refs" rows="2"${dis}>${esc((rr.object_contract_refs || []).join("\n"))}</textarea></label>
      <label class="fl">Allowed action refs (may only NARROW the release set)<textarea name="allowed_action_refs" rows="2"${dis}>${esc((rr.action_contract_refs || []).join("\n"))}</textarea></label>
      <button class="act" type="submit"${dis}>Install (binding is created disabled)</button> ${casNote}
    </form>`}`;
}

// ---- Installation detail -----------------------------------------------------------------------
function installationView(model, base, pkg, rel, inst) {
  const d = model.installation;
  if (!d?.ok || d.payload?.ok !== true || !d.payload.installation) {
    return `<h2>Installation ${esc(inst)}</h2>${d?.ok && d.payload?.ok === false ? `<div class="empty">not found — <code>${esc(d.payload?.error?.code || "package_installation_not_found")}</code></div>` : degraded(d)}`;
  }
  const entry = d.payload.installation;
  const ir = entry.record || {};
  const head = entry.agentgres?.head || "";
  const uninstalled = ir.surface_installation_state === "uninstalled";
  const casNote = head
    ? `<span class="sub" style="margin:0;text-transform:none;letter-spacing:0">compare-and-swap against admitted installation head <code>${esc(shortHash(head))}</code></span>`
    : `<span class="sub" style="margin:0;text-transform:none;letter-spacing:0">no admitted head is readable — uninstall is disabled rather than guessed</span>`;
  const dis = head && !uninstalled ? "" : " disabled";
  return `<h2 id="installation-detail">Installation binding</h2>
    <dl class="grid">
      <dt>Installation</dt><dd><code data-testid="inst-ref">${esc(ir.installation_ref || "—")}</code></dd>
      <dt>Release</dt><dd><a href="${base}?pkg=${enc(pkg)}&rel=${enc(rel)}">${code(ir.release_ref)}</a></dd>
      <dt>Org · project</dt><dd>${code(ir.org_ref)} ${ir.project_ref ? code(ir.project_ref) : `<span class="sub" style="margin:0;text-transform:none;letter-spacing:0">org-wide</span>`}</dd>
      <dt>Binding truth</dt><dd data-testid="inst-binding-truth">${bindingTruth(entry)}</dd>
      <dt>Registration</dt><dd>${pill("warn", `registration ${entry.registration_state || "absent"}`)}</dd>
      <dt>Visibility · revision</dt><dd>${pill("muted", ir.visibility || "—")} · rev ${esc(String(ir.revision ?? "—"))}</dd>
      <dt>Allowed objects</dt><dd>${(ir.allowed_object_contract_refs || []).map((v) => code(v)).join("<br>") || "—"}</dd>
      <dt>Allowed actions</dt><dd>${(ir.allowed_action_refs || []).map((v) => code(v)).join("<br>") || "—"}</dd>
      <dt>Admitted head</dt><dd><code data-testid="inst-admitted-head">${esc(head || "—")}</code></dd>
      <dt>Nonclaim</dt><dd class="sub" style="text-transform:none;letter-spacing:0;margin:0">${esc(entry.record?.nonclaim || d.payload.installation?.nonclaim || "The binding claims no runtime, route, or launch authority.")}</dd>
    </dl>
    <div class="gapcard">
      ${disabledCtl("Enable", ENABLE_GAP_REASON)}
      <p class="sub" style="margin:8px 0 0;text-transform:none;letter-spacing:0">Recall operates on the <a href="${base}?pkg=${enc(pkg)}&rel=${enc(rel)}">release</a>, never on one binding — a recalled release reads back here as <code>surface_release_recalled</code> with launch eligibility derived false, and the surface leaves the launcher feed.</p>
      <p class="sub" style="margin:8px 0 0;text-transform:none;letter-spacing:0">${esc(LAUNCHER_JOIN_NOTE)}</p>
    </div>
    <h3 style="margin:16px 0 6px;font-size:13px">Uninstall</h3>
    ${uninstalled ? `<div class="empty">Already uninstalled (revision ${esc(String(ir.revision ?? ""))}) — the transition is immutable history; re-submitting the original uninstall replays it.</div>` : ""}
    <form class="aform" method="post" action="${LEGACY_ROUTE}/${enc(pkg)}/uninstall">
      <input type="hidden" name="idempotency_key" value="${esc(mintKey())}">
      <input type="hidden" name="return" value="${esc(`${LEGACY_ROUTE}?pkg=${enc(pkg)}&rel=${enc(rel)}&inst=${enc(inst)}`)}">
      <input type="hidden" name="release_digest" value="${esc(rel)}">
      <input type="hidden" name="installation_id" value="${esc(inst)}">
      ${head ? `<input type="hidden" name="expected_installation_head" value="${esc(head)}">` : ""}
      <button class="act" type="submit"${dis}>Uninstall (removes only the local binding)</button> ${casNote}
    </form>`;
}

// ---- Marketplace mode --------------------------------------------------------------------------
function marketplaceView(model, registryBase) {
  const overview = model.results.overview;
  const listings = rowsOf(model.results.listings, "listings");
  const m = overview?.ok ? (overview.payload?.marketplace || {}) : null;
  const counts = m === null
    ? degraded(overview)
    : `<dl class="grid">
        <dt>Listings</dt><dd>${esc(String(m.listings ?? 0))} (${esc(String(m.published ?? 0))} published)</dd>
        <dt>Publish candidates</dt><dd>${esc(String(m.publish_candidates ?? 0))}</dd>
        <dt>Admission reviews</dt><dd>${esc(String(m.admission_reviews ?? 0))}</dd>
        <dt>Managed-instance offers</dt><dd>${esc(String(m.managed_instance_offers ?? 0))} <span class="sub" style="margin:0;text-transform:none;letter-spacing:0">(drafts only — never instantiated here)</span></dd>
        <dt>Publish invariant</dt><dd class="sub" style="text-transform:none;letter-spacing:0;margin:0">${esc(overview.payload?.status_note || "—")}</dd>
      </dl>`;
  const list = listings === null
    ? degraded(model.results.listings)
    : (listings.length
      ? `<table><thead><tr><th>Listing</th><th>Kind</th><th>Status</th><th>Public state</th><th>Updated</th></tr></thead><tbody>${listings.map((l) => `<tr>
          <td><b>${esc(l.name || l.id || "—")}</b><div style="color:#878a93;font-size:11.5px"><code>${esc(l.ref || l.id || "")}</code></div></td>
          <td>${pill("muted", l.listing_kind || "—")}</td>
          <td>${pill(l.status === "published" ? "ok" : "muted", l.status || "—")}</td>
          <td>${pill(l.public_state === "published" ? "ok" : "muted", l.public_state || "draft")}</td>
          <td>${esc(l.updated_at || "—")}</td>
        </tr>`).join("")}</tbody></table>`
      : `<div class="empty">No marketplace listings — the substrate is genuinely empty, not hidden. A listing drafts over real substrate on the governed lane; distribution metadata only, never an install.</div>`);
  return `<h2 id="marketplace-overview">Marketplace substrate</h2>
    <p class="sub" style="margin:-4px 0 12px"><b>Packages / Marketplace</b> — the optional discovery mode of the Packages owner (canon: a Marketplace entry point resolves here and never becomes a second package owner; marketplace admission is NOT package admission). This mode is <b>read-first</b>: real listing-plane truth below, verbs on their owner lane.</p>
    ${counts}
    <h3 style="margin:16px 0 6px;font-size:13px">Listings</h3>${list}
    <div class="gapcard">
      ${disabledCtl("Draft listing", MARKETPLACE_LADDER_REASON)} ${disabledCtl("Publish", MARKETPLACE_LADDER_REASON)} ${disabledCtl("Review", MARKETPLACE_LADDER_REASON)}
      <p class="sub" style="margin:8px 0 0;text-transform:none;letter-spacing:0">The governed draft→candidate→review→publish ladder keeps operating on <a href="/__ioi/marketplace">the /__ioi/marketplace owner lane</a> (storefront seed: <a href="/__ioi/marketplace/listings">listings</a>) until the marketplace-actions leg. Installing from a listing re-enters through the <a href="${registryBase}">package registry</a> — never a storefront-side install runtime.</p>
    </div>`;
}

// ---------------------------------------------------------------------------------------------
export function render(model, ctx) {
  const sp = ctx.url.searchParams;
  const onLegacyMount = ctx.url.pathname.startsWith("/__ioi/");
  const registryBase = onLegacyMount ? LEGACY_ROUTE : CANONICAL_ROUTE;
  const marketplaceBase = onLegacyMount ? LEGACY_MARKETPLACE_ROUTE : CANONICAL_MARKETPLACE_ROUTE;
  const marketplace = model.mode === "marketplace";
  const nav = `<nav class="tabs" aria-label="Packages">
    <a class="tab${marketplace ? "" : " active"}" href="${registryBase}">Registry</a>
    <a class="tab${marketplace ? " active" : ""}" href="${marketplaceBase}">Marketplace</a>
  </nav>`;
  let bodyHtml = "";
  let title = "Packages";
  if (marketplace) {
    title = "Packages / Marketplace";
    bodyHtml = `<h1>Packages / Marketplace</h1>
      <p class="sub">Optional mode of the <a href="${registryBase}">Packages</a> owner application — browse the real listing plane; package admission, releases, and installs live in the registry.</p>
      ${marketplaceView(model, registryBase)}`;
  } else {
    const pkg = (sp.get("pkg") || "").trim();
    const rel = (sp.get("rel") || "").trim();
    const inst = (sp.get("inst") || "").trim();
    const head = `<h1>Packages</h1>
      <p class="sub">The local lifecycle owner for reusable release material — package candidates, immutable admitted releases, and installation bindings over the closed daemon registry (<code>/v1/hypervisor/packages</code>). Admission grants no runtime, no registration, no launch eligibility; what is absent is named, never simulated. Marketplace is the <a href="${marketplaceBase}">optional mode</a>.</p>`;
    if (pkg && rel && inst) bodyHtml = head + installationView(model, registryBase, pkg, rel, inst);
    else if (pkg && rel) bodyHtml = head + releaseView(model, registryBase, pkg, rel);
    else if (pkg) bodyHtml = head + candidateView(model, registryBase, pkg);
    else bodyHtml = head + catalogView(model, registryBase);
  }
  const css = `:root{color-scheme:dark}
  body{margin:0;background:#0c0d10;color:#e6e7ea;font:14px/1.55 -apple-system,Segoe UI,Roboto,sans-serif}
  .wrap{max-width:1180px;margin:0 auto;padding:32px 24px 80px}
  a{color:#8ab4ff}
  h1{font-size:26px;margin:0 0 6px;letter-spacing:-.02em}
  .sub{color:#9a9da6;margin:0 0 22px;max-width:820px}
  h2{font-size:13px;letter-spacing:.04em;text-transform:uppercase;color:#878a93;margin:26px 0 10px;font-weight:600}
  .act{padding:8px 14px;border-radius:8px;border:0;background:#fff;color:#111;font:inherit;font-weight:600;text-decoration:none;cursor:pointer}
  .act.ghost{background:transparent;color:#cbd0da;border:1px solid #2a2c33}
  .act[disabled]{opacity:.45;cursor:not-allowed}
  .pill{display:inline-block;padding:2px 9px;border-radius:999px;font-size:11px;border:1px solid;white-space:nowrap;margin-left:4px}
  .ok{color:#46c277;border-color:#235c3b;background:#11281b}
  .warn{color:#d6a13a;border-color:#5c4a23;background:#28220f}
  .muted{color:#9a9da6;border-color:#2a2c33}
  .empty{color:#6f7280;padding:18px;border:1px dashed #24262d;border-radius:12px}
  .gapcard{padding:14px 16px;border:1px dashed #5c4a23;border-radius:12px;background:#15130c;margin:0 0 18px}
  .grid{display:grid;grid-template-columns:200px 1fr;gap:8px 16px;padding:16px;border:1px solid #24262d;border-radius:12px;background:#15171c;margin:0 0 18px}
  .grid dt{color:#878a93;font-size:12.5px}
  .grid dd{margin:0;color:#e6e7ea;word-break:break-all}
  code{font-size:11.5px;color:#aab;background:#0e0f13;padding:1px 5px;border-radius:4px}
  table{width:100%;border-collapse:collapse;font-size:13px;margin:0 0 14px}
  th{text-align:left;color:#878a93;font-weight:600;font-size:11.5px;text-transform:uppercase;letter-spacing:.04em;padding:6px 10px;border-bottom:1px solid #24262d}
  td{padding:8px 10px;border-bottom:1px solid #1b1d23;vertical-align:top}
  .tabs{display:flex;gap:4px;border-bottom:1px solid #24262d;margin:0 0 18px;flex-wrap:wrap}
  .tab{border-bottom:2px solid transparent;color:#9a9da6;font-weight:600;padding:9px 14px;text-decoration:none}
  .tab.active{color:#fff;border-bottom-color:#3a82f6}
  .aform{display:flex;flex-direction:column;gap:10px;max-width:640px;padding:14px 16px;border:1px solid #24262d;border-radius:12px;background:#15171c;margin:0 0 16px}
  .fl{display:flex;flex-direction:column;gap:4px;color:#878a93;font-size:12px}
  .fl input,.fl textarea,.fl select{padding:8px;border-radius:8px;border:1px solid #2a2c33;background:#0e0f13;color:#e6e7ea;font:inherit}
  .banner{margin:0 0 14px;padding:9px 12px;border-radius:8px;font-size:12.5px;line-height:1.5;outline:none}
  .banner code{word-break:break-all}
  .ok-banner{border:1px solid #235c3b;background:#11281b;color:#46c277}
  .no-banner{border:1px solid #5c4a23;background:#28220f;color:#d6a13a}
  @media(max-width:760px){.grid{grid-template-columns:130px 1fr}table{display:block;overflow-x:auto;max-width:100%}}`;
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)} · Hypervisor</title><style>${css}</style></head>
<body><div class="wrap">${nav}${banner(sp)}${bodyHtml}</div></body></html>`;
}

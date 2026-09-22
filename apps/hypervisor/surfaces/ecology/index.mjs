// Artifact Ecology — the persistent collective, read as what exists and what is RUNNING.
//
// Canon: domains/ioi-ai/collaborative-outcome-pattern.md § Persistent Artifact Ecology. "The useful
// Collective view is an artifact ecology, not a wall of agent chat bubbles. It shows what persistent
// systems exist, what is running, their ancestry and dependents, who can maintain or stop them, their
// current authority and budget, and what remains operational when participants and Sessions are removed."
//
// WHY THIS SURFACE IS NOT A CORE ONE. Missions, the operational read model core owns, organizes generic
// work results by the work SUBJECT each names and — in its own header — "resolves no application ref
// behind a subject". Resolving the ioi.ai composition behind a subject is exactly what this view does, so
// it is application-CONTRIBUTED and reads the same generic System-record seam the composition was
// admitted through. The daemon serves no room, collective, lineage or caretaker route at all (R-192), and
// this surface asks it for none.
//
// THE CLAIM IT REFUSES. A stored artifact, an installed definition and an actually-running healthy
// instance are three different facts. The rung is derived from what a record BINDS — runtime_ref,
// runtime_kind, installation_ref — and never from its status word, so a lineage recorded `active` with no
// runtime shows as STORED and the disagreement is shown beside it. `apps/hypervisor/scripts/lib/
// artifact-ecology.mjs` is the only deriver; this file renders what it returns and computes no posture,
// rung or coverage of its own.
//
// IT OWNS NOTHING. `actions` is empty and there is no `handleAction`. Stop, quarantine, repair, replace
// and retire are the composition's verbs, executed by their owners through the ioi.ai composer; this
// surface names them and links their coordinates. A surface that appeared to run them would be claiming an
// authority no route backs.
import { ioiGlobalRailHtml, IOI_GRAIL_CSS } from "../chrome.mjs";
import { escHtml, selectionQuery } from "../kit.mjs";
import { readJsonWithDeadline } from "../plane-read.mjs";
import {
  CONTRACTS,
  INTERVENTIONS,
  coverageFindings,
  dependentsOf,
  projectLineage,
  survivesRemoval,
} from "../../scripts/lib/artifact-ecology.mjs";

const ROUTE = "/__ioi/missions/ecology";
const DEFAULT_PLANE_TIMEOUT_MS = 3_000;
// The System picker gets a deadline of its own: the projection route re-verifies every genesis
// admission on every read, so it must never be able to hold up the ecology it only helps you find.
const PICKER_TIMEOUT_MS = 2_000;

export const ECOLOGY_APP_ICON_URI = `data:image/svg+xml,${encodeURIComponent(
  '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#8babfc" stroke-width="1.6"><circle cx="12" cy="5" r="2.4"/><circle cx="5" cy="18" r="2.4"/><circle cx="19" cy="18" r="2.4"/><path d="M12 7.4v4.2M12 11.6 6.6 16M12 11.6 17.4 16"/></svg>',
)}`;

export const meta = {
  slug: "ecology",
  route: ROUTE,
  verifier: "scripts/check-collective-artifact-ecology-surface.mjs",
  certification: "n/a",
};

const unavailablePlane = (status, code) => ({ ok: false, status, code, rows: [] });

/**
 * One seam read. A plane that did not answer is NOT an empty plane, and every count says so — a timeout
 * and a refusal are different outcomes and neither is zero.
 */
async function readRecords({ fetchImpl, base }, systemId, contractId, timeoutMs) {
  const path = `/v1/hypervisor/autonomous-systems/${encodeURIComponent(systemId)}/records?contract_id=${encodeURIComponent(contractId)}`;
  try {
    const { response, payload } = await readJsonWithDeadline(fetchImpl, `${base}${path}`, timeoutMs);
    if (!response.ok) return unavailablePlane(response.status, payload?.error?.code || "plane_unavailable");
    if (!Array.isArray(payload?.records)) return unavailablePlane(response.status, "plane_payload_invalid");
    return { ok: true, status: response.status, code: "", rows: payload.records.map((entry) => entry?.current).filter(Boolean) };
  } catch (error) {
    return unavailablePlane(0, error?.code === "plane_timeout" ? "plane_timeout" : "daemon_unavailable");
  }
}

/**
 * WHICH SYSTEMS THIS CALLER MAY SEE. `/autonomous-systems` is a get-BY-ID and refuses without one
 * (`system_genesis_system_id_required`); the enumeration is `/autonomous-systems/projection`, which
 * filters rows by the caller's own scopes BEFORE answering — so this surface never sees a System the
 * caller could not already read, and an empty answer is `honest_empty` rather than a hidden refusal.
 */
async function readSystems({ fetchImpl, base }, timeoutMs) {
  try {
    const { response, payload } = await readJsonWithDeadline(fetchImpl, `${base}/v1/hypervisor/autonomous-systems/projection`, timeoutMs);
    if (!response.ok) return unavailablePlane(response.status, payload?.error?.code || "plane_unavailable");
    if (!Array.isArray(payload?.systems)) return unavailablePlane(response.status, "plane_payload_invalid");
    return { ok: true, status: response.status, code: "", rows: payload.systems, state: payload.state ?? "" };
  } catch (error) {
    return unavailablePlane(0, error?.code === "plane_timeout" ? "plane_timeout" : "daemon_unavailable");
  }
}

const systemIdOf = (row) => String(row?.system_id ?? row?.id ?? row?.system?.system_id ?? "");
const PROJECTION_ROUTE = "/v1/hypervisor/autonomous-systems/projection";

export async function load(ctx) {
  // THE SEAM IS IDENTITY-FIRST, so this surface speaks to it through the request-scoped capability the
  // serve hands bound modules and never through a bare fetch. `daemonFetch` carries the CALLER's
  // identity and refuses any destination that is not daemon-relative, so the caller's envelope cannot
  // leave the daemon. An identity-less call here would not read as "anonymous": under local-development
  // posture the daemon adjudicates a loopback call as the operator, so a bare fetch would silently
  // PROMOTE this read. The plain-fetch branch exists for tests that inject their own transport.
  const transport = typeof ctx.daemonFetch === "function"
    ? { fetchImpl: ctx.daemonFetch, base: "" }
    : { fetchImpl: ctx.fetch || globalThis.fetch, base: ctx.daemon || "" };
  const requested = Number(ctx.planeTimeoutMs);
  const timeoutMs = Number.isFinite(requested) && requested > 0 ? Math.min(Math.floor(requested), 30_000) : DEFAULT_PLANE_TIMEOUT_MS;

  // THE ECOLOGY IS SCOPED TO A SYSTEM THE CALLER NAMES, and that is not a shortcut. The daemon itself
  // refuses to answer `/autonomous-systems` without a `system_id`, and the one route that DOES enumerate
  // — `/autonomous-systems/projection` — cryptographically re-verifies every System's genesis admission
  // on every GET (`projection_source: verified_owner_reconstruction`). Measured against an isolated
  // daemon holding one System: the projection took 48.5 SECONDS while the seam's own record read took
  // 259ms. So the ecology reads the records route directly for the named System and never waits on the
  // projection; the System PICKER asks the projection on a short deadline of its own and degrades to a
  // typed notice, because a slow picker must not be able to blank a fast ecology.
  const namedSystem = String(ctx.url?.searchParams?.get("system") ?? "").trim();

  if (!namedSystem) {
    const systems = await readSystems(transport, Math.min(timeoutMs, PICKER_TIMEOUT_MS));
    return {
      needs_system: true,
      systems,
      lineagePlane: { ok: systems.ok, code: systems.code },
      verdictPlane: { ok: systems.ok, code: systems.code },
      lineages: [], projected: [], verdicts: [], coverage: [], survival: [],
    };
  }

  const lineagePlane = await readRecords(transport, namedSystem, CONTRACTS.lineage, timeoutMs);
  const verdictPlane = await readRecords(transport, namedSystem, CONTRACTS.verdict, timeoutMs);
  const lineages = lineagePlane.ok ? lineagePlane.rows : [];

  // THE DERIVER IS THE ONLY DERIVER. This module computes no rung, posture or coverage itself.
  const projected = lineages.map((lineage) => ({
    ...projectLineage(lineage, { dependents: dependentsOf(String(lineage.lineage_id ?? ""), lineages) }),
    system_id: namedSystem,
  }));

  return {
    needs_system: false,
    system_id: namedSystem,
    systems: { ok: true, code: "", rows: [] },
    lineagePlane,
    verdictPlane,
    lineages,
    projected,
    verdicts: verdictPlane.ok ? verdictPlane.rows : [],
    coverage: projected.flatMap((p) => coverageFindings(p)),
    survival: projected.map((p) => survivesRemoval(p)),
  };
}

// ---- rendering ----------------------------------------------------------------------------------------
const shortRef = (reference) => {
  const raw = String(reference || "");
  return raw.length <= 38 ? raw : `${raw.slice(0, 20)}…${raw.slice(-14)}`;
};
const RUNG_LABEL = { stored: "Stored", installed: "Installed", running: "Running" };
const RUNG_MEANS = {
  stored: "bytes and an identity — nothing is installed and nothing runs",
  installed: "a definition is enabled somewhere — still nothing runs",
  running: "a runtime is bound and live",
};
const rungTone = (rung) => (rung === "running" ? "ok" : rung === "installed" ? "warn" : "muted");
const pill = (text, tone) => `<span class="ec-pill ${tone}">${escHtml(text)}</span>`;
const planeNotice = (name, plane) => (plane.ok ? "" : `<div class="ec-plane-error" role="status"><b>${escHtml(name)}</b> unavailable — <code>${escHtml(plane.code || "unknown")}</code>. Counts for this plane are not treated as zero.</div>`);
const metric = (label, value, tone = "") => `<div class="ec-metric ${tone}"><strong>${escHtml(String(value))}</strong><span>${escHtml(label)}</span></div>`;
const refList = (refs, empty) => (refs.length
  ? `<ul class="ec-refs">${refs.map((r) => `<li><code>${escHtml(shortRef(r))}</code></li>`).join("")}</ul>`
  : `<p class="ec-none">${escHtml(empty)}</p>`);

function renderRow(p, selectedId) {
  const disagrees = p.recorded_posture === "active" && !p.runtime_ref;
  return `<a class="ec-row${p.lineage_id === selectedId ? " selected" : ""}" href="${selectionQuery(ROUTE, { lineage: p.lineage_id })}" data-ioi-lineage="${escHtml(p.lineage_id)}" data-ioi-rung="${escHtml(p.rung)}" data-ioi-recorded-posture="${escHtml(p.recorded_posture)}">
    <div class="ec-row-copy"><strong>${escHtml(shortRef(p.artifact_ref))}</strong><span>${escHtml(shortRef(p.lineage_id))}</span></div>
    <div class="ec-row-pills">${pill(RUNG_LABEL[p.rung], rungTone(p.rung))}${pill(p.recorded_posture, "muted")}${disagrees ? pill("recorded active, no runtime", "danger") : ""}</div>
  </a>`;
}

function renderDetail(p, model) {
  if (!p) return `<section class="ec-detail empty"><div><b>No lineage selected</b><span>Pick a persistent system to see what is running, who can stop it, and what depends on it.</span></div></section>`;
  const survival = model.survival.find((s) => s.lineage_id === p.lineage_id) || { survives: false, because: "", takes_with_it: [] };
  const coverage = model.coverage.filter((line) => line.includes(p.lineage_id));
  const verdicts = model.verdicts.filter((v) => String(v?.controller_continuity?.lineage_ref ?? "") === p.lineage_id);
  return `<section class="ec-detail" data-ioi-detail="${escHtml(p.lineage_id)}" data-ioi-rung="${escHtml(p.rung)}">
    <header class="ec-detail-head">
      <div><p class="ec-eyebrow">${escHtml(RUNG_LABEL[p.rung])} — ${escHtml(RUNG_MEANS[p.rung])}</p><h2>${escHtml(shortRef(p.artifact_ref))}</h2><p class="ec-mono">${escHtml(p.lineage_id)}</p></div>
      <div class="ec-detail-pills">${pill(RUNG_LABEL[p.rung], rungTone(p.rung))}${pill(`recorded ${p.recorded_posture}`, "muted")}${p.orphan_reason ? pill(p.orphan_reason, "warn") : ""}</div>
    </header>

    <div class="ec-facts">
      <div><span>Artifact hash</span><strong><code>${escHtml(shortRef(p.artifact_sha256))}</code></strong></div>
      <div><span>Definition</span><strong><code>${escHtml(shortRef(p.definition_ref))}</code></strong></div>
      <div><span>Installation</span><strong>${p.installation_ref ? `<code>${escHtml(shortRef(p.installation_ref))}</code>` : "<em>none</em>"}</strong></div>
      <div><span>Runtime</span><strong>${p.runtime_ref ? `<code>${escHtml(shortRef(p.runtime_ref))}</code>` : "<em>none</em>"}</strong></div>
      <div><span>Runtime kind</span><strong>${escHtml(p.runtime_kind)}</strong></div>
    </div>

    <section class="ec-section" data-ioi-section="coverage">
      <div class="ec-section-title"><h3>Who can maintain or stop it</h3></div>
      <div class="ec-grid">
        <div><span>Accountable subject</span><strong><code>${escHtml(shortRef(p.accountable_subject_ref))}</code></strong></div>
        <div><span>Caretaker</span><strong>${p.caretaker_ref ? `<code>${escHtml(shortRef(p.caretaker_ref))}</code>` : "<em>none</em>"}</strong></div>
        <div><span>Stop policy</span><strong><code>${escHtml(shortRef(p.stop_policy_ref))}</code></strong></div>
      </div>
      ${coverage.length ? `<ul class="ec-findings">${coverage.map((line) => `<li>${escHtml(line.replace(/^coverage: /u, ""))}</li>`).join("")}</ul>` : `<p class="ec-none">Coverage is complete for this lineage.</p>`}
    </section>

    <section class="ec-section" data-ioi-section="survival">
      <div class="ec-section-title"><h3>What remains when participants and Sessions are removed</h3></div>
      <p class="${survival.survives ? "ec-ok" : "ec-warn"}" data-ioi-survives="${survival.survives}">${survival.survives
        ? `Survives — its accountable subject is <code>${escHtml(shortRef(survival.because))}</code>, which is durable and outlives any Session.`
        : `Does not survive — <code>${escHtml(shortRef(survival.because) || "no subject")}</code> is not a durable accountable subject.`}</p>
      ${survival.takes_with_it.length ? `<p class="ec-warn">Dependents that go with it: ${survival.takes_with_it.map((d) => `<code>${escHtml(shortRef(d))}</code>`).join(", ")}</p>` : `<p class="ec-none">Nothing depends on this lineage.</p>`}
    </section>

    <div class="ec-two-col">
      <section class="ec-section" data-ioi-section="ancestry">
        <div class="ec-section-title"><h3>Ancestry</h3></div>
        <p class="ec-label">Source artifacts</p>${refList(p.ancestry.source_artifact_refs, "No sources — this lineage was reused, not forked.")}
        <p class="ec-label">Successor artifact</p>${refList(p.ancestry.successor_artifact_ref ? [p.ancestry.successor_artifact_ref] : [], "No successor artifact.")}
        <p class="ec-label">Successor of</p>${refList(p.ancestry.successor_of ? [p.ancestry.successor_of] : [], "Not a successor of another lineage.")}
        <p class="ec-label">Transformation receipts</p>${refList(p.ancestry.transformation_receipt_refs, "No transformation receipts.")}
      </section>
      <section class="ec-section" data-ioi-section="dependencies">
        <div class="ec-section-title"><h3>Dependencies and dependents</h3></div>
        <p class="ec-label">Depends on</p>${refList(p.dependency_lineage_refs, "No dependencies.")}
        <p class="ec-label">Depended on by</p>${refList(p.dependents, "Nothing depends on this.")}
      </section>
    </div>

    <section class="ec-section" data-ioi-section="authority">
      <div class="ec-section-title"><h3>Current authority and budget</h3><span>Leases are shown by kind because they answer different questions</span></div>
      <div class="ec-two-col">
        <div><p class="ec-label">Context</p>${refList(p.leases.context, "No context leases.")}<p class="ec-label">Authority</p>${refList(p.leases.authority, "No authority leases.")}</div>
        <div><p class="ec-label">Resource</p>${refList(p.leases.resource, "No resource leases.")}<p class="ec-label">Budget</p>${refList(p.leases.budget, "No budget leases.")}</div>
      </div>
    </section>

    <section class="ec-section" data-ioi-section="effects">
      <div class="ec-section-title"><h3>Effects and receipts</h3></div>
      ${refList(p.effect_receipt_refs, "No effect receipts recorded against this lineage.")}
    </section>

    <section class="ec-section" data-ioi-section="evaluation">
      <div class="ec-section-title"><h3>Qualification</h3></div>
      ${verdicts.length
        ? `<ul class="ec-findings">${verdicts.map((v) => `<li data-ioi-verdict="${escHtml(String(v.verdict_ref ?? ""))}" data-ioi-outcome="${escHtml(String(v.outcome ?? ""))}">${escHtml(String(v.outcome ?? "unknown"))} — read from <code>${escHtml(shortRef(String(v.verdict_ref ?? "")))}</code>. A verdict is a judgment and grants nothing.</li>`).join("")}</ul>`
        : `<p class="ec-none">No qualification verdict has been admitted for this lineage. None is inferred here.</p>`}
    </section>

    <section class="ec-section" data-ioi-section="interventions">
      <div class="ec-section-title"><h3>Interventions</h3><span>Offered here, executed by their owners</span></div>
      ${p.offered_interventions.length
        ? `<div class="ec-verbs">${p.offered_interventions.map((verb) => `<span class="ec-verb" data-ioi-intervention="${escHtml(verb)}">${escHtml(verb)}</span>`).join("")}</div>`
        : `<p class="ec-none">This lineage is ${escHtml(p.recorded_posture)} and admits no further verb.</p>`}
      <p class="ec-boundary">These are the composition's own verbs. The Hypervisor serves no collective, lineage or caretaker route (R-192): they are executed by the ioi.ai composer against the record seam, and this surface writes nothing, mints no authority and changes no topology.</p>
    </section>
  </section>`;
}

export function render(model, ctx) {
  const requested = ctx.url.searchParams.get("rung") || "all";
  const rungs = ["stored", "installed", "running"];
  const rung = rungs.includes(requested) ? requested : "all";
  const shown = rung === "all" ? model.projected : model.projected.filter((p) => p.rung === rung);
  const requestedLineage = ctx.url.searchParams.get("lineage") || "";
  const selected = requestedLineage
    ? model.projected.find((p) => p.lineage_id === requestedLineage) || null
    : shown[0] || null;
  const selectedId = selected ? selected.lineage_id : "";
  const count = (r) => (model.lineagePlane.ok ? model.projected.filter((p) => p.rung === r).length : "—");
  const filters = ["all", ...rungs].map((entry) => `<a role="tab" aria-selected="${entry === rung}" class="ec-filter${entry === rung ? " active" : ""}" href="${selectionQuery(ROUTE, { lineage: selectedId, rung: entry === "all" ? "" : entry })}">${escHtml(entry)}</a>`).join("");
  const globalRail = ctx.embed ? "" : ioiGlobalRailHtml({ label: "Ecology", href: ROUTE, iconUri: ECOLOGY_APP_ICON_URI });
  const CSS = `
    :root{color-scheme:dark;--surface-base:28 28 28;--surface-01:22 21 21;--surface-03:31 31 31;--surface-hover:255 255 255;--content-primary:250 250 250;--content-secondary:163 163 163;--content-muted:115 115 115;--content-link:139 171 252;--border-base:64 64 64;--border-brand:94 138 253;--status-ok:108 255 100;--status-warn:254 154 91;--status-danger:255 83 90}
    @media(prefers-color-scheme:light){:root{color-scheme:light;--surface-base:250 250 250;--surface-01:255 255 255;--surface-03:245 245 245;--surface-hover:0 0 0;--content-primary:31 31 31;--content-secondary:82 82 82;--content-muted:115 115 115;--content-link:0 72 255;--border-base:225 225 225;--border-brand:47 105 253;--status-ok:28 125 44;--status-warn:154 82 12;--status-danger:173 0 2}}
    *{box-sizing:border-box}body{margin:0;background:rgb(var(--surface-base));color:rgb(var(--content-primary));font:14px/1.45 "ABC Diatype",-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}a{color:rgb(var(--content-link));text-decoration:none}code{font:11px/1.4 "ABC Diatype Mono",ui-monospace,monospace;color:rgb(var(--content-secondary));word-break:break-all}
    ${IOI_GRAIL_CSS}
    .ec-shell{display:flex;min-height:100svh}.ec-main{flex:1;min-width:0}
    .ec-top{position:sticky;top:0;z-index:5;display:flex;align-items:center;justify-content:space-between;gap:20px;height:64px;padding:0 24px;border-bottom:1px solid rgb(var(--border-base));background:rgb(var(--surface-base)/.92);backdrop-filter:blur(16px)}
    .ec-title{display:flex;align-items:baseline;gap:10px}.ec-title h1{font-size:20px;line-height:1;margin:0;font-weight:500}.ec-title span{color:rgb(var(--content-muted));font-size:12px}
    .ec-actions{display:flex;gap:8px}.ec-action{display:inline-flex;align-items:center;height:32px;padding:0 12px;border:1px solid rgb(var(--border-base));border-radius:8px;color:rgb(var(--content-primary));background:rgb(var(--surface-01));font-size:12px}.ec-action:hover{border-color:rgb(var(--border-brand))}
    .ec-summary{display:flex;border-bottom:1px solid rgb(var(--border-base));padding:0 24px}.ec-metric{display:flex;flex-direction:column;gap:2px;min-width:118px;padding:16px 22px 14px 0;margin-right:22px;border-right:1px solid rgb(var(--border-base))}.ec-metric:last-child{border-right:0}.ec-metric strong{font-size:20px;line-height:1.1;font-weight:500}.ec-metric span{color:rgb(var(--content-muted));font-size:11px}.ec-metric.attention strong{color:rgb(var(--status-warn))}
    .ec-tabs{display:flex;gap:2px;padding:12px 24px;border-bottom:1px solid rgb(var(--border-base));overflow:auto}.ec-filter{display:inline-flex;align-items:center;height:30px;padding:0 10px;border-radius:7px;color:rgb(var(--content-secondary));white-space:nowrap}.ec-filter:hover,.ec-filter.active{background:rgb(var(--surface-hover)/.07);color:rgb(var(--content-primary))}
    .ec-workspace{display:grid;grid-template-columns:minmax(280px,360px) minmax(0,1fr);min-height:calc(100svh - 178px)}
    .ec-sidebar{border-right:1px solid rgb(var(--border-base));background:rgb(var(--surface-01));min-width:0}.ec-sidebar-head{display:flex;justify-content:space-between;padding:14px 16px;border-bottom:1px solid rgb(var(--border-base));color:rgb(var(--content-muted));font-size:11px;text-transform:uppercase}
    .ec-row{display:grid;gap:8px;padding:14px 16px;border-bottom:1px solid rgb(var(--border-base));color:inherit;position:relative}.ec-row:hover{background:rgb(var(--surface-hover)/.05)}.ec-row.selected{background:rgb(var(--surface-hover)/.08)}.ec-row.selected:before{content:"";position:absolute;inset:0 auto 0 0;width:2px;background:rgb(var(--border-brand))}
    .ec-row-copy strong,.ec-row-copy span{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.ec-row-copy strong{font-weight:500}.ec-row-copy span{color:rgb(var(--content-muted));font-size:11px;margin-top:3px}.ec-row-pills{display:flex;flex-wrap:wrap;gap:6px}
    .ec-pill{display:inline-flex;align-items:center;height:20px;padding:0 7px;border:1px solid rgb(var(--border-base));border-radius:999px;color:rgb(var(--content-secondary));font-size:10px;white-space:nowrap}.ec-pill.ok{color:rgb(var(--status-ok));border-color:rgb(var(--status-ok)/.35)}.ec-pill.warn{color:rgb(var(--status-warn));border-color:rgb(var(--status-warn)/.35)}.ec-pill.danger{color:rgb(var(--status-danger));border-color:rgb(var(--status-danger)/.35)}
    .ec-detail{min-width:0;padding:24px 28px 64px}.ec-detail.empty{display:grid;place-items:center;color:rgb(var(--content-muted));text-align:center}.ec-detail.empty div{display:flex;flex-direction:column;gap:4px}
    .ec-detail-head{display:flex;justify-content:space-between;gap:18px;padding-bottom:18px;border-bottom:1px solid rgb(var(--border-base))}.ec-eyebrow{color:rgb(var(--content-muted));font-size:10px;text-transform:uppercase;margin:0 0 6px}.ec-detail-head h2{font-size:24px;line-height:1.2;font-weight:500;margin:0}.ec-mono{font:11px/1.4 ui-monospace,monospace;color:rgb(var(--content-muted));margin:6px 0 0;word-break:break-all}.ec-detail-pills{display:flex;flex-wrap:wrap;gap:6px;align-items:flex-start}
    .ec-facts,.ec-grid{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));border-bottom:1px solid rgb(var(--border-base))}.ec-grid{grid-template-columns:repeat(3,minmax(0,1fr));border-bottom:0}.ec-facts div,.ec-grid div{display:flex;flex-direction:column;gap:3px;padding:13px 12px 13px 0}.ec-facts span,.ec-grid span{color:rgb(var(--content-muted));font-size:10px;text-transform:uppercase}.ec-facts strong,.ec-grid strong{font-size:12px;font-weight:500;overflow:hidden;text-overflow:ellipsis}
    .ec-section{padding-top:24px}.ec-section-title{display:flex;align-items:baseline;justify-content:space-between;gap:14px;margin-bottom:10px}.ec-section-title h3{font-size:13px;font-weight:500;margin:0}.ec-section-title span{color:rgb(var(--content-muted));font-size:11px}
    .ec-two-col{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:28px}
    .ec-label{color:rgb(var(--content-muted));font-size:10px;text-transform:uppercase;margin:14px 0 6px}.ec-refs{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:4px}.ec-refs li{padding:5px 0;border-bottom:1px solid rgb(var(--border-base))}
    .ec-none{color:rgb(var(--content-muted));font-size:11px;margin:0}.ec-ok{color:rgb(var(--status-ok));font-size:12px}.ec-warn{color:rgb(var(--status-warn));font-size:12px}
    .ec-findings{list-style:none;margin:10px 0 0;padding:0;display:flex;flex-direction:column;gap:6px}.ec-findings li{padding:9px 11px;border-left:2px solid rgb(var(--status-warn));background:rgb(var(--status-warn)/.06);color:rgb(var(--content-secondary));font-size:11px}
    .ec-verbs{display:flex;flex-wrap:wrap;gap:8px}.ec-verb{display:inline-flex;align-items:center;height:26px;padding:0 10px;border:1px dashed rgb(var(--border-base));border-radius:7px;color:rgb(var(--content-secondary));font-size:11px}
    .ec-boundary{color:rgb(var(--content-muted));font-size:11px;margin-top:12px}
    .ec-plane-error{padding:11px 12px;border-left:2px solid rgb(var(--status-warn));background:rgb(var(--status-warn)/.06);color:rgb(var(--content-secondary));font-size:11px}
    @media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
    @media(max-width:980px){.ec-workspace{grid-template-columns:1fr}.ec-sidebar{border-right:0}.ec-detail{padding:22px 18px}.ec-facts{grid-template-columns:repeat(2,minmax(0,1fr))}.ec-grid,.ec-two-col{grid-template-columns:1fr}.ec-summary{overflow-x:auto}}
    @media(max-width:640px){.ec-top{height:auto;min-height:64px;padding:12px 14px;flex-wrap:wrap;gap:8px}.ec-title span{display:none}.ec-summary,.ec-tabs{padding-left:14px;padding-right:14px}.ec-detail-head{flex-direction:column}}`;
  if (model.needs_system) {
    const rows = model.systems.ok ? model.systems.rows : [];
    const body = model.systems.ok
      ? (rows.length
        ? `<div class="ec-run-list">${rows.map((r) => { const id = systemIdOf(r); return `<a class="ec-row" data-ioi-system="${escHtml(id)}" href="${selectionQuery(ROUTE, { system: id })}"><div class="ec-row-copy"><strong>${escHtml(shortRef(id))}</strong><span>persistent systems admitted under this System</span></div></a>`; }).join("")}</div>`
        : `<p class="ec-none" style="padding:18px">No System is admitted for this caller yet.</p>`)
      : `<p class="ec-none" style="padding:18px">The System picker could not be read — <code>${escHtml(model.systems.code || "unknown")}</code>. This does not mean there are none, and naming a System in the URL reads its ecology directly without the picker.</p>`;
    return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Artifact Ecology · Hypervisor</title><style>${CSS}</style></head><body data-ioi-ecology-state="needs_system"><div class="ec-shell">${globalRail}<main class="ec-main" data-ioi-ecology="persistent-executable-lineage">
      <header class="ec-top"><div class="ec-title"><h1>Artifact Ecology</h1><span>Name a System to read its persistent systems</span></div><div class="ec-actions"><a class="ec-action" href="/__ioi/missions">Missions</a></div></header>
      ${planeNotice("System picker", model.systems)}
      ${body}
      <p class="ec-boundary" style="padding:18px">The ecology is scoped to one System because the daemon refuses to enumerate them cheaply: <code>/autonomous-systems</code> requires a <code>system_id</code>, and the projection that does enumerate re-verifies every genesis admission on every read. The picker asks it on a short deadline of its own so a slow enumeration can never blank a fast ecology.</p>
    </main></div></body></html>`;
  }

  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Artifact Ecology · Hypervisor</title><style>${CSS}</style></head><body><div class="ec-shell">${globalRail}<main class="ec-main" data-ioi-ecology="persistent-executable-lineage">
    <header class="ec-top"><div class="ec-title"><h1>Artifact Ecology</h1><span>What persists, what is installed, and what is actually running</span></div><div class="ec-actions"><a class="ec-action" href="/__ioi/missions">Missions</a><a class="ec-action" href="/__ioi/operations">Operations substrate</a><a class="ec-action" href="${selectionQuery(ROUTE, { lineage: selectedId, rung: rung === "all" ? "" : rung })}" aria-label="Refresh ecology data">Refresh</a></div></header>
    <div class="ec-summary">${metric("lineages", model.lineagePlane.ok ? model.projected.length : "—")}${metric("stored", count("stored"))}${metric("installed", count("installed"))}${metric("running", count("running"))}${metric("coverage gaps", model.lineagePlane.ok ? model.coverage.length : "—", model.coverage.length ? "attention" : "")}</div>
    ${planeNotice("System record seam", model.lineagePlane)}${planeNotice("Qualification verdicts", model.verdictPlane)}
    <nav class="ec-tabs" role="tablist" aria-label="Rung filters">${filters}</nav>
    <div class="ec-workspace">
      <aside class="ec-sidebar"><div class="ec-sidebar-head"><span>Persistent systems</span><span>${model.lineagePlane.ok ? shown.length : "—"}</span></div>${shown.length ? shown.map((p) => renderRow(p, selectedId)).join("") : `<p class="ec-none" style="padding:18px">${model.lineagePlane.ok ? "No lineages are admitted under any active System." : "The seam did not answer; this is not an empty ecology."}</p>`}</aside>
      ${renderDetail(selected, model)}
    </div>
  </main></div></body></html>`;
}

// Read-only by contract: the composition's verbs belong to their owners.
export const actions = [];

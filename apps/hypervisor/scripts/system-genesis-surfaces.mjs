// M1.6/M1.7 pulled product surfaces (m1-system-genesis-product-journey) — the four surfaces
// m1.md names for the bounded System package/genesis/lifecycle profile:
//
//   /__ioi/systems/compose      Studio package/genesis composition (compact + advanced lanes)
//   /__ioi/systems/governance   Governance preview (pending proposals/approvals — preview, not authority)
//   /__ioi/systems/packages     Packages lifecycle (per-System instantiation states from the projection)
//   /__ioi/systems/<asg_tail>   Provisional System detail (compact + advanced read projection + ladder)
//
// Doctrine (estate rules, unchanged):
//   READ TRUTH — every fact rendered here is fetched from /v1/hypervisor/autonomous-systems*
//     daemon routes at request time; nothing is cached, synthesized, or defaulted.
//   NO UI-DERIVED TRUTH — this module holds no state and writes no files; the only mutation any
//     form performs is a verbatim proxy of the operator's declaration to the owning daemon route.
//     Composition (building a proposal body from form fields) grants nothing: the daemon is the
//     single validator/authority and every effect carries its wallet challenge/receipt.
//   NO PERMANENT SYSTEMS NAVIGATION — these surfaces mount as flat /__ioi routes reachable by
//     direct launch and by cross-links among themselves (M1.7: "without permanent Systems
//     navigation"). They are deliberately NOT a rail item, NOT an Applications suite card, and
//     NOT an app-catalog entry.
//   HONEST STATES — every readout stamps its product-journey state machine-readably as
//     data-journey-state ∈ {loading_or_pending, honest_empty, ready_or_proposed,
//     denied_or_revoked, unavailable_or_degraded, stale_conflict_or_ambiguous,
//     recovery_or_rollback, completed} so the journey verifier can assert honesty per state.
//     A daemon refusal renders its exact code/message verbatim; a dead daemon renders a named
//     degraded state (never a fabricated census); the projection's fail-closed
//     system_projection_source_incomplete renders as a stale/conflict stop, never a partial list.
import http from "node:http";
import { escHtml } from "../surfaces/kit.mjs";

const esc = escHtml;
const BASE = "/__ioi/systems";
const GENESIS_API = "/v1/hypervisor/autonomous-systems";
const KEY_RE = /^asg_[0-9a-f]{64}$/;
const OP_RE = /^[a-z_]{1,64}$/;
// M1.5d continuity wire ops (ContinuityTransitionOp::ALL) — the :op whitelist for the proxy.
const CONTINUITY_OPS = [
  "initiate_succession",
  "complete_succession",
  "migrate",
  "initiate_dissolution",
  "open_dissolution_disposition",
  "record_dissolution_domain_outcome",
  "complete_dissolution",
  "enroll_local",
  "exit_local_enrollment",
];
const HTMLH = { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" };

// ---- daemon transport ----------------------------------------------------------------------
// Governed lifecycle POSTs synchronously traverse the wallet network and can legitimately hold
// longer than undici's fixed 300s response-header ceiling, so this proxy uses node:http with a
// finite 15-minute transport ceiling (same boundary the M1 verifiers use). A transport failure
// resolves as { networkError } — the surfaces render it as a NAMED degraded state, never as
// fabricated truth.
function daemonJson(daemonUrl, method, path, payload) {
  let target;
  try {
    target = new URL(`${daemonUrl}${path}`);
  } catch (error) {
    return Promise.resolve({ networkError: `daemon URL invalid (${error.message})` });
  }
  const body = payload === undefined ? null : JSON.stringify(payload);
  return new Promise((resolve) => {
    const request = http.request(
      {
        hostname: target.hostname,
        port: target.port,
        path: `${target.pathname}${target.search}`,
        method,
        headers: {
          "content-type": "application/json",
          ...(body === null ? {} : { "content-length": Buffer.byteLength(body) }),
        },
      },
      (response) => {
        let raw = "";
        response.setEncoding("utf8");
        response.on("data", (chunk) => { raw += chunk; });
        response.on("error", (error) => resolve({ networkError: error.message || "daemon stream failed" }));
        response.on("end", () => {
          let parsed = {};
          try { parsed = JSON.parse(raw); } catch { parsed = {}; }
          resolve({ status: response.statusCode, body: parsed });
        });
      },
    );
    request.on("error", (error) => resolve({ networkError: error.message || "daemon unreachable" }));
    request.setTimeout(900_000, () => request.destroy(new Error("daemon call timed out")));
    if (body !== null) request.write(body);
    request.end();
  });
}

// ---- honest-state kit ----------------------------------------------------------------------
const stateBlock = (state, code, inner) =>
  `<div class="sysgen-state" data-journey-state="${esc(state)}"${code ? ` data-truth-code="${esc(code)}"` : ""}>${inner}</div>`;

function stateForErrorCode(code) {
  if (!code) return "denied_or_revoked";
  if (code.includes("pending")) return "loading_or_pending";
  if (code.includes("incomplete") || code.includes("conflict") || code.includes("ambiguous")) {
    return "stale_conflict_or_ambiguous";
  }
  if (code.endsWith("_not_found")) return "honest_empty";
  return "denied_or_revoked";
}

const NONCLAIMS_BANNER = `<p class="sub" data-sysgen-nonclaims="1" style="margin:6px 0 14px">Read projection of daemon-owned truth — presentation grants <b>no</b> authority, admission, activation, membership, network assurance, or runtime effect. Every consequential action below resolves to a <code>/v1/hypervisor/autonomous-systems</code> daemon route under its own wallet challenge; this surface holds no state of its own.</p>`;

const CROSSLINKS = `<p class="sub" style="margin:0 0 4px">Provisional M1 surfaces — reached by direct launch (no permanent Systems navigation): <a href="${BASE}/compose">Studio composer</a> · <a href="${BASE}/packages">Packages lifecycle</a> · <a href="${BASE}/governance">Governance preview</a></p>`;

const jsonPre = (value) => `<pre>${esc(JSON.stringify(value, null, 2))}</pre>`;

function pill(text, cls = "muted", attrs = "") {
  return `<span class="pill ${cls}"${attrs}>${esc(text)}</span>`;
}

// One shared renderer for every governed daemon response the surfaces proxy: 2xx effects,
// 403 approval challenges (rendered as an inspectable PREVIEW with the exact policy/request/
// effect hashes), 422 blocker reports (rendered blocker-by-blocker), and every other typed
// refusal verbatim. `resubmit` (optional) re-offers the SAME composed declaration with a
// wallet-grant field so an operator can attach existing authority; the grant travels to the
// daemon untouched.
function renderOutcome(result, { resubmit = null, backHref = null, actionLabel = "request" } = {}) {
  const back = backHref ? `<p><a href="${esc(backHref)}">← back</a></p>` : "";
  if (result.networkError) {
    return stateBlock(
      "unavailable_or_degraded",
      "daemon_unreachable",
      `<h2>Daemon unavailable</h2><div class="empty">The Hypervisor daemon did not answer (<code>${esc(result.networkError)}</code>). Nothing was submitted, nothing is claimed, and no plausible result is substituted.</div>${back}`,
    );
  }
  const body = result.body || {};
  const error = body.error;
  if (result.status === 200 || result.status === 201) {
    const record = body.autonomous_system_genesis_admission;
    const chain = body.autonomous_system_chain;
    const admissionTail = record?.admission_id
      ? String(record.admission_id).replace("system-genesis-admission://", "")
      : null;
    const headline = record
      ? `Genesis admission committed — <code>${esc(record.admission_id || "")}</code>`
      : chain
        ? `Lifecycle effect committed — chain status <code data-lifecycle-status="${esc(chain.status || "")}">${esc(chain.status || "")}</code> at sequence ${esc(String(chain.latest_sequence ?? ""))}`
        : `Daemon committed the ${esc(actionLabel)} (HTTP ${result.status})`;
    const detailLink = admissionTail && KEY_RE.test(admissionTail)
      ? `<p><a class="act" href="${BASE}/${encodeURIComponent(admissionTail)}">Open provisional System detail →</a></p>`
      : "";
    return stateBlock(
      "completed",
      null,
      `<h2>Committed</h2><p class="sub">${headline}. The full daemon response below is the owner truth — receipts and roots come from it, never from this page.</p>${detailLink}${jsonPre(body)}${back}`,
    );
  }
  if (error && error.blocker_report) {
    const blockers = Array.isArray(error.blocker_report.blockers) ? error.blocker_report.blockers : [];
    const rows = blockers
      .map((b) => `<tr data-blocker-code="${esc(b.code || "")}"><td><code>${esc(b.code || "")}</code></td><td><code>${esc(b.path || "")}</code></td><td>${esc(b.message || "")}</td></tr>`)
      .join("");
    return stateBlock(
      "denied_or_revoked",
      error.code || "",
      `<h2>Refused before authority — blocker report</h2>
       <p class="sub">The compiler refused this proposal (<code>${esc(error.code || "")}</code>) and admitted <b>nothing</b>. The report below is the daemon's <code>${esc(error.blocker_report.schema_version || "")}</code> verbatim.</p>
       <table><thead><tr><th>Blocker</th><th>Path</th><th>Message</th></tr></thead><tbody>${rows || `<tr><td colspan="3">report carried no blockers</td></tr>`}</tbody></table>
       ${jsonPre(error.blocker_report)}${back}`,
    );
  }
  if (error && error.approval) {
    const approval = error.approval;
    const resubmitForm = resubmit
      ? `<h3 style="margin:16px 0 6px">Attach existing authority</h3>
         <p class="sub">Approving is a wallet act, not a surface act: paste a wallet approval grant minted for the EXACT policy/request hashes above. The declaration below is resubmitted verbatim to the daemon route.</p>
         <form method="post" action="${esc(resubmit.action)}">
           <textarea name="${esc(resubmit.declarationField || "declaration")}" style="display:none">${esc(resubmit.declaration)}</textarea>
           ${resubmit.extraHidden || ""}
           <div class="field"><label>wallet_approval_grant (JSON)</label><textarea name="wallet_approval_grant" placeholder='{"schema_version":1,...}'></textarea></div>
           <button class="act" type="submit">Resubmit with grant</button>
         </form>`
      : "";
    return stateBlock(
      "ready_or_proposed",
      error.code || "",
      `<h2>Authority required — governed preview</h2>
       <p class="sub" data-sysgen-preview-nonclaim="1">This is a <b>preview, not authority</b>: the daemon computed the exact governed effect and refused it pending a wallet grant (<code>${esc(error.code || "")}</code>). Nothing was admitted or mutated; presentation grants no authority.</p>
       <dl class="grid">
         <dt>required_scope</dt><dd><code>${esc(error.required_scope || "")}</code></dd>
         <dt>required_authority_ref</dt><dd><code>${esc(error.required_authority_ref || "")}</code></dd>
         <dt>policy_hash</dt><dd><code data-approval="policy_hash">${esc(approval.policy_hash || "")}</code></dd>
         <dt>request_hash</dt><dd><code data-approval="request_hash">${esc(approval.request_hash || "")}</code></dd>
         <dt>effect_hash</dt><dd><code data-approval="effect_hash">${esc(approval.effect_hash || "")}</code></dd>
       </dl>${resubmitForm}${jsonPre(body)}${back}`,
    );
  }
  const code = error?.code || "";
  return stateBlock(
    stateForErrorCode(code),
    code,
    `<h2>Daemon refusal (HTTP ${esc(String(result.status || 0))})</h2>
     <p class="sub">The daemon refused this ${esc(actionLabel)} — <code>${esc(code || "untyped")}</code>: ${esc(error?.message || "no message")}. The refusal is shown verbatim; nothing advanced and no success is inferred.</p>
     ${jsonPre(body)}${back}`,
  );
}

// Compose-time input failures (unparseable JSON) never reach the daemon and never fabricate a
// daemon-shaped error: they render as a NAMED surface-input refusal with zero effect.
function renderInputRefusal(what, detail, backHref) {
  return stateBlock(
    "denied_or_revoked",
    "surface_declaration_unparseable",
    `<h2>Declaration not parseable</h2><div class="empty">${esc(what)} is not valid JSON (${esc(detail)}). Nothing was sent to the daemon and nothing changed. This is a compose-time input refusal owned by the surface, not daemon truth.</div><p><a href="${esc(backHref)}">← back</a></p>`,
  );
}

// ---- projection census (shared by packages / governance / detail) --------------------------
async function fetchCensus(daemonUrl, view, systemId = null) {
  const filter = systemId ? `&system_id=${encodeURIComponent(systemId)}` : "";
  return daemonJson(daemonUrl, "GET", `${GENESIS_API}/projection?view=${view}${filter}`);
}

// Classify a census response into one honest block OR usable systems. The projection is
// deliberately all-or-nothing on the daemon side: while any admitted System has not reached a
// live chain it answers system_lifecycle_not_found, and a local/Agentgres divergence answers
// the fail-closed system_projection_source_incomplete — both render as census-level stops.
function censusState(result) {
  if (result.networkError) {
    return {
      html: stateBlock(
        "unavailable_or_degraded",
        "daemon_unreachable",
        `<div class="empty">Census unavailable — the daemon did not answer (<code>${esc(result.networkError)}</code>). No cached or fabricated Systems are shown.</div>`,
      ),
    };
  }
  const body = result.body || {};
  if (result.status === 200 && body.state === "honest_empty") {
    return {
      html: stateBlock(
        "honest_empty",
        null,
        `<div class="empty">No admitted Systems exist — the projection reports <code>honest_empty</code> from <code>${esc(body.projection_source || "")}</code>. Nothing is fixtured or defaulted; admit a genesis from the <a href="${BASE}/compose">composer</a>.</div>`,
      ),
      body,
    };
  }
  if (result.status === 200 && body.state === "ready") {
    return { systems: body.systems || [], body };
  }
  const code = body.error?.code || "";
  if (code === "system_projection_source_incomplete") {
    return {
      html: stateBlock(
        "stale_conflict_or_ambiguous",
        code,
        `<div class="empty">Projection fail-closed — <code>${esc(code)}</code>: ${esc(body.error?.message || "")}. The local and Agentgres admission censuses disagree, so NO partial or plausible list is rendered until the owners reconcile.</div>`,
      ),
    };
  }
  if (code === "system_lifecycle_not_found") {
    return {
      html: stateBlock(
        "loading_or_pending",
        code,
        `<div class="empty">Census withheld while genesis work is in flight — <code>${esc(code)}</code>: ${esc(body.error?.message || "")}. At least one admitted System has not reached its live chain (materialize → initialize → activate pending), and the projection refuses to guess. Per-System progress lives on the <a href="${BASE}/governance">Governance preview</a> ladder.</div>`,
      ),
    };
  }
  return {
    html: stateBlock(
      stateForErrorCode(code),
      code,
      `<div class="empty">Projection refused (HTTP ${esc(String(result.status || 0))}) — <code>${esc(code || "untyped")}</code>: ${esc(body.error?.message || "no message")}.</div>`,
    ),
  };
}

// ---- compact-lane identity rebind ----------------------------------------------------------
// Pure composition-time convenience (the compact lane): re-point one package declaration at a
// distinct System identity before submission. This mirrors the M1.6 dual-genesis grammar —
// same release, distinct system/genesis/constitution/profile identities. It derives NO truth:
// the daemon recompiles, re-verifies, and re-challenges the composed proposal from scratch.
function applyCompactRebind(declared, fields) {
  const proposed = declared?.proposed_instantiation;
  const candidate = proposed?.candidate;
  if (!proposed || !candidate) return;
  const set = (target, key, value) => {
    if (value && target && typeof target === "object") target[key] = value;
  };
  set(candidate, "system_id", fields.system_id);
  set(candidate, "genesis_id", fields.genesis_id);
  set(candidate, "constitution_ref", fields.constitution_ref);
  const refs = candidate.initial_profile_refs;
  if (refs && typeof refs === "object") {
    set(refs, "deployment_profile_ref", fields.deployment_profile_ref);
    set(refs, "ordering_admission_finality_profile_ref", fields.ordering_profile_ref);
    if (fields.oracle_profile_ref) refs.oracle_evidence_profile_refs = [fields.oracle_profile_ref];
    set(refs, "lifecycle_continuity_profile_ref", fields.lifecycle_profile_ref);
  }
  set(proposed.constitution, "system_id", fields.system_id);
  set(proposed.constitution, "constitution_id", fields.constitution_ref);
  set(proposed.ordering_profile, "system_id", fields.system_id);
  set(proposed.ordering_profile, "constitution_ref", fields.constitution_ref);
  set(proposed.ordering_profile, "ordering_profile_id", fields.ordering_profile_ref);
  if (Array.isArray(proposed.oracle_profiles) && proposed.oracle_profiles[0]) {
    set(proposed.oracle_profiles[0], "system_id", fields.system_id);
    set(proposed.oracle_profiles[0], "oracle_evidence_profile_id", fields.oracle_profile_ref);
  }
  set(proposed.lifecycle_profile, "system_id", fields.system_id);
  set(proposed.lifecycle_profile, "constitution_ref", fields.constitution_ref);
  set(proposed.lifecycle_profile, "lifecycle_profile_id", fields.lifecycle_profile_ref);
}

// ---- Studio · System Genesis Composer ------------------------------------------------------
function renderComposePage(shell, lane) {
  const compact = lane !== "advanced";
  const laneTabs = `<div class="tabs">
    <a class="tab${compact ? " active" : ""}" href="${BASE}/compose?lane=compact" data-lane-tab="compact">Compact lane</a>
    <a class="tab${compact ? "" : " active"}" href="${BASE}/compose?lane=advanced" data-lane-tab="advanced">Advanced declaration lane</a>
  </div>`;
  const rebindFields = compact
    ? `<h2>Identity (optional rebind before submit)</h2>
       <p class="sub">The compact lane re-points the pasted package declaration at a distinct System identity — the M1.6 grammar for instantiating the SAME reusable release as another System. Leave blank to submit the declaration's own identity. Rebinding composes; it never validates — the daemon does.</p>
       <div class="two">
         <div class="field"><label>system_id (system://…)</label><input name="system_id" placeholder="system://acme/system-beta"></div>
         <div class="field"><label>genesis_id (genesis://…)</label><input name="genesis_id" placeholder="genesis://acme/system-beta/zero"></div>
         <div class="field"><label>constitution_ref</label><input name="constitution_ref" placeholder="constitution://acme/system-beta/v1"></div>
         <div class="field"><label>deployment_profile_ref</label><input name="deployment_profile_ref" placeholder="deployment-profile://…/revision/sha256:…"></div>
         <div class="field"><label>ordering_profile_ref</label><input name="ordering_profile_ref" placeholder="ordering-profile://…"></div>
         <div class="field"><label>oracle_profile_ref</label><input name="oracle_profile_ref" placeholder="oracle-evidence-profile://…"></div>
         <div class="field"><label>lifecycle_profile_ref</label><input name="lifecycle_profile_ref" placeholder="lifecycle-profile://…"></div>
       </div>`
    : "";
  const inner = `${CROSSLINKS}<h1>Studio · System Genesis Composer</h1>
  ${NONCLAIMS_BANNER}
  <p class="sub">Compose a bounded-System genesis proposal from a package release and submit it to the daemon's governed admission route. Submission without a grant returns the daemon's exact authority challenge (an inspectable preview); an invalid proposal returns its blocker report; a granted submission commits ONE admission with its receipt. All three outcomes render verbatim.</p>
  ${laneTabs}
  <form method="post" action="${BASE}/compose">
    <input type="hidden" name="lane" value="${compact ? "compact" : "advanced"}">
    <div class="field"><label>Package + genesis declaration (JSON: <code>{"release": …, "proposed_instantiation": …}</code>)</label>
      <textarea name="declaration" style="min-height:220px" placeholder='{"release": { … manifest release … }, "proposed_instantiation": { "schema_version": "ioi.autonomous-system-genesis-proposal-input.v1", … }}'></textarea></div>
    ${rebindFields}
    <div class="field"><label>wallet_approval_grant (optional JSON — leave blank to preview the authority challenge)</label>
      <textarea name="wallet_approval_grant"></textarea></div>
    <button class="act" type="submit">Submit to daemon admission route</button>
  </form>`;
  return shell("System Genesis Composer", inner);
}

async function handleComposeSubmit(daemonUrl, shell, form) {
  const lane = form.get("lane") === "advanced" ? "advanced" : "compact";
  const backHref = `${BASE}/compose?lane=${lane}`;
  let declared;
  try {
    declared = JSON.parse(form.get("declaration") || "");
  } catch (error) {
    return shell("Composer — input refused", `${CROSSLINKS}<h1>Studio · System Genesis Composer</h1>${renderInputRefusal("The declaration", error.message, backHref)}`);
  }
  if (lane === "compact") {
    applyCompactRebind(declared, {
      system_id: (form.get("system_id") || "").trim(),
      genesis_id: (form.get("genesis_id") || "").trim(),
      constitution_ref: (form.get("constitution_ref") || "").trim(),
      deployment_profile_ref: (form.get("deployment_profile_ref") || "").trim(),
      ordering_profile_ref: (form.get("ordering_profile_ref") || "").trim(),
      oracle_profile_ref: (form.get("oracle_profile_ref") || "").trim(),
      lifecycle_profile_ref: (form.get("lifecycle_profile_ref") || "").trim(),
    });
  }
  const grantText = (form.get("wallet_approval_grant") || "").trim();
  let requestBody = declared;
  if (grantText) {
    try {
      requestBody = { ...declared, wallet_approval_grant: JSON.parse(grantText) };
    } catch (error) {
      return shell("Composer — input refused", `${CROSSLINKS}<h1>Studio · System Genesis Composer</h1>${renderInputRefusal("The wallet_approval_grant", error.message, backHref)}`);
    }
  }
  const result = await daemonJson(daemonUrl, "POST", GENESIS_API, requestBody);
  const outcome = renderOutcome(result, {
    actionLabel: "genesis proposal",
    backHref,
    resubmit: {
      action: `${BASE}/compose`,
      declaration: JSON.stringify(declared),
      extraHidden: `<input type="hidden" name="lane" value="advanced">`,
    },
  });
  return shell("Composer — daemon outcome", `${CROSSLINKS}<h1>Studio · System Genesis Composer</h1><p class="sub">Lane: <b data-composed-lane="${lane}">${lane}</b> — the outcome below is the daemon's answer to the composed declaration, verbatim.</p>${outcome}`);
}

// ---- Packages lifecycle --------------------------------------------------------------------
function renderPackagesPage(shell, censusResult) {
  const census = censusState(censusResult);
  let content;
  if (census.html) {
    content = census.html;
  } else {
    const byPackage = new Map();
    for (const system of census.systems) {
      const key = `${system.package_id || "unrecorded-package"} · ${system.manifest_ref || ""}`;
      if (!byPackage.has(key)) byPackage.set(key, { package_id: system.package_id, manifest_ref: system.manifest_ref, systems: [] });
      byPackage.get(key).systems.push(system);
    }
    const cards = [...byPackage.values()].map((pkg) => {
      const rows = pkg.systems.map((system) => {
        const tail = system.source_record_tail || "";
        const link = KEY_RE.test(tail) ? `<a href="${BASE}/${encodeURIComponent(tail)}">${esc(system.system_id || "")}</a>` : esc(system.system_id || "");
        return `<tr data-system-id="${esc(system.system_id || "")}">
          <td>${link}</td>
          <td>${pill(system.status || "unknown", system.status === "active" ? "ok" : "warn", ` data-lifecycle-status="${esc(system.status || "")}"`)}</td>
          <td>${esc(String(system.latest_sequence ?? ""))}</td>
          <td><code>${esc(system.genesis_ref || "")}</code></td>
          <td><code>${esc(system.evidence_refs?.latest_receipt_ref || "")}</code></td>
        </tr>`;
      }).join("");
      return `<div class="card" style="display:block" data-package-id="${esc(pkg.package_id || "")}">
        <div class="row" style="justify-content:space-between;margin:0 0 6px"><b>${esc(pkg.package_id || "unrecorded package")}</b><code>${esc(pkg.manifest_ref || "")}</code></div>
        <table><thead><tr><th>System</th><th>Status</th><th>Seq</th><th>Genesis</th><th>Latest receipt</th></tr></thead><tbody>${rows}</tbody></table>
      </div>`;
    }).join("");
    content = stateBlock(
      "ready_or_proposed",
      null,
      `<p class="sub">${census.systems.length} System${census.systems.length === 1 ? "" : "s"} across ${byPackage.size} package${byPackage.size === 1 ? "" : "s"} — rebuilt per request from <code>${esc(census.body.projection_source || "")}</code> (schema <code>${esc(census.body.schema_version || "")}</code>).</p>${cards}`,
    );
  }
  const inner = `${CROSSLINKS}<h1>Packages — Autonomous System lifecycle</h1>
  ${NONCLAIMS_BANNER}
  <p class="sub">Every package release the daemon has admitted a genesis from, with the per-System instantiation states the M1.7 compact projection reconstructs. One reusable package may instantiate many distinct Systems (M1.6); each row is one System's live state.</p>
  ${content}`;
  return shell("Packages lifecycle", inner);
}

// ---- Governance preview --------------------------------------------------------------------
const LADDER_STAGES = [
  { key: "admission", label: "Genesis admission (M1.3)", path: (tail) => `/${tail}` },
  { key: "sequence_zero", label: "Sequence-zero materialization (M1.4)", path: (tail) => `/${tail}/sequence-zero-materialization` },
  { key: "initialize", label: "Initialize (M1.5, sequence 1)", path: (tail) => `/${tail}/initialize` },
  { key: "activate", label: "Activate (M1.5, sequence 2)", path: (tail) => `/${tail}/activate` },
];

async function renderLadder(daemonUrl, tail) {
  const stages = await Promise.all(
    LADDER_STAGES.map((stage) => daemonJson(daemonUrl, "GET", `${GENESIS_API}${stage.path(tail)}`)),
  );
  const rows = LADDER_STAGES.map((stage, index) => {
    const result = stages[index];
    if (result.networkError) {
      return `<tr data-ladder-stage="${stage.key}"><td>${esc(stage.label)}</td><td>${pill("daemon unreachable", "warn")}</td><td><code>${esc(result.networkError)}</code></td></tr>`;
    }
    if (result.status === 200) {
      const receiptRef = result.body?.autonomous_system_genesis_receipt?.receipt_ref
        || result.body?.autonomous_system_sequence_zero_materialization_receipt?.receipt_ref
        || result.body?.lifecycle_receipt?.receipt_ref
        || result.body?.activation_receipt?.receipt_ref
        || "";
      return `<tr data-ladder-stage="${stage.key}" data-ladder-state="admitted"><td>${esc(stage.label)}</td><td>${pill("admitted", "ok")}</td><td><code>${esc(receiptRef)}</code></td></tr>`;
    }
    const code = result.body?.error?.code || "untyped";
    return `<tr data-ladder-stage="${stage.key}" data-ladder-state="pending"><td>${esc(stage.label)}</td><td>${pill("not admitted", "muted")}</td><td><code>${esc(code)}</code> ${esc(result.body?.error?.message || "")}</td></tr>`;
  }).join("");
  return `<table><thead><tr><th>Governed stage</th><th>State</th><th>Owner evidence / refusal</th></tr></thead><tbody>${rows}</tbody></table>
  <p class="sub">Each row is a live daemon read — a refusal renders verbatim and never implies progress. Approvals happen ONLY as wallet grants attached on the <a href="${BASE}/compose">composer</a> or the System detail action forms; this preview cannot approve anything.</p>`;
}

async function renderGovernancePage(daemonUrl, shell, selectedTail) {
  const censusResult = await fetchCensus(daemonUrl, "compact");
  const census = censusState(censusResult);
  let censusHtml;
  if (census.html) {
    censusHtml = census.html;
  } else {
    const rows = census.systems.map((system) => {
      const tail = system.source_record_tail || "";
      return `<tr data-system-id="${esc(system.system_id || "")}">
        <td><code>${esc(system.system_id || "")}</code></td>
        <td>${pill(system.status || "unknown", system.status === "active" ? "ok" : "warn", ` data-lifecycle-status="${esc(system.status || "")}"`)}</td>
        <td>${KEY_RE.test(tail) ? `<a href="${BASE}/governance?system=${encodeURIComponent(tail)}">ladder →</a> · <a href="${BASE}/${encodeURIComponent(tail)}">detail →</a>` : "—"}</td>
      </tr>`;
    }).join("");
    censusHtml = stateBlock(
      "ready_or_proposed",
      null,
      `<table><thead><tr><th>System</th><th>Status</th><th>Inspect</th></tr></thead><tbody>${rows}</tbody></table>`,
    );
  }
  const ladder = selectedTail && KEY_RE.test(selectedTail)
    ? `<h2>Governed ladder — <code>${esc(selectedTail)}</code></h2>${await renderLadder(daemonUrl, selectedTail)}`
    : "";
  const inner = `${CROSSLINKS}<h1>Governance — genesis &amp; activation preview</h1>
  ${NONCLAIMS_BANNER}
  <p class="sub" data-sysgen-preview-nonclaim="1"><b>Preview, not authority.</b> This surface shows what the daemon would require for a genesis or lifecycle decision and where each admitted System stands on its governed ladder. It cannot approve, admit, or activate anything: approval is a wallet grant consumed by the daemon route, and this surface strips any grant pasted here.</p>
  <h2>Admitted Systems</h2>
  ${censusHtml}
  ${ladder}
  <h2>Preview a pending genesis proposal</h2>
  <p class="sub">Paste a package + genesis declaration to see the daemon's pending decision for it: the exact authority challenge (policy/request/effect hashes) a valid proposal awaits, or the blocker report an invalid one earns. Any <code>wallet_approval_grant</code> in the pasted body is <b>stripped before submission</b> — this preview never exercises authority.</p>
  <form method="post" action="${BASE}/governance/preview">
    <div class="field"><label>Declaration (JSON: <code>{"release": …, "proposed_instantiation": …}</code>)</label>
      <textarea name="declaration" style="min-height:180px"></textarea></div>
    <button class="act" type="submit">Preview pending decision</button>
  </form>`;
  return shell("Governance preview", inner);
}

async function handleGovernancePreview(daemonUrl, shell, form) {
  const backHref = `${BASE}/governance`;
  let declared;
  try {
    declared = JSON.parse(form.get("declaration") || "");
  } catch (error) {
    return shell("Governance preview — input refused", `${CROSSLINKS}<h1>Governance — genesis &amp; activation preview</h1>${renderInputRefusal("The declaration", error.message, backHref)}`);
  }
  let stripped = false;
  if (declared && typeof declared === "object" && "wallet_approval_grant" in declared) {
    delete declared.wallet_approval_grant;
    stripped = true;
  }
  const result = await daemonJson(daemonUrl, "POST", GENESIS_API, declared);
  const strippedNote = stripped
    ? `<p class="sub" data-grant-stripped="1">A <code>wallet_approval_grant</code> was present in the pasted declaration and was <b>stripped</b> — the Governance preview never carries authority to the daemon.</p>`
    : `<p class="sub" data-grant-stripped="0">No grant traveled with this preview.</p>`;
  const outcome = renderOutcome(result, { actionLabel: "genesis proposal preview", backHref });
  return shell(
    "Governance preview — pending decision",
    `${CROSSLINKS}<h1>Governance — genesis &amp; activation preview</h1><p class="sub" data-sysgen-preview-nonclaim="1"><b>Preview, not authority.</b></p>${strippedNote}${outcome}`,
  );
}

// ---- Provisional System detail -------------------------------------------------------------
function actionForm(action, label, skeleton, note) {
  return `<details class="card" style="display:block"><summary style="cursor:pointer"><b>${esc(label)}</b> <span class="sub" style="display:inline;margin:0;text-transform:none;letter-spacing:0">${esc(note || "")}</span></summary>
    <form method="post" action="${esc(action)}" style="margin-top:10px">
      <div class="field"><label>Request declaration (JSON — expected roots/refs are owner facts you hold from prior receipts)</label>
        <textarea name="request" style="min-height:110px">${esc(JSON.stringify(skeleton, null, 2))}</textarea></div>
      <div class="field"><label>wallet_approval_grant (optional JSON — omit to receive the authority challenge preview)</label>
        <textarea name="wallet_approval_grant"></textarea></div>
      <button class="act" type="submit">Submit to daemon route</button>
    </form></details>`;
}

async function renderDetailPage(daemonUrl, shell, tail, view) {
  const [admission, sequenceZero, initialize, activate] = await Promise.all([
    daemonJson(daemonUrl, "GET", `${GENESIS_API}/${tail}`),
    daemonJson(daemonUrl, "GET", `${GENESIS_API}/${tail}/sequence-zero-materialization`),
    daemonJson(daemonUrl, "GET", `${GENESIS_API}/${tail}/initialize`),
    daemonJson(daemonUrl, "GET", `${GENESIS_API}/${tail}/activate`),
  ]);
  const title = `System ${tail.slice(0, 16)}…`;
  const head = `${CROSSLINKS}<h1>Provisional System detail</h1>
  ${NONCLAIMS_BANNER}
  <p class="sub" data-provisional-detail="1">A provisional, launch-addressed readout of ONE System (<code>${esc(tail)}</code>) — deliberately not a permanent Systems navigation destination (M1.7). Compact and advanced views are the daemon's own read projections.</p>`;
  if (admission.networkError) {
    return shell(title, head + stateBlock(
      "unavailable_or_degraded",
      "daemon_unreachable",
      `<div class="empty">Daemon unreachable (<code>${esc(admission.networkError)}</code>) — no admission, chain, or receipt facts can be shown, and none are substituted.</div>`,
    ));
  }
  if (admission.status !== 200) {
    const code = admission.body?.error?.code || "";
    return shell(title, head + stateBlock(
      stateForErrorCode(code),
      code,
      `<div class="empty">No verified admission renders at this key — <code>${esc(code || "untyped")}</code>: ${esc(admission.body?.error?.message || "")}. Nothing substituted.</div>${jsonPre(admission.body || {})}`,
    ));
  }
  const record = admission.body.autonomous_system_genesis_admission || {};
  const receipt = admission.body.autonomous_system_genesis_receipt || {};
  const systemId = record.system_id || "";
  const [projCompact, projAdvanced] = await Promise.all([
    fetchCensus(daemonUrl, "compact", systemId),
    fetchCensus(daemonUrl, "advanced", systemId),
  ]);

  const identity = `<h2>Identity (admission owner truth)</h2><dl class="grid">
    <dt>system_id</dt><dd><code data-detail-system-id="${esc(systemId)}">${esc(systemId)}</code></dd>
    <dt>package_id</dt><dd><code>${esc(record.package_id || "")}</code></dd>
    <dt>manifest_ref</dt><dd><code>${esc(record.manifest_ref || "")}</code></dd>
    <dt>genesis_ref</dt><dd><code>${esc(record.genesis_ref || "")}</code></dd>
    <dt>proposal_root</dt><dd><code>${esc(record.proposal_root || "")}</code></dd>
    <dt>admission receipt</dt><dd><code>${esc(receipt.receipt_ref || "")}</code></dd>
    <dt>governing authority</dt><dd><code>${esc(record.governing_authority_ref || "")}</code></dd>
  </dl>`;

  const stageRow = (key, label, result, receiptPointer) => {
    if (result.networkError) return `<tr data-ladder-stage="${key}"><td>${esc(label)}</td><td>${pill("daemon unreachable", "warn")}</td><td><code>${esc(result.networkError)}</code></td></tr>`;
    if (result.status === 200) {
      const ref = receiptPointer(result.body) || "";
      return `<tr data-ladder-stage="${key}" data-ladder-state="admitted"><td>${esc(label)}</td><td>${pill("admitted", "ok")}</td><td><code>${esc(ref)}</code></td></tr>`;
    }
    const code = result.body?.error?.code || "untyped";
    return `<tr data-ladder-stage="${key}" data-ladder-state="pending"><td>${esc(label)}</td><td>${pill("not admitted", "muted")}</td><td><code>${esc(code)}</code> ${esc(result.body?.error?.message || "")}</td></tr>`;
  };
  const ladder = `<h2>Lifecycle ladder</h2><table><thead><tr><th>Stage</th><th>State</th><th>Owner evidence / refusal</th></tr></thead><tbody>
    ${stageRow("admission", "Genesis admission (M1.3)", admission, (b) => b?.autonomous_system_genesis_receipt?.receipt_ref)}
    ${stageRow("sequence_zero", "Sequence-zero materialization (M1.4)", sequenceZero, (b) => b?.autonomous_system_sequence_zero_materialization_receipt?.receipt_ref)}
    ${stageRow("initialize", "Initialize (sequence 1)", initialize, (b) => b?.lifecycle_receipt?.receipt_ref || b?.receipt?.receipt_ref)}
    ${stageRow("activate", "Activate (sequence 2)", activate, (b) => b?.activation_receipt?.receipt_ref || b?.lifecycle_receipt?.receipt_ref || b?.receipt?.receipt_ref)}
  </tbody></table>
  <p class="sub">Continuity ladder statuses render verbatim from the chain head below — dissolution runs <code>dissolution_pending</code> → <code>dissolving</code> → <code>dissolved</code>; succession, migration, and enrollment carry their own named statuses and scopes.</p>`;

  let projection;
  const chosen = view === "advanced" ? projAdvanced : projCompact;
  const chosenCensus = censusState(chosen);
  const viewTabs = `<div class="tabs">
    <a class="tab${view === "advanced" ? "" : " active"}" href="${BASE}/${encodeURIComponent(tail)}?view=compact">Compact preview</a>
    <a class="tab${view === "advanced" ? " active" : ""}" href="${BASE}/${encodeURIComponent(tail)}?view=advanced">Advanced projection</a>
  </div>`;
  if (chosenCensus.html) {
    projection = viewTabs + chosenCensus.html;
  } else {
    const mine = chosenCensus.systems.find((system) =>
      (view === "advanced" ? system?.compact?.system_id : system?.system_id) === systemId);
    if (!mine) {
      projection = viewTabs + stateBlock(
        "honest_empty",
        null,
        `<div class="empty">The ${esc(view)} projection carries no record for <code>${esc(systemId)}</code> — nothing substituted.</div>`,
      );
    } else {
      const compact = view === "advanced" ? mine.compact || {} : mine;
      const status = compact.status || "";
      projection = viewTabs + stateBlock(
        "completed",
        null,
        `<dl class="grid">
          <dt>status</dt><dd>${pill(status || "unknown", status === "active" ? "ok" : "warn", ` data-lifecycle-status="${esc(status)}"`)}</dd>
          <dt>latest_sequence</dt><dd><code>${esc(String(compact.latest_sequence ?? ""))}</code></dd>
          <dt>constitution_ref</dt><dd><code>${esc(compact.constitution_ref || "")}</code></dd>
          <dt>chain_root</dt><dd><code>${esc(compact.canonical_roots?.chain_root || "")}</code></dd>
          <dt>latest_state_root</dt><dd><code>${esc(compact.canonical_roots?.latest_state_root || "")}</code></dd>
          <dt>latest receipt</dt><dd><code>${esc(compact.evidence_refs?.latest_receipt_ref || "")}</code></dd>
          <dt>chain ref</dt><dd><code>${esc(compact.evidence_refs?.chain_ref || "")}</code></dd>
          <dt>projection_source</dt><dd><code>${esc(chosenCensus.body.projection_source || "")}</code></dd>
        </dl>
        <p class="sub">Nonclaims (daemon-declared): ${jsonInline(chosenCensus.body.nonclaims)}</p>
        ${jsonPre(mine)}`,
      );
    }
  }

  const continuityOptions = CONTINUITY_OPS.map((op) => `<option value="${op}">${op}</option>`).join("");
  const actions = `<h2>Governed lifecycle actions</h2>
  <p class="sub">Each form proxies ONE declaration verbatim to its owning daemon route. Without a grant the daemon answers its authority challenge (rendered as a preview); with a grant it commits or refuses — always shown verbatim. The serve layer never mutates state itself.</p>
  ${actionForm(`${BASE}/${encodeURIComponent(tail)}/sequence-zero-materialization`, "Materialize sequence zero (M1.4)", { expected_genesis_admission_record_root: "", expected_genesis_admission_receipt_root: "" }, "byte-verifies the admission you inspected above")}
  ${actionForm(`${BASE}/${encodeURIComponent(tail)}/initialize`, "Initialize (sequence 1)", { expected_sequence_zero_materialization_root: "", expected_sequence_zero_materialization_receipt_root: "", deployment_profile_revision: {} }, "binds the exact M1.4 artifact + pinned deployment revision")}
  ${actionForm(`${BASE}/${encodeURIComponent(tail)}/activate`, "Activate (sequence 2)", { expected_initialize_proposal_root: "", expected_initialize_decision_root: "", expected_initialize_state_root: "", expected_initialize_transition_root: "", expected_initialize_receipt_root: "" }, "refused by the daemon unless initialize is admitted")}
  <details class="card" style="display:block"><summary style="cursor:pointer"><b>Continuity transition (M1.5d)</b> <span class="sub" style="display:inline;margin:0;text-transform:none;letter-spacing:0">succession · migration · dissolution ladder · enrollment</span></summary>
    <form method="post" action="${BASE}/${encodeURIComponent(tail)}/continuity" style="margin-top:10px">
      <div class="field"><label>Operation</label><select name="op">${continuityOptions}</select></div>
      <div class="field"><label>Request declaration (JSON)</label>
        <textarea name="request" style="min-height:110px">${esc(JSON.stringify({ expected_chain_head_root: "", expected_predecessor_state_root: "", trigger_evidence_refs: [] }, null, 2))}</textarea></div>
      <div class="field"><label>wallet_approval_grant (optional JSON)</label><textarea name="wallet_approval_grant"></textarea></div>
      <button class="act" type="submit">Submit to daemon route</button>
    </form></details>
  ${actionForm(`${BASE}/${encodeURIComponent(tail)}/transitions`, "Protected transition (M1.5b)", { op: "", expected_chain_head_root: "", expected_predecessor_state_root: "" }, "one of the 14 generic protected ops; 'op' selects the route")}
  ${actionForm(`${BASE}/${encodeURIComponent(tail)}/amendments`, "Amendment execution (M1.5c)", {}, "executes an approved amendment exactly once under the constitution's own governance")}`;

  return shell(title, head + identity + ladder + `<h2>Read projection (M1.7)</h2>` + projection + actions);
}

function jsonInline(value) {
  return `<code>${esc(JSON.stringify(value ?? null))}</code>`;
}

async function handleDetailAction(daemonUrl, shell, tail, subPath, form) {
  const backHref = `${BASE}/${encodeURIComponent(tail)}`;
  let daemonPath = null;
  let label = subPath;
  if (subPath === "sequence-zero-materialization" || subPath === "initialize" || subPath === "activate" || subPath === "amendments") {
    daemonPath = `${GENESIS_API}/${tail}/${subPath}`;
  } else if (subPath === "continuity") {
    const op = (form.get("op") || "").trim();
    if (!CONTINUITY_OPS.includes(op)) {
      return shell("System action — input refused", `${CROSSLINKS}<h1>Provisional System detail</h1>${renderInputRefusal("The continuity operation", `'${op}' is not one of the nine M1.5d wire operations`, backHref)}`);
    }
    daemonPath = `${GENESIS_API}/${tail}/continuity/${op}`;
    label = `continuity ${op}`;
  } else if (subPath === "transitions") {
    let parsedProbe = {};
    try { parsedProbe = JSON.parse(form.get("request") || "{}"); } catch { /* handled below with the shared parse */ }
    const op = (form.get("op") || parsedProbe.op || "").trim();
    if (!OP_RE.test(op)) {
      return shell("System action — input refused", `${CROSSLINKS}<h1>Provisional System detail</h1>${renderInputRefusal("The transition operation", `'${op}' is not a canonical wire operation name`, backHref)}`);
    }
    daemonPath = `${GENESIS_API}/${tail}/transitions/${op}`;
    label = `transition ${op}`;
  } else {
    return null;
  }
  let request;
  try {
    request = JSON.parse(form.get("request") || "{}");
  } catch (error) {
    return shell("System action — input refused", `${CROSSLINKS}<h1>Provisional System detail</h1>${renderInputRefusal("The request declaration", error.message, backHref)}`);
  }
  if (request && typeof request === "object" && !Array.isArray(request)) delete request.op;
  const grantText = (form.get("wallet_approval_grant") || "").trim();
  let requestBody = request;
  if (grantText) {
    try {
      requestBody = { ...request, wallet_approval_grant: JSON.parse(grantText) };
    } catch (error) {
      return shell("System action — input refused", `${CROSSLINKS}<h1>Provisional System detail</h1>${renderInputRefusal("The wallet_approval_grant", error.message, backHref)}`);
    }
  }
  const result = await daemonJson(daemonUrl, "POST", daemonPath, requestBody);
  const outcome = renderOutcome(result, {
    actionLabel: label,
    backHref,
    resubmit: {
      action: `${BASE}/${encodeURIComponent(tail)}/${subPath}`,
      declaration: JSON.stringify(request),
      declarationField: "request",
      extraHidden: subPath === "continuity" ? `<input type="hidden" name="op" value="${esc((form.get("op") || "").trim())}">` : (subPath === "transitions" ? `<input type="hidden" name="op" value="${esc((form.get("op") || "").trim())}">` : ""),
    },
  });
  return shell(
    `System action — ${label}`,
    `${CROSSLINKS}<h1>Provisional System detail — governed action</h1><p class="sub">Route: <code>POST ${esc(daemonPath)}</code> — outcome verbatim.</p>${outcome}`,
  );
}

// ---- dispatch ------------------------------------------------------------------------------
// Returns true when the request was handled. `shell` is the estate page shell
// (automationsShell) and `daemonUrl` the serve's single daemon origin.
export async function handleSystemGenesisSurfaces(req, res, pathname, body, { daemonUrl, shell }) {
  if (pathname !== BASE && !pathname.startsWith(`${BASE}/`)) return false;
  const query = new URL(req.url || "", "http://x").searchParams;
  const sendHtml = (html) => { res.writeHead(200, HTMLH); res.end(html); };
  const form = () => new URLSearchParams(body.toString());

  if (pathname === BASE) {
    res.writeHead(302, { Location: `${BASE}/packages`, "Cache-Control": "no-cache" });
    res.end();
    return true;
  }
  if (pathname === `${BASE}/compose` && req.method === "GET") {
    sendHtml(renderComposePage(shell, query.get("lane") === "advanced" ? "advanced" : "compact"));
    return true;
  }
  if (pathname === `${BASE}/compose` && req.method === "POST") {
    sendHtml(await handleComposeSubmit(daemonUrl, shell, form()));
    return true;
  }
  if (pathname === `${BASE}/packages` && req.method === "GET") {
    sendHtml(renderPackagesPage(shell, await fetchCensus(daemonUrl, "compact")));
    return true;
  }
  if (pathname === `${BASE}/governance` && req.method === "GET") {
    sendHtml(await renderGovernancePage(daemonUrl, shell, query.get("system") || ""));
    return true;
  }
  if (pathname === `${BASE}/governance/preview` && req.method === "POST") {
    sendHtml(await handleGovernancePreview(daemonUrl, shell, form()));
    return true;
  }
  const rest = pathname.slice(BASE.length + 1).split("/");
  const tail = rest[0] || "";
  if (!KEY_RE.test(tail)) {
    res.writeHead(404, HTMLH);
    res.end(shell("Not found", `${CROSSLINKS}<h1>Provisional System detail</h1>${stateBlock("honest_empty", "system_genesis_key_invalid", `<div class="empty">'${esc(tail)}' is not a canonical <code>asg_&lt;64 hex&gt;</code> System key — nothing substituted.</div>`)}`));
    return true;
  }
  if (rest.length === 1 && req.method === "GET") {
    sendHtml(await renderDetailPage(daemonUrl, shell, tail, query.get("view") === "advanced" ? "advanced" : "compact"));
    return true;
  }
  if (rest.length === 2 && req.method === "POST") {
    const handled = await handleDetailAction(daemonUrl, shell, tail, rest[1], form());
    if (handled) { sendHtml(handled); return true; }
  }
  res.writeHead(404, HTMLH);
  res.end(shell("Not found", `${CROSSLINKS}<h1>Systems</h1><div class="empty">No such Systems surface route.</div>`));
  return true;
}

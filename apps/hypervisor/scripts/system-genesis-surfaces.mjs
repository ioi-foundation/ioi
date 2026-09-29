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
import { createHash } from "node:crypto";
import { callerOwnerRef, escHtml, refusalCodeOf, refusalMessageOf } from "../surfaces/kit.mjs";
import { relayChallengeDecision } from "./lib/wallet-authority.mjs";
import { challengePagePath } from "./authority-challenge-page.mjs";
import { renderTargetHealth } from "./operations-health.mjs";
import { renderTargetTelemetry } from "./operations-telemetry.mjs";

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
// THE CALLER RIDES EVERY READ (R-240). This transport used to send only content-type, so the
// principal-scoped reads (the Systems projection, the record seam) refused every signed-in owner as a
// stranger and the page printed "Projection refused (HTTP 401) — untyped". `daemon` is the daemon URL,
// or `{ url, headers }` carrying the caller's own identity headers — forwarded, never minted.
const IDENTITY_HEADERS = ["authorization", "cookie", "x-forwarded-host", "x-forwarded-for", "x-ioi-forwarded"];
function callerIdentityHeaders(req) {
  const out = {};
  for (const name of IDENTITY_HEADERS) if (req?.headers?.[name]) out[name] = req.headers[name];
  return out;
}
function daemonJson(daemon, method, path, payload) {
  const daemonUrl = typeof daemon === "string" ? daemon : daemon?.url;
  const identity = typeof daemon === "string" ? {} : daemon?.headers || {};
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
          ...identity,
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
    const card = approvalCard(error, resubmit);
    const resubmitForm = resubmit
      ? `<h3 style="margin:16px 0 6px">Attach existing authority</h3>
         <p class="sub">${card ? "Or attach a grant minted outside this deployment: " : "Approving is a wallet act, not a surface act: "}paste a wallet approval grant minted for the EXACT policy/request hashes above. The declaration below is resubmitted verbatim to the daemon route.</p>
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
       </dl>${card}${resubmitForm}${jsonPre(body)}${back}`,
    );
  }
  const code = error?.code || body?.code || "";
  return stateBlock(
    stateForErrorCode(code),
    code,
    `<h2>Daemon refusal (HTTP ${esc(String(result.status || 0))})</h2>
     <p class="sub">The daemon refused this ${esc(actionLabel)} — <code>${esc(code || "untyped")}</code>: ${esc(error?.message || body?.message || "no message")}. The refusal is shown verbatim; nothing advanced and no success is inferred.</p>
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

// ---- the operator's approval, through the daemon (R-240, journey WP-A) ---------------------
// A governed genesis or lifecycle step refused for want of a grant is PARKED by the daemon as a
// wallet approval challenge (`error.approval_challenge` on its 403: the exact hashes, scope and
// audience a grant would bind, in the daemon's own record). The challenge page then carries the
// operator's approval card: the passphrase goes, once, to the daemon's decision route through the
// approval cards' one relay (lib/wallet-authority.mjs relayChallengeDecision), and the daemon's
// deployment authority signs ONE one-use grant for exactly that record. This surface signs nothing,
// holds no key and keeps nothing typed (master guide §0.5.2, N9). A decision answers with the
// Resume form: the SAME declaration, naming the challenge's approval_ref, which the daemon claims
// only when the hashes it derives from the resubmitted declaration are the approved ones (N12), and
// consumes once. The same challenge is listed on its own page and in Approvals.
const CHALLENGE_ID_RE = /^wac_[0-9a-f]{32}$/u;
const APPROVAL_REF_RE = /^wallet-approval-challenge:\/\/wac_[0-9a-f]{32}$/u;
const approvalRefOf = (id) => `wallet-approval-challenge://${id}`;
const PASSPHRASE_INPUT = `<input type="password" name="operator_passphrase" autocomplete="off" required placeholder="operator passphrase" aria-label="Operator passphrase" data-ioi-operator-passphrase>`;

// The declaration a governed form re-offers, carried unchanged into the next form.
function carriedDeclaration(resubmit) {
  return `<textarea name="${esc(resubmit.declarationField || "declaration")}" style="display:none">${esc(resubmit.declaration)}</textarea>${resubmit.extraHidden || ""}`;
}

// The operator's approval card for the challenge the daemon parked (or why none can be offered).
function approvalCard(error, resubmit) {
  const parked = error?.approval_challenge && typeof error.approval_challenge === "object" ? error.approval_challenge : null;
  const id = String(parked?.challenge_id || "");
  if (!parked || !CHALLENGE_ID_RE.test(id)) {
    const withheld = typeof error?.approval_challenge_withheld === "string" ? error.approval_challenge_withheld : "";
    return withheld ? `<div class="card" style="display:block" data-approval-card="withheld"><h3 style="margin:0 0 6px">No approval card</h3><p class="sub">The daemon parked no challenge for this effect: ${esc(withheld)}</p></div>` : "";
  }
  const page = challengePagePath(id);
  const lead = `<p class="sub">The daemon parked this exact effect for the operator as challenge <code>${esc(id)}</code> — see <a href="${esc(page)}">its own page</a>; it is listed in Approvals too. Approving sends your operator passphrase to the daemon, whose deployment authority signs ONE one-use grant for exactly the hashes above; this page holds no key and keeps nothing you type. Once it is approved, resume the step to run it once.</p>`;
  const form = !resubmit
    ? `<p class="sub">Approve it on <a href="${esc(page)}">its own page</a>, then submit this step again naming <code>${esc(approvalRefOf(id))}</code>.</p>`
    : parked.decidable === true
      ? `<form method="post" action="${esc(resubmit.action)}" data-approval-card-form="1">${carriedDeclaration(resubmit)}<input type="hidden" name="approval_challenge_id" value="${esc(id)}"><div class="field"><label>Operator passphrase</label>${PASSPHRASE_INPUT}</div><button class="act" type="submit">Approve — sign one grant for exactly this</button></form>`
      : `<p class="sub" data-approval-undecidable="1">This daemon has no deployment authority to approve with (IOI_WALLET_AUTHORITY_BINARY and IOI_HYPERVISOR_LOCAL_AUTHORITY_STATE_DIR on the daemon), so no Hypervisor page approves it; the operator approves it with the local authority's approve command, or attaches a grant below.</p>`;
  return `<div class="card" style="display:block" data-approval-card="1" data-approval-challenge="${esc(id)}"><h3 style="margin:0 0 6px">Approve this effect</h3>${lead}${form}</div>`;
}

// The approval card's post: relay the operator's decision to the daemon, re-read the challenge from
// the daemon, and answer with the Resume form — or the daemon's refusal and the card again.
async function relayGovernedApproval(daemonUrl, form, { resubmit, backHref, actionLabel }) {
  const back = backHref ? `<p><a href="${esc(backHref)}">← back</a></p>` : "";
  const id = String(form.get("approval_challenge_id") || "").trim();
  let passphrase = form.get("operator_passphrase") || "";
  form.delete("operator_passphrase");
  if (!CHALLENGE_ID_RE.test(id)) {
    passphrase = "";
    return stateBlock("denied_or_revoked", "approval_challenge_id_invalid", `<h2>Not approved</h2><div class="empty">'${esc(id)}' is not a challenge the daemon parked (wac_ plus 32 lowercase hex). Nothing was sent to the daemon.</div>${back}`);
  }
  const relayed = await relayChallengeDecision({
    challengeId: id, decision: "approve", reason: `approved on the ${actionLabel} challenge page`, operatorPassphrase: passphrase,
    transport: (method, route, payload) => daemonJson(daemonUrl, method, route, payload).then((r) => {
      if (r.networkError) throw new Error(r.networkError);
      return { status: r.status, body: r.body };
    }),
  });
  passphrase = "";
  const reread = await daemonJson(daemonUrl, "GET", `/v1/hypervisor/authority/challenges/${id}`);
  const record = !reread.networkError && reread.status === 200 && reread.body?.challenge && typeof reread.body.challenge === "object" ? reread.body.challenge : null;
  const page = challengePagePath(id);
  const ref = approvalRefOf(id);
  const resume = `<form method="post" action="${esc(resubmit.action)}" data-approval-resume="1">${carriedDeclaration(resubmit)}<input type="hidden" name="approval_ref" value="${esc(ref)}"><button class="act" type="submit">Resume — run it once under this approval</button></form>`;
  if (record?.state === "approved") {
    const expires = Number(record.grant_expires_at_ms) > 0 ? new Date(Number(record.grant_expires_at_ms)).toISOString() : "";
    return stateBlock("ready_or_proposed", null, `<h2>Approved — resume to run it once</h2><p class="sub" data-approval-state="approved" data-approval-ref="${esc(ref)}">The daemon records challenge <code>${esc(id)}</code> approved${record.decision?.decided_by ? ` by <code>${esc(record.decision.decided_by)}</code>` : ""}: its deployment authority minted one one-use grant (<code>${esc(typeof record.grant_ref === "string" ? record.grant_ref : "")}</code>) for exactly its hashes${expires ? `, usable until ${esc(expires)}` : ""}. Nothing has run yet. Resuming submits the same declaration naming <code>${esc(ref)}</code>; the daemon presents the stored grant only if the hashes it derives from it are the approved ones, and consumes it once.</p>${resume}<p><a href="${esc(page)}">The challenge's own page →</a></p>${back}`);
  }
  if (Number(relayed.status) === 202 || relayed.error?.code === "challenge_decision_still_running" || record?.deciding) {
    return stateBlock("loading_or_pending", "challenge_decision_still_running", `<h2>Still deciding</h2><p class="sub" data-approval-state="deciding" data-approval-ref="${esc(ref)}">The daemon accepted the approval of challenge <code>${esc(id)}</code> and its deployment authority is still recording it; the daemon settles it on its own and nothing needs to be sent again. Resume once <a href="${esc(page)}">its own page</a> reads Approved — until then the daemon refuses the resume by name and runs nothing.</p>${resume}${back}`);
  }
  const code = relayed.error?.code || (record ? `challenge_${record.state || "unknown"}` : "challenge_unreadable");
  return stateBlock("denied_or_revoked", code, `<h2>Not approved</h2><p class="sub" data-approval-state="${esc(record?.state || "unknown")}">The daemon did not approve challenge <code>${esc(id)}</code> (HTTP ${esc(String(relayed.status || 0))}) — <code>${esc(code)}</code>: ${esc(relayed.error?.message || "no message")}. Nothing was approved, and the challenge reads as the daemon records it on <a href="${esc(page)}">its own page</a>.</p>${record?.state === "pending" ? approvalCard({ approval_challenge: { challenge_id: id, decidable: record.decidable === true } }, resubmit) : ""}${back}`);
}

// The authority a resubmitted governed form carries: a pasted grant, or the approval_ref of the
// challenge the operator approved (the daemon's locator form, `{approval_ref}`) — never both.
// Returns { grant } (null when none) or { refusal } — a surface-owned input refusal, nothing sent.
function carriedAuthority(form, backHref) {
  const grantText = (form.get("wallet_approval_grant") || "").trim();
  const approvalRef = (form.get("approval_ref") || "").trim();
  const refuse = (code, detail) => ({ refusal: stateBlock("denied_or_revoked", code, `<h2>Authority not understood</h2><div class="empty">${esc(detail)} Nothing was sent to the daemon and nothing changed. This is a compose-time input refusal owned by the surface, not daemon truth.</div><p><a href="${esc(backHref)}">← back</a></p>`) });
  if (grantText && approvalRef) return refuse("surface_authority_ambiguous", "The form names both a pasted wallet grant and an approval_ref; a governed step carries one authority.");
  if (approvalRef) {
    if (!APPROVAL_REF_RE.test(approvalRef)) return refuse("surface_approval_ref_invalid", `'${approvalRef}' is not a wallet-approval-challenge://wac_… ref the daemon issued.`);
    return { grant: { approval_ref: approvalRef } };
  }
  if (!grantText) return { grant: null };
  try {
    return { grant: JSON.parse(grantText) };
  } catch (error) {
    return { refusal: renderInputRefusal("The wallet_approval_grant", error.message, backHref) };
  }
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
  // Refusals come nested ({error:{code}}) or flat ({code, message} — identity-first refusals); read both.
  const code = result.status >= 400 ? refusalCodeOf(body, result.status) : body.error?.code || "";
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
      `<div class="empty">Projection refused (HTTP ${esc(String(result.status || 0))}) — <code>${esc(code || "untyped")}</code>: ${esc(refusalMessageOf(body) || "no message")}.</div>`,
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
  const resubmit = {
    action: `${BASE}/compose`,
    declaration: JSON.stringify(declared),
    extraHidden: `<input type="hidden" name="lane" value="advanced">`,
  };
  if (form.has("approval_challenge_id")) {
    const decided = await relayGovernedApproval(daemonUrl, form, { resubmit, backHref, actionLabel: "genesis proposal" });
    return shell("Composer — the operator's approval", `${CROSSLINKS}<h1>Studio · System Genesis Composer</h1>${decided}`);
  }
  const authority = carriedAuthority(form, backHref);
  if (authority.refusal) return shell("Composer — input refused", `${CROSSLINKS}<h1>Studio · System Genesis Composer</h1>${authority.refusal}`);
  const requestBody = authority.grant ? { ...declared, wallet_approval_grant: authority.grant } : declared;
  const result = await daemonJson(daemonUrl, "POST", GENESIS_API, requestBody);
  const outcome = renderOutcome(result, { actionLabel: "genesis proposal", backHref, resubmit });
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
    const code = refusalCodeOf(result.body, result.status) || "untyped";
    return `<tr data-ladder-stage="${stage.key}" data-ladder-state="pending"><td>${esc(stage.label)}</td><td>${pill("not admitted", "muted")}</td><td><code>${esc(code)}</code> ${esc(result.body?.error?.message || "")}</td></tr>`;
  }).join("");
  return `<table><thead><tr><th>Governed stage</th><th>State</th><th>Owner evidence / refusal</th></tr></thead><tbody>${rows}</tbody></table>
  <p class="sub">Each row is a live daemon read — a refusal renders verbatim and never implies progress. A step is approved on the challenge the daemon parks when it is submitted from the <a href="${BASE}/compose">composer</a> or the System's governed forms — the approval card, or the challenge's own page under <a href="/__ioi/authority/challenges">parked effects</a> — or with a wallet grant attached there; this preview cannot approve anything.</p>`;
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
  // A preview asks nothing of the operator: the daemon parks no challenge for it (R-240 journey WP-A).
  const previewDaemon = { url: daemonUrl.url, headers: { ...(daemonUrl.headers || {}), "x-ioi-governed-preview": "1" } };
  const result = await daemonJson(previewDaemon, "POST", GENESIS_API, declared);
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

// ---- the governed ladder's typed forms (R-240, journey WP-A #9) ---------------------------------
// Materialize, initialize and activate each bind the exact artifacts of the step before them. Their
// expected roots are not typed by a person: each field is prefilled from the daemon's own read of the
// step before (the detail page reads all four), hashed under the same domains the daemon re-derives
// and compares on submit — the daemon stays the validator, and a stale or foreign root is its refusal,
// shown verbatim. Approving happens on the challenge the daemon parks (the approval card), never by
// pasting a grant here. Initialize's pinned deployment profile revision has no source yet: no plane
// holds deployment profile revisions (genesis records only the ref), so it stays a pasted declaration
// and a named gap.
export const TYPED_LADDER_FIELDS = Object.freeze({
  "sequence-zero-materialization": ["expected_genesis_admission_record_root", "expected_genesis_admission_receipt_root"],
  initialize: ["expected_sequence_zero_materialization_root", "expected_sequence_zero_materialization_receipt_root"],
  activate: ["expected_initialize_proposal_root", "expected_initialize_decision_root", "expected_initialize_state_root", "expected_initialize_transition_root", "expected_initialize_receipt_root"],
});
// What still takes raw JSON: the continuity, protected-transition and amendment forms (their routes park
// no challenge yet, so they keep the pasted grant), and initialize's pinned deployment profile revision.
export const TYPED_LIFECYCLE_GAP = "typed lifecycle forms (continuity, transitions, amendments, the initialize deployment revision)";
function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
}
const rootOver = (material) => `sha256:${createHash("sha256").update(canonicalJson(material)).digest("hex")}`;
const isObject = (value) => value !== null && typeof value === "object" && !Array.isArray(value);

// The expected roots each step binds, from the daemon's reads of the steps before it (null where the
// step before has not been admitted: that field is empty, and the daemon's refusal says why).
export function ladderExpectations({ admission, sequenceZero, initialize }) {
  const record = admission?.status === 200 ? admission.body?.autonomous_system_genesis_admission : null;
  const receipt = admission?.status === 200 ? admission.body?.autonomous_system_genesis_receipt : null;
  const seq = sequenceZero?.status === 200 ? sequenceZero.body || {} : null;
  const init = initialize?.status === 200 ? initialize.body || {} : null;
  const state = isObject(init?.autonomous_system_activation_state) ? init.autonomous_system_activation_state : {};
  const facts = isObject(init?.lifecycle_receipt?.bound_facts) ? init.lifecycle_receipt.bound_facts : {};
  const str = (v) => (typeof v === "string" && v ? v : null);
  return {
    "sequence-zero-materialization": {
      expected_genesis_admission_record_root: isObject(record) ? rootOver({ domain: "ioi.autonomous-system-genesis-admission-record-jcs-sha256.v1", value: record }) : null,
      expected_genesis_admission_receipt_root: isObject(receipt) ? rootOver({ domain: "ioi.autonomous-system-genesis-admission-receipt-jcs-sha256.v1", value: receipt }) : null,
    },
    initialize: {
      expected_sequence_zero_materialization_root: isObject(seq?.autonomous_system_sequence_zero_materialization) ? rootOver({ domain: "ioi.autonomous-system-sequence-zero-materialization-artifact-jcs-sha256.v1", artifact: seq.autonomous_system_sequence_zero_materialization }) : null,
      expected_sequence_zero_materialization_receipt_root: isObject(seq?.autonomous_system_sequence_zero_materialization_receipt) ? rootOver({ domain: "ioi.autonomous-system-sequence-zero-materialization-receipt-artifact-jcs-sha256.v1", artifact: seq.autonomous_system_sequence_zero_materialization_receipt }) : null,
    },
    activate: {
      expected_initialize_proposal_root: str(facts.proposal_root),
      expected_initialize_decision_root: str(facts.decision_root),
      expected_initialize_state_root: str(state.activation_state_root),
      expected_initialize_transition_root: str(state.transition_root),
      expected_initialize_receipt_root: str(state.transition_receipt_root),
    },
  };
}

const LADDER_FIELD_LABELS = {
  expected_genesis_admission_record_root: "The genesis admission record it byte-verifies",
  expected_genesis_admission_receipt_root: "The genesis admission receipt",
  expected_sequence_zero_materialization_root: "The sequence-zero materialization it binds",
  expected_sequence_zero_materialization_receipt_root: "The sequence-zero materialization receipt",
  expected_initialize_proposal_root: "Initialize's proposal",
  expected_initialize_decision_root: "Initialize's decision",
  expected_initialize_state_root: "The state initialize admitted",
  expected_initialize_transition_root: "Initialize's transition",
  expected_initialize_receipt_root: "Initialize's transition receipt",
};

function typedLadderForm(action, subPath, label, note, expected, { admitted, next }) {
  const values = expected[subPath] || {};
  const known = TYPED_LADDER_FIELDS[subPath].every((name) => values[name]);
  const fields = TYPED_LADDER_FIELDS[subPath].map((name) => `<div class="field"><label>${esc(LADDER_FIELD_LABELS[name] || name)} <span class="sub" style="display:inline;margin:0;text-transform:none;letter-spacing:0">${values[name] ? "(from the daemon's read above)" : "(the step before is not admitted yet)"}</span></label><input name="${esc(name)}" value="${esc(values[name] || "")}" required spellcheck="false" autocomplete="off" data-ladder-root="${esc(name)}" data-ladder-root-source="${values[name] ? "daemon" : "absent"}" style="font-family:ui-monospace,monospace;font-size:12px"></div>`).join("");
  const revision = subPath === "initialize"
    ? `<div class="field"><label>Deployment profile revision (JSON — the pinned revision initialize binds; no plane holds deployment profile revisions yet, since the genesis records only the revision's ref, so it is pasted here)</label><textarea name="deployment_profile_revision" style="min-height:90px" placeholder='{"deployment_profile_ref": "deployment-profile://…/revision/sha256:…", "deployment_profile_root": "sha256:…", "profile": { … }}'></textarea></div>`
    : "";
  const status = admitted ? pill("admitted", "ok") : known ? pill(next ? "next step" : "ready", "warn") : pill("waiting on the step before", "muted");
  return `<details class="card" style="display:block" data-ladder-form="${esc(subPath)}"${next ? " open" : ""}><summary style="cursor:pointer"><b>${esc(label)}</b> ${status} <span class="sub" style="display:inline;margin:0;text-transform:none;letter-spacing:0">${esc(note || "")}</span></summary>
    <form method="post" action="${esc(action)}" style="margin-top:10px">
      <input type="hidden" name="request_form" value="typed">
      ${fields}${revision}
      <p class="sub">Submitting asks the daemon for this step: it re-derives every root above from its own records and refuses a stale or foreign one. Without an approval it parks this exact effect for the operator and the answer carries the approval card.</p>
      <button class="act" type="submit">Submit to daemon route</button>
    </form></details>`;
}

// The provisional detail's pieces — identity, lifecycle ladder, read projection, governed actions —
// built once and composed by two pages: the provisional detail below and the System workspace
// (/systems/<id>[/<mode>], ADR 0056 journey step 1). `viewHref(view)` is where the compact/advanced tabs
// point, so each page keeps a person on its own routes.
async function detailParts(daemonUrl, tail, view, viewHref) {
  const [admission, sequenceZero, initialize, activate] = await Promise.all([
    daemonJson(daemonUrl, "GET", `${GENESIS_API}/${tail}`),
    daemonJson(daemonUrl, "GET", `${GENESIS_API}/${tail}/sequence-zero-materialization`),
    daemonJson(daemonUrl, "GET", `${GENESIS_API}/${tail}/initialize`),
    daemonJson(daemonUrl, "GET", `${GENESIS_API}/${tail}/activate`),
  ]);
  const head = "";
  const shell = (_title, html) => ({ blocked: html });
  const title = "";
  if (admission.networkError) {
    return shell(title, head + stateBlock(
      "unavailable_or_degraded",
      "daemon_unreachable",
      `<div class="empty">Daemon unreachable (<code>${esc(admission.networkError)}</code>) — no admission, chain, or receipt facts can be shown, and none are substituted.</div>`,
    ));
  }
  if (admission.status !== 200) {
    const code = admission.status >= 400 ? refusalCodeOf(admission.body, admission.status) : "";
    return shell(title, head + stateBlock(
      stateForErrorCode(code),
      code,
      `<div class="empty">No verified admission renders at this key — <code>${esc(code || "untyped")}</code>: ${esc(refusalMessageOf(admission.body))}. Nothing substituted.</div>${jsonPre(admission.body || {})}`,
    ));
  }
  const record = admission.body.autonomous_system_genesis_admission || {};
  const receipt = admission.body.autonomous_system_genesis_receipt || {};
  const systemId = record.system_id || "";
  // Only the view this page renders is read: a projection read can take tens of seconds, and the
  // page used to fetch both views to draw one.
  const chosen = await fetchCensus(daemonUrl, view, systemId);

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
    const code = refusalCodeOf(result.body, result.status) || "untyped";
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
  const chosenCensus = censusState(chosen);
  const viewTabs = `<div class="tabs">
    <a class="tab${view === "advanced" ? "" : " active"}" href="${viewHref("compact")}">Compact preview</a>
    <a class="tab${view === "advanced" ? " active" : ""}" href="${viewHref("advanced")}">Advanced projection</a>
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

  const expected = ladderExpectations({ admission, sequenceZero, initialize });
  const continuityOptions = CONTINUITY_OPS.map((op) => `<option value="${op}">${op}</option>`).join("");
  const actions = `<h2>Governed lifecycle actions</h2>
  <p class="sub">Each form proxies ONE declaration verbatim to its owning daemon route. Without a grant the daemon answers its authority challenge (rendered as a preview); with a grant it commits or refuses — always shown verbatim. The serve layer never mutates state itself.</p>
  ${typedLadderForm(`${BASE}/${encodeURIComponent(tail)}/sequence-zero-materialization`, "sequence-zero-materialization", "Materialize sequence zero (M1.4)", "byte-verifies the admission you inspected above", expected, { admitted: sequenceZero.status === 200, next: sequenceZero.status !== 200 })}
  ${typedLadderForm(`${BASE}/${encodeURIComponent(tail)}/initialize`, "initialize", "Initialize (sequence 1)", "binds the exact M1.4 artifact + pinned deployment revision", expected, { admitted: initialize.status === 200, next: sequenceZero.status === 200 && initialize.status !== 200 })}
  ${typedLadderForm(`${BASE}/${encodeURIComponent(tail)}/activate`, "activate", "Activate (sequence 2)", "refused by the daemon unless initialize is admitted", expected, { admitted: activate.status === 200, next: initialize.status === 200 && activate.status !== 200 })}
  ${namedGap(TYPED_LIFECYCLE_GAP, "Typed forms for the continuity, protected-transition and amendment steps below (they take a raw JSON declaration, and their routes park no challenge yet, so a grant is pasted), and a source for initialize's pinned deployment profile revision")}
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

  return { identity, ladder, projection, actions, systemId, record };
}

async function renderDetailPage(daemonUrl, shell, tail, view) {
  const title = `System ${tail.slice(0, 16)}…`;
  const head = `${CROSSLINKS}<h1>Provisional System detail</h1>
  ${NONCLAIMS_BANNER}
  <p class="sub" data-provisional-detail="1">A provisional, launch-addressed readout of ONE System (<code>${esc(tail)}</code>) — deliberately not a permanent Systems navigation destination (M1.7). Compact and advanced views are the daemon's own read projections.</p>`;
  const parts = await detailParts(daemonUrl, tail, view, (v) => `${BASE}/${encodeURIComponent(tail)}?view=${v}`);
  if (parts.blocked) return shell(title, head + parts.blocked);
  return shell(title, head + parts.identity + parts.ladder + `<h2>Read projection (M1.7)</h2>` + parts.projection + parts.actions);
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
  const typed = form.get("request_form") === "typed" && TYPED_LADDER_FIELDS[subPath];
  try {
    if (typed) {
      // A typed ladder form: each expected root is its own field (prefilled from the daemon's reads);
      // initialize's deployment profile revision is still a pasted declaration (a named gap).
      request = Object.fromEntries(TYPED_LADDER_FIELDS[subPath].map((name) => [name, String(form.get(name) || "").trim()]));
      if (subPath === "initialize") request.deployment_profile_revision = JSON.parse(form.get("deployment_profile_revision") || "");
    } else {
      request = JSON.parse(form.get("request") || "{}");
    }
  } catch (error) {
    return shell("System action — input refused", `${CROSSLINKS}<h1>Provisional System detail</h1>${renderInputRefusal(typed ? "The deployment profile revision" : "The request declaration", error.message, backHref)}`);
  }
  if (request && typeof request === "object" && !Array.isArray(request)) delete request.op;
  const resubmit = {
    action: `${BASE}/${encodeURIComponent(tail)}/${subPath}`,
    declaration: JSON.stringify(request),
    declarationField: "request",
    extraHidden: subPath === "continuity" ? `<input type="hidden" name="op" value="${esc((form.get("op") || "").trim())}">` : (subPath === "transitions" ? `<input type="hidden" name="op" value="${esc((form.get("op") || "").trim())}">` : ""),
  };
  if (form.has("approval_challenge_id")) {
    const decided = await relayGovernedApproval(daemonUrl, form, { resubmit, backHref, actionLabel: label });
    return shell(`System action — ${label}`, `${CROSSLINKS}<h1>Provisional System detail — the operator's approval</h1>${decided}`);
  }
  const authority = carriedAuthority(form, backHref);
  if (authority.refusal) return shell("System action — input refused", `${CROSSLINKS}<h1>Provisional System detail</h1>${authority.refusal}`);
  const requestBody = authority.grant ? { ...request, wallet_approval_grant: authority.grant } : request;
  const result = await daemonJson(daemonUrl, "POST", daemonPath, requestBody);
  const outcome = renderOutcome(result, { actionLabel: label, backHref, resubmit });
  return shell(
    `System action — ${label}`,
    `${CROSSLINKS}<h1>Provisional System detail — governed action</h1><p class="sub">Route: <code>POST ${esc(daemonPath)}</code> — outcome verbatim.</p>${outcome}`,
  );
}

// ---- dispatch ------------------------------------------------------------------------------
// Returns true when the request was handled. `shell` is the estate page shell
// (automationsShell) and `daemonUrl` the serve's single daemon origin.
export async function handleSystemGenesisSurfaces(req, res, pathname, body, { daemonUrl: baseDaemonUrl, shell }) {
  if (pathname !== BASE && !pathname.startsWith(`${BASE}/`)) return false;
  // Every daemon call below carries the caller's identity (see daemonJson).
  const daemonUrl = { url: baseDaemonUrl, headers: callerIdentityHeaders(req) };
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
  if (pathname === `${BASE}/attach-data` && req.method === "POST") {
    await handleAttachData(daemonUrl, res, form());
    return true;
  }
  if (pathname === CHANGE_SET_ACTIONS.propose && req.method === "POST") {
    await handleProposeChangeSet(daemonUrl, res, form());
    return true;
  }
  if (pathname === CHANGE_SET_ACTIONS.merge && req.method === "POST") {
    await handleMergeChangeSet(daemonUrl, res, form());
    return true;
  }
  if (pathname === CHANGE_SET_ACTIONS.abandon && req.method === "POST") {
    await handleAbandonChangeSet(daemonUrl, res, form());
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

// ================================================================================================
// THE SYSTEM WORKSPACE — /systems/<id>[/<mode>] (ADR 0056 journey step 1, R-240).
//
// The daemon publishes seven mode routes per System — `/systems/<tail>`, `/design`, `/operate`,
// `/govern`, `/evidence`, `/improve`, `/interfaces` (system_projection_routes.rs) — and until now the
// serve answered every one with the generic "a detail view is not available yet" page, so nothing in
// the product could hand work to a System. The route shell now rewrites `/systems/<subpath>` to this
// lane. It ADOPTS the provisional detail's own pieces (`detailParts`) rather than re-authoring them,
// and it adds no verb: its forms are the provisional detail's, posting to the same owning lanes.
//
// POLICY FIRST. The per-System daemon reads by storage key check no identity today (a daemon gap,
// named separately), so the workspace must never read one for a System the caller cannot see. Every
// page is GATED on the filtered projection (`projection?view=compact&system_id=`), which filters by the
// caller before it builds a row: `honest_empty` means not in this caller's inventory — a typed absence
// and no per-key read; `system_lifecycle_not_found` means visible but not yet live — the ladder is safe
// to read; `ready` carries the row. Any other answer is rendered as the refusal it is.
//
// A System id spans path segments (`system://acme/one` → `/systems/acme/one`); the LAST segment is a
// mode only when it is one of the six mode words. Lifecycle forms live under GOVERN, as canon places
// them (Governance authorizes protected change; Operations performs member, placement and failover).
export const SYSTEM_WORKSPACE_LANE = "/__ioi/system-workspace";
const WORKSPACE_MODES = [
  ["", "Overview"], ["design", "Design"], ["operate", "Operate"], ["govern", "Govern"],
  ["evidence", "Evidence"], ["improve", "Improve"], ["interfaces", "Interfaces"],
];
const MODE_WORDS = new Set(WORKSPACE_MODES.map(([m]) => m).filter(Boolean));

// The daemon's own storage identity for a System (system_genesis_routes.rs `record_tail`): the sha256
// of the compact JSON {domain, system_id}. Used only AFTER the projection gate has shown the System is
// the caller's.
export function systemRecordTail(systemId) {
  return `asg_${createHash("sha256").update(JSON.stringify({ domain: "hypervisor.autonomous-system-genesis.identity.v1", system_id: systemId })).digest("hex")}`;
}

export function parseSystemWorkspacePath(rest) {
  let segments;
  try { segments = String(rest || "").split("/").filter(Boolean).map((s) => decodeURIComponent(s)); } catch { return null; }
  if (!segments.length || segments.some((s) => s === "." || s === ".." || /[\s]/u.test(s))) return null;
  let mode = "";
  if (segments.length > 1 && MODE_WORDS.has(segments[segments.length - 1])) mode = segments.pop();
  const tailPath = segments.join("/");
  return { systemId: `system://${tailPath}`, tailPath, mode };
}

const modeHref = (tailPath, mode) => `/systems/${tailPath.split("/").map(encodeURIComponent).join("/")}${mode ? `/${mode}` : ""}`;

function handOffs(links) {
  return `<p class="sub" data-system-handoffs="1">Where this mode's work happens today: ${links.map(([href, label]) => `<a href="${esc(href)}">${esc(label)} →</a>`).join(" · ")}</p>`;
}
function namedGap(plane, what) {
  return stateBlock("honest_empty", "named_gap", `<div class="empty" data-system-named-gap="${esc(plane)}">${esc(what)} — a named gap: <b>${esc(plane)}</b> is not built, so nothing here stands in for it.</div>`);
}

// ADR 0056 P2: the checks that observe this System and their admitted results, read from the
// health-check plane as the caller — the plane filters by tenant before this page sees a record.
async function systemHealth(daemonUrl, systemId) {
  const [checks, results] = await Promise.all([
    daemonJson(daemonUrl, "GET", "/v1/hypervisor/health-checks"),
    daemonJson(daemonUrl, "GET", `/v1/hypervisor/health-check-results?target_ref=${encodeURIComponent(systemId)}`),
  ]);
  const failed = [checks, results].find((r) => r.networkError || r.status !== 200 || r.body?.ok === false);
  if (failed) {
    const code = failed.networkError ? "daemon_unreachable" : refusalCodeOf(failed.body || {}, failed.status);
    return stateBlock(stateForErrorCode(code), code, `<div class="empty" data-system-health-unavailable="1">Health could not be read — <code>${esc(code)}</code>. Nothing is shown in its place.</div>`);
  }
  const all = checks.body.health_checks || [];
  const observed = all.some((c) => c.target_ref === systemId && c.enablement !== "archived") || (results.body.health_check_results || []).length > 0;
  return stateBlock(observed ? "ready_or_proposed" : "honest_empty", observed ? null : "no_health_check_observes_system", renderTargetHealth(systemId, all, results.body.health_check_results || []));
}

// ADR 0056 P6: the telemetry series about this System — its own, and those of what serves it (the
// checks that observe it, its runs) — each over the plane's bounded range read for the last 7 days, read
// as the caller; the plane filters by tenant before this page sees a series. At most six are drawn here;
// the lane lists them all.
const SYSTEM_TELEMETRY_SERIES = 6;
const SYSTEM_TELEMETRY_SPAN_MS = 7 * 86_400_000;
async function systemTelemetry(daemonUrl, systemId) {
  const listed = await daemonJson(daemonUrl, "GET", `/v1/hypervisor/telemetry/series?about_ref=${encodeURIComponent(systemId)}`);
  if (listed.networkError || listed.status !== 200 || listed.body?.ok !== true) {
    const code = listed.networkError ? "daemon_unreachable" : (listed.body?.error?.code || refusalCodeOf(listed.body || {}, listed.status));
    return stateBlock(stateForErrorCode(code), code, `<div class="empty" data-system-telemetry-unavailable="1">Telemetry could not be read — <code>${esc(code)}</code>. Nothing is shown in its place.</div>`);
  }
  const series = (Array.isArray(listed.body.series) ? listed.body.series : [])
    .filter((s) => s.subject_ref === systemId || s.scope_ref === systemId)
    .slice(0, SYSTEM_TELEMETRY_SERIES);
  const now = Date.now();
  const window = `from=${now - SYSTEM_TELEMETRY_SPAN_MS}&to=${now + 1}&step=3600`;
  const entries = await Promise.all(series.map(async (one) => {
    const tail = String(one.series_id || "").replace(/^telemetry-series:\/\//u, "");
    const read = await daemonJson(daemonUrl, "GET", `/v1/hypervisor/telemetry/series/${encodeURIComponent(tail)}/range?${window}`);
    if (read.networkError || read.status !== 200 || read.body?.ok !== true) {
      return { series: one, error: read.networkError ? "daemon_unreachable" : (read.body?.error?.code || refusalCodeOf(read.body || {}, read.status)) };
    }
    return { series: one, range: read.body.range };
  }));
  return stateBlock(entries.length ? "ready_or_proposed" : "honest_empty", entries.length ? null : "no_telemetry_series_about_system", renderTargetTelemetry(systemId, entries));
}

// R-240 journey WP-B: the System's own work — the Work projection narrowed by system_ref, read as the
// caller (every family is policy-filtered by its owner before the projection sees it). A run serves the
// System its automation's installation is scoped to; each row links its run, whose link lands on the
// run's timeline and receipts. Active and finished work are both listed; nothing is cached.
async function systemWork(daemonUrl, systemId) {
  const answers = await Promise.all(["active", "history"].map((view) =>
    daemonJson(daemonUrl, "GET", `/v1/hypervisor/work-projection?view=${view}&system_ref=${encodeURIComponent(systemId)}`)));
  const failed = answers.find((r) => r.networkError || r.status !== 200 || r.body?.ok !== true);
  if (failed) {
    const code = failed.networkError ? "daemon_unreachable" : refusalCodeOf(failed.body || {}, failed.status);
    return stateBlock(stateForErrorCode(code), code, `<div class="empty" data-system-work-unavailable="1">This System's work could not be read — <code>${esc(code)}</code>. Nothing is shown in its place.</div>`);
  }
  const rows = answers.flatMap((a) => (Array.isArray(a.body.rows) ? a.body.rows : []).filter((r) => r.system_ref === systemId));
  if (!rows.length) {
    return stateBlock("honest_empty", "no_work_names_system", `<div class="empty" data-system-work-empty="1">No run names this System yet. An automation created for it (New automation → System) installs onto it, and each of its runs is listed here.</div>`);
  }
  const body = rows.map((r) => `<tr data-system-work-row="${esc(r.subject_ref)}"><td><code>${esc(r.subject_ref)}</code></td><td>${esc(r.subject_kind)}</td><td>${esc(r.display_facets?.activity || "—")}</td><td><a href="${esc(r.canonical_detail_route)}">Run timeline and receipts →</a></td></tr>`).join("");
  return stateBlock("ready_or_proposed", null, `<table data-system-work="${esc(systemId)}"><thead><tr><th>Run</th><th>Kind</th><th>Activity</th><th>Proof</th></tr></thead><tbody>${body}</tbody></table>`);
}

async function renderSystemWorkspace(daemonUrl, shell, parsed) {
  const { systemId, tailPath, mode } = parsed;
  const modeLabel = (WORKSPACE_MODES.find(([m]) => m === mode) || ["", "Overview"])[1];
  const tabs = `<nav class="tabs" aria-label="System modes">${WORKSPACE_MODES.map(([m, label]) =>
    `<a class="tab${m === mode ? " active" : ""}" href="${esc(modeHref(tailPath, m))}">${esc(label)}</a>`).join("")}</nav>`;
  // The workspace marks a page as THIS System's only once the gate below has admitted the System to
  // the caller's inventory; before that, the address the caller asked for is shown as just that.
  const headFor = (admitted) => `<p class="sub" style="margin:0 0 4px"><a href="/systems">← All Systems</a></p>
  <h1 data-system-workspace-mode="${esc(mode || "overview")}">System · ${esc(modeLabel)}</h1>
  <p class="sub">${admitted ? `<code data-system-workspace-id="${esc(systemId)}">${esc(systemId)}</code>` : `requested <code data-system-requested="1">${esc(systemId)}</code>`}</p>${tabs}${NONCLAIMS_BANNER}`;
  const refusedHead = headFor(false);
  const title = `${modeLabel} · ${systemId}`;
  // THE GATE — the filtered projection, as the caller.
  const gate = await fetchCensus(daemonUrl, "compact", systemId);
  if (gate.networkError) {
    return shell(title, refusedHead + stateBlock("unavailable_or_degraded", "daemon_unreachable", `<div class="empty">The daemon did not answer (<code>${esc(gate.networkError)}</code>) — no System facts are shown, and none are substituted.</div>`));
  }
  const body = gate.body || {};
  let row = null;
  if (gate.status === 200 && body.state === "ready") row = (body.systems || []).find((s) => s.system_id === systemId) || null;
  const code = gate.status >= 400 ? refusalCodeOf(body, gate.status) : "";
  const visibleNotLive = code === "system_lifecycle_not_found";
  if (!row && !visibleNotLive) {
    if (gate.status === 200) {
      return shell(title, refusedHead + stateBlock("honest_empty", "system_not_in_inventory", `<div class="empty" data-system-not-in-inventory="1">No System <code>${esc(systemId)}</code> is in your inventory. Either it does not exist or it is not yours to see; the projection filters by who you are before it builds a row, so this page reads nothing more.</div>`));
    }
    const signIn = code === "request_principal_required" ? ` <a href="/__ioi/login?next=${esc(encodeURIComponent(modeHref(tailPath, mode)))}" target="_top">Sign in</a> to see your Systems.` : "";
    return shell(title, refusedHead + stateBlock(stateForErrorCode(code), code, `<div class="empty">The Systems projection refused this read — <code>${esc(code)}</code>: ${esc(refusalMessageOf(body))}.${signIn}</div>`));
  }
  const head = headFor(true);
  const tail = row?.source_record_tail || systemRecordTail(systemId);
  const pending = visibleNotLive
    ? stateBlock("loading_or_pending", code, `<div class="empty">This System is visible to you but has no live chain yet (<code>${esc(code)}</code>) — the lifecycle ladder below shows how far genesis has come.</div>`)
    : "";
  if (mode === "" || mode === "govern" || mode === "evidence") {
    const view = mode === "evidence" ? "advanced" : "compact";
    const parts = await detailParts(daemonUrl, tail, view, (v) => modeHref(tailPath, v === "advanced" ? "evidence" : ""));
    if (parts.blocked) return shell(title, head + pending + parts.blocked);
    if (mode === "") {
      return shell(title, head + pending + parts.identity + `<h2>Read projection</h2>` + parts.projection
        + `<h2>Health</h2>` + await systemHealth(daemonUrl, systemId)
        + `<h2>Telemetry</h2>` + await systemTelemetry(daemonUrl, systemId)
        + `<p class="sub">Attention: owner events for your work arrive in the notification inbox (<code>/v1/hypervisor/notifications</code>); the inbox is not narrowed to one System yet — this System's runs are listed on its <a href="${esc(modeHref(tailPath, "operate"))}">Operate</a> mode.</p>`);
    }
    if (mode === "govern") {
      return shell(title, head + pending + parts.ladder + parts.actions
        + `<h2>Limits — the standing limits of the connections this System uses</h2>` + await systemLimits(daemonUrl, systemId, tailPath)
        + handOffs([["/governance/limits?tab=limits", "Limits in Leases & Limits"], ["/governance/limits?tab=checkpoints", "Checkpoints"], ["/governance/approvals", "Approvals"]]));
    }
    return shell(title, head + pending + `<h2>Evidence — genesis and lifecycle receipts, operation log</h2>` + parts.projection
      + `<h2>Run receipts — this System's runs</h2>` + await systemWork(daemonUrl, systemId)
      + handOffs([["/provenance", "Provenance"], ["/evaluations", "Evaluations"]]));
  }
  if (mode === "operate") {
    const topo = row?.topology || {};
    const cell = (side) => `<td><code>${esc(topo?.[side]?.state || "—")}</code></td><td>${esc(topo?.[side]?.reason || "")}</td>`;
    const table = row
      ? `<h2>Desired versus observed</h2><table data-system-topology="1"><thead><tr><th></th><th>State</th><th>Reason</th></tr></thead><tbody><tr><th>Desired</th>${cell("desired")}</tr><tr><th>Observed</th>${cell("observed")}</tr></tbody></table>`
      : "";
    return shell(title, head + pending + table
      + `<h2>Runs attached to this System</h2>` + await systemWork(daemonUrl, systemId)
      + namedGap("System subject on session create (W3 C-1)", "Sessions attached to this System — a session names no System yet (session create takes no System subject); an automation's runs do")
      + handOffs([["/operations", "Operations"], ["/environments", "Environments"], ["/work", "Work"], ["/__ioi/automations/new", "New automation"]]));
  }
  if (mode === "design") {
    return shell(title, head + pending + await systemDesign(daemonUrl, systemId, tailPath, parsed.query)
      + handOffs([["/studio", "Studio"], ["/ontology", "Ontology"], ["/data", "Data"], ["/automations", "Automations"]]));
  }
  if (mode === "improve") {
    return shell(title, head + pending + await systemImprove(daemonUrl, systemId, parsed.query)
      + `<h2>Improvement campaigns</h2>` + namedGap(IMPROVEMENT_CAMPAIGN_GAP, "An improvement campaign scoped to this System — the campaign plane refuses a System scope by name (improvement_campaign_system_scope_not_admitted) until the constitution's protected profile binding exists; campaigns stay owner-scoped")
      + handOffs([["/improvement", "Improvement"], ["/foundry", "Foundry"], ["/studio", "Studio"]]));
  }
  return shell(title, head + pending + namedGap("interface-binding plane (W3)", "Generated and bound interfaces for this System")
    + handOffs([["/packages", "Packages"], ["/__ioi/developer-console", "Developer Console"]]));
}

export async function handleSystemWorkspace(req, res, pathname, { daemonUrl: baseDaemonUrl, shell }) {
  if (!pathname.startsWith(`${SYSTEM_WORKSPACE_LANE}/`) || req.method !== "GET") return false;
  const parsed = parseSystemWorkspacePath(pathname.slice(SYSTEM_WORKSPACE_LANE.length + 1));
  if (!parsed) {
    res.writeHead(404, HTMLH);
    res.end(shell("Not found", `<h1>System</h1>${stateBlock("honest_empty", "system_workspace_path_invalid", `<div class="empty">That is not a System address.</div>`)}`));
    return true;
  }
  const daemonUrl = { url: baseDaemonUrl, headers: callerIdentityHeaders(req) };
  res.writeHead(200, HTMLH);
  res.end(await renderSystemWorkspace(daemonUrl, shell, { ...parsed, query: new URL(req.url || "", "http://x").searchParams }));
  return true;
}

// ---- Govern mode: the System's limits (R-240, journey WP-A) --------------------------------------
// A standing limit is a STANDING ENVELOPE on one of Connections' connectors: its bounds (uses,
// budget, operations, expiry) are recorded as a standing grant on the deployment's authority node,
// and a session may name the connection only while it is active. A System's limits are the envelopes
// of the connectors behind the connections attached to it (SystemDataAttachment, subject kind
// `connection`: a provider connection, connection://provider/<connector>/<principal>), read as the
// caller from the connectors plane and the System-record seam. A connector with no provider
// connection (an API key, an MCP server) cannot be attached: v1's connection kind names provider
// connections and its wire is frozen, so that is named here as its own gap. Setting and removing a limit happens
// on Connections, with the operator passphrase. Whether this deployment can record limits at all is
// the daemon's own answer (`decidable` on its standing-envelope list: a deployment authority to
// record one with); both postures are said as they are. The limits do not yet bound the runs a System starts —
// no System session draws on one (the session-subject gap) — and the page says so.
export const SYSTEM_CONNECTOR_GAP = "connectors attached to a System (SystemDataAttachment v2)";
export async function systemLimits(daemonUrl, systemId, tailPath) {
  const [attachments, connectors, authority] = await Promise.all([
    daemonJson(daemonUrl, "GET", `${GENESIS_API}/${encodeURIComponent(systemId)}/records?contract_id=${encodeURIComponent(SYSTEM_DATA_ATTACHMENT_CONTRACT)}`),
    daemonJson(daemonUrl, "GET", "/v1/hypervisor/connectors"),
    daemonJson(daemonUrl, "GET", "/v1/hypervisor/authority/standing-envelopes"),
  ]);
  const failed = unreadCode(attachments) || unreadCode(connectors);
  if (failed) return stateBlock(stateForErrorCode(failed), failed, `<div class="empty" data-system-limits-unavailable="1">This System's limits could not be read — <code>${esc(failed)}</code>. Nothing is shown in their place.</div>`);
  const decidable = !authority.networkError && authority.status === 200 && authority.body?.decidable === true;
  const posture = decidable
    ? `<p class="sub" data-system-limits-authority="deployment">This deployment's daemon records limits on its deployment authority node: a connection's limits are set and removed on <a href="/__ioi/connections">Connections</a> with the operator passphrase, and a session may name a connection only while its limits are active.</p>`
    : `<p class="sub" data-system-limits-authority="none">This deployment's daemon has no deployment authority node to record limits on (IOI_WALLET_AUTHORITY_BINARY and IOI_HYPERVISOR_LOCAL_AUTHORITY_STATE_DIR on the daemon), so no connection here can carry limits, and a session can name none of them.</p>`;
  const byId = new Map((Array.isArray(connectors.body?.connectors) ? connectors.body.connectors : []).map((c) => [c.connector_id, c]));
  const connectorOf = (ref) => byId.get((/^connection:\/\/provider\/([^/]+)\//u.exec(String(ref || "")) || [])[1] || "") || null;
  const connectorGap = namedGap(SYSTEM_CONNECTOR_GAP, "Attaching a connector that has no provider connection — an API key, an MCP server — so its limits are this System's: the attachment names provider connections only");
  const attached = (Array.isArray(attachments.body?.records) ? attachments.body.records : [])
    .map((r) => r.current || {})
    .filter((r) => r.status === "attached" && r.subject_kind === "connection" && r.system_binding?.system_id === systemId);
  const unbound = `<p class="sub" data-system-limits-bound-runs="absent">These limits do not bound the runs this System starts yet: a session names no System (the session-subject gap on Operate), so no run of this System draws on them.</p>`;
  if (!attached.length) {
    return stateBlock("honest_empty", "no_connection_attached_to_system", `<div class="empty" data-system-limits="${esc(systemId)}">No connection is attached to this System, so it has no limits. Attach one on its <a href="${esc(modeHref(tailPath, "design"))}">Design</a> mode.</div>${posture}`) + connectorGap;
  }
  const money = (micro) => `$${(Number(micro || 0) / 1_000_000).toFixed(4)}`;
  const rows = attached.map((r) => {
    const c = connectorOf(r.subject_ref);
    const lease = c?.standing_lease && typeof c.standing_lease === "object" ? c.standing_lease : null;
    const b = lease?.bounds || {};
    const status = lease?.status || "none";
    const limits = lease
      ? `${esc(String(b.max_usages ?? "?"))} uses · budget ${esc(money(b.max_cumulative_spend_microusd))} · ${esc((b.operations || []).join("+") || "—")} · expires ${esc(b.expires_at_ms ? new Date(Number(b.expires_at_ms)).toISOString() : "—")}`
      : "no limits set — a session cannot name this connection";
    return `<tr data-system-limit-connection="${esc(r.subject_ref)}" data-standing-lease-status="${esc(status)}"><td>${c ? `<b>${esc(c.name || c.connector_id)}</b>` : `<span class="sub" style="margin:0">its connector is not registered</span>`}<br><code>${esc(r.subject_ref)}</code></td><td>${pill(lease ? status : "unbounded", status === "active" ? "ok" : "warn")}</td><td>${limits}</td></tr>`;
  }).join("");
  return stateBlock("ready_or_proposed", null, `<table data-system-limits="${esc(systemId)}"><thead><tr><th>Connection</th><th>Limits</th><th>Bounds</th></tr></thead><tbody>${rows}</tbody></table>${posture}${unbound}`) + connectorGap;
}

// ---- Design mode: what the System is made of (R-240 journey WP-C1) ------------------------------
// The blueprints bound to the System (Studio's own plane, narrowed by system_ref) and the data
// attached to it (SystemDataAttachment records in the System-record seam), each read as the caller
// from the plane that owns it. Attaching is one write through the seam; the subject stays its own
// plane's. Every read degrades on its own and names its refusal code; nothing is cached.
export const SYSTEM_DATA_ATTACHMENT_CONTRACT = "schema://ioi/components/hypervisor/system-data-attachment/v1";
const ATTACH_KINDS = { ontology: "Ontology", data_source: "Data source", connection: "Connection" };
const STUDIO_BLUEPRINTS = "/__ioi/studio/workbench?view=blueprints";
const sha256Hex = (text) => createHash("sha256").update(text).digest("hex");
// One attachment per System and subject: its identity is derived from both, so attaching the same
// subject again is the same record, and the seam replays or refuses it by name.
export function systemDataAttachmentId(systemId, subjectRef) {
  return `system-data-attachment://sda_${sha256Hex(`${systemId}\u0000${subjectRef}`).slice(0, 16)}`;
}
const unreadCode = (result) => (result.networkError
  ? "daemon_unreachable"
  : (result.status !== 200 || result.body?.ok === false) ? refusalCodeOf(result.body || {}, result.status) : null);

async function systemDesign(daemonUrl, systemId, tailPath, query) {
  const [blueprints, attachments, ontologies, sources, connections] = await Promise.all([
    daemonJson(daemonUrl, "GET", `/v1/hypervisor/studio/blueprints?system_ref=${encodeURIComponent(systemId)}`),
    daemonJson(daemonUrl, "GET", `${GENESIS_API}/${encodeURIComponent(systemId)}/records?contract_id=${encodeURIComponent(SYSTEM_DATA_ATTACHMENT_CONTRACT)}`),
    daemonJson(daemonUrl, "GET", "/v1/hypervisor/odk/domain-ontologies"),
    daemonJson(daemonUrl, "GET", "/v1/hypervisor/data-sources"),
    daemonJson(daemonUrl, "GET", "/v1/hypervisor/auth/connections"),
  ]);
  const acted = query?.get("acted") === "attach-data"
    ? stateBlock("completed", null, `<div class="empty" data-system-attach-result="attached">Attached <code>${esc(query.get("record") || "")}</code> to this System · receipt <code>${esc(query.get("receipt") || "")}</code></div>`)
    : query?.get("refused")
      ? stateBlock("denied_or_revoked", query.get("refused"), `<div class="empty" data-system-attach-result="refused">Not attached — <code>${esc(query.get("refused"))}</code>: ${esc(query.get("reason") || "")}. Nothing changed.</div>`)
      : "";

  // Designs bound to this System.
  const draftHref = `${STUDIO_BLUEPRINTS}&system_ref=${encodeURIComponent(systemId)}`;
  const draftLink = `<p class="sub"><a class="act" data-system-draft-blueprint="1" href="${esc(draftHref)}">Draft a blueprint for this System in Studio →</a></p>`;
  const bpCode = unreadCode(blueprints);
  const bpRows = bpCode ? [] : (Array.isArray(blueprints.body?.blueprints) ? blueprints.body.blueprints : []).filter((b) => b.system_ref === systemId);
  const designs = bpCode
    ? stateBlock(stateForErrorCode(bpCode), bpCode, `<div class="empty" data-system-designs-unavailable="1">The blueprints bound to this System could not be read — <code>${esc(bpCode)}</code>. Nothing is shown in their place.</div>`)
    : bpRows.length
      ? stateBlock("ready_or_proposed", null, `<table data-system-designs="${esc(systemId)}"><thead><tr><th>Blueprint</th><th>Status</th><th>Content hash</th><th>Updated</th></tr></thead><tbody>${bpRows.map((b) => `<tr data-system-blueprint="${esc(b.ref || "")}"><td><a href="${esc(`${STUDIO_BLUEPRINTS}&bp=${encodeURIComponent(b.id || "")}`)}"><b>${esc(b.name || b.id || "")}</b></a><br><code>${esc(b.ref || "")}</code></td><td>${pill(b.promote_state || b.status || "draft", b.promote_state ? "warn" : "muted")}</td><td><code>${esc(b.content_hash || "")}</code></td><td>${esc(b.updated_at || "")}</td></tr>`).join("")}</tbody></table>`)
      : stateBlock("honest_empty", "no_blueprint_bound_to_system", `<div class="empty" data-system-designs="${esc(systemId)}">No blueprint is bound to this System yet. A blueprint drafted in Studio for this System is bound to it when it is created, and is listed here.</div>`);

  // Data attached to this System, named by the subject planes' own reads (the caller's own).
  const ontCode = unreadCode(ontologies);
  const srcCode = unreadCode(sources);
  const ontList = ontCode ? [] : (Array.isArray(ontologies.body?.ontologies) ? ontologies.body.ontologies : []).filter((o) => String(o.ref || "").startsWith("ontology://"));
  const srcList = srcCode ? [] : (Array.isArray(sources.body?.data_sources) ? sources.body.data_sources : []).filter((s) => String(s.source_ref || "").startsWith("data-source:"));
  // Provider connections the caller may read (R-240 journey WP-A): a System's connections, whose
  // connectors carry its standing limits (listed on Govern mode). The attachment's connection kind names
  // a provider connection (connection://provider/<connector>/<principal>); a connector with none — an API
  // key or an MCP server — cannot be attached until a SystemDataAttachment successor names connectors.
  const cxCode = unreadCode(connections);
  const cxList = cxCode ? [] : (Array.isArray(connections.body?.connections) ? connections.body.connections : []).filter((c) => String(c.connection_ref || "").startsWith("connection://"));
  const cxRef = (c) => c.connection_ref;
  const cxLabel = (c) => `${String(c.connector_ref || "").replace(/^connector:\/\//u, "") || c.connection_ref} (${c.status || "unknown"})`;
  const names = new Map([...ontList.map((o) => [o.ref, o.domain || o.id || o.ref]), ...srcList.map((s) => [s.source_ref, s.name || s.source_id || s.source_ref]), ...cxList.map((c) => [cxRef(c), cxLabel(c)])]);
  const attCode = unreadCode(attachments);
  const attached = attCode ? [] : (Array.isArray(attachments.body?.records) ? attachments.body.records : [])
    .map((r) => ({ record: r.current || {}, head: r.head || "" }))
    .filter(({ record }) => record.status === "attached" && record.system_binding?.system_id === systemId);
  const attachedRefs = new Set(attached.map(({ record }) => record.subject_ref));
  const dataTable = attCode
    ? stateBlock(stateForErrorCode(attCode), attCode, `<div class="empty" data-system-data-unavailable="1">The data attached to this System could not be read — <code>${esc(attCode)}</code>. Nothing is shown in its place.</div>`)
    : attached.length
      ? stateBlock("ready_or_proposed", null, `<table data-system-data="${esc(systemId)}"><thead><tr><th>Kind</th><th>Name</th><th>Ref</th><th>Admitted head</th></tr></thead><tbody>${attached.map(({ record, head }) => `<tr data-system-attachment="${esc(record.attachment_id || "")}" data-subject-ref="${esc(record.subject_ref || "")}"><td>${esc(ATTACH_KINDS[record.subject_kind] || record.subject_kind || "")}</td><td>${names.has(record.subject_ref) ? `<b>${esc(names.get(record.subject_ref))}</b>` : `<span class="sub" style="margin:0">not in your own reads</span>`}</td><td><code>${esc(record.subject_ref || "")}</code></td><td><code>${esc(head)}</code></td></tr>`).join("")}</tbody></table>`)
      : stateBlock("honest_empty", "no_data_attached_to_system", `<div class="empty" data-system-data="${esc(systemId)}">No ontology, data source or connection is attached to this System yet.</div>`);
  const offer = (list, kind, refOf, labelOf) => list.filter((x) => !attachedRefs.has(refOf(x)))
    .map((x) => `<option value="${esc(`${kind}|${refOf(x)}`)}">${esc(labelOf(x))} — ${esc(refOf(x))}</option>`).join("");
  const ontOptions = offer(ontList, "ontology", (o) => o.ref, (o) => o.domain || o.id || o.ref);
  const srcOptions = offer(srcList, "data_source", (s) => s.source_ref, (s) => s.name || s.source_id || s.source_ref);
  const cxOptions = offer(cxList, "connection", cxRef, cxLabel);
  const unreadNote = [ontCode && `ontologies unavailable (<code>${esc(ontCode)}</code>)`, srcCode && `data sources unavailable (<code>${esc(srcCode)}</code>)`, cxCode && `connections unavailable (<code>${esc(cxCode)}</code>)`].filter(Boolean).join(" · ");
  const attachForm = ontOptions || srcOptions || cxOptions
    ? `<form method="post" action="${BASE}/attach-data" data-system-attach-form="1">
        <input type="hidden" name="system_id" value="${esc(systemId)}">
        <div class="field"><label>Attach an ontology, a data source or a connection you can see</label><select name="subject">${ontOptions ? `<optgroup label="Ontologies">${ontOptions}</optgroup>` : ""}${srcOptions ? `<optgroup label="Data sources">${srcOptions}</optgroup>` : ""}${cxOptions ? `<optgroup label="Connections">${cxOptions}</optgroup>` : ""}</select></div>
        <button class="act" type="submit">Attach to this System</button>
      </form>${unreadNote ? `<p class="sub">${unreadNote}</p>` : ""}`
    : `<div class="empty" data-system-attach-none="1">Nothing to attach: every ontology, data source and connection you can see is attached already, or you have none — create one in <a href="/ontology">Ontology</a>, <a href="/data">Data</a> or <a href="/__ioi/connections">Connections</a>.${unreadNote ? ` ${unreadNote}.` : ""}</div>`;

  return `${acted}<h2>Designs bound to this System</h2>${designs}${draftLink}`
    + `<h2>Data and connections attached to this System</h2>${dataTable}${attachForm}`
    + `<p class="sub">Attaching records that this System uses the subject; the subject stays owned and governed by its own plane, and attaching grants no access to it.</p>`;
}

// POST /__ioi/systems/attach-data — ONE SystemDataAttachment through the System-record seam, as the
// caller. POLICY FIRST, like every workspace page: the System must be an ACTIVE row of the caller's
// filtered projection before anything is written. The seam enforces the same on its own (ca1cf40de): only the
// System's admitter or an org admin holding its owner tenant may write, and the subject must be visible to them.
// The binding is derived by the seam, never composed here. The answer returns to Design mode.
async function handleAttachData(daemonUrl, res, form) {
  const systemId = (form.get("system_id") || "").trim();
  const [kind, ...refParts] = String(form.get("subject") || "").split("|");
  const subjectRef = refParts.join("|").trim();
  const tailPath = systemId.startsWith("system://") ? systemId.slice("system://".length) : "";
  const back = (params) => {
    res.writeHead(303, { Location: `${tailPath ? modeHref(tailPath, "design") : "/systems"}?${new URLSearchParams(params).toString()}`, "Cache-Control": "no-cache" });
    res.end();
  };
  if (!tailPath || /\s/u.test(systemId)) return back({ refused: "system_workspace_path_invalid", reason: "system_id is not a system:// ref" });
  if (!ATTACH_KINDS[kind] || !subjectRef) return back({ refused: "system_attachment_subject_invalid", reason: "choose an ontology, a data source or a connection from the form" });
  const gate = await fetchCensus(daemonUrl, "compact", systemId);
  const row = !gate.networkError && gate.status === 200 && gate.body?.state === "ready" ? (gate.body.systems || []).find((s) => s.system_id === systemId) : null;
  if (!row) {
    const code = gate.networkError ? "daemon_unreachable" : gate.status === 200 ? "system_not_in_inventory" : refusalCodeOf(gate.body || {}, gate.status);
    return back({ refused: code, reason: "attaching needs a System in your inventory" });
  }
  if (row.status !== "active") return back({ refused: "system_record_system_not_active", reason: `the System is ${row.status || "not active"}` });
  const who = await daemonJson(daemonUrl, "GET", "/v1/hypervisor/auth/whoami");
  const ownerRef = callerOwnerRef(who.body || {});
  if (!ownerRef) return back({ refused: "mutation_owner_ref_required", reason: "your session carries no org:// or project:// tenant to own the attachment" });
  const attachmentId = systemDataAttachmentId(systemId, subjectRef);
  const result = await daemonJson(daemonUrl, "POST", `${GENESIS_API}/${encodeURIComponent(systemId)}/records`, {
    owner_ref: ownerRef,
    idempotency_key: `system-data-attachment-${sha256Hex(`${attachmentId}\u0000genesis`).slice(0, 32)}`,
    contract_id: SYSTEM_DATA_ATTACHMENT_CONTRACT,
    object_id: attachmentId,
    parent_scope_ref: null,
    record: { schema_version: "ioi.hypervisor.system-data-attachment.v1", attachment_id: attachmentId, subject_kind: kind, subject_ref: subjectRef, status: "attached" },
    expected_head: null,
  });
  if (result.networkError) return back({ refused: "daemon_unreachable", reason: result.networkError });
  if ((result.status === 200 || result.status === 201) && result.body?.ok === true && result.body?.receipt_ref) {
    return back({ acted: "attach-data", record: attachmentId, receipt: result.body.receipt_ref, result: result.body.replayed ? "replayed" : "attached" });
  }
  return back({ refused: refusalCodeOf(result.body || {}, result.status) || `http_${result.status}`, reason: String(refusalMessageOf(result.body || {}) || "").slice(0, 200) });
}

// ---- Improve mode: change sets on the System's blueprints (R-240 journey WP-C2) ----------------
// A System improves through change sets on the blueprints bound to it (change-set v2, subject kind
// `blueprint`). A person proposes a draft over one of them — the daemon validates it with the
// blueprint's own successor checks — and merges it, which admits the draft through the blueprint's
// own compare-and-swap PATCH with the head the change set pinned; a moved head is refused by name.
// Both reads are the caller's own: Studio's plane narrowed to the System, and the change-set plane
// narrowed to blueprint subjects. Every write is one daemon route as the caller; nothing is signed
// or cached here. A campaign scoped to the System is a separate, named gap: the improvement campaign
// plane refuses a System scope by name until the constitution's protected profile binding exists,
// which needs an ADR.
export const IMPROVEMENT_CAMPAIGN_GAP = "System-scoped improvement campaigns (the constitution's protected profile binding — an ADR)";
const CHANGE_SET_ACTIONS = { propose: `${BASE}/change-sets/propose`, merge: `${BASE}/change-sets/merge`, abandon: `${BASE}/change-sets/abandon` };
const CHANGE_SET_RESULTS = { "propose-change-set": "Proposed", "merge-change-set": "Merged", "abandon-change-set": "Abandoned" };
const changeSetId = (ref) => (/^change:\/\/(cs_[0-9a-f]{16})$/u.exec(String(ref || "")) || [])[1] || null;

async function systemImprove(daemonUrl, systemId, query) {
  const [blueprints, changeSets] = await Promise.all([
    daemonJson(daemonUrl, "GET", `/v1/hypervisor/studio/blueprints?system_ref=${encodeURIComponent(systemId)}`),
    daemonJson(daemonUrl, "GET", "/v1/hypervisor/change-sets?kind=blueprint"),
  ]);
  const actedAs = CHANGE_SET_RESULTS[query?.get("acted") || ""];
  const acted = actedAs
    ? stateBlock("completed", null, `<div class="empty" data-system-change-set-result="${esc(query.get("acted"))}">${esc(actedAs)} <code>${esc(query.get("record") || "")}</code>${query.get("head") ? ` · the blueprint's admitted head is now <code>${esc(query.get("head"))}</code>` : ""}</div>`)
    : query?.get("refused")
      ? stateBlock("denied_or_revoked", query.get("refused"), `<div class="empty" data-system-change-set-result="refused">Not done — <code>${esc(query.get("refused"))}</code>: ${esc(query.get("reason") || "")}. ${query.get("record") ? `The change set <code>${esc(query.get("record"))}</code> is listed below as the daemon holds it.` : "Nothing changed."}</div>`)
      : "";
  const bpCode = unreadCode(blueprints);
  const csCode = unreadCode(changeSets);
  const bps = bpCode ? [] : (Array.isArray(blueprints.body?.blueprints) ? blueprints.body.blueprints : []).filter((b) => b.system_ref === systemId);
  const byRef = new Map(bps.map((b) => [b.ref, b]));
  const sets = csCode ? [] : (Array.isArray(changeSets.body?.change_sets) ? changeSets.body.change_sets : [])
    .filter((c) => c.subject?.kind === "blueprint" && byRef.has(c.subject?.family_ref));
  const hidden = (name, value) => `<input type="hidden" name="${esc(name)}" value="${esc(value)}">`;
  const rowActions = (c) => {
    const forms = [];
    if (c.status === "proposed") {
      forms.push(`<form method="post" action="${CHANGE_SET_ACTIONS.merge}" data-change-set-merge="${esc(c.change_set_ref)}" style="display:inline">${hidden("system_id", systemId)}${hidden("change_set_ref", c.change_set_ref)}<button class="act" type="submit">Merge into the blueprint</button></form>`);
    }
    if (c.status === "open" || c.status === "proposed") {
      forms.push(`<form method="post" action="${CHANGE_SET_ACTIONS.abandon}" data-change-set-abandon="${esc(c.change_set_ref)}" style="display:inline">${hidden("system_id", systemId)}${hidden("change_set_ref", c.change_set_ref)}<button type="submit">Abandon</button></form>`);
    }
    return forms.join(" ") || `<span class="sub" style="margin:0">${esc(c.status)} — nothing more to do</span>`;
  };
  const validationOf = (c) => {
    const v = c.validation;
    if (!v) return `<span class="sub" style="margin:0">not validated</span>`;
    const findings = (v.findings || []).map((f) => `<br><code>${esc(f.code)}</code> ${esc(f.message)}`).join("");
    return `${pill(v.outcome, v.outcome === "valid" ? "ok" : "warn")} draft ${esc(String(v.draft_ordinal))}${findings}`;
  };
  const headsOf = (c) => `pinned <code>${esc(c.subject?.base_head_ref || "")}</code>${c.merge ? `<br>resulting <code data-change-set-resulting-head="${esc(c.merge.resulting_head_ref || "")}">${esc(c.merge.resulting_head_ref || "")}</code><br>content <code>${esc(c.merge.resulting_revision_ref || "")}</code><br>plan <code>${esc(c.merge.branch_merge_plan_ref || "")}</code>` : ""}`;
  const table = csCode || bpCode
    ? stateBlock(stateForErrorCode(csCode || bpCode), csCode || bpCode, `<div class="empty" data-system-change-sets-unavailable="1">The change sets on this System's blueprints could not be read — <code>${esc(csCode || bpCode)}</code>. Nothing is shown in their place.</div>`)
    : sets.length
      ? stateBlock("ready_or_proposed", null, `<table data-system-change-sets="${esc(systemId)}"><thead><tr><th>Change set</th><th>Blueprint</th><th>Status</th><th>Validation</th><th>Heads</th><th></th></tr></thead><tbody>${sets.map((c) => {
        const b = byRef.get(c.subject.family_ref) || {};
        return `<tr data-system-change-set="${esc(c.change_set_ref)}" data-change-set-status="${esc(c.status)}" data-change-set-blueprint="${esc(c.subject.family_ref)}"><td><b>${esc(c.title || "")}</b>${c.description ? `<br><span class="sub" style="margin:0">${esc(c.description)}</span>` : ""}<br><code>${esc(c.change_set_ref)}</code></td><td>${esc(b.name || b.id || "")}<br><code>${esc(c.subject.family_ref)}</code></td><td>${pill(c.status, c.status === "merged" ? "ok" : c.status === "proposed" ? "warn" : "muted")}</td><td>${validationOf(c)}</td><td>${headsOf(c)}</td><td>${rowActions(c)}</td></tr>`;
      }).join("")}</tbody></table>`)
      : stateBlock("honest_empty", "no_change_set_on_system_blueprints", `<div class="empty" data-system-change-sets="${esc(systemId)}">No change set has been proposed on this System's blueprints yet.</div>`);
  const proposeForm = bps.length
    ? `<form method="post" action="${CHANGE_SET_ACTIONS.propose}" data-system-propose-change-set="1">
        ${hidden("system_id", systemId)}${hidden("form_nonce", globalThis.crypto.randomUUID())}
        <div class="field"><label>Blueprint</label><select name="blueprint">${bps.map((b) => `<option value="${esc(b.id || "")}">${esc(b.name || b.id || "")} — ${esc(b.ref || "")}</option>`).join("")}</select></div>
        <div class="field"><label>Change set title</label><input name="title" maxlength="200" required></div>
        <div class="field"><label>Why (description)</label><textarea name="description" maxlength="4000"></textarea></div>
        <p class="sub">The draft — leave a field blank to keep what the blueprint says. The daemon checks it with the blueprint's own successor checks before it is proposed.</p>
        <div class="field"><label>New name</label><input name="draft_name" maxlength="200"></div>
        <div class="field"><label>New description</label><textarea name="draft_description" maxlength="2000"></textarea></div>
        <div class="field"><label>New graph (a JSON object)</label><textarea name="draft_graph_json"></textarea></div>
        <button class="act" type="submit">Propose this change</button>
      </form>`
    : bpCode
      ? ""
      : `<div class="empty" data-system-propose-none="1">No blueprint is bound to this System yet, so there is nothing to change — draft one for it in Studio from its <b>Design</b> mode.</div>`;
  return `${acted}<h2>Change sets on this System's blueprints</h2>${table}<h2>Propose a change to a blueprint</h2>${proposeForm}`
    + `<p class="sub">A change set grants nothing: proposing records a draft; merging admits it through the blueprint's own compare-and-swap, and a blueprint whose head moved since the change set was opened is never merged over.</p>`;
}

// The workspace's Improve answers return here, carrying the record or the refusal.
function improveBack(res, systemId, params) {
  const tailPath = String(systemId || "").startsWith("system://") ? systemId.slice("system://".length) : "";
  res.writeHead(303, { Location: `${tailPath ? modeHref(tailPath, "improve") : "/systems"}?${new URLSearchParams(params).toString()}`, "Cache-Control": "no-cache" });
  res.end();
}
const daemonRefusal = (result, fallback) => (result.networkError
  ? { refused: "daemon_unreachable", reason: result.networkError }
  : { refused: refusalCodeOf(result.body || {}, result.status) || fallback || `http_${result.status}`, reason: String(refusalMessageOf(result.body || {}) || "").slice(0, 300) });

// POLICY FIRST: the System must be in the caller's filtered projection, and the blueprint one the
// Studio plane lists as bound to it for this caller, before anything is written.
async function improvableBlueprint(daemonUrl, systemId, blueprintRef) {
  if (!String(systemId).startsWith("system://") || /\s/u.test(systemId)) return { refusal: { refused: "system_workspace_path_invalid", reason: "system_id is not a system:// ref" } };
  const gate = await fetchCensus(daemonUrl, "compact", systemId);
  const row = !gate.networkError && gate.status === 200 && gate.body?.state === "ready" ? (gate.body.systems || []).find((s) => s.system_id === systemId) : null;
  if (!row) {
    const code = gate.networkError ? "daemon_unreachable" : gate.status === 200 ? "system_not_in_inventory" : refusalCodeOf(gate.body || {}, gate.status);
    return { refusal: { refused: code, reason: "improving needs a System in your inventory" } };
  }
  const listed = await daemonJson(daemonUrl, "GET", `/v1/hypervisor/studio/blueprints?system_ref=${encodeURIComponent(systemId)}`);
  const listCode = unreadCode(listed);
  if (listCode) return { refusal: { refused: listCode, reason: "the System's blueprints could not be read" } };
  const blueprint = (listed.body.blueprints || []).find((b) => b.system_ref === systemId && (b.ref === blueprintRef || b.id === blueprintRef));
  if (!blueprint) return { refusal: { refused: "change_set_subject_not_bound", reason: "that blueprint is not one bound to this System that you can read" } };
  return { blueprint };
}

// POST /__ioi/systems/change-sets/propose — open a blueprint change set with the form's draft,
// validate it (the blueprint's own successor checks) and propose it: three daemon writes as the
// caller, each with its own idempotency key derived from the rendered form's nonce, so a resubmitted
// form replays rather than opening a second change set.
async function handleProposeChangeSet(daemonUrl, res, form) {
  const systemId = (form.get("system_id") || "").trim();
  const back = (params) => improveBack(res, systemId, params);
  const nonce = (form.get("form_nonce") || "").trim();
  const title = (form.get("title") || "").trim();
  if (!nonce) return back({ refused: "change_set_form_nonce_required", reason: "submit the form the Improve mode rendered" });
  if (!title) return back({ refused: "change_set_title_required", reason: "a change set has a title" });
  const draft = {};
  const draftName = (form.get("draft_name") || "").trim();
  const draftDescription = (form.get("draft_description") || "").trim();
  const graphJson = (form.get("draft_graph_json") || "").trim();
  if (draftName) draft.name = draftName;
  if (draftDescription) draft.description = draftDescription;
  if (graphJson) {
    let graph;
    try { graph = JSON.parse(graphJson); } catch { graph = undefined; }
    if (!graph || typeof graph !== "object" || Array.isArray(graph)) return back({ refused: "change_set_draft_graph_invalid", reason: "the new graph must be a JSON object" });
    draft.graph = graph;
  }
  if (!Object.keys(draft).length) return back({ refused: "change_set_draft_empty", reason: "a change says what it changes: fill a new name, description or graph" });
  const { blueprint, refusal } = await improvableBlueprint(daemonUrl, systemId, (form.get("blueprint") || "").trim());
  if (refusal) return back(refusal);
  const key = `system-change-set-${sha256Hex(`${systemId}\u0000${blueprint.ref}\u0000${nonce}`).slice(0, 32)}`;
  const owner = blueprint.owner_ref;
  const opened = await daemonJson(daemonUrl, "POST", "/v1/hypervisor/change-sets", {
    owner_ref: owner, idempotency_key: key, subject: { kind: "blueprint", family: blueprint.id }, title, description: (form.get("description") || "").trim(), draft,
  });
  const cs = opened.body?.change_set;
  if (opened.networkError || ![200, 201].includes(opened.status) || !cs) return back(daemonRefusal(opened, "change_set_open_refused"));
  const record = cs.change_set_ref;
  const id = changeSetId(record);
  // A replayed form lands on the change set it opened, wherever that change set now stands.
  if (cs.status !== "open") return back({ acted: "propose-change-set", record });
  const validated = await daemonJson(daemonUrl, "POST", `/v1/hypervisor/change-sets/${id}/validate`, { owner_ref: owner, idempotency_key: `${key}-validate` });
  if (validated.networkError || validated.status !== 200) return back({ ...daemonRefusal(validated, "change_set_validate_refused"), record });
  const validation = validated.body?.change_set?.validation || {};
  if (validation.outcome !== "valid") {
    const finding = (validation.findings || [])[0] || {};
    return back({ refused: "change_set_draft_invalid", reason: `${finding.code || "invalid"}: ${String(finding.message || "the blueprint's own checks refused the draft").slice(0, 240)}`, record });
  }
  const proposed = await daemonJson(daemonUrl, "POST", `/v1/hypervisor/change-sets/${id}/propose`, { owner_ref: owner, idempotency_key: `${key}-propose` });
  if (proposed.networkError || proposed.status !== 200) return back({ ...daemonRefusal(proposed, "change_set_propose_refused"), record });
  return back({ acted: "propose-change-set", record });
}

// The change set a row form names, read as the caller, over a blueprint bound to this System.
async function improvableChangeSet(daemonUrl, systemId, changeSetRef) {
  const id = changeSetId(changeSetRef);
  if (!id) return { refusal: { refused: "change_set_not_found", reason: "that is not a change set ref" } };
  const read = await daemonJson(daemonUrl, "GET", `/v1/hypervisor/change-sets/${id}`);
  const cs = read.body?.change_set;
  if (read.networkError || read.status !== 200 || !cs) return { refusal: daemonRefusal(read, "change_set_not_found") };
  if (cs.subject?.kind !== "blueprint") return { refusal: { refused: "change_set_subject_not_bound", reason: "that change set is not over a blueprint" } };
  const { refusal } = await improvableBlueprint(daemonUrl, systemId, cs.subject.family_ref);
  return refusal ? { refusal } : { cs, id };
}

// POST /__ioi/systems/change-sets/merge — merge a proposed change set: the daemon admits its latest
// validated draft through the blueprint's own PATCH with the head the change set pinned.
async function handleMergeChangeSet(daemonUrl, res, form) {
  const systemId = (form.get("system_id") || "").trim();
  const back = (params) => improveBack(res, systemId, params);
  const { cs, id, refusal } = await improvableChangeSet(daemonUrl, systemId, (form.get("change_set_ref") || "").trim());
  if (refusal) return back(refusal);
  const ordinal = (cs.drafts || []).at(-1)?.ordinal || 0;
  const merged = await daemonJson(daemonUrl, "POST", `/v1/hypervisor/change-sets/${id}/merge`, { owner_ref: cs.owner_ref, idempotency_key: `system-change-set-merge-${id}-${ordinal}` });
  const after = merged.body?.change_set;
  if (merged.networkError || merged.status !== 200 || after?.status !== "merged") return back({ ...daemonRefusal(merged, "change_set_merge_refused"), record: cs.change_set_ref });
  return back({ acted: "merge-change-set", record: cs.change_set_ref, head: after.merge?.resulting_head_ref || "" });
}

// POST /__ioi/systems/change-sets/abandon — close an open or proposed change set without merging it.
async function handleAbandonChangeSet(daemonUrl, res, form) {
  const systemId = (form.get("system_id") || "").trim();
  const back = (params) => improveBack(res, systemId, params);
  const { cs, id, refusal } = await improvableChangeSet(daemonUrl, systemId, (form.get("change_set_ref") || "").trim());
  if (refusal) return back(refusal);
  const closed = await daemonJson(daemonUrl, "POST", `/v1/hypervisor/change-sets/${id}/abandon`, { owner_ref: cs.owner_ref, idempotency_key: `system-change-set-abandon-${id}`, note: "abandoned from the System's Improve mode" });
  if (closed.networkError || closed.status !== 200) return back({ ...daemonRefusal(closed, "change_set_abandon_refused"), record: cs.change_set_ref });
  return back({ acted: "abandon-change-set", record: cs.change_set_ref });
}

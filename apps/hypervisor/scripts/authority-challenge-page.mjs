// A PARKED EFFECT'S OWN APPROVAL PAGE (R-240, parked-effect approval page).
//
// Until this page, the Hypervisor approved a parked effect only when it had started the run itself (the run, provider and
// custody cards). An effect parked any other way — a wallet challenge a direct session execute or a capability-lease gate
// parked — had no page that could approve it: the adopted Approvals app lists it but has no passphrase field, so the operator
// had to leave the product for the local authority's approve command.
//
// This page is one parked challenge from DAEMON truth (`GET /v1/hypervisor/authority/challenges/:id`): what effect it is,
// the exact hashes, target scope and audience a grant would bind, who asked, when it expires and its state. For the
// operator it carries an Approve form (the operator passphrase) and a Deny form (a reason), both relayed to the daemon's
// decision route (`POST /v1/hypervisor/authority/challenges/:id/decision`) through the one relay the approval cards use
// (lib/wallet-authority.mjs relayChallengeDecision). The UI server holds no key (master guide §0.5.2, N9): the passphrase
// rides that one request to the daemon, which runs the deployment authority's own `approve` for the coordinates in its OWN
// record. The daemon decides who may decide; the page only hides the forms from anyone the daemon would refuse, and shows
// the daemon's refusal verbatim when a decision is posted anyway. Nothing here widens what the approver may sign: a scope
// outside the deployment approver's allowlist is refused by the authority itself, and the page says so in its words.
//
// A decision the daemon is still recording, one whose outcome an interruption left unknown, and an approval whose grant
// expired unused are each named from the daemon's own record (R-240, challenge states + re-ask): Deciding (who started it,
// when; both decisions disabled with that reason, and the page re-reads itself), a 202 as Still deciding (never a
// refusal), Outcome unknown (the daemon's named reason; Approve disabled by name, Deny open), and an expired grant as an
// ask that must be asked again, linked to its successor challenge when the requester's retry has parked one.
//
// This module is pure: it renders from what the serve read, and reaches no daemon, clock or network of its own.
import { escHtml as esc } from "../surfaces/kit.mjs";

export const CHALLENGE_PAGE_PREFIX = "/__ioi/authority/challenges";
export const challengePagePath = (id) => `${CHALLENGE_PAGE_PREFIX}/${encodeURIComponent(String(id || ""))}`;
export const CHALLENGE_PAGE_ROUTE = /^\/__ioi\/authority\/challenges\/([^/]+)$/u;
export const CHALLENGE_DECISION_PAGE_ROUTE = /^\/__ioi\/authority\/challenges\/([^/]+)\/(approve|deny)$/u;

const iso = (ms) => (Number(ms) > 0 ? new Date(Number(ms)).toISOString() : null);
const code = (v) => `<code>${esc(v)}</code>`;
function inWords(ms) {
  const m = Math.round(Math.abs(ms) / 60000);
  if (m < 1) return "under a minute";
  if (m < 90) return `${m} min`;
  const h = Math.round(m / 60);
  return h < 48 ? `${h} h` : `${Math.round(h / 24)} days`;
}

// ---- the state a reader sees, from the daemon's record alone -------------------------------------------------------------
// pending (and not past its expiry) · deciding (pending, an approve being recorded now: the record's `deciding` marker) ·
// outcome_unknown (pending, an interrupted approve whose outcome the daemon has not reconciled yet: its named reason) ·
// expired (pending, past its expiry: the daemon refuses a decision and drops it from its inbox; re-running the effect parks
// it again) · approved (one grant minted, not yet run) · grant_expired (approved, the grant's life ran out unused: the
// authority keeps one decision per request, so the action must be asked again — the requester's retry parks a successor) ·
// consuming (a retry is presenting the grant now) · completed (consumed: the effect ran once) · denied · unknown (a state
// this page does not know is named, never guessed). dir (principal_ref → name) names who started a decision.
const decidingOf = (c) => (c?.deciding && typeof c.deciding === "object" ? c.deciding : null);
const unknownOf = (c) => (c?.outcome_unknown && typeof c.outcome_unknown === "object" ? c.outcome_unknown : null);
const nameIn = (dir, ref) => (ref ? (dir?.get?.(ref) || ref) : "an operator");
export function challengeStateOf(c, nowMs = Date.now(), dir = null) {
  const state = String(c?.state || "");
  if (state === "pending") {
    // an approve being recorded settles on its own whatever the ask's expiry: it is named before anything else
    const deciding = decidingOf(c);
    if (deciding) return { key: "deciding", label: `Deciding — started ${deciding.started_at || "earlier"} by ${nameIn(dir, deciding.decided_by)}`, tone: "warn" };
    if (Number(c.expires_at_ms) > 0 && Number(c.expires_at_ms) <= nowMs) return { key: "expired", label: "Closed — expired undecided", tone: "muted" };
    const unknown = unknownOf(c);
    if (unknown) return { key: "outcome_unknown", label: `Outcome unknown — ${unknown.reason || "no reason named"}`, tone: "warn" };
    return { key: "pending", label: "Waiting for the operator", tone: "warn" };
  }
  if (state === "approved") {
    return Number(c.grant_expires_at_ms) > 0 && Number(c.grant_expires_at_ms) <= nowMs
      ? { key: "grant_expired", label: "Approved — grant expired unused; the action must be asked again", tone: "muted" }
      : { key: "approved", label: "Approved — grant minted, not yet run", tone: "ok" };
  }
  if (state === "consuming") return { key: "consuming", label: "Approved — being run now", tone: "ok" };
  if (state === "consumed") return { key: "completed", label: "Completed — the effect ran once", tone: "ok" };
  if (state === "denied") return { key: "denied", label: "Denied", tone: "muted" };
  return { key: "unknown", label: state ? `State ${state}` : "No state recorded", tone: "muted" };
}

// Who may decide, as the daemon adjudicates it (authority_challenge_routes.rs require_operator): an authenticated
// administrator, never an impersonated session. The page uses this only to hide the forms; the daemon decides.
export function operatorOf(who) {
  const p = who && who.authenticated === true && who.principal && typeof who.principal === "object" ? who.principal : null;
  return {
    signedIn: !!p,
    operator: !!p && p.role === "admin" && p.is_impersonated !== true,
    impersonated: !!p && p.is_impersonated === true,
    ref: p?.principal_ref || null,
    name: p?.name || p?.email || p?.principal_ref || null,
  };
}

// principal_ref → a name, from the daemon's directory (read when the caller may) and the caller themself
export function directoryOf(who, principals = []) {
  const dir = new Map();
  for (const p of Array.isArray(principals) ? principals : []) if (p?.principal_ref) dir.set(p.principal_ref, p.name || p.email || p.principal_ref);
  const me = who?.authenticated === true ? who.principal : null;
  if (me?.principal_ref) dir.set(me.principal_ref, me.name || me.email || me.principal_ref);
  return dir;
}
const personOf = (dir, ref) => (ref ? `${esc(dir?.get(ref) && dir.get(ref) !== ref ? `${dir.get(ref)} ` : "")}${code(ref)}` : "the daemon names no requester");

// What the effect is, in the preimage's own words: a session execute's intent and scopes, a capability lease's tools and
// resources.
export function effectOf(c) {
  const pre = c?.published_preimage && typeof c.published_preimage === "object" ? c.published_preimage : {};
  const rp = pre.request_preimage && typeof pre.request_preimage === "object" ? pre.request_preimage : {};
  const effect = pre.effect && typeof pre.effect === "object" ? pre.effect : {};
  const list = (v) => (Array.isArray(v) ? v.map((x) => (typeof x === "string" ? x : JSON.stringify(x))) : []);
  return {
    intent: typeof rp.intent === "string" ? rp.intent : typeof effect.intent === "string" ? effect.intent : null,
    scopes: list(rp.scopes).length ? list(rp.scopes) : list(effect.scopes),
    tools: list(pre.allowed_tools),
    resources: list(pre.resource_refs),
    workspace: typeof effect.workspace_root === "string" ? effect.workspace_root : null,
    policyDomain: pre.policy_preimage?.domain || null,
    requestDomain: rp.domain || null,
  };
}

const titleOf = (c) => `${c?.operation || "An effect"} on ${c?.subject_ref || "a subject"}`;
const pill = (s) => `<span class="pill ${esc(s.tone)}" data-ioi-challenge-state="${esc(s.key)}">${esc(s.label)}</span>`;
const row = (dt, dd) => (dd === null || dd === undefined || dd === "" ? "" : `<dt>${esc(dt)}</dt><dd>${dd}</dd>`);

// What the state means for the reader, in one sentence each.
const pageLink = (id, text) => `<a href="${esc(challengePagePath(id))}">${esc(text)}</a>`;
function stateSays(c, s, nowMs, dir) {
  const deciding = decidingOf(c), unknown = unknownOf(c);
  switch (s.key) {
    case "pending": return `The daemon refused to run this exact effect without a grant and parked it for the operator. It stays decidable until ${esc(iso(c.expires_at_ms) || "—")} (in ${esc(inWords(Number(c.expires_at_ms) - nowMs))}).`;
    case "deciding": return `The operator's approval is being recorded by the deployment authority now — started <span data-ioi-challenge-deciding-since>${esc(deciding.started_at || "earlier")}</span> by <span data-ioi-challenge-deciding-by>${personOf(dir, deciding.decided_by)}</span>. The daemon runs it to completion whether or not anyone waits, and refuses any other decision on this challenge until it settles. This page reads the daemon again every ${DECIDING_REFRESH_S} s — <a href="${esc(challengePagePath(c.challenge_id))}" data-ioi-challenge-reload>reload now</a>.`;
    case "outcome_unknown": return `An approval of this challenge was interrupted and its outcome is not known: <code data-ioi-challenge-unknown-reason>${esc(unknown.reason || "no reason named")}</code> — <span data-ioi-challenge-unknown-message>${esc(unknown.message || "")}</span>${unknown.since ? ` (since ${esc(unknown.since)}${unknown.checked_at ? `, last checked ${esc(unknown.checked_at)}` : ""})` : ""}. The daemon re-reads the authority's record before any decision and runs nothing on a guess, so Approve is refused by name until that settles it. Deny stays open: whatever the authority recorded, the daemon never presents it.`;
    case "expired": return `It expired at ${esc(iso(c.expires_at_ms) || "—")} with no decision: the daemon refuses a decision on it and has dropped it from its inbox. Re-running the effect parks it again.${unknown ? ` An interrupted approval's outcome was still unknown when it closed (<code>${esc(unknown.reason || "")}</code>).` : ""}`;
    case "approved": return `The operator approved it and the deployment authority minted one one-use grant for exactly these hashes. It has not run: the requester's retry names ${code(c.approval_ref || "")} and runs it once.`;
    case "grant_expired": return `The operator approved it, but its one-use grant expired at ${esc(iso(c.grant_expires_at_ms) || "—")} before any retry ran it. The deployment authority keeps one decision per request, so this approval can never be renewed and a retry naming it is refused (approval_ref_expired): the action must be asked again. The requester's retry of the effect parks a new challenge — the same effect under a fresh single-use nonce, so a new request hash — ${c.superseded_by ? `and has: <span data-ioi-challenge-superseded-by>${pageLink(c.superseded_by, "the new challenge")} (${code(c.superseded_by)})</span>.` : "and none has been parked yet."}`;
    case "consuming": return "A retry is presenting its one-use grant to the authority right now; it reads Completed once the run is admitted.";
    case "completed": return c.completed_by_grant_ref
      ? `It was never decided here: the step ran once${c.consumed_at ? ` at ${esc(c.consumed_at)}` : ""} under a grant presented directly for exactly these coordinates — <code data-ioi-challenge-completed-by-grant>${esc(String(c.completed_by_grant_ref))}</code> — so the daemon settled this challenge as completed by that grant. A retry naming it is refused.`
      : `The requester's retry ran it once under its one-use grant${c.consumed_at ? ` at ${esc(c.consumed_at)}` : ""}; the grant is spent and a replay is refused.${c.superseded_by ? ` A later crossing of the same effect was asked again as <span data-ioi-challenge-superseded-by>${pageLink(c.superseded_by, "a new challenge")} (${code(c.superseded_by)})</span>.` : ""}`;
    case "denied": return "The operator denied it; nothing may run under it. Re-running the effect asks again.";
    default: return "The daemon records a state this page does not know; nothing is inferred from it.";
  }
}
// A successor names the ask whose approval expired unused; it binds a new request hash for the same exact effect.
// A successor of a CONSUMED ask is a new crossing of an effect that already ran once (R-240, authority follow-ups).
const supersedesSays = (c) => (c?.supersedes
  ? c.supersedes_reason === "consumed"
    ? `<div class="meta" data-ioi-challenge-supersedes="${esc(c.supersedes)}" data-ioi-challenge-supersedes-reason="consumed">This asks the effect again: an earlier crossing of it (${pageLink(c.supersedes, c.supersedes)}) ran once under its one-use grant, and a new crossing is a new decision — the authority never decides one request twice, so this ask binds the same effect under a fresh single-use nonce (a new request hash).</div>`
    : `<div class="meta" data-ioi-challenge-supersedes="${esc(c.supersedes)}">This asks the effect again: its earlier approval (${pageLink(c.supersedes, c.supersedes)}) expired unused, and the authority never decides one request twice — so this ask binds the same effect under a fresh single-use nonce (a new request hash).</div>`
  : "");
// While a decision is being recorded the page reads the daemon again on its own (never a re-POST: it loads the page's own
// GET address, whether it was reached by a link or as a decision's answer).
const DECIDING_REFRESH_S = 10;
const refreshScript = (id) => `<script>setTimeout(function(){location.replace(${JSON.stringify(challengePagePath(id)).replace(/</gu, "\\u003c")});},${DECIDING_REFRESH_S * 1000});</script>`;

// The passphrase field is the serve's one shared field (the approval cards' own), passed in; a hint line under the forms
// says what a missing value needs (a browser's validation bubble alone moves nothing on the page).
const FORMS_SCRIPT = `<script>document.querySelectorAll("form[data-ioi-challenge-decision]").forEach(function(f){f.addEventListener("invalid",function(e){var h=document.querySelector("[data-ioi-field-hint]");if(h)h.textContent=(e.target.getAttribute("aria-label")||"This field")+" is needed to approve: it opens the sealed approver key for this one grant.";},true);f.addEventListener("submit",function(){var b=f.querySelector("button[type=submit]");if(b){b.disabled=true;b.textContent=b.getAttribute("data-busy")||"Sending…";}});});</script>`;

// A decision the daemon would refuse is a disabled control carrying its reason (the unified gap contract: aria-disabled and
// data-ioi-disabled-reason), never a live-looking button that fails.
const disabledButton = (label, reason, ghost = false) => `<button class="act${ghost ? " ghost" : ""}" type="button" disabled aria-disabled="true" data-ioi-disabled-reason="${esc(reason)}" title="${esc(reason)}">${esc(label)}</button>`;

function decideSection(c, s, me, opts) {
  const { passphraseField, dir } = opts;
  if (!["pending", "deciding", "outcome_unknown"].includes(s.key)) return "";
  if (!me.signedIn) return `<h2>Decide</h2><div class="empty" data-ioi-challenge-decide="signed-out">Only the deployment's operator decides a parked effect. <a href="/__ioi/login?next=${encodeURIComponent(challengePagePath(c.challenge_id))}">Sign in</a> as the operator to decide it.</div>`;
  if (!me.operator) {
    const why = me.impersonated ? "an impersonated session cannot decide one" : "the daemon refuses anyone else";
    return `<h2>Decide</h2><div class="empty" data-ioi-challenge-decide="not-operator">Only the deployment's operator (an administrator, signed in as themself) decides a parked effect, and ${esc(why)}. You are signed in as ${esc(me.name || "someone else")}.</div>`;
  }
  const path = challengePagePath(c.challenge_id);
  // An approve being recorded: both decisions are the daemon's 409 until it settles, so both are disabled with that reason.
  if (s.key === "deciding") {
    const d = decidingOf(c);
    const running = `A decision on this challenge is already running (started ${d.started_at || "earlier"} by ${nameIn(dir, d.decided_by)}): the deployment authority is recording it now, and the daemon refuses another decision until it settles. Nothing new would be started.`;
    return `<h2>Decide</h2><div class="decide" data-ioi-challenge-decide="deciding">${disabledButton("Approve", running)}${disabledButton("Deny", running, true)}</div><p class="cmsg" data-ioi-challenge-deciding-note>${esc(running)} <a href="${esc(path)}" data-ioi-challenge-reload>Reload</a></p>`;
  }
  const decidable = c.decidable !== false;
  const noDecider = "This daemon has no deployment authority to approve with (IOI_WALLET_AUTHORITY_BINARY and IOI_HYPERVISOR_LOCAL_AUTHORITY_STATE_DIR on the daemon), so approving is not possible from any Hypervisor page; the operator approves it with the local authority's approve command. Denying needs no key.";
  const unknown = s.key === "outcome_unknown" ? unknownOf(c) : null;
  // An interrupted approve whose outcome is unknown: the daemon refuses a new approve by name (challenge_outcome_unknown)
  // until reconciliation settles it; Deny stays open.
  const unknownWhy = unknown ? `The daemon refuses a new approve while an interrupted approval's outcome is unknown (${unknown.reason || "no reason named"}): it re-reads the authority's record first and runs nothing on a guess. Deny stays open.` : "";
  const approve = unknown
    ? `<span data-ioi-challenge-decision="approve">${disabledButton("Approve", unknownWhy)}</span>`
    : decidable
      ? `<form method="post" action="${esc(path)}/approve" data-ioi-challenge-decision="approve">${passphraseField} <button class="act" type="submit" data-busy="Approving — the authority is signing and recording (this can take a minute or two)…">Approve — sign one grant for exactly this</button></form>`
      : `<form method="post" action="${esc(path)}/approve" data-ioi-challenge-decision="approve"><button class="act" type="submit" disabled aria-disabled="true" data-ioi-disabled-reason="${esc(noDecider)}" title="${esc(noDecider)}">Approve</button></form>`;
  const deny = `<form method="post" action="${esc(path)}/deny" data-ioi-challenge-decision="deny"><input name="reason" maxlength="400" autocomplete="off" placeholder="reason (recorded with the denial)" aria-label="Reason for denying" style="background:#0c0d10;border:1px solid #2a2c33;color:#e6e7ea;border-radius:8px;padding:5px 8px;font-size:12px"> <button class="act ghost" type="submit" data-busy="Denying…">Deny</button></form>`;
  const lead = unknown
    ? "Approving is refused until the daemon settles the interrupted approval from the authority's record. Denying runs nothing, needs no key, and is always open: whatever the authority recorded, the daemon never presents it."
    : "Approving sends your operator passphrase to the daemon, whose deployment authority signs ONE one-use grant for exactly the hashes above with the sealed approver key; this page holds no key and keeps nothing you type. Denying runs nothing and needs no key.";
  return `<h2>Decide</h2><p class="sub">${lead}</p>
    <div class="decide" data-ioi-challenge-decide="operator">${approve}${deny}</div>${unknown ? `<p class="cmsg" data-ioi-challenge-unknown-note>${esc(unknownWhy)}</p>` : decidable ? "" : `<p class="cmsg" data-ioi-challenge-no-decider>${esc(noDecider)}</p>`}<p class="cmsg" data-ioi-field-hint></p>${FORMS_SCRIPT}`;
}

// A decision the daemon refused, in its own words; the record below is re-read after it.
// (two refusals are the relay's, not the daemon's: a decision the daemon never answered, and an approval sent with no
// passphrase, which is refused before anything reaches the daemon)
function refusalBanner(refusal, id) {
  if (!refusal) return "";
  const what = refusal.decision === "approve" ? "approval" : "denial";
  const words = `(HTTP ${esc(String(refusal.status || "—"))}): ${code(refusal.code || "refused")} — <span data-ioi-challenge-refusal-message>${esc(refusal.message || "")}</span>`;
  // A 202 is not a refusal: the approve is still running in the daemon, which settles the challenge on its own.
  if (refusal.code === "challenge_decision_still_running" || Number(refusal.status) === 202) {
    return `<div class="empty warn" role="status" data-ioi-challenge-still-deciding style="margin:0 0 18px">Still deciding — the daemon accepted this ${what} and its deployment authority is still recording it ${words}. The decision continues in the daemon and settles this challenge on its own; nothing needs to be sent again. The record below is the daemon's, re-read now${id ? `; <a href="${esc(challengePagePath(id))}" data-ioi-challenge-reload>reload</a> for the outcome` : ""}.</div>`;
  }
  const lead = refusal.code === "challenge_decision_unreachable"
    ? `The daemon did not answer this ${what} ${words}. Whether it was decided is read from the daemon once it answers — reload then.`
    : refusal.code === "operator_passphrase_required" && Number(refusal.status) === 400
      ? `This ${what} was not sent to the daemon ${words}. The daemon's record of this challenge is unchanged${refusal.recordShown ? " — it reads as below" : ""}.`
      : `The daemon refused this ${what} ${words}. The daemon's record of this challenge is unchanged${refusal.recordShown ? " — it reads as below" : ""}.`;
  return `<div class="empty" role="alert" data-ioi-challenge-refusal="${esc(refusal.code || "refused")}" style="border:1px solid #5c2a2a;color:#e8a0a0;margin:0 0 18px">${lead}</div>`;
}

// Earlier asks for this exact effect (closed by an expiry or a denial and reopened), and approves a stopped daemon left
// interrupted with nothing recorded on the authority (the operator decided afresh).
function historyRows(history, dir) {
  return history.map((h) => {
    const state = String(h?.state || "");
    const attempt = h?.reconciliation?.attempt && typeof h.reconciliation.attempt === "object" ? h.reconciliation.attempt : null;
    const closedAs = state === "interrupted" ? "Interrupted" : state === "expired" ? "Expired undecided" : state === "denied" ? "Denied" : state === "completed_by_presented_grant" ? "Completed by a presented grant" : state || "—";
    const decision = state === "completed_by_presented_grant"
      ? `none — the step ran under the presented grant <code>${esc(String(h.grant_ref || ""))}</code>${h.consumption_ref ? ` (admitted as <code>${esc(String(h.consumption_ref))}</code>)` : ""} while this challenge was ${esc(String(h.prior_state || "pending"))}`
      : state === "interrupted"
      ? `none — the daemon stopped mid-approve${attempt ? ` (started ${esc(attempt.started_at || "earlier")} by ${personOf(dir, attempt.decided_by)})` : ""}; the authority recorded ${esc(h.reconciliation?.authority_record === "absent" ? "nothing" : String(h.reconciliation?.authority_record || "nothing"))} for this request hash, so the operator decides afresh`
      : h?.decision && typeof h.decision === "object" ? `${esc(h.decision.decision || "—")} by ${personOf(dir, h.decision.decided_by)}${h.decision.reason ? ` — ${esc(h.decision.reason)}` : ""}` : "none";
    return `<tr data-ioi-challenge-history="${esc(state || "unknown")}"><td>${esc(closedAs)}</td><td>${esc(h?.closed_at || "—")}</td><td>${decision}</td></tr>`;
  }).join("");
}

// Page-scoped layout over the serve's shell: a value (a 71-character hash, a long scope) wraps inside its card at any
// width, the rows stack on a phone, and the two decision forms read as two groups.
const PAGE_CSS = `<style>
  [data-ioi-challenge-page] .grid{grid-template-columns:minmax(96px,160px) minmax(0,1fr)}
  [data-ioi-challenge-page] .grid dd{min-width:0;overflow-wrap:anywhere}
  [data-ioi-challenge-page] code{overflow-wrap:anywhere;word-break:break-all}
  [data-ioi-challenge-page] .card .name{overflow-wrap:anywhere}
  [data-ioi-challenge-page] .decide{display:flex;flex-wrap:wrap;gap:12px 28px;align-items:center;margin:0 0 10px}
  [data-ioi-challenge-page] .decide form{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
  [data-ioi-challenge-page] .decide input{min-width:0;max-width:100%}
  [data-ioi-challenge-page] .decide input[name=reason]{width:280px}
  [data-ioi-challenge-page] .act[disabled]{opacity:.45;cursor:not-allowed}
  @media(max-width:600px){[data-ioi-challenge-page] .grid{grid-template-columns:minmax(0,1fr);gap:2px 0}[data-ioi-challenge-page] .grid dd{margin-bottom:8px}[data-ioi-challenge-page] .decide input,[data-ioi-challenge-page] .decide input[name=reason]{width:100%}}
</style>`;
const pageOf = (html) => `${PAGE_CSS}<div data-ioi-challenge-page>${html}</div>`;

const PAGE_SUB = `One exact effect a daemon gate refused to run for want of a grant, parked for the operator's decision. <a href="${CHALLENGE_PAGE_PREFIX}">All parked effects →</a>`;

// A read that did not produce a challenge: the daemon stopped, the caller is signed out, or the daemon refused the id.
function readFailure(read, id) {
  const status = Number(read?.status) || 503;
  const body = read?.body || {};
  const errCode = body.error?.code || body.code || body.reason || "daemon_unavailable";
  const message = body.error?.message || body.message || "";
  if (status >= 500 && (errCode === "daemon_unavailable" || errCode === "plane_timeout")) {
    return { status: 503, inner: `<div class="empty" data-ioi-challenge-degraded data-error-code="${esc(errCode)}">The daemon is not answering (${code(errCode)}), so this page cannot read ${id ? `the parked effect ${code(id)}` : "the parked effects"} and shows nothing rather than a guess. Nothing can be approved or denied until it answers — start the daemon and reload.</div>` };
  }
  if (status === 401) {
    const next = id ? challengePagePath(id) : CHALLENGE_PAGE_PREFIX;
    return { status: 401, inner: `<div class="empty" data-ioi-challenge-signed-out data-error-code="${esc(errCode)}">The daemon shows parked effects only to a signed-in session (${code(errCode)}: ${esc(message || "an authenticated session is required")}). <a href="/__ioi/login?next=${encodeURIComponent(next)}">Sign in</a></div>` };
  }
  return { status, inner: `<div class="empty" data-ioi-challenge-missing data-error-code="${esc(errCode)}">The daemon did not return this parked effect (HTTP ${esc(String(status))}): ${code(errCode)}${message ? ` — ${esc(message)}` : ""}.</div>` };
}

/**
 * One parked challenge's page. read = the daemon's answer to GET /v1/hypervisor/authority/challenges/:id ({ ok, status,
 * body }); who = its whoami answer; principals = its directory (empty when the caller may not read it); refusal = a
 * decision the daemon just refused ({ decision, status, code, message }) or null; passphraseField = the serve's shared
 * operator-passphrase input. Returns { status, title, inner } for the serve's shell.
 */
export function renderChallengePage({ id, read, who, principals = [], refusal = null, nowMs = Date.now(), passphraseField = "" }) {
  const c = read?.ok && read.body?.challenge && typeof read.body.challenge === "object" ? read.body.challenge : null;
  if (!c) {
    const failed = readFailure(read, id);
    return { status: refusal ? refusal.status || failed.status : failed.status, title: "Parked effect", inner: pageOf(`<h1>Parked effect</h1><p class="sub">${PAGE_SUB}</p>${refusalBanner(refusal)}${failed.inner}`) };
  }
  const me = operatorOf(who);
  const dir = directoryOf(who, principals);
  const s = challengeStateOf(c, nowMs, dir);
  const e = effectOf(c);
  const decided = c.decision && typeof c.decision === "object" ? c.decision : null;
  const history = Array.isArray(c.history) ? c.history : [];
  const tags = (xs) => xs.map((x) => code(x)).join(" ");
  const inner = `<h1>${s.key === "pending" ? "Approve this effect?" : "Parked effect"}</h1><p class="sub">${PAGE_SUB}</p>
    ${refusalBanner(refusal ? { ...refusal, recordShown: true } : null, c.challenge_id)}
    <div class="card" data-ioi-challenge="${esc(c.challenge_id)}"><div class="main"><div class="name">${esc(titleOf(c))}${pill(s)}</div>
      <div class="meta" data-ioi-challenge-says>${stateSays(c, s, nowMs, dir)}</div>${supersedesSays(c)}</div></div>
    <h2>${s.key === "completed" ? "What it did" : ["pending", "deciding", "outcome_unknown", "approved", "consuming"].includes(s.key) ? "What it will do" : "The effect"}</h2>
    <dl class="grid">${row("Operation", esc(c.operation || "—"))}${row("Subject", code(c.subject_ref || "—"))}${row("Intent", e.intent === null ? null : `<span data-ioi-challenge-intent>${esc(e.intent)}</span>`)}${row("Scopes", e.scopes.length ? tags(e.scopes) : null)}${row("Tools", e.tools.length ? tags(e.tools) : null)}${row("Resources", e.resources.length ? tags(e.resources) : null)}${row("Workspace", e.workspace === null ? null : code(e.workspace))}</dl>
    <h2>${["pending", "deciding", "outcome_unknown", "expired", "denied"].includes(s.key) ? "What a grant would bind" : "What its grant binds"}</h2>
    <dl class="grid" data-ioi-challenge-binds>${row("Target scope", `<code data-ioi-challenge-target-scope>${esc(c.target_scope || "")}</code>`)}${row("Policy hash", `<code data-ioi-challenge-policy-hash>${esc(c.policy_hash || "")}</code>${e.policyDomain ? ` <span class="meta">(${esc(e.policyDomain)})</span>` : ""}`)}${row("Request hash", `<code data-ioi-challenge-request-hash>${esc(c.request_hash || "")}</code>${c.ask_nonce ? ` <span class="meta">(a re-ask: the effect's own request hash <code data-ioi-challenge-base-request-hash>${esc(c.base_request_hash || "")}</code>${e.requestDomain ? ` (${esc(e.requestDomain)})` : ""} under the single-use nonce <code>${esc(c.ask_nonce)}</code>)</span>` : e.requestDomain ? ` <span class="meta">(${esc(e.requestDomain)})</span>` : ""}`)}${row("Audience", c.audience ? `<code data-ioi-challenge-audience>${esc(c.audience)}</code> — the deployment's wallet capability account` : "none named — a grant without it could never be consumed, so the daemon refuses to approve one")}${row("Uses", "one — the grant is single-use, and it is minted for these coordinates only")}${row("Approval ref", c.approval_ref ? `${code(c.approval_ref)} — what the requester's retry names` : null)}</dl>
    ${c.published_preimage ? `<details><summary>The exact bytes the hashes commit to</summary><pre data-ioi-challenge-preimage>${esc(JSON.stringify(c.published_preimage, null, 2))}</pre></details>` : ""}
    <h2>Who asked, and when</h2>
    <dl class="grid">${row("Requested by", `<span data-ioi-challenge-requester>${personOf(dir, c.requester_ref)}</span>`)}${row("Asked", esc(c.created_at || "—"))}${row("Asked again", c.last_parked_at && Date.parse(c.last_parked_at) - Date.parse(c.created_at) > 1000 ? esc(c.last_parked_at) : null)}${row(s.key === "expired" ? "Expired" : "Expires", `<span data-ioi-challenge-expires>${esc(iso(c.expires_at_ms) || "—")}</span>`)}</dl>
    ${decided || c.grant_ref || c.consumed_at ? `<h2>Decision</h2><dl class="grid" data-ioi-challenge-decision-record>${decided ? row("Decided", `<span data-ioi-challenge-decided>${esc(decided.decision || "—")} by ${personOf(dir, decided.decided_by)} at ${esc(decided.decided_at || "—")}</span>`) : ""}${decided?.reason ? row("Reason", `<span data-ioi-challenge-reason>${esc(decided.reason)}</span>`) : ""}${decided?.reconciled_from ? row("Recorded", `<span data-ioi-challenge-reconciled>adopted from the authority's own record (${esc(decided.reconciled_from)}) after an interrupted approve — never minted twice</span>`) : ""}${decided?.outcome_unknown_at_denial?.reason ? row("Denied while", `<span data-ioi-challenge-denied-while-unknown>an interrupted approval's outcome was unknown (${code(decided.outcome_unknown_at_denial.reason)}); whatever the authority recorded, the daemon never presents it</span>`) : ""}${row("Grant", c.grant_ref ? `<code data-ioi-challenge-grant-ref>${esc(typeof c.grant_ref === "string" ? c.grant_ref : JSON.stringify(c.grant_ref))}</code>` : null)}${row("Grant expires", c.grant_expires_at_ms ? esc(iso(c.grant_expires_at_ms)) : null)}${row("Ran", c.consumed_at ? `<span data-ioi-challenge-consumed>${esc(c.consumed_at)}</span>` : null)}${row("Admitted as", c.consumed_by ? `<code data-ioi-challenge-consumed-by>${esc(c.consumed_by)}</code>` : null)}</dl>` : ""}
    ${decideSection(c, s, me, { passphraseField, dir })}
    ${history.length ? `<h2>${history.some((h) => h?.state === "interrupted") ? "Earlier asks and interrupted decisions" : history.some((h) => h?.state === "completed_by_presented_grant") ? "History of this challenge" : "Earlier asks for this exact effect"}</h2><table data-ioi-challenge-history-list><thead><tr><th>Closed as</th><th>When</th><th>Decision</th></tr></thead><tbody>${historyRows(history, dir)}</tbody></table>` : ""}
    ${s.key === "deciding" ? refreshScript(c.challenge_id) : ""}`;
  return { status: refusal ? refusal.status || 409 : 200, title: s.key === "pending" ? "Approve this effect?" : "Parked effect", inner: pageOf(inner) };
}

/** Every parked challenge, newest first (the daemon's order), each linking to its page. */
export function renderChallengeList({ read, who, principals = [], nowMs = Date.now() }) {
  const sub = "Every exact effect a daemon gate refused to run for want of a grant, parked for the operator's decision, newest first. Each opens its own page, where the operator approves it with the passphrase or denies it. The adopted <a href=\"/workspace/approvals-app\">Approvals app</a> lists them with the governance requests.";
  const list = read?.ok && Array.isArray(read.body?.challenges) ? read.body.challenges : null;
  if (!list) {
    const failed = readFailure(read, null);
    return { status: failed.status, title: "Parked effects", inner: pageOf(`<h1>Parked effects</h1><p class="sub">${sub}</p>${failed.inner}`) };
  }
  const dir = directoryOf(who, principals);
  const rows = list.filter((c) => c && c.challenge_id).map((c) => {
    const s = challengeStateOf(c, nowMs, dir);
    const e = effectOf(c);
    return `<tr data-ioi-challenge-row="${esc(c.challenge_id)}"><td><a href="${esc(challengePagePath(c.challenge_id))}">${esc(titleOf(c))}</a>${e.intent ? `<div class="meta" style="color:#878a93;font-size:12px">${esc(e.intent)}</div>` : ""}</td><td>${pill(s)}</td><td>${personOf(dir, c.requester_ref)}</td><td>${esc(c.created_at || "—")}</td></tr>`;
  });
  const pending = list.filter((c) => challengeStateOf(c, nowMs).key === "pending").length;
  const inner = `<h1>Parked effects</h1><p class="sub">${sub}</p>
    ${rows.length ? `<p class="meta" data-ioi-challenge-count="${pending}">${pending} waiting for the operator · ${rows.length} in all</p><table><thead><tr><th>Effect</th><th>State</th><th>Requested by</th><th>Asked</th></tr></thead><tbody>${rows.join("")}</tbody></table>` : `<div class="empty" data-ioi-challenge-count="0">No effect is parked: no daemon gate has refused one for want of a grant.</div>`}`;
  return { status: 200, title: "Parked effects", inner: pageOf(inner) };
}

// dead-control-census — pure judgement over controls measured out of a real browser (R-240).
//
// check:named-gap-perception judges the controls the estate DECLARES unavailable. It cannot see the
// more dangerous population: a control that carries no marker, no aria-disabled, looks live — and
// does nothing. That one reads as a promise. This module decides, for records a browser captured,
// which elements belong to that population, how each must be EXERCISED, and what the outcome of the
// exercise means. It reaches no browser, file, clock or network, so a census captured by anyone can
// be re-judged by anyone.

// Roles whose whole meaning is "activating me does something".
export const CLICK_ROLES = Object.freeze([
  "button", "link", "tab", "menuitem", "menuitemcheckbox", "menuitemradio", "checkbox", "switch",
  "option", "radio", "treeitem", "combobox",
]);

// Text-entry input types: exercised by TYPING, then by Enter.
export const TEXT_TYPES = Object.freeze(["", "text", "search", "email", "url", "tel", "number", "password"]);
// A date-like input is a field too, but "zq" is not a value it accepts and a click only opens the
// browser's picker (R-240: the Issues date-range facets read dead that way). It is exercised by
// setting a valid value, which is what a person choosing a date does.
export const DATE_TYPES = Object.freeze(["date", "datetime-local", "month", "week", "time"]);

// Slower than this and a person decides the link is broken before it answers.
export const SLOW_LANDING_MS = 5000;

// The five things a live control can change. All five unmoved is a dead control.
export const SIGNALS = Object.freeze(["url", "dom", "network", "state", "other"]);

// A reference lane is EVIDENCE ONLY (apps/hypervisor/AGENTS.md): `/__apps/*` on the serve, or the
// developer's reference-capture origin. Whether it answers depends on whether somebody's capture server is
// running, so it can never share a pin with product links.
export const CAPTURE_PORT = "9225";

export function isReferenceLane(url, serveOrigin) {
  let u;
  try { u = new URL(url); } catch { return false; }
  if (u.port === CAPTURE_PORT && (u.hostname === "localhost" || u.hostname === "127.0.0.1")) return true;
  return u.origin === serveOrigin && u.pathname.startsWith("/__apps/");
}

// Is this raw element record part of the live-looking population?
//
// A DECLARED GAP IS NOT: aria-disabled, native disabled, inert, or sitting inside one belongs to
// check:named-gap-perception, and neither census may absorb the other. A bare tabindex is NOT a
// control either — a scroll region is focusable so a keyboard can reach it, not so it can be
// activated — and a label's liveness is its control's, so neither is judged on its own.
export function isLiveLooking(el) {
  if (!el || el.visible !== true || el.declared === true) return false;
  const intrinsic = el.tag === "A" ? !!el.href
    : ["BUTTON", "SELECT", "TEXTAREA", "SUMMARY"].includes(el.tag)
      || (el.tag === "INPUT" && el.type !== "hidden")
      || el.onclick === true || el.contentEditable === true
      || CLICK_ROLES.includes(el.role || "");
  const pointerTop = el.cursor === "pointer" && el.parentCursor !== "pointer";
  if (!intrinsic && !pointerTop) return false;
  // The inner span of a link is the link; judging it separately double-counts one control.
  if (el.nestedInControl === true && !["INPUT", "SELECT", "TEXTAREA"].includes(el.tag)) return false;
  return true;
}

// How must this control be exercised? A click on a field proves nothing: the first census clicked
// seven form fields, saw nothing move, and called them dead.
//
// A contenteditable editor is a text field too (the adopted Approvals app's comment box: a click only put the caret in
// it, and it read dead). It is TYPED into only by a census that measures the field's own echo (editableEcho, and
// echoOnly below): typed words are page text, so a census that does not measure the echo would call every editor alive
// for showing what was typed — that census keeps clicking.
export function exerciseFor(el, { editableEcho = false } = {}) {
  if (el.tag === "A" && el.href) {
    if (el.href.startsWith("#")) return el.href.length > 1 ? "fragment" : "click";
    if (/^javascript:/iu.test(el.href)) return "click";
    return "fetch";
  }
  // A handle whose cursor says RESIZE is exercised by DRAGGING it: the shell's sidebar handle clicked
  // moved nothing and read dead, exactly as a clicked text field did before clause 2.
  if (/^(ew|ns|col|row|e|w|n|s)-resize$/u.test(el.cursor || "")) return "drag";
  if (el.tag === "SELECT") return "select";
  if (el.tag === "TEXTAREA" || (el.tag === "INPUT" && TEXT_TYPES.includes(el.type || "")) || (editableEcho && el.contentEditable === true)) return "type";
  if (el.tag === "INPUT" && DATE_TYPES.includes(el.type || "")) return "date";
  if (el.tag === "INPUT" && (el.type === "checkbox" || el.type === "radio")) return "toggle";
  return "click";
}

// What a TYPED field is typed (R-240, verifier hygiene, 2026-09-29). A number field is typed a NUMBER: "zq" is not a
// value it accepts, Playwright refuses to type letters into it, and the census scored Functions' number input
// click_failed for the census's own mistake. Every other text-entry type takes "zq".
export function typedValueFor(type) {
  return type === "number" ? "7" : "zq";
}

// A value each date-like input type accepts (far enough ahead that it never matches seeded data).
export function dateValueFor(type) {
  return { date: "2030-01-01", "datetime-local": "2030-01-01T09:00", month: "2030-01", week: "2030-W01", time: "09:00" }[type] || "2030-01-01";
}

// What did the exercise prove?
//
// alive          — at least one of the five signals moved.
// alive_by_form  — a field whose own change moves nothing, inside a form that CAN submit: its value
//                  is consumed when the form is sent, which is exactly what a form field is for.
// dead           — nothing moved and nothing can carry it later. The Object Explorer's saved-set
//                  Name field was this: typed into, Enter pressed, and its form's only submit was
//                  disabled — so every exit was closed.
// click_failed   — the control could not be activated at all (covered, detached, off-screen).
// (outcome.how: the exercise the census performed, when it chose one exerciseFor's defaults do not — a typed editor)
export function exerciseVerdict(el, outcome) {
  if (outcome?.error) return { verdict: "click_failed", why: String(outcome.error).slice(0, 160) };
  const moved = SIGNALS.filter((s) => outcome?.signals?.[s] === true);
  if (moved.length) return { verdict: "alive", why: moved.join(",") };
  const field = ["select", "type", "toggle", "date"].includes(outcome?.how || exerciseFor(el));
  if (field && el.formCanSubmit === true) return { verdict: "alive_by_form", why: "its form has an enabled submit" };
  if (!field && isSelfControl(el)) return { verdict: "self", why: "it points at where you already are" };
  return { verdict: "dead", why: field ? "a field whose change moves nothing and whose form cannot submit" : "activated, and none of the five signals moved" };
}

// Where did a link land?
export function landingVerdict(link, serveOrigin) {
  if (link.exercise === "fragment") {
    return link.fragmentTargetExists ? { verdict: "alive", why: "fragment target exists" } : { verdict: "dead_anchor", why: `no element with id ${link.href.slice(1)}` };
  }
  if (isReferenceLane(link.abs, serveOrigin)) return { verdict: "reference_lane", why: link.status != null ? `answered ${link.status}` : String(link.failure || "no answer") };
  if (link.failure || link.status == null) return { verdict: "bad_landing", why: String(link.failure || "no status").slice(0, 120) };
  // THE SIGN-IN WALL LANDS (R-240, verifier hygiene, 2026-09-29): a 401 page whose body offers the product's own sign-in
  // is where a signed-out person is SENT — the shipped product answers every signed-out visit with sign-in — not a
  // broken link. Only 401, and only with the sign-in link in the answer: a bare 401, a 403, a 404 stay bad landings.
  if (link.status === 401 && link.signInOffered === true) return { verdict: "alive", why: "status 401 with the product's sign-in offered (the sign-in wall)" };
  if (link.status >= 400) return { verdict: "bad_landing", why: `status ${link.status}` };
  if (link.ms > SLOW_LANDING_MS) return { verdict: "slow_landing", why: `${link.ms}ms > ${SLOW_LANDING_MS}ms` };
  return { verdict: "alive", why: `status ${link.status}` };
}

// Does a landing's body offer the product's sign-in (an anchor to /__ioi/login or /login)? Judged over bytes the census
// fetched, so a relying party can re-judge it.
export const SIGN_IN_HREF = /href="(?:\/__ioi\/login|\/login)(?:[?#"])/u;
export function offersSignIn(body) {
  return SIGN_IN_HREF.test(String(body || ""));
}

// A raw capture-origin href is a hard-coded developer URL in product copy: on any machine without
// the capture server running it is a browser error page, not even the serve's honest 503.
export function isRawCaptureHref(abs) {
  try { const u = new URL(abs); return u.port === CAPTURE_PORT; } catch { return false; }
}

// ---- THE OWNED SHELL (clause 8, R-240) ----------------------------------------------------------
// The shell is a single-page app, and three things a server-rendered surface never does break the
// census there unless they are judged here.

// 1. ITS READS ARE POSTS. Connect calls go out as POST /api/<pkg>.v1.<Service>/<Method>; refusing every
// non-GET would stop the shell booting. A request is a READ when its verb is, or when it is a Connect
// call whose method NAME is a read — and a read-looking name that carries a write verb is not.
export const READ_RPC = /^(Get|List|Watch|Check|Resolve|Validate|Parse|Search|Describe|Count|Is|Preview)[A-Z]/u;
export const WRITE_VERB = /(Create|Update|Delete|Start|Stop|Set|Mark|Reset|Regenerate|Send|Accept|Join|Remove|Revoke|Cancel)/u;
export function isReadRequest(method, url) {
  if (["GET", "HEAD", "OPTIONS"].includes(method)) return true;
  if (method !== "POST") return false;
  let pathname;
  try { pathname = new URL(url).pathname; } catch { return false; }
  const m = /^\/api\/[a-z]+\.v1\.[A-Za-z]+\/([A-Za-z]+)$/u.exec(pathname);
  return !!m && READ_RPC.test(m[1]) && !WRITE_VERB.test(m[1]);
}

// 2. IT NEVER GOES QUIET: it polls, streams and animates, so "a request fired" or "a node mutated"
// would call every control alive. Its signals are measured against the page AT REST — a request is
// the control's only if its key was not already heard while nobody touched anything, and the DOM
// moved only if what a person can READ changed (visible text, or an overlay opened or closed). And
// a menu item is judged against the page BEFORE its menu opened: an item whose only effect is its own
// menu closing did nothing — the account menu's Support was exactly that, and read as alive.
export function requestKey(method, url) {
  try { const u = new URL(url); return `${method} ${u.pathname}`; } catch { return `${method} ${url}`; }
}
// A FIELD'S OWN ECHO IS NOT A SIGNAL. An input's typed value is no part of the page's text, so typing into one never moved
// "dom" by itself — what counts is whether anything carries the value. A contenteditable editor's text IS page text (and
// its placeholder with it): typing into the adopted Approvals app's comment box moved the text by the typed words alone.
// The page moved only by that echo when putting the field's text after in place of its text before, at a place where it
// occurs, gives the page's text after (spacing and zero-width characters aside). fieldBefore/fieldAfter are null for
// every exercise but typing into a contenteditable, and then this never excuses anything.
const flat = (s) => String(s ?? "").replace(/[\u200B-\u200D\uFEFF]/gu, "").replace(/\s+/gu, " ").trim();
export function echoOnly({ textBefore, textAfter, fieldBefore, fieldAfter }) {
  if (fieldBefore == null || fieldAfter == null) return false;
  const a = flat(textBefore), b = flat(textAfter), fa = flat(fieldBefore), fb = flat(fieldAfter);
  if (a === b) return true;
  if (!fa) { // the field was empty: exactly its new text appeared, in one place
    for (let i = b.indexOf(fb); fb && i !== -1; i = b.indexOf(fb, i + 1)) if (flat(b.slice(0, i) + b.slice(i + fb.length)) === a) return true;
    return false;
  }
  for (let i = a.indexOf(fa); i !== -1; i = a.indexOf(fa, i + 1)) if (flat(a.slice(0, i) + fb + a.slice(i + fa.length)) === b) return true;
  return false;
}
export function spaSignals(m) {
  const rest = new Set(m.restKeys || []);
  return {
    url: m.urlBefore !== m.urlAfter,
    dom: (m.textBefore !== m.textAfter && !echoOnly(m)) || m.overlaysBefore !== m.overlaysAfter,
    network: (m.blocked || 0) > 0 || (m.requestKeys || []).some((k) => !rest.has(k)),
    state: m.stateMoved === true,
    other: (m.other || 0) > 0,
  };
}

// 3. EVERY PATH ANSWERS 200. The shell serves itself for any route, so fetching a link proves nothing
// (/changelog answered 200 and rendered "This page doesn't exist"). Its links are CLICKED, and a route
// the click opened must render something.
export const SPA_NOT_FOUND = /looked everywhere|this page doesn.t exist/iu;
export const SPA_MIN_TEXT = 40;
// 4. A CLICK THAT CRASHES THE PAGE MOVES THE DOM. The adopted Pipeline Builder's Deploy button swapped the editor for
// the app's error boundary ("Something went wrong when rendering the pipeline") and was scored alive for it. What a
// click LEADS TO is judged too: an error boundary the page did not show before the click is a crash, whatever moved.
export const ERROR_BOUNDARY = /Something went wrong when rendering|Something went wrong while rendering|An unexpected error has occurred|Application error: a client-side exception/iu;
export function crashVerdict({ textBefore, textAfter }) {
  const hit = String(textAfter || "").match(ERROR_BOUNDARY);
  if (!hit || ERROR_BOUNDARY.test(String(textBefore || ""))) return null;
  return { verdict: "crashed", why: `the page fell to its error boundary: "${hit[0]}"` };
}
// 5. A TAB A CLICK OPENS MUST LAND TOO. A new tab counted as "something happened" and was closed unread, so a link opening
// the shell's not-found page in a new tab read alive — the adopted Approvals app's Documentation (the reference's
// /docs/foundry/… path, 2026-09-28) was one. A tab on this serve is judged as a same-tab navigation is: it must answer, and
// render something that is not the not-found page or an error boundary. A tab on another origin (or one that never left
// about:blank) is not this serve's to judge.
export function popupLandingVerdict({ url, status, text }, serveOrigin) {
  let u;
  try { u = new URL(url); } catch { return null; }
  if (u.origin !== serveOrigin) return null;
  if (status != null && status >= 400) return { verdict: "bad_landing", why: `the tab it opened (${u.pathname}) answered ${status}` };
  const t = String(text || "").trim();
  const crash = t.match(ERROR_BOUNDARY);
  if (crash) return { verdict: "crashed", why: `the tab it opened (${u.pathname}) fell to its error boundary: "${crash[0]}"` };
  if (SPA_NOT_FOUND.test(t)) return { verdict: "bad_landing", why: `the tab it opened (${u.pathname}) is the shell's not-found page` };
  if (t.length < SPA_MIN_TEXT) return { verdict: "bad_landing", why: `the tab it opened (${u.pathname}) rendered nothing` };
  return null;
}
export function spaLandingVerdict({ urlChanged, text }) {
  if (!urlChanged) return null;
  const t = String(text || "").trim();
  if (t.length < SPA_MIN_TEXT) return { verdict: "bad_landing", why: "the route it opened rendered nothing" };
  if (SPA_NOT_FOUND.test(t)) return { verdict: "bad_landing", why: "the route it opened is the shell's not-found page" };
  return null;
}

// Which same-origin paths does the SHELL answer? Everything the serve does not render itself. A link
// from a registered surface into one of them is FETCHED as 200 whatever the shell then draws —
// "Open Workbench" on the Environments surface linked /workspaces/<id>, the shell's not-found page, on
// every row, and the fetch called it alive. Such a link must be RENDERED and read.
export const SERVE_RENDERED = /^\/(__ioi|__apps|v1|api|auth|scim|static|assets|changelog|join-organization|ioi-augmentation\.js)(\/|$|\?)/u;
export function isShellPath(pathname) {
  const p = String(pathname || "");
  if (!p.startsWith("/") || SERVE_RENDERED.test(p)) return false;
  return !/\.[a-z0-9]{2,5}$/iu.test(p); // a file, not a route
}

// A control that moved nothing because it points at WHERE YOU ALREADY ARE is not dead: the link to the
// page you are on, the tab already selected. "Login Configuration" in its own settings nav was one.
export function isSelfControl(el) {
  return el?.selfLink === true || el?.current === true;
}

export function censusTotals(rows) {
  const t = { live_looking: 0, exercised: 0, alive: 0, alive_by_form: 0, dead: 0, click_failed: 0, links_unique: 0, bad_landing: 0, slow_landing: 0, dead_anchor: 0, reference_lane: 0, raw_capture_href: 0 };
  for (const r of rows) {
    t.live_looking += r.count || 1;
    if (r.kind === "link") {
      t.links_unique += 1;
      if (r.verdict === "reference_lane" && isRawCaptureHref(r.abs || "")) t.raw_capture_href += 1;
    } else {
      t.exercised += 1;
    }
    if (r.verdict in t) t[r.verdict] += 1;
  }
  return t;
}

// The surface interaction kit (functional-runtime wave) — shared primitives every app module
// builds interaction from. Introduced with the Pipeline extraction; DELIBERATELY UNWIRED there
// (the extraction PR changes zero behavior) — node selection/inspectors wire these next.
//
// Design rules the kit encodes:
//   · The URL is the selection's single source of truth — refresh-preserving, deep-linkable
//     (parseSelection reads it, selectionQuery writes it with stable key order).
//   · A command is either a real daemon authority or a VISIBLE disabled control that names its
//     reason (disabledCommand) — never hidden, never a silent no-op.
//   · Detail panes and trays are shells the app fills with daemon truth (inspectorShell,
//     trayShell); proof always deep-links into the owning record (proofLink).
//   · Data-driven body regions announce themselves for the pixel harness's semantic-mask lane
//     (semanticMask) instead of being guessed at by selector.

// THE canonical HTML escaper — one definition estate-wide (moved from the serve's CX_ESC;
// serve and every surface module alias this).
export const escHtml = (s) => String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

const TIMELINE_COMPONENT = /^[A-Za-z0-9._~-]+$/;

// A PLANE THAT DID NOT ANSWER IS NOT AN EMPTY PLANE (R-240). Loaders carry each read's typed outcome
// on `degraded` "so a pane can name WHY, not just render absence" — and the panes never read it: with
// the daemon stopped, Data sources said "No data sources declared yet" about a registry it never
// read. This renders the outcome where a surface would otherwise draw absence as "none yet".
export function degradedNotice(degraded, labels = {}) {
  const keys = Object.keys(degraded || {});
  if (!keys.length) return "";
  const kinds = keys.map((k) => refusalKind(degraded[k] && degraded[k].code, degraded[k] && degraded[k].status));
  const items = keys.map((k, i) => `<li><b>${escHtml(labels[k] || k)}</b> — ${escHtml(REFUSAL_LEAD[kinds[i]])} <code>${escHtml((degraded[k] && degraded[k].code) || "unavailable")}</code>${degraded[k] && degraded[k].message ? ` ${escHtml(String(degraded[k].message).slice(0, 160))}` : ""}</li>`).join("");
  const head = kinds.every((k) => k === "unavailable") ? "The daemon did not answer every read on this page." : "Not every read on this page came back.";
  return `<div role="status" data-testid="degraded-notice" style="margin:12px 0;padding:10px 14px;border:1px solid #d1980b;border-radius:6px;background:rgba(209,152,11,.08);color:inherit;font-size:13px;line-height:1.5"><b>${head}</b> What follows may be incomplete, and an empty list below is not an empty registry:<ul style="margin:6px 0 0 18px;padding:0">${items}</ul>${kinds.includes("signed_out") ? `<div style="margin-top:6px">${SIGN_IN_LINK}</div>` : ""}</div>`;
}

// A REFUSAL IS NOT AN OUTAGE (R-240). The daemon answers a signed-out caller 401
// `request_principal_required` in a FLAT `{code, message}` body; other planes nest `{error:{code}}`
// or answer `{reason}`. Surfaces that read only `error.code` called a signed-out visitor's refusal
// `plane_unavailable`, and the ones that did read it still printed "did not answer" — a page that
// tells you the daemon is down when the answer is "sign in" sends you to the wrong fix.
export function refusalCodeOf(payload, status) {
  return payload?.error?.code || payload?.reason || payload?.code || (status ? `http_${status}` : "daemon_unavailable");
}
export function refusalMessageOf(payload) {
  return String(payload?.error?.message || payload?.message || "").slice(0, 300);
}
// Only a 4xx is a refusal; a 5xx, a timeout, an unreachable daemon or a payload off its contract is
// an outage, and says "unavailable".
export function refusalKind(code, status) {
  const c = String(code || "");
  if (status === 401 || c === "request_principal_required" || c === "unauthenticated") return "signed_out";
  if (status === 403 || c === "permission_denied") return "denied";
  if (status >= 400 && status < 500) return "refused";
  return "unavailable";
}
export const REFUSAL_LEAD = {
  signed_out: "answers signed-in callers only, and you are signed out —",
  denied: "refused this caller —",
  refused: "refused the read —",
  unavailable: "unavailable —",
};
export const SIGN_IN_LINK = `<a href="/__ioi/login" target="_top">Sign in</a> to read it.`;

// Daemon-owned timeline refs are navigable only when they name an exact internal timeline path.
// Keep this stricter than generic URL parsing: parsing would normalize traversal before validation.
export function canonicalTimelineRef(reference) {
  if (typeof reference !== "string" || reference.length === 0 || reference.length > 512) return "";
  const prefix = "/__ioi/run-timeline/";
  if (!reference.startsWith(prefix)) return "";
  const components = reference.slice(prefix.length).split("/");
  if (!components.length || components.some((component) =>
    !TIMELINE_COMPONENT.test(component) || component === "." || component === "..")) return "";
  return reference;
}

// Read the selection state carried by a URL: only the requested keys, only non-empty values.
export function parseSelection(url, keys) {
  const out = {};
  for (const k of keys) {
    const v = url.searchParams.get(k);
    if (v !== null && v !== "") out[k] = v;
  }
  return out;
}

// Serialize selection state onto a route with a STABLE query (sorted keys, empties dropped) so
// the same selection always produces the same URL — comparable, cacheable, diff-friendly.
export function selectionQuery(route, sel) {
  const q = Object.entries(sel || {})
    .filter(([, v]) => v !== undefined && v !== null && v !== "")
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`)
    .join("&");
  return q ? `${route}?${q}` : route;
}

// Right-panel detail shell: the app supplies the (already-escaped) body; the shell supplies the
// stable ids/testids the interaction verifiers drive.
export function inspectorShell({ id, title, subtitle, body, cls }) {
  return `<div id="${escHtml(id)}" class="ioi-inspector${cls ? " " + escHtml(cls) : ""}" data-testid="ioi-inspector">` +
    `<div class="ioi-inspector-hd"><span class="ioi-inspector-title">${escHtml(title)}</span>` +
    (subtitle ? `<span class="ioi-inspector-sub">${escHtml(subtitle)}</span>` : "") +
    `</div><div class="ioi-inspector-body">${body || ""}</div></div>`;
}

// Bottom preview/proof tray shell — same contract as inspectorShell.
export function trayShell({ id, title, body, cls }) {
  return `<div id="${escHtml(id)}" class="ioi-tray${cls ? " " + escHtml(cls) : ""}" data-testid="ioi-tray">` +
    `<div class="ioi-tray-hd">${escHtml(title)}</div><div class="ioi-tray-body">${body || ""}</div></div>`;
}

// A visible command that is not backed by an existing daemon authority: disabled IN PLACE with
// the reason named (title + data attribute the action verifiers assert on). Never hidden.
export function disabledCommand({ label, reason, cls }) {
  return `<button type="button" disabled aria-disabled="true" class="ioi-cmd-disabled${cls ? " " + escHtml(cls) : ""}"` +
    ` title="${escHtml(reason)}" data-ioi-disabled-reason="${escHtml(reason)}">${escHtml(label)}</button>`;
}

// Deep link into the owning daemon record (receipt, timeline, ledger entry, …).
export function proofLink({ href, label, external }) {
  return `<a class="ioi-proof-link" data-testid="ioi-proof-link" href="${escHtml(href)}"` +
    (external ? ` target="_blank" rel="noopener"` : "") + `>${escHtml(label)} ↗</a>`;
}

// Mark a data-driven body region for the pixel harness's semantic-mask lane: the region is live
// daemon truth (excluded from shell-pixel diffing by id, verified semantically instead).
export function semanticMask(id, inner) {
  return `<span data-ioi-sem-mask="${escHtml(id)}">${inner}</span>`;
}

// ---- GRE-1 LIGHT BODY CONTRACT (owner ruling "GRE-1 ADOPT", remediation plan §7) --------------
//
// The greenfield platform surfaces adopt the DARK-RAIL + LIGHT-BODY chrome contract: the platform
// session rail stays dark, the SURFACE BODIES render in the reference grammar the certified ports
// already speak (mst-* / ing-* / sch-* / bld-* / rgy-*). This is a BODY-THEME RE-SKIN OVER
// UNCHANGED TRUTH BINDINGS — it ends the two-worlds effect between a light certified port and the
// dark greenfield readout beside it, and it changes no daemon read, no predicate, no count, no
// marker, no link and no copy string.
//
// ONE token source, referenced by every opted-in handler (never six copy-pasted palettes):
//   GRE1_LIGHT           the palette values
//   GRE1_LIGHT_FONT_FACES the adopted typography (the faces the estate already serves)
//   GRE1_LIGHT_BODY_CSS  the shell-vocabulary override layer
//
// DISCIPLINE the block enforces on itself: GRE1_LIGHT_BODY_CSS declares COLOUR and TYPOGRAPHY
// properties ONLY — background, color, border-color, border-*-color, box-shadow, font, @font-face.
// It declares NO layout property (no display / grid / flex / width / height / margin / padding /
// position), so the re-skin provably cannot move a single box. Structure, data markers, responsive
// behaviour and every gap contract stay exactly where the dark shell put them.
export const GRE1_LIGHT = {
  bg: "#fff",              // page ground
  surface: "#f6f7f9",      // recessed panel / hover band
  text: "#1c2127",         // primary text
  text2: "#404854",        // secondary-strong (chips, labels)
  muted: "#5f6b7c",        // muted text — the floor for legibility on white (never #878a93)
  faint: "#7b8494",        // footnote text
  dash: "#a8b2be",         // typed-absence dash / graph edges
  border: "#e5e8eb",       // panel + table-head border
  border2: "#d1d1d1",      // control border
  rowline: "#f0f2f5",      // table row rule
  link: "#215db0",         // link + link-on-white accent
  accent: "#2d72d2",       // interactive accent (primary button, selected border)
  selBg: "#e8eef7",        // selected row / on-chip ground
  codeBg: "#f0f2f5",       // inline code ground
  okText: "#1c6e42", okBorder: "#9bc4ab", okBg: "#eef8f2",
  warnText: "#946638", warnBorder: "#f0dca6", warnBg: "#fff8e6",
  dangerText: "#a82a2a", dangerBorder: "#eab8b8", dangerBg: "#fdf0f0",
  font: "Source-Sans-Pro,Helvetica,sans-serif",
};

// The adopted typography, declared exactly as the changes port declares it (the estate already
// serves these three faces at /__ioi/fonts/*). font-display:swap so a cold cache never blanks the
// body text a verifier or a screenshot is reading.
export const GRE1_LIGHT_FONT_FACES = `
  @font-face{font-family:'Source-Sans-Pro';font-style:normal;font-weight:400;font-display:swap;src:url(/__ioi/fonts/source-sans-pro-400.woff2) format('woff2')}
  @font-face{font-family:'Source-Sans-Pro';font-style:normal;font-weight:600;font-display:swap;src:url(/__ioi/fonts/source-sans-pro-600.woff2) format('woff2')}
  @font-face{font-family:'Source-Sans-Pro';font-style:normal;font-weight:700;font-display:swap;src:url(/__ioi/fonts/source-sans-pro-700.woff2) format('woff2')}`;

// The override layer for the shared platform-shell vocabulary (.wrap/.card/.pill/.grid/.tabs/
// .chip/.wl*/.c*/.field — the classes automationsShell owns). Appended INSIDE that shell's own
// stylesheet, after its dark rules, for the surfaces that opt in with { theme: "light" }: every
// caller that does not opt in still renders the dark shell byte-for-byte.
export const GRE1_LIGHT_BODY_CSS = `${GRE1_LIGHT_FONT_FACES}
  :root{color-scheme:light}
  body{background:${GRE1_LIGHT.bg};color:${GRE1_LIGHT.text};font:14px/1.55 ${GRE1_LIGHT.font}}
  a{color:${GRE1_LIGHT.link}}
  .brand{color:${GRE1_LIGHT.muted}}
  .sub{color:${GRE1_LIGHT.muted}}
  .act{background:${GRE1_LIGHT.accent};color:#fff}
  .act:hover{background:${GRE1_LIGHT.link}}
  .act.ghost{background:transparent;color:${GRE1_LIGHT.link};border-color:${GRE1_LIGHT.border2}}
  .act.ghost:hover{color:${GRE1_LIGHT.link};border-color:${GRE1_LIGHT.accent};background:${GRE1_LIGHT.surface}}
  .act.danger{background:transparent;color:${GRE1_LIGHT.dangerText};border-color:${GRE1_LIGHT.dangerBorder}}
  .act.danger:hover{background:${GRE1_LIGHT.dangerBg}}
  h2{color:${GRE1_LIGHT.muted}}
  .card{border-color:${GRE1_LIGHT.border};background:${GRE1_LIGHT.bg}}
  a.card:hover{border-color:${GRE1_LIGHT.accent};background:${GRE1_LIGHT.surface}}
  .card .name{color:${GRE1_LIGHT.text}}
  .card .meta{color:${GRE1_LIGHT.muted}}
  .ok{color:${GRE1_LIGHT.okText};border-color:${GRE1_LIGHT.okBorder};background:${GRE1_LIGHT.okBg}}
  .warn{color:${GRE1_LIGHT.warnText};border-color:${GRE1_LIGHT.warnBorder};background:${GRE1_LIGHT.warnBg}}
  .muted{color:${GRE1_LIGHT.muted};border-color:${GRE1_LIGHT.border2};background:${GRE1_LIGHT.surface}}
  .empty{color:${GRE1_LIGHT.muted};border-color:${GRE1_LIGHT.border2};background:${GRE1_LIGHT.surface}}
  .grid{border-color:${GRE1_LIGHT.border};background:${GRE1_LIGHT.surface}}
  .grid dt{color:${GRE1_LIGHT.muted}}
  .grid dd{color:${GRE1_LIGHT.text}}
  code{color:${GRE1_LIGHT.text2};background:${GRE1_LIGHT.codeBg}}
  pre{background:${GRE1_LIGHT.surface};border-color:${GRE1_LIGHT.border};color:${GRE1_LIGHT.text}}
  .reveal{color:${GRE1_LIGHT.okText};background:${GRE1_LIGHT.okBg};border-color:${GRE1_LIGHT.okBorder}}
  th{color:${GRE1_LIGHT.muted};border-bottom-color:${GRE1_LIGHT.border}}
  td{border-bottom-color:${GRE1_LIGHT.rowline}}
  .tabs{border-bottom-color:${GRE1_LIGHT.border}}
  .tab{color:${GRE1_LIGHT.muted}}
  .tab:hover{color:${GRE1_LIGHT.text}}
  .tab.active{color:${GRE1_LIGHT.text};border-bottom-color:${GRE1_LIGHT.accent}}
  .cgraph{border-color:${GRE1_LIGHT.border};background:${GRE1_LIGHT.surface}}
  .cedge{color:${GRE1_LIGHT.dash}}
  .cnode{border-color:${GRE1_LIGHT.border2};background:${GRE1_LIGHT.bg}}
  .cnode:hover{border-color:${GRE1_LIGHT.accent}}
  .cnode.sel{border-color:${GRE1_LIGHT.accent};box-shadow:0 0 0 1px ${GRE1_LIGHT.accent} inset}
  .cnode.ok{border-left-color:${GRE1_LIGHT.okText}}
  .cnode.warn{border-left-color:${GRE1_LIGHT.warnText}}
  .cnode .ct{color:${GRE1_LIGHT.text}}
  .cnode .cs{color:${GRE1_LIGHT.muted}}
  .cinsp{border-color:${GRE1_LIGHT.border};background:${GRE1_LIGHT.bg}}
  .cmsg{color:${GRE1_LIGHT.warnText}}
  .chiplabel{color:${GRE1_LIGHT.muted}}
  .chip{background:${GRE1_LIGHT.bg};border-color:${GRE1_LIGHT.border2};color:${GRE1_LIGHT.text2}}
  .chip:hover{border-color:${GRE1_LIGHT.accent}}
  .chip.on{background:${GRE1_LIGHT.selBg};border-color:${GRE1_LIGHT.accent};color:${GRE1_LIGHT.link}}
  .wlrow:hover td{background:${GRE1_LIGHT.surface}}
  .wlrow.selrow td{background:${GRE1_LIGHT.selBg}}
  .wldrawer{border-color:${GRE1_LIGHT.border};background:${GRE1_LIGHT.bg}}
  .wldrawer h4{color:${GRE1_LIGHT.muted}}
  .wlk{color:${GRE1_LIGHT.muted}}
  .wlv{color:${GRE1_LIGHT.text}}
  .wlbl li{border-bottom-color:${GRE1_LIGHT.rowline}}
  .wlbl a{color:${GRE1_LIGHT.link}}
  .field label{color:${GRE1_LIGHT.text2}}
  .field input,.field select,.field textarea{border-color:${GRE1_LIGHT.border2};background:${GRE1_LIGHT.bg};color:${GRE1_LIGHT.text}}`;

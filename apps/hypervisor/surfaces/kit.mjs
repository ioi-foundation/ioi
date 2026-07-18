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

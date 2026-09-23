// NAMED-GAP PERCEPTION — does a control the estate has declared unavailable actually READ as
// unavailable to the person looking at it?
//
// THIS FILE REACHES NOTHING. No DOM, no browser, no serve, no clock. It takes plain records of
// already-measured computed style and returns findings, so the judgement can be drilled and
// mutation-tested without a browser, and so a relying party can re-derive the same verdict from a
// census someone else captured.
//
// WHY IT EXISTS. Every surface parity verifier in this estate asserts the same two things about a
// declared gap: `aria-disabled="true"` and a `title` containing "named gap". Both were true of the
// Solution Designer's `New Diagram` while it rendered as a solid green primary button with an
// ordinary arrow cursor — because the markup carries `class="dsg-hbtn success gap"` and NO
// `.dsg-hbtn.gap` rule was ever written. An attribute assertion cannot see that. Measured
// 2026-09-23 across all 36 registered surfaces: 272 labelled gap controls, of which 18 render as
// primary actions, 68 carry a cursor that says "clickable", 242 are `aria-disabled` on an element
// assistive technology does not treat as a control at all, and 47 carry the marker class with no
// `aria-disabled` whatsoever — invisible to every existing gate, because every existing gate keys
// on the attribute those 47 do not have.
//
// THE CONVENTION IS NOT INVENTED HERE. The estate already ships it on seven selectors
// (`.vtx-hbtn.gap`, `.vtx-view.gap`, `.mon-frow.gap`, `.mnc-tab.gap` = muted grey + `not-allowed`;
// `.dsg-pill.gap`, `.evl-pill.gap`, `.mch-pill.gap` = a low-alpha grey fill). What was missing was
// a definition shared by the other surfaces that use the same marker, and anything that checks it.

/**
 * The marker tokens that declare "this control is a named gap", as USED rather than as intended.
 *
 * MEASURED FROM THE SOURCE, not designed: `gap` is the shared one, and ten surfaces each minted a
 * private spelling instead. Listing them here is what lets the gate say how many marker vocabularies
 * exist, which is the real finding — a convention with eleven spellings is a convention nobody can
 * apply by habit.
 */
export const GAP_MARKER_TOKENS = Object.freeze([
  "gap", "mst-gap", "sch-gap", "rgy-gap", "mapp-gap", "ins-gap",
  "ing-gap", "inf-gap", "fus-gap", "dcx-gap", "bld-gap",
]);

/**
 * Tokens that contain "gap" and are NOT control markers. `*-gapnote` is explanatory PROSE — a
 * paragraph saying what is unavailable and why. Dimming it would hide the explanation, which is the
 * one thing on the surface doing its job. Excluded by name rather than by a pattern, because a
 * pattern that guessed would eventually swallow a control.
 */
export const NOT_CONTROL_MARKERS = Object.freeze(["dsg-gapnote", "mch-gapnote", "evl-gapnote", "src-gapnote", "pb-gapnote", "gaps"]);

/** Channel spread above which a colour is not grey. */
export const SATURATION_FLOOR = 40;
/** Alpha above which a background actually reads as a fill rather than a tint. */
export const FILL_ALPHA_FLOOR = 0.3;

/** Parse `rgb()` / `rgba()` exactly as `getComputedStyle` serializes it. Anything else is null. */
export function parseColor(value) {
  const match = String(value ?? "").match(/^rgba?\(([^)]+)\)$/u);
  if (match === null) return null;
  const parts = match[1].split(",").map((p) => Number.parseFloat(p.trim()));
  if (parts.length < 3 || parts.slice(0, 3).some((n) => !Number.isFinite(n))) return null;
  const alpha = parts.length > 3 ? parts[3] : 1;
  return { r: parts[0], g: parts[1], b: parts[2], a: Number.isFinite(alpha) ? alpha : 1 };
}

/** Element opacity at or below which a fill has been deliberately dimmed out of prominence. */
export const DIMMED_OPACITY_CEILING = 0.8;

/**
 * A fill reads as a PRIMARY action when it is saturated, opaque, AND not dimmed by the element's
 * own opacity. All three are required, and each one exists because leaving it out was wrong:
 *
 *   SATURATION — the estate's gap fill is grey `rgba(143,153,168,.15)`; without this test the
 *                convention condemns itself.
 *   ALPHA      — that same fill is nearly transparent; a tint is not a button.
 *   OPACITY    — MEASURED 2026-09-23 and this was a real defect in a first build of this file.
 *                `.spl-hbtn.gap{opacity:.62;cursor:not-allowed}` ships on nine surfaces and
 *                `.mapp-gap`, `.rgy-gap` and `.fus-gap` do the same. `opacity` does NOT change
 *                `backgroundColor`, so a test reading only the colour reported ten deliberately
 *                dimmed controls as undressed primary buttons — it would have pinned as debt a
 *                treatment the estate had already applied, and any later repair would then have
 *                looked like a regression. Dimming is a conventional disabled treatment and this
 *                judgement accepts it.
 */
export function isPrimaryFill(backgroundColor, opacity = 1) {
  const bg = parseColor(backgroundColor);
  if (bg === null) return false;
  if (bg.a <= FILL_ALPHA_FLOOR) return false;
  const alpha = Number.parseFloat(opacity);
  if (Number.isFinite(alpha) && alpha <= DIMMED_OPACITY_CEILING) return false;
  return Math.max(bg.r, bg.g, bg.b) - Math.min(bg.r, bg.g, bg.b) > SATURATION_FLOOR;
}

/** Does this element carry a gap marker token? Prose notes are deliberately not markers. */
export function hasGapMarker(className) {
  const tokens = String(className ?? "").split(/\s+/u).filter(Boolean);
  if (tokens.some((t) => NOT_CONTROL_MARKERS.includes(t))) return false;
  return tokens.some((t) => GAP_MARKER_TOKENS.includes(t));
}

/**
 * THE FOUR FINDINGS, each independent so one cannot mask another.
 *
 * `control` is a plain record: { text, className, tag, role, tabindex, ariaDisabled, cursor,
 * backgroundColor, opacity }. `tabindex` is the attribute value or null; `opacity` defaults to 1.
 */
export function perceptionFindings(control) {
  const findings = [];
  const marked = hasGapMarker(control?.className);
  const declared = control?.ariaDisabled === true;
  if (!marked && !declared) return findings; // not a gap at all; this judgement does not reach it

  // UNMARKED — carries the marker class and no `aria-disabled`. The worst of the four, because it
  // is invisible to every gate in the estate: they all key on the attribute this one lacks. A
  // screen reader announces it as an ordinary enabled control and actively vouches for it.
  if (marked && !declared) {
    findings.push(`unmarked_gap: \`${control.text || "(no label)"}\` carries a gap marker and no aria-disabled, so every existing parity check is blind to it and assistive technology announces it as enabled`);
  }

  // CURSOR — the pointer is the fastest signal a person gets, and `default` says "not clickable
  // but also not refused", which is the one thing this control is.
  if (control?.cursor !== "not-allowed") {
    findings.push(`cursor_not_disabled: \`${control.text || "(no label)"}\` renders \`cursor: ${control?.cursor ?? "(unset)"}\` — the pointer does not say the control is unavailable`);
  }

  // PRIMARY FILL — styled as the thing to click. A declared-unavailable control wearing the page's
  // call-to-action styling is not a subtle defect; it is the most prominent promise on the surface.
  if (isPrimaryFill(control?.backgroundColor, control?.opacity)) {
    findings.push(`primary_fill: \`${control.text || "(no label)"}\` renders a saturated opaque UNDIMMED fill (${control.backgroundColor} at opacity ${control?.opacity ?? 1}) while declared unavailable`);
  }

  // REACHABILITY — BOTH HALVES ARE REQUIRED, and the reason is why `aria-disabled` was chosen over
  // the native `disabled` attribute in the first place: `disabled` removes a control from the tab
  // order, `aria-disabled` keeps it perceivable so a person can find out WHY it is unavailable. The
  // why lives in the `title`. A role with no tabindex is announced correctly and can never be
  // reached to be announced; a tabindex with no role is reachable and announced as nothing. Either
  // alone defeats the choice, so either alone is the finding.
  const missing = [];
  if (declared && !control?.role) missing.push("no role");
  if (declared && control?.tabindex == null) missing.push("no tabindex");
  if (missing.length) {
    findings.push(`unreachable_control: \`${control.text || "(no label)"}\` is aria-disabled on a <${String(control?.tag ?? "?").toLowerCase()}> with ${missing.join(" and ")} — aria-disabled is chosen over disabled so the control stays perceivable, and ${missing.length === 2 ? "it is neither announced nor reachable" : missing[0] === "no role" ? "assistive technology is told a non-control is disabled" : "a keyboard user cannot reach it to be told anything"}`);
  }
  return findings;
}

/** Roll a census of control records into the four counts a pinned population is compared against. */
export function censusTotals(controls) {
  const totals = { labelled: 0, unmarked_gap: 0, cursor_not_disabled: 0, primary_fill: 0, unreachable_control: 0 };
  for (const control of Array.isArray(controls) ? controls : []) {
    if (!control?.text) continue; // an icon-only gap has no label to dim; counted elsewhere
    if (!hasGapMarker(control.className) && control.ariaDisabled !== true) continue;
    totals.labelled += 1;
    for (const finding of perceptionFindings(control)) {
      const code = finding.slice(0, finding.indexOf(":"));
      if (code in totals) totals[code] += 1;
    }
  }
  return totals;
}

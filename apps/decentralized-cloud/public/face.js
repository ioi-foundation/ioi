// decentralized.cloud — the public face.
//
// Renders exactly what the daemon returned and nothing else. There is no fixture,
// no seeded value and no cached price in this file: if a read fails, the failure is
// what gets rendered, by name. The live-vs-simulator rule here is the same one the
// M15.1 check enforces server-side — a candidate is live only if the daemon said
// live_evidence, carries a priced quote with a stated basis, carries observed_at and
// expires_at, is still inside its window, and is not a labelled simulator lane.

const el = (tag, attrs = {}, ...children) => {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else if (k === "style") node.setAttribute("style", v);
    // data-* and aria-* must go through setAttribute: assigning them as properties
    // silently creates a JS field and leaves the DOM without the attribute, which
    // would make the ticker's querySelectorAll find nothing and every countdown
    // freeze at its first value.
    else if (k.startsWith("aria-") || k.startsWith("data-") || k === "type" || k === "role") node.setAttribute(k, v);
    else node[k] = v;
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    node.append(typeof c === "string" ? document.createTextNode(c) : c);
  }
  return node;
};

const chip = (text, kind = "") => el("span", { class: `chip ${kind}`.trim() }, el("span", { class: "dot" }), text);

const clock = (iso) => {
  if (!iso) return "—";
  const t = Date.parse(iso);
  return Number.isFinite(t) ? new Date(t).toISOString().slice(11, 19) + "Z" : String(iso);
};

const minutesLeft = (iso) => {
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return null;
  return Math.round((t - Date.now()) / 60000);
};

const svgEl = (tag, attrs = {}, ...children) => {
  const node = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, String(v));
  for (const c of children.flat()) if (c) node.append(c);
  return node;
};

// ── The freshness dial ───────────────────────────────────────────────────────
// The fraction of a quote's own observed_at → expires_at window that is still
// unspent. Both endpoints come from the daemon's record of that candidate; the
// dial has no duration of its own and no animation that runs independently of
// them, so it cannot show a full window for an empty one. It is re-read from the
// same two timestamps every second by the ticker below.
const DIAL_R = 8;
const DIAL_C = 2 * Math.PI * DIAL_R;

function dialFraction(observedAt, expiresAt) {
  const o = Date.parse(observedAt), e = Date.parse(expiresAt);
  if (!Number.isFinite(o) || !Number.isFinite(e) || e <= o) return null;
  return Math.max(0, Math.min(1, (e - Date.now()) / (e - o)));
}

function dial(observedAt, expiresAt) {
  const node = svgEl("svg", {
    class: "dial", width: 20, height: 20, viewBox: "0 0 20 20",
    "data-observed": observedAt || "", "data-expires": expiresAt || "",
    role: "img",
  },
    svgEl("circle", { class: "track", cx: 10, cy: 10, r: DIAL_R }),
    svgEl("circle", { class: "sweep", cx: 10, cy: 10, r: DIAL_R,
      "stroke-dasharray": `0 ${DIAL_C.toFixed(2)}` }));
  paintDial(node);
  return node;
}

function paintDial(node) {
  const frac = dialFraction(node.getAttribute("data-observed"), node.getAttribute("data-expires"));
  const sweep = node.querySelector(".sweep");
  if (frac === null) {
    node.classList.add("spent");
    sweep.setAttribute("stroke-dasharray", `0 ${DIAL_C.toFixed(2)}`);
    node.setAttribute("aria-label", "no observation window");
    return;
  }
  node.classList.toggle("spent", frac <= 0);
  sweep.setAttribute("stroke-dasharray", `${(frac * DIAL_C).toFixed(2)} ${DIAL_C.toFixed(2)}`);
  node.setAttribute("aria-label", `${Math.round(frac * 100)}% of the quote window remaining`);
}

// Anything carrying data-expires is re-read from its own timestamps once a second.
// Countdown text is written from the same source as the dial beside it, so the two
// can never disagree.
setInterval(() => {
  for (const node of document.querySelectorAll("svg.dial")) paintDial(node);
  for (const node of document.querySelectorAll("[data-countdown]")) {
    // SECONDS below a minute, not "expired". `minutesLeft` rounds, so for the last
    // ~30 seconds of every quote window this printed "expired" beside a dial reading
    // "2% of the quote window remaining" — measured at 21:46:27Z against an expiry of
    // 21:46:48Z, twenty-one seconds in the future. The comment above claims the two
    // "can never disagree"; they disagreed on every quote, once per window, because
    // the dial reads the timestamps and the text read a rounded minute count.
    // A live quote labelled expired is the same failure as a stale quote labelled
    // live, in the other direction.
    const iso = node.getAttribute("data-countdown");
    const ms = Date.parse(iso) - Date.now();
    node.textContent = !Number.isFinite(ms) ? "—"
      : ms <= 0 ? "expired"
      : ms < 60000 ? `${Math.ceil(ms / 1000)}s left`
      : `${Math.round(ms / 60000)} min left`;
  }
  for (const node of document.querySelectorAll("[data-due]")) {
    const secs = Math.round((Date.parse(node.getAttribute("data-due")) - Date.now()) / 1000);
    node.textContent = !Number.isFinite(secs)
      ? "—"
      : secs > 0
        ? `next batch due in ${Math.floor(secs / 60)}m ${String(secs % 60).padStart(2, "0")}s`
        : "next batch overdue";
  }
}, 1000);

// ── The live rule ────────────────────────────────────────────────────────────
function classify(c) {
  const labels = Array.isArray(c?.eligibility_labels) ? c.eligibility_labels : [];
  if (labels.includes("simulated_control_plane")) return { live: false, reason: "simulated_control_plane" };
  if (c?.evidence_mode !== "live_evidence") return { live: false, reason: `evidence_mode ${c?.evidence_mode ?? "absent"}` };
  const q = c?.quote;
  if (!q) return { live: false, reason: "no quote" };
  if (q.evidence_mode !== "live_evidence") return { live: false, reason: `quote.evidence_mode ${q.evidence_mode ?? "absent"}` };
  if (typeof q.usd_per_hour !== "number") return { live: false, reason: "no price" };
  if (!q.basis) return { live: false, reason: "no stated basis" };
  if (!c.observed_at || !c.expires_at) return { live: false, reason: "no observation window" };
  if (Date.parse(c.expires_at) <= Date.now()) return { live: false, reason: "expired" };
  return { live: true, reason: "live_evidence" };
}

async function read(path) {
  const started = Date.now();
  try {
    const res = await fetch(path, { headers: { accept: "application/json" } });
    const body = await res.json();
    return { ok: res.ok, status: res.status, body, ms: Date.now() - started };
  } catch (err) {
    return { ok: false, status: 0, body: { state: "face_read_failed", reason: String(err) }, ms: Date.now() - started };
  }
}

const surface = document.getElementById("surface");

// ── Which surface is the reader actually looking at? ─────────────────────────
// Every render is async, and a slow read outlives the click that started it. A
// 31-second Sources response landing after the reader moved to Receipts will
// happily call replaceChildren and paint Sources' data under Receipts' heading and
// aria-current, with no signal that it did.
//
// That is disqualifying on THIS surface in particular. The whole claim here is that
// you can always tell where a number came from; a page that shows one surface's
// data under another surface's label breaks exactly the promise it exists to make.
//
// So: a generation counter bumped on every navigation, captured before each await,
// and checked before anything reaches the DOM. A late response from a superseded
// surface returns instead of painting. Routed through one function so a render
// cannot bypass the check by forgetting it.
let generation = 0;
const currentGeneration = () => generation;

const statusRegion = document.getElementById("surface-status");

function paint(mine, ...nodes) {
  if (mine !== generation) return false;
  surface.replaceChildren(...nodes);
  // Announce WHAT CHANGED, not the document. `aria-live` used to sit on <main>, so
  // every surface swap re-announced the whole page — and on Placement that was
  // 13.66 MB of text before that surface was rewritten. Shrinking Placement removed
  // the magnitude but not the fault: a live region that reads the document is a live
  // region nobody leaves switched on. This says the surface's own heading and the
  // machine-readable line under it — what a sighted reader takes from the top of the
  // page — and nothing else.
  if (statusRegion) {
    const heading = surface.querySelector("h1")?.textContent?.trim() || "";
    const meta = surface.querySelector(".meta")?.textContent?.trim() || "";
    statusRegion.textContent = [heading, meta].filter(Boolean).join(" — ").slice(0, 200);
  }
  return true;
}

// Cold start renders the daemon's own default intent, which already exists and is
// reachable by a GET. `?intent=` overrides it. Creating an intent with custom
// constraints is a write, and this surface performs none.
const DEFAULT_INTENT = "cloud-resource-intent://cri_default";
const intentRef = new URL(location.href).searchParams.get("intent") || DEFAULT_INTENT;

const waiting = (what) =>
  el("div", { class: "stack", style: "gap: 10px;" },
    el("p", { class: "prose" }, `Asking the daemon for ${what}.`),
    el("p", { class: "prose" },
      "A full candidate sweep is slow — it asks every live venue in turn. Nothing is " +
      "shown until it answers: an invented placeholder would be indistinguishable from " +
      "a real quote."));

const failure = (r) =>
  el("div", { class: "panel fault stack", style: "gap: 8px;" },
    el("div", { class: "eyebrow" }, r.body?.state || `http ${r.status}`),
    el("p", { class: "prose" }, r.body?.reason || "The read failed and the daemon gave no reason."));

// ── Candidates ───────────────────────────────────────────────────────────────
// Stale-while-refresh. The first paint has nothing to be stale FROM, so it says
// so; every later refresh leaves the previous batch on screen, dimmed and named as
// the older observation, while the new read is in flight. A page that blanks
// itself to refetch teaches its reader that an empty table means "loading", and on
// this surface an empty table has to keep meaning "no live price".
let lastPaint = null;

function setRefreshChip(state) {
  const chipEl = document.getElementById("refresh-chip");
  if (!chipEl) return;
  chipEl.className = state === "refreshing" ? "chip muted refreshing" : "chip muted";
  chipEl.lastChild.textContent = state === "refreshing" ? "re-reading the daemon" : "read-only surface";
}

async function renderCandidates({ silent = false } = {}) {
  const mine = currentGeneration();
  if (!silent || !lastPaint) paint(mine, waiting("candidates"));
  else {
    lastPaint.classList.add("stale");
    setRefreshChip("refreshing");
  }
  const [r, config] = await Promise.all([
    read(`/api/candidates?intent_ref=${encodeURIComponent(intentRef)}`),
    read("/api/face-config"),
  ]);
  if (mine !== currentGeneration()) return; // the reader has moved on
  setRefreshChip("idle");
  if (!r.ok) {
    // A failed refresh does not erase a good earlier reading; it is shown beside it.
    if (silent && lastPaint) {
      lastPaint.classList.remove("stale");
      lastPaint.prepend(failure(r));
      return;
    }
    return paint(mine, failure(r));
  }
  const cadence = config.ok ? config.body?.refresh_cadence_seconds : null;

  // A long-lived intent accumulates every sweep the daemon has ever run against it,
  // so the page reads the LATEST BATCH and says how much older evidence it set aside.
  // Showing a fresh quote beside a fortnight-old one would make the page a place
  // where prices go to be misread.
  const all = Array.isArray(r.body.candidates) ? r.body.candidates : [];
  const batches = new Map();
  for (const c of all) {
    const key = c.batch || "unbatched";
    const entry = batches.get(key) || { key, observed: "", items: [] };
    entry.items.push(c);
    if ((c.observed_at || "") > entry.observed) entry.observed = c.observed_at || "";
    batches.set(key, entry);
  }
  const latest = [...batches.values()].sort((a, b) => (a.observed < b.observed ? 1 : -1))[0]
    || { key: "none", observed: "", items: [] };
  const candidates = latest.items;
  const live = candidates.filter((c) => classify(c).live);
  const venues = [...new Set(live.map((c) => c.provider_kind))].sort();
  const observed = live[0]?.observed_at || r.body.at;

  const cheapest = live.length
    ? live.reduce((a, b) => (a.quote.usd_per_hour <= b.quote.usd_per_hour ? a : b))
    : null;

  const venueVerdict = venues.length >= 2
    ? el("div", { class: "panel flag stack", style: "gap: 9px;" },
        el("h2", {}, `${live.length} live quotes, across ${venues.length} venues`),
        el("p", { class: "prose" },
          `Two or more venues are quoting (${venues.join(", ")}), so this intent can be ` +
          "compared and routed, not merely priced."))
    : el("div", { class: "panel flag stack", style: "gap: 9px;" },
        el("h2", {}, `${live.length} live quote${live.length === 1 ? "" : "s"}, from ${venues.length === 1 ? "one venue" : "no venue"}`),
        el("p", { class: "prose" },
          "A routing decision needs at least two venues to be a decision at all. " +
          (venues.length === 1
            ? `Every quote below is real and every one of them is ${venues[0]}, so this intent can be priced but not routed, and no fee can be minted against it.`
            : "Nothing here is priced, and no price has been invented to fill the gap. " +
              "Quotes are good for about fifteen minutes, and taking a fresh one is a write " +
              "this surface does not perform — so an intent nobody has refreshed lately shows " +
              "its evidence expired rather than a price it cannot stand behind.")));

  // A REAL TABLE. This was four <div>s per row with a grid layout, and a review found
  // `document.querySelectorAll("table").length = 0` and `th = 0` on all five static
  // surfaces: "$0.0136" had no programmatic association with "PER HOUR" or with the
  // `vast` row it belonged to. That is the single most important datum on the surface,
  // and to a screen reader it was a loose number in a stack of loose numbers.
  //
  // The header stays a header at every width. Narrow screens scroll the table inside
  // its own container rather than restyling it into blocks, because changing `display`
  // on table elements strips their implicit roles — the fix would have removed the
  // semantics it was added to provide.
  const rows = [];

  if (cheapest) {
    rows.push(el("tr", { class: "trow" },
      el("th", { class: "stack", scope: "row", style: "gap: 7px;" },
        el("div", { class: "mono", style: "font-size: 14px;" }, cheapest.provider_kind || "—"),
        chip("live_evidence", "live")),
      el("td", { class: "mono", style: "font-size: 13px; color: var(--label); line-height: 1.5;" },
        cheapest.quote.basis,
        el("br"),
        cheapest.quote.quote_ref || "",
        el("br"),
        `observed ${clock(cheapest.observed_at)}`),
      el("td", { class: "mono", style: "font-size: 16px;" }, `$${cheapest.quote.usd_per_hour.toFixed(4)}`),
      el("td", { class: "freshness" },
        dial(cheapest.observed_at, cheapest.expires_at),
        el("div", { class: "stack", style: "gap: 4px;" },
          el("div", { class: "mono", style: "font-size: 13px;" }, clock(cheapest.expires_at)),
          el("div", {
            class: "mono", style: "font-size: 12px; color: var(--label);",
            "data-countdown": cheapest.expires_at || "",
          }, "—")))));
  }

  const remainder = live.filter((c) => c !== cheapest);
  if (remainder.length) {
    const kinds = [...new Set(remainder.map((c) => c.provider_kind))];
    rows.push(el("tr", { class: "trow" },
      el("th", { class: "mono", scope: "row", style: "font-size: 14px; color: var(--label);" }, kinds.join(", ")),
      el("td", { class: "prose" },
        `${remainder.length} further live quotes` +
        (kinds.length === 1 && kinds[0] === cheapest?.provider_kind
          ? " from the same venue — priced and comparable to each other, but they add no venue diversity."
          : ".")),
      el("td", { class: "mono", style: "font-size: 13px; color: var(--label);" },
        `$${Math.min(...remainder.map((c) => c.quote.usd_per_hour)).toFixed(4)} up`),
      el("td", { class: "mono", style: "font-size: 13px; color: var(--label);" }, "same window")));
  }

  // Everything that is not live is summarised by the reason it is not, rather than
  // given a row each: a default intent accumulates hundreds of candidates across
  // sweeps, and six hundred rows of "not a price" is not more honest than a count.
  const notLive = new Map();
  for (const c of candidates) {
    const verdict = classify(c);
    if (verdict.live) continue;
    const entry = notLive.get(verdict.reason) || { count: 0, kinds: new Set() };
    entry.count += 1;
    entry.kinds.add(c.provider_kind || c.source || "—");
    notLive.set(verdict.reason, entry);
  }

  for (const [reason, entry] of [...notLive.entries()].sort((a, b) => b[1].count - a[1].count)) {
    rows.push(el("tr", { class: "trow" },
      el("th", { class: "stack", scope: "row", style: "gap: 7px;" },
        el("div", { class: "mono", style: "font-size: 13px; color: var(--label);" },
          [...entry.kinds].sort().join(", ")),
        chip(reason === "expired" ? "expired" : "not a price", reason === "expired" ? "expired" : "")),
      el("td", { class: "prose" },
        `${entry.count} candidate${entry.count === 1 ? "" : "s"} — ${reason}.`),
      el("td", { class: "mono", style: "font-size: 13px; color: var(--label);" }, "—"),
      el("td", { class: "mono", style: "font-size: 13px; color: var(--label);" }, "—")));
  }

  const observedIso = latest.observed || observed;
  const dueIso = cadence && Date.parse(observedIso)
    ? new Date(Date.parse(observedIso) + cadence * 1000).toISOString()
    : null;

  const painted = el("div", { class: "stack", style: "gap: 26px;" },
      el("div", { class: "stack", style: "gap: 10px;" },
        el("h1", {}, r.body.intent_summary || "Candidates"),
        el("div", { class: "meta" },
          `${intentRef} · batch ${latest.key} · observed ${clock(observedIso)}` +
          ` · ${candidates.length} of ${all.length} candidates known for this intent`),
        // The dial is drawn only when there is a real window to draw. With no
        // cadence declared, this surface does not know when the next batch lands
        // and says so — an empty dial beside "no cadence" would be a measurement
        // of nothing dressed as one.
        dueIso
          ? el("div", { class: "freshness" },
              dial(observedIso, dueIso),
              el("span", { class: "meta", "data-due": dueIso }, "—"),
              el("span", { class: "meta" },
                // The cadence is a declared fact the face is told. The sweep DURATION
                // was a hardcoded "about 39s" written as though measured — the review
                // measured 31.6s. A number presented as measured must come from a
                // measurement or not be shown, so it is gone: the cadence is stated
                // because it is known, and the duration is not because it is not.
                `· the refresher sweeps every ${Math.round(cadence / 60)} minutes`))
          : el("div", { class: "meta" },
              "No refresh cadence is declared to this surface, so it makes no claim about " +
              "when the next batch lands. The quote windows below are still exact."),
        all.length > candidates.length
          ? el("div", { class: "meta" },
              `${all.length - candidates.length} older candidates from earlier sweeps are set aside — ` +
              "a price is only comparable against the sweep it was taken in.")
          : null),
      venueVerdict,
      el("div", { class: "eyebrow" }, "Evidence"),
      el("div", { class: "table-scroll" },
        el("table", { class: "table" },
          el("thead", {},
            el("tr", { class: "trow head" },
              el("th", { scope: "col" }, "venue"), el("th", { scope: "col" }, "evidence"),
              el("th", { scope: "col" }, "per hour"), el("th", { scope: "col" }, "good until"))),
          el("tbody", {}, rows))),
      el("p", { class: "prose" },
        "A price appears in this table only when the daemon returned it as live_evidence " +
        "with an observed_at, an expires_at still in the future, and a quote reference it " +
        "can be traced back to. Simulator lanes are excluded from the table, from the " +
        "venue count, and from any fee."));

  if (paint(mine, painted)) lastPaint = painted;
}

// The page re-reads on the same cadence the refresher sweeps on, so what is shown
// is never more than one sweep behind what the daemon holds. It refreshes in place:
// see renderCandidates' silent branch.
const POLL_MS = 30_000;
setInterval(() => {
  const current = document.querySelector('.nav button[aria-current="page"]');
  if (current?.dataset.surface === "candidates" && document.visibilityState === "visible") {
    renderCandidates({ silent: true });
  }
}, POLL_MS);

// ── Sources ──────────────────────────────────────────────────────────────────
async function renderSources() {
  // This is the read the reviewer's race fired on: measured at 31s, long enough for
  // a reader to click away twice before it lands.
  const mine = currentGeneration();
  paint(mine, waiting("source health"));
  const r = await read("/api/candidate-sources");
  if (!r.ok) return paint(mine, failure(r));

  const sources = Array.isArray(r.body.sources) ? r.body.sources : [];
  const quoting = sources.filter((s) => s.state === "live_quote_source");
  const absent = sources.filter((s) => s.state === "candidate_source_unavailable");
  const answering = sources.filter((s) => !quoting.includes(s) && !absent.includes(s));

  // The row used to render `s.reason || s.coverage || s.rule` and stop there, so the
  // evidence the daemon had ALREADY sent was dropped on the floor: vast came back
  // with http_status 200 and offers_seen 24, runpod with an http_status and a named
  // API error, and neither reached the screen — under a subtitle promising that "a
  // source without an adapter or without a credential says so in the row where a
  // price would have been." A reviewer asked whose fault runpod's absence was and
  // could not tell; the daemon had already said.
  //
  // `state` is last-persisted and can lag a fixed adapter, so the row shows the
  // observation's own timestamp beside it rather than implying the state is current.
  const EVIDENCE_KEYS = ["http_status", "offers_seen", "gpu_types_priced", "gpu_types_seen",
    "endpoint", "mode", "verified_ssh_accounts", "connected_cloud_accounts", "archive_objects"];
  const row = (s) => {
    const kind = s.state === "live_quote_source" || s.state === "available" || s.state === "storage_backends_engaged"
      ? "live" : s.state === "candidate_source_unavailable" ? "absent" : "muted";
    const ev = s.evidence && typeof s.evidence === "object" ? s.evidence : {};
    const detail = EVIDENCE_KEYS.filter((k) => ev[k] !== undefined && ev[k] !== null)
      .map((k) => `${k} ${ev[k]}`);
    return el("div", { class: "srow" },
      el("div", { class: "srow-head" },
        el("span", { class: "mono", style: "font-size: 14px;" }, s.source),
        chip(s.state, kind)),
      el("div", { class: "srow-reason" }, s.reason || s.coverage || s.rule || ""),
      ev.error ? el("div", { class: "srow-reason mono", style: "color: var(--expired);" }, String(ev.error)) : null,
      detail.length || s.at
        ? el("div", { class: "mono", style: "font-size: 12px; color: var(--label);" },
            [...detail, s.at ? `observed ${clock(s.at)}` : null].filter(Boolean).join(" · "))
        : null,
      ev.basis ? el("div", { class: "meta" }, `basis: ${ev.basis}`) : null);
  };

  paint(mine,
    el("div", { class: "stack", style: "gap: 24px;" },
      el("div", { class: "stack", style: "gap: 10px;" },
        el("h1", {}, "Sources"),
        el("div", { class: "meta" },
          `${sources.length} sources · ${quoting.length} quoting · ${answering.length} answering · ${absent.length} absent · read took ${(r.ms / 1000).toFixed(1)}s`)),
      el("p", { class: "prose" },
        "Health as the daemon reports it, in its own words. A source without an adapter " +
        "or without a credential says so in the row where a price would have been."),
      el("div", { class: "rail" }, sources.map(row))));
}

// ── Placement advisory ───────────────────────────────────────────────────────
async function renderPlacement() {
  const mine = currentGeneration();
  paint(mine, waiting("the placement advisory"));
  const [advisory, venues] = await Promise.all([
    read(`/api/placement-advisory${intentRef ? `?intent_ref=${encodeURIComponent(intentRef)}` : ""}`),
    read("/api/venues"),
  ]);
  if (!advisory.ok) return paint(mine, failure(advisory));

  // This surface used to be `JSON.stringify(advisory.body)` in a <pre>. An independent
  // review measured the result: 6,518,626 characters, 153,008 lines, a document
  // 6,063,630px tall that Chromium could not screenshot. Almost all of it is the
  // `candidates` array — 1,572 entries the reader did not ask for — while the fields
  // that answer the question, `recommendation` and its `reason_codes`, were buried
  // inside it. The advisory is now READ rather than dumped, and the body stays
  // reachable behind a disclosure with its bulk named and the candidate list left out,
  // because a raw body is evidence and hiding it would be the opposite of this
  // surface's point.
  const b = advisory.body || {};
  const rec = b.recommendation || null;
  const codes = Array.isArray(rec?.reason_codes) ? rec.reason_codes : [];
  // The candidate array is what makes the body unreadable, so the disclosure shows the
  // body WITHOUT it and says so, rather than silently printing something else.
  const { candidates, ...bodyWithoutCandidates } = b;
  const trimmed = JSON.stringify(bodyWithoutCandidates, null, 2);

  const fact = (label, value, kind) =>
    el("div", { class: "srow" },
      el("div", { class: "srow-head" },
        el("span", { class: "eyebrow" }, label),
        typeof value === "string" && kind !== undefined ? chip(value, kind) : el("span", { class: "mono" }, String(value))));

  paint(mine,
    el("div", { class: "stack", style: "gap: 24px;" },
      el("h1", {}, "Placement"),
      el("p", { class: "prose" },
        "An advisory is evidence, not authority. A placement decision cannot provision " +
        "anything: provider mutation still requires a wallet capability grant, and this " +
        "surface holds none and asks for none."),

      rec
        ? el("div", { class: "panel flag" },
            el("div", { class: "eyebrow" }, "Recommended"),
            el("h2", { style: "margin-top: 8px;" }, rec.display_name || rec.candidate_ref || "—"),
            el("div", { class: "mono", style: "font-size: 12px; color: var(--label); margin-top: 6px;" },
              [rec.venue, rec.candidate_ref].filter(Boolean).join(" · ")),
            codes.length
              ? el("div", { style: "display: flex; flex-wrap: wrap; gap: 8px; margin-top: 14px;" },
                  codes.map((c) => chip(c, "muted")))
              : el("p", { class: "prose", style: "margin-top: 12px;" },
                  "The advisory returned no reason codes for this recommendation."))
        : el("div", { class: "panel absent" },
            el("div", { class: "eyebrow" }, "No recommendation"),
            el("p", { class: "prose", style: "margin-top: 8px;" },
              b.no_eligible_candidate
                ? String(b.no_eligible_candidate)
                : "The advisory returned no recommendation and named no reason for its absence.")),

      el("div", { class: "rail" },
        fact("Considered", b.considered ?? "—"),
        fact("Eligible", b.eligible ?? "—"),
        fact("Effective venue", b.effective_venue ?? "—"),
        fact("Routing fee basis", b.routing_fee_basis ?? "—"),
        fact("Fee object minted", String(b.fee_object_minted) === "true" ? "minted" : "not minted",
          String(b.fee_object_minted) === "true" ? "live" : "muted"),
        fact("Advisory", b.advisory_ref ?? "—"),
        fact("Observed", clock(b.at))),

      b.authority_note ? el("p", { class: "prose" }, b.authority_note) : null,

      el("details", {},
        el("summary", { class: "eyebrow", style: "cursor: pointer; padding: 6px 0;" },
          `Advisory body as returned — ${trimmed.length.toLocaleString()} characters, ` +
          `with the ${Array.isArray(candidates) ? candidates.length.toLocaleString() : "0"}-entry candidate list omitted`),
        el("pre", { class: "code" }, trimmed)),

      // The venues body is the LARGER of the two and it used to be the unlabelled one:
      // a review measured 8,709,126 characters behind a summary reading only "Venues
      // as returned", sitting beside a sibling that carefully announced its own 3,771.
      // "The disclosure that announces its thrift holds 0.04% of the payload; the
      // silent one holds the rest." Both now state their size, and neither is opened
      // by default.
      venues.ok
        ? (() => {
            const vText = JSON.stringify(venues.body, null, 2);
            return el("details", {},
              el("summary", { class: "eyebrow", style: "cursor: pointer; padding: 6px 0;" },
                `Venues as returned — ${vText.length.toLocaleString()} characters`),
              el("pre", { class: "code" }, vText));
          })()
        : failure(venues)));
}

// ── Submit a job: designed, not connected ────────────────────────────────────
function renderJob() {
  const field = (label, value, hint) =>
    el("div", { class: "field" },
      el("div", { class: "field-label" }, label),
      el("div", { class: "field-box" }, el("span", {}, value), el("span", { class: "mono" }, "▾")),
      hint ? el("div", { class: "field-hint" }, hint) : null);

  paint(currentGeneration(),
    el("div", { class: "stack", style: "gap: 26px;" },
      el("div", { class: "panel absent stack", style: "gap: 8px;" },
        el("div", { class: "eyebrow" }, "designed, not connected"),
        el("p", { class: "prose" },
          "Drawn to the canonical CloudJobRequest shape and submits nothing. No field " +
          "here reaches a provider, a wallet, or a budget: this server exposes no " +
          "mutating route at all, so there is nothing for the button to call.")),
      el("div", { class: "stack", style: "gap: 9px;" },
        el("h1", {}, "Submit a job"),
        el("p", { class: "prose", style: "font-size: 16px;" },
          "This much capacity, under this budget, for this long, receipt back. You do not " +
          "name a venue — the venue is evidence in the receipt, not an input to the request.")),
      el("div", { class: "cols cols-2", style: "gap: 20px 24px; max-width: 900px;" },
        field("intent.runtime_class", "compute.gpu_runtime"),
        field("intent.gpu", "required · 1 device · 24 GB"),
        field("deadline", "max duration · 4 hours"),
        field("budget_ref", "select an external_spend budget",
          "An existing budget, never an amount typed here. A request with no resolvable budget is refused by name: budget_undiscovered_before_mutation."),
        field("authority_ref", "wallet grant · signed at submit",
          "A wallet grant for a human, a CapabilityLease draw-down for an agent. Never a provider credential — the caller never holds one."),
        field("redundancy", "none",
          "none · warm_standby · active_active. Declared or absent — never inferred, defaulted, or applied by a fallback you did not authorize.")),
      el("div", { class: "field" },
        el("div", { class: "field-label" }, "receipt_requirements"),
        el("div", { style: "display: flex; flex-wrap: wrap; gap: 9px;" },
          ["placement", "provider-operation", "spend", "failover", "offline-verifiable"]
            .map((r) => el("span", { class: "chip muted" }, r)))),
      el("div", { style: "display: flex; align-items: center; gap: 16px;" },
        el("button", { class: "button-inert", type: "button", disabled: true }, "Submit job"),
        el("span", { class: "field-hint", style: "max-width: 48ch;" },
          "Disabled until the job primitive lands. The button is drawn so the shape of the " +
          "commitment is reviewable now, and it is inert on purpose."),
        chip("not wired — job api not live", "muted")),

      // ── The same primitive, from both doors ────────────────────────────────
      // A human fills the form above; an agent posts the body below. They are not
      // two APIs with a shared name — they are one CloudJobRequest, and the only
      // field that differs is how authority was obtained: a wallet grant a person
      // signs, or a CapabilityLease an agent draws down. If these two ever drift
      // apart, one of the two callers is being offered a privilege the other is
      // not, which is how a second spine starts.
      el("div", { class: "stack", style: "gap: 14px; margin-top: 6px;" },
        el("div", { class: "eyebrow" }, "The same primitive, from both doors"),
        el("p", { class: "prose" },
          "The form above and the request below are the same CloudJobRequest. Neither " +
          "door names a venue, neither carries a provider credential, and neither can " +
          "widen what its authority already permits — a lease draw-down is a narrowing " +
          "of a grant a human made earlier, never a new grant an agent made for itself."),
        el("div", { class: "cols cols-2", style: "gap: 20px;" },
          el("div", { class: "stack", style: "gap: 9px;" },
            el("div", { class: "meta" }, "human · wallet grant signed at submit"),
            el("pre", { class: "code" }, JSON.stringify({
              schema_version: "ioi.cloud.job-request.v1",
              intent: { runtime_class: "compute.gpu_runtime", gpu: { required: true, devices: 1, min_gb: 24 } },
              deadline: { max_duration_hours: 4 },
              budget_ref: "external-spend-budget://esb_…",
              authority_ref: "wallet-grant://wg_…",
              redundancy: "none",
              receipt_requirements: ["placement", "provider-operation", "spend"],
            }, null, 2))),
          el("div", { class: "stack", style: "gap: 9px;" },
            el("div", { class: "meta" }, "agent · CapabilityLease draw-down"),
            el("pre", { class: "code" }, JSON.stringify({
              schema_version: "ioi.cloud.job-request.v1",
              intent: { runtime_class: "compute.gpu_runtime", gpu: { required: true, devices: 1, min_gb: 24 } },
              deadline: { max_duration_hours: 4 },
              budget_ref: "external-spend-budget://esb_…",
              authority_ref: "capability-lease://cl_…",
              redundancy: "none",
              receipt_requirements: ["placement", "provider-operation", "spend"],
            }, null, 2)))),
        el("p", { class: "prose" },
          "One field differs. That is the whole difference between a person and an " +
          "agent on this surface, and it is deliberate: the agent path is not a " +
          "lighter-weight API, it is the same request under an authority that was " +
          "delegated and can be revoked."))));
}

// ── Redundancy posture: designed, not connected ──────────────────────────────
function renderRedundancy() {
  // The job primitive's design document says the envelope accepts this field,
  // validates it, and REFUSES anything but `none` by name until the replica work
  // lands — replica placement, a per-replica exposure set and a switch policy do not
  // exist yet. So the two unbuilt postures are labelled as refused rather than as
  // available: a surface that offers what the primitive behind it will reject is
  // making a promise on someone else's behalf.
  const posture = (name, cost, whenItHelps, whatItCosts, chosen) =>
    el("div", { class: `panel stack ${chosen ? "flag" : "absent"}`, style: "gap: 10px;" },
      el("div", { style: "display: flex; align-items: center; justify-content: space-between; gap: 12px;" },
        el("h2", {}, name),
        chip(chosen ? "the only accepted value" : "refused by name until M15.9", "muted")),
      el("div", { class: "mono", style: "font-size: 13px; color: var(--label);" }, cost),
      el("p", { class: "prose" }, whenItHelps),
      el("p", { class: "prose" }, whatItCosts));

  paint(currentGeneration(),
    el("div", { class: "stack", style: "gap: 26px;" },
      el("div", { class: "panel absent stack", style: "gap: 8px;" },
        el("div", { class: "eyebrow" }, "designed, not connected"),
        el("p", { class: "prose" },
          "Drawn to the canonical RedundancyPosture shape and selects nothing. No " +
          "posture here is in force, because this surface performs no writes and a " +
          "posture is a property of a running job.")),
      el("div", { class: "stack", style: "gap: 9px;" },
        el("h1", {}, "Redundancy"),
        el("p", { class: "prose", style: "font-size: 16px;" },
          "What should happen when a venue fails underneath your work. This is declared " +
          "in the request or it is absent — it is never inferred from your budget, never " +
          "defaulted to something safer than you asked for, and never applied by a " +
          "fallback you did not authorize.")),
      el("div", { class: "cols cols-3", style: "gap: 20px;" },
        posture("none", "1× spend",
          "The job runs in one place. If that venue fails, the job fails and the receipt says which venue and when.",
          "Nothing is held in reserve, so recovery means resubmitting — and the second placement is priced at whatever the market is then, not at your original quote.",
          true),
        posture("warm_standby", "1× spend + reserved capacity",
          "A second venue holds capacity but does not execute. On failure the work moves there without waiting for a fresh placement round.",
          "You pay to reserve what you are not using, and the standby's quote has its own expiry — a reservation older than its window is not a reservation."),
        posture("active_active", "2× spend",
          "The work runs in two venues at once. A single venue failure costs nothing but the failed half.",
          "Everything is paid for twice, and any work with side effects has to be idempotent or the duplicate execution is a defect rather than a safeguard.")),
      el("div", { class: "stack", style: "gap: 12px;" },
        el("div", { class: "eyebrow" }, "What a posture cannot do"),
        el("p", { class: "prose" },
          "A posture never authorizes spend. warm_standby and active_active both cost " +
          "more than the budget a single placement was checked against, so choosing one " +
          "re-checks the budget and is refused by name — budget_undiscovered_before_mutation " +
          "— if the larger figure does not fit. A redundancy setting that could quietly " +
          "double a bill would be an authority this surface has no business holding."),
        el("p", { class: "prose" },
          "Today only `none` is accepted. The other two are drawn because the shape of the " +
          "choice is worth reviewing before it is built — but replica placement, per-replica " +
          "exposure and a switch policy do not exist yet, and until they do a request naming " +
          "either one is refused by name rather than quietly downgraded to `none`. A surface " +
          "that offered them would be promising something the primitive behind it rejects."),
        el("div", { style: "display: flex; align-items: center; gap: 16px;" },
          el("button", { class: "button-inert", type: "button", disabled: true }, "Apply posture"),
          chip("not wired — no running job to apply it to", "muted")))));
}

// ── Receipts: designed, not connected ────────────────────────────────────────
function renderReceipts() {
  const receipt = (kind, answers, fields) =>
    el("div", { class: "srow" },
      el("div", { class: "srow-head" },
        el("span", { class: "mono", style: "font-size: 14px;" }, kind),
        chip("shape only", "muted")),
      el("div", { class: "srow-reason" }, answers),
      el("div", { class: "mono", style: "font-size: 12px; color: var(--label);" }, fields));

  paint(currentGeneration(),
    el("div", { class: "stack", style: "gap: 26px;" },
      el("div", { class: "panel absent stack", style: "gap: 8px;" },
        el("div", { class: "eyebrow" }, "designed, not connected"),
        el("p", { class: "prose" },
          "These are the receipt kinds a completed job returns, drawn to their canonical " +
          "shape. This surface has never run a job, so it holds no receipts and shows " +
          "none — the list below is a contract, not a history.")),
      el("div", { class: "stack", style: "gap: 9px;" },
        el("h1", {}, "Receipts"),
        el("p", { class: "prose", style: "font-size: 16px;" },
          "A receipt is how you find out what actually happened, from a party that is not " +
          "the one that did it. Each kind below answers one question that would otherwise " +
          "have to be taken on trust.")),
      el("div", { class: "rail" },
        receipt("placement",
          "Which venue was chosen, against which candidates, on what evidence, and at what quoted price — including the candidates that were not chosen.",
          "venue · candidate_ref[] · quote_ref · observed_at · decided_at"),
        receipt("provider-operation",
          "What was actually asked of the provider and what it answered, so a failure can be attributed to the venue rather than to the platform.",
          "operation · provider_kind · request_digest · response_digest · at"),
        receipt("spend",
          "What it cost, measured against the provider's own billing rather than against the quote — a quote is a prediction and a receipt is not.",
          "budget_ref · quoted_usd · billed_usd · variance · settled_at"),
        receipt("failover",
          "Whether the declared posture was exercised, when, and what the second placement cost. Absent when nothing failed.",
          "from_venue · to_venue · posture · triggered_at · second_quote_ref"),
        receipt("offline-verifiable",
          "The bundle that lets someone outside this system check the four above without asking this system anything.",
          "chain · signatures · checkpoint_ref · verifier_version")),
      el("p", { class: "prose" },
        "decentralized.cloud does not define these formats and does not sign them. " +
        "Agentgres records what ran and what it cost, and the wallet plane holds the " +
        "authority the operation drew on. This surface would show them and own none of them.")));
}

// ── API ──────────────────────────────────────────────────────────────────────
function renderApi() {
  const route = (path, daemon, note) =>
    el("div", { class: "srow" },
      el("div", { class: "srow-head" },
        el("span", { class: "mono", style: "font-size: 14px;" }, `GET ${path}`),
        chip("read", "live")),
      el("div", { class: "srow-reason mono", style: "font-size: 12px;" }, daemon),
      el("div", { class: "srow-reason" }, note));

  paint(currentGeneration(),
    el("div", { class: "stack", style: "gap: 24px;" },
      el("h1", {}, "API"),
      // "Four reads" was FALSE: GET /api/face-config answers 200 and appeared on
      // neither this list nor the 404's allowlist. A review found it and was right to
      // call the sentence false as written — on a surface whose entire claim is that
      // it does not overstate itself, an undercount of its own attack surface is the
      // worst possible sentence to get wrong. Five, and the fifth is listed.
      el("p", { class: "prose" },
        "Five reads, exact-match and GET-only. A path that is not on this list is refused " +
        "by name rather than passed through, so no mutating daemon call is reachable from " +
        "this surface even by accident. Responses are the daemon's own, unaltered — the " +
        "evidence fields you see here are the evidence fields it returned."),
      el("div", { class: "rail" },
        route("/api/candidate-sources", "/v1/hypervisor/cloud-candidates/candidate-sources",
          "Per-source health with the daemon's own reason strings."),
        route("/api/candidates?intent_ref=…", "/v1/hypervisor/cloud-candidates/candidates",
          "Candidates for an existing intent. Opening an intent is a write and is not offered here."),
        route("/api/placement-advisory?intent_ref=…", "/v1/hypervisor/cloud-candidates/placement-advisory",
          "Advisory only — evidence, never authority."),
        route("/api/venues", "/v1/hypervisor/placement/venues",
          "The venue set the placement plane knows about."),
        route("/api/face-config", "— served locally, no daemon call",
          "This surface's own configuration. It reaches no daemon and carries no evidence; " +
          "it is listed because it answers 200 and a list of reachable paths that omits a " +
          "reachable path is not a list of reachable paths.")),
      el("p", { class: "prose" },
        "What this surface never owns: no session plane, no credential vault, no provider " +
        "integration, no placement scorer, no receipt format. decentralized.cloud proposes " +
        "candidates, wallet.network authorizes, Hypervisor places and executes, Agentgres " +
        "records what ran and what it cost. This page composes those four and adds none.")));
}

const SURFACES = {
  candidates: renderCandidates,
  sources: renderSources,
  placement: renderPlacement,
  job: renderJob,
  redundancy: renderRedundancy,
  receipts: renderReceipts,
  api: renderApi,
};

for (const button of document.querySelectorAll(".nav button")) {
  button.addEventListener("click", () => {
    // Bump FIRST: every read already in flight is now for a surface the reader has
    // left, and must not paint. This is the line that makes the guard work.
    generation += 1;
    for (const b of document.querySelectorAll(".nav button")) b.removeAttribute("aria-current");
    button.setAttribute("aria-current", "page");
    // Leaving candidates drops the stale-paint handle: a batch rendered before the
    // reader navigated away must not reappear under a later refresh as though it
    // had just been read.
    lastPaint = null;
    setRefreshChip("idle");
    SURFACES[button.dataset.surface]();
  });
}

document.getElementById("daemon-label").textContent = `daemon ${location.host}`;
renderCandidates();

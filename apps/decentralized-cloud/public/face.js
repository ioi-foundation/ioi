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
    else if (k.startsWith("aria-") || k === "type" || k === "role") node.setAttribute(k, v);
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

// Cold start renders the daemon's own default intent, which already exists and is
// reachable by a GET. `?intent=` overrides it. Creating an intent with custom
// constraints is a write, and this surface performs none.
const DEFAULT_INTENT = "cloud-resource-intent://cri_default";
const intentRef = new URL(location.href).searchParams.get("intent") || DEFAULT_INTENT;

const waiting = (what) =>
  el("div", { class: "stack", style: "gap: 10px;" },
    el("p", { class: "prose" }, `Asking the daemon for ${what}.`),
    el("p", { class: "prose" },
      "A full candidate sweep has taken up to 38.8 seconds here against one live adapter, " +
      "so this can be slow. Nothing is shown until it answers — an invented placeholder " +
      "would be indistinguishable from a real quote."));

const failure = (r) =>
  el("div", { class: "panel fault stack", style: "gap: 8px;" },
    el("div", { class: "eyebrow" }, r.body?.state || `http ${r.status}`),
    el("p", { class: "prose" }, r.body?.reason || "The read failed and the daemon gave no reason."));

// ── Candidates ───────────────────────────────────────────────────────────────
async function renderCandidates() {
  surface.replaceChildren(waiting("candidates"));
  const r = await read(`/api/candidates?intent_ref=${encodeURIComponent(intentRef)}`);
  if (!r.ok) return surface.replaceChildren(failure(r));

  const candidates = Array.isArray(r.body.candidates) ? r.body.candidates : [];
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

  const rows = [
    el("div", { class: "trow head" },
      el("div", {}, "venue"), el("div", {}, "evidence"), el("div", {}, "per hour"), el("div", {}, "good until")),
  ];

  if (cheapest) {
    const mins = minutesLeft(cheapest.expires_at);
    rows.push(el("div", { class: "trow" },
      el("div", { class: "stack", style: "gap: 7px;" },
        el("div", { class: "mono", style: "font-size: 14px;" }, cheapest.provider_kind || "—"),
        chip("live_evidence", "live")),
      el("div", { class: "mono", style: "font-size: 13px; color: var(--label); line-height: 1.5;" },
        cheapest.quote.basis,
        el("br"),
        cheapest.quote.quote_ref || ""),
      el("div", { class: "mono", style: "font-size: 16px;" }, `$${cheapest.quote.usd_per_hour.toFixed(4)}`),
      el("div", { class: "stack", style: "gap: 5px;" },
        el("div", { class: "mono", style: "font-size: 13px;" }, clock(cheapest.expires_at)),
        el("div", { class: "mono", style: "font-size: 12px; color: var(--label);" },
          mins > 0 ? `${mins} min left` : "expired"))));
  }

  const remainder = live.filter((c) => c !== cheapest);
  if (remainder.length) {
    const kinds = [...new Set(remainder.map((c) => c.provider_kind))];
    rows.push(el("div", { class: "trow" },
      el("div", { class: "mono", style: "font-size: 14px; color: var(--label);" }, kinds.join(", ")),
      el("div", { class: "prose" },
        `${remainder.length} further live quotes` +
        (kinds.length === 1 && kinds[0] === cheapest?.provider_kind
          ? " from the same venue — priced and comparable to each other, but they add no venue diversity."
          : ".")),
      el("div", { class: "mono", style: "font-size: 13px; color: var(--label);" },
        `$${Math.min(...remainder.map((c) => c.quote.usd_per_hour)).toFixed(4)} up`),
      el("div", { class: "mono", style: "font-size: 13px; color: var(--label);" }, "same window")));
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
    rows.push(el("div", { class: "trow" },
      el("div", { class: "stack", style: "gap: 7px;" },
        el("div", { class: "mono", style: "font-size: 13px; color: var(--label);" },
          [...entry.kinds].sort().join(", ")),
        chip(reason === "expired" ? "expired" : "not a price", reason === "expired" ? "expired" : "")),
      el("div", { class: "prose" },
        `${entry.count} candidate${entry.count === 1 ? "" : "s"} — ${reason}.`),
      el("div", { class: "mono", style: "font-size: 13px; color: var(--label);" }, "—"),
      el("div", { class: "mono", style: "font-size: 13px; color: var(--label);" }, "—")));
  }

  surface.replaceChildren(
    el("div", { class: "stack", style: "gap: 26px;" },
      el("div", { class: "stack", style: "gap: 10px;" },
        el("h1", {}, r.body.intent_summary || "Candidates"),
        el("div", { class: "meta" },
          `${intentRef} · observed ${clock(observed)} · this read took ${(r.ms / 1000).toFixed(1)}s`)),
      venueVerdict,
      el("div", { class: "eyebrow" }, "Evidence"),
      el("div", { class: "table" }, rows),
      el("p", { class: "prose" },
        "A price appears in this table only when the daemon returned it as live_evidence " +
        "with an observed_at, an expires_at still in the future, and a quote reference it " +
        "can be traced back to. Simulator lanes are excluded from the table, from the " +
        "venue count, and from any fee.")));
}

// ── Sources ──────────────────────────────────────────────────────────────────
async function renderSources() {
  surface.replaceChildren(waiting("source health"));
  const r = await read("/api/candidate-sources");
  if (!r.ok) return surface.replaceChildren(failure(r));

  const sources = Array.isArray(r.body.sources) ? r.body.sources : [];
  const quoting = sources.filter((s) => s.state === "live_quote_source");
  const absent = sources.filter((s) => s.state === "candidate_source_unavailable");
  const answering = sources.filter((s) => !quoting.includes(s) && !absent.includes(s));

  const row = (s) => {
    const kind = s.state === "live_quote_source" || s.state === "available" || s.state === "storage_backends_engaged"
      ? "live" : s.state === "candidate_source_unavailable" ? "" : "muted";
    return el("div", { class: "srow" },
      el("div", { class: "srow-head" },
        el("span", { class: "mono", style: "font-size: 14px;" }, s.source),
        chip(s.state, kind)),
      el("div", { class: "srow-reason" }, s.reason || s.coverage || s.rule || ""));
  };

  surface.replaceChildren(
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
  surface.replaceChildren(waiting("the placement advisory"));
  const [advisory, venues] = await Promise.all([
    read(`/api/placement-advisory${intentRef ? `?intent_ref=${encodeURIComponent(intentRef)}` : ""}`),
    read("/api/venues"),
  ]);
  if (!advisory.ok) return surface.replaceChildren(failure(advisory));

  surface.replaceChildren(
    el("div", { class: "stack", style: "gap: 24px;" },
      el("h1", {}, "Placement"),
      el("p", { class: "prose" },
        "An advisory is evidence, not authority. A placement decision cannot provision " +
        "anything: provider mutation still requires a wallet capability grant, and this " +
        "surface holds none and asks for none."),
      el("div", { class: "eyebrow" }, "Advisory, as returned"),
      el("pre", { class: "code" }, JSON.stringify(advisory.body, null, 2)),
      venues.ok
        ? el("div", { class: "stack", style: "gap: 12px;" },
            el("div", { class: "eyebrow" }, "Venues, as returned"),
            el("pre", { class: "code" }, JSON.stringify(venues.body, null, 2)))
        : failure(venues)));
}

// ── Submit a job: designed, not connected ────────────────────────────────────
function renderJob() {
  const field = (label, value, hint) =>
    el("div", { class: "field" },
      el("div", { class: "field-label" }, label),
      el("div", { class: "field-box" }, el("span", {}, value), el("span", { class: "mono" }, "▾")),
      hint ? el("div", { class: "field-hint" }, hint) : null);

  surface.replaceChildren(
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
      el("div", { style: "display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 20px 24px; max-width: 900px;" },
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
        chip("not wired — job api not live", "muted"))));
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

  surface.replaceChildren(
    el("div", { class: "stack", style: "gap: 24px;" },
      el("h1", {}, "API"),
      el("p", { class: "prose" },
        "Four reads, exact-match and GET-only. A path that is not on this list is refused " +
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
          "The venue set the placement plane knows about.")),
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
  api: renderApi,
};

for (const button of document.querySelectorAll(".nav button")) {
  button.addEventListener("click", () => {
    for (const b of document.querySelectorAll(".nav button")) b.removeAttribute("aria-current");
    button.setAttribute("aria-current", "page");
    SURFACES[button.dataset.surface]();
  });
}

document.getElementById("daemon-label").textContent = `daemon ${location.host}`;
renderCandidates();

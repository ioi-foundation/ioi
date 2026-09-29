// Operations / Telemetry — the product lane over the telemetry plane (ADR 0056 Amendment 1, plane 6).
//
// SEEDED FROM THE PRESERVED QUIVER PORT, NOT RECREATED. Amendment 1 split Quiver: "its time-series core
// becomes Operations / Telemetry, seeded from the preserved Quiver port (a rebinding of the seed, not a
// recreation)"; its BI dashboard builder is a terminal absence. The Quiver port is the I-4 splash-landing
// grammar (splash-landing-grammar.mjs) instantiated with the configuration serve-product-ui.mjs serves at
// /__ioi/evaluations/quiver: its app chip and tint, its "New analysis" entry, its Recents / Favorites view
// row and its recents table over a TYPED-ABSENT body. This lane runs that same implementation with that
// same configuration and rebinds its body to daemon truth: the recents table lists the caller's series
// (GET /v1/hypervisor/telemetry/series), and a series opens in the same grammar over the plane's bounded
// range read (GET /v1/hypervisor/telemetry/series/:id/range) — its raw points, the rolling mean the daemon
// derived and named, and the window and bounds it was held to. Nothing is computed here that the daemon
// did not answer; the chart plots the answer's own points.
//
// What the Quiver port offered that the daemon has no counterpart for stays where it was, disabled, with
// its reason (the unified gap contract: aria-disabled + title + data-ioi-disabled-reason): authoring an
// analysis (the BI builder is terminal; a series is declared by the producer that emits it), favorites,
// marketplace installs, formulas across series, annotations, export.
import { escHtml as esc, refusalCodeOf } from "../surfaces/kit.mjs";
import { renderSplashLanding } from "./splash-landing-grammar.mjs";
import { EVL_APP_TILE_URI } from "./evalsuites-assets.mjs";

export const TELEMETRY_ROUTE = "/operations/telemetry";
export const TELEMETRY_LANE = "/__ioi/operations/telemetry";

// The Quiver port's configuration, as served at /__ioi/evaluations/quiver — adopted verbatim where it
// still holds, rebound where the body now has a plane behind it (each rebinding says so).
const QUIVER_PORT = Object.freeze({
  appTileUri: EVL_APP_TILE_URI,
  chipTintRgba: "rgba(45,114,210,.08)",
  newLabel: "New analysis",
});
const GAP = Object.freeze({
  newAnalysis: "Quiver's analysis canvas and BI dashboard builder are a terminal absence (ADR 0056 Amendment 1): a series is declared by the daemon producer that emits its points — today Health's Evaluate — never authored here",
  favorites: "No favorites plane: the daemon keeps no per-person saved series (named gap)",
  store: "Marketplace install lanes are not bound to Telemetry (named gap)",
  help: "Reference help lane (named gap)",
  formula: "Only one derived series exists on the daemon — the rolling mean named in each range answer; formulas across series have no daemon counterpart (named gap)",
  annotate: "Annotations have no plane on the daemon: a point is what a producer admitted, and nothing annotates it (named gap)",
  export: "Export has no daemon route: the range answer is the one read, and no export or OTLP egress is declared (named gap)",
});

const SPANS = Object.freeze({ "1h": 3_600_000, "24h": 86_400_000, "7d": 7 * 86_400_000, "30d": 30 * 86_400_000 });
const tailOf = (ref, scheme) => (String(ref || "").startsWith(scheme) ? String(ref).slice(scheme.length) : "");
const seriesTail = (ref) => tailOf(ref, "telemetry-series://") || String(ref || "");
const when = (ms) => {
  const m = /^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})/u.exec(Number.isFinite(ms) ? new Date(ms).toISOString() : "");
  return m ? `${m[1]} ${m[2]} UTC` : "—";
};
const gap = (cls, label, reason) => `<span class="${cls} gap" aria-disabled="true" title="${esc(reason)}" data-ioi-disabled-reason="${esc(reason)}">${esc(label)}</span>`;

// A value in its unit: `1` is dimensionless, `s` seconds, `{token}` an annotated count.
export function valueText(value, unit) {
  if (typeof value !== "number" || !Number.isFinite(value)) return "—";
  const shown = Number.isInteger(value) ? String(value) : String(Math.round(value * 1000) / 1000);
  if (!unit || unit === "1") return shown;
  const annotated = /^\{(.+)\}$/u.exec(unit);
  return annotated ? `${shown} ${annotated[1]}${value === 1 ? "" : "s"}` : `${shown} ${unit}`;
}

// A subject or scope reference, linked to the surface that owns it.
export function subjectLink(ref) {
  const r = String(ref || "");
  const system = tailOf(r, "system://");
  if (system) return `<a href="/systems/${system.split("/").map(encodeURIComponent).join("/")}"><code>${esc(r)}</code></a>`;
  const check = tailOf(r, "health-check://");
  if (check) return `<a href="/operations/health?check=${encodeURIComponent(check)}#check-detail"><code>${esc(r)}</code></a>`;
  const automation = tailOf(r, "automation://");
  if (automation) return `<a href="/__ioi/automations/${encodeURIComponent(automation)}"><code>${esc(r)}</code></a>`;
  if (r.startsWith("automation-run://")) return `<a href="/automations?run=${encodeURIComponent(r)}"><code>${esc(r)}</code></a>`;
  if (r.startsWith("environment://")) return `<a href="/__ioi/environments"><code>${esc(r)}</code></a>`;
  return `<code>${esc(r || "—")}</code>`;
}

function sourceLink(ref) {
  const r = String(ref || "");
  const m = /^observation:\/\/health-check\/(hc_[0-9a-f]+)\//u.exec(r);
  if (m) return `<a href="/operations/health?check=${encodeURIComponent(m[1])}#check-detail"><code>${esc(r)}</code></a>`;
  return r ? subjectLink(r) : "—";
}

async function readJson(daemonFetch, path) {
  try {
    const r = await daemonFetch(path);
    return { status: r.status, body: await r.json().catch(() => ({})) };
  } catch (e) {
    return { status: 0, body: {}, networkError: String((e && e.message) || e) };
  }
}

function refusal(r) {
  if (r.networkError) return "daemon_unreachable";
  if (r.status === 200 && r.body?.ok !== false) return "";
  return r.body?.error?.code || refusalCodeOf(r.body || {}, r.status) || `http_${r.status}`;
}

// The range answer, plotted: each raw point where the answer put it (admitted filled, ephemeral hollow),
// and the derived series as a line. Scales come from the answer's own window and values.
export function renderRangeChart(range, { compact = false } = {}) {
  const points = Array.isArray(range?.points) ? range.points : [];
  const derived = Array.isArray(range?.derived?.points) ? range.derived.points : [];
  const from = range?.window?.from_unix_ms ?? 0;
  const to = range?.window?.to_unix_ms ?? from + 1;
  const values = [...points.map((p) => p.value), ...derived.map((p) => p.value)].filter((v) => typeof v === "number" && Number.isFinite(v));
  const [W, H, P] = compact ? [320, 80, 6] : [960, 160, 14];
  if (!values.length) {
    return `<div class="tl-chart tl-chart-empty" data-telemetry-chart="empty">No point falls in this window.</div>`;
  }
  let lo = Math.min(...values), hi = Math.max(...values);
  if (lo === hi) { lo -= 1; hi += 1; }
  const x = (t) => P + ((t - from) / Math.max(1, to - from)) * (W - 2 * P);
  const y = (v) => H - P - ((v - lo) / (hi - lo)) * (H - 2 * P);
  const dots = points.map((p) => `<circle cx="${x(p.time_unix_ms).toFixed(1)}" cy="${y(p.value).toFixed(1)}" r="3.5" class="${p.point_class === "admitted" ? "tl-dot" : "tl-dot tl-eph"}"><title>${esc(`${when(p.time_unix_ms)} · ${p.value} · ${p.point_class}`)}</title></circle>`).join("");
  const line = derived.length > 1 ? `<polyline class="tl-derived" points="${derived.map((p) => `${x(p.time_unix_ms).toFixed(1)},${y(p.value).toFixed(1)}`).join(" ")}"/>` : "";
  const label = `${range.metric?.name || "series"}: ${points.length} point(s) from ${when(from)} to ${when(to)}; the line is the ${range.derived?.derivation || "derived series"}`;
  return `<svg class="tl-chart" data-telemetry-chart="1" viewBox="0 0 ${W} ${H}" role="img" aria-label="${esc(label)}"><title>${esc(label)}</title><line x1="${P}" y1="${H - P}" x2="${W - P}" y2="${H - P}" class="tl-axis"/>${compact ? "" : `<text x="${P}" y="${P - 2}" class="tl-tick">${esc(String(Math.round(hi * 1000) / 1000))}</text><text x="${P}" y="${H - 2}" class="tl-tick">${esc(String(Math.round(lo * 1000) / 1000))}</text>`}${line}${dots}</svg>`;
}

const CHART_CSS = `<style>.tl-panel{padding:14px 32px 0}.tl-chart{width:100%;height:auto;min-height:40px;display:block;background:#f6f7f9;border:1px solid #e5e8eb;border-radius:4px}.tl-chart-empty{display:flex;align-items:center;justify-content:center;color:#5f6b7c;font-size:13px}.tl-axis{stroke:#c5cbd3;stroke-width:1}.tl-tick{fill:#5f6b7c;font-size:10px}.tl-dot{fill:#215db0}.tl-eph{fill:#fff;stroke:#215db0;stroke-width:1.5}.tl-derived{fill:none;stroke:#238551;stroke-width:2}.tl-facts{font-size:12px;color:#5f6b7c;margin:8px 0 0;line-height:1.6}.tl-facts code,.spl-rows code{word-break:break-all}.tl-verbs{display:flex;flex-wrap:wrap;gap:8px;margin:10px 0 0}.tl-verbs .gap{font-size:13px;border:1px solid rgba(95,107,124,.25);border-radius:4px;padding:3px 8px;opacity:.62;cursor:not-allowed}.tl-spans{display:flex;flex-wrap:wrap;gap:10px;font-size:13px;margin:0 0 10px}.tl-spans .on{font-weight:600;color:#1c2127}.tl-legend{font-size:12px;color:#5f6b7c}.tl-chart-empty{height:80px}.spl-rows .spl-row a{display:inline;padding:0;border:0;grid-template-columns:none}@media (max-width:640px){.tl-panel{padding:12px 16px 0}.spl-table{padding:10px 16px 40px}.spl-thead{display:none}.spl-rows .spl-row{grid-template-columns:1fr!important;gap:2px}}</style>`;

// ---- The block a System's Overview embeds (pure) --------------------------------------------------
// entries: [{ series, range, error }] — each series about the target with its range answer, or the code
// its read was refused with. Renders what it is given and links the lane for everything else.
export function renderTargetTelemetry(targetRef, entries) {
  const lane = `${TELEMETRY_ROUTE}?about=${encodeURIComponent(targetRef)}`;
  if (!entries.length) {
    return `<div class="empty" data-target-telemetry="${esc(targetRef)}" data-target-telemetry-empty="1">No telemetry series is about this yet. Each evaluation of a health check that observes it records its outcome as a point — <a href="/operations/health?target=${encodeURIComponent(targetRef)}#new-check">declare one in Operations / Health →</a> · <a href="${esc(lane)}">Operations / Telemetry →</a></div>`;
  }
  const rows = entries.map(({ series, range, error }) => {
    const tail = seriesTail(series.series_id);
    const unit = series.metric?.unit || "";
    const head = `<td><a href="${TELEMETRY_ROUTE}?series=${encodeURIComponent(tail)}"><code>${esc(series.metric?.name || "")}</code></a><br><span class="sub" style="margin:0">about ${subjectLink(series.subject_ref)}</span></td>`;
    if (error) {
      return `<tr data-system-telemetry-series="${esc(series.series_id)}">${head}<td colspan="4"><span data-system-telemetry-range-unavailable="${esc(error)}">The range read was refused — <code>${esc(error)}</code>. Nothing is shown in its place.</span></td></tr>`;
    }
    const points = range.points || [];
    const latest = points[points.length - 1] || null;
    const mean = (range.derived?.points || []).at(-1);
    const latestCell = latest
      ? `<span data-telemetry-point-source="${esc(latest.source_ref || "")}" data-telemetry-point-class="${esc(latest.point_class)}" data-telemetry-point-value="${esc(String(latest.value))}">${esc(valueText(latest.value, unit))}</span><br><span class="sub" style="margin:0">${esc(when(latest.time_unix_ms))} · ${esc(latest.point_class)}${latest.receipt_ref ? " · receipted" : ""}</span>`
      : `<span class="sub" style="margin:0">no point in the last 7 days</span>`;
    const meanCell = mean
      ? `<span data-telemetry-derived="${esc(range.derived.derivation)}">${esc(valueText(mean.value, unit))}</span><br><span class="sub" style="margin:0">${esc(range.derived.derivation.replace(/_/gu, " "))} of the last ${esc(String(range.derived.window_points))} point(s)</span>`
      : "—";
    return `<tr data-system-telemetry-series="${esc(series.series_id)}">${head}<td>${latestCell}</td><td>${meanCell}</td><td>${esc(String(range.points_in_window))}</td><td style="min-width:200px">${renderRangeChart(range, { compact: true })}</td></tr>`;
  }).join("");
  return `${CHART_CSS}<div class="hc-scroll" style="overflow-x:auto"><table data-target-telemetry="${esc(targetRef)}"><thead><tr><th>Series</th><th>Latest point</th><th>Derived</th><th>Points (7 days)</th><th>Trend</th></tr></thead><tbody>${rows}</tbody></table></div><p class="sub">Read from the telemetry plane as you (ADR 0056 P6): admitted points are replayed from each series' event stream with their receipts; ephemeral samples are held only in the daemon's memory and are gone after a restart. <a href="${esc(lane)}">Every series in Operations / Telemetry →</a></p>`;
}

// ---- The lane ---------------------------------------------------------------------------------------
export function renderTelemetryLanding(listR, query) {
  const code = refusal(listR);
  const about = (query.get("about") || "").trim();
  const all = code ? [] : (listR.body.series || []);
  const shown = about ? all.filter((s) => s.subject_ref === about || s.scope_ref === about) : all;
  let rowsHtml = "";
  if (code) {
    const signIn = /principal_required/u.test(code) ? ` <a href="/__ioi/login?next=${encodeURIComponent(TELEMETRY_ROUTE)}" target="_top">Sign in</a> to see your series.` : "";
    rowsHtml = `<div class="spl-empty" data-telemetry-unavailable="${esc(code)}">The telemetry plane refused this read — <code>${esc(code)}</code>. Nothing is shown in its place.${signIn}</div>`;
  } else {
    rowsHtml = shown.map((s) => {
      const tail = seriesTail(s.series_id);
      const lp = s.latest_point;
      return `<a href="${TELEMETRY_ROUTE}?series=${encodeURIComponent(tail)}" data-telemetry-series="${esc(s.series_id)}"><span><code>${esc(s.metric?.name || "")}</code></span><span><code>${esc(s.subject_ref || "")}</code>${s.scope_ref ? `<br><span style="color:#5f6b7c;font-size:12px">serves ${esc(s.scope_ref)}</span>` : ""}</span><span>${esc(s.metric?.unit || "")} · ${esc(s.metric?.instrument || "")}</span><span>${lp ? `${esc(valueText(lp.value, s.metric?.unit))} · ${esc(when(lp.time_unix_ms))} · ${esc(lp.point_class)}` : "no point yet"}</span></a>`;
    }).join("");
  }
  const filterNote = about ? ` Showing the series about <code>${esc(about)}</code> — <a href="${TELEMETRY_ROUTE}">all series</a>.` : "";
  return renderSplashLanding({
    slug: "operations/telemetry", routeOverride: TELEMETRY_LANE, title: "Operations / Telemetry",
    ...QUIVER_PORT,
    newGapReason: GAP.newAnalysis,
    storeGapReason: GAP.store, helpGapReason: GAP.help, favoritesGapReason: GAP.favorites,
    heroTitle: "Telemetry",
    heroDesc: "Metric trends about your Systems, their runs, environments and agents, read from the daemon's telemetry plane: each series is one event stream, and every admitted point carries its receipt.",
    columns: ["Series", "Subject", "Unit", "Last point"],
    rowsHtml,
    emptyCopy: "No series yet — each evaluation of a health check records its outcome here (Operations / Health). This table renders the daemon's series and never fabricates rows.",
    footHtml: `ADR 0056 Amendment 1, plane 6 — seeded from the preserved Quiver port: the same landing implementation (splash-landing-grammar.mjs) and configuration as <a href="/__ioi/evaluations/quiver">/__ioi/evaluations/quiver</a>, its recents table rebound from a typed absence onto <code>GET /v1/hypervisor/telemetry/series</code>.${filterNote} Producers today: Health's Evaluate (<code>ioi.health_check.passed</code>, admitted; <code>ioi.health_check.duration</code>, ephemeral). Named gaps: OpenTelemetry GenAI model and agent series (<code>gen_ai.client.token.usage</code>, <code>gen_ai.client.operation.duration</code>) are in the plane's profile with no producer wired yet; no external producer (OTLP ingest) route exists. Family: <a href="/operations">Operations</a> · <a href="/operations/health">Health</a> · <a href="/operations/issues">Issues</a>.`,
  });
}

export function renderTelemetrySeries(tail, seriesR, rangeR, query, spanKey) {
  const code = refusal(seriesR) || refusal(rangeR);
  const series = seriesR.body?.series_record || null;
  const range = rangeR.body?.range || null;
  const spans = `<div class="tl-spans" data-telemetry-spans="1">${Object.keys(SPANS).map((k) => k === spanKey ? `<span class="on">Last ${esc(k)}</span>` : `<a href="${TELEMETRY_ROUTE}?series=${encodeURIComponent(tail)}&amp;span=${esc(k)}">Last ${esc(k)}</a>`).join("")}</div>`;
  if (code || !series || !range) {
    const why = code || "telemetry_range_unreadable";
    return renderSplashLanding({
      slug: "operations/telemetry", routeOverride: TELEMETRY_LANE, title: "Operations / Telemetry", ...QUIVER_PORT,
      newGapReason: GAP.newAnalysis, storeGapReason: GAP.store, helpGapReason: GAP.help, favoritesGapReason: GAP.favorites,
      heroTitle: "Series", heroDesc: `telemetry-series://${tail}`, viewLabel: "Points",
      columns: ["Observed", "Value", "Rolling mean", "Class · source · receipt"],
      rowsHtml: `<div class="spl-empty" data-telemetry-unavailable="${esc(why)}">This series could not be read — <code>${esc(why)}</code>. Nothing is shown in its place. <a href="${TELEMETRY_ROUTE}">All series</a></div>`,
      emptyCopy: "", footHtml: `<a href="${TELEMETRY_ROUTE}">← All series</a>`,
    });
  }
  const unit = series.metric?.unit || "";
  const derivedAt = new Map((range.derived?.points || []).map((p) => [p.time_unix_ms, p.value]));
  const rowsHtml = [...(range.points || [])].reverse().map((p) => `<div class="spl-row" data-telemetry-point="${esc(p.source_ref || "")}" data-telemetry-point-class="${esc(p.point_class)}"><span>${esc(when(p.time_unix_ms))}</span><span>${esc(valueText(p.value, unit))}${(p.attributes || []).map((a) => `<br><span style="color:#5f6b7c;font-size:12px">${esc(a.key)} = ${esc(String(a.value))}</span>`).join("")}</span><span>${derivedAt.has(p.time_unix_ms) ? esc(valueText(derivedAt.get(p.time_unix_ms), unit)) : "—"}</span><span>${esc(p.point_class)} · ${sourceLink(p.source_ref)}${p.receipt_ref ? `<br><code style="font-size:11px">${esc(p.receipt_ref)}</code>` : `<br><span style="color:#5f6b7c;font-size:12px">no receipt (ephemeral)</span>`}</span></div>`).join("");
  const w = range.window || {};
  const facts = `<p class="tl-facts">About ${subjectLink(series.subject_ref)}${series.scope_ref ? `, serving ${subjectLink(series.scope_ref)}` : ""} · <code>${esc(series.metric?.name || "")}</code> in <code>${esc(unit)}</code> (${esc(series.metric?.instrument || "")}; ${esc(series.metric?.semantic_convention?.registry === "opentelemetry" ? "an OpenTelemetry semantic convention" : "an ioi. name — no OpenTelemetry convention fits")}) · produced by <code>${esc(series.producer_ref || "")}</code> for <code>${esc(series.producer_principal_ref || "")}</code>.<br>Window ${esc(when(w.from_unix_ms))} → ${esc(when(w.to_unix_ms))}, step ${esc(String(w.step_seconds))} s: ${esc(String(range.points_in_window))} point(s)${range.points_truncated ? `, the newest ${esc(String(range.bounds?.max_points))} shown` : ""}. <span data-telemetry-derivation="${esc(range.derived?.derivation || "")}"><b>Derived:</b> ${esc((range.derived?.derivation || "").replace(/_/gu, " "))} over ${esc(String(range.derived?.window_points))} point(s) — ${esc(range.derived?.formula || "")}</span>. Ephemeral samples held: ${esc(String(range.ephemeral_window?.held_points ?? 0))} of ${esc(String(range.ephemeral_window?.window_points ?? 0))}, in the daemon's memory only (gone after a restart). Stream <code>${esc(series.stream_id || "")}</code>.</p>`;
  const verbs = `<div class="tl-verbs">${gap("tl-verb", "Add formula", GAP.formula)}${gap("tl-verb", "Annotate", GAP.annotate)}${gap("tl-verb", "Export", GAP.export)}</div>`;
  const panelHtml = `${CHART_CSS}<div class="tl-panel" data-telemetry-detail="${esc(series.series_id)}">${spans}${renderRangeChart(range)}<div class="tl-legend">● admitted point · ○ ephemeral sample · — ${esc((range.derived?.derivation || "").replace(/_/gu, " "))}</div>${facts}${verbs}</div>`;
  return renderSplashLanding({
    slug: "operations/telemetry", routeOverride: TELEMETRY_LANE, title: "Operations / Telemetry", ...QUIVER_PORT,
    newGapReason: GAP.newAnalysis, storeGapReason: GAP.store, helpGapReason: GAP.help, favoritesGapReason: GAP.favorites,
    heroTitle: series.metric?.name || "Series",
    heroDesc: series.metric?.description || "",
    viewLabel: "Points",
    panelHtml,
    columns: ["Observed", "Value", "Rolling mean", "Class · source · receipt"],
    rowsHtml,
    emptyCopy: "No point falls in this window. Widen it above, or evaluate the check again.",
    footHtml: `<a href="${TELEMETRY_ROUTE}">← All series</a> · read from <code>GET /v1/hypervisor/telemetry/series/${esc(tail)}/range</code>; nothing on this page is stored or computed by the page.`,
  });
}

export async function handleOperationsTelemetry(req, res, pathname, deps) {
  if (pathname !== TELEMETRY_LANE || req.method !== "GET") return false;
  const { daemonFetch, sendHtml } = deps;
  const query = new URL(req.url, "http://x").searchParams;
  const tail = seriesTail((query.get("series") || "").trim());
  if (!tail) {
    sendHtml(res, 200, renderTelemetryLanding(await readJson(daemonFetch, "/v1/hypervisor/telemetry/series"), query));
    return true;
  }
  if (!/^ts_[0-9a-f]{16}$/u.test(tail)) {
    sendHtml(res, 200, renderTelemetrySeries("unknown", { status: 404, body: { ok: false, error: { code: "telemetry_series_not_found" } } }, { status: 404, body: {} }, query, "24h"));
    return true;
  }
  const spanKey = Object.hasOwn(SPANS, query.get("span") || "") ? query.get("span") : "24h";
  const now = Date.now();
  const params = new URLSearchParams({ from: String(now - SPANS[spanKey]), to: String(now + 1) });
  const [seriesR, rangeR] = await Promise.all([
    readJson(daemonFetch, `/v1/hypervisor/telemetry/series/${encodeURIComponent(tail)}`),
    readJson(daemonFetch, `/v1/hypervisor/telemetry/series/${encodeURIComponent(tail)}/range?${params}`),
  ]);
  sendHtml(res, 200, renderTelemetrySeries(tail, seriesR, rangeR, query, spanKey));
  return true;
}

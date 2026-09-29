// Operations / Telemetry (ADR 0056 P6) — the lane's pure renderers over the telemetry plane's answers.
import test from "node:test";
import assert from "node:assert/strict";
import { renderRangeChart, renderTargetTelemetry, renderTelemetryLanding, renderTelemetrySeries, valueText } from "./operations-telemetry.mjs";

const SYSTEM = "system://acme/lending";
const RESULT = "observation://health-check/hc_0123456789abcdef/hcr_fedcba9876543210";
const series = {
  series_id: "telemetry-series://ts_3f9a1c72b4e8d605", subject_ref: "health-check://hc_0123456789abcdef", scope_ref: SYSTEM,
  metric: { name: "ioi.health_check.passed", unit: "1", instrument: "gauge", description: "1 when an evaluation passed", semantic_convention: { registry: "ioi" } },
  stream_id: "event-stream://hypervisor-telemetry/series.ts_3f9a1c72b4e8d605", producer_ref: "daemon-producer://health-check-evaluate",
  producer_principal_ref: "user://ada", latest_point: { point_class: "admitted", time_unix_ms: 1790676300000, value: 1 },
};
const range = {
  metric: { name: "ioi.health_check.passed", unit: "1", instrument: "gauge" },
  window: { from_unix_ms: 1790668800000, to_unix_ms: 1790676600000, step_seconds: 3600 },
  bounds: { max_span_ms: 2678400000, max_buckets: 1440, max_points: 1000 },
  points: [
    { point_class: "admitted", time_unix_ms: 1790672400000, value: 0, attributes: [{ key: "ioi.health_check.outcome", value: "failed" }], source_ref: "observation://health-check/hc_0123456789abcdef/hcr_0000000000000001", receipt_ref: "receipt://agentgres/x" },
    { point_class: "admitted", time_unix_ms: 1790676300000, value: 1, attributes: [{ key: "ioi.health_check.outcome", value: "passed" }], source_ref: RESULT, receipt_ref: "receipt://agentgres/y" },
  ],
  points_in_window: 2, points_truncated: false,
  derived: { derivation: "rolling_mean", window_points: 5, formula: "mean of the last 5", points: [{ time_unix_ms: 1790672400000, value: 0 }, { time_unix_ms: 1790676300000, value: 0.5 }] },
  ephemeral_window: { retention: "process_memory", window_points: 512, held_points: 0 },
};

test("a value reads in its unit", () => {
  assert.equal(valueText(1, "1"), "1");
  assert.equal(valueText(0.1823, "s"), "0.182 s");
  assert.equal(valueText(12, "{token}"), "12 tokens");
  assert.equal(valueText(undefined, "s"), "—");
});

test("the chart plots the answer's own points and its derived line, and says when nothing falls in the window", () => {
  const svg = renderRangeChart(range);
  assert.equal((svg.match(/<circle /gu) || []).length, 2);
  assert.match(svg, /class="tl-derived"/u);
  assert.match(svg, /rolling_mean/u);
  assert.match(renderRangeChart({ ...range, points: [], derived: { ...range.derived, points: [] } }), /data-telemetry-chart="empty"/u);
});

test("a System's block names each series' latest point by its source, and a refused range by its code", () => {
  const html = renderTargetTelemetry(SYSTEM, [{ series, range }, { series: { ...series, series_id: "telemetry-series://ts_0000000000000000" }, error: "request_resource_scope_required" }]);
  assert.match(html, new RegExp(`data-telemetry-point-source="${RESULT}" data-telemetry-point-class="admitted"`, "u"));
  assert.match(html, /data-telemetry-derived="rolling_mean"/u);
  assert.match(html, /data-system-telemetry-range-unavailable="request_resource_scope_required"/u);
  assert.match(renderTargetTelemetry(SYSTEM, []), /data-target-telemetry-empty="1"/u);
});

test("the landing is the Quiver port's grammar over the caller's series; every Quiver gap carries the unified contract", () => {
  const html = renderTelemetryLanding({ status: 200, body: { ok: true, series: [series] } }, new URLSearchParams());
  assert.match(html, /data-telemetry-series="telemetry-series:\/\/ts_3f9a1c72b4e8d605"/u);
  assert.match(html, /New analysis/u);
  const disabled = (html.match(/aria-disabled="true"/gu) || []).length;
  assert.ok(disabled >= 4);
  assert.equal(disabled, (html.match(/data-ioi-disabled-reason=/gu) || []).length);
  const refused = renderTelemetryLanding({ status: 401, body: { ok: false, code: "request_principal_required" } }, new URLSearchParams());
  assert.match(refused, /data-telemetry-unavailable="request_principal_required"/u);
  assert.match(refused, /Sign in/u);
});

test("a series opens over its range read with the derivation named and the canvas verbs disabled with reasons", () => {
  const html = renderTelemetrySeries("ts_3f9a1c72b4e8d605", { status: 200, body: { ok: true, series_record: series } }, { status: 200, body: { ok: true, range } }, new URLSearchParams(), "24h");
  assert.match(html, new RegExp(`data-telemetry-point="${RESULT}" data-telemetry-point-class="admitted"`, "u"));
  assert.match(html, /data-telemetry-derivation="rolling_mean"/u);
  for (const verb of ["Add formula", "Annotate", "Export"]) assert.match(html, new RegExp(`data-ioi-disabled-reason="[^"]+">${verb}<`, "u"));
  const refused = renderTelemetrySeries("ts_3f9a1c72b4e8d605", { status: 404, body: { ok: false, error: { code: "telemetry_series_not_found" } } }, { status: 404, body: {} }, new URLSearchParams(), "24h");
  assert.match(refused, /data-telemetry-unavailable="telemetry_series_not_found"/u);
});

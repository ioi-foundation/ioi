import assert from "node:assert/strict";
import test from "node:test";

import { HYPERVISOR_HOME_COCKPIT_PROJECTION } from "./homeCockpitModel.ts";

test("home cockpit projection summarizes core surfaces without becoming truth", () => {
  const projection = HYPERVISOR_HOME_COCKPIT_PROJECTION;

  assert.equal(
    projection.schema_version,
    "ioi.hypervisor.home_cockpit_projection.v1",
  );
  assert.equal(projection.runtimeTruthSource, "daemon-runtime");
  assert.match(projection.boundary_invariant, /does not become runtime/);
  assert.match(projection.boundary_invariant, /authority/);
  assert.match(projection.boundary_invariant, /restore/);
  assert.match(projection.boundary_invariant, /storage truth/);

  const labels = new Set(projection.metrics.map((metric) => metric.label));
  for (const expected of [
    "Project restore",
    "Active session",
    "Privacy gates",
    "Provider posture",
    "Receipt evidence",
    "Harness comparison",
  ]) {
    assert.ok(labels.has(expected), expected);
  }
});

test("home cockpit metrics carry surface refs and evidence refs", () => {
  for (const metric of HYPERVISOR_HOME_COCKPIT_PROJECTION.metrics) {
    assert.ok(metric.metric_ref.startsWith("home-cockpit:"));
    assert.ok(metric.surface_ref.startsWith("surface:"));
    assert.ok(metric.value.length > 0);
    assert.ok(metric.detail.length > 0);
    assert.ok(metric.evidence_refs.length > 0);
  }

  assert.ok(
    HYPERVISOR_HOME_COCKPIT_PROJECTION.metrics.some(
      (metric) =>
        metric.surface_ref === "surface:privacy" &&
        metric.evidence_refs.every((ref) => ref.startsWith("receipt://privacy/")),
    ),
  );
  assert.ok(
    HYPERVISOR_HOME_COCKPIT_PROJECTION.metrics.some(
      (metric) =>
        metric.surface_ref === "surface:projects" &&
        metric.evidence_refs.some((ref) => ref.startsWith("agentgres://state-root/")),
    ),
  );
});

import assert from "node:assert/strict";
import test from "node:test";

import {
  HYPERVISOR_HOME_COCKPIT_PROJECTION,
  HYPERVISOR_HOME_COCKPIT_PROJECTION_PATH,
  loadHypervisorHomeCockpitProjection,
  normalizeHypervisorHomeCockpitProjection,
} from "./homeCockpitModel.ts";

test("home cockpit projection summarizes core surfaces without becoming truth", () => {
  const projection = HYPERVISOR_HOME_COCKPIT_PROJECTION;

  assert.equal(
    projection.schema_version,
    "ioi.hypervisor.home_cockpit_projection.v1",
  );
  assert.equal(projection.source, "fixture");
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

test("home cockpit projection normalizer preserves daemon truth boundary", () => {
  const projection = normalizeHypervisorHomeCockpitProjection(
    {
      projection_id: "home-cockpit:daemon/live",
      selected_project_id: "project:daemon",
      boundary_invariant: "Daemon projection; Home still only renders evidence.",
      metrics: [
        {
          metric_ref: "home-cockpit:daemon-session",
          label: "Daemon session",
          value: "active",
          detail: "session:daemon/live",
          surface_ref: "surface:sessions",
          evidence_refs: ["receipt://daemon/session"],
        },
      ],
    },
    { source: "daemon-home-cockpit-projection" },
  );

  assert.equal(projection.projection_id, "home-cockpit:daemon/live");
  assert.equal(projection.source, "daemon-home-cockpit-projection");
  assert.equal(projection.runtimeTruthSource, "daemon-runtime");
  assert.equal(projection.metrics[0]?.metric_ref, "home-cockpit:daemon-session");
  assert.deepEqual(projection.metrics[0]?.evidence_refs, [
    "receipt://daemon/session",
  ]);
});

test("home cockpit loader reads the daemon projection endpoint", async () => {
  const requests: string[] = [];
  const projection = await loadHypervisorHomeCockpitProjection({
    endpoint: "http://daemon.test/",
    fetchImpl: async (input) => {
      requests.push(String(input));
      return {
        ok: true,
        status: 200,
        async text() {
          return JSON.stringify({
            projection_id: "home-cockpit:daemon/load",
            metrics: [
              {
                metric_ref: "home-cockpit:receipt",
                label: "Receipt",
                value: "1",
                detail: "state root",
                surface_ref: "surface:receipts",
                evidence_refs: ["receipt://home/load"],
              },
            ],
          });
        },
      };
    },
  });

  assert.deepEqual(requests, [
    `http://daemon.test${HYPERVISOR_HOME_COCKPIT_PROJECTION_PATH}`,
  ]);
  assert.equal(projection.projection_id, "home-cockpit:daemon/load");
  assert.equal(projection.source, "daemon-home-cockpit-projection");
  assert.equal(projection.metrics[0]?.surface_ref, "surface:receipts");
});

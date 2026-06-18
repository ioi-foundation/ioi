import assert from "node:assert/strict";
import test from "node:test";

import {
  HYPERVISOR_CORE_TAXONOMY_SCHEMA_VERSION,
  buildHypervisorCoreTaxonomy,
} from "./runtime-hypervisor-core-taxonomy.mjs";

test("builds daemon-owned Hypervisor Core taxonomy projection", () => {
  const taxonomy = buildHypervisorCoreTaxonomy({
    nowIso: () => "2026-06-18T12:00:00.000Z",
  });

  assert.equal(taxonomy.schema_version, HYPERVISOR_CORE_TAXONOMY_SCHEMA_VERSION);
  assert.equal(taxonomy.core.execution_owner, "hypervisor-daemon");
  assert.equal(taxonomy.core.runtimeTruthSource, "daemon-runtime");
  assert.equal(taxonomy.generated_at, "2026-06-18T12:00:00.000Z");
  assert.deepEqual(
    taxonomy.first_class_clients.map((client) => client.kind),
    ["app", "web", "cli_headless"],
  );
  assert.deepEqual(
    taxonomy.optional_presentations.map((client) => client.kind),
    ["tui_presentation"],
  );
});

test("keeps application surfaces separate from adapter targets and retired Fleet", () => {
  const taxonomy = buildHypervisorCoreTaxonomy();
  const surfaceIds = taxonomy.application_surfaces.map((surface) => surface.id);
  const adapterFamilyIds = taxonomy.adapter_target_families.map(
    (family) => family.id,
  );

  assert.ok(surfaceIds.includes("workbench"));
  assert.ok(surfaceIds.includes("foundry"));
  assert.ok(surfaceIds.includes("providers"));
  assert.ok(surfaceIds.includes("environments"));
  assert.ok(!surfaceIds.includes("fleet"));
  assert.deepEqual(taxonomy.retired_surface_aliases, [
    {
      alias: "fleet",
      replacement: "sessions/providers/environments",
      reason:
        "Fleet posture is folded into Hypervisor session, provider, and environment management instead of a separate app surface.",
    },
  ]);

  assert.ok(adapterFamilyIds.includes("code_editor"));
  assert.ok(adapterFamilyIds.includes("terminal"));
  assert.ok(adapterFamilyIds.includes("provider"));
  assert.ok(
    taxonomy.adapter_target_families
      .find((family) => family.id === "code_editor")
      .allowed_surface_refs.includes("hypervisor-surface:workbench"),
  );
});

test("classifies external harnesses as proposal-source adapters only", () => {
  const taxonomy = buildHypervisorCoreTaxonomy();

  assert.deepEqual(
    taxonomy.agent_harness_adapters.map((adapter) => adapter.id),
    [
      "codex_style",
      "claude_style",
      "deepseek_style",
      "aider_style",
      "openhands_style",
      "generic_cli",
    ],
  );
  for (const adapter of taxonomy.agent_harness_adapters) {
    assert.equal(adapter.authority, "proposal_source_only");
    assert.equal(adapter.runtimeTruthSource, "daemon-runtime");
    assert.match(adapter.boundary, /not Hypervisor clients/);
  }
});

test("keeps authority, truth, storage, route, and L1 ownership explicit", () => {
  const taxonomy = buildHypervisorCoreTaxonomy();
  const owners = taxonomy.truth_boundaries.map((boundary) => boundary.owner);

  assert.deepEqual(owners, [
    "wallet.network",
    "Agentgres",
    "storage backends",
    "route engines",
    "IOI L1",
  ]);
  assert.match(taxonomy.anti_patterns.join("\n"), /storage backends/);
  assert.match(taxonomy.anti_patterns.join("\n"), /route engines/);
  assert.match(taxonomy.anti_patterns.join("\n"), /Workbench code-editor/);
});

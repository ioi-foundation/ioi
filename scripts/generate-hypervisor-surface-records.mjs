#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const routesDir = path.join(repoRoot, "crates/node/src/bin/hypervisor_daemon_routes");
const taxonomy = JSON.parse(fs.readFileSync(path.join(routesDir, "hypervisor_core_taxonomy.json"), "utf8"));
const outputPath = path.join(routesDir, "hypervisor_surface_records.json");
const depthByKey = {
  studio: "propose",
  automations: "inspect",
  ontology: "propose",
  data: "inspect",
  governance: "inspect",
  provenance: "inspect",
  evaluations: "inspect",
  improvement: "inspect",
  foundry: "inspect",
  packages: "inspect",
  "developer-workspace": "inspect",
  "developer-console": "inspect",
  environments: "inspect",
  operations: "inspect",
};

const registrations = taxonomy.application_registrations.map((row) => ({
  schema_version: "ioi.hypervisor.application_surface_registration.v1",
  surface_ref: row.surface_ref,
  surface_key: row.surface_key,
  surface_class: row.surface_class,
  display_name: row.display_name,
  surface_availability: row.surface_availability,
  canonical_route: row.canonical_route,
  canonical_owner_doc_ref: row.canonical_owner_doc_ref,
  effect_boundary: row.effect_boundary,
  declared_object_contract_refs: [],
  declared_action_contract_refs: [],
  context_route_resolver_refs: [],
}));

const admitted = registrations.filter((row) => row.surface_availability === "available");
const releases = admitted.map((row) => ({
  schema_version: "ioi.hypervisor.surface_release_record.v1",
  release_ref: `package://hypervisor/${row.surface_key}/release/source-owned-v1`,
  surface_ref: row.surface_ref,
  package_ref: `package://hypervisor/${row.surface_key}`,
  surface_distribution: "bundled",
  surface_admission_state: "admitted",
  surface_package_disposition: "active",
  surface_capability_depth: depthByKey[row.surface_key] ?? "browse",
  object_contract_refs: [],
  action_contract_refs: [],
  evidence_refs: ["evidence://implementation/hypervisor/source-owned-app/runtime-contract"],
}));
const installations = releases.map((release) => ({
  schema_version: "ioi.hypervisor.surface_installation_binding.v1",
  installation_ref: `install://hypervisor/${release.surface_ref.split("/").at(-1)}/local`,
  surface_ref: release.surface_ref,
  release_ref: release.release_ref,
  org_ref: "org://local",
  project_ref: null,
  surface_installation_state: "installed",
  surface_enablement_state: "enabled",
  visibility: "organization",
  allowed_object_contract_refs: release.object_contract_refs,
  allowed_action_refs: release.action_contract_refs,
  revision: 1,
}));
const serving_bindings = installations.map((installation) => {
  const registration = registrations.find((row) => row.surface_ref === installation.surface_ref);
  const key = registration.surface_key;
  return {
    schema_version: "ioi.hypervisor.surface_serving_binding.v1",
    serving_binding_ref: `surface-serving://hypervisor/${key}/source-owned-app`,
    surface_ref: installation.surface_ref,
    release_ref: installation.release_ref,
    installation_ref: installation.installation_ref,
    system_binding_ref: null,
    resolved_route: registration.canonical_route,
    runtime_ref: "runtime://hypervisor/source-owned-app",
    surface_operational_state: "serving",
    health_observation_refs: ["observation://hypervisor/source-owned-app/build-and-contract"],
  };
});

const output = {
  schema_version: "ioi.hypervisor.normalized_surface_record_set.v1",
  generated_from: "crates/node/src/bin/hypervisor_daemon_routes/hypervisor_core_taxonomy.json",
  registrations,
  releases,
  installations,
  system_interface_bindings: [],
  serving_bindings,
};
const rendered = `${JSON.stringify(output, null, 2)}\n`;

if (process.argv.includes("--check")) {
  const current = fs.existsSync(outputPath) ? fs.readFileSync(outputPath, "utf8") : "";
  if (current !== rendered) {
    console.error(`${path.relative(repoRoot, outputPath)} is stale; run node scripts/generate-hypervisor-surface-records.mjs --write`);
    process.exit(1);
  }
  console.log(JSON.stringify({ check: "hypervisor-surface-records", result: "PASS", registrations: registrations.length, releases: releases.length }));
} else if (process.argv.includes("--write")) {
  fs.writeFileSync(outputPath, rendered);
  console.log(`wrote ${path.relative(repoRoot, outputPath)}`);
} else {
  console.error("usage: node scripts/generate-hypervisor-surface-records.mjs --check|--write");
  process.exit(2);
}

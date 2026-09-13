#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const routesDir = path.join(repoRoot, "crates/node/src/bin/hypervisor_daemon_routes");
const taxonomy = JSON.parse(fs.readFileSync(path.join(routesDir, "hypervisor_core_taxonomy.json"), "utf8"));
const outputPath = path.join(routesDir, "hypervisor_surface_records.json");
// THE COMPILER READS EVERY AXIS; IT MINTS NONE (M08.8).
//
// Non-Negotiable 36 requires one registration over ELEVEN INDEPENDENT axes. This generator used to
// emit nine of them as literals — `"bundled"`, `"admitted"`, `"active"`, `"installed"`, `"enabled"`,
// `"serving"`, `"organization"` — plus a `depthByKey` lookup table living HERE rather than on the
// registration it describes. Nine axes with no per-surface variance are nine axes no consumer can
// distinguish and no check can assert against: the value was a property of the COMPILER, not of the
// surface. They are now registered facts on each taxonomy row, so a surface with a different
// distribution or a shallower capability depth registers it and this projection serves it. That
// today's population happens to be uniform is a fact about the population, not about the contract.
//
// The two axes canon names and nothing registered — `surface_origin` and `surface_creation_method`
// — are now registered too, so the daemon can project a value instead of an honest null.
const required = (row, axis) => {
  const value = row[axis];
  if (value === undefined || value === null || value === "") {
    throw new Error(
      `taxonomy registration ${row.surface_key}: ${axis} is not registered. Every axis is a ` +
        `registered fact on the row; a compiler that substituted a default here would make the ` +
        `absence invisible, which is the defect this generator was rewritten to end.`,
    );
  }
  return value;
};

// A list axis is registered when the array EXISTS, which is not the same as its being non-empty:
// `supported_context_kinds` is legitimately empty for a surface that answers no typed context, and
// collapsing "registered as none" into "not registered" would lose the difference this whole unit
// exists to preserve. `requiredList` is for the arrays that must carry at least one member;
// `requiredArray` for the one that need not.
const requiredArray = (row, axis) => {
  const value = row[axis];
  if (!Array.isArray(value)) {
    throw new Error(
      `taxonomy registration ${row.surface_key}: ${axis} is not registered as an array. An absent ` +
        `list and an empty one are different registrations and a compiler may not pick between them.`,
    );
  }
  return value;
};

const requiredList = (row, axis) => {
  const value = requiredArray(row, axis);
  if (value.length === 0) {
    throw new Error(
      `taxonomy registration ${row.surface_key}: ${axis} is registered empty. A surface with no ` +
        `placement appears in no projection and one with no launch mode cannot be launched; ` +
        `either is a registration defect rather than a posture.`,
    );
  }
  return value;
};

// THE ADMISSION TRANSACTION FOR THIS PLANE. The contradiction below is not expressible in
// `ioi.portable-invariants.v1` — the language has no way to say "if this array contains X" — so it
// is enforced where registrations are minted rather than written as an invariant that would not
// fire. Registering `contextual` while claiming no context kind declares a launch into nothing.
const contextualClaimChecked = (row) => {
  const modes = row.launch_modes ?? [];
  const kinds = row.supported_context_kinds ?? [];
  if (modes.includes("contextual") && kinds.length === 0) {
    throw new Error(
      `taxonomy registration ${row.surface_key}: launch mode \`contextual\` is registered with no ` +
        `supported_context_kinds. A contextual launch into no typed context is a launch into ` +
        `nothing; register a context kind or drop the mode.`,
    );
  }
  return row;
};

// The taxonomy row is the REGISTRATION of record; the projections below derive from it by
// surface_key rather than from each other, so an axis is read from where it is registered instead
// of being carried along and possibly reshaped in transit.
const rowOf = new Map(
  taxonomy.application_registrations.map((row) => [row.surface_key, row]),
);

const registrations = taxonomy.application_registrations.map(contextualClaimChecked).map((row) => ({
  // THE SUCCESSOR, not a widening. v1 is `wire_mutation_policy: forbidden` with
  // `additionalProperties: false`, and these records are wire data written against it — adding two
  // fields in place would change what already-admitted bytes mean. v2 carries the two axes as
  // REQUIRED, which is the whole point: under v1 a registration could omit them and the daemon had
  // nothing to project but a null.
  schema_version: "ioi.hypervisor.application_surface_registration.v2",
  surface_ref: row.surface_ref,
  surface_key: row.surface_key,
  surface_class: row.surface_class,
  display_name: row.display_name,
  surface_availability: row.surface_availability,
  canonical_route: row.canonical_route,
  canonical_owner_doc_ref: row.canonical_owner_doc_ref,
  effect_boundary: row.effect_boundary,
  // Read through `required` like every other registered axis: uniform across today's fifteen
  // surfaces, and uniform by measurement rather than by the compiler asserting it. The moment an
  // organization surface or an imported one is registered, this projection serves its real value
  // without a code change — which a literal here would not have done.
  surface_origin: required(rowOf.get(row.surface_key), "surface_origin"),
  surface_creation_method: required(rowOf.get(row.surface_key), "surface_creation_method"),
  // THE FIVE PROJECTIONS READ THESE, so a projection can no longer keep a list of its own members.
  // Shell serves `permanent_shell`, catalog serves `applications_catalog`, the palette serves the
  // `command_palette` launch mode and the contextual lane serves surfaces whose context kinds
  // contain the requested one. A hard-coded catalog is a membership decision made in a compiler,
  // which is exactly what ACC-10 clause 2 refuses.
  supported_placements: requiredList(rowOf.get(row.surface_key), "supported_placements"),
  launch_modes: requiredList(rowOf.get(row.surface_key), "launch_modes"),
  // May be empty by design: a surface that answers no typed context says so, and that is WHY it is
  // absent from a contextual projection rather than an oversight nobody can see.
  supported_context_kinds: requiredArray(rowOf.get(row.surface_key), "supported_context_kinds"),
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
  surface_distribution: required(rowOf.get(row.surface_key), "surface_distribution"),
  surface_admission_state: required(rowOf.get(row.surface_key), "surface_admission_state"),
  surface_package_disposition: required(rowOf.get(row.surface_key), "surface_package_disposition"),
  surface_capability_depth: required(rowOf.get(row.surface_key), "surface_capability_depth"),
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
  surface_installation_state: required(rowOf.get(release.surface_ref.split("/").at(-1)), "surface_installation_state"),
  surface_enablement_state: required(rowOf.get(release.surface_ref.split("/").at(-1)), "surface_enablement_state"),
  visibility: required(rowOf.get(release.surface_ref.split("/").at(-1)), "visibility"),
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
    surface_operational_state: required(rowOf.get(key), "surface_operational_state"),
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

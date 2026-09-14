#!/usr/bin/env node
// M08.10 · check:packages-product-lifecycle — the unit's composed done-bar.
//
// A clause table over scripts/lib/acceptance-journey.mjs, the same harness the ACC journey
// runners use, with NO absences and NO scheduled legs: a PARTIAL is impossible by construction,
// so this gate exits 0 or 1. Every child is isolated (each boots its own daemon or reads only
// the tree) and every child is CI-bound on its own — the packages journey (ci.yml, hypervisor
// workspace, floor-pinned in apps/hypervisor/verifier-floors.v1.json), the package-registry smoke
// (ci.yml root), the product-surface compiler (ci.yml root) and the route tests (Build and Test)
// — so this composition adds no CI time and re-derives the unit's whole lifecycle on ONE basis:
// intake → immutable release with dependency refs → admission → install → registration → serving
// binding → routing → recall with its impact record → uninstall.
//
//   node scripts/check-packages-product-lifecycle.mjs [--mutation] [--evidence <out.json>]

import { runJourney, app, rootScript, cargoTest, bounded } from "./lib/acceptance-journey.mjs";

const CLAUSES = [
  { id: "1", clause: "Intake and immutable release: the candidate freezes the ODK source mesh content-addressed; the v2 release carries canon's dependency_release_refs, resolved at admission (unknown, foreign-owner and recalled dependencies refuse by name) and bound into the release digest; the serving binding is derived from the DomainApp runtime ladder and refuses a non-serving runtime; the recall impact is derived from admitted truth and bounded to the recaller's tenants", unit: "M08.10 slices A, C, D (route tests)", checks: [bounded(cargoTest("ioi-node", ["--bin", "hypervisor-daemon", "package_registry_routes"]), 40)] },
  { id: "2", clause: "The lifecycle end to end against an isolated daemon and serve lane through the UI action lane: candidate → release → install (born disabled) → registration (enabled successor, compiled-join entry with no_serving_binding) → governed mount + serve → serving binding (launchable, resolved_launch_route = the runtime's route, canonical route 302) → stop-serving withdraws by derivation → re-serve restores → dependent release → recall with its impact record (installs, runtime still serving, dependent named, handoffs) → restart reconstruction → uninstall", unit: "M08.10 slices A–D", checks: [bounded(app("check:packages-journey"), 30)] },
  { id: "3", clause: "The registry's admission discipline with no DomainApp mounted: exact retry replay, same-scope stale-head refusal, restart recovery, contract-narrowing refusal, CAS uninstall, and the exact ten-path route inventory", unit: "M08.10", checks: [bounded(rootScript("smoke:package-registry"), 20)] },
  { id: "4", clause: "Compiler integration: the product-surface compiler joins registrations, releases, installations and serving bindings as independent axes; an extension's typed reasons are the join's stage reasons, never a special case", unit: "M08.8 · M08.10", checks: [bounded(rootScript("check:product-surface-compiler"), 40)] },
  { id: "5", clause: "Every record the lifecycle admits is a registered architecture contract with its generated fixture bar: release v2, application-surface registration v2, serving binding v2, package recall impact v1", unit: "M08.10", checks: [rootScript("check:architecture-contracts")] },
  { id: "N1", negative: true, clause: "Recall terminates nothing and cascades to no dependent: the impact record names the runtime that keeps serving and hands stop/unmount to the DomainApp plane; the dependent release stays active (asserted inside the journey after the recall)", unit: "M08.10 slice D", provenBy: "2" },
  { id: "N2", negative: true, clause: "Launchability is never declared: a serving binding over a mounted-but-not-serving runtime, a foreign runtime, or a second binding refuses by name, and stop-serving withdraws launchability with no registry mutation (asserted inside the journey)", unit: "M08.10 slice C", provenBy: "2" },
  { id: "N3", negative: true, clause: "This gate composes only isolated, CI-bound children — none targets the shared daemon, none needs a credential, and the table carries no absence and no scheduled leg, so PARTIAL cannot occur", unit: "M08.10", structural: (clauses) => { const soft = clauses.filter((c) => (c.absences?.length ?? 0) > 0 || (c.scheduled?.length ?? 0) > 0).map((c) => c.id); return { ok: soft.length === 0, detail: soft.length ? `soft clauses: ${soft.join(", ")}` : "no absences, no scheduled legs: the exit is 0 or 1" }; } },
];

await runJourney({
  gate: "M08.10",
  title: "packages product lifecycle",
  doc: "internal-docs/implementation/modules/M08-hypervisor-product-surfaces.md",
  clauses: CLAUSES,
});

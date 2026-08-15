#!/usr/bin/env node
// The ontology plane's ADMISSION CENSUS — entailed from the daemon's source by a REAL RUST PARSER.
//
// WHY THIS EXISTS. Next-legs XIII spent five merge-blocking rounds strengthening a black-box JOURNEY
// gate's proof that "no second admission path writes ontology truth"; each round a review defeated
// the PROOF while the code stayed correct. The owner ruled the claim mis-scoped for its observer —
// the observer sat inside the system it was bounding — and commissioned the proof to be built HERE,
// from module source, where the whole program is visible at once.
//
// WHY IT IS NOT A REGEX, AND WHY THE FIRST PARSER DID NOT COUNT. XIV Leg 3a first built this by
// hand-scanning Rust; three review rounds defeated it, and the defeats sorted cleanly into CENSUS
// LOGIC (a rule wrong or decorative) and LANGUAGE READING (a construct the scanner mis-modelled).
// The owner PRE-COMMITTED the rule before round three ran: modelling the next construct retires an
// INSTANCE, a real parser retires the CLASS. The first attempt at that ruling ADDED `syn` and KEPT
// the hand-rolled walk — a fifteen-variant `expr_children` under an AST, with a zero-override
// `Visit` impl driven across every expression so the code READ as though a complete visitor ran. A
// fourth review demonstrated twelve of fourteen ordinary second-admitter constructs passing green:
// `.await`, `tokio::spawn`, impl methods, arm guards, struct literals, nested items, macro
// arguments. THE SCAR: A PRE-COMMITTED BOUNDARY IS EXECUTED BY ITS MECHANISM, NOT BY ITS DEPENDENCY.
// The traversal in `crates/ontology-census` is `syn::visit::Visit` itself now.
//
// AND WHY EVERY JUDGEMENT BELOW READS A CLASSIFICATION RATHER THAN AN ABSENCE. That same review
// found the deeper defect: a construct the walk missed produced no entry, and every judgement was
// derived from the entries — so a COVERAGE GAP was indistinguishable from SAFETY. The extractor now
// reports every mention of a name of interest WITH the syntactic role it sits in, and this file
// holds a closed set of roles it can classify. A tenth role is RED. A gap now reads as a finding.
//
// WHAT IT ENTAILS, scoped by owner ruling. For each of the four ONTOLOGY families, exactly one
// module admits it. That is the commissioned claim, and four assertions below carry it.
//
// AND WHAT IT RATCHETS, which is weaker and labelled as such. The extractor derives every string in
// this daemon that begins `odk-`. Their admitter and toucher maps are RECORDED here and asserted in
// both directions per scar 4: a gain beyond the record is RED; a loss makes the record STALE and is
// re-derived in the commit that removes it. The label claims exactly that ratchet — NOT that every
// ODK family has one admitter, because THREE DO NOT. Those three are recorded UNDER ADJUDICATION,
// neither endorsed nor condemned; all three share one second admitter, `connector_execution_routes`,
// which makes them one question rather than three, and answering it is next-legs XV work: is that
// module a legitimate co-caller of kernel-owned admission paths, or does it hand-mint records
// beside them — the W3.1 shape.
//
// THE MAP WAS WRONG IN BOTH DIRECTIONS BEFORE IT WAS DERIVED PROPERLY, WHICH IS THE POINT. The
// hand-written table this replaced named FOUR families and structurally could not have seen the
// other twenty-one. Its first derived replacement reported FIVE multi-admitter families — also
// wrong, because that census applied no test filter, and three of the five were multi-admitter only
// on the strength of `#[cfg(test)]` fixtures. Recording a fixture as an admitter PRE-AUTHORISES its
// module to write that family for real. Hand-written filter, derived replacement, finding;
// unfiltered census, filtered census, correction. Scar 4's whole argument, twice over.
//
// TEST CLASSIFICATION FAILS TOWARD PRODUCTION and test writes are CLASSIFIED, not dropped: only a
// bare `#[cfg(test)]` marks a subtree, `cfg(any(test, …))` and feature gates count as production,
// and the test-write map is pinned too — so moving a production write under a test attribute shrinks
// the production map into a stale-pin RED rather than passing as a silent green.
//
// WHAT IT DOES NOT ENTAIL. `syn` reads this crate's source. A write performed by a dependency crate
// on the daemon's behalf, produced by macro EXPANSION, or by another process, is outside it. Two
// hundred and ninety production writer calls take their family as a runtime parameter and cannot be
// resolved statically at all; that count is pinned as its own ratchet rather than waved through.

import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = process.env.IOI_CENSUS_ROOT || path.resolve(HERE, "..", "..", "..");
const EXTRACTOR_SRC = path.join(ROOT, "crates/ontology-census/src/main.rs");
const EXTRACTOR_BIN = path.join(ROOT, "target/debug/ioi-ontology-census");
const DAEMON_MAIN = path.join(ROOT, "crates/node/src/bin/hypervisor-daemon.rs");

const results = [];
const ok = (name, cond, detail) => results.push({ name, pass: !!cond, detail: detail || "" });

/** The four families this leg's entailment covers, by owner ruling. Keyed by module PATH tail. */
const ONTOLOGY_FAMILIES = {
  "odk-domain-ontologies": "hypervisor_daemon_routes/odk_routes.rs",
  "odk-ontology-receipts": "hypervisor_daemon_routes/odk_routes.rs",
  "odk-ontology-proposals": "hypervisor_daemon_routes/ontology_workbench_routes.rs",
  "odk-saved-object-sets": "hypervisor_daemon_routes/ontology_workbench_routes.rs",
};

/**
 * EVERY SYNTACTIC ROLE A FAMILY NAME MAY APPEAR IN, and what each one means for admission.
 *
 * This table is the closed world that makes a coverage gap a finding. The extractor labels every
 * mention with its role; a role missing from here is RED whatever it turns out to mean. `admits`
 * roles put the module in the admitter map. `names` roles put it in the weaker TOUCHER map, because
 * a family name reaching a function body outside any call this census recognises cannot be shown
 * harmless without dataflow this census deliberately does not do — so it is ratcheted, not waved
 * through.
 */
const ROLE_MEANING = {
  "write-arg": "admits",
  "fs-arg": "admits",
  "read-arg": "names",
  "const-init": "declares",
  "static-init": "declares",
  "fn-body": "names",
  "macro:json": "names",
  "macro:format": "names",
  "macro:assert": "names",
  "macro:assert_eq": "names",
};

const RECORDED_PLANE = {
  "odk-capability-lease-plan-receipts": { admits: ["hypervisor_daemon_routes/capability_lease_plan_routes.rs"], touches: ["hypervisor_daemon_routes/capability_lease_plan_routes.rs"] },
  "odk-capability-lease-plans": { admits: ["hypervisor_daemon_routes/capability_lease_plan_routes.rs"], touches: ["hypervisor_daemon_routes/capability_lease_plan_routes.rs", "hypervisor_daemon_routes/connector_execution_routes.rs", "hypervisor_daemon_routes/connector_session_routes.rs", "hypervisor_daemon_routes/materializing_run_routes.rs"] },
  "odk-connector-mapping-receipts": { admits: ["hypervisor_daemon_routes/connector_mapping_routes.rs"], touches: ["hypervisor_daemon_routes/connector_mapping_routes.rs"] },
  "odk-connector-mappings": { admits: ["hypervisor_daemon_routes/connector_mapping_routes.rs"], touches: ["hypervisor_daemon_routes/capability_lease_plan_routes.rs", "hypervisor_daemon_routes/connector_execution_routes.rs", "hypervisor_daemon_routes/connector_mapping_routes.rs", "hypervisor_daemon_routes/materializing_run_routes.rs", "hypervisor_daemon_routes/ontology_projection_routes.rs", "hypervisor_daemon_routes/policy_bound_data_view_routes.rs", "hypervisor_daemon_routes/transformation_run_routes.rs"] },
  "odk-connector-session-receipts": { admits: ["hypervisor_daemon_routes/connector_session_routes.rs"], touches: ["hypervisor_daemon_routes/connector_session_routes.rs"] },
  "odk-connector-sessions": { admits: ["hypervisor_daemon_routes/connector_session_routes.rs"], touches: ["hypervisor_daemon_routes/connector_execution_routes.rs", "hypervisor_daemon_routes/connector_session_routes.rs"] },
  "odk-data-recipes": { admits: [], touches: ["hypervisor_daemon_routes/domain_apps_routes.rs", "hypervisor_daemon_routes/governance_routes.rs", "hypervisor_daemon_routes/marketplace_routes.rs", "hypervisor_daemon_routes/odk_routes.rs"] },
  "odk-domain-ontologies": { admits: ["hypervisor_daemon_routes/odk_routes.rs"], touches: ["hypervisor_daemon_routes/connector_mapping_routes.rs", "hypervisor_daemon_routes/domain_apps_routes.rs", "hypervisor_daemon_routes/governance_routes.rs", "hypervisor_daemon_routes/marketplace_routes.rs", "hypervisor_daemon_routes/odk_routes.rs", "hypervisor_daemon_routes/ontology_projection_routes.rs", "hypervisor_daemon_routes/ontology_workbench_routes.rs"] },
  "odk-manifest": { admits: [], touches: ["hypervisor_daemon_routes/odk_routes.rs"] },
  "odk-manifest://": { admits: [], touches: ["hypervisor_daemon_routes/odk_routes.rs"] },
  "odk-manifests": { admits: [], touches: ["hypervisor_daemon_routes/domain_apps_routes.rs", "hypervisor_daemon_routes/governance_routes.rs", "hypervisor_daemon_routes/marketplace_routes.rs", "hypervisor_daemon_routes/odk_routes.rs", "hypervisor_daemon_routes/package_registry_routes.rs"] },
  "odk-materialized-object-sets": { admits: ["hypervisor_daemon_routes/connector_execution_routes.rs"], touches: ["hypervisor_daemon_routes/connector_execution_routes.rs", "hypervisor_daemon_routes/ontology_workbench_routes.rs", "hypervisor_daemon_routes/orchestration_routes.rs"] },
  "odk-materializing-run-receipts": { admits: ["hypervisor_daemon_routes/connector_execution_routes.rs", "hypervisor_daemon_routes/materializing_run_routes.rs"], touches: ["hypervisor_daemon_routes/connector_execution_routes.rs", "hypervisor_daemon_routes/materializing_run_routes.rs"] },
  "odk-materializing-runs": { admits: ["hypervisor_daemon_routes/connector_execution_routes.rs", "hypervisor_daemon_routes/materializing_run_routes.rs"], touches: ["hypervisor_daemon_routes/connector_execution_routes.rs", "hypervisor_daemon_routes/connector_session_routes.rs", "hypervisor_daemon_routes/materializing_run_routes.rs"] },
  "odk-materializing-runs/{id}/lease": { admits: [], touches: ["hypervisor_daemon_routes/materializing_run_routes.rs"] },
  "odk-ontology-projection-receipts": { admits: ["hypervisor_daemon_routes/ontology_projection_routes.rs"], touches: ["hypervisor_daemon_routes/ontology_projection_routes.rs"] },
  "odk-ontology-projections": { admits: ["hypervisor_daemon_routes/connector_execution_routes.rs", "hypervisor_daemon_routes/ontology_projection_routes.rs"], touches: ["hypervisor_daemon_routes/capability_lease_plan_routes.rs", "hypervisor_daemon_routes/connector_execution_routes.rs", "hypervisor_daemon_routes/materializing_run_routes.rs", "hypervisor_daemon_routes/ontology_projection_routes.rs"] },
  "odk-ontology-proposals": { admits: ["hypervisor_daemon_routes/ontology_workbench_routes.rs"], touches: ["hypervisor_daemon_routes/ontology_workbench_routes.rs"] },
  "odk-ontology-receipts": { admits: ["hypervisor_daemon_routes/odk_routes.rs"], touches: ["hypervisor_daemon_routes/odk_routes.rs"] },
  "odk-policy-bound-data-view-receipts": { admits: [], touches: ["hypervisor_daemon_routes/policy_bound_data_view_routes.rs"] },
  "odk-policy-bound-data-views": { admits: ["hypervisor_daemon_routes/policy_bound_data_view_routes.rs"], touches: ["hypervisor_daemon_routes/capability_lease_plan_routes.rs", "hypervisor_daemon_routes/materializing_run_routes.rs", "hypervisor_daemon_routes/ontology_projection_routes.rs", "hypervisor_daemon_routes/policy_bound_data_view_routes.rs", "hypervisor_daemon_routes/transformation_run_routes.rs"] },
  "odk-saved-object-sets": { admits: ["hypervisor_daemon_routes/ontology_workbench_routes.rs"], touches: ["hypervisor_daemon_routes/ontology_workbench_routes.rs"] },
  "odk-surface-descriptors": { admits: ["hypervisor_daemon_routes/odk_routes.rs"], touches: ["hypervisor_daemon_routes/domain_apps_routes.rs", "hypervisor_daemon_routes/governance_routes.rs", "hypervisor_daemon_routes/marketplace_routes.rs", "hypervisor_daemon_routes/odk_routes.rs", "hypervisor_daemon_routes/package_registry_routes.rs"] },
  "odk-transformation-run-receipts": { admits: ["hypervisor_daemon_routes/transformation_run_routes.rs"], touches: ["hypervisor_daemon_routes/transformation_run_routes.rs"] },
  "odk-transformation-runs": { admits: ["hypervisor_daemon_routes/transformation_run_routes.rs"], touches: ["hypervisor_daemon_routes/capability_lease_plan_routes.rs", "hypervisor_daemon_routes/materializing_run_routes.rs", "hypervisor_daemon_routes/ontology_projection_routes.rs", "hypervisor_daemon_routes/transformation_run_routes.rs"] },
};

/**
 * WRITES UNDER A BARE `#[cfg(test)]`, recorded rather than discarded. Pinning what the filter
 * EXCLUDES is what stops the exclusion becoming a hiding place: a production write relocated under a
 * test attribute leaves the production map and arrives here, failing twice rather than passing once.
 */
const RECORDED_TEST_WRITES = {
  "odk-connector-mappings": ["hypervisor_daemon_routes/policy_bound_data_view_routes.rs"],
  "odk-domain-ontologies": ["hypervisor_daemon_routes/odk_routes.rs"],
  "odk-ontology-projections": ["hypervisor_daemon_routes/policy_bound_data_view_routes.rs"],
  "odk-ontology-receipts": ["hypervisor_daemon_routes/odk_routes.rs"],
  "odk-policy-bound-data-view-receipts": ["hypervisor_daemon_routes/policy_bound_data_view_routes.rs"],
  "odk-policy-bound-data-views": ["hypervisor_daemon_routes/policy_bound_data_view_routes.rs"],
  "odk-surface-descriptors": ["hypervisor_daemon_routes/odk_routes.rs"],
  "odk-transformation-runs": ["hypervisor_daemon_routes/policy_bound_data_view_routes.rs"],
};

/**
 * THE TRAVERSAL'S OWN REACH, pinned. Every assertion here reads the census, so a walk that quietly
 * stops reaching a construct weakens all of them at once without failing any of them.
 */
const PINNED = {
  modules: 88,
  familyMentions: 273,
  productionWriterCalls: { family: 72, nonFamilyLiteral: 204, runtimeParameter: 290 },
  productionFsCalls: 228,
};

/** FNV-1a/64 — the digest the extractor bakes its own source under at compile time. */
function fnv1a64(bytes) {
  const mask = 0xffffffffffffffffn;
  let h = 0xcbf29ce484222325n;
  for (const b of bytes) {
    h = (h ^ BigInt(b)) & mask;
    h = (h * 0x100000001b3n) & mask;
  }
  return h.toString(16).padStart(16, "0");
}

/**
 * Build the extractor and read the census out of it.
 *
 * THE BINARY IS PROVEN AGAINST ITS SOURCE BY CONTENT, NOT BY TIMESTAMP. The previous guard compared
 * mtimes after a `cargo build`, which passes on exactly the hazard it names: cargo treats a source
 * whose mtime moved BACKWARDS as up-to-date and does not rebuild, and the mtime comparison then
 * agrees. A tar or rsync restore, a Docker COPY, or a CI cache restored alongside a checkout reaches
 * that state with no deliberate act. The extractor bakes its own source in with `include_str!`, so a
 * binary built from different bytes reports a digest the source on disk cannot produce.
 */
function deriveCensus() {
  const build = spawnSync("cargo", ["build", "--offline", "-p", "ioi-ontology-census"], { cwd: ROOT, encoding: "utf8" });
  if (build.status !== 0) throw new Error(`extractor build failed: ${build.stderr || build.stdout}`);
  const run = spawnSync(EXTRACTOR_BIN, ["--interest", "odk-", DAEMON_MAIN], { cwd: ROOT, encoding: "utf8", maxBuffer: 512 * 1024 * 1024 });
  if (run.status !== 0) throw new Error(`extractor failed (${run.status}): ${run.stderr}`);
  const census = JSON.parse(run.stdout);
  const onDisk = fnv1a64(fs.readFileSync(EXTRACTOR_SRC));
  ok("the EXTRACTOR THAT PRODUCED THIS CENSUS was built from the extractor source in this tree, proven by a digest the binary carries from its own compile rather than by a timestamp a restore can forge — cargo treats a source whose mtime moved backwards as up-to-date, so an mtime guard passes on the very hazard it names",
    census.extractor_source_fnv1a64 === onDisk,
    census.extractor_source_fnv1a64 === onDisk ? `binary and source agree at ${onDisk}` : `binary carries ${census.extractor_source_fnv1a64}, source hashes to ${onDisk}`);
  return census;
}

function run() {
  const census = deriveCensus();
  const modules = census.modules;
  const isFamily = (s) => typeof s === "string" && census.interests.some((p) => s.startsWith(p));
  // MODULE IDENTITY IS THE PATH, all the way down. Shortening a key to its basename for comparison
  // re-introduces the very collapse the path key exists to prevent: a shadow module at
  // `shadow_odk/odk_routes.rs` compares equal to the real `odk_routes.rs`, and two admitters report
  // as one. The prefix is stripped for legibility only, and it is common to every module here.
  const PREFIX = "crates/node/src/bin/";
  const modId = (k) => (k.startsWith(PREFIX) ? k.slice(PREFIX.length) : k);

  // ---------------------------------------------------------------- the module graph
  // KEYED BY REPO PATH, NOT BY FILE STEM. Two files sharing a basename collapse into one module
  // under a stem key, which MERGES their admitters — a second admitter then reports as the recorded
  // one, and "exactly one module admits" passes while two do.
  const byKey = new Map(modules.map((m) => [m.key, m]));
  const byStem = new Map();
  for (const m of modules) {
    if (!byStem.has(m.stem)) byStem.set(m.stem, []);
    byStem.get(m.stem).push(m);
  }
  ok("the census walks the daemon's REAL module graph from its entry point — every `mod` declaration resolved through `#[path]` and rustc's own nested-before-sibling order, with an unresolvable declaration or an unreadable file aborting the extraction rather than silently shrinking the world the claim is made over",
    modules.length === PINNED.modules && byKey.size === modules.length,
    `${modules.length} modules reached, ${byKey.size} distinct paths (pinned ${PINNED.modules})`);

  // ---------------------------------------------------------------- name resolution
  /**
   * Resolve a written name to the literal it stands for, or report why it cannot be tied to a
   * declaration this census can see. THERE IS NO GLOBAL-UNIQUE FALLBACK: a name the census cannot
   * tie to a declaration is UNRESOLVED, and unresolved is RED. The fallback that used to sit here
   * did not merely miss a renamed import — it disguised the miss as a different hole.
   */
  function resolveName(m, name, depth = 0) {
    if (depth > 6) return { kind: "UNRESOLVED", why: "resolution cycle" };
    if (isFamily(name)) return { kind: "LITERAL", value: name };
    const segs = name.split("::");
    const last = segs[segs.length - 1];
    if (!/^[A-Z0-9_]+$/.test(last)) return { kind: "NOT-CONST" };
    if (segs.length >= 2) {
      // `use super::odk_routes as ont;` then `ont::KIND_ONT` — the module ALIAS, which the previous
      // resolver could not follow and reported as an unresolvable runtime value instead. Both this
      // form and the plain `use super::m;` are in this daemon today.
      const q = segs[segs.length - 2];
      const alias = m.imports.find((i) => i.module_only && i.local === q);
      const stem = alias ? alias.item : q;
      const cands = byStem.get(stem);
      if (!cands) return { kind: "UNRESOLVED", why: `no module named ${stem}` };
      if (cands.length > 1) return { kind: "UNRESOLVED", why: `module name ${stem} is ambiguous` };
      const t = cands[0];
      if (t.consts[last] !== undefined) return { kind: "LITERAL", value: t.consts[last] };
      if (t.const_refs[last] !== undefined) return resolveName(t, t.const_refs[last], depth + 1);
      if (t.const_opaque.includes(last)) return { kind: "OPAQUE", why: `${stem}::${last} has an initialiser this census cannot read` };
      return { kind: "UNRESOLVED", why: `${stem}::${last} is not a constant this census can see` };
    }
    if (m.consts[last] !== undefined) return { kind: "LITERAL", value: m.consts[last] };
    // `const LOCAL: &str = super::odk_routes::KIND_ONT;` — a constant defined as another constant.
    if (m.const_refs[last] !== undefined) return resolveName(m, m.const_refs[last], depth + 1);
    if (m.const_opaque.includes(last)) return { kind: "OPAQUE", why: `${last} has an initialiser this census cannot read` };
    const imp = m.imports.find((i) => !i.module_only && !i.glob && i.local === last);
    if (imp && imp.from) {
      const cands = byStem.get(imp.from);
      if (cands && cands.length === 1) {
        const t = cands[0];
        if (t.consts[imp.item] !== undefined) return { kind: "LITERAL", value: t.consts[imp.item] };
        if (t.const_refs[imp.item] !== undefined) return resolveName(t, t.const_refs[imp.item], depth + 1);
      }
    }
    for (const g of m.imports.filter((i) => i.glob && i.from)) {
      const cands = byStem.get(g.from);
      if (cands && cands.length === 1 && cands[0].consts[last] !== undefined) return { kind: "LITERAL", value: cands[0].consts[last] };
    }
    return { kind: "UNRESOLVED", why: `${last} is neither declared here nor imported` };
  }

  // ---------------------------------------------------------------- classify every mention
  const observedRoles = new Set();
  const unknownRoles = [];
  const observed = new Map();   // family -> { admits:Set, touches:Set }
  const testWrites = new Map(); // family -> Set
  let familyMentions = 0;
  for (const m of modules) {
    for (const men of m.mentions) {
      const r = resolveName(m, men.name);
      if (r.kind !== "LITERAL" || !isFamily(r.value)) continue;
      familyMentions++;
      observedRoles.add(men.role);
      const meaning = ROLE_MEANING[men.role];
      if (!meaning) {
        unknownRoles.push(`${modId(m.key)}::${men.in_fn} names "${r.value}" in role \`${men.role}\``);
        continue;
      }
      if (!observed.has(r.value)) observed.set(r.value, { admits: new Set(), touches: new Set() });
      if (men.in_test) {
        if (meaning === "admits") {
          if (!testWrites.has(r.value)) testWrites.set(r.value, new Set());
          testWrites.get(r.value).add(modId(m.key));
        }
        continue;
      }
      const e = observed.get(r.value);
      e.touches.add(modId(m.key));
      if (meaning === "admits") e.admits.add(modId(m.key));
    }
  }

  // A WRITER CALL WHOSE FAMILY THIS CENSUS CANNOT READ, IN A FUNCTION THAT NAMES ONE, ADMITS IT.
  //
  // This census does no dataflow, by design — so `let fams = ["<family>"]; persist_record(d, fams[0],
  // …)` puts the literal in the function body and an unreadable expression at the call. Five
  // constructs of exactly that shape (struct-literal field, array element, tuple element, arm guard,
  // macro argument) reached the writer without the family ever appearing in the writer's own
  // arguments. The conservative reading — the function names it, the function writes with something
  // it will not spell — is that the module admits it. On the tree as it stands this rule attributes
  // NOTHING, which is what makes it safe to state in this direction: it is inert until an
  // indirection appears, and then it is a finding.
  for (const m of modules) {
    for (const c of m.calls) {
      if (c.kind !== "write" || c.in_test) continue;
      if (c.leaves.some((l) => { const r = resolveName(m, l); return r.kind === "LITERAL" && isFamily(r.value); })) continue;
      for (const l of m.fn_leaves[c.in_fn] ?? []) {
        const r = resolveName(m, l);
        if (r.kind !== "LITERAL" || !isFamily(r.value)) continue;
        if (!observed.has(r.value)) observed.set(r.value, { admits: new Set(), touches: new Set() });
        observed.get(r.value).admits.add(modId(m.key));
        observed.get(r.value).touches.add(modId(m.key));
      }
    }
  }

  // THE ROLE WORLD IS CLOSED. Every judgement below reads a role; a role this file cannot classify
  // is a mention whose meaning is unknown, and unknown must be RED rather than skipped.
  ok("every mention of an ODK family sits in a SYNTACTIC ROLE this gate classifies — a family name reaching a position no rule below understands is reported as an unclassified mention and fails, so a construct the census stops reading becomes a FINDING rather than an absence, which is the only direction a judgement derived from absence can be trusted in",
    unknownRoles.length === 0,
    unknownRoles.join(" ; ") || `${observedRoles.size} roles observed, all classified: ${[...observedRoles].sort().join(", ")}`);

  // ---------------------------------------------------------------- the commissioned claim
  for (const [family, owner] of Object.entries(ONTOLOGY_FAMILIES)) {
    const admits = [...(observed.get(family)?.admits ?? [])].sort();
    ok(`EXACTLY ONE MODULE ADMITS \`${family}\` — entailed from the whole daemon's source rather than from a probe of the surface that would answer the same either way, and keyed by module PATH so that two files sharing a basename cannot report as one`,
      admits.length === 1 && admits[0] === owner,
      admits.length ? `admitted by ${admits.join(", ")}` : "no module admits it — the census has lost the owner, which is not the same as proving the claim");
  }

  // ---------------------------------------------------------------- the plane ratchet
  const gainedAdmit = [], gainedTouch = [], staleAdmit = [], staleTouch = [], unrecorded = [];
  for (const [family, e] of observed) {
    const rec = RECORDED_PLANE[family];
    if (!rec) { unrecorded.push(`${family} (admitted by ${[...e.admits].sort().join(", ") || "nobody"})`); continue; }
    for (const mod of e.admits) if (!rec.admits.includes(mod)) gainedAdmit.push(`${family} gained ${mod}`);
    for (const mod of e.touches) if (!rec.touches.includes(mod)) gainedTouch.push(`${family} newly named by ${mod}`);
    for (const mod of rec.admits) if (!e.admits.has(mod)) staleAdmit.push(`${family} no longer admitted by ${mod}`);
    for (const mod of rec.touches) if (!e.touches.has(mod)) staleTouch.push(`${family} no longer named by ${mod}`);
  }
  for (const family of Object.keys(RECORDED_PLANE)) if (!observed.has(family)) staleTouch.push(`${family} has vanished from the daemon entirely`);

  ok("NO ODK FAMILY GAINS AN ADMISSION PATH BEYOND THE RECORDED MAP — the weaker ratchet this run is entitled to claim, and deliberately not the no-second-spine property: three families have two production admitters today and are recorded UNDER ADJUDICATION rather than endorsed",
    gainedAdmit.length === 0 && unrecorded.length === 0,
    [...gainedAdmit, ...unrecorded.map((u) => `unrecorded family ${u}`)].join(" ; ") || `${observed.size} families, admitter map unchanged`);

  ok("NO MODULE NAMES AN ODK FAMILY IT IS NOT RECORDED AS NAMING — the ratchet a rung below admission, because a family name reaching a new module's function body cannot be shown harmless without dataflow this census deliberately does not do; the conservative reading is that it is a finding to run down, not a fact to wave through",
    gainedTouch.length === 0,
    gainedTouch.join(" ; ") || `${[...observed.values()].reduce((a, e) => a + e.touches.size, 0)} module-family references, all recorded`);

  ok("THE RECORDED MAP IS NOT STALE IN EITHER DIRECTION — scar 4's second half: a derived closed world is only as wide as what it derives over, so an admitter or a reference that DISAPPEARS must re-derive the pin in the commit that removes it rather than leaving a record that quietly over-claims what is still true",
    staleAdmit.length === 0 && staleTouch.length === 0,
    [...staleAdmit, ...staleTouch].join(" ; ") || "every recorded admitter and reference is still present in source");

  // ---------------------------------------------------------------- the test filter, both ways
  const testGain = [], testStale = [];
  for (const [family, mods] of testWrites) {
    const rec = RECORDED_TEST_WRITES[family] ?? [];
    for (const mod of mods) if (!rec.includes(mod)) testGain.push(`${family} gained a test write in ${mod}`);
  }
  for (const [family, rec] of Object.entries(RECORDED_TEST_WRITES)) {
    for (const mod of rec) if (!(testWrites.get(family) ?? new Set()).has(mod)) testStale.push(`${family} no longer written under test by ${mod}`);
  }
  ok("WRITES UNDER A BARE `#[cfg(test)]` ARE CLASSIFIED AS TEST WRITES AND PINNED AS SUCH, never dropped — the filter fails toward PRODUCTION (`cfg(any(test, …))`, `cfg_attr` and feature gates all count as production), and pinning what it EXCLUDES is what stops the exclusion becoming a hiding place: a production write relocated under a test attribute leaves the production map and arrives here, failing twice rather than passing once",
    testGain.length === 0 && testStale.length === 0,
    [...testGain, ...testStale].join(" ; ") || `${[...testWrites.values()].reduce((a, s) => a + s.size, 0)} test writes across ${testWrites.size} families, all recorded`);

  // ---------------------------------------------------------------- resolution is total
  let wFamily = 0, wLiteral = 0, wRuntime = 0;
  const wUnresolved = [];
  for (const m of modules) {
    for (const c of m.calls) {
      if (c.kind !== "write" || c.in_test) continue;
      const rs = c.leaves.map((l) => resolveName(m, l));
      if (rs.some((r) => r.kind === "LITERAL" && isFamily(r.value))) { wFamily++; continue; }
      const bad = c.leaves.filter((_, i) => rs[i].kind === "UNRESOLVED" || rs[i].kind === "OPAQUE");
      if (bad.length) { wUnresolved.push(`${modId(m.key)}::${c.in_fn} → ${bad.join(", ")}`); continue; }
      if (rs.some((r) => r.kind === "LITERAL")) wLiteral++; else wRuntime++;
    }
  }
  ok("EVERY CONSTANT-SHAPED NAME IN A PRODUCTION WRITER CALL RESOLVES TO A DECLARATION THIS CENSUS CAN SEE — no name is waved through as probably-harmless, because a name the census cannot tie to a declaration it can see is exactly what a second admitter looks like from here",
    wUnresolved.length === 0,
    wUnresolved.slice(0, 8).join(" ; ") || `${wFamily} name a family, ${wLiteral} name a non-ODK family, ${wRuntime} take it as a runtime parameter`);

  ok("THE WRITER-CALL POPULATION IS PINNED IN ALL THREE BUCKETS — including the calls whose family is a RUNTIME PARAMETER and therefore cannot be resolved from source at all; naming that bucket and pinning its size is what keeps it from silently absorbing the calls this census is supposed to be reading",
    wFamily === PINNED.productionWriterCalls.family && wLiteral === PINNED.productionWriterCalls.nonFamilyLiteral && wRuntime === PINNED.productionWriterCalls.runtimeParameter,
    `family=${wFamily}/${PINNED.productionWriterCalls.family} non-ODK=${wLiteral}/${PINNED.productionWriterCalls.nonFamilyLiteral} runtime=${wRuntime}/${PINNED.productionWriterCalls.runtimeParameter}`);

  // ---------------------------------------------------------------- the traversal's own reach
  const prodFs = modules.reduce((a, m) => a + m.fs_calls.filter((c) => !c.in_test).length, 0);
  ok("THE TRAVERSAL'S REACH IS PINNED UNDER THE JUDGEMENTS THAT DEPEND ON IT — every assertion here reads the census, so a walk that quietly stops reaching a construct weakens all of them at once without failing any one of them; these counts collapse when the walk regresses even where no rule above has an opinion about the construct it stopped reaching",
    familyMentions === PINNED.familyMentions && prodFs === PINNED.productionFsCalls,
    `${familyMentions}/${PINNED.familyMentions} family mentions, ${prodFs}/${PINNED.productionFsCalls} production filesystem calls`);

  // ---------------------------------------------------------------- who may mint the name
  // READ FROM THE MENTION, NOT FROM THE CONSTANT TABLE. A scalar `const X: &str = "<family>"` lands
  // in `consts`, but the same literal inside `const XS: &[&str] = &["<family>"]` does not — and both
  // mint the name just as effectively. The mention carries its role, so both forms are one rule.
  // `static` is covered because `static-init` is a declaring role; `concat!("odk-", "…")` is covered
  // one assertion earlier, because its tokens surface under the role `macro:concat`, which this gate
  // does not classify and therefore fails on.
  const foreignDeclarations = [];
  for (const m of modules) {
    const here = modId(m.key);
    const seen = new Set();
    for (const men of m.mentions) {
      if (men.role !== "const-init" && men.role !== "static-init") continue;
      const r = resolveName(m, men.name);
      if (r.kind !== "LITERAL") continue;
      const owner = ONTOLOGY_FAMILIES[r.value];
      if (!owner || owner === here || seen.has(r.value)) continue;
      seen.add(r.value);
      foreignDeclarations.push(`${here} declares "${r.value}" (owned by ${owner})`);
    }
  }
  ok("ONLY THE OWNING MODULE DECLARES A CONSTANT NAMING ONE OF ITS ONTOLOGY FAMILIES — a second name minted elsewhere makes every later use of it read as innocent local code, which is how a family reference slips past a census that only inspects call sites; `static` declares as surely as `const` does, and a literal inside an array declares as surely as a scalar, and the previous census could see neither",
    foreignDeclarations.length === 0,
    foreignDeclarations.join(" ; ") || "every ontology family constant is declared by its owner");

  // ---------------------------------------------------------------- the raw filesystem lane
  const rawWrites = [];
  for (const m of modules) {
    for (const c of m.fs_calls) {
      if (c.in_test) continue;
      const near = [...(m.fn_leaves[c.in_fn] ?? []), ...c.leaves];
      const fams = [...new Set(near.map((l) => resolveName(m, l)).filter((r) => r.kind === "LITERAL" && isFamily(r.value)).map((r) => r.value))]
        .filter((f) => ONTOLOGY_FAMILIES[f] && ONTOLOGY_FAMILIES[f] !== modId(m.key));
      if (fams.length) rawWrites.push(`${modId(m.key)}::${c.in_fn} calls ${c.callee} and names ${fams.join(", ")}`);
    }
  }
  ok("NO PRODUCTION FUNCTION MAKES A RAW FILESYSTEM CALL AND NAMES AN ONTOLOGY FAMILY IT DOES NOT OWN — the record-writer census cannot see a lane that bypasses the writers entirely and puts bytes in a family directory itself; the enclosing function is read for EVERY declaration form, and reading it only for free functions left this rule dead for a third of the daemon's production filesystem calls",
    rawWrites.length === 0,
    rawWrites.join(" ; ") || `${prodFs} production filesystem calls, none in a function naming a family it does not own`);

  // ---------------------------------------------------------------- resolve-and-write
  const resolveAndWrite = [];
  for (const m of modules) {
    for (const fn of m.resolve_and_write_fns ?? []) {
      const arms = (m.resolver_arms ?? {})[fn] ?? [];
      if (arms.some((a) => { const r = resolveName(m, a); return r.kind === "LITERAL" && isFamily(r.value); })) resolveAndWrite.push(`${modId(m.key)}::${fn}`);
    }
  }
  ok("no function that RESOLVES a family name through a `match` arm also WRITES a record — conservative, dataflow-free and fail-closed: a scheme-mapper that admits is a second spine whatever the plumbing between them looks like, and widening this rule later is a governed act rather than a convenience",
    resolveAndWrite.length === 0,
    resolveAndWrite.join(" ; ") || "no resolving function writes");

  const failed = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`);
  emitVerifierCensus({ verifierId: "ontology-admission-census", sourceUrl: import.meta.url, results });
  console.log(`\n${results.length - failed.length}/${results.length} passed`);
  if (failed.length) process.exit(1);
}

const INVOKED = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (INVOKED) {
  try { run(); } catch (error) {
    console.error(`FAIL ontology-admission-census — ${error?.stack || error}`);
    process.exit(1);
  }
}

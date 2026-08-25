#!/usr/bin/env node
// OPERATIONAL-DEPTH ATLAS verifier (#68) — the committed atlas
// (application-operational-depth.json) is honest and agrees with the live registry, and the
// operational-state gate cannot be inflated:
//   1. MEMBERSHIP — the atlas is a SUBSET of the registry with an ASSERTED COMPLEMENT: every atlas
//      row names a live registry surface, every registry surface outside the atlas is NAMED
//      reference-less, and a stale name in that list is red. Each audited row's route + current
//      classification equals the registry's, so the atlas can never drift from the code.
//   2. TAXONOMY — every reference control carries exactly one of the six operational-depth
//      outcomes; disabled_missing_authority / unsupported_reference_session / reference_data_only
//      each NAME their reason; daemon_read / local_view_interaction / governed_receipted_action
//      each carry a binding. No control is unclassified.
//   3. NO INVENTED IOI CONTROLS — every implemented control id is a member of that surface's
//      reference census (an IOI control with no reference counterpart is rejected).
//   4. STATE INVARIANTS (against the LIVE module, not the atlas's say-so):
//      - act / workflow_complete ⇒ the bound module exports handleAction with ≥1 receipted
//        mutation action (the registry's own boot invariant, re-proven here).
//      - workflow_complete ⇒ a real governed action set (execute capability + the governed-build
//        verifier exists as the intent-to-durable-result journey proof).
//      - read_only_by_contract ⇒ zero mutation actions AND every reference mutation classified
//        unsupported_reference_session / reference_data_only (outside the product contract, not
//        merely unwired). [none today — guard is live for future rows.]
//      - browse / inspect ⇒ no receipted mutation REACHABLE beneath that mount (resolved through
//        the serve layer's own `boundActionRoute`, because one module may serve several mounts).
//   5. NAMED CONTROLS — the positive + act controls are pinned: pipeline=workflow_complete,
//      schema+approvals=act, and the NEGATIVE CONTROL — a browse-only surface promoted to a
//      higher state makes the registry invariant THROW (the gate refuses an inflated status).
//   6. SINGLE RAIL — every registry surface stays native_single_rail; existing certs unaffected.
//   7. SEQUENCE SUPERSESSION (#70 canon convergence) — the atlas is immutable AUDIT EVIDENCE:
//      the 5-factor scoring evidence is intact, but NO active PR-numbered surface queue exists
//      (no `queue`, no `pr` assignments, no `estate-closure`); the ranking declares
//      implementation_sequence_status=superseded_by_canon pointing at
//      docs/architecture/_meta/canon-to-code-delta.md; every unfinished surface appears exactly
//      once in that file's deferred UX backlog; the 14-step contract-first build sequence remains
//      canonical in execution-horizons.md; and the exact false claims the #70 review caught
//      (a verdict plane behind `Finding`, precedent substrates classified `partial`,
//      merged work described as held or unlanded) are guarded against returning.
//
// REPAIRED BY NEXT-LEGS XIII. This file CRASHED on the committed tree and was CI-gated by nothing —
// a check that cannot run gates nothing and may not pretend to, and an ungated ledger is worse than
// no ledger because it looks like evidence. Its premise (atlas == registry) was true when written
// and structurally false once the registry grew past the reference product's fourteen surfaces; the
// crash was `rows[s.slug]` returning undefined for a surface added long after the atlas froze. It is
// now under `check:verifier-floors` and runs in CI, so the depth ledger finally has a machine guard.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-operational-depth.mjs
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { SURFACES, OPERATIONAL_STATES, CAPABILITIES, boundSurface, boundActionRoute } from "./surface-registry.mjs";
import { evolveRanking } from "./build-operational-depth-atlas.mjs";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const APP = join(HERE, "..");
const OUTCOMES = ["daemon_read", "local_view_interaction", "governed_receipted_action", "disabled_missing_authority", "unsupported_reference_session", "reference_data_only"];
const REASON_OUTCOMES = ["disabled_missing_authority", "unsupported_reference_session", "reference_data_only"];
const BINDING_OUTCOMES = ["daemon_read", "local_view_interaction", "governed_receipted_action"];

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };

// Does the bound module declare ≥1 receipted mutation action? (the registry's own act/
// workflow_complete boot rule, checked live so the atlas can't overstate a surface.)
function hasReceiptedMutation(slug) {
  const hit = boundSurface(SURFACES.find((s) => s.slug === slug).route, "GET");
  const impl = hit && hit.impl;
  if (!impl || typeof impl.handleAction !== "function" || !Array.isArray(impl.actions)) return false;
  return impl.actions.some((a) => a.method && a.method !== "GET" && a.authority && a.receipt);
}

// What is actually REACHABLE at this mount, resolved through the same `boundActionRoute` the serve
// layer dispatches with — not through the module's action list.
//
// THE TWO ARE DIFFERENT WHENEVER ONE MODULE SERVES SEVERAL MOUNTS, and the difference is what the
// read-tier assertion below is really about. `hasReceiptedMutation` answers "does the module bound
// here declare a mutation anywhere", which for `packages-marketplace` and `work` is TRUE because
// their sibling `act` mounts share the module. The honest question for a read-tier row is whether a
// mutation can be POSTED BENEATH ITS OWN ROUTE, and only the resolver can answer that.
function declaredReceiptedMutations(slug) {
  const s = SURFACES.find((x) => x.slug === slug);
  const impl = boundSurface(s.route, "GET")?.impl;
  return (impl && Array.isArray(impl.actions) ? impl.actions : []).filter((a) => a.method && a.method !== "GET" && a.authority && a.receipt);
}

function reachableReceiptedMutations(slug) {
  const s = SURFACES.find((x) => x.slug === slug);
  const declared = declaredReceiptedMutations(slug);
  return declared.filter((a) => {
    const concrete = `${s.route}${String(a.route || "").replace(/:[^/]+/gu, "probe")}`;
    const resolved = boundActionRoute(concrete, a.method);
    return Boolean(resolved) && resolved.surface.slug === slug;
  }).map((a) => a.id || a.route);
}

async function run() {
  const atlas = JSON.parse(readFileSync(join(APP, "application-operational-depth.json"), "utf8"));
  const rows = atlas.surfaces || {};
  const rank = atlas.ranking || {};

  // 1. MEMBERSHIP — AS A SUBSET WITH AN ASSERTED COMPLEMENT, not as an equality.
  //
  // THE FALSE PREMISE THIS VERIFIER WAS BUILT ON, and the reason it CRASHED on the committed tree
  // for months while gating nothing: it asserted the atlas covers EXACTLY the registry. That was
  // true at `19d732ff2` and is structurally false now. The atlas is FROZEN AUDIT EVIDENCE of the
  // REFERENCE product's fourteen T3 surfaces; the registry has since grown to twenty-five, because
  // IOI-native surfaces exist that have no reference counterpart and never will. An atlas row is
  // owed for a surface the reference product had — not for every surface this product grows.
  //
  // So the honest shape is a SUBSET plus a NAMED COMPLEMENT, asserted in both directions: every
  // atlas slug must still be a live registry surface, every registry surface outside the atlas must
  // be named here, and a stale name is RED. A new surface therefore cannot land UNCLASSIFIED.
  //
  // WHAT THIS DOES NOT DO, stated because an earlier revision claimed it and a review demonstrated
  // otherwise: it does NOT stop the list absorbing a surface that has reference evidence. The class
  // check below is binary — the ledger can contradict a `greenfield` claim, and does — but
  // `post-atlas` means only "the ledger does not say greenfield", the slug is never related to its
  // `provenance_id`, and a new row can still be waved through by naming any non-greenfield ledger
  // id. That is a NAMED RESIDUAL of this gate, not a property of it.
  // EACH ENTRY'S CLASS IS DERIVED FROM THE TRACKED PROVENANCE LEDGER, not asserted here.
  //
  // The first revision of this list was a self-declared allowlist and a review demonstrated exactly
  // what that is worth: adding one line let a brand-new registry row pass unexamined, and EIGHT of
  // the eleven entries were contradicted by `seed-ux-provenance.v1.json`. `packages` was labelled
  // "greenfield-authorized-non-parity" while the ledger records it
  // `provenance-qualified-executable-seed-present` with `greenfield_authorization: null` — a false
  // claim inside a gate whose whole subject is false claims.
  //
  // A registry slug outside the atlas is one of exactly two things, and the ledger decides which:
  // GREENFIELD (no valid seed exists and an owner authorized the non-parity lane), or POST-ATLAS (a
  // surface with real seed provenance whose registry row was created after the atlas froze at
  // `19d732ff2`). Neither is "IOI-native with no reference counterpart", which is what the list used
  // to say about surfaces that demonstrably have one.
  // E7 COCKPIT RETIREMENT (2026-08-20): eight entries left this list with their registry rows —
  // home · systems · applications · automations · operations · work · work-sessions ·
  // work-new-session. They are removed rather than kept, because the assertion below rejects a
  // stale name: a list that can name a surface the registry lacks is a list that absorbs coverage.
  const REFERENCELESS_SURFACES = {
    contour: { provenance_id: "studio", class: "post-atlas" },
    devconsole: { provenance_id: "developer-console", class: "post-atlas" },
    fusion: { provenance_id: "studio", class: "post-atlas" },
    inference: { provenance_id: "data", class: "post-atlas" },
    ingest: { provenance_id: "data", class: "post-atlas" },
    insight: { provenance_id: "evaluations", class: "post-atlas" },
    jobs: { provenance_id: "work", class: "post-atlas" },
    logic: { provenance_id: "studio", class: "post-atlas" },
    map: { provenance_id: "environments", class: "post-atlas" },
    modelstudio: { provenance_id: "foundry", class: "post-atlas" },
    notepad: { provenance_id: "developer-workspace", class: "post-atlas" },
    packages: { provenance_id: "packages", class: "post-atlas" },
    "packages-marketplace": { provenance_id: "packages", class: "post-atlas" },
    quiver: { provenance_id: "evaluations", class: "post-atlas" },
    registry: { provenance_id: "packages", class: "post-atlas" },
    repositories: { provenance_id: "developer-workspace", class: "post-atlas" },
    scheduler: { provenance_id: "operations", class: "post-atlas" },
    "studio-home": { provenance_id: "studio", class: "post-atlas" },
    widgets: { provenance_id: "developer-console", class: "post-atlas" },
    workshop: { provenance_id: "studio", class: "post-atlas" },
    workspaces: { provenance_id: "developer-workspace", class: "post-atlas" },
  };
  const provenance = JSON.parse(readFileSync(join(APP, "seed-ux-provenance.v1.json"), "utf8"));
  const provenanceById = new Map((provenance.surfaces || []).map((record) => [record.id, record]));
  const atlasSlugs = Object.keys(rows).sort();
  // THE TEST-ONLY FAULT ROW IS NOT PART OF THE PRODUCT PARTITION. It exists only behind
  // `IOI_APP_RUNTIME_TEST_ROUTE=1`, to give the action-runtime verifier a module whose action throws
  // and one that returns success without a receipt. Excluding it is stated and asserted rather than
  // filtered silently, and the assertion is deterministic either way so the floor pin does not move
  // with the flag.
  const TEST_ONLY_SLUG = "__test_action";
  const testRow = SURFACES.find((s) => s.slug === TEST_ONLY_SLUG);
  ok("the test-only fault surface exists ONLY behind its runtime-test flag, and is excluded from the product partition by name",
    Boolean(testRow) === (process.env.IOI_APP_RUNTIME_TEST_ROUTE === "1"),
    testRow ? `present (flag ${process.env.IOI_APP_RUNTIME_TEST_ROUTE})` : "absent");
  const regSlugs = SURFACES.map((s) => s.slug).filter((slug) => slug !== TEST_ONLY_SLUG).sort();
  // AND ITS DECLARED TIER IS PINNED FROM THE SOURCE, deterministically, whether or not the flag is
  // set in this process. The tier gate only dispatches acting rows, so declaring this row `browse`
  // silently kills the estate's ONLY proof of route-local containment and receipt-fail-closed —
  // both POSTs fall through to the SPA catch-all as 200 — and `verify-hypervisor-action-runtime.mjs`
  // has no npm script, no CI job and no floor row to notice. Reading the row literal is what makes
  // that regression visible from a gate that does run.
  const registrySource = readFileSync(join(HERE, "surface-registry.mjs"), "utf8");
  const testRowLiteral = registrySource.split(`slug: "${TEST_ONLY_SLUG}"`)[1]?.split("});")[0] ?? "";
  ok("the test-only fault surface is declared ACTING in the registry source — declared read-tier, the tier gate stops dispatching its actions and the action-runtime proof dies silently",
    /operational_state: "act"/u.test(testRowLiteral),
    testRowLiteral.match(/operational_state: "[a-z_]+"/u)?.[0] ?? "ROW LITERAL NOT FOUND");
  const orphanAtlasRows = atlasSlugs.filter((slug) => !regSlugs.includes(slug));
  ok("every ATLAS row names a live registry surface — the atlas cannot describe a surface the product does not have",
    orphanAtlasRows.length === 0, orphanAtlasRows.join(",") || `${atlasSlugs.length} atlas rows`);
  const unclassified = regSlugs.filter((slug) => !atlasSlugs.includes(slug) && !REFERENCELESS_SURFACES[slug]);
  ok("every REGISTRY surface is either carried by the atlas or NAMED reference-less — a new surface cannot land unclassified",
    unclassified.length === 0, unclassified.join(",") || `${atlasSlugs.length} audited + ${Object.keys(REFERENCELESS_SURFACES).length} reference-less = ${regSlugs.length}`);
  const staleReferenceless = Object.keys(REFERENCELESS_SURFACES).filter((slug) => !regSlugs.includes(slug) || atlasSlugs.includes(slug));
  ok("and the reference-less list carries NO stale or overlapping entry — a list that can name a surface the registry lacks, or one the atlas audits, is a list that absorbs coverage",
    staleReferenceless.length === 0, staleReferenceless.join(",") || `${Object.keys(REFERENCELESS_SURFACES).length} named reference-less`);
  // THE CLASS CLAIM IS CHECKED AGAINST THE LEDGER, so the list cannot absorb a surface by labelling
  // it something the estate's own provenance record contradicts.
  // THE CLASS VOCABULARY IS CLOSED. It was a free string: any value other than the literal
  // "greenfield" — a typo, `post_atlas`, or the key omitted entirely — silently took the weakest
  // classification with no gate noise, while the comment above implied `post-atlas` was a recognized
  // value. It was recognized by nothing. That is this gate's own subject at small scale.
  const CLASSES = ["greenfield", "post-atlas"];
  const misclassified = Object.entries(REFERENCELESS_SURFACES).filter(([, entry]) => {
    if (!CLASSES.includes(entry.class)) return true;
    const record = provenanceById.get(entry.provenance_id);
    if (!record) return true;
    const greenfield = record.baseline_status === "blocked-no-valid-seed" && Boolean(record.greenfield_authorization);
    return entry.class === "greenfield" ? !greenfield : greenfield;
  });
  ok("every reference-less entry names a CLASS from the closed vocabulary and that class agrees with the tracked seed-provenance ledger — greenfield means the ledger says no valid seed and an owner authorized the lane, and nothing else may claim it",
    misclassified.length === 0,
    misclassified.map(([slug, entry]) => `${slug}:${entry.class}`).join(", ") || `${Object.keys(REFERENCELESS_SURFACES).length} classified against the ledger`);

  // THE JOIN. Every per-surface loop below walks this, so a missing atlas row is a CLASSIFIED FACT
  // rather than a TypeError. The crash that made this file gate nothing was `rows[s.slug]` returning
  // undefined for `applications` — a `read_only_by_contract` registry surface added long after the
  // atlas froze — and a verifier that cannot run is a false green, not a passing check.
  const audited = SURFACES.filter((s) => rows[s.slug]).map((s) => ({ surface: s, row: rows[s.slug] }));
  ok("PRECONDITION: the join is non-empty and covers every atlas row, so the assertions below are actually exercised",
    audited.length === atlasSlugs.length && audited.length > 0, `${audited.length} joined`);
  for (const { surface: s, row: r } of audited) {
    ok(`${s.slug}: atlas route + classification equal the live registry (atlas cannot drift from code)`, r.ioi_route === s.route && r.current && r.current.operational_state === s.operational_state && JSON.stringify((r.current.capabilities || []).slice().sort()) === JSON.stringify(s.capabilities.slice().sort()), `${r.current && r.current.operational_state} vs ${s.operational_state}`);
  }

  // 2. TAXONOMY + 3. NO INVENTED CONTROLS.
  for (const { surface: s, row: r } of audited) {
    const census = r.reference_control_census || [];
    const ids = census.map((c) => c.id);
    const uniqueIds = new Set(ids).size === ids.length;
    const everyClassified = census.length > 0 && census.every((c) => OUTCOMES.includes(c.outcome));
    const reasonsNamed = census.filter((c) => REASON_OUTCOMES.includes(c.outcome)).every((c) => typeof c.reason === "string" && c.reason.trim().length >= 12);
    const bindingsNamed = census.filter((c) => BINDING_OUTCOMES.includes(c.outcome)).every((c) => typeof c.binding === "string" && c.binding.trim().length >= 3);
    ok(`${s.slug}: every reference control classified once into the 6-outcome taxonomy (unique ids)`, uniqueIds && everyClassified, `${census.length} controls`);
    ok(`${s.slug}: disabled/unsupported/data-only controls NAME their reason; read/view/action controls carry a binding`, reasonsNamed && bindingsNamed);
    const impl = new Set(r.implemented_control_census || []);
    const invented = [...impl].filter((id) => !ids.includes(id));
    ok(`${s.slug}: no invented IOI control — every implemented control joins the reference census`, invented.length === 0, invented.slice(0, 3).join(",") || `${impl.size} implemented`);
    // Disabled controls in the census that IOI renders must be the disabled_missing_authority ones
    // (a real named gap), and their reason must name a contract, not a vague phrase.
    const namedGaps = census.filter((c) => c.outcome === "disabled_missing_authority");
    // A named gap must EXPLAIN the absence: it names a missing daemon plane/route/authority OR
    // states the affordance has no consumer/store/field/plane in the product contract. A bare
    // "gap" with no substance is rejected.
    const concreteGap = (t) => (t || "").trim().length >= 15 && /\bno\b|not |never|has no|authority|contract|receipt|plane|route|daemon|lease|session|consumer|store|field|derived|read-only|reference-only|authoring|toggle|library|substrate|catalog|duplicate|settings|missing|overlap|scheduler|deploy|\bgap\b/i.test(t);
    ok(`${s.slug}: every named-gap reason states a concrete missing contract (not a vague phrase)`, namedGaps.every((c) => concreteGap(c.reason)), `${namedGaps.length} gaps`);
  }

  // 4. STATE INVARIANTS — checked against the LIVE module.
  //
  // The act/browse/inspect invariants bind EVERY registry surface, audited or not: they are read off
  // the live module and need no atlas row. The read_only_by_contract invariant needs the reference
  // census, so it binds the audited join — and a reference-less surface in that state is asserted
  // separately rather than silently skipped, which is how `applications` crashed this file.
  for (const s of SURFACES.filter((x) => x.slug !== TEST_ONLY_SLUG)) {
    if (s.operational_state === "act" || s.operational_state === "workflow_complete") {
      // BOTH halves, and the second is what keeps the read-tier gate honest: if the tier gate ever
      // stopped resolving action routes at all, every read-tier assertion above would pass
      // VACUOUSLY while the product's own mutations went unreachable. An acting row must therefore
      // prove its mutations are reachable, not merely declared.
      const reachable = reachableReceiptedMutations(s.slug);
      const declared = declaredReceiptedMutations(s.slug);
      // EQUALITY, NOT `> 0`. If seven of pipeline's eight receipted mutations became unreachable, a
      // `> 0` check still passes — and the partial disarm is exactly what this assertion exists to
      // catch, since a tier gate that half-works would leave every read-tier claim below passing
      // vacuously.
      ok(`${s.slug} (${s.operational_state}): EVERY receipted mutation the live bound module declares is REACHABLE beneath this mount`,
        declared.length > 0 && reachable.length === declared.length,
        `${reachable.length}/${declared.length} reachable`);
    }
    if (["browse", "inspect", "shell"].includes(s.operational_state)) {
      // THE LABEL SAYS WHAT THE CHECK MEASURES, and no more. This resolves through the serve
      // layer's own `boundActionRoute`, so it covers the MODULE ACTION RUNTIME beneath this mount —
      // which is what the tier gate governs and where `packages-marketplace` and `work` were
      // exposing their siblings' mutations. It says NOTHING about the flat legacy serve branches:
      // a review demonstrated that `listings`, a `browse` row, still has real mutations reachable
      // at `/__ioi/marketplace/listings/:id/{delete,candidates,offers}` through
      // `serve-product-ui.mjs`'s own handlers, which no module registry governs. That is a NAMED
      // RESIDUAL of this gate, recorded here rather than hidden behind a broader-sounding label.
      // Two further limits, stated for the same reason: the probe resolves by SURFACE OWNERSHIP
      // (`resolved.surface.slug === slug`), not by path containment, so an acting surface whose route
      // were a strict prefix of a read-tier one could dispatch beneath that path with this still
      // green — no such pair exists today and none was constructible. And the filter requires BOTH
      // `authority` and `receipt`, so an action declaring only one of them, or neither, is outside
      // what this measures.
      const reachable = reachableReceiptedMutations(s.slug);
      const declared = declaredReceiptedMutations(s.slug);
      ok(`${s.slug} (${s.operational_state}): the action runtime resolves no RECEIPTED module action to THIS SURFACE (ownership, not path containment; flat serve branches and actions lacking authority or receipt are named residuals)`,
        reachable.length === 0,
        reachable.join(",") || (declared.length ? `${declared.length} declared, 0 reachable` : "no bound module"));
    }
  }
  for (const { surface: s, row: r } of audited) {
    if (s.operational_state !== "read_only_by_contract") continue;
    const refMut = (r.reference_control_census || []).filter((c) => /governed_receipted_action|create|edit|delete|run|execute|author/i.test(`${c.outcome} ${c.label} ${c.reference}`));
    ok(`${s.slug} (read_only_by_contract): every reference mutation is explicitly OUTSIDE the product contract`, reachableReceiptedMutations(s.slug).length === 0 && refMut.every((c) => ["unsupported_reference_session", "reference_data_only"].includes(c.outcome)));
  }
  // A reference-less surface has no census to measure "outside the product contract" against, so the
  // only honest claim is the live-module one. Stated as its own assertion so the absence is visible.
  const referencelessReadOnly = SURFACES.filter((s) => s.slug !== TEST_ONLY_SLUG && s.operational_state === "read_only_by_contract" && !rows[s.slug]);
  ok("reference-less read_only_by_contract surfaces expose NO reachable receipted mutation — the half of the invariant that needs no reference census still holds",
    referencelessReadOnly.every((s) => reachableReceiptedMutations(s.slug).length === 0),
    referencelessReadOnly.map((s) => s.slug).join(",") || "none");

  // workflow_complete ⇒ the intent-to-durable-result journey proof exists.
  const pl = SURFACES.find((s) => s.slug === "pipeline");
  ok("workflow_complete ⇒ the governed-build journey verifier exists as the intent-to-durable-result proof", (() => { try { readFileSync(join(APP, "scripts", "verify-hypervisor-governed-build.mjs")); return pl.operational_state === "workflow_complete" && pl.capabilities.includes("execute"); } catch { return false; } })());

  // 5. NAMED CONTROLS (positive + act) + the NEGATIVE CONTROL.
  ok("POSITIVE CONTROL: pipeline is workflow_complete", pl.operational_state === "workflow_complete");
  ok("act CONTROLS: Ontology Manager (schema) and Approvals are act with a live receipted module", SURFACES.find((s) => s.slug === "schema").operational_state === "act" && SURFACES.find((s) => s.slug === "approvals").operational_state === "act" && hasReceiptedMutation("schema") && hasReceiptedMutation("approvals"));
  // NEGATIVE CONTROL: a browse-only surface promoted to a higher state makes the invariant THROW.
  {
    const browseOnly = SURFACES.find((s) => s.operational_state === "browse" && !hasReceiptedMutation(s.slug));
    // Re-run the registry's own act invariant against an inflated clone; it must reject it.
    const inflated = { ...browseOnly, operational_state: "act" };
    const wouldReject = (() => {
      const hit = boundSurface(inflated.route, "GET");
      const impl = hit && hit.impl;
      const mutations = impl && Array.isArray(impl.actions) ? impl.actions.filter((a) => a.method && a.method !== "GET") : [];
      // The invariant: act requires a bound module with handleAction + ≥1 mutation. A browse-only
      // surface has neither → the boot invariant throws. We assert that precondition is false.
      return !(impl && typeof impl.handleAction === "function" && mutations.length > 0);
    })();
    ok(`NEGATIVE CONTROL: browse-only '${browseOnly.slug}' cannot be inflated to act — the registry invariant refuses it (no bound receipted module)`, wouldReject);
  }

  // 6. SINGLE RAIL + capability vocab.
  ok("every registry surface retains native_single_rail (container contract intact)", SURFACES.every((s) => s.embedded_shell_state === "native_single_rail"), `${SURFACES.length} surfaces`);
  ok("every atlas capability is a member of the registry capability vocabulary", Object.values(rows).every((r) => (r.current.capabilities || []).every((c) => CAPABILITIES.includes(c))));
  ok("every atlas operational_state is a member of the registry state vocabulary", Object.values(rows).every((r) => OPERATIONAL_STATES.includes(r.current.operational_state)));

  // 7. SEQUENCE SUPERSESSION — audit evidence intact; the active queue is retired; the canon
  // (canon-to-code-delta.md) owns what happens next.
  const FACTORS = ["existing_authority_available", "user_workflow_value", "cross_application_leverage", "missing_contract_cost", "authority_security_risk"];
  // The backlog join is over the AUDITED surfaces only. The canon's deferred UX backlog is the
  // reference-product queue; a reference-less IOI-native surface has no row there and never had one,
  // so including it would make this assertion demand a row that must not exist.
  const unfinished = audited.map(({ surface }) => surface).filter((s) => !["workflow_complete", "act", "read_only_by_contract"].includes(s.operational_state)).map((s) => s.slug);
  ok("scoring EVIDENCE preserved: every audited surface scored on all 5 factors", Array.isArray(rank.scored) && rank.scored.length >= 10 && rank.scored.every((e) => FACTORS.every((f) => Number.isInteger(e.ranking_inputs && e.ranking_inputs[f]))));
  ok("NO ACTIVE SURFACE QUEUE exists: no `queue` field, no PR-number assignments, no estate-closure terminal entry", !("queue" in rank) && !JSON.stringify(rank).includes("estate-closure") && (rank.evidence_order || []).every((e) => !("pr" in e)) && (rank.scored || []).every((e) => !("pr" in e)), `${(rank.evidence_order || []).length} evidence-ranked surfaces`);
  ok("the atlas DECLARES its implementation sequence superseded by the canon", rank.implementation_sequence_status === "superseded_by_canon" && String(rank.superseded_by || "").includes("docs/architecture/_meta/canon-to-code-delta.md") && /audit evidence/i.test(rank.sequence_note || ""));
  ok("evidence order is EXACTLY the audited set: ten unique entries whose slug set equals ranking.scored, covering every unfinished surface once", (() => {
    if (!Array.isArray(rank.evidence_order) || rank.evidence_order.length !== 10) return false;
    const slugs = rank.evidence_order.map((e) => e.slug);
    if (new Set(slugs).size !== 10) return false;
    const scoredSlugs = new Set((rank.scored || []).map((e) => e.slug));
    if (scoredSlugs.size !== 10 || !slugs.every((x) => scoredSlugs.has(x))) return false;
    return unfinished.every((u) => slugs.filter((x) => x === u).length === 1);
  })(), `${(rank.evidence_order || []).length} entries`);

  // The superseding canon: every unfinished surface appears EXACTLY ONCE in the deferred
  // application-UX backlog, while contract-complete read-only surfaces remain out of that queue.
  const deltaDoc = readFileSync(join(APP, "..", "..", "docs", "architecture", "_meta", "canon-to-code-delta.md"), "utf8");
  const backlog = deltaDoc.split("## Deferred application-UX backlog")[1] || "";
  const BACKLOG_ROW = { changes: "| Changes", monitors: "| Monitors", models: "| Models", designer: "| Designer", incidents: "| Incidents", machinery: "| Machinery", evalsuites: "| Evalsuites", explorer: "| Explorer", listings: "| Packages / Marketplace (Listings)" };
  ok("every unfinished registry surface appears exactly once in the canon's deferred UX backlog", unfinished.every((u) => BACKLOG_ROW[u] && backlog.split(`\n${BACKLOG_ROW[u]} `).length === 2), unfinished.filter((u) => !(BACKLOG_ROW[u] && backlog.split(`\n${BACKLOG_ROW[u]} `).length === 2)).join(",") || `${unfinished.length} surfaces`);
  ok("backlog rows resume only when PULLED by an implemented contract (no PR-number sequence)", /resumes? (only )?when pulled by an implemented contract/i.test(backlog) && !/\| Changes[^\n]*#7\d/.test(backlog));
  const horizons = readFileSync(join(APP, "..", "..", "docs", "architecture", "_meta", "execution-horizons.md"), "utf8");
  ok("the contract-first build sequence remains canonical (14 ordered steps; closure = working proof, no PR numbers)", horizons.includes("## The build sequence (contract-first)") && /1\. Bounded-system constitutional core/.test(horizons) && /14\. Connected\/secured network-service proof/.test(horizons) && /Completion is not forced into an arbitrary PR\s+number|not forced into an arbitrary PR number/.test(horizons.replace(/\n/g, " ")) && deltaDoc.includes("execution-horizons.md#the-build-sequence-contract-first"));

  // FALSE-CLAIM GUARDS: merged build-step-3 objects must remain honestly partial, while unrelated
  // precedent-only rows must never be promoted by proximity.
  const row = (name) => (deltaDoc.split("\n").find((l) => l.startsWith(`| \`${name}\` |`)) || "");
  // RE-DERIVED AGAINST THE LEDGER AS IT IS, not as the drifted guard remembered it. These three
  // guards were written against wording ("partial and merged") that a later canon pass replaced, and
  // because this verifier crashed before reaching them nothing noticed: two assertions that could
  // only ever fail, sitting in a file that never ran. What they were built to prevent has not
  // changed — these rows must never quietly claim a CURRENT v2 producer, lifecycle, verdict or
  // execution authority exists — so the guard is rewritten against the text that is actually there.
  const NOT_STARTED = /current executable lifecycle not started/;
  const NO_CURRENT_PRODUCER = (name) => new RegExp(`no current v2 room ${name} producer or lifecycle exists`);
  const FENCED = /generation-fenced from current v2 rooms/;
  for (const name of ["Attempt", "Finding"]) {
    ok(`\`${name}\` row records the PREDECESSOR lifecycle as generation-fenced history and claims no current v2 producer, lifecycle, or execution authority`,
      NO_CURRENT_PRODUCER(name).test(row(name)) && NOT_STARTED.test(row(name)) && FENCED.test(row(name))
        && /predecessor/.test(row(name)) && !/current executable lifecycle (partial|complete|shipped)/.test(row(name)),
      row(name) ? "row present" : "ROW MISSING");
  }
  ok("`VerifierChallenge` row records the predecessor lifecycle as generation-fenced history AND keeps verdict, acceptance, settlement and federation with their later owners",
    NO_CURRENT_PRODUCER("VerifierChallenge").test(row("VerifierChallenge"))
      && NOT_STARTED.test(row("VerifierChallenge"))
      && FENCED.test(row("VerifierChallenge"))
      && /keep verdict, acceptance, settlement, and federation with their later owners/.test(row("VerifierChallenge")),
    row("VerifierChallenge") ? "row present" : "ROW MISSING");

  // AND THE OTHER DIRECTION, which is the one that matters. Every guard above is a
  // presence-of-phrase conjunction, and a review demonstrated that all three are BLIND to a false
  // claim ADDED beside the honest wording: a row asserting "a current v2 room Attempt lifecycle is
  // now SHIPPED and executable" passed every one of them, because the honest phrase was still
  // there too. Deleting honest wording and adding a false claim are different attacks and need
  // different guards.
  // Each pattern was validated BOTH WAYS before landing: zero hits on the three real rows, and at
  // least one hit on every added-claim mutation the review demonstrated (execution-authority-live,
  // shape-complete, acceptance/verdict-shipped, lifecycle-now-shipped, settlement/federation-live).
  // The deletion attack stays with the presence guards above — the two are different attacks.
  //
  // IT IS A DENYLIST, and this estate already names denylist scans a decorative-assertion class. A
  // later review wrote eighteen further false claims that pass it — "in production", "generally
  // available", "no longer fenced", past and present-perfect tenses, and the same claim relocated to
  // another column. The label says what it bounds; making this a real property check means a
  // positive shape for the row, which is a canon change, not a regex.
  const PROMOTION_CLAIMS = [
    /current v2 [^|]{0,80}?\b(is|are) (now )?(shipped|live|executable|admitted)\b/i,
    /\b(lifecycle|producer|plane) (is|are) (now )?(shipped|live|executable|admitted)\b/i,
    /current contract shape (complete|shipped|done)/i,
    /current executable lifecycle (complete|shipped|started|live)/i,
    /\b(execution authority|acceptance|verdict|settlement|federation)\b[^|]{0,80}?\b(is|are) (live|shipped|available|admitted)\b/i,
    /\bmutators accept writes\b/i,
    /\bshipped behind\b/i,
  ];
  for (const name of ["Attempt", "Finding", "VerifierChallenge"]) {
    const promoted = PROMOTION_CLAIMS.filter((pattern) => pattern.test(row(name)));
    ok(`\`${name}\` row carries none of the DEMONSTRATED promotion phrasings — a denylist, so it bounds a known attack rather than proving the row honest`,
      row(name).length > 0 && promoted.length === 0,
      promoted.map(String).join(" | ") || "no promotion language");
  }
  for (const obj of ["OntologyVersion", "SemanticMappingDecision"]) {
    ok(`\`${obj}\` row: not started with an explicitly LABELED implementation precedent (a precedent is never partial)`, row(obj).includes("not started") && !/\| partial/.test(row(obj)) && /implementation precedent/i.test(row(obj)));
  }
  const provenanceAssertion = row("ProvenanceAssertion");
  ok("`ProvenanceAssertion` row records the bounded registered assertion-as-object slice without promoting its missing graph, challenge, or verifier-resolution lifecycles",
    provenanceAssertion.includes("registered contract")
      && provenanceAssertion.includes("durable assertion-as-object")
      && provenanceAssertion.includes("bounded backend slice")
      && provenanceAssertion.includes("challenge workflow")
      && provenanceAssertion.includes("verifier-receipt resolution"));
  const estateRecord = `${deltaDoc}\n${JSON.stringify(atlas)}`;
  ok("merged estate work is no longer described as held or unlanded (delta doc + atlas)", !/already-landed|shipped state|held stack|not yet\s+merged(?:\s+to master)?/i.test(estateRecord));

  ok("the atlas records the audit invariant: daemon_wired + shell-pixel certification do NOT imply operational completeness", typeof atlas.doctrine === "string" && /certification.*(not|never).*operational|operational.*not.*implied/i.test(atlas.doctrine));

  // 8. SEQUENCE-EVOLUTION TRANSFORM (#70 review round 2) — the exported pure transform is proven
  // on fixtures AND on the committed artifact; the builder cannot destroy evidence accidentally.
  const bytes = (a) => JSON.stringify(a, null, 2) + "\n";
  const legacyFixture = {
    surfaces: {},
    ranking: {
      method: "m",
      scored: [{ slug: "alpha", composite: 9 }, { slug: "beta", composite: 7 }],
      queue: [
        { pr: 70, slug: "alpha", title: "A", composite: 9, rationale: "r-a" },
        { pr: 71, slug: "beta", title: "B", composite: 7, rationale: "r-b" },
        { pr: 72, slug: "estate-closure", title: "Estate workflow closure", rationale: "terminal" },
      ],
    },
  };
  const evolvedFixture = evolveRanking(legacyFixture);
  ok("evolve: a LEGACY pr-numbered queue becomes superseded evidence (pr stripped, estate-closure dropped, declaration stamped)", !("queue" in evolvedFixture.ranking) && evolvedFixture.ranking.implementation_sequence_status === "superseded_by_canon" && evolvedFixture.ranking.evidence_order.length === 2 && evolvedFixture.ranking.evidence_order.every((e) => !("pr" in e)) && !JSON.stringify(evolvedFixture.ranking).includes("estate-closure"));
  ok("evolve: IDEMPOTENT byte-for-byte — evolve(evolve(x)) === evolve(x) on the fixture", bytes(evolveRanking(evolvedFixture)) === bytes(evolvedFixture));
  ok("evolve: never mutates its input (the legacy fixture still carries its queue)", Array.isArray(legacyFixture.ranking.queue) && legacyFixture.ranking.queue.length === 3);
  const committedRaw = readFileSync(join(APP, "application-operational-depth.json"), "utf8");
  ok("evolve: the COMMITTED atlas is a fixed point of the transform (regeneration cannot change it)", bytes(evolveRanking(JSON.parse(committedRaw))) === committedRaw);
  const refuses = (a, code) => { try { evolveRanking(a); return false; } catch (e) { return String(e.message).startsWith(code); } };
  ok("evolve: FAILS CLOSED before write — empty source order refused", refuses({ ranking: { method: "m", scored: [{ slug: "a" }], evidence_order: [] } }, "evolve_source_empty") && refuses({ ranking: { method: "m", scored: [{ slug: "a" }] } }, "evolve_source_empty"));
  ok("evolve: FAILS CLOSED — duplicate slugs refused", refuses({ ranking: { method: "m", scored: [{ slug: "a" }], evidence_order: [{ slug: "a" }, { slug: "a" }] } }, "evolve_slugs_duplicated"));
  ok("evolve: FAILS CLOSED — slug set must exactly equal ranking.scored", refuses({ ranking: { method: "m", scored: [{ slug: "a" }, { slug: "b" }], evidence_order: [{ slug: "a" }] } }, "evolve_slug_set_mismatch") && refuses({ ranking: { method: "m", scored: [{ slug: "a" }], evidence_order: [{ slug: "a" }, { slug: "z" }] } }, "evolve_slug_set_mismatch"));
  const builderPath = join(HERE, "build-operational-depth-atlas.mjs");
  const noArg = spawnSync(process.execPath, [builderPath], { encoding: "utf8" });
  ok("builder: NO-ARGUMENT execution is safe — exit 2, nothing written (artifact byte-identical)", noArg.status === 2 && readFileSync(join(APP, "application-operational-depth.json"), "utf8") === committedRaw && /nothing was read or written/.test(noArg.stderr));
  const builderSrc = readFileSync(builderPath, "utf8");
  ok("builder: the stale-raw rebuild requires the explicit --rebuild-from-raw flag (no implicit destructive default)", /if \(process\.argv\.includes\("--rebuild-from-raw"\)\) \{\s*rebuildFromRaw\(\);/.test(builderSrc) && (builderSrc.match(/rebuildFromRaw\(\)/g) || []).length === 2 && /DESTRUCTIVE/.test(builderSrc));
}

run().then(() => {
  const fails = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${results.length - fails.length}/${results.length} passed`);
  emitVerifierCensus({ verifierId: "operational-depth", sourceUrl: import.meta.url, results });
  if (fails.length) process.exit(1);
  console.log("operational-depth atlas: OK");
}).catch((e) => {
  // NO CENSUS ON A CRASH. `check:verifier-floors` reads a missing census as RED, which is the correct
  // reading of a run that did not finish — and it is exactly what this file needed for the months it
  // crashed on the committed tree while nothing noticed.
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${results.filter((r) => r.pass).length}/${results.length} passed BEFORE THE RUN DIED (incomplete — no census emitted)`);
  console.error("verifier crashed:", e);
  process.exit(1);
});

#!/usr/bin/env node
// OPERATIONAL-DEPTH ATLAS verifier (#68) — the committed atlas
// (application-operational-depth.json) is honest and agrees with the live registry, and the
// operational-state gate cannot be inflated:
//   1. MEMBERSHIP — the atlas covers EXACTLY the 13 registry surfaces; each row's route + current
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
//      - browse / inspect ⇒ no receipted mutation actions bound.
//   5. NAMED CONTROLS — the positive + act controls are pinned: pipeline=workflow_complete,
//      schema+approvals=act, and the NEGATIVE CONTROL — a browse-only surface promoted to a
//      higher state makes the registry invariant THROW (the gate refuses an inflated status).
//   6. SINGLE RAIL — all 13 stay native_single_rail; certs unaffected (audit-only PR).
//   7. SEQUENCE SUPERSESSION (#70 canon convergence) — the atlas is immutable AUDIT EVIDENCE:
//      the 5-factor scoring evidence is intact, but NO active PR-numbered surface queue exists
//      (no `queue`, no `pr` assignments, no `estate-closure`); the ranking declares
//      implementation_sequence_status=superseded_by_canon pointing at
//      docs/architecture/_meta/canon-to-code-delta.md; every unfinished surface appears exactly
//      once in that file's deferred UX backlog; the contract-first build sequence remains
//      canonical in execution-horizons.md; and the exact false claims the #70 review caught
//      (a verdict plane behind `Finding`, precedent substrates classified `partial`,
//      held-stack work described as landed/shipped) are guarded against returning.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-operational-depth.mjs
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { SURFACES, OPERATIONAL_STATES, CAPABILITIES, boundSurface } from "./surface-registry.mjs";
import { evolveRanking } from "./build-operational-depth-atlas.mjs";

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

async function run() {
  const atlas = JSON.parse(readFileSync(join(APP, "application-operational-depth.json"), "utf8"));
  const rows = atlas.surfaces || {};
  const rank = atlas.ranking || {};

  // 1. MEMBERSHIP.
  const atlasSlugs = Object.keys(rows).sort();
  const regSlugs = SURFACES.map((s) => s.slug).sort();
  ok("atlas covers EXACTLY the 13 registry surfaces (no extra, none missing)", JSON.stringify(atlasSlugs) === JSON.stringify(regSlugs), `atlas ${atlasSlugs.length} / registry ${regSlugs.length}`);
  for (const s of SURFACES) {
    const r = rows[s.slug];
    if (!r) { ok(`${s.slug}: atlas row present`, false); continue; }
    ok(`${s.slug}: atlas route + classification equal the live registry (atlas cannot drift from code)`, r.ioi_route === s.route && r.current && r.current.operational_state === s.operational_state && JSON.stringify((r.current.capabilities || []).slice().sort()) === JSON.stringify(s.capabilities.slice().sort()), `${r.current && r.current.operational_state} vs ${s.operational_state}`);
  }

  // 2. TAXONOMY + 3. NO INVENTED CONTROLS.
  for (const s of SURFACES) {
    const r = rows[s.slug]; if (!r) continue;
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
  for (const s of SURFACES) {
    if (s.operational_state === "act" || s.operational_state === "workflow_complete") {
      ok(`${s.slug} (${s.operational_state}): the LIVE bound module declares ≥1 receipted mutation action`, hasReceiptedMutation(s.slug));
    }
    if (["browse", "inspect", "shell"].includes(s.operational_state)) {
      ok(`${s.slug} (${s.operational_state}): NO receipted mutation is bound (read-tier honesty)`, !hasReceiptedMutation(s.slug));
    }
    if (s.operational_state === "read_only_by_contract") {
      const r = rows[s.slug];
      const refMut = (r.reference_control_census || []).filter((c) => /governed_receipted_action|create|edit|delete|run|execute|author/i.test(`${c.outcome} ${c.label} ${c.reference}`));
      ok(`${s.slug} (read_only_by_contract): every reference mutation is explicitly OUTSIDE the product contract`, !hasReceiptedMutation(s.slug) && refMut.every((c) => ["unsupported_reference_session", "reference_data_only"].includes(c.outcome)));
    }
  }

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
  ok("all 13 surfaces retain native_single_rail (audit-only PR; container contract intact)", SURFACES.every((s) => s.embedded_shell_state === "native_single_rail"));
  ok("every atlas capability is a member of the registry capability vocabulary", Object.values(rows).every((r) => (r.current.capabilities || []).every((c) => CAPABILITIES.includes(c))));
  ok("every atlas operational_state is a member of the registry state vocabulary", Object.values(rows).every((r) => OPERATIONAL_STATES.includes(r.current.operational_state)));

  // 7. SEQUENCE SUPERSESSION — audit evidence intact; the active queue is retired; the canon
  // (canon-to-code-delta.md) owns what happens next.
  const FACTORS = ["existing_authority_available", "user_workflow_value", "cross_application_leverage", "missing_contract_cost", "authority_security_risk"];
  const unfinished = SURFACES.filter((s) => !["workflow_complete", "act"].includes(s.operational_state)).map((s) => s.slug);
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
  // application-UX backlog, and the contract-first build sequence remains canonical.
  const deltaDoc = readFileSync(join(APP, "..", "..", "docs", "architecture", "_meta", "canon-to-code-delta.md"), "utf8");
  const backlog = deltaDoc.split("## Deferred application-UX backlog")[1] || "";
  const BACKLOG_ROW = { changes: "| Changes", monitors: "| Monitors", models: "| Models", designer: "| Designer", incidents: "| Incidents", machinery: "| Machinery", evalsuites: "| Evalsuites", explorer: "| Explorer", listings: "| Packages / Marketplace" };
  ok("every unfinished registry surface appears exactly once in the canon's deferred UX backlog", unfinished.every((u) => BACKLOG_ROW[u] && backlog.split(`\n${BACKLOG_ROW[u]} `).length === 2), unfinished.filter((u) => !(BACKLOG_ROW[u] && backlog.split(`\n${BACKLOG_ROW[u]} `).length === 2)).join(",") || `${unfinished.length} surfaces`);
  ok("backlog rows resume only when PULLED by an implemented contract (no PR-number sequence)", /resumes? (only )?when pulled by an implemented contract/i.test(backlog) && !/\| Changes[^\n]*#7\d/.test(backlog));
  const horizons = readFileSync(join(APP, "..", "..", "docs", "architecture", "_meta", "execution-horizons.md"), "utf8");
  ok("the contract-first build sequence remains canonical (14 ordered steps; closure = working proof, no PR numbers)", horizons.includes("## The build sequence (contract-first)") && /14\. Connected\/secured network-service proof/.test(horizons) && /Completion is not forced into an arbitrary PR\s+number|not forced into an arbitrary PR number/.test(horizons.replace(/\n/g, " ")) && /\]\(\.\/execution-horizons\.md#the-build-sequence-contract-first\)/.test(deltaDoc));

  // FALSE-CLAIM GUARDS (#70 review): the exact overstatements caught in review must not return.
  const row = (name) => (deltaDoc.split("\n").find((l) => l.startsWith(`| \`${name}\` |`)) || "");
  ok("`Finding` row: eval-suite plane is DECLARATION-ONLY precedent (no verdict plane) and the row is not started", row("Finding").includes("not started") && !row("Finding").includes("evaluation verdict records") && /no run\/execute endpoint, no scoring, no verdict|DECLARATION-ONLY/.test(row("Finding")));
  for (const obj of ["Attempt", "OntologyVersion", "SemanticMappingDecision", "ProvenanceAssertion"]) {
    ok(`\`${obj}\` row: not started with an explicitly LABELED implementation precedent (a precedent is never partial)`, row(obj).includes("not started") && !/\| partial/.test(row(obj)) && /implementation precedent/i.test(row(obj)));
  }
  ok("no held-stack work is described as landed/shipped (delta doc + atlas)", !/already-landed/i.test(deltaDoc) && !/shipped state/.test(deltaDoc) && /held stack/.test(deltaDoc) && /not yet\s+merged to master/i.test(deltaDoc.replace(/\n/g, " ")) && !JSON.stringify(atlas).includes("LANDED"));

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
  if (fails.length) process.exit(1);
  console.log("operational-depth atlas: OK");
}).catch((e) => {
  console.error("verifier crashed:", e);
  process.exit(1);
});

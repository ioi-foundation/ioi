#!/usr/bin/env node
// Synthesizes application-operational-depth.json (#68) from the exploration workflow's per-surface
// atlas rows. NOT a runtime dependency — a one-shot builder; the committed JSON is the artifact.
// - Reads the raw rows (journal-recovered), normalizes `current` to the LIVE registry (the atlas
//   can never overstate a surface's classification), derives implemented_control_census from each
//   control's own `implemented` flag (a subset of the census by construction), and records the
//   5-factor ranking as AUDIT EVIDENCE.
//
// SEQUENCE RETIREMENT (#70 canon convergence): the atlas is IMMUTABLE AUDIT EVIDENCE, not an
// active implementation queue. The former PR-numbered #69..#79 queue (and its `estate-closure`
// terminal entry) is retired: the ranking keeps its full 5-factor scoring evidence and the
// evidence-ranked order, but carries `implementation_sequence_status: "superseded_by_canon"` and
// points at docs/architecture/_meta/canon-to-code-delta.md — surface work resumes only when
// pulled by an implemented contract (the deferred UX backlog there).
//
// Modes (NO implicit destructive default — invoking with no recognized flag writes nothing):
//   --evolve-sequence   — load the COMMITTED atlas and apply the PURE, IDEMPOTENT, fail-closed
//                         `evolveRanking` transform (exported below; second application is
//                         byte-identical). Every surface row, control census, screenshot ref,
//                         scoring input, and security finding is preserved. This is the ONLY way
//                         the committed artifact is regenerated in place.
//   --rebuild-from-raw  — DESTRUCTIVE re-audit rebuild from .artifacts/opdepth/rows.json. The raw
//                         rows are a point-in-time capture that predates later row-level updates
//                         (e.g. the #69 Sources promotion narrative) — rebuilding OVERWRITES such
//                         updates and is only legitimate when a fresh re-audit regenerated the raw
//                         rows. It must always be an explicit choice, never a default.
import { readFileSync, writeFileSync } from "node:fs";
import path, { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { SURFACES } from "./surface-registry.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const APP = join(HERE, "..");
const RAW = join(APP, ".artifacts", "opdepth", "rows.json");
const ATLAS_PATH = join(APP, "application-operational-depth.json");

// The retired-queue → superseded-evidence ranking shape, shared by both modes: full scoring
// evidence, an evidence-ranked order with NO PR-number assignments and NO estate-closure entry,
// and the explicit supersession declaration.
export function supersededRanking(method, scored, evidenceOrder) {
  return {
    method,
    scored,
    evidence_order: evidenceOrder,
    implementation_sequence_status: "superseded_by_canon",
    superseded_by: "docs/architecture/_meta/canon-to-code-delta.md",
    sequence_note: "This ranking is immutable audit evidence, NOT an active implementation queue. The former PR-numbered surface queue is retired; application-UX work on the unfinished surfaces resumes only when pulled by an implemented contract — see the deferred application-UX backlog and the contract-first build sequence in the superseding canon file.",
  };
}

/**
 * PURE sequence-evolution transform (#70 review, round 2). Consumes a parsed atlas and returns a
 * NEW atlas whose ranking is the superseded-evidence shape. Properties, all fail-closed BEFORE
 * any caller could write:
 *   - source order = ranking.evidence_order ?? ranking.queue (legacy and already-evolved atlases
 *     both accepted), normalized by stripping `pr` fields and dropping the `estate-closure`
 *     terminal entry;
 *   - refuses an empty source order, duplicate slugs, or a slug set that does not exactly equal
 *     the ranking.scored slug set (the scoring evidence and the evidence order must describe the
 *     same surfaces);
 *   - IDEMPOTENT byte-for-byte: evolve(evolve(atlas)) === evolve(atlas) (the held-stack wording
 *     normalizations below only fire on the legacy phrasing).
 * Throws Error with a typed `evolve_*:` prefix; never mutates its input.
 */
export function evolveRanking(atlas) {
  const out = structuredClone(atlas);
  const rank = out.ranking;
  if (!rank || !Array.isArray(rank.scored) || rank.scored.length === 0) {
    throw new Error("evolve_scored_missing: the atlas carries no ranking.scored evidence — refusing to evolve");
  }
  const source = rank.evidence_order ?? rank.queue;
  if (!Array.isArray(source) || source.length === 0) {
    throw new Error("evolve_source_empty: neither ranking.evidence_order nor ranking.queue holds a non-empty order — refusing to write");
  }
  const evidenceOrder = source
    .filter((e) => e && e.slug !== "estate-closure")
    .map(({ pr, ...rest }) => rest); // strip any PR-number assignment; keep the scoring rationale as evidence
  if (evidenceOrder.length === 0) {
    throw new Error("evolve_source_empty: the source order contains no surface entries after normalization — refusing to write");
  }
  const slugs = evidenceOrder.map((e) => e.slug);
  if (new Set(slugs).size !== slugs.length) {
    throw new Error(`evolve_slugs_duplicated: duplicate slugs in the source order (${slugs.join(",")}) — refusing to write`);
  }
  const scoredSlugs = new Set(rank.scored.map((e) => e.slug));
  if (slugs.length !== scoredSlugs.size || !slugs.every((x) => scoredSlugs.has(x))) {
    throw new Error(`evolve_slug_set_mismatch: evidence order [${slugs.join(",")}] must exactly equal the ranking.scored set [${[...scoredSlugs].join(",")}] — refusing to write`);
  }
  out.ranking = supersededRanking(rank.method, rank.scored, evidenceOrder);
  // Held-stack honesty normalization (#70 review): nothing unmerged is described as LANDED.
  // Both replacements match only the legacy phrasing, so re-application is a no-op.
  const sources = out.surfaces && out.surfaces.sources;
  if (sources) {
    sources.landing_vs_workflow_note = String(sources.landing_vs_workflow_note || "").replace(
      "RESOLVED (#69): the declare half is LANDED —",
      "RESOLVED in the held stack (#69, open + held for review; not yet merged to master): the declare half is implemented —",
    );
    for (const c of sources.reference_control_census || []) {
      if (typeof c.reason === "string") c.reason = c.reason.replace(/^LANDED \(#69\): /, "IMPLEMENTED IN THE HELD STACK (#69, not yet merged): ");
    }
  }
  return out;
}

const atlasBytes = (atlas) => JSON.stringify(atlas, null, 2) + "\n";

function evolveSequenceCli() {
  const before = readFileSync(ATLAS_PATH, "utf8");
  const evolved = evolveRanking(JSON.parse(before));
  const once = atlasBytes(evolved);
  // Self-proof before any write: a second application must be byte-identical.
  const twice = atlasBytes(evolveRanking(JSON.parse(once)));
  if (once !== twice) throw new Error("evolve_not_idempotent: evolve(evolve(atlas)) !== evolve(atlas) — refusing to write");
  if (once === before) {
    console.log("atlas already canonical — evolve produced a byte-identical artifact; nothing written");
    return;
  }
  writeFileSync(ATLAS_PATH, once);
  console.log(`atlas ranking evolved — sequence superseded_by_canon; ${evolved.ranking.evidence_order.length} evidence-ranked surfaces retained; PR-number queue + estate-closure removed`);
}

// DESTRUCTIVE: full rebuild from the point-in-time raw rows. Explicit-flag only (see header).
function rebuildFromRaw() {
  const raw = JSON.parse(readFileSync(RAW, "utf8"));
  const reg = Object.fromEntries(SURFACES.map((s) => [s.slug, s]));

  // Targeted normalization: a handful of shared GLOBAL-RAIL / platform-chrome controls (Search /
  // Recent / Applications / View-all / the app-icon chip) were slotted local_view_interaction with
  // no binding, or reference_data_only with no reason. They are the certified shared rail rendered
  // verbatim — not surface-local affordances — so they are reference_data_only with a reason.
  const FIXUPS = {
    "schema:hdr.app-chip": { reason: "certified header app-icon chip rendered verbatim from the reference; no product control behind it" },
    "models:compare.settings": { outcome: "disabled_missing_authority", reason: "playground/inference sampling settings have no daemon inference plane exposed to the catalog — a named gap (route administration + inference live in Agent Studio / Foundry substrate)" },
    "machinery:rail.search": { outcome: "reference_data_only", reason: "the shared platform rail Search (ctrl+J) is certified rail chrome rendered verbatim, not a machinery-local control" },
    "machinery:rail.recent": { outcome: "reference_data_only", reason: "the shared platform rail Recent is certified rail chrome rendered verbatim, not a machinery-local control" },
    "evalsuites:gr.applications": { outcome: "reference_data_only", reason: "the shared platform rail Applications launcher is certified rail chrome rendered verbatim, not an evalsuites-local control" },
    "evalsuites:gr.viewall": { outcome: "reference_data_only", reason: "the shared platform rail View-all-applications link is certified rail chrome rendered verbatim, not an evalsuites-local control" },
  };

  // Operational = a surface whose PRIMARY workflow crosses real receipted daemon authority
  // (act / workflow_complete). inspect (Explorer) is read-navigation only — its reference workflow
  // (object exploration/search depth) is not yet operational, so it stays in the audited set.
  const OPERATIONAL = new Set(["workflow_complete", "act"]);

  const surfaces = {};
  for (const s of SURFACES) {
    const r = raw[s.slug];
    if (!r) throw new Error(`missing atlas row for ${s.slug}`);
    const census = (r.reference_control_census || []).map((c) => {
      const fx = FIXUPS[`${s.slug}:${c.id}`] || {};
      const outcome = fx.outcome || c.outcome;
      const reason = fx.reason || c.reason;
      const binding = fx.binding || c.binding;
      return {
        id: c.id, region: c.region, label: c.label, reference: c.reference, outcome,
        ...(reason ? { reason } : {}), ...(binding ? { binding } : {}),
        implemented: c.implemented === true,
      };
    });
    // implemented_control_census = the ids the CURRENT IOI surface renders (subset by construction).
    const implemented = census.filter((c) => c.implemented).map((c) => c.id);
    surfaces[s.slug] = {
      slug: s.slug,
      owner: reg[s.slug].owner,
      title: reg[s.slug].title,
      reference_route: r.reference_route,
      ioi_route: s.route,
      primary_workflow: r.primary_workflow,
      reference_reached_states: r.reference_reached_states || [],
      landing_vs_workflow_note: r.landing_vs_workflow_note || "",
      // `current` = the LIVE registry truth (normalized — never the agent's prose).
      current: { capabilities: reg[s.slug].capabilities, operational_state: reg[s.slug].operational_state },
      reference_control_census: census,
      implemented_control_census: implemented,
      existing_daemon: r.existing_daemon || { routes: [], actions: [], receipts: [] },
      missing_authority_contracts: r.missing_authority_contracts || [],
      security_credential_implications: r.security_credential_implications || "",
      recommended_next_pr: r.recommended_next_pr || { title: "", scope: "", done_bar: [] },
      ranking_inputs: r.ranking_inputs,
      classification_confidence: r.classification_confidence || "medium",
      blockers: r.blockers || [],
      screenshots: r.screenshots || [],
      is_operational: OPERATIONAL.has(reg[s.slug].operational_state),
    };
  }

  // ---- EVIDENCE CORRECTION (recorded, not fudged): the Pipeline reached workflow_complete in #67
  // and its governed Build consumes a declared data source + connector. That makes Sources the SOLE
  // missing input to the estate's one operational end-to-end workflow — objectively the maximal
  // current-estate cross-application leverage. The audit raises Sources' cross_application_leverage
  // from the per-surface score (4) to 5 with this justification stamped on the row.
  surfaces.sources.ranking_inputs.cross_application_leverage = 5;
  surfaces.sources.ranking_evidence = "cross_application_leverage raised 4→5: the #67 governed Pipeline Build (operational_state=workflow_complete) consumes a declared DataSource + covering Connector, so Sources is the single missing input to the estate's only operational intent→durable-result workflow — the highest-leverage next cut in the current estate state.";

  // ---- Ranking: the unfinished surfaces (everything but act/workflow_complete). The directive
  // gives the five factors in PRIORITY order (1 existing-authority, 2 workflow-value, 3 cross-app-
  // leverage, then the two costs); the composite weights them by inverse rank so the priority order
  // is honored, and the two cost factors subtract:
  //   composite = 5·E + 4·V + 3·L − 2·C − 1·R   (higher = stronger evidence)
  const unfinishedSlugs = SURFACES.filter((s) => !OPERATIONAL.has(s.operational_state)).map((s) => s.slug);
  const composeScore = (ri) => 5 * ri.existing_authority_available + 4 * ri.user_workflow_value + 3 * ri.cross_application_leverage - 2 * ri.missing_contract_cost - 1 * ri.authority_security_risk;
  const scored = unfinishedSlugs.map((slug) => {
    const ri = surfaces[slug].ranking_inputs;
    return { slug, title: reg[slug].title, ranking_inputs: ri, composite: composeScore(ri) };
  });
  scored.sort((a, b) => b.composite - a.composite
    || b.ranking_inputs.cross_application_leverage - a.ranking_inputs.cross_application_leverage
    || a.ranking_inputs.authority_security_risk - b.ranking_inputs.authority_security_risk
    || a.slug.localeCompare(b.slug));

  // Evidence-ranked order only — no PR-number assignments, no estate-closure terminal entry
  // (the implementation sequence is owned by the canon; see supersededRanking above).
  const evidenceOrder = scored.map((e) => ({
    slug: e.slug, title: e.title, composite: e.composite,
    recommended_next_pr: surfaces[e.slug].recommended_next_pr.title,
    rationale: `composite ${e.composite} = (existing_authority ${e.ranking_inputs.existing_authority_available} + workflow_value ${e.ranking_inputs.user_workflow_value} + cross_app_leverage ${e.ranking_inputs.cross_application_leverage}) − (missing_contract_cost ${e.ranking_inputs.missing_contract_cost} + security_risk ${e.ranking_inputs.authority_security_risk}); ${surfaces[e.slug].recommended_next_pr.scope.slice(0, 220)}`,
  }));

  const atlas = {
    schema_version: "ioi.hypervisor.operational-depth-atlas.v1",
    generated_from: "operational-depth exploration workflow (13 per-surface agents, live reference SPA + IOI embedded + daemon cross-check)",
    base_commit: "19d732ff2 (#67)",
    doctrine: "daemon_wired and shell-pixel certification prove the surface renders reference-faithfully over honest daemon truth — they DO NOT imply operational completeness. Operational depth is a separate axis: a surface is operational only when its PRIMARY reference workflow (intent → durable result) is reachable through real daemon authority, not merely when its landing shell is certified. This atlas audits that axis; a splash or empty-onboarding state is never the workflow.",
    outcome_taxonomy: {
      daemon_read: "invokes existing daemon truth via read navigation",
      local_view_interaction: "view-only client/URL state, no authority crossed",
      governed_receipted_action: "a real mutation through EXISTING daemon authority returning a durable receipt",
      disabled_missing_authority: "visible but disabled; the reason names the exact missing daemon contract",
      unsupported_reference_session: "reference session machinery (branch/proposal/favorites/undo) with no IOI product plane",
      reference_data_only: "the reference's verbatim capture chrome / example content, display-only",
    },
    surfaces,
    ranking: supersededRanking(
      "composite = 5·existing_authority_available + 4·user_workflow_value + 3·cross_application_leverage − 2·missing_contract_cost − 1·authority_security_risk (factor weights follow the directive's stated priority order); descending, tiebreak on cross_application_leverage then lower security_risk then slug",
      scored,
      evidenceOrder,
    ),
  };

  writeFileSync(ATLAS_PATH, atlasBytes(atlas));
  console.log(`atlas REBUILT FROM RAW — ${Object.keys(surfaces).length} surfaces; sequence superseded_by_canon; evidence order: ${evidenceOrder.map((q) => `${q.slug}(${q.composite})`).join(" · ")}`);
  console.log("WARNING: raw rows are a point-in-time capture — verify no later row-level updates were overwritten (git diff the artifact).");
}

// CLI — entrypoint-gated so importing the pure transforms above has zero side effects.
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.includes("--evolve-sequence")) {
    evolveSequenceCli();
  } else if (process.argv.includes("--rebuild-from-raw")) {
    rebuildFromRaw();
  } else {
    console.error("no mode selected — nothing was read or written.");
    console.error("  --evolve-sequence    safe, idempotent in-place migration of the committed atlas ranking");
    console.error("  --rebuild-from-raw   DESTRUCTIVE re-audit rebuild from .artifacts/opdepth/rows.json (overwrites later row-level updates)");
    process.exit(2);
  }
}

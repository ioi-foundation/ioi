#!/usr/bin/env node
// Surface-module verifier (functional-runtime wave — the Pipeline extraction + interaction kit).
//
// Proves the module shape PR #57 builds on:
//   1. CONTRACT — surfaces/pipeline/index.mjs exports { meta, load, render, actions }; meta agrees
//      with its surface-registry entry AND its parity-matrix seed (one identity, three records).
//   2. MOUNT — the registry binds the module itself (identity, not a copy), and the module renders
//      OFFLINE against a dead daemon: honest empty lists, the certified shell landmarks intact.
//   3. EXTRACTION HYGIENE — the serve monolith no longer carries the moved code (renderer, global
//      rail, escaper definition); the kit's escHtml is the single escaper definition.
//   4. KIT UNITS — the interaction helpers behave (escaping, stable selection URLs, shells carrying
//      the ids/testids the interaction verifiers will drive, disabled commands naming reasons).
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-surface-modules.mjs
// Exit 0 = all assertions pass; exit 1 = one or more failed.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { SURFACES, boundSurface, surfaceBySlug } from "./surface-registry.mjs";
import * as pipeline from "../surfaces/pipeline/index.mjs";
import * as ontologyManager from "../surfaces/ontology-manager/index.mjs";
import * as objectExplorer from "../surfaces/object-explorer/index.mjs";
import * as missions from "../surfaces/missions/index.mjs";
import { canonicalTimelineRef, escHtml, parseSelection, selectionQuery, inspectorShell, trayShell, disabledCommand, proofLink, semanticMask } from "../surfaces/kit.mjs";
import { ONTOLOGY_CONTEXT_KEYS, parseOntologyContext, ontologyContextQuery, managerLink, explorerLink, objectTypeLink, objectSetLink, managerResourceLink, sourcesLink, provenanceReceiptLink, semanticBreadcrumb, semanticInspectorShell, disabledSemanticAction, formatRef } from "../surfaces/ontology-context.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const APP = join(HERE, "..");

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };

// R-192 (S5-1): one collection. The GoalRun plane this surface also read is gone from the daemon
// — goal runs are ioi.ai compositions over thread orchestration primitives, not Hypervisor
// surfaces — so a fixture naming it would prove nothing, and the retirement probe below asserts
// the surface no longer asks for it at all.
const MISSION_COLLECTIONS = {
  "/v1/hypervisor/work-results": "work_results",
};

function missionsFixtureFetch(overrides = {}) {
  return async (rawUrl) => {
    const pathname = new URL(rawUrl).pathname;
    const override = overrides[pathname] || {};
    const status = override.status || 200;
    let body = override.body;
    if (body === undefined && pathname === "/v1/hypervisor/operations") {
      body = { runs: { total: 0, recent: [], failures: [] } };
    }
    if (body === undefined && MISSION_COLLECTIONS[pathname]) {
      body = { [MISSION_COLLECTIONS[pathname]]: [] };
    }
    return new Response(JSON.stringify(body || {}), {
      status,
      headers: { "content-type": "application/json" },
    });
  };
}

async function run() {
  // 1. Contract + identity agreement.
  ok("pipeline module exports the surface contract", typeof pipeline.load === "function" && typeof pipeline.render === "function" && Array.isArray(pipeline.actions) && pipeline.meta && typeof pipeline.meta === "object");
  const reg = surfaceBySlug("pipeline");
  ok("module meta agrees with the registry entry", !!reg && pipeline.meta.slug === reg.slug && pipeline.meta.route === reg.route && pipeline.meta.verifier === reg.verifier && pipeline.meta.certification === reg.certification);
  const matrix = JSON.parse(readFileSync(join(APP, "harvest-app-parity-matrix.json"), "utf8"));
  const seed = (matrix.seeds || []).find((s) => s.slug === "pipeline");
  ok("module meta agrees with the parity-matrix seed", !!seed && seed.candidate_surface.split("?")[0] === pipeline.meta.route && seed.shell_pixel_certification_artifact === pipeline.meta.certification && seed.shell_pixel_certified === true);
  ok("command table honors the discipline contract: enabled ⇒ route+proof, disabled ⇒ named reason", pipeline.commands.length === 4 && pipeline.commands.every((a) => a.key && a.label && (a.enabled ? (typeof a.route === "string" && typeof a.proof === "string") : (typeof a.reason === "string" && a.reason.length > 20))));
  ok("Preview + Build are the enabled navigations (#67: Build = the governed workflow entry); Schedule/Deploy stay disabled named gaps", pipeline.commands.filter((a) => a.enabled).map((a) => a.key).join(",") === "preview,build" && !!pipeline.commands.find((a) => a.key === "build").authority && pipeline.commands.filter((a) => !a.enabled).map((a) => a.key).join(",") === "schedule,deploy");
  ok("the governed Build workflow declares its runtime mutation descriptors (#67: 8 stages, each authority+receipt bound, grants field-bounded)", pipeline.actions.length === 8 && pipeline.actions.every((a) => a.id && a.method === "POST" && a.route && a.authority && a.authority.plane && a.receipt && Array.isArray(a.fields)) && pipeline.actions.filter((a) => (a.fields || []).includes("wallet_approval_grant")).every((a) => a.fieldMax >= 4096) && typeof pipeline.handleAction === "function");

  // 2. Registry mounts the module itself; offline render keeps the certified shell landmarks.
  const hit = boundSurface("/__ioi/pipeline", "GET");
  ok("registry binds the module (identity, not a copy)", !!hit && hit.impl.render === pipeline.render && hit.impl.load === pipeline.load, hit ? "bound" : "no binding for /__ioi/pipeline");
  const ctx = { url: new URL("http://x/__ioi/pipeline"), daemon: "http://127.0.0.1:1" };
  const model = await pipeline.load(ctx);
  // The load contract on a dead daemon: every LIST key honest-empty AND the typed degradation
  // record present (the `degraded` key is the module's own truth about why the lists are empty —
  // asserting all-arrays was stale once that key landed; empty lists WITHOUT the record would be
  // the dishonest shape).
  const { degraded: deg, ...deadLists } = model;
  ok("dead daemon loads to honest empty lists + typed degradation record", Object.values(deadLists).every((v) => Array.isArray(v) && v.length === 0) && !!deg && typeof deg === "object", `${Object.keys(deadLists).length} list keys · degraded=${!!deg}`);
  const html = pipeline.render(model, ctx);
  ok("offline render keeps the certified shell landmarks", ["<title>Pipeline Builder</title>", "Pipeline outputs", "pb-shell", "APPLICATIONS"].every((m) => html.includes(m)));
  const selCtx = { url: new URL("http://x/__ioi/pipeline?ontology=does-not-exist"), daemon: "http://127.0.0.1:1" };
  ok("selection param accepted without drift on empty truth", pipeline.render(model, selCtx) === html, "unknown ontology falls back identically");

  // 3. Extraction hygiene — the monolith no longer carries the moved code.
  const serveSrc = readFileSync(join(HERE, "serve-product-ui.mjs"), "utf8");
  ok("serve no longer defines renderPipelineBuilder", !serveSrc.includes("function renderPipelineBuilder"));
  ok("serve no longer defines the global rail", !serveSrc.includes("function ioiGlobalRailHtml") && !serveSrc.includes("const IOI_GRAIL_CSS"));
  ok("serve aliases the kit escaper (no duplicate definition)", serveSrc.includes("const CX_ESC = escHtml") && !serveSrc.includes('replace(/&/g, "&amp;").replace(/</g'));
  ok("registry lists pipeline exactly once", SURFACES.filter((s) => s.slug === "pipeline").length === 1);
  const validTimeline = "/__ioi/run-timeline/goal-run/gr_deadbeef";
  ok("kit: timeline navigation accepts only exact internal non-traversing paths",
    canonicalTimelineRef(validTimeline) === validTimeline
      && [
        "javascript:alert(1)",
        "/__ioi/run-timeline/../governance",
        "/__ioi/run-timeline/%2e%2e/governance",
        "/__ioi/run-timeline/gr_deadbeef?return=/__ioi/governance",
        "/__ioi/run-timeline/gr_deadbeef#fragment",
        "//ioi.local/__ioi/run-timeline/gr_deadbeef",
      ].every((reference) => canonicalTimelineRef(reference) === ""));

  // 4. MISSIONS MODULE — contract-pulled, daemon-backed, and intentionally read-only.
  const missionsReg = surfaceBySlug("missions");
  ok("missions: module exports the read-only surface contract",
    typeof missions.load === "function" && typeof missions.render === "function"
      && Array.isArray(missions.actions) && missions.actions.length === 0
      && typeof missions.handleAction === "undefined");
  ok("missions: module meta agrees with the honest non-certified registry entry",
    !!missionsReg && missions.meta.slug === missionsReg.slug && missions.meta.route === missionsReg.route
      && missions.meta.verifier === missionsReg.verifier && missions.meta.certification === "n/a"
      && missionsReg.operational_state === "read_only_by_contract"
      && missionsReg.catalog_evidence?.schema === "ioi.hypervisor.catalog-contract-evidence.v1");
  const missionsHit = boundSurface("/__ioi/missions", "GET");
  ok("missions: registry binds the module (identity, not a copy)",
    !!missionsHit && missionsHit.impl.render === missions.render && missionsHit.impl.load === missions.load);
  const missionsCtx = { url: new URL("http://x/__ioi/missions"), daemon: "http://127.0.0.1:1", embed: true };
  const missionsModel = await missions.load(missionsCtx);
  const missionsHtml = missions.render(missionsModel, missionsCtx);
  ok("missions: dead daemon stays an honest unavailable projection with no mutation form",
    [missionsModel.results, missionsModel.operations]
      .every((plane) => plane.ok === false && plane.rows.length === 0)
      && missionsHtml.includes('data-missions-work-graph="work-results"')
      && missionsHtml.includes("Counts for this plane are not treated as zero")
      && !/<form\b/i.test(missionsHtml));
  const requestedPaths = [];
  const recordingFetch = (overrides = {}) => async (rawUrl, init) => {
    requestedPaths.push(new URL(rawUrl).pathname);
    return missionsFixtureFetch(overrides)(rawUrl, init);
  };
  const fixtureResult = {
    work_result_id: "work-result://wr_partial_outage",
    work_subject_ref: "work-run://partial-outage",
    outcome_class: "positive",
    status: "completed",
  };
  const partialCtx = {
    ...missionsCtx,
    url: new URL("http://x/__ioi/missions"),
    fetch: recordingFetch({
      "/v1/hypervisor/work-results": { status: 503, body: { error: { code: "results_unavailable" } } },
    }),
  };
  const partialModel = await missions.load(partialCtx);
  const partialHtml = missions.render(partialModel, partialCtx);
  ok("missions: a partial outage renders unknown at every dependent metric and never zero",
    partialModel.operations.ok === true
      && partialModel.results.ok === false
      && partialModel.subjects.length === 0
      && partialHtml.includes('data-missions-metric="results" data-value="unknown"')
      && partialHtml.includes('data-missions-metric="work-subjects" data-value="unknown"')
      && partialHtml.includes('data-missions-metric="failed-results" data-value="unknown"')
      && partialHtml.includes("WorkResult plane</b> unavailable"));
  ok("missions: the surface asks the daemon for exactly the two planes that still exist — no goal-run, room, participation, frontier, claim, offer, match, attempt, finding or challenge route is requested",
    requestedPaths.length > 0
      && [...new Set(requestedPaths)].sort().join(",")
        === "/v1/hypervisor/operations,/v1/hypervisor/work-results",
    [...new Set(requestedPaths)].sort().join(","));
  const malformedCtx = {
    ...missionsCtx,
    fetch: missionsFixtureFetch({
      "/v1/hypervisor/work-results": { body: { work_results: { not: "an array" } } },
    }),
  };
  const malformedModel = await missions.load(malformedCtx);
  const malformedHtml = missions.render(malformedModel, malformedCtx);
  const malformedRowModel = await missions.load({
    ...missionsCtx,
    fetch: missionsFixtureFetch({
      "/v1/hypervisor/work-results": { body: { work_results: [{}] } },
    }),
  });
  const mixedRowModel = await missions.load({
    ...missionsCtx,
    fetch: missionsFixtureFetch({
      "/v1/hypervisor/work-results": { body: { work_results: [fixtureResult, {}] } },
    }),
  });
  const mixedRowHtml = missions.render(mixedRowModel, missionsCtx);
  const offContractOutcomeModel = await missions.load({
    ...missionsCtx,
    fetch: missionsFixtureFetch({
      "/v1/hypervisor/work-results": { body: { work_results: [{ ...fixtureResult, outcome_class: "excellent" }] } },
    }),
  });
  const malformedOperationRunModel = await missions.load({
    ...missionsCtx,
    fetch: missionsFixtureFetch({
      "/v1/hypervisor/operations": { body: { runs: { total: 1, recent: [null], failures: [] } } },
    }),
  });
  const malformedOperationRunHtml = missions.render(malformedOperationRunModel, missionsCtx);
  ok("missions: malformed collection and exact invalid-row probes fail closed as plane_payload_invalid without crashing or invented rows",
    malformedModel.results.ok === false && malformedModel.results.status === 200
      && malformedModel.results.code === "plane_payload_invalid"
      && malformedHtml.includes("Subject list unavailable")
      && !malformedHtml.includes("No work subjects in this view")
      && malformedRowModel.results.ok === false
      && malformedRowModel.results.code === "plane_payload_invalid"
      && mixedRowModel.results.ok === false
      && mixedRowModel.results.rows.length === 0
      && mixedRowModel.results.code === "plane_payload_invalid"
      && !mixedRowHtml.includes("work-result://wr_partial_outage")
      && offContractOutcomeModel.results.ok === false
      && offContractOutcomeModel.results.code === "plane_payload_invalid"
      && malformedOperationRunModel.operations.ok === false
      && malformedOperationRunModel.operations.code === "plane_payload_invalid"
      && malformedOperationRunHtml.includes("Operations run queue</b> unavailable"));
  const timeoutStartedAt = Date.now();
  const timeoutModel = await missions.load({
    ...missionsCtx,
    planeTimeoutMs: 25,
    fetch: async (rawUrl, init) => {
      if (new URL(rawUrl).pathname === "/v1/hypervisor/work-results") {
        return new Promise(() => {
          init?.signal?.addEventListener("abort", () => {}, { once: true });
        });
      }
      return missionsFixtureFetch()(rawUrl, init);
    },
  });
  ok("missions: a never-resolving plane is bounded and becomes an honest timeout, not a hung route",
    Date.now() - timeoutStartedAt < 500
      && timeoutModel.results.ok === false
      && timeoutModel.results.code === "plane_timeout",
    `${Date.now() - timeoutStartedAt}ms/${timeoutModel.results.code}`);
  const bodyTimeoutStartedAt = Date.now();
  const bodyTimeoutModel = await missions.load({
    ...missionsCtx,
    planeTimeoutMs: 25,
    fetch: async (rawUrl, init) => {
      if (new URL(rawUrl).pathname === "/v1/hypervisor/work-results") {
        return {
          ok: true,
          status: 200,
          json: () => new Promise(() => {
            init?.signal?.addEventListener("abort", () => {}, { once: true });
          }),
        };
      }
      return missionsFixtureFetch()(rawUrl, init);
    },
  });
  ok("missions: the same deadline bounds a response body that stalls after headers",
    Date.now() - bodyTimeoutStartedAt < 500
      && bodyTimeoutModel.results.ok === false
      && bodyTimeoutModel.results.code === "plane_timeout",
    `${Date.now() - bodyTimeoutStartedAt}ms/${bodyTimeoutModel.results.code}`);
  const unsafeTimelineModel = await missions.load({
    ...missionsCtx,
    fetch: missionsFixtureFetch({
      "/v1/hypervisor/operations": {
        body: {
          runs: {
            total: 1,
            recent: [{ execution_id: "exec-safe-shape", status: "failed", timeline_ref: "javascript:alert(document.domain)" }],
            failures: [],
          },
        },
      },
    }),
  });
  const unsafeTimelineHtml = missions.render(unsafeTimelineModel, missionsCtx);
  ok("missions: operation proof links accept only canonical run-timeline paths",
    unsafeTimelineModel.operations.ok === false
      && unsafeTimelineModel.operations.code === "plane_payload_invalid"
      && !unsafeTimelineHtml.includes("javascript:")
      && !unsafeTimelineHtml.includes("alert(document.domain)"));
  // R-192 (S5-1): what this surface can check WITHOUT reaching another owner is identity
  // uniqueness on its one collection and the grouping of results under the subject each one
  // names — plus the honest states when a selection does not resolve. A subject is an opaque ref
  // from whatever application produced the result; this surface never resolves it.
  const resultOne = { work_result_id: "work-result://wr_aa", work_subject_ref: "work-run://alpha", outcome_class: "positive", status: "completed" };
  const resultTwo = { work_result_id: "work-result://wr_bb", work_subject_ref: "work-run://alpha", outcome_class: "inconclusive", status: "partial" };
  const resultOther = { work_result_id: "work-result://wr_cc", work_subject_ref: "automation-run://beta", outcome_class: "positive", status: "completed" };
  const alphaId = "work-run-alpha";
  const graphCtx = {
    ...missionsCtx,
    url: new URL(`http://x/__ioi/missions?subject=${alphaId}`),
    fetch: missionsFixtureFetch({
      "/v1/hypervisor/work-results": { body: { work_results: [resultOne, resultTwo, resultOther] } },
    }),
  };
  const graphModel = await missions.load(graphCtx);
  const graphHtml = missions.render(graphModel, graphCtx);
  ok("missions: results group under the subject each one names, an open subject is one with an unsettled result, and only the selected subject's results are rendered",
    graphModel.results.ok === true
      && graphModel.subjects.length === 2
      && graphModel.subjects[0].subject_ref === "work-run://alpha"
      && graphModel.subjects[0].results.length === 2
      && graphModel.subjects[0].open === true
      && graphModel.subjects[1].open === false
      && graphHtml.includes(`data-missions-selected-subject="${alphaId}"`)
      && graphHtml.includes("work-result://wr_aa")
      && graphHtml.includes("work-result://wr_bb")
      && !graphHtml.includes("work-result://wr_cc")
      && graphHtml.includes('data-missions-metric="work-subjects" data-value="2"'),
    JSON.stringify(graphModel.subjects.map((group) => [group.subject_id, group.results.length, group.open])));
  const duplicateModel = await missions.load({
    ...missionsCtx,
    fetch: missionsFixtureFetch({
      "/v1/hypervisor/work-results": { body: { work_results: [resultOne, { ...resultTwo, work_result_id: resultOne.work_result_id }] } },
    }),
  });
  ok("missions: two results claiming one identity invalidate the whole plane rather than rendering an ambiguous list",
    duplicateModel.results.ok === false
      && duplicateModel.results.code === "plane_relationship_invalid"
      && duplicateModel.results.rows.length === 0
      && duplicateModel.subjects.length === 0);
  const missingCtx = {
    ...missionsCtx,
    url: new URL("http://x/__ioi/missions?subject=work-run-absent"),
    fetch: missionsFixtureFetch({ "/v1/hypervisor/work-results": { body: { work_results: [resultOne] } } }),
  };
  const filteredCtx = {
    ...missionsCtx,
    url: new URL(`http://x/__ioi/missions?subject=${alphaId}&status=completed`),
    fetch: missionsFixtureFetch({ "/v1/hypervisor/work-results": { body: { work_results: [resultTwo, resultOther] } } }),
  };
  const missingHtml = missions.render(await missions.load(missingCtx), missingCtx);
  const filteredHtml = missions.render(await missions.load(filteredCtx), filteredCtx);
  ok("missions: a selection that does not resolve says which of the two honest reasons it is, and invents no detail",
    missingHtml.includes('data-missions-selection="work_subject_not_found"')
      && !missingHtml.includes("data-missions-selected-subject")
      && filteredHtml.includes('data-missions-selection="work_subject_filter_mismatch"'),
    `${missingHtml.includes('data-missions-selection="work_subject_not_found"')}/${filteredHtml.includes('data-missions-selection="work_subject_filter_mismatch"')}`);
  const cappedResults = Array.from({ length: 60 }, (_, index) => ({
    work_result_id: `work-result://wr_capped_${index}`,
    work_subject_ref: `work-run://capped-${index}`,
    outcome_class: "negative",
    status: "failed",
  }));
  const cappedCtx = {
    ...missionsCtx,
    fetch: missionsFixtureFetch({
      "/v1/hypervisor/work-results": { body: { work_results: cappedResults } },
    }),
  };
  const cappedHtml = missions.render(await missions.load(cappedCtx), cappedCtx);
  // Scoped to the incident list itself: the subject sidebar above it holds all sixty subjects, so
  // a whole-page substring probe would measure the sidebar and call the cap broken.
  const cappedIncidents = cappedHtml.slice(cappedHtml.indexOf('id="missions-incidents"'));
  ok("missions: the incident cap is deterministic and disclosed as showing first 50 of 60",
    cappedHtml.includes("showing first 50 of 60")
      && cappedIncidents.includes("work-run://capped-49")
      && !cappedIncidents.includes("work-run://capped-50"),
    `${cappedHtml.includes("showing first 50 of 60")}/${cappedIncidents.includes("work-run://capped-49")}/${cappedIncidents.includes("work-run://capped-50")}`);
  ok("serve no longer defines the extracted Missions renderer", !serveSrc.includes("function renderMissions"));

  // 5. ONTOLOGY MODULES (the #59 extraction) — same contract, same hygiene, both certified ports.
  const ONTOLOGY_MODULES = [
    { mod: ontologyManager, slug: "schema", route: "/__ioi/ontology/manager", title: "<title>Ontology Manager</title>", marks: ["Discover", "Object types", "og-grail"] },
    { mod: objectExplorer, slug: "explorer", route: "/__ioi/ontology/explorer", title: "<title>Object Explorer</title>", marks: ["Object type", "og-grail"] },
  ];
  for (const { mod, slug, route, title, marks } of ONTOLOGY_MODULES) {
    ok(`${slug}: module exports the surface contract`, typeof mod.load === "function" && typeof mod.render === "function" && Array.isArray(mod.actions) && mod.meta && mod.meta.slug === slug);
    const reg2 = surfaceBySlug(slug);
    ok(`${slug}: module meta agrees with the registry entry`, !!reg2 && mod.meta.route === reg2.route && mod.meta.verifier === reg2.verifier && mod.meta.certification === reg2.certification);
    const seed2 = (matrix.seeds || []).find((s) => s.slug === slug);
    ok(`${slug}: module meta agrees with the parity-matrix seed`, !!seed2 && seed2.candidate_surface.split("?")[0] === mod.meta.route && seed2.shell_pixel_certification_artifact === mod.meta.certification && seed2.shell_pixel_certified === true);
    const hit2 = boundSurface(route, "GET");
    ok(`${slug}: registry binds the module (identity, not a copy)`, !!hit2 && hit2.impl.render === mod.render && hit2.impl.load === mod.load);
    const ctx2 = { url: new URL(`http://x${route}`), daemon: "http://127.0.0.1:1" };
    const model2 = await mod.load(ctx2);
    const html2 = mod.render(model2, ctx2);
    ok(`${slug}: offline dead-daemon render keeps the certified shell landmarks`, [title, ...marks].every((m) => html2.includes(m)));
  }
  ok("serve no longer defines the ontology port renderers", !serveSrc.includes("function renderOntologyManagerPort") && !serveSrc.includes("function renderObjectExplorerPort"));
  ok("the odk substrate's own manager renderer STAYS in serve (not the certified port)", serveSrc.includes("function renderOntologyManager("));

  // 6. ONTOLOGY CONTEXT KIT — the semantic-layer primitives (unwired; PR60-62 wire them).
  const cu = new URL("http://x/r?ontology=ont-1&objectType=loan&objectSet=&pane=types&noise=z");
  const octx = parseOntologyContext(cu);
  ok("parseOntologyContext reads only known, non-empty keys", octx.ontology === "ont-1" && octx.objectType === "loan" && octx.pane === "types" && !("objectSet" in octx) && !("noise" in octx) && ONTOLOGY_CONTEXT_KEYS.length === 14 && ["definitionKind", "definitionId", "dataSource", "connectorMapping", "policyView", "ontologyProjection", "materializingRun", "receipt"].every((k) => ONTOLOGY_CONTEXT_KEYS.includes(k)));
  // #64 cross-plane keys: roundtrip-stable, unknown keys dropped, oversized values dropped.
  const xctx = parseOntologyContext(new URL("http://x/r?dataSource=ds_1&connectorMapping=cm_1&receipt=agentgres%3A%2F%2Fx%2Fr1&rogue=z"));
  ok("cross-plane context roundtrips (known keys only, canonical order)", xctx.dataSource === "ds_1" && xctx.connectorMapping === "cm_1" && xctx.receipt === "agentgres://x/r1" && !("rogue" in xctx) && ontologyContextQuery("/r", xctx) === "/r?connectorMapping=cm_1&dataSource=ds_1&receipt=agentgres%3A%2F%2Fx%2Fr1");
  ok("oversized context values are DROPPED (never truncated into a different identity)", !("ontology" in parseOntologyContext(new URL(`http://x/r?ontology=${"a".repeat(300)}`))));
  ok("link builders fail closed on missing owning ids", managerResourceLink("", "connector-mapping", "x") === null && managerResourceLink("o", "bogus-kind", "x") === null && sourcesLink("") === null && provenanceReceiptLink("") === null);
  const rt = ontologyContextQuery("/r", octx);
  ok("ontologyContextQuery is canonical (sorted keys, empties dropped) and roundtrips", rt === "/r?objectType=loan&ontology=ont-1&pane=types" && JSON.stringify(parseOntologyContext(new URL(`http://x${rt}`))) === JSON.stringify(octx));
  ok("ontologyContextQuery ignores unknown keys", ontologyContextQuery("/r", { ontology: "a", rogue: "x" }) === "/r?ontology=a");
  ok("surface link helpers target the owning routes", managerLink({ ontology: "a" }) === "/__ioi/ontology/manager?ontology=a" && explorerLink({ ontology: "a" }) === "/__ioi/ontology/explorer?ontology=a" && objectTypeLink("a", "loan") === "/__ioi/ontology/explorer?objectType=loan&ontology=a" && objectSetLink("a", "set-1") === "/__ioi/ontology/explorer?objectSet=set-1&ontology=a");
  const crumb = semanticBreadcrumb([{ label: "ont<1", href: "/__ioi/ontology/manager?ontology=a" }, { label: "Loan" }]);
  ok("semanticBreadcrumb links owned segments, escapes labels, carries the testid", crumb.includes('data-testid="ioi-sem-breadcrumb"') && crumb.includes("ont&lt;1") && crumb.includes('href="/__ioi/ontology/manager?ontology=a"') && crumb.includes('<span class="ioi-sem-crumb">Loan</span>') && crumb.includes(" → "));
  ok("semanticInspectorShell is the kit inspector with the semantic marker", semanticInspectorShell({ id: "x", title: "T", body: "b" }).includes("ioi-sem-inspector") && semanticInspectorShell({ id: "x", title: "T", body: "b" }).includes('data-testid="ioi-inspector"'));
  ok("disabledSemanticAction names its reason", disabledSemanticAction({ label: "Edit type", reason: "no ODK patch authority wired on this surface yet" }).includes("data-ioi-disabled-reason=") && disabledSemanticAction({ label: "E", reason: "r" }).includes("ioi-sem-action"));
  ok("formatRef escapes and marks refs", formatRef('ref<"&>') === '<code class="ioi-ref">ref&lt;&quot;&amp;&gt;</code>' && formatRef(null) === '<code class="ioi-ref"></code>');

  // 7. Interaction kit units.
  ok("escHtml escapes the four metacharacters", escHtml('&<>"') === "&amp;&lt;&gt;&quot;" && escHtml(null) === "" && escHtml(0) === "0");
  const u = new URL("http://x/r?node=mapping&ontology=ont-1&empty=&noise=z");
  const sel = parseSelection(u, ["node", "ontology", "empty", "absent"]);
  ok("parseSelection reads only present, non-empty keys", sel.node === "mapping" && sel.ontology === "ont-1" && !("empty" in sel) && !("absent" in sel) && !("noise" in sel));
  ok("selectionQuery is stable (sorted keys, empties dropped)", selectionQuery("/r", { ontology: "ont-1", node: "mapping", gone: "" }) === "/r?node=mapping&ontology=ont-1" && selectionQuery("/r", {}) === "/r");
  ok("selection roundtrip preserves state", JSON.stringify(parseSelection(new URL("http://x" + selectionQuery("/r", sel)), ["node", "ontology"])) === JSON.stringify(sel));
  ok("selectionQuery encodes values", selectionQuery("/r", { q: "a b&c" }) === "/r?q=a%20b%26c");
  const insp = inspectorShell({ id: "pb-insp", title: 'T<"', subtitle: "s", body: "<b>body</b>", cls: "x" });
  ok("inspectorShell carries id/testid and escapes chrome, not body", insp.includes('id="pb-insp"') && insp.includes('data-testid="ioi-inspector"') && insp.includes("T&lt;&quot;") && insp.includes("<b>body</b>"));
  const tray = trayShell({ id: "pb-tray", title: "Preview", body: "rows" });
  ok("trayShell carries id/testid", tray.includes('id="pb-tray"') && tray.includes('data-testid="ioi-tray"') && tray.includes("Preview"));
  const cmd = disabledCommand({ label: "Deploy", reason: 'needs release gate & lease "x"' });
  ok("disabledCommand is visibly disabled and names its reason", cmd.includes("disabled") && cmd.includes('aria-disabled="true"') && cmd.includes("data-ioi-disabled-reason=") && cmd.includes("&amp;") && cmd.includes("Deploy"));
  const pl = proofLink({ href: '/__ioi/run-timeline/r?a=1&b=2', label: "timeline", external: true });
  ok("proofLink escapes href and marks external", pl.includes('href="/__ioi/run-timeline/r?a=1&amp;b=2"') && pl.includes('rel="noopener"') && pl.includes('data-testid="ioi-proof-link"'));
  ok("semanticMask tags the region by id", semanticMask("rows", "<tr></tr>") === '<span data-ioi-sem-mask="rows"><tr></tr></span>');

  // 8. UNIFIED GAP CONTRACT (I-5, Reference-UX Remediation Program v2). One vocabulary estate-wide:
  // every named gap emitted with aria-disabled="true" + a human title MUST also carry the
  // machine-readable data-ioi-disabled-reason (the kit's disabledCommand shape). Checked at the
  // EMISSION POINT (source scan of the serving corpus), not by grepping rendered pages — a gap
  // authored without the machine reason is invisible to the journey verifiers that key on it.
  // The scan is line-based because every ad-hoc emission is a single-line template string; the
  // kit helper (multi-line, already compliant) is asserted separately above via disabledCommand.
  {
    const { readdirSync, statSync } = await import("node:fs");
    const corpus = [join(APP, "scripts", "serve-product-ui.mjs")];
    const walk = (dir) => { for (const e of readdirSync(dir)) { const f = join(dir, e); if (statSync(f).isDirectory()) walk(f); else if (f.endsWith(".mjs") && !/\.test\.mjs$/.test(f)) corpus.push(f); } };
    walk(join(APP, "surfaces"));
    let paired = 0; const unpaired = [];
    for (const f of corpus) {
      const lines = readFileSync(f, "utf8").split("\n");
      lines.forEach((line, i) => {
        if (!line.includes('aria-disabled="true"') || !line.includes("title=")) return;
        if (line.includes("data-ioi-disabled-reason")) paired += 1;
        else unpaired.push(`${f.replace(APP + "/", "")}:${i + 1}`);
      });
    }
    ok("unified gap contract: ZERO titled aria-disabled emissions lack data-ioi-disabled-reason", unpaired.length === 0, unpaired.slice(0, 5).join(" · "));
    // FLOOR (ratchet, verifier-floors pattern): the migrated corpus carries at least this many
    // paired named-gap emissions; a refactor that silently drops gap declarations goes red here.
    // Floor lowered 71→69 by AUT-2 (2026-08-19): the two monitors New-automation emissions became
    // LIVE in-shell create links — a gap became a function, the direction the ratchet exists to allow.
    // 69→68 by DAT-1 (2026-08-19): the sources Syncs tab emission became the LIVE lane link.
    const GAP_EMISSION_FLOOR = 68;
    ok(`unified gap contract: paired emission count >= floor (${GAP_EMISSION_FLOOR})`, paired >= GAP_EMISSION_FLOOR, `paired=${paired}`);
  }

  // 9. I-4 SPLASH-LANDING GRAMMAR (remediation v2, W3) — the one parameterized landing template
  // the census-proven splash instances (module/logic/contour/slate + the ported landings) share.
  // Contract: landmarks render; every gap control carries the unified contract; embed honors
  // native_single_rail (no global rail); rows are caller-owned truth (never invented here).
  {
    const { renderSplashLanding } = await import("./splash-landing-grammar.mjs");
    const fix = renderSplashLanding({
      slug: "x-fixture", title: "Fixture App", appTileUri: "data:,", newLabel: "New thing",
      newGapReason: "no authoring plane exists (typed absence)",
      heroTitle: "Fixture hero", heroDesc: "Fixture description.",
      columns: ["Files", "Creator", "Last viewed"],
      rowsHtml: "", emptyCopy: "No records — renders real truth, never fabricates rows.",
      footHtml: "evidence: fixture",
    });
    ok("I-4: landmarks render (title · store · New · Help · Recents · Favorites · columns · honest empty)", ["Fixture App", "New thing", "Help", "Recents", "Favorites", "Files", "never fabricates rows"].every((m) => fix.includes(m)));
    ok("I-4: every gap control carries the UNIFIED contract (aria-disabled + title + data-ioi-disabled-reason)", (fix.match(/aria-disabled="true"/g) || []).length >= 4 && (fix.match(/aria-disabled="true"/g) || []).length === (fix.match(/data-ioi-disabled-reason=/g) || []).length);
    const emb = renderSplashLanding({ slug: "x", title: "E", appTileUri: "data:,", newLabel: "N", newGapReason: "r", heroTitle: "h", heroDesc: "d", columns: ["a"], rowsHtml: "", emptyCopy: "e", embed: true });
    ok("I-4: embed honors native_single_rail (no ported global rail)", !emb.includes("og-grail"));
    const live = renderSplashLanding({ slug: "x", title: "L", appTileUri: "data:,", newLabel: "New", newHref: "/__ioi/x?new=1", heroTitle: "h", heroDesc: "d", columns: ["a"], rowsHtml: "", emptyCopy: "e" });
    ok("I-4: a live New entry is an anchor, not a gap", live.includes(`href="/__ioi/x?new=1"`) && !live.includes(`data-ioi-disabled-reason="no authoring`));
  }

}

run().then(() => {
  const fails = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${results.length - fails.length}/${results.length} passed`);
  if (fails.length) process.exit(1);
  console.log("surface-modules: OK");
}).catch((e) => {
  console.error("verifier crashed:", e);
  process.exit(1);
});

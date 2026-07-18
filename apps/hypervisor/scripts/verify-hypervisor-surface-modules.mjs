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

const MISSION_COLLECTIONS = {
  "/v1/hypervisor/outcome-rooms": "outcome_rooms",
  "/v1/hypervisor/room-participation-requests": "participation_requests",
  "/v1/hypervisor/room-participant-leases": "participant_leases",
  "/v1/hypervisor/work-frontier-items": "frontier_items",
  "/v1/hypervisor/work-claim-leases": "work_claims",
  "/v1/hypervisor/resource-offers": "resource_offers",
  "/v1/hypervisor/capability-offers": "capability_offers",
  "/v1/hypervisor/work-eligibility-matches": "eligibility_match_receipts",
  "/v1/hypervisor/attempts": "attempts",
  "/v1/hypervisor/findings": "findings",
  "/v1/hypervisor/work-results": "work_results",
  "/v1/hypervisor/verifier-challenges": "verifier_challenges",
  "/v1/hypervisor/goal-runs": "goal_runs",
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
  ok("dead daemon loads to honest empty lists", Object.values(model).every((v) => Array.isArray(v) && v.length === 0), `${Object.keys(model).length} list keys`);
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
    Object.values(missionsModel).every((entry) => entry.ok === false && entry.rows.length === 0)
      && missionsHtml.includes('data-missions-work-graph="hosted"')
      && missionsHtml.includes("Counts for this plane are not treated as zero")
      && !/<form\b/i.test(missionsHtml));
  const fixtureRoom = {
    outcome_room_id: "outcome-room://or_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    objective: "Partial-outage mission",
    status: "open",
    room_mode: "hosted",
  };
  const partialCtx = {
    ...missionsCtx,
    url: new URL(`http://x/__ioi/missions?room=${encodeURIComponent(fixtureRoom.outcome_room_id)}`),
    fetch: missionsFixtureFetch({
      "/v1/hypervisor/outcome-rooms": { body: { outcome_rooms: [fixtureRoom] } },
      "/v1/hypervisor/room-participant-leases": { status: 503, body: { error: { code: "participants_unavailable" } } },
      "/v1/hypervisor/work-frontier-items": { status: 503, body: { error: { code: "frontier_unavailable" } } },
      "/v1/hypervisor/work-claim-leases": { status: 503, body: { error: { code: "claims_unavailable" } } },
      "/v1/hypervisor/resource-offers": { status: 503, body: { error: { code: "offers_unavailable" } } },
      "/v1/hypervisor/capability-offers": { status: 503, body: { error: { code: "capabilities_unavailable" } } },
      "/v1/hypervisor/work-eligibility-matches": { status: 503, body: { error: { code: "matches_unavailable" } } },
      "/v1/hypervisor/verifier-challenges": { status: 503, body: { error: { code: "challenges_unavailable" } } },
    }),
  };
  const partialModel = await missions.load(partialCtx);
  const partialHtml = missions.render(partialModel, partialCtx);
  ok("missions: partial child-plane outage renders unknown at every dependent room/list/supply metric",
    partialHtml.includes('data-missions-frontier="unknown"')
      && partialHtml.includes('data-missions-live-claims="unknown"')
      && partialHtml.includes('data-missions-unresolved-challenges="unknown"')
      && partialHtml.includes("<b>—</b> work <b>—</b> claims <em>— blockers</em>")
      && partialHtml.includes('data-missions-metric="active-participants" data-value="unknown"')
      && partialHtml.includes('data-missions-metric="frontier-items" data-value="unknown"')
      && partialHtml.includes('data-missions-metric="live-claims" data-value="unknown"')
      && partialHtml.includes('data-missions-metric="challenge-blockers" data-value="unknown"')
      && partialHtml.includes('data-missions-metric="resource-offers" data-value="unknown"')
      && partialHtml.includes('data-missions-metric="capability-offers" data-value="unknown"')
      && partialHtml.includes('data-missions-metric="receipted-matches" data-value="unknown"'));
  const malformedCtx = {
    ...missionsCtx,
    fetch: missionsFixtureFetch({
      "/v1/hypervisor/outcome-rooms": { body: { outcome_rooms: { not: "an array" } } },
    }),
  };
  const malformedModel = await missions.load(malformedCtx);
  const malformedHtml = missions.render(malformedModel, malformedCtx);
  const malformedRoomRowModel = await missions.load({
    ...missionsCtx,
    fetch: missionsFixtureFetch({
      "/v1/hypervisor/outcome-rooms": { body: { outcome_rooms: [{}] } },
    }),
  });
  const malformedRoomRowHtml = missions.render(malformedRoomRowModel, missionsCtx);
  const mixedRoomRowModel = await missions.load({
    ...missionsCtx,
    fetch: missionsFixtureFetch({
      "/v1/hypervisor/outcome-rooms": { body: { outcome_rooms: [fixtureRoom, {}] } },
    }),
  });
  const mixedRoomRowHtml = missions.render(mixedRoomRowModel, missionsCtx);
  const malformedGoalRunModel = await missions.load({
    ...missionsCtx,
    fetch: missionsFixtureFetch({
      "/v1/hypervisor/goal-runs": { body: { goal_runs: [null] } },
    }),
  });
  const malformedGoalRunHtml = missions.render(malformedGoalRunModel, missionsCtx);
  const malformedOperationRunModel = await missions.load({
    ...missionsCtx,
    fetch: missionsFixtureFetch({
      "/v1/hypervisor/operations": { body: { runs: { total: 1, recent: [null], failures: [] } } },
    }),
  });
  const malformedOperationRunHtml = missions.render(malformedOperationRunModel, missionsCtx);
  ok("missions: malformed collection and exact invalid-row probes fail closed as plane_payload_invalid without crashing or invented rows",
    malformedModel.rooms.ok === false && malformedModel.rooms.status === 200
      && malformedModel.rooms.code === "plane_payload_invalid"
      && malformedHtml.includes('data-missions-rooms="unknown"')
      && malformedHtml.includes("Room list unavailable")
      && !malformedHtml.includes("No rooms in this view")
      && malformedRoomRowModel.rooms.ok === false
      && malformedRoomRowModel.rooms.code === "plane_payload_invalid"
      && malformedRoomRowHtml.includes('data-missions-rooms="unknown"')
      && !malformedRoomRowHtml.includes("Untitled mission")
      && mixedRoomRowModel.rooms.ok === false
      && mixedRoomRowModel.rooms.rows.length === 0
      && mixedRoomRowModel.rooms.code === "plane_payload_invalid"
      && !mixedRoomRowHtml.includes(fixtureRoom.objective)
      && malformedGoalRunModel.goalRuns.ok === false
      && malformedGoalRunModel.goalRuns.code === "plane_payload_invalid"
      && malformedGoalRunHtml.includes("Mission incidents</b> unavailable")
      && malformedOperationRunModel.operations.ok === false
      && malformedOperationRunModel.operations.code === "plane_payload_invalid"
      && malformedOperationRunHtml.includes("Operations run queue</b> unavailable"));
  const timeoutStartedAt = Date.now();
  const timeoutModel = await missions.load({
    ...missionsCtx,
    planeTimeoutMs: 25,
    fetch: async (rawUrl, init) => {
      if (new URL(rawUrl).pathname === "/v1/hypervisor/work-frontier-items") {
        return new Promise(() => {
          init?.signal?.addEventListener("abort", () => {}, { once: true });
        });
      }
      return missionsFixtureFetch()(rawUrl, init);
    },
  });
  ok("missions: a never-resolving child plane is bounded and becomes an honest timeout, not a hung route",
    Date.now() - timeoutStartedAt < 500
      && timeoutModel.frontier.ok === false
      && timeoutModel.frontier.code === "plane_timeout",
    `${Date.now() - timeoutStartedAt}ms/${timeoutModel.frontier.code}`);
  const bodyTimeoutStartedAt = Date.now();
  const bodyTimeoutModel = await missions.load({
    ...missionsCtx,
    planeTimeoutMs: 25,
    fetch: async (rawUrl, init) => {
      if (new URL(rawUrl).pathname === "/v1/hypervisor/work-frontier-items") {
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
      && bodyTimeoutModel.frontier.ok === false
      && bodyTimeoutModel.frontier.code === "plane_timeout",
    `${Date.now() - bodyTimeoutStartedAt}ms/${bodyTimeoutModel.frontier.code}`);
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
  const validRoomRef = fixtureRoom.outcome_room_id;
  const validRequestRef = "participation-request://rpr_ab";
  const validParticipantRef = "participant-lease://rpl_ab";
  const validFrontierRef = `frontier://wfi_${"1".repeat(64)}`;
  const validClaimRef = `work-claim://wcl_${"2".repeat(64)}`;
  const validGoalRunId = `gr_${"6".repeat(32)}`;
  const validGoalRef = `goal://${validGoalRunId}`;
  const validResultRef = "work-result://wr_ab";
  const validAttemptRef = `attempt://att_${"3".repeat(64)}`;
  const validFindingRef = `finding://fnd_${"4".repeat(64)}`;
  const validChallengeRef = `verifier-challenge://vc_${"5".repeat(64)}`;
  const validRoom = {
    ...fixtureRoom,
    participation_request_refs: [validRequestRef],
    participant_lease_refs: [validParticipantRef],
    released_participant_lease_refs: [],
    frontier_item_refs: [validFrontierRef],
    resource_offer_refs: [],
    capability_offer_refs: [],
    attempt_refs: [validAttemptRef],
    finding_refs: [validFindingRef],
    verifier_challenge_refs: [validChallengeRef],
    member_goal_run_refs: [validGoalRef],
  };
  const validGraphModel = await missions.load({
    ...missionsCtx,
    fetch: missionsFixtureFetch({
      "/v1/hypervisor/outcome-rooms": { body: { outcome_rooms: [validRoom] } },
      "/v1/hypervisor/room-participation-requests": {
        body: {
          participation_requests: [{
            participation_request_id: validRequestRef,
            outcome_room_ref: validRoomRef,
            requested_by_ref: "worker://valid-operator",
            participant_lease_ref: validParticipantRef,
            status: "admitted",
          }],
        },
      },
      "/v1/hypervisor/room-participant-leases": {
        body: {
          participant_leases: [{
            participant_lease_id: validParticipantRef,
            outcome_room_ref: validRoomRef,
            participant_ref: "worker://valid-operator",
            join_request_ref: validRequestRef,
            current_claim_ref: validClaimRef,
            status: "active",
          }],
        },
      },
      "/v1/hypervisor/work-frontier-items": {
        body: {
          frontier_items: [{
            frontier_item_id: validFrontierRef,
            outcome_room_ref: validRoomRef,
            claim_refs: [validClaimRef],
            active_claim_refs: [validClaimRef],
            status: "claimed",
          }],
        },
      },
      "/v1/hypervisor/work-claim-leases": {
        body: {
          work_claims: [{
            work_claim_id: validClaimRef,
            outcome_room_ref: validRoomRef,
            frontier_item_ref: validFrontierRef,
            claimant_ref: validParticipantRef,
            status: "active",
          }],
        },
      },
      "/v1/hypervisor/goal-runs": {
        body: {
          goal_runs: [{
            goal_run_id: validGoalRunId,
            goal_ref: validGoalRef,
            outcome_room_ref: validRoomRef,
            status: "active",
          }],
        },
      },
      "/v1/hypervisor/work-results": {
        body: {
          work_results: [{
            work_result_id: validResultRef,
            goal_ref: validGoalRef,
            goal_run_ref: validGoalRef,
            outcome_room_ref: validRoomRef,
            challenge_refs: [validChallengeRef],
            status: "completed",
          }],
        },
      },
      "/v1/hypervisor/attempts": {
        body: {
          attempts: [{
            attempt_id: validAttemptRef,
            outcome_room_ref: validRoomRef,
            frontier_item_ref: validFrontierRef,
            work_claim_ref: validClaimRef,
            participant_ref: validParticipantRef,
            goal_run_ref: validGoalRef,
            work_result_ref: validResultRef,
            status: "admitted",
          }],
        },
      },
      "/v1/hypervisor/findings": {
        body: {
          findings: [{
            finding_id: validFindingRef,
            outcome_room_ref: validRoomRef,
            attempt_ref: validAttemptRef,
            work_result_ref: validResultRef,
            participant_ref: validParticipantRef,
            supersedes_ref: null,
            status: "proposed",
          }],
        },
      },
      "/v1/hypervisor/verifier-challenges": {
        body: {
          verifier_challenges: [{
            verifier_challenge_id: validChallengeRef,
            outcome_room_ref: validRoomRef,
            challenger_ref: validParticipantRef,
            challenged_ref: validFindingRef,
            affected_attempt_refs: [validAttemptRef],
            status: "proposed",
          }],
        },
      },
    }),
  });
  const validGraphHtml = missions.render(validGraphModel, {
    ...missionsCtx,
    url: new URL(`http://x/__ioi/missions?room=${encodeURIComponent(validRoomRef)}`),
  });
  ok("missions: a complete owner-plane-consistent graph remains fully inspectable",
    ["rooms", "requests", "participants", "frontier", "claims", "attempts", "findings", "results", "challenges", "goalRuns"]
      .every((name) => validGraphModel[name].ok)
      && [validFrontierRef, validClaimRef, validAttemptRef, validFindingRef, validChallengeRef]
        .every((reference) => validGraphHtml.includes(reference)));
  const orphanRequestRef = "participation-request://rpr_cd";
  const orphanBacklinkModel = await missions.load({
    ...missionsCtx,
    fetch: missionsFixtureFetch({
      "/v1/hypervisor/outcome-rooms": {
        body: {
          outcome_rooms: [{
            ...fixtureRoom,
            participation_request_refs: [],
            participant_lease_refs: [],
            released_participant_lease_refs: [],
            frontier_item_refs: [],
            resource_offer_refs: [],
            capability_offer_refs: [],
            attempt_refs: [],
            finding_refs: [],
            verifier_challenge_refs: [],
            member_goal_run_refs: [],
          }],
        },
      },
      "/v1/hypervisor/room-participation-requests": {
        body: {
          participation_requests: [{
            participation_request_id: orphanRequestRef,
            outcome_room_ref: validRoomRef,
            requested_by_ref: "worker://orphan",
            participant_lease_ref: null,
            status: "submitted",
          }],
        },
      },
    }),
  });
  ok("missions: a child record absent from its room-owned backlink is not presented as admitted graph truth",
    orphanBacklinkModel.requests.ok === false
      && orphanBacklinkModel.requests.code === "plane_payload_invalid"
      && orphanBacklinkModel.requests.rows.length === 0);
  const danglingFrontierRef = `frontier://wfi_${"9".repeat(64)}`;
  const danglingOwnerBacklinkModel = await missions.load({
    ...missionsCtx,
    fetch: missionsFixtureFetch({
      "/v1/hypervisor/outcome-rooms": {
        body: {
          outcome_rooms: [{
            ...fixtureRoom,
            participation_request_refs: [],
            participant_lease_refs: [],
            released_participant_lease_refs: [],
            frontier_item_refs: [danglingFrontierRef],
            resource_offer_refs: [],
            capability_offer_refs: [],
            attempt_refs: [],
            finding_refs: [],
            verifier_challenge_refs: [],
            member_goal_run_refs: [],
          }],
        },
      },
      "/v1/hypervisor/work-frontier-items": { body: { frontier_items: [] } },
    }),
  });
  ok("missions: a room-owned backlink absent from its child plane makes that child plane unknown, not zero",
    danglingOwnerBacklinkModel.rooms.ok
      && danglingOwnerBacklinkModel.frontier.ok === false
      && danglingOwnerBacklinkModel.frontier.code === "plane_payload_invalid"
      && danglingOwnerBacklinkModel.frontier.rows.length === 0);
  const shapedAttemptRef = `attempt://att_${"a".repeat(64)}`;
  const unresolvedAttemptModel = await missions.load({
    ...missionsCtx,
    fetch: missionsFixtureFetch({
      "/v1/hypervisor/outcome-rooms": { body: { outcome_rooms: [fixtureRoom] } },
      "/v1/hypervisor/attempts": {
        body: {
          attempts: [{
            attempt_id: shapedAttemptRef,
            outcome_room_ref: fixtureRoom.outcome_room_id,
            frontier_item_ref: `frontier://wfi_${"b".repeat(64)}`,
            work_claim_ref: `work-claim://wcl_${"c".repeat(64)}`,
            participant_ref: "participant-lease://rpl_ab",
            goal_run_ref: "goal://missing-run",
            work_result_ref: null,
            status: "draft",
          }],
        },
      },
    }),
  });
  const unresolvedAttemptHtml = missions.render(unresolvedAttemptModel, missionsCtx);
  ok("missions: a shaped but non-resolving Attempt invalidates the whole Attempt plane",
    unresolvedAttemptModel.attempts.ok === false
      && unresolvedAttemptModel.attempts.code === "plane_payload_invalid"
      && unresolvedAttemptModel.attempts.rows.length === 0
      && !unresolvedAttemptHtml.includes(shapedAttemptRef));
  const roomB = {
    outcome_room_id: "outcome-room://or_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    objective: "Cross-room sentinel",
    status: "open",
    room_mode: "hosted",
    participation_request_refs: [],
    participant_lease_refs: [],
    released_participant_lease_refs: [],
    frontier_item_refs: [`frontier://wfi_${"e".repeat(64)}`],
    resource_offer_refs: [],
    capability_offer_refs: [],
    attempt_refs: [],
    finding_refs: [],
    verifier_challenge_refs: [],
    member_goal_run_refs: [],
  };
  const requestA = {
    participation_request_id: "participation-request://rpr_ab",
    outcome_room_ref: fixtureRoom.outcome_room_id,
    requested_by_ref: "worker://claimant",
    participant_lease_ref: "participant-lease://rpl_ab",
    status: "admitted",
  };
  const crossRoomClaimRef = `work-claim://wcl_${"d".repeat(64)}`;
  const participantA = {
    participant_lease_id: "participant-lease://rpl_ab",
    outcome_room_ref: fixtureRoom.outcome_room_id,
    participant_ref: requestA.requested_by_ref,
    join_request_ref: requestA.participation_request_id,
    current_claim_ref: crossRoomClaimRef,
    status: "active",
  };
  const roomA = {
    ...fixtureRoom,
    participation_request_refs: [requestA.participation_request_id],
    participant_lease_refs: [participantA.participant_lease_id],
    released_participant_lease_refs: [],
    frontier_item_refs: [],
    resource_offer_refs: [],
    capability_offer_refs: [],
    attempt_refs: [],
    finding_refs: [],
    verifier_challenge_refs: [],
    member_goal_run_refs: [],
  };
  const crossRoomModel = await missions.load({
    ...missionsCtx,
    fetch: missionsFixtureFetch({
      "/v1/hypervisor/outcome-rooms": { body: { outcome_rooms: [roomA, roomB] } },
      "/v1/hypervisor/room-participation-requests": { body: { participation_requests: [requestA] } },
      "/v1/hypervisor/room-participant-leases": { body: { participant_leases: [participantA] } },
      "/v1/hypervisor/work-frontier-items": {
        body: {
          frontier_items: [{
            frontier_item_id: `frontier://wfi_${"e".repeat(64)}`,
            outcome_room_ref: roomB.outcome_room_id,
            claim_refs: [crossRoomClaimRef],
            active_claim_refs: [crossRoomClaimRef],
            status: "claimed",
          }],
        },
      },
      "/v1/hypervisor/work-claim-leases": {
        body: {
          work_claims: [{
            work_claim_id: crossRoomClaimRef,
            outcome_room_ref: fixtureRoom.outcome_room_id,
            frontier_item_ref: `frontier://wfi_${"e".repeat(64)}`,
            claimant_ref: participantA.participant_lease_id,
            status: "active",
          }],
        },
      },
    }),
  });
  const crossRoomHtml = missions.render(crossRoomModel, missionsCtx);
  ok("missions: a cross-room Claim invalidates the whole Claim plane without partial rows",
    crossRoomModel.claims.ok === false
      && crossRoomModel.claims.code === "plane_payload_invalid"
      && crossRoomModel.claims.rows.length === 0
      && !crossRoomHtml.includes(crossRoomClaimRef));
  const cappedGoalRuns = Array.from({ length: 60 }, (_, index) => ({
    goal_run_id: `goal-run-${index}`,
    normalized_goal: `Goal ${index}`,
    status: "blocked",
    blockers: [{ reason_code: `blocked-${index}` }],
  }));
  const cappedCtx = {
    ...missionsCtx,
    fetch: missionsFixtureFetch({
      "/v1/hypervisor/goal-runs": { body: { goal_runs: cappedGoalRuns } },
    }),
  };
  const cappedHtml = missions.render(await missions.load(cappedCtx), cappedCtx);
  ok("missions: blocker cap is deterministic and disclosed as showing first 50 of 60",
    cappedHtml.includes("showing first 50 of 60")
      && cappedHtml.includes("/__ioi/run-timeline/goal-run/goal-run-49")
      && !cappedHtml.includes("/__ioi/run-timeline/goal-run/goal-run-50"));
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

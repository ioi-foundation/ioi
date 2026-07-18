// Missions — operational read model over the hosted OutcomeRoom graph.
//
// This surface intentionally declares no actions. It projects the daemon-owned room, frontier,
// participation, offer/match, Attempt/Finding, WorkResult, and VerifierChallenge records without
// minting acceptance, verdict, settlement, execution, or federation authority.
import { ioiGlobalRailHtml, IOI_GRAIL_CSS } from "../chrome.mjs";
import { canonicalTimelineRef, escHtml, proofLink, selectionQuery } from "../kit.mjs";
import { readJsonWithDeadline } from "../plane-read.mjs";

const ROUTE = "/__ioi/missions";
const DEFAULT_PLANE_TIMEOUT_MS = 3_000;
const UNRESOLVED_CHALLENGE = new Set([
  "proposed", "admitted", "investigating", "upheld", "rule_changed", "reverifying",
]);
const LIVE_CLAIM = new Set(["active", "waiting"]);

export const MISSIONS_APP_ICON_URI = `data:image/svg+xml,${encodeURIComponent(
  '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="2.4"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3"/></svg>',
)}`;

export const meta = {
  slug: "missions",
  route: ROUTE,
  verifier: "scripts/verify-hypervisor-app-parity-missions.mjs",
  certification: "n/a",
};

const unavailablePlane = (status, code) => ({
  ok: false,
  status,
  code,
  rows: [],
  payload: null,
});

const isRecord = (value) => !!value && typeof value === "object" && !Array.isArray(value);
const nonEmptyString = (value) => typeof value === "string" && value.trim().length > 0;
const fieldMatches = (record, field, pattern) => nonEmptyString(record[field]) && pattern.test(record[field]);
const optionalFieldMatches = (record, field, pattern) => record[field] == null || fieldMatches(record, field, pattern);
const everyArrayEntry = (values, validator) => Array.isArray(values) && values.every(validator);
const optionalRefArray = (record, field, pattern) => record[field] === undefined
  || everyArrayEntry(record[field], (reference) => nonEmptyString(reference) && pattern.test(reference));

const ROOM_REF = /^outcome-room:\/\/or_[0-9a-f]+$/;
const REQUEST_REF = /^participation-request:\/\/rpr_[0-9a-f]+$/;
const PARTICIPANT_REF = /^participant-lease:\/\/rpl_[0-9a-f]+$/;
const FRONTIER_REF = /^frontier:\/\/wfi_[0-9a-f]{64}$/;
const CLAIM_REF = /^work-claim:\/\/wcl_[0-9a-f]{64}$/;
const RESOURCE_OFFER_REF = /^resource-offer:\/\/rof_[0-9a-f]{64}$/;
const CAPABILITY_OFFER_REF = /^capability-offer:\/\/cof_[0-9a-f]{64}$/;
const MATCH_RECEIPT_REF = /^receipt:\/\/wem_[0-9a-f]{64}$/;
const ATTEMPT_REF = /^attempt:\/\/att_[0-9a-f]{64}$/;
const FINDING_REF = /^finding:\/\/fnd_[0-9a-f]{64}$/;
const WORK_RESULT_REF = /^work-result:\/\/wr_[0-9a-f]+$/;
const CHALLENGE_REF = /^verifier-challenge:\/\/vc_[0-9a-f]{64}$/;
const GOAL_REF = /^goal:\/\/(?!.*\.\.)[^\s?#]{1,160}$/;
const GOAL_RUN_ID = /^[A-Za-z0-9_-]{1,160}$/;

const roomBound = (record) => fieldMatches(record, "outcome_room_ref", ROOM_REF);
const hasStatus = (record) => nonEmptyString(record.status);
const rowValidators = {
  outcome_rooms: (row) => isRecord(row)
    && fieldMatches(row, "outcome_room_id", ROOM_REF)
    && hasStatus(row)
    && (nonEmptyString(row.objective) || nonEmptyString(row.objective_ref))
    && optionalRefArray(row, "participation_request_refs", REQUEST_REF)
    && optionalRefArray(row, "participant_lease_refs", PARTICIPANT_REF)
    && optionalRefArray(row, "released_participant_lease_refs", PARTICIPANT_REF)
    && optionalRefArray(row, "frontier_item_refs", FRONTIER_REF)
    && optionalRefArray(row, "resource_offer_refs", RESOURCE_OFFER_REF)
    && optionalRefArray(row, "capability_offer_refs", CAPABILITY_OFFER_REF)
    && optionalRefArray(row, "attempt_refs", ATTEMPT_REF)
    && optionalRefArray(row, "finding_refs", FINDING_REF)
    && optionalRefArray(row, "verifier_challenge_refs", CHALLENGE_REF)
    && optionalRefArray(row, "member_goal_run_refs", GOAL_REF)
    && (!Array.isArray(row.released_participant_lease_refs)
      || row.released_participant_lease_refs.every((reference) => row.participant_lease_refs?.includes(reference))),
  participation_requests: (row) => isRecord(row)
    && fieldMatches(row, "participation_request_id", REQUEST_REF)
    && roomBound(row)
    && nonEmptyString(row.requested_by_ref)
    && optionalFieldMatches(row, "participant_lease_ref", PARTICIPANT_REF)
    && hasStatus(row),
  participant_leases: (row) => isRecord(row)
    && fieldMatches(row, "participant_lease_id", PARTICIPANT_REF)
    && roomBound(row)
    && nonEmptyString(row.participant_ref)
    && fieldMatches(row, "join_request_ref", REQUEST_REF)
    && optionalFieldMatches(row, "current_claim_ref", CLAIM_REF)
    && hasStatus(row),
  frontier_items: (row) => isRecord(row)
    && fieldMatches(row, "frontier_item_id", FRONTIER_REF)
    && roomBound(row)
    && optionalRefArray(row, "claim_refs", CLAIM_REF)
    && optionalRefArray(row, "active_claim_refs", CLAIM_REF)
    && (!Array.isArray(row.active_claim_refs)
      || row.active_claim_refs.every((reference) => row.claim_refs?.includes(reference)))
    && hasStatus(row),
  work_claims: (row) => isRecord(row)
    && fieldMatches(row, "work_claim_id", CLAIM_REF)
    && fieldMatches(row, "frontier_item_ref", FRONTIER_REF)
    && fieldMatches(row, "claimant_ref", PARTICIPANT_REF)
    && roomBound(row)
    && optionalFieldMatches(row, "eligibility_match_receipt_ref", MATCH_RECEIPT_REF)
    && hasStatus(row),
  resource_offers: (row) => isRecord(row)
    && fieldMatches(row, "resource_offer_id", RESOURCE_OFFER_REF)
    && fieldMatches(row, "provider_participant_lease_ref", PARTICIPANT_REF)
    && roomBound(row)
    && hasStatus(row),
  capability_offers: (row) => isRecord(row)
    && fieldMatches(row, "capability_offer_id", CAPABILITY_OFFER_REF)
    && fieldMatches(row, "provider_participant_lease_ref", PARTICIPANT_REF)
    && roomBound(row)
    && hasStatus(row),
  eligibility_match_receipts: (row) => isRecord(row)
    && fieldMatches(row, "receipt_id", MATCH_RECEIPT_REF)
    && row.receipt_ref === row.receipt_id
    && row.receipt_type === "WorkEligibilityMatchReceipt"
    && isRecord(row.bound_facts)
    && fieldMatches(row.bound_facts, "outcome_room_ref", ROOM_REF)
    && fieldMatches(row.bound_facts, "frontier_item_ref", FRONTIER_REF)
    && fieldMatches(row.bound_facts, "participant_ref", PARTICIPANT_REF),
  attempts: (row) => isRecord(row)
    && fieldMatches(row, "attempt_id", ATTEMPT_REF)
    && fieldMatches(row, "frontier_item_ref", FRONTIER_REF)
    && fieldMatches(row, "work_claim_ref", CLAIM_REF)
    && fieldMatches(row, "participant_ref", PARTICIPANT_REF)
    && roomBound(row)
    && fieldMatches(row, "goal_run_ref", GOAL_REF)
    && optionalFieldMatches(row, "work_result_ref", WORK_RESULT_REF)
    && hasStatus(row),
  findings: (row) => isRecord(row)
    && fieldMatches(row, "finding_id", FINDING_REF)
    && fieldMatches(row, "attempt_ref", ATTEMPT_REF)
    && fieldMatches(row, "work_result_ref", WORK_RESULT_REF)
    && fieldMatches(row, "participant_ref", PARTICIPANT_REF)
    && roomBound(row)
    && optionalFieldMatches(row, "supersedes_ref", FINDING_REF)
    && hasStatus(row),
  work_results: (row) => isRecord(row)
    && fieldMatches(row, "work_result_id", WORK_RESULT_REF)
    && optionalFieldMatches(row, "outcome_room_ref", ROOM_REF)
    && fieldMatches(row, "goal_ref", GOAL_REF)
    && optionalFieldMatches(row, "goal_run_ref", GOAL_REF)
    && optionalRefArray(row, "challenge_refs", CHALLENGE_REF)
    && hasStatus(row),
  verifier_challenges: (row) => isRecord(row)
    && fieldMatches(row, "verifier_challenge_id", CHALLENGE_REF)
    && roomBound(row)
    && fieldMatches(row, "challenger_ref", PARTICIPANT_REF)
    && (fieldMatches(row, "challenged_ref", ATTEMPT_REF) || fieldMatches(row, "challenged_ref", FINDING_REF))
    && row.affected_attempt_refs?.length > 0
    && everyArrayEntry(row.affected_attempt_refs, (reference) => nonEmptyString(reference) && ATTEMPT_REF.test(reference))
    && hasStatus(row),
  goal_runs: (row) => isRecord(row)
    && fieldMatches(row, "goal_run_id", GOAL_RUN_ID)
    && optionalFieldMatches(row, "goal_ref", GOAL_REF)
    && optionalFieldMatches(row, "outcome_room_ref", ROOM_REF)
    && (!row.outcome_room_ref || fieldMatches(row, "goal_ref", GOAL_REF))
    && hasStatus(row)
    && (row.blockers === undefined || everyArrayEntry(row.blockers, (blocker) => isRecord(blocker) && nonEmptyString(blocker.reason_code))),
};

const operationRunValid = (row) => isRecord(row)
  && nonEmptyString(row.execution_id)
  && hasStatus(row)
  && (row.timeline_ref == null || canonicalTimelineRef(row.timeline_ref) !== "");

async function readCollection(fetchImpl, daemon, path, key, validateRow, timeoutMs) {
  try {
    const { response, payload } = await readJsonWithDeadline(fetchImpl, `${daemon}${path}`, timeoutMs);
    if (!response.ok) {
      return unavailablePlane(response.status, payload?.error?.code || "plane_unavailable");
    }
    if (!Array.isArray(payload?.[key]) || !payload[key].every(validateRow)) {
      return unavailablePlane(response.status, "plane_payload_invalid");
    }
    return { ok: true, status: response.status, code: "", rows: payload[key], payload };
  } catch (error) {
    return unavailablePlane(0, error?.code === "plane_timeout" ? "plane_timeout" : "daemon_unavailable");
  }
}

async function readOperations(fetchImpl, daemon, timeoutMs) {
  try {
    const { response, payload } = await readJsonWithDeadline(fetchImpl, `${daemon}/v1/hypervisor/operations`, timeoutMs);
    if (!response.ok) {
      return unavailablePlane(response.status, payload?.error?.code || "plane_unavailable");
    }
    if (!payload || typeof payload !== "object" || Array.isArray(payload)
      || !payload.runs || typeof payload.runs !== "object" || Array.isArray(payload.runs)
      || !Array.isArray(payload.runs.recent) || !Array.isArray(payload.runs.failures)
      || !payload.runs.recent.every(operationRunValid) || !payload.runs.failures.every(operationRunValid)
      || !Number.isFinite(payload.runs.total)) {
      return unavailablePlane(response.status, "plane_payload_invalid");
    }
    return { ok: true, status: response.status, code: "", rows: [], payload };
  } catch (error) {
    return unavailablePlane(0, error?.code === "plane_timeout" ? "plane_timeout" : "daemon_unavailable");
  }
}

const indexBy = (plane, field) => new Map(plane.rows.map((row) => [row[field], row]));
const hasUniqueKeys = (plane, field) => new Set(plane.rows.map((row) => row[field])).size === plane.rows.length;
const optionalRef = (record, field) => record[field] == null ? "" : String(record[field]);
const sameRoom = (record, roomReference) => roomRef(record) === roomReference;
const listIncludes = (record, field, reference) => Array.isArray(record?.[field])
  && record[field].includes(reference);

function validateModelRelationships(model) {
  const indexes = {
    rooms: indexBy(model.rooms, "outcome_room_id"),
    requests: indexBy(model.requests, "participation_request_id"),
    participants: indexBy(model.participants, "participant_lease_id"),
    frontier: indexBy(model.frontier, "frontier_item_id"),
    claims: indexBy(model.claims, "work_claim_id"),
    resourceOffers: indexBy(model.resourceOffers, "resource_offer_id"),
    capabilityOffers: indexBy(model.capabilityOffers, "capability_offer_id"),
    matches: indexBy(model.matches, "receipt_id"),
    attempts: indexBy(model.attempts, "attempt_id"),
    findings: indexBy(model.findings, "finding_id"),
    results: indexBy(model.results, "work_result_id"),
    challenges: indexBy(model.challenges, "verifier_challenge_id"),
    goalRuns: new Map(model.goalRuns.rows.filter((row) => row.goal_ref).map((row) => [row.goal_ref, row])),
  };
  const roomOwns = (roomReference, field, reference) => {
    const room = indexes.rooms.get(roomReference);
    return !!room && listIncludes(room, field, reference);
  };
  const roomBacklinksResolve = (field, index) => model.rooms.rows.every((room) =>
    !Array.isArray(room[field]) || room[field].every((reference) => index.has(reference)));
  const recordBacklinksResolve = (records, field, index) => records.every((record) =>
    record[field] == null || (Array.isArray(record[field])
      ? record[field].every((reference) => index.has(reference))
      : index.has(record[field])));
  const checks = [
    ["rooms", [], () => hasUniqueKeys(model.rooms, "outcome_room_id")],
    ["requests", ["rooms", "participants"], () => hasUniqueKeys(model.requests, "participation_request_id")
      && roomBacklinksResolve("participation_request_refs", indexes.requests)
      && model.requests.rows.every((request) => {
        const requestRef = request.participation_request_id;
        const leaseRef = optionalRef(request, "participant_lease_ref");
        if (!roomOwns(request.outcome_room_ref, "participation_request_refs", requestRef)) return false;
        if (!leaseRef) return request.status !== "admitted";
        const lease = indexes.participants.get(leaseRef);
        return PARTICIPANT_REF.test(leaseRef)
          && !!lease
          && sameRoom(lease, request.outcome_room_ref)
          && lease.join_request_ref === requestRef
          && lease.participant_ref === request.requested_by_ref;
      })],
    ["participants", ["rooms", "requests"], () => hasUniqueKeys(model.participants, "participant_lease_id")
      && roomBacklinksResolve("participant_lease_refs", indexes.participants)
      && roomBacklinksResolve("released_participant_lease_refs", indexes.participants)
      && model.participants.rows.every((participant) => {
        const request = indexes.requests.get(participant.join_request_ref);
        return roomOwns(participant.outcome_room_ref, "participant_lease_refs", participant.participant_lease_id)
          && !!request
          && sameRoom(request, participant.outcome_room_ref)
          && request.requested_by_ref === participant.participant_ref
          && request.participant_lease_ref === participant.participant_lease_id;
      })],
    ["frontier", ["rooms"], () => hasUniqueKeys(model.frontier, "frontier_item_id")
      && roomBacklinksResolve("frontier_item_refs", indexes.frontier)
      && model.frontier.rows.every((item) => roomOwns(
        item.outcome_room_ref,
        "frontier_item_refs",
        item.frontier_item_id,
      ))],
    ["claims", ["rooms", "frontier", "participants"], () => hasUniqueKeys(model.claims, "work_claim_id")
      && model.frontier.rows.every((item) =>
        recordBacklinksResolve([item], "claim_refs", indexes.claims)
        && recordBacklinksResolve([item], "active_claim_refs", indexes.claims))
      && recordBacklinksResolve(model.participants.rows, "current_claim_ref", indexes.claims)
      && model.claims.rows.every((claim) => {
        const frontier = indexes.frontier.get(claim.frontier_item_ref);
        const participant = indexes.participants.get(claim.claimant_ref);
        const claimIsLive = LIVE_CLAIM.has(claim.status);
        const matchRef = optionalRef(claim, "eligibility_match_receipt_ref");
        const match = matchRef ? indexes.matches.get(matchRef) : null;
        return indexes.rooms.has(claim.outcome_room_ref)
          && !!frontier && sameRoom(frontier, claim.outcome_room_ref)
          && !!participant && sameRoom(participant, claim.outcome_room_ref)
          && listIncludes(frontier, "claim_refs", claim.work_claim_id)
          && listIncludes(frontier, "active_claim_refs", claim.work_claim_id) === claimIsLive
          && (participant.current_claim_ref === claim.work_claim_id) === claimIsLive
          && (!matchRef || (model.matches.ok
            && MATCH_RECEIPT_REF.test(matchRef)
            && !!match
            && match.bound_facts?.outcome_room_ref === claim.outcome_room_ref
            && match.bound_facts?.frontier_item_ref === claim.frontier_item_ref
            && match.bound_facts?.participant_ref === claim.claimant_ref));
      })],
    ["resourceOffers", ["rooms", "participants"], () => hasUniqueKeys(model.resourceOffers, "resource_offer_id")
      && roomBacklinksResolve("resource_offer_refs", indexes.resourceOffers)
      && model.resourceOffers.rows.every((offer) => {
        const participant = indexes.participants.get(offer.provider_participant_lease_ref);
        return roomOwns(offer.outcome_room_ref, "resource_offer_refs", offer.resource_offer_id)
          && !!participant && sameRoom(participant, offer.outcome_room_ref);
      })],
    ["capabilityOffers", ["rooms", "participants"], () => hasUniqueKeys(model.capabilityOffers, "capability_offer_id")
      && roomBacklinksResolve("capability_offer_refs", indexes.capabilityOffers)
      && model.capabilityOffers.rows.every((offer) => {
        const participant = indexes.participants.get(offer.provider_participant_lease_ref);
        return roomOwns(offer.outcome_room_ref, "capability_offer_refs", offer.capability_offer_id)
          && !!participant && sameRoom(participant, offer.outcome_room_ref);
      })],
    ["matches", ["rooms", "frontier", "participants", "resourceOffers", "capabilityOffers"], () => hasUniqueKeys(model.matches, "receipt_id")
      && model.matches.rows.every((receipt) => {
        const facts = receipt.bound_facts;
        if (!Array.isArray(facts.resource_offers) || !Array.isArray(facts.capability_offers)) return false;
        const frontier = indexes.frontier.get(facts.frontier_item_ref);
        const participant = indexes.participants.get(facts.participant_ref);
        const offerCoordinates = [
          ...(Array.isArray(facts.resource_offers) ? facts.resource_offers.map((coordinate) => ["resourceOffers", coordinate]) : []),
          ...(Array.isArray(facts.capability_offers) ? facts.capability_offers.map((coordinate) => ["capabilityOffers", coordinate]) : []),
        ];
        return indexes.rooms.has(facts.outcome_room_ref)
          && !!frontier && sameRoom(frontier, facts.outcome_room_ref)
          && !!participant && sameRoom(participant, facts.outcome_room_ref)
          && offerCoordinates.every(([family, coordinate]) => {
            const offer = isRecord(coordinate) ? indexes[family].get(coordinate.offer_ref) : null;
            return !!offer
              && sameRoom(offer, facts.outcome_room_ref)
              && offer.provider_participant_lease_ref === facts.participant_ref;
          });
      })],
    ["goalRuns", ["rooms"], () => hasUniqueKeys(model.goalRuns, "goal_run_id")
      && roomBacklinksResolve("member_goal_run_refs", indexes.goalRuns)
      && model.goalRuns.rows.every((run) => !run.outcome_room_ref || (
        run.goal_ref === `goal://${run.goal_run_id}`
        && roomOwns(run.outcome_room_ref, "member_goal_run_refs", run.goal_ref)
      ))
      && model.goalRuns.rows.filter((run) => run.goal_ref).length === indexes.goalRuns.size],
    ["results", ["rooms", "goalRuns"], () => hasUniqueKeys(model.results, "work_result_id")
      && (!model.challenges.ok
        || recordBacklinksResolve(model.results.rows, "challenge_refs", indexes.challenges))
      && model.results.rows.every((result) => {
        if (!result.outcome_room_ref) return true;
        if (!indexes.rooms.has(result.outcome_room_ref)) return false;
        const goalRunRef = optionalRef(result, "goal_run_ref");
        if (!goalRunRef) return true;
        const run = indexes.goalRuns.get(goalRunRef);
        return !!run && run.outcome_room_ref === result.outcome_room_ref;
      })],
    ["attempts", ["rooms", "frontier", "claims", "participants", "goalRuns", "results"], () => hasUniqueKeys(model.attempts, "attempt_id")
      && roomBacklinksResolve("attempt_refs", indexes.attempts)
      && model.attempts.rows.every((attempt) => {
        const frontier = indexes.frontier.get(attempt.frontier_item_ref);
        const claim = indexes.claims.get(attempt.work_claim_ref);
        const participant = indexes.participants.get(attempt.participant_ref);
        const run = indexes.goalRuns.get(attempt.goal_run_ref);
        const resultRef = optionalRef(attempt, "work_result_ref");
        const result = resultRef ? indexes.results.get(resultRef) : null;
        return indexes.rooms.has(attempt.outcome_room_ref)
          && roomOwns(attempt.outcome_room_ref, "attempt_refs", attempt.attempt_id)
          && !!frontier && sameRoom(frontier, attempt.outcome_room_ref)
          && !!claim && sameRoom(claim, attempt.outcome_room_ref)
          && claim.frontier_item_ref === attempt.frontier_item_ref
          && claim.claimant_ref === attempt.participant_ref
          && !!participant && sameRoom(participant, attempt.outcome_room_ref)
          && !!run && run.outcome_room_ref === attempt.outcome_room_ref
          && (!resultRef || (!!result
            && result.outcome_room_ref === attempt.outcome_room_ref
            && result.goal_run_ref === attempt.goal_run_ref));
      })],
    ["findings", ["rooms", "attempts", "participants", "results"], () => hasUniqueKeys(model.findings, "finding_id")
      && roomBacklinksResolve("finding_refs", indexes.findings)
      && model.findings.rows.every((finding) => {
        const attempt = indexes.attempts.get(finding.attempt_ref);
        const participant = indexes.participants.get(finding.participant_ref);
        const result = indexes.results.get(finding.work_result_ref);
        const supersedesRef = optionalRef(finding, "supersedes_ref");
        const supersedes = supersedesRef ? indexes.findings.get(supersedesRef) : null;
        return indexes.rooms.has(finding.outcome_room_ref)
          && roomOwns(finding.outcome_room_ref, "finding_refs", finding.finding_id)
          && !!attempt && sameRoom(attempt, finding.outcome_room_ref)
          && attempt.participant_ref === finding.participant_ref
          && attempt.work_result_ref === finding.work_result_ref
          && !!participant && sameRoom(participant, finding.outcome_room_ref)
          && !!result && result.outcome_room_ref === finding.outcome_room_ref
          && (!supersedesRef || (!!supersedes && sameRoom(supersedes, finding.outcome_room_ref)));
      })],
    ["challenges", ["rooms", "participants", "attempts", "findings", "results"], () => hasUniqueKeys(model.challenges, "verifier_challenge_id")
      && roomBacklinksResolve("verifier_challenge_refs", indexes.challenges)
      && model.challenges.rows.every((challenge) => {
        const participant = indexes.participants.get(challenge.challenger_ref);
        const targetAttempt = indexes.attempts.get(challenge.challenged_ref);
        const targetFinding = indexes.findings.get(challenge.challenged_ref);
        const boundAttemptRef = targetAttempt?.attempt_id || targetFinding?.attempt_ref || "";
        const target = targetAttempt || targetFinding;
        const resultRef = target?.work_result_ref || "";
        const result = indexes.results.get(resultRef);
        return indexes.rooms.has(challenge.outcome_room_ref)
          && roomOwns(challenge.outcome_room_ref, "verifier_challenge_refs", challenge.verifier_challenge_id)
          && !!participant && sameRoom(participant, challenge.outcome_room_ref)
          && !!target && sameRoom(target, challenge.outcome_room_ref)
          && challenge.affected_attempt_refs.includes(boundAttemptRef)
          && challenge.affected_attempt_refs.every((reference) => {
            const attempt = indexes.attempts.get(reference);
            return !!attempt && sameRoom(attempt, challenge.outcome_room_ref);
          })
          && !!result && result.outcome_room_ref === challenge.outcome_room_ref
          && listIncludes(result, "challenge_refs", challenge.verifier_challenge_id);
      })],
  ];
  const invalidPayloads = [];
  for (const [name, dependencies, validator] of checks) {
    const plane = model[name];
    if (!plane.ok) continue;
    if (dependencies.every((dependency) => model[dependency].ok) && !validator()) {
      invalidPayloads.push(name);
    }
  }
  for (const name of invalidPayloads) {
    model[name] = unavailablePlane(model[name].status, "plane_payload_invalid");
  }
  let propagated;
  do {
    propagated = false;
    for (const [name, dependencies] of checks) {
      const plane = model[name];
      if (!plane.ok || plane.rows.length === 0) continue;
      if (dependencies.some((dependency) => !model[dependency].ok)) {
        model[name] = unavailablePlane(plane.status, "plane_dependency_unavailable");
        propagated = true;
      }
    }
  } while (propagated);
  for (const plane of Object.values(model)) {
    if (!plane.ok) plane.rows = [];
  }
  return model;
}

export async function load(ctx) {
  const fetchImpl = ctx.fetch || globalThis.fetch;
  const requestedTimeout = Number(ctx.planeTimeoutMs);
  const timeoutMs = Number.isFinite(requestedTimeout) && requestedTimeout > 0
    ? Math.min(Math.floor(requestedTimeout), 30_000)
    : DEFAULT_PLANE_TIMEOUT_MS;
  const specs = [
    ["rooms", "/v1/hypervisor/outcome-rooms", "outcome_rooms"],
    ["requests", "/v1/hypervisor/room-participation-requests", "participation_requests"],
    ["participants", "/v1/hypervisor/room-participant-leases", "participant_leases"],
    ["frontier", "/v1/hypervisor/work-frontier-items", "frontier_items"],
    ["claims", "/v1/hypervisor/work-claim-leases", "work_claims"],
    ["resourceOffers", "/v1/hypervisor/resource-offers", "resource_offers"],
    ["capabilityOffers", "/v1/hypervisor/capability-offers", "capability_offers"],
    ["matches", "/v1/hypervisor/work-eligibility-matches", "eligibility_match_receipts"],
    ["attempts", "/v1/hypervisor/attempts", "attempts"],
    ["findings", "/v1/hypervisor/findings", "findings"],
    ["results", "/v1/hypervisor/work-results", "work_results"],
    ["challenges", "/v1/hypervisor/verifier-challenges", "verifier_challenges"],
    ["goalRuns", "/v1/hypervisor/goal-runs", "goal_runs"],
  ];
  const [values, operations] = await Promise.all([
    Promise.all(specs.map(([, path, key]) => readCollection(fetchImpl, ctx.daemon, path, key, rowValidators[key], timeoutMs))),
    readOperations(fetchImpl, ctx.daemon, timeoutMs),
  ]);
  const model = Object.fromEntries(specs.map(([name], index) => [name, values[index]]));
  model.operations = operations;
  return validateModelRelationships(model);
}

const roomRef = (record) => String(record?.outcome_room_ref || "");
const value = (record, key, fallback = "") => String(record?.[key] ?? fallback);
const shortRef = (reference) => {
  const raw = String(reference || "");
  if (raw.length <= 34) return raw;
  return `${raw.slice(0, 18)}…${raw.slice(-12)}`;
};
const timestamp = (raw) => {
  const ms = Date.parse(raw || "");
  if (!Number.isFinite(ms)) return raw || "—";
  return new Date(ms).toLocaleString("en", {
    month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
  });
};
const statusTone = (status) => {
  const normalized = String(status || "").toLowerCase();
  if (["open", "active", "admitted", "completed", "resolved", "accepted"].includes(normalized)) return "ok";
  if (["blocked", "failed", "quarantined", "revoked", "rejected"].includes(normalized)) return "danger";
  if (["proposed", "submitted", "investigating", "upheld", "rule_changed", "reverifying", "verifying"].includes(normalized)) return "warn";
  return "muted";
};
const statusPill = (status) => `<span class="ms-pill ${statusTone(status)}">${escHtml(status || "unknown")}</span>`;
const byRoom = (plane, reference) => plane.rows.filter((record) => roomRef(record) === reference);
const matchRoom = (receipt) => String(receipt?.bound_facts?.outcome_room_ref || "");
const objective = (room) => value(room, "objective", value(room, "objective_ref", "Untitled mission"));

function planeNotice(name, plane) {
  if (plane.ok) return "";
  return `<div class="ms-plane-error" role="status"><b>${escHtml(name)}</b> unavailable — <code>${escHtml(plane.code)}</code>. Counts for this plane are not treated as zero.</div>`;
}

const planeCount = (plane, rows = plane.rows) => plane.ok ? rows.length : "—";
const planeCountAttr = (plane, rows = plane.rows) => plane.ok ? rows.length : "unknown";

function metric(label, count, tone = "") {
  const key = label.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
  const dataValue = count === "—" ? "unknown" : String(count);
  return `<div class="ms-metric ${tone}" data-missions-metric="${escHtml(key)}" data-value="${escHtml(dataValue)}"><strong>${escHtml(String(count))}</strong><span>${escHtml(label)}</span></div>`;
}

function renderRoomList(rooms, selectedRef, status, model) {
  const hrefFor = (room) => selectionQuery(ROUTE, {
    room: value(room, "outcome_room_id"),
    status: status === "all" ? "" : status,
  });
  if (!model.rooms.ok) {
    return `<div class="ms-empty"><b>Room list unavailable.</b><span>The OutcomeRoom registry could not be read; no empty-state inference was made.</span></div>`;
  }
  if (!rooms.length) {
    return `<div class="ms-empty"><b>No rooms in this view.</b><span>The daemon returned no hosted OutcomeRoom records matching this status.</span></div>`;
  }
  return `<div class="ms-room-list" role="list">${rooms.map((room) => {
    const reference = value(room, "outcome_room_id");
    const frontier = byRoom(model.frontier, reference);
    const claims = byRoom(model.claims, reference).filter((claim) => LIVE_CLAIM.has(value(claim, "status")));
    const challenges = byRoom(model.challenges, reference).filter((challenge) => UNRESOLVED_CHALLENGE.has(value(challenge, "status")));
    return `<a role="listitem" class="ms-room-row${reference === selectedRef ? " selected" : ""}" href="${hrefFor(room)}" aria-current="${reference === selectedRef ? "page" : "false"}">
      <span class="ms-room-state">${statusPill(value(room, "status"))}</span>
      <span class="ms-room-copy"><strong>${escHtml(objective(room))}</strong><span>${escHtml(shortRef(reference))} · ${escHtml(value(room, "room_mode", "hosted room"))}</span></span>
      <span class="ms-room-counts"><b>${planeCount(model.frontier, frontier)}</b> work <b>${planeCount(model.claims, claims)}</b> claims ${model.challenges.ok ? (challenges.length ? `<em>${challenges.length} blocked</em>` : "") : "<em>— blockers</em>"}</span>
    </a>`;
  }).join("")}</div>`;
}

function renderFrontier(reference, model) {
  const items = byRoom(model.frontier, reference);
  const claims = byRoom(model.claims, reference);
  if (!model.frontier.ok || !model.claims.ok) {
    return planeNotice("Frontier / claims", !model.frontier.ok ? model.frontier : model.claims);
  }
  if (!items.length) {
    return `<div class="ms-empty compact"><b>No frontier work.</b><span>This room has no admitted WorkFrontierItem records.</span></div>`;
  }
  return `<div class="ms-work-list">${items.map((item) => {
    const itemRef = value(item, "frontier_item_id");
    const itemClaims = claims.filter((claim) => value(claim, "frontier_item_ref") === itemRef);
    const live = itemClaims.filter((claim) => LIVE_CLAIM.has(value(claim, "status")));
    const dependencies = Array.isArray(item.dependency_refs) ? item.dependency_refs : [];
    return `<div class="ms-work-row">
      <div class="ms-work-main"><span>${statusPill(value(item, "status"))}</span><strong>${escHtml(value(item, "title", value(item, "summary", value(item, "item_kind", "work item"))))}</strong><code title="${escHtml(itemRef)}">${escHtml(shortRef(itemRef))}</code></div>
      <div class="ms-work-meta"><span>${escHtml(value(item, "item_kind", "task"))}</span><span>priority ${escHtml(value(item, "priority", "—"))}</span><span>${dependencies.length} dependencies</span><span>${live.length}/${escHtml(value(item, "max_concurrency", "1"))} live claims</span></div>
      ${itemClaims.length ? `<div class="ms-claim-lineage">${itemClaims.map((claim) => {
        const claimRef = value(claim, "work_claim_id");
        return `<span title="${escHtml(claimRef)}">${statusPill(value(claim, "status"))}<code>${escHtml(shortRef(claimRef))}</code></span>`;
      }).join("")}</div>` : ""}
    </div>`;
  }).join("")}</div>`;
}

function renderParticipants(reference, model) {
  if (!model.participants.ok || !model.requests.ok) {
    return planeNotice("Participation", !model.participants.ok ? model.participants : model.requests);
  }
  const participants = byRoom(model.participants, reference);
  const requests = byRoom(model.requests, reference);
  if (!participants.length && !requests.length) {
    return `<div class="ms-empty compact"><b>No participation records.</b><span>No requests or admitted participant leases are bound to this room.</span></div>`;
  }
  return `<div class="ms-person-list">${participants.map((participant) => `<div class="ms-person">
    <span class="ms-avatar" aria-hidden="true">${escHtml(value(participant, "admitted_role", "p").slice(0, 1).toUpperCase())}</span>
    <span><strong>${escHtml(shortRef(value(participant, "participant_ref", value(participant, "participant_lease_id"))))}</strong><small>${escHtml(value(participant, "admitted_role", "participant"))} · ${escHtml(shortRef(value(participant, "participant_lease_id")))}</small></span>
    ${statusPill(value(participant, "status"))}
  </div>`).join("")}${requests.filter((request) => !value(request, "participant_lease_ref")).map((request) => `<div class="ms-person request">
    <span class="ms-avatar" aria-hidden="true">?</span><span><strong>${escHtml(shortRef(value(request, "requested_by_ref")))}</strong><small>participation request · ${escHtml(shortRef(value(request, "participation_request_id")))}</small></span>${statusPill(value(request, "status"))}
  </div>`).join("")}</div>`;
}

function renderEvidence(reference, model) {
  const attempts = byRoom(model.attempts, reference);
  const findings = byRoom(model.findings, reference);
  const results = byRoom(model.results, reference);
  if (!model.attempts.ok || !model.findings.ok || !model.results.ok) {
    return planeNotice("Attempts / Findings / WorkResults", [model.attempts, model.findings, model.results].find((plane) => !plane.ok));
  }
  if (!attempts.length && !findings.length && !results.length) {
    return `<div class="ms-empty compact"><b>No evidence graph yet.</b><span>Attempts, Findings, and WorkResults appear here after their daemon admissions.</span></div>`;
  }
  const rows = [
    ...attempts.map((record) => ({ kind: "Attempt", id: value(record, "attempt_id"), status: value(record, "status"), time: value(record, "updated_at", value(record, "created_at")), result: value(record, "work_result_ref") })),
    ...findings.map((record) => ({ kind: "Finding", id: value(record, "finding_id"), status: value(record, "status"), time: value(record, "updated_at", value(record, "created_at")), result: value(record, "work_result_ref") })),
    ...results.map((record) => ({ kind: "WorkResult", id: value(record, "work_result_id"), status: value(record, "status"), time: value(record, "updated_at", value(record, "created_at")), result: value(record, "outcome_class") })),
  ].sort((left, right) => String(right.time).localeCompare(String(left.time))).slice(0, 16);
  return `<div class="ms-evidence" role="table"><div class="ms-evidence-head" role="row"><span>Record</span><span>Status</span><span>Coordinate</span><span>Updated</span></div>${rows.map((row) => `<div class="ms-evidence-row" role="row">
    <span><b>${escHtml(row.kind)}</b><small title="${escHtml(row.id)}">${escHtml(shortRef(row.id))}</small></span><span>${statusPill(row.status)}</span><code title="${escHtml(row.result)}">${escHtml(shortRef(row.result || "—"))}</code><time>${escHtml(timestamp(row.time))}</time>
  </div>`).join("")}</div>`;
}

function renderChallenges(reference, model) {
  if (!model.challenges.ok) return planeNotice("VerifierChallenge", model.challenges);
  const challenges = byRoom(model.challenges, reference);
  const unresolved = challenges.filter((challenge) => UNRESOLVED_CHALLENGE.has(value(challenge, "status")));
  if (!challenges.length) {
    return `<div class="ms-empty compact"><b>No verifier challenges.</b><span>No admitted challenge record currently affects this room.</span></div>`;
  }
  return `<div class="ms-challenges">${challenges.map((challenge) => {
    const challengeRef = value(challenge, "verifier_challenge_id");
    return `<div class="ms-challenge${UNRESOLVED_CHALLENGE.has(value(challenge, "status")) ? " unresolved" : ""}">
      <span>${statusPill(value(challenge, "status"))}</span><span><strong>${escHtml(value(challenge, "challenge_kind", "challenge"))}</strong><small title="${escHtml(value(challenge, "challenged_ref"))}">${escHtml(shortRef(value(challenge, "challenged_ref")))}</small></span>
      <code title="${escHtml(challengeRef)}">${escHtml(shortRef(challengeRef))}</code>
    </div>`;
  }).join("")}<p class="ms-boundary">${unresolved.length ? `${unresolved.length} unresolved challenge${unresolved.length === 1 ? "" : "s"} block room close and affected acceptance paths.` : "All challenge interlocks are cleared."} This surface displays the interlock; it does not create acceptance or verdict authority.</p></div>`;
}

function renderRoomDetail(room, model, selectionProblem = null) {
  if (!room) {
    const title = selectionProblem?.code === "room_filter_mismatch"
      ? "Selected room is outside this status view"
      : selectionProblem?.code === "room_not_found"
        ? "Selected room was not found"
        : "Select a mission room";
    const detail = selectionProblem?.code === "room_filter_mismatch"
      ? "No different room was selected. Change the status filter or choose a visible room."
      : selectionProblem?.code === "room_not_found"
        ? "No different room was selected. Choose a room from the current daemon registry."
        : "Choose a room to inspect its admitted work graph and proof posture.";
    return `<section class="ms-detail empty-detail"${selectionProblem ? ` data-missions-selection-error="${selectionProblem.code}" role="status"` : ""}><div><b>${title}</b><span>${detail}</span></div></section>`;
  }
  const reference = value(room, "outcome_room_id");
  const participants = byRoom(model.participants, reference);
  const frontier = byRoom(model.frontier, reference);
  const claims = byRoom(model.claims, reference);
  const challenges = byRoom(model.challenges, reference);
  const activeParticipants = participants.filter((record) => value(record, "status") === "active");
  const liveClaims = claims.filter((record) => LIVE_CLAIM.has(value(record, "status")));
  const blockers = challenges.filter((record) => UNRESOLVED_CHALLENGE.has(value(record, "status")));
  const resourceOffers = byRoom(model.resourceOffers, reference);
  const capabilityOffers = byRoom(model.capabilityOffers, reference);
  const matches = model.matches.rows.filter((receipt) => matchRoom(receipt) === reference);
  const proof = proofLink({ href: "/__ioi/work-ledger", label: "Open proof stream" });
  return `<section class="ms-detail" aria-label="Selected mission room" data-missions-selected-room="${escHtml(reference)}">
    <header class="ms-detail-head"><div><div class="ms-eyebrow">Hosted OutcomeRoom</div><h2>${escHtml(objective(room))}</h2><p title="${escHtml(reference)}">${escHtml(reference)}</p></div><div class="ms-detail-actions">${statusPill(value(room, "status"))}${proof}</div></header>
    <div class="ms-facts">
      <div><span>Host</span><strong>${escHtml(shortRef(value(room, "host_domain_ref", "—")))}</strong></div>
      <div><span>Mode</span><strong>${escHtml(value(room, "room_mode", "—"))}</strong></div>
      <div><span>Topology</span><strong>${escHtml(value(room, "coordination_topology", "—"))}</strong></div>
      <div><span>Revision</span><strong>${escHtml(value(room, "revision", "—"))}</strong></div>
      <div><span>Updated</span><strong>${escHtml(timestamp(value(room, "updated_at")))}</strong></div>
    </div>
    <div class="ms-room-metrics">${metric("active participants", planeCount(model.participants, activeParticipants))}${metric("frontier items", planeCount(model.frontier, frontier))}${metric("live claims", planeCount(model.claims, liveClaims))}${metric("challenge blockers", planeCount(model.challenges, blockers), blockers.length ? "attention" : "")}</div>
    <div class="ms-section"><div class="ms-section-title"><h3>Frontier and claims</h3><span>Admitted work and bounded concurrency</span></div>${renderFrontier(reference, model)}</div>
    <div class="ms-two-col">
      <div class="ms-section"><div class="ms-section-title"><h3>Participation</h3><span>Requests and current leases</span></div>${renderParticipants(reference, model)}</div>
      <div class="ms-section"><div class="ms-section-title"><h3>Eligibility supply</h3><span>Evidence matching, never allocation</span></div>
        <div class="ms-supply">${metric("resource offers", planeCount(model.resourceOffers, resourceOffers))}${metric("capability offers", planeCount(model.capabilityOffers, capabilityOffers))}${metric("receipted matches", planeCount(model.matches, matches))}</div>
        ${[model.resourceOffers, model.capabilityOffers, model.matches].some((plane) => !plane.ok) ? planeNotice("Offer / eligibility", [model.resourceOffers, model.capabilityOffers, model.matches].find((plane) => !plane.ok)) : ""}
      </div>
    </div>
    <div class="ms-section"><div class="ms-section-title"><h3>Attempts, Findings, and WorkResults</h3><span>Historical coordinates remain inspectable</span></div>${renderEvidence(reference, model)}</div>
    <div class="ms-section"><div class="ms-section-title"><h3>Verifier challenges</h3><span>Unresolved acceptance and close interlocks</span></div>${renderChallenges(reference, model)}</div>
    <footer class="ms-contract"><b>Contract boundary.</b> Hosted admission only. This read model grants no acceptance, verdict, settlement, execution, or federation authority.</footer>
  </section>`;
}

function renderLegacyOperations(model) {
  const operations = model.operations.payload || {};
  const runs = operations.runs || {};
  const recent = Array.isArray(runs.recent) ? runs.recent : [];
  const failures = Array.isArray(runs.failures) ? runs.failures : [];
  const goalRuns = model.goalRuns.rows;
  const blocked = goalRuns.filter((run) => Array.isArray(run.blockers) && run.blockers.length);
  const incidentCount = failures.length + blocked.length;
  const incidentsReady = model.operations.ok && model.goalRuns.ok;
  const runRows = recent.map((run) => {
    const timeline = canonicalTimelineRef(run.timeline_ref);
    return `<div class="ms-op-row"><span><b>${escHtml(run.name || run.execution_id || "mission run")}</b><small>${escHtml(shortRef(run.project_id || ""))}</small></span>${statusPill(run.status)}<time>${escHtml(timestamp(run.started_at))}</time>${timeline ? proofLink({ href: timeline, label: "Timeline", external: true }) : "<span>—</span>"}</div>`;
  }).join("");
  const incidentRows = [
    ...failures.map((run) => ({ kind: "run failure", subject: run.name || run.execution_id, reason: run.status, time: run.finished_at || run.started_at, proof: canonicalTimelineRef(run.timeline_ref) })),
    ...blocked.slice(0, 50).map((run) => ({ kind: "blocker", subject: run.normalized_goal || run.goal_ref || run.goal_run_id, reason: run.blockers?.[0]?.reason_code, time: run.updated_at || run.created_at, proof: run.goal_run_id ? `/__ioi/run-timeline/goal-run/${encodeURIComponent(run.goal_run_id)}` : "" })),
  ];
  const capDisclosure = incidentsReady && incidentRows.length < incidentCount
    ? ` · showing first ${incidentRows.length} of ${incidentCount}`
    : "";
  return `<div class="ms-legacy">
    <div class="ms-section"><div class="ms-section-title"><h3 id="missions-queue">Run queue</h3><span>${model.operations.ok ? `recent mission runs (${recent.length} of ${runs.total || 0})` : "run count unavailable"}</span></div>${model.operations.ok ? (runRows || `<div class="ms-empty compact"><b>No mission runs yet.</b><span>The daemon run queue is honestly empty.</span></div>`) : planeNotice("Operations run queue", model.operations)}</div>
    <div class="ms-section"><div class="ms-section-title"><h3 id="missions-incidents">Incidents &amp; blockers</h3><span>run failures + mission blockers needing remediation (${incidentsReady ? incidentCount : "unknown"})${capDisclosure} · <a href="/__ioi/missions/incidents">Open incident inbox</a></span></div>
      ${!incidentsReady ? planeNotice("Mission incidents", !model.operations.ok ? model.operations : model.goalRuns) : incidentRows.length ? `<div class="ms-op-list">${incidentRows.map((incident) => `<div class="ms-op-row"><span><b>${escHtml(incident.kind)}</b><small>${escHtml(incident.subject || "—")}</small></span>${statusPill(incident.reason)}<time>${escHtml(timestamp(incident.time))}</time>${incident.proof ? proofLink({ href: incident.proof, label: "Proof", external: true }) : "<span>—</span>"}</div>`).join("")}</div>` : `<div class="ms-empty compact"><b>No incidents.</b><span>No failed mission runs and no blocked mission runs right now.</span></div>`}
    </div>
    <footer class="ms-contract"><b>Operational boundary.</b> Hosted admission only; this surface grants no acceptance, verdict, settlement, execution, or federation authority. Unsupported reference lanes — creating/assigning incidents, editing job/build definitions, board/kanban views, SLA and escalation policy, comments, and assignees — remain named gaps. Substrate/infra incidents (storage repair, provider failover) live in <a href="/__ioi/operations">Operations</a>. Reference captures remain secondary baselines: <a href="/__apps/jobs">Builds</a> · <a href="/__apps/incidents">Issues</a>.</footer>
  </div>`;
}

export function render(model, ctx) {
  const allRooms = model.rooms.rows;
  const statuses = [...new Set(allRooms.map((room) => value(room, "status")).filter(Boolean))].sort();
  const requestedStatus = ctx.url.searchParams.get("status") || "all";
  const status = requestedStatus === "all" || statuses.includes(requestedStatus) ? requestedStatus : "all";
  const rooms = status === "all" ? allRooms : allRooms.filter((room) => value(room, "status") === status);
  const requestedRoom = ctx.url.searchParams.get("room") || "";
  const exactRequestedRoom = requestedRoom
    ? allRooms.find((room) => value(room, "outcome_room_id") === requestedRoom)
    : null;
  const selectionProblem = requestedRoom && !exactRequestedRoom
    ? { code: "room_not_found" }
    : requestedRoom && !rooms.includes(exactRequestedRoom)
      ? { code: "room_filter_mismatch" }
      : null;
  const selected = requestedRoom
    ? (selectionProblem ? null : exactRequestedRoom)
    : rooms.find((room) => value(room, "status") === "open") || rooms[0] || null;
  const selectedRef = selected ? value(selected, "outcome_room_id") : "";
  const liveClaims = model.claims.rows.filter((claim) => LIVE_CLAIM.has(value(claim, "status")));
  const unresolved = model.challenges.rows.filter((challenge) => UNRESOLVED_CHALLENGE.has(value(challenge, "status")));
  const filters = ["all", ...statuses].map((entry) => `<a role="tab" aria-selected="${entry === status}" class="ms-filter${entry === status ? " active" : ""}" href="${selectionQuery(ROUTE, { status: entry === "all" ? "" : entry })}">${escHtml(entry)} <span>${planeCount(model.rooms, entry === "all" ? allRooms : allRooms.filter((room) => value(room, "status") === entry))}</span></a>`).join("");
  const selectionUrl = selectionQuery(ROUTE, { room: selectedRef, status: status === "all" ? "" : status });
  const globalRail = ctx.embed ? "" : ioiGlobalRailHtml({
    label: "Missions", href: ROUTE, iconUri: MISSIONS_APP_ICON_URI,
  });
  const CSS = `
    :root{color-scheme:dark;--surface-base:28 28 28;--surface-01:22 21 21;--surface-03:31 31 31;--surface-hover:255 255 255;--content-primary:250 250 250;--content-secondary:163 163 163;--content-muted:115 115 115;--content-strong:212 212 212;--content-link:139 171 252;--content-negative:255 83 90;--border-base:64 64 64;--border-strong:82 82 82;--border-brand:94 138 253;--status-ok:108 255 100;--status-warn:254 154 91;--status-danger:255 83 90}
    @media(prefers-color-scheme:light){:root{color-scheme:light;--surface-base:250 250 250;--surface-01:255 255 255;--surface-03:245 245 245;--surface-hover:0 0 0;--content-primary:31 31 31;--content-secondary:82 82 82;--content-muted:115 115 115;--content-strong:64 64 64;--content-link:0 72 255;--content-negative:173 0 2;--border-base:225 225 225;--border-strong:212 212 212;--border-brand:47 105 253;--status-ok:28 125 44;--status-warn:154 82 12;--status-danger:173 0 2}}
    *{box-sizing:border-box}body{margin:0;background:rgb(var(--surface-base));color:rgb(var(--content-primary));font:14px/1.45 "ABC Diatype",-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}a{color:rgb(var(--content-link));text-decoration:none}button,a{transition:background-color .15s ease,color .15s ease,border-color .15s ease,transform .15s ease}code{font:11px/1.4 "ABC Diatype Mono",ui-monospace,monospace;color:rgb(var(--content-secondary));word-break:break-all}
    ${IOI_GRAIL_CSS}
    .ms-shell{display:flex;min-height:100svh}.ms-main{flex:1;min-width:0}.ms-top{position:sticky;top:0;z-index:5;display:flex;align-items:center;justify-content:space-between;gap:20px;height:64px;padding:0 24px;border-bottom:1px solid rgb(var(--border-base));background:rgb(var(--surface-base)/.92);backdrop-filter:blur(16px)}.ms-title{display:flex;align-items:baseline;gap:10px}.ms-title h1{font-size:20px;line-height:1;margin:0;font-weight:500}.ms-title span{color:rgb(var(--content-muted));font-size:12px}.ms-actions{display:flex;align-items:center;gap:8px}.ms-action{display:inline-flex;align-items:center;height:32px;padding:0 12px;border:1px solid rgb(var(--border-base));border-radius:8px;color:rgb(var(--content-primary));background:rgb(var(--surface-01));font-size:12px}.ms-action:hover{border-color:rgb(var(--border-brand));transform:translateY(-1px)}
    .ms-summary{display:flex;align-items:stretch;border-bottom:1px solid rgb(var(--border-base));padding:0 24px}.ms-metric{display:flex;flex-direction:column;gap:2px;min-width:112px;padding:16px 22px 14px 0;margin-right:22px;border-right:1px solid rgb(var(--border-base))}.ms-metric:last-child{border-right:0}.ms-metric strong{font-size:20px;line-height:1.1;font-weight:500}.ms-metric span{color:rgb(var(--content-muted));font-size:11px}.ms-metric.attention strong{color:rgb(var(--status-warn))}
    .ms-tabs{display:flex;align-items:center;gap:2px;padding:12px 24px;border-bottom:1px solid rgb(var(--border-base));overflow:auto}.ms-filter{display:inline-flex;align-items:center;gap:7px;height:30px;padding:0 10px;border-radius:7px;color:rgb(var(--content-secondary));white-space:nowrap}.ms-filter span{font-size:10px;color:rgb(var(--content-muted))}.ms-filter:hover,.ms-filter.active{background:rgb(var(--surface-hover)/.07);color:rgb(var(--content-primary))}
    .ms-workspace{display:grid;grid-template-columns:minmax(280px,340px) minmax(0,1fr);min-height:calc(100svh - 178px)}.ms-sidebar{border-right:1px solid rgb(var(--border-base));background:rgb(var(--surface-01));min-width:0}.ms-sidebar-head{display:flex;align-items:center;justify-content:space-between;padding:14px 16px;border-bottom:1px solid rgb(var(--border-base));color:rgb(var(--content-muted));font-size:11px;text-transform:uppercase}.ms-room-list{display:flex;flex-direction:column}.ms-room-row{display:grid;grid-template-columns:auto minmax(0,1fr);gap:8px 10px;padding:14px 16px;border-bottom:1px solid rgb(var(--border-base));color:inherit;position:relative}.ms-room-row:hover{background:rgb(var(--surface-hover)/.05)}.ms-room-row.selected{background:rgb(var(--surface-hover)/.08)}.ms-room-row.selected:before{content:"";position:absolute;inset:0 auto 0 0;width:2px;background:rgb(var(--border-brand))}.ms-room-copy{min-width:0}.ms-room-copy strong,.ms-room-copy span{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.ms-room-copy strong{font-weight:500}.ms-room-copy span{color:rgb(var(--content-muted));font-size:11px;margin-top:3px}.ms-room-counts{grid-column:2;color:rgb(var(--content-muted));font-size:10px}.ms-room-counts b{color:rgb(var(--content-secondary));font-weight:500}.ms-room-counts em{color:rgb(var(--status-warn));font-style:normal;margin-left:5px}
    .ms-detail{min-width:0;padding:24px 28px 64px;animation:ms-enter .18s ease-out both}.ms-detail.empty-detail{display:grid;place-items:center;color:rgb(var(--content-muted))}.empty-detail div{display:flex;flex-direction:column;gap:4px;text-align:center}.ms-detail-head{display:flex;justify-content:space-between;align-items:flex-start;gap:18px;padding-bottom:18px;border-bottom:1px solid rgb(var(--border-base))}.ms-eyebrow{color:rgb(var(--content-muted));font-size:10px;text-transform:uppercase;margin-bottom:6px}.ms-detail-head h2{font-size:24px;line-height:1.2;font-weight:500;margin:0}.ms-detail-head p{font:11px/1.4 ui-monospace,monospace;color:rgb(var(--content-muted));margin:6px 0 0;word-break:break-all}.ms-detail-actions{display:flex;align-items:center;gap:10px}.ioi-proof-link{font-size:12px}
    .ms-pill{display:inline-flex;align-items:center;height:20px;padding:0 7px;border:1px solid rgb(var(--border-base));border-radius:999px;color:rgb(var(--content-secondary));font-size:10px;white-space:nowrap}.ms-pill.ok{color:rgb(var(--status-ok));border-color:rgb(var(--status-ok)/.35)}.ms-pill.warn{color:rgb(var(--status-warn));border-color:rgb(var(--status-warn)/.35)}.ms-pill.danger{color:rgb(var(--status-danger));border-color:rgb(var(--status-danger)/.35)}
    .ms-facts{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:0;border-bottom:1px solid rgb(var(--border-base))}.ms-facts div{display:flex;flex-direction:column;gap:3px;padding:13px 12px 13px 0}.ms-facts span{color:rgb(var(--content-muted));font-size:10px;text-transform:uppercase}.ms-facts strong{font-size:12px;font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.ms-room-metrics,.ms-supply{display:flex;align-items:stretch;margin-top:4px}.ms-room-metrics .ms-metric,.ms-supply .ms-metric{min-width:0;flex:1}
    .ms-section{padding-top:24px}.ms-section-title{display:flex;align-items:baseline;justify-content:space-between;gap:14px;margin-bottom:10px}.ms-section-title h3{font-size:13px;font-weight:500;margin:0}.ms-section-title span{color:rgb(var(--content-muted));font-size:11px}.ms-two-col{display:grid;grid-template-columns:minmax(0,1fr) minmax(260px,.72fr);gap:28px}
    .ms-work-list,.ms-person-list,.ms-challenges,.ms-op-list{border-top:1px solid rgb(var(--border-base))}.ms-work-row{padding:11px 0;border-bottom:1px solid rgb(var(--border-base))}.ms-work-main{display:grid;grid-template-columns:auto minmax(140px,1fr) auto;align-items:center;gap:10px}.ms-work-main strong{font-weight:500}.ms-work-meta{display:flex;gap:14px;padding:5px 0 0 69px;color:rgb(var(--content-muted));font-size:10px}.ms-claim-lineage{display:flex;flex-wrap:wrap;gap:6px;padding:8px 0 0 69px}.ms-claim-lineage>span{display:flex;align-items:center;gap:6px;padding:3px 7px 3px 3px;border:1px solid rgb(var(--border-base));border-radius:999px;background:rgb(var(--surface-03))}.ms-claim-lineage .ms-pill{height:18px}.ms-person{display:grid;grid-template-columns:auto minmax(0,1fr) auto;align-items:center;gap:10px;padding:10px 0;border-bottom:1px solid rgb(var(--border-base))}.ms-avatar{display:grid;place-items:center;width:28px;height:28px;border-radius:50%;background:rgb(var(--surface-03));color:rgb(var(--content-secondary));font-size:11px}.ms-person strong,.ms-person small{display:block}.ms-person strong{font-size:12px;font-weight:500}.ms-person small{color:rgb(var(--content-muted));font-size:10px;margin-top:2px}
    .ms-evidence{border-top:1px solid rgb(var(--border-base))}.ms-evidence-head,.ms-evidence-row{display:grid;grid-template-columns:minmax(170px,1.3fr) 100px minmax(130px,1fr) 110px;align-items:center;gap:12px;padding:9px 0;border-bottom:1px solid rgb(var(--border-base))}.ms-evidence-head{color:rgb(var(--content-muted));font-size:10px;text-transform:uppercase}.ms-evidence-row>span:first-child b,.ms-evidence-row>span:first-child small{display:block}.ms-evidence-row b{font-size:11px;font-weight:500}.ms-evidence-row small,.ms-evidence-row time{color:rgb(var(--content-muted));font-size:10px}.ms-challenge{display:grid;grid-template-columns:auto minmax(160px,1fr) auto;align-items:center;gap:10px;padding:10px 0;border-bottom:1px solid rgb(var(--border-base))}.ms-challenge.unresolved{box-shadow:inset 2px 0 0 rgb(var(--status-warn));padding-left:10px}.ms-challenge strong,.ms-challenge small{display:block}.ms-challenge strong{font-size:12px;font-weight:500}.ms-challenge small{font-size:10px;color:rgb(var(--content-muted));margin-top:2px}.ms-boundary,.ms-contract{color:rgb(var(--content-muted));font-size:11px}.ms-contract{margin-top:26px;padding-top:14px;border-top:1px solid rgb(var(--border-base))}
    .ms-empty{display:flex;flex-direction:column;gap:4px;padding:22px;color:rgb(var(--content-muted))}.ms-empty.compact{padding:14px 0;border-top:1px solid rgb(var(--border-base))}.ms-empty b{color:rgb(var(--content-secondary));font-weight:500}.ms-plane-error{padding:11px 12px;border-left:2px solid rgb(var(--status-warn));background:rgb(var(--status-warn)/.06);color:rgb(var(--content-secondary));font-size:11px}.ms-op-row{display:grid;grid-template-columns:minmax(180px,1fr) 100px 120px 80px;align-items:center;gap:12px;padding:9px 0;border-bottom:1px solid rgb(var(--border-base))}.ms-op-row b,.ms-op-row small{display:block}.ms-op-row b{font-size:11px;font-weight:500}.ms-op-row small,.ms-op-row time{font-size:10px;color:rgb(var(--content-muted))}.ms-legacy{padding:0 28px 48px;border-top:1px solid rgb(var(--border-base))}
    @keyframes ms-enter{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:none}}@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}@media(max-width:980px){.ms-workspace{grid-template-columns:1fr}.ms-sidebar{border-right:0}.ms-detail{padding:22px 18px}.ms-facts{grid-template-columns:repeat(2,minmax(0,1fr))}.ms-two-col{grid-template-columns:1fr}.ms-summary{overflow:auto}.ms-evidence-head,.ms-evidence-row{grid-template-columns:minmax(150px,1fr) 90px 100px}.ms-evidence-head span:nth-child(3),.ms-evidence-row code{display:none}}@media(max-width:640px){.ms-top{padding:0 14px}.ms-title span{display:none}.ms-actions .ms-action:first-child{display:none}.ms-summary,.ms-tabs{padding-left:14px;padding-right:14px}.ms-detail-head{flex-direction:column}.ms-detail-actions{width:100%;justify-content:space-between}.ms-work-meta,.ms-claim-lineage{padding-left:0;flex-wrap:wrap}.ms-legacy{padding-left:18px;padding-right:18px}.ms-op-row{grid-template-columns:1fr auto}.ms-op-row time,.ms-op-row>a{display:none}}
  `;
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Missions · Hypervisor</title><style>${CSS}</style></head><body><div class="ms-shell">${globalRail}<main class="ms-main" data-missions-work-graph="hosted" data-missions-rooms="${planeCountAttr(model.rooms)}" data-missions-frontier="${planeCountAttr(model.frontier)}" data-missions-live-claims="${planeCountAttr(model.claims, liveClaims)}" data-missions-attempts="${planeCountAttr(model.attempts)}" data-missions-findings="${planeCountAttr(model.findings)}" data-missions-unresolved-challenges="${planeCountAttr(model.challenges, unresolved)}">
    <header class="ms-top"><div class="ms-title"><h1>Missions</h1><span>Hosted work graph</span></div><div class="ms-actions"><a class="ms-action" href="/__ioi/operations">Operations substrate</a><a class="ms-action" href="/__ioi/work-ledger">Proof stream</a><a class="ms-action" href="${selectionUrl}" aria-label="Refresh mission data">Refresh</a></div></header>
    <div class="ms-summary">${metric("rooms", planeCount(model.rooms))}${metric("open", planeCount(model.rooms, allRooms.filter((room) => value(room, "status") === "open")))}${metric("live claims", planeCount(model.claims, liveClaims))}${metric("unresolved challenges", planeCount(model.challenges, unresolved), unresolved.length ? "attention" : "")}${metric("attempts", planeCount(model.attempts))}${metric("findings", planeCount(model.findings))}</div>
    ${planeNotice("OutcomeRoom registry", model.rooms)}
    <nav class="ms-tabs" role="tablist" aria-label="Room status filters">${filters}</nav>
    <div class="ms-workspace"><aside class="ms-sidebar"><div class="ms-sidebar-head"><span>Mission rooms</span><span>${planeCount(model.rooms, rooms)}</span></div>${renderRoomList(rooms, selectedRef, status, model)}</aside>${renderRoomDetail(selected, model, selectionProblem)}</div>
    ${renderLegacyOperations(model)}
  </main></div></body></html>`;
}

// Read-only-by-contract: no actions and no handleAction export.
export const actions = [];

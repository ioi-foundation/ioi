/**
 * Work objects composed over the orchestration (R-177, S4b).
 *
 * WHAT THIS IS. The ioi.ai application's composition of the six work objects — WorkClaim, Attempt,
 * Finding, VerifierChallenge, ResourceOffer, CapabilityOffer (v4) — as records admitted under the
 * bounded System through the generic record seam. Every record takes its coordinates from the
 * composition: `orchestration_ref` is the composition's own scope, and the ACTOR is exactly one of a
 * `participation_ref` (an accepted, not-yet-exited OrchestrationParticipationRequest — a party
 * outside the host System) or a `delegation_ref` (`delegation://{thread_id}/{subagent_id}` — a
 * subagent of the coordinating thread). Frozen coordinates (`bound_coordinates`) carry the bound
 * record's ref, its orchestration and a control hash that IS the bound record's seam-derived payload
 * root, so anyone holding the served records re-derives them.
 *
 * WHAT THIS IS NOT. Not a plane and not a lease. The daemon's older routes for these objects are
 * the hosted spine this composition replaces (R-172 S4a/S4c); nothing here calls them. The
 * portable invariants pin the shape (an actor is present, the scope matches the binding, every
 * frozen coordinate belongs to this orchestration); that the participation is accepted and unexited,
 * that the delegation is a live subagent of THIS orchestration's thread, and that an attempt's claim
 * is held by its actor are this module's obligations, refused here by name and proven by the gate.
 */

import type { Orchestration, SystemRecordAdmitResult, SystemRecordChainResult } from "@ioi/agent-sdk";

import { COLLABORATION_CONTRACTS, CollaborationRefusal, type ParticipationRequestRecord } from "./collaboration.js";

export const WORK_CONTRACTS = {
  frontierItem: "schema://ioi/applications/ioi-ai/work-frontier-item/v3",
  claim: "schema://ioi/applications/ioi-ai/work-claim/v4",
  attempt: "schema://ioi/applications/ioi-ai/attempt/v4",
  finding: "schema://ioi/applications/ioi-ai/finding/v4",
  challenge: "schema://ioi/applications/ioi-ai/verifier-challenge/v4",
  resourceOffer: "schema://ioi/applications/ioi-ai/resource-offer/v4",
  capabilityOffer: "schema://ioi/applications/ioi-ai/capability-offer/v4",
} as const;

export type Actor = { participation_ref: string; delegation_ref: null } | { participation_ref: null; delegation_ref: string };

export interface FrozenCoordinate {
  record_ref: string;
  orchestration_ref: string;
  control_hash: string;
}

export class WorkRefusal extends Error {
  readonly code: string;
  readonly details: Record<string, unknown>;
  constructor(code: string, message: string, details: Record<string, unknown> = {}) {
    super(message);
    this.name = "WorkRefusal";
    this.code = code;
    this.details = details;
  }
}

// ---- pure ---------------------------------------------------------------------------------------

export function delegationRef(threadId: string, subagentId: string): string {
  return `delegation://${threadId}/${subagentId}`;
}

export function parseDelegationRef(ref: string): { thread_id: string; subagent_id: string } | null {
  const match = /^delegation:\/\/([^/\s]+)\/([^/\s]+)$/u.exec(ref);
  return match ? { thread_id: match[1], subagent_id: match[2] } : null;
}

export function participationActor(ref: string): Actor {
  return { participation_ref: ref, delegation_ref: null };
}

export function delegationActor(threadId: string, subagentId: string): Actor {
  return { participation_ref: null, delegation_ref: delegationRef(threadId, subagentId) };
}

/** A frozen coordinate of a served record: its ref, its orchestration, and the seam-derived payload root as the control hash. */
export function coordinateOf(record: Record<string, unknown>, recordRef: string): FrozenCoordinate {
  const binding = record.system_binding as { parent_scope_ref?: string; payload_root?: string } | undefined;
  if (!binding?.payload_root || !binding.parent_scope_ref) throw new WorkRefusal("work_coordinate_unbound", `the record ${recordRef} carries no seam-derived binding to freeze`);
  return { record_ref: recordRef, orchestration_ref: binding.parent_scope_ref, control_hash: binding.payload_root };
}

/** Offline: every frozen coordinate of a record equals the coordinate of the served record it names. */
export function verifyFrozenCoordinates(record: { orchestration_ref: string; bound_coordinates: Record<string, FrozenCoordinate | null> | null }, served: Record<string, { record: Record<string, unknown>; ref: string }>): { ok: boolean; findings: string[] } {
  const findings: string[] = [];
  for (const [name, coordinate] of Object.entries(record.bound_coordinates ?? {})) {
    if (!coordinate) continue;
    const bound = served[name];
    if (!bound) { findings.push(`no served record for the ${name} coordinate`); continue; }
    const expected = coordinateOf(bound.record, bound.ref);
    if (coordinate.record_ref !== expected.record_ref) findings.push(`${name}: record ref differs`);
    if (coordinate.control_hash !== expected.control_hash) findings.push(`${name}: control hash does not equal the served record's payload root`);
    if (coordinate.orchestration_ref !== record.orchestration_ref) findings.push(`${name}: coordinate from another orchestration`);
  }
  return { ok: findings.length === 0, findings };
}

// ---- the composer -------------------------------------------------------------------------------

export interface ClaimDraft {
  work_claim_id: string;
  frontier_item_ref: string;
  claimant_ref: string;
  actor: Actor;
  collaboration_terms_ref: string;
  collaboration_terms_root: string;
  terms_acceptance_ref: string;
  contribution_policy_ref: string;
  settlement_profile_ref: string;
  bounded_scope_ref: string;
  duplicate_work_policy: "exclusive" | "allowed" | "independent_replication" | "adversarial_replication";
  issued_at?: string;
  expires_at: string;
  context_lease_refs?: string[];
  authority_resource_compute_data_budget_and_tool_lease_refs?: string[];
}

export class Work {
  readonly orchestration: Orchestration;
  private readonly now: () => string;

  constructor(orchestration: Orchestration, options: { now?: () => string } = {}) {
    this.orchestration = orchestration;
    this.now = options.now ?? (() => new Date().toISOString());
  }

  // -- actors ---------------------------------------------------------------------------------------

  /**
   * The actor is one of two things and this composer checks which. A participation must be
   * accepted and not exited; a delegation must be a subagent the kernel lists under THIS
   * orchestration's coordinating thread. Neither the contract nor the seam can read another record.
   */
  async resolveActor(actor: Actor): Promise<Actor> {
    const both = actor.participation_ref !== null && actor.delegation_ref !== null;
    const neither = actor.participation_ref === null && actor.delegation_ref === null;
    if (both) throw new WorkRefusal("work_actor_ambiguous", "an actor is a participation or a delegation, never both");
    if (neither) throw new WorkRefusal("work_actor_required", "a work object has an actor: an accepted participation or a delegation of the coordinating thread");
    if (actor.participation_ref !== null) {
      const chain = await this.readChain(COLLABORATION_CONTRACTS.participation, actor.participation_ref);
      const current = chain?.current as ParticipationRequestRecord | null | undefined;
      if (!current) throw new WorkRefusal("work_actor_participation_unknown", `no participation ${actor.participation_ref} under this orchestration`);
      if (current.status !== "accepted") throw new WorkRefusal("work_actor_participation_not_accepted", `participation ${actor.participation_ref} is ${current.status}; only an accepted participation acts`, { status: current.status });
      if (current.exit !== null) throw new WorkRefusal("work_actor_participation_exited", `participation ${actor.participation_ref} has left; a participant that exited acts no more`);
      return actor;
    }
    const parsed = parseDelegationRef(actor.delegation_ref as string);
    if (!parsed) throw new WorkRefusal("work_actor_delegation_malformed", "a delegation ref is delegation://{thread_id}/{subagent_id}");
    if (parsed.thread_id !== this.orchestration.thread_id) throw new WorkRefusal("work_actor_delegation_foreign_thread", "a delegation acts only for the orchestration whose coordinating thread it belongs to", { delegation_thread: parsed.thread_id, this_thread: this.orchestration.thread_id });
    const listed = await this.orchestration.delegations();
    if (!(listed.subagents ?? []).some((s) => s.subagent_id === parsed.subagent_id)) throw new WorkRefusal("work_actor_delegation_unknown", `the kernel lists no subagent ${parsed.subagent_id} under thread ${parsed.thread_id}`);
    return actor;
  }

  private async readChain(contractId: string, objectId: string): Promise<SystemRecordChainResult | null> {
    try {
      const chain = await this.orchestration.recordChain(contractId, objectId);
      return chain.current ? chain : null;
    } catch (error) {
      const status = (error as { status?: number })?.status;
      if (status === 403 || status === 404) return null;
      throw error;
    }
  }

  private async requireRecord(contractId: string, objectId: string, code: string): Promise<SystemRecordChainResult> {
    const chain = await this.readChain(contractId, objectId);
    if (!chain) throw new WorkRefusal(code, `no ${contractId.split("/").slice(-2).join("/")} record ${objectId} under this orchestration`);
    return chain;
  }

  private static sameActor(a: { participation_ref?: unknown; delegation_ref?: unknown }, b: Actor): boolean {
    return (a.participation_ref ?? null) === b.participation_ref && (a.delegation_ref ?? null) === b.delegation_ref;
  }

  // -- claims ---------------------------------------------------------------------------------------

  async claim(draft: ClaimDraft): Promise<SystemRecordAdmitResult> {
    const actor = await this.resolveActor(draft.actor);
    await this.requireRecord(WORK_CONTRACTS.frontierItem, draft.frontier_item_ref, "work_frontier_item_unknown");
    const record = {
      schema_version: "ioi.applications.ioi-ai.work-claim.v4",
      work_claim_id: draft.work_claim_id,
      orchestration_ref: this.orchestration.scope_ref,
      frontier_item_ref: draft.frontier_item_ref,
      claimant_ref: draft.claimant_ref,
      participation_ref: actor.participation_ref,
      delegation_ref: actor.delegation_ref,
      eligibility_match_receipt_ref: null,
      task_offer_ref: null,
      task_acceptance_ref: null,
      routing_decision_ref: null,
      collaboration_terms_ref: draft.collaboration_terms_ref,
      collaboration_terms_root: draft.collaboration_terms_root,
      terms_acceptance_ref: draft.terms_acceptance_ref,
      contribution_policy_ref: draft.contribution_policy_ref,
      quote_ref: null,
      budget_reservation_ref: null,
      settlement_profile_ref: draft.settlement_profile_ref,
      bounded_scope_ref: draft.bounded_scope_ref,
      context_lease_refs: draft.context_lease_refs ?? [],
      authority_resource_compute_data_budget_and_tool_lease_refs: draft.authority_resource_compute_data_budget_and_tool_lease_refs ?? [],
      duplicate_work_policy: draft.duplicate_work_policy,
      issued_at: draft.issued_at ?? this.now(),
      expires_at: draft.expires_at,
      heartbeat_ref: null,
      renewal_count: 0,
      release_or_reassignment_reason: null,
      status: "active",
    };
    return this.orchestration.record({ contract_id: WORK_CONTRACTS.claim, object_id: draft.work_claim_id, record, expected_head: null });
  }

  // -- attempts -------------------------------------------------------------------------------------

  async attempt(draft: { attempt_id: string; actor: Actor; participant_ref: string; work_subject_ref: string; frontier_item_ref: string; work_claim_ref: string; goal_run_ref?: string | null; base: Record<string, unknown> }): Promise<SystemRecordAdmitResult> {
    const actor = await this.resolveActor(draft.actor);
    const item = await this.requireRecord(WORK_CONTRACTS.frontierItem, draft.frontier_item_ref, "work_frontier_item_unknown");
    const claim = await this.requireRecord(WORK_CONTRACTS.claim, draft.work_claim_ref, "work_claim_unknown");
    const claimRecord = claim.current as Record<string, unknown>;
    if (!Work.sameActor(claimRecord, actor)) throw new WorkRefusal("work_attempt_claim_not_held_by_actor", "an attempt is made under a claim its own actor holds", { claim_actor: { participation_ref: claimRecord.participation_ref, delegation_ref: claimRecord.delegation_ref } });
    if (claimRecord.status !== "active") throw new WorkRefusal("work_claim_not_active", `claim ${draft.work_claim_ref} is ${String(claimRecord.status)}`);
    const record = {
      ...draft.base,
      schema_version: "ioi.applications.ioi-ai.attempt.v4",
      attempt_id: draft.attempt_id,
      orchestration_ref: this.orchestration.scope_ref,
      work_subject_ref: draft.work_subject_ref,
      goal_run_ref: draft.goal_run_ref ?? null,
      frontier_item_ref: draft.frontier_item_ref,
      work_claim_ref: draft.work_claim_ref,
      participant_ref: draft.participant_ref,
      participation_ref: actor.participation_ref,
      delegation_ref: actor.delegation_ref,
      bound_coordinates: {
        goal_run: null,
        frontier_item: coordinateOf(item.current as Record<string, unknown>, draft.frontier_item_ref),
        work_claim: coordinateOf(claimRecord, draft.work_claim_ref),
      },
    };
    delete (record as Record<string, unknown>).system_binding;
    return this.orchestration.record({ contract_id: WORK_CONTRACTS.attempt, object_id: draft.attempt_id, record, expected_head: null });
  }

  // -- findings -------------------------------------------------------------------------------------

  async finding(draft: { finding_id: string; actor: Actor; attempt_ref: string; work_result_ref: string; participant_ref: string; proposed_by_ref: string; base: Record<string, unknown> }): Promise<SystemRecordAdmitResult> {
    const actor = await this.resolveActor(draft.actor);
    const attempt = await this.requireRecord(WORK_CONTRACTS.attempt, draft.attempt_ref, "work_attempt_unknown");
    const attemptRecord = attempt.current as Record<string, unknown>;
    if (!Work.sameActor(attemptRecord, actor)) throw new WorkRefusal("work_finding_actor_mismatch", "a finding is proposed by the actor of the attempt it reports", { attempt_actor: { participation_ref: attemptRecord.participation_ref, delegation_ref: attemptRecord.delegation_ref } });
    const record = {
      ...draft.base,
      schema_version: "ioi.applications.ioi-ai.finding.v4",
      finding_id: draft.finding_id,
      orchestration_ref: this.orchestration.scope_ref,
      attempt_ref: draft.attempt_ref,
      work_result_ref: draft.work_result_ref,
      participant_ref: draft.participant_ref,
      proposed_by_ref: draft.proposed_by_ref,
      participation_ref: actor.participation_ref,
      delegation_ref: actor.delegation_ref,
      bound_coordinates: { attempt: coordinateOf(attemptRecord, draft.attempt_ref), work_result: null },
    };
    delete (record as Record<string, unknown>).system_binding;
    return this.orchestration.record({ contract_id: WORK_CONTRACTS.finding, object_id: draft.finding_id, record, expected_head: null });
  }

  // -- challenges and offers ------------------------------------------------------------------------

  async challenge(draft: { verifier_challenge_id: string; actor: Actor; challenger_ref: string; challenged_ref: string; base: Record<string, unknown> }): Promise<SystemRecordAdmitResult> {
    const actor = await this.resolveActor(draft.actor);
    const challenged = (await this.readChain(WORK_CONTRACTS.finding, draft.challenged_ref)) ?? (await this.readChain(WORK_CONTRACTS.attempt, draft.challenged_ref));
    if (!challenged) throw new WorkRefusal("work_challenged_unknown", `no attempt or finding ${draft.challenged_ref} under this orchestration to challenge`);
    const record = { ...draft.base, schema_version: "ioi.applications.ioi-ai.verifier-challenge.v4", verifier_challenge_id: draft.verifier_challenge_id, orchestration_ref: this.orchestration.scope_ref, challenger_ref: draft.challenger_ref, challenged_ref: draft.challenged_ref, participation_ref: actor.participation_ref, delegation_ref: actor.delegation_ref };
    delete (record as Record<string, unknown>).system_binding;
    return this.orchestration.record({ contract_id: WORK_CONTRACTS.challenge, object_id: draft.verifier_challenge_id, record, expected_head: null });
  }

  async offer(kind: "resource" | "capability", draft: { id: string; actor: Actor; base: Record<string, unknown> }): Promise<SystemRecordAdmitResult> {
    const actor = await this.resolveActor(draft.actor);
    const contract = kind === "resource" ? WORK_CONTRACTS.resourceOffer : WORK_CONTRACTS.capabilityOffer;
    const idMember = kind === "resource" ? "resource_offer_id" : "capability_offer_id";
    const record = { ...draft.base, schema_version: kind === "resource" ? "ioi.applications.ioi-ai.resource-offer.v4" : "ioi.applications.ioi-ai.capability-offer.v4", [idMember]: draft.id, orchestration_ref: this.orchestration.scope_ref, participation_ref: actor.participation_ref, delegation_ref: actor.delegation_ref };
    delete (record as Record<string, unknown>).system_binding;
    return this.orchestration.record({ contract_id: contract, object_id: draft.id, record, expected_head: null });
  }

  // -- revisions ------------------------------------------------------------------------------------

  /** A status transition is a successor revision on the exact head, by the record's own actor. */
  async transition(contractId: string, objectId: string, patch: Record<string, unknown>, actor: Actor): Promise<SystemRecordAdmitResult> {
    const chain = await this.requireRecord(contractId, objectId, "work_record_unknown");
    const current = chain.current as Record<string, unknown>;
    if (!Work.sameActor(current, actor)) throw new WorkRefusal("work_transition_not_by_actor", "a work object is revised by its own actor");
    const { system_binding: _binding, ...rest } = current;
    return this.orchestration.record({ contract_id: contractId, object_id: objectId, record: { ...rest, ...patch }, expected_head: chain.head });
  }

  async read(contractId: string, objectId: string): Promise<SystemRecordChainResult> {
    return this.orchestration.recordChain(contractId, objectId);
  }
}

export { CollaborationRefusal };

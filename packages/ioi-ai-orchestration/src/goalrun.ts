/**
 * GoalRun composed over the orchestration (R-195, S5-3).
 *
 * WHAT THIS IS. The ioi.ai application's own GoalRun, as a record admitted under the bounded System
 * through the generic record seam — the same shape `work.ts` uses for the v4 work objects. It is
 * not a plane. The Hypervisor served a GoalRun family until 2026-09-18, when the owner ruled that
 * goal runs and outcome rooms are compositions over the daemon's thread orchestration primitives
 * rather than Hypervisor surfaces (R-192); every one of those routes is deleted and nothing here
 * calls one.
 *
 * WHAT IT IS COMPOSED FROM. The coordinating thread and its delegations are the kernel's, reached
 * through `Orchestration`. The delegation coordinate is `delegation://{thread_id}/{subagent_id}`,
 * which the daemon now mints as a typed edge on every spawn (R-194, S5-2a). The records are the
 * seam's. Nothing in this module holds a store.
 *
 * THE ONE RULE THIS MODULE EXISTS TO ENFORCE. A GoalRun's resolution fields — the profile revision
 * and its content hash, the resolved component set and its hash, the active skill set and its hash
 * — are NOT taken from the caller. They are read off the admitted
 * `goal-run-profile-resolution-receipt` and copied. A caller supplies the receipt ref and nothing
 * else about the resolution, so a GoalRun cannot claim a profile closure the receipt did not make.
 * That is unit M04.4's subject stated as code rather than as a hope: the receipt's own
 * `receipt_root` now recomputes over its closure by registered invariant (R-195 step 1), and this
 * composer refuses to admit a run whose resolution came from anywhere else.
 *
 * WHY IT IS ENFORCED HERE AND NOT BY A CONTRACT. The portable invariant language is single-record:
 * it can pin that a root recomputes over its OWN fields, and it cannot reach across two records to
 * say "this run's profile hash equals that receipt's". A cross-record obligation therefore belongs
 * to the composer, is refused here by name, and is proven by the gate — the same division
 * `work.ts` already uses for "the participation is accepted" and "the delegation is live".
 */

import type { Orchestration, SystemRecordAdmitResult, SystemRecordChainResult } from "@ioi/agent-sdk";

export const GOAL_RUN_CONTRACTS = {
  goalRun: "schema://ioi/applications/ioi-ai/goal-run/v2",
  activation: "schema://ioi/applications/ioi-ai/goal-run-activation/v2",
  activationReceipt: "schema://ioi/applications/ioi-ai/goal-run-activation-receipt/v2",
  admissionPathDecision: "schema://ioi/applications/ioi-ai/goal-run-admission-path-decision/v2",
  profile: "schema://ioi/applications/ioi-ai/goal-run-profile/v1",
  profileResolutionReceipt: "schema://ioi/applications/ioi-ai/goal-run-profile-resolution-receipt/v1",
  groundingLoop: "schema://ioi/applications/ioi-ai/goal-grounding-loop/v2",
  contextCell: "schema://ioi/applications/ioi-ai/context-cell/v2",
} as const;

export class GoalRunRefusal extends Error {
  readonly code: string;
  readonly detail: Record<string, unknown>;

  constructor(code: string, message: string, detail: Record<string, unknown> = {}) {
    super(message);
    this.name = "GoalRunRefusal";
    this.code = code;
    this.detail = detail;
  }
}

/** The closure a resolution receipt commits, as this composer reads it back off the admitted record. */
export interface ResolvedProfileClosure {
  receipt_ref: string;
  goal_run_profile_revision_ref: string;
  goal_run_profile_content_hash: string;
  resolved_component_set_snapshot_ref: string;
  resolved_component_set_hash: string;
  active_skill_set_snapshot_ref: string;
  active_skill_set_hash: string;
  unresolved_late_binding_requirement_refs: string[];
}

export interface GoalRunDraft {
  goal_run_id: string;
  goal_ref: string;
  owner_ref: string;
  /** The ONLY thing a caller says about the resolution. Everything else is read off it. */
  profile_resolution_receipt_ref: string;
  origin_surface:
    | "ioi_goal_chat"
    | "hypervisor_new_session"
    | "hypervisor_session"
    | "automation"
    | "marketplace_instance"
    | "api";
  normalized_goal: string;
  source_context_binding: { target_session_ref: string | null; project_ref: string | null };
  receipt_obligations: Array<Record<string, unknown>>;
  admitted_state_root_ref: string;
  authority_scope_refs: string[];
  /** Optional coordinates the run carries verbatim. */
  context_cell_refs?: string[];
  activation_ref?: string | null;
  grounding_loop_ref?: string | null;
  created_at?: string;
}

export class GoalRuns {
  readonly orchestration: Orchestration;
  private readonly now: () => string;

  constructor(orchestration: Orchestration, options: { now?: () => string } = {}) {
    this.orchestration = orchestration;
    this.now = options.now ?? (() => new Date().toISOString());
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

  /**
   * Read the profile closure off the ADMITTED receipt.
   *
   * Every field this returns is the receipt's, not the caller's. The receipt is served from the
   * seam under this orchestration, so a receipt admitted under a different composition is not
   * reachable here at all — the scope fence answers 403/404 and this reads as absent, which is the
   * refusal the caller gets. Its `receipt_root` recomputes over exactly these fields plus the rest
   * of the closure by registered invariant, so a served receipt that was edited after admission
   * fails at the seam before it reaches this function.
   */
  async resolveProfileClosure(receiptRef: string): Promise<ResolvedProfileClosure> {
    if (!/^receipt:\/\/[^\s]+$/u.test(receiptRef)) {
      throw new GoalRunRefusal(
        "goal_run_profile_resolution_receipt_ref_malformed",
        "a profile-resolution receipt ref is receipt://…",
        { receipt_ref: receiptRef },
      );
    }
    const chain = await this.readChain(GOAL_RUN_CONTRACTS.profileResolutionReceipt, receiptRef);
    if (!chain) {
      throw new GoalRunRefusal(
        "goal_run_profile_resolution_receipt_unknown",
        `no profile-resolution receipt ${receiptRef} under this orchestration`,
        { receipt_ref: receiptRef },
      );
    }
    const receipt = chain.current as Record<string, unknown>;
    const required = [
      "goal_run_profile_revision_ref",
      "goal_run_profile_content_hash",
      "resolved_component_set_snapshot_ref",
      "resolved_component_set_hash",
      "active_skill_set_snapshot_ref",
      "active_skill_set_hash",
    ] as const;
    for (const field of required) {
      if (typeof receipt[field] !== "string" || (receipt[field] as string).length === 0) {
        throw new GoalRunRefusal(
          "goal_run_profile_closure_incomplete",
          `the resolution receipt carries no ${field}; a run may not fill in a closure member the receipt left out`,
          { receipt_ref: receiptRef, field },
        );
      }
    }
    return {
      receipt_ref: receiptRef,
      goal_run_profile_revision_ref: receipt.goal_run_profile_revision_ref as string,
      goal_run_profile_content_hash: receipt.goal_run_profile_content_hash as string,
      resolved_component_set_snapshot_ref: receipt.resolved_component_set_snapshot_ref as string,
      resolved_component_set_hash: receipt.resolved_component_set_hash as string,
      active_skill_set_snapshot_ref: receipt.active_skill_set_snapshot_ref as string,
      active_skill_set_hash: receipt.active_skill_set_hash as string,
      unresolved_late_binding_requirement_refs: Array.isArray(receipt.unresolved_late_binding_requirement_refs)
        ? (receipt.unresolved_late_binding_requirement_refs as string[])
        : [],
    };
  }

  /**
   * Admit one GoalRun as a record of this orchestration.
   *
   * The run is admitted in `draft` with `continuation_state: "open"`: admission records that a
   * bounded pursuit exists and resolves from a committed closure. It does not start anything, and
   * this composer mints no session, thread or invocation — those are the kernel's primitives,
   * reached through the orchestration's own delegation verb.
   */
  async admit(draft: GoalRunDraft): Promise<SystemRecordAdmitResult> {
    if (!/^goal:\/\/[^\s]+$/u.test(draft.goal_ref)) {
      throw new GoalRunRefusal("goal_run_ref_malformed", "a goal ref is goal://…", { goal_ref: draft.goal_ref });
    }
    const existing = await this.readChain(GOAL_RUN_CONTRACTS.goalRun, draft.goal_run_id);
    if (existing) {
      throw new GoalRunRefusal(
        "goal_run_already_admitted",
        `goal run ${draft.goal_run_id} is already admitted under this orchestration`,
        { goal_run_id: draft.goal_run_id },
      );
    }
    const closure = await this.resolveProfileClosure(draft.profile_resolution_receipt_ref);
    const now = draft.created_at ?? this.now();
    const record = {
      // The registered const, which is the SHORT form. This family spells its schema_version
      // inconsistently — `goal-run/v2` is `ioi.goal-run.v2` while
      // `goal-run-admission-path-decision/v2` is `ioi.applications.ioi-ai.goal-run-admission-path-decision.v2`
      // — so it is never inferred from the contract id here. The member-set test pins this value
      // against the schema, and it caught the long form on the first run.
      schema_version: "ioi.goal-run.v2",
      goal_run_id: draft.goal_run_id,
      goal_ref: draft.goal_ref,
      owner_ref: draft.owner_ref,
      orchestration_ref: this.orchestration.scope_ref,
      // COPIED FROM THE RECEIPT, never from the caller. This is the rule the module exists for.
      goal_run_profile_revision_ref: closure.goal_run_profile_revision_ref,
      goal_run_profile_content_hash: closure.goal_run_profile_content_hash,
      resolved_component_set_snapshot_ref: closure.resolved_component_set_snapshot_ref,
      resolved_component_set_hash: closure.resolved_component_set_hash,
      active_skill_set_snapshot_ref: closure.active_skill_set_snapshot_ref,
      active_skill_set_hash: closure.active_skill_set_hash,
      goal_run_profile_resolution_receipt_ref: closure.receipt_ref,
      origin_surface: draft.origin_surface,
      normalized_goal: draft.normalized_goal,
      source_context_binding: {
        target_session_ref: draft.source_context_binding.target_session_ref,
        project_ref: draft.source_context_binding.project_ref,
      },
      receipt_obligations: draft.receipt_obligations,
      admitted_state_root_ref: draft.admitted_state_root_ref,
      authority_scope_refs: draft.authority_scope_refs,
      context_cell_refs: draft.context_cell_refs ?? [],
      activation_ref: draft.activation_ref ?? null,
      grounding_loop_ref: draft.grounding_loop_ref ?? null,
      created_at: now,
      updated_at: now,
      continuation_state: "open",
      status: "draft",
    };
    return this.orchestration.record({
      contract_id: GOAL_RUN_CONTRACTS.goalRun,
      object_id: draft.goal_run_id,
      record,
      expected_head: null,
    });
  }

  /** The admitted run, as the seam serves it. */
  async read(goalRunId: string): Promise<SystemRecordChainResult | null> {
    return this.readChain(GOAL_RUN_CONTRACTS.goalRun, goalRunId);
  }
}

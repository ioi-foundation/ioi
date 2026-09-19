/**
 * The context family composed over the orchestration (R-202, S5-3 unit M04.11).
 *
 * WHAT THIS IS. ioi.ai's ContextCell, ContextLease and ContextHandoff, admitted as records under the
 * bounded System through the generic record seam — the shape `goalrun.ts` and `work.ts` use. It is
 * not a plane: the daemon's context routes were deleted with the GoalRun plane on 2026-09-18
 * (R-192, S5-1) and nothing here calls one. Every byte lives in the Hypervisor; this module holds
 * no store.
 *
 * THE RULES THIS MODULE EXISTS TO ENFORCE are the ones the portable invariant language cannot: it
 * is single-record, so it pins each lease's and handoff's `receipt_root` over its own members and
 * can say nothing that spans two records. Everything that does span two records is refused HERE,
 * by name, before any write:
 *
 *   subject → cell     the cell's work subject is a GoalRun this orchestration admitted;
 *                      the composition coordinate is stamped, never authored;
 *   cell → lease       a lease is issued to a cell that exists here, on that cell's subject, to a
 *                      role the lease permits, over view REVISIONS the daemon serves;
 *   lease → successor  narrowing is SUBTRACTION — refs, patterns, scopes, labels and roles only
 *                      shrink, denials only grow, a ttl never lengthens or becomes unbounded, a
 *                      terminal lease admits no successor and resolves nothing;
 *   cell → successor   a cell never rewrites its subject, and names only live leases issued to it;
 *   handoff            two distinct cells on one subject; every travelling lease live and
 *                      permitted for the RECEIVER's role at send; only `sent` is ever decided, once;
 *                      acceptance is a CANDIDATE under the receiver's policy that copies no lease
 *                      and re-asserts every non-grant.
 *
 * `receipt_root` is COMPUTED here over canon's preimage — the draft has no field for it — so a
 * lease or handoff cannot present a root over members it did not carry. The registered invariant
 * recomputes the same preimage at the seam; the gate re-derives it a third time, independently.
 *
 * NOT CLAIMED, stated in the refusals rather than left implicit: a topology-bound cell (canon: six
 * axes "must equal that exact topology role") cannot be checked here because no RoleTopology
 * revision is a record under the seam, so such a cell is REFUSED rather than trusted; a lease
 * issued to a `harness-invocation://` is refused for the same reason; and acceptance requiring
 * declassification is not evaluated here — the `DeclassificationApproval` object has no record
 * under the seam to check against — so acceptance neither claims nor grants it.
 */

import { createHash } from "node:crypto";
import type { Orchestration, SystemRecordAdmitResult, SystemRecordChainResult } from "@ioi/agent-sdk";

export const CONTEXT_CONTRACTS = {
  cell: "schema://ioi/applications/ioi-ai/context-cell/v2",
  lease: "schema://ioi/applications/ioi-ai/context-lease/v1",
  handoff: "schema://ioi/applications/ioi-ai/context-handoff/v1",
  goalRun: "schema://ioi/applications/ioi-ai/goal-run/v2",
} as const;

/** The registered consts — never inferred from the contract id (this family spells them short). */
export const CONTEXT_SCHEMA_VERSIONS = {
  cell: "ioi.context-cell.v2",
  lease: "ioi.context-lease.v1",
  handoff: "ioi.context-handoff.v1",
} as const;

/**
 * Canon's preimages, in the registered invariants' member order: every field of the block except
 * `receipt_root` and the seam-derived `system_binding`. The wire member `schema_version` is not a
 * field of the block (R-199).
 */
export const LEASE_ROOT_MEMBERS = [
  "context_lease_id",
  "work_subject_ref",
  "context_cell_ref",
  "issued_to_ref",
  "lease_kind",
  "allowed_ref_patterns",
  "denied_ref_patterns",
  "authority_scope_refs",
  "budget_ref",
  "ttl_seconds",
  "receipt_required",
  "leased_refs",
  "information_flow_label_refs",
  "permitted_recipient_roles",
  "successor_of",
  "predecessor_remains_valid",
  "status",
] as const;

export const HANDOFF_ROOT_MEMBERS = [
  "handoff_id",
  "work_subject_ref",
  "from_context_cell_ref",
  "to_context_cell_ref",
  "handoff_kind",
  "payload_ref",
  "context_lease_refs",
  "acceptance_refs",
  "receipt_refs",
  "non_grants",
  "successor_of",
  "status",
] as const;

export const CELL_ROLES = [
  "conductor",
  "implementer",
  "reviewer",
  "verifier",
  "operator",
  "researcher",
  "specialist",
  "synthesizer",
  "resource_provider",
  "integrity_challenger",
  "memory_curator",
] as const;
export type CellRole = (typeof CELL_ROLES)[number];

export const LEASE_KINDS = [
  "canon",
  "repo_slice",
  "worktree",
  "memory_projection",
  "tool",
  "connector",
  "runtime",
  "authority",
  "budget",
  "surface",
  "receipt_view",
  "mixed",
] as const;
export type LeaseKind = (typeof LEASE_KINDS)[number];

export const HANDOFF_KINDS = [
  "task_brief",
  "implementation_result",
  "blocker",
  "diff_summary",
  "test_result",
  "review_request",
  "verification_result",
  "attempt_result",
  "finding",
  "resource_request",
  "capability_offer",
  "frontier_update",
  "verifier_challenge",
  "decision_request",
  "continuation_summary",
] as const;
export type HandoffKind = (typeof HANDOFF_KINDS)[number];

export const CELL_STATUSES = ["open", "active", "sleeping", "waiting", "handed_off", "summarized", "quarantined", "closed", "revoked"] as const;
export const LEASE_TERMINAL_STATUSES = new Set(["expired", "revoked", "consumed"]);

/** The five non-grants a handoff carries, all `none`, always — canon's constant block. */
export const HANDOFF_NON_GRANTS = Object.freeze({
  authority_widening: "none",
  context_declassification: "none",
  executable_state_transfer: "none",
  budget_creation: "none",
  receiver_policy_bypass: "none",
});

export class ContextRefusal extends Error {
  readonly code: string;
  readonly detail: Record<string, unknown>;

  constructor(code: string, message: string, detail: Record<string, unknown> = {}) {
    super(message);
    this.name = "ContextRefusal";
    this.code = code;
    this.detail = detail;
  }
}

// ---- the preimage, canonicalised exactly as the registered invariant canonicalises it ----------

function canonical(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${canonical(record[k])}`)
    .join(",")}}`;
}

/** SHA-256 over the canonical JSON of exactly `members` of `record`, as `sha256:<hex>`. */
export function receiptRootOf(record: Record<string, unknown>, members: readonly string[]): string {
  const material: Record<string, unknown> = {};
  for (const member of members) {
    if (!(member in record)) {
      throw new ContextRefusal("context_root_member_absent", `the preimage member ${member} is absent`, { member });
    }
    material[member] = record[member];
  }
  return `sha256:${createHash("sha256").update(canonical(material)).digest("hex")}`;
}

// ---- refs ---------------------------------------------------------------------------------------

const CELL_REF = /^context-cell:\/\/\S+$/u;
const LEASE_REF = /^context-lease:\/\/\S+$/u;
const HANDOFF_REF = /^handoff:\/\/\S+$/u;
const VIEW_REVISION_REF = /^view:\/\/(\S+?)\/revision\/(\d+)$/u;
const SUBJECT_REF = /^(?:goal|automation-run|work-run|run|invocation|harness-invocation|task|frontier|work-claim|attempt):\/\/\S+$/u;

/** A `view://<family>/revision/<n>` entry, parsed; anything else is not a leasable revision. */
export function parseViewRevisionRef(ref: string): { family: string; revision: number } | null {
  const m = VIEW_REVISION_REF.exec(ref);
  return m ? { family: m[1], revision: Number(m[2]) } : null;
}

function subset<T>(after: readonly T[], before: readonly T[]): boolean {
  const have = new Set(before);
  return after.every((x) => have.has(x));
}

// ---- the view reader the resolution folds through -----------------------------------------------

/**
 * The reader for `view://` revisions: the SDK's `PolicyBoundDataViewClient.query` has this shape,
 * and the composer takes the READER rather than the client so a test can hand it admitted views
 * without a daemon. A resolution is read under the caller's own identity; nothing here widens it.
 */
export interface ViewRevisionReader {
  query(input: { family: string; revision: number }): Promise<unknown>;
}

// ---- drafts -------------------------------------------------------------------------------------

export interface ContextCellDraft {
  context_cell_id: string;
  work_subject_ref: string;
  role_topology_revision_ref: string | null;
  role_binding_id: string;
  accountable_actor_ref: string;
  role: CellRole;
  resolver_revision_ref: string | null;
  resolver_content_hash: string | null;
  model_route_ref: string | null;
  memory_projection_refs: string[];
  information_flow_label_refs: string[];
  active_runtime_assignment_ref: string | null;
  authority_scope_refs: string[];
  compression_policy_ref: string | null;
  current_claim_ref: string | null;
  next_wake_condition_ref: string | null;
  /** The delegation this cell acts through, when it is a delegate of the coordinating thread. */
  delegation_ref?: string | null;
}

export interface ContextCellSuccessor {
  status?: (typeof CELL_STATUSES)[number];
  context_lease_refs?: string[];
  current_claim_ref?: string | null;
  next_wake_condition_ref?: string | null;
  memory_projection_refs?: string[];
  information_flow_label_refs?: string[];
}

export interface ContextLeaseDraft {
  context_lease_id: string;
  issued_to_ref: string;
  /** Optional: when present it must be the holding cell itself. */
  context_cell_ref?: string | null;
  lease_kind: LeaseKind;
  allowed_ref_patterns: string[];
  denied_ref_patterns: string[];
  authority_scope_refs: string[];
  budget_ref: string | null;
  ttl_seconds: number | null;
  receipt_required: boolean;
  leased_refs: string[];
  information_flow_label_refs: string[];
  permitted_recipient_roles: CellRole[];
}

export interface ContextLeaseNarrowing {
  context_lease_id: string;
  predecessor_remains_valid: boolean;
  allowed_ref_patterns?: string[];
  denied_ref_patterns?: string[];
  authority_scope_refs?: string[];
  ttl_seconds?: number | null;
  leased_refs?: string[];
  information_flow_label_refs?: string[];
  permitted_recipient_roles?: CellRole[];
}

export interface ContextHandoffDraft {
  handoff_id: string;
  from_context_cell_ref: string;
  to_context_cell_ref: string;
  handoff_kind: HandoffKind;
  payload_ref: string | null;
  context_lease_refs: string[];
  acceptance_refs: string[];
  receipt_refs: string[];
}

/** What a resolution says: the read model, rebuilt on every call, persisting nothing. */
export interface LeastContextResolution {
  nature: "read_model";
  context_lease_id: string;
  status: string;
  /** The dimensions this resolution INHERITS from the bound view revisions and labels — it restates none of them. */
  inherited_dimensions: readonly string[];
  bound_view_revisions: Array<{ ref: string; family: string; revision: number }>;
  /** Purposes every bound view supports — an intersection, so two views with different purposes permit none. */
  permitted_purposes: string[];
  /** Data classes any bound view exposes, each already fenced by that view's own posture. */
  exposed_data_classes: string[];
  denied_ref_patterns: string[];
  information_flow_label_refs: string[];
  permitted_recipient_roles: string[];
  /** Present when the lease binds no view: nothing was implied, and this says so. */
  reason: string | null;
}

// ---- shared reading ----------------------------------------------------------------------------

async function readChain(orchestration: Orchestration, contractId: string, objectId: string): Promise<SystemRecordChainResult | null> {
  try {
    const chain = await orchestration.recordChain(contractId, objectId);
    return chain.current ? chain : null;
  } catch (error) {
    const status = (error as { status?: number })?.status;
    // The seam's scope fence answers 403/404 for a record under another composition or tenant;
    // that reads here as ABSENT, which is the refusal the caller gets.
    if (status === 403 || status === 404) return null;
    throw error;
  }
}

async function requireCell(orchestration: Orchestration, cellRef: string, what: string): Promise<Record<string, unknown>> {
  if (!CELL_REF.test(cellRef)) {
    throw new ContextRefusal("context_cell_ref_malformed", `${what} names a cell as context-cell://…`, { ref: cellRef });
  }
  const chain = await readChain(orchestration, CONTEXT_CONTRACTS.cell, cellRef);
  if (!chain) {
    throw new ContextRefusal("context_cell_unknown", `${what}: no context cell ${cellRef} under this orchestration`, { ref: cellRef });
  }
  return chain.current as Record<string, unknown>;
}

async function requireLease(orchestration: Orchestration, leaseRef: string, what: string): Promise<Record<string, unknown>> {
  if (!LEASE_REF.test(leaseRef)) {
    throw new ContextRefusal("context_lease_ref_malformed", `${what} names a lease as context-lease://…`, { ref: leaseRef });
  }
  const chain = await readChain(orchestration, CONTEXT_CONTRACTS.lease, leaseRef);
  if (!chain) {
    throw new ContextRefusal("context_lease_unknown", `${what}: no context lease ${leaseRef} under this orchestration`, { ref: leaseRef });
  }
  return chain.current as Record<string, unknown>;
}

function leaseIsLive(lease: Record<string, unknown>): boolean {
  return !LEASE_TERMINAL_STATUSES.has(String(lease.status));
}

/** A lease the cell at `cellRef` may carry: exists here, same subject, issued to that cell, live. */
async function requireLeaseHeldBy(orchestration: Orchestration, leaseRef: string, cell: Record<string, unknown>, cellRef: string, what: string): Promise<Record<string, unknown>> {
  const lease = await requireLease(orchestration, leaseRef, what);
  if (lease.work_subject_ref !== cell.work_subject_ref) {
    throw new ContextRefusal("context_lease_subject_mismatch", `${what}: lease ${leaseRef} binds ${String(lease.work_subject_ref)}, the cell binds ${String(cell.work_subject_ref)}`, { lease: leaseRef, cell: cellRef });
  }
  if (lease.issued_to_ref !== cellRef) {
    throw new ContextRefusal("context_lease_not_issued_to_cell", `${what}: lease ${leaseRef} was issued to ${String(lease.issued_to_ref)}, not to ${cellRef}`, { lease: leaseRef, cell: cellRef });
  }
  if (!leaseIsLive(lease)) {
    throw new ContextRefusal("context_lease_terminal", `${what}: lease ${leaseRef} is ${String(lease.status)}; a terminal lease is held by nobody`, { lease: leaseRef, status: lease.status });
  }
  return lease;
}

// ---- cells --------------------------------------------------------------------------------------

export class ContextCells {
  readonly orchestration: Orchestration;

  constructor(orchestration: Orchestration) {
    this.orchestration = orchestration;
  }

  /** The GoalRun this orchestration admitted for `subjectRef`, or null. A subject nobody admitted is not a subject. */
  private async admittedRunFor(subjectRef: string): Promise<Record<string, unknown> | null> {
    const listed = await this.orchestration.records(CONTEXT_CONTRACTS.goalRun);
    for (const entry of listed.records) {
      const run = entry.current;
      if (run && run.goal_ref === subjectRef) return run;
    }
    return null;
  }

  async admit(draft: ContextCellDraft): Promise<SystemRecordAdmitResult> {
    if (!CELL_REF.test(draft.context_cell_id)) {
      throw new ContextRefusal("context_cell_ref_malformed", "a context cell id is context-cell://…", { ref: draft.context_cell_id });
    }
    if (!SUBJECT_REF.test(draft.work_subject_ref)) {
      throw new ContextRefusal("context_subject_ref_malformed", "a work subject is a canonical subject ref", { ref: draft.work_subject_ref });
    }
    if (!CELL_ROLES.includes(draft.role)) {
      throw new ContextRefusal("context_cell_role_unrecognized", `${String(draft.role)} is not a cell role`, { role: draft.role });
    }
    const existing = await readChain(this.orchestration, CONTEXT_CONTRACTS.cell, draft.context_cell_id);
    if (existing) {
      throw new ContextRefusal("context_cell_already_admitted", `context cell ${draft.context_cell_id} is already admitted under this orchestration`, { ref: draft.context_cell_id });
    }
    // subject → cell: the subject is a GoalRun THIS orchestration admitted — read off the seam, not the caller.
    const run = await this.admittedRunFor(draft.work_subject_ref);
    if (!run) {
      throw new ContextRefusal("context_subject_unadmitted", `no GoalRun for ${draft.work_subject_ref} is admitted under this orchestration; a cell binds an admitted subject`, { subject: draft.work_subject_ref });
    }
    // A topology-bound cell's six axes must equal the exact topology role, and no RoleTopology
    // revision is a record under the seam to check them against. Refused, not trusted.
    if (draft.role_topology_revision_ref !== null) {
      throw new ContextRefusal("context_cell_topology_binding_unverifiable", "a topology-bound cell cannot be admitted here: no RoleTopology revision is a record under this orchestration to check its role-binding axes against", { role_topology_revision_ref: draft.role_topology_revision_ref });
    }
    const record: Record<string, unknown> = {
      schema_version: CONTEXT_SCHEMA_VERSIONS.cell,
      context_cell_id: draft.context_cell_id,
      work_subject_ref: draft.work_subject_ref,
      role_topology_revision_ref: null,
      role_binding_id: draft.role_binding_id,
      accountable_actor_ref: draft.accountable_actor_ref,
      role: draft.role,
      resolver_revision_ref: draft.resolver_revision_ref,
      resolver_content_hash: draft.resolver_content_hash,
      model_route_ref: draft.model_route_ref,
      memory_projection_refs: [...draft.memory_projection_refs],
      // A lease is issued TO a cell, so no lease can precede the cell it is issued to; leases arrive on successors.
      context_lease_refs: [],
      information_flow_label_refs: [...draft.information_flow_label_refs],
      active_runtime_assignment_ref: draft.active_runtime_assignment_ref,
      authority_scope_refs: [...draft.authority_scope_refs],
      compression_policy_ref: draft.compression_policy_ref,
      current_claim_ref: draft.current_claim_ref,
      next_wake_condition_ref: draft.next_wake_condition_ref,
      status: "open",
      // STAMPED, never authored: the cell is a member of this composition and no other.
      orchestration_ref: this.orchestration.scope_ref,
      delegation_ref: draft.delegation_ref ?? null,
    };
    return this.orchestration.record({ contract_id: CONTEXT_CONTRACTS.cell, object_id: draft.context_cell_id, record, expected_head: null });
  }

  /**
   * A successor at the predecessor's EXACT head, on the cell's own identity. Canon gives the cell
   * no `successor_of`; the seam's compare-and-swap is the only succession it has.
   */
  async succeed(cellRef: string, patch: ContextCellSuccessor): Promise<SystemRecordAdmitResult> {
    const chain = await readChain(this.orchestration, CONTEXT_CONTRACTS.cell, cellRef);
    if (!chain) throw new ContextRefusal("context_cell_unknown", `no context cell ${cellRef} under this orchestration`, { ref: cellRef });
    const current = chain.current as Record<string, unknown>;
    if ("work_subject_ref" in patch || "orchestration_ref" in patch || "role_topology_revision_ref" in patch) {
      throw new ContextRefusal("context_cell_subject_rewritten", "a cell successor may not rewrite its work subject, its composition coordinate or its topology binding", { ref: cellRef });
    }
    if (patch.status !== undefined && !CELL_STATUSES.includes(patch.status)) {
      throw new ContextRefusal("context_cell_status_unrecognized", `${String(patch.status)} is not a cell status`, { status: patch.status });
    }
    if (patch.context_lease_refs) {
      for (const leaseRef of patch.context_lease_refs) {
        await requireLeaseHeldBy(this.orchestration, leaseRef, current, cellRef, "a cell successor");
      }
    }
    const { system_binding: _binding, ...rest } = current;
    const record = { ...rest, ...patch };
    return this.orchestration.record({ contract_id: CONTEXT_CONTRACTS.cell, object_id: cellRef, record, expected_head: chain.head });
  }

  async read(cellRef: string): Promise<SystemRecordChainResult | null> {
    return readChain(this.orchestration, CONTEXT_CONTRACTS.cell, cellRef);
  }
}

// ---- leases -------------------------------------------------------------------------------------

export class ContextLeases {
  readonly orchestration: Orchestration;
  private readonly views: ViewRevisionReader | null;

  constructor(orchestration: Orchestration, options: { views?: ViewRevisionReader } = {}) {
    this.orchestration = orchestration;
    this.views = options.views ?? null;
  }

  /** Every `view://` entry must be an admitted revision the daemon serves — a grammar cannot know whether a well-formed revision exists. */
  private async requireViewRevisions(leasedRefs: readonly string[], what: string): Promise<Array<{ ref: string; family: string; revision: number; view: unknown }>> {
    const bound: Array<{ ref: string; family: string; revision: number; view: unknown }> = [];
    for (const ref of leasedRefs) {
      if (!ref.startsWith("view://")) continue;
      const parsed = parseViewRevisionRef(ref);
      if (!parsed) {
        throw new ContextRefusal("context_lease_view_not_a_revision", `${what}: ${ref} is not a view REVISION (view://<family>/revision/<n>); a lease over a moving head cannot reproduce its least-context view`, { ref });
      }
      if (!this.views) {
        throw new ContextRefusal("context_lease_view_reader_required", `${what}: this composer has no view reader, so it cannot know whether ${ref} is an admitted revision — and it will not assume`, { ref });
      }
      let view: unknown;
      try {
        view = await this.views.query({ family: parsed.family, revision: parsed.revision });
      } catch (error) {
        throw new ContextRefusal("context_lease_view_unresolved", `${what}: ${ref} is not served as an admitted revision under the caller's identity`, { ref, reason: String((error as Error)?.message ?? error) });
      }
      if (view === null || typeof view !== "object") {
        throw new ContextRefusal("context_lease_view_unresolved", `${what}: ${ref} resolved to nothing`, { ref });
      }
      bound.push({ ref, family: parsed.family, revision: parsed.revision, view });
    }
    return bound;
  }

  async issue(draft: ContextLeaseDraft): Promise<SystemRecordAdmitResult> {
    if (!LEASE_REF.test(draft.context_lease_id)) {
      throw new ContextRefusal("context_lease_ref_malformed", "a context lease id is context-lease://…", { ref: draft.context_lease_id });
    }
    if (!LEASE_KINDS.includes(draft.lease_kind)) {
      throw new ContextRefusal("context_lease_kind_unrecognized", `${String(draft.lease_kind)} is not a lease kind`, { lease_kind: draft.lease_kind });
    }
    const existing = await readChain(this.orchestration, CONTEXT_CONTRACTS.lease, draft.context_lease_id);
    if (existing) {
      throw new ContextRefusal("context_lease_already_issued", `context lease ${draft.context_lease_id} is already issued under this orchestration`, { ref: draft.context_lease_id });
    }
    // cell → lease: issued to a cell that exists HERE; a harness-invocation is not a record under the seam.
    if (draft.issued_to_ref.startsWith("harness-invocation://")) {
      throw new ContextRefusal("context_lease_issued_to_unverifiable", "a lease issued to a harness invocation cannot be checked here: no invocation is a record under this orchestration", { issued_to_ref: draft.issued_to_ref });
    }
    const holder = await requireCell(this.orchestration, draft.issued_to_ref, "a lease's holder");
    const cellRef = draft.context_cell_ref ?? null;
    if (cellRef !== null && cellRef !== draft.issued_to_ref) {
      throw new ContextRefusal("context_lease_cell_not_the_holder", `context_cell_ref ${cellRef} is not the cell the lease is issued to (${draft.issued_to_ref})`, { context_cell_ref: cellRef, issued_to_ref: draft.issued_to_ref });
    }
    // the one dimension the lease owns: which cell ROLE may hold it — and the holder's role must be one of them
    if (draft.permitted_recipient_roles.length === 0 || !draft.permitted_recipient_roles.includes(holder.role as CellRole)) {
      throw new ContextRefusal("context_lease_holder_role_not_permitted", `the holder ${draft.issued_to_ref} has role ${String(holder.role)}, which the lease's permitted_recipient_roles do not include`, { role: holder.role, permitted_recipient_roles: draft.permitted_recipient_roles });
    }
    if (draft.ttl_seconds !== null && !(Number.isInteger(draft.ttl_seconds) && draft.ttl_seconds >= 1)) {
      throw new ContextRefusal("context_lease_ttl_invalid", "ttl_seconds is a positive integer or null", { ttl_seconds: draft.ttl_seconds });
    }
    await this.requireViewRevisions(draft.leased_refs, "a lease");
    const record: Record<string, unknown> = {
      schema_version: CONTEXT_SCHEMA_VERSIONS.lease,
      context_lease_id: draft.context_lease_id,
      // the subject is the HOLDER's, read off the cell — a lease cannot name a subject its cell does not bind
      work_subject_ref: holder.work_subject_ref,
      context_cell_ref: cellRef,
      issued_to_ref: draft.issued_to_ref,
      lease_kind: draft.lease_kind,
      allowed_ref_patterns: [...draft.allowed_ref_patterns],
      denied_ref_patterns: [...draft.denied_ref_patterns],
      authority_scope_refs: [...draft.authority_scope_refs],
      budget_ref: draft.budget_ref,
      ttl_seconds: draft.ttl_seconds,
      receipt_required: draft.receipt_required,
      leased_refs: [...draft.leased_refs],
      information_flow_label_refs: [...draft.information_flow_label_refs],
      permitted_recipient_roles: [...draft.permitted_recipient_roles],
      successor_of: null,
      predecessor_remains_valid: false,
      status: "active",
    };
    record.receipt_root = receiptRootOf(record, LEASE_ROOT_MEMBERS);
    return this.orchestration.record({ contract_id: CONTEXT_CONTRACTS.lease, object_id: draft.context_lease_id, record, expected_head: null });
  }

  /**
   * Narrowing is SUBTRACTION: a successor lease that only shrinks what its predecessor granted.
   * Widening any member is a NEW binding on record, never a successor of this one — refused by
   * the member's own name.
   */
  async narrow(predecessorRef: string, narrowing: ContextLeaseNarrowing): Promise<SystemRecordAdmitResult> {
    const prior = await requireLease(this.orchestration, predecessorRef, "a narrowing");
    if (!leaseIsLive(prior)) {
      throw new ContextRefusal("context_lease_terminal", `lease ${predecessorRef} is ${String(prior.status)}; a terminal lease admits no successor`, { ref: predecessorRef, status: prior.status });
    }
    if (!LEASE_REF.test(narrowing.context_lease_id)) {
      throw new ContextRefusal("context_lease_ref_malformed", "a successor lease id is context-lease://…", { ref: narrowing.context_lease_id });
    }
    const existing = await readChain(this.orchestration, CONTEXT_CONTRACTS.lease, narrowing.context_lease_id);
    if (existing) {
      throw new ContextRefusal("context_lease_already_issued", `context lease ${narrowing.context_lease_id} is already issued under this orchestration`, { ref: narrowing.context_lease_id });
    }
    const shrinkOnly: Array<[keyof ContextLeaseNarrowing & string, string]> = [
      ["leased_refs", "context_lease_leased_refs_widened"],
      ["allowed_ref_patterns", "context_lease_allowed_patterns_widened"],
      ["authority_scope_refs", "context_lease_authority_scopes_widened"],
      ["information_flow_label_refs", "context_lease_labels_widened"],
      ["permitted_recipient_roles", "context_lease_recipient_roles_widened"],
    ];
    const next: Record<string, unknown> = {};
    for (const [member, code] of shrinkOnly) {
      const proposed = narrowing[member] as string[] | undefined;
      const before = prior[member] as string[];
      if (proposed === undefined) { next[member] = [...before]; continue; }
      if (!subset(proposed, before)) {
        throw new ContextRefusal(code, `${member} may only shrink through a narrowing; widening is a new binding on record`, { member, added: proposed.filter((x) => !before.includes(x)) });
      }
      next[member] = [...proposed];
    }
    {
      const before = prior.denied_ref_patterns as string[];
      const proposed = narrowing.denied_ref_patterns ?? before;
      if (!subset(before, proposed)) {
        throw new ContextRefusal("context_lease_denial_dropped", "denied_ref_patterns may only grow through a narrowing; dropping a denial is a widening", { dropped: before.filter((x) => !proposed.includes(x)) });
      }
      next.denied_ref_patterns = [...proposed];
    }
    {
      const before = prior.ttl_seconds as number | null;
      const proposed = narrowing.ttl_seconds === undefined ? before : narrowing.ttl_seconds;
      if (before !== null && proposed === null) {
        throw new ContextRefusal("context_lease_ttl_unbounded", "a bounded lease cannot become unbounded through a narrowing", { before, proposed });
      }
      if (before !== null && proposed !== null && proposed > before) {
        throw new ContextRefusal("context_lease_ttl_extended", "a narrowing cannot extend the lease's ttl", { before, proposed });
      }
      if (proposed !== null && !(Number.isInteger(proposed) && proposed >= 1)) {
        throw new ContextRefusal("context_lease_ttl_invalid", "ttl_seconds is a positive integer or null", { ttl_seconds: proposed });
      }
      next.ttl_seconds = proposed;
    }
    const record: Record<string, unknown> = {
      schema_version: CONTEXT_SCHEMA_VERSIONS.lease,
      context_lease_id: narrowing.context_lease_id,
      work_subject_ref: prior.work_subject_ref,
      context_cell_ref: prior.context_cell_ref,
      issued_to_ref: prior.issued_to_ref,
      lease_kind: prior.lease_kind,
      allowed_ref_patterns: next.allowed_ref_patterns,
      denied_ref_patterns: next.denied_ref_patterns,
      authority_scope_refs: next.authority_scope_refs,
      budget_ref: prior.budget_ref,
      ttl_seconds: next.ttl_seconds,
      receipt_required: prior.receipt_required,
      leased_refs: next.leased_refs,
      information_flow_label_refs: next.information_flow_label_refs,
      permitted_recipient_roles: next.permitted_recipient_roles,
      successor_of: predecessorRef,
      predecessor_remains_valid: narrowing.predecessor_remains_valid,
      status: "active",
    };
    record.receipt_root = receiptRootOf(record, LEASE_ROOT_MEMBERS);
    return this.orchestration.record({ contract_id: CONTEXT_CONTRACTS.lease, object_id: narrowing.context_lease_id, record, expected_head: null });
  }

  /** Revocation is a successor at the predecessor's exact head whose status is `revoked`; it re-seals its own root. */
  async revoke(leaseRef: string): Promise<SystemRecordAdmitResult> {
    const chain = await readChain(this.orchestration, CONTEXT_CONTRACTS.lease, leaseRef);
    if (!chain) throw new ContextRefusal("context_lease_unknown", `no context lease ${leaseRef} under this orchestration`, { ref: leaseRef });
    const current = chain.current as Record<string, unknown>;
    if (!leaseIsLive(current)) {
      throw new ContextRefusal("context_lease_terminal", `lease ${leaseRef} is already ${String(current.status)}`, { ref: leaseRef, status: current.status });
    }
    const { system_binding: _binding, receipt_root: _root, ...rest } = current;
    const record: Record<string, unknown> = { ...rest, status: "revoked" };
    record.receipt_root = receiptRootOf(record, LEASE_ROOT_MEMBERS);
    return this.orchestration.record({ contract_id: CONTEXT_CONTRACTS.lease, object_id: leaseRef, record, expected_head: chain.head });
  }

  /**
   * The least-context view a lease resolves to: a READ MODEL rebuilt from the admitted lease and
   * the daemon's own view revisions on every call, persisting nothing. It names the dimensions it
   * inherits and restates none of them; permitted purposes fold by INTERSECTION and every resolved
   * input contributes its denials. A terminal lease resolves nothing — the fence is on the read.
   */
  async resolveLeastContext(leaseRef: string): Promise<LeastContextResolution> {
    const lease = await requireLease(this.orchestration, leaseRef, "a resolution");
    if (!leaseIsLive(lease)) {
      throw new ContextRefusal("context_lease_resolves_nothing", `lease ${leaseRef} is ${String(lease.status)}; a terminal lease resolves nothing`, { ref: leaseRef, status: lease.status });
    }
    const bound = await this.requireViewRevisions(lease.leased_refs as string[], "a resolution");
    const inherited = ["purpose", "data_classes", "privacy_class", "field_scope", "row_scope", "time_scope", "information_flow_labels"] as const;
    let permitted = null as Set<string> | null;
    const exposed = new Set<string>();
    for (const { view } of bound) {
      const v = view as Record<string, unknown>;
      const purposes = new Set<string>(typeof v.purpose === "string" ? [v.purpose] : Array.isArray(v.purpose) ? (v.purpose as string[]) : []);
      permitted = permitted === null ? purposes : new Set([...permitted].filter((p) => purposes.has(p)));
      for (const c of Array.isArray(v.data_classes) ? (v.data_classes as string[]) : []) exposed.add(c);
    }
    return {
      nature: "read_model",
      context_lease_id: leaseRef,
      status: String(lease.status),
      inherited_dimensions: inherited,
      bound_view_revisions: bound.map(({ ref, family, revision }) => ({ ref, family, revision })),
      permitted_purposes: permitted ? [...permitted].sort() : [],
      exposed_data_classes: [...exposed].sort(),
      denied_ref_patterns: [...(lease.denied_ref_patterns as string[])],
      information_flow_label_refs: [...(lease.information_flow_label_refs as string[])],
      permitted_recipient_roles: [...(lease.permitted_recipient_roles as string[])],
      reason: bound.length === 0 ? "the lease binds no view revision, so no purpose or data class is implied by it" : null,
    };
  }

  async read(leaseRef: string): Promise<SystemRecordChainResult | null> {
    return readChain(this.orchestration, CONTEXT_CONTRACTS.lease, leaseRef);
  }
}

// ---- handoffs -----------------------------------------------------------------------------------

export class ContextHandoffs {
  readonly orchestration: Orchestration;

  constructor(orchestration: Orchestration) {
    this.orchestration = orchestration;
  }

  async send(draft: ContextHandoffDraft): Promise<SystemRecordAdmitResult> {
    if (!HANDOFF_REF.test(draft.handoff_id)) {
      throw new ContextRefusal("context_handoff_ref_malformed", "a handoff id is handoff://…", { ref: draft.handoff_id });
    }
    if (!HANDOFF_KINDS.includes(draft.handoff_kind)) {
      throw new ContextRefusal("context_handoff_kind_unrecognized", `${String(draft.handoff_kind)} is not a handoff kind`, { handoff_kind: draft.handoff_kind });
    }
    const existing = await readChain(this.orchestration, CONTEXT_CONTRACTS.handoff, draft.handoff_id);
    if (existing) {
      throw new ContextRefusal("context_handoff_already_sent", `handoff ${draft.handoff_id} already exists under this orchestration`, { ref: draft.handoff_id });
    }
    if (draft.from_context_cell_ref === draft.to_context_cell_ref) {
      throw new ContextRefusal("context_handoff_to_self", "a cell handing off to itself is a summarisation, not a handoff between cells", { cell: draft.from_context_cell_ref });
    }
    const from = await requireCell(this.orchestration, draft.from_context_cell_ref, "a handoff's sender");
    const to = await requireCell(this.orchestration, draft.to_context_cell_ref, "a handoff's receiver");
    if (from.work_subject_ref !== to.work_subject_ref) {
      throw new ContextRefusal("context_handoff_subject_mismatch", `the sender binds ${String(from.work_subject_ref)} and the receiver binds ${String(to.work_subject_ref)}; a handoff stays on one subject`, { from: from.work_subject_ref, to: to.work_subject_ref });
    }
    for (const leaseRef of draft.context_lease_refs) {
      const lease = await requireLeaseHeldBy(this.orchestration, leaseRef, from, draft.from_context_cell_ref, "a handoff");
      const roles = lease.permitted_recipient_roles as string[];
      if (!roles.includes(String(to.role))) {
        throw new ContextRefusal("context_handoff_lease_not_permitted_for_receiver", `lease ${leaseRef} permits roles ${roles.join(", ")}; the receiving cell's role is ${String(to.role)} — refused at send, not discovered at acceptance`, { lease: leaseRef, receiver_role: to.role, permitted_recipient_roles: roles });
      }
    }
    const record: Record<string, unknown> = {
      schema_version: CONTEXT_SCHEMA_VERSIONS.handoff,
      handoff_id: draft.handoff_id,
      work_subject_ref: from.work_subject_ref,
      from_context_cell_ref: draft.from_context_cell_ref,
      to_context_cell_ref: draft.to_context_cell_ref,
      handoff_kind: draft.handoff_kind,
      payload_ref: draft.payload_ref,
      context_lease_refs: [...draft.context_lease_refs],
      acceptance_refs: [...draft.acceptance_refs],
      receipt_refs: [...draft.receipt_refs],
      non_grants: { ...HANDOFF_NON_GRANTS },
      successor_of: null,
      status: "sent",
    };
    record.receipt_root = receiptRootOf(record, HANDOFF_ROOT_MEMBERS);
    return this.orchestration.record({ contract_id: CONTEXT_CONTRACTS.handoff, object_id: draft.handoff_id, record, expected_head: null });
  }

  private async decide(handoffRef: string, status: "accepted" | "rejected"): Promise<{ admission: SystemRecordAdmitResult; candidate: HandoffCandidate | null }> {
    const chain = await readChain(this.orchestration, CONTEXT_CONTRACTS.handoff, handoffRef);
    if (!chain) throw new ContextRefusal("context_handoff_unknown", `no handoff ${handoffRef} under this orchestration`, { ref: handoffRef });
    const current = chain.current as Record<string, unknown>;
    if (current.status !== "sent") {
      throw new ContextRefusal("context_handoff_not_sent", `handoff ${handoffRef} is ${String(current.status)}; only a sent handoff can be decided, once`, { ref: handoffRef, status: current.status });
    }
    let candidate: HandoffCandidate | null = null;
    if (status === "accepted") {
      // A CANDIDATE under the RECEIVER's policy: which travelling leases the receiver's own role may
      // hold. Nothing is copied to the receiving cell and no authority moves; the receiver's cell
      // successor, if it ever names one of these leases, is refused by requireLeaseHeldBy — a
      // lease issued to the sender is not held by the receiver.
      const to = await requireCell(this.orchestration, String(current.to_context_cell_ref), "an acceptance");
      const permitted: string[] = [];
      const refused: Array<{ lease: string; reason: string }> = [];
      for (const leaseRef of current.context_lease_refs as string[]) {
        const lease = await readChain(this.orchestration, CONTEXT_CONTRACTS.lease, leaseRef);
        const record = lease?.current as Record<string, unknown> | undefined;
        if (!record || !leaseIsLive(record)) { refused.push({ lease: leaseRef, reason: "the lease is no longer live" }); continue; }
        const roles = record.permitted_recipient_roles as string[];
        if (!roles.includes(String(to.role))) { refused.push({ lease: leaseRef, reason: `the receiver's role ${String(to.role)} is not permitted` }); continue; }
        permitted.push(leaseRef);
      }
      candidate = { nature: "candidate", handoff_id: handoffRef, receiver: String(current.to_context_cell_ref), receiver_role: String(to.role), leases_the_receiver_may_hold: permitted, leases_refused_under_receiver_policy: refused, copies_no_lease: true, transfers_no_authority: true, non_grants: { ...HANDOFF_NON_GRANTS } };
    }
    const { system_binding: _binding, receipt_root: _root, ...rest } = current;
    const record: Record<string, unknown> = { ...rest, status, non_grants: { ...HANDOFF_NON_GRANTS } };
    record.receipt_root = receiptRootOf(record, HANDOFF_ROOT_MEMBERS);
    const admission = await this.orchestration.record({ contract_id: CONTEXT_CONTRACTS.handoff, object_id: handoffRef, record, expected_head: chain.head });
    return { admission, candidate };
  }

  /** Acceptance mints the decision successor and returns the receiver-policy CANDIDATE; it copies no lease and transfers no authority. */
  async accept(handoffRef: string): Promise<{ admission: SystemRecordAdmitResult; candidate: HandoffCandidate }> {
    const decided = await this.decide(handoffRef, "accepted");
    return { admission: decided.admission, candidate: decided.candidate as HandoffCandidate };
  }

  async reject(handoffRef: string): Promise<SystemRecordAdmitResult> {
    return (await this.decide(handoffRef, "rejected")).admission;
  }

  async read(handoffRef: string): Promise<SystemRecordChainResult | null> {
    return readChain(this.orchestration, CONTEXT_CONTRACTS.handoff, handoffRef);
  }
}

export interface HandoffCandidate {
  nature: "candidate";
  handoff_id: string;
  receiver: string;
  receiver_role: string;
  leases_the_receiver_may_hold: string[];
  leases_refused_under_receiver_policy: Array<{ lease: string; reason: string }>;
  copies_no_lease: true;
  transfers_no_authority: true;
  non_grants: typeof HANDOFF_NON_GRANTS;
}

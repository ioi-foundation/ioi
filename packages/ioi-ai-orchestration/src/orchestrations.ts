/**
 * The ioi.ai application's orchestrations, recorded under their bounded System (R-172 slice S4c-1,
 * register R-185).
 *
 * WHAT THIS IS. The S2 handle made durable. `Orchestration.compose` creates the coordinating
 * thread; this module admits ONE typed record for it — `schema://ioi/applications/ioi-ai/orchestration/v1`,
 * the successor of OutcomeRoom v2 — through the System-record seam, and everything the ioi.ai goal
 * space shows or changes is a read of that record's chain, a read of the kernel's thread and
 * subagents, or a revision of that record on its exact head. Listing is the seam's list under the
 * contract; opening is the seam's chain plus `Orchestration.open` on the handle the record carries;
 * attaching a GoalRun is a revision of `member_goal_run_refs`; a status change is a revision of
 * `status`. Nothing here survives a process except through a daemon admission, and the head the
 * seam hands back is the only coordinate a caller must carry.
 *
 * WHAT THIS IS NOT. Not a hosted coordination object. No daemon route serves an orchestration; no
 * reciprocal write lands in a GoalRun (its own composition follows in S4d); no roster, lease or
 * membership object is minted; a stale head is refused by the seam by name and this module never
 * pre-empts that refusal with a read of its own — the stream is the truth. A record the seam holds
 * for nobody visible is refused by the seam's scope fence (403), and that refusal is passed through
 * as it is: the composer claims neither absence nor existence for it.
 */

import { randomBytes } from "node:crypto";

import {
  Orchestration,
  projectOrchestrationGraph,
  type OrchestrationGraph,
  type RuntimeSubagentListResult,
  type RuntimeSubstrateClient,
  type SystemRecordAdmission,
  type SystemRecordAdmitResult,
  type SystemRecordChainResult,
  type SystemRecordListEntry,
} from "@ioi/agent-sdk";

export const ORCHESTRATION_CONTRACT = "schema://ioi/applications/ioi-ai/orchestration/v1";
export const ORCHESTRATION_SCHEMA_VERSION = "ioi.applications.ioi-ai.orchestration.v1";
export const ORCHESTRATION_ID_PREFIX = "orchestration://";
export const ORCHESTRATION_SCOPE_PREFIX = "app-scope://ioi-ai/orchestration/";
export const ORCHESTRATION_MEMBER_BOUND = 64;

const ID_TAIL = /^orc_[A-Za-z0-9_-]{1,160}$/u;
const GOAL_RUN_REF = /^goal:\/\/gr_[A-Za-z0-9_-]{1,160}$/u;
const HEAD = /^sha256:[0-9a-f]{64}$/u;
const THREAD_REF = /^thread:\/\/([A-Za-z0-9_-]{1,200})$/u;

export type OrchestrationMode = "private_goal" | "permissioned_team" | "cross_org" | "open_challenge";
export type OrchestrationTopology = "hosted_admission" | "federated_admission";
export type OrchestrationStatus = "open" | "paused" | "closed";

export const ORCHESTRATION_MODES: readonly OrchestrationMode[] = ["private_goal", "permissioned_team", "cross_org", "open_challenge"];
export const ORCHESTRATION_STATUSES: readonly OrchestrationStatus[] = ["open", "paused", "closed"];

/** The governance the application declares on an orchestration: refs it names, never policies it mints. */
export const GOVERNANCE_SCALAR_REFS = [
  "stop_policy_ref",
  "visibility_policy_ref",
  "participation_policy_ref",
  "privacy_policy_ref",
  "contribution_policy_ref",
  "cooperation_surplus_policy_ref",
  "coordination_policy_ref",
  "ordering_and_merge_policy_ref",
  "conflict_and_failover_policy_ref",
] as const;
export const GOVERNANCE_LIST_REFS = [
  "constraint_refs",
  "acceptance_criteria_refs",
  "collaboration_terms_refs",
  "artifact_license_rights_retention_and_export_policy_refs",
  "ontology_profile_refs",
  "scorecard_and_guardrail_refs",
  "verifier_path_refs",
  "resource_and_budget_refs",
] as const;
export const GOVERNANCE_NULLABLE_REFS = ["settlement_policy_ref", "multi_party_collaboration_ref"] as const;

export type OrchestrationGovernance = Record<(typeof GOVERNANCE_SCALAR_REFS)[number], string> &
  Record<(typeof GOVERNANCE_LIST_REFS)[number], string[]> &
  Record<(typeof GOVERNANCE_NULLABLE_REFS)[number], string | null>;

export interface OrchestrationRecord extends OrchestrationGovernance {
  schema_version: typeof ORCHESTRATION_SCHEMA_VERSION;
  orchestration_id: string;
  orchestration_ref: string;
  owner_ref: string;
  composed_by_ref: string;
  thread_ref: string;
  objective: string;
  objective_ref: string | null;
  mode: OrchestrationMode;
  coordination_topology: OrchestrationTopology;
  member_goal_run_refs: string[];
  composed_at: string;
  status: OrchestrationStatus;
  /** Derived by the seam on admission; present on every served record, never authored here. */
  system_binding?: Record<string, unknown>;
}

export interface OrchestrationDraft {
  objective: string;
  objective_ref?: string | null;
  mode: OrchestrationMode;
  coordination_topology?: OrchestrationTopology;
  composed_by_ref: string;
  governance: OrchestrationGovernance;
}

export class OrchestrationRefusal extends Error {
  readonly code: string;
  readonly details: Record<string, unknown>;

  constructor(code: string, message: string, details: Record<string, unknown> = {}) {
    super(message);
    this.name = "OrchestrationRefusal";
    this.code = code;
    this.details = details;
  }
}

export interface OrchestrationsScope {
  /** The bounded System the orchestrations are recorded under. */
  system_id: string;
  /** The owner scope the seam chains the records under: the resolved tenant, else the resolved principal. */
  owner_ref: string;
}

export interface OrchestrationsOptions {
  now?: () => string;
  /** Mints the id tail (`orc_…`); the default is 12 random bytes. Injected so a driven run can name what it composed. */
  mintId?: () => string;
}

export interface OrchestrationEntry {
  orchestration: OrchestrationRecord;
  resource_ref: string;
  head: string | null;
  revisions: number;
}

export interface OpenedOrchestration {
  handle: Orchestration;
  orchestration: OrchestrationRecord;
  head: string;
  revisions: OrchestrationRecord[];
  admissions: SystemRecordAdmission[];
}

export interface AdmittedOrchestration {
  handle: Orchestration;
  orchestration: OrchestrationRecord;
  head: string;
  admitted: SystemRecordAdmitResult;
}

export type MembershipTransition = "attach" | "detach";

export interface RevisedOrchestration extends AdmittedOrchestration {
  action: MembershipTransition | "transition";
  member_stamp?: OrchestrationMemberStamp;
}

export interface OrchestrationMemberStamp {
  goal_run_ref: string;
  orchestration_ref: string | null;
  stamped: boolean;
  durable: boolean;
  refusal: { status: number; code: string; message: string } | null;
}

// ---- coordinates -------------------------------------------------------------------------------

/** `orchestration://orc_x` or `orc_x` → `orc_x`; anything else → null. */
export function orchestrationIdTail(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const tail = value.startsWith(ORCHESTRATION_ID_PREFIX) ? value.slice(ORCHESTRATION_ID_PREFIX.length) : value;
  return ID_TAIL.test(tail) ? tail : null;
}

export function orchestrationId(tail: string): string {
  return `${ORCHESTRATION_ID_PREFIX}${tail}`;
}

/** The composition's scope for an orchestration — derived from its id and from nothing else. */
export function orchestrationScope(tail: string): string {
  return `${ORCHESTRATION_SCOPE_PREFIX}${tail}`;
}

/** The coordinating thread's id, read from the record's `thread_ref`. */
export function threadIdOf(record: Pick<OrchestrationRecord, "thread_ref">): string | null {
  const match = THREAD_REF.exec(record.thread_ref ?? "");
  return match?.[1] ?? null;
}

export function mintOrchestrationIdTail(): string {
  return `orc_${randomBytes(12).toString("hex")}`;
}

function governanceOf(input: OrchestrationGovernance): OrchestrationGovernance {
  const governance: Record<string, unknown> = {};
  for (const key of GOVERNANCE_SCALAR_REFS) governance[key] = input[key];
  for (const key of GOVERNANCE_LIST_REFS) governance[key] = [...(input[key] ?? [])];
  for (const key of GOVERNANCE_NULLABLE_REFS) governance[key] = input[key] ?? null;
  return governance as OrchestrationGovernance;
}

function stripBinding(record: OrchestrationRecord): OrchestrationRecord {
  const { system_binding: _binding, ...rest } = record;
  return rest as OrchestrationRecord;
}

function served(record: Record<string, unknown>): OrchestrationRecord {
  return record as unknown as OrchestrationRecord;
}

/** An admission the seam answered but did not shape as one is never read as success. */
function requireAdmitted(admitted: SystemRecordAdmitResult): SystemRecordAdmitResult {
  if (admitted?.ok !== true || typeof admitted.expected_head_for_successor !== "string" || !admitted.record || typeof admitted.record !== "object") {
    throw new OrchestrationRefusal("orchestration_admission_unreadable", "the seam's reply to the admission carried no ok, no successor head or no served record; nothing is claimed for it", { reply: admitted });
  }
  return admitted;
}

function statusOf(error: unknown): number | null {
  const status = (error as { status?: unknown })?.status;
  return typeof status === "number" ? status : null;
}

function parentScopeOf(entry: SystemRecordListEntry): string | null {
  const binding = entry.current?.system_binding as { parent_scope_ref?: unknown } | undefined;
  return typeof binding?.parent_scope_ref === "string" ? binding.parent_scope_ref : null;
}

function requireTail(value: unknown): string {
  const tail = orchestrationIdTail(value);
  if (!tail) throw new OrchestrationRefusal("orchestration_id_malformed", "an orchestration is addressed by its canonical orchestration://orc_ id", { value });
  return tail;
}

function requireHead(value: unknown): string {
  if (typeof value !== "string" || !HEAD.test(value)) {
    throw new OrchestrationRefusal("orchestration_expected_head_required", "a revision names the exact head it was computed against; the seam refuses any other by name");
  }
  return value;
}

function requireGoalRunRef(value: unknown): string {
  if (typeof value !== "string" || !GOAL_RUN_REF.test(value)) {
    throw new OrchestrationRefusal("orchestration_goal_run_ref_malformed", "membership names a canonical goal://gr_ ref", { value });
  }
  return value;
}

function requireOpen(record: OrchestrationRecord, action: string): void {
  if (record.status === "closed") {
    throw new OrchestrationRefusal("orchestration_closed", `${record.orchestration_id} is closed; a closed orchestration takes no ${action}`, { status: record.status });
  }
}

/**
 * The ioi.ai application's orchestrations under one System, as one owner scope sees them. Every
 * method is a daemon read, a daemon admission, or a revision on an exact head; the instance
 * remembers nothing between calls.
 */
export class Orchestrations {
  readonly system_id: string;
  readonly owner_ref: string;
  private readonly client: RuntimeSubstrateClient;
  private readonly now: () => string;
  private readonly mintId: () => string;

  constructor(client: RuntimeSubstrateClient, scope: OrchestrationsScope, options: OrchestrationsOptions = {}) {
    this.client = client;
    this.system_id = scope.system_id;
    this.owner_ref = scope.owner_ref;
    this.now = options.now ?? (() => new Date().toISOString());
    this.mintId = options.mintId ?? mintOrchestrationIdTail;
  }

  /** Compose: the coordinating thread first (the root), then the one record that makes the handle durable. */
  async compose(draft: OrchestrationDraft): Promise<AdmittedOrchestration> {
    const tail = this.mintId();
    if (!ID_TAIL.test(tail)) throw new OrchestrationRefusal("orchestration_id_malformed", "the minted id tail is not canonical", { tail });
    const objective = typeof draft.objective === "string" ? draft.objective.trim() : "";
    if (!objective || objective.length > 4096) {
      throw new OrchestrationRefusal("orchestration_objective_required", "an orchestration names the objective its coordinating thread is created with (1..4096 characters)");
    }
    if (!ORCHESTRATION_MODES.includes(draft.mode)) throw new OrchestrationRefusal("orchestration_mode_invalid", "mode is one of the declared orchestration modes", { mode: draft.mode });
    const scope_ref = orchestrationScope(tail);
    const handle = await Orchestration.compose(this.client, { system_id: this.system_id, owner_ref: this.owner_ref, scope_ref, objective });
    const record: OrchestrationRecord = {
      schema_version: ORCHESTRATION_SCHEMA_VERSION,
      orchestration_id: orchestrationId(tail),
      orchestration_ref: scope_ref,
      owner_ref: this.owner_ref,
      composed_by_ref: draft.composed_by_ref,
      thread_ref: `thread://${handle.thread_id}`,
      objective,
      objective_ref: draft.objective_ref ?? null,
      mode: draft.mode,
      coordination_topology: draft.coordination_topology ?? "hosted_admission",
      ...governanceOf(draft.governance),
      member_goal_run_refs: [],
      composed_at: this.now(),
      status: "open",
    };
    const admitted = requireAdmitted(await handle.record({ contract_id: ORCHESTRATION_CONTRACT, object_id: record.orchestration_id, record: record as unknown as Record<string, unknown>, expected_head: null }));
    return { handle, orchestration: served(admitted.record), head: admitted.expected_head_for_successor, admitted };
  }

  /** Every orchestration recorded under the System that this owner scope may read, at its current head. */
  async list(): Promise<OrchestrationEntry[]> {
    const listed = await this.client.listSystemRecords(this.system_id, ORCHESTRATION_CONTRACT);
    return (listed.records ?? [])
      .filter((entry) => entry.current !== null && entry.contract_id === ORCHESTRATION_CONTRACT)
      .map((entry) => ({ orchestration: served(entry.current as Record<string, unknown>), resource_ref: entry.resource_ref, head: entry.head, revisions: entry.revisions }));
  }

  /** Re-attach: the record's chain from the seam, and a handle opened on the coordinates the record carries. */
  async open(id: unknown): Promise<OpenedOrchestration> {
    const tail = requireTail(id);
    let chain: SystemRecordChainResult;
    try {
      chain = await this.client.getSystemRecord(this.system_id, ORCHESTRATION_CONTRACT, orchestrationId(tail));
    } catch (error) {
      if (statusOf(error) === 404) throw new OrchestrationRefusal("orchestration_absent", `no orchestration ${orchestrationId(tail)} is recorded under ${this.system_id} for this scope`, { orchestration_id: orchestrationId(tail) });
      throw error;
    }
    const current = chain.current ? served(chain.current) : null;
    if (!current || typeof chain.head !== "string") {
      throw new OrchestrationRefusal("orchestration_absent", `no orchestration ${orchestrationId(tail)} is recorded under ${this.system_id} for this scope`, { orchestration_id: orchestrationId(tail) });
    }
    const thread_id = threadIdOf(current);
    if (!thread_id) throw new OrchestrationRefusal("orchestration_root_unbound", `${current.orchestration_id} names no coordinating thread`, { thread_ref: current.thread_ref ?? null });
    const handle = Orchestration.open(this.client, { system_id: this.system_id, owner_ref: current.owner_ref, scope_ref: current.orchestration_ref, thread_id });
    return { handle, orchestration: current, head: chain.head, revisions: (chain.revisions ?? []).map(served), admissions: chain.admissions ?? [] };
  }

  /** Attach a GoalRun: a revision of the record on the exact head the caller loaded. */
  async attachGoalRun(id: unknown, goalRunRef: unknown, expectedHead: unknown): Promise<RevisedOrchestration> {
    const ref = requireGoalRunRef(goalRunRef);
    const revised = await this.revise(id, expectedHead, "attach", (current) => {
      requireOpen(current, "membership change");
      if (current.member_goal_run_refs.includes(ref)) {
        throw new OrchestrationRefusal("orchestration_goal_run_already_attached", `${ref} is already attached to ${current.orchestration_id}`, { goal_run_ref: ref });
      }
      if (current.member_goal_run_refs.length >= ORCHESTRATION_MEMBER_BOUND) {
        throw new OrchestrationRefusal("orchestration_members_over_bound", `${current.orchestration_id} already holds the ${ORCHESTRATION_MEMBER_BOUND} members its profile bounds`, { bound: ORCHESTRATION_MEMBER_BOUND });
      }
      return { ...current, member_goal_run_refs: [...current.member_goal_run_refs, ref] };
    });
    revised.member_stamp = await this.stampMember(ref, orchestrationScope(orchestrationIdTail(revised.orchestration.orchestration_id) ?? ""));
    return revised;
  }

  /** Detach a GoalRun: the reverse revision, on the exact head. */
  async detachGoalRun(id: unknown, goalRunRef: unknown, expectedHead: unknown): Promise<RevisedOrchestration> {
    const ref = requireGoalRunRef(goalRunRef);
    const revised = await this.revise(id, expectedHead, "detach", (current) => {
      requireOpen(current, "membership change");
      if (!current.member_goal_run_refs.includes(ref)) {
        throw new OrchestrationRefusal("orchestration_goal_run_not_attached", `${ref} is not attached to ${current.orchestration_id}`, { goal_run_ref: ref });
      }
      return { ...current, member_goal_run_refs: current.member_goal_run_refs.filter((member) => member !== ref) };
    });
    revised.member_stamp = await this.stampMember(ref, null);
    return revised;
  }

  /**
   * The reciprocal member: the seam revision is authoritative and already durable; the GoalRun
   * plane stores the ref the composer asserts (R-190). A refused stamp is reported, never hidden,
   * and never rolls the seam back — the composer retries the stamp, not the membership.
   */
  private async stampMember(goalRunRef: string, orchestrationRef: string | null): Promise<OrchestrationMemberStamp> {
    const goalRunId = goalRunRef.slice("goal://".length);
    try {
      const result = await this.client.stampGoalRunOrchestrationMembership(goalRunId, { orchestration_ref: orchestrationRef });
      return { goal_run_ref: goalRunRef, orchestration_ref: orchestrationRef, stamped: true, durable: result.durable !== false, refusal: null };
    } catch (error) {
      const status = typeof (error as { status?: unknown })?.status === "number" ? (error as { status: number }).status : 0;
      const daemonCode = (error as { details?: { daemon?: { error?: { code?: unknown } } } })?.details?.daemon?.error?.code;
      const code = typeof daemonCode === "string" ? daemonCode : typeof (error as { code?: unknown })?.code === "string" ? (error as { code: string }).code : "goal_run_orchestration_membership_unavailable";
      const message = error instanceof Error ? error.message : String(error);
      return { goal_run_ref: goalRunRef, orchestration_ref: orchestrationRef, stamped: false, durable: false, refusal: { status, code, message } };
    }
  }

  /** open ⇄ paused, and either → closed; closed is terminal. */
  async transition(id: unknown, status: unknown, expectedHead: unknown): Promise<RevisedOrchestration> {
    if (!ORCHESTRATION_STATUSES.includes(status as OrchestrationStatus)) {
      throw new OrchestrationRefusal("orchestration_status_invalid", "status is one of open, paused, closed", { status });
    }
    const next = status as OrchestrationStatus;
    return this.revise(id, expectedHead, "transition", (current) => {
      requireOpen(current, "transition");
      if (current.status === next) throw new OrchestrationRefusal("orchestration_transition_noop", `${current.orchestration_id} is already ${next}`, { status: next });
      return { ...current, status: next };
    });
  }

  /** The composed graph: the kernel's thread and subagents, and the seam's records scoped to this orchestration. */
  async graph(id: unknown): Promise<OrchestrationGraph> {
    const opened = await this.open(id);
    const [thread, delegations, records] = await Promise.all([opened.handle.thread(), opened.handle.delegations(), this.client.listSystemRecords(this.system_id)]);
    const scoped = (records.records ?? []).filter((entry) => parentScopeOf(entry) === opened.orchestration.orchestration_ref);
    return projectOrchestrationGraph({
      system_id: this.system_id,
      scope_ref: opened.orchestration.orchestration_ref,
      thread,
      subagents: delegations.subagents ?? [],
      reservations: opened.handle.reservations(),
      records: scoped,
    });
  }

  /** The delegations of the coordinating thread, as the kernel lists them. */
  async delegations(id: unknown): Promise<RuntimeSubagentListResult> {
    const opened = await this.open(id);
    return opened.handle.delegations();
  }

  private async revise(id: unknown, expectedHead: unknown, action: RevisedOrchestration["action"], mutate: (current: OrchestrationRecord) => OrchestrationRecord): Promise<RevisedOrchestration> {
    const head = requireHead(expectedHead);
    const opened = await this.open(id);
    const next = mutate(stripBinding(opened.orchestration));
    const admitted = requireAdmitted(await opened.handle.record({ contract_id: ORCHESTRATION_CONTRACT, object_id: next.orchestration_id, record: next as unknown as Record<string, unknown>, expected_head: head }));
    return { handle: opened.handle, orchestration: served(admitted.record), head: admitted.expected_head_for_successor, admitted, action };
  }
}

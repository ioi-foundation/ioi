/**
 * Orchestration composed from the daemon's thread orchestration primitives (R-172).
 *
 * WHAT THIS IS. An application-layer composition, node-graph style. A coordinating thread
 * (`POST /v1/threads`) is the root node; delegations are subagents of that thread
 * (ADR 0034: the thread fork is the delegation primitive and subagents are its surface);
 * per-dimension claims are work-lifecycle reservations on their own stream (M04.10, R-74); and the
 * application's own typed records live under the bounded System through the system-record seam
 * (R-172 S1), which validates by registered contract, derives the binding and admits on the shared
 * write path. The graph this module serves is DERIVED from those kernel- and substrate-owned
 * streams. This module keeps no truth of its own: nothing here survives a process except through a
 * daemon admission, and everything it reports can be re-read from the daemon after a restart.
 *
 * WHAT THIS IS NOT. Not a hypervisor plane. There is no coordination object, no membership roster
 * and no standing grant minted here or served by the platform for it (ADR 0022, ADR 0030,
 * ADR 0031). The platform knows contracts, Systems, threads, subagents and reservations; only an
 * application composes them into an orchestration and names what it composed. That is why every
 * name on this surface is a primitive's name or a graph word, and none is an application's.
 */

import { createHash } from "node:crypto";

import type {
  RuntimeSubagentListInput,
  RuntimeSubagentListResult,
  RuntimeSubagentRecord,
  RuntimeSubagentSpawnInput,
  RuntimeSubstrateClient,
  RuntimeThreadCreateInput,
} from "./substrate-client.js";
import type { RuntimeThreadRecord } from "./messages.js";

// ---- routes -------------------------------------------------------------------------------------

const encode = (value: string): string => encodeURIComponent(value);

/** The system-record seam (R-172 S1): typed application records under a bounded System. */
export const SYSTEM_RECORD_ROUTES = {
  admit: (systemId: string) => `/v1/hypervisor/autonomous-systems/${encode(systemId)}/records`,
  list: (systemId: string, contractId?: string) =>
    `/v1/hypervisor/autonomous-systems/${encode(systemId)}/records${
      contractId ? `?contract_id=${encode(contractId)}` : ""
    }`,
  get: (systemId: string, contractId: string, objectId: string) =>
    `/v1/hypervisor/autonomous-systems/${encode(systemId)}/records/${encode(
      systemRecordSlug(contractId),
    )}/${encode(systemRecordSlug(objectId))}`,
} as const;

/** The work-lifecycle plane's reservation admission (M04.10). */
/**
 * RETIRED 2026-09-18 (R-192, slice S5-1). This held the GoalRun plane's one membership endpoint,
 * which the composer called to stamp the reciprocal member after its seam revision (R-190, S4d-2).
 * The owner ruled goal runs and outcome rooms out of the Hypervisor — they are ioi.ai compositions
 * over its thread orchestration primitives — and the whole `/v1/goal-orchestration/` namespace is
 * gone. The route map is EMPTY rather than deleted so the retirement is a fact this file states,
 * and `stampGoalRunOrchestrationMembership` refuses locally instead of issuing a request that
 * would come back as an untyped 404 from the router's fallback.
 */
export const GOAL_RUN_ROUTES = {} as const;

/** The typed refusal that replaced the retired membership call. */
export const GOAL_RUN_MEMBERSHIP_RETIRED_CODE = "goal_run_membership_route_retired";

export interface GoalRunOrchestrationMembershipInput {
  orchestration_ref: string | null;
}

export interface GoalRunOrchestrationMembershipResult {
  ok: true;
  goal_run: Record<string, unknown>;
  durable: boolean;
  durability_note?: string;
}

export const WORK_LIFECYCLE_ROUTES = {
  reservations: "/v1/hypervisor/work-lifecycle/reservations",
  records: "/v1/hypervisor/work-lifecycle/records",
} as const;

// ---- contracts the composition speaks -----------------------------------------------------------

export const WORK_RESERVATION_SCHEMA_VERSION = "ioi.foundations.work-dimension-reservation.v1";

/**
 * The head of a reservation stream that holds no claim yet. A real value rather than an absence:
 * the reservation contract requires `expected_ancestor_head` to be a hash, so a first claim names
 * this and the daemon compares it against the empty stream.
 */
export const RESERVATION_GENESIS_HEAD =
  "sha256:0000000000000000000000000000000000000000000000000000000000000000";

// ---- wire shapes --------------------------------------------------------------------------------

export interface SystemRecordAdmitInput {
  owner_ref: string;
  idempotency_key: string;
  contract_id: string;
  object_id: string;
  parent_scope_ref?: string | null;
  record: Record<string, unknown>;
  expected_head?: string | null;
}

export interface SystemScopedObjectBinding {
  schema_version: string;
  system_id: string;
  parent_scope_ref: string;
  payload_root: string;
  principal_ref?: string;
  [key: string]: unknown;
}

export interface SystemRecordAdmission {
  contract_id?: string;
  identity_member?: string;
  idempotency_key?: string;
  parent_scope_ref?: string | null;
  recorded_at_ms?: number;
  resource_ref?: string;
  [key: string]: unknown;
}

export interface SystemRecordAdmitResult {
  ok: boolean;
  replayed: boolean;
  system_id: string;
  contract_id: string;
  resource_ref: string;
  record: Record<string, unknown> & { system_binding?: SystemScopedObjectBinding };
  admission: SystemRecordAdmission;
  expected_head_for_successor: string;
  receipt_ref?: string;
  operation_ref?: string;
  request_fingerprint?: string;
}

export interface SystemRecordListEntry {
  resource_ref: string;
  contract_id: string | null;
  current: Record<string, unknown> | null;
  head: string | null;
  revisions: number;
}

export interface SystemRecordListResult {
  ok: boolean;
  system_id: string;
  records: SystemRecordListEntry[];
  count: number;
}

export interface SystemRecordChainResult {
  ok: boolean;
  current: Record<string, unknown> | null;
  revisions: Array<Record<string, unknown>>;
  admissions: SystemRecordAdmission[];
  head: string | null;
  [key: string]: unknown;
}

export interface WorkReservationCandidate {
  schema_version: typeof WORK_RESERVATION_SCHEMA_VERSION;
  reservation_ref: string;
  work_ref: string;
  holder_ref: string;
  dimension: string;
  reserved_units: number;
  ancestor_chain: string[];
  expected_ancestor_head: string;
  protected_capacity: { recovery_units: number; integration_units: number };
  status: "active" | "transferred" | "released" | string;
  transferred_to_ref: string | null;
  transferred_from_ref: string | null;
  created_at_ms: number;
  expires_at_ms: number;
}

export interface WorkReservationAncestorBound {
  ancestor_ref: string;
  bound_units: number;
}

export interface WorkReservationAdmitInput {
  reservation: WorkReservationCandidate;
  ancestor_bounds: WorkReservationAncestorBound[];
}

export interface WorkReservationAdmitResult {
  reservation: WorkReservationCandidate;
  stream_tail: string;
  admitted_head: string;
  nonclaim?: string;
}

// ---- pure helpers -------------------------------------------------------------------------------

/** RFC 8785-style canonical JSON: sorted members, no whitespace. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
    .join(",")}}`;
}

/** The seam's resource slug: the first `://` becomes `-`, every other character outside [A-Za-z0-9_.-] becomes `.`. */
export function systemRecordSlug(ref: string): string {
  return ref.replace("://", "-").replace(/[^A-Za-z0-9_.-]/gu, ".");
}

/** The resource a record occupies under its System, exactly as the seam spells it. */
export function systemRecordResourceRef(systemId: string, contractId: string, objectId: string): string {
  return `${systemId}/${systemRecordSlug(contractId)}/${systemRecordSlug(objectId)}`;
}

/** The binding's payload root: sha256 over the canonical JSON of the record with `system_binding` present and null. */
export function deriveSystemRecordPayloadRoot(record: Record<string, unknown>): string {
  return `sha256:${createHash("sha256")
    .update(canonicalJson({ ...record, system_binding: null }))
    .digest("hex")}`;
}

/** A content-derived idempotency key: an exact retry of the same record under the same identity replays. */
export function deriveSystemRecordIdempotencyKey(
  contractId: string,
  objectId: string,
  record: Record<string, unknown>,
  expectedHead: string | null,
): string {
  const digest = createHash("sha256")
    .update(canonicalJson({ contract_id: contractId, object_id: objectId, expected_head: expectedHead, record }))
    .digest("hex");
  return `record:${systemRecordSlug(objectId)}:${digest.slice(0, 24)}`;
}

/** The stream one claim contends on: its OUTERMOST ancestor in the substrate's canonical alphabet. Mirrors the daemon. */
export function reservationStreamTail(candidate: Pick<WorkReservationCandidate, "ancestor_chain">): string | null {
  const root = candidate.ancestor_chain[candidate.ancestor_chain.length - 1];
  if (typeof root !== "string" || root.length === 0) return null;
  return `reservations.${root.replace(/[^A-Za-z0-9]/gu, "-")}`;
}

// ---- the composed graph -------------------------------------------------------------------------

export type OrchestrationNodeKind = "system" | "thread" | "subagent" | "reservation" | "record";
export type OrchestrationEdgeKind = "coordinates" | "delegates" | "reserves" | "records" | "scopes";

export interface OrchestrationNode {
  id: string;
  kind: OrchestrationNodeKind;
  ref: string;
  /** Who owns the truth this node is projected from. The composition owns none of it. */
  owner: "system-genesis" | "thread-kernel" | "work-lifecycle-kernel" | "system-record-seam";
  detail: Record<string, unknown>;
}

export interface OrchestrationEdge {
  from: string;
  to: string;
  kind: OrchestrationEdgeKind;
}

export interface OrchestrationGraph {
  system_id: string;
  scope_ref: string;
  root: string;
  nodes: OrchestrationNode[];
  edges: OrchestrationEdge[];
  nonclaim: string;
}

export interface OrchestrationGraphInput {
  system_id: string;
  scope_ref: string;
  thread: Pick<RuntimeThreadRecord, "thread_id"> & Partial<RuntimeThreadRecord>;
  subagents: RuntimeSubagentRecord[];
  reservations: WorkReservationAdmitResult[];
  records: SystemRecordListEntry[];
}

export const ORCHESTRATION_GRAPH_NONCLAIM =
  "This graph is a read model derived from kernel-owned threads and subagents, the work-lifecycle reservation stream and the system-record seam. It mints no object and grants no authority; every node is re-readable from the daemon and the composition owns none of them.";

/**
 * Project the composed graph from the primitives' own records. Pure: it reads nothing, and the
 * same inputs project the same graph, so a verifier can re-derive it after a restart.
 */
export function projectOrchestrationGraph(input: OrchestrationGraphInput): OrchestrationGraph {
  const systemNode = `system:${input.system_id}`;
  const threadNode = `thread:${input.thread.thread_id}`;
  const nodes: OrchestrationNode[] = [
    { id: systemNode, kind: "system", ref: input.system_id, owner: "system-genesis", detail: { scope_ref: input.scope_ref } },
    {
      id: threadNode,
      kind: "thread",
      ref: input.thread.thread_id,
      owner: "thread-kernel",
      detail: { status: input.thread.status ?? null, title: input.thread.title ?? null },
    },
  ];
  const edges: OrchestrationEdge[] = [{ from: systemNode, to: threadNode, kind: "coordinates" }];

  for (const subagent of [...input.subagents].sort(bySubagentId)) {
    const id = `subagent:${subagent.subagent_id ?? subagent.run_id ?? "?"}`;
    nodes.push({
      id,
      kind: "subagent",
      ref: subagent.subagent_id ?? "",
      owner: "thread-kernel",
      detail: {
        role: subagent.role ?? null,
        run_id: subagent.run_id ?? null,
        parent_thread_id: subagent.parent_thread_id ?? null,
        status: subagent.lifecycle_status ?? subagent.status ?? null,
      },
    });
    edges.push({ from: threadNode, to: id, kind: "delegates" });
  }

  for (const admitted of [...input.reservations].sort((a, b) =>
    a.reservation.reservation_ref.localeCompare(b.reservation.reservation_ref),
  )) {
    const id = `reservation:${admitted.reservation.reservation_ref}`;
    nodes.push({
      id,
      kind: "reservation",
      ref: admitted.reservation.reservation_ref,
      owner: "work-lifecycle-kernel",
      detail: {
        dimension: admitted.reservation.dimension,
        reserved_units: admitted.reservation.reserved_units,
        holder_ref: admitted.reservation.holder_ref,
        stream_tail: admitted.stream_tail,
        admitted_head: admitted.admitted_head,
      },
    });
    edges.push({ from: threadNode, to: id, kind: "reserves" });
  }

  for (const entry of [...input.records].sort((a, b) => a.resource_ref.localeCompare(b.resource_ref))) {
    const id = `record:${entry.resource_ref}`;
    const binding = (entry.current?.system_binding ?? null) as SystemScopedObjectBinding | null;
    nodes.push({
      id,
      kind: "record",
      ref: entry.resource_ref,
      owner: "system-record-seam",
      detail: {
        contract_id: entry.contract_id,
        head: entry.head,
        revisions: entry.revisions,
        parent_scope_ref: binding?.parent_scope_ref ?? null,
        payload_root: binding?.payload_root ?? null,
      },
    });
    edges.push({ from: threadNode, to: id, kind: "records" });
    edges.push({ from: systemNode, to: id, kind: "scopes" });
  }

  return {
    system_id: input.system_id,
    scope_ref: input.scope_ref,
    root: threadNode,
    nodes,
    edges,
    nonclaim: ORCHESTRATION_GRAPH_NONCLAIM,
  };
}

function bySubagentId(a: RuntimeSubagentRecord, b: RuntimeSubagentRecord): number {
  return (a.subagent_id ?? "").localeCompare(b.subagent_id ?? "");
}

// ---- the composer -------------------------------------------------------------------------------

export interface OrchestrationSpec {
  /** The bounded System the application's records live under (its governed genesis is the platform's). */
  system_id: string;
  /** The resolved caller's owner reference for the seam's owner-scoped chain (tenant or principal). */
  owner_ref: string;
  /** The application's own parent-scope reference for the records it composes; the platform does not interpret it. */
  scope_ref: string;
  /** The coordinating thread's goal. */
  objective: string;
  /** Anything else the coordinating thread is created with. */
  thread?: Omit<RuntimeThreadCreateInput, "goal">;
}

export interface OrchestrationHandle {
  system_id: string;
  owner_ref: string;
  scope_ref: string;
  thread_id: string;
}

export interface OrchestrationDelegation extends RuntimeSubagentSpawnInput {}

export interface OrchestrationClaim {
  reservation_ref: string;
  work_ref: string;
  holder_ref: string;
  dimension: string;
  reserved_units: number;
  /** Every ancestor whose bound this claim narrows, nearest first. */
  ancestor_chain: string[];
  /** The ancestors' ceilings, supplied by their owners; the daemon derives nothing here. */
  ancestor_bounds: WorkReservationAncestorBound[];
  /** The head the capacity was computed against; defaults to the last head this composer admitted on the same stream, else genesis. */
  expected_ancestor_head?: string;
  protected_capacity?: { recovery_units: number; integration_units: number };
  created_at_ms?: number;
  expires_at_ms: number;
}

export interface OrchestrationRecordInput {
  contract_id: string;
  object_id: string;
  record: Record<string, unknown>;
  /** Defaults to the composition's scope_ref. */
  parent_scope_ref?: string | null;
  /** Null (or absent) asserts the first admission of this object. */
  expected_head?: string | null;
  /** Defaults to a content-derived key, so an exact retry replays. */
  idempotency_key?: string;
}

/**
 * One orchestration: a coordinating thread, the subagents delegated from it, the reservations it
 * claims and the typed records it admits under its System. Every method is one daemon admission or
 * one daemon read; the instance only remembers the coordinates it was handed back.
 */
export class Orchestration {
  readonly system_id: string;
  readonly owner_ref: string;
  readonly scope_ref: string;
  readonly thread_id: string;
  private readonly client: RuntimeSubstrateClient;
  private readonly reservationHeads = new Map<string, string>();
  private readonly admittedReservations: WorkReservationAdmitResult[] = [];
  private readonly recordHeads = new Map<string, string>();

  private constructor(client: RuntimeSubstrateClient, handle: OrchestrationHandle) {
    this.client = client;
    this.system_id = handle.system_id;
    this.owner_ref = handle.owner_ref;
    this.scope_ref = handle.scope_ref;
    this.thread_id = handle.thread_id;
  }

  /** Create the coordinating thread; that thread record is the orchestration's root. */
  static async compose(client: RuntimeSubstrateClient, spec: OrchestrationSpec): Promise<Orchestration> {
    const thread = await client.createThread({ ...(spec.thread ?? {}), goal: spec.objective });
    return new Orchestration(client, {
      system_id: spec.system_id,
      owner_ref: spec.owner_ref,
      scope_ref: spec.scope_ref,
      thread_id: thread.thread_id,
    });
  }

  /** Re-attach to an orchestration whose coordinating thread already exists; reads nothing until asked. */
  static open(client: RuntimeSubstrateClient, handle: OrchestrationHandle): Orchestration {
    return new Orchestration(client, handle);
  }

  handle(): OrchestrationHandle {
    return { system_id: this.system_id, owner_ref: this.owner_ref, scope_ref: this.scope_ref, thread_id: this.thread_id };
  }

  /** The coordinating thread, as the kernel serves it. */
  async thread(): Promise<RuntimeThreadRecord> {
    return this.client.getThread(this.thread_id);
  }

  /** Delegate one unit of work: a subagent of the coordinating thread (ADR 0034). */
  async delegate(input: OrchestrationDelegation): Promise<RuntimeSubagentRecord> {
    return this.client.spawnSubagent(this.thread_id, input);
  }

  /** The delegations, as the kernel serves them. */
  async delegations(input: RuntimeSubagentListInput = {}): Promise<RuntimeSubagentListResult> {
    return this.client.listSubagents(this.thread_id, input);
  }

  /** Claim capacity on one dimension: an exact-head reservation on the work-lifecycle plane (M04.10). */
  async reserve(claim: OrchestrationClaim): Promise<WorkReservationAdmitResult> {
    const candidate: WorkReservationCandidate = {
      schema_version: WORK_RESERVATION_SCHEMA_VERSION,
      reservation_ref: claim.reservation_ref,
      work_ref: claim.work_ref,
      holder_ref: claim.holder_ref,
      dimension: claim.dimension,
      reserved_units: claim.reserved_units,
      ancestor_chain: [...claim.ancestor_chain],
      expected_ancestor_head: claim.expected_ancestor_head ?? this.reservationHead(claim.ancestor_chain),
      protected_capacity: claim.protected_capacity ?? { recovery_units: 0, integration_units: 0 },
      status: "active",
      transferred_to_ref: null,
      transferred_from_ref: null,
      created_at_ms: claim.created_at_ms ?? Date.now(),
      expires_at_ms: claim.expires_at_ms,
    };
    const admitted = await this.client.admitWorkReservation({
      reservation: candidate,
      ancestor_bounds: claim.ancestor_bounds,
    });
    this.reservationHeads.set(admitted.stream_tail, admitted.admitted_head);
    this.admittedReservations.push(admitted);
    return admitted;
  }

  /** The head the next claim on that chain's stream must name: the last one admitted here, else genesis. */
  reservationHead(ancestorChain: string[]): string {
    const tail = reservationStreamTail({ ancestor_chain: ancestorChain });
    return (tail && this.reservationHeads.get(tail)) ?? RESERVATION_GENESIS_HEAD;
  }

  /** The reservations this composer admitted (a session memory of daemon replies, not a store). */
  reservations(): WorkReservationAdmitResult[] {
    return [...this.admittedReservations];
  }

  /** Admit one typed application record under the System through the seam (R-172 S1). */
  async record(input: OrchestrationRecordInput): Promise<SystemRecordAdmitResult> {
    const expectedHead = input.expected_head ?? this.recordHeads.get(this.recordKey(input.contract_id, input.object_id)) ?? null;
    const admitted = await this.client.admitSystemRecord(this.system_id, {
      owner_ref: this.owner_ref,
      idempotency_key:
        input.idempotency_key ??
        deriveSystemRecordIdempotencyKey(input.contract_id, input.object_id, input.record, expectedHead),
      contract_id: input.contract_id,
      object_id: input.object_id,
      parent_scope_ref: input.parent_scope_ref === undefined ? this.scope_ref : input.parent_scope_ref,
      record: input.record,
      expected_head: expectedHead,
    });
    this.recordHeads.set(this.recordKey(input.contract_id, input.object_id), admitted.expected_head_for_successor);
    return admitted;
  }

  /** The records under the System (optionally one contract), as the seam serves their current heads. */
  async records(contractId?: string): Promise<SystemRecordListResult> {
    return this.client.listSystemRecords(this.system_id, contractId);
  }

  /** One record's full chain, as the seam serves it. */
  async recordChain(contractId: string, objectId: string): Promise<SystemRecordChainResult> {
    return this.client.getSystemRecord(this.system_id, contractId, objectId);
  }

  /** The composed graph, re-derived from the daemon's own reads on every call. */
  async graph(): Promise<OrchestrationGraph> {
    const [thread, delegations, records] = await Promise.all([
      this.thread(),
      this.delegations(),
      this.records(),
    ]);
    return projectOrchestrationGraph({
      system_id: this.system_id,
      scope_ref: this.scope_ref,
      thread,
      subagents: delegations.subagents ?? [],
      reservations: this.reservations(),
      records: records.records ?? [],
    });
  }

  private recordKey(contractId: string, objectId: string): string {
    return systemRecordResourceRef(this.system_id, contractId, objectId);
  }
}

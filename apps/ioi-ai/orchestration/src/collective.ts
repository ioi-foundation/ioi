/**
 * Collective resolution and persistent executable lineage, composed over the orchestration
 * (R-204, S5-3 unit M04.12 — the last unit of the slice).
 *
 * WHAT THIS IS. Two ioi.ai records admitted under the bounded System through the generic record
 * seam, on the shape `goalrun.ts` and `context.ts` use:
 *
 *   CollectiveResolutionReceipt  — freezes the exact dependency closure a collective pursuit runs
 *                                  under: the ACTIVE System's release, constitution and profile
 *                                  set; this orchestration; the GoalRunProfile revisions its
 *                                  admitted runs carry; the policies and requirements; and the
 *                                  existing owners it resolves to. It registers no new owner.
 *   PersistentExecutableLineage  — binds one executable artifact's lineage: exact identity and
 *                                  hash, sources and successor, transformation receipts,
 *                                  definition, installation and runtime identities, the durable
 *                                  accountable subject, caretaker and stop policy, leases,
 *                                  dependency lineages, health and effects, and a typed posture.
 *
 * Canon said the receipt was "daemon-derived". It is daemon-ADMITTED: this composer derives it
 * over records this orchestration already admitted; the seam derives its binding and re-derives
 * its `closure_root` by the registered invariant before a byte is served. No daemon route
 * resolves a collective closure (R-192), and this module calls none.
 *
 * THE RULES THIS MODULE EXISTS TO ENFORCE are the cross-record ones the single-record invariant
 * language cannot say, refused HERE by name before any write:
 *   resolution   the release/constitution/profile set are the ACTIVE System's, read from the
 *                daemon, never from the caller; every profile revision is carried by a GoalRun
 *                this orchestration admitted; the orchestration is itself a resolved owner; every
 *                owner ref RESOLVES — by the seam for goals, leases, lineages and the
 *                orchestration, by the daemon's own planes for everything else; nothing registers
 *                a new profile owner; one receipt per identity.
 *   lineage      a lineage is resolved under a receipt this orchestration admitted; its accountable
 *                subject is durable (never a session or a participant); a fork names admitted
 *                parents and a transformation receipt; install binds an installation the daemon
 *                serves; activate binds a runtime the daemon serves, live leases admitted here and
 *                a caretaker that resolves to an accountable actor; transitions are never skipped;
 *                repair and replacement name EXACT successors (a mutable latest is refused);
 *                retirement is terminal; posture is a READ MODEL recomputed from the owners on
 *                every call; removal of a creator or a caretaker never transfers ownership or
 *                extends a lease — it yields a typed posture successor or nothing at all.
 *
 * Both roots are COMPUTED here over canon's preimages — the drafts have no field for them — so a
 * record cannot present a root over members it did not carry.
 *
 * NOT CLAIMED, stated: the daemon has no ArtifactRef producer, so artifact identity arrives here
 * as an opaque `artifact://` ref FROZEN by its sha256 — the composer refuses inexactness, it does
 * not mint artifacts; lease expiry by clock is not evaluated by the daemon, so `expired` is a
 * status successor the M04.11 composer admits, and this module reads liveness by status; runtime
 * health is read through the injected owner resolver (a served runtime is live, an unserved one is
 * not) because the daemon's managed-worker states carry no quarantined/retired/stopped.
 */

import { createHash } from "node:crypto";
import type { Orchestration, SystemRecordAdmitResult, SystemRecordChainResult } from "@ioi/agent-sdk";
import { CONTEXT_CONTRACTS, LEASE_TERMINAL_STATUSES } from "./context.js";

export const COLLECTIVE_CONTRACTS = {
  receipt: "schema://ioi/applications/ioi-ai/collective-resolution-receipt/v1",
  lineage: "schema://ioi/applications/ioi-ai/persistent-executable-lineage/v1",
  goalRun: "schema://ioi/applications/ioi-ai/goal-run/v2",
} as const;

/** The registered consts — this family spells them LONG; pinned by the unit tests against the schemas. */
export const COLLECTIVE_SCHEMA_VERSIONS = {
  receipt: "ioi.applications.ioi-ai.collective-resolution-receipt.v1",
  lineage: "ioi.applications.ioi-ai.persistent-executable-lineage.v1",
} as const;

/** The receipt's preimage, in the registered invariant's member order (18; `closure_root` and the binding excluded). */
export const RECEIPT_ROOT_MEMBERS = [
  "schema_version",
  "receipt_id",
  "receipt_ref",
  "receipt_type",
  "resolved_by_ref",
  "system_id",
  "system_release_ref",
  "constitution_ref",
  "active_profile_set_ref",
  "orchestration_ref",
  "goal_run_profile_revision_refs",
  "policy_refs",
  "lease_policy_refs",
  "artifact_lifecycle_policy_ref",
  "requirement_refs",
  "resolved_owner_refs",
  "registers_no_new_owner",
  "resolved_at",
] as const;

/** The lineage's preimage: every field except `lineage_root` and the binding, in schema order. */
export const LINEAGE_ROOT_MEMBERS = [
  "schema_version",
  "lineage_id",
  "orchestration_ref",
  "resolution_receipt_ref",
  "artifact_ref",
  "artifact_sha256",
  "source_artifact_refs",
  "successor_artifact_ref",
  "transformation_receipt_refs",
  "definition_ref",
  "installation_ref",
  "runtime_ref",
  "runtime_kind",
  "accountable_subject_ref",
  "caretaker_ref",
  "stop_policy_ref",
  "lease_refs",
  "dependency_lineage_refs",
  "health_ref",
  "effect_receipt_refs",
  "posture",
  "successor_of",
] as const;

export const LINEAGE_STATUSES = ["observed", "reused", "forked", "installed", "active", "stopped", "quarantined", "repairing", "replaced", "retired"] as const;
export type LineageStatus = (typeof LINEAGE_STATUSES)[number];
export const ORPHAN_REASONS = ["owner_absent", "caretaker_absent", "dependency_unavailable", "artifact_unavailable", "health_stale", "authority_stale"] as const;
export type OrphanReason = (typeof ORPHAN_REASONS)[number];
export const RUNTIME_KINDS = ["none", "automation_run", "managed_worker_instance", "runtime_assignment", "delegation"] as const;
export type RuntimeKind = (typeof RUNTIME_KINDS)[number];
export const LINEAGE_TERMINAL_STATUSES = new Set<string>(["retired", "replaced"]);

/** Which posture each verb may follow — a transition that skips a step is refused by name. */
export const LINEAGE_TRANSITIONS: Record<string, readonly LineageStatus[]> = {
  install: ["reused", "forked", "repairing"],
  activate: ["installed", "stopped"],
  stop: ["active"],
  quarantine: ["active", "installed", "stopped"],
  repair: ["quarantined", "stopped"],
  replace: ["active", "stopped", "quarantined", "repairing", "installed"],
  retire: ["reused", "forked", "installed", "active", "stopped", "quarantined", "repairing"],
};

export class CollectiveRefusal extends Error {
  readonly code: string;
  readonly detail: Record<string, unknown>;

  constructor(code: string, message: string, detail: Record<string, unknown> = {}) {
    super(message);
    this.name = "CollectiveRefusal";
    this.code = code;
    this.detail = detail;
  }
}

// ---- the preimage, canonicalised exactly as the registered invariants canonicalise it ----------

function canonical(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${canonical(record[k])}`)
    .join(",")}}`;
}

export function rootOf(record: Record<string, unknown>, members: readonly string[]): string {
  const material: Record<string, unknown> = {};
  for (const member of members) {
    if (!(member in record)) throw new CollectiveRefusal("collective_root_member_absent", `the preimage member ${member} is absent`, { member });
    material[member] = record[member];
  }
  return `sha256:${createHash("sha256").update(canonical(material)).digest("hex")}`;
}

// ---- the readers this composer folds through --------------------------------------------------------

/** Asks the daemon's own planes whether a ref it does not hold as a seam record is served. */
export interface OwnerResolver {
  exists(ref: string): Promise<boolean>;
}
/** The ACTIVE System's coordinates, read from the daemon, never from the caller. */
export interface SystemReader {
  active(systemId: string): Promise<{ system_release_ref: string; constitution_ref: string; active_profile_set_ref: string } | null>;
}
/** Whether a ref names an accountable actor of this composition: an accepted participation or a live delegation. */
export interface ActorResolver {
  isAccountable(ref: string): Promise<boolean>;
}

// ---- refs ---------------------------------------------------------------------------------------

/** The registered identity shape: `collective-resolution://crr_<sha256 hex>` — a receipt is named by a digest, never by a slug. */
const RECEIPT_REF = /^collective-resolution:\/\/crr_[0-9a-f]{64}$/u;
/** The schemes a resolver may be named by, per the registered contract. */
const RESOLVER_REF = /^(?:org|project|system|user):\/\/\S{1,500}$/u;

/** Mint the canonical receipt identity for a seed (a caller-chosen name): `collective-resolution://crr_<sha256(seed)>`. */
export function collectiveReceiptId(seed: string): string {
  return `collective-resolution://crr_${createHash("sha256").update(seed).digest("hex")}`;
}
const LINEAGE_REF = /^lineage:\/\/\S+$/u;
const ARTIFACT_REF = /^artifact:\/\/\S+$/u;
const SHA256 = /^sha256:[0-9a-f]{64}$/u;
const ANY_REF = /^[a-z][a-z0-9+._-]*:\/\/\S{1,500}$/u;
const DURABLE_SUBJECT = /^(?:system|installation|worker|automation|automation-run|service|controller|runtime-assignment|managed-worker-instance):\/\/\S+$/u;
const LEASE_REF = /^(?:context-lease|authority-lease|resource-lease|budget-lease):\/\/\S+$/u;

async function readChain(orchestration: Orchestration, contractId: string, objectId: string): Promise<SystemRecordChainResult | null> {
  try {
    const chain = await orchestration.recordChain(contractId, objectId);
    return chain.current ? chain : null;
  } catch (error) {
    const status = (error as { status?: number })?.status;
    // the seam's scope fence answers 403/404 for another composition's or tenant's record: absent here
    if (status === 403 || status === 404) return null;
    throw error;
  }
}

// ---- the receipt --------------------------------------------------------------------------------

export interface ResolutionDraft {
  receipt_id: string;
  goal_run_profile_revision_refs: string[];
  policy_refs: string[];
  lease_policy_refs: string[];
  artifact_lifecycle_policy_ref: string;
  requirement_refs: string[];
  /** The owners the closure resolves to. The orchestration itself must be among them. */
  resolved_owner_refs: string[];
  resolved_at?: string;
}

export class CollectiveResolutions {
  readonly orchestration: Orchestration;
  private readonly owners: OwnerResolver | null;
  private readonly system: SystemReader | null;
  private readonly now: () => string;

  constructor(orchestration: Orchestration, options: { owners?: OwnerResolver; system?: SystemReader; now?: () => string } = {}) {
    this.orchestration = orchestration;
    this.owners = options.owners ?? null;
    this.system = options.system ?? null;
    this.now = options.now ?? (() => new Date().toISOString());
  }

  private async admittedRuns(): Promise<Array<Record<string, unknown>>> {
    const listed = await this.orchestration.records(COLLECTIVE_CONTRACTS.goalRun);
    return listed.records.map((e) => e.current).filter((r): r is Record<string, unknown> => Boolean(r));
  }

  /** An owner ref RESOLVES: by the seam for what this orchestration holds, by the daemon for the rest. */
  async ownerResolves(ref: string, runs?: Array<Record<string, unknown>>): Promise<boolean> {
    if (ref === this.orchestration.scope_ref) return true;
    if (ref.startsWith("app-scope://")) return false;
    if (ref.startsWith("goal://")) return (runs ?? (await this.admittedRuns())).some((r) => r.goal_ref === ref);
    if (ref.startsWith("context-lease://")) return (await readChain(this.orchestration, CONTEXT_CONTRACTS.lease, ref)) !== null;
    if (ref.startsWith("context-cell://")) return (await readChain(this.orchestration, CONTEXT_CONTRACTS.cell, ref)) !== null;
    if (ref.startsWith("lineage://")) return (await readChain(this.orchestration, COLLECTIVE_CONTRACTS.lineage, ref)) !== null;
    if (!this.owners) {
      throw new CollectiveRefusal("collective_resolution_owner_resolver_required", `this composer has no owner resolver, so it cannot know whether ${ref} is served — and it will not assume`, { ref });
    }
    return this.owners.exists(ref);
  }

  async resolve(draft: ResolutionDraft): Promise<SystemRecordAdmitResult> {
    if (!RECEIPT_REF.test(draft.receipt_id)) {
      throw new CollectiveRefusal("collective_resolution_ref_malformed", "a collective-resolution receipt id is collective-resolution://crr_<sha256 hex> — mint it with collectiveReceiptId(seed)", { ref: draft.receipt_id });
    }
    const existing = await readChain(this.orchestration, COLLECTIVE_CONTRACTS.receipt, draft.receipt_id);
    if (existing) {
      throw new CollectiveRefusal("collective_resolution_already_admitted", `receipt ${draft.receipt_id} is already admitted under this orchestration`, { ref: draft.receipt_id });
    }
    if (!this.system) {
      throw new CollectiveRefusal("collective_resolution_system_reader_required", "this composer has no System reader, so it cannot read the ACTIVE System's release, constitution and profile set — and it will not take them from the caller", {});
    }
    const active = await this.system.active(this.orchestration.system_id);
    if (!active) {
      throw new CollectiveRefusal("collective_resolution_system_inactive", `System ${this.orchestration.system_id} is not served as active`, { system_id: this.orchestration.system_id });
    }
    if (!draft.resolved_owner_refs.includes(this.orchestration.scope_ref)) {
      throw new CollectiveRefusal("collective_resolution_orchestration_not_resolved_owner", "the orchestration composing this receipt is itself one of the owners it resolves to; a closure that omits it is somebody else's", { orchestration_ref: this.orchestration.scope_ref });
    }
    const runs = await this.admittedRuns();
    for (const revision of draft.goal_run_profile_revision_refs) {
      if (!runs.some((r) => r.goal_run_profile_revision_ref === revision)) {
        // a revision no admitted run carries is a profile owner this receipt would have to REGISTER,
        // and canon refuses that rather than satisfying it
        throw new CollectiveRefusal("collective_resolution_profile_unadmitted", `no GoalRun admitted under this orchestration carries profile revision ${revision}; a resolution that would need a new profile owner is refused`, { revision });
      }
    }
    for (const owner of draft.resolved_owner_refs) {
      if (!ANY_REF.test(owner)) throw new CollectiveRefusal("collective_resolution_owner_ref_malformed", `${owner} is not a ref`, { owner });
      if (!(await this.ownerResolves(owner, runs))) {
        throw new CollectiveRefusal("collective_resolution_owner_unresolvable", `owner ${owner} does not resolve — not a record under this orchestration and not served by the daemon`, { owner });
      }
    }
    const record: Record<string, unknown> = {
      schema_version: COLLECTIVE_SCHEMA_VERSIONS.receipt,
      receipt_id: draft.receipt_id,
      receipt_ref: draft.receipt_id,
      receipt_type: "collective_resolution",
      // the resolver is the composition's owner when the contract can name it, else the System the resolution is made under
      resolved_by_ref: RESOLVER_REF.test(this.orchestration.owner_ref) ? this.orchestration.owner_ref : this.orchestration.system_id,
      // STAMPED from the daemon's active System, never authored
      system_id: this.orchestration.system_id,
      system_release_ref: active.system_release_ref,
      constitution_ref: active.constitution_ref,
      active_profile_set_ref: active.active_profile_set_ref,
      orchestration_ref: this.orchestration.scope_ref,
      goal_run_profile_revision_refs: [...draft.goal_run_profile_revision_refs],
      policy_refs: [...draft.policy_refs],
      lease_policy_refs: [...draft.lease_policy_refs],
      artifact_lifecycle_policy_ref: draft.artifact_lifecycle_policy_ref,
      requirement_refs: [...draft.requirement_refs],
      resolved_owner_refs: [...draft.resolved_owner_refs],
      registers_no_new_owner: true,
      resolved_at: draft.resolved_at ?? this.now(),
    };
    record.closure_root = rootOf(record, RECEIPT_ROOT_MEMBERS);
    return this.orchestration.record({ contract_id: COLLECTIVE_CONTRACTS.receipt, object_id: draft.receipt_id, record, expected_head: null });
  }

  async read(receiptRef: string): Promise<SystemRecordChainResult | null> {
    return readChain(this.orchestration, COLLECTIVE_CONTRACTS.receipt, receiptRef);
  }
}

// ---- the lineage --------------------------------------------------------------------------------

export interface LineageDraft {
  lineage_id: string;
  resolution_receipt_ref: string;
  artifact_ref: string;
  artifact_sha256: string;
  definition_ref: string;
  accountable_subject_ref: string;
  stop_policy_ref: string;
  dependency_lineage_refs?: string[];
  effect_receipt_refs?: string[];
}

export interface ForkDraft extends LineageDraft {
  source_artifact_refs: string[];
  transformation_receipt_refs: string[];
}

export interface LineagePosture {
  nature: "read_model";
  lineage_id: string;
  recorded: { status: string; orphan_reason: string | null };
  /** What the owners say NOW — the recorded posture is what was admitted, this is what holds. */
  derived: { status: string; orphan_reason: string | null };
  checks: {
    accountable_subject_durable: boolean;
    caretaker_resolves: boolean | null;
    leases_live: boolean;
    dependencies_available: boolean;
    runtime_served: boolean | null;
  };
}

export class ExecutableLineages {
  readonly orchestration: Orchestration;
  private readonly owners: OwnerResolver | null;
  private readonly actors: ActorResolver | null;

  constructor(orchestration: Orchestration, options: { owners?: OwnerResolver; actors?: ActorResolver } = {}) {
    this.orchestration = orchestration;
    this.owners = options.owners ?? null;
    this.actors = options.actors ?? null;
  }

  private requireOwners(): OwnerResolver {
    if (!this.owners) throw new CollectiveRefusal("lineage_owner_resolver_required", "this composer has no owner resolver, so it cannot know whether an installation or runtime is served — and it will not assume", {});
    return this.owners;
  }

  private async requireLineage(ref: string, what: string): Promise<SystemRecordChainResult> {
    if (!LINEAGE_REF.test(ref)) throw new CollectiveRefusal("lineage_ref_malformed", `${what} names a lineage as lineage://…`, { ref });
    const chain = await readChain(this.orchestration, COLLECTIVE_CONTRACTS.lineage, ref);
    if (!chain) throw new CollectiveRefusal("lineage_unknown", `${what}: no lineage ${ref} under this orchestration`, { ref });
    return chain;
  }

  private async requireDependencies(refs: readonly string[]): Promise<void> {
    for (const dep of refs) {
      const chain = await readChain(this.orchestration, COLLECTIVE_CONTRACTS.lineage, dep);
      if (!chain) throw new CollectiveRefusal("lineage_dependency_unknown", `dependency ${dep} is not a lineage under this orchestration`, { dependency: dep });
      const status = String((chain.current as Record<string, unknown>).posture && ((chain.current as Record<string, unknown>).posture as Record<string, unknown>).status);
      if (LINEAGE_TERMINAL_STATUSES.has(status)) throw new CollectiveRefusal("lineage_dependency_retired", `dependency ${dep} is ${status}`, { dependency: dep, status });
    }
  }

  private async base(draft: LineageDraft, what: string): Promise<Record<string, unknown>> {
    if (!LINEAGE_REF.test(draft.lineage_id)) throw new CollectiveRefusal("lineage_ref_malformed", "a lineage id is lineage://…", { ref: draft.lineage_id });
    if (!ARTIFACT_REF.test(draft.artifact_ref)) throw new CollectiveRefusal("lineage_artifact_ref_malformed", "an artifact ref is artifact://…", { ref: draft.artifact_ref });
    if (!SHA256.test(draft.artifact_sha256)) {
      throw new CollectiveRefusal("lineage_mutable_latest_refused", `${what} binds an EXACT artifact: a sha256 is required, a moving latest is not an identity`, { artifact_ref: draft.artifact_ref });
    }
    if (!DURABLE_SUBJECT.test(draft.accountable_subject_ref)) {
      throw new CollectiveRefusal("lineage_accountable_subject_not_durable", `${draft.accountable_subject_ref} is not a durable subject; a session or a participant cannot be the accountable subject of a runtime that outlives it`, { ref: draft.accountable_subject_ref });
    }
    const existing = await readChain(this.orchestration, COLLECTIVE_CONTRACTS.lineage, draft.lineage_id);
    if (existing) throw new CollectiveRefusal("lineage_already_admitted", `lineage ${draft.lineage_id} is already admitted under this orchestration`, { ref: draft.lineage_id });
    const receipt = await readChain(this.orchestration, COLLECTIVE_CONTRACTS.receipt, draft.resolution_receipt_ref);
    if (!receipt) throw new CollectiveRefusal("lineage_resolution_receipt_unknown", `no collective-resolution receipt ${draft.resolution_receipt_ref} under this orchestration; a lineage is resolved under one`, { ref: draft.resolution_receipt_ref });
    await this.requireDependencies(draft.dependency_lineage_refs ?? []);
    return {
      schema_version: COLLECTIVE_SCHEMA_VERSIONS.lineage,
      lineage_id: draft.lineage_id,
      orchestration_ref: this.orchestration.scope_ref,
      resolution_receipt_ref: draft.resolution_receipt_ref,
      artifact_ref: draft.artifact_ref,
      artifact_sha256: draft.artifact_sha256,
      source_artifact_refs: [],
      successor_artifact_ref: null,
      transformation_receipt_refs: [],
      definition_ref: draft.definition_ref,
      installation_ref: null,
      runtime_ref: null,
      runtime_kind: "none",
      accountable_subject_ref: draft.accountable_subject_ref,
      caretaker_ref: null,
      stop_policy_ref: draft.stop_policy_ref,
      lease_refs: [],
      dependency_lineage_refs: [...(draft.dependency_lineage_refs ?? [])],
      health_ref: null,
      effect_receipt_refs: [...(draft.effect_receipt_refs ?? [])],
      posture: { status: "reused", orphan_reason: null },
      successor_of: null,
    };
  }

  private async admit(record: Record<string, unknown>): Promise<SystemRecordAdmitResult> {
    record.lineage_root = rootOf(record, LINEAGE_ROOT_MEMBERS);
    return this.orchestration.record({ contract_id: COLLECTIVE_CONTRACTS.lineage, object_id: String(record.lineage_id), record, expected_head: null });
  }

  private async succeed(chain: SystemRecordChainResult, patch: Record<string, unknown>): Promise<SystemRecordAdmitResult> {
    const { system_binding: _b, lineage_root: _r, ...rest } = chain.current as Record<string, unknown>;
    const record: Record<string, unknown> = { ...rest, ...patch };
    record.lineage_root = rootOf(record, LINEAGE_ROOT_MEMBERS);
    return this.orchestration.record({ contract_id: COLLECTIVE_CONTRACTS.lineage, object_id: String(record.lineage_id), record, expected_head: chain.head });
  }

  private requireTransition(chain: SystemRecordChainResult, verb: keyof typeof LINEAGE_TRANSITIONS): Record<string, unknown> {
    const current = chain.current as Record<string, unknown>;
    const status = String((current.posture as Record<string, unknown>).status);
    if (LINEAGE_TERMINAL_STATUSES.has(status)) throw new CollectiveRefusal("lineage_terminal", `lineage ${String(current.lineage_id)} is ${status}; a terminal lineage admits no successor`, { status });
    if (!LINEAGE_TRANSITIONS[verb].includes(status as LineageStatus)) {
      throw new CollectiveRefusal("lineage_transition_skipped", `${verb} does not follow ${status}; it follows ${LINEAGE_TRANSITIONS[verb].join(", ")}`, { verb, status });
    }
    return current;
  }

  /** Observation is a READ MODEL: it persists nothing and confers nothing. */
  async observe(artifactRef: string, artifactSha256: string): Promise<{ nature: "read_model"; artifact_ref: string; artifact_sha256: string; exact: boolean; persisted: false; lineages_here: string[] }> {
    const listed = await this.orchestration.records(COLLECTIVE_CONTRACTS.lineage);
    const here = listed.records.map((e) => e.current).filter((r): r is Record<string, unknown> => Boolean(r) && r!.artifact_ref === artifactRef).map((r) => String(r.lineage_id));
    return { nature: "read_model", artifact_ref: artifactRef, artifact_sha256: artifactSha256, exact: SHA256.test(artifactSha256), persisted: false, lineages_here: here };
  }

  /** Reuse admits a lineage over an EXACT existing artifact, under a receipt this orchestration admitted. */
  async reuse(draft: LineageDraft): Promise<SystemRecordAdmitResult> {
    return this.admit(await this.base(draft, "a reuse"));
  }

  /** A fork names the admitted lineages it was forked from and the transformation receipt that produced it. */
  async fork(draft: ForkDraft): Promise<SystemRecordAdmitResult> {
    const record = await this.base(draft, "a fork");
    if (draft.source_artifact_refs.length === 0) throw new CollectiveRefusal("lineage_fork_parent_absent", "a fork names the exact source artifacts it was forked from", {});
    if (draft.transformation_receipt_refs.length === 0) throw new CollectiveRefusal("lineage_fork_receipt_absent", "a fork is a governed transformation and names the receipt that produced it", {});
    const listed = await this.orchestration.records(COLLECTIVE_CONTRACTS.lineage);
    const known = new Set(listed.records.map((e) => e.current).filter(Boolean).map((r) => String((r as Record<string, unknown>).artifact_ref)));
    for (const parent of draft.source_artifact_refs) {
      if (!known.has(parent)) throw new CollectiveRefusal("lineage_fork_parent_unknown", `parent ${parent} is not the artifact of any lineage under this orchestration`, { parent });
    }
    record.source_artifact_refs = [...draft.source_artifact_refs];
    record.transformation_receipt_refs = [...draft.transformation_receipt_refs];
    record.posture = { status: "forked", orphan_reason: null };
    return this.admit(record);
  }

  /** Install binds the exact artifact to an installation the daemon serves. */
  async install(lineageRef: string, input: { installation_ref: string; definition_ref?: string }): Promise<SystemRecordAdmitResult> {
    const chain = await this.requireLineage(lineageRef, "an install");
    this.requireTransition(chain, "install");
    if (!ANY_REF.test(input.installation_ref)) throw new CollectiveRefusal("lineage_installation_ref_malformed", "an installation ref is a ref", { ref: input.installation_ref });
    if (!(await this.requireOwners().exists(input.installation_ref))) {
      throw new CollectiveRefusal("lineage_installation_unbound", `installation ${input.installation_ref} is not served by the daemon; a lineage installs into something that exists`, { ref: input.installation_ref });
    }
    const patch: Record<string, unknown> = { installation_ref: input.installation_ref, posture: { status: "installed", orphan_reason: null } };
    if (input.definition_ref) patch.definition_ref = input.definition_ref;
    return this.succeed(chain, patch);
  }

  /** Activate binds a runtime the daemon serves, live leases admitted here, and a caretaker that resolves. */
  async activate(lineageRef: string, input: { runtime_ref: string; runtime_kind: RuntimeKind; lease_refs: string[]; caretaker_ref: string; health_ref?: string | null }): Promise<SystemRecordAdmitResult> {
    const chain = await this.requireLineage(lineageRef, "an activation");
    const current = this.requireTransition(chain, "activate");
    if (input.runtime_kind === "none" || !RUNTIME_KINDS.includes(input.runtime_kind)) {
      throw new CollectiveRefusal("lineage_runtime_kind_unrecognized", `${String(input.runtime_kind)} is not a runtime kind a lineage can be active as`, { runtime_kind: input.runtime_kind });
    }
    if (!ANY_REF.test(input.runtime_ref) || !(await this.requireOwners().exists(input.runtime_ref))) {
      throw new CollectiveRefusal("lineage_runtime_unbound", `runtime ${input.runtime_ref} is not served by the daemon; ArtifactRef.lifecycle.status = active satisfies nothing — a lineage is active as a runtime that exists`, { ref: input.runtime_ref });
    }
    for (const leaseRef of input.lease_refs) {
      if (!LEASE_REF.test(leaseRef)) throw new CollectiveRefusal("lineage_lease_ref_malformed", `${leaseRef} is not a lease ref`, { ref: leaseRef });
      if (leaseRef.startsWith("context-lease://")) {
        const lease = await readChain(this.orchestration, CONTEXT_CONTRACTS.lease, leaseRef);
        if (!lease) throw new CollectiveRefusal("lineage_lease_unknown", `lease ${leaseRef} is not admitted under this orchestration`, { ref: leaseRef });
        if (LEASE_TERMINAL_STATUSES.has(String((lease.current as Record<string, unknown>).status))) {
          throw new CollectiveRefusal("lineage_lease_not_live", `lease ${leaseRef} is ${String((lease.current as Record<string, unknown>).status)}; a runtime activates under live leases only`, { ref: leaseRef });
        }
      } else if (!(await this.requireOwners().exists(leaseRef))) {
        throw new CollectiveRefusal("lineage_lease_unknown", `lease ${leaseRef} is not served`, { ref: leaseRef });
      }
    }
    if (!this.actors) throw new CollectiveRefusal("lineage_actor_resolver_required", "this composer has no actor resolver, so it cannot know whether the caretaker is an accountable actor — and it will not assume", {});
    if (!(await this.actors.isAccountable(input.caretaker_ref))) {
      throw new CollectiveRefusal("lineage_caretaker_unresolvable", `caretaker ${input.caretaker_ref} is not an accepted participation or a live delegation of this composition`, { ref: input.caretaker_ref });
    }
    await this.requireDependencies(current.dependency_lineage_refs as string[]);
    return this.succeed(chain, {
      runtime_ref: input.runtime_ref,
      runtime_kind: input.runtime_kind,
      lease_refs: [...input.lease_refs],
      caretaker_ref: input.caretaker_ref,
      health_ref: input.health_ref ?? null,
      posture: { status: "active", orphan_reason: null },
    });
  }

  /**
   * Posture is a READ MODEL recomputed from the owners on every call and persisting nothing: what
   * was admitted is `recorded`; what the owners say now is `derived`. The two can differ, and the
   * difference is exactly the orphaned condition canon types.
   */
  async posture(lineageRef: string): Promise<LineagePosture> {
    const chain = await this.requireLineage(lineageRef, "a posture");
    const current = chain.current as Record<string, unknown>;
    const recorded = current.posture as { status: string; orphan_reason: string | null };
    const durable = DURABLE_SUBJECT.test(String(current.accountable_subject_ref));
    let caretaker: boolean | null = null;
    if (current.caretaker_ref) caretaker = this.actors ? await this.actors.isAccountable(String(current.caretaker_ref)) : null;
    let leasesLive = true;
    for (const leaseRef of current.lease_refs as string[]) {
      if (!leaseRef.startsWith("context-lease://")) continue;
      const lease = await readChain(this.orchestration, CONTEXT_CONTRACTS.lease, leaseRef);
      if (!lease || LEASE_TERMINAL_STATUSES.has(String((lease.current as Record<string, unknown>).status))) { leasesLive = false; break; }
    }
    let depsAvailable = true;
    for (const dep of current.dependency_lineage_refs as string[]) {
      const d = await readChain(this.orchestration, COLLECTIVE_CONTRACTS.lineage, dep);
      if (!d || LINEAGE_TERMINAL_STATUSES.has(String(((d.current as Record<string, unknown>).posture as Record<string, unknown>).status))) { depsAvailable = false; break; }
    }
    let runtimeServed: boolean | null = null;
    if (current.runtime_ref) runtimeServed = this.owners ? await this.owners.exists(String(current.runtime_ref)) : null;
    let derived: { status: string; orphan_reason: string | null } = { ...recorded };
    if (recorded.status === "active") {
      if (!durable) derived = { status: "stopped", orphan_reason: "owner_absent" };
      else if (caretaker === false) derived = { status: "quarantined", orphan_reason: "caretaker_absent" };
      else if (!leasesLive) derived = { status: "stopped", orphan_reason: "authority_stale" };
      else if (!depsAvailable) derived = { status: "stopped", orphan_reason: "dependency_unavailable" };
      else if (runtimeServed === false) derived = { status: "stopped", orphan_reason: "health_stale" };
    }
    return { nature: "read_model", lineage_id: lineageRef, recorded, derived, checks: { accountable_subject_durable: durable, caretaker_resolves: caretaker, leases_live: leasesLive, dependencies_available: depsAvailable, runtime_served: runtimeServed } };
  }

  /** A stop made BECAUSE of an orphan condition carries its typed reason; a policy stop carries none. */
  async stop(lineageRef: string, reason: OrphanReason | "policy"): Promise<SystemRecordAdmitResult> {
    const chain = await this.requireLineage(lineageRef, "a stop");
    this.requireTransition(chain, "stop");
    if (reason !== "policy" && !ORPHAN_REASONS.includes(reason)) throw new CollectiveRefusal("lineage_orphan_reason_unrecognized", `${String(reason)} is not a typed orphan reason`, { reason });
    return this.succeed(chain, { posture: { status: "stopped", orphan_reason: reason === "policy" ? null : reason } });
  }

  async quarantine(lineageRef: string, reason: OrphanReason): Promise<SystemRecordAdmitResult> {
    const chain = await this.requireLineage(lineageRef, "a quarantine");
    this.requireTransition(chain, "quarantine");
    if (!ORPHAN_REASONS.includes(reason)) throw new CollectiveRefusal("lineage_orphan_reason_unrecognized", `${String(reason)} is not a typed orphan reason; a quarantine is always an orphaned condition and names it`, { reason });
    return this.succeed(chain, { posture: { status: "quarantined", orphan_reason: reason } });
  }

  /** Repair names an EXACT successor artifact and the transformation receipt that produced it. */
  async repair(lineageRef: string, input: { successor_artifact_ref: string; successor_artifact_sha256: string; transformation_receipt_ref: string }): Promise<SystemRecordAdmitResult> {
    const chain = await this.requireLineage(lineageRef, "a repair");
    const current = this.requireTransition(chain, "repair");
    if (!ARTIFACT_REF.test(input.successor_artifact_ref)) throw new CollectiveRefusal("lineage_artifact_ref_malformed", "a successor artifact ref is artifact://…", { ref: input.successor_artifact_ref });
    if (!SHA256.test(input.successor_artifact_sha256)) throw new CollectiveRefusal("lineage_mutable_latest_refused", "a repair names an EXACT successor artifact by sha256; a moving latest cannot repair anything", { ref: input.successor_artifact_ref });
    if (!ANY_REF.test(input.transformation_receipt_ref)) throw new CollectiveRefusal("lineage_fork_receipt_absent", "a repair is a governed transformation and names its receipt", {});
    return this.succeed(chain, {
      successor_artifact_ref: input.successor_artifact_ref,
      transformation_receipt_refs: [...(current.transformation_receipt_refs as string[]), input.transformation_receipt_ref],
      posture: { status: "repairing", orphan_reason: null },
    });
  }

  /** Replacement names an admitted successor lineage that names this one as its predecessor; this lineage becomes terminal. */
  async replace(lineageRef: string, input: { successor_lineage_ref: string }): Promise<SystemRecordAdmitResult> {
    const chain = await this.requireLineage(lineageRef, "a replacement");
    this.requireTransition(chain, "replace");
    const successor = await readChain(this.orchestration, COLLECTIVE_CONTRACTS.lineage, input.successor_lineage_ref);
    if (!successor) throw new CollectiveRefusal("lineage_replacement_unknown", `successor ${input.successor_lineage_ref} is not a lineage under this orchestration`, { ref: input.successor_lineage_ref });
    if ((successor.current as Record<string, unknown>).successor_of !== lineageRef) {
      throw new CollectiveRefusal("lineage_replacement_not_a_successor", `${input.successor_lineage_ref} does not name ${lineageRef} as its predecessor`, { ref: input.successor_lineage_ref });
    }
    return this.succeed(chain, { posture: { status: "replaced", orphan_reason: null } });
  }

  /** A successor lineage: admitted like a reuse or fork, naming its predecessor (which must be admitted here and non-terminal). */
  async succeedFrom(predecessorRef: string, draft: LineageDraft): Promise<SystemRecordAdmitResult> {
    const prior = await this.requireLineage(predecessorRef, "a successor");
    const status = String(((prior.current as Record<string, unknown>).posture as Record<string, unknown>).status);
    if (LINEAGE_TERMINAL_STATUSES.has(status)) throw new CollectiveRefusal("lineage_terminal", `lineage ${predecessorRef} is ${status}`, { status });
    const record = await this.base(draft, "a successor");
    record.source_artifact_refs = [String((prior.current as Record<string, unknown>).artifact_ref)];
    record.successor_of = predecessorRef;
    return this.admit(record);
  }

  async retire(lineageRef: string): Promise<SystemRecordAdmitResult> {
    const chain = await this.requireLineage(lineageRef, "a retirement");
    this.requireTransition(chain, "retire");
    return this.succeed(chain, { posture: { status: "retired", orphan_reason: null }, runtime_ref: null, runtime_kind: "none" });
  }

  /** The creating principal's session ended: nothing moves. The subject is durable by construction, so this reports and writes nothing. */
  async onCreatorRemoved(lineageRef: string, sessionRef: string): Promise<{ transferred: false; extended: false; posture: LineagePosture }> {
    const posture = await this.posture(lineageRef);
    if (posture.checks.accountable_subject_durable === false) {
      throw new CollectiveRefusal("lineage_ownership_transfer_refused", `lineage ${lineageRef} has no durable accountable subject; removal of ${sessionRef} transfers nothing and this composer will not invent an owner`, { session_ref: sessionRef });
    }
    return { transferred: false, extended: false, posture };
  }

  /** A participation exited: if it was the caretaker, the lineage is quarantined with the typed reason; otherwise nothing moves. */
  async onParticipantExited(lineageRef: string, participationRef: string): Promise<SystemRecordAdmitResult | null> {
    const chain = await this.requireLineage(lineageRef, "a participant exit");
    const current = chain.current as Record<string, unknown>;
    if (current.caretaker_ref !== participationRef) return null;
    const status = String((current.posture as Record<string, unknown>).status);
    if (!LINEAGE_TRANSITIONS.quarantine.includes(status as LineageStatus)) return null;
    return this.succeed(chain, { posture: { status: "quarantined", orphan_reason: "caretaker_absent" } });
  }

  async read(lineageRef: string): Promise<SystemRecordChainResult | null> {
    return readChain(this.orchestration, COLLECTIVE_CONTRACTS.lineage, lineageRef);
  }
}

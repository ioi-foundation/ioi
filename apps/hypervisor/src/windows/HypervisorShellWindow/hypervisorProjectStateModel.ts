import { PROJECT_SCOPES, type ProjectScope } from "./hypervisorShellModel.ts";
import { DEFAULT_WORKBENCH_ADAPTER_PREFERENCE_REF } from "./hypervisorShellNavigationModel.ts";
import { HYPERVISOR_PRIVACY_POSTURE_PROJECTION_FIXTURE } from "./hypervisorPrivacyPostureModel.ts";
import { HYPERVISOR_PROVIDER_PLACEMENT_PROJECTION_FIXTURE } from "./hypervisorProviderPlacementModel.ts";
import { HYPERVISOR_RECEIPT_EVIDENCE_PROJECTION_FIXTURE } from "./hypervisorReceiptEvidenceModel.ts";
import { HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE } from "./hypervisorSessionOperationsModel.ts";

export type HypervisorProjectRestoreState =
  | "active"
  | "idle"
  | "archived"
  | "restore_ready"
  | "needs_authority";

export type HypervisorProjectCustodyPosture =
  | "local_private"
  | "redacted_remote"
  | "encrypted_archive"
  | "provider_session";

export interface HypervisorProjectStateRecord {
  project_id: string;
  name: string;
  description: string;
  environment: string;
  root_path: string;
  workspace_ref: string;
  current_session_ref: string | null;
  environment_ref: string | null;
  provider_candidate_ref: string | null;
  adapter_preference_ref: string;
  custody_posture: HypervisorProjectCustodyPosture;
  restore_state: HypervisorProjectRestoreState;
  agentgres_object_head_ref: string;
  state_root_ref: string;
  artifact_refs: string[];
  archive_ref: string;
  restore_ref: string;
  latest_receipt_refs: string[];
}

export interface HypervisorProjectStateProjection {
  schema_version: "ioi.hypervisor.project_state_projection.v1";
  projection_id: string;
  source: "daemon-project-state-projection" | "fixture" | "unverified";
  selected_project_id: string;
  records: HypervisorProjectStateRecord[];
  project_boundary_invariant: string;
  runtimeTruthSource: "daemon-runtime";
}

export const HYPERVISOR_PROJECT_STATE_DAEMON_ENDPOINT_STORAGE_KEY =
  "ioi.hypervisor.daemonEndpoint";
export const HYPERVISOR_PROJECT_STATE_DEFAULT_DAEMON_ENDPOINT =
  "http://127.0.0.1:8765";
export const HYPERVISOR_PROJECT_STATE_PROJECTION_PATH =
  "/v1/hypervisor/project-state";

type FetchLike = (
  input: string,
  init?: { method?: string; headers?: Record<string, string> },
) => Promise<{
  ok: boolean;
  status: number;
  text(): Promise<string>;
}>;

interface NormalizeProjectStateProjectionOptions {
  source?: HypervisorProjectStateProjection["source"];
}

interface LoadProjectStateProjectionOptions
  extends NormalizeProjectStateProjectionOptions {
  endpoint?: string;
  fetchImpl?: FetchLike;
  projectId?: string | null;
}

function projectRefId(project: ProjectScope): string {
  return `project:${project.id}`;
}

function projectRecord(
  project: ProjectScope,
  index: number,
): HypervisorProjectStateRecord {
  const isSelected = project.id === "hypervisor-core";
  const projectRef = projectRefId(project);
  const slug = project.id.replace(/[^a-z0-9-]+/gi, "-").toLowerCase();
  return {
    project_id: project.id,
    name: project.name,
    description: project.description,
    environment: project.environment,
    root_path: project.rootPath,
    workspace_ref: `workspace://${slug}`,
    current_session_ref: isSelected
      ? HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE.selected_session_ref
      : null,
    environment_ref: isSelected
      ? HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE.environment_ref
      : `environment:project/${slug}`,
    provider_candidate_ref: isSelected
      ? HYPERVISOR_PROVIDER_PLACEMENT_PROJECTION_FIXTURE.candidates[0]
          ?.candidate_ref ?? null
      : null,
    adapter_preference_ref: DEFAULT_WORKBENCH_ADAPTER_PREFERENCE_REF,
    custody_posture:
      index === 0 ? "local_private" : index === 1 ? "encrypted_archive" : "redacted_remote",
    restore_state:
      index === 0 ? "active" : index === 1 ? "restore_ready" : "needs_authority",
    agentgres_object_head_ref: `agentgres://object-head/${projectRef}`,
    state_root_ref: `agentgres://state-root/${projectRef}`,
    artifact_refs: [
      `artifact://project/${slug}/workspace-summary`,
      HYPERVISOR_PRIVACY_POSTURE_PROJECTION_FIXTURE.workspace_segments[
        Math.min(index, HYPERVISOR_PRIVACY_POSTURE_PROJECTION_FIXTURE.workspace_segments.length - 1)
      ]?.evidence_refs[0] ?? `artifact://project/${slug}/encrypted-ref`,
    ],
    archive_ref: isSelected
      ? HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE.archive_ref
      : `artifact://agentgres/archive/${slug}/latest`,
    restore_ref: isSelected
      ? HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE.restore_ref
      : `agentgres://restore/${slug}/latest`,
    latest_receipt_refs: isSelected
      ? HYPERVISOR_RECEIPT_EVIDENCE_PROJECTION_FIXTURE.records
          .slice(0, 3)
          .map((record) => record.receipt_ref)
      : [`receipt://project/${slug}/state`],
  };
}

export const HYPERVISOR_PROJECT_STATE_PROJECTION_FIXTURE: HypervisorProjectStateProjection =
  {
    schema_version: "ioi.hypervisor.project_state_projection.v1",
    projection_id: "project-state:hypervisor-core/default",
    source: "fixture",
    selected_project_id: "hypervisor-core",
    records: PROJECT_SCOPES.map(projectRecord),
    project_boundary_invariant:
      "Projects group workspace refs, sessions, adapter preferences, artifact refs, archive refs, restore refs, state roots, and receipts. Hypervisor clients inspect project state; Agentgres admits project truth and storage backends only hold bytes.",
    runtimeTruthSource: "daemon-runtime",
  };

export const HYPERVISOR_PROJECT_STATE_CLEAN_BOOT_PROJECTION: HypervisorProjectStateProjection =
  {
    schema_version: "ioi.hypervisor.project_state_projection.v1",
    projection_id: "project-state:clean-boot/empty",
    source: "fixture",
    selected_project_id: "",
    records: [],
    project_boundary_invariant:
      HYPERVISOR_PROJECT_STATE_PROJECTION_FIXTURE.project_boundary_invariant,
    runtimeTruthSource: "daemon-runtime",
  };

function objectRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function arrayOf(value: unknown): Record<string, unknown>[] {
  return Array.isArray(value) ? value.map(objectRecord) : [];
}

function stringValue(value: unknown, fallback: string): string {
  return typeof value === "string" && value.trim() ? value.trim() : fallback;
}

function nullableStringValue(value: unknown, fallback: string | null): string | null {
  return value === null || typeof value === "undefined"
    ? fallback
    : stringValue(value, fallback ?? "");
}

function stringList(value: unknown, fallback: string[]): string[] {
  if (!Array.isArray(value)) {
    return fallback;
  }
  const values = value
    .filter((item): item is string => typeof item === "string" && !!item.trim())
    .map((item) => item.trim());
  return values.length > 0 ? values : fallback;
}

function enumValue<T extends string>(
  value: unknown,
  fallback: T,
  allowed: readonly T[],
): T {
  return typeof value === "string" && allowed.includes(value as T)
    ? (value as T)
    : fallback;
}

function normalizeProjectStateRecord(
  item: Record<string, unknown>,
  index: number,
): HypervisorProjectStateRecord {
  const fallback =
    HYPERVISOR_PROJECT_STATE_PROJECTION_FIXTURE.records[index] ??
    HYPERVISOR_PROJECT_STATE_PROJECTION_FIXTURE.records[0]!;
  return {
    project_id: stringValue(item.project_id, fallback.project_id),
    name: stringValue(item.name, fallback.name),
    description: stringValue(item.description, fallback.description),
    environment: stringValue(item.environment, fallback.environment),
    root_path: stringValue(item.root_path, fallback.root_path),
    workspace_ref: stringValue(item.workspace_ref, fallback.workspace_ref),
    current_session_ref: nullableStringValue(
      item.current_session_ref,
      fallback.current_session_ref,
    ),
    environment_ref: nullableStringValue(
      item.environment_ref,
      fallback.environment_ref,
    ),
    provider_candidate_ref: nullableStringValue(
      item.provider_candidate_ref,
      fallback.provider_candidate_ref,
    ),
    adapter_preference_ref: stringValue(
      item.adapter_preference_ref,
      fallback.adapter_preference_ref,
    ),
    custody_posture: enumValue(item.custody_posture, fallback.custody_posture, [
      "local_private",
      "redacted_remote",
      "encrypted_archive",
      "provider_session",
    ]),
    restore_state: enumValue(item.restore_state, fallback.restore_state, [
      "active",
      "idle",
      "archived",
      "restore_ready",
      "needs_authority",
    ]),
    agentgres_object_head_ref: stringValue(
      item.agentgres_object_head_ref,
      fallback.agentgres_object_head_ref,
    ),
    state_root_ref: stringValue(item.state_root_ref, fallback.state_root_ref),
    artifact_refs: stringList(item.artifact_refs, fallback.artifact_refs),
    archive_ref: stringValue(item.archive_ref, fallback.archive_ref),
    restore_ref: stringValue(item.restore_ref, fallback.restore_ref),
    latest_receipt_refs: stringList(
      item.latest_receipt_refs,
      fallback.latest_receipt_refs,
    ),
  };
}

export function readHypervisorProjectStateDaemonEndpoint(): string {
  try {
    if (typeof window === "undefined") {
      return HYPERVISOR_PROJECT_STATE_DEFAULT_DAEMON_ENDPOINT;
    }
    return (
      window.localStorage.getItem(
        HYPERVISOR_PROJECT_STATE_DAEMON_ENDPOINT_STORAGE_KEY,
      ) || HYPERVISOR_PROJECT_STATE_DEFAULT_DAEMON_ENDPOINT
    );
  } catch {
    return HYPERVISOR_PROJECT_STATE_DEFAULT_DAEMON_ENDPOINT;
  }
}

export function normalizeHypervisorProjectStateProjection(
  snapshot: unknown,
  options: NormalizeProjectStateProjectionOptions = {},
): HypervisorProjectStateProjection {
  const value = objectRecord(snapshot);
  const fallback = HYPERVISOR_PROJECT_STATE_PROJECTION_FIXTURE;
  const records = arrayOf(value.records).map(normalizeProjectStateRecord);
  return {
    schema_version: "ioi.hypervisor.project_state_projection.v1",
    projection_id: stringValue(value.projection_id, fallback.projection_id),
    source: options.source ?? "daemon-project-state-projection",
    selected_project_id: stringValue(
      value.selected_project_id,
      fallback.selected_project_id,
    ),
    records: records.length > 0 ? records : fallback.records,
    project_boundary_invariant: stringValue(
      value.project_boundary_invariant,
      fallback.project_boundary_invariant,
    ),
    runtimeTruthSource: "daemon-runtime",
  };
}

export async function loadHypervisorProjectStateProjection(
  options: LoadProjectStateProjectionOptions = {},
): Promise<HypervisorProjectStateProjection> {
  const endpoint = options.endpoint ?? readHypervisorProjectStateDaemonEndpoint();
  const fetchImpl = options.fetchImpl ?? globalThis.fetch?.bind(globalThis);
  if (!fetchImpl) {
    throw new Error("fetch unavailable for Hypervisor project state projection");
  }
  const query = new URLSearchParams();
  if (options.projectId) {
    query.set("project_id", options.projectId);
  }
  const suffix = query.toString() ? `?${query.toString()}` : "";
  const url = `${endpoint.replace(/\/+$/, "")}${HYPERVISOR_PROJECT_STATE_PROJECTION_PATH}${suffix}`;
  const response = await fetchImpl(url, {
    method: "GET",
    headers: { accept: "application/json" },
  });
  const text = await response.text();
  const value = text ? JSON.parse(text) : {};
  if (!response.ok) {
    throw new Error(
      `Project state projection request failed with ${response.status}`,
    );
  }
  return normalizeHypervisorProjectStateProjection(value, {
    source: options.source ?? "daemon-project-state-projection",
  });
}

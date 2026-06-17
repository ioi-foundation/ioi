import { PROJECT_SCOPES, type ProjectScope } from "./hypervisorShellModel";
import { DEFAULT_WORKBENCH_ADAPTER_PREFERENCE_REF } from "./hypervisorShellNavigationModel";
import { HYPERVISOR_PRIVACY_POSTURE_PROJECTION_FIXTURE } from "./hypervisorPrivacyPostureModel";
import { HYPERVISOR_PROVIDER_PLACEMENT_PROJECTION_FIXTURE } from "./hypervisorProviderPlacementModel";
import { HYPERVISOR_RECEIPT_EVIDENCE_PROJECTION_FIXTURE } from "./hypervisorReceiptEvidenceModel";
import { HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE } from "./hypervisorSessionOperationsModel";

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
  selected_project_id: string;
  records: HypervisorProjectStateRecord[];
  project_boundary_invariant: string;
  runtimeTruthSource: "daemon-runtime";
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
    selected_project_id: "hypervisor-core",
    records: PROJECT_SCOPES.map(projectRecord),
    project_boundary_invariant:
      "Projects group workspace refs, sessions, adapter preferences, artifact refs, archive refs, restore refs, state roots, and receipts. Hypervisor clients inspect project state; Agentgres admits project truth and storage backends only hold bytes.",
    runtimeTruthSource: "daemon-runtime",
  };

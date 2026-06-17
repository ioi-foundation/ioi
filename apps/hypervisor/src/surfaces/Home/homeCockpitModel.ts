import { HYPERVISOR_HARNESS_COMPARISON_RUN_FIXTURE } from "../../windows/HypervisorShellWindow/harnessAdapterModel";
import { HYPERVISOR_PRIVACY_POSTURE_PROJECTION_FIXTURE } from "../../windows/HypervisorShellWindow/hypervisorPrivacyPostureModel";
import { HYPERVISOR_PROJECT_STATE_PROJECTION_FIXTURE } from "../../windows/HypervisorShellWindow/hypervisorProjectStateModel";
import { HYPERVISOR_PROVIDER_PLACEMENT_PROJECTION_FIXTURE } from "../../windows/HypervisorShellWindow/hypervisorProviderPlacementModel";
import { HYPERVISOR_RECEIPT_EVIDENCE_PROJECTION_FIXTURE } from "../../windows/HypervisorShellWindow/hypervisorReceiptEvidenceModel";
import { HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE } from "../../windows/HypervisorShellWindow/hypervisorSessionOperationsModel";

export interface HypervisorHomeCockpitMetric {
  metric_ref: string;
  label: string;
  value: string;
  detail: string;
  surface_ref: string;
  evidence_refs: string[];
}

export interface HypervisorHomeCockpitProjection {
  schema_version: "ioi.hypervisor.home_cockpit_projection.v1";
  projection_id: string;
  selected_project_id: string;
  runtimeTruthSource: "daemon-runtime";
  boundary_invariant: string;
  metrics: HypervisorHomeCockpitMetric[];
}

const selectedProject =
  HYPERVISOR_PROJECT_STATE_PROJECTION_FIXTURE.records.find(
    (record) =>
      record.project_id ===
      HYPERVISOR_PROJECT_STATE_PROJECTION_FIXTURE.selected_project_id,
  ) ?? HYPERVISOR_PROJECT_STATE_PROJECTION_FIXTURE.records[0];

const selectedProvider =
  HYPERVISOR_PROVIDER_PLACEMENT_PROJECTION_FIXTURE.candidates.find(
    (candidate) =>
      candidate.candidate_ref === selectedProject?.provider_candidate_ref,
  ) ?? HYPERVISOR_PROVIDER_PLACEMENT_PROJECTION_FIXTURE.candidates[0];

const blockedPrivacyControls =
  HYPERVISOR_PRIVACY_POSTURE_PROJECTION_FIXTURE.admission_controls.filter(
    (control) => control.blocks_unsafe_plaintext,
  );

export const HYPERVISOR_HOME_COCKPIT_PROJECTION: HypervisorHomeCockpitProjection =
  {
    schema_version: "ioi.hypervisor.home_cockpit_projection.v1",
    projection_id: "home-cockpit:hypervisor-core/default",
    selected_project_id:
      HYPERVISOR_PROJECT_STATE_PROJECTION_FIXTURE.selected_project_id,
    runtimeTruthSource: "daemon-runtime",
    boundary_invariant:
      "Home is a cockpit projection over Hypervisor Core, wallet.network, Agentgres, cTEE, providers, and receipts. It summarizes evidence; it does not become runtime, authority, restore, or storage truth.",
    metrics: [
      {
        metric_ref: "home-cockpit:project-restore",
        label: "Project restore",
        value: selectedProject?.restore_state.split("_").join(" ") ?? "unknown",
        detail: selectedProject?.restore_ref ?? "restore ref unavailable",
        surface_ref: "surface:projects",
        evidence_refs: [
          selectedProject?.state_root_ref ?? "agentgres://state-root/unavailable",
          selectedProject?.archive_ref ?? "artifact://archive/unavailable",
        ],
      },
      {
        metric_ref: "home-cockpit:session",
        label: "Active session",
        value:
          HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE.lifecycle_state,
        detail:
          HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE.selected_session_ref,
        surface_ref: "surface:sessions",
        evidence_refs:
          HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE.latest_receipt_refs,
      },
      {
        metric_ref: "home-cockpit:privacy",
        label: "Privacy gates",
        value: `${blockedPrivacyControls.length} blocking controls`,
        detail:
          HYPERVISOR_PRIVACY_POSTURE_PROJECTION_FIXTURE.selected_privacy_ref,
        surface_ref: "surface:privacy",
        evidence_refs: blockedPrivacyControls.map(
          (control) => control.receipt_ref,
        ),
      },
      {
        metric_ref: "home-cockpit:provider",
        label: "Provider posture",
        value: selectedProvider?.privacy_posture.split("_").join(" ") ?? "unknown",
        detail: selectedProvider?.direct_provider_ref ?? "provider unavailable",
        surface_ref: "surface:providers",
        evidence_refs: selectedProvider
          ? [selectedProvider.agentgres_receipt_ref, selectedProvider.restore_policy_ref]
          : [],
      },
      {
        metric_ref: "home-cockpit:receipts",
        label: "Receipt evidence",
        value: `${HYPERVISOR_RECEIPT_EVIDENCE_PROJECTION_FIXTURE.records.length} records`,
        detail:
          HYPERVISOR_RECEIPT_EVIDENCE_PROJECTION_FIXTURE.records[0]
            ?.state_root_ref ?? "state root unavailable",
        surface_ref: "surface:receipts",
        evidence_refs: HYPERVISOR_RECEIPT_EVIDENCE_PROJECTION_FIXTURE.records
          .slice(0, 3)
          .map((record) => record.receipt_ref),
      },
      {
        metric_ref: "home-cockpit:harness",
        label: "Harness comparison",
        value: `${HYPERVISOR_HARNESS_COMPARISON_RUN_FIXTURE.candidate_selection_refs.length} adapters`,
        detail: HYPERVISOR_HARNESS_COMPARISON_RUN_FIXTURE.comparison_mode,
        surface_ref: "surface:foundry",
        evidence_refs: HYPERVISOR_HARNESS_COMPARISON_RUN_FIXTURE.receipt_refs,
      },
    ],
  };

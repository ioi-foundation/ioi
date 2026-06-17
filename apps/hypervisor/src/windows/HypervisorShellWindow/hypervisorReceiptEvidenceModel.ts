import { HYPERVISOR_HARNESS_COMPARISON_RUN_FIXTURE } from "./harnessAdapterModel";
import { HYPERVISOR_PROVIDER_PLACEMENT_PROJECTION_FIXTURE } from "./hypervisorProviderPlacementModel";
import { HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE } from "./hypervisorSessionOperationsModel";

export type HypervisorReceiptEvidenceKind =
  | "session_lifecycle"
  | "authority"
  | "provider_placement"
  | "harness_comparison"
  | "environment_lease"
  | "artifact_restore";

export interface HypervisorReceiptEvidenceRecord {
  receipt_ref: string;
  kind: HypervisorReceiptEvidenceKind;
  summary: string;
  source_projection_ref: string;
  agentgres_operation_refs: string[];
  artifact_refs: string[];
  trace_refs: string[];
  state_root_ref: string;
  replay_ref: string;
  status: "admitted" | "draft" | "pending" | "blocked";
}

export interface HypervisorReceiptEvidenceProjection {
  schema_version: "ioi.hypervisor.receipt_evidence_projection.v1";
  projection_id: string;
  records: HypervisorReceiptEvidenceRecord[];
  receipt_boundary_invariant: string;
  runtimeTruthSource: "daemon-runtime";
}

function receiptRecord(
  receipt_ref: string,
  kind: HypervisorReceiptEvidenceKind,
  summary: string,
  source_projection_ref: string,
  status: HypervisorReceiptEvidenceRecord["status"] = "admitted",
): HypervisorReceiptEvidenceRecord {
  const normalizedRef = receipt_ref.replace(/^receipt:\/\//, "").replace(/^receipt:/, "");
  return {
    receipt_ref,
    kind,
    summary,
    source_projection_ref,
    agentgres_operation_refs: [
      `agentgres://operation/${kind}/${normalizedRef}`,
    ],
    artifact_refs: [`artifact://receipt-evidence/${kind}/${normalizedRef}`],
    trace_refs: [`trace://hypervisor/${kind}/${normalizedRef}`],
    state_root_ref: `agentgres://state-root/${kind}/${normalizedRef}`,
    replay_ref: `agentgres://replay/${kind}/${normalizedRef}`,
    status,
  };
}

const sessionProjection = HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE;
const providerProjection = HYPERVISOR_PROVIDER_PLACEMENT_PROJECTION_FIXTURE;
const harnessComparison = HYPERVISOR_HARNESS_COMPARISON_RUN_FIXTURE;

export const HYPERVISOR_RECEIPT_EVIDENCE_PROJECTION_FIXTURE: HypervisorReceiptEvidenceProjection =
  {
    schema_version: "ioi.hypervisor.receipt_evidence_projection.v1",
    projection_id: "receipt-evidence:hypervisor-core/default",
    receipt_boundary_invariant:
      "Receipts make transitions attributable; Agentgres admits operational truth, artifact refs bind payload meaning, and the Hypervisor client only renders evidence projections.",
    records: [
      ...sessionProjection.latest_receipt_refs.map((receiptRef, index) =>
        receiptRecord(
          receiptRef,
          index === 1 ? "authority" : index === 2 ? "environment_lease" : "session_lifecycle",
          index === 1
            ? "wallet.network scope and approval evidence for the selected session."
            : index === 2
              ? "Environment log/access lease evidence for the selected session."
              : "Session lifecycle transition admitted through Hypervisor Core.",
          sessionProjection.projection_id,
        ),
      ),
      ...providerProjection.candidates.map((candidate) =>
        receiptRecord(
          candidate.agentgres_receipt_ref,
          candidate.integration_kind === "decentralized_storage"
            ? "artifact_restore"
            : "provider_placement",
          `${candidate.label} placement candidate with ${candidate.privacy_posture} privacy posture.`,
          providerProjection.projection_id,
        ),
      ),
      ...harnessComparison.receipt_refs.slice(0, 4).map((receiptRef) =>
        receiptRecord(
          receiptRef,
          "harness_comparison",
          "Harness comparison draft receipt; candidate output is not runtime truth until admitted.",
          harnessComparison.run_id,
          receiptRef.startsWith("receipt:draft:") ? "draft" : "pending",
        ),
      ),
    ],
    runtimeTruthSource: "daemon-runtime",
  };

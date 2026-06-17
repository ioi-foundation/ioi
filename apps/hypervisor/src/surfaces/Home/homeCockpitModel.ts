import { HYPERVISOR_HARNESS_COMPARISON_RUN_FIXTURE } from "../../windows/HypervisorShellWindow/harnessAdapterModel.ts";
import { HYPERVISOR_PRIVACY_POSTURE_PROJECTION_FIXTURE } from "../../windows/HypervisorShellWindow/hypervisorPrivacyPostureModel.ts";
import { HYPERVISOR_PROJECT_STATE_PROJECTION_FIXTURE } from "../../windows/HypervisorShellWindow/hypervisorProjectStateModel.ts";
import { HYPERVISOR_PROVIDER_PLACEMENT_PROJECTION_FIXTURE } from "../../windows/HypervisorShellWindow/hypervisorProviderPlacementModel.ts";
import { HYPERVISOR_RECEIPT_EVIDENCE_PROJECTION_FIXTURE } from "../../windows/HypervisorShellWindow/hypervisorReceiptEvidenceModel.ts";
import { HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE } from "../../windows/HypervisorShellWindow/hypervisorSessionOperationsModel.ts";

export interface HypervisorHomeCockpitMetric {
  metric_ref: string;
  label: string;
  value: string;
  detail: string;
  surface_ref: string;
  evidence_refs: string[];
  drill_refs: HypervisorHomeCockpitDrillRef[];
}

export interface HypervisorHomeCockpitDrillRef {
  label: string;
  surface_ref: string;
  target_ref: string;
  evidence_ref: string;
}

export interface HypervisorHomeCockpitProjection {
  schema_version: "ioi.hypervisor.home_cockpit_projection.v1";
  projection_id: string;
  source: "daemon-home-cockpit-projection" | "fixture" | "unverified";
  selected_project_id: string;
  runtimeTruthSource: "daemon-runtime";
  boundary_invariant: string;
  metrics: HypervisorHomeCockpitMetric[];
}

export const HYPERVISOR_HOME_COCKPIT_DAEMON_ENDPOINT_STORAGE_KEY =
  "ioi.hypervisor.daemonEndpoint";
export const HYPERVISOR_HOME_COCKPIT_DEFAULT_DAEMON_ENDPOINT =
  "http://127.0.0.1:8765";
export const HYPERVISOR_HOME_COCKPIT_PROJECTION_PATH =
  "/v1/hypervisor/home-cockpit";

type FetchLike = (
  input: string,
  init?: { method?: string; headers?: Record<string, string> },
) => Promise<{
  ok: boolean;
  status: number;
  text(): Promise<string>;
}>;

interface NormalizeHomeCockpitProjectionOptions {
  source?: HypervisorHomeCockpitProjection["source"];
}

interface LoadHomeCockpitProjectionOptions
  extends NormalizeHomeCockpitProjectionOptions {
  endpoint?: string;
  fetchImpl?: FetchLike;
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
    source: "fixture",
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
        drill_refs: [
          {
            label: "Open project state",
            surface_ref: "surface:projects",
            target_ref: selectedProject?.project_id ?? "project:unavailable",
            evidence_ref:
              selectedProject?.state_root_ref ?? "agentgres://state-root/unavailable",
          },
          {
            label: "Review restore ref",
            surface_ref: "surface:receipts",
            target_ref: selectedProject?.restore_ref ?? "agentgres://restore/unavailable",
            evidence_ref:
              selectedProject?.archive_ref ?? "artifact://archive/unavailable",
          },
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
        drill_refs: [
          {
            label: "Inspect session",
            surface_ref: "surface:sessions",
            target_ref:
              HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE.selected_session_ref,
            evidence_ref:
              HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE.latest_receipt_refs[0] ??
              "receipt://session/unavailable",
          },
          {
            label: "Open terminal evidence",
            surface_ref: "surface:sessions",
            target_ref:
              HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE.terminal_events[0]
                ?.event_ref ?? "terminal:event/unavailable",
            evidence_ref:
              HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE.latest_receipt_refs[1] ??
              "receipt://terminal/unavailable",
          },
        ],
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
        drill_refs: blockedPrivacyControls.slice(0, 2).map((control) => ({
          label: control.label,
          surface_ref: "surface:privacy",
          target_ref: control.control_ref,
          evidence_ref: control.receipt_ref,
        })),
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
        drill_refs: selectedProvider
          ? [
              {
                label: "Inspect provider",
                surface_ref: "surface:providers",
                target_ref: selectedProvider.candidate_ref,
                evidence_ref: selectedProvider.agentgres_receipt_ref,
              },
              {
                label: "Review restore policy",
                surface_ref: "surface:environments",
                target_ref: selectedProvider.restore_policy_ref,
                evidence_ref: selectedProvider.restore_policy_ref,
              },
            ]
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
        drill_refs: HYPERVISOR_RECEIPT_EVIDENCE_PROJECTION_FIXTURE.records
          .slice(0, 2)
          .map((record) => ({
            label: record.summary,
            surface_ref: "surface:receipts",
            target_ref: record.receipt_ref,
            evidence_ref: record.state_root_ref,
          })),
      },
      {
        metric_ref: "home-cockpit:harness",
        label: "Harness comparison",
        value: `${HYPERVISOR_HARNESS_COMPARISON_RUN_FIXTURE.candidate_selection_refs.length} adapters`,
        detail: HYPERVISOR_HARNESS_COMPARISON_RUN_FIXTURE.comparison_mode,
        surface_ref: "surface:foundry",
        evidence_refs: HYPERVISOR_HARNESS_COMPARISON_RUN_FIXTURE.receipt_refs,
        drill_refs: [
          {
            label: "Compare harnesses",
            surface_ref: "surface:foundry",
            target_ref: HYPERVISOR_HARNESS_COMPARISON_RUN_FIXTURE.run_id,
            evidence_ref:
              HYPERVISOR_HARNESS_COMPARISON_RUN_FIXTURE.receipt_refs[0] ??
              "receipt://harness/unavailable",
          },
        ],
      },
    ],
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

function normalizeHomeCockpitMetric(
  item: Record<string, unknown>,
  index: number,
): HypervisorHomeCockpitMetric {
  const fallback =
    HYPERVISOR_HOME_COCKPIT_PROJECTION.metrics[index] ??
    HYPERVISOR_HOME_COCKPIT_PROJECTION.metrics[0]!;
  const evidenceRefs = Array.isArray(item.evidence_refs)
    ? item.evidence_refs
        .filter((ref): ref is string => typeof ref === "string" && !!ref.trim())
        .map((ref) => ref.trim())
    : fallback.evidence_refs;
  const drillRefs = Array.isArray(item.drill_refs)
    ? item.drill_refs.map((drillRef, drillIndex) =>
        normalizeHomeCockpitDrillRef(drillRef, fallback, drillIndex),
      )
    : fallback.drill_refs;
  return {
    metric_ref: stringValue(item.metric_ref, fallback.metric_ref),
    label: stringValue(item.label, fallback.label),
    value: stringValue(item.value, fallback.value),
    detail: stringValue(item.detail, fallback.detail),
    surface_ref: stringValue(item.surface_ref, fallback.surface_ref),
    evidence_refs: evidenceRefs.length > 0 ? evidenceRefs : fallback.evidence_refs,
    drill_refs: drillRefs.length > 0 ? drillRefs : fallback.drill_refs,
  };
}

function normalizeHomeCockpitDrillRef(
  snapshot: unknown,
  fallbackMetric: HypervisorHomeCockpitMetric,
  index: number,
): HypervisorHomeCockpitDrillRef {
  const value = objectRecord(snapshot);
  const fallback =
    fallbackMetric.drill_refs[index] ??
    fallbackMetric.drill_refs[0] ?? {
      label: fallbackMetric.label,
      surface_ref: fallbackMetric.surface_ref,
      target_ref: fallbackMetric.detail,
      evidence_ref: fallbackMetric.evidence_refs[0] ?? fallbackMetric.detail,
    };
  return {
    label: stringValue(value.label, fallback.label),
    surface_ref: stringValue(value.surface_ref, fallback.surface_ref),
    target_ref: stringValue(value.target_ref, fallback.target_ref),
    evidence_ref: stringValue(value.evidence_ref, fallback.evidence_ref),
  };
}

export function readHypervisorHomeCockpitDaemonEndpoint(): string {
  try {
    if (typeof window === "undefined") {
      return HYPERVISOR_HOME_COCKPIT_DEFAULT_DAEMON_ENDPOINT;
    }
    return (
      window.localStorage.getItem(
        HYPERVISOR_HOME_COCKPIT_DAEMON_ENDPOINT_STORAGE_KEY,
      ) || HYPERVISOR_HOME_COCKPIT_DEFAULT_DAEMON_ENDPOINT
    );
  } catch {
    return HYPERVISOR_HOME_COCKPIT_DEFAULT_DAEMON_ENDPOINT;
  }
}

export function normalizeHypervisorHomeCockpitProjection(
  snapshot: unknown,
  options: NormalizeHomeCockpitProjectionOptions = {},
): HypervisorHomeCockpitProjection {
  const value = objectRecord(snapshot);
  const metrics = arrayOf(value.metrics).map(normalizeHomeCockpitMetric);
  return {
    schema_version: "ioi.hypervisor.home_cockpit_projection.v1",
    projection_id: stringValue(
      value.projection_id,
      HYPERVISOR_HOME_COCKPIT_PROJECTION.projection_id,
    ),
    source: options.source ?? "daemon-home-cockpit-projection",
    selected_project_id: stringValue(
      value.selected_project_id,
      HYPERVISOR_HOME_COCKPIT_PROJECTION.selected_project_id,
    ),
    runtimeTruthSource: "daemon-runtime",
    boundary_invariant: stringValue(
      value.boundary_invariant,
      HYPERVISOR_HOME_COCKPIT_PROJECTION.boundary_invariant,
    ),
    metrics: metrics.length > 0 ? metrics : HYPERVISOR_HOME_COCKPIT_PROJECTION.metrics,
  };
}

export async function loadHypervisorHomeCockpitProjection(
  options: LoadHomeCockpitProjectionOptions = {},
): Promise<HypervisorHomeCockpitProjection> {
  const endpoint =
    options.endpoint ?? readHypervisorHomeCockpitDaemonEndpoint();
  const fetchImpl = options.fetchImpl ?? globalThis.fetch?.bind(globalThis);
  if (!fetchImpl) {
    throw new Error("fetch unavailable for Hypervisor home cockpit projection");
  }
  const url = `${endpoint.replace(/\/+$/, "")}${HYPERVISOR_HOME_COCKPIT_PROJECTION_PATH}`;
  const response = await fetchImpl(url, {
    method: "GET",
    headers: { accept: "application/json" },
  });
  const text = await response.text();
  const value = text ? JSON.parse(text) : {};
  if (!response.ok) {
    throw new Error(
      `Home cockpit projection request failed with ${response.status}`,
    );
  }
  return normalizeHypervisorHomeCockpitProjection(value, {
    source: options.source ?? "daemon-home-cockpit-projection",
  });
}

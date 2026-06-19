import { HYPERVISOR_HARNESS_COMPARISON_RUN_FIXTURE } from "./harnessAdapterModel.ts";
import { HYPERVISOR_PROVIDER_PLACEMENT_PROJECTION_FIXTURE } from "./hypervisorProviderPlacementModel.ts";
import { HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE } from "./hypervisorSessionOperationsModel.ts";

export type HypervisorReceiptEvidenceKind =
  | "session_lifecycle"
  | "authority"
  | "provider_placement"
  | "harness_comparison"
  | "environment_lease"
  | "artifact_restore";

export type HypervisorReceiptEvidenceSource =
  | "daemon-receipt-evidence-projection"
  | "fixture"
  | "unverified";

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
  source: HypervisorReceiptEvidenceSource;
  records: HypervisorReceiptEvidenceRecord[];
  page_cursor: string | null;
  next_page_cursor: string | null;
  page_size: number;
  has_more: boolean;
  receipt_boundary_invariant: string;
  runtimeTruthSource: "daemon-runtime";
}

export const HYPERVISOR_RECEIPT_EVIDENCE_DAEMON_ENDPOINT_STORAGE_KEY =
  "ioi.hypervisor.daemonEndpoint";
export const HYPERVISOR_RECEIPT_EVIDENCE_DEFAULT_DAEMON_ENDPOINT =
  "http://127.0.0.1:8765";
export const HYPERVISOR_RECEIPT_EVIDENCE_PROJECTION_PATH =
  "/v1/hypervisor/receipt-evidence";

type FetchLike = (
  input: string,
  init?: { method?: string; headers?: Record<string, string> },
) => Promise<{
  ok: boolean;
  status: number;
  text(): Promise<string>;
}>;

interface NormalizeReceiptEvidenceProjectionOptions {
  source?: HypervisorReceiptEvidenceSource;
}

interface LoadReceiptEvidenceProjectionOptions
  extends NormalizeReceiptEvidenceProjectionOptions {
  endpoint?: string;
  fetchImpl?: FetchLike;
  projectId?: string | null;
  sessionRef?: string | null;
  pageCursor?: string | null;
  pageSize?: number | null;
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
    source: "fixture",
    receipt_boundary_invariant:
      "Receipts make transitions attributable; Agentgres admits operational truth, artifact refs bind payload meaning, and the Hypervisor client only renders evidence projections.",
    page_cursor: null,
    next_page_cursor: null,
    page_size: 25,
    has_more: false,
    records: [
      ...sessionProjection.latest_receipt_refs.map((receiptRef, index) =>
        receiptRecord(
          receiptRef,
          index === 1 ? "authority" : index === 2 ? "environment_lease" : "session_lifecycle",
          index === 1
            ? "wallet.network scope and approval evidence for the selected session."
            : index === 2
              ? "Environment log/access lease evidence for the selected session."
              : "Session lifecycle transition completed for the selected workspace.",
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
          "Harness comparison draft receipt; candidate output is awaiting approval.",
          harnessComparison.run_id,
          receiptRef.startsWith("receipt:draft:") ? "draft" : "pending",
        ),
      ),
    ],
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
  if (value === null || typeof value === "undefined") {
    return fallback;
  }
  return typeof value === "string" && value.trim() ? value.trim() : fallback;
}

function numberValue(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

function booleanValue(value: unknown, fallback: boolean): boolean {
  return typeof value === "boolean" ? value : fallback;
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

function normalizeReceiptEvidenceRecord(
  item: Record<string, unknown>,
  index: number,
): HypervisorReceiptEvidenceRecord {
  const fallback =
    HYPERVISOR_RECEIPT_EVIDENCE_PROJECTION_FIXTURE.records[index] ??
    HYPERVISOR_RECEIPT_EVIDENCE_PROJECTION_FIXTURE.records[0]!;
  return {
    receipt_ref: stringValue(item.receipt_ref, fallback.receipt_ref),
    kind: enumValue(item.kind, fallback.kind, [
      "session_lifecycle",
      "authority",
      "provider_placement",
      "harness_comparison",
      "environment_lease",
      "artifact_restore",
    ]),
    summary: stringValue(item.summary, fallback.summary),
    source_projection_ref: stringValue(
      item.source_projection_ref,
      fallback.source_projection_ref,
    ),
    agentgres_operation_refs: stringList(
      item.agentgres_operation_refs,
      fallback.agentgres_operation_refs,
    ),
    artifact_refs: stringList(item.artifact_refs, fallback.artifact_refs),
    trace_refs: stringList(item.trace_refs, fallback.trace_refs),
    state_root_ref: stringValue(item.state_root_ref, fallback.state_root_ref),
    replay_ref: stringValue(item.replay_ref, fallback.replay_ref),
    status: enumValue(item.status, fallback.status, [
      "admitted",
      "draft",
      "pending",
      "blocked",
    ]),
  };
}

export function readHypervisorReceiptEvidenceDaemonEndpoint(): string {
  try {
    if (typeof window === "undefined") {
      return HYPERVISOR_RECEIPT_EVIDENCE_DEFAULT_DAEMON_ENDPOINT;
    }
    return (
      window.localStorage.getItem(
        HYPERVISOR_RECEIPT_EVIDENCE_DAEMON_ENDPOINT_STORAGE_KEY,
      ) || HYPERVISOR_RECEIPT_EVIDENCE_DEFAULT_DAEMON_ENDPOINT
    );
  } catch {
    return HYPERVISOR_RECEIPT_EVIDENCE_DEFAULT_DAEMON_ENDPOINT;
  }
}

export function normalizeHypervisorReceiptEvidenceProjection(
  snapshot: unknown,
  options: NormalizeReceiptEvidenceProjectionOptions = {},
): HypervisorReceiptEvidenceProjection {
  const value = objectRecord(snapshot);
  const fallback = HYPERVISOR_RECEIPT_EVIDENCE_PROJECTION_FIXTURE;
  const hasRecordsArray = Array.isArray(value.records);
  const records = arrayOf(value.records).map(normalizeReceiptEvidenceRecord);
  return {
    schema_version: "ioi.hypervisor.receipt_evidence_projection.v1",
    projection_id: stringValue(value.projection_id, fallback.projection_id),
    source: options.source ?? "daemon-receipt-evidence-projection",
    records: hasRecordsArray ? records : fallback.records,
    page_cursor: nullableStringValue(value.page_cursor, fallback.page_cursor),
    next_page_cursor: nullableStringValue(
      value.next_page_cursor,
      fallback.next_page_cursor,
    ),
    page_size: numberValue(value.page_size, fallback.page_size),
    has_more: booleanValue(value.has_more, fallback.has_more),
    receipt_boundary_invariant: stringValue(
      value.receipt_boundary_invariant,
      fallback.receipt_boundary_invariant,
    ),
    runtimeTruthSource: "daemon-runtime",
  };
}

export async function loadHypervisorReceiptEvidenceProjection({
  endpoint = readHypervisorReceiptEvidenceDaemonEndpoint(),
  fetchImpl = fetch,
  projectId,
  sessionRef,
  pageCursor,
  pageSize,
  source,
}: LoadReceiptEvidenceProjectionOptions = {}): Promise<HypervisorReceiptEvidenceProjection> {
  const base = endpoint.replace(/\/$/, "");
  const search = new URLSearchParams();
  if (projectId) search.set("project_id", projectId);
  if (sessionRef) search.set("session_ref", sessionRef);
  if (pageCursor) search.set("page_cursor", pageCursor);
  if (pageSize && Number.isFinite(pageSize)) {
    search.set("page_size", String(pageSize));
  }
  const query = search.toString();
  const response = await fetchImpl(
    `${base}${HYPERVISOR_RECEIPT_EVIDENCE_PROJECTION_PATH}${query ? `?${query}` : ""}`,
    { method: "GET" },
  );
  if (!response.ok) {
    throw new Error(
      `Hypervisor receipt evidence projection failed: ${response.status}`,
    );
  }
  const body = await response.text();
  return normalizeHypervisorReceiptEvidenceProjection(JSON.parse(body), {
    source,
  });
}

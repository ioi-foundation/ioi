import type {
  ActiveContextSnapshot as GeneratedActiveContextSnapshot,
  AtlasEdge as GeneratedAtlasEdge,
  AtlasNeighborhood as GeneratedAtlasNeighborhood,
  AtlasNode as GeneratedAtlasNode,
  SubstrateProofReceipt as GeneratedSubstrateProofReceipt,
  SubstrateProofView as GeneratedSubstrateProofView,
} from "../generated/autopilot-contracts";
import type { JsonRecord } from "./base";

export type AtlasEdge = GeneratedAtlasEdge;

export type AtlasNode = Omit<GeneratedAtlasNode, "metadata"> & {
  metadata: JsonRecord;
};

export type AtlasNeighborhood = Omit<
  GeneratedAtlasNeighborhood,
  "focus_id" | "nodes" | "edges"
> & {
  focus_id?: string | null;
  nodes: AtlasNode[];
  edges: AtlasEdge[];
};

export interface SkillMacroStepView {
  index: number;
  tool_name: string;
  target: string;
  params_json:
    | Record<string, unknown>
    | string
    | number
    | boolean
    | null
    | Array<unknown>;
}

export interface SkillBenchmarkView {
  sample_size: number;
  success_rate_bps: number;
  intervention_rate_bps: number;
  policy_incident_rate_bps: number;
  avg_cost: number;
  avg_latency_ms: number;
  passed: boolean;
  last_evaluated_height: number;
}

export interface SkillDetailView {
  skill_hash: string;
  name: string;
  description: string;
  lifecycle_state: string;
  source_type: string;
  archival_record_id: number;
  success_rate_bps: number;
  sample_size: number;
  source_session_id?: string | null;
  source_evidence_hash?: string | null;
  relative_path?: string | null;
  source_registry_id?: string | null;
  source_registry_label?: string | null;
  source_registry_uri?: string | null;
  source_registry_kind?: string | null;
  source_registry_sync_status?: string | null;
  source_registry_relative_path?: string | null;
  stale: boolean;
  used_tools: string[];
  steps: SkillMacroStepView[];
  benchmark: SkillBenchmarkView;
  markdown?: string | null;
  neighborhood: AtlasNeighborhood;
}

export type SubstrateProofReceipt = GeneratedSubstrateProofReceipt;

export type SubstrateProofView = Omit<
  GeneratedSubstrateProofView,
  "neighborhood" | "receipts"
> & {
  neighborhood: AtlasNeighborhood;
  receipts: SubstrateProofReceipt[];
};

export type ActiveContextSnapshot = Omit<
  GeneratedActiveContextSnapshot,
  "neighborhood" | "substrate"
> & {
  neighborhood: AtlasNeighborhood;
  substrate?: SubstrateProofView | null;
};

export interface BenchmarkTraceArtifactLink {
  label: string;
  path: string;
  href: string;
}

export interface BenchmarkTraceSpan {
  id: string;
  lane: string;
  parentSpanId?: string | null;
  stepIndex?: number | null;
  status: string;
  summary: string;
  startMs: number;
  endMs: number;
  durationMs?: number | null;
  capabilityTags: string[];
  attributesSummary: string;
  artifactLinks: BenchmarkTraceArtifactLink[];
}

export interface BenchmarkTraceLane {
  lane: string;
  spans: BenchmarkTraceSpan[];
}

export interface BenchmarkTraceBookmark {
  id: string;
  label: string;
  spanId: string;
  kind: string;
}

export interface BenchmarkTraceReplay {
  source: string;
  rangeStartMs: number;
  rangeEndMs: number;
  spanCount: number;
  lanes: BenchmarkTraceLane[];
  bookmarks: BenchmarkTraceBookmark[];
}

export interface BenchmarkTraceMetric {
  metricId: string;
  label: string;
  status: string;
  summary: string;
  supportingSpanIds: string[];
}

export interface BenchmarkTraceLinks {
  traceBundle?: string | null;
  traceAnalysis?: string | null;
  benchmarkSummary?: string | null;
  diagnosticSummary?: string | null;
}

export interface BenchmarkTraceSummary {
  env_id: string;
  model?: string | null;
  provider_calls: number;
  reward: number;
  terminated: boolean;
  query_text: string;
}

export interface BenchmarkTraceCaseView {
  suite: string;
  caseId: string;
  runId: string;
  runSort: number;
  result: string;
  summary: BenchmarkTraceSummary;
  findings: string[];
  traceMetrics: BenchmarkTraceMetric[];
  trace: BenchmarkTraceReplay | null;
  links: BenchmarkTraceLinks;
}

export interface BenchmarkTraceFeed {
  generatedAt?: string | null;
  repoRoot?: string | null;
  cases: BenchmarkTraceCaseView[];
}

export interface AtlasSearchResult {
  id: string;
  kind: string;
  title: string;
  summary: string;
  score: number;
  lens: string;
}

export type ContextAtlasLens = "Context" | "Skills" | "Substrate";
export type ContextAtlasMode = "List" | "Split" | "3D";

export interface ContextAtlasFocusRequest {
  sessionId?: string | null;
  focusId?: string | null;
  lens?: ContextAtlasLens;
  mode?: ContextAtlasMode;
}

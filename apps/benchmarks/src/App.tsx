import { useCallback, useEffect, useMemo, useState } from "react";

import initialBenchmarkData from "./generated/benchmark-data.json";
import {
  resolveInitialTriageSelection,
  resolveScorecardPreviewEnabled,
} from "./appShellState";
import {
  CandidatesView,
  DeploymentsView,
  OperationalContextPanel,
  PresetScorecardBoard,
  ResultPill,
  ScorecardHero,
} from "./components/ScorecardPanels";
import { withScorecardPreview } from "./scorecardPreview";
import {
  buildCandidatesViewModel,
  buildDeploymentsViewModel,
  buildScorecardViewModel,
} from "./scorecardViewModel";
import type { ScorecardMatrixInput } from "./scorecardViewModel";

/* ── Types ── */

type TabId = "dashboard" | "deployments" | "candidates" | "triage";
type ResultStatus = "pass" | "near-miss" | "red" | "interrupted" | "unknown";
type ResultFilter = "all" | ResultStatus;

type SuiteSummary = {
  suite: string;
  counts: Record<ResultStatus, number>;
  focusCaseId: string | null;
  focusResult: ResultStatus;
  latestRunId: string | null;
  liveRun: LiveRunRecord | null;
};

type LiveRunRecord = {
  suite: string;
  runId: string;
  taskSet: string;
  status: string;
  activeCaseId: string | null;
  totalCases: number;
  completedCases: number;
  updatedAtMs: number | null;
};

type TimelineStep = {
  stepIndex: number | null;
  chosenName: string | null;
  chosenArguments: Record<string, unknown> | null;
  requestedId: string | null;
  inferenceElapsedMs: number | null;
  inferenceGapFromPreviousFinishMs: number | null;
  actionErrorClass: string | null;
  routingFailureClass: string | null;
  routingSuccess: boolean | null;
  targetMismatch: string | null;
  clickedSemanticId: string | null;
  chosenTargets: string[];
  actionOutputSummary: string;
  pendingState: string;
  pendingTargets: string[];
  pendingAlignment: string | null;
  successSignal: string;
  successTargets: string[];
  successAlignment: string | null;
  recentSessionEvents: string;
  observationTargets: string[];
  observationDelta: { added: string[]; removed: string[]; changed: string[] };
  postActionObservationDelta: { added: string[]; removed: string[]; changed: string[] };
  postActionNewTargetTokens: string[];
  executionReceipts: string[];
  executionReceiptCount: number;
  bridgeEvents: string[];
  clickDelivery: string | null;
  clickAttempts: Array<{
    attemptIndex: number | null;
    method: string | null;
    dispatchElapsedMs: number | null;
    verifyElapsedMs: number | null;
    settleMs: number | null;
    postconditionMet: boolean | null;
    targetDisappeared: boolean | null;
    treeChanged: boolean | null;
    semanticChangeDelta: number | null;
    target: string;
  }>;
  dispatchFailures: Array<{
    method: string | null;
    dispatchElapsedMs: number | null;
    error: string;
  }>;
};

type TraceSpanRecord = {
  id: string;
  lane: string;
  parentSpanId: string | null;
  stepIndex: number | null;
  status: string;
  summary: string;
  startMs: number | null;
  endMs: number | null;
  durationMs: number | null;
  capabilityTags: string[];
  attributesSummary: string;
  artifactLinks: Array<{
    label: string;
    path: string;
    href: string;
  }>;
};

type TraceBookmarkRecord = {
  id: string;
  label: string;
  spanId: string;
  kind: string;
};

type TraceLaneRecord = {
  lane: string;
  spans: TraceSpanRecord[];
};

type TraceReplayRecord = {
  source: string;
  rangeStartMs: number | null;
  rangeEndMs: number | null;
  spanCount: number;
  bookmarks: TraceBookmarkRecord[];
  lanes: TraceLaneRecord[];
};

type CaseRecord = {
  suite: string;
  caseId: string;
  runId: string;
  summary: {
    provider_calls?: number;
    reward?: number;
    raw_reward?: number;
    model?: string;
    backend?: string;
    final_trigger?: string;
    query_text?: string;
    episode_step?: number;
    sync_count?: number;
  };
  result: ResultStatus;
  findings: string[];
  traceMetrics: Array<{
    metricId: string;
    label: string;
    status: string;
    summary: string;
    supportingSpanIds: string[];
  }>;
  detail: {
    phaseTiming: Record<string, number>;
    timeline: TimelineStep[];
  };
  trace: TraceReplayRecord;
  links: {
    caseDir: string;
    diagnosticJson: string;
    diagnosticMarkdown: string;
    inferenceCalls: string;
    inferenceTrace: string;
    bridgeState: string;
    traceBundle: string;
    traceAnalysis: string;
  };
};

type ParsedObsTarget = {
  id: string;
  tag: string | null;
  name: string | null;
  domId: string | null;
  selector: string | null;
  clickable: boolean;
  extras: Record<string, string>;
};

type BenchmarkDataShape = {
  generatedAt: string;
  liveDataPath?: string;
  liveStorePath?: string;
  suiteSummaries: SuiteSummary[];
  latestCases: CaseRecord[];
  agentModelMatrix?: ScorecardMatrixInput | null;
  studioArtifactBenchmarkSuite?: StudioArtifactBenchmarkSuite | null;
  studioArtifactArena?: StudioArtifactArenaView | null;
  studioArtifactReleaseGates?: StudioArtifactReleaseGatesView | null;
  studioArtifactDistillation?: StudioArtifactDistillationView | null;
  studioArtifactParityLoop?: StudioArtifactParityLoopView | null;
};

type BenchmarkMetricReading = {
  label: string;
  value: number | null;
  unit: string;
  available: boolean;
  method: string;
  numerator?: number | null;
  denominator?: number | null;
  supportingBenchmarkIds?: string[];
};

type StudioArtifactArenaRating = {
  participant: string;
  label?: string | null;
  rating: number;
  matches: number;
  wins: number;
  losses: number;
  draws: number;
};

type StudioArtifactBenchmarkCase = {
  benchmarkId: string;
  title: string;
  prompt: string;
  categories: string[];
  trackedParityTarget: boolean;
  externalReferenceCount: number;
  externalReferenceParticipants: string[];
  matchedCaseId: string | null;
  matchedRunId: string | null;
  matchedVerificationStatus: string | null;
  matchedClassification: string | null;
  judgeScore: number | null;
  firstPaintEvidenceScore: number | null;
  iterationsToClear: number | null;
  shimDependent: boolean | null;
  blueprintPresent: boolean;
  artifactIrPresent: boolean;
  selectedSkillCount: number;
  retrievedExemplarCount: number;
  caseAvailable: boolean;
  requiredInteractionContracts: string[];
  goldenEvaluationCriteria: string[];
};

type StudioArtifactBenchmarkSuite = {
  catalogVersion: number;
  totalBenchmarks: number;
  executedBenchmarks: number;
  missingBenchmarks: number;
  parityTargets: string[];
  metrics: Record<string, BenchmarkMetricReading>;
  arena: {
    available: boolean;
    matchCount: number;
    blindMatchCount: number;
    participantCount: number;
    winRateVsExternalReference: number | null;
    ratings: StudioArtifactArenaRating[];
  };
  externalReferences: {
    available: boolean;
    path: string | null;
    count: number;
    benchmarkCount: number;
  };
  cases: StudioArtifactBenchmarkCase[];
};

type StudioArtifactArenaView = {
  status: string;
  ledgerPath: string;
  ledgerHref: string;
  benchmarkCount: number;
  executedBenchmarkCount: number;
  comparativeBenchmarkCount: number;
  benchmarksWithBlindWinnerCount: number;
  internalExecutionCount: number;
  internalParticipantCount: number;
  externalReferenceCount: number;
  pairwiseMatchCount: number;
  blindMatchCount: number;
  pendingBlindMatchCount: number;
  topCompositeRatings: StudioArtifactArenaRating[];
  benchmarkLeaders: Array<{
    benchmarkId: string | null;
    title: string | null;
    pairwiseMatchCount: number;
    pendingBlindMatchCount: number;
    provisionalLeader: {
      participant?: string | null;
      label?: string | null;
      executionId?: string | null;
      caseId?: string | null;
      classification?: string | null;
      judgeScore?: number | null;
    } | null;
    blindWinner: {
      participant?: string | null;
      label?: string | null;
      source?: string | null;
      caseId?: string | null;
      unique?: boolean | null;
    } | null;
  }>;
  pendingBlindMatches: Array<{
    matchId: string | null;
    benchmarkId: string | null;
    benchmarkTitle: string | null;
    leftLabel: string | null;
    rightLabel: string | null;
    rationale: string | null;
  }>;
};

type StudioArtifactReleaseGatesView = {
  status: string;
  passing: boolean;
  reportPath: string;
  reportHref: string;
  gateCount: number;
  passCount: number;
  failCount: number;
  pendingCount: number;
  blockingGateIds: string[];
  ratchetCandidateIds: string[];
  topGates: Array<{
    id: string | null;
    label: string | null;
    status: string | null;
    operator: string | null;
    shipThreshold: number | null;
    reading: {
      value?: number | null;
      available?: boolean | null;
      failedCheckIds?: string[];
    } | null;
    ratchet: {
      status?: string | null;
      floor?: number | null;
      candidateFloor?: number | null;
    } | null;
  }>;
  ratchetCandidates: Array<{
    id: string | null;
    label: string | null;
    operator: string | null;
    currentValue: number | null;
    currentFloor: number | null;
    candidateFloor: number | null;
  }>;
};

type StudioArtifactParityLoopTarget = {
  id: string | null;
  label: string | null;
  summary: string | null;
  family: string | null;
  caseIds: string[];
};

type StudioArtifactParityLoopComparison = {
  improvedMetrics: string[];
  regressedMetrics: string[];
  unchangedMetrics: string[];
};

type StudioArtifactParityLoopReceipt = {
  createdAt: string | null;
  keepChange: boolean | null;
  noImprovementStreak: number;
  selectedInterventionFamily: string | null;
  allowedInterventionFamilies: string[];
  decision: {
    kind: string;
    reason: string;
  };
  weakestTarget: StudioArtifactParityLoopTarget | null;
  relevantCaseIds: string[];
  requiredReceipts: string[];
  comparison: StudioArtifactParityLoopComparison | null;
};

type StudioArtifactParityLoopView = {
  status: string;
  receiptCount: number;
  summaryPath: string;
  summaryHref: string;
  ledgerPath: string;
  ledgerHref: string;
  latestReceipt: StudioArtifactParityLoopReceipt | null;
  currentPlan: StudioArtifactParityLoopReceipt | null;
};

type StudioArtifactDistillationProposal = {
  proposalId: string | null;
  sourceKind: string | null;
  benchmarkId: string | null;
  benchmarkTitle: string | null;
  targetUpgrades: string[];
  typedReasons: string[];
  before: {
    caseId: string | null;
    classification: string | null;
    judgeScore: number | null;
  } | null;
  after: {
    caseId: string | null;
    classification: string | null;
    judgeScore: number | null;
  } | null;
  structuralChanges: {
    classificationDelta?: number | null;
    judgeScoreDelta?: number | null;
    firstPaintEvidenceDelta?: number | null;
  } | null;
  generalization: {
    generalizesAcrossRelatedPrompts?: boolean;
    relatedCaseCount?: number;
  } | null;
  status: string;
};

type StudioArtifactDistillationView = {
  status: string;
  ledgerPath: string;
  ledgerHref: string;
  proposalCount: number;
  appliedCount: number;
  measuredGain: number | null;
  topProposals: StudioArtifactDistillationProposal[];
};

type BenchmarkStoreRunRecord = {
  run_id?: string;
  task_set?: string;
  status?: string;
  active_case_id?: string | null;
  total_cases?: number;
  completed_cases?: number;
  updated_at_ms?: number | null;
  cases?: Array<{ case_id?: string }>;
};

type BenchmarkStoreShape = {
  runs?: BenchmarkStoreRunRecord[];
};

/* ── Constants ── */

const tabs: Array<{ id: TabId; label: string; shortcut: string }> = [
  { id: "dashboard", label: "Scorecard", shortcut: "1" },
  { id: "deployments", label: "Deployments", shortcut: "2" },
  { id: "candidates", label: "Candidates", shortcut: "3" },
  { id: "triage", label: "Triage", shortcut: "4" },
];

const resultFilters: Array<{ value: ResultFilter; label: string }> = [
  { value: "all", label: "All" },
  { value: "red", label: "Red" },
  { value: "interrupted", label: "Interrupted" },
  { value: "near-miss", label: "Near" },
  { value: "pass", label: "Pass" },
];

const timingLabels: Record<string, string> = {
  bootstrap_to_first_inference_start_ms: "Bootstrap → inference",
  bootstrap_to_first_grounded_target_ms: "Bootstrap → grounded",
  first_inference_elapsed_ms: "Inference elapsed",
  first_receipt_to_first_grounded_target_ms: "Receipt → grounded",
  first_grounded_target_to_terminal_ms: "Grounded → terminal",
  terminal_to_step_finish_tail_ms: "Terminal tail",
};

const ACTION_META: Record<string, { icon: string; cls: string; label: string }> = {
  browser__click: { icon: "🖱", cls: "act-click", label: "click" },
  browser__click_at: { icon: "⊕", cls: "act-synth", label: "synth click" },
  browser__hover: { icon: "👆", cls: "act-hover", label: "hover" },
  browser__wait: { icon: "⏳", cls: "act-wait", label: "wait" },
  browser__type: { icon: "⌨", cls: "act-type", label: "type" },
  browser__inspect: { icon: "📷", cls: "act-snap", label: "snapshot" },
  browser__select_option: { icon: "▾", cls: "act-select", label: "select" },
  browser__find_text: { icon: "🔍", cls: "act-find", label: "find" },
};

/* ── Utilities ── */

function v(value: string | number | null | undefined): string {
  if (value === null || value === undefined || value === "") return "—";
  return String(value);
}

function pj(value: unknown): string {
  try { return JSON.stringify(value, null, 2); } catch { return String(value); }
}

function relTime(iso: string): string {
  const d = Date.now() - new Date(iso).getTime();
  const m = Math.floor(d / 60_000);
  if (m < 1) return "just now";
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

function short(id: string) { return id.replace(/^miniwob_catalog_/, ""); }

function shortCaseId(id: string | null | undefined) {
  return id ? short(id).replace(/^miniwob_/, "") : "—";
}

function total(c: Record<ResultStatus, number>) {
  return c.pass + c["near-miss"] + c.red + c.interrupted + c.unknown;
}

function fmtPct(value: number | null | undefined) {
  return value == null ? "—" : `${Math.round(value * 100)}%`;
}

function fmtScore(value: number | null | undefined) {
  return value == null ? "—" : value.toFixed(2);
}

function fmtLoopStatus(value: string | null | undefined) {
  switch (value) {
    case "active":
      return "active";
    case "stop_parity":
      return "parity met";
    case "stop_plateau":
      return "plateau";
    case "stop_budget":
      return "budget cap";
    default:
      return value ? value.replace(/_/g, " ") : "—";
  }
}

function fmtLoopFamily(value: string | null | undefined) {
  return value ? value.replace(/_/g, " ") : "—";
}

function inferSuite(caseId: string | null | undefined): string {
  if (!caseId) return "Unknown";
  if (caseId.startsWith("miniwob_")) return "MiniWoB++";
  if (caseId.startsWith("osworld_")) return "OSWorld";
  if (caseId.startsWith("workarena_")) return "WorkArena";
  return "Unknown";
}

function collectLiveRunsFromStore(store: BenchmarkStoreShape): LiveRunRecord[] {
  if (!Array.isArray(store.runs)) {
    return [];
  }

  const latestBySuite = new Map<string, LiveRunRecord>();
  for (const run of store.runs) {
    const status = typeof run.status === "string" ? run.status : "completed";
    if (status !== "running") {
      continue;
    }

    const activeCaseId =
      typeof run.active_case_id === "string" && run.active_case_id
        ? run.active_case_id
        : null;
    const suite = inferSuite(
      activeCaseId ??
        (typeof run.cases?.[0]?.case_id === "string" ? run.cases[0].case_id : null),
    );
    if (suite === "Unknown") {
      continue;
    }

    const candidate: LiveRunRecord = {
      suite,
      runId: typeof run.run_id === "string" ? run.run_id : "run-local",
      taskSet: typeof run.task_set === "string" ? run.task_set : "unknown",
      status,
      activeCaseId,
      totalCases: typeof run.total_cases === "number" ? run.total_cases : 0,
      completedCases: typeof run.completed_cases === "number" ? run.completed_cases : 0,
      updatedAtMs: typeof run.updated_at_ms === "number" ? run.updated_at_ms : null,
    };

    const current = latestBySuite.get(suite);
    if (!current || (candidate.updatedAtMs ?? 0) >= (current.updatedAtMs ?? 0)) {
      latestBySuite.set(suite, candidate);
    }
  }

  return Array.from(latestBySuite.values()).sort(
    (left, right) => (right.updatedAtMs ?? 0) - (left.updatedAtMs ?? 0),
  );
}

function mergeLiveRunsIntoBenchmarkData(
  current: BenchmarkDataShape,
  liveRuns: LiveRunRecord[],
): BenchmarkDataShape {
  const liveRunsBySuite = new Map(liveRuns.map((entry) => [entry.suite, entry]));
  const seenSuites = new Set<string>();
  const mergedSummaries = current.suiteSummaries.map((summary) => {
    seenSuites.add(summary.suite);
    return {
      ...summary,
      liveRun: liveRunsBySuite.get(summary.suite) ?? null,
    };
  });

  for (const liveRun of liveRuns) {
    if (seenSuites.has(liveRun.suite)) {
      continue;
    }
    mergedSummaries.push({
      suite: liveRun.suite,
      counts: { pass: 0, "near-miss": 0, red: 0, interrupted: 0, unknown: 0 },
      focusCaseId: null,
      focusResult: "unknown",
      latestRunId: liveRun.runId,
      liveRun,
    });
  }

  return {
    ...current,
    suiteSummaries: mergedSummaries,
  };
}

function actMeta(name: string | null) {
  if (!name) return { icon: "?", cls: "act-unk", label: "unknown" };
  return ACTION_META[name] ?? { icon: "▸", cls: "act-gen", label: name.replace("browser__", "") };
}

function traceLaneLabel(lane: string) {
  return lane.replace(/_/g, " ");
}

function studioArtifactParticipantLabel(participant: string, label?: string | null) {
  if (label && label.trim()) {
    return label;
  }
  return participant
    .replace(/^reference:/, "external ")
    .replace(/^stack:/, "")
    .replace(/^generator:/, "")
    .replace(/^judge:/, "")
    .replace(/^scaffold:/, "")
    .replace(/^component_profile:/, "")
    .replace(/^skill_spine:/, "")
    .replace(/[_:.-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/\b[a-z]/g, (char) => char.toUpperCase());
}

function traceStatusClass(status: string) {
  return status.replace(/[^a-z0-9]+/gi, "-").toLowerCase();
}

function traceDurationLabel(ms: number | null) {
  return ms == null ? "—" : `${ms}ms`;
}

function parseObs(raw: string): ParsedObsTarget {
  const parts = raw.split(" ");
  const id = parts[0] ?? raw;
  const kv: Record<string, string> = {};
  for (let i = 1; i < parts.length; i++) {
    const eq = parts[i].indexOf("=");
    if (eq > 0) {
      const key = parts[i].slice(0, eq);
      let val = parts[i].slice(eq + 1);
      if (val.startsWith("[") && !val.endsWith("]")) {
        while (i + 1 < parts.length && !parts[i].endsWith("]")) { i++; val += " " + parts[i]; }
      }
      kv[key] = val;
    }
  }
  return { id, tag: kv.tag ?? null, name: kv.name ?? null, domId: kv.dom_id ?? null, selector: kv.selector ?? null, clickable: kv.dom_clickable === "true", extras: kv };
}

/* ── Tiny components ── */

function CopyBtn({ text, label }: { text: string; label?: string }) {
  const [ok, setOk] = useState(false);
  return (
    <button type="button" className="cpbtn" title={`Copy ${label ?? ""}`}
      onClick={() => { navigator.clipboard.writeText(text); setOk(true); setTimeout(() => setOk(false), 1600); }}>
      {ok ? "✓" : "⎘"}
    </button>
  );
}

/* ── Timing Waterfall ── */

function Waterfall({ entries }: { entries: [string, number][] }) {
  if (!entries.length) return null;
  const mx = Math.max(...entries.map(([, v]) => Math.abs(v)), 1);
  return (
    <div className="wf">{entries.map(([k, val]) => (
      <div key={k} className="wf-r">
        <span className="wf-l">{timingLabels[k] ?? k}</span>
        <div className="wf-t"><div className={`wf-f ${val < 0 ? "wf-n" : ""}`} style={{ width: `${Math.min((Math.abs(val) / mx) * 100, 100)}%` }} /></div>
        <span className="wf-v">{val}ms</span>
      </div>
    ))}</div>
  );
}

/* ── Parsed Observation Card ── */

function ObsCard({ t }: { t: ParsedObsTarget }) {
  return (
    <div className="obs">
      <div className="obs-h">
        <code className="obs-id">{t.id}</code>
        {t.clickable && <span className="obs-b obs-ck">clickable</span>}
        {t.tag && <span className="obs-b obs-tg">{t.tag}</span>}
      </div>
      {t.name && <span className="obs-nm">{t.name}</span>}
      {t.selector && (
        <div className="obs-sel">
          <code>{t.selector}</code>
          <CopyBtn text={t.selector} label="selector" />
        </div>
      )}
    </div>
  );
}

/* ── Step Minimap ── */

function Minimap({ steps, onSelect }: { steps: TimelineStep[]; onSelect: (i: number) => void }) {
  return (
    <div className="mm">{steps.map((s, i) => {
      let c = "mm-d mm-ok";
      if (s.actionErrorClass) c = "mm-d mm-err";
      else if (s.inferenceElapsedMs != null && s.inferenceElapsedMs > 3000) c = "mm-d mm-slow";
      return <button key={i} type="button" className={c} onClick={() => onSelect(i)}
        title={`Step ${s.stepIndex ?? i}: ${s.chosenName ?? "?"} (${s.inferenceElapsedMs ?? "?"}ms)`} />;
    })}</div>
  );
}

/* ── Git-Style Delta ── */

function Delta({ d }: { d: TimelineStep["observationDelta"] }) {
  if (!d.added.length && !d.removed.length && !d.changed.length) return null;
  return (
    <div className="diff">{[
      ...d.added.map((x, i) => <div key={`a${i}`} className="diff-l diff-a">+ {x}</div>),
      ...d.removed.map((x, i) => <div key={`r${i}`} className="diff-l diff-r">− {x}</div>),
      ...d.changed.map((x, i) => <div key={`c${i}`} className="diff-l diff-c">~ {x}</div>),
    ]}</div>
  );
}

/* ── Collapsible Step ── */

function Step({ step, caseId, open, toggle }: { step: TimelineStep; caseId: string; open: boolean; toggle: () => void }) {
  const meta = actMeta(step.chosenName);
  const err = !!(step.actionErrorClass || step.routingFailureClass);
  const mismatch = step.requestedId != null && step.clickedSemanticId != null && step.requestedId !== step.clickedSemanticId;
  const targets = useMemo(() => step.observationTargets.map(parseObs), [step.observationTargets]);

  return (
    <article className={`st ${open ? "st-open" : ""} ${err ? "st-err" : ""}`}>
      <button type="button" className="st-h" onClick={toggle} aria-expanded={open}>
        <div className="st-hl">
          <span className={`st-ic ${meta.cls}`}>{meta.icon}</span>
          <strong>{meta.label}</strong>
          {step.requestedId && <span className="st-tgt">→ {step.requestedId}</span>}
        </div>
        <div className="st-hr">
          {mismatch && <span className="st-mm">mismatch</span>}
          {err && <span className="st-fl">{step.actionErrorClass ?? step.routingFailureClass}</span>}
          {step.inferenceGapFromPreviousFinishMs != null && (
            <span className="st-ms">+{step.inferenceGapFromPreviousFinishMs}ms idle</span>
          )}
          {step.inferenceElapsedMs != null && <span className="st-ms">{step.inferenceElapsedMs}ms</span>}
          <span className={`st-ch ${open ? "st-ch-o" : ""}`}>▾</span>
        </div>
      </button>
      {open && (
        <div className="st-body">
          {step.chosenArguments && (
            <div className="st-args">
              <div className="st-args-h"><span className="sec-l">Arguments</span><CopyBtn text={pj(step.chosenArguments)} /></div>
              <pre className="cblk">{pj(step.chosenArguments)}</pre>
            </div>
          )}
          {step.actionOutputSummary && <div className="st-sec"><span className="sec-l">Output</span><p className="st-txt">{step.actionOutputSummary}</p></div>}
          {(step.clickAttempts.length > 0 || step.dispatchFailures.length > 0) && (
            <div className="st-sec">
              <span className="sec-l">Click trace</span>
              <div className="bev">
                {step.clickDelivery && <div className="bev-l">winning delivery: {step.clickDelivery}</div>}
                {step.clickAttempts.map((attempt, index) => {
                  const pieces = [
                    `attempt ${attempt.attemptIndex ?? index + 1}`,
                    attempt.method,
                    attempt.dispatchElapsedMs != null ? `${attempt.dispatchElapsedMs}ms dispatch` : null,
                    attempt.verifyElapsedMs != null ? `${attempt.verifyElapsedMs}ms verify` : null,
                    attempt.settleMs != null ? `${attempt.settleMs}ms settle` : null,
                    attempt.postconditionMet === true ? "postcondition met" : "postcondition open",
                    attempt.treeChanged === true ? "tree changed" : null,
                    attempt.targetDisappeared === true ? "target disappeared" : null,
                    attempt.semanticChangeDelta != null ? `delta ${attempt.semanticChangeDelta}` : null,
                    attempt.target || null,
                  ].filter(Boolean);
                  return <div key={`attempt-${index}`} className="bev-l">{pieces.join(" | ")}</div>;
                })}
                {step.dispatchFailures.map((failure, index) => {
                  const pieces = [
                    "dispatch failure",
                    failure.method,
                    failure.dispatchElapsedMs != null ? `${failure.dispatchElapsedMs}ms` : null,
                    failure.error || null,
                  ].filter(Boolean);
                  return <div key={`dispatch-failure-${index}`} className="bev-l">{pieces.join(" | ")}</div>;
                })}
              </div>
            </div>
          )}
          {(step.chosenTargets.length > 0 || step.pendingTargets.length > 0 || step.successTargets.length > 0) && (
            <div className="st-sec">
              <span className="sec-l">Decision audit</span>
              <div className="bev">
                {step.chosenTargets.length > 0 && <div className="bev-l">chosen: {step.chosenTargets.join(", ")}</div>}
                {step.pendingTargets.length > 0 && (
                  <div className="bev-l">
                    pending: {step.pendingTargets.join(", ")}
                    {step.pendingAlignment ? ` (${step.pendingAlignment})` : ""}
                  </div>
                )}
                {step.successTargets.length > 0 && (
                  <div className="bev-l">
                    success: {step.successTargets.join(", ")}
                    {step.successAlignment ? ` (${step.successAlignment})` : ""}
                  </div>
                )}
                {step.postActionNewTargetTokens.length > 0 && (
                  <div className="bev-l">post-action new: {step.postActionNewTargetTokens.join(", ")}</div>
                )}
              </div>
            </div>
          )}
          {step.pendingState && <div className="st-sec"><span className="sec-l">Pending state</span><p className="st-txt">{step.pendingState}</p></div>}
          {step.successSignal && <div className="st-sec"><span className="sec-l">Success signal</span><p className="st-txt">{step.successSignal}</p></div>}
          {step.recentSessionEvents && <div className="st-sec"><span className="sec-l">Recent session events</span><p className="st-txt">{step.recentSessionEvents}</p></div>}
          {targets.length > 0 && (
            <div className="st-sec">
              <span className="sec-l">Observation targets ({targets.length})</span>
              <div className="obs-g">{targets.map((t, i) => <ObsCard key={`${caseId}-${step.stepIndex}-t${i}`} t={t} />)}</div>
            </div>
          )}
          {(step.observationDelta.added.length > 0 || step.observationDelta.removed.length > 0 || step.observationDelta.changed.length > 0) && (
            <div className="st-sec">
              <span className="sec-l">Observation delta</span>
              <Delta d={step.observationDelta} />
            </div>
          )}
          {(step.postActionObservationDelta.added.length > 0 || step.postActionObservationDelta.removed.length > 0 || step.postActionObservationDelta.changed.length > 0) && (
            <div className="st-sec">
              <span className="sec-l">Post-action delta</span>
              <Delta d={step.postActionObservationDelta} />
            </div>
          )}
          {step.executionReceiptCount > 0 && (
            <div className="st-sec">
              <span className="sec-l">Execution receipts ({step.executionReceiptCount})</span>
              <div className="bev">{step.executionReceipts.map((receipt, i) => <div key={i} className="bev-l">{receipt}</div>)}</div>
            </div>
          )}
          {step.bridgeEvents.length > 0 && (
            <div className="st-sec">
              <span className="sec-l">Bridge events ({step.bridgeEvents.length})</span>
              <div className="bev">{step.bridgeEvents.map((e, i) => <div key={i} className="bev-l">{e}</div>)}</div>
            </div>
          )}
        </div>
      )}
    </article>
  );
}

function TraceViewer({
  trace,
  selectedSpanId,
  onSelectSpan,
}: {
  trace: TraceReplayRecord;
  selectedSpanId: string | null;
  onSelectSpan: (spanId: string) => void;
}) {
  const spans = useMemo(
    () => trace.lanes.flatMap((lane) => lane.spans),
    [trace.lanes],
  );
  const selectedSpan = spans.find((span) => span.id === selectedSpanId) ?? spans[0] ?? null;
  const rangeStart = trace.rangeStartMs;
  const rangeEnd = trace.rangeEndMs;
  const rangeWidth =
    rangeStart != null && rangeEnd != null
      ? Math.max(rangeEnd - rangeStart, 1)
      : 1;
  const totalDuration =
    rangeStart != null && rangeEnd != null
      ? Math.max(rangeEnd - rangeStart, 0)
      : null;

  if (trace.lanes.length === 0) {
    return null;
  }

  return (
    <div className="trv">
      <div className="trv-head">
        <div>
          <h3>
            Trace Replay <span className="scnt">{trace.spanCount} spans</span>
          </h3>
          <p className="trv-meta">
            {trace.source === "trace_bundle" ? "Recorded bundle" : "Synthesized from diagnostics"}
            {totalDuration != null ? ` · ${totalDuration}ms window` : ""}
          </p>
        </div>
        {trace.bookmarks.length > 0 && (
          <div className="trv-bms">
            {trace.bookmarks.map((bookmark) => (
              <button
                key={bookmark.id}
                type="button"
                className={`trv-bm trv-bm-${bookmark.kind} ${
                  selectedSpan?.id === bookmark.spanId ? "on" : ""
                }`}
                onClick={() => onSelectSpan(bookmark.spanId)}
              >
                {bookmark.label}
              </button>
            ))}
          </div>
        )}
      </div>

      <div className="trv-lanes">
        {trace.lanes.map((lane) => {
          const trackHeight = Math.max(lane.spans.length * 30, 30);
          return (
            <div key={lane.lane} className="trv-lane">
              <div className="trv-lh">
                <span className="trv-ln">{traceLaneLabel(lane.lane)}</span>
                <span className="trv-lc">{lane.spans.length}</span>
              </div>
              <div className="trv-track" style={{ height: `${trackHeight}px` }}>
                {lane.spans.map((span, index) => {
                  const startMs = span.startMs ?? rangeStart ?? 0;
                  const endMs = span.endMs ?? span.startMs ?? startMs;
                  const left =
                    rangeStart != null && rangeEnd != null
                      ? Math.max(((startMs - rangeStart) / rangeWidth) * 100, 0)
                      : 0;
                  const width =
                    rangeStart != null && rangeEnd != null
                      ? Math.max((((Math.max(endMs, startMs) - startMs) || 0) / rangeWidth) * 100, 3)
                      : 100;
                  return (
                    <button
                      key={span.id}
                      type="button"
                      className={`trv-span trv-span-${traceStatusClass(span.status)} ${
                        selectedSpan?.id === span.id ? "on" : ""
                      }`}
                      style={{
                        left: `${Math.min(left, 97)}%`,
                        width: `${Math.min(width, 100 - Math.min(left, 97))}%`,
                        top: `${index * 30}px`,
                      }}
                      onClick={() => onSelectSpan(span.id)}
                      title={`${span.id} · ${traceDurationLabel(span.durationMs)}`}
                    >
                      <span className="trv-span-sum">{span.summary || span.id}</span>
                      <span className="trv-span-ms">{traceDurationLabel(span.durationMs)}</span>
                    </button>
                  );
                })}
              </div>
            </div>
          );
        })}
      </div>

      {selectedSpan && (
        <div className="trv-det">
          <div className="trv-det-h">
            <div>
              <p className="eyebrow">Selected span</p>
              <h4>{selectedSpan.id}</h4>
            </div>
            <span className={`trv-st trv-st-${traceStatusClass(selectedSpan.status)}`}>
              {selectedSpan.status}
            </span>
          </div>
          <p className="trv-det-sum">{selectedSpan.summary || "No summary."}</p>
          <div className="trv-det-meta">
            <span>lane {selectedSpan.lane}</span>
            {selectedSpan.stepIndex != null && <span>step {selectedSpan.stepIndex}</span>}
            <span>{traceDurationLabel(selectedSpan.durationMs)}</span>
            {selectedSpan.startMs != null && rangeStart != null && (
              <span>+{selectedSpan.startMs - rangeStart}ms</span>
            )}
          </div>
          {selectedSpan.capabilityTags.length > 0 && (
            <div className="trv-tags">
              {selectedSpan.capabilityTags.map((tag) => (
                <span key={tag} className="trv-tag">
                  {tag}
                </span>
              ))}
            </div>
          )}
          {selectedSpan.attributesSummary && (
            <pre className="cblk trv-attrs">{selectedSpan.attributesSummary}</pre>
          )}
          {selectedSpan.artifactLinks.length > 0 && (
            <div className="alinks">
              {selectedSpan.artifactLinks.map((artifact) => (
                <a key={`${selectedSpan.id}-${artifact.path}`} href={artifact.href} className="alink">
                  {artifact.label} ↗
                </a>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/* ════════════════════════════════════════════════════════
   APP
   ════════════════════════════════════════════════════════ */

function App() {
  const [benchmarkData, setBenchmarkData] = useState(
    initialBenchmarkData as unknown as BenchmarkDataShape,
  );
  const scorecardPreviewEnabled = useMemo(
    () => resolveScorecardPreviewEnabled(window.location.search),
    [],
  );
  const [activeTab, setActiveTab] = useState<TabId>("dashboard");
  const [caseSearch, setCaseSearch] = useState("");
  const [resultFilter, setResultFilter] = useState<ResultFilter>("all");
  const [mobileInsp, setMobileInsp] = useState(false);
  const [openSteps, setOpenSteps] = useState<Set<number>>(new Set([0]));
  const [selTraceSpanId, setSelTraceSpanId] = useState<string | null>(null);

  useEffect(() => {
    const livePath = benchmarkData.liveDataPath ?? "/generated/benchmark-data.json";
    const liveStorePath = benchmarkData.liveStorePath ?? "/generated/benchmark-store.json";
    let active = true;

    const refresh = async () => {
      try {
        const timestamp = Date.now();
        const [dataResponse, storeResponse] = await Promise.all([
          fetch(`${livePath}?ts=${timestamp}`, { cache: "no-store" }),
          fetch(`${liveStorePath}?ts=${timestamp}`, { cache: "no-store" }),
        ]);
        const nextData =
          dataResponse.ok ? await dataResponse.json() as BenchmarkDataShape : null;
        const liveRuns =
          storeResponse.ok
            ? collectLiveRunsFromStore(await storeResponse.json() as BenchmarkStoreShape)
            : null;
        if (!active) {
          return;
        }
        setBenchmarkData((current) => {
          let merged = current;
          if (nextData && current.generatedAt !== nextData.generatedAt) {
            merged = nextData;
          }
          if (liveRuns) {
            merged = mergeLiveRunsIntoBenchmarkData(merged, liveRuns);
          }
          return merged;
        });
      } catch {
        // Keep the last good snapshot when live refresh is unavailable.
      }
    };

    void refresh();
    const intervalId = window.setInterval(() => {
      void refresh();
    }, 2000);

    return () => {
      active = false;
      window.clearInterval(intervalId);
    };
  }, [benchmarkData.liveDataPath, benchmarkData.liveStorePath]);

  const effectiveBenchmarkData = useMemo(
    () =>
      scorecardPreviewEnabled
        ? withScorecardPreview(benchmarkData)
        : benchmarkData,
    [benchmarkData, scorecardPreviewEnabled],
  );

  const suiteSummaries = effectiveBenchmarkData.suiteSummaries as SuiteSummary[];
  const latestCases = effectiveBenchmarkData.latestCases as CaseRecord[];
  const agentModelMatrix = effectiveBenchmarkData.agentModelMatrix ?? null;
  const studioArtifactBenchmarkSuite =
    effectiveBenchmarkData.studioArtifactBenchmarkSuite ?? null;
  const studioArtifactArena = effectiveBenchmarkData.studioArtifactArena ?? null;
  const studioArtifactReleaseGates =
    effectiveBenchmarkData.studioArtifactReleaseGates ?? null;
  const studioArtifactDistillation =
    effectiveBenchmarkData.studioArtifactDistillation ?? null;
  const studioArtifactParityLoop =
    effectiveBenchmarkData.studioArtifactParityLoop ?? null;
  const scorecardViewModel = useMemo(
    () =>
      buildScorecardViewModel(agentModelMatrix, effectiveBenchmarkData.generatedAt, {
        previewMode: scorecardPreviewEnabled,
      }),
    [agentModelMatrix, effectiveBenchmarkData.generatedAt, scorecardPreviewEnabled],
  );
  const deploymentsViewModel = useMemo(
    () =>
      buildDeploymentsViewModel(agentModelMatrix, scorecardViewModel, {
        previewMode: scorecardPreviewEnabled,
      }),
    [agentModelMatrix, scorecardPreviewEnabled, scorecardViewModel],
  );
  const candidatesViewModel = useMemo(
    () =>
      buildCandidatesViewModel(agentModelMatrix, scorecardViewModel, {
        previewMode: scorecardPreviewEnabled,
      }),
    [agentModelMatrix, scorecardPreviewEnabled, scorecardViewModel],
  );

  const headline = latestCases[0] ?? null;
  const initialTriageSelection = useMemo(
    () => resolveInitialTriageSelection(suiteSummaries, latestCases),
    [latestCases, suiteSummaries],
  );
  const [selSuite, setSelSuite] = useState(initialTriageSelection.suite);
  const [selCaseId, setSelCaseId] = useState<string | null>(
    initialTriageSelection.caseId,
  );

  // Keyboard shortcuts
  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      if ((e.target as HTMLElement)?.tagName === "INPUT") return;
      const m: Record<string, TabId> = {
        "1": "dashboard",
        "2": "deployments",
        "3": "candidates",
        "4": "triage",
      };
      if (m[e.key]) setActiveTab(m[e.key]);
    };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, []);

  const suiteCases = useMemo(() => latestCases.filter((c) => c.suite === selSuite), [latestCases, selSuite]);
  const activeSuiteRun = useMemo(
    () => suiteSummaries.find((entry) => entry.suite === selSuite)?.liveRun ?? null,
    [selSuite, suiteSummaries],
  );
  const showLivePlaceholder = useMemo(
    () =>
      activeSuiteRun?.status === "running" &&
      Boolean(activeSuiteRun.activeCaseId) &&
      !suiteCases.some((entry) => entry.caseId === activeSuiteRun.activeCaseId),
    [activeSuiteRun, suiteCases],
  );

  const filtered = useMemo(() => {
    let cs = suiteCases;
    if (resultFilter !== "all") cs = cs.filter((c) => c.result === resultFilter);
    if (caseSearch.trim()) { const q = caseSearch.toLowerCase(); cs = cs.filter((c) => c.caseId.toLowerCase().includes(q) || (c.summary.query_text ?? "").toLowerCase().includes(q)); }
    return cs;
  }, [resultFilter, suiteCases, caseSearch]);

  const selCase = filtered.find((c) => c.caseId === selCaseId) ?? suiteCases.find((c) => c.caseId === selCaseId) ?? filtered[0] ?? suiteCases[0] ?? headline;

  useEffect(() => {
    const defaultSpanId =
      selCase?.trace?.bookmarks?.[0]?.spanId ??
      selCase?.trace?.lanes?.[0]?.spans?.[0]?.id ??
      null;
    setSelTraceSpanId(defaultSpanId);
  }, [selCase?.caseId]);

  const rCounts = useMemo(() => {
    const c: Record<string, number> = {
      all: suiteCases.length,
      red: 0,
      interrupted: 0,
      "near-miss": 0,
      pass: 0,
      unknown: 0,
    };
    for (const x of suiteCases) c[x.result] = (c[x.result] ?? 0) + 1;
    return c;
  }, [suiteCases]);

  const latestSlices = useMemo(() => latestCases.slice(0, 10), [latestCases]);
  const liveRuns = useMemo(
    () =>
      suiteSummaries
        .flatMap((entry) =>
          entry.liveRun ? [{ suite: entry.suite, liveRun: entry.liveRun }] : [],
        )
        .sort(
          (left, right) =>
            (right.liveRun.updatedAtMs ?? 0) - (left.liveRun.updatedAtMs ?? 0),
        ),
    [suiteSummaries],
  );

  const goTriage = useCallback((suite: string, cid: string | null) => {
    setSelSuite(suite); setSelCaseId(cid); setActiveTab("triage"); setMobileInsp(false);
  }, []);

  const pickCase = useCallback((id: string) => {
    setSelCaseId(id); setMobileInsp(true); setOpenSteps(new Set([0])); setSelTraceSpanId(null);
  }, []);

  const togStep = useCallback((i: number) => setOpenSteps((p) => { const n = new Set(p); n.has(i) ? n.delete(i) : n.add(i); return n; }), []);

  const jumpStep = useCallback((i: number) => {
    setOpenSteps((p) => new Set(p).add(i));
    setTimeout(() => document.querySelector(`[data-si="${i}"]`)?.scrollIntoView({ behavior: "smooth", block: "center" }), 60);
  }, []);

  const totRed = suiteSummaries.reduce((s, x) => s + x.counts.red, 0);
  const totInterrupted = suiteSummaries.reduce(
    (s, x) => s + (x.counts.interrupted ?? 0),
    0,
  );
  const totPass = suiteSummaries.reduce((s, x) => s + x.counts.pass, 0);
  const totAll = suiteSummaries.reduce((s, x) => s + total(x.counts), 0);

  return (
    <div className="shell">
      {/* ── Sidebar ── */}
      <aside className="sidebar">
        <div className="brand"><p className="eyebrow">IOI</p><h1>Benchmarks</h1></div>
        <nav className="stabs">{tabs.map((t) => (
          <button key={t.id} type="button" className={`stab ${t.id === activeTab ? "on" : ""}`} onClick={() => setActiveTab(t.id)}>
            <strong>{t.label}</strong><kbd>{t.shortcut}</kbd>
          </button>
        ))}</nav>
        {scorecardViewModel && (
          <div className="sb-sec">
            <p className="eyebrow">Matrix</p>
            <div className="sb-card sb-card-matrix">
              <span>{scorecardViewModel.sidebarSummary.statusLabel}</span>
              <strong>{scorecardViewModel.sidebarSummary.leaderLabel}</strong>
              <p className="sb-card-copy">
                {scorecardViewModel.sidebarSummary.outcomeLabel}
                {" · "}
                {scorecardViewModel.sidebarSummary.gapCount} gaps
              </p>
            </div>
          </div>
        )}
        <div className="sb-sec">
          <p className="eyebrow">Live suites</p>
          <div className="sb-slist">{suiteSummaries.map((s) => {
            const t = total(s.counts);
            return (
              <button key={s.suite} type="button" className={`ssb ${s.suite === selSuite ? "on" : ""}`}
                onClick={() => goTriage(s.suite, s.focusCaseId)}>
                <div className="ssb-top"><strong>{s.suite}</strong><ResultPill status={s.focusResult} /></div>
                {t > 0 ? (
                  <div className="ssb-bar"><div className="ssb-trk">
                    <div className="ssb-p" style={{ width: `${(s.counts.pass / t) * 100}%` }} />
                    <div className="ssb-n" style={{ width: `${(s.counts["near-miss"] / t) * 100}%` }} />
                    <div className="ssb-i" style={{ width: `${((s.counts.interrupted ?? 0) / t) * 100}%` }} />
                  </div><span className="ssb-lbl">{s.counts.pass}/{t}</span></div>
                ) : <span className="ssb-sub">{s.liveRun ? "Live run in progress" : "No retained cases yet"}</span>}
                {s.liveRun?.status === "running" && (
                  <div className="ssb-live">
                    <span className="live-dot" />
                    <span>{s.liveRun.completedCases}/{s.liveRun.totalCases} live</span>
                    <span className="ssb-live-case">{shortCaseId(s.liveRun.activeCaseId)}</span>
                  </div>
                )}
              </button>
            );
          })}</div>
        </div>
        <div className="sb-ft">
          <div className="sb-card">
            <span>Data</span>
            <strong>{relTime(effectiveBenchmarkData.generatedAt)}</strong>
            {totInterrupted > 0 && <p className="sb-card-copy">{totInterrupted} interrupted</p>}
          </div>
        </div>
      </aside>

      {/* ── Main ── */}
      <main className="main">

        {/* ═══ DASHBOARD ═══ */}
        {activeTab === "dashboard" && (
          <div className="dash scorecard-page">
            {scorecardViewModel ? (
              <>
                <ScorecardHero scorecard={scorecardViewModel} />
                <PresetScorecardBoard scorecard={scorecardViewModel} />
              </>
            ) : (
              <>
                <div className="kpis">
                  <article className="kpi"><span>Cases</span><strong>{totAll}</strong></article>
                  <article className="kpi"><span>Pass rate</span><strong>{totAll ? Math.round((totPass / totAll) * 100) : 0}%</strong></article>
                  <article className="kpi kpi-d"><span>Active reds</span><strong>{totRed}</strong></article>
                  <article className="kpi kpi-w"><span>Interrupted</span><strong>{totInterrupted}</strong></article>
                  <article className="kpi"><span>Focus</span><strong>{headline ? short(headline.caseId) : "—"}</strong></article>
                </div>
              </>
            )}

            <OperationalContextPanel
              suiteSummaries={suiteSummaries}
              liveSuiteCount={liveRuns.length}
              totalCases={totAll}
              totalPass={totPass}
              totalRed={totRed}
              totalInterrupted={totInterrupted}
              onOpenTriage={goTriage}
              short={short}
              shortCaseId={shortCaseId}
            />

            {studioArtifactBenchmarkSuite && (
              <section className="panel artifact-benchmark-panel">
                <div className="panel-head">
                  <div>
                    <p className="eyebrow">Studio artifact benchmark</p>
                    <h2>Parity ladder</h2>
                  </div>
                  <div className="artifact-benchmark-headline">
                    <span>catalog v{studioArtifactBenchmarkSuite.catalogVersion}</span>
                    <span>
                      {studioArtifactBenchmarkSuite.executedBenchmarks}/
                      {studioArtifactBenchmarkSuite.totalBenchmarks} executed
                    </span>
                    <span>
                      {studioArtifactBenchmarkSuite.arena.available
                        ? `${studioArtifactBenchmarkSuite.arena.matchCount} pairwise`
                        : "arena pending"}
                    </span>
                    <span>
                      {studioArtifactBenchmarkSuite.externalReferences.available
                        ? `${studioArtifactBenchmarkSuite.externalReferences.count} external refs`
                        : "refs pending"}
                    </span>
                    {studioArtifactArena && (
                      <span>
                        {studioArtifactArena.pendingBlindMatchCount} blind pending
                      </span>
                    )}
                    {studioArtifactReleaseGates && (
                      <span>
                        {studioArtifactReleaseGates.failCount} gate fails
                      </span>
                    )}
                    {studioArtifactParityLoop && (
                      <span>{fmtLoopStatus(studioArtifactParityLoop.status)} loop</span>
                    )}
                    {studioArtifactDistillation && (
                      <span>
                        {studioArtifactDistillation.proposalCount} distillation proposals
                      </span>
                    )}
                  </div>
                </div>

                <div className="artifact-benchmark-strip">
                  <article className="artifact-benchmark-stat">
                    <span>Ready rate</span>
                    <strong>
                      {fmtPct(
                        studioArtifactBenchmarkSuite.metrics.readyRate?.value ?? null,
                      )}
                    </strong>
                  </article>
                  <article className="artifact-benchmark-stat">
                    <span>Shim rate</span>
                    <strong>
                      {fmtPct(
                        studioArtifactBenchmarkSuite.metrics.shimRequiredRate?.value ??
                          null,
                      )}
                    </strong>
                  </article>
                  <article className="artifact-benchmark-stat">
                    <span>Judge score</span>
                    <strong>
                      {fmtScore(
                        studioArtifactBenchmarkSuite.metrics.averageJudgeScore?.value ??
                          null,
                      )}
                    </strong>
                  </article>
                  <article className="artifact-benchmark-stat">
                    <span>1st-paint</span>
                    <strong>
                      {fmtScore(
                        studioArtifactBenchmarkSuite.metrics.firstPaintEvidenceScore
                          ?.value ?? null,
                      )}
                    </strong>
                  </article>
                  <article className="artifact-benchmark-stat">
                    <span>Coverage</span>
                    <strong>
                      {studioArtifactBenchmarkSuite.executedBenchmarks}/
                      {studioArtifactBenchmarkSuite.totalBenchmarks}
                    </strong>
                  </article>
                </div>

                <div className="artifact-benchmark-grid">
                  <div className="artifact-benchmark-list">
                    {studioArtifactBenchmarkSuite.cases.map((entry) => {
                      const focusable = entry.caseAvailable && entry.matchedCaseId;
                      const row = (
                        <>
                          <div className="artifact-benchmark-copy">
                            <div className="artifact-benchmark-title-row">
                              <strong>{entry.title}</strong>
                              {entry.trackedParityTarget && (
                                <span className="artifact-benchmark-flag">parity</span>
                              )}
                              {!entry.caseAvailable && (
                                <span className="artifact-benchmark-flag artifact-benchmark-flag-muted">
                                  pending
                                </span>
                              )}
                            </div>
                            <p>{entry.prompt}</p>
                            <div className="artifact-benchmark-tags">
                              {entry.categories.slice(0, 3).map((tag) => (
                                <span key={`${entry.benchmarkId}-${tag}`}>{tag}</span>
                              ))}
                              {entry.externalReferenceCount > 0 && (
                                <span>{entry.externalReferenceCount} refs</span>
                              )}
                            </div>
                          </div>
                          <div className="artifact-benchmark-score">
                            <span>{entry.matchedClassification ?? "unrun"}</span>
                            <strong>{fmtScore(entry.judgeScore)}</strong>
                            <small>
                              {entry.shimDependent === true
                                ? "shimmed"
                                : entry.caseAvailable
                                  ? "native"
                                  : "no evidence"}
                            </small>
                          </div>
                        </>
                      );

                      return focusable ? (
                        <button
                          key={entry.benchmarkId}
                          type="button"
                          className={`artifact-benchmark-row ${
                            entry.trackedParityTarget ? "parity" : ""
                          }`}
                          onClick={() =>
                            goTriage("Studio Artifacts", entry.matchedCaseId)
                          }
                        >
                          {row}
                        </button>
                      ) : (
                        <div
                          key={entry.benchmarkId}
                          className={`artifact-benchmark-row artifact-benchmark-row-static ${
                            entry.trackedParityTarget ? "parity" : ""
                          }`}
                        >
                          {row}
                        </div>
                      );
                    })}
                  </div>

                  <div className="artifact-benchmark-side">
                    <div className="artifact-benchmark-side-block">
                      <span className="eyebrow">Tracked targets</span>
                      <ul>
                        {studioArtifactBenchmarkSuite.cases
                          .filter((entry) => entry.trackedParityTarget)
                          .map((entry) => (
                            <li key={`target-${entry.benchmarkId}`}>
                              {entry.title}
                              {entry.matchedClassification
                                ? ` · ${entry.matchedClassification}`
                                : " · pending evidence"}
                            </li>
                          ))}
                      </ul>
                    </div>
                    <div className="artifact-benchmark-side-block">
                      <span className="eyebrow">Arena</span>
                      <p>
                        {studioArtifactBenchmarkSuite.arena.available
                          ? `${studioArtifactBenchmarkSuite.arena.matchCount} pairwise matches across ${studioArtifactBenchmarkSuite.arena.participantCount} participants`
                          : "Blind pairwise evidence has not been retained yet."}
                      </p>
                      <p>
                        {studioArtifactBenchmarkSuite.externalReferences.available
                          ? `${studioArtifactBenchmarkSuite.externalReferences.count} retained external reference artifacts across ${studioArtifactBenchmarkSuite.externalReferences.benchmarkCount} benchmarks`
                          : "No retained external reference catalog yet."}
                      </p>
                      {studioArtifactBenchmarkSuite.arena.available &&
                        studioArtifactBenchmarkSuite.arena.ratings
                          .slice(0, 3)
                          .map((entry) => (
                            <div
                              key={`elo-${entry.participant}`}
                              className="artifact-benchmark-rating"
                            >
                              <span>{studioArtifactParticipantLabel(entry.participant, entry.label)}</span>
                              <strong>{entry.rating}</strong>
                            </div>
                          ))}
                    </div>
                    {studioArtifactArena && (
                      <div className="artifact-benchmark-side-block">
                        <span className="eyebrow">Frontier arena</span>
                        <div className="artifact-benchmark-loop-head">
                          <strong>{fmtLoopStatus(studioArtifactArena.status)}</strong>
                          <span className="artifact-benchmark-loop-badge">
                            {studioArtifactArena.pendingBlindMatchCount} pending
                          </span>
                        </div>
                        <p>
                          {studioArtifactArena.comparativeBenchmarkCount} comparative benchmarks
                          across {studioArtifactArena.internalParticipantCount} internal stacks and{" "}
                          {studioArtifactArena.externalReferenceCount} retained external references.
                        </p>
                        <div className="artifact-benchmark-loop-meta">
                          <div className="artifact-benchmark-loop-kv">
                            <span>pairwise</span>
                            <strong>{studioArtifactArena.pairwiseMatchCount}</strong>
                          </div>
                          <div className="artifact-benchmark-loop-kv">
                            <span>blind winners</span>
                            <strong>{studioArtifactArena.benchmarksWithBlindWinnerCount}</strong>
                          </div>
                          <div className="artifact-benchmark-loop-kv">
                            <span>executions</span>
                            <strong>{studioArtifactArena.internalExecutionCount}</strong>
                          </div>
                        </div>
                        {studioArtifactArena.topCompositeRatings.length > 0 && (
                          <div className="artifact-benchmark-link-list">
                            {studioArtifactArena.topCompositeRatings.slice(0, 3).map((entry) => (
                              <div
                                key={`arena-top-${entry.participant}`}
                                className="artifact-benchmark-rating"
                              >
                                <span>{studioArtifactParticipantLabel(entry.participant, entry.label)}</span>
                                <strong>{entry.rating}</strong>
                              </div>
                            ))}
                          </div>
                        )}
                        {studioArtifactArena.benchmarkLeaders.length > 0 && (
                          <p className="artifact-benchmark-loop-note">
                            {studioArtifactArena.benchmarkLeaders
                              .slice(0, 2)
                              .map((entry) => {
                                const leader =
                                  entry.blindWinner?.label ??
                                  entry.provisionalLeader?.label ??
                                  "pending";
                                const mode = entry.blindWinner?.unique ? "blind" : "provisional";
                                return `${entry.title ?? entry.benchmarkId}: ${leader} (${mode})`;
                              })
                              .join(" · ")}
                          </p>
                        )}
                        {studioArtifactArena.pendingBlindMatches.length > 0 && (
                          <p className="artifact-benchmark-loop-note">
                            Next:{" "}
                            {studioArtifactArena.pendingBlindMatches
                              .slice(0, 2)
                              .map(
                                (entry) =>
                                  `${entry.benchmarkTitle ?? entry.benchmarkId}: ${entry.leftLabel ?? "left"} vs ${entry.rightLabel ?? "right"}`,
                              )
                              .join(" · ")}
                          </p>
                        )}
                        <div className="artifact-benchmark-link-list">
                          {studioArtifactArena.ledgerHref && (
                            <a
                              href={studioArtifactArena.ledgerHref}
                              target="_blank"
                              rel="noreferrer"
                            >
                              arena_ledger ↗
                            </a>
                          )}
                        </div>
                      </div>
                    )}
                    {studioArtifactReleaseGates && (
                      <div className="artifact-benchmark-side-block">
                        <span className="eyebrow">Release gates</span>
                        <div className="artifact-benchmark-loop-head">
                          <strong>{fmtLoopStatus(studioArtifactReleaseGates.status)}</strong>
                          <span className="artifact-benchmark-loop-badge">
                            {studioArtifactReleaseGates.failCount} fail /{" "}
                            {studioArtifactReleaseGates.pendingCount} pending
                          </span>
                        </div>
                        <p>
                          {studioArtifactReleaseGates.passCount}/
                          {studioArtifactReleaseGates.gateCount} gates are currently passing.
                        </p>
                        <div className="artifact-benchmark-loop-meta">
                          <div className="artifact-benchmark-loop-kv">
                            <span>blocking</span>
                            <strong>
                              {studioArtifactReleaseGates.blockingGateIds.length}
                            </strong>
                          </div>
                          <div className="artifact-benchmark-loop-kv">
                            <span>ratchets</span>
                            <strong>
                              {studioArtifactReleaseGates.ratchetCandidateIds.length}
                            </strong>
                          </div>
                          <div className="artifact-benchmark-loop-kv">
                            <span>status</span>
                            <strong>
                              {studioArtifactReleaseGates.passing ? "ship" : "hold"}
                            </strong>
                          </div>
                        </div>
                        {studioArtifactReleaseGates.topGates.length > 0 && (
                          <p className="artifact-benchmark-loop-note">
                            {studioArtifactReleaseGates.topGates
                              .slice(0, 2)
                              .map((gate) => {
                                const reading =
                                  typeof gate.reading?.value === "number"
                                    ? gate.reading.value.toFixed(2)
                                    : gate.reading?.available === false
                                      ? "pending"
                                      : "—";
                                return `${gate.label ?? gate.id}: ${reading} (${gate.status ?? "unknown"})`;
                              })
                              .join(" · ")}
                          </p>
                        )}
                        {studioArtifactReleaseGates.ratchetCandidates.length > 0 && (
                          <p className="artifact-benchmark-loop-note">
                            Ratchet:{" "}
                            {studioArtifactReleaseGates.ratchetCandidates
                              .slice(0, 2)
                              .map(
                                (gate) =>
                                  `${gate.label ?? gate.id} → ${gate.candidateFloor?.toFixed(2) ?? "—"}`,
                              )
                              .join(" · ")}
                          </p>
                        )}
                        <div className="artifact-benchmark-link-list">
                          {studioArtifactReleaseGates.reportHref && (
                            <a
                              href={studioArtifactReleaseGates.reportHref}
                              target="_blank"
                              rel="noreferrer"
                            >
                              release_gates ↗
                            </a>
                          )}
                        </div>
                      </div>
                    )}
                    {studioArtifactParityLoop?.currentPlan && (
                      <div className="artifact-benchmark-side-block">
                        <span className="eyebrow">Autonomous parity loop</span>
                        <div className="artifact-benchmark-loop-head">
                          <strong>{fmtLoopStatus(studioArtifactParityLoop.status)}</strong>
                          <span className="artifact-benchmark-loop-badge">
                            {studioArtifactParityLoop.receiptCount} receipts
                          </span>
                        </div>
                        <p>{studioArtifactParityLoop.currentPlan.decision.reason}</p>
                        <div className="artifact-benchmark-loop-meta">
                          <div className="artifact-benchmark-loop-kv">
                            <span>intervention</span>
                            <strong>
                              {fmtLoopFamily(
                                studioArtifactParityLoop.currentPlan.selectedInterventionFamily,
                              )}
                            </strong>
                          </div>
                          <div className="artifact-benchmark-loop-kv">
                            <span>streak</span>
                            <strong>
                              {studioArtifactParityLoop.currentPlan.noImprovementStreak}
                            </strong>
                          </div>
                          <div className="artifact-benchmark-loop-kv">
                            <span>target</span>
                            <strong>
                              {studioArtifactParityLoop.currentPlan.weakestTarget?.label ??
                                "—"}
                            </strong>
                          </div>
                        </div>
                        {studioArtifactParityLoop.currentPlan.relevantCaseIds.length > 0 && (
                          <p className="artifact-benchmark-loop-note">
                            Cases: {studioArtifactParityLoop.currentPlan.relevantCaseIds.join(", ")}
                          </p>
                        )}
                        {studioArtifactParityLoop.latestReceipt?.comparison && (
                          <p className="artifact-benchmark-loop-note">
                            Last delta:{" "}
                            {studioArtifactParityLoop.latestReceipt.comparison.improvedMetrics
                              .length > 0
                              ? `improved ${studioArtifactParityLoop.latestReceipt.comparison.improvedMetrics.join(", ")}`
                              : "no improved metrics recorded"}
                          </p>
                        )}
                        <div className="artifact-benchmark-link-list">
                          {studioArtifactParityLoop.summaryHref && (
                            <a
                              href={studioArtifactParityLoop.summaryHref}
                              className="alink"
                            >
                              corpus_summary ↗
                            </a>
                          )}
                          {studioArtifactParityLoop.ledgerHref && (
                            <a
                              href={studioArtifactParityLoop.ledgerHref}
                              className="alink"
                            >
                              parity_ledger ↗
                            </a>
                          )}
                        </div>
                      </div>
                    )}
                    {studioArtifactDistillation && (
                      <div className="artifact-benchmark-side-block">
                        <span className="eyebrow">Distillation</span>
                        <div className="artifact-benchmark-loop-head">
                          <strong>{fmtLoopStatus(studioArtifactDistillation.status)}</strong>
                          <span className="artifact-benchmark-loop-badge">
                            {studioArtifactDistillation.proposalCount} proposals
                          </span>
                        </div>
                        <p>
                          {studioArtifactDistillation.appliedCount > 0
                            ? `${studioArtifactDistillation.appliedCount} upgrades already measured in the retained lane.`
                            : "Winning retained runs are captured as typed distillation proposals before they are folded back into the default stack."}
                        </p>
                        <div className="artifact-benchmark-loop-meta">
                          <div className="artifact-benchmark-loop-kv">
                            <span>applied</span>
                            <strong>{studioArtifactDistillation.appliedCount}</strong>
                          </div>
                          <div className="artifact-benchmark-loop-kv">
                            <span>gain</span>
                            <strong>{fmtScore(studioArtifactDistillation.measuredGain)}</strong>
                          </div>
                          <div className="artifact-benchmark-loop-kv">
                            <span>ledger</span>
                            <strong>{studioArtifactDistillation.ledgerPath ? "retained" : "—"}</strong>
                          </div>
                        </div>
                        {studioArtifactDistillation.topProposals[0] && (
                          <div className="artifact-benchmark-distill-card">
                            <strong>
                              {studioArtifactDistillation.topProposals[0].benchmarkTitle ??
                                studioArtifactDistillation.topProposals[0].benchmarkId ??
                                "Top proposal"}
                            </strong>
                            <p>
                              {studioArtifactDistillation.topProposals[0].before?.caseId ?? "—"}
                              {" → "}
                              {studioArtifactDistillation.topProposals[0].after?.caseId ?? "—"}
                            </p>
                            <div className="artifact-benchmark-tags">
                              {studioArtifactDistillation.topProposals[0].targetUpgrades.map(
                                (target) => (
                                  <span key={`distill-target-${target}`}>
                                    {fmtLoopFamily(target)}
                                  </span>
                                ),
                              )}
                            </div>
                            <p className="artifact-benchmark-loop-note">
                              Reasons:{" "}
                              {studioArtifactDistillation.topProposals[0].typedReasons.length > 0
                                ? studioArtifactDistillation.topProposals[0].typedReasons
                                    .map((reason) => fmtLoopFamily(reason))
                                    .join(", ")
                                : "no typed reasons retained"}
                            </p>
                          </div>
                        )}
                        <div className="artifact-benchmark-link-list">
                          {studioArtifactDistillation.ledgerHref && (
                            <a
                              href={studioArtifactDistillation.ledgerHref}
                              className="alink"
                            >
                              distillation_ledger ↗
                            </a>
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              </section>
            )}

            {liveRuns.length > 0 && (
              <section className="panel">
                <div className="panel-head">
                  <div>
                    <p className="eyebrow">Live runs</p>
                    <h2>In-flight suites</h2>
                  </div>
                </div>
                <div className="rail-ls">
                  {liveRuns.map(({ suite, liveRun }) => (
                    <button
                      key={`${suite}:${liveRun.runId}`}
                      type="button"
                      className="rcase rcase-live"
                      onClick={() => goTriage(suite, liveRun.activeCaseId)}
                    >
                      <div className="rc-top">
                        <h3>{suite}</h3>
                        <span className="pill pill-unknown">
                          <span className="pill-i">◌</span>
                          running
                        </span>
                      </div>
                      <p className="rc-q">
                        {liveRun.completedCases}/{liveRun.totalCases} completed
                        {liveRun.activeCaseId
                          ? ` · ${shortCaseId(liveRun.activeCaseId)} active`
                          : ""}
                      </p>
                      <div className="rc-m">
                        <span>{liveRun.taskSet}</span>
                        <span>{liveRun.runId}</span>
                      </div>
                    </button>
                  ))}
                </div>
              </section>
            )}

            <section className="panel">
              <div className="panel-head">
                <div>
                  <p className="eyebrow">Recent cases</p>
                  <h2>Latest retained slices</h2>
                </div>
              </div>
              <div className="rail-ls">
                {latestSlices.map((entry) => (
                  <button
                    key={`${entry.runId}:${entry.caseId}`}
                    type="button"
                    className="rcase"
                    onClick={() => goTriage(entry.suite, entry.caseId)}
                  >
                    <div className="rc-top">
                      <h3>{short(entry.caseId)}</h3>
                      <ResultPill status={entry.result} />
                    </div>
                    <p className="rc-q">{entry.summary.query_text ?? "—"}</p>
                    <div className="rc-m">
                      <span>{entry.suite}</span>
                      <span>{entry.runId}</span>
                      <span>{v(entry.summary.provider_calls)} calls</span>
                    </div>
                  </button>
                ))}
                {latestSlices.length === 0 && (
                  <p className="empty">No retained cases are available yet.</p>
                )}
              </div>
            </section>
          </div>
        )}

        {activeTab === "deployments" &&
          (deploymentsViewModel ? (
            <DeploymentsView deployments={deploymentsViewModel} />
          ) : (
            <div className="dash deployments-page">
              <section className="panel">
                <div className="panel-head">
                  <div>
                    <p className="eyebrow">Deployments</p>
                    <h2>Tiered defaults</h2>
                  </div>
                </div>
                <p className="empty">
                  No retained deployment summary is available yet.
                </p>
              </section>
            </div>
          ))}

        {activeTab === "candidates" &&
          (candidatesViewModel ? (
            <CandidatesView candidates={candidatesViewModel} />
          ) : (
            <div className="dash candidates-page">
              <section className="panel">
                <div className="panel-head">
                  <div>
                    <p className="eyebrow">Candidates</p>
                    <h2>Retained change review</h2>
                  </div>
                </div>
                <p className="empty">
                  No retained candidate summary is available yet.
                </p>
              </section>
            </div>
          ))}

        {/* ═══ TRIAGE ═══ */}
        {activeTab === "triage" && (
          <div className="triage">
            {mobileInsp && <button type="button" className="mob-back" onClick={() => setMobileInsp(false)}>← Back to cases</button>}

            <div className={`rail ${mobileInsp ? "rail-hide" : ""}`}>
              <div className="rail-hd">
                {activeSuiteRun?.status === "running" && (
                  <div className="live-run-card">
                    <div className="live-run-head">
                      <span className="eyebrow">Live Run</span>
                      <span className="live-run-pill">{activeSuiteRun.taskSet}</span>
                    </div>
                    <strong>{activeSuiteRun.runId}</strong>
                    <p>
                      {activeSuiteRun.completedCases}/{activeSuiteRun.totalCases} completed
                      {activeSuiteRun.activeCaseId ? ` · running ${shortCaseId(activeSuiteRun.activeCaseId)}` : ""}
                    </p>
                  </div>
                )}
                <div className="rail-flt">{resultFilters.map((f) => (
                  <button key={f.value} type="button" className={`fchip ${resultFilter === f.value ? "on" : ""}`} onClick={() => setResultFilter(f.value)}>
                    {f.label} <span className="fchip-n">{rCounts[f.value] ?? 0}</span>
                  </button>
                ))}</div>
                <input type="text" className="rail-q" placeholder="Filter…" value={caseSearch} onChange={(e) => setCaseSearch(e.target.value)} />
              </div>
              <div className="rail-ls">
                {showLivePlaceholder && activeSuiteRun?.activeCaseId && (
                  <div className="rcase rcase-live" aria-live="polite">
                    <div className="rc-top"><h3>{short(activeSuiteRun.activeCaseId)}</h3><span className="pill pill-unknown"><span className="pill-i">◌</span>running</span></div>
                    <p className="rc-q">Live case in progress. The detailed summary will appear here as soon as the case finishes.</p>
                    <div className="rc-m">
                      <span>{activeSuiteRun.completedCases}/{activeSuiteRun.totalCases} completed</span>
                      <span>{activeSuiteRun.taskSet}</span>
                      <span className="rc-live-tag">active</span>
                    </div>
                  </div>
                )}
                {(filtered.length > 0 ? filtered : suiteCases).map((c) => (
                  <button
                    key={c.caseId}
                    type="button"
                    className={`rcase rcase-${c.result} ${c.caseId === selCase?.caseId ? "on" : ""}`}
                    onClick={() => pickCase(c.caseId)}
                  >
                    <div className="rc-top"><h3>{short(c.caseId)}</h3><ResultPill status={c.result} /></div>
                    <p className="rc-q">{c.summary.query_text ?? "—"}</p>
                    <div className="rc-m">
                      <span>{v(c.summary.provider_calls)} calls</span>
                      <span>r={v(c.summary.reward)}</span>
                      <span>{c.detail.timeline.length} steps</span>
                      {c.findings.length > 0 && <span className="rc-tag">{c.findings.length}f</span>}
                    </div>
                  </button>
                ))}
                {filtered.length === 0 && suiteCases.length > 0 && <p className="empty">No matches.</p>}
              </div>
            </div>

            {selCase && (
              <div className={`insp ${!mobileInsp ? "insp-hide" : ""}`}>
                <div className="insp-sticky">
                  <div className="insp-hd">
                    <div>
                      <p className="eyebrow">{selCase.suite} · {selCase.runId}</p>
                      <h2>{selCase.caseId}</h2>
                      <div className="insp-qr">
                        <p className="insp-q">{selCase.summary.query_text ?? "—"}</p>
                        {selCase.summary.query_text && <CopyBtn text={selCase.summary.query_text} label="query" />}
                      </div>
                    </div>
                    <ResultPill status={selCase.result} />
                  </div>
                  <div className="insp-ms">{[
                    ["backend", v(selCase.summary.backend)], ["model", v(selCase.summary.model)],
                    ["calls", v(selCase.summary.provider_calls)], ["reward", v(selCase.summary.reward)],
                    ["raw", v(selCase.summary.raw_reward)], ["trigger", v(selCase.summary.final_trigger)],
                  ].map(([k, val]) => <div key={k} className="im"><span className="im-k">{k}</span><span className="im-v">{val}</span></div>)}</div>
                  {selCase.detail.timeline.length > 1 && <Minimap steps={selCase.detail.timeline} onSelect={jumpStep} />}
                </div>

                <div className="insp-body">
                  {selCase.findings.length > 0 && (
                    <div className="findings"><h3>Failure motifs</h3><ul>{selCase.findings.map((f, i) => <li key={i}>{f}</li>)}</ul></div>
                  )}
                  {Object.keys(selCase.detail.phaseTiming).length > 0 && (
                    <div className="isec"><h3>Timing waterfall</h3><Waterfall entries={Object.entries(selCase.detail.phaseTiming)} /></div>
                  )}
                  {selCase.traceMetrics.length > 0 && (
                    <div className="isec">
                      <h3>Trace metrics</h3>
                      <div className="tmg">
                        {selCase.traceMetrics.map((metric) => (
                          <button
                            key={metric.metricId}
                            type="button"
                            className={`tm tm-${traceStatusClass(metric.status)} ${
                              metric.supportingSpanIds[0] ? "tm-jump" : ""
                            } ${selTraceSpanId && metric.supportingSpanIds.includes(selTraceSpanId) ? "on" : ""}`}
                            onClick={() => metric.supportingSpanIds[0] && setSelTraceSpanId(metric.supportingSpanIds[0])}
                          >
                            <span className="tm-h">
                              <strong>{metric.label}</strong>
                              <span className="tm-st">{metric.status}</span>
                            </span>
                            {metric.summary && <span className="tm-s">{metric.summary}</span>}
                            {metric.supportingSpanIds.length > 0 && (
                              <span className="tm-ref">
                                spans {metric.supportingSpanIds.join(", ")}
                              </span>
                            )}
                          </button>
                        ))}
                      </div>
                    </div>
                  )}
                  {selCase.trace && selCase.trace.lanes.length > 0 && (
                    <div className="isec">
                      <TraceViewer
                        trace={selCase.trace}
                        selectedSpanId={selTraceSpanId}
                        onSelectSpan={setSelTraceSpanId}
                      />
                    </div>
                  )}
                  <div className="isec"><h3>Artifacts</h3>
                    <div className="alinks">{([
                      ["case_dir", selCase.links.caseDir],
                      ["diagnostic.md", selCase.links.diagnosticMarkdown], ["diagnostic.json", selCase.links.diagnosticJson],
                      ["inference_calls", selCase.links.inferenceCalls], ["inference_trace", selCase.links.inferenceTrace],
                      ["bridge_state", selCase.links.bridgeState],
                      ["trace_bundle", selCase.links.traceBundle], ["trace_analysis", selCase.links.traceAnalysis],
                    ] as const)
                      .filter(([, h]) => Boolean(h))
                      .map(([l, h]) => <a key={l} href={h} className="alink">{l} ↗</a>)}</div>
                  </div>
                  <div className="isec"><h3>Timeline <span className="scnt">{selCase.detail.timeline.length} steps</span></h3>
                    <div className="tl-ls">{selCase.detail.timeline.map((s, i) => (
                      <div key={`${selCase.caseId}-${s.stepIndex ?? i}`} data-si={i}>
                        <Step step={s} caseId={selCase.caseId} open={openSteps.has(i)} toggle={() => togStep(i)} />
                      </div>
                    ))}</div>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

      </main>
    </div>
  );
}

export default App;

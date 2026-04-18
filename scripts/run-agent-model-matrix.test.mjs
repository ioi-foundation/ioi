import assert from "node:assert/strict";
import test from "node:test";

import {
  artifactCommandDiagnostics,
  candidateLedgerForRun,
  decisionForRun,
  deploymentProfileForPreset,
  latestSummaryForRun,
  ollamaGenerateUrlForPreset,
  ollamaManagedModelNamesForPreset,
  ollamaResidentEntriesFromPsOutput,
  ollamaModelsToStopForTransition,
  ollamaResidentModelNamesFromPsOutput,
  ollamaTransitionStatusForPsOutput,
  ollamaWarmupPayloadForModel,
  runAbortReasonForShippedDefaultTimeouts,
  shouldIsolatePresetTransition,
  studioProofTraceMessages,
  timeoutDiagnosticLabel,
} from "./run-agent-model-matrix.mjs";

function makeScorecard(metrics) {
  return { available: true, reason: "", metrics };
}

function makePreset({
  presetId,
  label,
  role = "planner_verifier",
  benchmarkTier = "tier1",
  deploymentProfile = "local_workstation",
  shippedDefault = false,
  experimental = true,
  summaryPath = `/tmp/${presetId}-summary.json`,
  runRootPath = `/tmp/${presetId}`,
  topFindings = [],
  artifact = {},
  coding = {},
  research = {},
  computer = {},
  latency = {},
  discipline = {},
}) {
  return {
    presetId,
    label,
    role,
    benchmarkTier,
    deploymentProfile,
    shippedDefault,
    experimental,
    summaryPath,
    runRootPath,
    topFindings,
    scorecards: {
      artifactQuality: makeScorecard({
        passRate: 0,
        averageValidationScore: 0,
        verifierPassRate: 0,
        routeMatchRate: 0,
        averageRepairLoopIterations: 0,
        ...artifact,
      }),
      codingCompletion: makeScorecard({
        taskPassRate: 0,
        targetedTestPassRate: 0,
        verifierPassRate: 0,
        patchSynthesisReadyRate: 0,
        ...coding,
      }),
      researchQuality: makeScorecard({
        citationVerifierPassRate: 0,
        sourceIndependenceRate: 0,
        synthesisCompleteness: 0,
        freshnessPassRate: 0,
        quoteGroundingPassRate: 0,
        ...research,
      }),
      computerUseCompletion: makeScorecard({
        rewardFloorPassRate: 0,
        postconditionPassRate: 0,
        meanStepCount: 0,
        ...computer,
      }),
      latencyAndResourcePressure: makeScorecard({
        meanWallClockMs: 100,
        p95WallClockMs: 120,
        residentModelBytes: null,
        processorKind: "GPU",
        ...latency,
      }),
      operationalDiscipline: makeScorecard({
        conformancePassRate: 0.9,
        comparisonValidityRate: 1,
        protectedSplitPassRate: 1,
        rollbackReadinessRate: 1,
        ...discipline,
      }),
    },
  };
}

test("deploymentProfileForPreset respects explicit profiles and remote fallbacks", () => {
  assert.equal(
    deploymentProfileForPreset({
      deploymentProfile: "consumerLocal",
      runtimeKind: "local_http",
      benchmarkTier: "tier1",
      runtimeModel: "qwen3:8b",
    }),
    "local_gpu_8gb_class",
  );
  assert.equal(
    deploymentProfileForPreset({
      runtimeKind: "remote_http",
      family: "remote_http",
      benchmarkTier: "tier3",
      label: "Remote multimodal lane",
    }),
    "blind_cloud_standard",
  );
});

test("candidateLedgerForRun emits lineage and validation summaries", () => {
  const presets = [
    makePreset({
      presetId: "baseline",
      label: "Baseline",
      role: "baseline_local",
      benchmarkTier: "tier0",
      deploymentProfile: "local_gpu_8gb_class",
      shippedDefault: true,
      experimental: false,
      topFindings: ["Artifact lane still coverage-light."],
      artifact: { averageValidationScore: 0.2, verifierPassRate: 0.5 },
      latency: { meanWallClockMs: 180, p95WallClockMs: 220 },
    }),
    makePreset({
      presetId: "local-challenger",
      label: "Local Challenger",
      deploymentProfile: "local_workstation",
      topFindings: ["Research verifier still soft on long-horizon tasks."],
      artifact: { averageValidationScore: 0.8, verifierPassRate: 1, passRate: 1 },
      coding: {
        taskPassRate: 1,
        targetedTestPassRate: 1,
        verifierPassRate: 1,
        patchSynthesisReadyRate: 1,
      },
      research: {
        citationVerifierPassRate: 1,
        sourceIndependenceRate: 1,
        synthesisCompleteness: 1,
        freshnessPassRate: 1,
        quoteGroundingPassRate: 1,
      },
      computer: { rewardFloorPassRate: 1, postconditionPassRate: 1 },
      latency: { meanWallClockMs: 90, p95WallClockMs: 110 },
      discipline: { conformancePassRate: 1 },
    }),
    makePreset({
      presetId: "cloud-leader",
      label: "Cloud Leader",
      benchmarkTier: "tier3",
      deploymentProfile: "blind_cloud_standard",
      topFindings: ["Blind-cloud posture keeps this in shadow."],
      artifact: { averageValidationScore: 0.9, verifierPassRate: 1, passRate: 1 },
      coding: {
        taskPassRate: 1,
        targetedTestPassRate: 1,
        verifierPassRate: 1,
        patchSynthesisReadyRate: 1,
      },
      research: {
        citationVerifierPassRate: 1,
        sourceIndependenceRate: 1,
        synthesisCompleteness: 1,
        freshnessPassRate: 1,
        quoteGroundingPassRate: 1,
      },
      computer: { rewardFloorPassRate: 1, postconditionPassRate: 1 },
      latency: { meanWallClockMs: 70, p95WallClockMs: 90 },
      discipline: { conformancePassRate: 0.98 },
    }),
  ];
  const decision = {
    leaderPresetId: "cloud-leader",
    artifactLeaderPresetId: "cloud-leader",
    missingCoverage: [],
  };

  const ledger = candidateLedgerForRun(presets, decision);

  assert.equal(ledger.length, 3);
  assert.deepEqual(
    ledger.map((entry) => [entry.presetId, entry.deploymentProfile, entry.status]),
    [
      ["baseline", "local_gpu_8gb_class", "retained_default"],
      ["local-challenger", "local_workstation", "promotable"],
      ["cloud-leader", "blind_cloud_standard", "shadow_winner"],
    ],
  );
  assert.equal(ledger[1].parentCandidateId, "candidate:baseline");
  assert.deepEqual(ledger[1].changedContracts, [
    "role-model assignment",
    "verification policy",
    "recovery loop",
  ]);
  assert.deepEqual(ledger[2].evidenceLinks, [
    { label: "summary", path: "/tmp/cloud-leader-summary.json" },
    { label: "retained_run", path: "/tmp/cloud-leader" },
  ]);
  assert.equal(ledger[2].validationSummary.bestRequiredCount, 5);
  assert.equal(ledger[1].validationSummary.requiredReadyCount, 6);
  assert.equal(ledger[1].comparisonIntent, "model_change");
  assert.equal(ledger[1].executionScope, "fleet_shared");
  assert.equal(ledger[1].evaluationLanes.validation, "retained");
  assert.equal(ledger[1].rollbackTarget, "candidate:baseline");
  assert.equal(ledger[2].conformanceStatus, "warn");
});

test("decisionForRun keeps the default when a challenger regresses latency", () => {
  const decision = decisionForRun([
    makePreset({
      presetId: "baseline",
      label: "Baseline",
      shippedDefault: true,
      experimental: false,
      artifact: { averageValidationScore: 0.1 },
      latency: { meanWallClockMs: 100, p95WallClockMs: 120 },
    }),
    makePreset({
      presetId: "challenger",
      label: "Challenger",
      artifact: { averageValidationScore: 0.1 },
      computer: { rewardFloorPassRate: 1, postconditionPassRate: 1 },
      latency: { meanWallClockMs: 220, p95WallClockMs: 260 },
    }),
  ]);

  assert.equal(decision.outcome, "keep_default");
  assert.equal(decision.leaderPresetId, "baseline");
  assert.match(decision.summary, /shipped default still holds/i);
});

test("decisionForRun does not promote on a single challenger win", () => {
  const currentRun = [
    makePreset({
      presetId: "baseline",
      label: "Baseline",
      shippedDefault: true,
      experimental: false,
      artifact: { averageValidationScore: 0.1 },
      latency: { meanWallClockMs: 180, p95WallClockMs: 220 },
    }),
    makePreset({
      presetId: "challenger",
      label: "Challenger",
      artifact: { averageValidationScore: 0.8, verifierPassRate: 1, passRate: 1 },
      coding: {
        taskPassRate: 1,
        targetedTestPassRate: 1,
        verifierPassRate: 1,
        patchSynthesisReadyRate: 1,
      },
      research: {
        citationVerifierPassRate: 1,
        sourceIndependenceRate: 1,
        synthesisCompleteness: 1,
        freshnessPassRate: 1,
        quoteGroundingPassRate: 1,
      },
      computer: { rewardFloorPassRate: 1, postconditionPassRate: 1 },
      latency: { meanWallClockMs: 90, p95WallClockMs: 110 },
    }),
  ];
  const decision = decisionForRun(currentRun, {
    currentRunId: "2026-04-03T05-01-30-814Z",
  });

  assert.equal(decision.outcome, "keep_default");
  assert.equal(decision.leaderPresetId, "challenger");
  assert.equal(decision.retainedPromotionWinCount, 1);
  assert.equal(decision.requiredRetainedPromotionWins, 2);
  assert.equal(decision.promotionReady, false);
  assert.match(decision.summary, /1\/2 retained wins toward promotion/i);
});

test("decisionForRun promotes after repeated retained challenger wins", () => {
  const currentRun = [
    makePreset({
      presetId: "baseline",
      label: "Baseline",
      shippedDefault: true,
      experimental: false,
      artifact: { averageValidationScore: 0.1 },
      latency: { meanWallClockMs: 180, p95WallClockMs: 220 },
    }),
    makePreset({
      presetId: "challenger",
      label: "Challenger",
      artifact: { averageValidationScore: 0.8, verifierPassRate: 1, passRate: 1 },
      coding: {
        taskPassRate: 1,
        targetedTestPassRate: 1,
        verifierPassRate: 1,
        patchSynthesisReadyRate: 1,
      },
      research: {
        citationVerifierPassRate: 1,
        sourceIndependenceRate: 1,
        synthesisCompleteness: 1,
        freshnessPassRate: 1,
        quoteGroundingPassRate: 1,
      },
      computer: { rewardFloorPassRate: 1, postconditionPassRate: 1 },
      latency: { meanWallClockMs: 90, p95WallClockMs: 110 },
    }),
  ];
  const decision = decisionForRun(currentRun, {
    currentRunId: "2026-04-03T05-01-30-814Z",
    previousRuns: [
      {
        runId: "2026-04-03T03-15-26-954Z",
        presets: currentRun,
      },
    ],
  });

  assert.equal(decision.outcome, "promote_challenger");
  assert.equal(decision.leaderPresetId, "challenger");
  assert.equal(decision.retainedPromotionWinCount, 2);
  assert.equal(decision.requiredRetainedPromotionWins, 2);
  assert.equal(decision.promotionReady, true);
  assert.deepEqual(decision.retainedPromotionRunIds, [
    "2026-04-03T03-15-26-954Z",
    "2026-04-03T05-01-30-814Z",
  ]);
  assert.match(decision.summary, /clearing the 2-run promotion gate/i);
});

test("latestSummaryForRun marks partial preset progress as running", () => {
  const summary = latestSummaryForRun({
    paths: {
      presetCatalogPath: "/tmp/presets.json",
      benchmarkCatalogPath: "/tmp/benchmarks.json",
      latestSummaryPath: "/tmp/latest-summary.json",
    },
    runId: "2026-04-05T22-04-48-477Z",
    runRoot: "/tmp/runs/2026-04-05T22-04-48-477Z",
    previousRuns: [],
    presetSummaries: [
      {
        ...makePreset({
          presetId: "baseline",
          label: "Baseline",
          shippedDefault: true,
          experimental: false,
        }),
        cases: [
          {
            benchmarkId: "artifact-smoke",
            status: "completed",
          },
        ],
      },
    ],
    runAbortReason: null,
    plannedPresetCount: 2,
  });

  assert.equal(summary.status, "running");
  assert.equal(summary.summarizedPresetCount, 1);
  assert.equal(summary.completedPresetCount, 1);
  assert.equal(summary.fullyCompletedPresetCount, 1);
  assert.equal(summary.plannedPresetCount, 2);
  assert.equal(summary.presets.length, 1);
});

test("latestSummaryForRun retains a blocked top-level summary when aborted", () => {
  const summary = latestSummaryForRun({
    paths: {
      presetCatalogPath: "/tmp/presets.json",
      benchmarkCatalogPath: "/tmp/benchmarks.json",
      latestSummaryPath: "/tmp/latest-summary.json",
    },
    runId: "2026-04-05T22-04-48-477Z",
    runRoot: "/tmp/runs/2026-04-05T22-04-48-477Z",
    previousRuns: [],
    presetSummaries: [],
    runAbortReason: "Run interrupted by SIGINT.",
    plannedPresetCount: 2,
  });

  assert.equal(summary.status, "blocked");
  assert.equal(summary.summarizedPresetCount, 0);
  assert.equal(summary.runAbortReason, "Run interrupted by SIGINT.");
  assert.match(summary.decision.summary, /Run blocked: Run interrupted by SIGINT/i);
});

test("latestSummaryForRun distinguishes summarized presets from fully completed presets", () => {
  const summary = latestSummaryForRun({
    paths: {
      presetCatalogPath: "/tmp/presets.json",
      benchmarkCatalogPath: "/tmp/benchmarks.json",
      latestSummaryPath: "/tmp/latest-summary.json",
    },
    runId: "2026-04-05T22-46-31-670Z",
    runRoot: "/tmp/runs/2026-04-05T22-46-31-670Z",
    previousRuns: [],
    presetSummaries: [
      {
        ...makePreset({
          presetId: "baseline",
          label: "Baseline",
          shippedDefault: true,
          experimental: false,
        }),
        cases: [
          {
            benchmarkId: "artifact-download-bundle",
            status: "completed",
            result: "pass",
          },
        ],
      },
      {
        ...makePreset({
          presetId: "interrupted",
          label: "Interrupted Candidate",
        }),
        cases: [
          {
            benchmarkId: "artifact-download-bundle",
            status: "interrupted",
            result: "unknown",
          },
        ],
      },
    ],
    runAbortReason: "Run interrupted by SIGINT.",
    plannedPresetCount: 2,
  });

  assert.equal(summary.status, "blocked");
  assert.equal(summary.summarizedPresetCount, 2);
  assert.equal(summary.completedPresetCount, 1);
  assert.equal(summary.fullyCompletedPresetCount, 1);
  assert.equal(summary.comparedPresetCount, 2);
  assert.equal(summary.executedPresetCount, 2);
});

test("ollamaManagedModelNamesForPreset dedupes the runtime and acceptance models", () => {
  assert.deepEqual(
    ollamaManagedModelNamesForPreset({
      runtimeKind: "local_http",
      family: "ollama_openai",
      runtimeModel: "qwen3:8b",
      artifactAcceptanceModel: "qwen3:8b",
    }),
    ["qwen3:8b"],
  );
  assert.deepEqual(
    ollamaManagedModelNamesForPreset({
      runtimeKind: "local_http",
      family: "ollama_openai",
      runtimeModel: "llama3.2:3b",
      artifactAcceptanceModel: "qwen2.5:14b",
    }),
    ["llama3.2:3b", "qwen2.5:14b"],
  );
});

test("ollamaResidentModelNamesFromPsOutput parses resident model names from ollama ps", () => {
  const output = [
    "NAME              ID              SIZE      PROCESSOR    UNTIL",
    "llama3.2:3b       abc123          2.0 GB    100% GPU     4 minutes from now",
    "qwen2.5:14b       def456          9.0 GB    100% GPU     3 minutes from now",
    "",
  ].join("\n");
  assert.deepEqual(ollamaResidentModelNamesFromPsOutput(output), [
    "llama3.2:3b",
    "qwen2.5:14b",
  ]);
});

test("ollamaResidentEntriesFromPsOutput keeps transition-state fields", () => {
  const output = [
    "NAME              ID              SIZE      PROCESSOR          CONTEXT    UNTIL",
    "qwen2.5:14b       def456          9.0 GB    29%/71% CPU/GPU   4096       Stopping...",
    "qwen3:8b          ghi789          5.2 GB    100% GPU          4096       2 minutes from now",
    "",
  ].join("\n");

  assert.deepEqual(ollamaResidentEntriesFromPsOutput(output), [
    {
      name: "qwen2.5:14b",
      id: "def456",
      size: "9.0 GB",
      processor: "29%/71% CPU/GPU",
      context: "4096",
      until: "Stopping...",
    },
    {
      name: "qwen3:8b",
      id: "ghi789",
      size: "5.2 GB",
      processor: "100% GPU",
      context: "4096",
      until: "2 minutes from now",
    },
  ]);
});

test("ollamaModelsToStopForTransition isolates all resident non-target ollama models", () => {
  const currentPreset = {
    runtimeKind: "local_http",
    family: "ollama_openai",
    runtimeModel: "llama3.2:3b",
    artifactAcceptanceModel: "qwen2.5:14b",
  };
  const nextPreset = {
    runtimeKind: "local_http",
    family: "ollama_openai",
    runtimeModel: "qwen3:8b",
    artifactAcceptanceModel: "qwen3:8b",
  };
  const psOutput = [
    "NAME              ID              SIZE      PROCESSOR    UNTIL",
    "llama3.2:3b       abc123          2.0 GB    100% GPU     4 minutes from now",
    "qwen2.5:14b       def456          9.0 GB    100% GPU     3 minutes from now",
    "nomic-embed-text:latest ghi012    595 MB    100% GPU     3 minutes from now",
    "qwen3:8b          ghi789          5.2 GB    100% GPU     2 minutes from now",
  ].join("\n");

  assert.equal(shouldIsolatePresetTransition(currentPreset, nextPreset), true);
  assert.deepEqual(
    ollamaModelsToStopForTransition(currentPreset, nextPreset, psOutput),
    ["llama3.2:3b", "qwen2.5:14b", "nomic-embed-text:latest"],
  );
  assert.deepEqual(
    ollamaModelsToStopForTransition(
      currentPreset,
      { runtimeKind: "remote_http", family: "remote_http" },
      psOutput,
    ),
    [],
  );
});

test("ollamaTransitionStatusForPsOutput requires a clean resident warm state", () => {
  const nextPreset = {
    runtimeKind: "local_http",
    family: "ollama_openai",
    runtimeModel: "qwen3:8b",
    artifactAcceptanceModel: "qwen3:8b",
  };

  const unstable = ollamaTransitionStatusForPsOutput(
    nextPreset,
    [
      "NAME              ID              SIZE      PROCESSOR          CONTEXT    UNTIL",
      "qwen2.5:14b       def456          9.0 GB    29%/71% CPU/GPU   4096       Stopping...",
      "",
    ].join("\n"),
  );
  assert.equal(unstable.ready, false);
  assert.deepEqual(unstable.blockingModels, ["qwen2.5:14b"]);
  assert.deepEqual(unstable.missingWarmModels, ["qwen3:8b"]);
  assert.deepEqual(unstable.stoppingWarmModels, []);

  const stable = ollamaTransitionStatusForPsOutput(
    nextPreset,
    [
      "NAME              ID              SIZE      PROCESSOR          CONTEXT    UNTIL",
      "qwen3:8b          ghi789          5.2 GB    100% GPU          4096       2 minutes from now",
      "",
    ].join("\n"),
  );
  assert.equal(stable.ready, true);
  assert.deepEqual(stable.blockingModels, []);
  assert.deepEqual(stable.missingWarmModels, []);
  assert.deepEqual(stable.stoppingWarmModels, []);
});

test("ollamaGenerateUrlForPreset derives the native generate endpoint from the health URL", () => {
  assert.equal(
    ollamaGenerateUrlForPreset({
      runtimeHealthUrl: "http://127.0.0.1:11434/api/tags",
      runtimeUrl: "http://127.0.0.1:11434/v1/chat/completions",
    }),
    "http://127.0.0.1:11434/api/generate",
  );
});

test("ollamaWarmupPayloadForModel uses a tiny keep-alive generate request", () => {
  assert.deepEqual(JSON.parse(ollamaWarmupPayloadForModel("qwen3:8b")), {
    model: "qwen3:8b",
    prompt: "Reply with OK.",
    stream: false,
    keep_alive: "10m",
    options: {
      num_predict: 1,
      temperature: 0,
    },
  });
});

test("studioProofTraceMessages extracts stage breadcrumbs from mixed stderr", () => {
  const output = [
    "INFO bootstrap starting",
    "[studio-proof-trace] artifact_generation:start renderer=HtmlIframe",
    "[2026-04-03T12:59:47Z ERROR ioi_api::vm::inference::http_adapter] Provider Error 500 Internal Server Error: overloaded",
    "[studio-proof-trace] artifact_generation:materialization_inference:start id=candidate-1 prompt_bytes=5065 temperature=0.2 max_tokens=1600",
    "",
  ].join("\n");

  assert.deepEqual(studioProofTraceMessages(output), [
    "artifact_generation:start renderer=HtmlIframe",
    "artifact_generation:materialization_inference:start id=candidate-1 prompt_bytes=5065 temperature=0.2 max_tokens=1600",
  ]);
});

test("artifactCommandDiagnostics keeps last proof trace and provider error", () => {
  const diagnostics = artifactCommandDiagnostics({
    stdout: "",
    stderr: [
      "[studio-proof-trace] artifact_generation:start renderer=HtmlIframe",
      "[2026-04-03T12:59:47Z ERROR ioi_api::vm::inference::http_adapter] Provider Error 500 Internal Server Error: overloaded",
      "[studio-proof-trace] artifact_generation:materialization_inference:start id=candidate-1 prompt_bytes=5065 temperature=0.2 max_tokens=1600",
      "",
    ].join("\n"),
    error: "spawnSync /home/heathledger/Documents/ioi/repos/ioi/target/debug/cli ETIMEDOUT",
    timedOut: true,
    status: 1,
  });

  assert.equal(diagnostics.timedOut, true);
  assert.equal(diagnostics.studioProofTraceCount, 2);
  assert.match(
    diagnostics.lastStudioProofTrace,
    /artifact_generation:materialization_inference:start/,
  );
  assert.match(diagnostics.lastProviderError, /Provider Error 500 Internal Server Error/);
});

test("timeoutDiagnosticLabel prefers the benchmark id and includes last trace context", () => {
  const label = timeoutDiagnosticLabel({
    benchmarkId: "artifact-download-bundle",
    title: "Artifact download bundle",
    timedOut: true,
    lastStudioProofTrace:
      "artifact_generation:materialization_inference:start id=candidate-1 prompt_bytes=5065 temperature=0.2 max_tokens=1600",
    lastProviderError: null,
  });

  assert.match(label, /^artifact-download-bundle \(/);
  assert.match(label, /last_trace=artifact_generation:materialization_inference:start/);
});

test("runAbortReasonForShippedDefaultTimeouts aborts a full retained comparison after repeated default timeouts", () => {
  const reason = runAbortReasonForShippedDefaultTimeouts({
    options: {
      presets: ["ollama-openai", "planner-grade-local-oss-qwen3-8b"],
      benchmarks: null,
      skipComputerUse: false,
    },
    selectedPresets: [
      { id: "ollama-openai", shippedDefault: true, runtimeKind: "local_http" },
      {
        id: "planner-grade-local-oss-qwen3-8b",
        shippedDefault: false,
        runtimeKind: "local_http",
      },
    ],
    preset: { id: "ollama-openai", shippedDefault: true, runtimeKind: "local_http" },
    caseResults: [
      {
        benchmarkId: "artifact-download-bundle",
        status: "timed_out",
        timedOut: true,
        lastStudioProofTrace:
          "artifact_generation:materialization_inference:start id=candidate-1 prompt_bytes=5065 temperature=0.2 max_tokens=1600",
      },
      {
        benchmarkId: "artifact-markdown-report",
        status: "timed_out",
        timedOut: true,
        lastProviderError: "Provider Error 500 Internal Server Error: overloaded",
      },
    ],
  });

  assert.match(reason, /Shipped default preset 'ollama-openai' timed out on the first 2 attempted benchmarks/i);
  assert.match(reason, /First timed-out slices:/);
  assert.match(reason, /artifact-download-bundle/);
  assert.match(reason, /last_trace=artifact_generation:materialization_inference:start/);
});

test("runAbortReasonForShippedDefaultTimeouts does not fire for partial runs or mixed outcomes", () => {
  assert.equal(
    runAbortReasonForShippedDefaultTimeouts({
      options: {
        presets: ["ollama-openai", "planner-grade-local-oss-qwen3-8b"],
        benchmarks: ["artifact-editorial-launch-page"],
        skipComputerUse: false,
      },
      selectedPresets: [
        { id: "ollama-openai", shippedDefault: true, runtimeKind: "local_http" },
        {
          id: "planner-grade-local-oss-qwen3-8b",
          shippedDefault: false,
          runtimeKind: "local_http",
        },
      ],
      preset: {
        id: "ollama-openai",
        shippedDefault: true,
        runtimeKind: "local_http",
      },
      caseResults: [
        { status: "timed_out", timedOut: true },
        { status: "timed_out", timedOut: true },
      ],
    }),
    null,
  );

  assert.equal(
    runAbortReasonForShippedDefaultTimeouts({
      options: {
        presets: ["ollama-openai", "planner-grade-local-oss-qwen3-8b"],
        benchmarks: null,
        skipComputerUse: false,
      },
      selectedPresets: [
        { id: "ollama-openai", shippedDefault: true, runtimeKind: "local_http" },
        {
          id: "planner-grade-local-oss-qwen3-8b",
          shippedDefault: false,
          runtimeKind: "local_http",
        },
      ],
      preset: {
        id: "ollama-openai",
        shippedDefault: true,
        runtimeKind: "local_http",
      },
      caseResults: [
        { status: "timed_out", timedOut: true },
        { status: "completed", timedOut: false },
      ],
    }),
    null,
  );
});

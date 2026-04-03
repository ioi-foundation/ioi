import assert from "node:assert/strict";
import test from "node:test";

import {
  decisionForRun,
  ollamaGenerateUrlForPreset,
  ollamaManagedModelNamesForPreset,
  ollamaResidentEntriesFromPsOutput,
  ollamaModelsToStopForTransition,
  ollamaResidentModelNamesFromPsOutput,
  ollamaTransitionStatusForPsOutput,
  ollamaWarmupPayloadForModel,
  runAbortReasonForShippedDefaultTimeouts,
  shouldIsolatePresetTransition,
} from "./run-agent-model-matrix.mjs";

function makeScorecard(metrics) {
  return { available: true, reason: "", metrics };
}

function makePreset({
  presetId,
  label,
  shippedDefault = false,
  experimental = true,
  artifact = {},
  coding = {},
  research = {},
  computer = {},
  latency = {},
}) {
  return {
    presetId,
    label,
    shippedDefault,
    experimental,
    scorecards: {
      artifactQuality: makeScorecard({
        passRate: 0,
        averageJudgeScore: 0,
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
    },
  };
}

test("decisionForRun keeps the default when a challenger regresses latency", () => {
  const decision = decisionForRun([
    makePreset({
      presetId: "baseline",
      label: "Baseline",
      shippedDefault: true,
      experimental: false,
      artifact: { averageJudgeScore: 0.1 },
      latency: { meanWallClockMs: 100, p95WallClockMs: 120 },
    }),
    makePreset({
      presetId: "challenger",
      label: "Challenger",
      artifact: { averageJudgeScore: 0.1 },
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
      artifact: { averageJudgeScore: 0.1 },
      latency: { meanWallClockMs: 180, p95WallClockMs: 220 },
    }),
    makePreset({
      presetId: "challenger",
      label: "Challenger",
      artifact: { averageJudgeScore: 0.8, verifierPassRate: 1, passRate: 1 },
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
      artifact: { averageJudgeScore: 0.1 },
      latency: { meanWallClockMs: 180, p95WallClockMs: 220 },
    }),
    makePreset({
      presetId: "challenger",
      label: "Challenger",
      artifact: { averageJudgeScore: 0.8, verifierPassRate: 1, passRate: 1 },
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
      { status: "timed_out", timedOut: true },
      { status: "timed_out", timedOut: true },
    ],
  });

  assert.match(reason, /Shipped default preset 'ollama-openai' timed out on the first 2 attempted benchmarks/i);
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

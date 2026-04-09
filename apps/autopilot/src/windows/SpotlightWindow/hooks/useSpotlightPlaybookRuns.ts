import { useCallback, useEffect, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { continueSessionTask } from "@ioi/agent-ide";
import {
  getSessionOperatorRuntime,
  type SessionOperatorRuntime,
} from "../../../services/sessionRuntime";
import type {
  LocalEngineAgentPlaybookRecord,
  LocalEngineParentPlaybookReceiptRecord,
  LocalEngineParentPlaybookRunRecord,
  LocalEngineWorkerCompletionContract,
} from "../../../types";

export type SpotlightPlaybookStepRecord =
  LocalEngineParentPlaybookRunRecord["steps"][number] & {
  dependsOnStepIds: string[];
  dependsOnLabels: string[];
};

export type SpotlightPlaybookRunRecord = Omit<
  LocalEngineParentPlaybookRunRecord,
  "steps"
> & {
  playbookSummary: string | null;
  mergeContract: LocalEngineWorkerCompletionContract | null;
  steps: SpotlightPlaybookStepRecord[];
};

type SpotlightPlaybookRunsState = {
  runs: SpotlightPlaybookRunRecord[];
  loading: boolean;
  busyRunId: string | null;
  message: string | null;
  error: string | null;
};

const INITIAL_STATE: SpotlightPlaybookRunsState = {
  runs: [],
  loading: false,
  busyRunId: null,
  message: null,
  error: null,
};

function runBelongsToSession(
  run: LocalEngineParentPlaybookRunRecord,
  sessionId: string,
): boolean {
  if (run.parentSessionId === sessionId || run.activeChildSessionId === sessionId) {
    return true;
  }
  return run.steps.some((step) => step.childSessionId === sessionId);
}

function selectRunsForSession(
  snapshotRuns: LocalEngineParentPlaybookRunRecord[],
  sessionId: string | null,
): LocalEngineParentPlaybookRunRecord[] {
  if (!sessionId) {
    return [];
  }

  return snapshotRuns
    .filter((run) => runBelongsToSession(run, sessionId))
    .sort((left, right) => right.updatedAtMs - left.updatedAtMs);
}

function latestRunReceipt(
  run: SpotlightPlaybookRunRecord,
): LocalEngineParentPlaybookReceiptRecord | null {
  return run.steps
    .flatMap((step) => step.receipts)
    .sort((left, right) => right.timestampMs - left.timestampMs)[0] ?? null;
}

function latestStepReceipt(
  step: SpotlightPlaybookStepRecord,
): LocalEngineParentPlaybookReceiptRecord | null {
  return [...step.receipts].sort(
    (left, right) => right.timestampMs - left.timestampMs,
  )[0] ?? null;
}

function enrichRun(
  run: LocalEngineParentPlaybookRunRecord,
  playbooksById: Map<string, LocalEngineAgentPlaybookRecord>,
): SpotlightPlaybookRunRecord {
  const playbook = playbooksById.get(run.playbookId);
  const playbookSteps = new Map(
    (playbook?.steps ?? []).map((step) => [step.stepId, step]),
  );

  return {
    ...run,
    playbookSummary: playbook?.summary ?? null,
    mergeContract: playbook?.completionContract ?? null,
    steps: run.steps.map((step) => {
      const definition = playbookSteps.get(step.stepId);
      const dependsOnStepIds = definition?.dependsOn ?? [];
      const dependsOnLabels = dependsOnStepIds.map((dependsOnStepId) => {
        const dependency = playbookSteps.get(dependsOnStepId);
        return dependency?.label ?? dependsOnStepId;
      });

      return {
        ...step,
        dependsOnStepIds,
        dependsOnLabels,
      };
    }),
  };
}

function buildMergeDirective(mergeMode?: string | null): string {
  const normalized = (mergeMode || "").trim().toLowerCase();
  switch (normalized) {
    case "attach evidence":
      return "Attach the worker receipts and artifacts as evidence in the parent plan without discarding the current draft.";
    case "replace draft":
      return "Replace the current parent draft/output with the promoted worker result and note what changed.";
    case "completion message":
      return "Turn the promoted worker result into the parent plan's completion/update message and keep the operator-facing narrative concise.";
    case "append summary":
    default:
      return "Append the promoted worker summary into the parent plan and retain the existing draft unless the evidence requires a rewrite.";
  }
}

function buildPromotionPrompt({
  run,
  receipt,
  targetLabel,
}: {
  run: SpotlightPlaybookRunRecord;
  receipt: LocalEngineParentPlaybookReceiptRecord;
  targetLabel: string;
}): string {
  const mergeContract = run.mergeContract;
  const lines = [
    "Operator instruction:",
    `Promote the ${targetLabel} result into the parent plan now.`,
    `Playbook: ${run.playbookLabel}`,
    `Run: ${run.runId}`,
    `Parent session: ${run.parentSessionId}`,
    mergeContract?.mergeMode ? `Merge mode: ${mergeContract.mergeMode}` : undefined,
    mergeContract?.successCriteria
      ? `Success criteria: ${mergeContract.successCriteria}`
      : undefined,
    mergeContract?.expectedOutput
      ? `Expected output: ${mergeContract.expectedOutput}`
      : undefined,
    mergeContract?.verificationHint
      ? `Verification hint: ${mergeContract.verificationHint}`
      : undefined,
    `Worker result summary: ${receipt.summary}`,
    receipt.templateId ? `Worker template: ${receipt.templateId}` : undefined,
    receipt.workflowId ? `Workflow: ${receipt.workflowId}` : undefined,
    receipt.childSessionId ? `Child session: ${receipt.childSessionId}` : undefined,
    receipt.receiptRef ? `Receipt ref: ${receipt.receiptRef}` : undefined,
    receipt.artifactIds.length > 0
      ? `Artifacts: ${receipt.artifactIds.join(", ")}`
      : "Artifacts: none",
    "Promotion rules:",
    `- ${buildMergeDirective(mergeContract?.mergeMode)}`,
    "- Reuse the cited worker evidence instead of re-running the same delegated work unless validation fails.",
    "- If the promoted result is insufficient, say exactly what is missing before delegating again.",
    "- Preserve operator-visible receipts and references in the parent narrative.",
  ];

  return lines.filter(Boolean).join("\n");
}

async function loadRuns(
  runtime: SessionOperatorRuntime,
  sessionId: string | null,
) : Promise<SpotlightPlaybookRunRecord[]> {
  const snapshot = await runtime.getLocalEngineSnapshot();
  const playbooksById = new Map(
    snapshot.agentPlaybooks.map((playbook) => [playbook.playbookId, playbook]),
  );
  return selectRunsForSession(snapshot.parentPlaybookRuns, sessionId).map((run) =>
    enrichRun(run, playbooksById),
  );
}

export function useSpotlightPlaybookRuns(sessionId: string | null) {
  const [state, setState] = useState<SpotlightPlaybookRunsState>(INITIAL_STATE);

  const refreshRuns = useCallback(
    async (showLoading: boolean = false) => {
      if (!sessionId) {
        setState((current) => ({
          ...current,
          runs: [],
          loading: false,
          busyRunId: null,
          message: null,
          error: null,
        }));
        return;
      }

      if (showLoading) {
        setState((current) => ({
          ...current,
          loading: true,
          message: null,
          error: null,
        }));
      }

      try {
        const runs = await loadRuns(getSessionOperatorRuntime(), sessionId);
        setState((current) => ({
          ...current,
          runs,
          loading: false,
          error: null,
        }));
      } catch (error) {
        setState((current) => ({
          ...current,
          loading: false,
          error: String(error),
        }));
      }
    },
    [sessionId],
  );

  useEffect(() => {
    void refreshRuns(true);
  }, [refreshRuns]);

  useEffect(() => {
    let active = true;
    const unlistenPromise = listen("local-engine-updated", () => {
      if (!active) {
        return;
      }
      void refreshRuns(false);
    });

    return () => {
      active = false;
      void unlistenPromise.then((unlisten) => unlisten());
    };
  }, [refreshRuns]);

  const runAction = useCallback(
    async (
      runId: string,
      successMessage: string,
      action: (runtime: SessionOperatorRuntime) => Promise<void>,
    ) => {
      setState((current) => ({
        ...current,
        busyRunId: runId,
        message: null,
        error: null,
      }));

      try {
        const runtime = getSessionOperatorRuntime();
        await action(runtime);
        const runs = await loadRuns(runtime, sessionId);
        setState((current) => ({
          ...current,
          runs,
          loading: false,
          busyRunId: null,
          message: successMessage,
          error: null,
        }));
      } catch (error) {
        setState((current) => ({
          ...current,
          busyRunId: null,
          error: String(error),
        }));
      }
    },
    [sessionId],
  );

  const retryPlaybookRun = useCallback(
    async (runId: string) =>
      runAction(
        runId,
        "Retry request sent to the active parent playbook step.",
        (runtime) => runtime.retryLocalEngineParentPlaybookRun(runId),
      ),
    [runAction],
  );

  const resumePlaybookRun = useCallback(
    async (runId: string, stepId?: string | null) =>
      runAction(
        runId,
        stepId
          ? "Resume request sent for the selected parent playbook step."
          : "Resume request sent for the current parent playbook step.",
        (runtime) => runtime.resumeLocalEngineParentPlaybookRun(runId, stepId),
      ),
    [runAction],
  );

  const dismissPlaybookRun = useCallback(
    async (runId: string) =>
      runAction(
        runId,
        "Parent playbook run dismissed from Spotlight.",
        (runtime) => runtime.dismissLocalEngineParentPlaybookRun(runId),
      ),
    [runAction],
  );

  const messageWorkerSession = useCallback(
    async (runId: string, workerSessionId: string, message: string) => {
      const trimmedMessage = message.trim();
      if (!trimmedMessage) {
        setState((current) => ({
          ...current,
          error: "Worker message cannot be empty.",
        }));
        return;
      }

      setState((current) => ({
        ...current,
        busyRunId: runId,
        message: null,
        error: null,
      }));

      try {
        await continueSessionTask(workerSessionId, trimmedMessage);
        const runs = await loadRuns(getSessionOperatorRuntime(), sessionId ?? null);
        setState((current) => ({
          ...current,
          runs,
          loading: false,
          busyRunId: null,
          message: "Operator message sent to the delegated worker session.",
          error: null,
        }));
      } catch (error) {
        setState((current) => ({
          ...current,
          busyRunId: null,
          error: String(error),
        }));
      }
    },
    [sessionId],
  );

  const stopWorkerSession = useCallback(
    async (runId: string, workerSessionId: string) => {
      setState((current) => ({
        ...current,
        busyRunId: runId,
        message: null,
        error: null,
      }));

      try {
        await continueSessionTask(
          workerSessionId,
          [
            "Operator instruction:",
            "Stop your current work now.",
            "Summarize current status, blockers, touched files, and any artifacts or receipts produced so far.",
            "Do not continue execution until the operator sends a new instruction.",
          ].join("\n"),
        );
        const runs = await loadRuns(getSessionOperatorRuntime(), sessionId ?? null);
        setState((current) => ({
          ...current,
          runs,
          loading: false,
          busyRunId: null,
          message: "Stop instruction sent to the delegated worker session.",
          error: null,
        }));
      } catch (error) {
        setState((current) => ({
          ...current,
          busyRunId: null,
          error: String(error),
        }));
      }
    },
    [sessionId],
  );

  const promoteRunResult = useCallback(
    async (runId: string) => {
      const run = state.runs.find((candidate) => candidate.runId === runId);
      const receipt = run ? latestRunReceipt(run) : null;
      if (!run || !receipt || !receipt.success) {
        setState((current) => ({
          ...current,
          error:
            "A successful worker receipt is required before promoting the run result.",
        }));
        return;
      }

      await runAction(
        runId,
        "Run result promotion sent to the parent session.",
        async () => {
          await continueSessionTask(
            run.parentSessionId,
            buildPromotionPrompt({
              run,
              receipt,
              targetLabel: `run '${run.playbookLabel}'`,
            }),
          );
        },
      );
    },
    [runAction, state.runs],
  );

  const promoteStepResult = useCallback(
    async (runId: string, stepId: string) => {
      const run = state.runs.find((candidate) => candidate.runId === runId);
      const step = run?.steps.find((candidate) => candidate.stepId === stepId);
      const receipt = step ? latestStepReceipt(step) : null;
      if (!run || !step || !receipt || !receipt.success) {
        setState((current) => ({
          ...current,
          error:
            "A successful step receipt is required before promoting this worker result.",
        }));
        return;
      }

      await runAction(
        runId,
        `Step result promotion sent to the parent session for '${step.label}'.`,
        async () => {
          await continueSessionTask(
            run.parentSessionId,
            buildPromotionPrompt({
              run,
              receipt,
              targetLabel: `step '${step.label}'`,
            }),
          );
        },
      );
    },
    [runAction, state.runs],
  );

  return {
    ...state,
    refreshRuns,
    retryPlaybookRun,
    resumePlaybookRun,
    dismissPlaybookRun,
    messageWorkerSession,
    stopWorkerSession,
    promoteRunResult,
    promoteStepResult,
  };
}

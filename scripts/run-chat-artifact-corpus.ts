import path from "node:path";
import process from "node:process";

import {
  contractEvidenceRoot,
  corpusCases,
  evidenceRoot,
  liveEvidenceRoot,
} from "./chat-artifact-corpus/config";
import {
  buildHtmlDistinctnessCheck,
  buildRefinementPatchCheck,
  caseRetainsStyleSteering,
  summarizeCaseTotals,
} from "./chat-artifact-corpus/classification";
import { ensureCleanDirectory, writeJson } from "./chat-artifact-corpus/artifact-files";
import {
  buildRevisionFlow,
  executeCase,
  loadPersistedCaseSummaries,
  runLiveChatRuntimeLane,
} from "./chat-artifact-corpus/flows";
import type { CaseSummary, CorpusSummary } from "./chat-artifact-corpus/types";

function selectedCorpusCases() {
  const raw = process.env.CHAT_ARTIFACT_CORPUS_CASES?.trim();
  if (!raw) {
    return corpusCases;
  }

  const requestedIds = raw
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
  const requestedSet = new Set(requestedIds);
  const selected = corpusCases.filter((caseConfig) => requestedSet.has(caseConfig.id));
  const missing = requestedIds.filter(
    (caseId) => !selected.some((caseConfig) => caseConfig.id === caseId),
  );
  if (missing.length > 0) {
    throw new Error(`Unknown corpus case ids: ${missing.join(", ")}`);
  }
  return selected;
}

function selectedLanes() {
  const raw = process.env.CHAT_ARTIFACT_CORPUS_LANES?.trim().toLowerCase();
  if (!raw || raw === "both") {
    return { contract: true, live: true };
  }

  const lanes = new Set(
    raw
      .split(",")
      .map((value) => value.trim())
      .filter(Boolean),
  );
  const invalid = Array.from(lanes).filter(
    (lane) => lane !== "contract" && lane !== "live",
  );
  if (invalid.length > 0) {
    throw new Error(`Unknown corpus lane ids: ${invalid.join(", ")}`);
  }
  return {
    contract: lanes.has("contract"),
    live: lanes.has("live"),
  };
}

async function main() {
  const selectedCases = selectedCorpusCases();
  const lanes = selectedLanes();
  const partialRun =
    selectedCases.length !== corpusCases.length || !lanes.contract || !lanes.live;

  if (partialRun) {
    console.log(
      `ChatRuntime artifact corpus partial run: lanes=${lanes.contract && lanes.live ? "both" : lanes.contract ? "contract" : "live"}, cases=${selectedCases.map((caseConfig) => caseConfig.id).join(", ")}`,
    );
  } else {
    await ensureCleanDirectory(evidenceRoot);
    await ensureCleanDirectory(contractEvidenceRoot);
    await ensureCleanDirectory(liveEvidenceRoot);
  }

  const executedCases = await loadPersistedCaseSummaries(contractEvidenceRoot, corpusCases);
  if (lanes.contract) {
    for (const caseConfig of selectedCases) {
      console.log(`contract:${caseConfig.id}:start`);
      const startedAt = Date.now();
      const summary = await executeCase(caseConfig, executedCases);
      executedCases.set(caseConfig.id, summary);
      console.log(
        `contract:${caseConfig.id}:done:${((Date.now() - startedAt) / 1000).toFixed(1)}s:${summary.classification}`,
      );
    }
  }

  const revisionFlow = await buildRevisionFlow(executedCases);
  const htmlDistinctness = buildHtmlDistinctnessCheck(executedCases);
  const refinementPatchFlow = buildRefinementPatchCheck(executedCases);
  const targetedEditFlowCase = executedCases.get("html-dog-shampoo-targeted-chart");
  const styleSteeringCase = executedCases.get("html-dog-shampoo-enterprise");

  const caseSummaries = corpusCases
    .map((caseConfig) => executedCases.get(caseConfig.id))
    .filter((value): value is CaseSummary => Boolean(value));
  const contractTotals = summarizeCaseTotals(caseSummaries);
  const liveChatRuntime = await runLiveChatRuntimeLane({
    seedCases: await loadPersistedCaseSummaries(liveEvidenceRoot, corpusCases),
    selectedCases: lanes.live ? selectedCases : [],
  });
  const totals = summarizeCaseTotals([...caseSummaries, ...liveChatRuntime.cases]);

  const summary: CorpusSummary = {
    generatedAt: new Date().toISOString(),
    evidenceRoot,
    cases: caseSummaries,
    lanes: {
      contract: {
        evidenceRoot: contractEvidenceRoot,
        status:
          contractTotals.blocked > 0
            ? "blocked"
            : contractTotals.repairable > 0
              ? "repairable"
              : "pass",
      },
      liveChatRuntime,
    },
    parityChecks: {
      htmlDistinctness,
      refinementPatchFlow,
      targetedEditFlow: {
        caseId: "html-dog-shampoo-targeted-chart",
        passed:
          targetedEditFlowCase?.classification === "pass" &&
          (targetedEditFlowCase.editIntent?.selectedTargets.length ?? 0) > 0,
      },
      styleSteeringFlow: {
        caseId: "html-dog-shampoo-enterprise",
        passed:
          styleSteeringCase?.classification === "pass" &&
          caseRetainsStyleSteering(styleSteeringCase, ["enterprise"]),
      },
      revisionFlow,
      repeatedRunVariationFlow:
        liveChatRuntime.repeatedRunVariationFlow ?? {
          renderer: "svg",
          sourceCaseId: "svg-ai-tools-hero",
          prompt: "Create an SVG hero concept for an AI tools brand",
          runCount: 0,
          uniqueSignatureCount: 0,
          classification: "blocked",
          strongestContradiction:
            "Live summary did not record repeated-run variation evidence.",
          failingRunIds: [],
          runs: [],
        },
    },
    totals,
  };

  await writeJson(path.join(evidenceRoot, "corpus-summary.json"), summary);
  await writeJson(
    path.join(liveEvidenceRoot, "live-chat-artifact-summary.json"),
    liveChatRuntime,
  );

  const parityFailures = [
    summary.lanes.liveChatRuntime.status !== "pass",
    !summary.parityChecks.htmlDistinctness.allDistinct,
    !summary.parityChecks.refinementPatchFlow.allPatched,
    !summary.parityChecks.targetedEditFlow.passed,
    !summary.parityChecks.styleSteeringFlow.passed,
    summary.parityChecks.revisionFlow.compare.classification !== "pass",
    summary.parityChecks.revisionFlow.restore.classification !== "pass",
    summary.parityChecks.revisionFlow.branch.classification !== "pass",
    summary.parityChecks.repeatedRunVariationFlow.classification !== "pass",
  ].some(Boolean);

  if (!partialRun && (totals.repairable > 0 || totals.blocked > 0 || parityFailures)) {
    throw new Error(
      `Corpus contained failing cases: pass=${totals.pass}, repairable=${totals.repairable}, blocked=${totals.blocked}, liveChatRuntime=${summary.lanes.liveChatRuntime.status}`,
    );
  }

  console.log(
    `ChatRuntime artifact corpus complete: ${totals.pass} pass, ${totals.repairable} repairable, ${totals.blocked} blocked`,
  );
  console.log(`Evidence root: ${evidenceRoot}`);
  console.log(
    `Live ChatRuntime lane: ${summary.lanes.liveChatRuntime.status} (${summary.lanes.liveChatRuntime.strongestContradiction ?? "ok"})`,
  );
}

main().catch((error) => {
  console.error(error instanceof Error ? error.stack ?? error.message : String(error));
  process.exitCode = 1;
});

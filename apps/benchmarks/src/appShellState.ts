export type ShellSuiteSummary = {
  suite: string;
  focusCaseId: string | null;
};

export type ShellCaseRecord = {
  suite: string;
  caseId: string;
};

export function resolveScorecardPreviewEnabled(
  search: string | null | undefined,
): boolean {
  return new URLSearchParams(search ?? "").get("scorecardPreview") === "1";
}

export function resolveInitialTriageSelection(
  suiteSummaries: ShellSuiteSummary[],
  latestCases: ShellCaseRecord[],
  fallbackSuite = "MiniWoB++",
) {
  const focusSuite = suiteSummaries.find((suite) => suite.focusCaseId)?.suite ?? null;
  const headline = latestCases[0] ?? null;

  return {
    suite: focusSuite ?? headline?.suite ?? fallbackSuite,
    caseId: headline?.caseId ?? null,
  };
}

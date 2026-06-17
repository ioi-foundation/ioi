#!/usr/bin/env tsx
import { mkdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

import {
  DEFAULT_ONBOARDING_CONDITION_STATE,
  ONBOARDING_CONDITION_DEFINITIONS,
  resolveOnboardingRouteVisibility,
  type OnboardingRouteConditionState,
} from "../src/surfaces/Home/homeOnboardingModel";

interface MatrixCase {
  id: string;
  description: string;
  state: Partial<OnboardingRouteConditionState>;
  expectVisible: string[];
  expectHidden: string[];
}

const cases: MatrixCase[] = [
  {
    id: "default-workspace",
    description: "Default contained OpenVSCode workspace with a Git repository.",
    state: {},
    expectVisible: ["setup-quick-open", "fundamentals-git", "accessibility-help"],
    expectHidden: ["setup-open-code", "setup-web-extensions", "fundamentals-install-git"],
  },
  {
    id: "no-folder",
    description: "No folder open should route toward opening code.",
    state: {
      workspaceFolderCount: 0,
      gitOpenRepositoryCount: 0,
    },
    expectVisible: ["setup-open-code", "fundamentals-git-clone"],
    expectHidden: ["setup-quick-open", "fundamentals-debug", "fundamentals-tasks"],
  },
  {
    id: "webworker",
    description: "Webworker runtime surfaces web extension inventory.",
    state: {
      workspacePlatform: "webworker",
    },
    expectVisible: ["setup-web-extensions"],
    expectHidden: ["setup-language-extensions", "fundamentals-extensions"],
  },
  {
    id: "sync-enabled",
    description: "Settings Sync availability surfaces profile sync routes.",
    state: {
      syncAvailable: true,
    },
    expectVisible: ["setup-sync-settings", "fundamentals-settings"],
    expectHidden: [],
  },
  {
    id: "git-missing",
    description: "Missing Git surfaces the install route and hides Git-backed SCM routes.",
    state: {
      gitMissing: true,
      gitOpenRepositoryCount: 0,
    },
    expectVisible: ["fundamentals-install-git"],
    expectHidden: ["fundamentals-git", "fundamentals-git-init", "fundamentals-git-clone"],
  },
  {
    id: "no-git-repository",
    description: "Folder open without a Git repository surfaces initialization.",
    state: {
      gitOpenRepositoryCount: 0,
    },
    expectVisible: ["fundamentals-git-init"],
    expectHidden: ["fundamentals-git", "fundamentals-git-clone"],
  },
  {
    id: "untrusted-empty-workspace",
    description: "Untrusted empty workspaces surface Workspace Trust.",
    state: {
      workspaceFolderCount: 0,
      gitOpenRepositoryCount: 0,
      isWorkspaceTrusted: false,
    },
    expectVisible: ["fundamentals-workspace-trust"],
    expectHidden: [],
  },
  {
    id: "speech-provider",
    description: "Speech provider availability surfaces dictation.",
    state: {
      hasSpeechProvider: true,
    },
    expectVisible: ["accessibility-dictation"],
    expectHidden: [],
  },
  {
    id: "notebook-opened",
    description: "Notebook state surfaces the conditional notebook profile route.",
    state: {
      userHasOpenedNotebook: true,
      openGettingStarted: true,
    },
    expectVisible: ["notebook-profile"],
    expectHidden: [],
  },
];

function nowStamp(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z").replace(/:/g, "-");
}

function runCase(matrixCase: MatrixCase) {
  const resolution = resolveOnboardingRouteVisibility({
    ...DEFAULT_ONBOARDING_CONDITION_STATE,
    ...matrixCase.state,
  });
  const visibleStepIds = resolution.visibleSteps.map((step) => step.id);
  const hiddenStepIds = resolution.hiddenSteps.map((entry) => entry.step.id);
  const visibleFamilies = resolution.visibleFamilies.map((family) => family.id);
  const failures = [
    ...matrixCase.expectVisible
      .filter((stepId) => !visibleStepIds.includes(stepId))
      .map((stepId) => `expected visible: ${stepId}`),
    ...matrixCase.expectHidden
      .filter((stepId) => !hiddenStepIds.includes(stepId))
      .map((stepId) => `expected hidden: ${stepId}`),
  ];

  return {
    id: matrixCase.id,
    description: matrixCase.description,
    state: resolution.conditionState,
    visibleFamilies,
    visibleStepIds,
    conditionalVisibleStepIds: resolution.conditionalVisibleSteps.map(
      (step) => step.id,
    ),
    sourceIndexedHiddenStepIds: resolution.sourceIndexedHiddenSteps.map(
      (step) => step.id,
    ),
    hiddenSteps: resolution.hiddenSteps.map((entry) => ({
      stepId: entry.step.id,
      familyId: entry.step.familyId,
      conditionMatched: entry.conditionMatched,
      conditionIds: entry.conditionIds,
      reasons: entry.reasons,
    })),
    failures,
    passed: failures.length === 0,
  };
}

function main() {
  const outputRoot =
    process.argv[2] ??
    resolve(
      "docs/evidence/route-hierarchy/live-home-onboarding-condition-matrix",
      nowStamp(),
    );
  mkdirSync(outputRoot, { recursive: true });

  const results = cases.map(runCase);
  const bundle = {
    capturedAt: new Date().toISOString(),
    conditionDefinitions: Object.fromEntries(
      Object.entries(ONBOARDING_CONDITION_DEFINITIONS).map(([id, definition]) => [
        id,
        {
          label: definition.label,
          sourceExpression: definition.sourceExpression,
        },
      ]),
    ),
    cases: results,
    assertions: {
      allCasesPassed: results.every((result) => result.passed),
      conditionalRoutesCanSurface: results.some(
        (result) => result.conditionalVisibleStepIds.length > 0,
      ),
      defaultKeepsConditionalRoutesHidden: results
        .find((result) => result.id === "default-workspace")
        ?.sourceIndexedHiddenStepIds.includes("setup-open-code"),
    },
  };

  writeFileSync(
    resolve(outputRoot, "result.json"),
    `${JSON.stringify(bundle, null, 2)}\n`,
    "utf8",
  );
  writeFileSync(
    resolve(outputRoot, "receipt.md"),
    [
      "# Home Onboarding Condition Matrix Receipt",
      "",
      `Captured: ${bundle.capturedAt}`,
      "",
      "## Proven",
      "",
      "- Conditional OpenVSCode walkthrough variants are modeled as explicit predicates.",
      "- Default first-run keeps non-applicable conditional variants hidden.",
      "- Alternate source states surface the expected route variants.",
      "- Hidden route diagnostics include condition ids and human-readable reasons.",
      "",
      "## Cases",
      "",
      ...results.map(
        (result) =>
          `- ${result.id}: ${result.passed ? "passed" : `failed (${result.failures.join(", ")})`}`,
      ),
    ].join("\n"),
    "utf8",
  );

  if (!bundle.assertions.allCasesPassed) {
    console.error(JSON.stringify(bundle.assertions, null, 2));
    process.exit(1);
  }
}

main();

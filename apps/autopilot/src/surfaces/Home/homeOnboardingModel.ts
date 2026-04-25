import type { AutopilotThemeId } from "../../services/autopilotAppearance";

export type OnboardingFamilyId =
  | "setup-vscode-web"
  | "setup-vscode"
  | "learn-fundamentals"
  | "accessibility"
  | "notebooks";

export type OnboardingSourceVisibility =
  | "default-welcome"
  | "source-known-conditional"
  | "source-indexed-command-or-conditional";

export type OnboardingCaptureStatus =
  | "captured"
  | "source-known-needs-targeted-capture"
  | "source-indexed-not-default-visible";

export type OnboardingCompletionPredicate =
  | "appearance-selected"
  | "project-selected"
  | "context-reviewed"
  | "runtime-reviewed"
  | "policy-reviewed"
  | "palette-opened"
  | "workspace-opened"
  | "evidence-reviewed"
  | "accessibility-reviewed"
  | "manual";

export type OnboardingConditionId =
  | "always"
  | "isWeb"
  | "notWeb"
  | "webWorker"
  | "notWebWorker"
  | "syncAvailable"
  | "workspaceEmpty"
  | "workspacePresent"
  | "gitEnabled"
  | "gitMissing"
  | "gitAvailable"
  | "gitRepositoryOpen"
  | "gitRepositoryAbsent"
  | "scmViewInactive"
  | "terminalClosed"
  | "notCodespaces"
  | "workspaceUntrusted"
  | "accessibilityContext"
  | "speechProvider"
  | "openGettingStarted"
  | "notebookOpened";

export interface OnboardingRouteConditionState {
  isWeb: boolean;
  workspacePlatform: "desktop" | "webworker" | "node";
  syncAvailable: boolean;
  workspaceFolderCount: number;
  gitEnabled: boolean;
  gitMissing: boolean;
  gitOpenRepositoryCount: number;
  activeViewlet: string | null;
  terminalIsOpen: boolean;
  remoteName: string | null;
  isWorkspaceTrusted: boolean;
  accessibilityContext: boolean;
  hasSpeechProvider: boolean;
  openGettingStarted: boolean;
  userHasOpenedNotebook: boolean;
}

export interface OnboardingConditionDefinition {
  id: OnboardingConditionId;
  label: string;
  sourceExpression: string;
  predicate: (state: OnboardingRouteConditionState) => boolean;
}

export type OnboardingActionId =
  | "appearance.selectTheme"
  | "project.openWorkspace"
  | "context.openCapabilities"
  | "runtime.openSettings"
  | "policy.openPolicy"
  | "palette.open"
  | "workspace.open"
  | "evidence.openRuns"
  | "accessibility.openSettings"
  | "home.markDone"
  | "workbench.toggleMenuBar"
  | "extensions.openPopularWeb"
  | "extensions.openLanguage"
  | "settings.sync"
  | "quickOpen.open"
  | "workbench.openTerminal"
  | "workbench.openDebug"
  | "workbench.openGit"
  | "workbench.runTasks"
  | "workbench.openShortcuts"
  | "workbench.workspaceTrust"
  | "notebook.profile";

export type OnboardingMediaKind =
  | "theme-picker"
  | "single-image"
  | "empty-markdown"
  | "notebook-profile";

export interface OnboardingActionDefinition {
  id: OnboardingActionId;
  label: string;
  commandPaletteId: string;
  commandPaletteLabel: string;
  sourceCommand?: string;
}

export interface OnboardingSourceAction {
  index: number;
  label: string;
  command?: string;
}

export interface OnboardingSourceReference {
  familyId: OnboardingFamilyId;
  sourceFamilyId: string;
  familyTitle: string;
  pageTitle: string;
  stepId: string;
  stepTitle: string;
  nlsIndexes: number[];
  actionIndexes: number[];
  media: string[];
  condition: string;
  conditionIds: OnboardingConditionId[];
  captureStatus: OnboardingCaptureStatus;
}

export interface AutopilotOnboardingStep {
  id: string;
  familyId: OnboardingFamilyId;
  sourceStepId: string;
  title: string;
  body: string;
  source: OnboardingSourceReference;
  sourceActions: OnboardingSourceAction[];
  conditionIds: OnboardingConditionId[];
  targetRoute: string;
  completionPredicate: OnboardingCompletionPredicate;
  primaryAction: OnboardingActionDefinition;
  secondaryActions: OnboardingActionDefinition[];
  media: {
    kind: OnboardingMediaKind;
    assets: string[];
    alt: string;
  };
  fidelity: "exact-label" | "adapted-label" | "diagnostic-only";
  visibleInFirstRun: boolean;
}

export interface AutopilotOnboardingFamily {
  id: OnboardingFamilyId;
  sourceId: string;
  title: string;
  sourceTitle: string;
  pageTitle: string;
  summary: string;
  sourceTitleIndex: number;
  sourceSummaryIndex: number;
  sourceVisibility: OnboardingSourceVisibility;
  visibleInFirstRun: boolean;
  steps: AutopilotOnboardingStep[];
}

export interface HomeDashboardCard {
  id: string;
  title: string;
  detail: string;
  meta: string;
  actionLabel: string;
  actionId: OnboardingActionId;
}

export const HOME_ONBOARDING_FOCUS_EVENT = "autopilot-home-onboarding-focus";

export const DEFAULT_ONBOARDING_CONDITION_STATE: OnboardingRouteConditionState = {
  isWeb: true,
  workspacePlatform: "node",
  syncAvailable: false,
  workspaceFolderCount: 1,
  gitEnabled: true,
  gitMissing: false,
  gitOpenRepositoryCount: 1,
  activeViewlet: null,
  terminalIsOpen: false,
  remoteName: null,
  isWorkspaceTrusted: true,
  accessibilityContext: true,
  hasSpeechProvider: false,
  openGettingStarted: true,
  userHasOpenedNotebook: false,
};

export const ONBOARDING_CONDITION_DEFINITIONS: Record<
  OnboardingConditionId,
  OnboardingConditionDefinition
> = {
  always: {
    id: "always",
    label: "Always",
    sourceExpression: "always",
    predicate: () => true,
  },
  isWeb: {
    id: "isWeb",
    label: "Web workbench",
    sourceExpression: "isWeb",
    predicate: (state) => state.isWeb,
  },
  notWeb: {
    id: "notWeb",
    label: "Desktop workbench",
    sourceExpression: "!isWeb",
    predicate: (state) => !state.isWeb,
  },
  webWorker: {
    id: "webWorker",
    label: "Web worker workspace",
    sourceExpression: "workspacePlatform == 'webworker'",
    predicate: (state) => state.workspacePlatform === "webworker",
  },
  notWebWorker: {
    id: "notWebWorker",
    label: "Non-web-worker workspace",
    sourceExpression: "workspacePlatform != 'webworker'",
    predicate: (state) => state.workspacePlatform !== "webworker",
  },
  syncAvailable: {
    id: "syncAvailable",
    label: "Settings Sync available",
    sourceExpression: "syncStatus != uninitialized",
    predicate: (state) => state.syncAvailable,
  },
  workspaceEmpty: {
    id: "workspaceEmpty",
    label: "No workspace folder",
    sourceExpression: "workspaceFolderCount == 0",
    predicate: (state) => state.workspaceFolderCount === 0,
  },
  workspacePresent: {
    id: "workspacePresent",
    label: "Workspace folder open",
    sourceExpression: "workspaceFolderCount != 0",
    predicate: (state) => state.workspaceFolderCount !== 0,
  },
  gitEnabled: {
    id: "gitEnabled",
    label: "Git enabled",
    sourceExpression: "config.git.enabled",
    predicate: (state) => state.gitEnabled,
  },
  gitMissing: {
    id: "gitMissing",
    label: "Git missing",
    sourceExpression: "git.missing",
    predicate: (state) => state.gitMissing,
  },
  gitAvailable: {
    id: "gitAvailable",
    label: "Git available",
    sourceExpression: "!git.missing",
    predicate: (state) => !state.gitMissing,
  },
  gitRepositoryOpen: {
    id: "gitRepositoryOpen",
    label: "Git repository open",
    sourceExpression: "gitOpenRepositoryCount != 0",
    predicate: (state) => state.gitOpenRepositoryCount !== 0,
  },
  gitRepositoryAbsent: {
    id: "gitRepositoryAbsent",
    label: "No Git repository open",
    sourceExpression: "gitOpenRepositoryCount == 0",
    predicate: (state) => state.gitOpenRepositoryCount === 0,
  },
  scmViewInactive: {
    id: "scmViewInactive",
    label: "Source Control view inactive",
    sourceExpression: "activeViewlet != 'workbench.view.scm'",
    predicate: (state) => state.activeViewlet !== "workbench.view.scm",
  },
  terminalClosed: {
    id: "terminalClosed",
    label: "Terminal closed",
    sourceExpression: "!terminalIsOpen",
    predicate: (state) => !state.terminalIsOpen,
  },
  notCodespaces: {
    id: "notCodespaces",
    label: "Not Codespaces",
    sourceExpression: "remoteName != codespaces",
    predicate: (state) => state.remoteName !== "codespaces",
  },
  workspaceUntrusted: {
    id: "workspaceUntrusted",
    label: "Workspace untrusted",
    sourceExpression: "!isWorkspaceTrusted",
    predicate: (state) => !state.isWorkspaceTrusted,
  },
  accessibilityContext: {
    id: "accessibilityContext",
    label: "Accessibility walkthrough context",
    sourceExpression: "accessibility context",
    predicate: (state) => state.accessibilityContext,
  },
  speechProvider: {
    id: "speechProvider",
    label: "Speech provider available",
    sourceExpression: "hasSpeechProvider",
    predicate: (state) => state.hasSpeechProvider,
  },
  openGettingStarted: {
    id: "openGettingStarted",
    label: "Getting Started enabled",
    sourceExpression: "config.openGettingStarted",
    predicate: (state) => state.openGettingStarted,
  },
  notebookOpened: {
    id: "notebookOpened",
    label: "Notebook opened",
    sourceExpression: "userHasOpenedNotebook",
    predicate: (state) => state.userHasOpenedNotebook,
  },
};

function conditionIdsForSourceExpression(
  condition: string,
): OnboardingConditionId[] {
  const ids = new Set<OnboardingConditionId>();
  const expression = condition.trim();
  if (!expression || expression === "always") {
    ids.add("always");
  }
  if (expression.includes("!isWeb")) {
    ids.add("notWeb");
  } else if (expression.includes("isWeb")) {
    ids.add("isWeb");
  }
  if (expression.includes("workspacePlatform == 'webworker'")) {
    ids.add("webWorker");
  }
  if (expression.includes("workspacePlatform != 'webworker'")) {
    ids.add("notWebWorker");
  }
  if (expression.includes("syncStatus != uninitialized")) {
    ids.add("syncAvailable");
  }
  if (expression.includes("workspaceFolderCount == 0")) {
    ids.add("workspaceEmpty");
  }
  if (expression.includes("workspaceFolderCount != 0")) {
    ids.add("workspacePresent");
  }
  if (expression.includes("config.git.enabled")) {
    ids.add("gitEnabled");
  }
  if (expression.includes("!git.missing")) {
    ids.add("gitAvailable");
  } else if (expression.includes("git.missing")) {
    ids.add("gitMissing");
  }
  if (expression.includes("gitOpenRepositoryCount == 0")) {
    ids.add("gitRepositoryAbsent");
  }
  if (expression.includes("gitOpenRepositoryCount != 0")) {
    ids.add("gitRepositoryOpen");
  }
  if (expression.includes("activeViewlet != 'workbench.view.scm'")) {
    ids.add("scmViewInactive");
  }
  if (expression.includes("!terminalIsOpen")) {
    ids.add("terminalClosed");
  }
  if (expression.includes("remoteName != codespaces")) {
    ids.add("notCodespaces");
  }
  if (expression.includes("!isWorkspaceTrusted")) {
    ids.add("workspaceUntrusted");
  }
  if (expression.includes("accessibility context")) {
    ids.add("accessibilityContext");
  }
  if (expression.includes("hasSpeechProvider")) {
    ids.add("speechProvider");
  }
  if (expression.includes("config.openGettingStarted")) {
    ids.add("openGettingStarted");
  }
  if (expression.includes("userHasOpenedNotebook")) {
    ids.add("notebookOpened");
  }
  return ids.size > 0 ? [...ids] : ["always"];
}

function action(
  id: OnboardingActionId,
  label: string,
  commandPaletteId: string,
  commandPaletteLabel: string,
  sourceCommand?: string,
): OnboardingActionDefinition {
  return { id, label, commandPaletteId, commandPaletteLabel, sourceCommand };
}

function sourceAction(
  index: number,
  label: string,
  command?: string,
): OnboardingSourceAction {
  return { index, label, command };
}

interface FamilySeed {
  id: OnboardingFamilyId;
  sourceId: string;
  title: string;
  sourceTitle: string;
  pageTitle: string;
  summary: string;
  titleIndex: number;
  summaryIndex: number;
  visibility: OnboardingSourceVisibility;
  visibleInFirstRun: boolean;
}

const FAMILY_SEEDS: Record<OnboardingFamilyId, FamilySeed> = {
  "setup-vscode-web": {
    id: "setup-vscode-web",
    sourceId: "SetupWeb",
    title: "Get Started with Autopilot",
    sourceTitle: "Get Started with VS Code for the Web",
    pageTitle: "Setup VS Code Web",
    summary:
      "Customize the shell, bind your codebase, learn the runtime paths, and start working inside the contained OpenVSCode workbench.",
    titleIndex: 15264,
    summaryIndex: 15265,
    visibility: "default-welcome",
    visibleInFirstRun: true,
  },
  "setup-vscode": {
    id: "setup-vscode",
    sourceId: "Setup",
    title: "Setup VS Code",
    sourceTitle: "Get started with VS Code",
    pageTitle: "Setup VS Code",
    summary: "Non-web setup source inventory retained for parity tracking.",
    titleIndex: 15255,
    summaryIndex: 15256,
    visibility: "source-known-conditional",
    visibleInFirstRun: false,
  },
  "learn-fundamentals": {
    id: "learn-fundamentals",
    sourceId: "Beginner",
    title: "Learn the Fundamentals",
    sourceTitle: "Learn the Fundamentals",
    pageTitle: "Essential Features",
    summary: "Get an overview of the most essential features.",
    titleIndex: 15336,
    summaryIndex: 15337,
    visibility: "default-welcome",
    visibleInFirstRun: true,
  },
  accessibility: {
    id: "accessibility",
    sourceId: "SetupAccessibility",
    title: "Get Started with Accessibility Features",
    sourceTitle: "Get Started with Accessibility Features",
    pageTitle: "Setup VS Code Accessibility",
    summary:
      "Learn the tools and shortcuts that make the workbench accessible.",
    titleIndex: 15292,
    summaryIndex: 15293,
    visibility: "source-indexed-command-or-conditional",
    visibleInFirstRun: true,
  },
  notebooks: {
    id: "notebooks",
    sourceId: "notebooks",
    title: "Customize Notebooks",
    sourceTitle: "Customize Notebooks",
    pageTitle: "Notebooks",
    summary: "Conditional notebook source inventory retained for future routing.",
    titleIndex: 15373,
    summaryIndex: 15376,
    visibility: "source-known-conditional",
    visibleInFirstRun: false,
  },
};

interface StepSeed {
  id: string;
  familyId: OnboardingFamilyId;
  sourceStepId: string;
  title: string;
  body: string;
  nlsIndexes: number[];
  sourceActions: OnboardingSourceAction[];
  media: AutopilotOnboardingStep["media"];
  condition: string;
  captureStatus: OnboardingCaptureStatus;
  targetRoute: string;
  completionPredicate: OnboardingCompletionPredicate;
  primaryAction: OnboardingActionDefinition;
  secondaryActions?: OnboardingActionDefinition[];
  fidelity?: AutopilotOnboardingStep["fidelity"];
  visibleInFirstRun?: boolean;
}

function makeStep(seed: StepSeed): AutopilotOnboardingStep {
  const family = FAMILY_SEEDS[seed.familyId];
  const conditionIds = conditionIdsForSourceExpression(seed.condition);
  return {
    id: seed.id,
    familyId: seed.familyId,
    sourceStepId: seed.sourceStepId,
    title: seed.title,
    body: seed.body,
    sourceActions: seed.sourceActions,
    source: {
      familyId: seed.familyId,
      sourceFamilyId: family.sourceId,
      familyTitle: family.sourceTitle,
      pageTitle: family.pageTitle,
      stepId: seed.sourceStepId,
      stepTitle: seed.title,
      nlsIndexes: seed.nlsIndexes,
      actionIndexes: seed.sourceActions.map((item) => item.index),
      media: seed.media.assets,
      condition: seed.condition,
      conditionIds,
      captureStatus: seed.captureStatus,
    },
    conditionIds,
    targetRoute: seed.targetRoute,
    completionPredicate: seed.completionPredicate,
    primaryAction: seed.primaryAction,
    secondaryActions: seed.secondaryActions ?? [],
    media: seed.media,
    fidelity: seed.fidelity ?? "exact-label",
    visibleInFirstRun: seed.visibleInFirstRun ?? family.visibleInFirstRun,
  };
}

const setupWebSteps: AutopilotOnboardingStep[] = [
  makeStep({
    id: "setup-theme",
    familyId: "setup-vscode-web",
    sourceStepId: "pickColorThemeWeb",
    title: "Choose your theme",
    body:
      "The right theme helps you focus on your code, is easy on your eyes, and is simply more fun to use.",
    nlsIndexes: [15267, 15268],
    sourceActions: [
      sourceAction(15269, "Browse Color Themes", "workbench.action.selectTheme"),
    ],
    media: {
      kind: "theme-picker",
      assets: ["dark.png", "light.png", "dark-hc.png", "light-hc.png"],
      alt: "OpenVSCode theme choices",
    },
    condition: "always",
    captureStatus: "captured",
    targetRoute: "Autopilot appearance settings + OpenVSCode colorTheme",
    completionPredicate: "appearance-selected",
    primaryAction: action(
      "appearance.selectTheme",
      "Browse Color Themes",
      "autopilot.onboarding.appearance",
      "Home: Choose Autopilot Theme",
      "workbench.action.selectTheme",
    ),
  }),
  makeStep({
    id: "setup-ui-density",
    familyId: "setup-vscode-web",
    sourceStepId: "menuBarWeb",
    title: "Just the right amount of UI",
    body:
      "The full menu bar is available in the dropdown menu to make room for your code. Toggle its appearance for faster access.",
    nlsIndexes: [15270, 15271],
    sourceActions: [
      sourceAction(15272, "Toggle Menu Bar", "workbench.action.toggleMenuBar"),
    ],
    media: {
      kind: "single-image",
      assets: ["menuBar.svg"],
      alt: "Comparing menu dropdown with the visible menu bar",
    },
    condition: "isWeb",
    captureStatus: "captured",
    targetRoute: "Autopilot shell density and workbench menu preference",
    completionPredicate: "manual",
    primaryAction: action(
      "workbench.toggleMenuBar",
      "Toggle Menu Bar",
      "autopilot.onboarding.toggleMenuBar",
      "Home: Toggle Menu Bar",
      "workbench.action.toggleMenuBar",
    ),
  }),
  makeStep({
    id: "setup-web-extensions",
    familyId: "setup-vscode-web",
    sourceStepId: "extensionsWebWeb",
    title: "Code with extensions",
    body:
      "Extensions are VS Code's power-ups. A growing number are becoming available in the web.",
    nlsIndexes: [15273, 15274],
    sourceActions: [
      sourceAction(
        15275,
        "Browse Popular Web Extensions",
        "workbench.extensions.action.showPopularExtensions",
      ),
    ],
    media: {
      kind: "single-image",
      assets: ["extensions-web.svg"],
      alt: "VS Code extension marketplace with featured language extensions",
    },
    condition: "workspacePlatform == 'webworker'",
    captureStatus: "source-known-needs-targeted-capture",
    targetRoute: "Contained OpenVSCode extensions view",
    completionPredicate: "workspace-opened",
    primaryAction: action(
      "extensions.openPopularWeb",
      "Browse Popular Web Extensions",
      "autopilot.onboarding.extensions.web",
      "Home: Browse Web Extensions",
      "workbench.extensions.action.showPopularExtensions",
    ),
    visibleInFirstRun: false,
  }),
  makeStep({
    id: "setup-language-extensions",
    familyId: "setup-vscode-web",
    sourceStepId: "findLanguageExtensionsWeb",
    title: "Rich support for all your languages",
    body:
      "Code smarter with syntax highlighting, inline suggestions, linting and debugging. While many languages are built-in, many more can be added as extensions.",
    nlsIndexes: [15276, 15277],
    sourceActions: [
      sourceAction(
        15278,
        "Browse Language Extensions",
        "workbench.extensions.action.showLanguageExtensions",
      ),
    ],
    media: {
      kind: "single-image",
      assets: ["languages.svg"],
      alt: "Language extensions",
    },
    condition: "workspacePlatform != 'webworker'",
    captureStatus: "captured",
    targetRoute: "Contained OpenVSCode language extensions view",
    completionPredicate: "workspace-opened",
    primaryAction: action(
      "extensions.openLanguage",
      "Browse Language Extensions",
      "autopilot.onboarding.extensions.language",
      "Home: Browse Language Extensions",
      "workbench.extensions.action.showLanguageExtensions",
    ),
  }),
  makeStep({
    id: "setup-sync-settings",
    familyId: "setup-vscode-web",
    sourceStepId: "settingsSyncWeb",
    title: "Sync settings across devices",
    body:
      "Keep your essential customizations backed up and updated across all your devices.",
    nlsIndexes: [15279, 15280],
    sourceActions: [
      sourceAction(
        15281,
        "Backup and Sync Settings",
        "workbench.userDataSync.actions.turnOn",
      ),
    ],
    media: {
      kind: "single-image",
      assets: ["settingsSync.svg"],
      alt: "Turn on Sync entry in the settings gear menu",
    },
    condition: "syncStatus != uninitialized",
    captureStatus: "source-known-needs-targeted-capture",
    targetRoute: "Autopilot profile settings and OpenVSCode sync posture",
    completionPredicate: "manual",
    primaryAction: action(
      "settings.sync",
      "Backup and Sync Settings",
      "autopilot.onboarding.settingsSync",
      "Home: Open Profile Sync Settings",
      "workbench.userDataSync.actions.turnOn",
    ),
    visibleInFirstRun: false,
  }),
  makeStep({
    id: "setup-command-palette",
    familyId: "setup-vscode-web",
    sourceStepId: "commandPaletteTaskWeb",
    title: "Unlock productivity with the Command Palette",
    body:
      "Run commands without reaching for your mouse to accomplish any task in VS Code.",
    nlsIndexes: [15282, 15283],
    sourceActions: [
      sourceAction(15284, "Open Command Palette", "workbench.action.showCommands"),
    ],
    media: {
      kind: "single-image",
      assets: ["commandPalette.svg"],
      alt: "Command Palette overlay for searching and executing commands",
    },
    condition: "always",
    captureStatus: "captured",
    targetRoute: "Autopilot Command Palette",
    completionPredicate: "palette-opened",
    primaryAction: action(
      "palette.open",
      "Open Command Palette",
      "autopilot.onboarding.palette",
      "Home: Open Command Palette",
      "workbench.action.showCommands",
    ),
  }),
  makeStep({
    id: "setup-open-code",
    familyId: "setup-vscode-web",
    sourceStepId: "pickAFolderTask-WebWeb",
    title: "Open up your code",
    body:
      "You're all set to start coding. You can open a local project or a remote repository to get your files into VS Code.",
    nlsIndexes: [15285, 15286],
    sourceActions: [
      sourceAction(15287, "Open Folder", "workbench.action.addRootFolder"),
      sourceAction(15288, "Open Repository", "remoteHub.openRepository"),
    ],
    media: {
      kind: "single-image",
      assets: ["openFolder.svg"],
      alt: "Explorer view showing buttons for opening folder and cloning repository",
    },
    condition: "workspaceFolderCount == 0",
    captureStatus: "source-known-needs-targeted-capture",
    targetRoute: "Autopilot project selection and contained direct Workspace",
    completionPredicate: "project-selected",
    primaryAction: action(
      "project.openWorkspace",
      "Open Folder",
      "autopilot.onboarding.openWorkspace",
      "Home: Open Workspace",
      "workbench.action.addRootFolder",
    ),
    secondaryActions: [
      action(
        "project.openWorkspace",
        "Open Repository",
        "autopilot.onboarding.openRepository",
        "Home: Open Repository",
        "remoteHub.openRepository",
      ),
    ],
    visibleInFirstRun: false,
  }),
  makeStep({
    id: "setup-quick-open",
    familyId: "setup-vscode-web",
    sourceStepId: "quickOpenWeb",
    title: "Quickly navigate between your files",
    body:
      "Navigate between files in an instant with one keystroke. Tip: Open multiple files by pressing the right arrow key.",
    nlsIndexes: [15289, 15290],
    sourceActions: [
      sourceAction(15291, "Quick Open a File", "toSide:workbench.action.quickOpen"),
    ],
    media: {
      kind: "single-image",
      assets: ["search.svg"],
      alt: "Go to file in quick search",
    },
    condition: "workspaceFolderCount != 0",
    captureStatus: "captured",
    targetRoute: "Contained OpenVSCode quick open",
    completionPredicate: "workspace-opened",
    primaryAction: action(
      "quickOpen.open",
      "Quick Open a File",
      "autopilot.onboarding.quickOpen",
      "Home: Quick Open A File",
      "toSide:workbench.action.quickOpen",
    ),
  }),
];

const setupDesktopSteps: AutopilotOnboardingStep[] = [
  makeStep({
    id: "setup-desktop-theme",
    familyId: "setup-vscode",
    sourceStepId: "pickColorTheme",
    title: "Choose your theme",
    body:
      "The right theme helps you focus on your code, is easy on your eyes, and is simply more fun to use.",
    nlsIndexes: [15258, 15259],
    sourceActions: [
      sourceAction(15260, "Browse Color Themes", "workbench.action.selectTheme"),
    ],
    media: {
      kind: "theme-picker",
      assets: ["dark.png", "light.png", "dark-hc.png", "light-hc.png"],
      alt: "OpenVSCode theme choices",
    },
    condition: "!isWeb",
    captureStatus: "source-indexed-not-default-visible",
    targetRoute: "Secondary source inventory only",
    completionPredicate: "appearance-selected",
    primaryAction: action(
      "appearance.selectTheme",
      "Browse Color Themes",
      "autopilot.onboarding.desktopTheme",
      "Home: Choose Theme From Desktop Source",
      "workbench.action.selectTheme",
    ),
    visibleInFirstRun: false,
  }),
  makeStep({
    id: "setup-video-tutorial",
    familyId: "setup-vscode",
    sourceStepId: "videoTutorial",
    title: "Watch video tutorials",
    body:
      "Watch the first in a series of short and practical video tutorials for VS Code's key features.",
    nlsIndexes: [15261, 15262],
    sourceActions: [sourceAction(15263, "Watch Tutorial", "https://aka.ms/vscode-getting-started-video")],
    media: {
      kind: "single-image",
      assets: ["learn.svg"],
      alt: "VS Code tutorials",
    },
    condition: "!isWeb",
    captureStatus: "source-indexed-not-default-visible",
    targetRoute: "Source inventory only",
    completionPredicate: "manual",
    primaryAction: action(
      "home.markDone",
      "Watch Tutorial",
      "autopilot.onboarding.videoTutorial",
      "Home: Watch Tutorial",
    ),
    visibleInFirstRun: false,
  }),
];

const fundamentalsSteps: AutopilotOnboardingStep[] = [
  makeStep({
    id: "fundamentals-settings",
    familyId: "learn-fundamentals",
    sourceStepId: "settingsAndSync",
    title: "Tune your settings",
    body:
      "Customize every aspect of VS Code and sync customizations across devices.",
    nlsIndexes: [15339, 15340],
    sourceActions: [
      sourceAction(15341, "Open Settings", "toSide:workbench.action.openSettings"),
    ],
    media: {
      kind: "single-image",
      assets: ["settings.svg"],
      alt: "VS Code Settings",
    },
    condition: "workspacePlatform != 'webworker' && syncStatus != uninitialized",
    captureStatus: "source-known-needs-targeted-capture",
    targetRoute: "Autopilot settings and contained OpenVSCode settings",
    completionPredicate: "manual",
    primaryAction: action(
      "runtime.openSettings",
      "Open Settings",
      "autopilot.onboarding.settings",
      "Home: Open Settings",
      "toSide:workbench.action.openSettings",
    ),
    visibleInFirstRun: false,
  }),
  makeStep({
    id: "fundamentals-extensions",
    familyId: "learn-fundamentals",
    sourceStepId: "extensions",
    title: "Code with extensions",
    body:
      "Extensions are VS Code's power-ups. They range from handy productivity hacks, expanding out-of-the-box features, to adding completely new capabilities.",
    nlsIndexes: [15342, 15343],
    sourceActions: [
      sourceAction(
        15344,
        "Browse Popular Extensions",
        "workbench.extensions.action.showPopularExtensions",
      ),
    ],
    media: {
      kind: "single-image",
      assets: ["extensions.svg"],
      alt: "VS Code extension marketplace with featured language extensions",
    },
    condition: "workspacePlatform != 'webworker'",
    captureStatus: "captured",
    targetRoute: "Contained OpenVSCode extensions view",
    completionPredicate: "workspace-opened",
    primaryAction: action(
      "extensions.openPopularWeb",
      "Browse Popular Extensions",
      "autopilot.onboarding.extensions",
      "Home: Browse Extensions",
      "workbench.extensions.action.showPopularExtensions",
    ),
  }),
  makeStep({
    id: "fundamentals-terminal",
    familyId: "learn-fundamentals",
    sourceStepId: "terminal",
    title: "Built-in terminal",
    body:
      "Quickly run shell commands and monitor build output, right next to your code.",
    nlsIndexes: [15345, 15346],
    sourceActions: [
      sourceAction(15347, "Open Terminal", "workbench.action.terminal.toggleTerminal"),
    ],
    media: {
      kind: "single-image",
      assets: ["terminal.svg"],
      alt: "Integrated terminal running commands",
    },
    condition: "workspacePlatform != 'webworker' && remoteName != codespaces && !terminalIsOpen",
    captureStatus: "captured",
    targetRoute: "Contained OpenVSCode terminal",
    completionPredicate: "workspace-opened",
    primaryAction: action(
      "workbench.openTerminal",
      "Open Terminal",
      "autopilot.onboarding.terminal",
      "Home: Open Terminal",
      "workbench.action.terminal.toggleTerminal",
    ),
  }),
  makeStep({
    id: "fundamentals-debug",
    familyId: "learn-fundamentals",
    sourceStepId: "debugging",
    title: "Watch your code in action",
    body:
      "Accelerate your edit, build, test, and debug loop by setting up a launch configuration.",
    nlsIndexes: [15348, 15349],
    sourceActions: [
      sourceAction(15350, "Run your Project", "workbench.action.debug.selectandstart"),
    ],
    media: {
      kind: "single-image",
      assets: ["debug.svg"],
      alt: "Run and debug view",
    },
    condition: "workspacePlatform != 'webworker' && workspaceFolderCount != 0",
    captureStatus: "captured",
    targetRoute: "Contained OpenVSCode run/debug view",
    completionPredicate: "workspace-opened",
    primaryAction: action(
      "workbench.openDebug",
      "Run your Project",
      "autopilot.onboarding.debug",
      "Home: Run Project",
      "workbench.action.debug.selectandstart",
    ),
  }),
  makeStep({
    id: "fundamentals-git-clone",
    familyId: "learn-fundamentals",
    sourceStepId: "scmClone",
    title: "Track your code with Git",
    body:
      "Set up the built-in version control for your project to track your changes and collaborate with others.",
    nlsIndexes: [15351, 15352],
    sourceActions: [sourceAction(15353, "Clone Repository", "git.clone")],
    media: {
      kind: "single-image",
      assets: ["git.svg"],
      alt: "Source Control view",
    },
    condition: "config.git.enabled && !git.missing && workspaceFolderCount == 0",
    captureStatus: "source-known-needs-targeted-capture",
    targetRoute: "Contained OpenVSCode source control",
    completionPredicate: "workspace-opened",
    primaryAction: action(
      "workbench.openGit",
      "Clone Repository",
      "autopilot.onboarding.git.clone",
      "Home: Clone Repository",
      "git.clone",
    ),
    visibleInFirstRun: false,
  }),
  makeStep({
    id: "fundamentals-git-init",
    familyId: "learn-fundamentals",
    sourceStepId: "scmSetup",
    title: "Track your code with Git",
    body:
      "Set up the built-in version control for your project to track your changes and collaborate with others.",
    nlsIndexes: [15354, 15355],
    sourceActions: [sourceAction(15356, "Initialize Git Repository", "git.init")],
    media: {
      kind: "single-image",
      assets: ["git.svg"],
      alt: "Source Control view",
    },
    condition:
      "config.git.enabled && !git.missing && workspaceFolderCount != 0 && gitOpenRepositoryCount == 0",
    captureStatus: "source-known-needs-targeted-capture",
    targetRoute: "Contained OpenVSCode source control",
    completionPredicate: "workspace-opened",
    primaryAction: action(
      "workbench.openGit",
      "Initialize Git Repository",
      "autopilot.onboarding.git.init",
      "Home: Initialize Git Repository",
      "git.init",
    ),
    visibleInFirstRun: false,
  }),
  makeStep({
    id: "fundamentals-git",
    familyId: "learn-fundamentals",
    sourceStepId: "scm",
    title: "Track your code with Git",
    body:
      "No more looking up Git commands! Git and GitHub workflows are seamlessly integrated.",
    nlsIndexes: [15357, 15358],
    sourceActions: [
      sourceAction(15359, "Open Source Control", "workbench.view.scm"),
    ],
    media: {
      kind: "single-image",
      assets: ["git.svg"],
      alt: "Source Control view",
    },
    condition:
      "config.git.enabled && !git.missing && workspaceFolderCount != 0 && gitOpenRepositoryCount != 0 && activeViewlet != 'workbench.view.scm'",
    captureStatus: "captured",
    targetRoute: "Contained OpenVSCode source control",
    completionPredicate: "workspace-opened",
    primaryAction: action(
      "workbench.openGit",
      "Open Source Control",
      "autopilot.onboarding.git",
      "Home: Open Source Control",
      "workbench.view.scm",
    ),
  }),
  makeStep({
    id: "fundamentals-install-git",
    familyId: "learn-fundamentals",
    sourceStepId: "installGit",
    title: "Install Git",
    body: "Install Git to track changes in your projects.",
    nlsIndexes: [15360, 15361],
    sourceActions: [sourceAction(15362, "Install Git", "https://aka.ms/vscode-install-git")],
    media: {
      kind: "single-image",
      assets: ["git.svg"],
      alt: "Install Git",
    },
    condition: "git.missing",
    captureStatus: "source-known-needs-targeted-capture",
    targetRoute: "Source-known Git missing variant",
    completionPredicate: "manual",
    primaryAction: action(
      "workbench.openGit",
      "Install Git",
      "autopilot.onboarding.git.install",
      "Home: Install Git",
    ),
    visibleInFirstRun: false,
  }),
  makeStep({
    id: "fundamentals-tasks",
    familyId: "learn-fundamentals",
    sourceStepId: "tasks",
    title: "Automate your project tasks",
    body:
      "Create tasks for your common workflows and enjoy the integrated experience of running scripts and automatically checking results.",
    nlsIndexes: [15363, 15364],
    sourceActions: [
      sourceAction(15365, "Run Auto-detected Tasks", "workbench.action.tasks.runTask"),
    ],
    media: {
      kind: "single-image",
      assets: ["runTask.svg"],
      alt: "Task runner",
    },
    condition: "workspaceFolderCount != 0 && workspacePlatform != 'webworker'",
    captureStatus: "captured",
    targetRoute: "IOI runs and contained OpenVSCode tasks",
    completionPredicate: "evidence-reviewed",
    primaryAction: action(
      "workbench.runTasks",
      "Run Auto-detected Tasks",
      "autopilot.onboarding.tasks",
      "Home: Run Tasks",
      "workbench.action.tasks.runTask",
    ),
  }),
  makeStep({
    id: "fundamentals-shortcuts",
    familyId: "learn-fundamentals",
    sourceStepId: "shortcuts",
    title: "Customize your shortcuts",
    body:
      "Once you have discovered your favorite commands, create custom keyboard shortcuts for instant access.",
    nlsIndexes: [15366, 15367],
    sourceActions: [
      sourceAction(
        15368,
        "Keyboard Shortcuts",
        "toSide:workbench.action.openGlobalKeybindings",
      ),
    ],
    media: {
      kind: "single-image",
      assets: ["shortcuts.svg"],
      alt: "Interactive shortcuts",
    },
    condition: "always",
    captureStatus: "captured",
    targetRoute: "Autopilot accessibility and OpenVSCode keybindings",
    completionPredicate: "accessibility-reviewed",
    primaryAction: action(
      "workbench.openShortcuts",
      "Keyboard Shortcuts",
      "autopilot.onboarding.shortcuts",
      "Home: Open Keyboard Shortcuts",
      "toSide:workbench.action.openGlobalKeybindings",
    ),
  }),
  makeStep({
    id: "fundamentals-workspace-trust",
    familyId: "learn-fundamentals",
    sourceStepId: "workspaceTrust",
    title: "Safely browse and edit code",
    body:
      "Workspace Trust lets you decide whether your project folders should allow or restrict automatic code execution.",
    nlsIndexes: [15369, 15370],
    sourceActions: [
      sourceAction(15371, "Workspace Trust", "https://code.visualstudio.com/docs/editor/workspace-trust"),
      sourceAction(15372, "enable trust", "toSide:workbench.trust.manage"),
    ],
    media: {
      kind: "single-image",
      assets: ["workspaceTrust.svg"],
      alt: "Workspace Trust editor in Restricted mode",
    },
    condition: "workspacePlatform != 'webworker' && !isWorkspaceTrusted && workspaceFolderCount == 0",
    captureStatus: "source-known-needs-targeted-capture",
    targetRoute: "Autopilot policy boundaries and OpenVSCode Workspace Trust",
    completionPredicate: "policy-reviewed",
    primaryAction: action(
      "workbench.workspaceTrust",
      "Workspace Trust",
      "autopilot.onboarding.workspaceTrust",
      "Home: Workspace Trust",
      "toSide:workbench.trust.manage",
    ),
    visibleInFirstRun: false,
  }),
];

const accessibilitySteps: AutopilotOnboardingStep[] = [
  makeStep({
    id: "accessibility-help",
    familyId: "accessibility",
    sourceStepId: "accessibilityHelp",
    title: "Use the accessibility help dialog to learn about features",
    body:
      "The accessibility help dialog provides information about what to expect from a feature and the commands or keybindings to operate them.",
    nlsIndexes: [15295, 15296],
    sourceActions: [
      sourceAction(15297, "Open Accessibility Help", "editor.action.accessibilityHelp"),
    ],
    media: {
      kind: "empty-markdown",
      assets: [],
      alt: "Accessibility help commands",
    },
    condition: "accessibility context",
    captureStatus: "source-indexed-not-default-visible",
    targetRoute: "Autopilot accessibility diagnostics and OpenVSCode help",
    completionPredicate: "accessibility-reviewed",
    primaryAction: action(
      "accessibility.openSettings",
      "Open Accessibility Help",
      "autopilot.onboarding.accessibility.help",
      "Home: Open Accessibility Help",
      "editor.action.accessibilityHelp",
    ),
  }),
  makeStep({
    id: "accessibility-view",
    familyId: "accessibility",
    sourceStepId: "accessibleView",
    title: "Inspect content in the accessible view",
    body:
      "The accessible view is available for the terminal, hovers, notifications, comments, notebook output, chat responses, inline completions, and debug console output.",
    nlsIndexes: [15298, 15299],
    sourceActions: [
      sourceAction(15300, "Open Accessible View", "editor.action.accessibleView"),
    ],
    media: { kind: "empty-markdown", assets: [], alt: "Accessible view" },
    condition: "accessibility context",
    captureStatus: "source-indexed-not-default-visible",
    targetRoute: "Autopilot accessibility settings",
    completionPredicate: "accessibility-reviewed",
    primaryAction: action(
      "accessibility.openSettings",
      "Open Accessible View",
      "autopilot.onboarding.accessibleView",
      "Home: Open Accessible View",
      "editor.action.accessibleView",
    ),
  }),
  makeStep({
    id: "accessibility-verbosity",
    familyId: "accessibility",
    sourceStepId: "verbositySettings",
    title: "Control the verbosity of aria labels",
    body:
      "Screen reader verbosity settings exist around the workbench so familiar users can reduce repeated hints.",
    nlsIndexes: [15301, 15302],
    sourceActions: [
      sourceAction(
        15303,
        "Open Accessibility Settings",
        "workbench.action.openAccessibilitySettings",
      ),
    ],
    media: { kind: "empty-markdown", assets: [], alt: "Accessibility settings" },
    condition: "accessibility context",
    captureStatus: "source-indexed-not-default-visible",
    targetRoute: "Autopilot accessibility settings",
    completionPredicate: "accessibility-reviewed",
    primaryAction: action(
      "accessibility.openSettings",
      "Open Accessibility Settings",
      "autopilot.onboarding.accessibility.settings",
      "Home: Open Accessibility Settings",
      "workbench.action.openAccessibilitySettings",
    ),
  }),
  makeStep({
    id: "accessibility-command-palette",
    familyId: "accessibility",
    sourceStepId: "commandPaletteTaskAccessibility",
    title: "Unlock productivity with the Command Palette",
    body:
      "Run commands without reaching for your mouse to accomplish any task in VS Code.",
    nlsIndexes: [15304, 15305],
    sourceActions: [
      sourceAction(15306, "Open Command Palette", "workbench.action.showCommands"),
    ],
    media: {
      kind: "single-image",
      assets: ["commandPalette.svg"],
      alt: "Command Palette",
    },
    condition: "accessibility context",
    captureStatus: "source-indexed-not-default-visible",
    targetRoute: "Autopilot Command Palette",
    completionPredicate: "palette-opened",
    primaryAction: action(
      "palette.open",
      "Open Command Palette",
      "autopilot.onboarding.accessibility.palette",
      "Home: Open Accessibility Palette",
      "workbench.action.showCommands",
    ),
  }),
  makeStep({
    id: "accessibility-keybindings",
    familyId: "accessibility",
    sourceStepId: "keybindingsAccessibility",
    title: "Customize your keyboard shortcuts",
    body:
      "Once you have discovered your favorite commands, create custom keyboard shortcuts for instant access.",
    nlsIndexes: [15307, 15308],
    sourceActions: [
      sourceAction(
        15309,
        "Keyboard Shortcuts",
        "toSide:workbench.action.openGlobalKeybindings",
      ),
    ],
    media: {
      kind: "single-image",
      assets: ["shortcuts.svg"],
      alt: "Keyboard shortcuts",
    },
    condition: "accessibility context",
    captureStatus: "source-indexed-not-default-visible",
    targetRoute: "Autopilot accessibility settings and OpenVSCode keybindings",
    completionPredicate: "accessibility-reviewed",
    primaryAction: action(
      "workbench.openShortcuts",
      "Keyboard Shortcuts",
      "autopilot.onboarding.accessibility.shortcuts",
      "Home: Open Accessibility Shortcuts",
      "toSide:workbench.action.openGlobalKeybindings",
    ),
  }),
  makeStep({
    id: "accessibility-signals",
    familyId: "accessibility",
    sourceStepId: "accessibilitySignals",
    title:
      "Fine tune which accessibility signals you want to receive via audio or a braille device",
    body:
      "Accessibility sounds and announcements are played around the workbench for different events.",
    nlsIndexes: [15310, 15311],
    sourceActions: [
      sourceAction(15312, "List Signal Sounds", "signals.sounds.help"),
      sourceAction(15313, "List Signal Announcements", "accessibility.announcement.help"),
    ],
    media: { kind: "empty-markdown", assets: [], alt: "Accessibility signals" },
    condition: "accessibility context",
    captureStatus: "source-indexed-not-default-visible",
    targetRoute: "Autopilot accessibility settings",
    completionPredicate: "accessibility-reviewed",
    primaryAction: action(
      "accessibility.openSettings",
      "List Signal Sounds",
      "autopilot.onboarding.accessibility.signals",
      "Home: List Accessibility Signals",
      "signals.sounds.help",
    ),
  }),
  makeStep({
    id: "accessibility-hover",
    familyId: "accessibility",
    sourceStepId: "hover",
    title: "Access the hover in the editor to get more information on a variable or symbol",
    body:
      "While focus is in the editor on a variable or symbol, a hover can be focused with the Show or Open Hover command.",
    nlsIndexes: [15314, 15315],
    sourceActions: [
      sourceAction(15316, "Show or Focus Hover", "editor.action.showHover"),
    ],
    media: { kind: "empty-markdown", assets: [], alt: "Editor hover" },
    condition: "accessibility context",
    captureStatus: "source-indexed-not-default-visible",
    targetRoute: "Contained OpenVSCode editor command",
    completionPredicate: "accessibility-reviewed",
    primaryAction: action(
      "workspace.open",
      "Show or Focus Hover",
      "autopilot.onboarding.accessibility.hover",
      "Home: Show Hover",
      "editor.action.showHover",
    ),
  }),
  makeStep({
    id: "accessibility-symbols",
    familyId: "accessibility",
    sourceStepId: "goToSymbol",
    title: "Navigate to symbols in a file",
    body: "The Go to Symbol command is useful for navigating between important landmarks in a document.",
    nlsIndexes: [15317, 15318],
    sourceActions: [
      sourceAction(15319, "Go to Symbol", "editor.action.goToSymbol"),
    ],
    media: { kind: "empty-markdown", assets: [], alt: "Go to symbol" },
    condition: "accessibility context",
    captureStatus: "source-indexed-not-default-visible",
    targetRoute: "Contained OpenVSCode editor command",
    completionPredicate: "accessibility-reviewed",
    primaryAction: action(
      "workspace.open",
      "Go to Symbol",
      "autopilot.onboarding.accessibility.symbols",
      "Home: Go To Symbol",
      "editor.action.goToSymbol",
    ),
  }),
  makeStep({
    id: "accessibility-folding",
    familyId: "accessibility",
    sourceStepId: "codeFolding",
    title: "Use code folding to collapse blocks of code and focus on the code you're interested in.",
    body:
      "Fold or unfold a code section with the Toggle Fold command. Fold or unfold recursively with the Toggle Fold Recursively command.",
    nlsIndexes: [15320, 15321],
    sourceActions: [
      sourceAction(15322, "Toggle Fold", "editor.toggleFold"),
      sourceAction(15323, "Toggle Fold Recursively", "editor.toggleFoldRecursively"),
    ],
    media: { kind: "empty-markdown", assets: [], alt: "Code folding" },
    condition: "accessibility context",
    captureStatus: "source-indexed-not-default-visible",
    targetRoute: "Contained OpenVSCode editor command",
    completionPredicate: "accessibility-reviewed",
    primaryAction: action(
      "workspace.open",
      "Toggle Fold",
      "autopilot.onboarding.accessibility.folding",
      "Home: Toggle Fold",
      "editor.toggleFold",
    ),
  }),
  makeStep({
    id: "accessibility-intellisense",
    familyId: "accessibility",
    sourceStepId: "intellisense",
    title: "Use Intellisense to improve coding efficiency",
    body:
      "Intellisense suggestions can be opened with the Trigger Intellisense command, and inline suggestions can be triggered separately.",
    nlsIndexes: [15324, 15325],
    sourceActions: [
      sourceAction(15326, "Trigger Intellisense", "editor.action.triggerSuggest"),
      sourceAction(15327, "Trigger Inline Suggestion", "editor.action.inlineSuggest.trigger"),
    ],
    media: { kind: "empty-markdown", assets: [], alt: "Intellisense" },
    condition: "accessibility context",
    captureStatus: "source-indexed-not-default-visible",
    targetRoute: "Contained OpenVSCode editor command",
    completionPredicate: "accessibility-reviewed",
    primaryAction: action(
      "workspace.open",
      "Trigger Intellisense",
      "autopilot.onboarding.accessibility.intellisense",
      "Home: Trigger Intellisense",
      "editor.action.triggerSuggest",
    ),
  }),
  makeStep({
    id: "accessibility-settings",
    familyId: "accessibility",
    sourceStepId: "accessibilitySettings",
    title: "Configure accessibility settings",
    body:
      "Accessibility settings can be configured by running the Open Accessibility Settings command.",
    nlsIndexes: [15328, 15329],
    sourceActions: [
      sourceAction(
        15330,
        "Open Accessibility Settings",
        "workbench.action.openAccessibilitySettings",
      ),
    ],
    media: { kind: "empty-markdown", assets: [], alt: "Accessibility settings" },
    condition: "accessibility context",
    captureStatus: "source-indexed-not-default-visible",
    targetRoute: "Autopilot accessibility settings",
    completionPredicate: "accessibility-reviewed",
    primaryAction: action(
      "accessibility.openSettings",
      "Open Accessibility Settings",
      "autopilot.onboarding.accessibility.configure",
      "Home: Configure Accessibility Settings",
      "workbench.action.openAccessibilitySettings",
    ),
  }),
  makeStep({
    id: "accessibility-dictation",
    familyId: "accessibility",
    sourceStepId: "dictation",
    title: "Use dictation to write code and text in the editor and terminal",
    body:
      "Dictation allows you to write code and text using your voice in the editor and terminal.",
    nlsIndexes: [15331, 15332],
    sourceActions: [
      sourceAction(15333, "Voice: Start Dictation in Editor", "workbench.action.editorDictation.start"),
      sourceAction(15334, "Terminal: Start Dictation in Terminal", "workbench.action.terminal.startVoice"),
      sourceAction(15335, "Terminal: Stop Dictation in Terminal", "workbench.action.terminal.stopVoice"),
    ],
    media: { kind: "empty-markdown", assets: [], alt: "Dictation commands" },
    condition: "hasSpeechProvider",
    captureStatus: "source-indexed-not-default-visible",
    targetRoute: "Autopilot accessibility settings",
    completionPredicate: "accessibility-reviewed",
    primaryAction: action(
      "accessibility.openSettings",
      "Voice: Start Dictation in Editor",
      "autopilot.onboarding.accessibility.dictation",
      "Home: Start Dictation",
      "workbench.action.editorDictation.start",
    ),
  }),
];

const notebookSteps: AutopilotOnboardingStep[] = [
  makeStep({
    id: "notebook-profile",
    familyId: "notebooks",
    sourceStepId: "notebookProfile",
    title: "Select the layout for your notebooks",
    body: "Get notebooks to feel just the way you prefer.",
    nlsIndexes: [15375, 15376, 15377, 15378, 15379],
    sourceActions: [],
    media: {
      kind: "notebook-profile",
      assets: [],
      alt: "Notebook profile choices",
    },
    condition: "config.openGettingStarted && userHasOpenedNotebook",
    captureStatus: "source-indexed-not-default-visible",
    targetRoute: "Source-indexed notebook route",
    completionPredicate: "manual",
    primaryAction: action(
      "notebook.profile",
      "Select Notebook Layout",
      "autopilot.onboarding.notebookProfile",
      "Home: Select Notebook Layout",
      "notebook.setProfile",
    ),
    visibleInFirstRun: false,
  }),
];

const familySteps: Record<OnboardingFamilyId, AutopilotOnboardingStep[]> = {
  "setup-vscode-web": setupWebSteps,
  "setup-vscode": setupDesktopSteps,
  "learn-fundamentals": fundamentalsSteps,
  accessibility: accessibilitySteps,
  notebooks: notebookSteps,
};

export const AUTOPILOT_ONBOARDING_FAMILIES: AutopilotOnboardingFamily[] = (
  Object.keys(FAMILY_SEEDS) as OnboardingFamilyId[]
).map((familyId) => {
  const seed = FAMILY_SEEDS[familyId];
  return {
    id: seed.id,
    sourceId: seed.sourceId,
    title: seed.title,
    sourceTitle: seed.sourceTitle,
    pageTitle: seed.pageTitle,
    summary: seed.summary,
    sourceTitleIndex: seed.titleIndex,
    sourceSummaryIndex: seed.summaryIndex,
    sourceVisibility: seed.visibility,
    visibleInFirstRun: seed.visibleInFirstRun,
    steps: familySteps[familyId],
  };
});

export const FIRST_RUN_ONBOARDING_FAMILIES = AUTOPILOT_ONBOARDING_FAMILIES.filter(
  (family) => family.visibleInFirstRun,
);

export const AUTOPILOT_ONBOARDING_STEPS =
  AUTOPILOT_ONBOARDING_FAMILIES.flatMap((family) => family.steps);

export const FIRST_RUN_ONBOARDING_STEPS =
  FIRST_RUN_ONBOARDING_FAMILIES.flatMap((family) =>
    family.steps.filter((step) => step.visibleInFirstRun),
  );

export interface OnboardingRouteResolution {
  conditionState: OnboardingRouteConditionState;
  visibleFamilies: AutopilotOnboardingFamily[];
  visibleSteps: AutopilotOnboardingStep[];
  hiddenSteps: Array<{
    step: AutopilotOnboardingStep;
    conditionMatched: boolean;
    conditionIds: OnboardingConditionId[];
    reasons: string[];
  }>;
  conditionalVisibleSteps: AutopilotOnboardingStep[];
  sourceIndexedHiddenSteps: AutopilotOnboardingStep[];
}

export function normalizeOnboardingConditionState(
  patch: Partial<OnboardingRouteConditionState> = {},
): OnboardingRouteConditionState {
  return {
    ...DEFAULT_ONBOARDING_CONDITION_STATE,
    ...patch,
    workspaceFolderCount: Math.max(
      0,
      Math.trunc(
        patch.workspaceFolderCount ??
          DEFAULT_ONBOARDING_CONDITION_STATE.workspaceFolderCount,
      ),
    ),
    gitOpenRepositoryCount: Math.max(
      0,
      Math.trunc(
        patch.gitOpenRepositoryCount ??
          DEFAULT_ONBOARDING_CONDITION_STATE.gitOpenRepositoryCount,
      ),
    ),
  };
}

export function onboardingConditionsMatch(
  conditionIds: readonly OnboardingConditionId[],
  state: OnboardingRouteConditionState,
): boolean {
  return conditionIds.every((conditionId) =>
    ONBOARDING_CONDITION_DEFINITIONS[conditionId].predicate(state),
  );
}

function hiddenReasonsForStep(
  step: AutopilotOnboardingStep,
  state: OnboardingRouteConditionState,
): string[] {
  const reasons = step.conditionIds
    .filter(
      (conditionId) =>
        !ONBOARDING_CONDITION_DEFINITIONS[conditionId].predicate(state),
    )
    .map((conditionId) => ONBOARDING_CONDITION_DEFINITIONS[conditionId].label);
  if (!step.visibleInFirstRun) {
    reasons.push("Source-known conditional route");
  }
  return reasons;
}

function shouldSurfaceStep(
  step: AutopilotOnboardingStep,
  family: AutopilotOnboardingFamily,
  state: OnboardingRouteConditionState,
): boolean {
  const matched = onboardingConditionsMatch(step.conditionIds, state);
  if (!matched) {
    return false;
  }
  if (family.visibleInFirstRun && step.visibleInFirstRun) {
    return true;
  }
  return !step.visibleInFirstRun && step.conditionIds.some((conditionId) => conditionId !== "always");
}

export function resolveOnboardingRouteVisibility(
  patch: Partial<OnboardingRouteConditionState> = {},
): OnboardingRouteResolution {
  const conditionState = normalizeOnboardingConditionState(patch);
  const visibleFamilies: AutopilotOnboardingFamily[] = [];
  const visibleSteps: AutopilotOnboardingStep[] = [];
  const hiddenSteps: OnboardingRouteResolution["hiddenSteps"] = [];

  for (const family of AUTOPILOT_ONBOARDING_FAMILIES) {
    const resolvedFamilySteps = family.steps.filter((step) =>
      shouldSurfaceStep(step, family, conditionState),
    );
    if (resolvedFamilySteps.length > 0) {
      visibleFamilies.push({
        ...family,
        visibleInFirstRun: true,
        steps: resolvedFamilySteps,
      });
      visibleSteps.push(...resolvedFamilySteps);
    }
    for (const step of family.steps) {
      if (resolvedFamilySteps.includes(step)) {
        continue;
      }
      const conditionMatched = onboardingConditionsMatch(step.conditionIds, conditionState);
      hiddenSteps.push({
        step,
        conditionMatched,
        conditionIds: step.conditionIds,
        reasons: hiddenReasonsForStep(step, conditionState),
      });
    }
  }

  return {
    conditionState,
    visibleFamilies,
    visibleSteps,
    hiddenSteps,
    conditionalVisibleSteps: visibleSteps.filter((step) => !step.visibleInFirstRun),
    sourceIndexedHiddenSteps: hiddenSteps
      .map((entry) => entry.step)
      .filter((step) => step.source.captureStatus !== "captured"),
  };
}

export const HOME_DASHBOARD_CARDS: HomeDashboardCard[] = [
  {
    id: "workspace",
    title: "Workspace",
    detail: "Open the contained OpenVSCode workbench for code browsing and IOI panes.",
    meta: "Direct child webview",
    actionLabel: "Open Workspace",
    actionId: "workspace.open",
  },
  {
    id: "runs",
    title: "Runs and evidence",
    detail: "Inspect runtime runs, receipts, artifacts, and review-ready proof bundles.",
    meta: "IOI authoritative",
    actionLabel: "Open Runs",
    actionId: "evidence.openRuns",
  },
  {
    id: "policy",
    title: "Policy",
    detail: "Review approval posture, connector boundaries, and evidence egress.",
    meta: "Shield state",
    actionLabel: "Open Policy",
    actionId: "policy.openPolicy",
  },
  {
    id: "context",
    title: "Codebase context",
    detail: "Verify project scope, connector posture, and codebase-first defaults.",
    meta: "Shared runtime substrate",
    actionLabel: "Open Capabilities",
    actionId: "context.openCapabilities",
  },
];

export function findOnboardingStep(stepId: string): AutopilotOnboardingStep | null {
  return AUTOPILOT_ONBOARDING_STEPS.find((step) => step.id === stepId) ?? null;
}

export function findFirstRunOnboardingStep(
  stepId: string,
): AutopilotOnboardingStep | null {
  return FIRST_RUN_ONBOARDING_STEPS.find((step) => step.id === stepId) ?? null;
}

export function findOnboardingFamily(
  familyId: OnboardingFamilyId,
): AutopilotOnboardingFamily | null {
  return AUTOPILOT_ONBOARDING_FAMILIES.find((family) => family.id === familyId) ?? null;
}

export function defaultOnboardingStepId(): string {
  return FIRST_RUN_ONBOARDING_STEPS[0]?.id ?? "setup-theme";
}

export function recommendedAccessibilityTheme(): AutopilotThemeId {
  return "light-high-contrast";
}

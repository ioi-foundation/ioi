import {
  AUTOPILOT_THEME_OPTIONS,
  type AutopilotAppearanceState,
  type AutopilotThemeId,
} from "../../services/autopilotAppearance";
import commandPaletteSvg from "../../assets/openvscode-walkthrough/commandPalette.svg";
import darkHcPng from "../../assets/openvscode-walkthrough/dark-hc.png";
import darkPng from "../../assets/openvscode-walkthrough/dark.png";
import debugSvg from "../../assets/openvscode-walkthrough/debug.svg";
import extensionsWebSvg from "../../assets/openvscode-walkthrough/extensions-web.svg";
import extensionsSvg from "../../assets/openvscode-walkthrough/extensions.svg";
import gitSvg from "../../assets/openvscode-walkthrough/git.svg";
import languagesSvg from "../../assets/openvscode-walkthrough/languages.svg";
import learnSvg from "../../assets/openvscode-walkthrough/learn.svg";
import lightHcPng from "../../assets/openvscode-walkthrough/light-hc.png";
import lightPng from "../../assets/openvscode-walkthrough/light.png";
import menuBarSvg from "../../assets/openvscode-walkthrough/menuBar.svg";
import openFolderSvg from "../../assets/openvscode-walkthrough/openFolder.svg";
import runTaskSvg from "../../assets/openvscode-walkthrough/runTask.svg";
import searchSvg from "../../assets/openvscode-walkthrough/search.svg";
import settingsSyncSvg from "../../assets/openvscode-walkthrough/settingsSync.svg";
import settingsSvg from "../../assets/openvscode-walkthrough/settings.svg";
import shortcutsSvg from "../../assets/openvscode-walkthrough/shortcuts.svg";
import terminalSvg from "../../assets/openvscode-walkthrough/terminal.svg";
import workspaceTrustSvg from "../../assets/openvscode-walkthrough/workspaceTrust.svg";
import {
  AUTOPILOT_ONBOARDING_FAMILIES,
  type AutopilotOnboardingFamily,
  type AutopilotOnboardingStep,
  type OnboardingActionId,
} from "./homeOnboardingModel";

const WALKTHROUGH_MEDIA: Record<string, string> = {
  "commandPalette.svg": commandPaletteSvg,
  "dark-hc.png": darkHcPng,
  "dark.png": darkPng,
  "debug.svg": debugSvg,
  "extensions-web.svg": extensionsWebSvg,
  "extensions.svg": extensionsSvg,
  "git.svg": gitSvg,
  "languages.svg": languagesSvg,
  "learn.svg": learnSvg,
  "light-hc.png": lightHcPng,
  "light.png": lightPng,
  "menuBar.svg": menuBarSvg,
  "openFolder.svg": openFolderSvg,
  "runTask.svg": runTaskSvg,
  "search.svg": searchSvg,
  "settings.svg": settingsSvg,
  "settingsSync.svg": settingsSyncSvg,
  "shortcuts.svg": shortcutsSvg,
  "terminal.svg": terminalSvg,
  "workspaceTrust.svg": workspaceTrustSvg,
};

interface HomeWalkthroughDocumentProps {
  selectedStep: AutopilotOnboardingStep;
  completedStepIds: ReadonlySet<string>;
  appearance: AutopilotAppearanceState;
  onBack: () => void;
  onSkipForNow: () => void;
  onApplyTheme: (themeId: AutopilotThemeId) => void;
  onExecuteAction: (actionId: OnboardingActionId) => void;
  onFocusStep: (stepId: string) => void;
  families: AutopilotOnboardingFamily[];
  onMarkStepDone: (stepId?: string) => void;
  onNextStep: () => void;
}

function currentFamilyForStep(
  step: AutopilotOnboardingStep,
  families: AutopilotOnboardingFamily[],
) {
  return (
    families.find((family) => family.id === step.familyId) ??
    families[0] ??
    AUTOPILOT_ONBOARDING_FAMILIES[0]!
  );
}

function renderStepMarker(complete: boolean, selected: boolean) {
  if (complete) {
    return "✓";
  }
  if (selected) {
    return "●";
  }
  return "○";
}

function ThemePickerMedia({
  appearance,
  onApplyTheme,
}: {
  appearance: AutopilotAppearanceState;
  onApplyTheme: (themeId: AutopilotThemeId) => void;
}) {
  return (
    <div
      className="chat-home-walkthrough-theme-media"
      aria-label="Theme choices"
      data-home-walkthrough-media="theme-picker"
    >
      {AUTOPILOT_THEME_OPTIONS.map((theme) => {
        const mediaSrc = WALKTHROUGH_MEDIA[theme.sourceMedia];
        const selected = appearance.themeId === theme.id;
        return (
          <button
            type="button"
            key={theme.id}
            className={selected ? "is-selected" : ""}
            data-home-theme={theme.id}
            data-home-action="appearance.selectTheme"
            onClick={() => onApplyTheme(theme.id)}
            aria-pressed={selected}
          >
            {mediaSrc ? <img src={mediaSrc} alt="" /> : null}
            <span>{theme.label}</span>
          </button>
        );
      })}
      <button
        type="button"
        className="chat-home-walkthrough-more-themes"
        data-home-action="appearance.selectTheme"
        onClick={() => onApplyTheme(appearance.themeId)}
      >
        See More Themes...
      </button>
    </div>
  );
}

function EmptyMarkdownMedia({ step }: { step: AutopilotOnboardingStep }) {
  return (
    <div
      className="chat-home-walkthrough-empty-media"
      aria-label={step.media.alt}
      data-home-walkthrough-media="empty-markdown"
    >
      <div />
      <ul>
        {step.sourceActions.map((sourceAction) => (
          <li key={`${step.id}-${sourceAction.index}`}>{sourceAction.label}</li>
        ))}
      </ul>
    </div>
  );
}

function NotebookProfileMedia() {
  return (
    <div
      className="chat-home-walkthrough-notebook-media"
      aria-label="Notebook profile choices"
      data-home-walkthrough-media="notebook-profile"
    >
      <span>Default</span>
      <span>Jupyter</span>
      <span>Colab</span>
    </div>
  );
}

function StepMedia({
  appearance,
  selectedStep,
  onApplyTheme,
}: {
  appearance: AutopilotAppearanceState;
  selectedStep: AutopilotOnboardingStep;
  onApplyTheme: (themeId: AutopilotThemeId) => void;
}) {
  if (selectedStep.media.kind === "theme-picker") {
    return <ThemePickerMedia appearance={appearance} onApplyTheme={onApplyTheme} />;
  }

  if (selectedStep.media.kind === "empty-markdown") {
    return <EmptyMarkdownMedia step={selectedStep} />;
  }

  if (selectedStep.media.kind === "notebook-profile") {
    return <NotebookProfileMedia />;
  }

  const mediaName = selectedStep.media.assets[0];
  const mediaSrc = mediaName ? WALKTHROUGH_MEDIA[mediaName] : null;
  return (
    <div
      className="chat-home-walkthrough-image-media"
      aria-label={selectedStep.media.alt}
      data-home-walkthrough-media={mediaName ?? "missing"}
    >
      {mediaSrc ? <img src={mediaSrc} alt="" /> : <EmptyMarkdownMedia step={selectedStep} />}
    </div>
  );
}

export function HomeWalkthroughDocument({
  selectedStep,
  completedStepIds,
  appearance,
  onBack,
  onSkipForNow,
  onApplyTheme,
  onExecuteAction,
  onFocusStep,
  families,
  onMarkStepDone,
  onNextStep,
}: HomeWalkthroughDocumentProps) {
  const currentFamily = currentFamilyForStep(selectedStep, families);
  const familySteps = currentFamily.steps;
  const selectedStepIndex = Math.max(
    0,
    familySteps.findIndex((step) => step.id === selectedStep.id),
  );

  return (
    <div
      className="chat-home-walkthrough-document"
      data-home-walkthrough-family={currentFamily.id}
      data-home-walkthrough-source-family={currentFamily.sourceId}
    >
      <div className="chat-home-walkthrough-topbar">
        <button
          type="button"
          className="chat-home-walkthrough-back"
          onClick={onBack}
        >
          ‹ {currentFamily.id === "setup-vscode-web" ? "Go Back" : "Welcome"}
        </button>
        <button
          type="button"
          className="chat-home-walkthrough-skip"
          data-home-action="home.skipForNow"
          onClick={onSkipForNow}
        >
          Skip for now
        </button>
      </div>

      <div className="chat-home-walkthrough-grid">
        <div className="chat-home-walkthrough-copy">
          <header>
            <h1>{currentFamily.title}</h1>
            <p>{currentFamily.summary}</p>
          </header>

          <ol className="chat-home-walkthrough-steps" aria-label={currentFamily.pageTitle}>
            {familySteps.map((step) => {
              const selected = step.id === selectedStep.id;
              const complete = completedStepIds.has(step.id);
              return (
                <li key={step.id}>
                  <div
                    role="button"
                    tabIndex={0}
                    className={`chat-home-walkthrough-step ${
                      selected ? "is-selected" : ""
                    } ${complete ? "is-complete" : ""}`}
                    data-home-step={step.id}
                    data-home-source-step={step.sourceStepId}
                    data-home-capture-status={step.source.captureStatus}
                    onClick={() => onFocusStep(step.id)}
                    onKeyDown={(event) => {
                      if (event.key === "Enter" || event.key === " ") {
                        event.preventDefault();
                        onFocusStep(step.id);
                      }
                    }}
                    aria-current={selected ? "step" : undefined}
                  >
                    <span className="chat-home-walkthrough-step-marker" aria-hidden="true">
                      {renderStepMarker(complete, selected)}
                    </span>
                    <span className="chat-home-walkthrough-step-content">
                      <strong>{step.title}</strong>
                      {selected ? (
                        <>
                          <em>{step.body}</em>
                          <span className="chat-home-walkthrough-actions">
                            <button
                              type="button"
                              data-home-action={step.primaryAction.id}
                              onClick={(event) => {
                                event.stopPropagation();
                                onExecuteAction(step.primaryAction.id);
                              }}
                            >
                              {step.primaryAction.label}
                            </button>
                            {step.secondaryActions.map((actionItem) => (
                              <button
                                type="button"
                                key={`${step.id}-${actionItem.id}-${actionItem.label}`}
                                data-home-action={actionItem.id}
                                onClick={(event) => {
                                  event.stopPropagation();
                                  onExecuteAction(actionItem.id);
                                }}
                              >
                                {actionItem.label}
                              </button>
                            ))}
                          </span>
                        </>
                      ) : null}
                    </span>
                  </div>
                </li>
              );
            })}
          </ol>

          <footer className="chat-home-walkthrough-footer">
            <button
              type="button"
              data-home-action="home.markDone"
              onClick={() => onMarkStepDone(selectedStep.id)}
            >
              ✓ Mark Done
            </button>
            <button
              type="button"
              data-home-action="home.nextSection"
              onClick={onNextStep}
            >
              Next Section →
            </button>
          </footer>
        </div>

        <div
          className="chat-home-walkthrough-media"
          data-home-selected-step-index={selectedStepIndex}
        >
          <StepMedia
            appearance={appearance}
            selectedStep={selectedStep}
            onApplyTheme={onApplyTheme}
          />
        </div>
      </div>
    </div>
  );
}

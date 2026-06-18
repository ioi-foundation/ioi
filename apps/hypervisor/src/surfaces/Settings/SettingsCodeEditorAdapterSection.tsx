import {
  HYPERVISOR_CODE_EDITOR_ADAPTER_PREFERENCES,
  buildCodeEditorAdapterLaunchPlan,
  getCodeEditorAdapterPreferenceByRef,
  getCodeEditorAdapterPreferenceRef,
  type HypervisorCodeEditorAdapterControlAction,
  type HypervisorCodeEditorAdapterCustodyPosture,
  type HypervisorCodeEditorAdapterLaunchMode,
} from "../../windows/HypervisorShellWindow/hypervisorShellNavigationModel";
import type { SettingsViewBodyView } from "./settingsViewTypes";

function launchModeLabel(mode: HypervisorCodeEditorAdapterLaunchMode): string {
  switch (mode) {
    case "embedded":
      return "Embedded";
    case "external":
      return "Desktop editor";
    case "remote_url":
      return "Browser editor";
    default:
      return String(mode).split("_").join(" ");
  }
}

function custodyPostureLabel(
  posture: HypervisorCodeEditorAdapterCustodyPosture,
): string {
  switch (posture) {
    case "local_projection":
      return "Local workspace";
    case "redacted_projection":
      return "Limited workspace";
    default:
      return String(posture).split("_").join(" ");
  }
}

function controlActionLabel(action: HypervisorCodeEditorAdapterControlAction) {
  switch (action) {
    case "open_embedded_code_editor":
      return "Open embedded";
    case "open_desktop_editor":
      return "Open desktop";
    case "open_browser_editor":
      return "Open browser editor";
    default:
      return String(action).split("_").join(" ");
  }
}

export function SettingsCodeEditorAdapterSection({
  view,
}: {
  view: SettingsViewBodyView;
}) {
  const selectedPreference = getCodeEditorAdapterPreferenceByRef(
    view.codeEditorAdapterPreferenceRef,
  );
  const selectedLaunchPlan = buildCodeEditorAdapterLaunchPlan(selectedPreference);

  return (
    <div className="chat-settings-stack">
      <article className="chat-settings-card">
        <div className="chat-settings-card-head">
          <div>
            <span className="chat-settings-card-eyebrow">
              code editor adapter
            </span>
            <h2>Default editor target</h2>
          </div>
          <span className="chat-settings-pill">
            {controlActionLabel(selectedLaunchPlan.control_action)}
          </span>
        </div>
        <p className="chat-settings-body">
          Choose the embedded, desktop, or browser-based code editor that
          Hypervisor should preselect. Sessions and Environments own terminal,
          VM, node, and provider routes.
        </p>
        <div className="chat-settings-summary-grid">
          {HYPERVISOR_CODE_EDITOR_ADAPTER_PREFERENCES.map((preference) => {
            const preferenceRef = getCodeEditorAdapterPreferenceRef(preference);
            const launchPlan = buildCodeEditorAdapterLaunchPlan(preference);
            const selected =
              preferenceRef === view.codeEditorAdapterPreferenceRef;

            return (
              <button
                type="button"
                key={preference.adapter_id}
                className={`chat-settings-subcard ${
                  selected ? "is-live" : ""
                }`}
                data-code-editor-adapter-preference={preferenceRef}
                data-code-editor-adapter-executor-lane={
                  launchPlan.executor_lane
                }
                data-code-editor-adapter-control-action={
                  launchPlan.control_action
                }
                data-code-editor-adapter-control-channel-ref={
                  launchPlan.control_channel_ref
                }
                aria-pressed={selected}
                onClick={() =>
                  view.setCodeEditorAdapterPreferenceRef(preferenceRef)
                }
              >
                <strong>{preference.label}</strong>
                <span>{preference.description}</span>
                <small>
                  {launchModeLabel(preference.launch_mode)} ·{" "}
                  {custodyPostureLabel(preference.custody_posture)} ·{" "}
                  {controlActionLabel(launchPlan.control_action)}
                </small>
              </button>
            );
          })}
        </div>
        <div className="chat-settings-callout">
          <strong>Session preference</strong>
          <p>
            The selected target becomes the default code editor for new
            workspace sessions.
          </p>
        </div>
      </article>
    </div>
  );
}

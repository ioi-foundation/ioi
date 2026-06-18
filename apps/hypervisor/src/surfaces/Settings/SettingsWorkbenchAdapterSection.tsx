import {
  HYPERVISOR_WORKBENCH_ADAPTER_PREFERENCES,
  buildWorkbenchAdapterLaunchPlan,
  getWorkbenchAdapterPreferenceByRef,
  getWorkbenchAdapterPreferenceRef,
  type HypervisorWorkbenchAdapterControlAction,
  type HypervisorWorkbenchAdapterCustodyPosture,
  type HypervisorWorkbenchAdapterLaunchMode,
} from "../../windows/HypervisorShellWindow/hypervisorShellNavigationModel";
import type { SettingsViewBodyView } from "./settingsViewTypes";

function launchModeLabel(mode: HypervisorWorkbenchAdapterLaunchMode): string {
  switch (mode) {
    case "embedded":
      return "Embedded";
    case "external":
      return "Desktop editor";
    case "remote_url":
      return "Browser session";
    case "headless":
      return "Terminal session";
    default:
      return String(mode).split("_").join(" ");
  }
}

function custodyPostureLabel(
  posture: HypervisorWorkbenchAdapterCustodyPosture,
): string {
  switch (posture) {
    case "local_projection":
      return "Local workspace";
    case "redacted_projection":
      return "Limited workspace";
    case "provider_session":
      return "Provider session";
    case "headless_session":
      return "Headless session";
    default:
      return String(posture).split("_").join(" ");
  }
}

function controlActionLabel(action: HypervisorWorkbenchAdapterControlAction) {
  switch (action) {
    case "open_embedded_workbench":
      return "Open embedded";
    case "open_desktop_editor":
      return "Open desktop";
    case "open_browser_workspace":
      return "Open browser";
    case "attach_terminal_session":
      return "Attach terminal";
    case "attach_provider_workspace":
      return "Attach workspace";
    case "attach_hypervisor_node":
      return "Attach node";
    default:
      return String(action).split("_").join(" ");
  }
}

export function SettingsWorkbenchAdapterSection({
  view,
}: {
  view: SettingsViewBodyView;
}) {
  const selectedPreference = getWorkbenchAdapterPreferenceByRef(
    view.workbenchAdapterPreferenceRef,
  );
  const selectedLaunchPlan = buildWorkbenchAdapterLaunchPlan(selectedPreference);

  return (
    <div className="chat-settings-stack">
      <article className="chat-settings-card">
        <div className="chat-settings-card-head">
          <div>
            <span className="chat-settings-card-eyebrow">
              Workbench adapter
            </span>
            <h2>Default session target</h2>
          </div>
          <span className="chat-settings-pill">
            {controlActionLabel(selectedLaunchPlan.control_action)}
          </span>
        </div>
        <p className="chat-settings-body">
          Choose the default editor, terminal, browser workspace, VM, or node
          adapter that New Session should preselect. You can still change the
          target when starting a session.
        </p>
        <div className="chat-settings-summary-grid">
          {HYPERVISOR_WORKBENCH_ADAPTER_PREFERENCES.map((preference) => {
            const preferenceRef = getWorkbenchAdapterPreferenceRef(preference);
            const launchPlan = buildWorkbenchAdapterLaunchPlan(preference);
            const selected =
              preferenceRef === view.workbenchAdapterPreferenceRef;

            return (
              <button
                type="button"
                key={preference.adapter_id}
                className={`chat-settings-subcard ${
                  selected ? "is-live" : ""
                }`}
                data-workbench-adapter-preference={preferenceRef}
                data-workbench-adapter-executor-lane={
                  launchPlan.executor_lane
                }
                data-workbench-adapter-control-action={
                  launchPlan.control_action
                }
                data-workbench-adapter-control-channel-ref={
                  launchPlan.control_channel_ref
                }
                aria-pressed={selected}
                onClick={() =>
                  view.setWorkbenchAdapterPreferenceRef(preferenceRef)
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
            The selected target becomes the default place where Workbench opens
            code, terminal, browser, VM, or node sessions.
          </p>
        </div>
      </article>
    </div>
  );
}

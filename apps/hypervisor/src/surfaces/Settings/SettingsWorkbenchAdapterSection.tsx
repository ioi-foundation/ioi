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
      return "Browser editor";
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
    case "open_browser_editor":
      return "Open browser editor";
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
            <h2>Default editor target</h2>
          </div>
          <span className="chat-settings-pill">
            {controlActionLabel(selectedLaunchPlan.control_action)}
          </span>
        </div>
        <p className="chat-settings-body">
          Choose the embedded, desktop, or browser-based code editor that
          Workbench should preselect. Sessions and Environments own terminal,
          VM, node, and provider routes.
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
            code editor sessions.
          </p>
        </div>
      </article>
    </div>
  );
}

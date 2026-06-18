import {
  HYPERVISOR_WORKBENCH_ADAPTER_PREFERENCES,
  getWorkbenchAdapterPreferenceByRef,
  getWorkbenchAdapterPreferenceRef,
} from "../../windows/HypervisorShellWindow/hypervisorShellNavigationModel";
import type { SettingsViewBodyView } from "./settingsViewTypes";

export function SettingsWorkbenchAdapterSection({
  view,
}: {
  view: SettingsViewBodyView;
}) {
  const selectedPreference = getWorkbenchAdapterPreferenceByRef(
    view.workbenchAdapterPreferenceRef,
  );

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
            {selectedPreference.launch_mode}
          </span>
        </div>
        <p className="chat-settings-body">
          Choose the default editor, terminal, browser workspace, VM, or node
          adapter that New Session should preselect. Every launch still binds a
          harness, model route, privacy posture, authority scopes, and receipts.
        </p>
        <div className="chat-settings-summary-grid">
          {HYPERVISOR_WORKBENCH_ADAPTER_PREFERENCES.map((preference) => {
            const preferenceRef = getWorkbenchAdapterPreferenceRef(preference);
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
                aria-pressed={selected}
                onClick={() =>
                  view.setWorkbenchAdapterPreferenceRef(preferenceRef)
                }
              >
                <strong>{preference.label}</strong>
                <span>{preference.description}</span>
                <small>
                  {preference.launch_mode} /{" "}
                  {preference.custody_posture.split("_").join(" ")}
                </small>
              </button>
            );
          })}
        </div>
        <div className="chat-settings-callout">
          <strong>Launch binding</strong>
          <p>
            New Session emits the selected adapter as
            <code>adapter_preference_ref</code> so Workbench sessions can be
            replayed, inspected, and receipted against the target the operator
            actually chose.
          </p>
        </div>
      </article>
    </div>
  );
}

import { SettingsEnvironmentSection } from "./SettingsEnvironmentSection";
import { SettingsIdentitySection } from "./SettingsIdentitySection";
import { SettingsKnowledgeSection } from "./SettingsKnowledgeSection";
import { SettingsMaintenanceSection } from "./SettingsMaintenanceSection";
import { SettingsManagedSection } from "./SettingsManagedSection";
import { SettingsRuntimeSection } from "./SettingsRuntimeSection";
import { SettingsSkillSourcesSection } from "./SettingsSkillSourcesSection";
import { SettingsSourcesSection } from "./SettingsSourcesSection";
import { SettingsStorageApiSection } from "./SettingsStorageApiSection";
import { isEngineSection } from "./ChatSettingsView.shared";
import type { SettingsViewBodyView } from "./ChatSettingsView.types";

export function ChatSettingsViewBody({
  view,
}: {
  view: SettingsViewBodyView;
}) {
  const { selectedSection, setSelectedSection, renderEngineControls } = view;

  return (
    <>
      <aside className="studio-settings-sidebar">
        <div className="studio-settings-sidebar-head">
          <strong>Control documents</strong>
          <span>Kernel-backed</span>
        </div>

        <button
          type="button"
          className={`studio-settings-target ${
            selectedSection === "identity" ? "active" : ""
          }`}
          onClick={() => setSelectedSection("identity")}
        >
          <strong>Identity</strong>
          <span>Display name, locale, and operator metadata.</span>
        </button>
        <button
          type="button"
          className={`studio-settings-target ${
            selectedSection === "knowledge" ? "active" : ""
          }`}
          onClick={() => setSelectedSection("knowledge")}
        >
          <strong>Knowledge</strong>
          <span>Collections, entry ingestion, search, and retrieval-ready sources.</span>
        </button>
        <button
          type="button"
          className={`studio-settings-target ${
            selectedSection === "skill_sources" ? "active" : ""
          }`}
          onClick={() => setSelectedSection("skill_sources")}
        >
          <strong>Skill sources</strong>
          <span>Repo or local skill roots, sync status, and provenance controls.</span>
        </button>
        <button
          type="button"
          className={`studio-settings-target ${
            selectedSection === "managed_settings" ? "active" : ""
          }`}
          onClick={() => setSelectedSection("managed_settings")}
        >
          <strong>Managed settings</strong>
          <span>Signed sync channels, effective policy, and local override posture.</span>
        </button>
        <button
          type="button"
          className={`studio-settings-target ${
            selectedSection === "runtime" ? "active" : ""
          }`}
          onClick={() => setSelectedSection("runtime")}
        >
          <strong>Runtime</strong>
          <span>Execution posture, watchdogs, memory, launcher, and throughput.</span>
        </button>
        <button
          type="button"
          className={`studio-settings-target ${
            selectedSection === "storage_api" ? "active" : ""
          }`}
          onClick={() => setSelectedSection("storage_api")}
        >
          <strong>Storage / API</strong>
          <span>Paths, bind address, compatibility routes, and API exposure.</span>
        </button>
        <button
          type="button"
          className={`studio-settings-target ${
            selectedSection === "sources" ? "active" : ""
          }`}
          onClick={() => setSelectedSection("sources")}
        >
          <strong>Sources</strong>
          <span>Model and backend galleries plus migration import sources.</span>
        </button>
        <button
          type="button"
          className={`studio-settings-target ${
            selectedSection === "environment" ? "active" : ""
          }`}
          onClick={() => setSelectedSection("environment")}
        >
          <strong>Environment</strong>
          <span>Environment bindings and runtime-specific external inputs.</span>
        </button>
        <button
          type="button"
          className={`studio-settings-target ${
            selectedSection === "local_data" ? "active" : ""
          }`}
          onClick={() => setSelectedSection("local_data")}
        >
          <strong>Local data</strong>
          <span>What is stored in the shell and what survives resets.</span>
        </button>
        <button
          type="button"
          className={`studio-settings-target ${
            selectedSection === "repair_reset" ? "active" : ""
          }`}
          onClick={() => setSelectedSection("repair_reset")}
        >
          <strong>Repair / reset</strong>
          <span>Clear local state when builds or policies are carrying context.</span>
        </button>
        <button
          type="button"
          className={`studio-settings-target ${
            selectedSection === "diagnostics" ? "active" : ""
          }`}
          onClick={() => setSelectedSection("diagnostics")}
        >
          <strong>Diagnostics</strong>
          <span>Current shell state, runtime posture, and recent local resets.</span>
        </button>
      </aside>

      <section className="studio-settings-panel">
        {isEngineSection(selectedSection) ? renderEngineControls() : null}

        {selectedSection === "identity" ? (
          <SettingsIdentitySection view={view} />
        ) : null}
        {selectedSection === "managed_settings" ? (
          <SettingsManagedSection view={view} />
        ) : null}
        {selectedSection === "runtime" ? (
          <SettingsRuntimeSection view={view} />
        ) : null}
        {selectedSection === "storage_api" ? (
          <SettingsStorageApiSection view={view} />
        ) : null}
        {selectedSection === "sources" ? (
          <SettingsSourcesSection view={view} />
        ) : null}
        {selectedSection === "environment" ? (
          <SettingsEnvironmentSection view={view} />
        ) : null}
        {selectedSection === "knowledge" ? (
          <SettingsKnowledgeSection view={view} />
        ) : null}
        {selectedSection === "skill_sources" ? (
          <SettingsSkillSourcesSection view={view} />
        ) : null}
        {selectedSection === "local_data" ||
        selectedSection === "repair_reset" ||
        selectedSection === "diagnostics" ? (
          <SettingsMaintenanceSection view={view} />
        ) : null}
      </section>
    </>
  );
}

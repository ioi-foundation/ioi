import { useEffect, useState } from "react";
import {
  DEFAULT_WORKBENCH_ADAPTER_PREFERENCE_REF,
  HYPERVISOR_CODE_EDITOR_ADAPTER_PREFERENCE_STORAGE_KEY,
  HYPERVISOR_CODE_EDITOR_ADAPTER_PREFERENCES,
  getCodeEditorAdapterPreferenceRef,
} from "../../windows/HypervisorShellWindow/hypervisorShellNavigationModel";
import { SettingsViewBody } from "./SettingsViewBody";
import { type SettingsSection } from "./settingsViewShared";

function readStoredCodeEditorAdapterPreferenceRef(): string {
  if (typeof window === "undefined") {
    return DEFAULT_WORKBENCH_ADAPTER_PREFERENCE_REF;
  }
  const stored = window.localStorage.getItem(
    HYPERVISOR_CODE_EDITOR_ADAPTER_PREFERENCE_STORAGE_KEY,
  );
  if (
    stored &&
    HYPERVISOR_CODE_EDITOR_ADAPTER_PREFERENCES.some(
      (preference) => getCodeEditorAdapterPreferenceRef(preference) === stored,
    )
  ) {
    return stored;
  }
  return DEFAULT_WORKBENCH_ADAPTER_PREFERENCE_REF;
}

interface SettingsViewProps {
  seedSection?: SettingsSection | null;
  onConsumeSeedSection?: () => void;
}

export function SettingsView({
  seedSection,
  onConsumeSeedSection,
}: SettingsViewProps) {
  const [selectedSection, setSelectedSection] =
    useState<SettingsSection>("identity");
  const [codeEditorAdapterPreferenceRef, setCodeEditorAdapterPreferenceRef] =
    useState(readStoredCodeEditorAdapterPreferenceRef);

  useEffect(() => {
    if (!seedSection) {
      return;
    }
    setSelectedSection(seedSection);
    onConsumeSeedSection?.();
  }, [onConsumeSeedSection, seedSection]);

  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }
    window.localStorage.setItem(
      HYPERVISOR_CODE_EDITOR_ADAPTER_PREFERENCE_STORAGE_KEY,
      codeEditorAdapterPreferenceRef,
    );
  }, [codeEditorAdapterPreferenceRef]);

  return (
    <div className="hypervisor-settings-view hypervisor-settings-view--reference">
      <div className="hypervisor-settings-layout">
        <SettingsViewBody
          view={{
            selectedSection,
            setSelectedSection,
            codeEditorAdapterPreferenceRef,
            setCodeEditorAdapterPreferenceRef,
          }}
        />
      </div>
    </div>
  );
}

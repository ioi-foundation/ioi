import type { Dispatch, SetStateAction } from "react";
import type { SettingsSection } from "./settingsViewShared";

export type SettingsViewBodyView = {
  selectedSection: SettingsSection;
  setSelectedSection: Dispatch<SetStateAction<SettingsSection>>;
  codeEditorAdapterPreferenceRef: string;
  setCodeEditorAdapterPreferenceRef: Dispatch<SetStateAction<string>>;
};

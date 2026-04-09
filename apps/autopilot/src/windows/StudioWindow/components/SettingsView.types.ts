import type { Dispatch, ReactNode, SetStateAction } from "react";
import type {
  AssistantUserProfile,
  SessionHookSnapshot,
  KnowledgeCollectionEntryContent,
  KnowledgeCollectionRecord,
  KnowledgeCollectionSearchHit,
  LocalEngineControlPlane,
  LocalEngineSnapshot,
  SkillSourceRecord,
} from "../../../types";
import type {
  CapabilityGovernanceRequest,
  SessionPermissionProfileId,
  ShieldPolicyState,
  ShieldRememberedApprovalSnapshot,
} from "../policyCenter";
import type { SettingsSection } from "./SettingsView.shared";

export type SettingsViewBodyView = {
  selectedSection: SettingsSection;
  setSelectedSection: Dispatch<SetStateAction<SettingsSection>>;
  profileDraft: AssistantUserProfile;
  profileSaving: boolean;
  profileError: string | null;
  onProfileDraftChange: <K extends keyof AssistantUserProfile>(
    key: K,
    value: AssistantUserProfile[K],
  ) => void;
  onResetProfileDraft: () => void;
  onSaveProfile: () => Promise<void>;
  profileDirty: boolean;
  policyState: ShieldPolicyState;
  governanceRequest?: CapabilityGovernanceRequest | null;
  controlPlane: LocalEngineControlPlane | null;
  updateEngineDraft: (
    updater: (current: LocalEngineControlPlane) => LocalEngineControlPlane,
  ) => void;
  renderEngineControls: () => ReactNode;
  engineSnapshot: LocalEngineSnapshot | null;
  knowledgeCollections: KnowledgeCollectionRecord[];
  knowledgeLoading: boolean;
  knowledgeBusy: boolean;
  knowledgeError: string | null;
  setKnowledgeError: Dispatch<SetStateAction<string | null>>;
  knowledgeMessage: string | null;
  knowledgeCollectionName: string;
  setKnowledgeCollectionName: Dispatch<SetStateAction<string>>;
  knowledgeCollectionDescription: string;
  setKnowledgeCollectionDescription: Dispatch<SetStateAction<string>>;
  setSelectedKnowledgeCollectionId: Dispatch<SetStateAction<string | null>>;
  knowledgeEntryTitle: string;
  setKnowledgeEntryTitle: Dispatch<SetStateAction<string>>;
  knowledgeEntryContent: string;
  setKnowledgeEntryContent: Dispatch<SetStateAction<string>>;
  knowledgeImportPath: string;
  setKnowledgeImportPath: Dispatch<SetStateAction<string>>;
  knowledgeSourceUri: string;
  setKnowledgeSourceUri: Dispatch<SetStateAction<string>>;
  knowledgeSourceInterval: string;
  setKnowledgeSourceInterval: Dispatch<SetStateAction<string>>;
  knowledgeSearchQuery: string;
  setKnowledgeSearchQuery: Dispatch<SetStateAction<string>>;
  knowledgeSearchResults: KnowledgeCollectionSearchHit[];
  setKnowledgeSearchResults: Dispatch<
    SetStateAction<KnowledgeCollectionSearchHit[]>
  >;
  knowledgeSearchLoading: boolean;
  setKnowledgeSearchLoading: Dispatch<SetStateAction<boolean>>;
  knowledgeEntryLoading: boolean;
  setKnowledgeEntryLoading: Dispatch<SetStateAction<boolean>>;
  selectedKnowledgeEntryContent: KnowledgeCollectionEntryContent | null;
  setSelectedKnowledgeEntryContent: Dispatch<
    SetStateAction<KnowledgeCollectionEntryContent | null>
  >;
  skillSources: SkillSourceRecord[];
  skillSourcesLoading: boolean;
  skillSourcesBusy: boolean;
  skillSourcesError: string | null;
  skillSourcesMessage: string | null;
  skillSourceLabel: string;
  setSkillSourceLabel: Dispatch<SetStateAction<string>>;
  skillSourceUri: string;
  setSkillSourceUri: Dispatch<SetStateAction<string>>;
  setSelectedSkillSourceId: Dispatch<SetStateAction<string | null>>;
  selectedKnowledgeCollection: KnowledgeCollectionRecord | null;
  selectedSkillSource: SkillSourceRecord | null;
  authorityHookSnapshot: SessionHookSnapshot | null;
  authorityRememberedApprovals: ShieldRememberedApprovalSnapshot | null;
  authorityStatus: "idle" | "loading" | "ready" | "error";
  authorityError: string | null;
  authorityApplyingProfileId: SessionPermissionProfileId | null;
  authorityMessage: string | null;
  authorityCurrentProfileId: SessionPermissionProfileId | null;
  authorityActiveOverrideCount: number;
  handleApplyAuthorityProfile: (
    profileId: SessionPermissionProfileId,
  ) => Promise<void>;
  onOpenPolicySurface: () => void;
  onOpenConnections: () => void;
  summary: string | null;
  diagnostics: ReadonlyArray<{ label: string; value: string; tone: string }>;
  runKnowledgeAction: (
    action: () => Promise<void>,
    successMessage: string,
  ) => Promise<void>;
  runSkillSourceAction: (
    action: () => Promise<void>,
    successMessage: string,
  ) => Promise<void>;
  handleReset: () => Promise<void>;
  isResetting: boolean;
  resetConfirmOpen: boolean;
  setResetConfirmOpen: Dispatch<SetStateAction<boolean>>;
  error: string | null;
  [key: string]: any;
};

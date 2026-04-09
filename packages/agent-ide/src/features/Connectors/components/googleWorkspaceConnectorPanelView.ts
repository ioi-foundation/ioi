import type {
  ConnectorActionDefinition,
  ConnectorSubscriptionSummary,
  ConnectorSummary,
} from "../../../runtime/agent-runtime";
import type { GoogleWorkspaceConnectorState } from "../hooks/useGoogleWorkspaceConnector";
import type {
  GoogleScopeBundle,
  WorkspaceOnboardingStepId,
  WorkspaceServiceGroup,
  WorkspaceTabId,
} from "./googleWorkspaceConnectorPanelConfig";

export type GoogleWorkspaceConnectorPanelView = {
  connector: ConnectorSummary;
  workspace: GoogleWorkspaceConnectorState;
  onOpenPolicyCenter?: (connector: ConnectorSummary) => void;
  policySummary?: {
    headline: string;
    detail: string;
  };
  activeTab: WorkspaceTabId;
  setActiveTab: (tab: WorkspaceTabId) => void;
  actionsById: Map<string, ConnectorActionDefinition>;
  capabilityGroups: WorkspaceServiceGroup[];
  automationGroups: WorkspaceServiceGroup[];
  advancedGroups: WorkspaceServiceGroup[];
  activeSubscriptions: ConnectorSubscriptionSummary[];
  attentionSubscriptions: ConnectorSubscriptionSummary[];
  availability: string;
  availabilityStyle: string;
  isConnected: boolean;
  missingOauthClient: boolean;
  onboardingStep: WorkspaceOnboardingStepId;
  selectedBundles: GoogleScopeBundle[];
  requestedScopes: string[];
  canBeginAuth: boolean;
  reconnectScopes: string[];
  tokenStoragePath?: string;
  clientStoragePath?: string;
  openAction: (
    tab: WorkspaceTabId,
    actionId: string,
    presetInput?: Record<string, string>,
  ) => void;
  focusedActionModalOpen: boolean;
  openFocusedActionModal: () => void;
  closeFocusedActionModal: () => void;
  openAuthLink: () => void;
  copyAuthLink: () => Promise<void>;
  resetGoogleSetup: () => Promise<void>;
  reopenScopeSelection: () => Promise<void>;
  retryConsent: () => Promise<void>;
  saveOauthClientAndContinue: () => Promise<void>;
  unlockBundleContext: {
    actionLabel: string;
    recommendations: UnlockBundleRecommendation[];
  } | null;
  rememberUnlockBundleContext: (
    actionLabel: string,
    recommendations: UnlockBundleRecommendation[],
  ) => void;
  [key: string]: any;
};

export type UnlockBundleRecommendation = {
  bundleId: string;
  reason: string;
};

// packages/agent-ide/src/index.ts

export { AgentEditor } from "./AgentEditor";
export { WorkflowComposer } from "./WorkflowComposer";
export { createWorkflowHarnessTools } from "./runtime/workflow-harness-tools";
export {
  actionKindForWorkflowNodeType,
  actionKindIsEntry,
  actionKindIsTerminal,
  actionKindRequiresCompletionVerification,
  validateActionEdge,
  workflowNodeTypeForActionKind,
} from "./runtime/agent-execution-substrate";
export { ActivityBar } from "./features/Shell/ActivityBar";
export { AssistantWorkbenchView } from "./features/Shell/AssistantWorkbenchView";
export { SessionHistorySidebar } from "./features/Shell/SessionHistorySidebar";
export { FleetView } from "./features/Fleet/FleetView";
export { AgentsDashboard } from "./features/Dashboard/AgentsDashboard";
export { BuilderView } from "./features/Builder/BuilderView";
export { RuntimeCatalogView } from "./features/Marketplace/RuntimeCatalogView";
export { ConnectorsView } from "./features/Connectors/ConnectorsView";
export { GenericConnectorPanel } from "./features/Connectors/components/GenericConnectorPanel";
export { GoogleWorkspaceConnectorPanel } from "./features/Connectors/components/GoogleWorkspaceConnectorPanel";
export { MailConnectorPanel } from "./features/Connectors/components/MailConnectorPanel";
export { useMailConnectorActions } from "./features/Connectors/hooks/useMailConnectorActions";
export {
  createChatSessionStore,
  createConnectedSessionStore,
  createNormalizedChatSessionStore,
  createSessionStore,
  appendUniqueSessionArtifact,
  appendUniqueSessionEvent,
  buildSessionReplTargets,
  buildChatContinueFailureTask,
  buildOptimisticChatContinueTask,
  composeRuntimeChatTaskNormalizer,
  createNormalizedRuntimeChatSessionControllerStore,
  createRuntimeChatSessionControllerStore,
  createRuntimeSessionControllerStore,
  createSessionControllerStore,
  normalizeRuntimeChatTaskDefaults,
  selectPrimarySessionReplTarget,
} from "./runtime/session-controller";
export {
  useSessionConversationScroll,
  useSessionDeferredFocus,
  useSessionChatArtifactDrawer,
} from "./runtime/use-session-conversation-surface";
export {
  assistantWorkbenchEvidenceThreadId,
  assistantWorkbenchEvidenceThreadIdForSession,
  assistantWorkbenchActivityTargetKey,
  assistantWorkbenchSessionTargetKey,
  assistantWorkbenchSurfaceForSession,
  createAssistantWorkbenchActivity,
  type AssistantWorkbenchSurface,
} from "./runtime/assistant-workbench-activity";
export {
  useAssistantWorkbenchState,
  useAssistantWorkbenchStore,
} from "./runtime/use-assistant-workbench-state";
export { useAssistantWorkbenchController } from "./runtime/use-assistant-workbench-controller";
export { useAssistantWorkbenchActions } from "./runtime/use-assistant-workbench-controller";
export {
  useHydrateSessionStore,
  useSessionControllerHydration,
} from "./runtime/use-session-controller-hydration";
export {
  isSessionComposerSubmissionBlocked,
  isWaitingForClarificationStep,
  isWaitingForSudoStep,
  useSessionComposer,
} from "./runtime/use-session-composer";
export { useSessionInputComposer } from "./runtime/use-session-composer";
export { useSessionGateState } from "./runtime/use-session-gate-state";
export { useSessionApprovalState } from "./runtime/use-session-gate-state";
export {
  formatSessionTimeAgo,
  groupSessionHistoryByDate,
  useSessionHistoryBrowser,
} from "./runtime/use-session-history-browser";
export { useFilteredSessionHistory } from "./runtime/use-session-history-browser";
export { useSessionInspectionSurface } from "./runtime/use-session-inspection-surface";
export { useSessionInterruptionActions } from "./runtime/use-session-interruption-actions";
export { useSessionRuntimePresentation } from "./runtime/use-session-runtime-presentation";
export {
  buildSessionRunPresentation,
  dedupeSessionActivityEvents,
} from "./runtime/session-run-presentation";
export { useSessionRunSurface } from "./runtime/use-session-run-surface";
export { useSessionDisplayState } from "./runtime/use-session-run-surface";
export { useSessionShellOrchestration } from "./runtime/use-session-shell-orchestration";
export { useSessionShellActions } from "./runtime/use-session-shell-orchestration";
export { useSessionShellShortcuts } from "./runtime/use-session-shell-shortcuts";
export { useSessionTurnContexts } from "./runtime/use-session-turn-contexts";
export { useSessionViewState } from "./runtime/use-session-view-state";
export { useSessionUiState } from "./runtime/use-session-view-state";
export {
  dismissAssistantSession,
  getActiveAssistantSession,
  getAssistantSessionProjection,
  getAssistantSessionRuntime,
  listAssistantSessions,
  listenAssistantSessionEvent,
  listenAssistantSessionProjection,
  loadAssistantSession,
  loadAssistantSessionArtifacts,
  loadAssistantSessionEvents,
  respondToAssistantSessionGate,
  setActiveAssistantSessionRuntime,
  setDefaultAssistantSessionRuntime,
  startAssistantSession,
  stopAssistantSession,
  submitAssistantSessionInput,
  submitAssistantSessionRuntimePassword,
  continueSessionTask,
  dismissSessionTask,
  getCurrentSessionTask,
  getSessionProjection,
  getSessionRuntime,
  hideGateShell,
  hidePillShell,
  hideChatSessionShell,
  getActiveAssistantWorkbenchSession,
  getRecentAssistantWorkbenchActivities,
  listenAssistantWorkbenchActivity,
  listenAssistantWorkbenchSession,
  listSessionHistory,
  listenSessionProjection,
  listenSessionEvent,
  loadSessionTask,
  loadSessionThreadArtifacts,
  loadSessionThreadEvents,
  activateAssistantWorkbenchSession,
  openChatAssistantWorkbench,
  openChatAutopilotIntent,
  openChatCapabilityTarget,
  openChatPolicyTarget,
  openChatSessionTarget,
  openChatShellView,
  reportAssistantWorkbenchActivity,
  respondToSessionGate,
  setDefaultSessionRuntime,
  setSessionRuntime,
  showGateShell,
  showPillShell,
  showChatSessionShell,
  showChatShell,
  startSessionTask,
  stopSessionTask,
  submitSessionRuntimePassword,
} from "./runtime/session-runtime";
export { parseShieldApprovalRequest } from "./runtime/shield-approval";
export { buildConnectorApprovalMemoryRequest } from "./runtime/shield-approval";
export {
  buildMeetingBriefDraft,
  buildMeetingPrepAutopilotIntent,
  buildReplyAutopilotIntent,
  buildReplyBody,
  buildReplyReferences,
  collectCalendarLinks,
  ensureReplySubject,
  extractDisplayName,
  extractEmailAddress,
  formatWorkbenchEventTime,
} from "./runtime/assistant-workbench-content";
export {
  getSessionId,
  getSessionStepText,
  isWaitingForClarificationStep as isClarificationWaitStep,
  isWaitingForSudoStep as isSudoPasswordWaitStep,
  normalizeSessionSummary,
  sessionSummaryLooksLive,
  shouldRetainSessionOnMissingProjection,
} from "./runtime/session-status";

export type {
  AgentWorkbenchRuntime,
  AgentRuntime,
  AssistantSessionEventName,
  AssistantSessionGateResponse,
  AssistantSessionProjection,
  AssistantSessionRuntime,
  AssistantSessionThreadLoadOptions,
  AgentSessionEventName,
  AgentSessionGateResponse,
  AgentSessionProjection,
  AgentSessionRuntime,
  AgentSessionThreadLoadOptions,
  GraphCapabilityCatalog,
  GraphModelBindingCatalog,
  GraphPayload,
  GraphEvent,
  GraphRuntimeCapabilityOption,
  GraphRuntimeModelOption,
  CacheResult,
  AgentSummary,
  FleetState,
  Zone,
  Container,
  RuntimeCatalogEntry,
  ConnectorSummary,
  ConnectorStatus,
  ConnectorPluginId,
  ConnectorFieldType,
  ConnectorActionKind,
  ConnectorFieldOption,
  ConnectorFieldDefinition,
  ConnectorActionDefinition,
  ConnectorActionRequest,
  ConnectorActionResult,
  ConnectorApprovalMemoryRequest,
  ConnectorConfigureRequest,
  ConnectorConfigureResult,
  ConnectorSubscriptionStatus,
  ConnectorSubscriptionSummary,
  WalletMailMessage,
  WalletMailReadLatestInput,
  WalletMailListRecentInput,
  WalletMailDeleteSpamInput,
  WalletMailReplyInput,
  WalletMailReadLatestResult,
  WalletMailListRecentResult,
  WalletMailDeleteSpamResult,
  WalletMailReplyResult,
  WalletMailConnectorAuthMode,
  WalletMailConnectorTlsMode,
  WalletMailConfigureAccountInput,
  WalletMailConfigureAccountResult,
  WalletMailConfiguredAccount,
  InstalledWorkflowStatus,
  InstalledWorkflowKind,
  InstalledWorkflowSummary,
  WorkflowRunReceipt,
  CreateMonitorWorkflowRequest,
  ChatViewTarget,
  ChatCapabilityDetailSection,
  GmailThreadMessageDetail,
  GmailThreadDetail,
  CalendarAttendeeDetail,
  CalendarEventDetail,
  AssistantWorkbenchSession,
  AssistantWorkbenchActivity,
  AssistantWorkbenchActivityAction,
  AssistantWorkbenchActivityStatus,
} from "./runtime/agent-runtime";
export type { ShieldApprovalRequest } from "./runtime/shield-approval";
export type {
  AgentActionBindingRef,
  AgentActionFrame,
  AgentActionKind,
  AgentActionPolicy,
  AgentActionValidationIssue,
  AgentExecutionSurface,
} from "./runtime/agent-execution-substrate";
export type {
  UseAssistantWorkbenchStateOptions,
} from "./runtime/use-assistant-workbench-state";
export type {
  AssistantWorkbenchBusyAction,
  UseAssistantWorkbenchActionsOptions,
  UseAssistantWorkbenchControllerOptions,
} from "./runtime/use-assistant-workbench-controller";
export type {
  ChatSessionLike,
  ChatSessionMessageLike,
  LineageSessionLike,
  SessionArtifactLike,
  SessionAttachTargetLike,
  SessionEventLike,
  SessionHistoryPollingOptions,
  SessionListEntryLike,
  SessionPollingOptions,
  SessionStoreAdapter,
  SessionStoreConfig,
  SessionStoreConnectOptions,
  SessionStoreState,
  SessionControllerArtifactLike,
  SessionControllerBootstrapOptions,
  SessionControllerLineageTaskLike,
  SessionControllerConfig,
  SessionControllerChatMessageLike,
  SessionControllerChatTaskLike,
  SessionControllerEventLike,
  SessionControllerHistoryPollingOptions,
  SessionControllerRuntime,
  SessionControllerChatSurfaceTaskLike,
  SessionControllerStoreState,
  SessionControllerTaskPollingOptions,
  SessionControllerReplSessionLike,
  SessionControllerReplTarget,
} from "./runtime/session-controller";
export type {
  SessionComposerMessageLike,
  SessionComposerTaskLike,
  UseSessionComposerOptions,
} from "./runtime/use-session-composer";
export type { UseHydrateSessionStoreOptions } from "./runtime/use-session-controller-hydration";
export type {
  UseSessionConversationScrollOptions,
  UseSessionDeferredFocusOptions,
  UseSessionChatArtifactDrawerOptions,
} from "./runtime/use-session-conversation-surface";
export type {
  SessionClarificationOption,
  SessionClarificationRequest,
  SessionCredentialRequest,
  SessionGateChatEvent,
  SessionGateInfo,
  SessionGateTaskLike,
  UseSessionGateStateOptions,
} from "./runtime/use-session-gate-state";
export type { UseSessionInterruptionActionsOptions } from "./runtime/use-session-interruption-actions";
export type {
  SessionRuntimePresentationEntry,
  SessionRuntimePresentationEventLike,
  SessionRuntimePresentationGroup,
  SessionRuntimePresentationMessageLike,
  SessionRuntimeTimelineStep,
  UseSessionRuntimePresentationOptions,
} from "./runtime/use-session-runtime-presentation";
export type { UseSessionControllerHydrationOptions } from "./runtime/use-session-controller-hydration";
export type {
  BuildSessionRunPresentationOptions,
  SessionActivityEventRef,
  SessionRunPresentation,
} from "./runtime/session-run-presentation";
export type {
  SessionHistoryGroup,
  SessionHistorySummaryLike,
  UseSessionHistoryBrowserOptions,
} from "./runtime/use-session-history-browser";
export type { UseSessionInspectionSurfaceOptions } from "./runtime/use-session-inspection-surface";
export type {
  UseSessionDisplayStateOptions,
  SessionRunSurfaceTaskLike,
  UseSessionRunSurfaceOptions,
} from "./runtime/use-session-run-surface";
export type {
  UseSessionShellActionsOptions,
  UseSessionShellOrchestrationOptions,
} from "./runtime/use-session-shell-orchestration";
export type { UseSessionShellShortcutsOptions } from "./runtime/use-session-shell-shortcuts";
export type {
  SessionConversationMessageLike,
  SessionConversationTurn,
  SessionScreenshotReceiptLike,
  SessionSourceBrowseLike,
  SessionSourceSearchLike,
  SessionStreamMetadata,
  SessionThoughtAgentLike,
  SessionTurnContext,
  SessionTurnWindowLike,
  UseSessionTurnContextsOptions,
} from "./runtime/use-session-turn-contexts";
export type {
  SessionUiState,
  SessionViewState,
  UseSessionUiStateOptions,
  UseSessionViewStateOptions,
} from "./runtime/use-session-view-state";

export type {
  MailConnectorActionsState,
  MailProviderPresetKey,
  MailTlsMode,
} from "./features/Connectors/hooks/useMailConnectorActions";

export * from "./types/graph";

export interface LocalEngineCapabilityFamily {
  id: string;
  label: string;
  description: string;
  status: string;
  availableCount: number;
  toolNames: string[];
  operatorSummary: string;
}

export interface LocalEngineControlAction {
  itemId: string;
  title: string;
  summary: string;
  status: string;
  severity: string;
  requestedAtMs: number;
  dueAtMs?: number | null;
  approvalScope?: string | null;
  sensitiveActionType?: string | null;
  recommendedAction?: string | null;
  recoveryHint?: string | null;
  requestHash?: string | null;
}

export interface LocalEngineActivityRecord {
  eventId: string;
  sessionId: string;
  family: string;
  title: string;
  toolName: string;
  timestampMs: number;
  success: boolean;
  operation?: string | null;
  subjectKind?: string | null;
  subjectId?: string | null;
  backendId?: string | null;
  errorClass?: string | null;
}

export interface LocalEngineJobRecord {
  jobId: string;
  title: string;
  summary: string;
  status: string;
  origin: string;
  subjectKind: string;
  operation: string;
  createdAtMs: number;
  updatedAtMs: number;
  progressPercent: number;
  sourceUri?: string | null;
  subjectId?: string | null;
  backendId?: string | null;
  severity?: string | null;
  approvalScope?: string | null;
}

export interface LocalEngineModelRecord {
  modelId: string;
  status: string;
  residency: string;
  installedAtMs: number;
  updatedAtMs: number;
  sourceUri?: string | null;
  backendId?: string | null;
  hardwareProfile?: string | null;
  jobId?: string | null;
  bytesTransferred?: number | null;
}

export interface LocalEngineBackendRecord {
  backendId: string;
  status: string;
  health: string;
  installedAtMs: number;
  updatedAtMs: number;
  sourceUri?: string | null;
  alias?: string | null;
  hardwareProfile?: string | null;
  jobId?: string | null;
  installPath?: string | null;
  entrypoint?: string | null;
  healthEndpoint?: string | null;
  pid?: number | null;
  lastStartedAtMs?: number | null;
  lastHealthCheckAtMs?: number | null;
}

export interface LocalEngineGalleryEntryPreview {
  entryId: string;
  label: string;
  summary: string;
  sourceUri?: string | null;
}

export interface LocalEngineGalleryCatalogRecord {
  galleryId: string;
  kind: string;
  label: string;
  sourceUri: string;
  syncStatus: string;
  compatibilityTier: string;
  enabled: boolean;
  entryCount: number;
  updatedAtMs: number;
  lastJobId?: string | null;
  lastSyncedAtMs?: number | null;
  catalogPath?: string | null;
  sampleEntries: LocalEngineGalleryEntryPreview[];
  lastError?: string | null;
}

export interface LocalEngineWorkerCompletionContract {
  successCriteria: string;
  expectedOutput: string;
  mergeMode: string;
  verificationHint?: string | null;
}

export interface LocalEngineWorkerWorkflowRecord {
  workflowId: string;
  harnessWorkflowId?: string | null;
  harnessActivationId?: string | null;
  harnessHash?: string | null;
  label: string;
  summary: string;
  goalTemplate: string;
  triggerIntents: string[];
  defaultBudget?: number | null;
  maxRetries?: number | null;
  allowedTools: string[];
  completionContract?: LocalEngineWorkerCompletionContract | null;
}

export interface LocalEngineWorkerTemplateRecord {
  templateId: string;
  label: string;
  role: string;
  summary: string;
  defaultBudget: number;
  maxRetries: number;
  allowedTools: string[];
  completionContract: LocalEngineWorkerCompletionContract;
  workflows: LocalEngineWorkerWorkflowRecord[];
}

export interface LocalEngineAgentPlaybookStepRecord {
  stepId: string;
  label: string;
  summary: string;
  workerTemplateId: string;
  workerWorkflowId: string;
  goalTemplate: string;
  dependsOn: string[];
}

export interface LocalEngineAgentPlaybookRecord {
  playbookId: string;
  label: string;
  summary: string;
  goalTemplate: string;
  triggerIntents: string[];
  recommendedFor: string[];
  defaultBudget: number;
  completionContract: LocalEngineWorkerCompletionContract;
  steps: LocalEngineAgentPlaybookStepRecord[];
}

export interface LocalEngineParentPlaybookReceiptRecord {
  eventId: string;
  timestampMs: number;
  phase: string;
  status: string;
  success: boolean;
  summary: string;
  receiptRef?: string | null;
  childSessionId?: string | null;
  templateId?: string | null;
  workflowId?: string | null;
  errorClass?: string | null;
  artifactIds: string[];
}

export interface LocalEngineParentPlaybookStepRunRecord {
  stepId: string;
  label: string;
  summary: string;
  status: string;
  childSessionId?: string | null;
  templateId?: string | null;
  workflowId?: string | null;
  updatedAtMs?: number | null;
  completedAtMs?: number | null;
  errorClass?: string | null;
  receipts: LocalEngineParentPlaybookReceiptRecord[];
}

export interface LocalEngineParentPlaybookRunRecord {
  runId: string;
  parentSessionId: string;
  playbookId: string;
  playbookLabel: string;
  status: string;
  latestPhase: string;
  summary: string;
  currentStepId?: string | null;
  currentStepLabel?: string | null;
  activeChildSessionId?: string | null;
  startedAtMs: number;
  updatedAtMs: number;
  completedAtMs?: number | null;
  errorClass?: string | null;
  steps: LocalEngineParentPlaybookStepRunRecord[];
}

export interface LocalEngineRuntimeProfile {
  mode: string;
  endpoint: string;
  defaultModel: string;
  baselineRole: string;
  kernelAuthority: string;
}

export interface LocalEngineStorageConfig {
  modelsPath: string;
  backendsPath: string;
  artifactsPath: string;
  cachePath: string;
}

export interface LocalEngineWatchdogConfig {
  enabled: boolean;
  idleCheckEnabled: boolean;
  idleTimeout: string;
  busyCheckEnabled: boolean;
  busyTimeout: string;
  checkInterval: string;
  forceEvictionWhenBusy: boolean;
  lruEvictionMaxRetries: number;
  lruEvictionRetryInterval: string;
}

export interface LocalEngineMemoryConfig {
  reclaimerEnabled: boolean;
  thresholdPercent: number;
  preferGpu: boolean;
  targetResource: string;
}

export interface LocalEngineBackendPolicyConfig {
  maxConcurrency: number;
  maxQueuedRequests: number;
  parallelBackendLoads: number;
  allowParallelRequests: boolean;
  healthProbeInterval: string;
  logLevel: string;
  autoShutdownOnIdle: boolean;
}

export interface LocalEngineResponseConfig {
  retainReceiptsDays: number;
  persistArtifacts: boolean;
  allowStreaming: boolean;
  storeRequestPreviews: boolean;
}

export interface LocalEngineApiConfig {
  bindAddress: string;
  remoteAccessEnabled: boolean;
  corsMode: string;
  authMode: string;
}

export interface LocalEngineLauncherConfig {
  autoStartOnBoot: boolean;
  reopenChatOnLaunch: boolean;
  autoCheckUpdates: boolean;
  releaseChannel: string;
  showKernelConsole: boolean;
}

export interface LocalEngineGallerySource {
  id: string;
  kind: string;
  label: string;
  uri: string;
  enabled: boolean;
  syncStatus: string;
  compatibilityTier: string;
}

export interface LocalEngineEnvironmentBinding {
  key: string;
  value: string;
  secret: boolean;
}

export interface LocalEngineControlPlane {
  runtime: LocalEngineRuntimeProfile;
  storage: LocalEngineStorageConfig;
  watchdog: LocalEngineWatchdogConfig;
  memory: LocalEngineMemoryConfig;
  backendPolicy: LocalEngineBackendPolicyConfig;
  responses: LocalEngineResponseConfig;
  api: LocalEngineApiConfig;
  launcher: LocalEngineLauncherConfig;
  galleries: LocalEngineGallerySource[];
  environment: LocalEngineEnvironmentBinding[];
  notes: string[];
}

export interface LocalEngineConfigMigrationRecord {
  migrationId: string;
  fromVersion: number;
  toVersion: number;
  appliedAtMs: number;
  summary: string;
  details: string[];
}

export interface LocalEngineStagedOperation {
  operationId: string;
  subjectKind: string;
  operation: string;
  title: string;
  sourceUri?: string | null;
  subjectId?: string | null;
  notes?: string | null;
  createdAtMs: number;
  status: string;
}

export interface LocalEngineManagedSettingsChannelRecord {
  channelId: string;
  label: string;
  sourceUri: string;
  status: string;
  verificationStatus: string;
  summary: string;
  precedence: number;
  authorityLabel?: string | null;
  signatureAlgorithm?: string | null;
  profileId?: string | null;
  schemaVersion?: number | null;
  issuedAtMs?: number | null;
  expiresAtMs?: number | null;
  refreshedAtMs?: number | null;
  localOverrideCount: number;
  overriddenFields: string[];
}

export interface LocalEngineManagedSettingsSnapshot {
  syncStatus: string;
  summary: string;
  activeChannelId?: string | null;
  activeChannelLabel?: string | null;
  activeSourceUri?: string | null;
  lastRefreshedAtMs?: number | null;
  lastSuccessfulRefreshAtMs?: number | null;
  lastFailedRefreshAtMs?: number | null;
  refreshError?: string | null;
  localOverrideCount: number;
  localOverrideFields: string[];
  channels: LocalEngineManagedSettingsChannelRecord[];
}

export interface LocalEngineSnapshot {
  generatedAtMs: number;
  totalNativeTools: number;
  pendingControlCount: number;
  pendingApprovalCount: number;
  activeIssueCount: number;
  capabilities: LocalEngineCapabilityFamily[];
  pendingControls: LocalEngineControlAction[];
  jobs: LocalEngineJobRecord[];
  recentActivity: LocalEngineActivityRecord[];
  registryModels: LocalEngineModelRecord[];
  managedBackends: LocalEngineBackendRecord[];
  galleryCatalogs: LocalEngineGalleryCatalogRecord[];
  workerTemplates: LocalEngineWorkerTemplateRecord[];
  agentPlaybooks: LocalEngineAgentPlaybookRecord[];
  parentPlaybookRuns: LocalEngineParentPlaybookRunRecord[];
  controlPlaneSchemaVersion: number;
  controlPlaneProfileId: string;
  controlPlaneMigrations: LocalEngineConfigMigrationRecord[];
  controlPlane: LocalEngineControlPlane;
  managedSettings: LocalEngineManagedSettingsSnapshot;
  stagedOperations: LocalEngineStagedOperation[];
}

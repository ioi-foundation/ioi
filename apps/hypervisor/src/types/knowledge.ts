export interface DetectorPolicyConfig {
  enabled: boolean;
  minScore?: number | null;
  minAgeMinutes?: number | null;
  leadTimeMinutes?: number | null;
  toastMinScore?: number | null;
}

export interface AssistantAttentionGlobalPolicy {
  toastsEnabled: boolean;
  badgeEnabled: boolean;
  digestEnabled: boolean;
  hostedInferenceAllowed: boolean;
}

export interface ConnectorAttentionPolicy {
  scanMode?: string | null;
}

export interface AssistantAttentionPolicy {
  version: number;
  global: AssistantAttentionGlobalPolicy;
  detectors: Record<string, DetectorPolicyConfig>;
  connectors: Record<string, ConnectorAttentionPolicy>;
}

export interface AssistantAttentionProfile {
  version: number;
  preferredSurfaces: string[];
  highValueContacts: string[];
  focusWindows: string[];
  notificationFeedback: Record<string, Record<string, number>>;
}

export interface AssistantUserProfile {
  version: number;
  displayName: string;
  preferredName?: string | null;
  roleLabel?: string | null;
  timezone: string;
  locale: string;
  primaryEmail?: string | null;
  avatarSeed: string;
  groundingAllowed: boolean;
}

export interface KnowledgeCollectionSourceRecord {
  sourceId: string;
  kind: string;
  uri: string;
  pollIntervalMinutes?: number | null;
  enabled: boolean;
  syncStatus: string;
  lastSyncedAtMs?: number | null;
  lastError?: string | null;
}

export interface KnowledgeCollectionEntryRecord {
  entryId: string;
  title: string;
  kind: string;
  scope: string;
  artifactId: string;
  byteCount: number;
  chunkCount: number;
  archivalRecordIds: number[];
  createdAtMs: number;
  updatedAtMs: number;
  contentPreview: string;
}

export interface KnowledgeCollectionRecord {
  collectionId: string;
  label: string;
  description: string;
  createdAtMs: number;
  updatedAtMs: number;
  active: boolean;
  entries: KnowledgeCollectionEntryRecord[];
  sources: KnowledgeCollectionSourceRecord[];
}

export interface KnowledgeCollectionEntryContent {
  collectionId: string;
  entryId: string;
  title: string;
  kind: string;
  artifactId: string;
  byteCount: number;
  content: string;
}

export interface KnowledgeCollectionSearchHit {
  collectionId: string;
  entryId: string;
  title: string;
  scope: string;
  score: number;
  lexicalScore: number;
  semanticScore?: number | null;
  trustLevel: string;
  snippet: string;
  archivalRecordId: number;
  inspectId?: number | null;
}

export interface SkillSourceDiscoveredSkill {
  name: string;
  description?: string | null;
  relativePath: string;
}

export interface SkillSourceRecord {
  sourceId: string;
  label: string;
  uri: string;
  kind: string;
  enabled: boolean;
  syncStatus: string;
  lastSyncedAtMs?: number | null;
  lastError?: string | null;
  discoveredSkills: SkillSourceDiscoveredSkill[];
}

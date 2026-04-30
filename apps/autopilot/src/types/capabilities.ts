import type { ConnectorSummary } from "./agent-ide";
import type { SkillCatalogEntry } from "./generated";
import type {
  SkillSourceDiscoveredSkill,
  SkillSourceRecord,
} from "./knowledge";
import type { LocalEngineSnapshot } from "./local-engine";

export interface CapabilityAuthorityDescriptor {
  tierId: string;
  tierLabel: string;
  governedProfileId?: string | null;
  governedProfileLabel?: string | null;
  summary: string;
  detail: string;
  signals: string[];
}

export interface CapabilityLeaseDescriptor {
  availability: string;
  availabilityLabel: string;
  runtimeTargetId?: string | null;
  runtimeTargetLabel?: string | null;
  modeId?: string | null;
  modeLabel?: string | null;
  summary: string;
  detail: string;
  requiresAuth: boolean;
  signals: string[];
}

export interface CapabilityRegistryEntry {
  entryId: string;
  kind: string;
  label: string;
  summary: string;
  sourceKind: string;
  sourceLabel: string;
  sourceUri?: string | null;
  trustPosture: string;
  governedProfile?: string | null;
  availability: string;
  statusLabel: string;
  whySelectable: string;
  governingFamilyId?: string | null;
  relatedGoverningEntryIds: string[];
  governingFamilyHints: string[];
  runtimeTarget?: string | null;
  leaseMode?: string | null;
  authority: CapabilityAuthorityDescriptor;
  lease: CapabilityLeaseDescriptor;
}

export interface CapabilityRegistrySummary {
  generatedAtMs: number;
  totalEntries: number;
  connectorCount: number;
  connectedConnectorCount: number;
  runtimeSkillCount: number;
  trackedSourceCount: number;
  filesystemSkillCount: number;
  extensionCount: number;
  modelCount: number;
  backendCount: number;
  nativeFamilyCount: number;
  pendingEngineControlCount: number;
  activeIssueCount: number;
  authoritativeSourceCount: number;
}

export interface ExtensionContributionRecord {
  kind: string;
  label: string;
  path?: string | null;
  itemCount?: number | null;
  detail?: string | null;
}

export interface ExtensionManifestRecord {
  extensionId: string;
  manifestKind: string;
  manifestPath: string;
  rootPath: string;
  sourceLabel: string;
  sourceUri: string;
  sourceKind: string;
  enabled: boolean;
  name: string;
  displayName?: string | null;
  version?: string | null;
  description?: string | null;
  developerName?: string | null;
  authorName?: string | null;
  authorEmail?: string | null;
  authorUrl?: string | null;
  category?: string | null;
  trustPosture: string;
  governedProfile: string;
  homepage?: string | null;
  repository?: string | null;
  license?: string | null;
  keywords: string[];
  capabilities: string[];
  defaultPrompts: string[];
  contributions: ExtensionContributionRecord[];
  filesystemSkills: SkillSourceDiscoveredSkill[];
  marketplaceName?: string | null;
  marketplaceDisplayName?: string | null;
  marketplaceCategory?: string | null;
  marketplaceInstallationPolicy?: string | null;
  marketplaceAuthenticationPolicy?: string | null;
  marketplaceProducts: string[];
  marketplaceAvailableVersion?: string | null;
  marketplaceCatalogIssuedAtMs?: number | null;
  marketplaceCatalogExpiresAtMs?: number | null;
  marketplaceCatalogRefreshedAtMs?: number | null;
  marketplaceCatalogRefreshSource?: string | null;
  marketplaceCatalogChannel?: string | null;
  marketplaceCatalogSourceId?: string | null;
  marketplaceCatalogSourceLabel?: string | null;
  marketplaceCatalogSourceUri?: string | null;
  marketplacePackageUrl?: string | null;
  marketplaceCatalogRefreshBundleId?: string | null;
  marketplaceCatalogRefreshBundleLabel?: string | null;
  marketplaceCatalogRefreshBundleIssuedAtMs?: number | null;
  marketplaceCatalogRefreshBundleExpiresAtMs?: number | null;
  marketplaceCatalogRefreshAvailableVersion?: string | null;
  marketplaceVerificationStatus?: string | null;
  marketplaceSignatureAlgorithm?: string | null;
  marketplaceSignerIdentity?: string | null;
  marketplacePublisherId?: string | null;
  marketplaceSigningKeyId?: string | null;
  marketplacePublisherLabel?: string | null;
  marketplacePublisherTrustStatus?: string | null;
  marketplacePublisherTrustSource?: string | null;
  marketplacePublisherRootId?: string | null;
  marketplacePublisherRootLabel?: string | null;
  marketplaceAuthorityBundleId?: string | null;
  marketplaceAuthorityBundleLabel?: string | null;
  marketplaceAuthorityBundleIssuedAtMs?: number | null;
  marketplaceAuthorityTrustBundleId?: string | null;
  marketplaceAuthorityTrustBundleLabel?: string | null;
  marketplaceAuthorityTrustBundleIssuedAtMs?: number | null;
  marketplaceAuthorityTrustBundleExpiresAtMs?: number | null;
  marketplaceAuthorityTrustBundleStatus?: string | null;
  marketplaceAuthorityTrustIssuerId?: string | null;
  marketplaceAuthorityTrustIssuerLabel?: string | null;
  marketplaceAuthorityId?: string | null;
  marketplaceAuthorityLabel?: string | null;
  marketplacePublisherStatementIssuedAtMs?: number | null;
  marketplacePublisherTrustDetail?: string | null;
  marketplacePublisherRevokedAtMs?: number | null;
  marketplaceVerificationError?: string | null;
  marketplaceVerifiedAtMs?: number | null;
  marketplaceVerificationSource?: string | null;
  marketplaceVerifiedDigestSha256?: string | null;
  marketplaceTrustScoreLabel?: string | null;
  marketplaceTrustScoreSource?: string | null;
  marketplaceTrustRecommendation?: string | null;
}

export interface CapabilityRegistrySnapshot {
  generatedAtMs: number;
  summary: CapabilityRegistrySummary;
  entries: CapabilityRegistryEntry[];
  connectors: ConnectorSummary[];
  skillCatalog: SkillCatalogEntry[];
  skillSources: SkillSourceRecord[];
  extensionManifests: ExtensionManifestRecord[];
  localEngine: LocalEngineSnapshot;
}

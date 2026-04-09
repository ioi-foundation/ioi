import assert from "node:assert/strict";
import type { ExtensionManifestRecord } from "../../../types";
import { buildMcpOverview } from "./artifactHubMcpModel.ts";

function manifest(
  overrides: Partial<ExtensionManifestRecord>,
): ExtensionManifestRecord {
  return {
    extensionId: "extension:demo",
    manifestKind: "codex_plugin",
    manifestPath: "/tmp/demo/.codex-plugin/plugin.json",
    rootPath: "/tmp/demo",
    sourceLabel: "Demo source",
    sourceUri: "/tmp/demo",
    sourceKind: "tracked_source",
    enabled: true,
    name: "demo",
    displayName: "Demo Bridge",
    version: "1.0.0",
    description: "Demo bridge",
    developerName: null,
    authorName: null,
    authorEmail: null,
    authorUrl: null,
    category: "Automation",
    trustPosture: "local_only",
    governedProfile: "runtime_bridge",
    homepage: null,
    repository: null,
    license: null,
    keywords: [],
    capabilities: [],
    defaultPrompts: [],
    contributions: [],
    filesystemSkills: [],
    marketplaceName: null,
    marketplaceDisplayName: null,
    marketplaceCategory: null,
    marketplaceInstallationPolicy: null,
    marketplaceAuthenticationPolicy: null,
    marketplaceProducts: [],
    marketplaceAvailableVersion: null,
    marketplaceCatalogIssuedAtMs: null,
    marketplaceCatalogExpiresAtMs: null,
    marketplaceCatalogRefreshedAtMs: null,
    marketplaceCatalogRefreshSource: null,
    marketplaceCatalogChannel: null,
    marketplaceCatalogSourceId: null,
    marketplaceCatalogSourceLabel: null,
    marketplaceCatalogSourceUri: null,
    marketplaceCatalogRefreshBundleId: null,
    marketplaceCatalogRefreshBundleLabel: null,
    marketplaceCatalogRefreshBundleIssuedAtMs: null,
    marketplaceCatalogRefreshBundleExpiresAtMs: null,
    marketplaceCatalogRefreshAvailableVersion: null,
    marketplaceVerificationStatus: null,
    marketplaceSignatureAlgorithm: null,
    marketplaceSignerIdentity: null,
    marketplacePublisherId: null,
    marketplaceSigningKeyId: null,
    marketplacePublisherLabel: null,
    marketplacePublisherTrustStatus: null,
    marketplacePublisherTrustSource: null,
    marketplacePublisherRootId: null,
    marketplacePublisherRootLabel: null,
    marketplaceAuthorityBundleId: null,
    marketplaceAuthorityBundleLabel: null,
    marketplaceAuthorityBundleIssuedAtMs: null,
    marketplaceAuthorityTrustBundleId: null,
    marketplaceAuthorityTrustBundleLabel: null,
    marketplaceAuthorityTrustBundleIssuedAtMs: null,
    marketplaceAuthorityTrustBundleExpiresAtMs: null,
    marketplaceAuthorityTrustBundleStatus: null,
    marketplaceAuthorityTrustIssuerId: null,
    marketplaceAuthorityTrustIssuerLabel: null,
    marketplaceAuthorityId: null,
    marketplaceAuthorityLabel: null,
    marketplacePublisherStatementIssuedAtMs: null,
    marketplacePublisherTrustDetail: null,
    marketplacePublisherRevokedAtMs: null,
    marketplaceVerificationError: null,
    marketplaceVerifiedAtMs: null,
    marketplaceVerificationSource: null,
    marketplaceVerifiedDigestSha256: null,
    marketplaceTrustScoreLabel: null,
    marketplaceTrustScoreSource: null,
    marketplaceTrustRecommendation: null,
    ...overrides,
  };
}

{
  const overview = buildMcpOverview([]);
  assert.equal(overview.tone, "setup");
  assert.equal(overview.bridgeCount, 0);
  assert.equal(overview.cards[0].actionView, "plugins");
}

{
  const overview = buildMcpOverview([
    manifest({
      governedProfile: "governed_marketplace",
      trustPosture: "policy_limited",
      contributions: [
        {
          kind: "mcp_servers",
          label: "Filesystem MCP",
          path: "./mcp/filesystem.json",
          itemCount: 2,
          detail: "Two filesystem-backed MCP endpoints.",
        },
      ],
    }),
  ]);

  assert.equal(overview.tone, "attention");
  assert.equal(overview.serverCount, 2);
  assert.equal(overview.reviewCount, 1);
  assert.equal(overview.cards[1].actionView, "permissions");
  assert.equal(overview.servers[0].contributionPath, "./mcp/filesystem.json");
}

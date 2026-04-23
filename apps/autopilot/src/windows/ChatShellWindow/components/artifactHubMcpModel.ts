import type { ArtifactHubViewKey, ExtensionManifestRecord } from "../../../types";

export type McpTone = "ready" | "setup" | "attention";

export interface McpServerRecord {
  extensionId: string;
  label: string;
  trustPosture: string;
  governedProfile: string;
  sourceLabel: string;
  sourceUri: string;
  contributionPath?: string | null;
  contributionDetail?: string | null;
  serverCount: number;
}

export interface McpOverviewCard {
  id: "bridge" | "trust" | "sources";
  label: string;
  tone: McpTone;
  value: string;
  detail: string;
  meta: string[];
  actionView?: ArtifactHubViewKey;
}

export interface McpOverview {
  tone: McpTone;
  statusLabel: string;
  statusDetail: string;
  bridgeCount: number;
  serverCount: number;
  reviewCount: number;
  cards: McpOverviewCard[];
  servers: McpServerRecord[];
}

const MCP_TONE_RANK: Record<McpTone, number> = {
  ready: 0,
  setup: 1,
  attention: 2,
};

function strongestTone(values: McpTone[]): McpTone {
  return values.reduce<McpTone>((current, candidate) => {
    return MCP_TONE_RANK[candidate] > MCP_TONE_RANK[current]
      ? candidate
      : current;
  }, "ready");
}

function humanizeStatus(value: string): string {
  const text = value.trim().replace(/[_-]+/g, " ");
  return text ? text.replace(/\b\w/g, (char) => char.toUpperCase()) : "Unknown";
}

function serversForManifest(
  manifest: ExtensionManifestRecord,
): McpServerRecord[] {
  return manifest.contributions
    .filter((contribution) => contribution.kind === "mcp_servers")
    .map((contribution) => ({
      extensionId: manifest.extensionId,
      label: manifest.displayName || manifest.name,
      trustPosture: manifest.trustPosture,
      governedProfile: manifest.governedProfile,
      sourceLabel: manifest.sourceLabel,
      sourceUri: manifest.sourceUri,
      contributionPath: contribution.path || null,
      contributionDetail: contribution.detail || null,
      serverCount: Math.max(1, contribution.itemCount ?? 1),
    }));
}

export function buildMcpOverview(
  manifests: ExtensionManifestRecord[],
): McpOverview {
  const bridgeManifests = manifests.filter((manifest) =>
    manifest.contributions.some((contribution) => contribution.kind === "mcp_servers"),
  );
  const servers = bridgeManifests.flatMap(serversForManifest);
  const serverCount = servers.reduce((count, server) => count + server.serverCount, 0);
  const reviewRequiredCount = bridgeManifests.filter((manifest) => {
    return (
      manifest.trustPosture === "policy_limited" ||
      manifest.governedProfile === "runtime_bridge" ||
      manifest.governedProfile === "governed_marketplace"
    );
  }).length;
  const distinctSourceCount = new Set(
    bridgeManifests.map((manifest) => `${manifest.sourceLabel}:${manifest.sourceUri}`),
  ).size;

  const bridgeCard: McpOverviewCard = {
    id: "bridge",
    label: "Runtime bridge",
    tone: bridgeManifests.length > 0 ? "ready" : "setup",
    value:
      bridgeManifests.length > 0
        ? `${bridgeManifests.length} bridge package(s)`
        : "No MCP bridge packages published",
    detail:
      bridgeManifests.length > 0
        ? "The shared capability registry already knows which extension manifests contribute MCP servers into the runtime bridge lane."
        : "Install or enable an extension that contributes MCP servers to make this family visible in the governed runtime bridge lane.",
    meta: [`${serverCount} server contribution(s)`, `${distinctSourceCount} source(s)`],
    actionView: "plugins",
  };
  const trustCard: McpOverviewCard = {
    id: "trust",
    label: "Trust posture",
    tone:
      bridgeManifests.length === 0
        ? "setup"
        : reviewRequiredCount > 0
          ? "attention"
          : "ready",
    value:
      bridgeManifests.length === 0
        ? "Awaiting MCP packages"
        : reviewRequiredCount > 0
          ? `${reviewRequiredCount} bridge package(s) governed`
          : "Bridge packages aligned",
    detail:
      bridgeManifests.length === 0
        ? "Trust review will appear here once MCP bridge packages are discovered."
        : reviewRequiredCount > 0
          ? "At least one MCP bridge package widens runtime reach and should stay visible in the governed plugin and permission flows."
          : "Current MCP bridge packages are already surfaced through the same governed plugin path as the rest of the capability fabric.",
    meta: bridgeManifests.map((manifest) =>
      `${manifest.displayName || manifest.name}: ${humanizeStatus(manifest.trustPosture)}`,
    ),
    actionView: reviewRequiredCount > 0 ? "permissions" : "plugins",
  };
  const sourcesCard: McpOverviewCard = {
    id: "sources",
    label: "Source operations",
    tone: bridgeManifests.length > 0 ? "ready" : "setup",
    value:
      distinctSourceCount > 0
        ? `${distinctSourceCount} source root(s)`
        : "No source roots published",
    detail:
      distinctSourceCount > 0
        ? "Review or manage MCP bridge packages through the same plugin and doctor surfaces that already own extension lifecycle, trust, and conformance."
        : "Once MCP bridge packages are available, this drawer will point back into the managed plugin and diagnostics flows.",
    meta: bridgeManifests.map((manifest) => manifest.sourceLabel),
    actionView: "doctor",
  };

  const cards = [bridgeCard, trustCard, sourcesCard];
  const tone = strongestTone(cards.map((card) => card.tone));

  return {
    tone,
    statusLabel:
      tone === "attention"
        ? "Governed MCP bridge review"
        : tone === "setup"
          ? "MCP bridge not configured yet"
          : "MCP bridge posture aligned",
    statusDetail:
      tone === "attention"
        ? "The repo now has a first-class MCP surface, and at least one bridge package still deserves explicit trust or policy review."
        : tone === "setup"
          ? "No extension manifest is currently publishing MCP servers into the shared capability registry."
          : "MCP bridge packages are visible as governed capability fabric instead of hidden shell-local configuration.",
    bridgeCount: bridgeManifests.length,
    serverCount,
    reviewCount: reviewRequiredCount,
    cards,
    servers,
  };
}

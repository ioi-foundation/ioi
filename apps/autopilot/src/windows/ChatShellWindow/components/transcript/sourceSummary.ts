import type { SourceSummary, ChatArtifactSession } from "../../../../types";
import { firstStringValue, normalizedDomain } from "../../viewmodels/contentPipeline.helpers";

export function operatorStepSourceSummary(
  step: NonNullable<ChatArtifactSession["activeOperatorRun"]>["steps"][number],
  stepIndex: number,
): SourceSummary | null {
  const sourceUrls = new Set<string>();
  const domainCounts = new Map<string, number>();
  const browses: SourceSummary["browses"] = [];

  for (const source of step.sourceRefs) {
    const url = firstStringValue(source.url);
    if (!url) {
      continue;
    }
    if (!sourceUrls.has(url)) {
      sourceUrls.add(url);
      const domain =
        firstStringValue(source.domain) || normalizedDomain(url) || "unknown";
      domainCounts.set(domain, (domainCounts.get(domain) || 0) + 1);
      browses.push({
        url,
        domain,
        title: firstStringValue(source.title) || undefined,
        stepIndex,
      });
    }
  }

  if (sourceUrls.size === 0) {
    return null;
  }

  const domains = Array.from(domainCounts.entries())
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .map(([domain, count]) => ({
      domain,
      count,
      faviconUrl: `https://www.google.com/s2/favicons?sz=64&domain=${encodeURIComponent(domain)}`,
    }));

  return {
    totalSources: sourceUrls.size,
    sourceUrls: Array.from(sourceUrls),
    domains,
    searches: [],
    browses,
  };
}

export function sourceQueryFromReason(reason: string | null | undefined): string | null {
  const raw = String(reason || "").trim();
  if (!raw) {
    return null;
  }
  const quoted = raw.match(/for "([^"]+)"/i);
  if (quoted?.[1]?.trim()) {
    return quoted[1].trim();
  }
  return null;
}

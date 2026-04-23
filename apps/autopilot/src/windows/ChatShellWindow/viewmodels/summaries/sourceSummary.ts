import type {
  ActivityEventRef,
  SourceBrowseRow,
  SourceSearchRow,
  SourceSummary,
} from "../../../../types";
import {
  eventOutput,
  extractUrls,
  faviconUrlForDomain,
  firstStringValue,
  normalizedDomain,
  parseWebBundle,
  toValueString,
  WEB_READ_TOOL,
  WEB_SEARCH_TOOL,
} from "../contentPipeline.helpers";

const MAX_SOURCE_DOMAIN_PREVIEW = 3;

function includeSourceUrl(
  rawUrl: string,
  sourceUrls: Set<string>,
  domainCounts: Map<string, number>,
): void {
  const trimmed = rawUrl.trim();
  if (!trimmed) return;
  sourceUrls.add(trimmed);
  const domain = normalizedDomain(trimmed);
  if (!domain) return;
  const current = domainCounts.get(domain) || 0;
  domainCounts.set(domain, current + 1);
}

export function buildSourceSummary(
  events: ActivityEventRef[],
  operatorSourceRefs: Array<{
    url?: string | null;
    domain?: string | null;
    title?: string | null;
  }> = [],
): SourceSummary | null {
  const sourceUrls = new Set<string>();
  const domainCounts = new Map<string, number>();
  const searches: SourceSearchRow[] = [];
  const browses: SourceBrowseRow[] = [];
  const seenBrowseUrls = new Set<string>();

  for (const entry of events) {
    if (entry.kind !== "workload_event" && entry.kind !== "receipt_event") continue;
    const normalizedTool = (entry.toolName || "").trim().toLowerCase();
    const bundle = parseWebBundle(entry.event);
    const receiptKind = toValueString(entry.event.digest?.kind).trim().toLowerCase();
    const isSearchEvent =
      normalizedTool.includes(WEB_SEARCH_TOOL)
      || (!!bundle?.query && !bundle?.url)
      || (receiptKind === "web_retrieve"
        && toValueString(entry.event.details?.query).trim().length > 0);
    const isReadEvent =
      normalizedTool.includes(WEB_READ_TOOL)
      || !!bundle?.url
      || (receiptKind === "web_retrieve"
        && toValueString(entry.event.details?.url).trim().length > 0);
    if (!isSearchEvent && !isReadEvent) {
      continue;
    }

    const sourceCandidateUrls =
      bundle?.sources.map((source) => source.url) || extractUrls(eventOutput(entry.event));
    for (const url of sourceCandidateUrls) {
      includeSourceUrl(url, sourceUrls, domainCounts);
    }

    if (isSearchEvent) {
      searches.push({
        query: bundle?.query || toValueString(entry.event.details?.query).trim() || "web search",
        resultCount: sourceCandidateUrls.length,
        stepIndex: entry.event.step_index,
      });
      continue;
    }

    if (isReadEvent) {
      const readUrl = firstStringValue(
        bundle?.url,
        entry.event.details?.url,
        bundle?.documents[0]?.url,
        bundle?.sources[0]?.url,
        sourceCandidateUrls[0],
      );
      if (!readUrl) continue;

      includeSourceUrl(readUrl, sourceUrls, domainCounts);
      if (seenBrowseUrls.has(readUrl)) continue;
      seenBrowseUrls.add(readUrl);

      browses.push({
        url: readUrl,
        domain: normalizedDomain(readUrl) || "unknown",
        title: firstStringValue(bundle?.documents[0]?.title, bundle?.sources[0]?.title),
        stepIndex: entry.event.step_index,
      });
    }
  }

  for (const source of operatorSourceRefs) {
    const readUrl = firstStringValue(source.url);
    if (!readUrl) continue;
    includeSourceUrl(readUrl, sourceUrls, domainCounts);
    if (seenBrowseUrls.has(readUrl)) continue;
    seenBrowseUrls.add(readUrl);
    browses.push({
      url: readUrl,
      domain: firstStringValue(source.domain) || normalizedDomain(readUrl) || "unknown",
      title: firstStringValue(source.title),
      stepIndex: 0,
    });
  }

  const totalSources =
    sourceUrls.size > 0 ? sourceUrls.size : searches.reduce((sum, row) => sum + row.resultCount, 0);

  if (totalSources === 0 && searches.length === 0 && browses.length === 0) {
    return null;
  }

  const domains = Array.from(domainCounts.entries())
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, MAX_SOURCE_DOMAIN_PREVIEW)
    .map(([domain, count]) => ({
      domain,
      count,
      faviconUrl: faviconUrlForDomain(domain),
    }));

  return {
    totalSources,
    sourceUrls: Array.from(sourceUrls),
    domains,
    searches,
    browses,
  };
}

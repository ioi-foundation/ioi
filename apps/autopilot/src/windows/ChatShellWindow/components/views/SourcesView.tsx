import type { SourceBrowseRow, SourceSearchRow } from "../../../../types";
import { icons } from "../Icons";
import { ArtifactHubEmptyState } from "./shared/ArtifactHubEmptyState";

export function SourcesView({
  searches,
  browses,
  visibleSourceCount,
  openExternalUrl,
}: {
  searches: SourceSearchRow[];
  browses: SourceBrowseRow[];
  visibleSourceCount: number;
  openExternalUrl: (url: string) => Promise<void>;
}) {
  if (searches.length === 0 && browses.length === 0) {
    return <ArtifactHubEmptyState message="No evidence was captured for this run." />;
  }

  return (
    <div className="source-artifact-content">
      <div className="source-agent-header">
        <span className="source-agent-title">Evidence</span>
        <span className="source-agent-count">{visibleSourceCount}</span>
      </div>

      {searches.map((entry, index) => (
        <div className="source-row" key={`source-search-${index}`}>
          <span className="source-row-icon">{icons.search}</span>
          <div className="source-row-content">
            <span className="source-row-kind">Search</span>
            <span className="source-row-primary source-row-query">
              {entry.query}
            </span>
          </div>
          <span className="source-row-badge">{entry.resultCount}</span>
        </div>
      ))}

      {browses.map((entry, index) => (
        <div className="source-row" key={`source-browse-${index}`}>
          <span className="source-row-icon">{icons.globe}</span>
          <div className="source-row-content">
            <span className="source-row-kind">Opened source</span>
            <button
              className="source-row-link"
              onClick={() => void openExternalUrl(entry.url)}
              type="button"
              title={entry.url}
            >
              {entry.url}
            </button>
          </div>
        </div>
      ))}
    </div>
  );
}


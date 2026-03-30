import type { WorkspaceSearchPaneProps } from "../types";

export function WorkspaceSearchPane({
  searchDraft,
  searchLoading,
  searchError,
  searchResult,
  onSearchDraftChange,
  onRunSearch,
  onOpenMatch,
}: WorkspaceSearchPaneProps) {
  return (
    <section className="workspace-pane">
      <header className="workspace-pane-header">
        <div>
          <span className="workspace-pane-eyebrow">Workspace</span>
          <h3>Search</h3>
        </div>
      </header>

      <div className="workspace-search-box">
        <input
          type="search"
          value={searchDraft}
          onChange={(event) => onSearchDraftChange(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter") {
              event.preventDefault();
              onRunSearch();
            }
          }}
          placeholder="Search the project"
        />
        <button type="button" className="workspace-pane-button" onClick={onRunSearch}>
          Search
        </button>
      </div>

      {searchLoading ? <p className="workspace-pane-message">Searching project...</p> : null}
      {searchError ? <p className="workspace-pane-message">{searchError}</p> : null}

      {searchResult ? (
        <>
          <p className="workspace-pane-caption">
            {searchResult.totalMatches} matches across {searchResult.files.length} files
          </p>
          <div className="workspace-search-results">
            {searchResult.files.map((file) => (
              <section key={file.path} className="workspace-search-file">
                <header className="workspace-search-file-header">
                  <strong>{file.path}</strong>
                  <span>{file.matchCount}</span>
                </header>
                <div className="workspace-search-match-list">
                  {file.matches.map((match) => (
                    <button
                      key={`${match.path}:${match.line}:${match.column}`}
                      type="button"
                      className="workspace-search-match"
                      onClick={() => onOpenMatch(match)}
                    >
                      <span className="workspace-search-match-location">
                        {match.line}:{match.column}
                      </span>
                      <span className="workspace-search-match-preview">{match.preview}</span>
                    </button>
                  ))}
                </div>
              </section>
            ))}
          </div>
        </>
      ) : null}
    </section>
  );
}

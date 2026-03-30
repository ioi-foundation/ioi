import { humanize } from "./capabilities/model";
import { formatSettingsTime } from "./SettingsView.shared";
import type { SettingsViewBodyView } from "./SettingsView.types";

export function SettingsKnowledgeSection({
  view,
}: {
  view: SettingsViewBodyView;
}) {
  const {
    runtime,
    knowledgeCollections,
    knowledgeLoading,
    knowledgeBusy,
    knowledgeError,
    setKnowledgeError,
    knowledgeMessage,
    knowledgeCollectionName,
    setKnowledgeCollectionName,
    knowledgeCollectionDescription,
    setKnowledgeCollectionDescription,
    setSelectedKnowledgeCollectionId,
    knowledgeEntryTitle,
    setKnowledgeEntryTitle,
    knowledgeEntryContent,
    setKnowledgeEntryContent,
    knowledgeImportPath,
    setKnowledgeImportPath,
    knowledgeSourceUri,
    setKnowledgeSourceUri,
    knowledgeSourceInterval,
    setKnowledgeSourceInterval,
    knowledgeSearchQuery,
    setKnowledgeSearchQuery,
    knowledgeSearchResults,
    setKnowledgeSearchResults,
    knowledgeSearchLoading,
    setKnowledgeSearchLoading,
    knowledgeEntryLoading,
    setKnowledgeEntryLoading,
    selectedKnowledgeEntryContent,
    setSelectedKnowledgeEntryContent,
    selectedKnowledgeCollection,
    runKnowledgeAction,
  } = view;

  return (
    <div className="studio-settings-stack">
      <article className="studio-settings-card">
        <div className="studio-settings-card-head">
          <div>
            <span className="studio-settings-card-eyebrow">Knowledge</span>
            <h2>Collections and retrieval scopes</h2>
          </div>
          <span className="studio-settings-pill">
            {knowledgeCollections.length} collections
          </span>
        </div>
        <p className="studio-settings-body">
          LocalAI-style collections now land in `ioi-memory` as durable,
          embedding-backed knowledge entries. Each entry gets its own retrieval
          scope so agent IDE flows can target or exclude it cleanly.
        </p>
        {knowledgeMessage ? (
          <p className="studio-settings-success">{knowledgeMessage}</p>
        ) : null}
        {knowledgeError ? (
          <p className="studio-settings-error">{knowledgeError}</p>
        ) : null}
        <div className="studio-settings-profile-grid">
          <label className="studio-settings-field">
            <span>Collection name</span>
            <input
              value={knowledgeCollectionName}
              onChange={(event) => setKnowledgeCollectionName(event.target.value)}
              placeholder="research-notes"
            />
          </label>
          <label className="studio-settings-field studio-settings-field--wide">
            <span>Description</span>
            <input
              value={knowledgeCollectionDescription}
              onChange={(event) =>
                setKnowledgeCollectionDescription(event.target.value)
              }
              placeholder="What this collection is for"
            />
          </label>
        </div>
        <div className="studio-settings-actions">
          <button
            type="button"
            className="studio-settings-secondary"
            disabled={knowledgeBusy || knowledgeCollectionName.trim().length === 0}
            onClick={() =>
              void runKnowledgeAction(async () => {
                const created = await runtime.createKnowledgeCollection(
                  knowledgeCollectionName,
                  knowledgeCollectionDescription || null,
                );
                setKnowledgeCollectionName("");
                setKnowledgeCollectionDescription("");
                setSelectedKnowledgeCollectionId(created.collectionId);
              }, "Knowledge collection created.")
            }
          >
            {knowledgeBusy ? "Working..." : "Create collection"}
          </button>
        </div>
      </article>

      <article className="studio-settings-card">
        <div className="studio-settings-card-head">
          <div>
            <span className="studio-settings-card-eyebrow">Collections</span>
            <h2>Registry</h2>
          </div>
          <span className="studio-settings-pill">
            {knowledgeLoading ? "Loading" : `${knowledgeCollections.length} live`}
          </span>
        </div>
        {knowledgeLoading ? (
          <p className="studio-settings-body">Loading knowledge collections...</p>
        ) : knowledgeCollections.length === 0 ? (
          <p className="studio-settings-body">
            No knowledge collections exist yet. Create one above to begin
            ingesting files or durable notes.
          </p>
        ) : (
          <div className="studio-settings-summary-grid">
            {knowledgeCollections.map((collection) => (
              <button
                key={collection.collectionId}
                type="button"
                className={`studio-settings-subcard ${
                  selectedKnowledgeCollection?.collectionId ===
                  collection.collectionId
                    ? "is-live"
                    : ""
                }`}
                onClick={() => {
                  setSelectedKnowledgeCollectionId(collection.collectionId);
                  setKnowledgeSearchResults([]);
                  setSelectedKnowledgeEntryContent(null);
                }}
              >
                <strong>{collection.label}</strong>
                <span>{collection.entries.length} entries</span>
                <small>{collection.sources.length} sources</small>
                <p>{collection.description || collection.collectionId}</p>
              </button>
            ))}
          </div>
        )}
      </article>

      {selectedKnowledgeCollection ? (
        <article className="studio-settings-card">
          <div className="studio-settings-card-head">
            <div>
              <span className="studio-settings-card-eyebrow">
                Selected collection
              </span>
              <h2>{selectedKnowledgeCollection.label}</h2>
            </div>
            <span className="studio-settings-pill">
              {selectedKnowledgeCollection.entries.length} entries
            </span>
          </div>
          <p className="studio-settings-body">
            Scope root: <code>{selectedKnowledgeCollection.collectionId}</code>.
            Entries are kept as independent retrieval scopes for clean
            delete/reset semantics.
          </p>
          <div className="studio-settings-summary-grid">
            <article className="studio-settings-subcard">
              <strong>Entries</strong>
              <span>{selectedKnowledgeCollection.entries.length}</span>
            </article>
            <article className="studio-settings-subcard">
              <strong>Sources</strong>
              <span>{selectedKnowledgeCollection.sources.length}</span>
            </article>
            <article className="studio-settings-subcard">
              <strong>Updated</strong>
              <span>
                {formatSettingsTime(selectedKnowledgeCollection.updatedAtMs)}
              </span>
            </article>
            <article className="studio-settings-subcard">
              <strong>Created</strong>
              <span>
                {formatSettingsTime(selectedKnowledgeCollection.createdAtMs)}
              </span>
            </article>
          </div>
          <div className="studio-settings-actions">
            <button
              type="button"
              className="studio-settings-secondary"
              disabled={knowledgeBusy}
              onClick={() =>
                void runKnowledgeAction(
                  () =>
                    runtime.resetKnowledgeCollection(
                      selectedKnowledgeCollection.collectionId,
                    ),
                  "Knowledge collection reset.",
                )
              }
            >
              Reset collection
            </button>
            <button
              type="button"
              className="studio-settings-danger"
              disabled={knowledgeBusy}
              onClick={() =>
                void runKnowledgeAction(async () => {
                  await runtime.deleteKnowledgeCollection(
                    selectedKnowledgeCollection.collectionId,
                  );
                  setSelectedKnowledgeCollectionId(null);
                  setKnowledgeSearchResults([]);
                  setSelectedKnowledgeEntryContent(null);
                }, "Knowledge collection removed.")
              }
            >
              Delete collection
            </button>
          </div>
        </article>
      ) : null}

      {selectedKnowledgeCollection ? (
        <article className="studio-settings-card">
          <div className="studio-settings-card-head">
            <div>
              <span className="studio-settings-card-eyebrow">Ingestion</span>
              <h2>Add entries</h2>
            </div>
            <span className="studio-settings-pill">Retrieval-ready</span>
          </div>
          <div className="studio-settings-profile-grid">
            <label className="studio-settings-field">
              <span>Entry title</span>
              <input
                value={knowledgeEntryTitle}
                onChange={(event) => setKnowledgeEntryTitle(event.target.value)}
                placeholder="Q2 launch notes"
              />
            </label>
            <label className="studio-settings-field studio-settings-field--wide">
              <span>Note content</span>
              <textarea
                value={knowledgeEntryContent}
                onChange={(event) => setKnowledgeEntryContent(event.target.value)}
                placeholder="Paste durable knowledge or procedure notes here."
                rows={6}
              />
            </label>
            <div className="studio-settings-actions">
              <button
                type="button"
                className="studio-settings-secondary"
                disabled={
                  knowledgeBusy ||
                  knowledgeEntryTitle.trim().length === 0 ||
                  knowledgeEntryContent.trim().length === 0
                }
                onClick={() =>
                  void runKnowledgeAction(async () => {
                    await runtime.addKnowledgeTextEntry(
                      selectedKnowledgeCollection.collectionId,
                      knowledgeEntryTitle,
                      knowledgeEntryContent,
                    );
                    setKnowledgeEntryTitle("");
                    setKnowledgeEntryContent("");
                  }, "Knowledge note ingested.")
                }
              >
                Add text entry
              </button>
            </div>
          </div>
          <div className="studio-settings-profile-grid">
            <label className="studio-settings-field studio-settings-field--wide">
              <span>Import file path</span>
              <input
                value={knowledgeImportPath}
                onChange={(event) => setKnowledgeImportPath(event.target.value)}
                placeholder="/abs/path/to/doc.md"
              />
            </label>
            <div className="studio-settings-actions">
              <button
                type="button"
                className="studio-settings-secondary"
                disabled={knowledgeBusy || knowledgeImportPath.trim().length === 0}
                onClick={() =>
                  void runKnowledgeAction(async () => {
                    await runtime.importKnowledgeFile(
                      selectedKnowledgeCollection.collectionId,
                      knowledgeImportPath,
                    );
                    setKnowledgeImportPath("");
                  }, "Knowledge file imported.")
                }
              >
                Import file
              </button>
            </div>
          </div>
        </article>
      ) : null}

      {selectedKnowledgeCollection ? (
        <article className="studio-settings-card">
          <div className="studio-settings-card-head">
            <div>
              <span className="studio-settings-card-eyebrow">Sources</span>
              <h2>Registered source endpoints</h2>
            </div>
            <span className="studio-settings-pill">
              {selectedKnowledgeCollection.sources.length} configured
            </span>
          </div>
          <div className="studio-settings-profile-grid">
            <label className="studio-settings-field studio-settings-field--wide">
              <span>Source URI or path</span>
              <input
                value={knowledgeSourceUri}
                onChange={(event) => setKnowledgeSourceUri(event.target.value)}
                placeholder="https://docs.example.com or /data/docs"
              />
            </label>
            <label className="studio-settings-field">
              <span>Poll interval minutes</span>
              <input
                value={knowledgeSourceInterval}
                onChange={(event) =>
                  setKnowledgeSourceInterval(event.target.value)
                }
                placeholder="60"
              />
            </label>
          </div>
          <div className="studio-settings-actions">
            <button
              type="button"
              className="studio-settings-secondary"
              disabled={knowledgeBusy || knowledgeSourceUri.trim().length === 0}
              onClick={() =>
                void runKnowledgeAction(async () => {
                  await runtime.addKnowledgeCollectionSource(
                    selectedKnowledgeCollection.collectionId,
                    knowledgeSourceUri,
                    knowledgeSourceInterval.trim().length > 0
                      ? Number(knowledgeSourceInterval)
                      : null,
                  );
                  setKnowledgeSourceUri("");
                  setKnowledgeSourceInterval("");
                }, "Knowledge source registered.")
              }
            >
              Add source
            </button>
          </div>
          <div className="studio-settings-stack studio-settings-stack--compact">
            {selectedKnowledgeCollection.sources.length === 0 ? (
              <p className="studio-settings-body">
                No recurring sources are registered for this collection yet.
              </p>
            ) : (
              selectedKnowledgeCollection.sources.map((source) => (
                <article key={source.sourceId} className="studio-settings-subcard">
                  <div className="studio-settings-subcard-head">
                    <strong>{source.uri}</strong>
                    <span>{humanize(source.syncStatus)}</span>
                  </div>
                  <div className="studio-settings-chip-row">
                    <span className="studio-settings-chip">
                      {humanize(source.kind)}
                    </span>
                    <span className="studio-settings-chip">
                      {source.enabled ? "Enabled" : "Disabled"}
                    </span>
                    {source.pollIntervalMinutes ? (
                      <span className="studio-settings-chip">
                        Every {source.pollIntervalMinutes} min
                      </span>
                    ) : null}
                  </div>
                  <div className="studio-settings-actions">
                    <button
                      type="button"
                      className="studio-settings-secondary"
                      disabled={knowledgeBusy}
                      onClick={() =>
                        void runKnowledgeAction(
                          () =>
                            runtime.removeKnowledgeCollectionSource(
                              selectedKnowledgeCollection.collectionId,
                              source.sourceId,
                            ),
                          "Knowledge source removed.",
                        )
                      }
                    >
                      Remove source
                    </button>
                  </div>
                </article>
              ))
            )}
          </div>
        </article>
      ) : null}

      {selectedKnowledgeCollection ? (
        <article className="studio-settings-card">
          <div className="studio-settings-card-head">
            <div>
              <span className="studio-settings-card-eyebrow">Search</span>
              <h2>Collection retrieval check</h2>
            </div>
            <span className="studio-settings-pill">Hybrid</span>
          </div>
          <div className="studio-settings-profile-grid">
            <label className="studio-settings-field studio-settings-field--wide">
              <span>Search query</span>
              <input
                value={knowledgeSearchQuery}
                onChange={(event) => setKnowledgeSearchQuery(event.target.value)}
                placeholder="What does this collection know about..."
              />
            </label>
          </div>
          <div className="studio-settings-actions">
            <button
              type="button"
              className="studio-settings-secondary"
              disabled={
                knowledgeSearchLoading || knowledgeSearchQuery.trim().length === 0
              }
              onClick={async () => {
                setKnowledgeSearchLoading(true);
                setKnowledgeError(null);
                try {
                  const results = await runtime.searchKnowledgeCollection(
                    selectedKnowledgeCollection.collectionId,
                    knowledgeSearchQuery,
                    8,
                  );
                  setKnowledgeSearchResults(results);
                } catch (nextError) {
                  setKnowledgeError(String(nextError));
                } finally {
                  setKnowledgeSearchLoading(false);
                }
              }}
            >
              {knowledgeSearchLoading ? "Searching..." : "Search collection"}
            </button>
          </div>
          <div className="studio-settings-stack studio-settings-stack--compact">
            {knowledgeSearchResults.map((result) => (
              <article
                key={`${result.archivalRecordId}-${result.entryId}`}
                className="studio-settings-subcard"
              >
                <div className="studio-settings-subcard-head">
                  <strong>{result.title}</strong>
                  <span>{Math.round(result.score * 100)}%</span>
                </div>
                <div className="studio-settings-chip-row">
                  <span className="studio-settings-chip">{result.entryId}</span>
                  <span className="studio-settings-chip">{result.trustLevel}</span>
                  <span className="studio-settings-chip">{result.scope}</span>
                </div>
                <p>{result.snippet}</p>
              </article>
            ))}
            {!knowledgeSearchLoading &&
            knowledgeSearchQuery.trim().length > 0 &&
            knowledgeSearchResults.length === 0 ? (
              <p className="studio-settings-body">
                No hits yet for this query in the selected collection.
              </p>
            ) : null}
          </div>
        </article>
      ) : null}

      {selectedKnowledgeCollection ? (
        <article className="studio-settings-card">
          <div className="studio-settings-card-head">
            <div>
              <span className="studio-settings-card-eyebrow">Entries</span>
              <h2>Stored artifacts and scopes</h2>
            </div>
            <span className="studio-settings-pill">
              {selectedKnowledgeCollection.entries.length} stored
            </span>
          </div>
          <div className="studio-settings-stack studio-settings-stack--compact">
            {selectedKnowledgeCollection.entries.length === 0 ? (
              <p className="studio-settings-body">
                This collection does not have any entries yet.
              </p>
            ) : (
              selectedKnowledgeCollection.entries.map((entry) => (
                <article key={entry.entryId} className="studio-settings-subcard">
                  <div className="studio-settings-subcard-head">
                    <strong>{entry.title}</strong>
                    <span>{humanize(entry.kind)}</span>
                  </div>
                  <div className="studio-settings-chip-row">
                    <span className="studio-settings-chip">{entry.scope}</span>
                    <span className="studio-settings-chip">
                      {entry.chunkCount} chunks
                    </span>
                    <span className="studio-settings-chip">
                      {entry.byteCount} bytes
                    </span>
                  </div>
                  <p>{entry.contentPreview}</p>
                  <div className="studio-settings-actions">
                    <button
                      type="button"
                      className="studio-settings-secondary"
                      disabled={knowledgeEntryLoading}
                      onClick={async () => {
                        setKnowledgeEntryLoading(true);
                        setKnowledgeError(null);
                        try {
                          const content =
                            await runtime.getKnowledgeCollectionEntryContent(
                              selectedKnowledgeCollection.collectionId,
                              entry.entryId,
                            );
                          setSelectedKnowledgeEntryContent(content);
                        } catch (nextError) {
                          setKnowledgeError(String(nextError));
                        } finally {
                          setKnowledgeEntryLoading(false);
                        }
                      }}
                    >
                      {knowledgeEntryLoading ? "Opening..." : "Open entry"}
                    </button>
                    <button
                      type="button"
                      className="studio-settings-danger"
                      disabled={knowledgeBusy}
                      onClick={() =>
                        void runKnowledgeAction(
                          async () => {
                            await runtime.removeKnowledgeCollectionEntry(
                              selectedKnowledgeCollection.collectionId,
                              entry.entryId,
                            );
                            if (
                              selectedKnowledgeEntryContent?.entryId ===
                              entry.entryId
                            ) {
                              setSelectedKnowledgeEntryContent(null);
                            }
                          },
                          "Knowledge entry removed.",
                        )
                      }
                    >
                      Remove entry
                    </button>
                  </div>
                </article>
              ))
            )}
          </div>
        </article>
      ) : null}

      {selectedKnowledgeEntryContent ? (
        <article className="studio-settings-card">
          <div className="studio-settings-card-head">
            <div>
              <span className="studio-settings-card-eyebrow">Entry content</span>
              <h2>{selectedKnowledgeEntryContent.title}</h2>
            </div>
            <span className="studio-settings-pill">
              {selectedKnowledgeEntryContent.byteCount} bytes
            </span>
          </div>
          <label className="studio-settings-field studio-settings-field--wide">
            <span>Materialized artifact</span>
            <textarea
              value={selectedKnowledgeEntryContent.content}
              readOnly
              rows={12}
            />
          </label>
        </article>
      ) : null}
    </div>
  );
}

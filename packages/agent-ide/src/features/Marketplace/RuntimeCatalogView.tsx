import { useState, useEffect } from "react";
import { AgentWorkbenchRuntime, RuntimeCatalogEntry } from "../../runtime/agent-runtime";
import "./RuntimeCatalogView.css";

interface RuntimeCatalogViewProps {
  runtime: AgentWorkbenchRuntime;
  onStageEntry: (entry: RuntimeCatalogEntry) => void;
}

export function RuntimeCatalogView({
  runtime,
  onStageEntry,
}: RuntimeCatalogViewProps) {
  const [entries, setEntries] = useState<RuntimeCatalogEntry[]>([]);
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;

    setLoading(true);
    setError(null);
    runtime
      .getRuntimeCatalogEntries()
      .then((items) => {
        if (!active) return;
        setEntries(items);
      })
      .catch((nextError) => {
        if (!active) return;
        setError(String(nextError));
        setEntries([]);
      })
      .finally(() => {
        if (!active) return;
        setLoading(false);
      });

    return () => {
      active = false;
    };
  }, [runtime]);

  const filtered = entries.filter((entry) =>
    entry.name.toLowerCase().includes(search.toLowerCase()),
  );

  return (
    <div className="runtime-catalog-view">
      <div className="catalog-header">
        <h1>Runtime Catalog</h1>
        <input 
            type="text" 
            placeholder="Search runtime entries..." 
            className="catalog-search" 
            value={search}
            onChange={e => setSearch(e.target.value)}
        />
      </div>
      
      <div className="catalog-grid">
        {loading ? <p>Loading live runtime catalog…</p> : null}
        {error ? <p>{error}</p> : null}
        {filtered.map((entry) => (
          <div
            key={entry.id}
            className="catalog-card"
            onClick={() => onStageEntry(entry)}
          >
            <div className="catalog-card-visual">
               <div className="catalog-card-icon">{entry.icon || "📦"}</div>
            </div>
            <div className="catalog-card-info">
              <h3>{entry.name}</h3>
              <p className="catalog-card-owner">{entry.ownerLabel}</p>
              <p className="catalog-card-description">{entry.description}</p>
              <div className="catalog-card-footer">
                <span className="catalog-card-kind">{entry.entryKind}</span>
                <span className="catalog-card-status">
                  {entry.statusLabel ?? entry.runtimeNotes}
                </span>
              </div>
              <small className="catalog-card-notes">{entry.runtimeNotes}</small>
            </div>
          </div>
        ))}
        {!loading && !error && filtered.length === 0 ? (
          <p>No live runtime entries matched this search.</p>
        ) : null}
      </div>
    </div>
  );
}

import {
  startTransition,
  useDeferredValue,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { TauriRuntime } from "../../../services/TauriRuntime";
import { ContextAtlasGraph3D } from "../../../components/ContextAtlasGraph3D";
import type {
  ActiveContextItem,
  ActiveContextSnapshot,
  AtlasNeighborhood,
  AtlasNode,
  AtlasSearchResult,
  ContextAtlasFocusRequest,
  ContextAtlasLens,
  ContextAtlasMode,
  SkillCatalogEntry,
  SkillDetailView,
  SubstrateProofView,
} from "../../../types";

const LENSES: ContextAtlasLens[] = ["Context", "Skills", "Substrate"];
const MODES: ContextAtlasMode[] = ["List", "Split", "3D"];

function lensToApiLens(lens: ContextAtlasLens): string {
  return lens.toLowerCase();
}

function badgeValue(...values: Array<string | null | undefined>): string {
  return values.filter(Boolean).join(" · ");
}

function skillHashFromFocusId(focusId: string | null): string | null {
  if (!focusId || !focusId.startsWith("skill:")) return null;
  return focusId.slice("skill:".length);
}

function prettyMetadata(value: unknown): string {
  return JSON.stringify(value ?? {}, null, 2);
}

function InspectorSection({
  title,
  children,
}: {
  title: string;
  children: ReactNode;
}) {
  return (
    <section className="context-atlas-inspector-section">
      <h4>{title}</h4>
      {children}
    </section>
  );
}

function ContextItemList({
  title,
  items,
  selectedId,
  onSelect,
}: {
  title: string;
  items: ActiveContextItem[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}) {
  if (items.length === 0) return null;

  return (
    <section className="context-atlas-list-group">
      <div className="context-atlas-list-group-head">
        <h3>{title}</h3>
        <span>{items.length}</span>
      </div>
      <div className="context-atlas-rows">
        {items.map((item) => {
          const targetId = item.focus_id || item.id;
          return (
            <button
              key={item.id}
              className={`context-atlas-row ${selectedId === targetId ? "selected" : ""}`}
              onClick={() => onSelect(targetId)}
              type="button"
            >
              <div className="context-atlas-row-head">
                <span className="context-atlas-row-title">{item.title}</span>
                <span className="context-atlas-row-badge">
                  {badgeValue(item.badge, item.secondary_badge)}
                </span>
              </div>
              <p>{item.summary}</p>
            </button>
          );
        })}
      </div>
    </section>
  );
}

export function ContextAtlasView({
  runtime,
  request,
}: {
  runtime: TauriRuntime;
  request?: ContextAtlasFocusRequest | null;
}) {
  const [lens, setLens] = useState<ContextAtlasLens>("Skills");
  const [mode, setMode] = useState<ContextAtlasMode>("Split");
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [focusId, setFocusId] = useState<string | null>(null);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [skillCatalog, setSkillCatalog] = useState<SkillCatalogEntry[]>([]);
  const [activeContext, setActiveContext] = useState<ActiveContextSnapshot | null>(null);
  const [substrate, setSubstrate] = useState<SubstrateProofView | null>(null);
  const [neighborhood, setNeighborhood] = useState<AtlasNeighborhood>({
    lens: "skills",
    title: "Evidence Atlas",
    summary: "",
    nodes: [],
    edges: [],
  });
  const [searchResults, setSearchResults] = useState<AtlasSearchResult[]>([]);
  const [selectedSkillDetail, setSelectedSkillDetail] = useState<SkillDetailView | null>(null);

  const deferredQuery = useDeferredValue(query);

  useEffect(() => {
    if (!request) return;
    if (request.lens) {
      setLens(request.lens);
    }
    if (request.mode) {
      setMode(request.mode);
    }
    if (request.sessionId !== undefined) {
      setSessionId(request.sessionId ?? null);
    }
    if (request.focusId !== undefined) {
      setFocusId(request.focusId ?? null);
      setSelectedNodeId(request.focusId ?? null);
    }
  }, [request]);

  useEffect(() => {
    let cancelled = false;

    async function loadLensState() {
      setLoading(true);
      setError(null);
      try {
        if (lens === "Context") {
          if (!sessionId) {
            startTransition(() => {
              setActiveContext(null);
              setSubstrate(null);
              setNeighborhood({
                lens: "context",
                title: "Active Context",
                summary: "Select a run or session to inspect turn-local memory, skills, and evidence.",
                nodes: [],
                edges: [],
              });
            });
            return;
          }
          const snapshot = await runtime.getActiveContext(sessionId);
          if (cancelled) return;
          startTransition(() => {
            setActiveContext(snapshot);
            setSubstrate(snapshot.substrate ?? null);
            setNeighborhood(snapshot.neighborhood);
            const nextFocus =
              focusId && snapshot.neighborhood.nodes.some((node) => node.id === focusId)
                ? focusId
                : snapshot.active_skill_id || snapshot.focus_id;
            setSelectedNodeId(nextFocus || null);
          });
          return;
        }

        if (lens === "Substrate") {
          const proof = await runtime.getSubstrateProof({
            sessionId,
            skillHash: skillHashFromFocusId(focusId),
          });
          if (cancelled) return;
          startTransition(() => {
            setSubstrate(proof);
            setActiveContext(null);
            setNeighborhood(proof.neighborhood);
            setSelectedNodeId(
              focusId && proof.neighborhood.nodes.some((node) => node.id === focusId)
                ? focusId
                : proof.neighborhood.focus_id || null,
            );
          });
          return;
        }

        const [catalog, skillNeighborhood] = await Promise.all([
          runtime.getSkillCatalog(),
          runtime.getAtlasNeighborhood({
            focusId,
            lens: lensToApiLens(lens),
          }),
        ]);
        if (cancelled) return;
        startTransition(() => {
          setSkillCatalog(catalog);
          setActiveContext(null);
          setSubstrate(null);
          setNeighborhood(skillNeighborhood);
          const nextFocus =
            focusId && skillNeighborhood.nodes.some((node) => node.id === focusId)
              ? focusId
              : skillNeighborhood.focus_id || null;
          setSelectedNodeId(nextFocus);
        });
      } catch (loadError) {
        if (cancelled) return;
        setError(String(loadError));
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }

    void loadLensState();
    return () => {
      cancelled = true;
    };
  }, [focusId, lens, runtime, sessionId]);

  useEffect(() => {
    let cancelled = false;
    const skillHash = skillHashFromFocusId(selectedNodeId);
    if (!skillHash) {
      setSelectedSkillDetail(null);
      return;
    }

    runtime.getSkillDetail(skillHash).then((detail) => {
      if (cancelled) return;
      setSelectedSkillDetail(detail);
    }).catch(() => {
      if (!cancelled) {
        setSelectedSkillDetail(null);
      }
    });

    return () => {
      cancelled = true;
    };
  }, [runtime, selectedNodeId]);

  useEffect(() => {
    let cancelled = false;
    if (!deferredQuery.trim()) {
      setSearchResults([]);
      return;
    }

    runtime.searchAtlas(deferredQuery, lensToApiLens(lens)).then((results) => {
      if (cancelled) return;
      startTransition(() => {
        setSearchResults(results);
      });
    }).catch(() => {
      if (!cancelled) {
        setSearchResults([]);
      }
    });

    return () => {
      cancelled = true;
    };
  }, [deferredQuery, lens, runtime]);

  const selectedNode = useMemo<AtlasNode | null>(
    () => neighborhood.nodes.find((node) => node.id === selectedNodeId) || null,
    [neighborhood.nodes, selectedNodeId],
  );

  const skillsList = useMemo(() => {
    if (searchResults.length > 0) {
      return searchResults
        .filter((result) => result.kind === "skill")
        .map((result) => ({
          nodeId: result.id,
          name: result.title,
          description: result.summary,
          lifecycle: "Matched",
          source: result.kind,
        }));
    }
    return skillCatalog.map((entry) => ({
      nodeId: `skill:${entry.skill_hash}`,
      name: entry.name,
      description: entry.description,
      lifecycle: entry.lifecycle_state,
      source: entry.source_type,
    }));
  }, [searchResults, skillCatalog]);

  const graphTitle =
    lens === "Context"
      ? activeContext?.goal || "Active Context"
      : lens === "Substrate"
        ? substrate?.summary || "Substrate"
        : neighborhood.title;

  const renderListPane = () => {
    if (lens === "Context") {
      return (
        <div className="context-atlas-list-pane">
          <ContextItemList
            title="Skills"
            items={activeContext?.skills || []}
            selectedId={selectedNodeId}
            onSelect={setSelectedNodeId}
          />
          <ContextItemList
            title="Tools"
            items={activeContext?.tools || []}
            selectedId={selectedNodeId}
            onSelect={setSelectedNodeId}
          />
          <ContextItemList
            title="Evidence"
            items={activeContext?.evidence || []}
            selectedId={selectedNodeId}
            onSelect={setSelectedNodeId}
          />
          {(activeContext?.constraints.length || 0) > 0 && (
            <section className="context-atlas-list-group">
              <div className="context-atlas-list-group-head">
                <h3>Constraints</h3>
                <span>{activeContext?.constraints.length || 0}</span>
              </div>
              <div className="context-atlas-rows">
                {(activeContext?.constraints || []).map((constraint) => (
                  <button
                    key={constraint.id}
                    className={`context-atlas-row ${selectedNodeId === `constraint:${constraint.id}` ? "selected" : ""}`}
                    onClick={() => setSelectedNodeId(`constraint:${constraint.id}`)}
                    type="button"
                  >
                    <div className="context-atlas-row-head">
                      <span className="context-atlas-row-title">{constraint.label}</span>
                      <span className="context-atlas-row-badge">{constraint.severity}</span>
                    </div>
                    <p>{constraint.summary}</p>
                  </button>
                ))}
              </div>
            </section>
          )}
          {(activeContext?.recent_actions.length || 0) > 0 && (
            <section className="context-atlas-list-group">
              <div className="context-atlas-list-group-head">
                <h3>Recent Actions</h3>
                <span>{activeContext?.recent_actions.length || 0}</span>
              </div>
              <div className="context-atlas-actions-list">
                {(activeContext?.recent_actions || []).map((action, index) => (
                  <div className="context-atlas-action-chip" key={`${index}:${action}`}>
                    {action}
                  </div>
                ))}
              </div>
            </section>
          )}
        </div>
      );
    }

    if (lens === "Substrate") {
      return (
        <div className="context-atlas-list-pane">
          <section className="context-atlas-list-group">
            <div className="context-atlas-list-group-head">
              <h3>Receipts</h3>
              <span>{substrate?.receipts.length || 0}</span>
            </div>
            <div className="context-atlas-rows">
              {(substrate?.receipts || []).map((receipt) => {
                const queryNodeId = `query:${receipt.query_hash}`;
                return (
                  <button
                    key={receipt.event_id}
                    className={`context-atlas-row ${selectedNodeId === queryNodeId ? "selected" : ""}`}
                    onClick={() => setSelectedNodeId(queryNodeId)}
                    type="button"
                  >
                    <div className="context-atlas-row-head">
                      <span className="context-atlas-row-title">{receipt.tool_name}</span>
                      <span className="context-atlas-row-badge">
                        {receipt.success ? "success" : "failure"}
                      </span>
                    </div>
                    <p>
                      k={receipt.k} · ef={receipt.ef_search} · root=
                      {receipt.index_root.slice(0, 12)}
                    </p>
                  </button>
                );
              })}
            </div>
          </section>
        </div>
      );
    }

    return (
      <div className="context-atlas-list-pane">
        <section className="context-atlas-list-group">
          <div className="context-atlas-list-group-head">
            <h3>{searchResults.length > 0 ? "Search Results" : "Skill Catalog"}</h3>
            <span>{skillsList.length}</span>
          </div>
          <div className="context-atlas-rows">
            {skillsList.map((entry) => {
              const nodeId = entry.nodeId;
              return (
                <button
                  key={nodeId}
                  className={`context-atlas-row ${selectedNodeId === nodeId ? "selected" : ""}`}
                  onClick={() => {
                    setFocusId(nodeId);
                    setSelectedNodeId(nodeId);
                  }}
                  type="button"
                >
                  <div className="context-atlas-row-head">
                    <span className="context-atlas-row-title">{entry.name}</span>
                    <span className="context-atlas-row-badge">
                      {badgeValue(entry.lifecycle, entry.source)}
                    </span>
                  </div>
                  <p>{entry.description}</p>
                </button>
              );
            })}
          </div>
        </section>
      </div>
    );
  };

  return (
    <div className="context-atlas-shell">
      <aside className="context-atlas-sidebar">
        <div className="context-atlas-sidebar-head">
          <span className="context-atlas-kicker">Evidence Atlas</span>
          <h2>Context Atlas</h2>
          <p>
            Explore the active context, durable skill catalog, and substrate proof layer through a
            single typed graph.
          </p>
        </div>

        <div className="context-atlas-controls">
          <div className="context-atlas-toggle-group">
            {LENSES.map((candidateLens) => (
              <button
                key={candidateLens}
                className={lens === candidateLens ? "active" : ""}
                onClick={() => setLens(candidateLens)}
                type="button"
              >
                {candidateLens}
              </button>
            ))}
          </div>
          <div className="context-atlas-toggle-group">
            {MODES.map((candidateMode) => (
              <button
                key={candidateMode}
                className={mode === candidateMode ? "active" : ""}
                onClick={() => setMode(candidateMode)}
                type="button"
              >
                {candidateMode}
              </button>
            ))}
          </div>
        </div>

        <label className="context-atlas-search">
          <span>Search Atlas</span>
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="skills, evidence, docs"
          />
        </label>

        <div className="context-atlas-sidebar-summary">
          <div>
            <span>Session</span>
            <strong>{sessionId || "none"}</strong>
          </div>
          <div>
            <span>Focus</span>
            <strong>{focusId || selectedNodeId || neighborhood.focus_id || "none"}</strong>
          </div>
          <div>
            <span>Scope</span>
            <strong>{graphTitle}</strong>
          </div>
        </div>

        {(loading || error) && (
          <div className="context-atlas-status">
            {loading && <span>Loading atlas context…</span>}
            {!!error && <span>{error}</span>}
          </div>
        )}
      </aside>

      <main className={`context-atlas-main context-atlas-main--${mode.toLowerCase()}`}>
        {mode !== "3D" && renderListPane()}
        {mode !== "List" && (
          <div className="context-atlas-graph-pane">
            <ContextAtlasGraph3D
              neighborhood={neighborhood}
              onSelectNode={setSelectedNodeId}
              title={graphTitle}
            />
          </div>
        )}
      </main>

      <aside className="context-atlas-inspector">
        <div className="context-atlas-inspector-head">
          <span className="context-atlas-kicker">Inspector</span>
          <h3>{selectedNode?.label || "Select a node"}</h3>
          <p>{selectedNode?.summary || "Choose a node from the list or 3D graph."}</p>
        </div>

        {selectedSkillDetail ? (
          <>
            <InspectorSection title="Lifecycle">
              <div className="context-atlas-metadata-grid">
                <div>
                  <span>State</span>
                  <strong>{selectedSkillDetail.lifecycle_state}</strong>
                </div>
                <div>
                  <span>Source</span>
                  <strong>{selectedSkillDetail.source_type}</strong>
                </div>
                <div>
                  <span>Success</span>
                  <strong>{selectedSkillDetail.success_rate_bps} bps</strong>
                </div>
                <div>
                  <span>Samples</span>
                  <strong>{selectedSkillDetail.sample_size}</strong>
                </div>
              </div>
            </InspectorSection>
            <InspectorSection title="Tools">
              <div className="context-atlas-actions-list">
                {selectedSkillDetail.used_tools.map((toolName) => (
                  <div className="context-atlas-action-chip" key={toolName}>
                    {toolName}
                  </div>
                ))}
              </div>
            </InspectorSection>
            <InspectorSection title="Macro Steps">
              <div className="context-atlas-step-list">
                {selectedSkillDetail.steps.map((step) => (
                  <article className="context-atlas-step-card" key={`${step.index}:${step.tool_name}`}>
                    <header>
                      <span>#{step.index + 1}</span>
                      <strong>{step.tool_name}</strong>
                    </header>
                    <pre>{prettyMetadata(step.params_json)}</pre>
                  </article>
                ))}
              </div>
            </InspectorSection>
            {selectedSkillDetail.markdown && (
              <InspectorSection title="Published Doc">
                <pre className="context-atlas-pre">{selectedSkillDetail.markdown}</pre>
              </InspectorSection>
            )}
          </>
        ) : selectedNode ? (
          <>
            <InspectorSection title="Node">
              <div className="context-atlas-metadata-grid">
                <div>
                  <span>Kind</span>
                  <strong>{selectedNode.kind}</strong>
                </div>
                <div>
                  <span>Status</span>
                  <strong>{selectedNode.status || "n/a"}</strong>
                </div>
              </div>
            </InspectorSection>
            <InspectorSection title="Metadata">
              <pre className="context-atlas-pre">{prettyMetadata(selectedNode.metadata)}</pre>
            </InspectorSection>
          </>
        ) : null}
      </aside>
    </div>
  );
}

import { invoke } from "@tauri-apps/api/core";
import { useEffect, useState } from "react";
import type { AgentRuntime } from "@ioi/agent-ide";
import type { AssistantWorkbenchSession } from "../../../types";
import { MissionControlChatView } from "./MissionControlChatView";

type UtilityTab = "operator" | "explorer" | "artifacts";

interface ProjectScope {
  id: string;
  name: string;
  description: string;
  environment: string;
  rootPath: string;
}

interface ProjectGitStatus {
  is_repo: boolean;
  branch: string | null;
  dirty: boolean;
  last_commit: string | null;
}

interface ProjectExplorerNode {
  name: string;
  path: string;
  kind: string;
  children: ProjectExplorerNode[];
}

interface ProjectArtifactCandidate {
  title: string;
  path: string;
  artifact_type: string;
}

interface ProjectShellSnapshot {
  root_path: string;
  git: ProjectGitStatus;
  tree: ProjectExplorerNode[];
  artifacts: ProjectArtifactCandidate[];
}

interface StudioLeftUtilityPaneProps {
  currentProject: ProjectScope;
  activeTab: UtilityTab;
  onTabChange: (tab: UtilityTab) => void;
  onClose: () => void;
  surface: "chat" | "reply-composer" | "meeting-prep";
  session: AssistantWorkbenchSession | null;
  runtime: AgentRuntime;
  seedIntent?: string | null;
  onConsumeSeedIntent?: () => void;
  onBackToInbox: () => void;
  onOpenInbox: () => void;
  onOpenAutopilot: (intent: string) => void;
}

function renderTree(nodes: ProjectExplorerNode[], depth = 0) {
  return nodes.map((node) => (
    <div key={`${node.kind}:${node.path}`} className="studio-utility-tree-group">
      <div
        className={`studio-utility-tree-row ${
          node.kind === "directory" ? "is-directory" : "is-file"
        }`}
        style={{ paddingLeft: `${12 + depth * 16}px` }}
      >
        <span className="studio-utility-tree-name">{node.name}</span>
        <span className="studio-utility-tree-path">{node.path}</span>
      </div>
      {node.children.length > 0 ? renderTree(node.children, depth + 1) : null}
    </div>
  ));
}

function tabDescription(tab: UtilityTab): string {
  if (tab === "explorer") return "Project explorer";
  if (tab === "artifacts") return "Project artifacts";
  return "Operator lane";
}

export function StudioLeftUtilityPane({
  currentProject,
  activeTab,
  onTabChange,
  onClose,
  surface,
  session,
  runtime,
  seedIntent,
  onConsumeSeedIntent,
  onBackToInbox,
  onOpenInbox,
  onOpenAutopilot,
}: StudioLeftUtilityPaneProps) {
  const [snapshot, setSnapshot] = useState<ProjectShellSnapshot | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [initBusy, setInitBusy] = useState(false);

  useEffect(() => {
    if (activeTab === "operator") return;

    let cancelled = false;
    setLoading(true);
    setError(null);

    void invoke<ProjectShellSnapshot>("project_shell_inspect", {
      root: currentProject.rootPath,
    })
      .then((result) => {
        if (!cancelled) {
          setSnapshot(result);
        }
      })
      .catch((nextError) => {
        if (!cancelled) {
          setError(String(nextError));
          setSnapshot(null);
        }
      })
      .finally(() => {
        if (!cancelled) {
          setLoading(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [activeTab, currentProject.rootPath]);

  const initializeRepository = async () => {
    setInitBusy(true);
    setError(null);
    try {
      const result = await invoke<ProjectShellSnapshot>(
        "project_initialize_repository",
        {
          root: currentProject.rootPath,
        },
      );
      setSnapshot(result);
    } catch (nextError) {
      setError(String(nextError));
    } finally {
      setInitBusy(false);
    }
  };

  return (
    <aside className="studio-left-utility-pane" aria-label="Project utilities">
      <div className="studio-left-utility-header">
        <div className="studio-left-utility-copy">
          <span className="studio-left-utility-kicker">Utilities</span>
          <strong>{tabDescription(activeTab)}</strong>
          <p>{currentProject.name}</p>
        </div>
        <button
          type="button"
          className="studio-left-utility-close"
          onClick={onClose}
        >
          Hide
        </button>
      </div>

      <div className="studio-left-utility-tabs" role="tablist" aria-label="Utility tabs">
        {(["operator", "explorer", "artifacts"] as UtilityTab[]).map((tab) => (
          <button
            key={tab}
            type="button"
            role="tab"
            aria-selected={activeTab === tab}
            className={`studio-left-utility-tab ${
              activeTab === tab ? "is-active" : ""
            }`}
            onClick={() => onTabChange(tab)}
          >
            {tab === "operator"
              ? "Operator"
              : tab === "explorer"
                ? "Explorer"
                : "Artifacts"}
          </button>
        ))}
      </div>

      <div className="studio-left-utility-body">
        {activeTab === "operator" ? (
          <MissionControlChatView
            embedded
            surface={surface}
            session={session}
            runtime={runtime}
            seedIntent={seedIntent}
            onConsumeSeedIntent={onConsumeSeedIntent}
            onBackToInbox={onBackToInbox}
            onOpenInbox={onOpenInbox}
            onOpenAutopilot={onOpenAutopilot}
          />
        ) : null}

        {activeTab === "explorer" ? (
          <div className="studio-left-utility-panel">
            <section className="studio-left-utility-card">
              <div className="studio-left-utility-card-head">
                <strong>Project root</strong>
                <span>{currentProject.environment}</span>
              </div>
              <p>{snapshot?.root_path || currentProject.rootPath}</p>
            </section>

            <section className="studio-left-utility-card">
              <div className="studio-left-utility-card-head">
                <strong>Repository</strong>
                <span>
                  {snapshot?.git.is_repo
                    ? snapshot.git.dirty
                      ? "Dirty"
                      : "Clean"
                    : "Not initialized"}
                </span>
              </div>
              {snapshot?.git.is_repo ? (
                <>
                  <p>
                    Branch {snapshot.git.branch || "detached"} ·{" "}
                    {snapshot.git.last_commit || "No commits yet"}
                  </p>
                </>
              ) : (
                <p>Initialize a repository so workers and diffs operate inside a known boundary.</p>
              )}
              {!snapshot?.git.is_repo ? (
                <button
                  type="button"
                  className="studio-left-utility-action"
                  onClick={initializeRepository}
                  disabled={initBusy}
                >
                  {initBusy ? "Initializing..." : "Initialize repository"}
                </button>
              ) : null}
            </section>

            <section className="studio-left-utility-card studio-left-utility-card--tree">
              <div className="studio-left-utility-card-head">
                <strong>Files</strong>
                <span>{snapshot?.tree.length || 0}</span>
              </div>
              {loading ? <p>Loading project tree...</p> : null}
              {error ? <p>{error}</p> : null}
              {!loading && !error && snapshot ? (
                <div className="studio-utility-tree">{renderTree(snapshot.tree)}</div>
              ) : null}
            </section>
          </div>
        ) : null}

        {activeTab === "artifacts" ? (
          <div className="studio-left-utility-panel">
            <section className="studio-left-utility-card">
              <div className="studio-left-utility-card-head">
                <strong>Artifact lens</strong>
                <span>{snapshot?.artifacts.length || 0}</span>
              </div>
              <p>Project-scoped reports, revisions, bundles, logs, and output files.</p>
            </section>

            {loading ? <p className="studio-left-utility-feedback">Loading artifacts...</p> : null}
            {error ? <p className="studio-left-utility-feedback">{error}</p> : null}

            {!loading && !error && snapshot ? (
              <div className="studio-left-utility-artifacts">
                {snapshot.artifacts.length > 0 ? (
                  snapshot.artifacts.map((artifact) => (
                    <article
                      key={`${artifact.artifact_type}:${artifact.path}`}
                      className="studio-left-utility-card"
                    >
                      <div className="studio-left-utility-card-head">
                        <strong>{artifact.title}</strong>
                        <span>{artifact.artifact_type}</span>
                      </div>
                      <p>{artifact.path}</p>
                    </article>
                  ))
                ) : (
                  <section className="studio-left-utility-card">
                    <div className="studio-left-utility-card-head">
                      <strong>No project artifacts yet</strong>
                      <span>Ready</span>
                    </div>
                    <p>Run workflows or export reports and they will start showing up here.</p>
                  </section>
                )}
              </div>
            ) : null}
          </div>
        ) : null}
      </div>
    </aside>
  );
}

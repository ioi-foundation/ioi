// Session detail / Workspace — source-owned React (cut 4). Route: /sessions/:id.
//
// Source-derived from the product-ui working surface: a split between the agent conversation /
// run-timeline (left) and the workspace — files / editor / terminal (right). The conversation
// renders the daemon's REAL turns, folded from its runtime event stream (GET /v1/threads/:id/events).
// The workspace mounts the source-owned VS Code-like workbench (@ioi/workspace-substrate WorkspaceHost),
// reused exactly as the dev preview mounts it. Wiring the workbench to this session's live
// environment workspace is a deeper follow-on (see TODO below) — for now it renders in its preview
// form within the session layout, while the timeline is fully wired to real daemon data.
import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { MessageSquare, Layers, User, Bot, Cog, Circle, RefreshCw } from "lucide-react";
import {
  WorkspaceHost,
  type WorkspaceAdapter,
  type WorkspaceDeleteResult,
  type WorkspaceFileDocument,
  type WorkspaceLanguageServiceSnapshot,
  type WorkspaceNode,
  type WorkspacePathMutationResult,
  type WorkspaceSnapshot,
  type WorkspaceSourceControlState,
  type WorkspaceTerminalReadResult,
  type WorkspaceTerminalSession,
} from "@ioi/workspace-substrate";
import "./Session.css";
import { relativeTime } from "../../data/threads";
import { fetchSessionTimeline, type SessionTimeline, type Turn } from "./sessionModel";

// ── Workbench preview adapter (reused pattern from the source-owned dev preview) ─────────────────
// TODO(session-workspace): bind this WorkspaceHost to the session's live environment workspace
// (env-files / terminals daemon contracts) instead of this in-memory preview scaffold. The
// substrate + adapter contract is the wiring point; the conversation/timeline above is already
// fully wired to real /v1/threads/:id data.
const WS_ROOT = "/workspace";
const WS_NODE = "WORKSPACE";

const WS_TREE: WorkspaceNode[] = [
  {
    name: WS_NODE,
    path: WS_NODE,
    kind: "directory",
    hasChildren: true,
    children: [
      { name: "src", path: `${WS_NODE}/src`, kind: "directory", hasChildren: false, children: [] },
      { name: "README.md", path: `${WS_NODE}/README.md`, kind: "file", hasChildren: false, children: [] },
    ],
  },
];

const WS_SNAPSHOT: WorkspaceSnapshot = {
  rootPath: WS_ROOT,
  displayName: "workspace",
  git: { isRepo: true, branch: "main", dirty: false, lastCommit: "Session workspace" },
  tree: WS_TREE,
};

const WS_LANG: WorkspaceLanguageServiceSnapshot = {
  generatedAtMs: Date.now(),
  workspaceRoot: WS_ROOT,
  path: `${WS_NODE}/README.md`,
  languageId: "markdown",
  availability: "ready",
  statusLabel: "Ready",
  serviceLabel: "Language Service",
  serverLabel: "Language Service",
  detail: null,
  diagnostics: [],
  symbols: [],
};

const WS_SCM: WorkspaceSourceControlState = { git: WS_SNAPSHOT.git, entries: [] };

function wsFile(path: string): WorkspaceFileDocument {
  const name = path.split("/").pop() ?? path;
  return {
    name,
    path,
    absolutePath: `${WS_ROOT}/${path}`,
    languageHint: name.endsWith(".md") ? "markdown" : "plaintext",
    content: `# ${name}\n\nThis session's workspace will mount here.\n`,
    sizeBytes: 64,
    modifiedAtMs: Date.now(),
    isBinary: false,
    isTooLarge: false,
    readOnly: true,
  };
}

const noMutation = (path: string): Promise<WorkspacePathMutationResult> => Promise.resolve({ path });

const workspaceAdapter: WorkspaceAdapter = {
  inspectWorkspace: async () => WS_SNAPSHOT,
  listDirectory: async (_root, path) => (path === WS_NODE ? WS_TREE[0].children : []),
  readFile: async (_root, path) => wsFile(path),
  getLanguageServiceSnapshot: async () => WS_LANG,
  getLanguageDefinition: async () => [],
  getLanguageReferences: async () => [],
  getLanguageCodeActions: async () => [],
  writeFile: async (_root, path, content) => ({ ...wsFile(path), content, sizeBytes: content.length }),
  createFile: async (_root, path) => wsFile(path),
  createDirectory: async (_root, path) => noMutation(path),
  statPath: async (_root, path) => ({
    kind: path.includes(".") ? "file" : "directory",
    sizeBytes: 64,
    modifiedAtMs: Date.now(),
    readOnly: true,
  }),
  renamePath: async (_root, _from, to) => noMutation(to),
  deletePath: async (_root, path) => ({ deletedPath: path } as WorkspaceDeleteResult),
  searchText: async (_root, query) => ({ query, totalMatches: 0, files: [] }),
  getSourceControlState: async () => WS_SCM,
  getDiff: async (_root, path) => ({
    id: `diff:${path}`,
    path,
    title: path,
    originalLabel: "HEAD",
    modifiedLabel: "Working Tree",
    originalContent: "",
    modifiedContent: "",
    languageHint: "plaintext",
    isBinary: false,
  }),
  commitChanges: async () => ({
    state: WS_SCM,
    committedFileCount: 0,
    remainingChangeCount: 0,
    commitSummary: "",
  }),
  stagePaths: async () => WS_SCM,
  unstagePaths: async () => WS_SCM,
  discardPaths: async () => WS_SCM,
  createTerminalSession: async () =>
    ({
      sessionId: "session-terminal",
      shell: "/bin/bash",
      rootPath: WS_ROOT,
      startedAtMs: Date.now(),
      cols: 80,
      rows: 24,
    }) as WorkspaceTerminalSession,
  readTerminalSession: async () =>
    ({ sessionId: "session-terminal", chunks: [], cursor: 0, running: false, exitCode: null }) as WorkspaceTerminalReadResult,
  writeTerminalSession: async () => undefined,
  resizeTerminalSession: async () => undefined,
  closeTerminalSession: async () => undefined,
};

// ── Conversation / run-timeline ──────────────────────────────────────────────────────────────────
function ActorIcon({ actor }: { actor: string }) {
  if (actor === "user") return <User size={14} />;
  if (actor === "assistant") return <Bot size={14} />;
  return <Cog size={14} />;
}

function TurnCard({ turn }: { turn: Turn }) {
  return (
    <article className="se-turn" data-testid="session-turn">
      <header className="se-turnhead">
        <span className="se-turnno">Turn {turn.index}</span>
        <span className={`se-turnstatus is-${turn.status}`}>
          <Circle size={8} /> {turn.status}
        </span>
      </header>

      {turn.prompt && (
        <div className="se-msg is-user" data-testid="session-turn-prompt">
          <span className="se-msgicon"><User size={14} /></span>
          <div className="se-msgbody">{turn.prompt}</div>
        </div>
      )}

      {turn.items.length > 0 && (
        <ul className="se-activity">
          {turn.items.map((it) => (
            <li key={it.seq} className="se-act">
              <span className="se-acticon"><ActorIcon actor={it.actor} /></span>
              <span className="se-actkind">{it.kind}</span>
              {it.text && <span className="se-acttext">{it.text}</span>}
            </li>
          ))}
        </ul>
      )}

      {turn.reply && (
        <div className="se-msg is-agent" data-testid="session-turn-reply">
          <span className="se-msgicon"><Bot size={14} /></span>
          <div className="se-msgbody">{turn.reply}</div>
        </div>
      )}
    </article>
  );
}

// ── Surface ──────────────────────────────────────────────────────────────────────────────────────
export function SessionView() {
  const { id = "" } = useParams<{ id: string }>();
  const [data, setData] = useState<SessionTimeline | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    let live = true;
    setData(null);
    setError(null);
    fetchSessionTimeline(id)
      .then((d) => live && setData(d))
      .catch((e) => live && setError(String(e?.message || e)));
    return () => {
      live = false;
    };
  }, [id, reloadKey]);

  const session = data?.session;
  const turns = data?.turns ?? [];

  return (
    <div className="se">
      {/* Session header */}
      <header className="se-header" data-testid="session-header">
        <div className="se-headmain">
          <span className={"se-headdot" + (session?.running ? " is-running" : "")} />
          <h1 className="se-title">{session?.title || (error ? "Session" : "Loading session…")}</h1>
          {session && <span className="se-status">{session.running ? "active" : "stopped"}</span>}
        </div>
        <div className="se-headmeta">
          {session?.updatedAt && <span className="se-updated">updated {relativeTime(session.updatedAt)}</span>}
          <button className="se-refresh" onClick={() => setReloadKey((k) => k + 1)} title="Refresh">
            <RefreshCw size={14} />
          </button>
        </div>
      </header>

      <div className="se-split">
        {/* Conversation / run timeline */}
        <section className="se-pane se-convo">
          <div className="se-panehead">
            <MessageSquare size={15} /> Conversation
          </div>
          <div className="se-timeline" data-testid="session-timeline">
            {error && (
              <div className="se-state" data-testid="session-error">
                Daemon unavailable: {error}
              </div>
            )}
            {!error && data === null && (
              <div className="se-state" data-testid="session-loading">
                Loading conversation…
              </div>
            )}
            {!error && data !== null && turns.length === 0 && (
              <div className="se-state" data-testid="session-empty">
                No turns yet. This session has not run the agent.
              </div>
            )}
            {!error && data !== null && turns.map((t) => <TurnCard key={t.id} turn={t} />)}
          </div>
        </section>

        {/* Workspace — source-owned workbench (files / editor / terminal) */}
        <section className="se-pane se-workspace" data-testid="session-workspace">
          <div className="se-panehead">
            <Layers size={15} /> Workspace
          </div>
          <div className="se-workhost">
            <WorkspaceHost
              adapter={workspaceAdapter}
              root={WS_ROOT}
              title="Session workspace"
              showHeader={false}
              showBottomPanel={false}
              initialSnapshot={WS_SNAPSHOT}
              initialState={{
                activePane: "files",
                activeBottomPanel: "output",
                bottomPanelOpen: false,
                expandedPaths: { [WS_NODE]: true },
                documents: [],
                activeDocumentPath: null,
              }}
            />
          </div>
        </section>
      </div>
    </div>
  );
}

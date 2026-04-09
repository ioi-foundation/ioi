import { useEffect, useMemo, useState } from "react";
import type { KeyboardEvent, ReactNode } from "react";
import { formatSessionTimeAgo } from "../../runtime/use-session-history-browser";
import type { SessionHistorySummaryLike } from "../../runtime/use-session-history-browser";
import {
  useSessionHistoryFolders,
  type SessionHistoryFolderRecord,
} from "../../runtime/use-session-history-folders";

function workspaceLabel(workspaceRoot?: string | null): string | null {
  const trimmed = workspaceRoot?.trim();
  if (!trimmed) {
    return null;
  }

  const normalized = trimmed.replace(/\\/g, "/");
  const segments = normalized.split("/").filter(Boolean);
  return segments[segments.length - 1] ?? normalized;
}

function uniqueSessionParts(parts: Array<string | null | undefined>): string[] {
  const seen = new Set<string>();
  const unique: string[] = [];

  parts.forEach((part) => {
    const trimmed = part?.trim();
    if (!trimmed) {
      return;
    }
    const key = trimmed.toLowerCase();
    if (seen.has(key)) {
      return;
    }
    seen.add(key);
    unique.push(trimmed);
  });

  return unique;
}

function sessionSubtitle(session: SessionHistorySummaryLike): string | null {
  const parts = uniqueSessionParts([
    session.phase,
    session.current_step,
    session.resume_hint,
    workspaceLabel(session.workspace_root),
  ]);
  return parts.length > 0 ? parts.join(" · ") : null;
}

function matchesSessionQuery(
  session: SessionHistorySummaryLike,
  normalizedQuery: string,
) {
  if (!normalizedQuery) {
    return true;
  }

  return [
    session.title,
    session.phase,
    session.current_step,
    session.resume_hint,
    session.workspace_root,
    session.session_id,
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase()
    .includes(normalizedQuery);
}

function MoreHorizontalIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <circle cx="6" cy="12" r="1.6" />
      <circle cx="12" cy="12" r="1.6" />
      <circle cx="18" cy="12" r="1.6" />
    </svg>
  );
}

function FolderIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path
        d="M3.5 7.25a2 2 0 0 1 2-2h4.3l1.7 1.9H18.5a2 2 0 0 1 2 2v7.35a2 2 0 0 1-2 2h-13a2 2 0 0 1-2-2Z"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function FolderAddIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path
        d="M3.5 7.25a2 2 0 0 1 2-2h4.3l1.7 1.9H18.5a2 2 0 0 1 2 2v7.35a2 2 0 0 1-2 2h-13a2 2 0 0 1-2-2Z"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <path
        d="M12.2 10.2v5.2M9.6 12.8h5.2"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinecap="round"
      />
    </svg>
  );
}

function ThreadFileIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path
        d="M7 4.75h7l4 4v10.5a1.75 1.75 0 0 1-1.75 1.75h-9.5A1.75 1.75 0 0 1 5 19.25V6.5A1.75 1.75 0 0 1 6.75 4.75Z"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <path
        d="M14 4.75v4h4"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function ChevronRightIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path
        d="M9 6.75 15 12l-6 5.25"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function ChevronDownIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path
        d="M6.75 9 12 15l5.25-6"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function CheckIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path
        d="M5.5 12.5 9.5 16.5 18.5 7.5"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function CloseIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path
        d="m7.5 7.5 9 9m0-9-9 9"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinecap="round"
      />
    </svg>
  );
}

type HistoryMenuState =
  | {
      kind: "folder";
      id: string;
    }
  | {
      kind: "session";
      id: string;
    }
  | null;

interface FolderView<TSession extends SessionHistorySummaryLike> {
  folder: SessionHistoryFolderRecord;
  sessions: TSession[];
  visible: boolean;
  matchedByName: boolean;
}

export interface SessionHistorySidebarProps<
  TSession extends SessionHistorySummaryLike,
> {
  sessions: TSession[];
  onSelectSession: (id: string) => void;
  onNewChat: () => void;
  searchQuery: string;
  onSearchChange: (query: string) => void;
  onToggleSidebar: () => void;
  activeSessionId?: string | null;
  title?: string;
  newLabel?: string;
  emptyLabel?: string;
  icons: {
    plus: ReactNode;
    search: ReactNode;
    sidebar: ReactNode;
  };
}

export function SessionHistorySidebar<
  TSession extends SessionHistorySummaryLike,
>({
  sessions,
  onSelectSession,
  onNewChat,
  searchQuery,
  onSearchChange,
  onToggleSidebar,
  activeSessionId = null,
  title = "Chats",
  newLabel = "New",
  emptyLabel = "No chats yet",
  icons,
}: SessionHistorySidebarProps<TSession>) {
  const normalizedQuery = searchQuery.trim().toLowerCase();
  const {
    folders,
    createFolder,
    renameFolder,
    deleteFolder,
    toggleFolderCollapsed,
    moveSessionToFolder,
  } = useSessionHistoryFolders();
  const [menuState, setMenuState] = useState<HistoryMenuState>(null);
  const [editingFolderId, setEditingFolderId] = useState<string | null>(null);
  const [editingFolderName, setEditingFolderName] = useState("");

  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }

    const handlePointerDown = (event: PointerEvent) => {
      const target = event.target;
      if (!(target instanceof Element)) {
        setMenuState(null);
        return;
      }

      if (
        target.closest(".history-row-menu") ||
        target.closest(".history-row-action") ||
        target.closest(".history-folder-edit-shell")
      ) {
        return;
      }

      setMenuState(null);
    };

    window.addEventListener("pointerdown", handlePointerDown);
    return () => {
      window.removeEventListener("pointerdown", handlePointerDown);
    };
  }, []);

  const folderViews = useMemo<FolderView<TSession>[]>(() => {
    return folders
      .map((folder) => {
        const folderSessionIds = new Set(folder.sessionIds);
        const orderedSessions = sessions.filter((session) =>
          folderSessionIds.has(session.session_id),
        );
        const matchedByName = normalizedQuery
          ? folder.name.toLowerCase().includes(normalizedQuery)
          : false;
        const visibleSessions = normalizedQuery
          ? matchedByName
            ? orderedSessions
            : orderedSessions.filter((session) =>
                matchesSessionQuery(session, normalizedQuery),
              )
          : orderedSessions;

        return {
          folder,
          sessions: visibleSessions,
          matchedByName,
          visible: normalizedQuery
            ? matchedByName || visibleSessions.length > 0
            : true,
        };
      })
      .filter((folderView) => folderView.visible);
  }, [folders, normalizedQuery, sessions]);

  const assignedSessionIds = useMemo(() => {
    return new Set(folders.flatMap((folder) => folder.sessionIds));
  }, [folders]);

  const unfiledSessions = useMemo(
    () =>
      sessions.filter(
        (session) =>
          !assignedSessionIds.has(session.session_id) &&
          matchesSessionQuery(session, normalizedQuery),
      ),
    [assignedSessionIds, normalizedQuery, sessions],
  );

  const hasVisibleResults = folderViews.length > 0 || unfiledSessions.length > 0;

  const closeMenus = () => {
    setMenuState(null);
  };

  const startFolderRename = (folder: SessionHistoryFolderRecord) => {
    setEditingFolderId(folder.id);
    setEditingFolderName(folder.name);
    closeMenus();
  };

  const submitFolderRename = () => {
    if (!editingFolderId) {
      return;
    }

    renameFolder(editingFolderId, editingFolderName);
    setEditingFolderId(null);
    setEditingFolderName("");
  };

  const cancelFolderRename = () => {
    setEditingFolderId(null);
    setEditingFolderName("");
  };

  const handleFolderRenameKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === "Enter") {
      event.preventDefault();
      submitFolderRename();
      return;
    }

    if (event.key === "Escape") {
      event.preventDefault();
      cancelFolderRename();
    }
  };

  const handleCreateFolder = (initialSessionId?: string | null) => {
    const createdFolder = createFolder({
      initialSessionId,
    });
    setEditingFolderId(createdFolder.id);
    setEditingFolderName(createdFolder.name);
    closeMenus();
  };

  const handleDeleteFolder = (folder: SessionHistoryFolderRecord) => {
    if (
      typeof window !== "undefined" &&
      !window.confirm(
        `Delete "${folder.name}"? Chats in this folder will stay available in Chats.`,
      )
    ) {
      return;
    }

    deleteFolder(folder.id);
    if (editingFolderId === folder.id) {
      cancelFolderRename();
    }
    closeMenus();
  };

  const renderSessionRow = (
    session: TSession,
    currentFolder: SessionHistoryFolderRecord | null,
  ) => {
    const subtitle = sessionSubtitle(session);
    const titleText = session.title?.trim() || "Untitled chat";
    const accessibilitySummary = uniqueSessionParts([
      titleText,
      subtitle,
      formatSessionTimeAgo(session.timestamp),
    ]).join(" · ");
    const isActive = activeSessionId === session.session_id;
    const availableDestinationFolders = folders.filter(
      (folder) => folder.id !== currentFolder?.id,
    );
    const menuOpen =
      menuState?.kind === "session" && menuState.id === session.session_id;

    return (
      <div
        key={session.session_id}
        className={`history-item-shell ${isActive ? "active" : ""}`}
      >
        <button
          className={`history-item ${isActive ? "active" : ""}`}
          onClick={() => onSelectSession(session.session_id)}
          title={accessibilitySummary}
        >
          <span className="history-item-selection-rail" aria-hidden="true" />
          <span className="history-item-icon" aria-hidden="true">
            <ThreadFileIcon />
          </span>
          <span className="history-copy">
            <span className="history-title">{titleText}</span>
          </span>
        </button>
        <button
          className={`history-row-action ${
            menuOpen ? "is-open" : ""
          }`}
          aria-label={`Chat actions for ${titleText}`}
          onClick={(event) => {
            event.stopPropagation();
            setMenuState((current) =>
              current?.kind === "session" && current.id === session.session_id
                ? null
                : {
                    kind: "session",
                    id: session.session_id,
                  },
            );
          }}
        >
          <MoreHorizontalIcon />
        </button>
        {menuOpen ? (
          <div className="history-row-menu history-row-menu--session">
            {currentFolder ? (
              <button
                className="history-row-menu-item"
                onClick={() => {
                  moveSessionToFolder(session.session_id, null);
                  closeMenus();
                }}
              >
                Move to Chats
              </button>
            ) : null}
            {availableDestinationFolders.map((folder) => (
              <button
                key={folder.id}
                className="history-row-menu-item"
                onClick={() => {
                  moveSessionToFolder(session.session_id, folder.id);
                  closeMenus();
                }}
              >
                Move to {folder.name}
              </button>
            ))}
            <button
              className="history-row-menu-item"
              onClick={() => {
                handleCreateFolder(session.session_id);
              }}
            >
              Move to New Folder
            </button>
          </div>
        ) : null}
      </div>
    );
  };

  return (
    <aside className="history-sidebar">
      <div className="sidebar-header">
        <div className="sidebar-header-copy">
          <span className="sidebar-title">{title}</span>
        </div>
        <div className="sidebar-header-actions">
          <button
            className="sidebar-icon-btn"
            onClick={onToggleSidebar}
            title="Hide sidebar (⌘K)"
          >
            <MoreHorizontalIcon />
          </button>
          <button
            className="sidebar-icon-btn sidebar-icon-btn--accent"
            onClick={onNewChat}
            title={`Start ${newLabel.toLowerCase()}`}
          >
            {icons.plus}
          </button>
        </div>
      </div>

      <div className="sidebar-search">
        <div className="search-box">
          {icons.search}
          <input
            placeholder="Search chats..."
            value={searchQuery}
            onChange={(event) => onSearchChange(event.target.value)}
          />
        </div>
      </div>

      <div className="sidebar-history">
        <button
          className="history-utility-row"
          onClick={() => handleCreateFolder()}
          title="Create folder"
        >
          <span className="history-utility-icon">
            <FolderAddIcon />
          </span>
          <span className="history-utility-label">New Folder</span>
        </button>

        {folderViews.map(({ folder, sessions: folderSessions, matchedByName }) => {
          const isExpanded = normalizedQuery ? true : !folder.collapsed;
          const isEditing = editingFolderId === folder.id;
          const menuOpen = menuState?.kind === "folder" && menuState.id === folder.id;

          return (
            <section key={folder.id} className="history-folder">
              <div className="history-folder-shell">
                {isEditing ? (
                  <div className="history-folder-edit-shell">
                    <span className="history-folder-icon" aria-hidden="true">
                      <FolderIcon />
                    </span>
                    <input
                      className="history-folder-edit-input"
                      value={editingFolderName}
                      onChange={(event) => setEditingFolderName(event.target.value)}
                      onKeyDown={handleFolderRenameKeyDown}
                      autoFocus
                    />
                    <button
                      className="history-inline-action"
                      aria-label="Save folder"
                      onMouseDown={(event) => event.preventDefault()}
                      onClick={submitFolderRename}
                    >
                      <CheckIcon />
                    </button>
                    <button
                      className="history-inline-action"
                      aria-label="Cancel rename"
                      onMouseDown={(event) => event.preventDefault()}
                      onClick={cancelFolderRename}
                    >
                      <CloseIcon />
                    </button>
                  </div>
                ) : (
                  <>
                    <button
                      className="history-folder-row history-folder-trigger"
                      onClick={() => toggleFolderCollapsed(folder.id)}
                      title={
                        matchedByName
                          ? `${folder.name} matches your search`
                          : folder.name
                      }
                    >
                      <span
                        className="history-folder-disclosure"
                        aria-hidden="true"
                      >
                        {isExpanded ? <ChevronDownIcon /> : <ChevronRightIcon />}
                      </span>
                      <span className="history-folder-icon" aria-hidden="true">
                        <FolderIcon />
                      </span>
                      <span className="history-folder-label">{folder.name}</span>
                    </button>
                    <button
                      className={`history-row-action history-row-action--folder ${
                        menuOpen ? "is-open" : ""
                      }`}
                      aria-label={`Folder actions for ${folder.name}`}
                      onClick={(event) => {
                        event.stopPropagation();
                        setMenuState((current) =>
                          current?.kind === "folder" && current.id === folder.id
                            ? null
                            : {
                                kind: "folder",
                                id: folder.id,
                              },
                        );
                      }}
                    >
                      <MoreHorizontalIcon />
                    </button>
                    {menuOpen ? (
                      <div className="history-row-menu history-row-menu--folder">
                        <button
                          className="history-row-menu-item"
                          onClick={() => startFolderRename(folder)}
                        >
                          Rename Folder
                        </button>
                        <button
                          className="history-row-menu-item history-row-menu-item--danger"
                          onClick={() => handleDeleteFolder(folder)}
                        >
                          Delete Folder
                        </button>
                      </div>
                    ) : null}
                  </>
                )}
              </div>
              {isExpanded ? (
                <div className="history-folder-children">
                  {folderSessions.length > 0 ? (
                    folderSessions.map((session) => renderSessionRow(session, folder))
                  ) : (
                    <div className="history-folder-empty">Empty folder</div>
                  )}
                </div>
              ) : null}
            </section>
          );
        })}

        {unfiledSessions.length > 0 ? (
          <section className="history-folder history-folder--unfiled">
            <div className="history-folder-shell">
              <div className="history-folder-row history-folder-row--static">
                <span
                  className="history-folder-disclosure history-folder-disclosure--placeholder"
                  aria-hidden="true"
                >
                  <ChevronDownIcon />
                </span>
                <span className="history-folder-icon" aria-hidden="true">
                  <ThreadFileIcon />
                </span>
                <span className="history-folder-label">Chats</span>
              </div>
            </div>
            <div className="history-folder-children">
              {unfiledSessions.map((session) => renderSessionRow(session, null))}
            </div>
          </section>
        ) : null}

        {!hasVisibleResults ? (
          <div className="history-empty">
            {searchQuery ? "No matches found" : emptyLabel}
          </div>
        ) : null}
      </div>
    </aside>
  );
}

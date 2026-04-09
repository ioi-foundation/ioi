import { useCallback, useEffect, useMemo, useRef, useState } from "react";

const STORAGE_KEY = "ioi.agent-ide.session-history-folders.v1";
const UPDATE_EVENT = "ioi:agent-ide-session-history-folders-updated";
const STORAGE_VERSION = 1;

export interface SessionHistoryFolderRecord {
  id: string;
  name: string;
  sessionIds: string[];
  collapsed: boolean;
  createdAtMs: number;
  updatedAtMs: number;
}

export interface SessionHistoryFoldersEnvelope {
  version: number;
  folders: SessionHistoryFolderRecord[];
}

export interface CreateSessionHistoryFolderOptions {
  name?: string | null;
  initialSessionId?: string | null;
}

function canUseStorage() {
  return (
    typeof window !== "undefined" &&
    typeof window.localStorage !== "undefined"
  );
}

function createFolderId() {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }

  return `session-folder-${Date.now()}-${Math.random().toString(16).slice(2, 10)}`;
}

function normalizeFolderName(name?: string | null) {
  const trimmed = name?.trim();
  return trimmed && trimmed.length > 0 ? trimmed : "New Folder";
}

function uniqueStrings(values: string[]) {
  const seen = new Set<string>();
  const unique: string[] = [];

  values.forEach((value) => {
    if (!value || seen.has(value)) {
      return;
    }
    seen.add(value);
    unique.push(value);
  });

  return unique;
}

function normalizeFolderRecord(
  folder: Partial<SessionHistoryFolderRecord>,
  seenSessionIds: Set<string>,
): SessionHistoryFolderRecord | null {
  if (typeof folder.id !== "string" || folder.id.trim().length === 0) {
    return null;
  }

  const sessionIds = uniqueStrings(
    Array.isArray(folder.sessionIds)
      ? folder.sessionIds.filter((sessionId): sessionId is string => {
          if (typeof sessionId !== "string" || sessionId.trim().length === 0) {
            return false;
          }
          if (seenSessionIds.has(sessionId)) {
            return false;
          }
          seenSessionIds.add(sessionId);
          return true;
        })
      : [],
  );

  const createdAtMs =
    typeof folder.createdAtMs === "number" && Number.isFinite(folder.createdAtMs)
      ? folder.createdAtMs
      : Date.now();
  const updatedAtMs =
    typeof folder.updatedAtMs === "number" && Number.isFinite(folder.updatedAtMs)
      ? folder.updatedAtMs
      : createdAtMs;

  return {
    id: folder.id,
    name: normalizeFolderName(folder.name),
    sessionIds,
    collapsed: folder.collapsed === true,
    createdAtMs,
    updatedAtMs,
  };
}

function normalizeEnvelope(
  value: unknown,
): SessionHistoryFoldersEnvelope {
  if (!value || typeof value !== "object") {
    return {
      version: STORAGE_VERSION,
      folders: [],
    };
  }

  const candidate = value as {
    version?: unknown;
    folders?: unknown;
  };
  const seenSessionIds = new Set<string>();
  const folders = Array.isArray(candidate.folders)
    ? candidate.folders
        .map((folder) =>
          normalizeFolderRecord(
            folder as Partial<SessionHistoryFolderRecord>,
            seenSessionIds,
          ),
        )
        .filter((folder): folder is SessionHistoryFolderRecord => folder !== null)
    : [];

  return {
    version:
      typeof candidate.version === "number" && Number.isFinite(candidate.version)
        ? candidate.version
        : STORAGE_VERSION,
    folders,
  };
}

function readEnvelope() {
  if (!canUseStorage()) {
    return {
      version: STORAGE_VERSION,
      folders: [],
    } satisfies SessionHistoryFoldersEnvelope;
  }

  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) {
      return {
        version: STORAGE_VERSION,
        folders: [],
      } satisfies SessionHistoryFoldersEnvelope;
    }
    return normalizeEnvelope(JSON.parse(raw));
  } catch {
    return {
      version: STORAGE_VERSION,
      folders: [],
    } satisfies SessionHistoryFoldersEnvelope;
  }
}

function persistEnvelope(envelope: SessionHistoryFoldersEnvelope) {
  if (!canUseStorage()) {
    return;
  }

  window.localStorage.setItem(STORAGE_KEY, JSON.stringify(envelope));
}

function dispatchEnvelopeUpdate(envelope: SessionHistoryFoldersEnvelope) {
  if (typeof window === "undefined") {
    return;
  }

  window.dispatchEvent(
    new CustomEvent<SessionHistoryFoldersEnvelope>(UPDATE_EVENT, {
      detail: envelope,
    }),
  );
}

export function buildNextSessionHistoryFolderName(
  existingNames: string[],
  baseName = "New Folder",
) {
  const normalizedBase = normalizeFolderName(baseName);
  const existingLookup = new Set(
    existingNames.map((name) => name.trim().toLowerCase()).filter(Boolean),
  );

  if (!existingLookup.has(normalizedBase.toLowerCase())) {
    return normalizedBase;
  }

  let index = 2;
  while (existingLookup.has(`${normalizedBase} ${index}`.toLowerCase())) {
    index += 1;
  }
  return `${normalizedBase} ${index}`;
}

function moveSessionIds(
  folders: SessionHistoryFolderRecord[],
  sessionId: string,
  targetFolderId: string | null,
) {
  return folders.map((folder) => {
    const withoutSession = folder.sessionIds.filter(
      (candidate) => candidate !== sessionId,
    );
    const shouldAssign = targetFolderId === folder.id;
    const nextSessionIds = shouldAssign
      ? uniqueStrings([...withoutSession, sessionId])
      : withoutSession;

    if (
      nextSessionIds.length === folder.sessionIds.length &&
      nextSessionIds.every((candidate, index) => candidate === folder.sessionIds[index])
    ) {
      return folder;
    }

    return {
      ...folder,
      sessionIds: nextSessionIds,
      updatedAtMs: Date.now(),
    };
  });
}

export interface UseSessionHistoryFoldersResult {
  folders: SessionHistoryFolderRecord[];
  createFolder: (
    options?: CreateSessionHistoryFolderOptions,
  ) => SessionHistoryFolderRecord;
  renameFolder: (folderId: string, nextName: string) => void;
  deleteFolder: (folderId: string) => void;
  toggleFolderCollapsed: (folderId: string) => void;
  moveSessionToFolder: (sessionId: string, folderId: string | null) => void;
  findFolderForSession: (sessionId: string) => SessionHistoryFolderRecord | null;
}

export function useSessionHistoryFolders(): UseSessionHistoryFoldersResult {
  const [envelope, setEnvelope] = useState<SessionHistoryFoldersEnvelope>(() =>
    readEnvelope(),
  );
  const envelopeRef = useRef(envelope);

  useEffect(() => {
    envelopeRef.current = envelope;
  }, [envelope]);

  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }

    const syncFromStorage = () => {
      const nextEnvelope = readEnvelope();
      envelopeRef.current = nextEnvelope;
      setEnvelope(nextEnvelope);
    };

    const handleStorage = (event: StorageEvent) => {
      if (event.key !== STORAGE_KEY) {
        return;
      }
      syncFromStorage();
    };

    const handleEnvelopeUpdate = (event: Event) => {
      const detail = (event as CustomEvent<SessionHistoryFoldersEnvelope>).detail;
      if (detail && Array.isArray(detail.folders)) {
        const nextEnvelope = normalizeEnvelope(detail);
        envelopeRef.current = nextEnvelope;
        setEnvelope(nextEnvelope);
        return;
      }
      syncFromStorage();
    };

    window.addEventListener("storage", handleStorage);
    window.addEventListener(UPDATE_EVENT, handleEnvelopeUpdate as EventListener);

    return () => {
      window.removeEventListener("storage", handleStorage);
      window.removeEventListener(
        UPDATE_EVENT,
        handleEnvelopeUpdate as EventListener,
      );
    };
  }, []);

  const commitEnvelope = useCallback((nextEnvelope: SessionHistoryFoldersEnvelope) => {
    envelopeRef.current = nextEnvelope;
    setEnvelope(nextEnvelope);
    persistEnvelope(nextEnvelope);
    dispatchEnvelopeUpdate(nextEnvelope);
  }, []);

  const createFolder = useCallback(
    (
      options: CreateSessionHistoryFolderOptions = {},
    ): SessionHistoryFolderRecord => {
      const current = envelopeRef.current;
      const timestamp = Date.now();
      const nextFolder: SessionHistoryFolderRecord = {
        id: createFolderId(),
        name: buildNextSessionHistoryFolderName(
          current.folders.map((folder) => folder.name),
          options.name ?? undefined,
        ),
        sessionIds:
          typeof options.initialSessionId === "string" &&
          options.initialSessionId.trim().length > 0
            ? [options.initialSessionId]
            : [],
        collapsed: false,
        createdAtMs: timestamp,
        updatedAtMs: timestamp,
      };
      const nextEnvelope = {
        version: STORAGE_VERSION,
        folders: moveSessionIds(
          [...current.folders, nextFolder],
          options.initialSessionId ?? "",
          nextFolder.sessionIds.length > 0 ? nextFolder.id : null,
        ),
      } satisfies SessionHistoryFoldersEnvelope;
      commitEnvelope(nextEnvelope);
      return nextFolder;
    },
    [commitEnvelope],
  );

  const renameFolder = useCallback(
    (folderId: string, nextName: string) => {
      const normalizedName = normalizeFolderName(nextName);
      const nextEnvelope = {
        version: STORAGE_VERSION,
        folders: envelopeRef.current.folders.map((folder) =>
          folder.id === folderId
            ? {
                ...folder,
                name: normalizedName,
                updatedAtMs: Date.now(),
              }
            : folder,
        ),
      } satisfies SessionHistoryFoldersEnvelope;
      commitEnvelope(nextEnvelope);
    },
    [commitEnvelope],
  );

  const deleteFolder = useCallback(
    (folderId: string) => {
      const nextEnvelope = {
        version: STORAGE_VERSION,
        folders: envelopeRef.current.folders.filter((folder) => folder.id !== folderId),
      } satisfies SessionHistoryFoldersEnvelope;
      commitEnvelope(nextEnvelope);
    },
    [commitEnvelope],
  );

  const toggleFolderCollapsed = useCallback(
    (folderId: string) => {
      const nextEnvelope = {
        version: STORAGE_VERSION,
        folders: envelopeRef.current.folders.map((folder) =>
          folder.id === folderId
            ? {
                ...folder,
                collapsed: !folder.collapsed,
                updatedAtMs: Date.now(),
              }
            : folder,
        ),
      } satisfies SessionHistoryFoldersEnvelope;
      commitEnvelope(nextEnvelope);
    },
    [commitEnvelope],
  );

  const moveSessionToFolder = useCallback(
    (sessionId: string, folderId: string | null) => {
      const nextEnvelope = {
        version: STORAGE_VERSION,
        folders: moveSessionIds(envelopeRef.current.folders, sessionId, folderId),
      } satisfies SessionHistoryFoldersEnvelope;
      commitEnvelope(nextEnvelope);
    },
    [commitEnvelope],
  );

  const folders = useMemo(() => envelope.folders, [envelope.folders]);

  const findFolderForSession = useCallback(
    (sessionId: string) =>
      envelopeRef.current.folders.find((folder) =>
        folder.sessionIds.includes(sessionId),
      ) ?? null,
    [],
  );

  return {
    folders,
    createFolder,
    renameFolder,
    deleteFolder,
    toggleFolderCollapsed,
    moveSessionToFolder,
    findFolderForSession,
  };
}

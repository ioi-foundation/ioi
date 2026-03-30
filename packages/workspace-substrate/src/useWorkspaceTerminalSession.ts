import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type {
  WorkspaceActivityEntry,
  WorkspaceAdapter,
  WorkspaceProblemEntry,
  WorkspaceTerminalController,
  WorkspaceTerminalSession,
} from "./types";

interface UseWorkspaceTerminalSessionOptions {
  adapter: WorkspaceAdapter;
  root: string;
  enabled?: boolean;
}

interface ParsedDiagnostic {
  severity: WorkspaceProblemEntry["severity"];
  title: string;
  detail: string;
  path?: string;
  line?: number;
  column?: number;
}

interface PendingRustDiagnostic {
  severity: WorkspaceProblemEntry["severity"];
  title: string;
  detail: string;
}

const MAX_HISTORY_CHARS = 200_000;
const MAX_ACTIVITY_ENTRIES = 80;
const MAX_OUTPUT_ENTRIES = 240;
const MAX_PROBLEM_ENTRIES = 80;

const ANSI_ESCAPE_PATTERN =
  /\u001b(?:\[[0-?]*[ -/]*[@-~]|\][^\u0007]*(?:\u0007|\u001b\\))/g;

const COLON_DIAGNOSTIC_PATTERN =
  /^(?<path>.+?):(?<line>\d+):(?<column>\d+):\s*(?<severity>error|warning|info|note)(?:\[[^\]]+\])?(?::|\s+-)?\s*(?<message>.+)$/i;
const DASH_DIAGNOSTIC_PATTERN =
  /^(?<path>.+?):(?<line>\d+):(?<column>\d+)\s*-\s*(?<severity>error|warning|info|note)\s*(?<code>[A-Z]+\d+)?:?\s*(?<message>.+)$/i;
const PAREN_DIAGNOSTIC_PATTERN =
  /^(?<path>.+?)\((?<line>\d+),(?<column>\d+)\):\s*(?<severity>error|warning|info|note)\s*(?<code>[A-Z]+\d+)?:?\s*(?<message>.+)$/i;
const RUST_HEADER_PATTERN =
  /^(?<severity>error|warning|info|note)(?:\[(?<code>[^\]]+)\])?:\s*(?<message>.+)$/i;
const RUST_LOCATION_PATTERN =
  /^\s*-->\s+(?<path>.+?):(?<line>\d+):(?<column>\d+)/;

function stripAnsi(value: string): string {
  return value.replace(ANSI_ESCAPE_PATTERN, "");
}

function toRelativePath(root: string, rawPath: string | undefined): string | undefined {
  if (!rawPath) {
    return undefined;
  }

  const normalizedRoot = root.replace(/\\/g, "/").replace(/\/+$/, "");
  const normalizedPath = rawPath
    .trim()
    .replace(/^["']|["']$/g, "")
    .replace(/\\/g, "/")
    .replace(/^\.\//, "");

  if (!normalizedPath) {
    return undefined;
  }

  if (normalizedPath === normalizedRoot) {
    return "";
  }

  if (normalizedRoot && normalizedPath.startsWith(`${normalizedRoot}/`)) {
    return normalizedPath.slice(normalizedRoot.length + 1);
  }

  return normalizedPath;
}

function severityToActivityKind(
  severity: WorkspaceProblemEntry["severity"],
): WorkspaceActivityEntry["kind"] {
  if (severity === "error") {
    return "error";
  }
  if (severity === "warning") {
    return "warning";
  }
  return "info";
}

function sourceForCommand(command: string | null): string {
  const label = command?.trim().split(/\s+/)[0];
  return label ? label.slice(0, 24) : "terminal";
}

function truncateTitle(value: string, max = 140): string {
  if (value.length <= max) {
    return value;
  }
  return `${value.slice(0, max - 1)}…`;
}

function classifyOutputKind(line: string): WorkspaceActivityEntry["kind"] {
  if (/\berror\b/i.test(line) || /\bfailed\b/i.test(line)) {
    return "error";
  }
  if (/\bwarn(?:ing)?\b/i.test(line)) {
    return "warning";
  }
  if (/\bfinished\b/i.test(line) || /\bpassed\b/i.test(line) || /\bsuccess\b/i.test(line)) {
    return "success";
  }
  return "info";
}

function parseLineNumber(value: string | undefined): number | undefined {
  if (!value) {
    return undefined;
  }
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : undefined;
}

function normalizeProblemSeverity(value: string | undefined): WorkspaceProblemEntry["severity"] {
  if (!value) {
    return "error";
  }
  if (value.toLowerCase() === "warning") {
    return "warning";
  }
  if (value.toLowerCase() === "info" || value.toLowerCase() === "note") {
    return "info";
  }
  return "error";
}

function parseSingleLineDiagnostic(
  line: string,
  root: string,
): ParsedDiagnostic | null {
  const colonMatch = line.match(COLON_DIAGNOSTIC_PATTERN);
  const dashMatch = line.match(DASH_DIAGNOSTIC_PATTERN);
  const parenMatch = line.match(PAREN_DIAGNOSTIC_PATTERN);
  const match = colonMatch ?? dashMatch ?? parenMatch;
  if (!match?.groups) {
    return null;
  }

  const severity = normalizeProblemSeverity(match.groups.severity);
  const code = match.groups.code?.trim();
  const message = match.groups.message?.trim() ?? line.trim();
  const title = code ? `${code}: ${message}` : message;

  return {
    severity,
    title,
    detail: line.trim(),
    path: toRelativePath(root, match.groups.path),
    line: parseLineNumber(match.groups.line),
    column: parseLineNumber(match.groups.column),
  };
}

function diagnosticKey(problem: ParsedDiagnostic): string {
  return [
    problem.severity,
    problem.path ?? "",
    problem.line ?? "",
    problem.column ?? "",
    problem.title,
  ].join(":");
}

export function useWorkspaceTerminalSession({
  adapter,
  root,
  enabled = true,
}: UseWorkspaceTerminalSessionOptions): WorkspaceTerminalController {
  const [requestedEnabled, setRequestedEnabled] = useState(enabled);
  const [launchVersion, setLaunchVersion] = useState(enabled ? 1 : 0);
  const [session, setSession] = useState<WorkspaceTerminalSession | null>(null);
  const [running, setRunning] = useState(enabled);
  const [exitCode, setExitCode] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [activityEntries, setActivityEntries] = useState<WorkspaceActivityEntry[]>([]);
  const [outputEntries, setOutputEntries] = useState<WorkspaceActivityEntry[]>([]);
  const [problems, setProblems] = useState<WorkspaceProblemEntry[]>([]);

  const rootRef = useRef(root);
  const sessionRef = useRef<WorkspaceTerminalSession | null>(null);
  const exitCodeRef = useRef<number | null>(null);
  const errorRef = useRef<string | null>(null);
  const activityEntriesRef = useRef<WorkspaceActivityEntry[]>([]);
  const outputEntriesRef = useRef<WorkspaceActivityEntry[]>([]);
  const problemsRef = useRef<WorkspaceProblemEntry[]>([]);
  const problemKeysRef = useRef<Set<string>>(new Set());
  const historyRef = useRef("");
  const listenersRef = useRef(new Set<(text: string) => void>());
  const stateListenersRef = useRef(new Set<() => void>());
  const lineBufferRef = useRef("");
  const inputBufferRef = useRef("");
  const currentCommandRef = useRef<string | null>(null);
  const pendingRustDiagnosticRef = useRef<PendingRustDiagnostic | null>(null);
  const sessionIdRef = useRef<string | null>(null);
  const cursorRef = useRef(0);
  const sequenceRef = useRef(0);
  const runningRef = useRef(enabled);
  const requestedEnabledRef = useRef(enabled);

  const commitActivityEntries = useCallback((entries: WorkspaceActivityEntry[]) => {
    if (entries.length === 0) {
      return;
    }
    const next = [...entries.reverse(), ...activityEntriesRef.current].slice(
      0,
      MAX_ACTIVITY_ENTRIES,
    );
    activityEntriesRef.current = next;
    setActivityEntries(next);
  }, []);

  const commitOutputEntries = useCallback((entries: WorkspaceActivityEntry[]) => {
    if (entries.length === 0) {
      return;
    }
    const next = [...entries.reverse(), ...outputEntriesRef.current].slice(
      0,
      MAX_OUTPUT_ENTRIES,
    );
    outputEntriesRef.current = next;
    setOutputEntries(next);
  }, []);

  const resetProblems = useCallback(() => {
    pendingRustDiagnosticRef.current = null;
    problemKeysRef.current = new Set();
    problemsRef.current = [];
    setProblems([]);
  }, []);

  const commitProblemEntries = useCallback((entries: ParsedDiagnostic[]) => {
    if (entries.length === 0) {
      return;
    }

    const nextProblems: WorkspaceProblemEntry[] = [];
    for (const entry of entries) {
      const key = diagnosticKey(entry);
      if (problemKeysRef.current.has(key)) {
        continue;
      }
      problemKeysRef.current.add(key);
      sequenceRef.current += 1;
      nextProblems.push({
        id: `terminal-problem:${sequenceRef.current}`,
        severity: entry.severity,
        source: sourceForCommand(currentCommandRef.current),
        title: entry.title,
        detail: entry.detail,
        path: entry.path,
        line: entry.line,
        column: entry.column,
      });
    }

    if (nextProblems.length === 0) {
      return;
    }

    const next = [...nextProblems.reverse(), ...problemsRef.current].slice(
      0,
      MAX_PROBLEM_ENTRIES,
    );
    problemsRef.current = next;
    setProblems(next);
  }, []);

  const createEntry = useCallback(
    (
      kind: WorkspaceActivityEntry["kind"],
      source: string,
      title: string,
      detail: string | null = null,
      path?: string,
      line?: number,
      column?: number,
    ): WorkspaceActivityEntry => {
      sequenceRef.current += 1;
      return {
        id: `terminal-activity:${sequenceRef.current}`,
        kind,
        source,
        title,
        detail,
        timestampMs: Date.now(),
        path,
        line,
        column,
      };
    },
    [],
  );

  const pushHistory = useCallback((text: string) => {
    historyRef.current = `${historyRef.current}${text}`.slice(-MAX_HISTORY_CHARS);
    for (const listener of listenersRef.current) {
      listener(text);
    }
  }, []);

  const processTerminalLine = useCallback(
    (
      rawLine: string,
      nextActivityEntries: WorkspaceActivityEntry[],
      nextOutputEntries: WorkspaceActivityEntry[],
      nextProblemEntries: ParsedDiagnostic[],
    ) => {
      const strippedLine = stripAnsi(rawLine).trim();
      if (!strippedLine) {
        return;
      }

      let lineProblem: ParsedDiagnostic | null = null;
      const rustLocation = strippedLine.match(RUST_LOCATION_PATTERN);
      if (pendingRustDiagnosticRef.current && rustLocation?.groups) {
        lineProblem = {
          severity: pendingRustDiagnosticRef.current.severity,
          title: pendingRustDiagnosticRef.current.title,
          detail: pendingRustDiagnosticRef.current.detail,
          path: toRelativePath(root, rustLocation.groups.path),
          line: parseLineNumber(rustLocation.groups.line),
          column: parseLineNumber(rustLocation.groups.column),
        };
        nextProblemEntries.push(lineProblem);
        pendingRustDiagnosticRef.current = null;
      } else {
        const rustHeader = strippedLine.match(RUST_HEADER_PATTERN);
        if (rustHeader?.groups) {
          const severity = normalizeProblemSeverity(rustHeader.groups.severity);
          const code = rustHeader.groups.code?.trim();
          const message = rustHeader.groups.message?.trim() ?? strippedLine;
          pendingRustDiagnosticRef.current = {
            severity,
            title: code ? `${code}: ${message}` : message,
            detail: strippedLine,
          };
        }

        const singleLineProblem = parseSingleLineDiagnostic(strippedLine, root);
        if (singleLineProblem) {
          lineProblem = singleLineProblem;
          nextProblemEntries.push(singleLineProblem);
          pendingRustDiagnosticRef.current = null;
        }
      }

      if (
        currentCommandRef.current &&
        (strippedLine === currentCommandRef.current ||
          strippedLine.endsWith(`$ ${currentCommandRef.current}`) ||
          strippedLine.endsWith(`# ${currentCommandRef.current}`))
      ) {
        return;
      }

      const source = sourceForCommand(currentCommandRef.current);
      const kind = classifyOutputKind(strippedLine);
      nextOutputEntries.push(
        createEntry(
          kind,
          source,
          truncateTitle(strippedLine),
          strippedLine.length > 140 ? strippedLine : null,
          lineProblem?.path,
          lineProblem?.line,
          lineProblem?.column,
        ),
      );

      if (lineProblem) {
        nextActivityEntries.push(
          createEntry(
            severityToActivityKind(lineProblem.severity),
            source,
            lineProblem.title,
            lineProblem.detail,
            lineProblem.path,
            lineProblem.line,
            lineProblem.column,
          ),
        );
      }
    },
    [createEntry, root],
  );

  const ingestText = useCallback(
    (text: string) => {
      const normalized = stripAnsi(text).replace(/\r\n/g, "\n").replace(/\r/g, "\n");
      if (!normalized) {
        return;
      }

      lineBufferRef.current += normalized;
      const segments = lineBufferRef.current.split("\n");
      lineBufferRef.current = segments.pop() ?? "";

      const nextActivityEntries: WorkspaceActivityEntry[] = [];
      const nextOutputEntries: WorkspaceActivityEntry[] = [];
      const nextProblemEntries: ParsedDiagnostic[] = [];

      for (const line of segments) {
        processTerminalLine(
          line,
          nextActivityEntries,
          nextOutputEntries,
          nextProblemEntries,
        );
      }

      commitOutputEntries(nextOutputEntries);
      commitActivityEntries(nextActivityEntries);
      commitProblemEntries(nextProblemEntries);
    },
    [commitActivityEntries, commitOutputEntries, commitProblemEntries, processTerminalLine],
  );

  const recordCommandStart = useCallback(
    (command: string) => {
      currentCommandRef.current = command;
      resetProblems();

      const source = sourceForCommand(command);
      const title = `Ran ${command}`;
      const detail = `PTY session attached to ${root}`;
      const entry = createEntry("info", source, title, detail);
      commitActivityEntries([entry]);
      commitOutputEntries([createEntry("info", source, `$ ${command}`, null)]);
    },
    [commitActivityEntries, commitOutputEntries, createEntry, resetProblems, root],
  );

  const write = useCallback(
    async (data: string) => {
      const sessionId = sessionIdRef.current;
      if (!sessionId) {
        return;
      }

      let buffer = inputBufferRef.current;
      for (const character of data) {
        if (character === "\r" || character === "\n") {
          const command = buffer.trim();
          buffer = "";
          if (command) {
            recordCommandStart(command);
          }
          continue;
        }

        if (character === "\x7f" || character === "\b") {
          buffer = buffer.slice(0, -1);
          continue;
        }

        if (character.charCodeAt(0) >= 32 && character.charCodeAt(0) !== 127) {
          buffer += character;
        }
      }
      inputBufferRef.current = buffer;

      try {
        await adapter.writeTerminalSession(sessionId, data);
      } catch (writeError) {
        const message = String(writeError);
        setError(message);
        commitActivityEntries([
          createEntry("error", "terminal", "Terminal write failed", message),
        ]);
      }
    },
    [adapter, commitActivityEntries, createEntry, recordCommandStart],
  );

  const resize = useCallback(
    async (cols: number, rows: number) => {
      const sessionId = sessionIdRef.current;
      if (!sessionId) {
        return;
      }

      try {
        await adapter.resizeTerminalSession(
          sessionId,
          Math.max(cols, 40),
          Math.max(rows, 12),
        );
      } catch (resizeError) {
        setError(String(resizeError));
      }
    },
    [adapter],
  );

  const getHistory = useCallback(() => historyRef.current, []);

  const subscribe = useCallback((listener: (text: string) => void) => {
    listenersRef.current.add(listener);
    return () => {
      listenersRef.current.delete(listener);
    };
  }, []);

  const subscribeState = useCallback((listener: () => void) => {
    stateListenersRef.current.add(listener);
    return () => {
      stateListenersRef.current.delete(listener);
    };
  }, []);

  const start = useCallback(() => {
    setRequestedEnabled(true);
    setLaunchVersion((current) => current + 1);
    setError(null);
  }, []);

  useEffect(() => {
    if (!enabled) {
      return;
    }
    setRequestedEnabled(true);
    setLaunchVersion((current) => (current === 0 ? 1 : current));
  }, [enabled]);

  useEffect(() => {
    rootRef.current = root;
  }, [root]);

  useEffect(() => {
    sessionRef.current = session;
  }, [session]);

  useEffect(() => {
    runningRef.current = running;
  }, [running]);

  useEffect(() => {
    requestedEnabledRef.current = requestedEnabled;
  }, [requestedEnabled]);

  useEffect(() => {
    exitCodeRef.current = exitCode;
  }, [exitCode]);

  useEffect(() => {
    errorRef.current = error;
  }, [error]);

  useEffect(() => {
    activityEntriesRef.current = activityEntries;
  }, [activityEntries]);

  useEffect(() => {
    outputEntriesRef.current = outputEntries;
  }, [outputEntries]);

  useEffect(() => {
    problemsRef.current = problems;
  }, [problems]);

  useEffect(() => {
    for (const listener of stateListenersRef.current) {
      listener();
    }
  }, [activityEntries, error, exitCode, problems, root, running, session, outputEntries]);

  useEffect(() => {
    historyRef.current = "";
    lineBufferRef.current = "";
    inputBufferRef.current = "";
    currentCommandRef.current = null;
    pendingRustDiagnosticRef.current = null;
    cursorRef.current = 0;
    activityEntriesRef.current = [];
    outputEntriesRef.current = [];
    problemsRef.current = [];
    problemKeysRef.current = new Set();
    setActivityEntries([]);
    setOutputEntries([]);
    setProblems([]);
    setSession(null);
    setExitCode(null);
    setError(null);
    setRunning(requestedEnabled);

    if (!requestedEnabled) {
      sessionIdRef.current = null;
      return;
    }

    let cancelled = false;

    const openSession = async () => {
      try {
        const created = await adapter.createTerminalSession(root, 100, 28);
        if (cancelled) {
          await adapter.closeTerminalSession(created.sessionId).catch(() => undefined);
          return;
        }

        sessionIdRef.current = created.sessionId;
        setSession(created);
        setRunning(true);
        commitActivityEntries([
          createEntry("success", "terminal", "Workspace terminal attached", root),
        ]);

        while (!cancelled && sessionIdRef.current === created.sessionId) {
          const result = await adapter.readTerminalSession(created.sessionId, cursorRef.current);
          if (cancelled || sessionIdRef.current !== created.sessionId) {
            break;
          }

          if (result.chunks.length > 0) {
            const combinedText = result.chunks.map((chunk) => chunk.text).join("");
            pushHistory(combinedText);
            ingestText(combinedText);
          }

          cursorRef.current = result.cursor;
          setRunning(result.running);
          setExitCode(result.exitCode);

          if (!result.running && runningRef.current) {
            const title =
              result.exitCode == null
                ? "Terminal session closed"
                : `Terminal process exited (${result.exitCode})`;
            const kind: WorkspaceActivityEntry["kind"] =
              result.exitCode && result.exitCode !== 0 ? "error" : "info";
            const entry = createEntry(kind, "terminal", title, currentCommandRef.current);
            commitActivityEntries([entry]);
            commitOutputEntries([entry]);
          }

          if (!result.running) {
            break;
          }

          await new Promise((resolve) => {
            window.setTimeout(resolve, result.running ? 90 : 220);
          });
        }
      } catch (sessionError) {
        if (cancelled) {
          return;
        }

        const message = String(sessionError);
        setError(message);
        setRunning(false);
        const entry = createEntry("error", "terminal", "Terminal unavailable", message);
        commitActivityEntries([entry]);
        commitOutputEntries([entry]);
      }
    };

    void openSession();

    return () => {
      cancelled = true;
      const sessionId = sessionIdRef.current;
      sessionIdRef.current = null;
      cursorRef.current = 0;
      if (sessionId) {
        void adapter.closeTerminalSession(sessionId).catch(() => undefined);
      }
    };
  }, [
    adapter,
    commitActivityEntries,
    commitOutputEntries,
    createEntry,
    ingestText,
    launchVersion,
    pushHistory,
    requestedEnabled,
    root,
  ]);

  const controller = useMemo<WorkspaceTerminalController>(() => {
    return {
      get root() {
        return rootRef.current;
      },
      get enabled() {
        return requestedEnabledRef.current;
      },
      get session() {
        return sessionRef.current;
      },
      get running() {
        return runningRef.current;
      },
      get exitCode() {
        return exitCodeRef.current;
      },
      get error() {
        return errorRef.current;
      },
      get activityEntries() {
        return activityEntriesRef.current;
      },
      get outputEntries() {
        return outputEntriesRef.current;
      },
      get problems() {
        return problemsRef.current;
      },
      getHistory,
      subscribe,
      subscribeState,
      start,
      write,
      resize,
    };
  }, [getHistory, resize, start, subscribe, subscribeState, write]);

  return controller;
}

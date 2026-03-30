import { useEffect, useMemo, useRef, useState } from "react";
import clsx from "clsx";
import type { WorkspaceTerminalController } from "../types";

interface WorkspaceTerminalViewProps {
  controller: WorkspaceTerminalController;
  className?: string;
  showMeta?: boolean;
}

export function WorkspaceTerminalView({
  controller,
  className,
  showMeta = true,
}: WorkspaceTerminalViewProps) {
  const hostRef = useRef<HTMLDivElement | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [, setRenderVersion] = useState(0);
  const history = controller.getHistory();
  const shouldMountCanvas =
    Boolean(controller.session) ||
    Boolean(history) ||
    controller.running ||
    controller.exitCode != null ||
    Boolean(controller.error);

  useEffect(() => {
    return controller.subscribeState(() => {
      setRenderVersion((version) => version + 1);
    });
  }, [controller, controller.subscribeState]);

  useEffect(() => {
    if (!shouldMountCanvas || !hostRef.current) {
      return;
    }
    let cancelled = false;
    let cleanup: (() => void) | null = null;
    setError(null);

    const mountTerminal = async () => {
      try {
        const [{ Terminal }, { FitAddon }] = await Promise.all([
          import("@xterm/xterm"),
          import("@xterm/addon-fit"),
          import("@xterm/xterm/css/xterm.css"),
        ]);

        if (cancelled || !hostRef.current) {
          return;
        }

        const terminal = new Terminal({
          allowProposedApi: false,
          convertEol: true,
          cursorBlink: true,
          fontFamily:
            'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace',
          fontSize: 12,
          lineHeight: 1.45,
          rows: 24,
          cols: 100,
          scrollback: 4000,
          theme: {
            background: "#10110d",
            foreground: "#f3eee1",
            cursor: "#f8d26a",
            cursorAccent: "#161914",
            black: "#0d0f0b",
            red: "#f28073",
            green: "#8fd88b",
            yellow: "#f0cf6a",
            blue: "#6ea7ff",
            magenta: "#c59af0",
            cyan: "#6fd6df",
            white: "#f3eee1",
            brightBlack: "#6f7569",
            brightRed: "#ff9a8f",
            brightGreen: "#a7e7a4",
            brightYellow: "#ffd977",
            brightBlue: "#8bb9ff",
            brightMagenta: "#d9b4ff",
            brightCyan: "#8ae8ef",
            brightWhite: "#fffbf2",
          },
        });

        const fitAddon = new FitAddon();
        terminal.loadAddon(fitAddon);
        terminal.open(hostRef.current);
        terminal.reset();
        terminal.clear();

        const initialHistory = controller.getHistory();
        if (initialHistory) {
          terminal.write(initialHistory);
        }

        const pushResize = () => {
          fitAddon.fit();
          void controller
            .resize(Math.max(terminal.cols, 40), Math.max(terminal.rows, 12))
            .catch((resizeError) => {
              setError(String(resizeError));
            });
        };

        pushResize();
        terminal.focus();

        const resizeObserver = new ResizeObserver(() => {
          pushResize();
        });
        resizeObserver.observe(hostRef.current);

        const dataDisposable = terminal.onData((data) => {
          void controller.write(data).catch((writeError) => {
            setError(String(writeError));
          });
        });

        const unsubscribe = controller.subscribe((text) => {
          terminal.write(text);
        });

        cleanup = () => {
          unsubscribe();
          dataDisposable.dispose();
          resizeObserver.disconnect();
          terminal.dispose();
        };
      } catch (loadError) {
        if (!cancelled) {
          setError(String(loadError));
        }
      }
    };

    void mountTerminal();

    return () => {
      cancelled = true;
      cleanup?.();
    };
  }, [
    controller.getHistory,
    controller.resize,
    controller.root,
    controller.subscribe,
    controller.write,
    shouldMountCanvas,
  ]);

  const statusLabel = useMemo(() => {
    if (controller.error || error) {
      return "Terminal unavailable";
    }
    if (controller.running) {
      return "Live PTY session";
    }
    if (controller.exitCode == null) {
      return "Terminal closed";
    }
    return `Process exited (${controller.exitCode})`;
  }, [controller.error, controller.exitCode, controller.running, error]);

  return (
    <div className={clsx("workspace-terminal-view", className)}>
      {showMeta ? (
        <div className="workspace-terminal-meta">
          <div className="workspace-terminal-meta-copy">
            <span className="workspace-pane-eyebrow">{statusLabel}</span>
            <strong>{controller.session?.shell ?? "Workspace shell"}</strong>
          </div>
          <code>{controller.session?.rootPath ?? controller.root}</code>
        </div>
      ) : null}

      {shouldMountCanvas ? (
        <div className="workspace-terminal-canvas" ref={hostRef} />
      ) : (
        <div className="workspace-terminal-loading">
          <span className="workspace-pane-eyebrow">Terminal</span>
          <strong>
            {controller.enabled
              ? "Starting workspace runtime…"
              : "Terminal is idle"}
          </strong>
          <p>
            {controller.enabled
              ? "Preparing the shared PTY session for this workspace."
              : "Open the local Terminal panel or use Terminal > New Terminal to start a build-plane shell."}
          </p>
        </div>
      )}

      {controller.error || error ? (
        <div className="workspace-terminal-error">{controller.error ?? error}</div>
      ) : null}
    </div>
  );
}

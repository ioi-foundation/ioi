import { useCallback, useEffect, useMemo, useState } from "react";

const STORAGE_KEY = "autopilot.spotlight.vim_mode.v1";
const UPDATE_EVENT = "autopilot:spotlight-vim-mode-updated";

interface SpotlightVimModeEnvelope {
  enabled: boolean;
  mode: SpotlightVimModeId;
  updatedAtMs: number;
}

export type SpotlightVimModeId = "standard" | "vim_normal" | "vim_insert";

export interface SpotlightVimModeHint {
  id: string;
  label: string;
  keys: string;
  detail: string;
  availability: string;
}

export interface SpotlightVimModeSnapshot {
  generatedAtMs: number;
  enabled: boolean;
  modeId: SpotlightVimModeId;
  modeLabel: string;
  statusLabel: string;
  statusDetail: string;
  scopeLabel: string;
  sourceLabel: string;
  syncLabel: string;
  parityLabel: string;
  parityDetail: string;
  keyHints: SpotlightVimModeHint[];
}

interface UseSpotlightVimModeResult {
  snapshot: SpotlightVimModeSnapshot;
  toggle: () => void;
  setEnabled: (enabled: boolean) => void;
  enterInsertMode: () => void;
  enterNormalMode: () => void;
}

function canUseStorage(): boolean {
  return (
    typeof window !== "undefined" &&
    typeof window.localStorage !== "undefined"
  );
}

function modifierLabel(): string {
  if (typeof navigator === "undefined") {
    return "Ctrl";
  }

  const platform =
    `${navigator.platform || ""} ${navigator.userAgent || ""}`.toLowerCase();
  return platform.includes("mac") ? "Cmd" : "Ctrl";
}

function readEnvelope(): SpotlightVimModeEnvelope {
  if (!canUseStorage()) {
    return {
      enabled: false,
      mode: "standard",
      updatedAtMs: Date.now(),
    };
  }

  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) {
      return {
        enabled: false,
        mode: "standard",
        updatedAtMs: Date.now(),
      };
    }
    const parsed = JSON.parse(raw) as Partial<SpotlightVimModeEnvelope>;
    return {
      enabled: parsed.enabled === true,
      mode:
        parsed.enabled === true
          ? parsed.mode === "vim_insert"
            ? "vim_insert"
            : "vim_normal"
          : "standard",
      updatedAtMs:
        typeof parsed.updatedAtMs === "number" && Number.isFinite(parsed.updatedAtMs)
          ? parsed.updatedAtMs
          : Date.now(),
    };
  } catch {
    return {
      enabled: false,
      mode: "standard",
      updatedAtMs: Date.now(),
    };
  }
}

function persistEnvelope(envelope: SpotlightVimModeEnvelope) {
  if (!canUseStorage()) {
    return;
  }

  window.localStorage.setItem(STORAGE_KEY, JSON.stringify(envelope));
}

function dispatchEnvelopeUpdate(envelope: SpotlightVimModeEnvelope) {
  if (typeof window === "undefined") {
    return;
  }

  window.dispatchEvent(
    new CustomEvent<SpotlightVimModeEnvelope>(UPDATE_EVENT, {
      detail: envelope,
    }),
  );
}

export function useSpotlightVimMode(enabled = true): UseSpotlightVimModeResult {
  const [envelope, setEnvelope] = useState<SpotlightVimModeEnvelope>(() =>
    readEnvelope(),
  );

  useEffect(() => {
    if (!enabled || typeof window === "undefined") {
      return;
    }

    const syncFromStorage = () => {
      setEnvelope(readEnvelope());
    };

    const handleStorage = (event: StorageEvent) => {
      if (event.key !== STORAGE_KEY) {
        return;
      }
      syncFromStorage();
    };

    const handleEnvelopeUpdate = (
      event: Event,
    ) => {
      const detail = (event as CustomEvent<SpotlightVimModeEnvelope>).detail;
      if (detail && typeof detail.enabled === "boolean") {
        setEnvelope(detail);
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
  }, [enabled]);

  const setEnabled = useCallback((nextEnabled: boolean) => {
    const nextEnvelope: SpotlightVimModeEnvelope = {
      enabled: nextEnabled,
      mode: nextEnabled ? "vim_normal" : "standard",
      updatedAtMs: Date.now(),
    };
    persistEnvelope(nextEnvelope);
    setEnvelope(nextEnvelope);
    dispatchEnvelopeUpdate(nextEnvelope);
  }, []);

  const toggle = useCallback(() => {
    setEnabled(!envelope.enabled);
  }, [envelope.enabled, setEnabled]);

  const enterInsertMode = useCallback(() => {
    if (!envelope.enabled) {
      return;
    }
    const nextEnvelope = {
      enabled: true,
      mode: "vim_insert" as const,
      updatedAtMs: Date.now(),
    };
    persistEnvelope(nextEnvelope);
    setEnvelope(nextEnvelope);
    dispatchEnvelopeUpdate(nextEnvelope);
  }, [envelope.enabled]);

  const enterNormalMode = useCallback(() => {
    if (!envelope.enabled) {
      return;
    }
    const nextEnvelope = {
      enabled: true,
      mode: "vim_normal" as const,
      updatedAtMs: Date.now(),
    };
    persistEnvelope(nextEnvelope);
    setEnvelope(nextEnvelope);
    dispatchEnvelopeUpdate(nextEnvelope);
  }, [envelope.enabled]);

  const snapshot = useMemo<SpotlightVimModeSnapshot>(() => {
    const modifier = modifierLabel();
    const keyHints: SpotlightVimModeHint[] = envelope.enabled
      ? [
          {
            id: "vim-enter-insert",
            label: "Enter insert mode",
            keys: "i",
            detail:
              "From normal mode, `i` enters insert mode at the current caret and hands regular typing back to the composer.",
            availability:
              envelope.mode === "vim_normal" ? "Live now" : "Ready from normal mode",
          },
          {
            id: "vim-append-insert",
            label: "Append and insert",
            keys: "i · a · I · A",
            detail:
              "From normal mode, `i` and `a` enter insert near the caret, while `I` jumps to the first non-blank column and `A` jumps to the end of the current line before entering insert mode.",
            availability:
              envelope.mode === "vim_normal" ? "Live now" : "Ready from normal mode",
          },
          {
            id: "vim-caret-motion",
            label: "Move the caret",
            keys: "h · j · k · l",
            detail:
              "In normal mode, `h` and `l` move the composer caret left and right, while `j` and `k` move down and up between composer lines without entering insert mode.",
            availability:
              envelope.mode === "vim_normal" ? "Live now" : "Ready from normal mode",
          },
          {
            id: "vim-line-motion",
            label: "Jump within the line",
            keys: "0 · ^ · $",
            detail:
              "In normal mode, `0` jumps to the start of the current line, `^` jumps to the first non-blank column, and `$` jumps to the end of the current line; `0` also stays available as an operator motion for `d0` and `c0`.",
            availability:
              envelope.mode === "vim_normal" ? "Live now" : "Ready from normal mode",
          },
          {
            id: "vim-document-motion",
            label: "Jump by absolute lines",
            keys: "gg · G · 2gg · 2G",
            detail:
              "In normal mode, `gg` jumps to the first line, `G` jumps to the last line, and count prefixes like `2gg` or `2G` jump to an absolute line over the same shared composer motion state.",
            availability:
              envelope.mode === "vim_normal" ? "Live now" : "Ready from normal mode",
          },
          {
            id: "vim-word-motion",
            label: "Move by word runs",
            keys: "w · b · e",
            detail:
              "In normal mode, `w` moves to the next word-like run, `b` moves back to the previous word-like run, and `e` lands on the end of the current or next word-like run.",
            availability:
              envelope.mode === "vim_normal" ? "Live now" : "Ready from normal mode",
          },
          {
            id: "vim-delete-char",
            label: "Delete a character",
            keys: "x · 3x",
            detail:
              "In normal mode, `x` deletes the character under or after the caret without entering insert mode, and count prefixes like `3x` repeat the same edit depth.",
            availability:
              envelope.mode === "vim_normal" ? "Live now" : "Ready from normal mode",
          },
          {
            id: "vim-change-delete-operators",
            label: "Delete and change by motion",
            keys:
              "dw · de · db · d0 · d^ · dgg · dG · cw · ce · cb · c0 · c^ · cgg · cG · diw · daw · di\" · da\" · ci\" · ca\" · di' · da' · ci' · ca' · di( · da( · ci( · ca( · di[ · da[ · ci[ · ca[ · di{ · da{ · ci{ · ca{ · D · C · dd · cc · 2w · 2dw · 2dd · o · O",
            detail:
              "In normal mode, `dw` and `de` delete forward by word motion, `db` deletes backward by word motion, `d0` trims back to the start of the current line, `d^` trims back to the first non-blank column, `dgg` trims back to the requested document line, `dG` deletes to the document end, `cw`, `ce`, `cb`, `c0`, `c^`, `cgg`, and `cG` change those spans into insert mode, `diw` and `ciw` target the current inner word run, `daw` and `caw` include surrounding spacing, `di\"` / `ci\"` and `di'` / `ci'` target quoted content, `da\"` / `ca\"` and `da'` / `ca'` include the surrounding quotes, `di(` / `ci(`, `di[` / `ci[`, and `di{` / `ci{` target the current delimited content, `da(` / `ca(`, `da[` / `ca[`, and `da{` / `ca{` include the surrounding delimiters, count prefixes like `2w`, `2dw`, `2dd`, and `3x` repeat supported motions and edits, and count-driven `gg` / `G` forms also target absolute document lines, `D` and `C` operate to the end of the line, doubled operators apply the same delete/change flow to the whole current line, and `o` / `O` open a new indented line below or above before entering insert mode.",
            availability:
              envelope.mode === "vim_normal" ? "Live now" : "Ready from normal mode",
          },
          {
            id: "vim-repeat-change",
            label: "Repeat the last edit",
            keys: ".",
            detail:
              "In normal mode, `.` repeats the last Spotlight composer edit command, including `x`, line-end edits, and doubled line operators.",
            availability:
              envelope.mode === "vim_normal" ? "Live now" : "Ready from normal mode",
          },
          {
            id: "vim-return-normal",
            label: "Return to normal",
            keys: "Esc",
            detail:
              "Escape now returns the Spotlight composer to normal mode instead of hiding the shell when Vim mode is enabled.",
            availability:
              envelope.mode === "vim_insert" ? "Live now" : "Available from insert mode",
          },
          {
            id: "vim-shell-fallback",
            label: "Shell command affordances",
            keys: `${modifier}+K · /`,
            detail:
              "Command palette and slash affordances stay available while the first normal-mode commands are active.",
            availability: "Live today",
          },
        ]
      : [
          {
            id: "vim-standard-input",
            label: "Standard composer",
            keys: `${modifier}+K · / · Enter`,
            detail:
              "The shell is currently using its standard command-palette and submit shortcuts.",
            availability: "Live today",
          },
          {
            id: "vim-preview-toggle",
            label: "Vim shell toggle",
            keys: "/vim",
            detail:
              "Enable Vim Mode to use the current Spotlight subset: `i`, `a`, `I`, `A`, `h`, `j`, `k`, `l`, `0`, `^`, `$`, `gg`, `G`, absolute-line jumps like `2gg` and `2G`, `w`, `b`, `e`, count prefixes like `2w`, `3x`, `2dw`, and `2dd`, `x`, `dw`, `de`, `db`, `d0`, `d^`, `dgg`, `dG`, `cw`, `ce`, `cb`, `c0`, `c^`, `cgg`, `cG`, `diw`, `daw`, `ciw`, `caw`, `di\"`, `da\"`, `ci\"`, `ca\"`, `di'`, `da'`, `ci'`, `ca'`, `di(`, `da(`, `ci(`, `ca(`, `di[`, `da[`, `ci[`, `ca[`, `di{`, `da{`, `ci{`, `ca{`, `D`, `C`, `dd`, `cc`, `o`, `O`, `.`, and `Esc`.",
            availability: "Available now",
          },
        ];

    return {
      generatedAtMs: Date.now(),
      enabled: envelope.enabled,
      modeId: envelope.mode,
      modeLabel: envelope.enabled
        ? envelope.mode === "vim_insert"
          ? "Insert mode"
          : "Normal mode"
        : "Standard shell input",
      statusLabel: envelope.enabled
        ? envelope.mode === "vim_insert"
          ? "Vim insert mode active"
          : "Vim normal mode active"
        : "Standard posture enabled",
      statusDetail: envelope.enabled
        ? envelope.mode === "vim_insert"
          ? "The Spotlight composer is currently accepting normal typing under Vim insert mode."
          : "The Spotlight composer is currently in Vim normal mode. Use `h`, `j`, `k`, and `l` to move, `0`, `^`, and `$` for line edges, `gg`, `G`, and absolute-line jumps like `2gg` / `2G` for document travel, `w`, `b`, and `e` for word runs, count prefixes like `2w` and `3x` for repeat depth, `x`, `dw`, `de`, `db`, `d0`, `d^`, `dgg`, `dG`, `cw`, `ce`, `cb`, `c0`, `c^`, `cgg`, `cG`, `diw`, `daw`, `ciw`, `caw`, `di\"`, `da\"`, `ci\"`, `ca\"`, `di'`, `da'`, `ci'`, `ca'`, `di(`, `da(`, `ci(`, `ca(`, `di[`, `da[`, `ci[`, `ca[`, `di{`, `da{`, `ci{`, `ca{`, `D`, `C`, `dd`, `cc`, `o`, and `O` to edit, `.` to repeat the last edit, `i`, `a`, `I`, or `A` to enter insert mode, and `Esc` to stay in command posture."
        : "The shell is using its standard input stack. Vim mode can be enabled for the current Spotlight command subset.",
      scopeLabel: "Spotlight shell session",
      sourceLabel: "Local Spotlight preference",
      syncLabel: "Persists in local shell storage",
      parityLabel: envelope.enabled ? "Behavioral partial parity" : "Command surface parity",
      parityDetail:
        "This slice now includes real modal composer behavior with repeatable edits: normal mode, insert mode, `i`, `a`, `I`, `A`, `h`, `j`, `k`, `l`, `0`, `^`, `$`, `gg`, `G`, absolute-line jumps through count prefixes, `w`, `b`, `e`, count prefixes for supported motions and edits, `x`, `dw`, `de`, `db`, `d0`, `d^`, `dgg`, `dG`, `cw`, `ce`, `cb`, `c0`, `c^`, `cgg`, `cG`, `diw`, `daw`, `ciw`, `caw`, `di\"`, `da\"`, `ci\"`, `ca\"`, `di'`, `da'`, `ci'`, `ca'`, `di(`, `da(`, `ci(`, `ca(`, `di[`, `da[`, `ci[`, `ca[`, `di{`, `da{`, `ci{`, `ca{`, `D`, `C`, `dd`, `cc`, `o`, `O`, `.`, and `Esc`. Richer Vim motions and broader cross-shell/editor parity are still follow-on work.",
      keyHints,
    };
  }, [envelope.enabled, envelope.mode]);

  return {
    snapshot,
    toggle,
    setEnabled,
    enterInsertMode,
    enterNormalMode,
  };
}

import { useEffect } from "react";

export interface UseSessionShellShortcutsOptions {
  activeDropdown: string | null;
  clearActiveDropdown: () => void;
  inspectionVisible: boolean;
  closeInspectionSurface: () => Promise<void> | void;
  canHideShell?: boolean;
  hideCurrentShell?: () => Promise<void>;
  toggleCommandPalette?: () => void;
  toggleSidebar: () => void;
  startNewSession: () => void;
}

function isEditableTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) {
    return false;
  }

  const tag = target.tagName.toLowerCase();
  return (
    target.isContentEditable ||
    tag === "input" ||
    tag === "textarea" ||
    tag === "select"
  );
}

export function useSessionShellShortcuts({
  activeDropdown,
  clearActiveDropdown,
  inspectionVisible,
  closeInspectionSurface,
  canHideShell = false,
  hideCurrentShell,
  toggleCommandPalette,
  toggleSidebar,
  startNewSession,
}: UseSessionShellShortcutsOptions) {
  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      const key = event.key.toLowerCase();
      const hasCommandModifier = event.metaKey || event.ctrlKey;

      if (hasCommandModifier && key === "k") {
        event.preventDefault();
        if (toggleCommandPalette) {
          toggleCommandPalette();
          return;
        }
        toggleSidebar();
        return;
      }

      if (hasCommandModifier && key === "n") {
        event.preventDefault();
        startNewSession();
        return;
      }

      if (isEditableTarget(event.target)) {
        return;
      }

      if (event.key === "Escape") {
        if (activeDropdown) {
          clearActiveDropdown();
        } else if (inspectionVisible) {
          void closeInspectionSurface();
        } else if (canHideShell) {
          void hideCurrentShell?.();
        }
        return;
      }

    };

    window.addEventListener("keydown", handleKeyDown, true);
    return () => window.removeEventListener("keydown", handleKeyDown, true);
  }, [
    activeDropdown,
    canHideShell,
    clearActiveDropdown,
    closeInspectionSurface,
    hideCurrentShell,
    inspectionVisible,
    startNewSession,
    toggleCommandPalette,
    toggleSidebar,
  ]);
}

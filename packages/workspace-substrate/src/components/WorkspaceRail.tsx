import clsx from "clsx";
import type { WorkspaceRailProps } from "../types";

const ITEMS: Array<{ id: WorkspaceRailProps["activePane"]; label: string; short: string }> = [
  { id: "files", label: "Files", short: "F" },
  { id: "search", label: "Search", short: "S" },
  { id: "source-control", label: "Source Control", short: "G" },
];

export function WorkspaceRail({ activePane, onSelectPane }: WorkspaceRailProps) {
  return (
    <nav className="workspace-rail" aria-label="Workspace navigation">
      {ITEMS.map((item) => (
        <button
          key={item.id}
          type="button"
          className={clsx(
            "workspace-rail-button",
            activePane === item.id && "is-active",
          )}
          onClick={() => onSelectPane(item.id)}
          title={item.label}
          aria-label={item.label}
        >
          <span className="workspace-rail-button-indicator" aria-hidden="true" />
          <span className="workspace-rail-button-glyph" aria-hidden="true">
            {item.short}
          </span>
        </button>
      ))}
    </nav>
  );
}

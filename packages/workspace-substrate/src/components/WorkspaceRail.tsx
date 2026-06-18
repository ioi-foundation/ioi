import clsx from "clsx";
import { Codicon } from "./Codicon";
import workbenchRailStripFiles from "../assets/workbench-rail-strip-files.png";
import workbenchRailStripSearch from "../assets/workbench-rail-strip-search.png";
import workbenchRailStripSourceControl from "../assets/workbench-rail-strip-source-control.png";
import type { WorkspaceRailProps } from "../types";

const PRIMARY_ITEMS: Array<{ id: WorkspaceRailProps["activePane"]; label: string }> = [
  { id: "files", label: "Explorer" },
  { id: "search", label: "Search" },
  { id: "source-control", label: "Source Control" },
];

function glyphForPane(id: WorkspaceRailProps["activePane"]) {
  switch (id) {
    case "files":
      return <Codicon name="file" />;
    case "search":
      return <Codicon name="search" />;
    case "source-control":
      return <Codicon name="source-control" />;
    default:
      return null;
  }
}

function stripForPane(id: WorkspaceRailProps["activePane"]) {
  switch (id) {
    case "search":
      return workbenchRailStripSearch;
    case "source-control":
      return workbenchRailStripSourceControl;
    case "files":
    default:
      return workbenchRailStripFiles;
  }
}

export function WorkspaceRail({
  activePane,
  onSelectPane,
  onTogglePrimarySidebar,
}: WorkspaceRailProps) {
  return (
    <nav
      className="workspace-rail"
      aria-label="Workspace navigation"
      data-inspection-target="workspace-rail"
    >
      <img src={stripForPane(activePane)} alt="" className="workspace-rail-strip" aria-hidden="true" />
      <div className="workspace-rail-live">
        <div className="workspace-rail-group workspace-rail-group--menu">
          <button
            type="button"
            className="workspace-rail-button workspace-rail-button--menu"
            onClick={onTogglePrimarySidebar}
            aria-label="Toggle primary side bar"
            title="Toggle primary side bar"
          >
            <span className="workspace-rail-button-glyph">
              <Codicon name="menu" />
            </span>
          </button>
        </div>

        <div className="workspace-rail-group workspace-rail-group--primary">
          {PRIMARY_ITEMS.map((item) => (
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
              data-inspection-target="workspace-rail-item"
              data-workspace-pane={item.id}
            >
              <span className="workspace-rail-button-indicator" aria-hidden="true" />
              <span className="workspace-rail-button-glyph" aria-hidden="true">
                {glyphForPane(item.id)}
              </span>
            </button>
          ))}
        </div>

        <div className="workspace-rail-spacer" />
      </div>
    </nav>
  );
}

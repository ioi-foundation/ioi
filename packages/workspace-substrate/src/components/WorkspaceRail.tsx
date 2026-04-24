import clsx from "clsx";
import { Codicon } from "./Codicon";
import workbenchRailStripExtensions from "../assets/workbench-rail-strip-extensions.png";
import workbenchRailStripFiles from "../assets/workbench-rail-strip-files.png";
import workbenchRailStripIoi from "../assets/workbench-rail-strip-ioi.png";
import workbenchRailStripRunAndDebug from "../assets/workbench-rail-strip-run-and-debug.png";
import workbenchRailStripSearch from "../assets/workbench-rail-strip-search.png";
import workbenchRailStripSourceControl from "../assets/workbench-rail-strip-source-control.png";
import type { WorkspaceRailProps } from "../types";

const PRIMARY_ITEMS: Array<{ id: WorkspaceRailProps["activePane"]; label: string }> = [
  { id: "files", label: "Explorer" },
  { id: "search", label: "Search" },
  { id: "source-control", label: "Source Control" },
];

const SECONDARY_ITEMS: Array<{ id: WorkspaceRailProps["activePane"]; label: string }> = [
  { id: "run-and-debug", label: "Run and Debug" },
  { id: "extensions", label: "Extensions" },
  { id: "ioi", label: "IOI" },
];

function IoIActivityIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path d="M5 5h6v6H5V5Zm8 0h6v3h-6V5Zm0 5h6v9h-6v-9ZM5 13h6v6H5v-6Z" fill="currentColor" />
    </svg>
  );
}

function glyphForPane(id: WorkspaceRailProps["activePane"]) {
  switch (id) {
    case "files":
      return <Codicon name="file" />;
    case "search":
      return <Codicon name="search" />;
    case "source-control":
      return <Codicon name="source-control" />;
    case "run-and-debug":
      return <Codicon name="debug-alt-small" />;
    case "extensions":
      return <Codicon name="extensions" />;
    case "ioi":
      return <IoIActivityIcon />;
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
    case "run-and-debug":
      return workbenchRailStripRunAndDebug;
    case "extensions":
      return workbenchRailStripExtensions;
    case "ioi":
      return workbenchRailStripIoi;
    case "files":
    default:
      return workbenchRailStripFiles;
  }
}

export function WorkspaceRail({
  activePane,
  onSelectPane,
  onSelectOperatorSurface,
  onTogglePrimarySidebar,
}: WorkspaceRailProps) {
  return (
    <nav className="workspace-rail" aria-label="Workspace navigation">
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
            >
              <span className="workspace-rail-button-indicator" aria-hidden="true" />
              <span className="workspace-rail-button-glyph" aria-hidden="true">
                {glyphForPane(item.id)}
              </span>
            </button>
          ))}
        </div>

        <div className="workspace-rail-group workspace-rail-group--secondary">
          {SECONDARY_ITEMS.map((item) => (
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
                {glyphForPane(item.id)}
              </span>
            </button>
          ))}
        </div>

        <div className="workspace-rail-spacer" />

        <div className="workspace-rail-group workspace-rail-group--footer">
          <button
            type="button"
            className="workspace-rail-button"
            onClick={() => {
              onSelectOperatorSurface?.("connections");
              onSelectPane("ioi");
            }}
            title="Connections"
            aria-label="Connections"
          >
            <span className="workspace-rail-button-glyph">
              <Codicon name="account" />
            </span>
          </button>
          <button
            type="button"
            className="workspace-rail-button"
            onClick={() => {
              onSelectOperatorSurface?.("policy");
              onSelectPane("ioi");
            }}
            title="Policy"
            aria-label="Policy"
          >
            <span className="workspace-rail-button-glyph">
              <Codicon name="settings-gear" />
            </span>
          </button>
        </div>
      </div>
    </nav>
  );
}

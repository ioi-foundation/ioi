import "./IDEHeader.css";

interface IDEHeaderProps {
  projectName?: string;
  onSave?: () => void;
  onOpen?: () => void;
  onRun?: () => void;
  onZoomIn?: () => void;
  onZoomOut?: () => void;
  onFit?: () => void;
}

export function IDEHeader({
  projectName,
  onSave,
  onOpen,
  onRun,
  onZoomIn,
  onZoomOut,
  onFit,
}: IDEHeaderProps) {
  return (
    <header className="ide-header">
      <div className="header-row header-toolbar header-toolbar--editor">
        <div className="toolbar-section toolbar-section--project">
          <span className="project-kicker">Workflow</span>
          <span className="project-meta project-meta--strong">
            {projectName || "Untitled Agent"}
          </span>
        </div>

        <div className="toolbar-section toolbar-section--actions">
          {onOpen ? (
            <button className="toolbar-btn toolbar-btn--secondary" onClick={onOpen} type="button">
              Open
            </button>
          ) : null}
          {onSave ? (
            <button className="toolbar-btn toolbar-btn--secondary" onClick={onSave} type="button">
              Save
            </button>
          ) : null}
          <button className="toolbar-btn toolbar-btn--secondary" onClick={onZoomIn} type="button">
            Zoom In
          </button>
          <button className="toolbar-btn toolbar-btn--secondary" onClick={onZoomOut} type="button">
            Zoom Out
          </button>
          <button className="toolbar-btn toolbar-btn--secondary" onClick={onFit} type="button">
            Fit
          </button>
          <button className="toolbar-btn toolbar-btn--primary" onClick={onRun} type="button">
            Run
          </button>
        </div>
      </div>
    </header>
  );
}

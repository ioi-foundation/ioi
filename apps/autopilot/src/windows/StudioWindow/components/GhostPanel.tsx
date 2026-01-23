export function GhostChatPanel() {
  return (
    <aside className="ghost-panel">
      <div className="ghost-panel-header">
        <h2 className="ghost-panel-title">
          <span className="ghost-panel-indicator" />
          Ghost Copilot
        </h2>
      </div>
      <div className="ghost-panel-messages">
        <div className="ghost-panel-msg">
          I'm watching your actions. Perform the manual task in the "Sandbox" browser, and I'll generate the graph nodes.
        </div>
      </div>
      <div className="ghost-panel-input">
        <input type="text" placeholder="Describe intent..." />
      </div>
    </aside>
  );
}

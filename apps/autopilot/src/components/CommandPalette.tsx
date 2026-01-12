import { useState, useRef, useEffect } from "react";
import { useAgentStore } from "../store/agentStore";
import "./CommandPalette.css";

interface CommandPaletteProps {
  onClose: () => void;
}

interface Command {
  id: string;
  label: string;
  shortcut?: string;
  icon: string;
  category: string;
}

const commands: Command[] = [
  { id: "run", label: "Run Workflow", shortcut: "F5", icon: "▶", category: "Execution" },
  { id: "replay", label: "Replay Last Run", shortcut: "R", icon: "⟲", category: "Execution" },
  { id: "pause", label: "Pause Execution", icon: "⏸", category: "Execution" },
  { id: "add-node", label: "Add Node", shortcut: "Tab", icon: "+", category: "Canvas" },
  { id: "add-subgraph", label: "Add Subgraph", icon: "□", category: "Canvas" },
  { id: "fit-graph", label: "Fit to Graph", shortcut: "⌘1", icon: "⤢", category: "View" },
  { id: "toggle-minimap", label: "Toggle Minimap", shortcut: "M", icon: "⊞", category: "View" },
  { id: "toggle-grid", label: "Toggle Grid", shortcut: "G", icon: "#", category: "View" },
  { id: "open-timeline", label: "Open Timeline", shortcut: "T", icon: "⏱", category: "Panels" },
  { id: "open-receipts", label: "Open Receipts", icon: "🧾", category: "Panels" },
  { id: "open-settings", label: "Open Settings", shortcut: "⌘,", icon: "⚙", category: "App" },
  { id: "open-providers", label: "Browse Providers", icon: "☁", category: "App" },
  { id: "open-marketplace", label: "Browse Marketplace", icon: "🛒", category: "App" },
];

export function CommandPalette({ onClose }: CommandPaletteProps) {
  const [query, setQuery] = useState("");
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const { startTask } = useAgentStore();

  const filteredCommands = commands.filter(
    (cmd) =>
      cmd.label.toLowerCase().includes(query.toLowerCase()) ||
      cmd.category.toLowerCase().includes(query.toLowerCase())
  );

  // Group by category
  const groupedCommands = filteredCommands.reduce((acc, cmd) => {
    if (!acc[cmd.category]) acc[cmd.category] = [];
    acc[cmd.category].push(cmd);
    return acc;
  }, {} as Record<string, Command[]>);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  useEffect(() => {
    setSelectedIndex(0);
  }, [query]);

  const handleExecute = (cmdId: string) => {
    if (cmdId === "run") {
      startTask("Run from Palette");
    }
    console.log("Execute:", cmdId);
    onClose();
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    switch (e.key) {
      case "ArrowDown":
        e.preventDefault();
        setSelectedIndex((i) => Math.min(i + 1, filteredCommands.length - 1));
        break;
      case "ArrowUp":
        e.preventDefault();
        setSelectedIndex((i) => Math.max(i - 1, 0));
        break;
      case "Enter":
        e.preventDefault();
        if (filteredCommands[selectedIndex]) {
          handleExecute(filteredCommands[selectedIndex].id);
        }
        break;
      case "Escape":
        onClose();
        break;
    }
  };

  return (
    <div className="command-palette-overlay" onClick={onClose}>
      <div className="command-palette" onClick={(e) => e.stopPropagation()}>
        <div className="command-palette-input-wrapper">
          <svg
            className="command-palette-search-icon"
            width="16"
            height="16"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
          >
            <circle cx="11" cy="11" r="8" />
            <path d="m21 21-4.35-4.35" />
          </svg>
          <input
            ref={inputRef}
            type="text"
            className="command-palette-input"
            placeholder="Search commands…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={handleKeyDown}
          />
          <kbd className="command-palette-esc">ESC</kbd>
        </div>

        <div className="command-palette-results">
          {Object.entries(groupedCommands).map(([category, cmds]) => (
            <div key={category} className="command-group">
              <div className="command-group-title">{category}</div>
              {cmds.map((cmd, cmdIdx) => {
                const globalIdx = filteredCommands.indexOf(cmd);
                return (
                  <button
                    key={cmd.id}
                    className={`command-item ${globalIdx === selectedIndex ? "selected" : ""}`}
                    onClick={() => handleExecute(cmd.id)}
                  >
                    <span className="command-icon">{cmd.icon}</span>
                    <span className="command-label">{cmd.label}</span>
                    {cmd.shortcut && <kbd className="command-shortcut">{cmd.shortcut}</kbd>}
                  </button>
                );
              })}
            </div>
          ))}

          {filteredCommands.length === 0 && (
            <div className="command-empty">
              No commands found for "{query}"
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
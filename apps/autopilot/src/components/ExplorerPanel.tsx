import { useState } from "react";
import "./ExplorerPanel.css";

interface ExplorerPanelProps {
  width: number;
}

type Tab = "ONTOLOGY" | "LIBRARY";

// --- Types ---
interface TreeItem {
  id: string;
  name: string;
  type: "category" | "object" | "link" | "action" | "function";
  children?: TreeItem[];
  expanded?: boolean;
  meta?: string;
}

interface LibraryItem {
  id: string;
  name: string;
  icon: string;
  type: string;
}

interface LibraryGroup {
  id: string;
  name: string;
  items: LibraryItem[];
}

// --- Data ---
const ontologyTree: TreeItem[] = [
  {
    id: "obj-types",
    name: "Object Types",
    type: "category",
    expanded: true,
    children: [
      { id: "ot-invoice", name: "Invoice", type: "object", meta: "12 props" },
      { id: "ot-vendor", name: "Vendor", type: "object", meta: "8 props" },
      { id: "ot-payment", name: "Payment_Run", type: "object", meta: "5 props" },
      { id: "ot-risk", name: "Risk_Report", type: "object", meta: "22 props" },
    ],
  },
  {
    id: "link-types",
    name: "Link Types",
    type: "category",
    expanded: true,
    children: [
      { id: "lt-inv-vend", name: "Invoice ↔ Vendor", type: "link", meta: "Many-to-One" },
      { id: "lt-inv-pay", name: "Invoice ↔ Payment", type: "link", meta: "One-to-One" },
    ],
  },
  {
    id: "actions",
    name: "Actions",
    type: "category",
    expanded: true,
    children: [
      { id: "act-approve", name: "Approve_Invoice", type: "action", meta: "Write" },
      { id: "act-flag", name: "Flag_Risk", type: "action", meta: "Write" },
      { id: "act-email", name: "Send_Remittance", type: "action", meta: "Side-effect" },
    ],
  },
];

const libraryGroups: LibraryGroup[] = [
  {
    id: "triggers",
    name: "Triggers",
    items: [
      { id: "cron", name: "Cron Schedule", icon: "⏰", type: "trigger" },
      { id: "webhook", name: "Webhook", icon: "🔗", type: "trigger" },
      { id: "manual", name: "Manual Invocation", icon: "▶️", type: "trigger" },
    ],
  },
  {
    id: "actions",
    name: "Actions & Tools",
    items: [
      { id: "http", name: "HTTP Request", icon: "🌐", type: "action" },
      { id: "llm", name: "LLM Transform", icon: "🧠", type: "model" },
      { id: "code", name: "Code Execution", icon: "💻", type: "action" },
      { id: "slack", name: "Slack Message", icon: "💬", type: "action" },
    ],
  },
  {
    id: "logic",
    name: "Logic & Governance",
    items: [
      { id: "gate", name: "Policy Gate", icon: "🛡️", type: "gate" },
      { id: "router", name: "Conditional Router", icon: "🔀", type: "action" },
      { id: "receipt", name: "Receipt Logger", icon: "🧾", type: "receipt" },
    ],
  },
];

export function ExplorerPanel({ width }: ExplorerPanelProps) {
  // [MODIFIED] Changed default to LIBRARY
  const [activeTab, setActiveTab] = useState<Tab>("LIBRARY");
  const [tree, setTree] = useState(ontologyTree);
  const [selectedId, setSelectedId] = useState<string>("ot-invoice");
  const [searchQuery, setSearchQuery] = useState("");

  const toggleExpand = (id: string) => {
    const updateTree = (items: TreeItem[]): TreeItem[] => {
      return items.map((item) => {
        if (item.id === id) {
          return { ...item, expanded: !item.expanded };
        }
        if (item.children) {
          return { ...item, children: updateTree(item.children) };
        }
        return item;
      });
    };
    setTree(updateTree(tree));
  };

  const handleDragStart = (e: React.DragEvent, item: LibraryItem) => {
    e.dataTransfer.setData("nodeId", item.id);
    e.dataTransfer.setData("nodeName", item.name);
    e.dataTransfer.effectAllowed = "copy";
  };

  return (
    <aside className="explorer-panel" style={{ width }}>
      {/* Tabs */}
      <div className="explorer-tabs">
        <button
          className={`explorer-tab ${activeTab === "LIBRARY" ? "active" : ""}`}
          onClick={() => setActiveTab("LIBRARY")}
        >
          Library
        </button>
        <button
          className={`explorer-tab ${activeTab === "ONTOLOGY" ? "active" : ""}`}
          onClick={() => setActiveTab("ONTOLOGY")}
        >
          Ontology
        </button>
      </div>

      {/* Search */}
      <div className="explorer-search">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <circle cx="11" cy="11" r="8" />
          <path d="m21 21-4.35-4.35" />
        </svg>
        <input
          type="text"
          className="search-input"
          placeholder={activeTab === "ONTOLOGY" ? "Search objects..." : "Search tools..."}
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
        />
      </div>

      <div className="explorer-content">
        {activeTab === "ONTOLOGY" ? (
          <>
            <div className="section-header">Active Ontology: Finance_V2</div>
            <div className="explorer-tree">
              {tree.map((item) => (
                <TreeNode
                  key={item.id}
                  item={item}
                  depth={0}
                  selectedId={selectedId}
                  onSelect={setSelectedId}
                  onToggle={toggleExpand}
                />
              ))}
            </div>
          </>
        ) : (
          <div className="explorer-library">
            {libraryGroups.map((group) => (
              <div key={group.id} className="library-group">
                <div className="section-header">{group.name}</div>
                {group.items.map((item) => (
                  <div
                    key={item.id}
                    className="library-item"
                    draggable
                    onDragStart={(e) => handleDragStart(e, item)}
                  >
                    <span className="lib-icon">{item.icon}</span>
                    <span className="lib-name">{item.name}</span>
                    <span className="lib-desc">{item.type}</span>
                  </div>
                ))}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Legend (Only for Ontology) */}
      {activeTab === "ONTOLOGY" && (
        <div className="explorer-legend">
          <div className="legend-title">Ontology Elements</div>
          <div className="legend-grid">
            <div className="legend-item"><div className="legend-color" style={{background: "#A78BFA"}}></div><span className="legend-label">Object</span></div>
            <div className="legend-item"><div className="legend-color" style={{background: "#60A5FA"}}></div><span className="legend-label">Link</span></div>
            <div className="legend-item"><div className="legend-color" style={{background: "#34D399"}}></div><span className="legend-label">Action</span></div>
            <div className="legend-item"><div className="legend-color" style={{background: "#FBBF24"}}></div><span className="legend-label">Function</span></div>
          </div>
        </div>
      )}
    </aside>
  );
}

// --- Tree Node Component ---
interface TreeNodeProps {
  item: TreeItem;
  depth: number;
  selectedId: string;
  onSelect: (id: string) => void;
  onToggle: (id: string) => void;
}

function TreeNode({ item, depth, selectedId, onSelect, onToggle }: TreeNodeProps) {
  const hasChildren = item.children && item.children.length > 0;
  const isSelected = item.id === selectedId;

  const getIcon = () => {
    switch (item.type) {
      case "category": return item.expanded ? "📂" : "📁";
      case "object": return "🧊";
      case "link": return "🔗";
      case "action": return "⚡";
      case "function": return "ƒ";
      default: return "📄";
    }
  };

  const getTypeClass = () => {
    switch (item.type) {
      case "object": return "object-type";
      case "link": return "link-type";
      case "action": return "action-type";
      default: return "";
    }
  };

  return (
    <div className="tree-node">
      <div
        className={`tree-item ${isSelected ? "selected" : ""} ${getTypeClass()}`}
        style={{ paddingLeft: 12 + depth * 12 }}
        onClick={() => {
          if (hasChildren) onToggle(item.id);
          onSelect(item.id);
        }}
      >
        {hasChildren ? (
          <span className={`tree-arrow ${item.expanded ? "expanded" : ""}`}>
            <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="m9 18 6-6-6-6" />
            </svg>
          </span>
        ) : (
          <span className="tree-arrow-placeholder" />
        )}
        <span className="tree-icon">{getIcon()}</span>
        <span className="tree-name">{item.name}</span>
        {item.meta && <span className="tree-meta">{item.meta}</span>}
      </div>

      {hasChildren && item.expanded && (
        <div className="tree-children">
          {item.children!.map((child) => (
            <TreeNode
              key={child.id}
              item={child}
              depth={depth + 1}
              selectedId={selectedId}
              onSelect={onSelect}
              onToggle={onToggle}
            />
          ))}
        </div>
      )}
    </div>
  );
}
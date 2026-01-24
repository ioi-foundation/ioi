import { useState, useCallback, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import "./ContextSidebar.css";

interface ContextSidebarProps {
  width: number;
}

type SidebarTab = "MEMORY" | "INVENTORY";

// Node categories for the Inventory tab
interface NodeCategory {
  id: string;
  name: string;
  expanded: boolean;
  nodes: {
    id: string;
    name: string;
    icon: string;
    description?: string;
    schema?: string; // [NEW] Added schema
  }[];
}

const nodeCategories: NodeCategory[] = [
  {
    id: "ioi-native",
    name: "IOI Native",
    expanded: true,
    nodes: [
      { id: "agency-firewall", name: "Agency Firewall", icon: "🛡️" },
      { id: "receipt-logger", name: "Receipt Logger", icon: "🧾" },
      { id: "burst-router", name: "Burst Router", icon: "⚡" },
      { id: "provider-select", name: "Provider Select", icon: "🎯" },
      { id: "attestation", name: "Attestation Node", icon: "✅" },
    ],
  },
  {
    id: "tools",
    name: "Tools",
    expanded: false,
    nodes: [
      { id: "filesystem", name: "Filesystem", icon: "📁" },
      { id: "browser", name: "Browser", icon: "🌐" },
      { id: "http", name: "HTTP Request", icon: "🔗" },
      { id: "cron", name: "Cron Trigger", icon: "⏰" },
      { id: "slack", name: "Slack", icon: "💬" },
    ],
  },
  {
    id: "models",
    name: "Models",
    expanded: false,
    nodes: [
      { id: "local-llm", name: "Local LLM", icon: "🤖" },
      { id: "remote-llm", name: "Remote LLM", icon: "☁️" },
      { id: "embeddings", name: "Embeddings", icon: "📐" },
      { id: "classifier", name: "Classifier", icon: "🏷️" },
    ],
  },
  {
    id: "governance",
    name: "Governance",
    expanded: false,
    nodes: [
      { id: "approval-gate", name: "Approval Gate", icon: "✋" },
      { id: "spend-gate", name: "Spend Gate", icon: "💵" },
      { id: "policy-gate", name: "Policy Gate", icon: "📋" },
    ],
  },
];

// Mock memory items
const memoryItems = [
  { id: "m1", name: "invoices_q3.pdf", chunks: 128, type: "pdf" },
  { id: "m2", name: "vendor_list.csv", chunks: 42, type: "csv" },
];

export function ContextSidebar({ width }: ContextSidebarProps) {
  const [activeTab, setActiveTab] = useState<SidebarTab>("INVENTORY");
  const [categories, setCategories] = useState(nodeCategories);
  const [searchQuery, setSearchQuery] = useState("");
  const [isDragOver, setIsDragOver] = useState(false);

  // [NEW] Fetch Dynamic Tools from Kernel
  useEffect(() => {
    const fetchTools = async () => {
      try {
        // LlmToolDefinition: { name, description, parameters }
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const tools = await invoke<any[]>("get_available_tools");
        
        if (tools && tools.length > 0) {
          const dynamicNodes = tools.map(t => {
            // MCP tools are namespaced like "filesystem__write_file"
            // We want to display "write_file" but keep full ID
            const displayName = t.name.includes("__") ? t.name.split("__")[1] : t.name;
            return {
              id: t.name, // Full ID: "filesystem__write_file"
              name: displayName.replace(/_/g, ' '), // "write file"
              icon: "🔧",
              description: t.description,
              schema: t.parameters // JSON schema string
            };
          });

          setCategories(prev => prev.map(cat => {
            if (cat.id === "tools") {
              return {
                ...cat,
                // Merge static tools with dynamic ones, avoiding duplicates if any
                nodes: [
                  ...cat.nodes.filter(n => !dynamicNodes.some(dn => dn.id === n.id)), 
                  ...dynamicNodes
                ]
              };
            }
            return cat;
          }));
        }
      } catch (e) {
        console.error("Failed to fetch MCP tools:", e);
      }
    };

    fetchTools();
  }, []);

  const toggleCategory = useCallback((categoryId: string) => {
    setCategories((prev) =>
      prev.map((cat) =>
        cat.id === categoryId ? { ...cat, expanded: !cat.expanded } : cat
      )
    );
  }, []);

  // [MODIFIED] Added optional schema param to persist tool definition during drag
  const handleDragStart = (e: React.DragEvent, nodeId: string, nodeName: string, schema?: string) => {
    e.dataTransfer.setData("nodeId", nodeId);
    e.dataTransfer.setData("nodeName", nodeName);
    if (schema) {
      e.dataTransfer.setData("nodeSchema", schema);
    }
    e.dataTransfer.effectAllowed = "copy";
  };

  const handleFileDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
    // Handle file ingestion
    const files = Array.from(e.dataTransfer.files);
    console.log("Ingesting files:", files.map(f => f.name));
  };

  const filteredCategories = categories.map((cat) => ({
    ...cat,
    nodes: cat.nodes.filter((node) =>
      node.name.toLowerCase().includes(searchQuery.toLowerCase())
    ),
  })).filter((cat) => searchQuery === "" || cat.nodes.length > 0);

  return (
    <aside className="context-sidebar" style={{ width }}>
      {/* Tab Switcher */}
      <div className="sidebar-tabs">
        <button
          className={`sidebar-tab ${activeTab === "MEMORY" ? "active" : ""}`}
          onClick={() => setActiveTab("MEMORY")}
        >
          <span className="tab-icon">🧠</span>
          SFS
        </button>
        <button
          className={`sidebar-tab ${activeTab === "INVENTORY" ? "active" : ""}`}
          onClick={() => setActiveTab("INVENTORY")}
        >
          <span className="tab-icon">🧰</span>
          Inventory
        </button>
      </div>

      {/* Content Area */}
      <div className="sidebar-content">
        {activeTab === "MEMORY" ? (
          <MemoryView 
            items={memoryItems}
            isDragOver={isDragOver}
            onDragOver={(e) => { e.preventDefault(); setIsDragOver(true); }}
            onDragLeave={() => setIsDragOver(false)}
            onDrop={handleFileDrop}
          />
        ) : (
          <InventoryView
            categories={filteredCategories}
            searchQuery={searchQuery}
            onSearchChange={setSearchQuery}
            onToggleCategory={toggleCategory}
            onDragStart={handleDragStart}
          />
        )}
      </div>

      {/* Hardware Footer */}
      <div className="hardware-footer">
        <div className="hw-stat">
          <span className="hw-icon">🧠</span>
          <div className="hw-info">
            <span className="hw-label">VRAM</span>
            <div className="hw-bar">
              <div className="hw-bar-fill" style={{ width: "58%" }} />
            </div>
            <span className="hw-val">14/24 GB</span>
          </div>
        </div>
        <div className="hw-stat">
          <span className="hw-icon">🛡️</span>
          <div className="hw-info">
            <span className="hw-label">GUARDIAN</span>
            <span className="hw-val secure">Enclave OK</span>
          </div>
        </div>
      </div>
    </aside>
  );
}

interface MemoryViewProps {
  items: typeof memoryItems;
  isDragOver: boolean;
  onDragOver: (e: React.DragEvent) => void;
  onDragLeave: () => void;
  onDrop: (e: React.DragEvent) => void;
}

function MemoryView({ items, isDragOver, onDragOver, onDragLeave, onDrop }: MemoryViewProps) {
  return (
    <div className="memory-view">
      {/* Drop Zone */}
      <div
        className={`drop-zone ${isDragOver ? "drag-over" : ""}`}
        onDragOver={onDragOver}
        onDragLeave={onDragLeave}
        onDrop={onDrop}
      >
        <div className="drop-icon">📥</div>
        <span className="drop-text">Ingest Context</span>
        <span className="drop-sub">Drop PDFs, Markdown, Code</span>
      </div>

      {/* Active Context */}
      <div className="memory-section">
        <h4 className="section-title">Active Context</h4>
        <div className="memory-list">
          {items.map((item) => (
            <div key={item.id} className="memory-item">
              <span className="file-icon">
                {item.type === "pdf" ? "📄" : "📊"}
              </span>
              <span className="file-name">{item.name}</span>
              <span className="file-meta">{item.chunks} chunks</span>
            </div>
          ))}
        </div>
      </div>

      {/* Vector Stats */}
      <div className="memory-section">
        <h4 className="section-title">Vector Store</h4>
        <div className="vector-stats">
          <div className="stat-row">
            <span className="stat-label">Total Embeddings</span>
            <span className="stat-value">1,247</span>
          </div>
          <div className="stat-row">
            <span className="stat-label">Storage</span>
            <span className="stat-value">48 MB</span>
          </div>
        </div>
      </div>
    </div>
  );
}

interface InventoryViewProps {
  categories: NodeCategory[];
  searchQuery: string;
  onSearchChange: (query: string) => void;
  onToggleCategory: (id: string) => void;
  onDragStart: (e: React.DragEvent, nodeId: string, nodeName: string, schema?: string) => void;
}

function InventoryView({
  categories,
  searchQuery,
  onSearchChange,
  onToggleCategory,
  onDragStart,
}: InventoryViewProps) {
  return (
    <div className="inventory-view">
      {/* Search */}
      <div className="inventory-search">
        <input
          type="text"
          className="search-input"
          placeholder="Search nodes..."
          value={searchQuery}
          onChange={(e) => onSearchChange(e.target.value)}
        />
      </div>

      {/* Categories */}
      <div className="inventory-categories">
        {categories.map((category) => (
          <div key={category.id} className="node-category">
            <button
              className="category-header"
              onClick={() => onToggleCategory(category.id)}
            >
              <svg
                className={`category-chevron ${category.expanded ? "expanded" : ""}`}
                width="12"
                height="12"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
              >
                <path d="m9 18 6-6-6-6" />
              </svg>
              <span className="category-name">{category.name}</span>
              <span className="category-count">{category.nodes.length}</span>
            </button>

            {category.expanded && (
              <div className="category-nodes">
                {category.nodes.map((node) => (
                  <div
                    key={node.id}
                    className="node-item"
                    draggable
                    // [MODIFIED] Pass schema to handler
                    onDragStart={(e) => onDragStart(e, node.id, node.name, node.schema)}
                  >
                    <span className="node-icon">{node.icon}</span>
                    <span className="node-name">{node.name}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
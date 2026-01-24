// src/components/ExplorerPanel.tsx
import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import "./ExplorerPanel.css";

interface ExplorerPanelProps {
  width: number;
}

type Tab = "LIBRARY" | "ONTOLOGY" | "FILES";

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
  description?: string;
  schema?: string; // Schema for dynamic tools
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
];

// Static Base Groups
const initialLibraryGroups: LibraryGroup[] = [
  {
    id: "logic",
    name: "Logic & Governance",
    items: [
      { id: "agency-firewall", name: "Agency Firewall", icon: "🛡️", type: "gate" },
      { id: "approval-gate", name: "Approval Gate", icon: "✋", type: "gate" },
      { id: "burst-router", name: "Burst Router", icon: "⚡", type: "action" },
      { id: "receipt-logger", name: "Receipt Logger", icon: "🧾", type: "receipt" },
    ],
  },
  {
    id: "models",
    name: "Models",
    items: [
      { id: "local-llm", name: "Local LLM", icon: "🤖", type: "model" },
      { id: "remote-llm", name: "Remote LLM", icon: "☁️", type: "model" },
    ],
  },
];

export function ExplorerPanel({ width }: ExplorerPanelProps) {
  const [activeTab, setActiveTab] = useState<Tab>("LIBRARY");
  const [tree, setTree] = useState(ontologyTree);
  const [selectedId, setSelectedId] = useState<string>("ot-invoice");
  const [searchQuery, setSearchQuery] = useState("");
  const [library, setLibrary] = useState<LibraryGroup[]>(initialLibraryGroups);
  
  // File State
  const [isDragOver, setIsDragOver] = useState(false);
  const [memoryFiles, setMemoryFiles] = useState([
    { id: "m1", name: "invoices_q3.pdf", chunks: 128 },
    { id: "m2", name: "vendor_list.csv", chunks: 42 },
  ]);

  // --- Dynamic Tool Hydration ---
  useEffect(() => {
    const fetchTools = async () => {
      try {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const tools = await invoke<any[]>("get_available_tools");
        
        if (tools && tools.length > 0) {
          const dynamicItems: LibraryItem[] = tools.map(t => {
            const displayName = t.name.includes("__") ? t.name.split("__")[1] : t.name;
            return {
              id: t.name, 
              name: displayName.replace(/_/g, ' '), 
              icon: "🔧",
              type: "tool",
              description: t.description,
              schema: t.parameters 
            };
          });

          // Update state, avoiding duplicates
          setLibrary(prev => {
            const hasTools = prev.find(g => g.id === "tools");
            if (hasTools) return prev; // Already hydrated or handled elsewhere

            return [
              ...prev,
              {
                id: "tools",
                name: "MCP Tools (Dynamic)",
                items: dynamicItems
              }
            ];
          });
        }
      } catch (e) {
        console.error("Failed to fetch MCP tools:", e);
      }
    };

    fetchTools();
  }, []);

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
    if (item.schema) {
      e.dataTransfer.setData("nodeSchema", item.schema);
    }
    e.dataTransfer.effectAllowed = "copy";
  };

  const handleFileDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
    const files = Array.from(e.dataTransfer.files);
    // Mock ingestion
    const newFiles = files.map((f, i) => ({
        id: `new-${Date.now()}-${i}`,
        name: f.name,
        chunks: Math.floor(Math.random() * 500)
    }));
    setMemoryFiles(prev => [...prev, ...newFiles]);
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
        <button
          className={`explorer-tab ${activeTab === "FILES" ? "active" : ""}`}
          onClick={() => setActiveTab("FILES")}
        >
          Files
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
          placeholder="Search..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
        />
      </div>

      <div className="explorer-content">
        {activeTab === "ONTOLOGY" && (
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
        )}

        {activeTab === "LIBRARY" && (
          <div className="explorer-library">
            {library.map((group) => {
                const filteredItems = group.items.filter(i => 
                    i.name.toLowerCase().includes(searchQuery.toLowerCase())
                );
                
                if (filteredItems.length === 0) return null;

                return (
                  <div key={group.id} className="library-group">
                    <div className="section-header">{group.name}</div>
                    {filteredItems.map((item) => (
                      <div
                        key={item.id}
                        className="library-item"
                        draggable
                        onDragStart={(e) => handleDragStart(e, item)}
                        title={item.description}
                      >
                        <span className="lib-icon">{item.icon}</span>
                        <span className="lib-name">{item.name}</span>
                        <span className="lib-desc">{item.type}</span>
                      </div>
                    ))}
                  </div>
                );
            })}
          </div>
        )}

        {activeTab === "FILES" && (
            <div className="memory-view" style={{padding: 12}}>
                <div
                    className={`drop-zone ${isDragOver ? "drag-over" : ""}`}
                    onDragOver={(e) => { e.preventDefault(); setIsDragOver(true); }}
                    onDragLeave={() => setIsDragOver(false)}
                    onDrop={handleFileDrop}
                    style={{
                        border: '2px dashed #3F4652',
                        borderRadius: 8,
                        padding: 24,
                        textAlign: 'center',
                        marginBottom: 16,
                        background: isDragOver ? 'rgba(61, 133, 198, 0.1)' : 'transparent',
                        color: '#9CA3AF'
                    }}
                >
                    <div style={{fontSize: 24, marginBottom: 8}}>📥</div>
                    <div style={{fontSize: 12, fontWeight: 600}}>Ingest Context</div>
                    <div style={{fontSize: 10, opacity: 0.7}}>PDF, CSV, MD</div>
                </div>

                <div className="section-header" style={{background: 'transparent', paddingLeft: 0}}>Indexed Files</div>
                <div className="memory-list" style={{display: 'flex', flexDirection: 'column', gap: 4}}>
                    {memoryFiles.map(f => (
                        <div key={f.id} className="memory-item" style={{display: 'flex', alignItems: 'center', gap: 8, padding: 8, background: '#252A33', borderRadius: 4}}>
                            <span>📄</span>
                            <div style={{flex: 1, fontSize: 12, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: '#E5E7EB'}}>{f.name}</div>
                            <div style={{fontSize: 10, color: '#6B7280'}}>{f.chunks} chk</div>
                        </div>
                    ))}
                </div>
            </div>
        )}
      </div>

      {/* Hardware Footer - Transferred from ContextSidebar */}
      <div className="hardware-footer" style={{marginTop: 'auto', padding: '10px 12px', background: '#181B21', borderTop: '1px solid #2E333D', display: 'flex', gap: 8}}>
        <div style={{display: 'flex', alignItems: 'center', gap: 8, flex: 1, padding: 6, background: '#252A33', borderRadius: 4}}>
          <span style={{fontSize: 14}}>🧠</span>
          <div style={{display: 'flex', flexDirection: 'column', width: '100%'}}>
            <div style={{fontSize: 9, color: '#6B7280', fontWeight: 700}}>VRAM</div>
            <div style={{height: 4, background: '#3F4652', borderRadius: 2, marginTop: 2, overflow: 'hidden'}}>
               <div style={{height: '100%', width: '58%', background: '#3D85C6'}}></div>
            </div>
          </div>
        </div>
        <div style={{display: 'flex', alignItems: 'center', gap: 8, padding: 6, background: '#252A33', borderRadius: 4}}>
           <span style={{fontSize: 14}}>🛡️</span>
           <span style={{fontSize: 10, color: '#34D399', fontWeight: 600}}>OK</span>
        </div>
      </div>
    </aside>
  );
}

// --- Tree Node Component (Unchanged) ---
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

  return (
    <div className="tree-node">
      <div
        className={`tree-item ${isSelected ? "selected" : ""}`}
        style={{ paddingLeft: 12 + depth * 12 }}
        onClick={() => {
          if (hasChildren) onToggle(item.id);
          onSelect(item.id);
        }}
      >
        <span className={`tree-arrow ${item.expanded ? "expanded" : ""}`} style={{opacity: hasChildren ? 1 : 0}}>
            <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="m9 18 6-6-6-6" /></svg>
        </span>
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
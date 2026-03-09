// packages/agent-ide/src/features/Editor/Explorer/Explorer.tsx
import React, { useState, useEffect } from "react";
import {
  AgentRuntime,
  InstalledWorkflowSummary,
  WorkflowRunReceipt,
} from "../../../runtime/agent-runtime";
import { ProjectFile } from "../../../types/graph";
import { Icons } from "../../../ui/icons"; 
import "./Explorer.css";

interface ExplorerProps {
  runtime: AgentRuntime;
  onDragStart: (e: React.DragEvent, type: string, name: string, schema?: string) => void;
  onLoadProject?: (project: ProjectFile, workflow?: InstalledWorkflowSummary) => void;
}

type Tab = "LIBRARY" | "AUTOMATIONS" | "ONTOLOGY" | "MEMORY";

interface TreeItem {
  id: string;
  name: string;
  type: "category" | "object" | "link";
  children?: TreeItem[];
  expanded?: boolean;
  meta?: string;
}

interface LibraryItem {
  id: string;
  name: string;
  icon: React.ReactNode;
  type: string;
  description?: string;
  schema?: string;
}

const initialOntology: TreeItem[] = [
  {
    id: "obj-types",
    name: "Object Types",
    type: "category",
    expanded: true,
    children: [
      { id: "ot-invoice", name: "Invoice", type: "object", meta: "12 props" },
      { id: "ot-vendor", name: "Vendor", type: "object", meta: "8 props" },
      { id: "ot-trans", name: "Transaction", type: "object", meta: "15 props" },
    ],
  },
  {
    id: "links",
    name: "Link Types",
    type: "category",
    expanded: false,
    children: [
      { id: "lt-has-vendor", name: "Has Vendor", type: "link" },
    ],
  },
];

const staticLibrary: LibraryItem[] = [
  { id: "action", name: "Action Node", icon: <Icons.Action />, type: "action", description: "Generic execution step" },
  { id: "model", name: "LLM Model", icon: <Icons.Brain />, type: "model", description: "Inference node" },
  { id: "trigger", name: "Trigger", icon: <Icons.Trigger />, type: "trigger", description: "Event source" },
  { id: "gate", name: "Logic Gate", icon: <Icons.Gate />, type: "gate", description: "Governance control" },
  { id: "web_search", name: "Web Search", icon: <span>🌐</span>, type: "web_search", description: "Edge web search (typed evidence bundle with sources + provenance)" },
  { id: "web_read", name: "Web Read", icon: <span>📄</span>, type: "web_read", description: "Read a URL and extract quote spans for citations" },
];

export function Explorer({ runtime, onDragStart, onLoadProject }: ExplorerProps) {
  const [activeTab, setActiveTab] = useState<Tab>("LIBRARY");
  const [libraryItems, setLibraryItems] = useState<LibraryItem[]>(staticLibrary);
  const [ontology, setOntology] = useState(initialOntology);
  const [searchQuery, setSearchQuery] = useState("");
  const [workflows, setWorkflows] = useState<InstalledWorkflowSummary[]>([]);
  const [workflowBusyId, setWorkflowBusyId] = useState<string | null>(null);
  const [workflowMessage, setWorkflowMessage] = useState<string | null>(null);

  useEffect(() => {
    runtime.getAvailableTools().then((tools: any[]) => {
      const dynamicItems = tools.map((t: any) => ({
        id: t.name,
        name: t.name.split("__").pop() || t.name,
        icon: <span>🔧</span>,
        type: "tool",
        description: t.description,
        schema: t.parameters
      }));
      setLibraryItems(prev => {
        const existingIds = new Set(prev.map(i => i.id));
        const newItems = dynamicItems.filter(i => !existingIds.has(i.id));
        return [...prev, ...newItems];
      });
    });
  }, [runtime]);

  useEffect(() => {
    if (!runtime.listInstalledWorkflows) return;
    void refreshWorkflows();
  }, [runtime]);

  const toggleExpand = (id: string) => {
    const updateTree = (items: TreeItem[]): TreeItem[] => {
      return items.map((item) => {
        if (item.id === id) return { ...item, expanded: !item.expanded };
        if (item.children) return { ...item, children: updateTree(item.children) };
        return item;
      });
    };
    setOntology(updateTree(ontology));
  };

  const filteredLibrary = libraryItems.filter(i => 
    i.name.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const filteredWorkflows = workflows.filter((workflow) => {
    const haystack = [
      workflow.title,
      workflow.description,
      workflow.sourceLabel,
      ...workflow.keywords,
    ]
      .join(" ")
      .toLowerCase();
    return haystack.includes(searchQuery.toLowerCase());
  });

  async function refreshWorkflows() {
    if (!runtime.listInstalledWorkflows) return;
    try {
      const items = await runtime.listInstalledWorkflows();
      setWorkflows(items);
      setWorkflowMessage(null);
    } catch (error) {
      setWorkflowMessage(String(error));
    }
  }

  async function openWorkflow(workflow: InstalledWorkflowSummary) {
    if (!runtime.getInstalledWorkflowProject || !onLoadProject) return;
    try {
      setWorkflowBusyId(workflow.workflowId);
      const project = await runtime.getInstalledWorkflowProject(workflow.workflowId);
      onLoadProject(project, workflow);
      setWorkflowMessage(null);
    } catch (error) {
      setWorkflowMessage(String(error));
    } finally {
      setWorkflowBusyId(null);
    }
  }

  async function runWorkflow(workflow: InstalledWorkflowSummary) {
    if (!runtime.runWorkflowNow) return;
    try {
      setWorkflowBusyId(workflow.workflowId);
      const receipt: WorkflowRunReceipt = await runtime.runWorkflowNow(workflow.workflowId);
      setWorkflowMessage(
        `Ran ${workflow.title}: ${receipt.status} at ${new Date(receipt.completedAtMs).toLocaleTimeString()}`
      );
      await refreshWorkflows();
    } catch (error) {
      setWorkflowMessage(String(error));
    } finally {
      setWorkflowBusyId(null);
    }
  }

  async function toggleWorkflow(workflow: InstalledWorkflowSummary) {
    const action =
      workflow.status === "paused" ? runtime.resumeWorkflow : runtime.pauseWorkflow;
    if (!action) return;
    try {
      setWorkflowBusyId(workflow.workflowId);
      await action(workflow.workflowId);
      await refreshWorkflows();
      setWorkflowMessage(null);
    } catch (error) {
      setWorkflowMessage(String(error));
    } finally {
      setWorkflowBusyId(null);
    }
  }

  async function deleteWorkflow(workflow: InstalledWorkflowSummary) {
    if (!runtime.deleteWorkflow) return;
    try {
      setWorkflowBusyId(workflow.workflowId);
      await runtime.deleteWorkflow(workflow.workflowId);
      await refreshWorkflows();
      setWorkflowMessage(null);
    } catch (error) {
      setWorkflowMessage(String(error));
    } finally {
      setWorkflowBusyId(null);
    }
  }

  return (
    <div className="explorer-panel">
      {/* Tabs */}
      <div className="explorer-tabs">
        <button 
            className={`explorer-tab ${activeTab === "LIBRARY" ? "active" : ""}`} 
            onClick={() => setActiveTab("LIBRARY")}
        >
            ASSETS
        </button>
        <button 
            className={`explorer-tab ${activeTab === "AUTOMATIONS" ? "active" : ""}`} 
            onClick={() => setActiveTab("AUTOMATIONS")}
        >
            AUTOMATIONS
        </button>
        <button 
            className={`explorer-tab ${activeTab === "ONTOLOGY" ? "active" : ""}`} 
            onClick={() => setActiveTab("ONTOLOGY")}
        >
            ONTOLOGY
        </button>
        <button 
            className={`explorer-tab ${activeTab === "MEMORY" ? "active" : ""}`} 
            onClick={() => setActiveTab("MEMORY")}
        >
            MEMORY
        </button>
      </div>

      {/* Search */}
      <div className="explorer-search">
        <input 
            className="search-input" 
            placeholder="Search..." 
            value={searchQuery} 
            onChange={(e) => setSearchQuery(e.target.value)}
        />
      </div>

      {/* Content */}
      <div className="explorer-content">
        {activeTab === "LIBRARY" && (
          <div className="library-list">
            {filteredLibrary.map(item => (
              <div
                key={item.id}
                className="explorer-item"
                draggable
                onDragStart={(e) => onDragStart(e, item.type, item.name, item.schema)}
                title={item.description}
              >
                <span className="explorer-item-icon">{item.icon}</span>
                <span>{item.name}</span>
              </div>
            ))}
          </div>
        )}

        {activeTab === "AUTOMATIONS" && (
          <div className="workflow-list">
            <div className="workflow-toolbar">
              <button className="workflow-action quiet" onClick={() => void refreshWorkflows()}>
                Refresh
              </button>
            </div>
            {workflowMessage && <div className="workflow-message">{workflowMessage}</div>}
            {filteredWorkflows.length === 0 && (
              <div className="workflow-empty">
                No installed workflows are visible from this runtime.
              </div>
            )}
            {filteredWorkflows.map((workflow) => (
              <div key={workflow.workflowId} className="workflow-card">
                <div className="workflow-card-header">
                  <div>
                    <div className="workflow-title">{workflow.title}</div>
                    <div className="workflow-meta">
                      {workflow.status} • every {workflow.pollIntervalSeconds}s
                    </div>
                  </div>
                  <div className={`workflow-status ${workflow.status}`}>
                    {workflow.status}
                  </div>
                </div>
                <div className="workflow-description">{workflow.description}</div>
                <div className="workflow-meta-line">{workflow.sourceLabel}</div>
                <div className="workflow-keywords">
                  {workflow.keywords.map((keyword) => (
                    <span key={keyword} className="workflow-keyword">
                      {keyword}
                    </span>
                  ))}
                </div>
                <div className="workflow-actions">
                  <button
                    className="workflow-action primary"
                    disabled={workflowBusyId === workflow.workflowId || !onLoadProject || !runtime.getInstalledWorkflowProject}
                    onClick={() => void openWorkflow(workflow)}
                  >
                    Open
                  </button>
                  <button
                    className="workflow-action"
                    disabled={workflowBusyId === workflow.workflowId || !runtime.runWorkflowNow}
                    onClick={() => void runWorkflow(workflow)}
                  >
                    Run now
                  </button>
                  <button
                    className="workflow-action"
                    disabled={workflowBusyId === workflow.workflowId || (!runtime.pauseWorkflow && !runtime.resumeWorkflow)}
                    onClick={() => void toggleWorkflow(workflow)}
                  >
                    {workflow.status === "paused" ? "Resume" : "Pause"}
                  </button>
                  <button
                    className="workflow-action danger"
                    disabled={workflowBusyId === workflow.workflowId || !runtime.deleteWorkflow}
                    onClick={() => void deleteWorkflow(workflow)}
                  >
                    Delete
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}

        {activeTab === "ONTOLOGY" && (
          <div className="ontology-tree">
            {ontology.map(item => (
                <TreeNode key={item.id} item={item} onToggle={toggleExpand} depth={0} />
            ))}
          </div>
        )}

        {activeTab === "MEMORY" && (
            <div className="memory-view">
                <div className="drop-zone">
                    <div className="drop-icon">📥</div>
                    <div className="drop-text">Ingest Context</div>
                </div>
                
                <div className="section-title">ACTIVE CONTEXT</div>
                <div className="memory-list">
                    <MemoryItem name="invoices_q3.pdf" size="2.4 MB" />
                    <MemoryItem name="vendor_list.csv" size="48 KB" />
                </div>
            </div>
        )}
      </div>
    </div>
  );
}

function TreeNode({ item, onToggle, depth }: { item: TreeItem; onToggle: (id: string) => void; depth: number }) {
    const hasChildren = item.children && item.children.length > 0;
    return (
        <div className="tree-node">
            <div 
                className={`tree-item ${item.type}`} 
                style={{ paddingLeft: `${depth * 12 + 12}px` }}
                onClick={() => hasChildren && onToggle(item.id)}
            >
                <span className={`tree-arrow ${item.expanded ? 'expanded' : ''}`} style={{opacity: hasChildren ? 1 : 0}}>▶</span>
                <span className="tree-icon">{item.type === 'category' ? (item.expanded ? '📂' : '📁') : '🧊'}</span>
                <span className="tree-name">{item.name}</span>
                {item.meta && <span className="tree-meta">{item.meta}</span>}
            </div>
            {hasChildren && item.expanded && (
                <div>
                    {item.children!.map(child => (
                        <TreeNode key={child.id} item={child} onToggle={onToggle} depth={depth + 1} />
                    ))}
                </div>
            )}
        </div>
    );
}

function MemoryItem({ name, size }: { name: string; size: string }) {
    return (
        <div className="memory-item">
            <span>📄</span>
            <div className="file-name">{name}</div>
            <div className="file-meta">{size}</div>
        </div>
    );
}

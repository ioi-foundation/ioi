import { useState } from "react";
import "./LeftPanel.css";

interface LeftPanelProps {
  width: number;
}

interface NodeCategory {
  id: string;
  name: string;
  expanded: boolean;
  nodes: {
    id: string;
    name: string;
    icon: string;
    description?: string;
  }[];
}

const initialCategories: NodeCategory[] = [
  {
    id: "recommended",
    name: "Recommended (IOI-native)",
    expanded: true,
    nodes: [
      { id: "agency-firewall", name: "Agency Firewall Gate", icon: "🛡️" },
      { id: "receipt-logger", name: "Receipt Logger", icon: "🧾" },
      { id: "session-auth", name: "Session Auth", icon: "🔐" },
      { id: "burst-router", name: "Burst Router", icon: "⚡" },
      { id: "settlement-escrow", name: "Settlement Escrow", icon: "💰" },
      { id: "policy-budget", name: "Policy Budget", icon: "📊" },
      { id: "provider-select", name: "Provider Select", icon: "🎯" },
      { id: "attestation", name: "Attestation", icon: "✅" },
    ],
  },
  {
    id: "tools",
    name: "Tools",
    expanded: false,
    nodes: [
      { id: "filesystem", name: "Filesystem (scoped)", icon: "📁" },
      { id: "browser", name: "Browser (scoped)", icon: "🌐" },
      { id: "email", name: "Email", icon: "📧" },
      { id: "slack", name: "Slack", icon: "💬" },
      { id: "github", name: "GitHub", icon: "🐙" },
      { id: "stripe", name: "Stripe", icon: "💳" },
      { id: "sql", name: "SQL", icon: "🗄️" },
      { id: "http", name: "HTTP (allowlist)", icon: "🔗" },
      { id: "cron", name: "Cron", icon: "⏰" },
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
      { id: "ocr", name: "OCR", icon: "👁️" },
      { id: "classifier", name: "Classifier", icon: "🏷️" },
      { id: "codegen", name: "CodeGen", icon: "💻" },
    ],
  },
  {
    id: "memory",
    name: "Memory",
    expanded: false,
    nodes: [
      { id: "local-vault", name: "Local Vault", icon: "🔒" },
      { id: "vector-store", name: "Vector Store", icon: "📊" },
      { id: "session-cache", name: "Session Cache", icon: "💾" },
      { id: "rag-source", name: "RAG Source", icon: "📚" },
    ],
  },
  {
    id: "governance",
    name: "Governance / Liability",
    expanded: false,
    nodes: [
      { id: "approval-gate", name: "Approval Gate", icon: "✋" },
      { id: "spend-gate", name: "Spend Gate", icon: "💵" },
      { id: "legal-gate", name: "Legal Gate", icon: "⚖️" },
      { id: "audit-gate", name: "Audit Gate", icon: "📋" },
      { id: "escrow-bond", name: "Escrow / Bond", icon: "🏦" },
    ],
  },
];

const templates = [
  { id: "invoice-guard", name: "Invoice Guard", icon: "📄" },
  { id: "ops-triage", name: "Ops Triage", icon: "🚨" },
  { id: "sales-outreach", name: "Sales Outreach (safe)", icon: "📈" },
  { id: "defi-watchdog", name: "DeFi Watchdog", icon: "🐕" },
];

export function LeftPanel({ width }: LeftPanelProps) {
  const [searchQuery, setSearchQuery] = useState("");
  const [categories, setCategories] = useState(initialCategories);

  const toggleCategory = (categoryId: string) => {
    setCategories((prev) =>
      prev.map((cat) =>
        cat.id === categoryId ? { ...cat, expanded: !cat.expanded } : cat
      )
    );
  };

  const handleDragStart = (e: React.DragEvent, nodeId: string, nodeName: string) => {
    e.dataTransfer.setData("nodeId", nodeId);
    e.dataTransfer.setData("nodeName", nodeName);
    e.dataTransfer.effectAllowed = "copy";
  };

  const filteredCategories = categories.map((cat) => ({
    ...cat,
    nodes: cat.nodes.filter((node) =>
      node.name.toLowerCase().includes(searchQuery.toLowerCase())
    ),
  })).filter((cat) => searchQuery === "" || cat.nodes.length > 0);

  return (
    <aside className="left-panel" style={{ width }}>
      <div className="panel-header">
        <h2 className="panel-title">Build</h2>
        <div className="panel-actions">
          <button className="btn btn-ghost btn-icon" title="New Node">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M12 5v14M5 12h14" />
            </svg>
          </button>
        </div>
      </div>

      {/* Quick Actions */}
      <div className="panel-section">
        <div className="quick-actions">
          <button className="quick-action-btn">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M12 5v14M5 12h14" />
            </svg>
            New Node
          </button>
          <button className="quick-action-btn">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <rect x="3" y="3" width="18" height="18" rx="2" />
              <path d="M12 8v8M8 12h8" />
            </svg>
            New Subgraph
          </button>
        </div>
      </div>

      {/* Search */}
      <div className="panel-section">
        <input
          type="text"
          className="input search-input"
          placeholder="Search nodes…"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
        />
      </div>

      {/* Node Categories */}
      <div className="panel-content">
        {filteredCategories.map((category) => (
          <div key={category.id} className="node-category">
            <button
              className="category-header"
              onClick={() => toggleCategory(category.id)}
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
                    onDragStart={(e) => handleDragStart(e, node.id, node.name)}
                  >
                    <span className="node-icon">{node.icon}</span>
                    <span className="node-name">{node.name}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        ))}

        {/* Templates */}
        <div className="node-category">
          <button
            className="category-header"
            onClick={() => {}}
          >
            <svg
              className="category-chevron expanded"
              width="12"
              height="12"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
            >
              <path d="m9 18 6-6-6-6" />
            </svg>
            <span className="category-name">Templates</span>
          </button>
          <div className="category-nodes">
            {templates.map((template) => (
              <div key={template.id} className="node-item template-item">
                <span className="node-icon">{template.icon}</span>
                <span className="node-name">{template.name}</span>
              </div>
            ))}
          </div>
        </div>

        {/* My Library */}
        <div className="node-category">
          <button className="category-header">
            <svg
              className="category-chevron"
              width="12"
              height="12"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
            >
              <path d="m9 18 6-6-6-6" />
            </svg>
            <span className="category-name">My Library</span>
            <span className="category-count">2</span>
          </button>
        </div>
      </div>
    </aside>
  );
}

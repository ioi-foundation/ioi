import { useState } from "react";
import "./BuilderView.css";

interface BuilderViewProps {
  onSwitchToCompose: () => void;
}

const templates = [
  {
    id: "invoice",
    icon: "📄",
    iconBg: "linear-gradient(135deg, #4a9eff, #06b6d4)",
    name: "Invoice Processor",
    desc: "Parse invoices, classify vendors, and route for approval",
    accent: "blue",
  },
  {
    id: "defi",
    icon: "💰",
    iconBg: "linear-gradient(135deg, #22c55e, #06b6d4)",
    name: "DeFi Research Agent",
    desc: "Monitor protocols and generate yield opportunity reports",
    accent: "green",
  },
  {
    id: "email",
    icon: "✉️",
    iconBg: "linear-gradient(135deg, #ef4444, #f97316)",
    name: "Email Assistant",
    desc: "Organize and manage your inbox automatically",
    accent: "red",
  },
  {
    id: "market",
    icon: "📊",
    iconBg: "linear-gradient(135deg, #a855f7, #ec4899)",
    name: "Market Brief Agent",
    desc: "Daily market analysis with key insights digest",
    accent: "purple",
  },
];

const modelOptions = [
  { id: "deepseek", name: "DeepSeek V3", icon: "🧠" },
  { id: "claude", name: "Claude 3.5", icon: "🤖" },
  { id: "llama", name: "Llama 3.3 70B", icon: "🦙" },
  { id: "local", name: "Local Ollama", icon: "💻" },
];

export function BuilderView({ onSwitchToCompose }: BuilderViewProps) {
  const [prompt, setPrompt] = useState("");
  const [selectedModel, setSelectedModel] = useState(modelOptions[0]);
  const [showModelSelect, setShowModelSelect] = useState(false);

  const handleSubmit = () => {
    if (!prompt.trim()) return;
    console.log("Building agent with prompt:", prompt);
    // In real implementation, this would trigger agent generation
  };

  return (
    <div className="builder-view">
      <div className="builder-content">
        {/* Hero Section */}
        <div className="builder-hero">
          <div className="builder-icon">
            <svg viewBox="0 0 48 48" fill="none">
              <path
                d="M24 4L44 14V34L24 44L4 34V14L24 4Z"
                stroke="url(#builder-gradient)"
                strokeWidth="2"
              />
              <path
                d="M24 18L32 22L24 26L16 22L24 18Z"
                fill="url(#builder-gradient)"
              />
              <path
                d="M18 12L30 12M16 20L32 20M18 28L30 28"
                stroke="url(#builder-gradient)"
                strokeWidth="1"
                opacity="0.5"
              />
              <defs>
                <linearGradient
                  id="builder-gradient"
                  x1="4"
                  y1="4"
                  x2="44"
                  y2="44"
                >
                  <stop stopColor="#4a9eff" />
                  <stop offset="1" stopColor="#a855f7" />
                </linearGradient>
              </defs>
            </svg>
          </div>

          <h1 className="builder-title">
            Tell us about the workflow you want to create
          </h1>
          <p className="builder-subtitle">
            Describe what you want your agent to do and we'll guide you step-by-step
          </p>
        </div>

        {/* Input Section */}
        <div className="builder-input-container">
          <textarea
            className="builder-textarea"
            placeholder="Describe the workflow you would like to build...

Example: &quot;Create an invoice processing agent that reads PDF invoices from my email, extracts vendor info and amounts, classifies them by category, and routes high-value invoices for human approval before logging to our accounting system.&quot;"
            value={prompt}
            onChange={(e) => setPrompt(e.target.value)}
          />

          <div className="builder-input-footer">
            {/* Model Selector */}
            <div className="model-selector-wrapper">
              <button
                className="model-selector"
                onClick={() => setShowModelSelect(!showModelSelect)}
              >
                <span className="model-icon">{selectedModel.icon}</span>
                <span className="model-name">{selectedModel.name}</span>
                <svg
                  width="12"
                  height="12"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                  style={{ transform: showModelSelect ? "rotate(180deg)" : "none" }}
                >
                  <path d="m6 9 6 6 6-6" />
                </svg>
              </button>

              {showModelSelect && (
                <div className="model-dropdown">
                  {modelOptions.map((model) => (
                    <button
                      key={model.id}
                      className={`model-option ${selectedModel.id === model.id ? "active" : ""}`}
                      onClick={() => {
                        setSelectedModel(model);
                        setShowModelSelect(false);
                      }}
                    >
                      <span className="model-icon">{model.icon}</span>
                      <span>{model.name}</span>
                    </button>
                  ))}
                </div>
              )}
            </div>

            {/* Submit Button */}
            <button
              className="submit-btn"
              onClick={handleSubmit}
              disabled={!prompt.trim()}
            >
              <svg
                width="18"
                height="18"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
              >
                <line x1="22" y1="2" x2="11" y2="13" />
                <polygon points="22 2 15 22 11 13 2 9 22 2" />
              </svg>
            </button>
          </div>
        </div>

        {/* Manual Link */}
        <button className="manual-link" onClick={onSwitchToCompose}>
          Create manually in Compose →
        </button>

        {/* Templates Section */}
        <div className="templates-section">
          <div className="templates-divider">
            <span>or start from a template</span>
          </div>

          <div className="templates-grid">
            {templates.map((template) => (
              <div
                key={template.id}
                className={`template-card accent-${template.accent}`}
              >
                <div
                  className="template-icon"
                  style={{ background: template.iconBg }}
                >
                  {template.icon}
                </div>
                <div className="template-name">{template.name}</div>
                <div className="template-desc">{template.desc}</div>
                <div className="template-arrow">
                  <svg
                    width="16"
                    height="16"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="2"
                  >
                    <line x1="7" y1="17" x2="17" y2="7" />
                    <polyline points="7 7 17 7 17 17" />
                  </svg>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// packages/agent-ide/src/features/Editor/Inspector/views/GraphConfigView.tsx
import { useEffect, useMemo, useState } from "react";
import {
  AgentRuntime,
  GraphCapabilityCatalog,
  GraphModelBindingCatalog,
} from "../../../../runtime/agent-runtime";
import { GraphGlobalConfig } from "../../../../types/graph";

interface GraphConfigViewProps {
  config: GraphGlobalConfig;
  runtime: AgentRuntime;
  onOpenSystemSettings?: () => void;
  onChange: (updates: Partial<GraphGlobalConfig>) => void;
}

const FALLBACK_BINDING_CATALOG: GraphModelBindingCatalog = {
  refreshedAtMs: 0,
  models: [],
};

const FALLBACK_CAPABILITY_CATALOG: GraphCapabilityCatalog = {
  refreshedAtMs: 0,
  capabilities: [],
};

const UNRUNNABLE_MODEL_STATUSES = new Set([
  "failed",
  "cancelled",
  "queued",
  "installing",
  "loading",
  "unloading",
]);

const commonBindings = [
  {
    key: "reasoning",
    label: "Reasoning",
    description: "Default text generation and reasoning slot for responses/model nodes.",
  },
  {
    key: "vision",
    label: "Vision",
    description: "Image and screenshot understanding slot for vision_read nodes.",
  },
  {
    key: "embedding",
    label: "Embedding",
    description: "Default embedding model slot for embeddings and retrieval paths.",
  },
  {
    key: "image",
    label: "Image",
    description: "Default image generation and editing slot for media nodes.",
  },
];

const commonCapabilities = [
  {
    key: "reasoning",
    label: "Reasoning",
    familyId: "responses",
    description: "Workflow-level text generation and planning capability.",
    defaultBindingKey: "reasoning",
  },
  {
    key: "vision",
    label: "Vision",
    familyId: "vision",
    description: "Image and screenshot understanding before graph execution starts.",
    defaultBindingKey: "vision",
  },
  {
    key: "embedding",
    label: "Embedding",
    familyId: "embeddings",
    description: "Vector generation and retrieval support for memory-aware workflows.",
    defaultBindingKey: "embedding",
  },
  {
    key: "image",
    label: "Image",
    familyId: "image",
    description: "Image generation and editing readiness for media-heavy graphs.",
    defaultBindingKey: "image",
  },
  {
    key: "speech",
    label: "Speech",
    familyId: "speech",
    description: "Speech synthesis capability for audio artifact nodes and narration flows.",
  },
  {
    key: "video",
    label: "Video",
    familyId: "video",
    description: "Video generation readiness for longer-running media workflows.",
  },
];

function modelStatusIsRunnable(status?: string): boolean {
  if (!status) return false;
  return !UNRUNNABLE_MODEL_STATUSES.has(status.trim().toLowerCase());
}

function badgeStyle(tone: "success" | "warning" | "error" | "neutral") {
  switch (tone) {
    case "success":
      return {
        color: "var(--status-success)",
        background: "color-mix(in srgb, var(--status-success) 18%, transparent)",
        border: "1px solid color-mix(in srgb, var(--status-success) 32%, transparent)",
      };
    case "warning":
      return {
        color: "var(--status-warning)",
        background: "color-mix(in srgb, var(--status-warning) 18%, transparent)",
        border: "1px solid color-mix(in srgb, var(--status-warning) 32%, transparent)",
      };
    case "error":
      return {
        color: "var(--status-error)",
        background: "color-mix(in srgb, var(--status-error) 18%, transparent)",
        border: "1px solid color-mix(in srgb, var(--status-error) 32%, transparent)",
      };
    default:
      return {
        color: "var(--text-secondary)",
        background: "var(--surface-3)",
        border: "1px solid var(--border-subtle)",
      };
  }
}

export function GraphConfigView({
  config,
  runtime,
  onOpenSystemSettings,
  onChange,
}: GraphConfigViewProps) {
  const safeConfig = config || {
    env: "",
    modelBindings: {},
    requiredCapabilities: {},
    policy: { maxBudget: 0, maxSteps: 50, timeoutMs: 30000 },
    contract: { developerBond: 0, adjudicationRubric: "" },
    meta: { name: "", description: "" },
  };
  const modelBindings = safeConfig.modelBindings || {};
  const requiredCapabilities = safeConfig.requiredCapabilities || {};
  const [bindingCatalog, setBindingCatalog] = useState<GraphModelBindingCatalog>(
    FALLBACK_BINDING_CATALOG
  );
  const [capabilityCatalog, setCapabilityCatalog] = useState<GraphCapabilityCatalog>(
    FALLBACK_CAPABILITY_CATALOG
  );

  useEffect(() => {
    let cancelled = false;

    async function hydrateRuntimeCatalogs() {
      if (runtime.getGraphModelBindingCatalog) {
        try {
          const catalog = await runtime.getGraphModelBindingCatalog();
          if (!cancelled) {
            setBindingCatalog(catalog);
          }
        } catch {
          if (!cancelled) {
            setBindingCatalog(FALLBACK_BINDING_CATALOG);
          }
        }
      }

      if (runtime.getGraphCapabilityCatalog) {
        try {
          const catalog = await runtime.getGraphCapabilityCatalog();
          if (!cancelled) {
            setCapabilityCatalog(catalog);
          }
        } catch {
          if (!cancelled) {
            setCapabilityCatalog(FALLBACK_CAPABILITY_CATALOG);
          }
        }
      }
    }

    void hydrateRuntimeCatalogs();

    return () => {
      cancelled = true;
    };
  }, [runtime]);

  const modelsById = useMemo(
    () => new Map(bindingCatalog.models.map((model) => [model.modelId, model])),
    [bindingCatalog.models]
  );
  const capabilitiesById = useMemo(
    () => new Map(capabilityCatalog.capabilities.map((capability) => [capability.capabilityId, capability])),
    [capabilityCatalog.capabilities]
  );

  const updateBinding = (
    bindingKey: string,
    updates: { modelId?: string; modelHash?: string; required?: boolean }
  ) => {
    const nextBinding = {
      ...(modelBindings[bindingKey] || {}),
      ...updates,
    };
    onChange({
      modelBindings: {
        ...modelBindings,
        [bindingKey]: nextBinding,
      },
    });
  };

  const updateCapability = (
    capabilityKey: string,
    updates: { required?: boolean; bindingKey?: string; notes?: string }
  ) => {
    const nextCapability = {
      ...(requiredCapabilities[capabilityKey] || {}),
      ...updates,
    };
    onChange({
      requiredCapabilities: {
        ...requiredCapabilities,
        [capabilityKey]: nextCapability,
      },
    });
  };

  const requiredCapabilityIssues = commonCapabilities
    .map((capability) => {
      const requirement = requiredCapabilities[capability.key] || {};
      if (!requirement.required) return null;

      const bindingKey = requirement.bindingKey || capability.defaultBindingKey;
      const runtimeCapability = capabilitiesById.get(capability.key);

      if (bindingKey) {
        const binding = modelBindings[bindingKey] || {};
        const modelId = String(binding.modelId || "").trim();
        const resolvedModel = modelId ? modelsById.get(modelId) : null;

        if (!modelId) {
          return `${capability.label} requires the '${bindingKey}' model slot, but it is not configured.`;
        }
        if (!resolvedModel) {
          return `${capability.label} expects '${modelId}', but that model is not present in the live Local Engine registry.`;
        }
        if (!modelStatusIsRunnable(resolvedModel.status)) {
          return `${capability.label} is bound to '${modelId}', but Local Engine reports status '${resolvedModel.status}'.`;
        }
        if (!runtimeCapability || runtimeCapability.availableCount === 0) {
          return `${capability.label} does not have a surfaced runtime family in the current Local Engine snapshot.`;
        }
        return null;
      }

      if (!runtimeCapability || runtimeCapability.availableCount === 0) {
        return `${capability.label} is marked required, but the Local Engine snapshot does not expose that capability yet.`;
      }
      return null;
    })
    .filter((issue): issue is string => Boolean(issue));

  return (
    <div className="inspector-view">
      <div className="section-header" style={{ marginBottom: 16 }}>
        <span style={{ fontWeight: 700 }}>Graph settings</span>
      </div>

      <div className="form-group">
        <label>Workflow name</label>
        <input 
            value={safeConfig.meta?.name || ""}
            onChange={e => onChange({ meta: { ...safeConfig.meta, name: e.target.value } })}
            placeholder="Untitled Agent"
        />
      </div>

      <div className="form-group">
        <label>Runtime env (JSON)</label>
        <textarea 
            className="code-editor"
            rows={8}
            value={safeConfig.env || ""}
            onChange={e => onChange({ env: e.target.value })}
            placeholder='{"API_KEY": "..."}'
        />
      </div>

      <div className="form-group">
        <label>Model bindings</label>
        <div className="law-card">
          {bindingCatalog.models.length > 0 ? (
            <div style={{ fontSize: 11, color: "var(--text-tertiary)", marginBottom: 10 }}>
              Backed by {bindingCatalog.models.length} Local Engine models from the live registry.
            </div>
          ) : (
            <div style={{ fontSize: 11, color: "var(--text-tertiary)", marginBottom: 10 }}>
              No live Local Engine registry catalog is available yet. You can still type model ids manually.
            </div>
          )}
          {commonBindings.map((binding) => {
            const value = modelBindings[binding.key] || {};
            const resolvedModel = value.modelId ? modelsById.get(value.modelId) : null;
            return (
              <div
                key={binding.key}
                className="capability-row"
                style={{ alignItems: "stretch", flexDirection: "column", gap: 10 }}
              >
                <div>
                  <div className="cap-title" style={{ marginBottom: 4 }}>
                    {binding.label}
                  </div>
                  <div style={{ fontSize: 11, color: "var(--text-muted)" }}>
                    {binding.description}
                  </div>
                </div>

                <div style={{ display: "grid", gap: 8 }}>
                  <input
                    list={`graph-model-binding-options-${binding.key}`}
                    value={value.modelId || ""}
                    onChange={(event) =>
                      updateBinding(binding.key, { modelId: event.target.value })
                    }
                    placeholder={`${binding.key}.modelId`}
                  />
                  <datalist id={`graph-model-binding-options-${binding.key}`}>
                    {bindingCatalog.models.map((model) => (
                      <option
                        key={`${binding.key}-${model.modelId}`}
                        value={model.modelId}
                      >
                        {`${model.status} / ${model.residency || "unknown"}`}
                      </option>
                    ))}
                  </datalist>
                  {resolvedModel ? (
                    <div style={{ fontSize: 11, color: "var(--text-tertiary)" }}>
                      Registry state: {resolvedModel.status}
                      {resolvedModel.residency ? ` / ${resolvedModel.residency}` : ""}
                      {resolvedModel.backendId ? ` via ${resolvedModel.backendId}` : ""}
                    </div>
                  ) : value.modelId ? (
                    <div style={{ fontSize: 11, color: "var(--status-warning)" }}>
                      This model id is not currently present in the Local Engine registry.
                    </div>
                  ) : null}
                  <input
                    value={value.modelHash || ""}
                    onChange={(event) =>
                      updateBinding(binding.key, { modelHash: event.target.value })
                    }
                    placeholder="Optional explicit model hash"
                  />
                  <label style={{ display: "flex", gap: 8, alignItems: "center" }}>
                    <input
                      type="checkbox"
                      checked={Boolean(value.required)}
                      onChange={(event) =>
                        updateBinding(binding.key, { required: event.target.checked })
                      }
                    />
                    Mark this slot as required for the workflow
                  </label>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      <div className="form-group">
        <label>Capability requirements</label>
        <div className="law-card">
          <div style={{ fontSize: 11, color: "var(--text-tertiary)", marginBottom: 10 }}>
            Declare workflow-wide runtime prerequisites before the graph starts. Required
            capabilities block execution up front and point operators back to the Local Engine
            control plane when the environment is not ready.
          </div>

          {commonCapabilities.map((capability) => {
            const requirement = requiredCapabilities[capability.key] || {};
            const bindingKey = requirement.bindingKey || capability.defaultBindingKey;
            const runtimeCapability = capabilitiesById.get(capability.key);
            const binding = bindingKey ? modelBindings[bindingKey] || {} : null;
            const modelId = binding ? String(binding.modelId || "").trim() : "";
            const resolvedModel = modelId ? modelsById.get(modelId) : null;

            let badgeTone: "success" | "warning" | "error" | "neutral" = "neutral";
            let statusLabel = requirement.required ? "Required" : "Optional";
            let detail = requirement.required
              ? "The graph must satisfy this capability before execution starts."
              : "This capability can stay optional until the workflow depends on it.";

            if (bindingKey) {
              if (modelId && resolvedModel && modelStatusIsRunnable(resolvedModel.status)) {
                badgeTone = requirement.required ? "success" : "neutral";
                statusLabel = requirement.required ? "Ready" : "Configured";
                detail = `${bindingKey} -> ${modelId} (${resolvedModel.status}${
                  resolvedModel.residency ? ` / ${resolvedModel.residency}` : ""
                })`;
              } else if (requirement.required && !modelId) {
                badgeTone = "warning";
                statusLabel = "Missing binding";
                detail = `Configure the '${bindingKey}' model slot for this workflow.`;
              } else if (requirement.required && modelId && !resolvedModel) {
                badgeTone = "error";
                statusLabel = "Missing model";
                detail = `'${modelId}' is not present in the live Local Engine registry.`;
              } else if (
                requirement.required &&
                resolvedModel &&
                !modelStatusIsRunnable(resolvedModel.status)
              ) {
                badgeTone = "error";
                statusLabel = "Not runnable";
                detail = `Local Engine reports '${modelId}' as '${resolvedModel.status}'.`;
              }
            } else if (runtimeCapability) {
              if (runtimeCapability.availableCount > 0) {
                badgeTone = requirement.required ? "success" : "neutral";
                statusLabel = requirement.required ? "Ready" : runtimeCapability.status;
                detail = runtimeCapability.operatorSummary;
              } else if (requirement.required) {
                badgeTone = "error";
                statusLabel = "Unavailable";
                detail = "The current Local Engine snapshot does not expose this capability yet.";
              }
            } else if (requirement.required) {
              badgeTone = "error";
              statusLabel = "Unavailable";
              detail = "The current Local Engine snapshot does not expose this capability yet.";
            }

            return (
              <div
                key={capability.key}
                className="capability-row"
                style={{ alignItems: "stretch", flexDirection: "column", gap: 10 }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", gap: 12 }}>
                  <div>
                    <div className="cap-title" style={{ marginBottom: 4 }}>
                      {capability.label}
                    </div>
                    <div style={{ fontSize: 11, color: "var(--text-muted)" }}>
                      {capability.description}
                    </div>
                  </div>

                  <span
                    style={{
                      ...badgeStyle(badgeTone),
                      alignSelf: "flex-start",
                      borderRadius: 999,
                      fontSize: 11,
                      fontWeight: 700,
                      padding: "4px 10px",
                      whiteSpace: "nowrap",
                    }}
                  >
                    {statusLabel}
                  </span>
                </div>

                <div style={{ fontSize: 11, color: "var(--text-secondary)" }}>{detail}</div>

                {runtimeCapability ? (
                  <div style={{ fontSize: 11, color: "var(--text-tertiary)" }}>
                    Local Engine family: {runtimeCapability.label} / {runtimeCapability.status}
                    {" · "}
                    {runtimeCapability.availableCount} surfaced tool
                    {runtimeCapability.availableCount === 1 ? "" : "s"}
                  </div>
                ) : null}

                <label style={{ display: "flex", gap: 8, alignItems: "center" }}>
                  <input
                    type="checkbox"
                    checked={Boolean(requirement.required)}
                    onChange={(event) =>
                      updateCapability(capability.key, { required: event.target.checked })
                    }
                  />
                  Mark this capability as required for the workflow
                </label>

                {bindingKey ? (
                  <div style={{ fontSize: 11, color: "var(--text-tertiary)" }}>
                    Uses model binding slot <strong>{bindingKey}</strong>.
                  </div>
                ) : null}

                {requirement.required && badgeTone !== "success" && onOpenSystemSettings ? (
                  <button
                    type="button"
                    className="toolbar-btn toolbar-btn--secondary"
                    onClick={onOpenSystemSettings}
                    style={{ alignSelf: "flex-start" }}
                  >
                    Open Local Engine Settings
                  </button>
                ) : null}
              </div>
            );
          })}

          {requiredCapabilityIssues.length > 0 ? (
            <div
              style={{
                marginTop: 12,
                padding: 12,
                borderRadius: 12,
                background: "color-mix(in srgb, var(--status-warning) 14%, transparent)",
                border: "1px solid color-mix(in srgb, var(--status-warning) 32%, transparent)",
              }}
            >
              <div style={{ fontWeight: 700, marginBottom: 6 }}>Preflight issues</div>
              {requiredCapabilityIssues.map((issue) => (
                <div key={issue} style={{ fontSize: 11, color: "var(--text-secondary)" }}>
                  {issue}
                </div>
              ))}
            </div>
          ) : null}
        </div>
      </div>

      <div className="form-group">
        <label>Workflow policy</label>
        <div className="law-card">
            
            {/* Max Budget Row */}
            <div className="capability-row">
                <div className="cap-header">
                    <span className="cap-icon">💰</span>
                    <span className="cap-title">TOTAL BUDGET CAP</span>
                </div>
                <div className="cap-body" style={{flexDirection: 'column', alignItems: 'stretch', gap: 8}}>
                    <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center'}}>
                        <input 
                            type="range" 
                            className="budget-slider"
                            min="0" max="50" step="0.5"
                            value={safeConfig.policy?.maxBudget || 0}
                            onChange={e => onChange({ policy: { ...safeConfig.policy, maxBudget: parseFloat(e.target.value) } })}
                        />
                        <span className="budget-value">${(safeConfig.policy?.maxBudget || 0).toFixed(2)}</span>
                    </div>
                </div>
            </div>

            {/* Recursion Limit Row */}
            <div className="capability-row">
                <div className="cap-header">
                    <span className="cap-icon">🔄</span>
                    <span className="cap-title">MAX STEPS</span>
                </div>
                <div className="cap-body">
                    <input 
                        type="number"
                        value={safeConfig.policy?.maxSteps || 50}
                        onChange={e => onChange({ policy: { ...safeConfig.policy, maxSteps: parseInt(e.target.value) } })}
                        style={{width: '100%'}}
                    />
                </div>
            </div>

        </div>
      </div>
    </div>
  );
}

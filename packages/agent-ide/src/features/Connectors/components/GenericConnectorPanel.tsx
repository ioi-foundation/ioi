import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type RefObject,
} from "react";
import type {
  AgentRuntime,
  ConnectorActionDefinition,
  ConnectorActionRequest,
  ConnectorActionResult,
  ConnectorConfigureResult,
  ConnectorFieldDefinition,
  ConnectorSummary,
} from "../../../runtime/agent-runtime";
import {
  ConnectorActionPreviewStage,
  ConnectorActionUnlockModal,
} from "./ConnectorUnlockSurface";
import {
  ConnectorActionWorkbench,
  ConnectorExecutionMeta,
  ConnectorFocusedFormCard,
  ConnectorInlineResultCard,
} from "./ConnectorExecutionWorkbench";
import { getConnectorFocusedFormRecommendation } from "./connectorActionPatterns";
import { WorkspaceModal } from "./googleWorkspaceConnectorPanelParts";

type GenericConnectorPanelSection = "all" | "setup" | "actions";
type GenericActionsState = {
  status: "idle" | "loading" | "ready" | "error";
  actions: ConnectorActionDefinition[];
  error: string | null;
};

interface GenericConnectorPanelProps {
  runtime: AgentRuntime;
  connector: ConnectorSummary;
  section?: GenericConnectorPanelSection;
  onConfigured?: (result: ConnectorConfigureResult) => void;
  onOpenPolicyCenter?: (connector: ConnectorSummary) => void;
}

function connectorStatusLabel(status: ConnectorSummary["status"]): string {
  switch (status) {
    case "connected":
      return "Connected";
    case "degraded":
      return "Attention";
    case "disabled":
      return "Disabled";
    default:
      return "Connect required";
  }
}

function connectorStatusTone(
  status: ConnectorSummary["status"],
): "ready" | "attention" | "setup" {
  switch (status) {
    case "connected":
      return "ready";
    case "degraded":
      return "attention";
    default:
      return "setup";
  }
}

function actionKindLabel(kind: ConnectorActionDefinition["kind"]): string {
  switch (kind) {
    case "read":
      return "Read";
    case "write":
      return "Write";
    case "workflow":
      return "Workflow";
    case "admin":
      return "Admin";
    case "expert":
      return "Expert";
    default:
      return kind;
  }
}

function actionServiceLabel(action: ConnectorActionDefinition): string {
  return action.serviceLabel ?? action.service ?? "Connector action";
}

function buildInitialInput(
  action: ConnectorActionDefinition | null,
): Record<string, string | number> {
  if (!action) {
    return {};
  }

  const next: Record<string, string | number> = {};
  action.fields.forEach((field) => {
    if (field.defaultValue !== undefined) {
      next[field.id] = field.defaultValue;
      return;
    }
    if (field.type === "select" && field.options && field.options.length > 0) {
      next[field.id] = field.options[0]?.value ?? "";
      return;
    }
    next[field.id] = "";
  });
  return next;
}

function normalizeActionInput(
  action: ConnectorActionDefinition,
  input: Record<string, string | number>,
): ConnectorActionRequest["input"] {
  const payload: Record<string, unknown> = {};
  action.fields.forEach((field) => {
    const rawValue = input[field.id];
    if (rawValue === undefined || rawValue === "") {
      return;
    }
    payload[field.id] =
      field.type === "number" ? Number(rawValue) : rawValue;
  });
  return payload;
}

function renderGenericActionField(
  field: ConnectorFieldDefinition,
  value: string | number,
  onChange: (fieldId: string, value: string) => void,
  ref?: RefObject<
    HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement | null
  >,
) {
  if (field.type === "textarea") {
    return (
      <label key={field.id} className="workspace-field textarea">
        {field.label}
        <textarea
          ref={ref as RefObject<HTMLTextAreaElement> | undefined}
          value={String(value)}
          onChange={(event) => onChange(field.id, event.target.value)}
          placeholder={field.placeholder}
          rows={5}
        />
        {field.description ? <span>{field.description}</span> : null}
      </label>
    );
  }

  if (field.type === "select") {
    return (
      <label key={field.id} className="workspace-field">
        {field.label}
        <select
          ref={ref as RefObject<HTMLSelectElement> | undefined}
          value={String(value)}
          onChange={(event) => onChange(field.id, event.target.value)}
        >
          {(field.options ?? []).map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>
        {field.description ? <span>{field.description}</span> : null}
      </label>
    );
  }

  return (
    <label key={field.id} className="workspace-field">
      {field.label}
      <input
        ref={ref as RefObject<HTMLInputElement> | undefined}
        type={
          field.type === "number"
            ? "number"
            : field.type === "email"
              ? "email"
              : "text"
        }
        value={String(value)}
        onChange={(event) => onChange(field.id, event.target.value)}
        placeholder={field.placeholder}
      />
      {field.description ? <span>{field.description}</span> : null}
    </label>
  );
}

function GenericConnectorActionComposer({
  connectorReady,
  action,
  input,
  busy,
  runtimeReady,
  error,
  result,
  showFocusedFormButton = false,
  onOpenFocusedForm,
  onInputChange,
  onRun,
}: {
  connectorReady: boolean;
  action: ConnectorActionDefinition | null;
  input: Record<string, string | number>;
  busy: boolean;
  runtimeReady: boolean;
  error: string | null;
  result: ConnectorActionResult | null;
  showFocusedFormButton?: boolean;
  onOpenFocusedForm?: () => void;
  onInputChange: (fieldId: string, value: string) => void;
  onRun: () => void;
}) {
  const composerRef = useRef<HTMLDivElement | null>(null);
  const firstFieldRef = useRef<
    HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement | null
  >(null);
  const focusedFormRecommendation = getConnectorFocusedFormRecommendation(
    action ?? { fields: [] },
  );

  useEffect(() => {
    if (!action) {
      return;
    }
    const frame = window.requestAnimationFrame(() => {
      composerRef.current?.scrollIntoView({
        block: "start",
        inline: "nearest",
        behavior: "auto",
      });
      const firstField = firstFieldRef.current;
      firstField?.focus({ preventScroll: false });
      if (
        firstField &&
        (firstField instanceof HTMLInputElement ||
          firstField instanceof HTMLTextAreaElement)
      ) {
        firstField.select();
      }
    });
    return () => window.cancelAnimationFrame(frame);
  }, [action?.id]);

  if (!action) {
    return (
      <div className="workspace-empty-state">
        <strong>Select an action</strong>
        <p>Pick a live connector action to configure and run it here.</p>
      </div>
    );
  }

  const canRun = connectorReady && runtimeReady;

  return (
    <div ref={composerRef} className="workspace-action-panel workspace-composer-card">
      <div className="workspace-panel-heading-row">
        <div className="workspace-panel-heading">
          <span>Task composer</span>
          <strong>{action.label}</strong>
        </div>
        {showFocusedFormButton ? (
          <button
            type="button"
            className={`btn-secondary workspace-focus-form-button ${
              focusedFormRecommendation.recommended ? "recommended" : ""
            }`}
            onClick={onOpenFocusedForm}
          >
            {focusedFormRecommendation.buttonLabel}
          </button>
        ) : null}
      </div>

      <div className="workspace-action-summary">
        <span className={`workspace-action-kind kind-${action.kind}`}>
          {actionKindLabel(action.kind)}
        </span>
        <p>{action.description || "Live runtime action exposed by this connector."}</p>
        {action.confirmBeforeRun ? (
          <p className="workspace-inline-note">
            This action may request confirmation before it makes changes.
          </p>
        ) : null}
        {showFocusedFormButton && focusedFormRecommendation.note ? (
          <p className="workspace-inline-note">{focusedFormRecommendation.note}</p>
        ) : null}
        {!connectorReady ? (
          <p className="workspace-inline-note">
            Connect this surface before running {action.label}.
          </p>
        ) : null}
        {action.requiredScopes && action.requiredScopes.length > 0 ? (
          <div className="workspace-required-scopes">
            {action.requiredScopes.map((scope) => (
              <code key={scope}>{scope}</code>
            ))}
          </div>
        ) : null}
      </div>

      {action.fields.length > 0 ? (
        <div className="workspace-action-grid">
          {action.fields.map((field, index) =>
            renderGenericActionField(
              field,
              input[field.id] ?? "",
              onInputChange,
              index === 0 ? firstFieldRef : undefined,
            ),
          )}
        </div>
      ) : (
        <p className="workspace-auth-note">
          No additional input is required for this action.
        </p>
      )}

      <div className="workspace-action-actions">
        <button
          type="button"
          className="btn-primary"
          onClick={onRun}
          disabled={busy || !canRun}
        >
          {busy ? "Running..." : `Run ${action.label}`}
        </button>
      </div>

      {error ? <p className="connector-test-error">{error}</p> : null}
      {result ? (
        <>
          <ConnectorInlineResultCard
            summary={result.summary}
            details={[
              `Provider ${result.provider}`,
              result.toolName ? `Tool ${result.toolName}` : null,
              result.executedAtUtc ? `Executed ${result.executedAtUtc}` : null,
            ].filter((detail): detail is string => Boolean(detail))}
          />
          <pre className="connector-test-result">
            {result.rawOutput?.trim() ||
              JSON.stringify(result.data, null, 2)}
          </pre>
        </>
      ) : null}
    </div>
  );
}

export function GenericConnectorPanel({
  runtime,
  connector,
  section = "all",
  onConfigured,
  onOpenPolicyCenter,
}: GenericConnectorPanelProps) {
  const [actionsState, setActionsState] = useState<GenericActionsState>({
    status: "idle",
    actions: [],
    error: null,
  });
  const [selectedActionId, setSelectedActionId] = useState<string | null>(null);
  const [selectedPreviewActionId, setSelectedPreviewActionId] = useState<
    string | null
  >(null);
  const [focusedActionModalOpen, setFocusedActionModalOpen] = useState(false);
  const [input, setInput] = useState<Record<string, string | number>>({});
  const [configureBusy, setConfigureBusy] = useState(false);
  const [configureMessage, setConfigureMessage] = useState<string | null>(null);
  const [configureError, setConfigureError] = useState<string | null>(null);
  const [runBusy, setRunBusy] = useState(false);
  const [runError, setRunError] = useState<string | null>(null);
  const [runResult, setRunResult] = useState<ConnectorActionResult | null>(null);
  const [statusOverride, setStatusOverride] = useState<
    ConnectorSummary["status"] | null
  >(null);

  const effectiveStatus = statusOverride ?? connector.status;
  const connectorReady =
    effectiveStatus === "connected" || effectiveStatus === "degraded";
  const runtimeCanRun = Boolean(runtime.runConnectorAction);
  const selectedAction = useMemo(
    () =>
      actionsState.actions.find((action) => action.id === selectedActionId) ??
      actionsState.actions[0] ??
      null,
    [actionsState.actions, selectedActionId],
  );
  const selectedPreviewAction = useMemo(
    () =>
      actionsState.actions.find((action) => action.id === selectedPreviewActionId) ??
      null,
    [actionsState.actions, selectedPreviewActionId],
  );
  const previewActions = useMemo(
    () =>
      actionsState.actions.slice(0, 2).map((action) => ({
        id: action.id,
        categoryLabel: actionServiceLabel(action),
        title: action.label,
        description:
          action.description || "Live runtime action exposed by this connector.",
        hint: connectorReady
          ? "Open this action in the task composer"
          : "Unlock this action: connect the surface first",
      })),
    [actionsState.actions, connectorReady],
  );

  const requestActions = useCallback(async () => {
    if (!runtime.getConnectorActions) {
      setActionsState({
        status: "error",
        actions: [],
        error:
          "This runtime does not expose live connector-action inspection yet.",
      });
      return;
    }

    setActionsState((current) => ({
      status: "loading",
      actions: current.actions,
      error: null,
    }));

    try {
      const actions = await runtime.getConnectorActions(connector.id);
      setActionsState({
        status: "ready",
        actions,
        error: null,
      });
    } catch (error) {
      setActionsState((current) => ({
        status: "error",
        actions: current.actions,
        error: String(error),
      }));
    }
  }, [connector.id, runtime]);

  useEffect(() => {
    void requestActions();
  }, [requestActions]);

  useEffect(() => {
    setSelectedActionId((current) => {
      if (current && actionsState.actions.some((action) => action.id === current)) {
        return current;
      }
      return actionsState.actions[0]?.id ?? null;
    });
  }, [actionsState.actions]);

  useEffect(() => {
    setInput(buildInitialInput(selectedAction));
    setRunError(null);
    setRunResult(null);
  }, [selectedAction]);

  useEffect(() => {
    setStatusOverride(null);
    setConfigureMessage(null);
    setConfigureError(null);
    setRunError(null);
    setRunResult(null);
  }, [connector.id]);

  const handleInputChange = useCallback((fieldId: string, value: string) => {
    setInput((current) => ({
      ...current,
      [fieldId]: value,
    }));
  }, []);

  const handleConfigure = useCallback(async () => {
    if (!runtime.configureConnector) {
      setConfigureError(
        "This runtime does not expose a generic configure flow yet.",
      );
      return false;
    }

    setConfigureBusy(true);
    setConfigureMessage(null);
    setConfigureError(null);
    try {
      const result = await runtime.configureConnector({
        connectorId: connector.id,
        input: {},
      });
      setStatusOverride(result.status);
      setConfigureMessage(result.summary);
      onConfigured?.(result);
      return true;
    } catch (error) {
      setConfigureError(String(error));
      return false;
    } finally {
      setConfigureBusy(false);
    }
  }, [connector.id, onConfigured, runtime]);

  const handleUnlockContinue = useCallback(async () => {
    if (selectedPreviewAction) {
      setSelectedActionId(selectedPreviewAction.id);
    }
    const configured = await handleConfigure();
    if (configured) {
      setSelectedPreviewActionId(null);
    }
  }, [handleConfigure, selectedPreviewAction]);

  const handleRun = useCallback(async () => {
    if (!selectedAction || !runtime.runConnectorAction) {
      return;
    }

    setRunBusy(true);
    setRunError(null);
    setRunResult(null);
    try {
      const result = await runtime.runConnectorAction({
        connectorId: connector.id,
        actionId: selectedAction.id,
        input: normalizeActionInput(selectedAction, input),
      });
      setRunResult(result);
    } catch (error) {
      setRunError(String(error));
    } finally {
      setRunBusy(false);
    }
  }, [connector.id, input, runtime, selectedAction]);

  const renderActionsSurface = () => {
    if (actionsState.status === "error") {
      return (
        <section className="workspace-auth-stage">
          <div className="workspace-auth-stage-head">
            <div>
              <span className="workspace-hero-kicker">Live tools</span>
              <h4>Connector actions unavailable</h4>
              <p>
                {actionsState.error ??
                  "The runtime could not load connector actions for this surface."}
              </p>
            </div>
            <button type="button" className="btn-secondary" onClick={() => void requestActions()}>
              Retry
            </button>
          </div>
        </section>
      );
    }

    if (actionsState.status === "idle" || actionsState.status === "loading") {
      return (
        <section className="workspace-auth-stage">
          <div className="workspace-auth-stage-head">
            <div>
              <span className="workspace-hero-kicker">Live tools</span>
              <h4>Loading connector actions</h4>
              <p>Inspecting connector-backed actions from the live runtime…</p>
            </div>
            <span className="workspace-health-pill tone-setup">Loading</span>
          </div>
        </section>
      );
    }

    if (actionsState.actions.length === 0) {
      return (
        <section className="workspace-auth-stage">
          <div className="workspace-auth-stage-head">
            <div>
              <span className="workspace-hero-kicker">Live tools</span>
              <h4>No connector actions published</h4>
              <p>
                This connector is live, but it does not currently publish any
                callable actions through the runtime.
              </p>
            </div>
            <span className="workspace-health-pill tone-setup">0 tools</span>
          </div>
        </section>
      );
    }

    return (
      <>
        <ConnectorActionWorkbench
          className="generic-connector-workbench"
          title={`${connector.name} actions`}
          summary={
            connectorReady
              ? "Use the shared connector workbench to browse runtime actions, tune input, and run the selected tool."
              : "Preview live runtime actions here, then connect the surface before you run them."
          }
          shortcuts={
            <>
              <span
                className={`workspace-health-pill tone-${connectorStatusTone(effectiveStatus)}`}
              >
                {connectorStatusLabel(effectiveStatus)}
              </span>
              {selectedAction?.confirmBeforeRun ? (
                <span className="workspace-kind-chip">Confirm before run</span>
              ) : null}
              {selectedAction?.requiredScopes?.length ? (
                <span className="workspace-kind-chip">
                  {selectedAction.requiredScopes.length} scopes
                </span>
              ) : null}
            </>
          }
          actionLabel={selectedAction?.label ?? null}
          browser={
            <div>
              <div className="workspace-section-header">
                <div>
                  <span className="workspace-hero-kicker">
                    {connector.provider}
                  </span>
                  <h4>Run shared connector actions</h4>
                  <p>
                    This is the default connector execution shell for runtime
                    surfaces that do not need a bespoke Google or Mail panel.
                  </p>
                </div>
              </div>
              <div className="workspace-capability-grid">
                {actionsState.actions.map((action) => (
                  <button
                    key={action.id}
                    type="button"
                    className={`workspace-featured-action ${
                      selectedAction?.id === action.id ? "active" : ""
                    }`}
                    onClick={() => setSelectedActionId(action.id)}
                  >
                    <strong>{action.label}</strong>
                    <p>
                      {action.description ||
                        "Live runtime action exposed by this connector."}
                    </p>
                    <div className="workspace-kind-list">
                      <span className="workspace-kind-chip">
                        {actionKindLabel(action.kind)}
                      </span>
                      <span className="workspace-kind-chip">
                        {actionServiceLabel(action)}
                      </span>
                      {action.fields.length > 0 ? (
                        <span className="workspace-kind-chip">
                          {action.fields.length} fields
                        </span>
                      ) : null}
                    </div>
                  </button>
                ))}
              </div>
            </div>
          }
          sidebar={
            focusedActionModalOpen ? (
              <ConnectorFocusedFormCard
                actionLabel={selectedAction?.label ?? null}
                description="The focused modal is open for denser connector actions. Return here when you want the inline workbench again."
                onReturn={() => setFocusedActionModalOpen(false)}
              />
            ) : (
              <GenericConnectorActionComposer
                connectorReady={connectorReady}
                action={selectedAction}
                input={input}
                busy={runBusy}
                runtimeReady={runtimeCanRun}
                error={runError}
                result={runResult}
                showFocusedFormButton
                onOpenFocusedForm={() => setFocusedActionModalOpen(true)}
                onInputChange={handleInputChange}
                onRun={() => void handleRun()}
              />
            )
          }
        />

        {selectedAction ? (
          <ConnectorExecutionMeta>
            <span>
              Service <code>{actionServiceLabel(selectedAction)}</code>
            </span>
            <span>
              Kind <code>{actionKindLabel(selectedAction.kind)}</code>
            </span>
            <span>
              Fields <code>{selectedAction.fields.length}</code>
            </span>
            {selectedAction.toolName ? (
              <span>
                Tool <code>{selectedAction.toolName}</code>
              </span>
            ) : null}
          </ConnectorExecutionMeta>
        ) : null}

        <WorkspaceModal
          open={focusedActionModalOpen && Boolean(selectedAction)}
          title={selectedAction ? `Focused form · ${selectedAction.label}` : "Focused form"}
          description="Use the focused form when you want the primary connector fields and run control to stay fully in view."
          onClose={() => setFocusedActionModalOpen(false)}
        >
          <GenericConnectorActionComposer
            connectorReady={connectorReady}
            action={selectedAction}
            input={input}
            busy={runBusy}
            runtimeReady={runtimeCanRun}
            error={runError}
            result={runResult}
            onInputChange={handleInputChange}
            onRun={() => void handleRun()}
          />
        </WorkspaceModal>
      </>
    );
  };

  return (
    <>
      {(section === "all" || section === "setup") && !connectorReady ? (
        <>
          {previewActions.length > 0 ? (
            <ConnectorActionPreviewStage
              kicker="Preview"
              title="Unlock connector actions"
              summary="Lead with the most useful runtime actions, then connect the surface only when you know what you want to unlock."
              statusLabel={connectorStatusLabel(effectiveStatus)}
              actions={previewActions}
              onSelectAction={setSelectedPreviewActionId}
            />
          ) : null}

          <section className="workspace-auth-stage">
            <div className="workspace-auth-stage-head">
              <div>
                <span className="workspace-hero-kicker">Setup</span>
                <h4>Connect this surface</h4>
                <p>
                  Attach the runtime session for {connector.name} so the shared
                  action workbench can run its live connector tools.
                </p>
              </div>
              <span
                className={`workspace-health-pill tone-${connectorStatusTone(effectiveStatus)}`}
              >
                {connectorStatusLabel(effectiveStatus)}
              </span>
            </div>
            {connector.notes ? <p className="workspace-inline-note">{connector.notes}</p> : null}
            {actionsState.status === "loading" ? (
              <p className="workspace-inline-note">
                Loading live action metadata for this surface…
              </p>
            ) : null}
            <div className="workspace-card-actions">
              <button
                type="button"
                className="btn-primary"
                onClick={() => void handleConfigure()}
                disabled={configureBusy}
              >
                {configureBusy ? "Connecting..." : "Connect this surface"}
              </button>
              {onOpenPolicyCenter ? (
                <button
                  type="button"
                  className="btn-secondary"
                  onClick={() => onOpenPolicyCenter(connector)}
                >
                  Open policy
                </button>
              ) : null}
            </div>
            {configureMessage ? (
              <p className="connector-test-success">{configureMessage}</p>
            ) : null}
            {configureError ? (
              <p className="connector-test-error">{configureError}</p>
            ) : null}
          </section>
        </>
      ) : null}

      {(section === "all" || section === "setup") && connectorReady ? (
        <section className="workspace-auth-stage">
          <div className="workspace-auth-stage-head">
            <div>
              <span className="workspace-hero-kicker">Session ready</span>
              <h4>{connector.name} is connected</h4>
              <p>
                This surface is ready for the shared connector workbench. Refresh
                the session here if you need to rehydrate runtime state.
              </p>
            </div>
            <span
              className={`workspace-health-pill tone-${connectorStatusTone(effectiveStatus)}`}
            >
              {connectorStatusLabel(effectiveStatus)}
            </span>
          </div>
          <div className="workspace-card-actions">
            <button
              type="button"
              className="btn-secondary"
              onClick={() => void handleConfigure()}
              disabled={configureBusy}
            >
              {configureBusy ? "Refreshing..." : "Refresh connector session"}
            </button>
            {onOpenPolicyCenter ? (
              <button
                type="button"
                className="btn-secondary"
                onClick={() => onOpenPolicyCenter(connector)}
              >
                Open policy
              </button>
            ) : null}
          </div>
          {configureMessage ? (
            <p className="connector-test-success">{configureMessage}</p>
          ) : null}
          {configureError ? (
            <p className="connector-test-error">{configureError}</p>
          ) : null}
        </section>
      ) : null}

      {section === "all" || section === "actions" ? renderActionsSurface() : null}

      <ConnectorActionUnlockModal
        open={Boolean(selectedPreviewAction)}
        title={
          selectedPreviewAction
            ? `Unlock ${selectedPreviewAction.label}`
            : "Unlock connector action"
        }
        description="This connector action needs a connected runtime surface before it can run."
        summaryCategory={selectedPreviewAction ? actionServiceLabel(selectedPreviewAction) : "Connector action"}
        summaryTitle={selectedPreviewAction?.label ?? "Connector action"}
        summaryDescription={
          selectedPreviewAction?.description ||
          "Live runtime action exposed by this connector."
        }
        onClose={() => setSelectedPreviewActionId(null)}
      >
        <article className="workspace-stat-card workspace-summary-card">
          <span>Blocked by setup</span>
          <strong>{connectorStatusLabel(effectiveStatus)}</strong>
          <p>
            {selectedPreviewAction
              ? `${selectedPreviewAction.label} needs this surface connected before Autopilot can run it.`
              : "Connect this surface before you run its live actions."}
          </p>
        </article>

        {selectedPreviewAction?.requiredScopes?.length ? (
          <article className="workspace-stat-card workspace-summary-card">
            <span>Required scopes</span>
            <strong>{selectedPreviewAction.requiredScopes.length} scopes</strong>
            <div className="workspace-required-scopes">
              {selectedPreviewAction.requiredScopes.map((scope) => (
                <code key={scope}>{scope}</code>
              ))}
            </div>
          </article>
        ) : null}

        <div className="workspace-card-actions">
          <button
            type="button"
            className="btn-primary"
            onClick={() => void handleUnlockContinue()}
            disabled={configureBusy}
          >
            {configureBusy ? "Connecting..." : "Connect and continue"}
          </button>
          {onOpenPolicyCenter ? (
            <button
              type="button"
              className="btn-secondary"
              onClick={() => onOpenPolicyCenter(connector)}
            >
              Open policy
            </button>
          ) : null}
        </div>
        {configureError ? <p className="connector-test-error">{configureError}</p> : null}
      </ConnectorActionUnlockModal>
    </>
  );
}

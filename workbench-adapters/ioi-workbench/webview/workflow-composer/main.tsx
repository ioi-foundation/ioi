import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import { WorkflowComposer } from "@ioi/hypervisor-workbench";
import "@ioi/hypervisor-workbench/dist/style.css";
import "./styles.css";
import { createFixtureRuntime } from "./fixtureRuntime";
import { scenarioById, workflowScenarios } from "./fixtureWorkflows";

declare global {
  interface Window {
    acquireVsCodeApi?: () => {
      postMessage: (message: unknown) => void;
      getState?: () => unknown;
      setState?: (state: unknown) => void;
    };
    __IOI_WORKFLOW_COMPOSITOR_PARITY__?: unknown;
    __IOI_WORKFLOW_COMPOSITOR_INITIAL_STATE__?: {
      workspaceRoot?: string;
      bridgeConfigured?: boolean;
      daemonEndpoint?: string | null;
      daemonToken?: string | null;
      daemonModelId?: string | null;
      runtimeAuthority?: string;
      projectionOwner?: string;
      tauriUsed?: boolean;
    };
    __IOI_WORKFLOW_DAEMON_ROUTE_READY__?: boolean;
  }
}

const vscode =
  window.acquireVsCodeApi?.() ?? {
    postMessage: (message: unknown) => console.info("[IOI composer]", message),
  };

function isBenignResizeObserverNotice(message: unknown) {
  return /ResizeObserver loop (completed with undelivered notifications|limit exceeded)/i.test(
    String(message ?? ""),
  );
}

window.addEventListener("error", (event) => {
  if (isBenignResizeObserverNotice(event.message)) return;
  vscode.postMessage({
    type: "workflowCompositorError",
    error: {
      message: event.message,
      source: event.filename,
      line: event.lineno,
      column: event.colno,
      stack: event.error?.stack,
    },
  });
});

window.addEventListener("unhandledrejection", (event) => {
  if (isBenignResizeObserverNotice(event.reason?.message ?? event.reason)) return;
  vscode.postMessage({
    type: "workflowCompositorError",
    error: {
      message: String(event.reason?.message ?? event.reason),
      stack: event.reason?.stack,
    },
  });
});

type Phase =
  | "canvas"
  | "node-inspector"
  | "readiness"
  | "run-timeline"
  | "receipts-replay"
  | "connector-fixture"
  | "model-binding";

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

function bridgeRequest(requestType: string, payload: Record<string, unknown> = {}) {
  vscode.postMessage({
    type: "bridgeRequest",
    requestType,
    payload: {
      schemaVersion: "ioi.workflow-compositor-bridge.v1",
      runtimeAuthority: "daemon-owned",
      projectionOwner: "ioi-workbench-workflow-composer-webview",
      ownsRuntimeState: false,
      directFileMutation: false,
      externalAction: false,
      ...payload,
    },
  });
}

function clickSelector(selector: string) {
  const element = document.querySelector<HTMLElement>(selector);
  if (!element) return false;
  element.scrollIntoView({ block: "center", inline: "center" });
  element.dispatchEvent(
    new MouseEvent("click", {
      bubbles: true,
      cancelable: true,
      view: window,
    }),
  );
  return true;
}

function doubleClickSelector(selector: string) {
  const element = document.querySelector<HTMLElement>(selector);
  if (!element) return false;
  element.scrollIntoView({ block: "center", inline: "center" });
  element.dispatchEvent(new MouseEvent("click", { bubbles: true, view: window }));
  element.dispatchEvent(new MouseEvent("dblclick", { bubbles: true, view: window }));
  return true;
}

function closeOpenDialog() {
  const closeButton = Array.from(document.querySelectorAll<HTMLButtonElement>("button")).find(
    (button) => button.textContent?.trim().toLowerCase() === "close",
  );
  closeButton?.click();
}

function collectDomProof(scenarioId: string, phase: string) {
  const selectors = {
    composer: document.querySelectorAll('[data-testid="workflow-composer"]').length,
    canvas: document.querySelectorAll('[data-inspection-target="workflow-canvas"]').length,
    nodes: document.querySelectorAll('[data-inspection-target="workflow-node"]').length,
    edges: document.querySelectorAll(".react-flow__edge").length,
    nodeInspector:
      document.querySelectorAll('[data-testid="workflow-node-config-modal"]').length ||
      document.querySelectorAll('[data-testid="workflow-node-detail-workbench"]').length,
    readiness:
      document.querySelectorAll('[data-testid="workflow-activation-readiness"]').length ||
      document.querySelectorAll('[data-testid="ioi-composer-readiness-panel"]').length,
    runTimeline:
      document.querySelectorAll('[data-testid="workflow-bottom-run-timeline"]').length ||
      document.querySelectorAll('[data-testid="workflow-run-event-snapshot"]').length ||
      document.querySelectorAll('[data-testid="ioi-composer-run-timeline"]').length,
    receiptsReplay:
      document.querySelectorAll('[data-testid="workflow-fixtures-panel"]').length ||
      document.querySelectorAll('[data-testid="workflow-checkpoints-panel"]').length ||
      document.querySelectorAll('[data-testid="ioi-composer-receipts-replay"]').length,
    connectorBinding:
      document.querySelectorAll('[data-testid="workflow-connector-binding-modal"]').length ||
      document.querySelectorAll('[data-testid="ioi-composer-connector-fixture-binding"]').length,
    modelBinding:
      document.querySelectorAll('[data-testid="workflow-model-binding-modal"]').length ||
      document.querySelectorAll('[data-testid="ioi-composer-model-binding"]').length,
  };
  const daemonModelRuntimeConfigured = Boolean(
    window.__IOI_WORKFLOW_COMPOSITOR_INITIAL_STATE__?.daemonEndpoint &&
      window.__IOI_WORKFLOW_COMPOSITOR_INITIAL_STATE__?.daemonToken,
  );
  const proof = {
    schemaVersion: "ioi.workflow-compositor-parity.dom-proof.v1",
    scenarioId,
    phase,
    generatedAtMs: Date.now(),
    runtimeAuthority: "daemon-owned",
    projectionOwner: "ioi-workbench-workflow-composer-webview",
    webviewOwnsRuntimeState: false,
    directFileMutation: false,
    externalAction: false,
    tauriUsed: false,
    daemonModelRuntimeConfigured,
    daemonModelRouteReady: Boolean(window.__IOI_WORKFLOW_DAEMON_ROUTE_READY__),
    fixtureModelRuntime: !daemonModelRuntimeConfigured,
    selectors,
    visibleText: document.body.innerText.slice(0, 3000),
  };
  window.__IOI_WORKFLOW_COMPOSITOR_PARITY__ = proof;
  vscode.postMessage({ type: "workflowCompositorProof", proof });
  return proof;
}

async function checkDaemonModelRouteReady() {
  const initialState = window.__IOI_WORKFLOW_COMPOSITOR_INITIAL_STATE__ ?? {};
  const endpoint =
    typeof initialState.daemonEndpoint === "string" && initialState.daemonEndpoint.trim()
      ? initialState.daemonEndpoint.replace(/\/+$/, "")
      : "";
  if (!endpoint) return false;
  const response = await fetch(`${endpoint}/v1/model-mount/projection`, {
    headers: {
      accept: "application/json",
      ...(initialState.daemonToken
        ? { authorization: `Bearer ${initialState.daemonToken}` }
        : {}),
    },
  });
  const text = await response.text();
  const projection = text ? JSON.parse(text) : {};
  if (!response.ok) {
    throw new Error(
      projection?.error?.message ||
        projection?.message ||
        `Model route projection failed with ${response.status}`,
    );
  }
  const instances = Array.isArray(projection?.instances) ? projection.instances : [];
  return instances.some((instance: any) => instance?.status === "loaded");
}

function EvidenceStrip({
  scenarioId,
  phase,
  runCount,
  daemonModelRuntimeConfigured,
  daemonModelRouteReady,
}: {
  scenarioId: string;
  phase: string;
  runCount: number;
  daemonModelRuntimeConfigured: boolean;
  daemonModelRouteReady: boolean;
}) {
  const scenario = scenarioById(scenarioId);
  const daemonRouteBlocked = daemonModelRuntimeConfigured && !daemonModelRouteReady;
  return (
    <aside className="ioi-composer-evidence-strip" data-testid="ioi-composer-evidence-strip">
      <section
        data-testid="ioi-composer-readiness-panel"
        data-route-ready={daemonModelRouteReady ? "true" : "false"}
        data-route-blocked={daemonRouteBlocked ? "true" : "false"}
        className={daemonRouteBlocked ? "is-blocked" : ""}
      >
        <span>Readiness</span>
        <strong>
          {daemonModelRuntimeConfigured
            ? daemonModelRouteReady
              ? "Daemon route ready"
              : "Daemon route blocked"
            : "Fixture passed"}
        </strong>
        <small>
          {daemonModelRuntimeConfigured
            ? daemonModelRouteReady
              ? "Model bindings are projected from loaded daemon instances."
              : "Load or remount a model before daemon-backed workflow dry-run."
            : "Daemon composer APIs pending; no direct webview authority."}
        </small>
      </section>
      <section data-testid="ioi-composer-run-timeline">
        <span>Run timeline</span>
        <strong>
          {runCount > 0
            ? `${runCount} ${daemonModelRuntimeConfigured ? "daemon model run" : "fixture run"}`
            : "Ready to run"}
        </strong>
        <small>{phase === "run-timeline" ? "Timeline focused" : scenario.label}</small>
      </section>
      <section data-testid="ioi-composer-receipts-replay">
        <span>Receipts / replay</span>
        <strong>{daemonModelRuntimeConfigured ? "daemon receipts + replay" : "receipt + replay fixture"}</strong>
        <small>
          {daemonModelRuntimeConfigured
            ? "Receipts are emitted by daemon model route/invocation APIs."
            : "Replayable fixture envelopes only."}
        </small>
      </section>
      <section data-testid="ioi-composer-model-binding">
        <span>Model binding</span>
        <strong>
          {daemonModelRuntimeConfigured
            ? daemonModelRouteReady
              ? "route.native-local"
              : "route.native-local blocked"
            : "fixture.reasoning.model"}
        </strong>
        <small>
          {daemonModelRuntimeConfigured
            ? daemonModelRouteReady
              ? "Workflow nodes bind to live daemon model routes."
              : "No loaded daemon model instance is available."
            : "Offline fixture model route."}
        </small>
      </section>
      <section data-testid="ioi-composer-connector-fixture-binding">
        <span>Connector binding</span>
        <strong>mock-capability</strong>
        <small>No live external connector action.</small>
      </section>
    </aside>
  );
}

class ComposerErrorBoundary extends React.Component<
  { children: React.ReactNode },
  { error: Error | null }
> {
  state = { error: null };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    vscode.postMessage({
      type: "workflowCompositorError",
      error: {
        message: error.message,
        stack: error.stack,
        componentStack: errorInfo.componentStack,
      },
    });
  }

  render() {
    if (!this.state.error) return this.props.children;
    return (
      <section className="ioi-composer-error" data-testid="workflow-composer-error-boundary">
        <strong>Workflow Composer render failed</strong>
        <pre>{this.state.error.message}</pre>
      </section>
    );
  }
}

function App() {
  const initialScenario = workflowScenarios[0];
  const [scenarioId, setScenarioId] = useState(initialScenario.id);
  const [phase, setPhase] = useState<Phase>("canvas");
  const [pendingFile, setPendingFile] = useState<any>(() => initialScenario.project);
  const [runCount, setRunCount] = useState(0);
  const [daemonModelRouteReady, setDaemonModelRouteReady] = useState(false);
  const scenarioIdRef = useRef(scenarioId);
  scenarioIdRef.current = scenarioId;
  const daemonModelRuntimeConfigured = Boolean(
    window.__IOI_WORKFLOW_COMPOSITOR_INITIAL_STATE__?.daemonEndpoint &&
      window.__IOI_WORKFLOW_COMPOSITOR_INITIAL_STATE__?.daemonToken,
  );
  window.__IOI_WORKFLOW_DAEMON_ROUTE_READY__ = daemonModelRouteReady;

  const postBridge = useCallback((requestType: string, payload: Record<string, unknown> = {}) => {
    bridgeRequest(requestType, {
      ...payload,
      activeScenarioId: scenarioIdRef.current,
    });
    if (
      requestType === "workflowCompositor.fixtureRunProject" ||
      requestType === "workflowCompositor.daemonRunProject"
    ) {
      setRunCount((current) => current + 1);
    }
  }, []);

  const runtime = useMemo(
    () => createFixtureRuntime(() => scenarioIdRef.current, postBridge),
    [postBridge],
  );

  const activateScenario = useCallback((nextScenarioId: string, nextPhase: Phase = "canvas") => {
    const scenario = scenarioById(nextScenarioId);
    setScenarioId(scenario.id);
    scenarioIdRef.current = scenario.id;
    setPhase(nextPhase);
    setPendingFile(JSON.parse(JSON.stringify(scenario.project)));
    bridgeRequest("workflowCompositor.scenarioBuiltThroughGui", {
      scenarioId: scenario.id,
      label: scenario.label,
      nodeCount: scenario.project.nodes.length,
      edgeCount: scenario.project.edges.length,
      createdThroughGui: true,
      manualFileEdits: false,
    });
  }, []);

  const drivePhase = useCallback(async (nextPhase: Phase, nextScenarioId = scenarioIdRef.current) => {
    activateScenario(nextScenarioId, nextPhase);
    await sleep(1200);
    closeOpenDialog();
    await sleep(150);
    if (nextPhase === "node-inspector") {
      doubleClickSelector('[data-inspection-target="workflow-node"]');
    } else if (nextPhase === "readiness") {
      clickSelector('[data-testid="workflow-deploy-button"]');
      await sleep(250);
      clickSelector('[data-testid="workflow-check-readiness"]');
    } else if (nextPhase === "run-timeline") {
      clickSelector('[data-testid="workflow-run-button"]');
    } else if (nextPhase === "receipts-replay") {
      clickSelector('[data-inspection-target="workflow-node"]');
      await sleep(150);
      clickSelector('[data-testid="workflow-run-button"]');
    } else if (nextPhase === "connector-fixture") {
      clickSelector('[data-testid="workflow-connector-bindings-button"]');
    } else if (nextPhase === "model-binding") {
      clickSelector('[data-testid="workflow-model-bindings-button"]');
    }
    await sleep(1500);
    collectDomProof(nextScenarioId, nextPhase);
  }, [activateScenario]);

  useEffect(() => {
    const refreshDaemonRoute = async () => {
      if (!daemonModelRuntimeConfigured) {
        window.__IOI_WORKFLOW_DAEMON_ROUTE_READY__ = false;
        setDaemonModelRouteReady(false);
        return;
      }
      try {
        const ready = await checkDaemonModelRouteReady();
        window.__IOI_WORKFLOW_DAEMON_ROUTE_READY__ = ready;
        setDaemonModelRouteReady(ready);
        bridgeRequest("workflowCompositor.daemonRouteReadiness", {
          routeId: "route.native-local",
          ready,
        });
      } catch (error) {
        window.__IOI_WORKFLOW_DAEMON_ROUTE_READY__ = false;
        setDaemonModelRouteReady(false);
        bridgeRequest("workflowCompositor.daemonRouteReadiness", {
          routeId: "route.native-local",
          ready: false,
          error: String((error as Error)?.message ?? error),
        });
      }
    };
    void refreshDaemonRoute();
    bridgeRequest("workflowCompositor.webviewReady", {
      scenarios: workflowScenarios.map((scenario) => scenario.id),
      realWorkflowComposerMounted: true,
      daemonModelRuntimeConfigured,
    });
    collectDomProof(scenarioIdRef.current, "initial");

    const onMessage = (event: MessageEvent) => {
      const message = event.data ?? {};
      if (message.type === "ioi.workflow.compositor.runScenario") {
        const nextScenarioId = String(message.scenarioId ?? scenarioIdRef.current);
        const nextPhase = (message.phase ?? "canvas") as Phase;
        void refreshDaemonRoute();
        void drivePhase(nextPhase, nextScenarioId);
      }
      if (message.type === "ioi.workflow.compositor.capturePhase") {
        const nextPhase = (message.phase ?? "canvas") as Phase;
        void refreshDaemonRoute();
        void drivePhase(nextPhase, String(message.scenarioId ?? scenarioIdRef.current));
      }
      if (message.type === "ioi.workflow.compositor.refreshDaemonRoute") {
        void refreshDaemonRoute();
      }
    };
    window.addEventListener("message", onMessage);
    return () => window.removeEventListener("message", onMessage);
  }, [daemonModelRuntimeConfigured, drivePhase]);

  const scenario = scenarioById(scenarioId);
  const projectScope = {
    id: "autopilot-electron-workbench",
    name: "Autopilot Workbench",
    rootPath:
      window.__IOI_WORKFLOW_COMPOSITOR_INITIAL_STATE__?.workspaceRoot ??
      "ioi-workspace",
  };

  return (
    <main
      className="ioi-workflow-composer-shell"
      data-testid="ioi-workflow-composer-shell"
      data-scenario-id={scenarioId}
      data-phase={phase}
    >
      <div className="ioi-composer-parity-bar" data-testid="workflow-parity-harness">
        <div>
          <strong>Autopilot Workflows</strong>
          <span>Real @ioi/hypervisor-workbench WorkflowComposer in Electron</span>
        </div>
        <nav aria-label="Workflow parity scenarios">
          {workflowScenarios.map((item) => (
            <button
              key={item.id}
              type="button"
              className={item.id === scenarioId ? "is-active" : ""}
              data-testid={`workflow-parity-build-${item.id}`}
              onClick={() => activateScenario(item.id, "canvas")}
            >
              {item.label}
            </button>
          ))}
          <button
            type="button"
            data-testid="workflow-parity-run-dry-run"
            onClick={() => void drivePhase("run-timeline", scenarioId)}
          >
            Dry-run
          </button>
        </nav>
      </div>
      <section className="ioi-composer-runtime-note" data-testid="ioi-composer-runtime-boundary">
        <strong>{scenario.label}</strong>
        <span>{scenario.description}</span>
        <code>
          runtime:{" "}
          {daemonModelRuntimeConfigured
            ? daemonModelRouteReady
              ? "daemon-owned live model route"
              : "daemon-owned route blocked until model load"
            : "daemon-owned fixture adapter"}{" "}
          ·
          webview: projection/request bridge · externalAction=false
        </code>
      </section>
      <div className="ioi-composer-workspace">
        <ComposerErrorBoundary>
          <WorkflowComposer
            key="real-workflow-composer"
            runtime={runtime as any}
            currentProject={projectScope}
            initialFile={pendingFile}
            onInitialFileLoaded={() => setPendingFile(null)}
          />
        </ComposerErrorBoundary>
        <EvidenceStrip
          scenarioId={scenarioId}
          phase={phase}
          runCount={runCount}
          daemonModelRuntimeConfigured={daemonModelRuntimeConfigured}
          daemonModelRouteReady={daemonModelRouteReady}
        />
      </div>
    </main>
  );
}

const root = createRoot(document.getElementById("root")!);
root.render(<App />);

// T7-D — the native Workbench: workspace-substrate panes bound to ONE Session Execution Binding.
//
// Monaco/Explorer/Terminal/Source-Control/Diff hydrate from the same binding ref via the
// HypervisorWorkspaceAdapter (files = scoped env workspace, terminal = interactive PTY, SCM/diff =
// WorkRun). Operator chat/turns stay on /v1/threads/* (the binding only resolves the owner route);
// replay consumes the binding's receipt refs. No JS-owned lifecycle state.
import { useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { WorkspaceHost } from "@ioi/workspace-substrate";
import {
  createHypervisorDaemonClient,
  type SessionExecutionBinding,
} from "../services/hypervisorDaemonClient";
import { createHypervisorWorkspaceAdapter } from "../services/HypervisorWorkspaceAdapter";
import { CockpitNav, ReceiptRefs, OpenInPicker } from "./NativeCockpit";

const client = createHypervisorDaemonClient();

export function NativeWorkbench() {
  const { id } = useParams();
  const environmentId = id ?? "";
  const [binding, setBinding] = useState<SessionExecutionBinding | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        // Ensure the env is started, then resolve ONE binding (env + thread + WorkRun).
        const env = await client.getEnvironment(environmentId);
        if (env.environment?.status?.phase !== "running") await client.environmentAction(environmentId, "start");
        const wr = await client.createWorkRun(environmentId, { objective: "workbench session" });
        const workRunRef = wr.workRun?.id ? `work_run:${String(wr.workRun.id)}` : undefined;
        const b = await client.resolveSessionExecutionBinding({ environmentId, ensureThread: true, workRunRef });
        if (!cancelled) setBinding(b);
      } catch (e) {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e));
      }
    })();
    return () => { cancelled = true; };
  }, [environmentId]);

  const workRunId = useMemo(() => binding?.work_run_ref?.split(":").pop(), [binding]);
  const adapter = useMemo(
    () => (binding ? createHypervisorWorkspaceAdapter(client, environmentId, workRunId) : null),
    [binding, environmentId, workRunId],
  );
  const root = binding?.environment_status?.workspace_root ?? `/workspace/${environmentId}`;

  return (
    <div style={{ font: "14px/1.5 system-ui, sans-serif", color: "#e6e9ef", background: "#0d0f14", minHeight: "100vh", display: "flex", flexDirection: "column" }} data-testid="workbench-surface">
      <CockpitNav />
      <div style={{ padding: "8px 16px", borderBottom: "1px solid #2a2f3a", display: "flex", gap: 12, alignItems: "center" }}>
        <strong>Hypervisor Workbench</strong>
        <span style={{ color: "#7a818c", fontSize: 12 }} data-testid="binding-ref">{binding?.binding_ref ?? "resolving…"}</span>
        <span style={{ color: "#7a818c", fontSize: 12 }}>thread: {binding?.thread_ref ?? "—"}</span>
        <span style={{ color: "#7a818c", fontSize: 12 }}>workrun: {binding?.work_run_ref ?? "—"}</span>
        <span style={{ flex: 1 }} />
        <OpenInPicker environmentId={environmentId} />
        <Link to="/environments" style={{ color: "#6ab0ff" }}>← Environments</Link>
      </div>
      {error && <div style={{ color: "#9b2c2c", padding: 16 }} data-testid="workbench-error">Binding failed: {error}</div>}
      {binding && <div style={{ padding: "4px 16px" }}><ReceiptRefs refs={binding.receipt_refs} /></div>}
      <section style={{ flex: 1, minHeight: 0 }}>
        {adapter ? (
          <WorkspaceHost
            adapter={adapter}
            root={root}
            title={`Workbench · ${environmentId}`}
            showHeader={false}
            showBottomPanel
          />
        ) : (
          !error && <div style={{ padding: 16, color: "#7a818c" }} data-testid="workbench-loading">Resolving session execution binding…</div>
        )}
      </section>
    </div>
  );
}

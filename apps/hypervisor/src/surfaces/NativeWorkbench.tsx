// v2 Workbench surface — binding-aware editor over the Session Execution Binding. Converted onto
// the UX kit (ZERO hex): the chrome (toolbar/binding bar) is kit; the editor substrate
// (WorkspaceHost / Monaco) is left untouched — the kit frames it, it does not restyle it. The shell
// owns the rail; this renders inside the Open Application frame.
import { useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { WorkspaceHost } from "@ioi/workspace-substrate";
import {
  createHypervisorDaemonClient,
  type SessionExecutionBinding,
} from "../services/hypervisorDaemonClient";
import { createHypervisorWorkspaceAdapter } from "../services/HypervisorWorkspaceAdapter";
import { Heading, Mono, Muted, Spacer, StatusDot, ReceiptRefs, BlockerNotice } from "../ui";
import { OpenInPicker } from "./NativeCockpit";

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
    <div className="hv-col" style={{ height: "100%" }} data-testid="workbench-surface">
      <div className="hv-toolbar">
        <Heading level={2}>Hypervisor Workbench</Heading>
        <StatusDot tone={binding ? "success" : error ? "danger" : "neutral"} />
        <Mono>{binding?.binding_ref ?? "resolving…"}</Mono>
        <Muted>thread: {binding?.thread_ref ?? "—"}</Muted>
        <Muted>workrun: {binding?.work_run_ref ?? "—"}</Muted>
        <Spacer />
        <OpenInPicker environmentId={environmentId} />
        <Link to="/environments" className="hv-link">← Environments</Link>
      </div>
      {error && <div style={{ padding: "var(--spacing-lg)" }} data-testid="workbench-error"><BlockerNotice reasons={[`Binding failed: ${error}`]} /></div>}
      {binding && <div style={{ padding: "0 var(--spacing-lg)" }}><ReceiptRefs refs={binding.receipt_refs} /></div>}
      <section style={{ flex: 1, minHeight: 0 }}>
        {adapter ? (
          <WorkspaceHost adapter={adapter} root={root} title={`Workbench · ${environmentId}`} showHeader={false} showBottomPanel />
        ) : (
          !error && <div style={{ padding: "var(--spacing-lg)" }} data-testid="workbench-loading"><Muted>Resolving session execution binding…</Muted></div>
        )}
      </section>
    </div>
  );
}

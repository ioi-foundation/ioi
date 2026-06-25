// v2 catalog surfaces — Environments (the pressure surface; Providers folded in) + Sessions.
// Converted onto the UX kit: ZERO hex, ZERO bespoke inline color/background — every visual comes
// from kit components (../ui) over the global.css token system. Home + rail are owned by the shell.
import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  createHypervisorDaemonClient,
  type EnvironmentSummary,
  type ProviderInfo,
} from "../services/hypervisorDaemonClient";
import {
  Heading, Muted, Mono, Button, Card, Row, Spacer, Badge, StatusDot,
  ReadinessBadge, ComponentGrid, BlockerNotice, AuthorityControl,
  IconPlus,
} from "../ui";

const phaseTone = (phase?: string) => (phase === "running" ? "success" : phase === "stopped" ? "neutral" : "danger");

const client = createHypervisorDaemonClient();

// ---- "Open in…" affordance: editor-target launch over the daemon (effectful → AuthorityControl) ----
export function OpenInPicker({ environmentId }: { environmentId: string }) {
  const [targets, setTargets] = useState<Array<{ target_id: string; status: string }>>([]);
  const [status, setStatus] = useState<string>("");
  useEffect(() => { void client.listEditorTargets().then((r) => setTargets((r.targets ?? []).map((t) => ({ target_id: t.target_id, status: t.status })))); }, []);

  const openBrowser = async () => {
    setStatus("provisioning…");
    const svc = await client.createEditorService(environmentId, "vscode-browser");
    const sid = svc.editorService?.service_id;
    if (!sid) { setStatus("could not create editor service"); return; }
    const lease = await client.createEditorAccessLease(`session:${environmentId}`, environmentId, sid);
    await client.startEditorService(sid);
    const open = await client.editorServiceOpenUrl(sid, lease.lease_ref ?? "");
    if (open.ok && open.open_url) { window.open(open.open_url, "_blank"); setStatus("opened"); }
    else setStatus(open.reason ?? "editor runtime not ready");
  };
  const label = (id: string): string => ({ vscode: "Packaged VS Code", "vscode-browser": "VS Code Browser", "vscode-insiders": "VS Code Insiders" } as Record<string, string>)[id] ?? id;

  return (
    <div className="hv-openin" data-testid="open-in-picker">
      <Muted>Open in…</Muted>
      <Link to={`/workbench/${environmentId}`} className="hv-link" data-testid="open-in-native">Native Workbench</Link>
      <AuthorityControl
        productLabel="VS Code Browser"
        advancedLabel="Provision openvscode-server + capability lease + lease-authenticated proxy"
        onAct={openBrowser}
        testId="open-in-vscode-browser"
      />
      {targets.filter((t) => t.status === "declared").map((t) => (
        <Button key={t.target_id} size="sm" variant="ghost" disabled title={`${t.target_id} is a declared target (not yet provable end-to-end)`} data-testid="open-in-declared">
          {label(t.target_id)} (declared)
        </Button>
      ))}
      {status && <Muted>{status}</Muted>}
      <Muted>· mediation: gated_execution</Muted>
    </div>
  );
}

// ---- Environments (provider placement folded in) ----
export function EnvironmentsSurface() {
  const [envs, setEnvs] = useState<EnvironmentSummary[]>([]);
  const [providers, setProviders] = useState<ProviderInfo[]>([]);
  const [busy, setBusy] = useState(false);
  const [loaded, setLoaded] = useState(false);
  const [rebuilding, setRebuilding] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    const [e, p] = await Promise.all([client.listEnvironments(), client.listProviders()]);
    setEnvs(e.environments ?? []);
    setProviders(p.providers ?? []);
    setLoaded(true);
  }, []);
  useEffect(() => { void refresh(); }, [refresh]);

  const create = async () => {
    setBusy(true);
    try {
      const r = await client.createEnvironment({ environment_class_id: "local-workspace-v0", project_id: "native-ux" });
      const id = r.environment?.id;
      if (id) await client.environmentAction(id, "start");
      await refresh();
    } finally { setBusy(false); }
  };
  const act = async (id: string, action: "start" | "stop" | "delete") => { await client.environmentAction(id, action); await refresh(); };
  const rebuild = async (id: string) => { setRebuilding(id); try { await client.rebuildEnvironment(id); await refresh(); } finally { setRebuilding(null); } };
  const tone = (s: string) => (s === "available" ? "success" : s === "not_configured" ? "neutral" : "danger");

  return (
    <div className="hv-page" data-testid="environments-surface">
      <div className="hv-page__head">
        <Row><Heading level={1}>Environments</Heading><Badge tone="neutral">{envs.length}</Badge></Row>
        <Muted>Provider placement, runtime substrate, and environment lifecycle.</Muted>
      </div>

      <Row wrap>
        <Muted>Providers:</Muted>
        {providers.map((p) => <Badge key={p.provider_ref} tone={tone(p.status)}>{p.provider_ref}: {p.status}</Badge>)}
      </Row>

      <div>
        <Button variant="primary" onClick={create} disabled={busy} data-testid="create-env">
          <IconPlus size={15} />{busy ? "Creating…" : "Create + Start environment"}
        </Button>
      </div>

      {!loaded && <Muted>Loading environments…</Muted>}

      <div className="hv-stack">
        {envs.map((e) => (
          <Card key={e.id} testId="env-card">
            <Row>
              <Mono>{e.id}</Mono>
              <ReadinessBadge mode={e.status?.readiness?.mode} />
              <StatusDot tone={phaseTone(e.status?.phase)} /><Muted>{e.status?.phase}</Muted>
              <Spacer />
              <Link to={`/workbench/${e.id}`} className="hv-link" data-testid="open-workbench">Open Workbench</Link>
              <Button size="sm" onClick={() => rebuild(e.id)} disabled={rebuilding === e.id} data-testid="rebuild-env" title="Rebuild from devcontainer/recipe (daemon lifecycle)">{rebuilding === e.id ? "Rebuilding…" : "Rebuild"}</Button>
              <Button size="sm" variant="ghost" onClick={() => act(e.id, "stop")}>Stop</Button>
              <Button size="sm" variant="danger" onClick={() => act(e.id, "delete")}>Delete</Button>
            </Row>
            <BlockerNotice reasons={e.status?.readiness?.reasons} />
            <div style={{ marginTop: "var(--spacing-sm)" }}><ComponentGrid components={e.status?.components} /></div>
            <div style={{ marginTop: "var(--spacing-sm)" }}><OpenInPicker environmentId={e.id} /></div>
          </Card>
        ))}
        {envs.length === 0 && <Muted>No environments yet.</Muted>}
      </div>
    </div>
  );
}

// ---- Sessions (minimal; live + historical execution) ----
export function SessionsSurface() {
  const [envs, setEnvs] = useState<EnvironmentSummary[]>([]);
  const [workRuns, setWorkRuns] = useState<Array<Record<string, unknown>>>([]);
  useEffect(() => {
    void client.listEnvironments().then((r) => setEnvs(r.environments ?? []));
    void client.listWorkRuns().then((r) => setWorkRuns(r.workRuns ?? []));
  }, []);
  return (
    <div className="hv-page" data-testid="sessions-surface">
      <div className="hv-page__head">
        <Heading level={1}>Sessions</Heading>
        <Muted>Live and historical execution. A session binds an environment + thread + WorkRun.</Muted>
      </div>
      <div className="hv-stack">
        {envs.map((e) => (
          <Card key={e.id}>
            <Row>
              <Mono>{e.id}</Mono>
              <ReadinessBadge mode={e.status?.readiness?.mode} />
              <Muted>{e.status?.phase}</Muted>
              <Spacer />
              <Link to={`/workbench/${e.id}`} className="hv-link">Workbench</Link>
            </Row>
          </Card>
        ))}
        {envs.length === 0 && <Muted>No active sessions.</Muted>}
      </div>
      <Heading level={2}>WorkRuns ({workRuns.length})</Heading>
      <div className="hv-col">
        {workRuns.map((w, i) => <Muted key={String(w.id ?? i)}>{String(w.id)} — {String(w.review_state ?? w.status ?? "")}</Muted>)}
      </div>
    </div>
  );
}

export function SessionDetailSurface() {
  const { id } = useParams();
  return (
    <div className="hv-page" data-testid="session-detail">
      <Heading level={1}>Session {id ?? ""}</Heading>
      <Link to={`/workbench/${id ?? ""}`} className="hv-link">Open Workbench</Link>
    </div>
  );
}

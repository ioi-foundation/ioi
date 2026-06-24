// T7-A/C — native operator surfaces (Sessions, Providers, Environments) + shared status
// components. Every surface is a projection over daemon truth via the typed client; no JS-owned
// lifecycle state, no provider-native IDs as truth. Every action button maps to a daemon route or
// is disabled with a blocker reason.
import React, { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  createHypervisorDaemonClient,
  type EnvironmentSummary,
  type ProviderInfo,
} from "../services/hypervisorDaemonClient";

const client = createHypervisorDaemonClient();

// ---- T7-C shared status components ----

export function ReadinessBadge({ mode }: { mode?: string }) {
  const color = mode === "full" ? "#1f9d55" : mode === "degraded" ? "#b7791f" : "#9b2c2c";
  return <span style={{ background: color, color: "#fff", borderRadius: 4, padding: "1px 8px", fontSize: 12 }}>{mode ?? "unknown"}</span>;
}

export function EnvironmentComponentGrid({ components }: { components?: Record<string, { phase?: string }> }) {
  const entries = Object.entries(components ?? {});
  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(140px,1fr))", gap: 6 }} data-testid="component-grid">
      {entries.map(([name, c]) => (
        <div key={name} style={{ border: "1px solid #2a2f3a", borderRadius: 6, padding: "6px 8px", fontSize: 12 }}>
          <div style={{ color: "#9aa4b2" }}>{name}</div>
          <div style={{ color: c.phase === "ready" ? "#1f9d55" : "#9aa4b2" }}>{c.phase ?? "—"}</div>
        </div>
      ))}
    </div>
  );
}

export function ProviderHealthBadge({ status }: { status: string }) {
  const color = status === "available" ? "#1f9d55" : status === "not_configured" ? "#7a818c" : "#9b2c2c";
  return <span style={{ background: color, color: "#fff", borderRadius: 4, padding: "1px 8px", fontSize: 12 }}>{status}</span>;
}

export function ResourceAllocationBadge({ pools }: { pools: number }) {
  return <span style={{ color: "#9aa4b2", fontSize: 12 }}>{pools} pool(s)</span>;
}

export function ReceiptRefs({ refs }: { refs: string[] }) {
  if (!refs.length) return null;
  return (
    <ul style={{ margin: "4px 0", paddingLeft: 16, fontSize: 11, color: "#7a818c" }} data-testid="receipt-refs">
      {refs.map((r) => <li key={r}>{r}</li>)}
    </ul>
  );
}

export function AuthorityBlockerPanel({ reasons }: { reasons?: string[] }) {
  if (!reasons || reasons.length === 0) return null;
  return <div style={{ color: "#b7791f", fontSize: 12 }}>Blocked: {reasons.join("; ")}</div>;
}

// ---- shell ----

const shell: React.CSSProperties = { font: "14px/1.5 system-ui, sans-serif", color: "#e6e9ef", background: "#0d0f14", minHeight: "100vh" };
const nav: React.CSSProperties = { display: "flex", gap: 16, padding: "10px 16px", borderBottom: "1px solid #2a2f3a", background: "#11141b" };

export function CockpitNav() {
  return (
    <nav style={nav} data-testid="cockpit-nav">
      <Link to="/" style={{ color: "#e6e9ef" }}>Home</Link>
      <Link to="/sessions" style={{ color: "#e6e9ef" }}>Sessions</Link>
      <Link to="/providers" style={{ color: "#e6e9ef" }}>Providers</Link>
      <Link to="/environments" style={{ color: "#e6e9ef" }}>Environments</Link>
    </nav>
  );
}

function Surface({ title, children, testid }: { title: string; children: React.ReactNode; testid: string }) {
  return (
    <div style={shell}>
      <CockpitNav />
      <main style={{ padding: 16 }} data-testid={testid}>
        <h1 style={{ fontSize: 18, marginTop: 0 }}>{title}</h1>
        {children}
      </main>
    </div>
  );
}

// ---- Home ----

export function HomeSurface() {
  return (
    <Surface title="Hypervisor — Operator Cockpit" testid="home-surface">
      <p style={{ color: "#9aa4b2" }}>
        Native surfaces project daemon truth over the Session Execution Binding. Open{" "}
        <Link to="/environments" style={{ color: "#6ab0ff" }}>Environments</Link> to bind a Workbench.
      </p>
    </Surface>
  );
}

// ---- Environments ----

export function EnvironmentsSurface() {
  const [envs, setEnvs] = useState<EnvironmentSummary[]>([]);
  const [busy, setBusy] = useState(false);
  const refresh = useCallback(async () => {
    const r = await client.listEnvironments();
    setEnvs(r.environments ?? []);
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

  return (
    <Surface title="Environments" testid="environments-surface">
      <button onClick={create} disabled={busy} data-testid="create-env" style={{ marginBottom: 12 }}>
        {busy ? "Creating…" : "Create + Start environment"}
      </button>
      <div style={{ display: "grid", gap: 12 }}>
        {envs.map((e) => (
          <div key={e.id} style={{ border: "1px solid #2a2f3a", borderRadius: 8, padding: 12 }} data-testid="env-card">
            <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
              <strong>{e.id}</strong>
              <ReadinessBadge mode={e.status?.readiness?.mode} />
              <span style={{ color: "#9aa4b2" }}>{e.status?.phase}</span>
              <span style={{ flex: 1 }} />
              <Link to={`/workbench/${e.id}`} style={{ color: "#6ab0ff" }} data-testid="open-workbench">Open Workbench</Link>
              <button onClick={() => act(e.id, "stop")}>Stop</button>
              <button onClick={() => act(e.id, "delete")}>Delete</button>
            </div>
            <AuthorityBlockerPanel reasons={e.status?.readiness?.reasons} />
            <div style={{ marginTop: 8 }}><EnvironmentComponentGrid components={e.status?.components} /></div>
          </div>
        ))}
        {envs.length === 0 && <p style={{ color: "#7a818c" }}>No environments yet.</p>}
      </div>
    </Surface>
  );
}

// ---- Providers ----

export function ProvidersSurface() {
  const [providers, setProviders] = useState<ProviderInfo[]>([]);
  const [poolCount, setPoolCount] = useState(0);
  useEffect(() => {
    void client.listProviders().then((r) => setProviders(r.providers ?? []));
    void client.resourcePools().then((r) => setPoolCount(((r as { pools?: unknown[] }).pools ?? []).length));
  }, []);
  return (
    <Surface title="Providers" testid="providers-surface">
      <div style={{ marginBottom: 8 }}><ResourceAllocationBadge pools={poolCount} /></div>
      <div style={{ display: "grid", gap: 8 }}>
        {providers.map((p) => (
          <div key={p.provider_ref} style={{ border: "1px solid #2a2f3a", borderRadius: 8, padding: 10 }} data-testid="provider-card">
            <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
              <strong>{p.provider_ref}</strong>
              <ProviderHealthBadge status={p.status} />
              <span style={{ color: "#7a818c", fontSize: 12 }}>{String((p.capabilities as { locality?: string }).locality ?? "")}</span>
            </div>
            {p.status !== "available" && <div style={{ color: "#7a818c", fontSize: 12 }}>{p.reason}</div>}
          </div>
        ))}
      </div>
    </Surface>
  );
}

// ---- Sessions ----

export function SessionsSurface() {
  const [workRuns, setWorkRuns] = useState<Array<Record<string, unknown>>>([]);
  const [envs, setEnvs] = useState<EnvironmentSummary[]>([]);
  useEffect(() => {
    void client.listWorkRuns().then((r) => setWorkRuns(r.workRuns ?? []));
    void client.listEnvironments().then((r) => setEnvs(r.environments ?? []));
  }, []);
  return (
    <Surface title="Sessions" testid="sessions-surface">
      <p style={{ color: "#9aa4b2" }}>Active environments and their WorkRuns. A session binds an environment + thread + WorkRun.</p>
      <div style={{ display: "grid", gap: 8 }}>
        {envs.map((e) => (
          <div key={e.id} style={{ border: "1px solid #2a2f3a", borderRadius: 8, padding: 10 }} data-testid="session-card">
            <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
              <strong>{e.id}</strong>
              <ReadinessBadge mode={e.status?.readiness?.mode} />
              <span style={{ color: "#9aa4b2" }}>{e.status?.phase}</span>
              <span style={{ flex: 1 }} />
              <Link to={`/workbench/${e.id}`} style={{ color: "#6ab0ff" }}>Workbench</Link>
            </div>
          </div>
        ))}
      </div>
      <h2 style={{ fontSize: 14, color: "#9aa4b2" }}>WorkRuns ({workRuns.length})</h2>
      <ul style={{ fontSize: 12, color: "#7a818c" }}>
        {workRuns.map((w, i) => <li key={String(w.id ?? i)}>{String(w.id)} — {String(w.review_state ?? w.status ?? "")}</li>)}
      </ul>
    </Surface>
  );
}

export function SessionDetailSurface() {
  const { id } = useParams();
  return (
    <Surface title={`Session ${id ?? ""}`} testid="session-detail">
      <Link to={`/workbench/${id ?? ""}`} style={{ color: "#6ab0ff" }}>Open Workbench</Link>
    </Surface>
  );
}

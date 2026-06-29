// Connections cockpit — source-owned React, source-derived from the product-ui serve cockpit.
// Same route anatomy (categories → cards → pills/actions), same visual system; the only change
// is the data boundary: typed daemon clients (connectionsModel.fetchConnections).
import { useEffect, useState } from "react";
import "./Connections.css";
import {
  CATEGORY_ORDER,
  authDescriptor,
  connectHref,
  connectionCategory,
  fetchConnections,
  isBound,
  leaseCount,
  toolsLabel,
  type ConnectionsData,
  type Connector,
} from "./connectionsModel";

function ConnectorCard({ c, leaseN }: { c: Connector; leaseN: number }) {
  const bound = isBound(c);
  const risk = c.org_policy?.risk_posture || "standard";
  return (
    <div className="cx-card" data-testid="connection-card">
      <div className="cx-main">
        <div className="cx-name">
          {c.name || c.service}
          {!bound && <span className="cx-pill cx-warn">needs auth</span>}
          <span className="cx-pill cx-risk">risk: {risk}</span>
        </div>
        <div className="cx-meta">
          {authDescriptor(c)} · <code>{c.base_url || ""}</code> · tools: {toolsLabel(c)}
          {leaseN ? ` · ${leaseN} lease${leaseN > 1 ? "s" : ""} issued` : ""}
        </div>
      </div>
      {bound ? (
        <span className="cx-pill cx-ok">connected</span>
      ) : (
        <a className="cx-act" href={connectHref(c)} target="_blank" rel="noopener" data-testid="connect-action">
          Connect ↗
        </a>
      )}
    </div>
  );
}

export function ConnectionsView() {
  const [data, setData] = useState<ConnectionsData | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    fetchConnections()
      .then((d) => live && setData(d))
      .catch((e) => live && setError(String(e?.message || e)));
    return () => {
      live = false;
    };
  }, []);

  const groups: Record<string, Connector[]> = {};
  for (const c of data?.connectors || []) {
    (groups[connectionCategory(c)] ||= []).push(c);
  }
  const cats = Object.keys(groups).sort(
    (a, b) => CATEGORY_ORDER.indexOf(a as never) - CATEGORY_ORDER.indexOf(b as never),
  );
  const scm = data?.scmConnectors || [];
  const hasAny = cats.length > 0 || scm.length > 0;

  return (
    <div className="cx-wrap">
      <div className="cx-brand">IOI Hypervisor</div>
      <h1 className="cx-h1">Connections</h1>
      <p className="cx-sub">
        Every external capability binding the workspace can use. Agents receive only scoped,
        policy-gated capability leases — the underlying credentials are sealed in the daemon and
        never reach a session.
      </p>

      <div className="cx-add">
        <a href="/__ioi/connections/add?type=mcp">+ MCP server</a>
        <a href="/__ioi/slack/setup">+ Connect Slack</a>
        <a href="/__ioi/connections/add?type=bearer">+ API key / service</a>
      </div>

      {error && <div className="cx-empty" data-testid="connections-error">Daemon unavailable: {error}</div>}
      {!error && data === null && <div className="cx-empty" data-testid="connections-loading">Loading connections…</div>}
      {!error && data !== null && !hasAny && (
        <div className="cx-empty" data-testid="connections-empty">No connections yet — add one above.</div>
      )}

      {!error &&
        data !== null &&
        cats.map((cat) => (
          <section key={cat} data-testid="connection-group">
            <h2 className="cx-h2">{cat}</h2>
            {groups[cat].map((c) => (
              <ConnectorCard key={c.connector_id} c={c} leaseN={leaseCount(data.leases, c.connector_id)} />
            ))}
          </section>
        ))}

      {!error && scm.length > 0 && (
        <section data-testid="connection-group">
          <h2 className="cx-h2">Code / SCM</h2>
          {scm.map((c, i) => {
            const bound = c.auth_posture === "token-lease:bound";
            return (
              <div className="cx-card" key={`${c.name || c.kind}-${i}`} data-testid="connection-card">
                <div className="cx-main">
                  <div className="cx-name">
                    {c.name || c.kind}
                    {!bound && <span className="cx-pill cx-warn">needs auth</span>}
                  </div>
                  <div className="cx-meta">
                    {c.kind} · <code>{c.host || c.remote_url || ""}</code>
                    {c.connected_login ? ` · @${c.connected_login}` : ""}
                  </div>
                </div>
                {bound ? (
                  <span className="cx-pill cx-ok">connected</span>
                ) : (
                  <a
                    className="cx-act cx-ghost"
                    href="/settings/runners?user-settings=git-authentications"
                    target="_blank"
                    rel="noopener"
                  >
                    Git authentications ↗
                  </a>
                )}
              </div>
            );
          })}
        </section>
      )}
    </div>
  );
}

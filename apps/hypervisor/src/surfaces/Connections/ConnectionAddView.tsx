// Add connection surface — source-owned React, source-derived from the product-ui connections
// add form (back link → typed form: MCP server = name + url; bearer/API = name + base_url + tool +
// token). The route is /connections/add?type=mcp|bearer (the dead /__ioi/connections/add alias is
// kept working too). Data boundary: the native daemon connector estate (connectionsModel.
// addMcpConnector / addBearerConnector → POST /v1/hypervisor/connectors [+ /oauth/discover or
// /credential]). The created connector is the daemon's own record — nothing fabricated.
import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { ArrowLeft, Check, KeyRound, Server } from "lucide-react";
import "./Connections.css";
import {
  addBearerConnector,
  addMcpConnector,
  type Connector,
} from "./connectionsModel";

type AddType = "mcp" | "bearer";

function normalizeType(raw: string | null): AddType {
  return raw === "bearer" ? "bearer" : "mcp";
}

export function ConnectionAddView() {
  const [params, setParams] = useSearchParams();
  const type = normalizeType(params.get("type"));

  // MCP fields
  const [mcpName, setMcpName] = useState("");
  const [mcpUrl, setMcpUrl] = useState("");
  // Bearer fields
  const [bName, setBName] = useState("");
  const [bBaseUrl, setBBaseUrl] = useState("");
  const [bTool, setBTool] = useState("");
  const [bToolPath, setBToolPath] = useState("");
  const [bToken, setBToken] = useState("");

  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [created, setCreated] = useState<Connector | null>(null);

  function switchType(next: AddType) {
    setError(null);
    setCreated(null);
    setParams({ type: next }, { replace: true });
  }

  const canSubmit =
    !submitting &&
    (type === "mcp"
      ? mcpName.trim().length > 0 && mcpUrl.trim().length > 0
      : bName.trim().length > 0 &&
        bBaseUrl.trim().length > 0 &&
        bTool.trim().length > 0 &&
        bToken.trim().length > 0);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!canSubmit) return;
    setSubmitting(true);
    setError(null);
    try {
      const connector =
        type === "mcp"
          ? await addMcpConnector({ name: mcpName, url: mcpUrl })
          : await addBearerConnector({
              name: bName,
              baseUrl: bBaseUrl,
              tool: bTool,
              toolPath: bToolPath,
              token: bToken,
            });
      setCreated(connector);
    } catch (err) {
      setError(String((err as Error)?.message || err));
    } finally {
      setSubmitting(false);
    }
  }

  if (created) {
    const bound = created.auth_posture === "token-lease:bound";
    return (
      <div className="cx-wrap" data-testid="connection-add-page">
        <a className="cxa-back" href="/connections" data-testid="connection-add-back">
          <ArrowLeft size={14} /> Connections
        </a>
        <div className="cxa-success" data-testid="connection-add-success">
          <span className="cxa-success-icon" aria-hidden="true">
            <Check size={22} />
          </span>
          <h1 className="cx-h1">Connection added</h1>
          <p className="cx-sub">
            <strong>{created.name || created.service}</strong> is registered in the daemon.
            {type === "mcp"
              ? " Connect it to discover its tools and authorize OAuth."
              : bound
                ? " The token is sealed — agents receive only a scoped lease."
                : " Finish authorizing it from the Connections cockpit."}
          </p>
          <dl className="cxa-receipt" data-testid="connection-add-receipt">
            <div>
              <dt>ID</dt>
              <dd>
                <code>{created.connector_id}</code>
              </dd>
            </div>
            <div>
              <dt>Kind</dt>
              <dd>{created.kind || "—"}</dd>
            </div>
            <div>
              <dt>Endpoint</dt>
              <dd>
                <code>{created.base_url || "—"}</code>
              </dd>
            </div>
            <div>
              <dt>Status</dt>
              <dd>{bound ? "connected" : "needs auth"}</dd>
            </div>
          </dl>
          <a className="cx-act cxa-cta" href="/connections">
            View connections
          </a>
        </div>
      </div>
    );
  }

  return (
    <div className="cx-wrap" data-testid="connection-add-page">
      <a className="cxa-back" href="/connections" data-testid="connection-add-back">
        <ArrowLeft size={14} /> Connections
      </a>
      <h1 className="cx-h1">Add connection</h1>
      <p className="cx-sub">
        Register an external capability binding. Credentials are sealed in the daemon — agents only
        ever receive scoped, policy-gated capability leases.
      </p>

      <div className="cxa-tabs" data-testid="connection-add-tabs" role="tablist">
        <button
          type="button"
          role="tab"
          className={"cxa-tab" + (type === "mcp" ? " is-active" : "")}
          aria-selected={type === "mcp"}
          onClick={() => switchType("mcp")}
          data-testid="connection-add-tab-mcp"
        >
          <Server size={15} /> MCP server
        </button>
        <button
          type="button"
          role="tab"
          className={"cxa-tab" + (type === "bearer" ? " is-active" : "")}
          aria-selected={type === "bearer"}
          onClick={() => switchType("bearer")}
          data-testid="connection-add-tab-bearer"
        >
          <KeyRound size={15} /> API key / service
        </button>
      </div>

      {type === "mcp" ? (
        <form className="cxa-form" onSubmit={submit} data-testid="connection-add-form-mcp">
          <p className="cxa-hint">
            Register an MCP server URL — the daemon auto-discovers its tools and OAuth (Dynamic
            Client Registration) when you connect. No vendor app needed.
          </p>
          <label className="cxa-field">
            <span className="cxa-label">Name</span>
            <input
              className="cxa-input"
              type="text"
              placeholder="e.g. Linear"
              value={mcpName}
              onChange={(e) => setMcpName(e.target.value)}
              data-testid="mcp-name"
            />
          </label>
          <label className="cxa-field">
            <span className="cxa-label">MCP server URL</span>
            <input
              className="cxa-input"
              type="text"
              placeholder="https://mcp.example.com/mcp"
              value={mcpUrl}
              onChange={(e) => setMcpUrl(e.target.value)}
              data-testid="mcp-url"
            />
          </label>
          {error && (
            <div className="cx-empty" data-testid="connection-add-error">
              Couldn’t add: {error}
            </div>
          )}
          <div className="cxa-actions">
            <a className="cxa-cancel" href="/connections">
              Cancel
            </a>
            <button
              type="submit"
              className="cx-act"
              disabled={!canSubmit}
              data-testid="connection-add-submit"
            >
              {submitting ? "Adding…" : "Add & discover"}
            </button>
          </div>
        </form>
      ) : (
        <form className="cxa-form" onSubmit={submit} data-testid="connection-add-form-bearer">
          <p className="cxa-hint">
            A bearer-token HTTP connector. Declare the one tool the agent may call; the token is
            sealed in the daemon and only a scoped lease ever reaches a session.
          </p>
          <label className="cxa-field">
            <span className="cxa-label">Name</span>
            <input
              className="cxa-input"
              type="text"
              placeholder="e.g. Linear API"
              value={bName}
              onChange={(e) => setBName(e.target.value)}
              data-testid="bearer-name"
            />
          </label>
          <label className="cxa-field">
            <span className="cxa-label">Base URL</span>
            <input
              className="cxa-input"
              type="text"
              placeholder="https://api.example.com"
              value={bBaseUrl}
              onChange={(e) => setBBaseUrl(e.target.value)}
              data-testid="bearer-base-url"
            />
          </label>
          <div className="cxa-row">
            <label className="cxa-field">
              <span className="cxa-label">Tool name</span>
              <input
                className="cxa-input"
                type="text"
                placeholder="e.g. create_issue"
                value={bTool}
                onChange={(e) => setBTool(e.target.value)}
                data-testid="bearer-tool"
              />
            </label>
            <label className="cxa-field">
              <span className="cxa-label">
                Tool path <span className="cxa-optional">(optional)</span>
              </span>
              <input
                className="cxa-input"
                type="text"
                placeholder="/v1/issues"
                value={bToolPath}
                onChange={(e) => setBToolPath(e.target.value)}
                data-testid="bearer-tool-path"
              />
            </label>
          </div>
          <label className="cxa-field">
            <span className="cxa-label">API token</span>
            <input
              className="cxa-input"
              type="password"
              placeholder="sealed in the daemon"
              value={bToken}
              onChange={(e) => setBToken(e.target.value)}
              data-testid="bearer-token"
            />
          </label>
          {error && (
            <div className="cx-empty" data-testid="connection-add-error">
              Couldn’t add: {error}
            </div>
          )}
          <div className="cxa-actions">
            <a className="cxa-cancel" href="/connections">
              Cancel
            </a>
            <button
              type="submit"
              className="cx-act"
              disabled={!canSubmit}
              data-testid="connection-add-submit"
            >
              {submitting ? "Sealing…" : "Add + seal token"}
            </button>
          </div>
        </form>
      )}
    </div>
  );
}

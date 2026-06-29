// Settings panes — source-owned React content panes for the Settings shell. Each pane is
// source-derived from the matching product-ui Settings route (table/summary layout, headers,
// empty/loading/error states) with the data boundary on the native daemon (settingsModel).
// Panes whose plane the daemon doesn't own render an honest StubPane ("not yet ported"), never a
// fabricated row.
import { useEffect, useState } from "react";
import { Users, Server, GitBranch, KeyRound, Ticket, Construction } from "lucide-react";
import { Skeleton } from "../../components/Skeleton";
import {
  fetchMetering,
  fmtDate,
  fmtOcu,
  listGitAuths,
  listMembers,
  listRunners,
  listSecrets,
  listTokens,
  type GitAuth,
  type Member,
  type Metering,
  type Runner,
  type SecretRow,
  type TokenRow,
} from "./settingsModel";

function initials(name: string): string {
  const parts = name.trim().split(/\s+/).filter(Boolean);
  if (!parts.length) return "?";
  return (parts[0][0] + (parts[1]?.[0] || "")).toUpperCase();
}

// Generic async-state hook for a list pane: null = loading, [] = empty, error = string.
function useList<T>(fetcher: () => Promise<T[]>, deps: unknown[] = []) {
  const [data, setData] = useState<T[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let live = true;
    setData(null);
    setError(null);
    fetcher()
      .then((d) => live && setData(d))
      .catch((e) => live && setError(String(e?.message || e)));
    return () => {
      live = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  return { data, error };
}

function PaneHead({ title, sub }: { title: string; sub: string }) {
  return (
    <div className="st-pane-head">
      <h1 className="st-h1">{title}</h1>
      <p className="st-sub">{sub}</p>
    </div>
  );
}

// Column width templates so the table skeleton echoes each pane's real columns.
const SKEL_COLS: Record<string, string[]> = {
  members: ["46%", "32%", "44px", "38%"],
  runners: ["48%", "34%", "40%", "44px"],
  gitauth: ["40%", "30%", "38%", "44px"],
  secrets: ["44%", "32%", "30%"],
  tokens: ["40%", "60px", "30%", "30%", "30%"],
};

function StateRows({
  pane,
  error,
  loading,
  shape = "table",
}: {
  pane: string;
  error: string | null;
  loading: boolean;
  shape?: "table" | "cards";
}) {
  if (error)
    return (
      <div className="st-state" data-testid={`${pane}-error`}>
        Daemon unavailable: {error}
      </div>
    );
  if (!loading) return null;
  if (shape === "cards")
    return (
      <div className="st-meter-grid" data-testid={`${pane}-loading`} role="status" aria-label="Loading" aria-busy="true">
        {[0, 1, 2, 3].map((i) => (
          <div className="st-meter-card st-skel-card" key={i} aria-hidden="true">
            <Skeleton w="50%" h={11} r={5} />
            <Skeleton w={84} h={24} className="st-skel-metervalue" />
          </div>
        ))}
      </div>
    );
  const cols = SKEL_COLS[pane] || ["44%", "32%", "30%"];
  return (
    <div className="st-skel-table" data-testid={`${pane}-loading`} role="status" aria-label="Loading" aria-busy="true">
      <div className="st-skel-row st-skel-head" aria-hidden="true">
        {cols.map((w, c) => (
          <Skeleton key={c} w={w} h={10} r={4} />
        ))}
      </div>
      {[0, 1, 2, 3].map((r) => (
        <div className="st-skel-row" key={r} aria-hidden="true">
          {cols.map((w, c) => (
            <Skeleton key={c} w={w} h={13} r={5} />
          ))}
        </div>
      ))}
    </div>
  );
}

// ---------------- Members ----------------
export function MembersPane() {
  const { data, error } = useList<Member>(listMembers);
  const loading = !error && data === null;
  const empty = !error && data !== null && data.length === 0;
  return (
    <div data-testid="settings-pane" data-pane="members">
      <PaneHead title="Members" sub="Everyone with access to this workspace and their role." />
      <div className="st-toolbar">
        <span className="st-pill st-pill-muted">{data ? `${data.length} member${data.length === 1 ? "" : "s"}` : "—"}</span>
        <span className="st-toolbar-spacer" />
        <a className="st-btn st-ghost" href="/settings/members/invite" data-testid="members-invite">
          Invite
        </a>
      </div>
      <StateRows pane="members" error={error} loading={loading} />
      {empty && (
        <div className="st-empty" data-testid="members-empty">
          <span className="st-empty-icon"><Users size={36} strokeWidth={1.3} /></span>
          <h2 className="st-empty-title">No members</h2>
          <p className="st-empty-sub">Invite people to give them access to this workspace.</p>
        </div>
      )}
      {!error && data && data.length > 0 && (
        <table className="st-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Date joined</th>
              <th>Role</th>
              <th>Authenticated with</th>
            </tr>
          </thead>
          <tbody>
            {data.map((m) => (
              <tr key={m.id} data-testid="members-row">
                <td>
                  <div className="st-person">
                    <span className="st-avatar">{initials(m.name)}</span>
                    <div>
                      <div className="st-person-name">{m.name}</div>
                      {m.email && <div className="st-person-email">{m.email}</div>}
                    </div>
                  </div>
                </td>
                <td className="st-cell-muted">{fmtDate(m.joinedAt)}</td>
                <td>
                  <span className={"st-pill " + (m.role === "Admin" ? "st-pill-info" : "st-pill-muted")}>{m.role}</span>
                </td>
                <td className="st-cell-muted">{m.authenticatedWith}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

// ---------------- Runners + Git authentications ----------------
export function RunnersPane() {
  const runners = useList<Runner>(listRunners);
  const gits = useList<GitAuth>(listGitAuths);
  const rLoading = !runners.error && runners.data === null;
  const rEmpty = !runners.error && runners.data !== null && runners.data.length === 0;
  const gLoading = !gits.error && gits.data === null;
  const gEmpty = !gits.error && gits.data !== null && gits.data.length === 0;
  return (
    <div data-testid="settings-pane" data-pane="runners">
      <PaneHead title="Runners" sub="Compute hosts that execute environments and agents, plus the Git authentications environments use to clone." />

      <h2 className="st-section-h2">Runners</h2>
      <StateRows pane="runners" error={runners.error} loading={rLoading} />
      {rEmpty && (
        <div className="st-empty" data-testid="runners-empty">
          <span className="st-empty-icon"><Server size={36} strokeWidth={1.3} /></span>
          <h2 className="st-empty-title">No runners</h2>
          <p className="st-empty-sub">No compute providers are registered.</p>
        </div>
      )}
      {!runners.error && runners.data && runners.data.length > 0 && (
        <table className="st-table">
          <thead>
            <tr>
              <th>Runner</th>
              <th>Isolation</th>
              <th>Locality</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {runners.data.map((r) => (
              <tr key={r.id} data-testid="runner-row">
                <td>
                  <div className="st-cell-strong">{r.id}</div>
                  <div className="st-person-email" title={r.reason}>{r.reason}</div>
                </td>
                <td className="st-cell-muted">{r.isolation}</td>
                <td className="st-cell-muted">{r.locality}{r.remote ? " · remote" : ""}</td>
                <td>
                  <span className={"st-pill " + (r.available ? "st-pill-ok" : "st-pill-warn")}>{r.status}</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <h2 className="st-section-h2" style={{ marginTop: 32 }}>Git authentications</h2>
      <p className="st-sub" style={{ marginBottom: 14 }}>
        Source-control connections used by runners to clone repositories. Credentials are sealed in
        the daemon and never reach a session.
      </p>
      <StateRows pane="gitauth" error={gits.error} loading={gLoading} />
      {gEmpty && (
        <div className="st-empty" data-testid="gitauth-empty">
          <span className="st-empty-icon"><GitBranch size={36} strokeWidth={1.3} /></span>
          <h2 className="st-empty-title">No Git authentications</h2>
          <p className="st-empty-sub">Connect a source-control host to let runners clone private repositories.</p>
        </div>
      )}
      {!gits.error && gits.data && gits.data.length > 0 && (
        <table className="st-table">
          <thead>
            <tr>
              <th>Host</th>
              <th>Kind</th>
              <th>Account</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {gits.data.map((g) => (
              <tr key={g.id} data-testid="gitauth-row">
                <td className="st-cell-mono">{g.host}</td>
                <td className="st-cell-muted">{g.kind}</td>
                <td className="st-cell-muted">{g.login ? `@${g.login}` : "—"}</td>
                <td>
                  <span className={"st-pill " + (g.bound ? "st-pill-ok" : "st-pill-warn")}>
                    {g.bound ? "connected" : "needs auth"}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

// ---------------- Secrets ----------------
export function SecretsPane() {
  const { data, error } = useList<SecretRow>(listSecrets);
  const loading = !error && data === null;
  const empty = !error && data !== null && data.length === 0;
  return (
    <div data-testid="settings-pane" data-pane="secrets">
      <PaneHead title="Secrets" sub="Credentials sealed at rest in the daemon. The value never leaves the daemon — only the name and mount are shown here." />
      <div className="st-toolbar">
        <span className="st-toolbar-spacer" />
        <a className="st-btn st-ghost" href="/__ioi/connections/add?type=bearer" data-testid="secrets-add">
          New secret
        </a>
      </div>
      <StateRows pane="secrets" error={error} loading={loading} />
      {empty && (
        <div className="st-empty" data-testid="secrets-empty">
          <span className="st-empty-icon"><KeyRound size={36} strokeWidth={1.3} /></span>
          <h2 className="st-empty-title">No secrets</h2>
          <p className="st-empty-sub">Add a secret to make a credential available to environments without exposing its value.</p>
        </div>
      )}
      {!error && data && data.length > 0 && (
        <table className="st-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Type</th>
              <th>Created</th>
            </tr>
          </thead>
          <tbody>
            {data.map((s) => (
              <tr key={s.id} data-testid="secret-row">
                <td className="st-cell-strong">{s.name}</td>
                <td className="st-cell-muted">{s.mountType}</td>
                <td className="st-cell-muted">{fmtDate(s.createdAt)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

// ---------------- API access tokens ----------------
export function TokensPane() {
  const { data, error } = useList<TokenRow>(listTokens);
  const loading = !error && data === null;
  const empty = !error && data !== null && data.length === 0;
  return (
    <div data-testid="settings-pane" data-pane="tokens">
      <PaneHead title="API access tokens" sub="Tokens that authenticate inbound API calls on your behalf. The token value is shown once on creation and is never recoverable." />
      <div className="st-toolbar">
        <span className="st-toolbar-spacer" />
        <button className="st-btn st-ghost" type="button" data-testid="tokens-create">
          New token
        </button>
      </div>
      <StateRows pane="tokens" error={error} loading={loading} />
      {empty && (
        <div className="st-empty" data-testid="tokens-empty">
          <span className="st-empty-icon"><Ticket size={36} strokeWidth={1.3} /></span>
          <h2 className="st-empty-title">No API access tokens</h2>
          <p className="st-empty-sub">Create a token to call the API programmatically.</p>
        </div>
      )}
      {!error && data && data.length > 0 && (
        <table className="st-table">
          <thead>
            <tr>
              <th>Description</th>
              <th>Access</th>
              <th>Created</th>
              <th>Expires</th>
              <th>Last used</th>
            </tr>
          </thead>
          <tbody>
            {data.map((t) => (
              <tr key={t.id} data-testid="token-row">
                <td className="st-cell-strong">{t.description}</td>
                <td>
                  <span className={"st-pill " + (t.readOnly ? "st-pill-muted" : "st-pill-info")}>
                    {t.readOnly ? "read-only" : "read-write"}
                  </span>
                </td>
                <td className="st-cell-muted">{fmtDate(t.createdAt)}</td>
                <td className="st-cell-muted">{fmtDate(t.expiresAt)}</td>
                <td className="st-cell-muted">{t.lastUsedAt ? fmtDate(t.lastUsedAt) : "never"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

// ---------------- Metering & Cost ----------------
export function MeteringPane() {
  const [data, setData] = useState<Metering | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let live = true;
    fetchMetering()
      .then((d) => live && setData(d))
      .catch((e) => live && setError(String(e?.message || e)));
    return () => {
      live = false;
    };
  }, []);
  const loading = !error && data === null;
  const pct = data && data.budgetOcu > 0 ? Math.min(100, (data.usedOcu / data.budgetOcu) * 100) : 0;
  return (
    <div data-testid="settings-pane" data-pane="metering">
      <PaneHead title="Metering & Cost" sub="Compute Units (OCU) consumed from real execution receipts, against the wallet-funded budget. Not SaaS billing — the daemon's own economic plane." />
      <StateRows pane="metering" error={error} loading={loading} shape="cards" />
      {!error && data && (
        <>
          <div className="st-meter-grid" data-testid="metering-summary">
            <div className="st-meter-card">
              <div className="st-meter-label">Budget</div>
              <div className="st-meter-value">{fmtOcu(data.budgetOcu)}<span className="st-meter-unit">OCU</span></div>
            </div>
            <div className="st-meter-card">
              <div className="st-meter-label">Used</div>
              <div className="st-meter-value">{fmtOcu(data.usedOcu)}<span className="st-meter-unit">OCU</span></div>
              <div className="st-meter-bar"><div className="st-meter-bar-fill" style={{ width: `${pct}%` }} /></div>
            </div>
            <div className="st-meter-card">
              <div className="st-meter-label">Available</div>
              <div className="st-meter-value">{fmtOcu(data.availableOcu)}<span className="st-meter-unit">OCU</span></div>
            </div>
            <div className="st-meter-card">
              <div className="st-meter-label">Auto-funding</div>
              <div className="st-meter-value" style={{ fontSize: 18 }}>
                <span className={"st-pill " + (data.autoFund ? "st-pill-ok" : "st-pill-muted")}>
                  {data.autoFund ? "enabled" : "disabled"}
                </span>
              </div>
            </div>
          </div>

          <h2 className="st-section-h2">Consumption by category</h2>
          {data.metrics.length === 0 ? (
            <div className="st-state" data-testid="metering-empty">No consumption recorded yet.</div>
          ) : (
            <table className="st-table">
              <thead>
                <tr>
                  <th>Category</th>
                  <th>Total (OCU)</th>
                </tr>
              </thead>
              <tbody>
                {data.metrics.map((m) => (
                  <tr key={m.kind || m.name} data-testid="metering-row">
                    <td className="st-cell-strong">{m.name}</td>
                    <td className="st-cell-mono">{fmtOcu(m.total)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </>
      )}
    </div>
  );
}

// ---------------- Honest placeholder for unported panes ----------------
export function StubPane({ title, sub }: { title: string; sub: string }) {
  return (
    <div data-testid="settings-pane" data-pane="stub">
      <PaneHead title={title} sub={sub} />
      <div className="st-stub" data-testid="settings-stub">
        <span className="st-stub-badge">Not yet ported</span>
        <Construction size={26} color="#6f7280" />
        <h2 className="st-stub-title">This settings pane has not been ported into source yet.</h2>
        <p className="st-stub-sub">
          The source-owned extraction of this pane is in progress. No data is shown here rather than
          fabricating rows — the underlying plane is wired in a later cut.
        </p>
      </div>
    </div>
  );
}

export function NotFoundPane() {
  return (
    <div data-testid="settings-pane" data-pane="notfound">
      <PaneHead title="Settings" sub="" />
      <div className="st-state" data-testid="settings-notfound">
        Unknown settings page. Choose a section from the left.
      </div>
    </div>
  );
}

import { useEffect } from "react";

// API — what this surface is allowed to ask the daemon, in full.
//
// The allowlist is exact-match and GET-only, and it is published here rather than
// described. A route not on it is refused BY NAME rather than passed through, so no
// mutating daemon call is reachable from this surface even by accident.
//
// This page lists the same four reads the server enforces. If it ever listed a fifth,
// the server would still refuse it — the list here is documentation, and the server's
// map is the authority. That asymmetry is deliberate: a surface that could widen its
// own access by editing its own documentation is not an allowlist.

const READS = [
  ["/api/candidate-sources", "/v1/hypervisor/cloud-candidates/candidate-sources", "—"],
  ["/api/candidates", "/v1/hypervisor/cloud-candidates/candidates", "intent_ref"],
  ["/api/placement-advisory", "/v1/hypervisor/cloud-candidates/placement-advisory", "intent_ref"],
  ["/api/venues", "/v1/hypervisor/placement/venues", "—"],
  ["/api/jobs", "/v1/hypervisor/cloud-jobs", "—"],
  ["/api/jobs/:id", "/v1/hypervisor/cloud-jobs/:id", "—"],
  ["/api/budgets", "/v1/hypervisor/resource/budgets", "—"],
];

const WRITES = [
  [
    "/api/jobs",
    "POST /v1/hypervisor/cloud-jobs",
    "Admits a proposal. The daemon's own words: admission authorizes nothing. No provider is touched and nothing is spent.",
  ],
  [
    "/api/jobs/:id/dry-run",
    "POST /v1/hypervisor/cloud-jobs/:id/execute",
    "Runs the placement decision and stops. The proxy sets dry_run itself rather than forwarding it, so no request composed by a client reaches a metered provider operation.",
  ],
];

export default function Api({ announce }) {
  useEffect(() => { announce(`API — ${READS.length} reads on the allowlist, GET only`); }, [announce]);

  return (
    <div className="stack" style={{ gap: "24px" }}>
      <div className="stack" style={{ gap: "9px" }}>
        <h1>API</h1>
        <p className="prose" style={{ fontSize: "16px" }}>
          Everything this surface can ask the daemon, and nothing else. Exact-match,
          GET only. Query parameters not listed are dropped rather than forwarded.
        </p>
      </div>

      <div className="table-scroll">
        <table className="table t-api">
          <caption className="sr-only">The read allowlist this surface is served behind</caption>
          <thead>
            <tr>
              <th scope="col">This surface asks</th>
              <th scope="col">The daemon route it stands for</th>
              <th scope="col">Forwarded query</th>
            </tr>
          </thead>
          <tbody>
            {READS.map(([face, daemon, query]) => (
              <tr key={face} className="trow">
                <th scope="row" className="mono" style={{ fontSize: "13px" }}>{face}</th>
                <td className="mono basis">{daemon}</td>
                <td className="mono">{query}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="stack" style={{ gap: "12px" }}>
        <div className="eyebrow">and the two writes — the whole of them</div>
        {/* This opened "Until the job door was wired this surface exposed no mutating
            route at all" — true, and past tense — and the gate forbidding the surface
            from claiming it performs no writes fired on it anyway. A regex cannot read
            tense. I would rather rewrite one sentence than teach that particular
            assertion to be lenient: it guards the exact claim a reviewer proved false
            once already, in a stub panel, and an assertion with an exception in it is
            an assertion someone will fit their next sentence through. */}
        <p className="prose">
          The job door added this surface's only two writes; before it, every route here
          was a read. The second of them carries the boundary that
          matters: a real execution is a metered provider operation, and the proxy sets
          the dry-run flag itself on every execute instead of forwarding what the caller
          sent. There is no request a client can compose that reaches a provider through
          this surface. A real run is a spend, and a spend needs an explicit owner
          authorization naming amount, venue ceiling, offer hash and teardown.
        </p>
        <div className="table-scroll">
          <table className="table t-api">
            <caption className="sr-only">The two writes this surface exposes</caption>
            <thead>
              <tr>
                <th scope="col">This surface accepts</th>
                <th scope="col">The daemon route it stands for</th>
                <th scope="col">What it does</th>
              </tr>
            </thead>
            <tbody>
              {WRITES.map(([face, daemon, what]) => (
                <tr key={face} className="trow">
                  <th scope="row" className="mono" style={{ fontSize: "13px" }}>POST {face}</th>
                  <td className="mono basis">{daemon}</td>
                  <td className="basis">{what}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="meta">
          No PUT, no PATCH, no DELETE, on any path. A POST to anything not in this table
          is refused by name: <span className="mono">write_not_on_allowlist</span>.
        </p>
      </div>

      <div className="stack" style={{ gap: "9px" }}>
        <div className="eyebrow">what this surface owns</div>
        <p className="prose">
          Nothing. No database, no session plane, no credential vault, no provider
          integration, no placement scorer, no receipt format. Every number rendered
          here was returned by the daemon on this request; nothing is cached as truth,
          seeded, or fixtured.
        </p>
        <p className="prose">
          The one thing held between reads is the LAST ANSWER, shown dimmed and dated
          while a newer read is in flight — because a page that blanks itself to refetch
          teaches its reader that an empty table means "loading", and here an empty
          table has to keep meaning "no live price".
        </p>
      </div>
    </div>
  );
}

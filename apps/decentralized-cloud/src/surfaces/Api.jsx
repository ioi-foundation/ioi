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
        <table className="quotes">
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

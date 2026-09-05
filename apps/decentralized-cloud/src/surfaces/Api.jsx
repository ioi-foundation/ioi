import { useEffect } from "react";

// API — what this surface is allowed to ask the daemon, in full.
//
// The allowlist is exact-match and GET-only, and it is published here rather than
// described. A route not on it is refused BY NAME rather than passed through, so no
// mutating daemon call is reachable from this surface even by accident.
//
// THIS PAGE USED TO HAND-COPY THE LIST. It introduced seven rows as "the same four
// reads the server enforces" — a count that had been true two routes earlier, sitting
// directly above the rows disproving it. The proxy's own 404 body told callers the same
// wrong number, and the header chip counted the writes by hand.
//
// The rows and the proxy's dispatch are now the SAME table, imported. This page cannot
// list a route the server does not serve, cannot miss one it does, and cannot miscount
// what it lists — the counts in the prose below are generated from the rows.
//
// The asymmetry the old comment claimed is now real rather than asserted: this file
// cannot widen the surface's access by editing itself, because it no longer holds a
// list at all. It renders one.

import { readRoutes, writeRoutes, capabilitySentences } from "../logic/capability.mjs";

const SENTENCES = capabilitySentences();
const READS = readRoutes();
const WRITES = writeRoutes();

export default function Api({ announce }) {
  useEffect(() => { announce(`API — ${SENTENCES.readAllowlist}`); }, [announce]);

  return (
    <div className="stack" style={{ gap: "24px" }}>
      <div className="stack" style={{ gap: "9px" }}>
        <h1>API</h1>
        <p className="prose" style={{ fontSize: "16px" }}>
          {SENTENCES.whatItDoes} Exact-match, GET only for the reads. Query parameters
          not listed are dropped rather than forwarded.
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
            {READS.map((r) => (
              <tr key={r.face} className="trow">
                <th scope="row" className="mono" style={{ fontSize: "13px" }}>{r.face}</th>
                <td className="mono basis">{r.daemon || "answered by this surface — never leaves the process"}</td>
                <td className="mono">{r.query.length ? r.query.join(", ") : "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="stack" style={{ gap: "12px" }}>
        <div className="eyebrow">and the {SENTENCES.writePhrase} — the whole of them</div>
        {/* This opened "Until the job door was wired this surface exposed no mutating
            route at all" — true, and past tense — and the gate forbidding the surface
            from claiming it performs no writes fired on it anyway. A regex cannot read
            tense. I would rather rewrite one sentence than teach that particular
            assertion to be lenient: it guards the exact claim a reviewer proved false
            once already, in a stub panel, and an assertion with an exception in it is
            an assertion someone will fit their next sentence through. */}
        <p className="prose">
          The job door added this surface&rsquo;s {SENTENCES.writePhrase}, and{" "}
          {SENTENCES.spendClause}. The second of
          them carries the boundary that matters: a real execution is a metered provider
          operation, and the proxy sets the dry-run flag itself on every execute instead
          of forwarding what the caller sent. There is no request a client can compose
          that reaches a provider through this surface. A real run is a spend, and a
          spend needs an explicit owner authorization naming amount, venue ceiling,
          offer hash and teardown.
        </p>
        <div className="table-scroll">
          <table className="table t-api">
            <caption className="sr-only">The {SENTENCES.writePhrase} this surface exposes</caption>
            <thead>
              <tr>
                <th scope="col">This surface accepts</th>
                <th scope="col">The daemon route it stands for</th>
                <th scope="col">What it does</th>
              </tr>
            </thead>
            <tbody>
              {WRITES.map((r) => (
                <tr key={r.face} className="trow">
                  <th scope="row" className="mono" style={{ fontSize: "13px" }}>{r.method} {r.face}</th>
                  <td className="mono basis">{r.method} {r.daemon}</td>
                  <td className="basis">{r.does}</td>
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

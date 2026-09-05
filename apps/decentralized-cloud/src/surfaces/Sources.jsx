import { useEffect } from "react";
import { useSurfaceRead } from "../useSurfaceRead.js";
import { clock } from "../logic/classify.mjs";
import { Chip, Waiting, Failure, Kept } from "../components/Bits.jsx";

// SOURCES — the surface stale-while-refresh was built for.
//
// Source reads have been measured at 31s, 56s, 60s, 61s and one 504 at 75.003s. Long
// enough that a reader who clicks away and back would otherwise pay the whole cost
// twice and stare at nothing meanwhile. The cache lives outside React state precisely
// so it survives this component unmounting, which is the case it exists for.

export default function Sources({ announce }) {
  const state = useSurfaceRead("sources", "/api/candidate-sources");
  const body = state.data;

  const sources = Array.isArray(body?.sources) ? body.sources : [];
  const quoting = sources.filter((s) => s.state === "live_quote_source");
  const absent = sources.filter((s) => s.state === "candidate_source_unavailable");
  const answering = sources.filter((s) => !quoting.includes(s) && !absent.includes(s));

  useEffect(() => {
    if (state.phase === "first") return;
    announce(`Sources — ${quoting.length} quoting, ${absent.length} unavailable`);
  }, [state.phase, quoting.length, absent.length, announce]);

  if (state.phase === "first") return <Waiting what="source health" />;

  // THE ROW SHOWS THE EVIDENCE THE DAEMON ALREADY SENT. It used to render
  // `s.reason || s.coverage || s.rule` and stop there, so vast came back with
  // http_status 200 and offers_seen 24, runpod with an http_status and a named API
  // error, and NEITHER reached the screen — under a subtitle promising that "a source
  // without an adapter or without a credential says so in the row where a price would
  // have been." A reviewer asked whose fault runpod's absence was and could not tell.
  // The daemon had already said.
  const row = (s) => (
    <tr key={s.provider_kind || s.source_ref} className="trow">
      <th scope="row" className="stack" style={{ gap: "7px" }}>
        <div className="mono" style={{ fontSize: "14px" }}>{s.provider_kind || s.source_ref || "—"}</div>
        <Chip kind={s.state === "live_quote_source" ? "live" : s.state === "candidate_source_unavailable" ? "absent" : "muted"}>
          {s.state || "state absent"}
        </Chip>
      </th>
      <td className="mono basis">
        {[
          s.reason,
          s.coverage,
          s.rule,
          s.http_status != null ? `http_status ${s.http_status}` : null,
          s.offers_seen != null ? `offers_seen ${s.offers_seen}` : null,
          s.error || s.error_code || null,
        ]
          .filter(Boolean)
          .map((line, i) => <div key={i}>{line}</div>)}
        {/* `state` is LAST PERSISTED and can lag a fixed adapter, so the row shows the
            observation's own timestamp beside it rather than implying the state is
            current. A fixed adapter reports broken until a refresh runs. */}
        <div className="meta">observed {clock(s.observed_at || body?.at)}</div>
      </td>
    </tr>
  );

  const view = (
    <div className="stack" style={{ gap: "18px" }}>
      <h1>Sources</h1>
      <p className="meta">
        {quoting.length} quoting · {answering.length} answering without a price ·{" "}
        {absent.length} unavailable · read in {state.ms != null ? `${(state.ms / 1000).toFixed(1)}s` : "—"}
      </p>
      <p className="prose">
        A source without an adapter or without a credential says so in the row where a
        price would have been. Nothing here is inferred: every line is a field the
        daemon returned for that source.
      </p>
      <div className="table-scroll">
        <table className="quotes">
          <caption className="sr-only">Candidate sources and the state the daemon last persisted for each</caption>
          <thead>
            <tr>
              <th scope="col">Source</th>
              <th scope="col">What the daemon said</th>
            </tr>
          </thead>
          <tbody>{[...quoting, ...answering, ...absent].map(row)}</tbody>
        </table>
      </div>
      {sources.length === 0 && (
        <p className="prose">The daemon returned no sources for this read.</p>
      )}
    </div>
  );

  if (state.phase === "failed") {
    return (
      <div className="stack" style={{ gap: "16px" }}>
        <Failure result={state.failure} />
        {state.data && <Kept at={state.at}>{view}</Kept>}
      </div>
    );
  }
  return state.stale ? <Kept at={state.at}>{view}</Kept> : view;
}

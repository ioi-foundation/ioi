import { useEffect, useState } from "react";
import { useSurfaceRead } from "../useSurfaceRead.js";
import { stamp, duration } from "../logic/classify.mjs";
import { Chip, Waiting, Failure, Kept, breakable } from "../components/Bits.jsx";

// SOURCES — the surface stale-while-refresh was built for.
//
// Source reads have been measured at 31s, 56s, 60s, 61s and one 504 at 75.003s. Long
// enough that a reader who clicks away and back would otherwise pay the whole cost
// twice and stare at nothing meanwhile. The cache lives outside React state precisely
// so it survives this component unmounting, which is the case it exists for.

export default function Sources({ announce }) {
  const state = useSurfaceRead("sources", "/api/candidate-sources");
  // Which set the ledger shows; "all" until a tile is pressed.
  const [filter, setFilter] = useState("all");
  const body = state.data;

  const sources = Array.isArray(body?.sources) ? body.sources : [];
  const quoting = sources.filter((s) => s.state === "live_quote_source");
  const absent = sources.filter((s) => s.state === "candidate_source_unavailable");
  const answering = sources.filter((s) => !quoting.includes(s) && !absent.includes(s));

  useEffect(() => {
    if (state.phase === "first") return;
    // A failed read with nothing kept announces the failure, not a row of zeros: a
    // daemon-down capture caught "0 quoting, 0 unavailable" being read out as a count.
    if (state.phase === "failed" && !state.data) { announce("Sources & health — the daemon did not answer; nothing to count"); return; }
    announce(`Sources — ${quoting.length} quoting, ${absent.length} unavailable`);
  }, [state.phase, state.data, quoting.length, absent.length, announce]);

  if (state.phase === "first") return (
    <Waiting
      what="source health"
      title="Sources &amp; health"
      willShow={
        "This page lists every place a price can come from: each venue's endpoint, " +
        "whether it answered, how many offers it returned, and the daemon's own words " +
        "for why it did not. It is how you check that a price on Candidates came from " +
        "somewhere real."
      }
      why="Each source is asked in turn, and a full round has been measured at 27 to 61 seconds."
    />
  );

  // THE ROW SHOWS THE EVIDENCE THE DAEMON ALREADY SENT. It used to render
  // `s.reason || s.coverage || s.rule` and stop there, so vast came back with
  // http_status 200 and offers_seen 24, runpod with an http_status and a named API
  // error, and NEITHER reached the screen — under a subtitle promising that "a source
  // without an adapter or without a credential says so in the row where a price would
  // have been." A reviewer asked whose fault runpod's absence was and could not tell.
  // The daemon had already said.
  // THE FIELDS ARE READ FROM A LIVE BODY, not from what I assumed they were called.
  //
  // My port read `provider_kind`, `source_ref`, `reason`, `rule`, `http_status`,
  // `offers_seen`. The daemon sends `source`, `coverage`, `state` and an `evidence`
  // OBJECT. None of the names I used exist, so every one of the thirteen rows rendered
  // "—" in the Source column and dropped nearly all of the evidence — on the surface
  // whose subtitle promises it shows the evidence the daemon already sent.
  //
  // That is the same defect the vanilla surface was fixed for, reintroduced by me
  // porting the render without checking the field names against a real response. The
  // name of a field is a fact about the daemon, and I guessed it.
  //
  // `evidence` is rendered by walking whatever keys it actually carries rather than by
  // naming them here, so a daemon that starts sending a new one shows it instead of
  // silently dropping it — which is the failure mode this row already had once.
  const evidenceLines = (s) => {
    const out = [];
    if (s.coverage) out.push(s.coverage);
    const ev = s.evidence && typeof s.evidence === "object" ? s.evidence : null;
    if (ev) {
      for (const [k, v] of Object.entries(ev)) {
        if (v === null || v === undefined || v === "") continue;
        out.push(k === "basis" ? String(v) : `${k} ${typeof v === "object" ? JSON.stringify(v) : v}`);
      }
    }
    return out;
  };

  const row = (s) => (
    <tr key={s.source || s.state} className="trow">
      <th scope="row" className="stack" style={{ gap: "7px" }}>
        <div className="mono" style={{ fontSize: "14px" }}>{breakable(s.source || "source not named by the daemon")}</div>
        <Chip kind={s.state === "live_quote_source" ? "live" : s.state === "candidate_source_unavailable" ? "absent" : "muted"}>
          {s.state || "state absent"}
        </Chip>
      </th>
      <td className="mono src-evidence">
        {evidenceLines(s).length > 0
          ? evidenceLines(s).map((line, i) => <div key={i}>{line}</div>)
          : <span className="meta">the daemon returned no evidence for this source</span>}
        {/* `state` is LAST PERSISTED and can lag a fixed adapter, so the row shows the
            observation's own timestamp beside it rather than implying the state is
            current. A fixed adapter reports broken until a refresh runs. */}
        <div className="meta">observed {stamp(s.observed_at || body?.at)}</div>
      </td>
    </tr>
  );

  // THE HEALTH PANEL. A console's health page opens on the counts, each a tile that
  // names its set in the daemon's own state word and filters the ledger beneath when
  // pressed. The counts are the same three sets the population line publishes; the
  // tiles are BUTTONS with aria-pressed, so a keyboard reader can narrow the ledger
  // and a screen reader is told which filter holds. Green is the quoting tile only,
  // because green is live evidence; the other two are grey and dashed grey, the
  // absence device the chips already wear.
  const shown = filter === "quoting" ? quoting : filter === "answering" ? answering : filter === "absent" ? absent : [...quoting, ...answering, ...absent];
  const tile = (key, kind, n, label, word) => (
    <button
      type="button"
      className={`health-tile health-${kind}${filter === key ? " is-on" : ""}`}
      aria-pressed={filter === key}
      onClick={() => setFilter(filter === key ? "all" : key)}
    >
      <span className="health-n">{n}</span>
      <span className="health-label">{label}</span>
      <span className="health-word mono">{word}</span>
    </button>
  );

  const view = (
    <div className="stack" style={{ gap: "18px" }}>
      <h1>Sources &amp; health</h1>
      <p className="meta">
        {sources.length} sources asked · read at {stamp(state.at)} in {duration(state.ms)} · GET /api/candidate-sources
      </p>
      <div className="health-strip" role="group" aria-label="Source health — press a tile to filter the ledger">
        {tile("quoting", "live", quoting.length, "quoting live prices", "live_quote_source")}
        {tile("answering", "muted", answering.length, "answering, no price", "available · credential_preflight_only · storage_backends_engaged")}
        {tile("absent", "absent", absent.length, "unavailable, by name", "candidate_source_unavailable")}
      </div>
      <p className="prose">
        A source without an adapter or without a credential says so in the row where a
        price would have been. Nothing here is inferred: every line is a field the
        daemon returned for that source, and <span className="mono">state</span> is
        what the daemon last persisted — a fixed adapter reports unavailable until a
        refresh runs.
      </p>
      <p className="meta" aria-live="polite">
        {filter === "all" ? `showing all ${shown.length}` : `showing ${shown.length} of ${sources.length} — ${filter === "absent" ? "unavailable" : filter}`}
        {filter !== "all" && (
          <>
            {" · "}
            <button type="button" className="linklike" onClick={() => setFilter("all")}>show all</button>
          </>
        )}
      </p>
      <div className="table-scroll">
        <table className="table t-sources">
          <caption className="sr-only">Candidate sources and the state the daemon last persisted for each</caption>
          <thead>
            <tr>
              <th scope="col">Source</th>
              <th scope="col">What the daemon said</th>
            </tr>
          </thead>
          <tbody>{shown.map(row)}</tbody>
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

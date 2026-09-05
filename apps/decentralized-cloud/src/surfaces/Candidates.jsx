import { useEffect } from "react";
import { useSurfaceRead } from "../useSurfaceRead.js";
import { intentRef, keptState } from "../logic/read.mjs";
import { classify, stamp } from "../logic/classify.mjs";
import { latestBatch, summarise, venueVerdict } from "../logic/batches.mjs";
import { populationLine, FUNNEL_NOTE } from "../logic/population.mjs";
import { Chip, Waiting, Failure, Kept } from "../components/Bits.jsx";
import Freshness from "../components/Freshness.jsx";

const POLL_MS = 30_000;

// PRICES CARRY THEIR UNIT AND THEIR CURRENCY, always, in the cell. A scripted edit
// once ate the `$` from two price cells and every check stayed green: node --check
// passed, the gate passed, table semantics measured correct, overflow measured zero.
// The number rendered as "0.0136" and nothing on the surface could tell you whether
// that was dollars, cents, or an hour of nothing.
const price = (usdPerHour) => `$${usdPerHour.toFixed(4)}`;

export default function Candidates({ announce }) {
  // LATEST BATCH, SERVER-SIDE. The daemon gained `?latest=true`, which returns the
  // newest sweep only with a `selection` block saying how many exist.
  //
  // This retires three separate problems at once, all of which were consequences of the
  // face asking for everything and throwing most of it away:
  //   - 13.6 MB became 191 KB, so this surface can keep its answer across a reload like
  //     every other one, and the "too large for this browser to keep" apology goes.
  //   - the read went from 27-39 seconds to about one.
  //   - `considered` now comes from the daemon rather than being inferred here, so the
  //     count on this page and the count on Placement have ONE source. Five cold
  //     readers could not reconcile them; they were two derivations of one population.
  const state = useSurfaceRead(
    "candidates",
    `/api/candidates?intent_ref=${encodeURIComponent(intentRef())}&latest=true`,
    { pollMs: POLL_MS }
  );

  const body = state.data;
  // The body IS the latest batch now. `latestBatch` still runs — it is the one rule for
  // "which sweep is newest" and a second one here would be a second spine — but with a
  // single batch in the body it is an identity, and the set-aside count comes from the
  // daemon's own selection block instead of from what this page happened to be sent.
  const { latest, batchCount } = latestBatch(body?.candidates);
  const selection = body?.selection || null;
  const considered = typeof selection?.considered === "number" ? selection.considered : null;
  const setAside = considered !== null ? considered - latest.items.length : 0;
  const { live, venues, cheapest } = summarise(latest.items);
  const verdict = venueVerdict({ live, venues });
  // Venue groups, in the order of each venue's cheapest quote. `live` is already price
  // ascending, so the first item seen for a venue IS its cheapest and the groups fall
  // into cheapest-first order by the order venues first appear — one sort, no second
  // derivation of "cheapest".
  const groups = [];
  for (const c of live) {
    const v = c.provider_kind || "—";
    let g = groups.find((x) => x.venue === v);
    if (!g) { g = { venue: v, items: [] }; groups.push(g); }
    g.items.push(c);
  }

  useEffect(() => {
    if (state.phase === "first") return;
    announce(`Candidates — ${verdict.heading}`);
  }, [state.phase, verdict.heading, announce]);

  if (state.phase === "first") return (
    <Waiting
      what="candidates"
      title="Candidates"
      willShow={
        "This page lists the live rental prices the daemon holds for one intent, " +
        "cheapest first: which venue quoted, what the price is per hour, the quote it " +
        "came from, and how long that quote is still good for."
      }
      why="A full sweep asks every live venue in turn and has been measured at 27 to 39 seconds."
    />
  );

  const table = (
    <div className="table-scroll">
      {/* A REAL TABLE. This was four <div>s per row with a grid layout, and a review
          found `document.querySelectorAll("table").length = 0` and `th = 0` on all
          five static surfaces: "$0.0136" had no programmatic association with "PER
          HOUR" or with the `vast` row it belonged to. That is the single most
          important datum on the surface, and to a screen reader it was a loose number
          in a stack of loose numbers.

          The header stays a header at every width. Narrow screens scroll the table
          inside its own container rather than restyling it into blocks, because
          changing `display` on table elements strips their implicit roles — the fix
          would have removed the semantics it was added to provide. */}
      {/* GROUPED BY VENUE, PRICE FIRST.
          One table, one <tbody> per venue, so the semantics hold (every row keeps its
          column; the group header is a row-group header) while a reader sees the shape
          a cold reader asked for: which venues, how many each, cheapest of each, and
          the price as the column the eye lands on. Groups are ordered by their cheapest
          quote and rows inside each by price, so the first data row of the first group
          is the headline's cheapest — the gate's "headline equals row one" holds by
          construction, as before.
          The per-row live_evidence chip is gone: every row in this table passed the
          live rule, so the chip belongs in the header, not forty-three times down the
          left edge ("five identical badges stacked down the left edge, all saying the
          same thing" — reader on the direction canvases). */}
      <table className="table t-quotes">
        <caption className="sr-only">
          Live quotes for this intent, from the most recent sweep, grouped by venue, cheapest first within each
        </caption>
        <thead>
          <tr>
            {/* The order is STATED where the reader is looking, rather than left to be
                inferred from the numbers. A sorted table that does not say it is
                sorted asks every reader to verify it by eye. */}
            <th scope="col">USD / hour <span className="meta">· cheapest first</span></th>
            <th scope="col">Offer</th>
            <th scope="col">Basis</th>
            <th scope="col">Good for</th>
          </tr>
        </thead>
        {groups.map((g) => (
          <tbody key={g.venue} className="tgroup">
            <tr className="tgroup-head">
              <th scope="rowgroup" colSpan={4}>
                <span className="tgroup-venue">{g.venue}</span>
                <span className="tgroup-count">{g.items.length} live</span>
                <span className="tgroup-cheapest mono">cheapest {price(g.items[0].quote.usd_per_hour)}/hr</span>
                <Chip kind="live">live_evidence</Chip>
              </th>
            </tr>
            {g.items.map((c) => (
              <tr key={c.candidate_ref || `${c.provider_kind}-${c.observed_at}`} className="trow">
                <th className="mono price" scope="row">{price(c.quote.usd_per_hour)}</th>
                <td className="offer">
                  <div className="offer-name">{c.display_name || c.provider_kind || "—"}</div>
                  {/* The daemon's region is "<city>, <country>" and some offers carry
                      an empty city, arriving as ", CN". The leading separator is
                      dropped — nothing is added — because ", CN" in a cell reads as a
                      rendering fault rather than as an offer with no city. */}
                  {c.region && <div className="meta">{String(c.region).replace(/^\s*,\s*/, "")}</div>}
                </td>
                <td className="mono basis">
                  {c.quote.basis}
                  <br />
                  {c.quote.quote_ref || ""}
                  <br />
                  {/* DATED, not just clocked. A cold reader noted `04:31:49Z` has no
                      date — and a quote's age is the whole question on this surface, so
                      a bare time is the one format it cannot use. */}
                  {`observed ${stamp(c.observed_at)}`}
                </td>
                <td className="freshness">
                  {/* THE DEPLETING BAR, replacing the ring three independent readers read
                      as a loading spinner. Same arithmetic (classify.dialFraction), now
                      with a readable time beside it. */}
                  <Freshness observedAt={c.observed_at} expiresAt={c.expires_at} size="row" />
                </td>
              </tr>
            ))}
          </tbody>
        ))}
      </table>
    </div>
  );

  const board = (
    <div className="stack" style={{ gap: "18px" }}>
      <h1>Candidates</h1>
      {/* THE POPULATION LINE, from the one derivation every counting surface uses.
          Four cold readers could not reconcile 45 live here against 4,514 considered on
          Placement and 13 sources on Sources — all three correct, all three counting
          different sets, with nothing naming the sets. Three true numbers with no
          stated relationship read as three claims that cannot all be true. */}
      <p className="meta">
        {populationLine({
          live: live.length,
          venues: venues.length,
          batch: latest.items.length,
          // The daemon's own number, so this page and Placement cannot disagree.
          held: considered,
        })}
        {cheapest ? ` · cheapest ${price(cheapest.quote.usd_per_hour)}/hr` : ""}
      </p>
      <p className="meta">{FUNNEL_NOTE}</p>

      <div className={`panel flag stack`} style={{ gap: "9px" }}>
        <h2>{verdict.heading}</h2>
        <p className="prose">{verdict.body}</p>
      </div>

      {live.length > 0 && table}

      {live.length === 0 && (
        <p className="prose">
          No candidate in the most recent sweep meets the live rule, and no price has
          been invented to fill the gap. An empty table here means "no live price" and
          is never allowed to also mean "loading".
        </p>
      )}

      {/* WHY THIS SURFACE ALONE FORGETS. Every other read-backed surface keeps its
          last answer across a reload and shows it, dated, while it refreshes. This one
          cannot: a full sweep for this intent measures about 13 MB, well past what a
          browser will store. Without this line a reader sees Sources and Receipts
          remember and Candidates forget, with nothing to explain the difference, and
          reasonably concludes the page is unreliable. */}
      {/* RETIRED, and worth recording why. This surface used to say "starts empty on
          every visit; its last answer is too large for this browser to keep", which was
          true and which a cold reader correctly read as an apology for an
          implementation constraint — and which CONTRADICTED the API surface's flat
          claim that the last answer is always kept. Two surfaces of one product stating
          opposite caching behaviour.
          The fix was not to reword either sentence. It was `?latest=true`: the face now
          asks for the sweep it renders instead of asking for everything and discarding
          it, so the body is 191 KB, it persists like every other surface, and neither
          sentence needs to exist. The condition is left here as a guard — if a body
          ever grows past the cap again, the reader is told rather than left to notice
          a surface that forgets. */}
      {keptState("candidates") === "too_large" && (
        <p className="meta">
          This surface could not keep its last answer: the daemon returned more than this
          browser will store, so there is nothing to show while the next read runs. Every
          other surface keeps theirs.
        </p>
      )}

      {/* The set-aside count is stated rather than silently dropped. A long-lived
          intent accumulates every sweep ever run against it; showing a fresh quote
          beside a fortnight-old one would make this a place where prices go to be
          misread. */}
      {setAside > 0 && (
        <p className="meta">
          Reading the most recent sweep only: {setAside} older observation
          {setAside === 1 ? "" : "s"} from {batchCount - 1} earlier batch
          {batchCount - 1 === 1 ? "" : "es"} set aside, not mixed in.
        </p>
      )}

      {/* Every candidate the live rule REFUSED, with the clause that refused it.
          A surface that silently drops what it will not count teaches nobody why. */}
      {latest.items.length > live.length && (
        <details className="stack" style={{ gap: "8px" }}>
          <summary className="meta">
            {latest.items.length - live.length} candidate
            {latest.items.length - live.length === 1 ? "" : "s"} in this sweep are not
            live, and why
          </summary>
          <ul className="reasons">
            {latest.items
              .filter((c) => !classify(c).live)
              .map((c, i) => (
                <li key={c.candidate_ref || i} className="mono">
                  {c.provider_kind || "—"} — {classify(c).reason}
                </li>
              ))}
          </ul>
        </details>
      )}
    </div>
  );

  // A failed refresh does not erase a good earlier reading; the failure is shown
  // ABOVE it, because "the last answer, and why we could not get a newer one" is more
  // useful than either alone.
  if (state.phase === "failed") {
    return (
      <div className="stack" style={{ gap: "16px" }}>
        <Failure result={state.failure} />
        {state.data && <Kept at={state.at}>{board}</Kept>}
      </div>
    );
  }

  return state.stale ? <Kept at={state.at}>{board}</Kept> : board;
}

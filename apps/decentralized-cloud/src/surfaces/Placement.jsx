import { useEffect } from "react";
import { useSurfaceRead } from "../useSurfaceRead.js";
import { intentRef } from "../logic/read.mjs";
import { stamp } from "../logic/classify.mjs";
import { Waiting, Failure, Kept, Chip } from "../components/Bits.jsx";

// PLACEMENT — an ADVISORY, and the word is load-bearing.
//
// This surface renders what the daemon's placement advisory returned. It does not
// score, rank or choose: the picker lives in the daemon, and a second scorer on the
// face would be a second spine — the estate's one structural law — and would be the
// mechanism by which a surface eventually disagreed with the receipt it points at.
//
// This surface was once 13.66 MB of text, which is why the live region no longer
// reads the document. It is now a summary and the evidence behind it.

export default function Placement({ announce }) {
  const state = useSurfaceRead(
    "placement",
    `/api/placement-advisory?intent_ref=${encodeURIComponent(intentRef())}`
  );
  // THE FIELD NAMES ARE THE DAEMON'S, and this surface had them wrong from the start.
  //
  // It read `body.decision`, and `body.considered` as an array. The daemon sends
  // `recommendation` — carrying a venue, a display name, a candidate ref and an array
  // of reason codes — with `considered` and `eligible` as COUNTS (3750 and 47), plus
  // `effective_venue`, `routing_fee_basis` and its own `authority_note`.
  //
  // So this page rendered "The daemon returned no advisory for this intent. Nothing has
  // been chosen here to fill the gap." while the daemon was returning a complete
  // advisory with a named recommendation. A blind reviewer scored the surface as 900px
  // of honest emptiness. It was not honest, it was WRONG, and it read as honest because
  // the empty state had been written so carefully.
  //
  // This is the Sources defect exactly — a renderer ported against guessed field names
  // — and the field contract did not catch it because every path on this route was
  // declared OPTIONAL, so absence was permitted for all of them. A contract in which
  // everything is optional cannot fail.
  const body = state.data;
  const rec = body?.recommendation || null;
  const reasonCodes = Array.isArray(rec?.reason_codes) ? rec.reason_codes : [];
  const consideredCount = typeof body?.considered === "number" ? body.considered : null;
  const eligibleCount = typeof body?.eligible === "number" ? body.eligible : null;

  useEffect(() => {
    if (state.phase === "first") return;
    announce(`Placement — ${rec ? `advisory recommends ${rec.venue}` : "no advisory"}`);
  }, [state.phase, rec, announce]);

  if (state.phase === "first") return <Waiting what="a placement advisory" title="Placement" />;

  const view = (
    <div className="stack" style={{ gap: "18px" }}>
      <h1>Placement</h1>
      <p className="meta">advisory · read in {state.ms != null ? `${(state.ms / 1000).toFixed(1)}s` : "—"}</p>
      <p className="prose">
        An advisory, not a decision. The venue picker runs in the daemon; this surface
        renders what it returned and scores nothing of its own. A ranking computed here
        could disagree with the receipt it claims to explain, and there would be no way
        to tell which was wrong.
      </p>

      {rec ? (
        <div className="table-scroll">
          {/* THE DECISION TABLE. The recommendation is row one, and every fact the
              advisory carries is a cell rather than a clause — because this surface
              failed the paragraph test outright: strip the prose and nothing remained
              but the word "advisory" and a read time. */}
          <table className="table t-decision">
            <caption className="sr-only">
              The daemon's placement advisory: what it recommends, on what evidence, and
              what it explicitly cannot do
            </caption>
            <thead>
              <tr>
                <th scope="col">What</th>
                <th scope="col">The daemon&rsquo;s answer</th>
              </tr>
            </thead>
            <tbody>
              <tr className="trow">
                <th scope="row">Recommends</th>
                <td className="stack" style={{ gap: "6px" }}>
                  <div className="mono" style={{ fontSize: "15px" }}>{rec.venue || "—"}</div>
                  {rec.display_name && <div className="meta">{rec.display_name}</div>}
                  <div className="meta mono" style={{ fontSize: "11px" }}>{rec.candidate_ref || ""}</div>
                </td>
              </tr>
              <tr className="trow">
                <th scope="row">Why</th>
                <td>
                  {/* REASON CODES AS CHIPS, verbatim from the daemon. These are the
                      daemon's own vocabulary and are not paraphrased here — a
                      paraphrased reason code is a reason code you cannot look up. */}
                  {reasonCodes.length > 0 ? (
                    <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
                      {reasonCodes.map((c) => <span key={c} className="chip muted">{c}</span>)}
                    </div>
                  ) : <span className="meta">the advisory carried no reason codes</span>}
                </td>
              </tr>
              <tr className="trow">
                <th scope="row">Out of how many</th>
                <td>
                  {eligibleCount !== null && consideredCount !== null
                    ? <span><strong>{eligibleCount}</strong> eligible, out of {consideredCount} considered</span>
                    : <span className="meta">the advisory did not say</span>}
                </td>
              </tr>
              <tr className="trow">
                <th scope="row">Fee</th>
                <td className="stack" style={{ gap: "6px" }}>
                  {body?.fee_object_minted === false
                    ? <Chip kind="absent">no fee minted for this advisory</Chip>
                    : body?.fee_object_minted === true
                      ? <Chip>fee minted</Chip>
                      : <span className="meta">the advisory did not say</span>}
                  {body?.routing_fee_basis && (
                    <div className="meta mono">basis: {body.routing_fee_basis}</div>
                  )}
                </td>
              </tr>
              <tr className="trow">
                <th scope="row">What it cannot do</th>
                {/* The daemon's own authority_note, verbatim. It is the sentence that
                    makes the advisory safe, and it is the daemon's to write. */}
                <td className="basis">{body?.authority_note || "—"}</td>
              </tr>
              <tr className="trow">
                <th scope="row">Read at</th>
                <td className="meta">
                  {stamp(body?.at)} · {body?.advisory_ref || ""}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      ) : (
        <div className="stack" style={{ gap: "9px" }}>
          <p className="prose">
            The daemon returned no advisory for this intent. Nothing has been chosen here
            to fill the gap.
          </p>
          {/* THE NEXT STEP. An empty surface that does not say what would fill it leaves
              the reader with nothing to do — which is what a reviewer found here. */}
          <p className="meta">
            An advisory is produced against an intent that has live candidates. Submitting
            a job for this intent is what asks the daemon to place it.
          </p>
        </div>
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

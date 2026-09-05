import { useEffect } from "react";
import { useSurfaceRead } from "../useSurfaceRead.js";
import { intentRef } from "../logic/read.mjs";
import { clock } from "../logic/classify.mjs";
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
  const body = state.data;
  const decision = body?.decision || null;
  const considered = Array.isArray(body?.considered) ? body.considered : [];

  useEffect(() => {
    if (state.phase === "first") return;
    announce(`Placement — ${decision ? "an advisory was returned" : "no advisory"}`);
  }, [state.phase, decision, announce]);

  if (state.phase === "first") return <Waiting what="a placement advisory" />;

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

      {decision ? (
        <div className="panel flag stack" style={{ gap: "9px" }}>
          {/* Read `decision.selected.*`, not `decision.*`. A `.get()` on the wrong path
              once returned null silently and persisted nulls as evidence; it was caught
              only because the assertion demanded the venue be PRESENT, not merely that
              the field exist. An assertion shaped "the field exists" passes on a null. */}
          <h2>{decision.selected?.provider_kind || "no venue named in the advisory"}</h2>
          <p className="prose">{decision.rationale || decision.reason || "The advisory carried no rationale."}</p>
          <p className="meta">
            {decision.decision_ref || decision.advisory_ref || ""} · observed {clock(body?.at)}
          </p>
        </div>
      ) : (
        <p className="prose">
          The daemon returned no advisory for this intent. Nothing has been chosen here
          to fill the gap.
        </p>
      )}

      {considered.length > 0 && (
        <div className="table-scroll">
          <table className="quotes">
            <caption className="sr-only">Venues the daemon considered for this intent</caption>
            <thead>
              <tr>
                <th scope="col">Venue</th>
                <th scope="col">What the daemon said about it</th>
              </tr>
            </thead>
            <tbody>
              {considered.map((c, i) => (
                <tr key={c.provider_kind || i} className="trow">
                  <th scope="row" className="stack" style={{ gap: "7px" }}>
                    <div className="mono" style={{ fontSize: "14px" }}>{c.provider_kind || "—"}</div>
                    {c.eligible === false && <Chip kind="absent">not eligible</Chip>}
                  </th>
                  <td className="mono basis">{c.reason || c.note || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
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

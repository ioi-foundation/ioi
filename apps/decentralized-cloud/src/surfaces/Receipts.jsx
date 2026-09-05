import { useEffect, useState } from "react";
import { useSurfaceRead } from "../useSurfaceRead.js";
import { stamp } from "../logic/classify.mjs";
import { jobView } from "../logic/job-door.mjs";
import { Chip, Waiting, Failure, Kept } from "../components/Bits.jsx";

// RECEIPTS — WIRED, and rendered from real records.
//
// This surface used to draw the SHAPE of a receipt with nothing behind it, and
// deliberately showed no filled-in example, because a plausible receipt on the one page
// whose entire claim is auditability would be indistinguishable from a real one.
//
// It now reads the daemon's own job records and renders what each one actually
// carries. That rule survives the wiring intact and gets stricter, not looser: where a
// record has no receipt, this page says the record has no receipt. It does not fill the
// row with a shape, an ellipsis, or a plausible ref.
//
// THE FEE EXISTS ONLY AS A MINTED RECEIPT, from two or more REAL (non-simulator)
// candidates. That is the daemon's rule to enforce; this surface's job is to never
// contradict it, which it does by rendering only what a record says.

export default function Receipts({ announce }) {
  const state = useSurfaceRead("jobs", "/api/jobs");
  const allJobs = (Array.isArray(state.data?.jobs) ? state.data.jobs : []).map(jobView);

  // THE GATE'S OWN RECORDS ARE HIDDEN, COUNTED, AND AVAILABLE — never deleted.
  //
  // The face gate admits a real job every time it runs, which is what makes the door
  // proven rather than asserted. Those proposals are real records and they pile up.
  // Deleting them would make the gate's evidence unauditable; leaving them mixed in
  // would make this page's headline count a number about my test runs rather than
  // about the product. So they are filtered by the tag the gate wrote into the
  // daemon's own record, the count is stated, and one click shows them.
  const [showGate, setShowGate] = useState(false);
  const gateJobs = allJobs.filter((j) => j.gateAdmitted);
  const jobs = showGate ? allJobs : allJobs.filter((j) => !j.gateAdmitted);

  const withReceipts = jobs.filter((j) => j.receipts && Object.keys(j.receipts).length > 0);

  useEffect(() => {
    if (state.phase === "first") return;
    announce(`Receipts — ${jobs.length} job records, ${withReceipts.length} carrying receipts`);
  }, [state.phase, jobs.length, withReceipts.length, announce]);

  if (state.phase === "first") return <Waiting what="job records" />;

  const view = (
    <div className="stack" style={{ gap: "18px" }}>
      <h1>Receipts</h1>
      <p className="meta">
        {jobs.length} job record{jobs.length === 1 ? "" : "s"} ·{" "}
        {withReceipts.length} carrying receipts · read in{" "}
        {state.ms != null ? `${(state.ms / 1000).toFixed(1)}s` : "—"}
      </p>
      <p className="prose">
        Every row is a record the daemon holds. A receipt is the only place a fee
        exists: no fee is charged for pricing, for looking, or for a decision taken
        between fewer than two real venues. Where a record carries no receipt, this page
        says so — it does not draw the shape of one.
      </p>

      {gateJobs.length > 0 && (
        <p className="meta">
          {showGate
            ? `showing ${gateJobs.length} gate-admitted proposal${gateJobs.length === 1 ? "" : "s"} alongside the rest`
            : `${gateJobs.length} gate-admitted proposal${gateJobs.length === 1 ? "" : "s"} hidden`}
          {" — "}records the face's own verification created to prove the job door
          against this daemon. They are labelled in the daemon's record rather than
          deleted: a check that erases its own evidence cannot be audited.{" "}
          <button
            type="button"
            className="linklike"
            aria-pressed={showGate}
            onClick={() => setShowGate((v) => !v)}
          >
            {showGate ? "hide them" : "show them"}
          </button>
        </p>
      )}

      {jobs.length === 0 && (
        <p className="prose">
          {allJobs.length === 0
            ? "The daemon holds no job records. Nothing has been invented to fill the page."
            : "Every job record the daemon holds was admitted by this surface's own verification. No product job has been submitted yet, and none has been invented to stand in for one."}
        </p>
      )}

      {jobs.length > 0 && (
        <div className="table-scroll">
          <table className="table t-receipts">
            <caption className="sr-only">
              Job records held by the daemon, and the receipts each one carries
            </caption>
            <thead>
              <tr>
                <th scope="col">Job</th>
                <th scope="col">Authority</th>
                <th scope="col">Receipts</th>
                <th scope="col">State</th>
              </tr>
            </thead>
            <tbody>
              {jobs.map((j) => (
                <tr key={j.id} className="trow">
                  <th scope="row" className="stack" style={{ gap: "6px" }}>
                    <div className="mono" style={{ fontSize: "13px" }}>{j.id}</div>
                    <div className="meta">{stamp(j.createdAt)}</div>
                  </th>
                  <td className="mono basis">
                    <div>{j.callerKind || "—"}</div>
                    <div>{j.authorityMode || "—"}</div>
                    <div className="meta">{j.authorityRef || "—"}</div>
                  </td>
                  <td className="basis">
                    {j.receipts && Object.keys(j.receipts).length > 0 ? (
                      <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
                        {Object.keys(j.receipts).map((k) => (
                          <span key={k} className="chip muted">{k}</span>
                        ))}
                      </div>
                    ) : (
                      // Not "—", and not an empty cell. The absence is the finding and
                      // it is said in words: a reader who sees a blank cell cannot tell
                      // it apart from a cell that failed to render.
                      <span className="meta">
                        this record carries no receipt — it was admitted or placed, not run
                      </span>
                    )}
                    {j.receiptRequirements.length > 0 && (
                      <div className="meta" style={{ marginTop: "6px" }}>
                        required: {j.receiptRequirements.join(", ")}
                      </div>
                    )}
                  </td>
                  <td>
                    <Chip kind="muted">{j.state || "state absent"}</Chip>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <p className="prose">
        A simulator candidate never counts toward the two venues a fee needs, and never
        counts toward a fee. That rule is enforced in the daemon and rendered here — it
        is not a courtesy of this page.
      </p>
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

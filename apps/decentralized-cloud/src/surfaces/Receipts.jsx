import { useEffect, useState } from "react";
import { useSurfaceRead } from "../useSurfaceRead.js";
import { stamp, duration } from "../logic/classify.mjs";
import { jobView, originUnknown, ORIGIN_TAGGING_SINCE } from "../logic/job-door.mjs";
import { Chip, Waiting, Failure, Kept } from "../components/Bits.jsx";
import Receipt from "../components/Receipt.jsx";

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
  // SORTED, NEWEST FIRST, AND THE ORDER IS STATED IN THE HEADER.
  // This was the daemon's response order: a reviewer measured stamps running
  // 01:31 → 01:02 → 23:24 → 23:25 → 23:26. A ledger in arbitrary order is not a
  // ledger. Records with no timestamp sort last rather than being treated as old.
  const unsorted = showGate ? allJobs : allJobs.filter((j) => !j.gateAdmitted);
  const jobs = [...unsorted].sort((a, b) => {
    const at = Date.parse(a.createdAt || "") || -Infinity;
    const bt = Date.parse(b.createdAt || "") || -Infinity;
    return bt - at;
  });

  const withReceipts = jobs.filter((j) => j.receipts.length > 0);
  const unattributed = jobs.filter(originUnknown);

  useEffect(() => {
    if (state.phase === "first") return;
    announce(`Receipts — ${jobs.length} job records, newest first, ${withReceipts.length} carrying receipts`);
  }, [state.phase, jobs.length, withReceipts.length, announce]);

  if (state.phase === "first") return (
    <Waiting
      what="job records"
      title="Receipts"
      willShow={
        "A receipt is the daemon's record that something happened: what kind of event " +
        "it was, a hash you can check it against, and whether a fee was minted. It is " +
        "the only place a fee exists. This page lists every job the daemon holds, " +
        "newest first, with the receipts each one carries and the venue it was placed on."
      }
      why="The daemon is asked for every job record it holds."
    />
  );

  const view = (
    <div className="stack" style={{ gap: "18px" }}>
      <h1>Receipts</h1>
      {/* SHOWN, HIDDEN, AND THE TOTAL — all three, because two of them alone are worse
          than either. A cold reader: "30 records shown, 37 hidden. The header count
          says 30 without saying whether 30 includes or excludes the 37. From the
          picture I cannot tell if the true total is 30, 37, or 67. This is the sharpest
          unexplained number in the whole set."
          They were right: `jobs` is the filtered list and `allJobs` is everything, and
          the page published the filtered count as though it were the population. */}
      <p className="meta">
        {jobs.length} job record{jobs.length === 1 ? "" : "s"} shown
        {gateJobs.length > 0 && !showGate
          ? ` · ${gateJobs.length} hidden · ${allJobs.length} in total`
          : ""}
        {" · "}{withReceipts.length} carrying receipts · read in {duration(state.ms)}
      </p>
      <p className="prose">
        Every row is a record the daemon holds. A receipt is the only place a fee
        exists: no fee is charged for pricing, for looking, or for a decision taken
        between fewer than two real venues. Where a record carries no receipt, this page
        says so — it does not draw the shape of one.
      </p>
      {/* The limits and the epistemology — no amount column, unattributed records, the
          gate's own hidden records — come AFTER the ledger now. On a phone they were
          four paragraphs and ~450px of notes before the first row: purpose → facts →
          limits → epistemology is the order every surface here follows, and the
          ledger is the facts. */}
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
                <th scope="col">Job <span className="meta">· newest first</span></th>
                <th scope="col">Authority</th>
                <th scope="col">Receipts</th>
                {/* WHERE IT WENT. A receipts ledger that cannot say which venue the
                    placement chose is missing the fact most readers open it for, and
                    the job record has carried it all along. */}
                <th scope="col">Venue</th>
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
                    {j.receipts.length > 0 ? (
                      // THE RECEIPT'S KIND AND ITS ANCHORS, never its position in a
                      // list. This rendered `Object.keys(receipts)` — indices, because
                      // the daemon sends an array — so every chip on the page read "0"
                      // under a column headed Receipts.
                      // AS AN OBJECT, not a chip and a hash. A cold reader: "what a
                      // receipt IS is named on four surfaces and never displayed." The
                      // ticket carries kind, root, and the fee fact from the record's own
                      // fields — the claim the product is most often asked to prove.
                      <div className="stack" style={{ gap: "0" }}>
                        {j.receipts.map((r, i) => <Receipt key={r.ref || i} r={r} compact />)}
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
                  <td className="basis">
                    {j.venue ? (
                      <div className="stack" style={{ gap: "4px" }}>
                        <div className="mono" style={{ fontSize: "13px" }}>{j.venue}</div>
                        {j.quoteRef && (
                          <div className="meta mono" style={{ fontSize: "11px" }}>{j.quoteRef}</div>
                        )}
                      </div>
                    ) : j.state === "placed" ? (
                      // THE RECORD DISAGREES WITH ITSELF, and the surface says so
                      // rather than picking the half that reads better.
                      //
                      // A cold reader found a row with STATE `placed`, a full
                      // placement-decision receipt, and this cell reading "not placed
                      // yet — no venue was chosen". Reading the record back:
                      // `placement.venue` and `placement.candidate_ref` are both null
                      // while the RECEIPT for the same `decision_ref` names
                      // `selected_candidate_ref`. The daemon's own record contradicts
                      // itself, and "not placed yet" was this surface INFERRING from
                      // one half of it — an inference that is flatly false, on a
                      // ledger whose whole claim is that it renders what is there.
                      <span className="meta">
                        placed, but this record names no venue — its receipt names a
                        selected candidate and its placement block does not. Reported to
                        the daemon; not resolved here, because a surface that picks the
                        more plausible half of a contradiction is guessing.
                      </span>
                    ) : (
                      <span className="meta">not placed — no venue was chosen</span>
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

      {/* WHY THERE IS NO AMOUNT COLUMN, said once rather than asked on every row.
          A fee exists only as a minted receipt, and nothing reachable from this
          surface can mint one, so an amount column would be empty on every row
          forever. An always-empty column is a question the page keeps asking and
          never answers. */}
      <p className="meta">
        There is no amount column. A fee exists only as a minted receipt, and no
        execution is reachable from this surface — so every row would carry an empty
        one. Each row states whether a fee was minted instead.
      </p>

      {/* RECORDS THIS SURFACE CANNOT ATTRIBUTE, counted and named. Both verifiers now
          tag every record they create; earlier ones carry no tag and the daemon does
          not permit a field rewrite, so they cannot be labelled retroactively from
          here. Saying "some of these rows may be verification records and I cannot tell
          you which" is worse than useless only if it is not said. */}
      {unattributed.length > 0 && (
        <p className="meta">
          {unattributed.length} of these records predate origin tagging (before{" "}
          <span className="mono">{ORIGIN_TAGGING_SINCE}</span>) and carry no origin.
          Some are almost certainly this surface&rsquo;s own verification runs. This page
          will not guess which: attributing a record by the shape of its authority ref
          would silently reclassify a real job, which is a worse error than an
          unattributed one.
        </p>
      )}

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

import { useEffect, useState } from "react";
import { useSurfaceRead } from "../useSurfaceRead.js";
import { stamp, duration } from "../logic/classify.mjs";
import { jobView } from "../logic/job-door.mjs";
import { hashForSurface } from "../logic/surfaces.mjs";
import { Chip, Waiting, Failure, Kept, Eyebrow } from "../components/Bits.jsx";
import Receipt from "../components/Receipt.jsx";
import PageHead from "../components/PageHead.jsx";

// ONE JOB RECORD — the detail page under Jobs & receipts.
//
// A console's resource table opens into a resource page; this is that page for a
// CloudJobRequest the daemon holds. It reads the record by id through the route on
// the capability table and renders what the record carries: its state, who asked and
// with what authority, the budget it may draw on, where it was placed and on which
// quote, the receipts as tickets, and the raw record beneath for a reader who wants
// the bytes. Nothing is inferred from a half of the record: where the placement block
// and the receipt disagree, both are shown and the disagreement is said.
export default function JobDetail({ id, announce }) {
  const state = useSurfaceRead(`job:${id}`, `/api/jobs/${encodeURIComponent(id)}`);
  const raw = state.data?.job || (state.data && state.data.job_id ? state.data : null);
  const job = raw ? jobView(raw) : null;
  const [showRaw, setShowRaw] = useState(false);

  useEffect(() => {
    if (state.phase === "first") return;
    if (!job) { announce(`Job ${id} — the daemon returned no record`); return; }
    announce(`Job ${id} — ${job.state || "state absent"}, ${job.receipts.length} receipt${job.receipts.length === 1 ? "" : "s"}`);
  }, [state.phase, job, id, announce]);

  if (state.phase === "first") return (
    <Waiting
      what={`job record ${id}`}
      title={id}
      willShow="One job record: its state, its authority, its budget, where it was placed and the receipts it carries."
      why="One record by id is a small read and usually answers in under a second."
    />
  );

  const crumb = (
    <>
      <a className="entry-name" href={hashForSurface("receipts")}>Jobs &amp; receipts</a> · <span className="mono">{id}</span>
    </>
  );

  const view = job ? (
    <div className="stack" style={{ gap: "24px" }}>
      <PageHead
        surface="receipts"
        crumb={crumb}
        title={<span className="mono job-title">{job.id}</span>}
        meta={`GET /api/jobs/${id} · read at ${stamp(state.at)} in ${duration(state.ms)}${job.createdAt ? ` · created ${stamp(job.createdAt)}` : ""}`}
        aside={<Chip kind="muted">{job.state || "state absent"}</Chip>}
      />

      <div className="cols cols-2 job-detail" style={{ gap: "24px" }}>
        <section className="stack" style={{ gap: "10px" }} aria-labelledby="jd-record">
          <Eyebrow>the record</Eyebrow>
          <h2 id="jd-record">What the daemon holds</h2>
          <div className="table-scroll">
            <table className="table t-pairs t-jobrecord">
              <caption className="sr-only">Fields of this job record, as the daemon holds them</caption>
              <tbody>
                {[
                  ["state", job.state],
                  ["caller_kind", job.callerKind],
                  ["authority mode", job.authorityMode],
                  ["authority_ref", job.authorityRef],
                  ["budget_ref", job.budgetRef],
                  ["budget discovered before mutation", job.budgetDiscoveredBeforeMutation === null ? null : String(job.budgetDiscoveredBeforeMutation)],
                  ["redundancy", job.redundancy === null ? null : String(job.redundancy)],
                  ["receipt requirements", job.receiptRequirements.length ? job.receiptRequirements.join(", ") : null],
                  ["fee object minted", job.feeMinted === null ? null : String(job.feeMinted)],
                  ["origin", job.gateAdmitted ? "this surface's own verification (gate-admitted)" : (job.evidenceRefs.length ? job.evidenceRefs.join(", ") : null)],
                ].map(([k, v]) => (
                  <tr key={k} className="trow">
                    <th scope="row" className="mono" style={{ fontSize: "13px" }}>{k}</th>
                    <td className="mono basis">{v ?? <span className="meta">the record does not say</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        <section className="stack" style={{ gap: "10px" }} aria-labelledby="jd-placement">
          <Eyebrow>placement</Eyebrow>
          <h2 id="jd-placement">Where it went</h2>
          {job.venue ? (
            <div className="panel flag stack" style={{ gap: "8px" }}>
              <div className="mono" style={{ fontSize: "20px" }}>{job.venue}</div>
              {job.quoteRef && <div className="meta mono">{job.quoteRef}</div>}
              {job.placement?.candidate_ref && <div className="meta mono">{job.placement.candidate_ref}</div>}
              {Array.isArray(job.placement?.reason_codes) && job.placement.reason_codes.length > 0 && (
                <ul className="reasons">
                  {job.placement.reason_codes.map((r) => <li key={r} className="mono">{r}</li>)}
                </ul>
              )}
            </div>
          ) : job.state === "placed" ? (
            <div className="panel absent stack" style={{ gap: "8px" }}>
              <Eyebrow>the record disagrees with itself</Eyebrow>
              <p className="prose">
                State <span className="mono">placed</span>, but the placement block names no
                venue. If a receipt below names a selected candidate, the two halves of this
                record contradict each other; this page shows both and picks neither.
              </p>
            </div>
          ) : (
            <p className="prose">Not placed — no venue was chosen. A proposal that was admitted or refused stops here.</p>
          )}
        </section>
      </div>

      <section className="stack" style={{ gap: "10px" }} aria-labelledby="jd-receipts">
        <Eyebrow>receipts</Eyebrow>
        <h2 id="jd-receipts">{job.receipts.length} receipt{job.receipts.length === 1 ? "" : "s"}</h2>
        {job.receipts.length > 0 ? (
          <div className="stack" style={{ gap: "0" }}>
            {job.receipts.map((r, i) => <Receipt key={r.ref || i} r={r} />)}
          </div>
        ) : (
          <p className="prose">This record carries no receipt — it was admitted or placed, not run. Nothing is drawn where a ticket would be.</p>
        )}
      </section>

      <section className="stack" style={{ gap: "10px" }} aria-labelledby="jd-raw">
        <Eyebrow>the bytes</Eyebrow>
        <h2 id="jd-raw">The record as the daemon sent it</h2>
        <p className="meta">
          <button type="button" className="linklike" aria-pressed={showRaw} onClick={() => setShowRaw((v) => !v)}>
            {showRaw ? "hide the raw record" : "show the raw record"}
          </button>
          {" — "}every field above is read from this body; nothing is added to it.
        </p>
        {showRaw && <pre className="code">{JSON.stringify(raw, null, 2)}</pre>}
      </section>
    </div>
  ) : (
    <div className="stack" style={{ gap: "16px" }}>
      <PageHead surface="receipts" crumb={crumb} title={<span className="mono job-title">{id}</span>} />
      <p className="prose">The daemon answered, but the body carried no job record for this id. Nothing has been drawn in its place.</p>
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

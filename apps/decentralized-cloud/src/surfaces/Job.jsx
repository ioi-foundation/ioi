import { useEffect, useRef, useState } from "react";
import { useSurfaceRead } from "../useSurfaceRead.js";
import { Chip, Failure } from "../components/Bits.jsx";
import { HUMAN_REQUEST, AGENT_REQUEST } from "../logic/job-request.mjs";
import { composeRequest, admit, dryRun, refusal, jobView } from "../logic/job-door.mjs";

// SUBMIT A JOB — WIRED, on the human path.
//
// This surface used to be drawn and inert, labelled "designed, not connected". It now
// posts a real CloudJobRequest to the daemon through the face's write door and renders
// whatever comes back — an admission or a refusal — from the daemon's own body.
//
// WHAT IT STILL CANNOT DO, and why that is a boundary rather than a gap:
//
//   A REAL EXECUTION IS NOT REACHABLE FROM HERE. The daemon's execute route runs a
//   metered provider operation unless the body carries `dry_run: true`. The face's
//   proxy overwrites that field to true on every execute, server-side, after parsing
//   the body — so no request a client can compose reaches a provider. That is proven,
//   not asserted: a request carrying `dry_run: false` came back with `dry_run: true`
//   and a job in state `placed`, with nothing spent.
//
//   A real execution is a spend. It needs an explicit owner authorization naming
//   amount, venue ceiling, offer hash and teardown, and no such authorization can
//   arrive through a web form. The budget this door can draw on is real and has real
//   money behind it, which is what makes the fence load-bearing rather than tidy.
//
//   THE AGENT LANE IS BUILT AND UNREACHABLE FROM HERE. It is not missing: the daemon
//   resolves `caller_kind: "agent"` through a CapabilityLease draw-down and that
//   resolver is proven in-process to its honest maximum. What is not proven is the
//   binding WRITE on a real mint and byte-identical receipts on a live agent
//   execution, and both are M03.12's proof to run. This surface has no lease to draw
//   down and no business minting one, so it sends `caller_kind: "human"` and says so.

const REDUNDANCY = ["none", "warm_standby", "active_active"];

export default function Job({ announce }) {
  const budgets = useSurfaceRead("budgets", "/api/budgets");
  const [form, setForm] = useState({
    budgetRef: "",
    authorityRef: "wallet-grant://",
    hours: 4,
    devices: 1,
    minGb: 24,
    redundancy: "none",
  });
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState(null);
  const [dry, setDry] = useState(null);
  const [dryBusy, setDryBusy] = useState(false);

  useEffect(() => { announce("Submit a job — wired to the daemon on the human path"); }, [announce]);

  const spendBudgets = (budgets.data?.budgets || budgets.data?.items || [])
    .filter((b) => b.scope === "external_spend");

  // NO BUDGET IS PRESELECTED, even when only one exists.
  //
  // I wrote that auto-selection first, as a convenience, and then looked at what it
  // does: it puts a real external_spend budget into a request the reader did not
  // choose, and the submit button becomes live the instant the page finishes loading.
  // Choosing which money a job may draw on is the one decision on this form that
  // should never be made by a default. The button stays disabled until someone picks.

  const set = (k) => (e) => setForm((f) => ({ ...f, [k]: e.target.value }));

  // THE OUTCOME OF A WRITE IS ANNOUNCED, AND FOCUS MOVES TO IT.
  //
  // A reviewer submitted a job, got a 201 back, and measured that the page's only live
  // region still read "Submit a job — wired to the daemon on the human path". The
  // result panel rendered 209px below an unscrolled fold with no role, no announcement
  // and no focus move: a screen-reader user pressed the only button on the surface and
  // was told nothing had happened, and a sighted user was told by a panel they could
  // not see.
  //
  // This is the only place on the surface where a reader causes something, so it is the
  // one place where "what happened" cannot be left to be discovered.
  const outcomeRef = useRef(null);
  const announceOutcome = (r, verb) => {
    const f = refusal(r);
    announce(
      f
        ? `${verb} refused by the daemon: ${f.code}. ${f.detail || ""}`
        : `${verb} accepted. ${r.body?.job?.job_id || ""} is ${r.body?.job?.state || "recorded"}.`
    );
    // Focus lands on the outcome, not on the top of the page: the reader asked a
    // question and the answer is what they should arrive at.
    requestAnimationFrame(() => outcomeRef.current?.focus());
  };

  async function onSubmit(e) {
    e.preventDefault();
    setSubmitting(true);
    setDry(null);
    announce("Submitting the job to the daemon.");
    const r = await admit(composeRequest(form));
    setResult(r);
    setSubmitting(false);
    announceOutcome(r, "Admission");
  }

  async function onDryRun(jobId) {
    setDryBusy(true);
    announce("Running the placement decision. No provider is contacted.");
    const r = await dryRun(jobId, `face-${Date.now()}`);
    setDry(r);
    setDryBusy(false);
    announceOutcome(r, "Dry run");
  }

  const refused = result ? refusal(result) : null;
  const job = result?.ok ? jobView(result.body?.job) : null;
  const dryJob = dry?.ok ? jobView(dry.body?.job) : null;
  const dryRefused = dry ? refusal(dry) : null;

  return (
    <div className="stack" style={{ gap: "26px" }}>
      <div className="stack" style={{ gap: "9px" }}>
        <h1>Submit a job</h1>
        <p className="prose" style={{ fontSize: "16px" }}>
          This much capacity, under this budget, for this long, receipt back. You do not
          name a venue — the venue is evidence in the receipt, not an input to the request.
        </p>
      </div>

      {/* The spend fence, stated where the button is, not in a footnote. */}
      <div className="panel absent stack" style={{ gap: "8px" }}>
        <div className="eyebrow">what this door can and cannot do</div>
        <p className="prose">
          Submitting admits a <strong>proposal</strong>: the daemon records it and it
          authorizes nothing. A dry run then stops at the placement receipt and touches
          no provider. <strong>A real execution is not reachable from this surface</strong> —
          the proxy sets the dry-run flag itself on every execute rather than forwarding
          it, so no request composed here can reach a metered provider operation. A real
          run is a spend, and a spend needs an explicit owner authorization that names
          the amount, the venue ceiling, the offer hash and the teardown.
        </p>
      </div>

      <form className="stack" style={{ gap: "20px", maxWidth: "900px" }} onSubmit={onSubmit}>
        <div className="cols cols-2" style={{ gap: "20px 24px" }}>
          <label className="field">
            <span className="field-label">budget_ref</span>
            <select className="field-box" value={form.budgetRef} onChange={set("budgetRef")} required>
              <option value="">select an external_spend budget</option>
              {spendBudgets.map((b) => (
                <option key={b.budget_id} value={`budget://${b.budget_id}`}>
                  {b.name || b.budget_id} — {b.currency} {b.remaining ?? b.limit} remaining
                </option>
              ))}
            </select>
            <span className="field-hint">
              An existing budget, never an amount typed here. This list is the daemon's
              own; the form can only send back a ref it was given. A request with no
              resolvable budget is refused by name:{" "}
              <span className="mono">budget_undiscovered_before_mutation</span>.
            </span>
          </label>

          <label className="field">
            <span className="field-label">authority_ref</span>
            <input className="field-box" type="text" value={form.authorityRef}
              onChange={set("authorityRef")} required spellCheck="false" />
            <span className="field-hint">
              A wallet grant, presented at submit. Never a provider credential — the
              caller never holds one. A ref of the wrong kind is refused by name:{" "}
              <span className="mono">job_authority_mode_mismatch</span>.
            </span>
          </label>

          <label className="field">
            <span className="field-label">deadline · max duration (hours)</span>
            <input className="field-box" type="number" min="1" max="72" value={form.hours}
              onChange={set("hours")} required />
            <span className="field-hint">
              Without one there is no boundary at which an unfinished job becomes a
              failed one. Absent, it is refused:{" "}
              <span className="mono">job_deadline_required</span>.
            </span>
          </label>

          <label className="field">
            <span className="field-label">intent.gpu</span>
            <span style={{ display: "flex", gap: "8px" }}>
              <input className="field-box" type="number" min="1" max="8" value={form.devices}
                onChange={set("devices")} aria-label="devices" />
              <input className="field-box" type="number" min="1" max="200" value={form.minGb}
                onChange={set("minGb")} aria-label="minimum GB" />
            </span>
            <span className="field-hint">devices, and minimum GB per device.</span>
          </label>

          <label className="field">
            <span className="field-label">redundancy</span>
            <select className="field-box" value={form.redundancy} onChange={set("redundancy")}>
              {REDUNDANCY.map((r) => <option key={r} value={r}>{r}</option>)}
            </select>
            <span className="field-hint">
              Declared or absent — never inferred or defaulted. Postures beyond{" "}
              <span className="mono">none</span> are refused rather than downgraded,
              because a caller who asked for redundancy and silently received none would
              believe their work was protected when it was not.
            </span>
          </label>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "16px", flexWrap: "wrap" }}>
          <button className="button" type="submit" disabled={submitting || !form.budgetRef}>
            {submitting ? "asking the daemon…" : "Admit this job"}
          </button>
          <Chip kind="live">wired · POST /v1/hypervisor/cloud-jobs</Chip>
        </div>
      </form>

      {refused && (
        <div className="panel fault stack" style={{ gap: "8px" }}
          ref={outcomeRef} tabIndex={-1} role="alert">
          <div className="eyebrow mono">{refused.code}</div>
          <p className="prose">{refused.detail || "The daemon refused and gave no reason, which is itself worth reporting."}</p>
          <p className="meta">refused by the daemon · http {refused.status}</p>
        </div>
      )}

      {job && (
        <div className="panel flag stack" style={{ gap: "12px" }}
          ref={outcomeRef} tabIndex={-1} role="status">
          <div className="eyebrow">admitted as a proposal — nothing is authorized and nothing is spent</div>
          <h2 className="mono">{job.id}</h2>
          <div className="table-scroll">
            <table className="table">
              <caption className="sr-only">What the daemon recorded for this job</caption>
              <tbody>
                {[
                  ["state", job.state],
                  ["caller_kind", job.callerKind],
                  ["authority mode", job.authorityMode],
                  ["authority_ref", job.authorityRef],
                  ["budget_ref", job.budgetRef],
                  ["budget discovered before mutation", String(job.budgetDiscoveredBeforeMutation)],
                  ["redundancy", String(job.redundancy)],
                ].map(([k, v]) => (
                  <tr key={k} className="trow">
                    <th scope="row" className="mono" style={{ fontSize: "13px" }}>{k}</th>
                    <td className="mono basis">{v ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: "14px", flexWrap: "wrap" }}>
            <button className="button" type="button" disabled={dryBusy} onClick={() => onDryRun(job.id)}>
              {dryBusy ? "placing…" : "Dry run — place it, touch no provider"}
            </button>
            <span className="field-hint" style={{ maxWidth: "44ch" }}>
              Runs the placement decision and stops. The proxy sets the dry-run flag
              itself; there is no control here that could run this for real.
            </span>
          </div>
        </div>
      )}

      {dryRefused && (
        <div className="panel fault stack" style={{ gap: "8px" }}>
          <div className="eyebrow mono">{dryRefused.code}</div>
          <p className="prose">{dryRefused.detail || "The dry run was refused and the response carried no reason."}</p>
        </div>
      )}

      {dryJob && (
        <div className="panel flag stack" style={{ gap: "10px" }}>
          <div className="eyebrow">
            dry run · {String(dry.body?.dry_run)} — the daemon confirms it touched no provider
          </div>
          <h2 className="mono">{dryJob.state}</h2>
          {dry.body?.note && <p className="prose">{dry.body.note}</p>}
          {/* The end of the road on this surface, stated as the DESIGN it is rather
              than as a thing that is missing. A public page is a dry-run door: it
              decides a placement and stops. Executing is a spend, and a spend is
              authorized by a wallet grant presented at the moment it happens — which
              is a thing a person does, not a thing a web form carries. */}
          <p className="prose">
            <strong>Placement decided; execution requires a wallet grant — not offered
            on this surface.</strong> That is the design, not a gap: a public page is a
            dry-run door. Running this for real is a metered provider spend, authorized
            at the moment of spend against the daemon's own gate, and nothing on this
            page can stand in for that.
          </p>
          <p className="meta">
            The dry-run flag above is the DAEMON's echo of what it received, not what
            this page sent. That is the fact worth having: a request carrying dry_run
            false comes back true.
          </p>
        </div>
      )}

      {budgets.phase === "failed" && <Failure result={budgets.failure} />}

      {/* ── The same primitive, from both doors ────────────────────────────── */}
      <div className="stack" style={{ gap: "14px", marginTop: "6px" }}>
        <div className="eyebrow">The same primitive, from both doors</div>
        <p className="prose">
          The form above and the request below are the same CloudJobRequest. Neither door
          names a venue, neither carries a provider credential, and neither can widen what
          its authority already permits — a lease draw-down is a narrowing of a grant a
          human made earlier, never a new grant an agent made for itself.
        </p>
        <p className="prose">
          The agent lane is <strong>built and unreachable from this surface</strong>. The
          daemon resolves an agent caller through a CapabilityLease draw-down and that
          resolver is proven in-process to its honest maximum. What is unproven is the
          binding write on a real mint and byte-identical receipts on a live agent
          execution — both are <span className="mono">M03.12</span>'s proof to run. This
          page sends <span className="mono">caller_kind: "human"</span> and nothing else,
          because it has no lease to draw down and no business minting one.
        </p>
        <div className="cols cols-2" style={{ gap: "20px" }}>
          <div className="stack" style={{ gap: "9px" }}>
            <div className="meta">human · wallet grant signed at submit — the lane this door uses</div>
            <pre className="code">{JSON.stringify(HUMAN_REQUEST, null, 2)}</pre>
          </div>
          <div className="stack" style={{ gap: "9px" }}>
            <div className="meta">agent · CapabilityLease draw-down — built, unreachable from here</div>
            <pre className="code">{JSON.stringify(AGENT_REQUEST, null, 2)}</pre>
          </div>
        </div>
      </div>
    </div>
  );
}

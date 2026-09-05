import { useEffect } from "react";
import { Chip, NotConnected } from "../components/Bits.jsx";
import { HUMAN_REQUEST, AGENT_REQUEST } from "../logic/job-request.mjs";

// SUBMIT A JOB — designed, not connected, and saying so in its own words.
//
// The daemon's cloud-job routes exist and are green on m15. THIS SURFACE is not
// connected to them yet: Phase C wires the human path, and until it does, every claim
// on this page is about a shape rather than about a capability. A stub a reader
// cannot tell from truth is refused; a labelled stub is a design deliverable.
//
// The label is rendered TEXT, not a comment and not a colour. The face gate strips
// comments from the served bytes before asserting this surface says it, because a
// source-text assertion can be satisfied by a comment — and was, twice: once by a
// fixed-length slice running into the next function's label, and once by a section
// banner containing the same phrase.

const Field = ({ label, value, hint }) => (
  <div className="field">
    <div className="field-label">{label}</div>
    <div className="field-box"><span>{value}</span><span className="mono">▾</span></div>
    {hint ? <div className="field-hint">{hint}</div> : null}
  </div>
);

// The two request bodies are imported, not written here, so the gate can compare the
// SAME objects this surface renders rather than parsing them back out of the source.

export default function Job({ announce }) {
  useEffect(() => { announce("Submit a job — designed, not connected"); }, [announce]);

  return (
    <div className="stack" style={{ gap: "26px" }}>
      <NotConnected>
        Drawn to the canonical CloudJobRequest shape and submits nothing. No field here
        reaches a provider, a wallet, or a budget: this server exposes no mutating route
        at all, so there is nothing for the button to call.
      </NotConnected>

      <div className="stack" style={{ gap: "9px" }}>
        <h1>Submit a job</h1>
        <p className="prose" style={{ fontSize: "16px" }}>
          This much capacity, under this budget, for this long, receipt back. You do not
          name a venue — the venue is evidence in the receipt, not an input to the request.
        </p>
      </div>

      <div className="cols cols-2" style={{ gap: "20px 24px", maxWidth: "900px" }}>
        <Field label="intent.runtime_class" value="compute.gpu_runtime" />
        <Field label="intent.gpu" value="required · 1 device · 24 GB" />
        <Field label="deadline" value="max duration · 4 hours" />
        <Field
          label="budget_ref"
          value="select an external_spend budget"
          hint="An existing budget, never an amount typed here. A request with no resolvable budget is refused by name: budget_undiscovered_before_mutation."
        />
        <Field
          label="authority_ref"
          value="wallet grant · signed at submit"
          hint="A wallet grant for a human, a CapabilityLease draw-down for an agent. Never a provider credential — the caller never holds one."
        />
        <Field
          label="redundancy"
          value="none"
          hint="none · warm_standby · active_active. Declared or absent — never inferred, defaulted, or applied by a fallback you did not authorize."
        />
      </div>

      <div className="field">
        <div className="field-label">receipt_requirements</div>
        <div style={{ display: "flex", flexWrap: "wrap", gap: "9px" }}>
          {["placement", "provider-operation", "spend", "failover", "offline-verifiable"].map((r) => (
            <span key={r} className="chip muted">{r}</span>
          ))}
        </div>
      </div>

      <div style={{ display: "flex", alignItems: "center", gap: "16px", flexWrap: "wrap" }}>
        <button className="button-inert" type="button" disabled>Submit job</button>
        <span className="field-hint" style={{ maxWidth: "48ch" }}>
          Disabled until this surface is wired to the daemon's cloud-job routes. The
          button is drawn so the shape of the commitment is reviewable now, and it is
          inert on purpose.
        </span>
        <Chip kind="muted">not wired — this surface calls no job route</Chip>
      </div>

      {/* ── The same primitive, from both doors ──────────────────────────────
          A human fills the form above; an agent posts the body below. They are not two
          APIs with a shared name — they are one CloudJobRequest, and the only field
          that differs is how authority was obtained: a wallet grant a person signs, or
          a CapabilityLease an agent draws down. If these two ever drift apart, one of
          the two callers is being offered a privilege the other is not, which is how a
          second spine starts. */}
      <div className="stack" style={{ gap: "14px", marginTop: "6px" }}>
        <div className="eyebrow">The same primitive, from both doors</div>
        <p className="prose">
          The form above and the request below are the same CloudJobRequest. Neither door
          names a venue, neither carries a provider credential, and neither can widen what
          its authority already permits — a lease draw-down is a narrowing of a grant a
          human made earlier, never a new grant an agent made for itself.
        </p>
        <div className="cols cols-2" style={{ gap: "20px" }}>
          <div className="stack" style={{ gap: "9px" }}>
            <div className="meta">human · wallet grant signed at submit</div>
            <pre className="code">{JSON.stringify(HUMAN_REQUEST, null, 2)}</pre>
          </div>
          <div className="stack" style={{ gap: "9px" }}>
            <div className="meta">agent · CapabilityLease draw-down</div>
            <pre className="code">{JSON.stringify(AGENT_REQUEST, null, 2)}</pre>
          </div>
        </div>
      </div>
    </div>
  );
}

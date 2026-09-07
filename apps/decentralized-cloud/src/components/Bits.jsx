import { envelope } from "../logic/classify.mjs";

// The small shared pieces. Each carries the rule it enforces, because each exists
// because that rule was once broken on this surface.

// A STATE WORD BREAKS AT ITS UNDERSCORES, NEVER INSIDE A WORD. `candidate_source_
// unavailable` is 28 mono characters; on a phone the chip either painted over the
// next column or, with `overflow-wrap: anywhere`, broke as `live_quote_sour / ce` —
// two readers read that as a fault. A <wbr> after each underscore gives the browser
// the break the token already has, so it wraps as `candidate_source_ / unavailable`
// and the text a reader copies is unchanged. Only strings are treated; other
// children pass through.
export const breakable = (s) => {
  if (typeof s !== "string" || !s.includes("_")) return s;
  const parts = s.split("_");
  return parts.flatMap((p, i) => (i < parts.length - 1 ? [p + "_", <wbr key={i} />] : [p]));
};
export const Chip = ({ children, kind = "" }) => (
  <span className={`chip ${kind}`.trim()}><span className="dot" />{breakable(children)}</span>
);

export const Eyebrow = ({ children }) => <div className="eyebrow">{children}</div>;

// WAITING. Nothing is shown until the daemon answers, and the wait says why. An
// invented placeholder would be indistinguishable from a real quote, which on this
// surface is the one thing that must never be true.
// A TRUE first load — nothing kept, nothing to show. Rare now that the store survives
// a reload, and it must still not be a blank rectangle.
//
// A reviewer sampled a cold Sources load fourteen times across 39,417ms and measured:
// zero rows throughout, `aria-busy` null in every sample, zero elements matching
// skeleton/shimmer/spinner/loading, opacity 1, no <h1> on the document at all, and the
// polite live region holding the EMPTY STRING for the entire wait before jumping
// straight to the result. A sighted reader could not tell working from hung, and a
// screen-reader user was told nothing for thirty-nine seconds.
//
// The refusal to invent a placeholder stands — an invented quote is the one thing this
// surface must never render. What changes is that waiting is now a STATE with a name,
// a heading and a machine-readable busy flag, instead of an absence.
// A cold reader given only pictures said of Sources, Placement and Receipts: "same
// layout, same two grey paragraphs, one of which is copy-pasted verbatim between them
// — if you covered the titles I could not tell which cell was which." They were right,
// and worse: the shared paragraph explained why a CANDIDATE SWEEP is slow, on two
// pages that are not about candidates. Boilerplate that describes a different page is
// not an explanation, it is furniture.
//
// So the wait says what THIS read is waiting on and why THIS read is slow, and the
// page states what it will show when it arrives — because the same reader could not
// answer "what is this page for?" on any of the three.
export const Waiting = ({ what, title, why, willShow }) => (
  <div className="stack" style={{ gap: "10px" }} aria-busy="true">
    {/* The heading exists DURING the wait. A document whose first heading appears 39
        seconds after load has no structure to navigate for all of that time. */}
    {title && <h1>{title}</h1>}
    <p className="prose" role="status">
      Asking the daemon for {what}.
    </p>
    {/* WHAT THIS PAGE IS FOR, said while it is empty. A page that only explains itself
        once its data arrives does not explain itself to anyone who leaves first. */}
    {willShow && <p className="prose">{willShow}</p>}
    <p className="meta">
      {why} Nothing is shown until it answers: an invented placeholder would be
      indistinguishable from a real one.
    </p>
  </div>
);

// FAILURE, reading BOTH envelope shapes. The face's own proxy answers
// `{ state, reason }`; the daemon answers a refusal as `{ ok: false, error: { code,
// message } }`. Reading only the first meant every daemon-shaped refusal — every 422
// the job primitive raises, every named provider-plane code — rendered as "http 422"
// over "the daemon gave no reason", while the body in front of us carried both the
// name and the sentence.
//
// Saying "no reason was given" when a reason WAS given is the worst thing this
// surface can do: it is the one page whose entire claim is that you can always see
// where a number, or a refusal, came from. The fallback fires only when the body
// genuinely carries neither.
// THE DAEMON-DOWN COMPOSITION. The proxy names the state — candidate_plane_unreachable,
// candidate_plane_timeout, face_read_failed — and the panel renders that name and
// the reason verbatim. What it adds is what to do: a read is re-run when a reader
// returns to the surface, the daemon's health is on Sources, and a kept answer, if
// there is one, is shown beneath this panel dated as the previous reading. Nothing
// here retries on a timer: a page that hammers a daemon that is down is not being
// helpful, and nothing spins.
const DOWN_STATES = new Set(["candidate_plane_unreachable", "candidate_plane_timeout", "face_read_failed", "job_plane_unreachable", "job_plane_timeout"]);
export const Failure = ({ result }) => {
  const { code, detail } = envelope(result);
  const down = DOWN_STATES.has(code);
  return (
    <div className="panel fault stack" style={{ gap: "8px" }} role="alert">
      <Eyebrow>{down ? `the daemon did not answer · ${code}` : code}</Eyebrow>
      <p className="prose">
        {detail || "The read failed and the response carried no reason — which is itself worth reporting."}
      </p>
      {down && (
        <p className="meta fault-next">
          This surface re-reads when you return to it. The previous answer, if this browser holds one,
          is shown beneath and dated. Source health is on{" "}
          <a href="#/sources">Sources &amp; health</a>; the daemon this console talks to is named in
          the rail's foot.
        </p>
      )}
    </div>
  );
};

// THE UNWIRED LABEL. A surface that is designed but not connected says so in its own
// words, on screen, where a reader sees it — not in a comment, not in a tooltip, and
// not in a colour. The face gate asserts this against the SERVED BYTES with comments
// stripped, because a source-text assertion can be satisfied by a comment and once
// was, twice.
export const NotConnected = ({ children }) => (
  <div className="panel absent stack" style={{ gap: "8px" }}>
    <Eyebrow>designed, not connected</Eyebrow>
    <p className="prose">{children}</p>
  </div>
);

// UNWIRED — the place a number would stand on a surface the daemon does not feed yet.
//
// A console panel drawn for a read that is not on the capability table gets one of
// these where its figure would go: the name of what would stand there and the route
// it would come from, in a dashed box, with no digit in it. One grep for "Unwired"
// finds every such placeholder on the face. A panel that drew a plausible figure — a
// zero, a dash in a currency cell, an empty sparkline — would be indistinguishable
// from a panel that read one, which is the one thing this surface refuses.
export const Unwired = ({ would, route, children }) => (
  <div className="unwired">
    <div className="unwired-head">
      <span className="eyebrow">not wired</span>
      {route && <span className="mono unwired-route">{route}</span>}
    </div>
    {would && <p className="unwired-would">would show: {would}</p>}
    {children}
  </div>
);

// A kept answer, dimmed and dated. Stale-while-refresh shows the previous reading
// immediately rather than an empty page, because an empty surface here has to keep
// meaning "no live price" and can never also come to mean "loading".
export const Kept = ({ at, children }) => (
  <div className="stale">
    <p className="meta">
      the previous answer, read at {at ? new Date(at).toISOString().slice(11, 19) + "Z" : "—"} — a newer one is in flight
    </p>
    {children}
  </div>
);

import { envelope } from "../logic/classify.mjs";

// The small shared pieces. Each carries the rule it enforces, because each exists
// because that rule was once broken on this surface.

export const Chip = ({ children, kind = "" }) => (
  <span className={`chip ${kind}`.trim()}><span className="dot" />{children}</span>
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
export const Waiting = ({ what, title }) => (
  <div className="stack" style={{ gap: "10px" }} aria-busy="true">
    {/* The heading exists DURING the wait. A document whose first heading appears 39
        seconds after load has no structure to navigate for all of that time. */}
    {title && <h1>{title}</h1>}
    <p className="prose" role="status">
      Asking the daemon for {what}. This can take up to a minute.
    </p>
    <p className="prose">
      A full candidate sweep is slow — it asks every live venue in turn. Nothing is
      shown until it answers: an invented placeholder would be indistinguishable from
      a real quote.
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
export const Failure = ({ result }) => {
  const { code, detail } = envelope(result);
  return (
    <div className="panel fault stack" style={{ gap: "8px" }}>
      <Eyebrow>{code}</Eyebrow>
      <p className="prose">
        {detail || "The read failed and the response carried no reason — which is itself worth reporting."}
      </p>
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

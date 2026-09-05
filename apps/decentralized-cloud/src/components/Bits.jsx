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
export const Waiting = ({ what }) => (
  <div className="stack" style={{ gap: "10px" }}>
    <p className="prose">Asking the daemon for {what}.</p>
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
  <div className="panel notice stack" style={{ gap: "8px" }}>
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

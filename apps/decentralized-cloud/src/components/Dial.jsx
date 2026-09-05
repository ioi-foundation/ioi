import { useEffect, useState } from "react";
import { dialFraction } from "../logic/classify.mjs";

// THE FRESHNESS DIAL.
//
// The fraction of a quote's OWN observed_at → expires_at window that is still
// unspent. Both endpoints come from the daemon's record of that candidate. The dial
// has no duration of its own and no animation that runs independently of them, so it
// cannot show a full window for an empty one — which is the entire reason it is
// computed rather than animated.
//
// It is re-derived from the same two timestamps once a second. A CSS transition would
// have been cheaper and would have been a lie: it would keep sweeping smoothly while
// the data behind it said nothing at all.
//
// This is also the ring/arc mark's only surviving job. It was proposed as the
// product's identity, failed its review for reading as a spinner or a letterform, and
// was demoted to exactly this — a freshness dial, where "reads as a progress
// indicator" is not a fault but the correct meaning.

const R = 8;
const C = 2 * Math.PI * R;

export default function Dial({ observedAt, expiresAt }) {
  const [, tick] = useState(0);

  useEffect(() => {
    const t = setInterval(() => tick((n) => n + 1), 1000);
    return () => clearInterval(t);
  }, []);

  const f = dialFraction(observedAt, expiresAt);

  // No window, or a malformed one, draws NOTHING rather than an empty ring. An empty
  // ring is a claim that the window is spent; absence of a window is a different fact
  // and gets a different rendering.
  if (f === null) {
    return (
      <svg className="dial" width="22" height="22" viewBox="0 0 22 22" role="img" aria-label="no observation window">
        <circle cx="11" cy="11" r={R} className="dial-track" fill="none" strokeDasharray="2 3" />
      </svg>
    );
  }

  const pct = Math.round(f * 100);
  return (
    <svg
      className="dial"
      width="22"
      height="22"
      viewBox="0 0 22 22"
      role="img"
      aria-label={`${pct}% of this quote's observation window remains`}
    >
      <circle cx="11" cy="11" r={R} className="dial-track" fill="none" />
      <circle
        cx="11"
        cy="11"
        r={R}
        className="dial-ink"
        fill="none"
        strokeDasharray={`${(C * f).toFixed(3)} ${C.toFixed(3)}`}
        transform="rotate(-90 11 11)"
      />
    </svg>
  );
}

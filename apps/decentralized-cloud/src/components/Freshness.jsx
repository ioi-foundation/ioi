import { useEffect, useState } from "react";
import { dialFraction, minutesLeft, clock } from "../logic/classify.mjs";

// THE DEPLETING BAR — the freshness dial, redrawn as a thing a reader can READ.
//
// Three independent readers mistook the ring for a loading spinner: "it carries no
// readable value and reads as a loading indicator that never resolved." A ring with no
// number is a ring a reader has to interpret, and the interpretation they reach is the
// one every other product taught them. A bar with a time beside it needs no
// interpretation.
//
// The arithmetic is unchanged and lives in classify.mjs: the fraction of THIS quote's
// own observed_at → expires_at window still unspent. There is no duration of its own
// and no animation independent of those two timestamps — it is re-derived once a second
// from the daemon's record, so a bar that looks full IS a window that is full. That is
// the only motion on the landing, and it is motion that shows real change.
//
// Colour: the unspent portion is green because it is live evidence — the same meaning
// green carries everywhere here. The spent portion is the track. When the window is
// gone the bar is red, which is the one thing red means: expired.

export default function Freshness({ observedAt, expiresAt, size = "row" }) {
  const [, tick] = useState(0);
  useEffect(() => {
    const t = setInterval(() => tick((n) => n + 1), 1000);
    return () => clearInterval(t);
  }, []);

  const f = dialFraction(observedAt, expiresAt);
  const m = minutesLeft(expiresAt);

  // No window, or a malformed one, draws NOTHING but says so. An empty bar is a claim
  // that the window is spent; absence of a window is a different fact.
  if (f === null) {
    return (
      <div className={`fresh fresh-${size} fresh-none`} role="img" aria-label="no observation window">
        <div className="fresh-track" />
        <div className="fresh-text mono">no window</div>
      </div>
    );
  }

  const expired = f <= 0;
  const pct = Math.round(f * 100);
  const text = expired
    ? `expired ${clock(expiresAt)}`
    : m !== null && m >= 1
      ? `${m} min left · until ${clock(expiresAt)}`
      : `under a minute · until ${clock(expiresAt)}`;
  return (
    <div
      className={`fresh fresh-${size}${expired ? " fresh-expired" : ""}`}
      role="img"
      aria-label={`${pct}% of this quote's observation window remains; ${text}`}
    >
      <div className="fresh-track">
        <div className="fresh-left" style={{ width: `${(f * 100).toFixed(2)}%` }} />
      </div>
      <div className="fresh-text mono">{text}</div>
    </div>
  );
}

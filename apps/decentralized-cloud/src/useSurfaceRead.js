import { useEffect, useRef, useState } from "react";
import { read, recall, remember } from "./logic/read.mjs";

// THE GUARD, IN REACT.
//
// The vanilla surface held a module-level `generation` counter, bumped on every
// navigation, captured before each await and checked before anything reached the DOM.
// React does not need a counter to avoid painting an unmounted component — but it
// does NOT protect against the fault that counter existed for, which is subtler than
// unmounting: a slow read for surface X landing while the reader is on surface Y,
// where the component is still mounted because it is the same component instance with
// a different key, or where a refresh interval fires against a stale closure.
//
// So the guard is kept, in the only form that is honest here: every read captures the
// token that was current when it STARTED, and the result is discarded unless that
// token is still current when it LANDS. One place, so a caller cannot bypass it by
// forgetting — which is why the original routed every render through one function.
//
// WHAT THIS HOOK GUARANTEES, and what the surfaces are allowed to rely on:
//   1. A response for a superseded read never reaches state.
//   2. The FIRST load of a surface has nothing to be stale from, so it says so.
//      Every later refresh keeps the previous answer on screen, dimmed and dated,
//      while the new read is in flight — because a page that blanks itself to refetch
//      teaches its reader that an empty table means "loading", and on this surface an
//      empty table has to keep meaning "no live price".
//   3. A FAILED refresh does not erase a good earlier reading. The failure is shown
//      ABOVE the kept answer, because "the last answer, and why we could not get a
//      newer one" is more useful than either alone.

export function useSurfaceRead(key, path, { enabled = true, pollMs = null } = {}) {
  const [state, setState] = useState(() => {
    const kept = recall(key);
    return kept
      ? { phase: "refreshing", data: kept.body, ms: kept.ms, at: kept.at, stale: true, failure: null }
      : { phase: "first", data: null, ms: null, at: null, stale: false, failure: null };
  });
  const token = useRef(0);

  useEffect(() => {
    if (!enabled) return undefined;
    let cancelled = false;
    const mine = ++token.current;

    const run = async (silent) => {
      const kept = recall(key);
      if (!silent) {
        setState(
          kept
            ? { phase: "refreshing", data: kept.body, ms: kept.ms, at: kept.at, stale: true, failure: null }
            : { phase: "first", data: null, ms: null, at: null, stale: false, failure: null }
        );
      }
      const r = await read(path);
      // The guard. `mine !== token.current` means the reader has moved on, or a newer
      // read for this same surface has started; either way this response is answering
      // a question nobody is asking any more.
      if (cancelled || mine !== token.current) return;
      if (!r.ok) {
        const still = recall(key);
        setState({
          phase: "failed",
          data: still ? still.body : null,
          ms: still ? still.ms : r.ms,
          at: still ? still.at : null,
          stale: Boolean(still),
          failure: r,
        });
        return;
      }
      remember(key, r.body, r.ms);
      const now = recall(key);
      setState({ phase: "ready", data: r.body, ms: r.ms, at: now.at, stale: false, failure: null });
    };

    run(false);

    if (!pollMs) return () => { cancelled = true; };
    // The poll refreshes SILENTLY — it must not blank the surface it is refreshing,
    // and it must not fire while the tab is hidden, because a background tab re-asking
    // a 60-second sweep every 30 seconds is a cost nobody chose to pay.
    const timer = setInterval(() => {
      if (typeof document !== "undefined" && document.visibilityState !== "visible") return;
      run(true);
    }, pollMs);
    return () => { cancelled = true; clearInterval(timer); };
  }, [key, path, enabled, pollMs]);

  return state;
}

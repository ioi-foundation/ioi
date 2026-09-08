import { useSyncExternalStore } from "react";
import { daemonStatus, subscribe } from "../logic/health.mjs";
import { hashForSurface } from "../logic/surfaces.mjs";

// THE DAEMON-DOWN BANNER — the shell says it once.
//
// When the last daemon-bound read this browser made came back as a named unreachable
// state, one band under the top bar carries the state word, the reason verbatim, the
// route it failed on and the time. It is a `role="status"` region, not an alert: the
// per-read panels on the surface already alert, and a shell that shouted the same fact
// a second time would be noise. It clears on the next daemon read that succeeds.
//
// It is NOT drawn on "unknown" — before the first read has landed there is nothing to
// say about the daemon, and a banner that appeared on every cold load would teach a
// reader that the console is usually broken.
export function useDaemonStatus() {
  return useSyncExternalStore(subscribe, daemonStatus, daemonStatus);
}

export default function DaemonBanner({ host }) {
  const s = useDaemonStatus();
  if (s.state !== "down") return null;
  return (
    <div className="daemon-banner" role="status">
      <span className="daemon-banner-word">the daemon did not answer</span>
      <span className="mono daemon-banner-code">{s.code}</span>
      <span className="daemon-banner-text">
        {host ? <>at <span className="mono">{host}</span> · </> : null}
        {s.path ? <><span className="mono">{s.path}</span> · </> : null}
        {s.at ? `${String(s.at).slice(11, 19)}Z` : ""}
        {s.reason ? ` · ${s.reason}` : ""}
      </span>
      <a className="daemon-banner-link" href={hashForSurface("sources")}>Sources &amp; health →</a>
    </div>
  );
}

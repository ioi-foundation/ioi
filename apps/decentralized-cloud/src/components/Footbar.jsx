import { hashForSurface } from "../logic/surfaces.mjs";
import { useDaemonStatus } from "./DaemonBanner.jsx";

// THE FOOT BAR — the console's bottom edge, on onyx.
//
// A console keeps its utilities and its fine print along the bottom: here the API and
// Settings surfaces and the brand page on the left, and on the right the project line
// — which daemon this is a face of, whether it answered the last read, and the
// generated capability sentence the gate reads by id. It used to live in the rail's
// foot; the rail is a navigation panel now, and a panel that can be closed is no place
// for the one line a reader is owed on every screen.
export default function Footbar({ daemonHost, capabilityChip }) {
  const daemon = useDaemonStatus();
  const dotKind = daemon.state === "answering" ? "muted" : daemon.state === "down" ? "absent" : "";
  const dotWord = daemon.state === "answering" ? "answered the last read" : daemon.state === "down" ? "did not answer the last read" : "not asked yet";
  return (
    <footer className="footbar">
      <nav className="footbar-links" aria-label="Utilities">
        <a href={hashForSurface("api")}>API</a>
        <a href={hashForSurface("settings")}>Settings</a>
        <a href="/brand/">Brand</a>
      </nav>
      <div className="footbar-project">
        <span className="meta rail-daemon" id="daemon-label">
          <span className={`rail-dot ${dotKind}`.trim()} aria-hidden="true" />
          daemon {daemonHost}
          <span className="sr-only"> — {dotWord}</span>
        </span>
        <span className="chip muted" id="refresh-chip">
          <span className="dot" />{capabilityChip}
        </span>
      </div>
    </footer>
  );
}

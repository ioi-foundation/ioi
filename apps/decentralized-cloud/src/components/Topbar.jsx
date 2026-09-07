import { useEffect, useRef } from "react";
import Lockup from "./Lockup.jsx";
import { hashForSurface } from "../logic/surfaces.mjs";

// THE TOP BAR — identity, search, and the two things every console puts top-right:
// who you are and where you are placing.
//
// SEARCH is real and small. It filters the rail by surface name and Enter opens the
// first match; `/` focuses it from anywhere that is not already a text field. It does
// not search resources, records or quotes, and the placeholder says exactly what it
// searches, because a search box that looks like a console's global search and only
// filters twelve names would be a promise the box cannot keep.
//
// THE PRINCIPAL is not a login. On this surface a principal is a wallet, and what it
// may do is a CapabilityLease. This face holds no wallet session and mints nothing, so
// the chip says so and is a link to the IAM surface, where the shape of a lease is
// drawn and labelled. THE POSTURE — custody, support boundary, region preferences —
// lives on the intent, not on a dropdown; it is a link to Placement. Neither is a
// control that pretends to set something it cannot.
export default function Topbar({ query, setQuery, onSearchEnter, matchCount }) {
  const box = useRef(null);

  useEffect(() => {
    const onKey = (e) => {
      if (e.key !== "/" || e.metaKey || e.ctrlKey || e.altKey) return;
      const t = e.target;
      const typing = t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.tagName === "SELECT" || t.isContentEditable);
      if (typing) return;
      e.preventDefault();
      box.current?.focus();
      box.current?.select();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  return (
    <header className="topbar">
      <div className="topbar-left">
        <Lockup />
      </div>

      <form
        className="console-search"
        role="search"
        onSubmit={(e) => { e.preventDefault(); onSearchEnter(); }}
      >
        <input
          ref={box}
          id="console-search"
          className="console-search-box"
          type="search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search surfaces — press /"
          aria-label="Search surfaces by name. Resources and records are not searched on this branch."
          aria-describedby="console-search-scope"
          autoComplete="off"
          spellCheck="false"
        />
        <span id="console-search-scope" className="console-search-scope mono">
          {query.trim()
            ? `${matchCount} surface${matchCount === 1 ? "" : "s"} match`
            : "surfaces only"}
        </span>
      </form>

      <div className="topbar-status">
        <a className="chip absent topbar-posture" href={hashForSurface("placement")}>
          <span className="dot" />posture · on the intent, not set here
        </a>
        <a className="chip absent topbar-principal" href={hashForSurface("iam")}>
          <span className="dot" />principal · no wallet session
        </a>
      </div>
    </header>
  );
}

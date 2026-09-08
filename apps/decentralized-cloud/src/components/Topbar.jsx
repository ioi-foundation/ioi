import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import Lockup from "./Lockup.jsx";
import { SURFACES, GROUPS, hashForSurface } from "../logic/surfaces.mjs";
import { recall } from "../logic/read.mjs";
import { jobView } from "../logic/job-door.mjs";
import { buildIndex, searchIndex, indexScope, kindWord } from "../logic/palette.mjs";
import { useDaemonStatus } from "./DaemonBanner.jsx";
import { IconGrid, IconSearch, IconTerminal, IconBell, IconHelp, IconGear, IconChevron, IconClose, SurfaceIcon } from "./Icons.jsx";

// THE TOP BAR — the shape a console user's hands already know.
//
// Left to right: the lockup; the SERVICES GRID (nine dots) that opens every surface
// by group; the SEARCH with its shortcut chip, which is the command palette; then the
// utilities every console keeps top-right — a terminal (the API surface), a bell (what
// needs a look, counted from the kept reads), help (Settings, which says what this
// surface is), a gear (Settings) — and the two dropdown-shaped controls: the placement
// posture where a region selector would be, and the principal where the account is.
// Neither dropdown SETS anything: each opens the surface that says what it honestly
// can, and its chevron is the shape, not a promise.
//
// THE PALETTE searches the surface registry and WHAT THIS BROWSER HAS ALREADY READ —
// sources by name with their state, venues in the latest sweep with their cheapest,
// job records by id, budgets — each with its read stamp. It fetches nothing to answer
// a keystroke and indexes nothing the daemon did not say; the scope line under the box
// counts exactly what is searchable now.
export default function Topbar({ go, announce, surface }) {
  const box = useRef(null);
  const listRef = useRef(null);
  const menuRef = useRef(null);
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const [menu, setMenu] = useState(false);
  const daemon = useDaemonStatus();
  const items = useMemo(() => buildIndex(recall), [open, query, surface, daemon]); // eslint-disable-line react-hooks/exhaustive-deps
  const results = useMemo(() => searchIndex(items, query), [items, query]);
  const scope = useMemo(() => indexScope(items), [items]);

  // The bell's count: what the kept reads say needs a look — sources named
  // unavailable and jobs the daemon refused. Zero before any read has landed is
  // shown as no badge, not as "0", because nothing has been counted yet.
  const attention = useMemo(() => {
    const src = recall("sources")?.body?.sources;
    const jobs = recall("jobs")?.body?.jobs;
    const absent = Array.isArray(src) ? src.filter((s) => s && s.state === "candidate_source_unavailable").length : 0;
    const refused = Array.isArray(jobs) ? jobs.filter((j) => j && /^refused/.test(j.state || "") && !jobView(j).gateAdmitted).length : 0;
    return { n: absent + refused, counted: Array.isArray(src) || Array.isArray(jobs) };
  }, [daemon, surface]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    const onKey = (e) => {
      const slash = e.key === "/" && !e.metaKey && !e.ctrlKey && !e.altKey;
      const k = (e.key === "k" || e.key === "K") && (e.metaKey || e.ctrlKey);
      if (e.key === "Escape" && menu) { setMenu(false); return; }
      if (!slash && !k) return;
      const t = e.target;
      const typing = t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.tagName === "SELECT" || t.isContentEditable);
      if (slash && typing) return;
      e.preventDefault();
      box.current?.focus();
      box.current?.select();
      setOpen(true);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [menu]);

  useEffect(() => {
    if (!menu) return undefined;
    const onDown = (e) => { if (menuRef.current && !menuRef.current.contains(e.target)) setMenu(false); };
    document.addEventListener("mousedown", onDown);
    return () => document.removeEventListener("mousedown", onDown);
  }, [menu]);

  useEffect(() => { setActive(0); }, [query, open]);

  const choose = useCallback((item) => {
    if (!item) return;
    setOpen(false);
    setQuery("");
    announce(`Opening ${item.label} — ${kindWord(item.kind)}`);
    if (item.kind === "surface") go(item.key);
    else location.hash = item.href;
    box.current?.blur();
  }, [go, announce]);

  const onKeyDown = (e) => {
    if (e.key === "ArrowDown") { e.preventDefault(); setOpen(true); setActive((i) => Math.min(results.length - 1, i + 1)); }
    else if (e.key === "ArrowUp") { e.preventDefault(); setActive((i) => Math.max(0, i - 1)); }
    else if (e.key === "Enter") { e.preventDefault(); if (open) choose(results[active]); }
    else if (e.key === "Escape") { e.preventDefault(); setOpen(false); setQuery(""); box.current?.blur(); }
  };

  useEffect(() => {
    if (!open || !listRef.current) return;
    listRef.current.querySelector(`[data-index="${active}"]`)?.scrollIntoView?.({ block: "nearest" });
  }, [active, open]);

  const listId = "palette-list";
  const activeId = open && results[active] ? `palette-opt-${active}` : undefined;

  return (
    <header className="topbar">
      <div className="topbar-left">
        <a className="topbar-home" href={hashForSurface("home")} aria-label="decentralized.cloud console home">
          <Lockup />
        </a>
        {/* THE SERVICES GRID. Every surface, by group, in one panel — the console's
            "all services" menu. Unwired surfaces wear the dashed mark here too. */}
        <div className="services" ref={menuRef}>
          <button
            type="button"
            id="services-button"
            className="bar-btn"
            aria-label="All surfaces"
            aria-haspopup="true"
            aria-expanded={menu}
            aria-controls="services-menu"
            onClick={() => setMenu((v) => !v)}
          >
            <IconGrid />
          </button>
          {menu && (
            <div id="services-menu" className="services-menu" role="dialog" aria-label="All surfaces">
              <div className="services-head">
                <span className="services-title">All surfaces</span>
                <a className="entry-name" href={hashForSurface("catalog")} onClick={() => setMenu(false)}>All resources →</a>
                <button type="button" className="bar-btn services-close" aria-label="Close" onClick={() => setMenu(false)}><IconClose /></button>
              </div>
              <div className="services-groups">
                {GROUPS.map((g) => {
                  const list = SURFACES.filter((s) => s.group === g.id);
                  if (!list.length) return null;
                  return (
                    <div key={g.id} className="services-group">
                      <div className="services-eyebrow">{g.label || "Console"}</div>
                      <ul>
                        {list.map((s) => (
                          <li key={s.id}>
                            <a href={hashForSurface(s.id)} onClick={() => { setMenu(false); go(s.id); }}
                              {...(s.id === surface ? { "aria-current": "page" } : {})}>
                              <span className="rail-icon" aria-hidden="true"><SurfaceIcon id={s.id} /></span>
                              {s.label}
                              {!s.wired && <><span className="rail-mark" aria-hidden="true" /><span className="sr-only"> — designed, not connected</span></>}
                            </a>
                          </li>
                        ))}
                      </ul>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      </div>

      <div className="console-search palette" role="search">
        <span className="search-lens" aria-hidden="true"><IconSearch /></span>
        <input
          ref={box}
          id="console-search"
          className="console-search-box"
          type="search"
          role="combobox"
          value={query}
          onChange={(e) => { setQuery(e.target.value); setOpen(true); }}
          onFocus={() => setOpen(true)}
          onBlur={() => setTimeout(() => setOpen(false), 120)}
          onKeyDown={onKeyDown}
          placeholder="Search"
          aria-label="Search surfaces and what this browser has already read from the daemon. Nothing is fetched to answer a keystroke."
          aria-describedby="console-search-scope"
          aria-expanded={open}
          aria-controls={listId}
          aria-autocomplete="list"
          aria-activedescendant={activeId}
          autoComplete="off"
          spellCheck="false"
        />
        <span className="search-key mono" aria-hidden="true">[/]</span>
        {/* The scope line lives inside the results pop-over while it is open, and is
            read to a screen reader (never painted) while it is closed: under a 48px bar
            there is no room for a second line, and a line that clips is a line that lies. */}
        {!open && <span id="console-search-scope" className="sr-only">{scope}</span>}
        {open && (
        <div className="palette-pop">
        <span id="console-search-scope" className="console-search-scope mono">
          {query.trim() ? `${results.length} match${results.length === 1 ? "" : "es"} · ${scope}` : scope}
        </span>
          <ul id={listId} ref={listRef} className="palette-list" role="listbox" aria-label="Results">
            {results.length === 0 && (
              <li className="palette-empty meta" role="option" aria-selected="false" aria-disabled="true">
                nothing matches "{query}" among {scope}
              </li>
            )}
            {results.map((r, i) => (
              <li
                key={`${r.kind}:${r.key}`}
                id={`palette-opt-${i}`}
                data-index={i}
                role="option"
                aria-selected={i === active}
                className={`palette-opt${i === active ? " is-active" : ""}`}
                onMouseDown={(e) => { e.preventDefault(); choose(r); }}
                onMouseEnter={() => setActive(i)}
              >
                <span className="palette-kind mono">{kindWord(r.kind)}</span>
                <span className={`palette-label${r.kind === "surface" || r.kind === "category" ? "" : " mono"}`}>{r.label}</span>
                <span className="palette-hint meta">{r.hint}</span>
              </li>
            ))}
          </ul>
        </div>
        )}
      </div>

      <div className="topbar-status">
        <a className="bar-btn" href={hashForSurface("api")} aria-label="API — what this surface may ask the daemon" title="API"><IconTerminal /></a>
        <a className="bar-btn bar-bell" href={hashForSurface("home")} aria-label={attention.counted ? `${attention.n} things need a look` : "Needs a look — nothing read yet"} title="Needs a look">
          <IconBell />
          {attention.counted && attention.n > 0 && <span className="bar-badge mono" aria-hidden="true">{attention.n}</span>}
        </a>
        <a className="bar-btn" href={hashForSurface("settings")} aria-label="Help — what this surface is configured to do" title="Help"><IconHelp /></a>
        <a className="bar-btn" href={hashForSurface("settings")} aria-label="Settings" title="Settings"><IconGear /></a>
        {/* Where a region selector stands: the placement posture, which lives on the
            intent and is not set here. Where the account stands: the principal, which
            is a wallet this face does not hold. Each is a door, drawn as the control. */}
        <a className="bar-menu topbar-posture" href={hashForSurface("placement")}>
          <span className="chip-long">Posture · on the intent</span>
          <span className="chip-short">Posture</span>
          <IconChevron />
        </a>
        <a className="bar-menu topbar-principal" href={hashForSurface("iam")}>
          <span className="chip-long">No wallet session</span>
          <span className="chip-short">No wallet</span>
          <IconChevron />
        </a>
      </div>
    </header>
  );
}

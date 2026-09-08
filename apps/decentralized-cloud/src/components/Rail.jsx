import { SURFACES, GROUPS, CATALOG_ANCHORS, hashForCategory } from "../logic/surfaces.mjs";
import { SurfaceIcon } from "./Icons.jsx";

// THE NAVIGATION PANEL — the console's left edge, behind the hamburger.
//
// A stranger from another cloud console reads the left panel before anything else: a
// product list, grouped, with the current one marked. This is that list, from the
// registry, in the registry's order — Home and Deploy first, then Workloads,
// Resources, Marketplace, Account, and the surface itself. Nothing here is a claim
// about the daemon; every button is a surface, and a surface that reads nothing says
// so on its own page and wears a dashed mark here.
//
// It stays a <nav> of <button>s with data-surface, because the gate walks exactly that
// — every registered surface must have a real visible box at every width once the
// panel is open, and the per-surface sweep clicks them by name. `aria-current="page"`
// marks the one open.
//
// OPEN AND CLOSED are the shell's state (`open`), toggled by the hamburger in the bar
// under the top bar — open by default on a desktop, closed by default on a phone. The
// panel is a panel, not a drawer over the page: closing it gives the surface the
// width, which is what a console user closes it for.
//
// THE CATALOGUE ANCHORS sit under "All resources" as links (not buttons: they are
// addresses of one surface, not surfaces), disclosed only while the catalogue is the
// open surface, each opening it at one category.
export default function Rail({ surface, go, category = null, open = true }) {
  return (
    <nav id="console-rail" className={`nav console-rail${open ? " is-open" : ""}`} aria-label="Surfaces" hidden={!open}>
      <div id="rail-groups" className="rail-groups">
        {GROUPS.map((g) => {
          const items = SURFACES.filter((s) => s.group === g.id);
          if (items.length === 0) return null;
          return (
            <div key={g.id} className="rail-group" role="group" aria-label={g.label || "Console"}>
              {g.label && <div className="rail-eyebrow">{g.label}</div>}
              {items.map((s) => (
                <div key={s.id} className="rail-item">
                  <button
                    type="button"
                    data-surface={s.id}
                    {...(s.id === surface ? { "aria-current": "page" } : {})}
                    onClick={() => go(s.id)}
                  >
                    <span className="rail-icon" aria-hidden="true"><SurfaceIcon id={s.id} /></span>
                    <span className="rail-label">{s.label}</span>
                    {!s.wired && (
                      <>
                        <span className="rail-mark" aria-hidden="true" />
                        <span className="sr-only"> — designed, not connected</span>
                      </>
                    )}
                  </button>
                  {s.id === "catalog" && surface === "catalog" && (
                    <ul className="rail-sub" aria-label="Resource categories">
                      {CATALOG_ANCHORS.map((a) => (
                        <li key={a.id}>
                          <a href={hashForCategory(a.id)} {...(category === a.id ? { "aria-current": "location" } : {})}>
                            {a.label}
                          </a>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              ))}
            </div>
          );
        })}
      </div>
    </nav>
  );
}

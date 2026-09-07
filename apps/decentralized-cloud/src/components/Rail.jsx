import { SURFACES, GROUPS } from "../logic/surfaces.mjs";

// THE PRODUCT RAIL — the console's left edge.
//
// A stranger from another cloud console reads the left rail before anything else: a
// product list, grouped, with the current one marked. This is that list, from the
// registry, in the registry's order. Nothing here is a claim about the daemon; every
// button is a surface, and a surface that reads nothing says so on its own page.
//
// It stays a <nav> of <button>s with data-surface, because the gate walks exactly that
// — every registered surface must have a real visible box at every width, and the
// per-surface sweep clicks them by name. `aria-current="page"` marks the one open.
//
// `matches` is the set of ids the search box currently allows; a button outside it is
// `hidden`, which removes it from the tab order too — a filtered-out surface should
// not be a tab stop a keyboard reader has to walk past.
//
// THE FOOT of the rail is where this console says which daemon it is a face of and
// what it may ask it — the place a console keeps its project and account line. The
// capability chip is GENERATED from the route table the proxy dispatches from, so
// adding a write changes it in the same edit; the gate compares the rendered text
// against the generator.
export default function Rail({ surface, go, matches, daemonHost, capabilityChip }) {
  return (
    <nav className="nav console-rail" aria-label="Surfaces">
      {GROUPS.map((g) => {
        const items = SURFACES.filter((s) => s.group === g.id);
        if (items.length === 0) return null;
        return (
          <div key={g.id} className="rail-group" role="group" aria-label={g.label || "Console"}>
            {g.label && <div className="rail-eyebrow">{g.label}</div>}
            {items.map((s) => (
              <button
                key={s.id}
                type="button"
                data-surface={s.id}
                hidden={matches ? !matches.has(s.id) : false}
                {...(s.id === surface ? { "aria-current": "page" } : {})}
                onClick={() => go(s.id)}
              >
                <span className="rail-label">{s.label}</span>
                {/* An unwired surface is marked in the rail too, not only on its own
                    page: a reader deciding where to click is owed the fact before the
                    click, not after. */}
                {!s.wired && (
                  <>
                    <span className="rail-mark" aria-hidden="true" />
                    <span className="sr-only"> — designed, not connected</span>
                  </>
                )}
              </button>
            ))}
          </div>
        );
      })}
      <div className="rail-foot">
        <span className="meta" id="daemon-label">daemon {daemonHost}</span>
        <span className="chip muted" id="refresh-chip">
          <span className="dot" />{capabilityChip}
        </span>
      </div>
    </nav>
  );
}

// Applications surface — source-owned React, source-derived from the product-ui serve
// augmentation (the "Applications" sidebar section + the applications catalog modal). Same route
// anatomy — a favorites strip plus a categorized catalog browser (category rail → grouped rows →
// detail card) — and the same dark visual system. The only change is the data boundary: a static
// IOI-owned catalog (the daemon owns no applications/favorites plane yet) and honest client-only
// favorites in localStorage, instead of a server-rendered fetch. See applicationsModel.ts.
import { useMemo, useState } from "react";
import { LayoutGrid, Search, Star, X, ChevronRight, FileText } from "lucide-react";
import "./Applications.css";
import {
  ALL_CATEGORY,
  CATEGORIES,
  CATALOG,
  categoryCount,
  filterCatalog,
  getApp,
  groupByCategory,
  loadFavorites,
  saveFavorites,
  toggleFavorite,
  type AppEntry,
} from "./applicationsModel";

function AppIcon({ app, size = 28 }: { app: AppEntry; size?: number }) {
  return (
    <span
      className="ap-icon"
      aria-hidden="true"
      style={{ background: app.color, width: size, height: size, fontSize: size <= 28 ? 11 : 14 }}
    >
      {app.glyph}
    </span>
  );
}

export function ApplicationsView() {
  const [favorites, setFavorites] = useState<string[]>(() => loadFavorites());
  const [category, setCategory] = useState<string>(ALL_CATEGORY);
  const [query, setQuery] = useState("");
  const [activeId, setActiveId] = useState<string | null>(null);

  const filtered = useMemo(() => filterCatalog(category, query), [category, query]);
  const groups = useMemo(() => groupByCategory(filtered), [filtered]);
  const active = getApp(activeId) || filtered[0] || null;
  const favoriteApps = favorites.map(getApp).filter((a): a is AppEntry => a !== null);

  function flip(id: string) {
    const next = toggleFavorite(favorites, id);
    setFavorites(next);
    saveFavorites(next);
  }

  return (
    <div className="ap-wrap">
      <div className="ap-brand">IOI Hypervisor</div>
      <h1 className="ap-h1">Applications</h1>
      <p className="ap-sub">
        Launch and pin the workspace applications. Favorite the apps you use most — they surface here
        and in the rail. Browse the full catalog below by category or search.
      </p>

      {/* Favorites strip — empty by default (no daemon plane owns favorites yet). */}
      <section className="ap-favsec" data-testid="applications-favorites">
        <h2 className="ap-h2">
          <Star size={13} /> Favorites
        </h2>
        {favoriteApps.length === 0 ? (
          <div className="ap-empty" data-testid="applications-empty">
            Your favorite apps will appear here
          </div>
        ) : (
          <div className="ap-favgrid">
            {favoriteApps.map((app) => (
              <button
                key={app.id}
                className="ap-favcard"
                data-testid="app-card"
                onClick={() => setActiveId(app.id)}
                title={app.description}
              >
                <AppIcon app={app} />
                <span className="ap-favname">{app.name}</span>
                <span
                  className="ap-favstar is-on"
                  role="button"
                  aria-label={`Unfavorite ${app.name}`}
                  onClick={(e) => {
                    e.stopPropagation();
                    flip(app.id);
                  }}
                >
                  <Star size={14} fill="currentColor" />
                </span>
              </button>
            ))}
          </div>
        )}
      </section>

      {/* Catalog browser — category rail · grouped rows · detail card. */}
      <section className="ap-catalog" data-testid="applications-catalog">
        <div className="ap-cathead">
          <LayoutGrid size={13} /> <span>Catalog</span>
          <label className="ap-search">
            <Search size={15} />
            <input
              data-testid="applications-search"
              value={query}
              placeholder="Search for applications…"
              onChange={(e) => setQuery(e.target.value)}
            />
            {query && (
              <button className="ap-searchclear" aria-label="Clear search" onClick={() => setQuery("")}>
                <X size={14} />
              </button>
            )}
          </label>
        </div>

        <div className="ap-catbody">
          <nav className="ap-catrail" aria-label="Application categories">
            {[ALL_CATEGORY, ...CATEGORIES].map((cat) => {
              const count = cat === ALL_CATEGORY ? CATALOG.length : categoryCount(cat);
              return (
                <button
                  key={cat}
                  className="ap-cat"
                  data-active={String(category === cat)}
                  data-testid="applications-category"
                  onClick={() => setCategory(cat)}
                >
                  <span>{cat}</span>
                  <span className="ap-catcount">{count}</span>
                </button>
              );
            })}
          </nav>

          <main className="ap-list">
            {groups.length === 0 ? (
              <div className="ap-nodetail" data-testid="applications-no-results">
                No applications match this search.
              </div>
            ) : (
              groups.map((g) => (
                <div className="ap-group" key={g.category}>
                  <h3 className="ap-grouptitle">{g.category}</h3>
                  {g.apps.map((app) => {
                    const fav = favorites.includes(app.id);
                    return (
                      <button
                        key={app.id}
                        className="ap-row"
                        data-testid="app-card"
                        data-selected={String(active?.id === app.id)}
                        onClick={() => setActiveId(app.id)}
                      >
                        <AppIcon app={app} />
                        <span className="ap-rowcopy">
                          <span className="ap-rowtitle">{app.name}</span>
                          <span className="ap-rowdesc">{app.description}</span>
                        </span>
                        <span
                          className={"ap-rowstar" + (fav ? " is-on" : "")}
                          role="button"
                          aria-label={fav ? `Unfavorite ${app.name}` : `Favorite ${app.name}`}
                          data-testid="favorite-toggle"
                          onClick={(e) => {
                            e.stopPropagation();
                            flip(app.id);
                          }}
                        >
                          <Star size={15} fill={fav ? "currentColor" : "none"} />
                        </span>
                      </button>
                    );
                  })}
                </div>
              ))
            )}
          </main>

          <aside className="ap-detail">
            {active ? (
              <div className="ap-detailcard" data-testid="applications-detail">
                <div className="ap-detailtop">
                  <AppIcon app={active} size={44} />
                  <button
                    className={"ap-favbtn" + (favorites.includes(active.id) ? " is-on" : "")}
                    onClick={() => flip(active.id)}
                  >
                    <Star size={14} fill={favorites.includes(active.id) ? "currentColor" : "none"} />
                    {favorites.includes(active.id) ? "Favorited" : "Favorite"}
                  </button>
                </div>
                <h2 className="ap-detailtitle">{active.name}</h2>
                <div className="ap-detailcat">{active.category}</div>
                <p className="ap-detaildesc">{active.description}</p>
                <button className="ap-detaillink">
                  <FileText size={14} /> Documentation <ChevronRight size={13} />
                </button>
              </div>
            ) : (
              <div className="ap-nodetail">Select an application to see details.</div>
            )}
          </aside>
        </div>
      </section>
    </div>
  );
}

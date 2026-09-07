import { useEffect, useMemo, useState } from "react";
import { useSurfaceRead } from "../useSurfaceRead.js";
import { intentRef } from "../logic/read.mjs";
import { classify, stamp, duration } from "../logic/classify.mjs";
import { latestBatch } from "../logic/batches.mjs";
import { populationLine } from "../logic/population.mjs";
import { resolveCatalog } from "../logic/catalog.mjs";
import { hashForSurface } from "../logic/surfaces.mjs";
import { Chip, Waiting, Failure, Kept, Eyebrow } from "../components/Bits.jsx";
import Hero from "../components/Hero.jsx";

// ALL RESOURCES — the landing. The decentralized counterpart of a console's "all
// services by category" page: every resource class this router can be asked for,
// grouped the way the canon groups them, and under each the venues and networks that
// can supply it, each with the state the daemon last persisted for it.
//
// It exists because a stranger arriving at a table of prices could not say what the
// product was. This page answers that in the first second, from the daemon: here is
// everything it can route, and here is what is answering right now.

const money = (n) => (typeof n === "number" ? `$${n.toFixed(4)}/hr` : null);

// `category` is the catalogue anchor an address opened this at (#/catalog/compute),
// or null for the whole catalogue. An anchor view is the same read and the same
// tables, narrowed to one category, with its own heading and a way back; the hero
// belongs to the whole catalogue and is not drawn on an anchor.
export default function Catalog({ announce, category = null }) {
  const sources = useSurfaceRead("sources", "/api/candidate-sources");
  const cands = useSurfaceRead(
    "candidates",
    `/api/candidates?intent_ref=${encodeURIComponent(intentRef())}&latest=true`
  );
  const [filter, setFilter] = useState("");

  // Live counts per venue come from the ONE live rule, over the latest batch only.
  // The catalog module is not allowed to decide liveness; it is handed the result.
  const liveByVenue = useMemo(() => {
    const { latest } = latestBatch(cands.data?.candidates);
    const map = new Map();
    for (const c of latest.items) {
      if (!classify(c).live) continue;
      const k = c.provider_kind;
      const cur = map.get(k) || { count: 0, cheapest: null };
      cur.count += 1;
      const p = c.quote?.usd_per_hour;
      if (typeof p === "number" && (cur.cheapest === null || p < cur.cheapest)) cur.cheapest = p;
      map.set(k, cur);
    }
    return map;
  }, [cands.data]);

  const sourceList = Array.isArray(sources.data?.sources) ? sources.data.sources : [];
  const { categories, counts } = useMemo(
    () => resolveCatalog(sourceList, liveByVenue),
    [sourceList, liveByVenue]
  );

  const liveTotal = [...liveByVenue.values()].reduce((a, v) => a + v.count, 0);
  const venuesQuoting = liveByVenue.size;
  const considered = typeof cands.data?.selection?.considered === "number" ? cands.data.selection.considered : null;

  const shownCategories = category ? categories.filter((c) => c.id === category) : categories;
  const title = category ? (shownCategories[0]?.title || category) : "All resources";

  useEffect(() => {
    if (sources.phase === "first") return;
    announce(`${title} — ${counts.quoting} quoting, ${counts.answering} answering, ${counts.planned} not yet a source`);
  }, [sources.phase, title, counts.quoting, counts.answering, counts.planned, announce]);

  // The heading: the hero's statement is the page's h1 on the whole catalogue, so
  // the catalogue's own heading is an h2 there; on an anchor there is no hero and
  // the category is the h1.
  const Heading = category ? "h1" : "h2";

  // THE HERO PAINTS FIRST, AND THE CATALOG WAITS BENEATH IT. The sources read runs
  // about half a minute and the catalog needs it; the hero needs the candidates read,
  // which takes about a second. Gating the whole landing on the slow read put a
  // stranger in front of a waiting paragraph for the thirty seconds that decide
  // whether they believe the product is real.
  if (sources.phase === "first") {
    return (
      <div className="stack catalog-page">
        {!category && <Hero />}
        {/* The heading is an h2 here: the hero's statement is the page's one h1, and a
            waiting block that minted a second one would give the page two. */}
        <Heading className="catalog-h">{title}</Heading>
        <Waiting
          what="the list of candidate sources — the quote above is already live; the catalog is what is still coming"
          title={null}
          willShow={
            "Every kind of infrastructure this router can be asked for — compute, storage, " +
            "networking, runtimes, confidential compute — and, under each, every venue or " +
            "network that can supply it, with whether it is quoting real prices right now, " +
            "connected without an adapter, or not yet a source at all."
          }
          why="The daemon is asked for the state it last persisted for each source."
        />
      </div>
    );
  }

  const q = filter.trim().toLowerCase();
  const matches = (text) => !q || String(text).toLowerCase().includes(q);

  const view = (
    <div className="stack catalog-page">
      {!category && <Hero />}
      <div className="catalog-head">
        <div className="stack catalog-title">
          {category && (
            <p className="meta">
              <a className="entry-name" href={hashForSurface("catalog")}>All resources</a> · {title}
            </p>
          )}
          <Heading className="catalog-h">{title}</Heading>
          <p className="prose catalog-lede">
            {category
              ? `Every ${title.toLowerCase()} class the router can be asked for, and every venue or network that can supply it, with the state each supply source is in right now — read from the daemon, not from a brochure.`
              : "One request, any venue. This is everything the router can place work on, by category, with the state each supply source is in right now — read from the daemon, not from a brochure."}
          </p>
        </div>
        <div className="stack catalog-now">
          <Eyebrow>right now</Eyebrow>
          <p className="mono catalog-line">
            {populationLine({
              live: liveTotal,
              venues: venuesQuoting,
              // `selection.considered` is the HELD set — every candidate ever swept for
              // this intent — and it was handed to the advisory's "considered" slot,
              // so the catalog said "6,727 considered by the advisory" against
              // Placement's 47. Right label module, wrong slot; the verifier caught it.
              held: considered ?? undefined,
              sources: counts.sources,
            })}
          </p>
          {/* ON AN ANCHOR THE COUNTS ARE THE CATEGORY'S. The whole-catalogue line
              counted every entry while the page showed one family — a Compute page
              saying "14 answering" over four classes. The population line above stays:
              it names its sets, which are the intent's and not the page's. */}
          <p className="meta">
            {category
              ? `${shownCategories.reduce((n, c) => n + c.classes.length, 0)} classes · ` +
                `${shownCategories.reduce((n, c) => n + c.classes.reduce((m, cls) => m + cls.entries.length, 0), 0)} venues or networks · ` +
                // The live count comes from the candidates read, which lands separately
                // from the sources read; before it lands the page said "0 quoting",
                // which is a number, not a wait. A 390 capture caught it.
                (cands.data
                  ? `${shownCategories.reduce((n, c) => n + c.classes.reduce((m, cls) => m + cls.entries.filter((e) => e.state.live).length, 0), 0)} quoting live prices for this intent · `
                  : "live prices: asking the daemon · ")
              : `${counts.quoting} quoting · ${counts.answering} answering · ${counts.planned} not yet a source · `}
            read at {stamp(sources.at)} in {duration(sources.ms)}
          </p>
        </div>
      </div>

      <div className="catalog-tools">
        <label className="field catalog-filter">
          <span className="field-label">find a resource or venue</span>
          <input
            className="field-box"
            type="search"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="gpu, akash, archive, dns…"
            aria-label="Filter the catalog"
          />
        </label>
        <p className="meta">
          green means a venue is quoting live prices for this intent; everything else is grey.
        </p>
      </div>

      <Eyebrow>{category ? `${title} — resource classes` : "resources by category"}</Eyebrow>
      <div className="catalog">
        {shownCategories.map((cat) => {
          const rows = cat.classes.flatMap((cls) =>
            cls.entries
              .filter((e) => matches(`${cls.label} ${cls.id} ${e.name} ${e.kind} ${e.state.word}`))
              .map((e) => ({ cls, e }))
          );
          if (rows.length === 0) return null;
          return (
            <section key={cat.id} className="cat" aria-labelledby={`cat-${cat.id}`}>
              <div className="cat-head">
                <h2 id={`cat-${cat.id}`}>{cat.title}</h2>
                <span className="meta">{cat.classes.length} classes</span>
              </div>
              <div className="table-scroll">
                <table className="table t-catalog">
                  <caption className="sr-only">{cat.title} — resource classes and the venues that can supply them</caption>
                  <thead>
                    <tr>
                      <th scope="col">Resource</th>
                      <th scope="col">Venue or network</th>
                      <th scope="col">State</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map(({ cls, e }, i) => {
                      const first = i === 0 || rows[i - 1].cls.id !== cls.id;
                      return (
                        <tr key={`${cls.id}:${e.name}`} className="trow">
                          <th scope="row" className="cls-cell">
                            {first ? (
                              <>
                                <div className="cls-name">{cls.label}</div>
                                <div className="meta mono">{cls.id}</div>
                              </>
                            ) : null}
                          </th>
                          <td>
                            <a className="entry-name" href={hashForSurface(e.state.chip === "live" ? "candidates" : "sources")}>
                              {e.name}
                            </a>
                            <div className="meta">{e.kind}</div>
                          </td>
                          <td className="entry-state">
                            <Chip kind={e.state.chip}>{e.state.word}</Chip>
                            {e.state.live && (
                              <div className="meta">
                                {e.state.live.count} live · cheapest {money(e.state.live.cheapest)}
                              </div>
                            )}
                            {!e.state.live && e.state.evidence && (
                              <div className="meta entry-evidence">{e.state.evidence}</div>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </section>
          );
        })}
      </div>

      <div className="catalog-foot">
        <a className="entry-name" href={hashForSurface("candidates")}>Live prices →</a>
        <a className="entry-name" href={hashForSurface("job")}>Submit a job →</a>
        <a className="entry-name" href={hashForSurface("receipts")}>Receipts →</a>
      </div>
    </div>
  );

  if (sources.phase === "failed") {
    return (
      <div className="stack" style={{ gap: "16px" }}>
        <Failure result={sources.failure} />
        {sources.data && <Kept at={sources.at}>{view}</Kept>}
      </div>
    );
  }
  return sources.stale ? <Kept at={sources.at}>{view}</Kept> : view;
}

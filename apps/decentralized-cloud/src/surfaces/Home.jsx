import { useEffect, useMemo } from "react";
import { useSurfaceRead } from "../useSurfaceRead.js";
import { intentRef } from "../logic/read.mjs";
import { stamp, duration, classify } from "../logic/classify.mjs";
import { latestBatch, summarise } from "../logic/batches.mjs";
import { jobView } from "../logic/job-door.mjs";
import { SURFACES, hashForSurface, hashForJob } from "../logic/surfaces.mjs";
import { recentVisits } from "../logic/visited.mjs";
import { Chip, Failure, Unwired, breakable } from "../components/Bits.jsx";
import Freshness from "../components/Freshness.jsx";
import Widget from "../components/Widget.jsx";
import { SurfaceIcon, IconInfo } from "../components/Icons.jsx";

// CONSOLE HOME — the welcome page, in the shape a console user's eye already knows.
//
// A grid of widgets, each a card with a bold title, an Info link, an outlined action
// pill and a centred footer door: Recently visited, Welcome, Health, Cost and usage,
// Live prices, Recent activity, Sources. What differs from the reference is the
// substance: every figure is a daemon read with its route and read time under it, a
// widget whose read has not landed says "asking" and carries no digit, and a widget
// the daemon cannot feed yet is drawn with an Unwired placeholder where its figure
// would go. Nothing here is a total the daemon did not send.

const label = (id) => SURFACES.find((s) => s.id === id)?.label || id;
const price = (usd) => `$${usd.toFixed(4)}`;

// A widget's read line: the route it read and how long that took, or the fact that
// it is still asking with the measured cost of the read.
const readLine = (state, route, cost) => {
  if (state.phase === "first") return `asking ${route} — ${cost}`;
  if (state.phase === "failed" && !state.data) return `${route} — the read failed; see the fault above`;
  return `${route} · read at ${stamp(state.at)} in ${duration(state.ms)}${state.stale ? " · a newer read is in flight" : ""}`;
};

export default function Home({ announce }) {
  const intent = intentRef();
  const sources = useSurfaceRead("sources", "/api/candidate-sources");
  const jobs = useSurfaceRead("jobs", "/api/jobs");
  const budgets = useSurfaceRead("budgets", "/api/budgets");
  const cands = useSurfaceRead("candidates", `/api/candidates?intent_ref=${encodeURIComponent(intent)}&latest=true`);

  const sourceList = Array.isArray(sources.data?.sources) ? sources.data.sources : [];
  const quoting = sourceList.filter((s) => s.state === "live_quote_source");
  const absent = sourceList.filter((s) => s.state === "candidate_source_unavailable");
  const answering = sourceList.filter((s) => !quoting.includes(s) && !absent.includes(s));

  const allJobs = (Array.isArray(jobs.data?.jobs) ? jobs.data.jobs : []).map(jobView);
  const productJobs = allJobs.filter((j) => !j.gateAdmitted)
    .sort((a, b) => (Date.parse(b.createdAt || "") || -Infinity) - (Date.parse(a.createdAt || "") || -Infinity));
  const recentJobs = productJobs.slice(0, 5);
  const hiddenJobs = allJobs.length - productJobs.length;
  const refusedJobs = productJobs.filter((j) => /^refused/.test(j.state || ""));
  const placedJobs = productJobs.filter((j) => j.state === "placed");

  const budgetList = (budgets.data?.budgets || []).filter((b) => b.scope === "external_spend");
  const budget = budgetList[0] || null;

  const { cheapest, live, venues } = useMemo(() => {
    const { latest } = latestBatch(cands.data?.candidates);
    return summarise(latest.items);
  }, [cands.data]);
  const notLive = useMemo(() => {
    const { latest } = latestBatch(cands.data?.candidates);
    return latest.items.filter((c) => !classify(c).live).length;
  }, [cands.data]);
  const byVenue = venues.map((v) => {
    const items = live.filter((c) => c.provider_kind === v);
    return { venue: v, n: items.length, best: items[0] };
  });

  const visits = recentVisits().filter((v) => v.id !== "home");

  useEffect(() => {
    if (sources.phase === "first" && jobs.phase === "first") return;
    const allDown = [sources, jobs, budgets, cands].every((r) => r.phase === "failed" && !r.data);
    if (allDown) { announce("Console Home — the daemon did not answer any read; nothing to count"); return; }
    announce(
      `Console Home — ${quoting.length} sources quoting, ${absent.length} unavailable, ${productJobs.length} job records, ` +
      `${live.length} candidates live right now`
    );
  }, [sources.phase, jobs.phase, budgets.phase, cands.phase, sources.data, jobs.data, budgets.data, cands.data, quoting.length, absent.length, productJobs.length, live.length, announce]);

  // A health row: the label, the count large, the window it was counted over. The
  // count is a digit only once its read has landed; before that the row says asking.
  const healthRow = (state, what, n, over, href) => (
    <li className="hrow">
      <a className="hrow-link" href={href}>
        <span className="hrow-what">{what}</span>
        <span className="hrow-n mono">{state.phase === "first" ? <span className="meta">asking</span> : state.phase === "failed" && !state.data ? <span className="meta">no answer</span> : n}</span>
        <span className="hrow-over meta">{over}</span>
      </a>
    </li>
  );

  return (
    <div className="stack home">
      <div className="home-head">
        <h1 className="home-title">Console Home <a className="widget-info" href={hashForSurface("settings")}>Info</a></h1>
        <p className="meta home-intent">intent <span className="mono">{intent}</span></p>
      </div>

      <div className="home-grid">
        {/* RECENTLY VISITED — this browser only, and it says so. */}
        <Widget id="w-visited" title="Recently visited" info={hashForSurface("settings")} span={2}
          action={{ label: "All surfaces", href: hashForSurface("catalog") }}
          read="kept in this browser only — never sent anywhere">
          {visits.length > 0 ? (
            <ul className="visited-grid">
              {visits.map((v) => (
                <li key={v.id}>
                  <a className="visited-tile" href={hashForSurface(v.id)}>
                    <span className="visited-icon" aria-hidden="true"><SurfaceIcon id={v.id} /></span>
                    <span className="visited-name">{label(v.id)}</span>
                    <span className="meta">{stamp(v.at)}</span>
                  </a>
                </li>
              ))}
            </ul>
          ) : (
            <div className="empty">
              <p className="empty-title">No recently visited surfaces</p>
              <p className="empty-text">Explore one of these commonly visited surfaces.</p>
              <p className="empty-links">
                <a href={hashForSurface("job")}>Deploy</a>
                <a href={hashForSurface("candidates")}>Live prices</a>
                <a href={hashForSurface("receipts")}>Jobs &amp; receipts</a>
                <a href={hashForSurface("spend")}>Spend</a>
              </p>
            </div>
          )}
        </Widget>

        {/* WELCOME — the three doors a first visit needs. */}
        <Widget id="w-welcome" title="Welcome to decentralized.cloud" span={1}>
          <ul className="welcome">
            <li>
              <span className="welcome-icon" aria-hidden="true"><SurfaceIcon id="job" /></span>
              <div>
                <a className="welcome-link" href={hashForSurface("job")}>Deploy your first job</a>
                <p className="welcome-text">One envelope, human or agent: capacity, budget, deadline, receipt back. A dry run, nothing spent.</p>
              </div>
            </li>
            <li>
              <span className="welcome-icon" aria-hidden="true"><SurfaceIcon id="candidates" /></span>
              <div>
                <a className="welcome-link" href={hashForSurface("candidates")}>Read the live prices</a>
                <p className="welcome-text">Every venue quoting for this intent, cheapest first, each quote with the window it is still good for.</p>
              </div>
            </li>
            <li>
              <span className="welcome-icon" aria-hidden="true"><SurfaceIcon id="placement" /></span>
              <div>
                <a className="welcome-link" href={hashForSurface("placement")}>How placement decides</a>
                <p className="welcome-text">The daemon&rsquo;s advisory: one venue, the reason codes, how many were eligible of how many considered.</p>
              </div>
            </li>
          </ul>
        </Widget>

        {/* HEALTH — three counts, each a door, the way a console's health widget reads. */}
        <Widget id="w-health" title="Health" info={hashForSurface("sources")} span={1}
          footer={{ label: "Go to Sources & health", href: hashForSurface("sources") }}
          read={readLine(sources, "GET /api/candidate-sources", "27 to 61 s")}>
          {sources.phase === "failed" && <Failure result={sources.failure} />}
          <ul className="hrows">
            {healthRow(sources, "Sources unavailable", absent.length, "latest read · by name", hashForSurface("sources"))}
            {healthRow(jobs, "Jobs refused", refusedJobs.length, "all records", hashForSurface("receipts"))}
            {healthRow(cands, "Not live in the sweep", notLive, "latest sweep", hashForSurface("candidates"))}
          </ul>
        </Widget>

        {/* COST AND USAGE — budgets are real; settled spend has no route yet. */}
        <Widget id="w-cost" title="Cost and usage" info={hashForSurface("spend")} span={2}
          action={{ label: "Spend", href: hashForSurface("spend") }}
          footer={{ label: "Go to Spend", href: hashForSurface("spend") }}
          read={readLine(budgets, "GET /api/budgets", "under a second")}>
          {budgets.phase === "failed" && <Failure result={budgets.failure} />}
          {budget ? (
            <div className="cost">
              <div className="cost-figs">
                <div className="cost-fig">
                  <span className="cost-label">Spent</span>
                  <span className="cost-n mono">{budget.currency} {budget.spent ?? "—"}</span>
                </div>
                <div className="cost-fig">
                  <span className="cost-label">Remaining</span>
                  <span className="cost-n mono">{budget.currency} {budget.remaining ?? "—"}</span>
                </div>
                <div className="cost-fig">
                  <span className="cost-label">Budget</span>
                  <span className="cost-n mono">{budget.currency} {budget.limit ?? "—"}</span>
                </div>
              </div>
              <div className="budget-bar" role="img" aria-label={`${budget.spent ?? 0} of ${budget.limit ?? 0} ${budget.currency} spent`}>
                <div className="budget-spent" style={{ width: `${typeof budget.limit === "number" && budget.limit > 0 ? Math.min(100, ((budget.spent || 0) / budget.limit) * 100) : 0}%` }} />
              </div>
              <p className="meta">{budget.name || budget.budget_id} · external_spend{budgetList.length > 1 ? ` · ${budgetList.length - 1} more on Spend` : ""}</p>
            </div>
          ) : budgets.phase === "ready" ? (
            <p className="empty-text">The daemon holds no external_spend budget. Nothing has been drawn to stand in for one.</p>
          ) : budgets.phase === "first" ? (
            <p className="empty-text">Asking the daemon for its budgets.</p>
          ) : null}
          <Unwired
            would="settled provider spend by venue, each figure reconciled against a receipt"
            route="provider spend reconciliation — not on the capability table"
          />
        </Widget>

        {/* LIVE PRICES — the cheapest quote and the venues quoting, from the latest sweep. */}
        <Widget id="w-live" title="Live prices" info={hashForSurface("candidates")} span={2}
          action={{ label: "All live prices", href: hashForSurface("candidates") }}
          footer={{ label: "Go to Live prices", href: hashForSurface("candidates") }}
          read={readLine(cands, "GET /api/candidates?latest=true", "about a second")}>
          {cands.phase === "failed" && <Failure result={cands.failure} />}
          {cheapest ? (
            <div className="livebox">
              <div className="live-cheapest">
                <span className="cost-label">Cheapest live quote</span>
                <span className="live-price mono">{price(cheapest.quote.usd_per_hour)}<span className="live-unit"> / GPU · hour</span></span>
                <span className="live-venue">{cheapest.display_name || cheapest.provider_kind}{cheapest.region ? <span className="meta"> · {String(cheapest.region).replace(/^\s*,\s*/, "")}</span> : null}</span>
                <Freshness observedAt={cheapest.observed_at} expiresAt={cheapest.expires_at} size="row" />
              </div>
              <ul className="live-venues">
                {byVenue.map((v) => (
                  <li key={v.venue} className="live-venue-row">
                    <span className="mono">{v.venue}</span>
                    <span className="meta">{v.n} live</span>
                    <span className="mono live-venue-price">from {price(v.best.quote.usd_per_hour)}</span>
                  </li>
                ))}
                <li className="live-venue-row live-venue-total">
                  <span>{live.length} live · {notLive} not live</span>
                  <span />
                  <Chip kind="live">live_evidence</Chip>
                </li>
              </ul>
            </div>
          ) : cands.phase === "ready" ? (
            <p className="empty-text">No candidate in the latest sweep passes the live rule, and no price has been invented to stand here.</p>
          ) : cands.phase === "first" ? (
            <p className="empty-text">Asking the daemon for the latest sweep — about a second.</p>
          ) : null}
        </Widget>

        {/* RECENT ACTIVITY — the newest job records, the way Jobs & receipts lists them. */}
        <Widget id="w-activity" title="Recent activity" info={hashForSurface("receipts")} count={productJobs.length || undefined} span={4}
          action={{ label: "Jobs & receipts", href: hashForSurface("receipts") }}
          footer={{ label: "Go to Jobs & receipts", href: hashForSurface("receipts") }}
          read={readLine(jobs, "GET /api/jobs", "under a second") + (hiddenJobs > 0 ? ` · ${hiddenJobs} gate-admitted proposals hidden, as on Jobs & receipts` : "")}>
          {jobs.phase === "failed" && <Failure result={jobs.failure} />}
          {recentJobs.length > 0 ? (
            <div className="table-scroll">
              <table className="table t-activity">
                <caption className="sr-only">The newest job records the daemon holds</caption>
                <thead>
                  <tr>
                    <th scope="col">Job <span className="meta">· newest first</span></th>
                    <th scope="col">State</th>
                    <th scope="col">Venue</th>
                    <th scope="col">Receipts</th>
                  </tr>
                </thead>
                <tbody>
                  {recentJobs.map((j) => (
                    <tr key={j.id} className="trow">
                      <th scope="row">
                        <a className="entry-name mono" style={{ fontSize: "13px" }} href={hashForJob(j.id)}>{j.id}</a>
                        <div className="meta">{stamp(j.createdAt)}</div>
                      </th>
                      <td><Chip kind="muted">{j.state || "state absent"}</Chip></td>
                      <td className="mono basis">{j.venue || <span className="meta">none chosen</span>}</td>
                      <td className="basis">
                        {j.receipts.length > 0
                          ? `${j.receipts.length} receipt${j.receipts.length === 1 ? "" : "s"}: ${j.receipts.map((r) => r.kind || "unnamed").join(", ")}`
                          : <span className="meta">none — admitted or placed, not run</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : jobs.phase === "ready" ? (
            <p className="empty-text">
              {allJobs.length === 0 ? "The daemon holds no job records." : "Every job record the daemon holds was admitted by this surface's own verification; no product job has been submitted yet."}
            </p>
          ) : jobs.phase === "first" ? (
            <p className="empty-text">Asking the daemon for its job records.</p>
          ) : null}
          {placedJobs.length > 0 && <p className="meta">{placedJobs.length} placed · {refusedJobs.length} refused · {productJobs.length} product records</p>}
        </Widget>

        {/* SOURCES — which candidate sources answered, from the same read Sources & health renders in full. */}
        <Widget id="w-sources" title="Sources" info={hashForSurface("sources")} count={sourceList.length || undefined} span={2}
          action={{ label: "Sources & health", href: hashForSurface("sources") }}
          footer={{ label: "Go to Sources & health", href: hashForSurface("sources") }}
          read={readLine(sources, "GET /api/candidate-sources", "27 to 61 s")}>
          {sourceList.length > 0 ? (
            <>
              <p className="meta">{quoting.length} quoting · {answering.length} answering without a price · {absent.length} unavailable</p>
              <div className="table-scroll">
                <table className="table t-health">
                  <caption className="sr-only">Candidate sources and the state the daemon last persisted for each</caption>
                  <thead>
                    <tr><th scope="col">Source</th><th scope="col">State</th></tr>
                  </thead>
                  <tbody>
                    {[...quoting, ...answering].map((s) => (
                      <tr key={s.source || s.state} className="trow">
                        <th scope="row" className="mono">{breakable(s.source || "source not named")}</th>
                        <td><Chip kind={s.state === "live_quote_source" ? "live" : "muted"}>{s.state || "state absent"}</Chip></td>
                      </tr>
                    ))}
                    {absent.length > 0 && (
                      <tr className="trow">
                        <th scope="row"><Chip kind="absent">{absent.length} unavailable</Chip></th>
                        <td className="basis">
                          <span className="mono health-absent-names">{absent.map((s) => s.source || "unnamed").join(" · ")}</span>
                          <span className="meta"> · candidate_source_unavailable, by name</span>
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </>
          ) : sources.phase === "first" ? (
            <p className="empty-text">Each source is asked in turn; a full round has been measured at 27 to 61 seconds. Nothing is drawn until it answers.</p>
          ) : null}
        </Widget>

        {/* RESOURCES — the four families, as doors into the catalogue. */}
        <Widget id="w-resources" title="Resources" info={hashForSurface("catalog")} span={2}
          action={{ label: "All resources", href: hashForSurface("catalog") }}
          footer={{ label: "Go to All resources", href: hashForSurface("catalog") }}>
          <ul className="res-grid">
            {[["compute", "Compute", "VMs, microVMs, containers, GPU runtime"], ["storage", "Storage", "object, block, archive, content-addressed"], ["network", "Networking", "address leases, ingress, DNS, TLS"], ["runtime", "Runtime", "model servers, browsers, workbenches"]].map(([id, name, what]) => (
              <li key={id}>
                <a className="res-tile" href={`#/catalog/${id}`}>
                  <span className="visited-icon" aria-hidden="true"><SurfaceIcon id={id === "compute" ? "catalog" : id === "runtime" ? "placement" : id} /></span>
                  <span className="visited-name">{name}</span>
                  <span className="meta">{what}</span>
                </a>
              </li>
            ))}
          </ul>
          <p className="meta"><IconInfo /> the state of every venue under each family is read live from the daemon on the catalogue</p>
        </Widget>
      </div>
    </div>
  );
}

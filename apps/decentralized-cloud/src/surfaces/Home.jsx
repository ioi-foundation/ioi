import { useEffect, useMemo } from "react";
import { useSurfaceRead } from "../useSurfaceRead.js";
import { intentRef } from "../logic/read.mjs";
import { stamp, duration, classify } from "../logic/classify.mjs";
import { latestBatch, summarise } from "../logic/batches.mjs";
import { jobView } from "../logic/job-door.mjs";
import { SURFACES, hashForSurface } from "../logic/surfaces.mjs";
import { recentVisits } from "../logic/visited.mjs";
import { Chip, Failure, Eyebrow, Unwired, breakable } from "../components/Bits.jsx";
import Freshness from "../components/Freshness.jsx";

// HOME — the console's welcome page.
//
// The shape a stranger from another console expects on landing: a row of quick
// actions, then widgets — health, cost and usage, recent activity, the thing that is
// live right now, and where they were last. Every widget names the route it reads and
// the time the read took; a widget whose read has not landed says "asking" with the
// measured cost of that read, and a widget the daemon cannot feed yet is drawn with an
// Unwired placeholder where its figure would go. Nothing here is a total the daemon
// did not send: the counts are the same sets the Sources and Receipts surfaces
// publish, under the same names.
//
// A widget is a real section with a heading; the activity and health widgets are
// real tables, so the cell and collision probes cover them at every width.

const label = (id) => SURFACES.find((s) => s.id === id)?.label || id;
const price = (usd) => `$${usd.toFixed(4)}`;

// A widget's foot: the route it read and how long that took, or the fact that it is
// still asking with the measured cost of the read. One component, so no widget can
// carry a figure without its source beside it.
function ReadLine({ state, route, cost }) {
  if (state.phase === "first") return <p className="meta widget-read">asking {route} — {cost}</p>;
  if (state.phase === "failed" && !state.data) return <p className="meta widget-read">{route} — the read failed; see the fault above</p>;
  return (
    <p className="meta widget-read">
      {route} · read at {stamp(state.at)} in {duration(state.ms)}{state.stale ? " · a newer read is in flight" : ""}
    </p>
  );
}

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

  // The product's jobs, newest first — the gate's own records hidden the way Receipts
  // hides them, and the count of what is hidden stated.
  const allJobs = (Array.isArray(jobs.data?.jobs) ? jobs.data.jobs : []).map(jobView);
  const productJobs = allJobs.filter((j) => !j.gateAdmitted)
    .sort((a, b) => (Date.parse(b.createdAt || "") || -Infinity) - (Date.parse(a.createdAt || "") || -Infinity));
  const recentJobs = productJobs.slice(0, 5);
  const hiddenJobs = allJobs.length - productJobs.length;

  const budgetList = (budgets.data?.budgets || []).filter((b) => b.scope === "external_spend");

  const { cheapest, live } = useMemo(() => {
    const { latest } = latestBatch(cands.data?.candidates);
    return summarise(latest.items);
  }, [cands.data]);
  const notLive = useMemo(() => {
    const { latest } = latestBatch(cands.data?.candidates);
    return latest.items.filter((c) => !classify(c).live).length;
  }, [cands.data]);

  const visits = recentVisits().filter((v) => v.id !== "home");

  useEffect(() => {
    if (sources.phase === "first" && jobs.phase === "first") return;
    announce(
      `Home — ${quoting.length} sources quoting, ${absent.length} unavailable, ${productJobs.length} job records, ` +
      `${live.length} candidates live right now`
    );
  }, [sources.phase, jobs.phase, quoting.length, absent.length, productJobs.length, live.length, announce]);

  return (
    <div className="stack home">
      <div className="home-head">
        <div className="stack" style={{ gap: "8px" }}>
          <h1>Home</h1>
          <p className="prose" style={{ fontSize: "16px" }}>
            One request, any venue, a receipt back. What is answering, what it costs,
            what ran last — each figure from the daemon, with the route and the read
            time beside it.
          </p>
        </div>
        <div className="stack home-principal">
          <Eyebrow>acting as</Eyebrow>
          <Chip kind="absent">no wallet session — see IAM</Chip>
          <p className="meta">Placement posture lives on the intent <span className="mono">{intent}</span>.</p>
        </div>
      </div>

      {/* QUICK CREATE. The four things a console user comes to do, as doors, not as
          a hero. Each names its surface and what it does there in one line. */}
      <section className="stack" aria-labelledby="home-quick" style={{ gap: "10px" }}>
        <Eyebrow>quick actions</Eyebrow>
        <h2 id="home-quick" className="sr-only">Quick actions</h2>
        <ul className="quick">
          <li><a className="quick-tile" href={hashForSurface("job")}><span className="quick-title">Submit a job</span><span className="meta">one envelope, dry run, nothing spent</span></a></li>
          <li><a className="quick-tile" href={hashForSurface("candidates")}><span className="quick-title">Live prices</span><span className="meta">the latest sweep, cheapest first</span></a></li>
          <li><a className="quick-tile" href={hashForSurface("placement")}><span className="quick-title">Where it would run</span><span className="meta">the daemon&rsquo;s advisory, with reasons</span></a></li>
          <li><a className="quick-tile" href={hashForSurface("catalog")}><span className="quick-title">All resources</span><span className="meta">every class, every venue, its state now</span></a></li>
        </ul>
      </section>

      <div className="widgets">
        {/* HEALTH — the sources, from the same read Sources renders in full. */}
        <section className="widget" aria-labelledby="home-health">
          <div className="widget-head">
            <h2 id="home-health">Health</h2>
            <a className="entry-name" href={hashForSurface("sources")}>Sources &amp; health →</a>
          </div>
          {sources.phase === "failed" && <Failure result={sources.failure} />}
          {sourceList.length > 0 ? (
            <>
              <p className="meta">
                {quoting.length} quoting · {answering.length} answering without a price · {absent.length} unavailable
              </p>
              <div className="table-scroll">
                <table className="table t-health">
                  <caption className="sr-only">Candidate sources and the state the daemon last persisted for each</caption>
                  <thead>
                    <tr><th scope="col">Source</th><th scope="col">State</th></tr>
                  </thead>
                  <tbody>
                    {[...quoting, ...answering, ...absent].map((s) => (
                      <tr key={s.source || s.state} className="trow">
                        <th scope="row" className="mono">{breakable(s.source || "source not named")}</th>
                        <td>
                          <Chip kind={s.state === "live_quote_source" ? "live" : s.state === "candidate_source_unavailable" ? "absent" : "muted"}>
                            {s.state || "state absent"}
                          </Chip>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          ) : sources.phase === "first" ? (
            <p className="prose">Each source is asked in turn; a full round has been measured at 27 to 61 seconds. Nothing is drawn until it answers.</p>
          ) : null}
          <ReadLine state={sources} route="GET /api/candidate-sources" cost="measured at 27 to 61 s" />
        </section>

        {/* COST AND USAGE — budgets are real; settled spend has no route yet. */}
        <section className="widget" aria-labelledby="home-cost">
          <div className="widget-head">
            <h2 id="home-cost">Cost and usage</h2>
            <a className="entry-name" href={hashForSurface("spend")}>Spend →</a>
          </div>
          {budgets.phase === "failed" && <Failure result={budgets.failure} />}
          {budgetList.length > 0 ? (
            <ul className="budgets">
              {budgetList.map((b) => (
                <li key={b.budget_id} className="budget">
                  <div className="budget-name">{b.name || b.budget_id}</div>
                  <div className="budget-figs mono">
                    <span>{b.currency} {b.spent ?? "—"} spent</span>
                    <span>{b.currency} {b.remaining ?? "—"} remaining</span>
                    <span className="meta">of {b.currency} {b.limit ?? "—"}</span>
                  </div>
                  <div className="budget-bar" role="img"
                    aria-label={`${b.spent ?? 0} of ${b.limit ?? 0} ${b.currency} spent`}>
                    <div className="budget-spent" style={{ width: `${typeof b.limit === "number" && b.limit > 0 ? Math.min(100, ((b.spent || 0) / b.limit) * 100) : 0}%` }} />
                  </div>
                </li>
              ))}
            </ul>
          ) : budgets.phase === "ready" ? (
            <p className="prose">The daemon holds no external_spend budget. Nothing has been drawn to stand in for one.</p>
          ) : null}
          <ReadLine state={budgets} route="GET /api/budgets" cost="under a second" />
          <Unwired
            would="settled provider spend by venue, each figure reconciled against a receipt"
            route="provider spend reconciliation — not on the capability table"
          />
        </section>

        {/* RECENT ACTIVITY — the newest job records, the way Receipts lists them. */}
        <section className="widget widget-wide" aria-labelledby="home-activity">
          <div className="widget-head">
            <h2 id="home-activity">Recent activity</h2>
            <a className="entry-name" href={hashForSurface("receipts")}>Receipts →</a>
          </div>
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
                        <div className="mono" style={{ fontSize: "13px" }}>{j.id}</div>
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
            <p className="prose">
              {allJobs.length === 0
                ? "The daemon holds no job records."
                : "Every job record the daemon holds was admitted by this surface's own verification; no product job has been submitted yet."}
            </p>
          ) : null}
          {hiddenJobs > 0 && recentJobs.length > 0 && (
            <p className="meta">{productJobs.length} product records in total · {hiddenJobs} gate-admitted proposals hidden, as on Receipts</p>
          )}
          <ReadLine state={jobs} route="GET /api/jobs" cost="under a second" />
        </section>

        {/* LIVE NOW — the cheapest live quote in the latest sweep, with its window. */}
        <section className="widget" aria-labelledby="home-live">
          <div className="widget-head">
            <h2 id="home-live">Live now</h2>
            <a className="entry-name" href={hashForSurface("candidates")}>Candidates →</a>
          </div>
          {cands.phase === "failed" && <Failure result={cands.failure} />}
          {cheapest ? (
            <div className="stack" style={{ gap: "8px" }}>
              <div className="eyebrow">cheapest live quote in the latest sweep</div>
              <div className="home-price mono">{price(cheapest.quote.usd_per_hour)}<span className="meta"> / GPU · hour</span></div>
              <div>{cheapest.display_name || cheapest.provider_kind}{cheapest.region ? <span className="meta"> · {String(cheapest.region).replace(/^\s*,\s*/, "")}</span> : null}</div>
              <Freshness observedAt={cheapest.observed_at} expiresAt={cheapest.expires_at} size="row" />
              <p className="meta">{live.length} live · {notLive} not live in this sweep · <Chip kind="live">live_evidence</Chip></p>
            </div>
          ) : cands.phase === "ready" ? (
            <p className="prose">No candidate in the latest sweep passes the live rule, and no price has been invented to stand here.</p>
          ) : null}
          <ReadLine state={cands} route="GET /api/candidates?latest=true" cost="about a second" />
        </section>

        {/* RECENTLY VISITED — this browser only. */}
        <section className="widget" aria-labelledby="home-visited">
          <div className="widget-head">
            <h2 id="home-visited">Recently visited</h2>
          </div>
          {visits.length > 0 ? (
            <ul className="visited">
              {visits.map((v) => (
                <li key={v.id}>
                  <a className="entry-name" href={hashForSurface(v.id)}>{label(v.id)}</a>
                  <span className="meta"> · {stamp(v.at)}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="prose">Nothing yet. Surfaces you open appear here.</p>
          )}
          <p className="meta widget-read">kept in this browser only — never sent anywhere</p>
        </section>
      </div>
    </div>
  );
}

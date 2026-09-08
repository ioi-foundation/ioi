import { useEffect } from "react";
import { useSurfaceRead } from "../useSurfaceRead.js";
import { stamp, duration } from "../logic/classify.mjs";
import { Unwired, Eyebrow, Chip, Waiting, Failure, Kept } from "../components/Bits.jsx";
import { hashForSurface } from "../logic/surfaces.mjs";
import PageHead from "../components/PageHead.jsx";

// SPEND — cost and usage. Wired to the daemon's budgets; the rest drawn and labelled.
//
// A hyperscaler's cost page counts what its own meter recorded. This one can show two
// things honestly today: the external_spend BUDGETS the daemon holds — limit, spent,
// remaining, in the budget's own currency, the same list Submit a job offers — and the
// SHAPE of what is not readable yet. No route on the capability table returns settled
// provider spend, its reconciliation, or a SpendEstimate, so those panels carry an
// Unwired placeholder where their figure would go rather than a zero a reader would
// take for "nothing spent". Akash is the one lane where spend has settled through
// the estate; nothing here counts a quote, a simulator, or an estimate as a cost.

const money = (cur, n) => (typeof n === "number" ? `${cur} ${n.toLocaleString("en-US", { maximumFractionDigits: 2 })}` : "—");

export default function Spend({ announce }) {
  const state = useSurfaceRead("budgets", "/api/budgets");
  const budgets = (state.data?.budgets || []).filter((b) => b.scope === "external_spend");
  const others = (state.data?.budgets || []).filter((b) => b.scope !== "external_spend");

  useEffect(() => {
    if (state.phase === "first") return;
    announce(`Spend — ${budgets.length} external_spend budget${budgets.length === 1 ? "" : "s"}; settled spend is not wired`);
  }, [state.phase, budgets.length, announce]);

  if (state.phase === "first") return (
    <Waiting
      what="the daemon's budgets"
      title="Spend"
      willShow={
        "Cost and usage: every external_spend budget the daemon holds — limit, spent, " +
        "remaining — and, drawn but not wired, the settled provider spend that no route " +
        "on the capability table returns yet."
      }
      why="The budgets read is small and usually answers in under a second."
    />
  );

  const view = (
    <div className="stack" style={{ gap: "24px" }}>
      <PageHead
        surface="spend"
        title="Spend"
        lede="Cost and usage. Real provider spend only, reconciled by the daemon; a quote is a quote, a simulator is labelled a simulator, and neither is ever counted here."
        meta={`${budgets.length} external_spend budget${budgets.length === 1 ? "" : "s"} · GET /api/budgets · read at ${stamp(state.at)} in ${duration(state.ms)}`}
        aside={<Chip kind="live">wired · GET /api/budgets</Chip>}
      />

      <section className="stack" style={{ gap: "10px" }} aria-labelledby="spend-budgets">
        <h2 id="spend-budgets">Budgets</h2>
        <p className="meta">
          {budgets.length} external_spend budget{budgets.length === 1 ? "" : "s"}
          {others.length ? ` · ${others.length} of another scope, not shown` : ""} · read at {stamp(state.at)} in {duration(state.ms)}
        </p>
        {budgets.length > 0 ? (
          <div className="table-scroll">
            <table className="table t-budgets">
              <caption className="sr-only">The daemon's external_spend budgets: limit, spent and remaining in each budget's own currency</caption>
              <thead>
                <tr>
                  <th scope="col">Budget</th>
                  <th scope="col">Spent</th>
                  <th scope="col">Remaining</th>
                  <th scope="col">Limit</th>
                  <th scope="col">Drawn</th>
                </tr>
              </thead>
              <tbody>
                {budgets.map((b) => {
                  const pct = typeof b.limit === "number" && b.limit > 0 ? Math.min(100, ((b.spent || 0) / b.limit) * 100) : 0;
                  return (
                    <tr key={b.budget_id} className="trow">
                      <th scope="row">
                        <div className="budget-name">{b.name || b.budget_id}</div>
                        <div className="meta mono">{b.budget_id}{b.created_at ? ` · since ${stamp(b.created_at)}` : ""}</div>
                        {b.authority_required && <div className="meta">draws require a wallet authorization</div>}
                      </th>
                      <td className="mono price">{money(b.currency, b.spent)}</td>
                      <td className="mono price">{money(b.currency, b.remaining)}</td>
                      <td className="mono basis">{money(b.currency, b.limit)}</td>
                      <td>
                        <div className="budget-bar" role="img" aria-label={`${pct.toFixed(0)}% of this budget drawn`}>
                          <div className="budget-spent" style={{ width: `${pct}%` }} />
                        </div>
                        <div className="meta">{pct.toFixed(0)}%</div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="prose">The daemon holds no external_spend budget. Nothing has been drawn to stand in for one.</p>
        )}
        <p className="meta">
          A budget is the ceiling a job may draw on; it is discovered before any mutation
          and a request with none is refused by name. Spent and remaining are the daemon&rsquo;s
          own figures, not a sum computed here.
        </p>
      </section>

      <div className="cols cols-2 spend-panels">
        <section className="panel stack spend-panel" aria-labelledby="spend-settled">
          <Eyebrow>settled spend</Eyebrow>
          <h2 id="spend-settled">By venue, this month</h2>
          <Unwired
            would="one row per venue with settled spend, the currency the provider billed in, and the receipt each figure is reconciled against — a SpendEstimate beside it where one was made"
            route="provider spend reconciliation — not on the capability table"
          />
        </section>
        <section className="panel stack spend-panel" aria-labelledby="spend-quotes">
          <Eyebrow>quotes are not costs</Eyebrow>
          <h2 id="spend-quotes">Quoted vs. settled</h2>
          <Unwired
            would="the cheapest live quote beside the last settled price on the same venue, each dated, so a reader can see how far a quote is from a bill"
            route="GET /api/candidates + provider spend reconciliation"
          />
        </section>
      </div>

      <div className="stack" style={{ gap: "10px" }}>
        <Eyebrow>what a settled figure here would have to carry</Eyebrow>
        <div className="table-scroll">
          <table className="table t-pairs">
            <caption className="sr-only">The provenance every spend figure on this page must carry before it is shown</caption>
            <thead>
              <tr>
                <th scope="col">Every spend figure</th>
                <th scope="col">Why</th>
              </tr>
            </thead>
            <tbody>
              {[
                ["names its venue and the provider's own bill",
                  "spend is customer-borne on a venue the caller connected; the daemon records and reconciles it and hides no markup inside it"],
                ["names the receipt it reconciles against",
                  "a spend with no receipt is a number with no witness — the receipt chain is the product"],
                ["carries the time it was reconciled",
                  "a settled figure from last week beside a quote from this minute must not read as one column"],
                ["excludes every simulator candidate",
                  "a simulator lane never counts toward a total, a fee, or a cheapest — here or anywhere on this surface"],
              ].map(([k, v]) => (
                <tr key={k} className="trow">
                  <th scope="row">{k}</th>
                  <td className="basis">{v}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="catalog-foot">
        <span className="meta">The one settled-spend lane in the estate is Akash. Where a budget can be drawn on today:</span>
        <a className="entry-name" href={hashForSurface("job")}>Submit a job →</a>
        <a className="entry-name" href={hashForSurface("receipts")}>Receipts →</a>
      </div>
    </div>
  );

  if (state.phase === "failed") {
    return (
      <div className="stack" style={{ gap: "16px" }}>
        <Failure result={state.failure} />
        {state.data && <Kept at={state.at}>{view}</Kept>}
      </div>
    );
  }
  return state.stale ? <Kept at={state.at}>{view}</Kept> : view;
}

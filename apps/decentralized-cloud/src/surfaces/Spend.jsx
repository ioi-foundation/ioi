import { useEffect } from "react";
import { NotConnected, Unwired, Eyebrow, Chip } from "../components/Bits.jsx";
import { hashForSurface } from "../logic/surfaces.mjs";

// SPEND — cost and usage, designed, not connected.
//
// A hyperscaler's cost page counts what its own meter recorded. This one can only ever
// count real provider spend the daemon reconciled — Akash is the one lane where spend
// has settled through the estate — and it must never count a quote, a simulator, or an
// estimate as a cost. Today the capability table carries no read for settled spend or
// reconciliation, so this surface renders the SHAPE of the page with no figure in it
// and says so, rather than a zero that a reader would take for "nothing spent".
//
// The canonical object this page would render is a SpendEstimate beside the
// reconciled spend; neither is read here yet.
export default function Spend({ announce }) {
  useEffect(() => { announce("Spend — designed, not connected"); }, [announce]);

  return (
    <div className="stack" style={{ gap: "24px" }}>
      <div className="stack" style={{ gap: "9px" }}>
        <h1>Spend</h1>
        <p className="prose" style={{ fontSize: "16px" }}>
          Cost and usage. Real provider spend only, reconciled by the daemon; a quote is
          a quote, a simulator is labelled a simulator, and neither is ever counted here.
        </p>
      </div>

      <NotConnected>
        This surface reads no spend. No route on the capability table returns settled
        provider spend, its reconciliation, or a SpendEstimate, and this page will not
        derive a cost from a price list. Every panel below is the shape of the page with nothing in it: the
        first figure that stands here will be one the daemon returned, with the venue,
        the receipt and the time it was reconciled beside it.
      </NotConnected>

      <div className="cols cols-3 spend-panels">
        <section className="panel stack spend-panel" aria-labelledby="spend-settled">
          <Eyebrow>settled spend</Eyebrow>
          <h2 id="spend-settled">By venue, this month</h2>
          <Unwired
            would="one row per venue with settled spend, the currency the provider billed in, and the receipt each figure is reconciled against"
            route="provider spend reconciliation — not on the capability table"
          />
        </section>
        <section className="panel stack spend-panel" aria-labelledby="spend-budgets">
          <Eyebrow>budgets</Eyebrow>
          <h2 id="spend-budgets">Limit, spent, remaining</h2>
          <Unwired
            would="the daemon's external_spend budgets — the same list Submit a job offers — with limit, spent and remaining in the budget's own currency"
            route="GET /api/budgets — on the table, not read by this surface yet"
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
        <Eyebrow>what a figure here would have to carry</Eyebrow>
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
        <span className="meta">The one settled-spend lane in the estate is Akash. Where money can be drawn on today:</span>
        <a className="entry-name" href={hashForSurface("job")}>Submit a job →</a>
        <a className="entry-name" href={hashForSurface("receipts")}>Receipts →</a>
      </div>
      <p className="meta">
        <Chip kind="absent">no figure on this page was read from the daemon</Chip>
      </p>
    </div>
  );
}

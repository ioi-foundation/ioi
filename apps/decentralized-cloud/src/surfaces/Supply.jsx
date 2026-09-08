import { useEffect } from "react";
import { NotConnected, Unwired, Eyebrow, Chip } from "../components/Bits.jsx";
import { hashForSurface } from "../logic/surfaces.mjs";
import PageHead from "../components/PageHead.jsx";

// SUPPLY REGISTRY — the marketplace page, designed, not connected.
//
// A hyperscaler's marketplace sells things; this one lists where capacity can come
// from and on what evidence, and it is forbidden from preferring anything. The
// estate's own supply — managed capacity, contributed supply registered through a
// CloudSupplyRegistration — enters placement as an ordinary candidate, scored by the
// same evidence as every other venue, and every decision that includes it must say
// whether it won or lost and why. There is no featured tile, and there never will be.
//
// No route on the capability table returns the registry, so the page is drawn and
// labelled. The venues placement can already choose between ARE on the table, and the
// catalogue renders them; this page will read that route when it is wired.
export default function Supply({ announce }) {
  useEffect(() => { announce("Supply registry — designed, not connected"); }, [announce]);

  return (
    <div className="stack" style={{ gap: "24px" }}>
      <PageHead
        surface="supply"
        title="Supply registry"
        lede="Every venue placement can draw on, the evidence each one quotes with, and the rule that none of them is preferred — including the estate's own."
        aside={<Chip kind="absent">designed, not connected</Chip>}
      />

      <NotConnected>
        This surface reads no registry. No route on the capability table returns
        registered supply — managed capacity or contributed supply — so the register
        below has no rows. What can be seen today is the catalogue: every venue the
        router can place work on, with the state the daemon last persisted for it.
      </NotConnected>

      <section className="stack" style={{ gap: "10px" }} aria-labelledby="supply-register">
        <Eyebrow>the register</Eyebrow>
        <h2 id="supply-register">Venues and networks, by evidence</h2>
        <div className="table-scroll">
          <table className="table t-supply">
            <caption className="sr-only">The columns a supply row would carry; no registry is read on this branch</caption>
            <thead>
              <tr>
                <th scope="col">Venue</th>
                <th scope="col">Form</th>
                <th scope="col">Evidence mode</th>
                <th scope="col">Fee basis</th>
                <th scope="col">Neutrality</th>
              </tr>
            </thead>
            <tbody>
              <tr className="trow">
                <td colSpan={5}>
                  <Unwired
                    would="one row per venue: its form (connected provider, GPU marketplace, DePIN network, local capacity, managed capacity, contributed supply), the evidence mode its quotes carry, the fee basis the daemon states for it, and — for first-party supply — whether it won or lost the last decision it was in, against the named alternatives"
                    route="GET /api/venues — on the table, not read by this surface yet; supply registrations — not on the table"
                  />
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <div className="cols cols-2" style={{ gap: "20px" }}>
        <section className="panel stack" style={{ gap: "10px" }} aria-labelledby="supply-managed">
          <Eyebrow>managed capacity</Eyebrow>
          <h2 id="supply-managed">Provider of record</h2>
          <p className="prose">
            Capacity the estate or a partner runs and bills as managed infrastructure.
            The daemon reports it today as <span className="mono">managed_capacity_not_offered</span>:
            there is no managed plane, and nothing is proposed in its place.
          </p>
          <Chip kind="absent">not offered — the daemon&rsquo;s own word</Chip>
        </section>
        <section className="panel stack" style={{ gap: "10px" }} aria-labelledby="supply-contributed">
          <Eyebrow>contributed supply</Eyebrow>
          <h2 id="supply-contributed">Register capacity</h2>
          <p className="prose">
            An independent operator registering capacity signs a CloudSupplyRegistration;
            its metadata belongs to this registry, its credentials and custody to the
            daemon&rsquo;s provider plane, and its settlement to the declared profile.
          </p>
          <Unwired
            would="the registration form — capacity class, evidence the operator can present, settlement profile — and a submit that is a proposal, not an admission"
            route="supply registration — not on the capability table"
          />
        </section>
      </div>

      <div className="catalog-foot">
        <a className="entry-name" href={hashForSurface("catalog")}>All resources — every venue, with its state now →</a>
        <a className="entry-name" href={hashForSurface("sources")}>Sources &amp; health →</a>
      </div>
    </div>
  );
}

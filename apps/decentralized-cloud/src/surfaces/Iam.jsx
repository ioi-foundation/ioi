import { useEffect } from "react";
import { NotConnected, Unwired, Eyebrow } from "../components/Bits.jsx";

// IAM — leases, designed, not connected.
//
// On this surface identity and authority are two different things and the page keeps
// them apart. A PRINCIPAL is a wallet; an IdP identity is never machine authority.
// What a principal may do is a CapabilityLease: scoped to a facet set, expiring, drawn
// down rather than presented, and always a NARROWING of a grant a person made — an
// agent's lease can never widen into something the human's grant did not cover.
//
// This face holds no wallet session, reads no lease, and mints nothing: no route on the
// capability table returns a principal or its leases. So the page draws the two tables
// a reader would open this surface for — the principal, and its leases — and says in
// its own words that both are empty because nothing is read, not because nothing
// exists.
export default function Iam({ announce }) {
  useEffect(() => { announce("IAM — leases, designed, not connected"); }, [announce]);

  return (
    <div className="stack" style={{ gap: "24px" }}>
      <div className="stack" style={{ gap: "9px" }}>
        <h1>IAM · leases</h1>
        <p className="prose" style={{ fontSize: "16px" }}>
          A principal is a wallet. What it may do is a lease — scoped, expiring, drawn
          down — never a role in a user table, and never a provider credential in the
          caller&rsquo;s hands.
        </p>
      </div>

      <NotConnected>
        This surface holds no wallet session and reads no lease. No route on the
        capability table returns a principal or its CapabilityLeases, and this page
        will not stand in a placeholder principal. The tables below are the shape of
        the page: a reader who arrives here with a wallet would see their principal in
        the first and every lease it holds in the second, each with what it permits and
        when it expires.
      </NotConnected>

      <section className="stack" style={{ gap: "10px" }} aria-labelledby="iam-principal">
        <Eyebrow>principal</Eyebrow>
        <h2 id="iam-principal">Who is asking</h2>
        <Unwired
          would="the wallet principal this console is acting as, with the authority mode it can present — a signed grant for a person, a lease draw-down for an agent"
          route="wallet principal — not on the capability table"
        />
      </section>

      <section className="stack" style={{ gap: "10px" }} aria-labelledby="iam-leases">
        <Eyebrow>capability leases</Eyebrow>
        <h2 id="iam-leases">What it may do, for how long</h2>
        <div className="table-scroll">
          <table className="table t-leases">
            <caption className="sr-only">The columns a lease row would carry; no lease is read on this branch</caption>
            <thead>
              <tr>
                <th scope="col">Lease</th>
                <th scope="col">Scope · facets</th>
                <th scope="col">Drawn down</th>
                <th scope="col">Expires</th>
              </tr>
            </thead>
            <tbody>
              <tr className="trow">
                <td colSpan={4}>
                  <Unwired
                    would="one row per lease: its ref, the facets it permits (a job envelope binds only what the lease carries), how much of it has been drawn, and its expiry — with an expired lease drawn the way an expired quote is"
                    route="capability leases by principal — not on the capability table"
                  />
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <div className="stack" style={{ gap: "10px" }}>
        <Eyebrow>the rules this page will keep when it is wired</Eyebrow>
        <div className="table-scroll">
          <table className="table t-pairs">
            <caption className="sr-only">Rules the IAM surface keeps</caption>
            <thead>
              <tr>
                <th scope="col">Rule</th>
                <th scope="col">Why</th>
              </tr>
            </thead>
            <tbody>
              {[
                ["a lease narrows a grant; it never widens one",
                  "an agent acting on a lease can do at most what the person who granted it could — the same envelope, the same receipts, one fewer authority"],
                ["the caller never sees a provider credential",
                  "credentials stay in the daemon's vault; a lease is a permission to have the daemon act, not a key"],
                ["identity is not authority",
                  "signing in through an identity provider proves who you are; only a wallet grant or a lease proves what you may spend"],
                ["nothing here creates a grant or a lease",
                  "a grant is signed by a person at the moment of spend, and a web form cannot carry that moment"],
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
    </div>
  );
}

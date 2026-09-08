import { useEffect } from "react";
import { NotConnected, Unwired, Eyebrow, Chip } from "../components/Bits.jsx";
import PageHead from "../components/PageHead.jsx";
import { hashForCategory, hashForSurface } from "../logic/surfaces.mjs";

// STORAGE — archive custody, designed, not connected.
//
// The tab a person from S3 or Cloud Storage opens first. What it would show is
// buckets that are content addresses, the deals and replicas behind each, and the
// restore evidence that says the bytes can come back — because on this surface
// "storage availability does not equal restore validity" is canon, not a caveat. The
// console does not own the payload bytes or the encrypted archive custody; it owns
// the routing of a storage requirement to a venue and the receipts that say what
// happened.
//
// No route on the capability table returns a CustodyPlan, a storage ResourceLease or
// an archive record, so the page draws the shape and says so in its own words. What
// the daemon CAN say today about storage — which venues and networks can supply each
// class, and their state — is in the catalogue under Storage, and the page links
// there rather than restating it.

// The four canon classes, with the tier a console user would call each. The tier word
// is a reading aid; the class is the canon's.
const CLASSES = [
  { id: "storage.object", tier: "hot", what: "Objects behind a bucket that is a content address. Pinned, gatewayed, replicated by policy." },
  { id: "storage.block", tier: "hot", what: "Block volumes attached to a placement. Live with the workload; not an archive." },
  { id: "storage.archive", tier: "cold", what: "Sealed archive custody. Sealed before write; export and restore are wallet-gated." },
  { id: "storage.cas", tier: "cold", what: "Content-addressed storage as the durable form: the address is the proof of what was stored." },
];

export default function Storage({ announce }) {
  useEffect(() => { announce("Storage — archive custody, designed, not connected"); }, [announce]);

  return (
    <div className="stack" style={{ gap: "24px" }}>
      <PageHead
        surface="storage"
        title="Storage"
        lede="Buckets that are content addresses, the deals and replicas behind them, and the evidence that the bytes can come back. Sealed before write; export and restore are wallet-gated."
        aside={<Chip kind="absent">designed, not connected</Chip>}
      />

      <NotConnected>
        This surface reads no archive, no custody plan and no storage lease. No route on
        the capability table returns a CustodyPlan, a storage ResourceLease or an
        archive record, and this page will not draw a bucket that is not there. The
        tables below are the shape of the page. What the daemon can say about storage
        today — which venues and networks can supply each class, and the state each is
        in — is in{" "}
        <a href={hashForCategory("storage")}>All resources · Storage</a>.
      </NotConnected>

      <section className="stack" style={{ gap: "10px" }} aria-labelledby="storage-buckets">
        <Eyebrow>buckets</Eyebrow>
        <h2 id="storage-buckets">What is held, where, and whether it can come back</h2>
        <div className="table-scroll">
          <table className="table t-storage">
            <caption className="sr-only">The columns a bucket row would carry; no archive is read on this branch</caption>
            <thead>
              <tr>
                <th scope="col">Bucket · content address</th>
                <th scope="col">Class</th>
                <th scope="col">Custody</th>
                <th scope="col">Replicas · deals</th>
                <th scope="col">Restore evidence</th>
              </tr>
            </thead>
            <tbody>
              <tr className="trow">
                <td colSpan={5}>
                  <Unwired
                    would="one row per bucket: its content address, the storage class it was requested as, the custody posture (Standard or Private) from the CustodyPlan, the venues holding a replica or a deal with each deal's window, and the last restore evidence — with a bucket whose restore evidence is stale drawn the way an expired quote is"
                    route="archive custody records, custody plans, storage leases — not on the capability table"
                  />
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section className="stack" style={{ gap: "10px" }} aria-labelledby="storage-classes">
        <Eyebrow>the classes</Eyebrow>
        <h2 id="storage-classes">Four canon classes, two tiers</h2>
        <div className="table-scroll">
          <table className="table t-pairs t-storage-classes">
            <caption className="sr-only">The storage resource classes the router can be asked for</caption>
            <thead>
              <tr>
                <th scope="col">Class</th>
                <th scope="col">Tier</th>
                <th scope="col">What it is</th>
              </tr>
            </thead>
            <tbody>
              {CLASSES.map((c) => (
                <tr key={c.id} className="trow">
                  <th scope="row" className="mono" style={{ fontSize: "13px" }}>{c.id}</th>
                  <td><Chip kind="muted">{c.tier}</Chip></td>
                  <td className="basis">{c.what}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="meta">
          A StorageRequirement on the intent names one of these; the venues that can
          supply it are read live in the catalogue.{" "}
          <a className="entry-name" href={hashForCategory("storage")}>All resources · Storage →</a>
        </p>
      </section>

      <div className="cols cols-2" style={{ gap: "20px" }}>
        <section className="panel stack" style={{ gap: "10px" }} aria-labelledby="storage-custody">
          <Eyebrow>custody</Eyebrow>
          <h2 id="storage-custody">Sealed before write</h2>
          <p className="prose">
            A CustodyPlan says how archive bytes, snapshot material and restore evidence
            are handled, and under which posture. The payload never passes through this
            console: it does not own the bytes or the encrypted custody, and no panel
            here will ever show a file&rsquo;s contents.
          </p>
          <Unwired
            would="the custody plan for a selected bucket — posture, sealing, provider trust, restore material — as the daemon holds it"
            route="CustodyPlan by bucket — not on the capability table"
          />
        </section>
        <section className="panel stack" style={{ gap: "10px" }} aria-labelledby="storage-restore">
          <Eyebrow>export and restore</Eyebrow>
          <h2 id="storage-restore">Wallet-gated, receipted</h2>
          <p className="prose">
            Export and restore are spends and authority crossings, so each is a job with
            a wallet grant at the moment it happens, and each leaves a receipt. A restore
            that produced no receipt did not happen as far as this page is concerned.
          </p>
          <Unwired
            would="a restore door: pick a bucket, a destination class and a budget; submit as a proposal through Deploy, and follow the receipt on Jobs & receipts"
            route="restore as a CloudJobRequest with a storage requirement — the envelope exists; the storage lane behind it does not"
          />
        </section>
      </div>

      <div className="stack" style={{ gap: "10px" }}>
        <Eyebrow>the rules this page will keep when it is wired</Eyebrow>
        <div className="table-scroll">
          <table className="table t-pairs">
            <caption className="sr-only">Rules the Storage surface keeps</caption>
            <thead>
              <tr>
                <th scope="col">Rule</th>
                <th scope="col">Why</th>
              </tr>
            </thead>
            <tbody>
              {[
                ["storage availability is not restore validity",
                  "a deal that is live proves a provider holds bytes; only restore evidence proves the bytes come back — the two are drawn as two columns and never merged"],
                ["the payload never passes through this console",
                  "decentralized.cloud routes a storage requirement and keeps the receipts; the bytes and the encrypted custody are not its to hold or to show"],
                ["a replica is a receipt, not a promise",
                  "each replica or deal row is the daemon's record of one, with its window; nothing here counts a replica a receipt does not name"],
                ["export and restore need a grant",
                  "moving archive bytes is a spend and an authority crossing; it is a job with a wallet grant, never a button that just does it"],
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
        <a className="entry-name" href={hashForCategory("storage")}>All resources · Storage — venues and their state now →</a>
        <a className="entry-name" href={hashForSurface("job")}>Deploy →</a>
      </div>
    </div>
  );
}

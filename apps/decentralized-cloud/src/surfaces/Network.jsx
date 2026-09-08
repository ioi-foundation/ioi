import { useEffect } from "react";
import { NotConnected, Unwired, Eyebrow, Chip } from "../components/Bits.jsx";
import PageHead from "../components/PageHead.jsx";
import { hashForCategory, hashForSurface } from "../logic/surfaces.mjs";

// NETWORK — ingress, names, certificates and address leases, designed, not connected.
//
// This is where a decentralized cloud usually falls apart, which is why it gets a
// first-class tab: a hosted endpoint without a name and a certificate is not a
// delivered job — the canon pulled network.dns and network.tls forward for exactly
// this. The page would show every endpoint a placement exposes, the name
// and certificate bound to it, and the address lease it rides on.
//
// No route on the capability table returns an ingress, a name, a certificate or an
// address ResourceLease, so the page draws the shape and says so. The network
// classes the router can be asked for, and which venues can supply them, are read
// live in the catalogue under Networking.

const CLASSES = [
  { id: "network.ip_lease", what: "An address held for a placement's lifetime as a provider-native ResourceLease. It cannot authorize spend by itself." },
  { id: "network.ingress", what: "The door to a workload: a listener the placement exposes, bound to a name and a certificate before it counts as delivered." },
  { id: "network.dns", what: "A name pointed at an ingress. Pulled forward into scope because a preview or a site without one is not a delivered job." },
  { id: "network.tls", what: "A certificate for the name. Same reason: an endpoint without one is not delivered." },
];

export default function Network({ announce }) {
  useEffect(() => { announce("Network — ingress, names and certificates, designed, not connected"); }, [announce]);

  return (
    <div className="stack" style={{ gap: "24px" }}>
      <PageHead
        surface="network"
        title="Network"
        lede="Ingress, names, certificates and address leases — the part a hosted job is not delivered without. Every endpoint with the name and certificate bound to it and the lease it rides on."
        aside={<Chip kind="absent">designed, not connected</Chip>}
      />

      <NotConnected>
        This surface reads no ingress, no name, no certificate and no address lease. No
        route on the capability table returns a NetworkRequirement&rsquo;s fulfilment or
        a network ResourceLease, and this page will not draw an endpoint that is not
        there. The table below is the shape of the page. What the daemon can say about
        network today — which venues and networks can supply each class, and their
        state — is in <a href={hashForCategory("network")}>All resources · Networking</a>.
      </NotConnected>

      <section className="stack" style={{ gap: "10px" }} aria-labelledby="network-endpoints">
        <Eyebrow>endpoints</Eyebrow>
        <h2 id="network-endpoints">What is exposed, under which name, with which certificate</h2>
        <div className="table-scroll">
          <table className="table t-network">
            <caption className="sr-only">The columns an endpoint row would carry; no ingress is read on this branch</caption>
            <thead>
              <tr>
                <th scope="col">Endpoint</th>
                <th scope="col">Job</th>
                <th scope="col">Name</th>
                <th scope="col">Certificate</th>
                <th scope="col">Address lease</th>
              </tr>
            </thead>
            <tbody>
              <tr className="trow">
                <td colSpan={5}>
                  <Unwired
                    would="one row per exposed listener: the ingress and the job it belongs to, the DNS name bound to it, the certificate and its expiry (an expired certificate drawn the way an expired quote is), and the ResourceLease for the address with its window"
                    route="ingress, dns, tls and address-lease records — not on the capability table"
                  />
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section className="stack" style={{ gap: "10px" }} aria-labelledby="network-classes">
        <Eyebrow>the classes</Eyebrow>
        <h2 id="network-classes">Four canon classes</h2>
        <div className="table-scroll">
          <table className="table t-pairs">
            <caption className="sr-only">The network resource classes the router can be asked for</caption>
            <thead>
              <tr>
                <th scope="col">Class</th>
                <th scope="col">What it is</th>
              </tr>
            </thead>
            <tbody>
              {CLASSES.map((c) => (
                <tr key={c.id} className="trow">
                  <th scope="row" className="mono" style={{ fontSize: "13px" }}>{c.id}</th>
                  <td className="basis">{c.what}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="meta">
          A NetworkRequirement on the intent names one of these; the venues that can
          supply it are read live in the catalogue.{" "}
          <a className="entry-name" href={hashForCategory("network")}>All resources · Networking →</a>
        </p>
      </section>

      <div className="cols cols-2" style={{ gap: "20px" }}>
        <section className="panel stack" style={{ gap: "10px" }} aria-labelledby="network-private">
          <Eyebrow>private links</Eyebrow>
          <h2 id="network-private">Between placements</h2>
          <p className="prose">
            A link between two workloads on two venues is two address leases and a
            policy. Nothing here is drawn as connected until the daemon holds a lease at
            each end.
          </p>
          <Unwired
            would="the links between placements this principal holds, each end's lease and the venue it is on"
            route="private links — no canon object yet; recorded as a gap, not drawn as a feature"
          />
        </section>
        <section className="panel stack" style={{ gap: "10px" }} aria-labelledby="network-gateway">
          <Eyebrow>content gateways</Eyebrow>
          <h2 id="network-gateway">Serving a content address</h2>
          <p className="prose">
            A bucket on Storage becomes a site when an ingress, a name and a certificate
            are bound to its content address. That binding is a job, with a receipt.
          </p>
          <Unwired
            would="gateways serving a content address, with the name and certificate bound to each"
            route="gateway bindings — not on the capability table"
          />
        </section>
      </div>

      <div className="catalog-foot">
        <a className="entry-name" href={hashForCategory("network")}>All resources · Networking — venues and their state now →</a>
        <a className="entry-name" href={hashForSurface("storage")}>Storage →</a>
        <a className="entry-name" href={hashForSurface("job")}>Deploy →</a>
      </div>
    </div>
  );
}

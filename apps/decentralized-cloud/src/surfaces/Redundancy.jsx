import { useEffect } from "react";
import { NotConnected, Chip } from "../components/Bits.jsx";

// REDUNDANCY POSTURE — designed, not connected.
//
// A posture is DECLARED or ABSENT. It is never inferred from a job's shape, never
// defaulted to something safe-sounding, and never applied by a fallback the caller did
// not authorize: doubling a job's cost because a surface guessed the operator would
// have wanted it is a spend nobody approved.
//
// Reactive failover already exists in the daemon. Proactive redundancy is a different
// thing and this surface is careful not to imply the second from the first.

// A TABLE, NOT THREE PROSE CARDS.
//
// This surface failed the paragraph test: strip the prose and three labelled empty
// boxes remained. The honesty survived — the DESIGNED, NOT CONNECTED eyebrow is
// structural — but nothing said which posture the daemon accepts or why the others are
// refused, which is the entire content of the page.
//
// The four columns are the four questions a reader actually has, and each is now a
// cell rather than a clause buried in a paragraph: what is it, will the daemon take it,
// why not, and what would have to be true for it to work.
const POSTURES = [
  {
    id: "none",
    accepted: true,
    what:
      "One placement. If it fails, reactive failover may move the work — that is the " +
      "daemon's existing behaviour and it is not a redundancy posture.",
    whyNot: null,
    needs: null,
  },
  {
    id: "warm_standby",
    accepted: false,
    what:
      "A second placement held ready on a provider of a different class. Hard " +
      "provider-class diversity: two instances at the same vendor are not a standby, " +
      "they are one outage.",
    whyNot: "Replica placement is not built.",
    needs: "A second placement the daemon can hold, and a switch policy that decides when to use it.",
  },
  {
    id: "active_active",
    accepted: false,
    what:
      "Both placements run. The budget multiplier is EXPLICIT in the request — the " +
      "caller states that they are paying twice, because nothing here may quietly " +
      "spend a multiple of what was authorized.",
    whyNot: "Replica placement and per-replica exposure are not built.",
    needs: "A per-replica exposure set, and a budget that authorizes the multiple up front.",
  },
];

export default function Redundancy({ announce }) {
  useEffect(() => { announce("Redundancy — designed, not connected"); }, [announce]);

  return (
    <div className="stack" style={{ gap: "24px" }}>
      {/* This panel said "and this server exposes no mutating route" for a build after
          the job door was wired. It exposes two, and a reviewer put a job through one to
          prove the sentence false — inside the "designed, not connected" panel, which is
          the exact construct this product spends its credibility on.
          I had fixed the header chip and the API surface when I wired the door and
          missed this. My own absence-assertion missed it too, because it was pinned to
          the phrase "read-only surface" and this sentence claimed the same thing in
          different words. An absence assertion pinned to one wording is not an absence
          assertion; the gate now looks for the claim rather than the phrasing. */}
      <NotConnected>
        The postures below are the canonical RedundancyPosture values and this surface
        sets none of them. Declaring a posture is part of a job request — and the daemon
        accepts only <span className="mono">none</span>, refusing the other two by name
        because replica placement, a per-replica exposure set and a switch policy are
        not built yet. A posture is refused rather than quietly downgraded, so
        nothing here can leave you believing your work is protected when it is not.
      </NotConnected>

      <div className="stack" style={{ gap: "9px" }}>
        <h1>Redundancy</h1>
        <p className="prose" style={{ fontSize: "16px" }}>
          A posture is declared or it is absent. It is never inferred, never defaulted,
          and never applied by a fallback you did not authorize.
        </p>
      </div>

      <div className="table-scroll">
        <table className="table t-postures">
          <caption className="sr-only">
            The three redundancy postures, which the daemon accepts, and what each
            refused one would need in order to work
          </caption>
          <thead>
            <tr>
              <th scope="col">Posture</th>
              <th scope="col">Accepted</th>
              <th scope="col">What it means</th>
              <th scope="col">Why not, and what would change it</th>
            </tr>
          </thead>
          <tbody>
            {POSTURES.map((p) => (
              <tr key={p.id} className="trow">
                <th scope="row" className="mono" style={{ fontSize: "13px" }}>{p.id}</th>
                <td>
                  {/* The state as a CHIP, so it survives a reader who is skimming and a
                      reader who is not reading prose at all. This was a fact you could
                      only get by reading a paragraph above the cards. */}
                  {p.accepted
                    ? <Chip kind="live">the daemon accepts this</Chip>
                    : <Chip kind="absent">refused by name</Chip>}
                </td>
                <td className="basis">{p.what}</td>
                <td className="basis">
                  {p.whyNot
                    ? (
                      <div className="stack" style={{ gap: "5px" }}>
                        <div>{p.whyNot}</div>
                        <div className="meta">Would need: {p.needs}</div>
                      </div>
                    )
                    : <span className="meta">— it is the one posture that works today</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <p className="prose">
        Every replica earns its own receipts. A posture that produced one receipt for
        two placements would be a posture you could not audit, and an unaudited replica
        is indistinguishable from a billing error.
      </p>
      <p className="meta">
        STATELESS work only. A posture that runs two copies of something holding state
        is not redundancy, it is two divergent truths.
      </p>
    </div>
  );
}

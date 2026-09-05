import { useEffect } from "react";
import { NotConnected } from "../components/Bits.jsx";

// REDUNDANCY POSTURE — designed, not connected.
//
// A posture is DECLARED or ABSENT. It is never inferred from a job's shape, never
// defaulted to something safe-sounding, and never applied by a fallback the caller did
// not authorize: doubling a job's cost because a surface guessed the operator would
// have wanted it is a spend nobody approved.
//
// Reactive failover already exists in the daemon. Proactive redundancy is a different
// thing and this surface is careful not to imply the second from the first.

const POSTURES = [
  {
    id: "none",
    title: "none",
    body:
      "One placement. If it fails, reactive failover may move the work — that is the " +
      "daemon's existing behaviour and it is not a redundancy posture.",
  },
  {
    id: "warm_standby",
    title: "warm_standby",
    body:
      "A second placement is held ready on a provider of a different class. Hard " +
      "provider-class diversity: two instances at the same vendor are not a standby, " +
      "they are one outage.",
  },
  {
    id: "active_active",
    title: "active_active",
    body:
      "Both placements run. The budget multiplier is EXPLICIT in the request — the " +
      "caller states that they are paying twice, because nothing here may quietly " +
      "spend a multiple of what was authorized.",
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
        until M15.9, because replica placement, a per-replica exposure set and a switch
        policy do not exist yet. A posture is refused rather than quietly downgraded, so
        nothing here can leave you believing your work is protected when it is not.
      </NotConnected>

      <div className="stack" style={{ gap: "9px" }}>
        <h1>Redundancy</h1>
        <p className="prose" style={{ fontSize: "16px" }}>
          A posture is declared or it is absent. It is never inferred, never defaulted,
          and never applied by a fallback you did not authorize.
        </p>
      </div>

      <div className="cols cols-3" style={{ gap: "20px" }}>
        {POSTURES.map((p) => (
          <div key={p.id} className="panel stack" style={{ gap: "9px" }}>
            <div className="eyebrow mono">{p.title}</div>
            <p className="prose">{p.body}</p>
          </div>
        ))}
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

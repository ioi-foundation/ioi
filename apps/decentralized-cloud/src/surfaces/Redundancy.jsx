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
      <NotConnected>
        The postures below are the canonical RedundancyPosture values and this surface
        sets none of them. Declaring a posture is part of a job request, and this server
        exposes no mutating route.
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

import { useEffect } from "react";
import { useSurfaceRead } from "../useSurfaceRead.js";
import { Waiting, Failure, Kept, Eyebrow, Chip } from "../components/Bits.jsx";
import { stamp } from "../logic/classify.mjs";
import PageHead from "../components/PageHead.jsx";

// SETTINGS — wired, to the one route this surface answers itself.
//
// A console's settings page is where a reader learns what the thing in front of them
// is configured to do. Here that is small and exact: the surface's own configuration
// route, which never leaves the process — whether an operator declared a refresh
// cadence, which daemon reads the proxy will forward, and the capability sentence
// generated from the route table. Nothing here is a preference that changes the
// daemon; there is nothing on this surface a reader can set that the daemon honours.
export default function Settings({ announce }) {
  const state = useSurfaceRead("face-config", "/api/face-config");
  const body = state.data;

  useEffect(() => {
    if (state.phase === "first") return;
    announce("Settings — this surface's own configuration");
  }, [state.phase, announce]);

  if (state.phase === "first") return (
    <Waiting
      what="this surface's configuration"
      title="Settings"
      willShow={
        "What this surface is configured to do: whether a refresh cadence is declared, " +
        "which daemon reads its proxy forwards, and the capability sentence generated " +
        "from its route table."
      }
      why="This route is answered in-process and does not ask the daemon."
    />
  );

  const cadence = body?.refresh_cadence_seconds;
  const reads = Array.isArray(body?.daemon_reads) ? body.daemon_reads : [];

  const view = (
    <div className="stack" style={{ gap: "24px" }}>
      <PageHead
        surface="settings"
        title="Settings"
        lede="What this surface is configured to do. Every line is its own configuration route; nothing here changes the daemon."
        aside={<Chip kind="live">wired · GET /api/face-config</Chip>}
      />

      <div className="table-scroll">
        <table className="table t-pairs">
          <caption className="sr-only">This surface's configuration, from its own route</caption>
          <thead>
            <tr>
              <th scope="col">Setting</th>
              <th scope="col">Value</th>
            </tr>
          </thead>
          <tbody>
            <tr className="trow">
              <th scope="row">Refresh cadence</th>
              <td className="basis">
                {typeof cadence === "number"
                  ? <span className="mono">{cadence} s — declared by an operator process, not reachable from here</span>
                  : <span>none declared — this surface makes no claim about when the next batch lands</span>}
              </td>
            </tr>
            <tr className="trow">
              <th scope="row">Daemon reads forwarded</th>
              <td className="basis">
                <ul className="reasons">
                  {reads.map((r) => <li key={r} className="mono">{r}</li>)}
                </ul>
              </td>
            </tr>
            <tr className="trow">
              <th scope="row">Capability</th>
              <td className="basis">{body?.capability || "—"}</td>
            </tr>
            <tr className="trow">
              <th scope="row">Kept answers</th>
              <td className="basis">
                The last answer per surface is kept in this browser only, dated, and
                dropped after a day. Nothing leaves the browser.
              </td>
            </tr>
            <tr className="trow">
              <th scope="row">Motion</th>
              <td className="basis">
                Follows your system&rsquo;s reduced-motion setting. Two things move on
                the face: the mark in the header, which is the brand&rsquo;s own
                animation and claims nothing, and the freshness bar, bound to a
                quote&rsquo;s own window. Both stop under reduced motion.
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div className="stack" style={{ gap: "8px" }}>
        <Eyebrow>note from the route</Eyebrow>
        <p className="prose">{body?.note || "—"}</p>
        <p className="meta">read at {stamp(state.at)}</p>
      </div>
      <Chip kind="live">wired · GET /api/face-config — answered by this surface, never leaves the process</Chip>
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

import { useState } from "react";
import { Button, Muted } from "../ui";
import { putPreference } from "../data/productSurface";
import { SurfaceStateFrame } from "./SurfaceStateFrame";

export function GraphCanvas({ ownerKey }: { ownerKey: string }) {
  const [x, setX] = useState(48);
  const [revision, setRevision] = useState(0);
  const [saved, setSaved] = useState(false);
  const [failed, setFailed] = useState(false);
  const save = async () => {
    try {
      const result = await putPreference(`canvas-${ownerKey}`, "surface_preference", {
        schema_version: "ioi.hypervisor.canvas_layout.v1",
        owner_object_ref: `view://${ownerKey}/draft`, owner_revision: "draft", viewport: { x, y: 24, zoom: 1 },
        presentation_nodes: [{ node_ref: "node://example", x, y: 24 }], presentation_edges: [], semantic_graph_mutation_allowed: false,
      }, revision);
      setRevision(Number(result.preference.revision)); setSaved(true); setFailed(false);
    } catch { setFailed(true); }
  };
  return <section className="hv-canvas" aria-label="Presentation canvas">
    <div className="hv-canvas__toolbar"><Muted>Layout changes persist presentation geometry only; owner graph semantics are unchanged.</Muted><Button onClick={() => setX((value) => value + 16)}>Move presentation node</Button><Button onClick={() => void save()}>Save layout</Button></div>
    <div className="hv-canvas__stage"><div className="hv-canvas__node" style={{ transform: `translateX(${x}px)` }}>Owner-backed node</div></div>
    {saved ? <SurfaceStateFrame state="completed" detail={`Layout revision ${revision} persisted with a mutation receipt.`} /> : null}
    {failed ? <SurfaceStateFrame state="failed" detail="Layout persistence failed; graph semantics were not mutated." /> : null}
  </section>;
}

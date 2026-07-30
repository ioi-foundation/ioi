import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Badge, Card, Heading, Muted, Row, TextInput } from "../ui";
import { loadProductSurfaceProjection, type ProductSurfaceProjection } from "../data/productSurface";
import { SurfaceStateFrame } from "./SurfaceStateFrame";

export function ApplicationsSurface() {
  const [projection, setProjection] = useState<ProductSurfaceProjection | null>(null);
  const [degraded, setDegraded] = useState(false);
  const [search, setSearch] = useState("");
  useEffect(() => { void loadProductSurfaceProjection().then((result) => { setProjection(result.projection); setDegraded(result.source !== "daemon"); }); }, []);
  const entries = useMemo(() => projection?.application_entries.filter((entry) => entry.display_name.toLowerCase().includes(search.toLowerCase())) ?? [], [projection, search]);
  return <div className="hv-page" data-testid="surface-applications"><header className="hv-page__head"><Row><Heading>Applications</Heading><Badge>compiled</Badge></Row><Muted>One policy-filtered catalog feeds navigation, search, command palette, contextual launch, and the Open Application frame.</Muted></header>
    <TextInput aria-label="Search applications" placeholder="Search the compiled catalog" value={search} onChange={(event) => setSearch(event.target.value)} />
    {!projection ? <SurfaceStateFrame state="loading" /> : null}{degraded ? <SurfaceStateFrame state="degraded" detail="The daemon compiler is unavailable. This source-owned fallback is labeled degraded and grants no launch authority." /> : null}
    <div className="hv-app-grid">{entries.map((entry) => <Card key={entry.identity_ref}><Row><h2>{entry.display_name}</h2><Badge tone={entry.launchable ? "success" : "neutral"}>{entry.launchable ? entry.surface_capability_depth ?? "browse" : entry.disabled_reason_codes.join(", ")}</Badge></Row>{entry.launchable && entry.resolved_launch_route ? <Link className="hv-link" to={entry.resolved_launch_route}>Open application</Link> : <Muted>Not launchable</Muted>}</Card>)}</div>
  </div>;
}

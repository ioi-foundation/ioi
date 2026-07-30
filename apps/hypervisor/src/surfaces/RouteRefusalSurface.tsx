import { useLocation } from "react-router-dom";
import { Heading, Muted } from "../ui";
import { SurfaceStateFrame } from "./SurfaceStateFrame";

export function RouteRefusalSurface() {
  const { pathname } = useLocation();
  const replacement = pathname === "/sessions" ? "/work/sessions" : pathname === "/missions" ? "/work" : null;
  return <div className="hv-page" data-testid="route-retirement-refusal"><Heading>Route retired</Heading><SurfaceStateFrame state="denied" detail="This path is retired and does not redirect, proxy, read, mutate, or invoke." /><pre className="hv-record">{JSON.stringify({ schema_version: "ioi.hypervisor.route_retirement_refusal.v1", code: "hypervisor.route_retired", requested_route: pathname, canonical_replacement_route: replacement, read_performed: false, mutation_performed: false, final_invocation_performed: false }, null, 2)}</pre>{replacement ? <Muted>Canonical route guidance: {replacement}</Muted> : null}</div>;
}

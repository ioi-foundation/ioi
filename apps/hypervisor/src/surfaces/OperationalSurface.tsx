import { useEffect, useMemo, useState } from "react";
import { useLocation } from "react-router-dom";
import { Badge, Button, Card, Heading, Muted, Row, TextInput } from "../ui";
import { loadProductSurfaceProjection, queryCollection, type CollectionPage, type ProductSurfaceEntry } from "../data/productSurface";
import { SurfaceStateFrame } from "./SurfaceStateFrame";
import { GraphCanvas } from "./GraphCanvas";

const JOURNEYS: Record<string, { title: string; job: string; owner: string; collection?: string; actions: string[] }> = {
  systems: { title: "Systems", job: "Inspect desired and observed topology without fabricating System truth.", owner: "governed autonomous systems", collection: "systems", actions: ["Inspect topology", "Open interfaces"] },
  projects: { title: "Projects", job: "Organize bounded context, memory, connectors, environments, and work.", owner: "project domain", collection: "projects", actions: ["Open project", "Create proposal"] },
  studio: { title: "Studio", job: "Constitute and compose a bounded autonomous institution.", owner: "system constitution", actions: ["Compose draft", "Preview authority"] },
  automations: { title: "Automations", job: "Define triggers, schedules, monitors, services, and governed workflow runs.", owner: "automation domain", collection: "automations", actions: ["New automation", "Inspect runs"] },
  ontology: { title: "Ontology", job: "Define semantic object, link, action, function, and value-type contracts.", owner: "ontology domain", actions: ["Explore objects", "Draft revision"] },
  data: { title: "Data", job: "Supply governed sources, recipes, datasets, media, consent, and custody posture.", owner: "data domain", actions: ["Add source proposal", "Inspect recipes"] },
  governance: { title: "Governance", job: "Review authority, approvals, leases, policy, budgets, and protected changes.", owner: "authority and policy", actions: ["Review approvals", "Inspect leases"] },
  provenance: { title: "Provenance", job: "Inspect receipts, lineage, replay, artifacts, and state-root continuity.", owner: "evidence and Agentgres", actions: ["Search receipts", "Open replay"] },
  evaluations: { title: "Evaluations", job: "Operate suites, frozen epochs, scorecards, exposure, and re-verification.", owner: "evaluation domain", actions: ["New suite proposal", "Inspect scorecards"] },
  improvement: { title: "Improvement", job: "Govern agendas, candidates, assurance, activation, and recovery handoff.", owner: "improvement domain", actions: ["Open agenda", "Compare candidates"] },
  foundry: { title: "Foundry", job: "Construct admitted model, route, dataset, experiment, and evaluator assets.", owner: "foundry domain", actions: ["New experiment", "Inspect assets"] },
  packages: { title: "Packages", job: "Manage release, dependency, installation, impact, recall, and optional exchange.", owner: "package lifecycle", actions: ["Inspect releases", "Install proposal"] },
  "developer-workspace": { title: "Developer Workspace", job: "Use code, files, terminal, ports, and debugging inside an environment.", owner: "workspace substrate", actions: ["Open environment", "Create session"] },
  "developer-console": { title: "Developer Console", job: "Register connectors, tools, APIs, service identities, SDKs, and conformance.", owner: "connectors and tools", actions: ["Register connector", "Run conformance"] },
  environments: { title: "Environments", job: "Manage runtime placement, lifecycle, services, ports, and recovery.", owner: "environment domain", actions: ["Create proposal", "Inspect runtime"] },
  operations: { title: "Operations", job: "Operate provider capacity, scheduler health, storage custody, failover, and spend.", owner: "operations domain", actions: ["Inspect health", "Open incidents"] },
  "embodied-systems": { title: "Embodied Systems", job: "Reserved for admitted native runtime graphs and deployment-bound supervision.", owner: "embodied runtime", actions: [] },
};

export function OperationalSurface() {
  const key = useLocation().pathname.split("/").filter(Boolean)[0] ?? "systems";
  const journey = JOURNEYS[key] ?? JOURNEYS.systems;
  const [query, setQuery] = useState("");
  const [page, setPage] = useState<CollectionPage | null>(null);
  const [surfaceEntry, setSurfaceEntry] = useState<ProductSurfaceEntry | null>(null);
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    if (!journey.collection) return;
    let live = true; setFailed(false);
    void queryCollection(journey.collection, query).then((value) => { if (live) setPage(value); }).catch(() => { if (live) { setFailed(true); setPage(null); } });
    return () => { live = false; };
  }, [journey.collection, query]);
  useEffect(() => {
    let live = true;
    void loadProductSurfaceProjection().then(({ projection }) => {
      if (!live) return;
      setSurfaceEntry(projection.application_entries.find((entry) => entry.identity_ref === `surface://hypervisor/${key}`) ?? null);
    });
    return () => { live = false; };
  }, [key]);
  const records = useMemo(() => page?.items ?? [], [page]);
  return <div className="hv-page" data-testid={`surface-${key}`}>
    <header className="hv-page__head"><Row><Heading>{journey.title}</Heading><Badge>{surfaceEntry?.surface_capability_depth ?? "unproven"}</Badge></Row><Muted>{journey.job}</Muted><span className="hv-owner">Canonical owner: {journey.owner}</span></header>
    {surfaceEntry && !surfaceEntry.launchable && key !== "embodied-systems" ? <SurfaceStateFrame state="blocked" detail={`The daemon compiler did not admit this surface: ${surfaceEntry.disabled_reason_codes.join(", ") || "no eligible binding"}.`} /> : null}
    {key === "embodied-systems" ? <SurfaceStateFrame state="missing_prerequisite" detail="This registration is planned and deliberately nonlaunchable until its native runtime is admitted." /> : null}
    {journey.collection ? <TextInput aria-label={`Search ${journey.title}`} placeholder="Search policy-visible records" value={query} onChange={(event) => setQuery(event.target.value)} /> : null}
    {journey.collection && !page && !failed ? <SurfaceStateFrame state="loading" /> : null}
    {journey.collection && failed ? <SurfaceStateFrame state="degraded" detail="The daemon collection projection is unavailable; no records are fabricated." /> : null}
    {journey.collection && page && records.length === 0 ? <SurfaceStateFrame state="empty" /> : null}
    {records.map((record, index) => <Card key={String(record.id ?? record.ref ?? index)}><pre className="hv-record">{JSON.stringify(record, null, 2)}</pre></Card>)}
    {page ? <Muted>{page.total_policy_visible} policy-visible · {page.serialized_bytes} bytes · bounded page</Muted> : null}
    {key === "ontology" || key === "studio" || key === "automations" ? <GraphCanvas ownerKey={key} /> : null}
    <div className="hv-action-row">{journey.actions.map((action) => <Button key={action} disabled title="Requires an admitted owner mutation contract and authority preview">{action}</Button>)}</div>
  </div>;
}

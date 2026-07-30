import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { Badge, Card, Heading, Muted, Row } from "../ui";
import { queryCollection, type CollectionPage } from "../data/productSurface";
import { SurfaceStateFrame } from "./SurfaceStateFrame";
import { listGoalRuns, type GoalRunRecord } from "../data/goalRuns";
import { GoalRunPanel } from "./GoalRunPanel";

export function SessionsSurface({ create = false }: { create?: boolean }) {
  const { id } = useParams();
  const [page, setPage] = useState<CollectionPage | null>(null);
  const [failed, setFailed] = useState(false);
  const [goalRuns, setGoalRuns] = useState<GoalRunRecord[] | null>(null);
  useEffect(() => { if (!create) void queryCollection("sessions", id ?? "").then(setPage).catch(() => setFailed(true)); }, [create, id]);
  useEffect(() => { if (!create && id) void listGoalRuns(id).then(setGoalRuns).catch(() => setFailed(true)); }, [create, id]);
  if (create) return <div className="hv-page" data-testid="new-session"><header className="hv-page__head"><Row><Heading>New Session</Heading><Badge>proposal</Badge></Row><Muted>Bind project, environment, model route, harness, tools, memory, privacy, budget, and authority before admission.</Muted></header><SurfaceStateFrame state="missing_prerequisite" detail="Select an admitted environment and model route before a Session launch proposal can be created." /></div>;
  return <div className="hv-page" data-testid="surface-sessions">
    <header className="hv-page__head"><Row><Heading>{id ? `Session ${id}` : "Sessions"}</Heading><Badge>Work projection</Badge></Row><Muted>Transcript, execution waterfall, detail drawer, and typed WorkRun evidence are projections of daemon-owned execution truth.</Muted></header>
    {!page && !failed ? <SurfaceStateFrame state="loading" /> : null}
    {failed ? <SurfaceStateFrame state="degraded" /> : null}
    {page && page.items.length === 0 ? <SurfaceStateFrame state="empty" /> : null}
    {page?.items.map((record, index) => <Card key={String(record.id ?? index)}>
      <div className="hv-session-grid"><section><h2>Transcript</h2><pre className="hv-record">{JSON.stringify(record, null, 2)}</pre></section><section><h2>Execution waterfall</h2><SurfaceStateFrame state="completed" detail="Only admitted event and receipt timings appear here." /></section><aside><h2>Detail</h2><Muted>WorkRun, authority, artifacts, receipts, recovery, and replay references.</Muted></aside></div>
    </Card>)}
    {id && goalRuns?.length === 0 ? <SurfaceStateFrame state="empty" detail="This Session has no admitted GoalRuns." /> : null}
    {goalRuns?.map((run) => <GoalRunPanel key={run.goal_run_id} run={run} />)}
  </div>;
}

import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Badge, Card, Heading, Muted, Row } from "../ui";
import { queryCollection, type CollectionPage } from "../data/productSurface";
import { SurfaceStateFrame } from "./SurfaceStateFrame";
import { listGoalRuns, type GoalRunRecord } from "../data/goalRuns";
import { GoalRunPanel } from "./GoalRunPanel";

export function WorkSurface() {
  const [page, setPage] = useState<CollectionPage | null>(null);
  const [degraded, setDegraded] = useState(false);
  const [goalRuns, setGoalRuns] = useState<GoalRunRecord[] | null>(null);
  const [goalRunsDegraded, setGoalRunsDegraded] = useState(false);
  useEffect(() => { void queryCollection("work_runs").then(setPage).catch(() => setDegraded(true)); }, []);
  useEffect(() => { void listGoalRuns().then(setGoalRuns).catch(() => setGoalRunsDegraded(true)); }, []);
  return <div className="hv-page" data-testid="surface-work">
    <header className="hv-page__head"><Row><Heading>Work</Heading><Badge>typed projection</Badge></Row><Muted>GoalRuns, AutomationRuns, OutcomeRooms, Sessions, WorkRuns, queues, reviews, incidents, and history remain owned by their typed domains.</Muted></header>
    <nav className="hv-tabs"><Link to="/work">Overview</Link><Link to="/work/sessions">Sessions</Link><Link to="/work/new-session">New Session</Link></nav>
    {!page && !degraded ? <SurfaceStateFrame state="loading" /> : null}
    {degraded ? <SurfaceStateFrame state="degraded" /> : null}
    {page && page.items.length === 0 ? <SurfaceStateFrame state="empty" detail="No policy-visible WorkRuns exist for this organization." /> : null}
    {page?.items.map((record, index) => <Card key={String(record.id ?? index)}><pre className="hv-record">{JSON.stringify(record, null, 2)}</pre></Card>)}
    <section aria-labelledby="goal-runs-heading">
      <h2 id="goal-runs-heading">GoalRuns</h2>
      {!goalRuns && !goalRunsDegraded ? <SurfaceStateFrame state="loading" /> : null}
      {goalRunsDegraded ? <SurfaceStateFrame state="degraded" detail="GoalRun owner records are unavailable; no fixture data is shown." /> : null}
      {goalRuns?.length === 0 ? <SurfaceStateFrame state="empty" detail="No policy-visible GoalRuns exist." /> : null}
      {goalRuns?.map((run) => <GoalRunPanel key={run.goal_run_id} run={run} />)}
    </section>
  </div>;
}

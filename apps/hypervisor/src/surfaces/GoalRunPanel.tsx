import { useEffect, useState } from "react";
import { Badge, Card, Muted, Row } from "../ui";
import { listGoalRunEvents, type GoalRunRecord } from "../data/goalRuns";
import { SurfaceStateFrame } from "./SurfaceStateFrame";

function resultState(run: GoalRunRecord) {
  if (run.status === "complete") return "completed" as const;
  if (run.status === "revoked") return "denied" as const;
  if (run.blockers?.length) return "blocked" as const;
  if (run.continuation_state === "course_correcting") return "recovery" as const;
  return null;
}

export function GoalRunPanel({ run }: { run: GoalRunRecord }) {
  const [events, setEvents] = useState<Array<Record<string, unknown>> | null>(null);
  const [eventFailure, setEventFailure] = useState(false);
  useEffect(() => {
    void listGoalRunEvents(run.goal_run_id).then(setEvents).catch(() => setEventFailure(true));
  }, [run.goal_run_id]);
  const state = resultState(run);
  return <Card>
    <Row>
      <h2>{run.normalized_goal}</h2>
      <Badge>{run.admission_path_status.replace(/_/g, " ")}</Badge>
      <Badge>{run.status}</Badge>
    </Row>
    <Muted>{run.goal_ref} · {run.result_profile ?? "profile not projected"}</Muted>
    {state ? <SurfaceStateFrame state={state} detail={`${run.continuation_state}; ${run.work_result_refs.length} retained result(s), ${run.receipt_refs.length} receipt ref(s).`} /> : null}
    <div className="hv-session-grid">
      <section aria-label="GoalRun transcript">
        <h2>Transcript</h2>
        {!events && !eventFailure ? <SurfaceStateFrame state="loading" /> : null}
        {eventFailure ? <SurfaceStateFrame state="degraded" detail="The event owner is unavailable; no transcript was synthesized." /> : null}
        {events?.length === 0 ? <SurfaceStateFrame state="empty" detail="No admitted GoalRun events exist yet." /> : null}
        {events?.length ? <ol className="hv-run-events">{events.map((event, index) => <li key={String(event.event_id ?? index)}><pre className="hv-record">{JSON.stringify(event, null, 2)}</pre></li>)}</ol> : null}
      </section>
      <section aria-label="GoalRun execution waterfall">
        <h2>Execution waterfall</h2>
        <dl className="hv-run-facts">
          <div><dt>Phase</dt><dd>{run.active_loop_phase ?? "not selected"}</dd></div>
          <div><dt>Continuation</dt><dd>{run.continuation_state}</dd></div>
          <div><dt>Topology</dt><dd>{run.role_topology_ref ?? "direct single pursuit"}</dd></div>
        </dl>
      </section>
      <aside aria-label="GoalRun evidence detail">
        <h2>Detail</h2>
        <dl className="hv-run-facts">
          <div><dt>Results</dt><dd>{run.work_result_refs.length}</dd></div>
          <div><dt>Receipts</dt><dd>{run.receipt_refs.length}</dd></div>
          <div><dt>Lifecycle records</dt><dd>{run.lifecycle_record_refs?.length ?? 0}</dd></div>
        </dl>
      </aside>
    </div>
  </Card>;
}

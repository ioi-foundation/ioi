// Automations surface — source-owned React, source-derived from the product-ui automations
// route (sticky header + New action → stat cards → list rows, with a template-led empty state).
// Same route anatomy and visual system; the only change is the data boundary: a typed daemon
// client (automationsModel.fetchAutomations → GET /v1/hypervisor/automations).
import { useEffect, useState } from "react";
import { CalendarClock, Hand, Workflow, Plus, Play } from "lucide-react";
import "./Automations.css";
import { Skeleton } from "../../components/Skeleton";
import {
  computeStats,
  fetchAutomations,
  relativeTime,
  stepSummary,
  triggerLabel,
  type Automation,
  type AutomationsData,
} from "./automationsModel";

const NEW_HREF = "/automations/new";

function triggerIcon(kind?: string) {
  if (kind === "schedule") return <CalendarClock size={15} />;
  if (kind === "event") return <Workflow size={15} />;
  return <Hand size={15} />;
}

function AutomationRow({ a }: { a: Automation }) {
  const kind = a.trigger?.kind || "manual";
  return (
    <div className="au-row" data-testid="automation-row">
      <span className="au-rowicon" aria-hidden="true">
        {triggerIcon(kind)}
      </span>
      <div className="au-rowmain">
        <div className="au-rowname">
          {a.name || a.automation_id}
          <span className="au-pill au-trigger">{triggerLabel(a.trigger)}</span>
        </div>
        <div className="au-rowmeta">
          {a.project_id || "—"} · {stepSummary(a.steps)}
          {a.environment_class_id ? (
            <>
              {" · "}
              <code>{a.environment_class_id}</code>
            </>
          ) : null}
        </div>
      </div>
      <span className="au-rowage">{relativeTime(a.created_at)}</span>
      <a
        className="au-run"
        href={`${NEW_HREF}?from=${encodeURIComponent(a.automation_id)}`}
        data-testid="automation-run"
      >
        <Play size={13} /> Run
      </a>
    </div>
  );
}

export function AutomationsView() {
  const [data, setData] = useState<AutomationsData | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    fetchAutomations()
      .then((d) => live && setData(d))
      .catch((e) => live && setError(String(e?.message || e)));
    return () => {
      live = false;
    };
  }, []);

  const automations = data?.automations || [];
  const hasAny = automations.length > 0;
  const stats = computeStats(automations);

  return (
    <div className="au-wrap">
      <div className="au-head">
        <div>
          <div className="au-brand">IOI Hypervisor</div>
          <h1 className="au-h1">Automations</h1>
        </div>
        <a className="au-new" href={NEW_HREF} data-testid="automations-new">
          <Plus size={16} /> New
        </a>
      </div>
      <p className="au-sub">
        Run agents on a schedule or automatically in response to events. Each workflow runs in a
        fresh, policy-gated environment with its own scoped capability leases.
      </p>

      {error && (
        <div className="au-empty" data-testid="automations-error">
          Daemon unavailable: {error}
        </div>
      )}
      {!error && data === null && (
        <div data-testid="automations-loading" role="status" aria-label="Loading automations" aria-busy="true">
          <div className="au-stats" aria-hidden="true">
            {[0, 1, 2].map((i) => (
              <div className="au-stat au-stat-skel" key={i}>
                <Skeleton w="55%" h={11} r={5} />
                <Skeleton w={44} h={22} className="au-skel-statvalue" />
              </div>
            ))}
          </div>
          <section className="au-list" aria-hidden="true">
            {[0, 1, 2, 3].map((i) => (
              <div className="au-row au-row-skel" key={i}>
                <Skeleton w={30} h={30} r={8} />
                <div className="au-rowmain">
                  <Skeleton w={`${36 + ((i * 9) % 28)}%`} h={13} />
                  <Skeleton w={`${52 + ((i * 6) % 22)}%`} h={11} r={5} className="au-skel-meta" />
                </div>
                <Skeleton w={62} h={28} r={8} />
              </div>
            ))}
          </section>
        </div>
      )}

      {!error && data !== null && (
        <div className="au-stats" data-testid="automations-stats">
          {stats.map((s) => (
            <div
              key={s.key}
              className={"au-stat" + (s.accent ? " is-accent" : "")}
              data-testid="automation-stat"
            >
              <div className="au-statlabel">{s.label}</div>
              <div className="au-statvalue">{s.value}</div>
            </div>
          ))}
        </div>
      )}

      {!error && data !== null && !hasAny && (
        <div className="au-blank" data-testid="automations-empty">
          <Workflow size={26} className="au-blankicon" aria-hidden="true" />
          <div className="au-blanktitle">No automations yet</div>
          <div className="au-blanktext">
            Run agents on a schedule or in response to events. Click New to create your first
            workflow.
          </div>
          <a className="au-new au-blankcta" href={NEW_HREF}>
            <Plus size={16} /> Create automation
          </a>
        </div>
      )}

      {!error && data !== null && hasAny && (
        <section className="au-list" data-testid="automations-list">
          {automations.map((a) => (
            <AutomationRow key={a.automation_id} a={a} />
          ))}
        </section>
      )}
    </div>
  );
}

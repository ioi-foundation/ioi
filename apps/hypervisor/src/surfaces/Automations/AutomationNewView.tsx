// New automation surface — source-owned React, source-derived from the product-ui /automations/new
// route (back link → titled create form: name, trigger kind, steps → submit). Same route anatomy;
// the only change is the data boundary: an honest daemon create (automationsModel.createAutomation
// → POST /v1/hypervisor/automations), which returns the persisted record. Nothing is fabricated —
// on success we show the real created automation; on failure we surface the daemon's reason.
import { useState } from "react";
import {
  ArrowLeft,
  CalendarClock,
  Check,
  Hand,
  Plus,
  Trash2,
  Workflow,
} from "lucide-react";
import "./Automations.css";
import {
  createAutomation,
  type Automation,
  type AutomationStep,
} from "./automationsModel";

type TriggerKind = "manual" | "schedule" | "event";

type StepDraft = { kind: string; value: string };

const TRIGGERS: { kind: TriggerKind; label: string; icon: JSX.Element }[] = [
  { kind: "manual", label: "Manual", icon: <Hand size={15} /> },
  { kind: "schedule", label: "Cron schedule", icon: <CalendarClock size={15} /> },
  { kind: "event", label: "Event", icon: <Workflow size={15} /> },
];

const STEP_KINDS = ["agent", "command", "proposal"] as const;

function stepValuePlaceholder(kind: string): string {
  if (kind === "command") return "shell command (e.g. npm test)";
  if (kind === "proposal") return "proposal title";
  return "agent prompt";
}

function toAutomationStep(s: StepDraft): AutomationStep {
  const value = s.value.trim();
  if (s.kind === "command") return { kind: "command", command: value };
  if (s.kind === "proposal") return { kind: "proposal", title: value };
  return { kind: "agent", prompt: value };
}

export function AutomationNewView() {
  const [name, setName] = useState("");
  const [trigger, setTrigger] = useState<TriggerKind>("manual");
  const [cron, setCron] = useState("0 9 * * 1");
  const [event, setEvent] = useState("");
  const [project, setProject] = useState("");
  const [steps, setSteps] = useState<StepDraft[]>([{ kind: "agent", value: "" }]);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [created, setCreated] = useState<Automation | null>(null);

  const validSteps = steps.filter((s) => s.value.trim().length > 0);
  const canSubmit =
    name.trim().length > 0 &&
    validSteps.length > 0 &&
    (trigger !== "event" || event.trim().length > 0) &&
    !submitting;

  function setStep(i: number, patch: Partial<StepDraft>) {
    setSteps((prev) => prev.map((s, idx) => (idx === i ? { ...s, ...patch } : s)));
  }
  function addStep() {
    setSteps((prev) => [...prev, { kind: "agent", value: "" }]);
  }
  function removeStep(i: number) {
    setSteps((prev) => (prev.length > 1 ? prev.filter((_, idx) => idx !== i) : prev));
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!canSubmit) return;
    setSubmitting(true);
    setError(null);
    try {
      const automation = await createAutomation({
        name,
        trigger: {
          kind: trigger,
          ...(trigger === "schedule" ? { cron: cron.trim() } : {}),
          ...(trigger === "event" ? { event: event.trim() } : {}),
        },
        steps: validSteps.map(toAutomationStep),
        project_id: project,
      });
      setCreated(automation);
    } catch (err) {
      setError(String((err as Error)?.message || err));
    } finally {
      setSubmitting(false);
    }
  }

  if (created) {
    return (
      <div className="au-wrap" data-testid="automation-new-page">
        <a className="aun-back" href="/automations" data-testid="automation-new-back">
          <ArrowLeft size={14} /> Automations
        </a>
        <div className="aun-success" data-testid="automation-new-success">
          <span className="aun-success-icon" aria-hidden="true">
            <Check size={22} />
          </span>
          <h1 className="au-h1">Automation created</h1>
          <p className="au-sub">
            <strong>{created.name}</strong> was admitted by the daemon.
          </p>
          <dl className="aun-receipt" data-testid="automation-new-receipt">
            <div>
              <dt>ID</dt>
              <dd>
                <code>{created.automation_id}</code>
              </dd>
            </div>
            <div>
              <dt>Trigger</dt>
              <dd>{created.trigger?.kind || "manual"}</dd>
            </div>
            <div>
              <dt>Steps</dt>
              <dd>{(created.steps || []).length}</dd>
            </div>
            <div>
              <dt>Environment class</dt>
              <dd>
                <code>{created.environment_class_id || "—"}</code>
              </dd>
            </div>
          </dl>
          <a className="au-new aun-cta" href="/automations">
            View automations
          </a>
        </div>
      </div>
    );
  }

  return (
    <div className="au-wrap" data-testid="automation-new-page">
      <a className="aun-back" href="/automations" data-testid="automation-new-back">
        <ArrowLeft size={14} /> Automations
      </a>
      <h1 className="au-h1">New automation</h1>
      <p className="au-sub">
        Run agents on a schedule or in response to events. Each workflow runs in a fresh,
        policy-gated environment with its own scoped capability leases.
      </p>

      <form className="aun-form" onSubmit={submit} data-testid="automation-new-form">
        <label className="aun-field">
          <span className="aun-label">Name</span>
          <input
            className="aun-input"
            type="text"
            placeholder="e.g. nightly-changelog"
            value={name}
            onChange={(e) => setName(e.target.value)}
            data-testid="automation-name"
          />
        </label>

        <fieldset className="aun-field aun-fieldset">
          <span className="aun-label">Trigger</span>
          <div className="aun-triggers" data-testid="automation-triggers">
            {TRIGGERS.map((t) => (
              <button
                type="button"
                key={t.kind}
                className={"aun-trigger" + (trigger === t.kind ? " is-active" : "")}
                onClick={() => setTrigger(t.kind)}
                data-testid={`automation-trigger-${t.kind}`}
                aria-pressed={trigger === t.kind}
              >
                {t.icon} {t.label}
              </button>
            ))}
          </div>
          {trigger === "schedule" && (
            <input
              className="aun-input aun-input-sub"
              type="text"
              placeholder="cron expression (e.g. 0 9 * * 1)"
              value={cron}
              onChange={(e) => setCron(e.target.value)}
              data-testid="automation-cron"
            />
          )}
          {trigger === "event" && (
            <input
              className="aun-input aun-input-sub"
              type="text"
              placeholder="event name (e.g. pull_request.opened)"
              value={event}
              onChange={(e) => setEvent(e.target.value)}
              data-testid="automation-event"
            />
          )}
        </fieldset>

        <label className="aun-field">
          <span className="aun-label">
            Project <span className="aun-optional">(optional)</span>
          </span>
          <input
            className="aun-input"
            type="text"
            placeholder="project id"
            value={project}
            onChange={(e) => setProject(e.target.value)}
            data-testid="automation-project"
          />
        </label>

        <fieldset className="aun-field aun-fieldset">
          <span className="aun-label">Steps</span>
          <div className="aun-steps" data-testid="automation-steps">
            {steps.map((s, i) => (
              <div className="aun-step" key={i} data-testid="automation-step">
                <select
                  className="aun-select"
                  value={s.kind}
                  onChange={(e) => setStep(i, { kind: e.target.value })}
                  data-testid="automation-step-kind"
                >
                  {STEP_KINDS.map((k) => (
                    <option key={k} value={k}>
                      {k}
                    </option>
                  ))}
                </select>
                <input
                  className="aun-input aun-step-input"
                  type="text"
                  placeholder={stepValuePlaceholder(s.kind)}
                  value={s.value}
                  onChange={(e) => setStep(i, { value: e.target.value })}
                  data-testid="automation-step-value"
                />
                <button
                  type="button"
                  className="aun-step-remove"
                  onClick={() => removeStep(i)}
                  disabled={steps.length <= 1}
                  aria-label="Remove step"
                  data-testid="automation-step-remove"
                >
                  <Trash2 size={14} />
                </button>
              </div>
            ))}
          </div>
          <button
            type="button"
            className="aun-addstep"
            onClick={addStep}
            data-testid="automation-add-step"
          >
            <Plus size={14} /> Add step
          </button>
        </fieldset>

        {error && (
          <div className="au-empty" data-testid="automation-new-error">
            Couldn’t create automation: {error}
          </div>
        )}

        <div className="aun-actions">
          <a className="aun-cancel" href="/automations">
            Cancel
          </a>
          <button
            type="submit"
            className="au-new"
            disabled={!canSubmit}
            data-testid="automation-submit"
          >
            {submitting ? "Creating…" : "Create automation"}
          </button>
        </div>
      </form>
    </div>
  );
}

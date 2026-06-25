// Layer 3 — Home cockpit, product-grade AND working: real Model/Project/Reasoning dropdowns backed
// by the daemon, and a New Session that actually launches (creates + starts an environment and lands
// in its Workbench over the Session Execution Binding).
import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Heading, Muted, Button, TextArea, Spacer, Dropdown,
  BrandMark, IconSend, IconPlus, IconProjects, IconSpark, IconBug, IconShield,
} from "../ui";
import { createHypervisorDaemonClient } from "../services/hypervisorDaemonClient";

const client = createHypervisorDaemonClient();

const REASONING = [{ value: "low", label: "Low" }, { value: "medium", label: "Medium" }, { value: "high", label: "High" }];
const SUGGESTIONS = [
  { label: "Automate env setup", Icon: IconSpark },
  { label: "Fix a bug", Icon: IconBug },
  { label: "Boost test coverage", Icon: IconShield },
];

export function HomeCockpit() {
  const navigate = useNavigate();
  const [task, setTask] = useState("");
  const [models, setModels] = useState<Array<{ value: string; label: string }>>([]);
  const [model, setModel] = useState("");
  const [projects, setProjects] = useState<Array<{ value: string; label: string }>>([{ value: "scratch", label: "Work in a project" }]);
  const [project, setProject] = useState("scratch");
  const [reasoning, setReasoning] = useState("medium");
  const [launching, setLaunching] = useState(false);

  useEffect(() => {
    void client.listModels().then((r) => {
      const opts = r.models.map((m) => ({ value: m.id, label: m.id }));
      setModels(opts);
      if (opts[0]) setModel(opts[0].value);
    });
    void client.listProjects().then((r) => {
      const opts = (r.projects ?? []).map((p) => ({ value: String(p.project_id ?? p.id ?? p.name), label: String(p.name ?? p.project_id ?? p.id) }));
      setProjects([{ value: "scratch", label: "Work in a project" }, ...opts]);
    });
  }, []);

  const launch = async () => {
    setLaunching(true);
    try {
      const r = await client.createEnvironment({ environment_class_id: "local-workspace-v0", project_id: project === "scratch" ? "native-ux" : project });
      const id = r.environment?.id;
      if (id) { await client.environmentAction(id, "start"); navigate(`/workbench/${id}`); }
    } finally { setLaunching(false); }
  };

  return (
    <div className="hv-cockpit" data-testid="home-surface">
      <div className="hv-cockpit__hero">
        <span className="hv-cockpit__mark"><BrandMark size={26} /></span>
        <Heading level={1}>What do you want to get done today?</Heading>
        <Muted>Launch governed work — pick a project, model, and authority context.</Muted>
      </div>

      <div className="hv-cockpit__composer">
        <TextArea placeholder="Describe your task or type / for commands" value={task} onChange={(e) => setTask(e.target.value)} data-testid="composer-input" />
        <div className="hv-cockpit__bar" data-testid="composer-knobs">
          <Dropdown icon={<IconProjects size={14} />} value={project} options={projects} onChange={setProject} testId="composer-project" />
          <Dropdown label="Model" value={model} options={models.length ? models : [{ value: "", label: "—" }]} onChange={setModel} testId="composer-model" />
          <Dropdown label="Reasoning" value={reasoning} options={REASONING} onChange={setReasoning} testId="composer-reasoning" />
          <Spacer />
          <Button variant="ghost" size="sm" title="Attach context" aria-label="Attach"><IconPlus size={15} /></Button>
          <Button variant="primary" size="sm" onClick={launch} disabled={launching} data-testid="composer-launch" title="Launch session">
            <IconSend size={15} />{launching ? "Launching…" : ""}
          </Button>
        </div>
      </div>

      <div className="hv-cockpit__suggestions">
        {SUGGESTIONS.map(({ label, Icon }) => (
          <button key={label} className="hv-suggestion" data-testid="suggestion" type="button" onClick={() => setTask(label)}><Icon size={14} /><span>{label}</span></button>
        ))}
      </div>
    </div>
  );
}

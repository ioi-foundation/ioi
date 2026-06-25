// Layer 3 — the Applications catalog (foundations/01-ux-shell-and-ia.md). The breadth layer: a
// queryable modal, NOT rail sprawl. Groups + the v2 catalog surfaces. Built surfaces route into the
// Open Application frame; not-yet-built surfaces are honestly marked (open the build-status frame).
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Modal, TextInput } from "../ui";

type App = { id: string; name: string; job: string; route?: string; built: boolean };
type Group = { label: string; apps: App[] };

// The v2 estate, grouped per canon catalog labels. `built` = a live native route exists today.
const CATALOG: Group[] = [
  { label: "Developer Workbench", apps: [
    { id: "workbench", name: "Workbench", job: "Code, files, terminals, changes, receipts — IDE of IDEs.", route: "/environments", built: true },
    { id: "environments", name: "Environments", job: "Provider placement, env lifecycle, services, tasks, ports, restore.", route: "/environments", built: true },
  ] },
  { label: "Agents & Models", apps: [
    { id: "agent-studio", name: "Agent Studio", job: "Author agents/workers: harness, tools, memory, route, authority, packaging.", built: false },
    { id: "foundry", name: "Foundry", job: "Model/dataset/eval/training/experiment/conversion/inference/promotion factory.", built: false },
  ] },
  { label: "Automation", apps: [
    { id: "automations", name: "Automations", job: "Durable workflows, services, schedules, triggers, functions, MCP-as-tool.", route: "/automations", built: false },
  ] },
  { label: "Data & Ontology", apps: [
    { id: "odk", name: "ODK", job: "Ontology, data recipes, datasets, blueprints, generate object-aware surfaces.", built: false },
    { id: "domain-apps", name: "Domain Apps", job: "Operate generated object-aware consoles + ad-hoc analysis.", built: false },
  ] },
  { label: "Govern & Privacy", apps: [
    { id: "governance", name: "Governance", job: "Authority, policy, approvals, revocation, release controls, RSI gates.", built: false },
  ] },
  { label: "Operate & Evidence", apps: [
    { id: "operations", name: "Operations", job: "Jobs, incidents, health, routing, resource queues/quotas/spend.", built: false },
    { id: "work-ledger", name: "Work Ledger", job: "Receipts, replay, proof, artifacts, state roots, settlement views.", built: false },
  ] },
  { label: "Packages & Learning", apps: [
    { id: "marketplace", name: "Marketplace", job: "Install/publish/hire workers, packages, integrations, blueprints, outcomes.", built: false },
    { id: "developer-integrations", name: "Developer & Integrations", job: "Connectors, MCP gateway, APIs, SDKs, ADK, service accounts, conformance.", built: false },
  ] },
  { label: "Domain Apps", apps: [
    { id: "robot-fleets", name: "Robot Fleets / Embodied", job: "Roadmap: fleet identity, control bridge, sensor/actuator, failsafe, replay.", built: false },
  ] },
];

export function ApplicationsModal({ onClose }: { onClose: () => void }) {
  const navigate = useNavigate();
  const [q, setQ] = useState("");
  const query = q.trim().toLowerCase();
  const groups = CATALOG.map((g) => ({
    ...g,
    apps: g.apps.filter((a) => !query || a.name.toLowerCase().includes(query) || a.job.toLowerCase().includes(query)),
  })).filter((g) => g.apps.length > 0);

  const open = (a: App) => {
    if (a.built && a.route) { navigate(a.route); onClose(); }
    else { navigate(`/app/${a.id}`); onClose(); } // build-status frame for not-yet-built surfaces
  };

  return (
    <Modal title="Applications" onClose={onClose}>
      <div className="hv-col">
        <TextInput autoFocus placeholder="Search applications…" value={q} onChange={(e) => setQ(e.target.value)} data-testid="apps-search" />
        <div className="hv-catalog__groups" data-testid="apps-catalog">
          {groups.map((g) => (
            <div key={g.label}>
              <div className="hv-catalog__group-label" data-testid="apps-group">{g.label}</div>
              <div className="hv-col">
                {g.apps.map((a) => (
                  <div key={a.id} className="hv-appcard" data-testid="appcard" onClick={() => open(a)}>
                    <div className="hv-row">
                      <span className="hv-appcard__name">{a.name}</span>
                      {!a.built && <span className="hv-badge hv-badge--neutral">soon</span>}
                    </div>
                    <span className="hv-appcard__job">{a.job}</span>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    </Modal>
  );
}

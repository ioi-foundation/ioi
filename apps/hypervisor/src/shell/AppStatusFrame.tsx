// Layer 3 — honest build-status frame for catalog surfaces not yet built (and the Projects /
// Automations / New Session rail targets). Renders inside the Open Application frame. No fake UI:
// it names the surface, its v2 job, and that it lands in a later application-surface slice.
import { useParams, Link } from "react-router-dom";
import { Heading, Muted, Badge, Card, Col, Row } from "../ui";
import { EmptyState } from "../ui";

const JOBS: Record<string, { name: string; job: string }> = {
  "agent-studio": { name: "Agent Studio", job: "Author agents/workers: harness, tools, memory, model route, authority, packaging." },
  foundry: { name: "Foundry", job: "Model/dataset/eval/training/experiment/conversion/inference/promotion factory." },
  odk: { name: "ODK", job: "Ontology, data recipes, datasets, blueprints, and generate object-aware surfaces." },
  "domain-apps": { name: "Domain Apps", job: "Operate generated object-aware consoles + ad-hoc analysis." },
  governance: { name: "Governance", job: "Authority, policy, approvals, revocation, release controls, RSI proposal gates." },
  operations: { name: "Operations", job: "Jobs, incidents, health, routing, resource queues/quotas/spend." },
  "work-ledger": { name: "Work Ledger", job: "Receipts, replay, proof, artifacts, state roots, settlement views." },
  marketplace: { name: "Marketplace", job: "Install/publish/hire workers, packages, integrations, blueprints, outcomes." },
  "developer-integrations": { name: "Developer & Integrations", job: "Connectors, MCP gateway, APIs, SDKs, ADK, service accounts, conformance." },
  "robot-fleets": { name: "Robot Fleets / Embodied", job: "Roadmap: fleet identity, control bridge, sensor/actuator registry, failsafe, replay." },
  projects: { name: "Projects", job: "Durable work containers, collaboration contexts, repos, workspaces, files, proof posture." },
  automations: { name: "Automations", job: "Durable workflows, services, schedules, triggers, functions, MCP-as-tool composition." },
  settings: { name: "Organization settings", job: "Preferences only. Authority/policy/approvals live in Governance." },
};

export function AppStatusFrame({ surfaceId }: { surfaceId?: string }) {
  const params = useParams();
  const id = surfaceId ?? params.id ?? "";
  const entry = JOBS[id] ?? { name: id || "Application", job: "A v2 catalog surface." };
  return (
    <div style={{ padding: "var(--spacing-xl)" }}>
      <Card>
        <Col>
          <Row>
            <Heading level={1}>{entry.name}</Heading>
            <Badge tone="neutral">not built yet</Badge>
          </Row>
          <Muted>{entry.job}</Muted>
          <EmptyState
            title="Lands in a later application-surface slice"
            hint="The UX substrate (kit + shell) is the current lane. Catalog surfaces are built on it, one slice at a time, after the substrate gate is green."
          >
            <Link to="/environments" className="hv-link">← Open Environments (a live surface)</Link>
          </EmptyState>
        </Col>
      </Card>
    </div>
  );
}

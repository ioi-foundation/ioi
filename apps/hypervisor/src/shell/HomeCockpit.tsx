// Layer 3 — Home cockpit. The command surface (foundations/01-ux-shell-and-ia.md). Composer
// bundles the canon vocabulary (Agent·Mode·Model·Reasoning·Speed·Tools·Memory·Authority·Budget·
// Privacy) as knobs, with suggestions. Product language only; subsystem terms live in advanced.
import { useState } from "react";
import { Heading, Muted, Button, TextArea, Row, Spacer } from "../ui";

const KNOBS = ["Agent", "Mode", "Model", "Reasoning", "Speed", "Tools", "Memory", "Authority", "Budget", "Privacy"];
const SUGGESTIONS = ["Automate env setup", "Fix a bug", "Boost test coverage"];

export function HomeCockpit() {
  const [task, setTask] = useState("");
  return (
    <div className="hv-cockpit" data-testid="home-surface">
      <div className="hv-col" style={{ textAlign: "center" }}>
        <Heading level={1}>What do you want to get done today?</Heading>
        <Muted>Launch governed work — pick a project, model, and authority context.</Muted>
      </div>
      <div className="hv-cockpit__composer">
        <TextArea placeholder="Describe your task or type / for commands" value={task} onChange={(e) => setTask(e.target.value)} data-testid="composer-input" />
        <div className="hv-cockpit__knobs" data-testid="composer-knobs">
          {KNOBS.map((k) => <span key={k} className="hv-knob">{k}</span>)}
        </div>
        <Row>
          <Muted>Work in a project</Muted>
          <Spacer />
          <Button variant="primary" disabled={!task.trim()} data-testid="composer-launch">New Session</Button>
        </Row>
      </div>
      <Row wrap>
        {SUGGESTIONS.map((s) => <span key={s} className="hv-chip" data-testid="suggestion">{s}</span>)}
      </Row>
    </div>
  );
}

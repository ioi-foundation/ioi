// Layer 3 — Home cockpit, product-grade. The command surface (foundations/01-ux-shell-and-ia.md):
// brand mark, a composer that reads like a real command box (project + model + reasoning selectors,
// attach, send), and iconed suggestions. Composer vocabulary lives behind the selectors + Advanced.
import { useState } from "react";
import {
  Heading, Muted, Button, TextArea, Spacer,
  BrandMark, IconSend, IconPlus, IconChevronDown, IconProjects, IconSpark, IconBug, IconShield,
} from "../ui";

const SUGGESTIONS = [
  { label: "Automate env setup", Icon: IconSpark },
  { label: "Fix a bug", Icon: IconBug },
  { label: "Boost test coverage", Icon: IconShield },
];

function Selector({ icon, label, value, testId }: { icon?: React.ReactNode; label?: string; value: string; testId?: string }) {
  return (
    <button className="hv-selector" data-testid={testId} type="button">
      {icon}
      {label && <span className="hv-tertiary">{label}</span>}
      <span className="hv-selector__value">{value}</span>
      <IconChevronDown size={13} />
    </button>
  );
}

export function HomeCockpit() {
  const [task, setTask] = useState("");
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
          <Selector icon={<IconProjects size={14} />} value="Work in a project" testId="composer-project" />
          <Selector label="Model" value="Native local" testId="composer-model" />
          <Selector label="Reasoning" value="Medium" testId="composer-reasoning" />
          <Spacer />
          <Button variant="ghost" size="sm" title="Attach context" aria-label="Attach"><IconPlus size={15} /></Button>
          <Button variant="primary" size="sm" disabled={!task.trim()} data-testid="composer-launch" title="Launch session"><IconSend size={15} /></Button>
        </div>
      </div>

      <div className="hv-cockpit__suggestions">
        {SUGGESTIONS.map(({ label, Icon }) => (
          <button key={label} className="hv-suggestion" data-testid="suggestion" type="button"><Icon size={14} /><span>{label}</span></button>
        ))}
      </div>
    </div>
  );
}

// Estate status manifest — the single place status truth flips when a
// surface changes stage. Both estate sites consume this shape (ioi-ai mirrors
// it); public copy must not claim a stage ahead of this file. Keys are
// hypervisor.com product slugs plus estate-level surfaces. Never mark a
// surface ahead of what actually ships.

const ESTATE_STATUS = {
  version: "2026-07-21",
  labels: {
    "private-preview": "Private preview",
    "design-stage": "Design stage",
    "single-node-proof": "Single-node proof",
    "evidence-gated": "Evidence-gated",
    planned: "Planned",
  },
  surfaces: {
    app: "private-preview",
    web: "private-preview",
    cli: "private-preview",
    sdk: "private-preview",
    adk: "private-preview",
    odk: "private-preview",
    mcp: "private-preview",
    os: "design-stage",
    embodied: "design-stage",
    "authority-gateway": "single-node-proof",
    "ioi-l1": "evidence-gated",
    "ioi-ai-goal-space": "planned",
  },
};

if (typeof window !== "undefined") window.ESTATE_STATUS = ESTATE_STATUS;
export default ESTATE_STATUS;

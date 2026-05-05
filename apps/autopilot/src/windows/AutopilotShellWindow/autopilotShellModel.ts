import type { AssistantUserProfile } from "../../types";

export type PrimaryView =
  | "home"
  | "chat"
  | "workspace"
  | "workflows"
  | "runs"
  | "mounts"
  | "inbox"
  | "capabilities"
  | "policy"
  | "settings";

export interface ProjectScope {
  id: string;
  name: string;
  description: string;
  environment: string;
  rootPath: string;
}

export const DEFAULT_PROFILE: AssistantUserProfile = {
  version: 1,
  displayName: "Operator",
  preferredName: null,
  roleLabel: "Private Operator",
  timezone: "UTC",
  locale: "en-US",
  primaryEmail: null,
  avatarSeed: "OP",
  groundingAllowed: false,
};

export const WORKSPACE_NAME = "IOI Workspace";

export const PROJECT_SCOPES: ProjectScope[] = [
  {
    id: "autopilot-core",
    name: "Autopilot Core",
    description: "Worker control plane and operator shell.",
    environment: "Production",
    rootPath: ".",
  },
  {
    id: "nested-guardian",
    name: "Nested Guardian",
    description: "Consensus verification and safety protocols.",
    environment: "Research",
    rootPath: "docs/architecture/consensus/aft",
  },
  {
    id: "capability-lab",
    name: "Capability Lab",
    description: "Connections, skills, and policy experiments.",
    environment: "Staging",
    rootPath: "apps/autopilot",
  },
];

export function isEditableElement(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  const tag = target.tagName.toLowerCase();
  return (
    target.isContentEditable ||
    tag === "input" ||
    tag === "textarea" ||
    tag === "select"
  );
}

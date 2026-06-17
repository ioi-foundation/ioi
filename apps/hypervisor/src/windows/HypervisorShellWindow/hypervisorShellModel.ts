import type { AssistantUserProfile } from "../../types";
import type { HypervisorSurfaceId } from "./hypervisorShellNavigationModel";

export type PrimaryView = HypervisorSurfaceId;

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
    id: "hypervisor-core",
    name: "Hypervisor Core",
    description: "Shared substrate for governed sessions, adapters, and operator surfaces.",
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
    rootPath: "apps/hypervisor",
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

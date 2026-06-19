import { showHypervisorWithLaunchRequest } from "./hypervisorLaunchState";

function openHypervisorSurface(path: string) {
  window.location.assign(path);
}

export async function openCompanionChat() {
  openHypervisorSurface("/sessions");
}

export async function openCompanionGate() {
  openHypervisorSurface("/authority");
}

export async function openCompanionNotifications() {
  openHypervisorSurface("/authority");
}

export async function openCompanionHypervisor() {
  openHypervisorSurface("/home");
}

export async function openCompanionSettings() {
  openHypervisorSurface("/settings");
}

export async function openCompanionCapabilities() {
  openHypervisorSurface("/agents");
}

export async function openCompanionCapabilitySetup(
  connectorId?: string | null,
) {
  await showHypervisorWithLaunchRequest({
    kind: "capability",
    connectorId: connectorId ?? null,
    detailSection: connectorId ? "setup" : null,
  });
  openHypervisorSurface("/agents");
}

export async function openCompanionCapabilityActions(
  connectorId?: string | null,
) {
  await showHypervisorWithLaunchRequest({
    kind: "capability",
    connectorId: connectorId ?? null,
    detailSection: "actions",
  });
  openHypervisorSurface("/agents");
}

export async function openCompanionCapabilityTarget(
  connectorId?: string | null,
  detailSection?: "setup" | "policy" | null,
) {
  await showHypervisorWithLaunchRequest({
    kind: "capability",
    connectorId: connectorId ?? null,
    detailSection: detailSection ?? null,
  });
  openHypervisorSurface("/agents");
}

export async function openCompanionPolicyTarget(
  connectorId?: string | null,
) {
  await showHypervisorWithLaunchRequest({
    kind: "policy",
    connectorId: connectorId ?? null,
  });
  openHypervisorSurface("/authority");
}

export async function openCompanionHypervisorIntent(intent: string) {
  await showHypervisorWithLaunchRequest({
    kind: "hypervisor-intent",
    intent,
  });
  openHypervisorSurface("/sessions");
}

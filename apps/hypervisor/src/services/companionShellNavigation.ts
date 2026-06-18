import {
  openChatHypervisorIntent,
  openChatCapabilities,
  openChatCapabilityActions,
  openChatCapabilitySetup,
  openChatCapabilityTarget,
  openChatCatalog,
  openChatNotifications,
  openChatPolicyTarget,
  openChatSettings,
} from "./chatShellNavigation";

export async function openCompanionChat() {
  window.location.assign("/sessions");
}

export async function openCompanionGate() {
  window.location.assign("/authority");
}

export async function openCompanionNotifications() {
  await openChatNotifications();
}

export async function openCompanionHypervisor() {
  window.location.assign("/home");
}

export async function openCompanionSettings() {
  await openChatSettings();
}

export async function openCompanionCapabilities() {
  await openChatCapabilities();
}

export async function openCompanionCatalog() {
  await openChatCatalog();
}

export async function openCompanionCapabilitySetup(
  connectorId?: string | null,
) {
  await openChatCapabilitySetup(connectorId);
}

export async function openCompanionCapabilityActions(
  connectorId?: string | null,
) {
  await openChatCapabilityActions(connectorId);
}

export async function openCompanionCapabilityTarget(
  connectorId?: string | null,
  detailSection?: "setup" | "policy" | null,
) {
  await openChatCapabilityTarget(connectorId, detailSection ?? undefined);
}

export async function openCompanionPolicyTarget(
  connectorId?: string | null,
) {
  await openChatPolicyTarget(connectorId);
}

export async function openCompanionHypervisorIntent(intent: string) {
  await openChatHypervisorIntent(intent);
}

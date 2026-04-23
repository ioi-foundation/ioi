import {
  openChatAutopilotIntent,
  openChatCapabilities,
  openChatCapabilityActions,
  openChatCapabilitySetup,
  openChatCapabilityTarget,
  openChatCatalog,
  openChatNotifications,
  openChatPolicyTarget,
  openChatShell,
  openChatSettings,
  openChatShellView,
} from "./chatShellNavigation";
import { showGateShell } from "@ioi/agent-ide";

export async function openCompanionChat() {
  await openChatShell();
}

export async function openCompanionGate() {
  await showGateShell();
}

export async function openCompanionNotifications() {
  await openChatNotifications();
}

export async function openCompanionAutopilot() {
  await openChatShellView("autopilot");
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

export async function openCompanionAutopilotIntent(intent: string) {
  await openChatAutopilotIntent(intent);
}

import {
  openChatAssistantWorkbench as openWorkbenchChatAssistantWorkbench,
  openChatHypervisorIntent as openWorkbenchChatIntent,
  openChatCapabilityTarget as openWorkbenchChatCapabilityTarget,
  openChatPolicyTarget as openWorkbenchChatPolicyTarget,
  openChatSessionTarget as openWorkbenchChatSessionTarget,
  openChatShellView as openWorkbenchChatShellView,
  showChatSessionShell as showWorkbenchChatShell,
} from "@ioi/hypervisor-workbench";

export type ChatAssistantWorkbenchSession = Parameters<
  typeof openWorkbenchChatAssistantWorkbench
>[0];
export type ChatShellView = Parameters<typeof openWorkbenchChatShellView>[0];
export type ChatShellCapabilityDetailSection = Parameters<
  typeof openWorkbenchChatCapabilityTarget
>[1];

export async function openChatShellView(view: ChatShellView) {
  await openWorkbenchChatShellView(view);
}

export async function openChatShell() {
  await showWorkbenchChatShell();
}

export async function openChatNotifications() {
  await openChatShellView("notifications");
}

export async function openChatSettings() {
  await openChatShellView("settings");
}

export async function openChatCapabilities() {
  await openChatShellView("capabilities");
}

export async function openChatCatalog() {
  await openChatShellView("catalog");
}

export async function openChatPolicyView() {
  await openChatShellView("policy");
}

export async function openChatHypervisorIntent(intent: string) {
  await openWorkbenchChatIntent(intent);
}

export async function openChatAssistantWorkbench(
  session: ChatAssistantWorkbenchSession,
) {
  await openWorkbenchChatAssistantWorkbench(session);
}

export async function openChatSessionTarget(sessionId: string) {
  await openWorkbenchChatSessionTarget(sessionId);
}

export async function openChatEvidenceSession(sessionId: string) {
  await openChatSessionTarget(sessionId);
}

export async function openChatCapabilityTarget(
  connectorId?: string | null,
  detailSection?: ChatShellCapabilityDetailSection,
) {
  await openWorkbenchChatCapabilityTarget(connectorId, detailSection);
}

export async function openChatCapabilitySetup(connectorId?: string | null) {
  await openChatCapabilityTarget(connectorId, connectorId ? "setup" : undefined);
}

export async function openChatCapabilityActions(connectorId?: string | null) {
  await openChatCapabilityTarget(connectorId, "actions");
}

export async function openChatPolicyTarget(connectorId?: string | null) {
  await openWorkbenchChatPolicyTarget(connectorId);
}

export async function openChatConnectorPolicy(connectorId?: string | null) {
  await openChatPolicyTarget(connectorId);
}

import {
  openChatAssistantWorkbench as openAgentIdeChatAssistantWorkbench,
  openChatAutopilotIntent as openAgentIdeChatAutopilotIntent,
  openChatCapabilityTarget as openAgentIdeChatCapabilityTarget,
  openChatPolicyTarget as openAgentIdeChatPolicyTarget,
  openChatSessionTarget as openAgentIdeChatSessionTarget,
  openChatShellView as openAgentIdeChatShellView,
  showChatSessionShell as showAgentIdeChatShell,
} from "@ioi/agent-ide";

export type ChatAssistantWorkbenchSession = Parameters<
  typeof openAgentIdeChatAssistantWorkbench
>[0];
export type ChatShellView = Parameters<typeof openAgentIdeChatShellView>[0];
export type ChatShellCapabilityDetailSection = Parameters<
  typeof openAgentIdeChatCapabilityTarget
>[1];

export async function openChatShellView(view: ChatShellView) {
  await openAgentIdeChatShellView(view);
}

export async function openChatShell() {
  await showAgentIdeChatShell();
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

export async function openChatAutopilotIntent(intent: string) {
  await openAgentIdeChatAutopilotIntent(intent);
}

export async function openChatAssistantWorkbench(
  session: ChatAssistantWorkbenchSession,
) {
  await openAgentIdeChatAssistantWorkbench(session);
}

export async function openChatSessionTarget(sessionId: string) {
  await openAgentIdeChatSessionTarget(sessionId);
}

export async function openChatEvidenceSession(sessionId: string) {
  await openChatSessionTarget(sessionId);
}

export async function openChatCapabilityTarget(
  connectorId?: string | null,
  detailSection?: ChatShellCapabilityDetailSection,
) {
  await openAgentIdeChatCapabilityTarget(connectorId, detailSection);
}

export async function openChatCapabilitySetup(connectorId?: string | null) {
  await openChatCapabilityTarget(connectorId, connectorId ? "setup" : undefined);
}

export async function openChatCapabilityActions(connectorId?: string | null) {
  await openChatCapabilityTarget(connectorId, "actions");
}

export async function openChatPolicyTarget(connectorId?: string | null) {
  await openAgentIdeChatPolicyTarget(connectorId);
}

export async function openChatConnectorPolicy(connectorId?: string | null) {
  await openChatPolicyTarget(connectorId);
}

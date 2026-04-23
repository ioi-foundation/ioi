import { useAgentStore } from "../session/autopilotSession";

export async function openCurrentChatShellSession() {
  await useAgentStore.getState().showChatSession();
}

export async function openNewChatShellSession() {
  const store = useAgentStore.getState();
  store.startNewSession();
  await store.showChatSession();
}

export async function openChatShellSession(sessionId: string) {
  const store = useAgentStore.getState();
  await store.loadSession(sessionId);
  await store.showChatSession();
}

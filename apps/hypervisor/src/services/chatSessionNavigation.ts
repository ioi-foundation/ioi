import { useHypervisorSessionStore } from "../session/hypervisorSession";

export async function openCurrentChatShellSession() {
  await useHypervisorSessionStore.getState().showChatSession();
}

export async function openNewChatShellSession() {
  const store = useHypervisorSessionStore.getState();
  store.startNewSession();
  await store.showChatSession();
}

export async function openChatShellSession(sessionId: string) {
  const store = useHypervisorSessionStore.getState();
  await store.loadSession(sessionId);
  await store.showChatSession();
}

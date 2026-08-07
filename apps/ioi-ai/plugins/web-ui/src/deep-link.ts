export const UI_BASE = ((import.meta as unknown as { env?: { BASE_URL?: string } }).env?.BASE_URL ?? "/").replace(
  /\/$/,
  "",
);

export function deepLinkPath(
  base: string,
  view: string,
  sessionId: string | null,
  contextScope?: string | null,
  itemId?: string | null,
): string {
  const b = base.replace(/\/$/, "");
  if (view === "contexts" && contextScope) {
    if (itemId) throw new Error("the contexts view is addressed by scope, not by item id");
    return `${b}/contexts?scope=${encodeURIComponent(contextScope)}`;
  }
  if (view === "goals" && itemId?.startsWith("room:")) {
    return `${b}/rooms/${encodeURIComponent(itemId.slice("room:".length))}`;
  }
  if (view === "goals" && itemId?.startsWith("activation:")) {
    return `${b}/goal-activations/${encodeURIComponent(itemId.slice("activation:".length))}`;
  }
  if (view !== "chats") return `${b}/${encodeURIComponent(view)}${itemId ? `/${encodeURIComponent(itemId)}` : ""}`;
  if (itemId) throw new Error("the chats view is addressed by session, not by item id");
  return `${b}/${sessionId ? `?session=${encodeURIComponent(sessionId)}` : ""}`;
}

function decodeSegment(seg: string): string | null {
  if (!seg) return null;
  try {
    return decodeURIComponent(seg);
  } catch {
    return null;
  }
}

export function parseDeepLink(
  base: string,
  pathname: string,
  search: string,
): { view: string | null; session: string | null; item: string | null } {
  const params = new URLSearchParams(search);
  const b = base.replace(/\/$/, "");
  const rel = pathname.startsWith(b) ? pathname.slice(b.length) : pathname;
  const segments = rel.replace(/^\/+/, "").split("/");
  const pathView = decodeSegment(segments[0] ?? "");
  const projectKind = segments[1] === "channel" || segments[1] === "group" ? segments[1] : null;
  let projectItem: string | null = null;
  if (pathView === "projects") {
    projectItem = projectKind ? decodeSegment(segments[2] ?? "") : decodeSegment(segments[1] ?? "");
  }
  const requestedView = params.get("view") ?? (pathView === "projects" ? "contexts" : pathView);
  let view = requestedView;
  if (requestedView === "connectors") view = "keychain";
  if (requestedView === "rooms") view = "goals";
  if (requestedView === "goal-activations") view = "goals";
  let item = projectItem ?? decodeSegment(segments[1] ?? "");
  if (pathView === "projects" && projectKind && projectItem) item = `${projectKind}:${projectItem}`;
  if (pathView === "rooms") {
    const room = decodeSegment(segments[1] ?? "");
    item = room ? `room:${room}` : null;
  }
  if (pathView === "goal-activations") {
    const activation = decodeSegment(segments[1] ?? "");
    item = activation ? `activation:${activation}` : null;
  }
  return {
    view,
    session: params.get("session"),
    item,
  };
}

export function sessionLink(origin: string, base: string, sessionId: string): string {
  return `${origin}${deepLinkPath(base, "chats", sessionId)}`;
}

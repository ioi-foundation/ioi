// RECENTLY VISITED — this browser only, and it says so.
//
// A console's home lists the surfaces a reader opened last. Here that list lives in
// localStorage and nowhere else: it never leaves the browser, it is not a claim about
// the daemon, and it can be empty on a first visit, in a private window, or after
// the reader clears site data. Every access is wrapped: localStorage throws outright
// in some privacy modes, and a home that failed to render because its convenience
// broke would be worse than no convenience.
const KEY = "dc.visited";
const MAX = 6;

const storage = () => {
  try {
    if (typeof localStorage === "undefined") return null;
    return localStorage;
  } catch {
    return null;
  }
};

export function recordVisit(id) {
  const s = storage();
  if (!s || !id) return;
  try {
    const cur = JSON.parse(s.getItem(KEY) || "[]");
    const next = [{ id, at: new Date().toISOString() }, ...(Array.isArray(cur) ? cur : []).filter((v) => v && v.id !== id)]
      .slice(0, MAX);
    s.setItem(KEY, JSON.stringify(next));
  } catch {
    // Quota, private mode, corrupt entry: the list is a convenience and is dropped.
  }
}

export function recentVisits() {
  const s = storage();
  if (!s) return [];
  try {
    const cur = JSON.parse(s.getItem(KEY) || "[]");
    return Array.isArray(cur) ? cur.filter((v) => v && typeof v.id === "string") : [];
  } catch {
    return [];
  }
}

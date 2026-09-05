// READS, AND THE GUARANTEE THAT A LATE ONE CANNOT PAINT.
//
// Framework-free. The React port changes HOW the guard is held — a ref instead of a
// module-level counter — but not WHAT it guarantees, and the guarantee is the part
// that matters, so it is stated here beside the code that implements it.
//
// THE FAULT THIS DEFENDS AGAINST, from the original surface's own comment: every
// render is async, and a slow read outlives the click that started it. A 31-second
// Sources response landing after the reader moved to Receipts will happily paint
// Sources' data under Receipts' heading and aria-current, with no signal that it did.
// Sources reads have been measured at 31s, 56s, 60s, 61s and one 504 at 75.003s.
//
// That is disqualifying on THIS surface in particular. The whole claim here is that
// you can always tell where a number came from; a page that shows one surface's data
// under another surface's label breaks exactly the promise it exists to make.

export async function read(path) {
  const started = Date.now();
  try {
    const res = await fetch(path, { headers: { accept: "application/json" } });
    const body = await res.json();
    return { ok: res.ok, status: res.status, body, ms: Date.now() - started };
  } catch (err) {
    // A network failure is rendered as a named state, not as an empty surface. An
    // empty table on this page has to keep meaning "no live price"; it can never also
    // come to mean "the read broke".
    return { ok: false, status: 0, body: { state: "face_read_failed", reason: String(err) }, ms: Date.now() - started };
  }
}

// ── The stale-while-refresh store ───────────────────────────────────────────
// The last successful read per surface, kept so a revisit shows the previous answer
// immediately instead of an empty page for a minute. Nothing in it is invented: it is
// the last thing the daemon actually said, and it is always rendered WITH the time it
// said it, dimmed, so a reader can tell a kept answer from a fresh one.
//
// This deliberately lives OUTSIDE React state. It must survive a component
// unmounting when the reader navigates away and back — which is precisely the case it
// exists for — and a store that resets on unmount would reintroduce the minute of
// blank page it was built to remove.
const store = new Map();

export const remember = (key, body, ms) =>
  store.set(key, { body, ms, at: new Date().toISOString() });

export const recall = (key) => store.get(key) || null;

// Leaving a surface drops nothing from the store, but the CANDIDATES paint handle is
// separate and is dropped on navigation: a batch rendered before the reader navigated
// away must not reappear under a later refresh as though it had just been read.
export const forget = (key) => store.delete(key);

// The face's own default intent. It already exists on the daemon and is reachable by
// a GET; `?intent=` overrides it. Creating an intent with custom constraints is a
// WRITE, and this surface performs none.
export const DEFAULT_INTENT = "cloud-resource-intent://cri_default";

export function intentRef() {
  if (typeof location === "undefined") return DEFAULT_INTENT;
  return new URL(location.href).searchParams.get("intent") || DEFAULT_INTENT;
}

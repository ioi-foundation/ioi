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

// ── AND IT SURVIVES A PAGE LOAD, WHICH IS THE CASE IT WAS BUILT FOR ─────────
//
// The Map above already kept the last answer across NAVIGATION. It did not survive a
// RELOAD, so a cold visit had nothing to show — and a blind reviewer measured a cold
// load of Sources sitting at zero rows for 39,417ms with no skeleton, no aria-busy,
// and the live region holding the empty string for the whole time. Three of seven
// surfaces are a blank page in the contact sheet for the same reason.
//
// So the store is persisted. The honesty conditions are the ones the in-memory version
// already met, and they are what make this a KEPT ANSWER rather than a fixture:
//
//   - Nothing is invented. It is the last thing THE DAEMON actually said.
//   - It is always rendered WITH the time it said it, dimmed, marked stale, with the
//     refresh state beside it. A reader can tell a kept answer from a fresh one.
//   - It EXPIRES. Past the ceiling below it is dropped rather than shown: a week-old
//     price rendered as a kept answer is a price this surface cannot stand behind, and
//     "dated" stops being a sufficient warning at some distance.
//   - It is per-browser and never leaves it.
//
// Every access is wrapped. localStorage throws outright in some privacy modes, and a
// surface that failed to render because its CACHE broke would be worse than no cache.
const PERSIST_PREFIX = "dc.read.";
// A kept answer older than this is not shown at all. Quotes are good for about fifteen
// minutes; a day is far past that, and is deliberately generous because the value here
// is "the page is not blank while it refreshes", not "this number is current".
const KEEP_MS = 24 * 60 * 60 * 1000;
// A body bigger than this is not persisted. A full candidate sweep runs to thousands of
// records, and filling a reader's storage quota to avoid a spinner is not a trade this
// surface gets to make on their behalf.
const MAX_PERSIST_BYTES = 512 * 1024;

const storage = () => {
  try {
    if (typeof localStorage === "undefined") return null;
    return localStorage;
  } catch {
    return null;
  }
};

// Why a surface has no kept answer, so it can SAY so rather than just behaving
// differently from its neighbours for reasons the reader cannot see.
//
// This is not hypothetical: the candidates body for the default intent measures
// 13.6 MB — a full sweep is thousands of records — against a localStorage quota of a
// few megabytes. Candidates therefore CANNOT keep its answer across a reload, while
// Sources (4 KB), Receipts (88 KB) and Budgets (375 B) can. A reader who saw one
// surface remember and another forget, with nothing explaining the difference, would
// reasonably conclude the page was unreliable.
const persistOutcome = new Map();
export const keptState = (key) => persistOutcome.get(key) || null;

const persist = (key, entry) => {
  const s = storage();
  if (!s) { persistOutcome.set(key, "no_storage"); return; }
  try {
    const payload = JSON.stringify(entry);
    if (payload.length > MAX_PERSIST_BYTES) {
      // Too large to keep. The PREVIOUS entry is removed rather than left behind: an
      // older kept answer presented as the latest kept answer is the one outcome worse
      // than no cache at all.
      s.removeItem(PERSIST_PREFIX + key);
      persistOutcome.set(key, "too_large");
      return;
    }
    s.setItem(PERSIST_PREFIX + key, payload);
    persistOutcome.set(key, "kept");
  } catch {
    // Quota, private mode, disabled storage. The in-memory store still works.
    persistOutcome.set(key, "storage_refused");
  }
};

// Hydrated on first recall rather than at import: this module is imported by the gate
// and by node scripts, where there is no localStorage at all.
const hydrated = new Set();
const hydrate = (key) => {
  if (hydrated.has(key)) return;
  hydrated.add(key);
  const s = storage();
  if (!s) return;
  try {
    const raw = s.getItem(PERSIST_PREFIX + key);
    if (!raw) return;
    const entry = JSON.parse(raw);
    const age = Date.now() - Date.parse(entry?.at || "");
    if (!entry?.at || !Number.isFinite(age) || age > KEEP_MS) {
      s.removeItem(PERSIST_PREFIX + key);
      return;
    }
    store.set(key, entry);
  } catch {
    // A corrupt entry is dropped, not repaired. Nothing here is worth guessing at.
    try { s.removeItem(PERSIST_PREFIX + key); } catch { /* nothing further to do */ }
  }
};

export const remember = (key, body, ms) => {
  const entry = { body, ms, at: new Date().toISOString() };
  store.set(key, entry);
  persist(key, entry);
};

export const recall = (key) => {
  hydrate(key);
  const entry = store.get(key) || null;
  if (!entry) return null;
  // The ceiling applies to the in-memory copy too, so a tab left open overnight does
  // not go on showing yesterday's answer as its kept one.
  const age = Date.now() - Date.parse(entry.at || "");
  if (Number.isFinite(age) && age > KEEP_MS) {
    store.delete(key);
    return null;
  }
  return entry;
};

// Leaving a surface drops nothing from the store, but the CANDIDATES paint handle is
// separate and is dropped on navigation: a batch rendered before the reader navigated
// away must not reappear under a later refresh as though it had just been read.
export const forget = (key) => {
  store.delete(key);
  // The persisted copy goes too. A `forget` that left the answer on disk would bring
  // it back on the next reload, which is the opposite of what the caller asked for.
  const s = storage();
  if (s) { try { s.removeItem(PERSIST_PREFIX + key); } catch { /* nothing to do */ } }
};

// The face's own default intent. It already exists on the daemon and is reachable by
// a GET; `?intent=` overrides it. Creating an intent with custom constraints is a
// WRITE, and this surface performs none.
export const DEFAULT_INTENT = "cloud-resource-intent://cri_default";

export function intentRef() {
  if (typeof location === "undefined") return DEFAULT_INTENT;
  return new URL(location.href).searchParams.get("intent") || DEFAULT_INTENT;
}

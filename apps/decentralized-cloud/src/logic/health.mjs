// THE DAEMON'S REACHABILITY, AS ONE FACT THE SHELL CAN SHOW ONCE.
//
// Every read on this surface goes through `read()` in read.mjs, and every read that
// the daemon did not answer comes back as a named state — candidate_plane_unreachable,
// candidate_plane_timeout, face_read_failed and their job-plane twins. Before this
// module each surface rendered that fault on its own: Home showed four identical panels,
// one per widget, when one daemon was down once. The panels stay (each carries its own
// route and reason), but the shell now also knows the one fact they share, and says it
// once, under the top bar, with the time it was last observed.
//
// FRAMEWORK-FREE, and nothing here is invented: the status is the outcome of the last
// daemon-bound read this browser actually made. "unknown" means no daemon read has
// completed yet — not "up", which would be a claim without a measurement.

export const DOWN_STATES = new Set([
  "candidate_plane_unreachable",
  "candidate_plane_timeout",
  "face_read_failed",
  "job_plane_unreachable",
  "job_plane_timeout",
]);

// Routes answered in-process never reach the daemon, so their outcome says nothing
// about it. Kept as a list of prefixes rather than a regex so it can be read.
const IN_PROCESS = ["/api/face-config"];
const isDaemonPath = (path) => String(path || "").startsWith("/api/") && !IN_PROCESS.some((p) => String(path).startsWith(p));

let status = { state: "unknown", at: null, code: null, reason: null, path: null };
const listeners = new Set();
const notify = () => { for (const fn of listeners) fn(status); };

// Called by read() with the request path and its result envelope. A successful daemon
// read clears a down state; a failed one names it. A failure that is NOT a down state —
// a 404 off the allowlist, a 422 refusal — says nothing about reachability and leaves
// the status alone: the daemon answered, just not with what was asked.
export const reportRead = (path, result) => {
  if (!isDaemonPath(path)) return;
  const at = new Date().toISOString();
  if (result && result.ok) {
    if (status.state !== "answering") { status = { state: "answering", at, code: null, reason: null, path }; notify(); }
    else status = { ...status, at, path };
    return;
  }
  const body = result && result.body;
  const code = body && (body.state || (body.error && body.error.code)) || null;
  if (!DOWN_STATES.has(code)) return;
  const reason = body && (body.reason || (body.error && body.error.message)) || null;
  status = { state: "down", at, code, reason, path };
  notify();
};

export const daemonStatus = () => status;

export const subscribe = (fn) => {
  listeners.add(fn);
  return () => listeners.delete(fn);
};

// THE LIVE RULE — the one judgement this surface is not allowed to get wrong.
//
// Ported verbatim from public/face.js in the React port. The comments come with it
// because they are not decoration: each clause here exists because a fixture, a
// stale quote or a simulator lane once reached a surface that called it live.
//
// The rule is the same one the M15.1 check enforces server-side. A candidate is live
// ONLY if the daemon said live_evidence, carries a priced quote with a stated basis,
// carries observed_at and expires_at, is still inside its window, and is not a
// labelled simulator lane. Every one of those is a conjunct: a disjunction here would
// be blind, because it would pass under two different behaviours and could not detect
// a change between them.
//
// This module is deliberately FRAMEWORK-FREE and imports nothing. It is the reason
// the port is a port and not a rewrite: the rendering can change, and this cannot.

export function classify(c) {
  const labels = Array.isArray(c?.eligibility_labels) ? c.eligibility_labels : [];
  if (labels.includes("simulated_control_plane")) return { live: false, reason: "simulated_control_plane" };
  if (c?.evidence_mode !== "live_evidence") return { live: false, reason: `evidence_mode ${c?.evidence_mode ?? "absent"}` };
  const q = c?.quote;
  if (!q) return { live: false, reason: "no quote" };
  if (q.evidence_mode !== "live_evidence") return { live: false, reason: `quote.evidence_mode ${q.evidence_mode ?? "absent"}` };
  if (typeof q.usd_per_hour !== "number") return { live: false, reason: "no price" };
  if (!q.basis) return { live: false, reason: "no stated basis" };
  if (!c.observed_at || !c.expires_at) return { live: false, reason: "no observation window" };
  if (Date.parse(c.expires_at) <= Date.now()) return { live: false, reason: "expired" };
  return { live: true, reason: "live_evidence" };
}

// ── The freshness dial ───────────────────────────────────────────────────────
// The fraction of a quote's own observed_at → expires_at window that is still
// unspent. Both endpoints come from the daemon's record of that candidate; the dial
// has no duration of its own and no animation that runs independently of them, so it
// cannot show a full window for an empty one.
export function dialFraction(observedAt, expiresAt) {
  const o = Date.parse(observedAt), e = Date.parse(expiresAt);
  if (!Number.isFinite(o) || !Number.isFinite(e) || e <= o) return null;
  return Math.max(0, Math.min(1, (e - Date.now()) / (e - o)));
}

export const minutesLeft = (iso) => {
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return null;
  return Math.round((t - Date.now()) / 60000);
};

export const clock = (iso) => {
  if (!iso) return "—";
  const t = Date.parse(iso);
  return Number.isFinite(t) ? new Date(t).toISOString().slice(11, 19) + "Z" : String(iso);
};

// ── The error envelope, both shapes ──────────────────────────────────────────
// A refusal arrives in one of two shapes and the original renderer read only one.
// The face's own proxy answers `{ state, reason }`; the daemon answers a refusal as
// `{ ok: false, error: { code, message } }`. Reading only the first meant every
// daemon-shaped refusal — every 422 the job primitive raises, every named
// provider-plane code — rendered as "http 422" over "the daemon gave no reason",
// while the body in front of us carried both the name and the sentence.
//
// Saying "no reason was given" when a reason WAS given is the worst thing this
// surface can do: it is the one page whose entire claim is that you can always see
// where a number, or a refusal, came from.
export function envelope(r) {
  const err = r?.body?.error;
  const code = err?.code || r?.body?.state || r?.body?.code || `http ${r?.status ?? 0}`;
  const detail = err?.message || r?.body?.reason || r?.body?.detail || null;
  return { code, detail };
}

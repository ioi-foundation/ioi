// Non-component presentation values: class-name constants and value formatters.
//
// These live outside ui.jsx so that file can export components only, which is
// what react-refresh requires to hot-reload a module reliably.

export const cx = (...values) => values.filter(Boolean).join(' ');

/* ── class-name constants ───────────────────────────────────────────── */

// 44px, not 40. Every button in the product came from this string, so the whole
// hire ladder — six Continues and the control that starts a paid run — sat 4px
// under the touch minimum on the width where most of them will be pressed.
const buttonBase =
  'inline-flex min-h-11 items-center justify-center gap-2 rounded-lg px-4 py-2 text-sm font-bold transition ' +
  'focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-600 ' +
  'disabled:cursor-not-allowed disabled:opacity-45';

export const buttonStyles = {
  primary: `${buttonBase} bg-slate-950 text-white hover:bg-blue-700`,
  secondary: `${buttonBase} border border-slate-300 bg-white text-slate-800 hover:border-slate-500 hover:bg-slate-50`,
  ghost: `${buttonBase} text-slate-600 hover:bg-slate-100 hover:text-slate-900`,
};

export const inputStyles =
  'w-full rounded-lg border border-slate-300 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none ' +
  'placeholder:text-slate-400 focus:border-blue-600 focus:ring-2 focus:ring-blue-100';

/* ── value formatters ───────────────────────────────────────────────── */

export function formatAmount(value) {
  if (!value) return 'Owner quote required';
  const amount = (Number(value.amount_minor || 0) / 100).toFixed(2);
  return `${value.asset || ''} ${amount}`.trim();
}

export function formatCadence(value) {
  if (!value?.cadence) return null;
  return value.cadence === 'once' ? 'one-time' : `per ${value.cadence}`;
}

export function formatDate(value) {
  if (!value) return null;
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return null;
  return parsed.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

// Trims a long typed ref to its tail so a card stays scannable. The full value
// is always still reachable — callers put it in a title attribute.
export function shortRef(value, tail = 12) {
  if (!value) return '';
  const text = String(value);
  const body = text.includes('://') ? text.slice(text.indexOf('://') + 3) : text;
  return body.length <= tail ? body : `…${body.slice(-tail)}`;
}

/* ── deterministic visual identity ──────────────────────────────────── */

// The legacy grid gave each card a gradient so the eye could tell rows apart.
// That affordance is worth keeping, but the colour must not be invented per
// render: it is derived from the release's composition root, so a given release
// always renders the same identity. It encodes nothing beyond that hash.
export function identityStyle(seed) {
  let hash = 0;
  const text = String(seed || '');
  for (let index = 0; index < text.length; index += 1) {
    hash = (hash * 31 + text.charCodeAt(index)) >>> 0;
  }
  const hue = hash % 360;
  const partner = (hue + 38) % 360;
  return { background: `linear-gradient(135deg, hsl(${hue} 46% 26%) 0%, hsl(${partner} 52% 16%) 100%)` };
}

/* ── receipt vocabulary ─────────────────────────────────────────────── */

// The exact action strings minted by domain/service.mjs. Anything not in this
// map falls back to the raw action, so a new owner action can never render as
// a wrong-but-plausible label.
export const ACTION_LABELS = {
  'worker.draft.created': 'Draft created',
  'worker.draft.updated': 'Draft updated',
  'worker.draft.validated': 'Draft validated',
  'worker.package.released': 'Package released',
  'worker.registration.created': 'Registered privately',
  'worker.promotion.created': 'Publication proposed',
  'worker.promotion.submitted': 'Submitted for admission',
  'worker.submission.benchmarked': 'Benchmark admitted',
  'worker.listing.published': 'Listing published',
  'worker.quote.created': 'Quote created',
  'worker.instance.hired': 'Worker hired',
  'worker.integration.bound': 'Integration bound',
  'worker.integration.tested': 'Integration tested',
  // transitionInstance mints `worker.instance.${transition}.requested`
  'worker.instance.suspend.requested': 'Suspend requested',
  'worker.instance.resume.requested': 'Resume requested',
  'worker.instance.archive.requested': 'Archive requested',
  'worker.instance.restore.requested': 'Restore requested',
};

export const actionLabel = (action) => ACTION_LABELS[action] || String(action || '').replace(/\./g, ' · ');

export function relativeTime(value, now = Date.now()) {
  const parsed = Date.parse(value);
  if (Number.isNaN(parsed)) return '';
  const seconds = Math.max(0, Math.round((now - parsed) / 1000));
  if (seconds < 60) return 'just now';
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

/* ── derived handle ─────────────────────────────────────────────────── */

// A short, stable, speakable identifier for a listing — "RRS·242169".
// Initials come from the name, the suffix from the composition root, so it is
// derived entirely from values the listing already carries and never drifts.
// It is NOT an owner-issued identifier: call sites surface the full release ref
// alongside it so nobody mistakes the shorthand for the thing itself.
export function workerHandle(name, compositionRoot) {
  const initials = String(name || '')
    .split(/\s+/).filter(Boolean).slice(0, 3)
    .map((word) => word[0].toUpperCase()).join('') || 'W';
  const digest = String(compositionRoot || '').replace(/^sha256:/, '').slice(0, 6);
  return digest ? `${initials}·${digest}` : initials;
}

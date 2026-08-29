// Presentation primitives for the aiagent.xyz product surfaces.
//
// Every element rendered through this module resolves to exactly one of four
// things, and nothing else:
//
//   read truth           a value projected from the domain API
//   local UI state       search, filter, sort, disclosure — client-side only
//   receipted authority  a mutation that returns an owner receipt
//   disabled named gap   a visible, disabled slot that NAMES the missing owner
//
// The retired prototype under fixtures/legacy-ui/ is the visual reference for
// density and hierarchy only. Its hard-coded listings, ratings, review counts,
// market ticker, and wallet-success states are not reproduced here in any form:
// where it asserted something no owner can back, this renders <Gap /> instead.

import React from 'react';
import { cx, buttonStyles, inputStyles } from './presentation';

export function Button({ variant = 'primary', className, ...rest }) {
  return <button className={cx(buttonStyles[variant], className)} {...rest} />;
}

export function Field({ label, value, onChange, multiline = false, hint, required = true, ...rest }) {
  const Tag = multiline ? 'textarea' : 'input';
  return (
    <label className="block">
      <span className="text-sm font-semibold text-slate-800">{label}</span>
      {React.createElement(Tag, {
        required,
        className: cx(inputStyles, 'mt-1.5', multiline && 'min-h-24 resize-y'),
        value: value || '',
        onChange: (event) => onChange(event.target.value),
        ...rest,
      })}
      {hint && <span className="mt-1 block text-xs leading-5 text-slate-500">{hint}</span>}
    </label>
  );
}

// React 19 passes `ref` as an ordinary prop, so no forwardRef wrapper is needed.
export function SearchInput({ value, onChange, placeholder = 'Search', className, ref }) {
  return (
    <div className={cx('relative', className)}>
      <svg
        className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500"
        fill="none"
        stroke="currentColor"
        viewBox="0 0 24 24"
        aria-hidden="true"
      >
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
      </svg>
      <input
        ref={ref}
        type="search"
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        aria-label={placeholder}
        className="w-full rounded-md border border-slate-200 bg-slate-100 py-2 pl-9 pr-3 text-sm text-slate-900 outline-none placeholder:text-slate-500 focus:border-blue-500 focus:bg-white"
      />
    </div>
  );
}

/* ── state + labelling ──────────────────────────────────────────────── */

// Tone is derived from the domain vocabulary, not chosen per call site, so the
// same state never renders two different colours across surfaces.
// Canon, "Listing Admission And Benchmark Metadata", fixes two vocabularies:
//   listing status:   draft | submitted | benchmarking | listed | routing_eligible
//                     | suspended | revoked
//   benchmark status: unbenchmarked | scheduled | running | passed | failed
//                     | stale | disputed
// Both are mapped in full even though this store emits only a few of them today.
// A renderer that handles a state is not a claim that the state occurred, and
// wiring the rest later should need no UI work.
const TONES = {
  // listing status
  draft: 'slate', submitted: 'blue', benchmarking: 'blue', listed: 'emerald',
  routing_eligible: 'emerald', suspended: 'amber', revoked: 'red',
  // benchmark status
  unbenchmarked: 'slate', scheduled: 'blue', running: 'blue', passed: 'emerald',
  failed: 'red', stale: 'amber', disputed: 'amber',
  // private registration status, worker-endpoints.md "Private Registration
  // Projection": pending_preflight | ready | offline | incompatible | expired |
  // revoked | re_pair_required. Canon requires My workers to expose all seven,
  // and no owner reports any of them yet — but a renderer that does not know a
  // state renders it grey and unlabelled, which is a silent wrong answer on the
  // day one arrives. Handling a state is not a claim that it occurred.
  pending_preflight: 'blue', offline: 'slate', incompatible: 'red', re_pair_required: 'amber',
  // onboarding plan step status, worker-marketplace.md "Managed Worker
  // Onboarding Plans": missing | ready | completed | blocked | unsupported |
  // skipped. Two of the six occur in this store today; a renderer that does not
  // know a state renders it grey and unlabelled, which is a silent wrong answer
  // on the day one arrives.
  missing: 'amber', completed: 'emerald', blocked: 'red', unsupported: 'slate', skipped: 'slate',
  // readiness mode, same section: full | degraded | notification_only |
  // dry_run_only | blocked.
  full: 'emerald', degraded: 'amber', notification_only: 'amber', dry_run_only: 'amber',
  // vocabulary this store emits today
  published: 'emerald', active: 'emerald', admitted: 'emerald', ready: 'emerald',
  installed: 'emerald', open: 'emerald', validated: 'blue', awaiting_benchmark: 'blue',
  pending: 'blue', private: 'slate', unknown: 'slate', never: 'slate',
  archived: 'amber', authority_pending: 'amber', expired: 'amber', consumed: 'amber',
  refused: 'red', invalid: 'red',
};

const TONE_CLASSES = {
  emerald: 'bg-emerald-50 text-emerald-700 ring-emerald-600/20',
  blue: 'bg-blue-50 text-blue-700 ring-blue-600/20',
  slate: 'bg-slate-100 text-slate-600 ring-slate-500/20',
  amber: 'bg-amber-50 text-amber-800 ring-amber-600/25',
  red: 'bg-red-50 text-red-700 ring-red-600/20',
};

// One token can mean two different things in two vocabularies, and a tone map
// keyed only by the token cannot say so. `ready` is the case: a *binding* that
// is ready has been tested and works, and an onboarding *step* that is ready is
// prepared and unproven — one terminal, one not, both emerald, sitting eight
// rows apart on the same page under a count that called only one of them
// completed. Tone stays derived rather than chosen per call site; the call site
// only says which vocabulary its value came from.
const VOCABULARY_TONES = {
  // worker-marketplace.md, "Managed Worker Onboarding Plans": step status is
  // missing | ready | completed | blocked | unsupported | skipped.
  plan_step: { ready: 'blue', missing: 'amber', completed: 'emerald', blocked: 'red', unsupported: 'slate', skipped: 'slate' },
};

export function State({ value, label, vocabulary }) {
  const raw = String(value ?? 'unknown');
  const tone = TONE_CLASSES[VOCABULARY_TONES[vocabulary]?.[raw.toLowerCase()] || TONES[raw.toLowerCase()] || 'slate'];
  return (
    <span className={cx('inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-bold uppercase tracking-[.12em] ring-1 ring-inset', tone)}>
      {label ? `${label}: ${raw.replace(/_/g, ' ')}` : raw.replace(/_/g, ' ')}
    </span>
  );
}

// A canon vocabulary, rendered as terms rather than as controls.
//
// Chip is for values a record actually carries — a license, a config revision,
// a declared surface. An enumeration nobody can choose from is not that. Set in
// chips, a vocabulary borrows the exact shape of a multi-select: bordered,
// rounded, padded, grouped. That is a dead button with a disclaimer underneath
// it, and on touch the thumb reaches the first pill well before the eye reaches
// the disclaimer. Terms read as terms at any size, and there is nothing to
// press.
// The marker leads each term rather than sitting between two of them. A
// separator between terms leaves a dangling character wherever the list wraps,
// and the terms here are multi-word, so the marker has to survive the wrap to
// be doing any work at all.
export function TermList({ items, className }) {
  return (
    <ul className={cx('flex flex-wrap items-baseline gap-x-4 gap-y-0.5 text-xs leading-6 text-slate-600', className)}>
      {items.map((item) => (
        <li key={item} className="flex items-baseline gap-1.5">
          <span aria-hidden="true" className="h-1 w-1 shrink-0 rounded-full bg-slate-400" />
          <span>{item}</span>
        </li>
      ))}
    </ul>
  );
}

export function Chip({ children, tone = 'slate', title }) {
  const classes = {
    slate: 'border-slate-200 bg-slate-50 text-slate-600',
    blue: 'border-blue-100 bg-blue-50 text-blue-700',
  }[tone];
  return (
    <span title={title} className={cx('inline-flex max-w-full items-center truncate rounded border px-2 py-1 text-[11px] font-medium', classes)}>
      {children}
    </span>
  );
}

/* ── the disabled named gap ─────────────────────────────────────────── */

// The single most important primitive here. Where the retired prototype showed
// a star rating, a review count, an install total, or a verified badge, no
// owner in this estate can produce that value. Rather than delete the affordance
// (losing the density that made the old UI scannable) or fake it (claiming
// something untrue), the slot renders in place, visibly inert, naming the owner
// that would have to exist for it to carry a value.
export function Gap({ label, owner, className, block = false, wrap = false }) {
  const title = `No value: ${owner} is not registered in this estate.`;
  if (block) {
    return (
      <div
        aria-disabled="true"
        title={title}
        className={cx('rounded-lg border border-dashed border-slate-300 bg-slate-50/60 px-3 py-2.5 text-xs leading-5 text-slate-500', className)}
      >
        <span className="font-semibold text-slate-600">{label}</span>
        <span className="mt-0.5 block">Unavailable — no {owner}.</span>
      </div>
    );
  }
  return (
    <span
      aria-disabled="true"
      title={title}
      className={cx('gap-1.5 text-[11px] font-medium text-slate-500',
        wrap ? 'flex items-start' : 'inline-flex items-center', className)}
    >
      <svg className={cx('h-3 w-3 shrink-0', wrap && 'mt-[3px]')} viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden="true">
        <circle cx="6" cy="6" r="4.6" />
        <path strokeLinecap="round" d="M3.2 8.8 8.8 3.2" />
      </svg>
      {/* Truncation needs a constrained width; in a narrow column it clips
          instead of wrapping, so callers in tight layouts opt into `wrap`. */}
      {/* A caller that has already stated the state elsewhere on the row passes
          no label, and the marker keeps only the clause nothing else carries.
          Repeating "Not disclosed" two inches from a column that says exactly
          that is the page arguing rather than reporting. */}
      <span className={wrap ? 'leading-5' : 'truncate'}>
        {label ? `${label} — ` : ''}no {owner}
      </span>
    </span>
  );
}

// The state of a read, standing in the slot its value would have occupied.
//
// It is deliberately neither of the two things it sits between. Not a value:
// the column it lands in carries typed refs, counts and revisions in mono, and
// "unreadable" set in that face is a state word wearing a datum's clothes —
// a reviewer read it as one of the values beside it. And not a Gap: a Gap says
// no owner exists to produce this, which is the opposite of what a failed read
// means. The owner is there; the answer did not arrive, and asking again is a
// live possibility rather than a category error.
const READ_STATE_TEXT = {
  reading: 'reading…',
  unreadable: 'could not be read',
  not_reported: 'not reported',
};

// `label` and `size` exist for the one case where a read state is the whole
// content of a panel rather than a marker in a value slot. It stays one
// component so the glyph and the colour cannot diverge between the two.
export function ReadState({ status, label, size = 'marker', className }) {
  const alarming = status === 'unreadable';
  const wide = size === 'panel';
  return (
    <span className={cx('inline-flex items-baseline gap-1.5 font-medium',
      wide ? 'text-sm' : 'text-[11px]',
      alarming ? 'text-amber-800' : 'text-slate-500', className)}>
      {/* Top-aligned in the panel size: centred against a block that wraps to
          two lines, the glyph floats between them and stops reading as the
          marker for the first. */}
      <svg className={cx('shrink-0', wide ? 'h-3.5 w-3.5 self-start mt-[3px]' : 'h-3 w-3 self-center')} viewBox="0 0 12 12" fill="none" stroke="currentColor"
           strokeWidth="1.6" aria-hidden="true">
        {alarming
          ? <path strokeLinecap="round" strokeLinejoin="round" d="M6 1.6 11 10.4H1L6 1.6ZM6 5.2v2.2M6 8.9v.1" />
          : <><circle cx="6" cy="6" r="4.6" strokeDasharray="2.4 2" /><path strokeLinecap="round" d="M6 3.4V6l1.8 1.1" /></>}
      </svg>
      {label || READ_STATE_TEXT[status]}
    </span>
  );
}

/* ── layout ─────────────────────────────────────────────────────────── */

export function Card({ as: Component = 'div', className, children, ...rest }) {
  return React.createElement(
    Component,
    {
      className: cx(
        'flex flex-col overflow-hidden rounded-xl border border-slate-200 bg-white',
        'transition hover:border-slate-300 hover:shadow-lg hover:shadow-slate-200/60',
        className,
      ),
      ...rest,
    },
    children,
  );
}

// A facet pill. The retired prototype's equivalent row filtered by an
// "execution shape" taxonomy that does not exist in this domain; these are
// built from values actually present on the listings themselves.
export function Pill({ active, children, ...rest }) {
  return (
    <button
      type="button"
      aria-pressed={active}
      className={cx(
        'rounded-full border px-3.5 py-1.5 text-sm font-medium transition',
        active
          ? 'border-slate-950 bg-slate-950 text-white'
          : 'border-slate-200 bg-white text-slate-600 hover:border-slate-400 hover:text-slate-900',
      )}
      {...rest}
    >
      {children}
    </button>
  );
}

export function RailSection({ title, children }) {
  return (
    <div>
      <p className="text-[11px] font-bold uppercase tracking-[.12em] text-slate-500">{title}</p>
      <div className="mt-3">{children}</div>
    </div>
  );
}

// Trust signals above the fold, taken from the catalog concept. Every figure is
// a count the store can produce; nothing is a percentage of an unknown total.
//
// A figure has three states and they are not interchangeable. Not yet known is
// not zero — the console rendered "RUNNING 0" while the deployments call was in
// flight, which is a claim that you have none. Not readable is not unknown
// either: an em dash stood for loading, for a failed read, and for ordinary
// missing data all at once, so a slow network and a dead endpoint were
// pixel-identical.
//
// A figure is therefore derived from the load itself, not from a value plus two
// flags a call site has to remember to keep in sync with it. The first cut took
// `value`, `pending` and `unreadable` as three independent props; three of the
// four console figures passed all three and the fourth — the most consequential
// — passed only the value, which is exactly how "RUNNING 0" survived. Given the
// load, "loaded" is the only state that can produce a numeral, and forgetting is
// not expressible.
//
// `select` returning undefined means the read succeeded and did not carry this
// figure, which is not a value either: a falsy default is not a finding.
// Type and tracking scales, kept where the primitives are so a call site cannot
// quietly add a sixth body size. Body: 10 · 11 · 12 (xs) · 14 (sm). Display: 2xl
// upward. Letter-spacing on small caps: .12em for a label, .18em for a page
// eyebrow, and nothing else — .1em and .14em had drifted back in as one- and
// two-use strays.
export function StatRow({ items }) {
  return (
    <dl className="flex flex-wrap gap-x-10 gap-y-4">
      {items.map(({ label, from, select, tone, title }) => {
        const value = from.loading || from.error || !from.value ? undefined : select(from.value);
        const state = from.loading ? 'pending' : value === undefined ? 'unreadable' : 'ready';
        const weight = state === 'ready' && typeof tone === 'function' ? tone(value) : undefined;
        return (
          <div key={label} title={state === 'unreadable' ? `${label} could not be read.` : title}>
            <dt className="text-[11px] font-bold uppercase tracking-[.12em] text-slate-500">{label}</dt>
            {state === 'pending' ? (
              <dd className="mt-1">
                <span role="status" aria-label={`Reading ${label}`}
                      className="block h-7 w-16 animate-pulse rounded bg-slate-200" />
              </dd>
            ) : state === 'unreadable' ? (
              <dd className="mt-2 text-sm font-bold text-amber-700">not reported</dd>
            ) : (
              <dd className={cx('mt-1 text-2xl font-black tracking-tight',
                weight === 'good' ? 'text-emerald-600' : weight === 'bad' ? 'text-red-600' : 'text-slate-950')}>
                {value}
              </dd>
            )}
          </div>
        );
      })}
    </dl>
  );
}

export function Handle({ children, title }) {
  return (
    <span title={title} className="inline-flex items-center rounded bg-slate-900/5 px-1.5 py-0.5 font-mono text-[11px] font-bold tracking-tight text-blue-700">
      {children}
    </span>
  );
}

// The admission chain as a spine, borrowed from the provenance concept. Reads
// far better than a flat table because the order is the order things happened.
export function Spine({ nodes }) {
  return (
    <ol className="relative ml-2 border-l-2 border-slate-200 pl-6">
      {nodes.map((node) => (
        <li key={node.title} className="relative pb-6 last:pb-0">
          <span
            aria-hidden="true"
            className={cx('absolute -left-[31px] top-1 h-3.5 w-3.5 rounded-full border-2 bg-white',
              node.done ? 'border-emerald-500' : 'border-slate-300')}
          />
          <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
            <h3 className="text-sm font-bold text-slate-900">{node.title}</h3>
            {node.when && <span className="font-mono text-[11px] text-slate-500">{node.when}</span>}
          </div>
          <dl className="mt-1.5 space-y-1">
            {node.rows.filter(([, value]) => value).map(([label, value]) => (
              <div key={label} className="flex flex-wrap gap-x-2 text-[11px] leading-5">
                <dt className="font-mono uppercase tracking-[.12em] text-slate-500">{label}</dt>
                <dd className="min-w-0 break-all font-mono text-slate-600">{value}</dd>
              </div>
            ))}
          </dl>
        </li>
      ))}
    </ol>
  );
}

// The three invocation modes canon requires the buyer-facing surface to present
// before any runtime detail (worker-marketplace.md, "Invocation And Management
// Modes"). Only "Run managed" has an endpoint today; the other two render as
// named gaps rather than disabled buttons that imply a path exists.
export function ModeCard({ title, blurb, detail, action, owner, selected }) {
  const live = Boolean(action);
  return (
    <div className={cx(
      'flex h-full flex-col rounded-xl border p-4',
      live ? 'border-slate-200 bg-white' : 'border-dashed border-slate-300 bg-slate-50/60',
      selected && 'border-slate-950 ring-1 ring-slate-950',
    )}>
      <h3 className={cx('text-sm font-bold', live ? 'text-slate-900' : 'text-slate-500')}>{title}</h3>
      <p className={cx('mt-1.5 flex-1 text-xs leading-5', live ? 'text-slate-600' : 'text-slate-500')}>{blurb}</p>
      {detail && <p className="mt-2 text-[11px] leading-5 text-slate-500">{detail}</p>}
      <div className="mt-3">
        {live ? action : <Gap wrap label="Unavailable" owner={owner} />}
      </div>
    </div>
  );
}

// Canon: advanced posture belongs behind the buyer-facing steps, not in front
// of them. Everything technical on a listing lives inside one of these.
export function Drawer({ title, hint, children, open = false }) {
  return (
    <details open={open} className="group rounded-xl border border-slate-200 bg-white">
      <summary className="flex cursor-pointer list-none items-center gap-2 px-4 py-3 text-sm font-bold text-slate-800 hover:bg-slate-50">
        <svg className="h-3.5 w-3.5 shrink-0 text-slate-500 transition group-open:rotate-90" viewBox="0 0 12 12"
             fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
          <path strokeLinecap="round" strokeLinejoin="round" d="M4.5 2.5 8 6l-3.5 3.5" />
        </svg>
        {title}
        {hint && <span className="ml-auto text-[11px] font-medium text-slate-500">{hint}</span>}
      </summary>
      <div className="border-t border-slate-100 px-4 py-4">{children}</div>
    </details>
  );
}

// Why a requirement is not shown, in the publisher's terms rather than the
// product's. None of these is a Gap: a Gap says no owner exists to produce this
// value, and all three of these are answers from an owner that does.
// The right-hand token for each state a requirement row can be in.
const REQUIREMENT_TOKENS = {
  absent: 'not disclosed',
  none: 'none declared',
  undeclared: 'not declared',
  withheld: 'withheld',
  unresolved: 'unreadable',
  not_reported: 'not reported',
};

const DISCLOSURE_ABSENCE = {
  undeclared: 'The admitted package declares nothing here.',
  withheld: 'The publisher did not admit this for public disclosure.',
  unresolved: 'The admitted composition behind this listing could not be reached, so nothing is shown.',
  // A listing that answered without a projection at all is not a listing whose
  // composition could not be reached: the first is a response that did not carry
  // the field, the second is a domain that looked and could not tie the listing
  // to the package that was admitted. The gate caught these rendering as one
  // sentence, which is the same collapse this projection exists to undo.
  not_reported: 'This listing did not report a disclosure projection.',
};

// Why a disclosure is not showing, in one sentence, for the cases where a caller
// needs the sentence without the row around it. `reading` and `unreadable`
// belong to the read rather than to the disclosure, and are here so that a
// caller cannot answer them with `declares none` — which is what the bind
// control did while the listing read was still in flight, telling an operator
// their package asked for no authority at all.
export function DisclosureNote({ state, className }) {
  if (state === 'reading' || state === 'unreadable') {
    return <ReadState className={className} status={state} />;
  }
  return (
    <p className={cx('max-w-[52ch] text-xs leading-5 text-slate-600', className)}>
      {DISCLOSURE_ABSENCE[state] || 'This disclosure is not available.'}
    </p>
  );
}

// A requirement the buyer must satisfy before the worker can act.
//
// `field` is one entry of the listing's disclosure projection — `{state, value}`
// — and carries its own state, so this renders what the publisher's package
// actually says instead of inferring from an empty array. Four answers, four
// renderings: the declared values; a package that declares none of them; a
// publisher who did not admit the field; and a composition that could not be
// reached. Callers with no projection at all still pass `owner` and get the
// named gap, which is the fifth and different thing: nothing exists to ask.
// `supplies: false` marks a row whose values are fixed by the package rather than
// supplied by the buyer. Inside a section titled "What it needs from you" the
// same token — "2 declared" — meant the opposite of what it meant two rows above
// it: three things you must provide, against two the package has already chosen
// and you provide none of. Same word, same weight, same position, opposite
// obligation, with the correction 12px grey and last in the reading order.
export function Requirement({ label, field, owner, note, supplies = true }) {
  const values = field?.state === 'disclosed'
    ? (Array.isArray(field.value) ? field.value : [field.value]).filter(Boolean)
    : null;
  return (
    <div className="py-3">
      {/* The count is the row's own declaration that it has an answer. A
          reviewer measured the answered row against the three markers below it
          — same left rail, same height, same optical weight — and found the only
          real data in the section winning on content alone. Derived from the
          values themselves, so it cannot disagree with them.
          The values are NOT re-cased or renamed on the way through: they are the
          package's own tokens, and this surface shows the word the owner
          returned. What would make `crm` mean a particular CRM to a buyer is the
          IntegrationSurfaceProfile behind it, which no owner here resolves —
          a legibility gap that is not closed by relabelling. */}
      {/* Every row carries a token, not only the answered ones. With it on the
          two rows that had values the column was ragged — two tokens and two
          voids — and silent exactly where a reader scanning for what is missing
          needs it. The token is derived from the same state the body renders,
          so the two halves of a row cannot say different things. */}
      <div className="flex flex-wrap items-baseline justify-between gap-x-3">
        {label && <p className="text-xs font-bold text-slate-800">{label}</p>}
        <p className="text-[11px] font-medium text-slate-500">
          {values?.length
            ? (supplies ? `${values.length} declared` : 'fixed — nothing to supply')
            : REQUIREMENT_TOKENS[values ? 'none' : field?.state || 'absent']}
        </p>
      </div>
      <div className={label ? 'mt-1.5' : ''}>
        {!field ? <Gap wrap owner={owner} />
          : values?.length ? (
            <div className="flex flex-wrap gap-1.5">
              {values.map((value) => <Chip key={value}>{value}</Chip>)}
            </div>
          ) : (
            <p className="max-w-[52ch] text-xs leading-5 text-slate-600">
              {values ? 'The admitted package declares none.' : DISCLOSURE_ABSENCE[field.state]}
            </p>
          )}
      </div>
      {/* Only where values arrived: a caveat about what the values mean is not a
          caveat about their absence, and printing it under a marker would attach
          it to the wrong fact. */}
      {note && values?.length ? (
        <p className="mt-1.5 max-w-[62ch] text-xs leading-5 text-slate-500">{note}</p>
      ) : null}
    </div>
  );
}

// Canon's hire ladder is a sequence, not a button. The stepper shows the whole
// sequence up front so a buyer can see what configuring actually involves
// before starting, including the steps this estate cannot yet complete.
export function Stepper({ steps, current, onSelect }) {
  return (
    <ol className="space-y-1">
      {steps.map((step, index) => {
        // A rung that collects nothing was never completed — it was passed over.
        // Marking it done would contradict the badge sitting next to it.
        const state = index === current ? 'current'
          : index < current ? (step.pending ? 'skipped' : 'done')
          : 'ahead';
        return (
          <li key={step.key}>
            <button
              type="button"
              onClick={() => onSelect(index)}
              aria-current={state === 'current' ? 'step' : undefined}
              className={cx(
                'flex w-full items-start gap-3 rounded-lg px-3 py-2.5 text-left transition',
                state === 'current' ? 'bg-slate-950 text-white'
                  : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900',
              )}
            >
              <span className={cx(
                'mt-0.5 grid h-5 w-5 shrink-0 place-items-center rounded-full text-[10px] font-bold',
                state === 'current' ? 'bg-white text-slate-950'
                  : state === 'done' ? 'bg-emerald-500 text-white'
                  : state === 'skipped' ? 'border border-dashed border-slate-300 text-slate-500'
                  : 'border border-slate-300 text-slate-500',
              )}>
                {state === 'done' ? '✓' : state === 'skipped' ? '–' : index + 1}
              </span>
              <span className="min-w-0">
                <span className="flex items-center gap-1.5">
                  <span className="text-sm font-semibold">{step.title}</span>
                  {/* Marked before it is entered, so walking the ladder is not
                      five clicks to discover four rungs are inert. */}
                  {step.pending && (
                    <span className={cx('rounded px-1 py-px text-[10px] font-bold uppercase tracking-[.12em]',
                      state === 'current' ? 'bg-white/20 text-white' : 'bg-slate-200 text-slate-700')}>
                      pending
                    </span>
                  )}
                </span>
                <span className={cx('block text-[11px] leading-4',
                  state === 'current' ? 'text-white/60' : 'text-slate-500')}>
                  {step.blurb}
                </span>
              </span>
            </button>
          </li>
        );
      })}
    </ol>
  );
}

// A slot this surface is designed for but cannot yet operate — a control with
// no endpoint, or a disclosure with no projection. It keeps the label and the
// explanation a live one would have, so the step reads as designed rather than
// missing.
//
// Dashed, never the solid white of Panel: an inert slot has to be
// distinguishable from a live one without reading a word, and 11px grey text
// floated to the far edge of a solid card is not that. The marker sits in the
// heading row so it is read before the contents rather than after them.
export function InertPanel({ label, owner, marker = 'Not configurable yet', hint, children, className }) {
  return (
    <div className={cx('rounded-xl border border-dashed border-slate-300 bg-slate-50/60 p-4', className)}>
      <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
        <p className="text-sm font-semibold text-slate-700">{label}</p>
        <Gap label={marker} owner={owner} />
      </div>
      {hint && <p className="mt-1 max-w-[60ch] text-xs leading-5 text-slate-500">{hint}</p>}
      {children}
    </div>
  );
}

// Three roles were being spelled out inline at every call site, with three
// different tracking values for what is one role. One component each, one value
// each: page eyebrows keep the wider .18em inside SectionHead, every smaller
// label uses .12em.
export function SubHeading({ children, className, ...rest }) {
  return (
    <h2 className={cx('text-sm font-bold uppercase tracking-[.12em] text-slate-500', className)} {...rest}>
      {children}
    </h2>
  );
}

export function Eyebrow({ children, className }) {
  return (
    <p className={cx('text-[11px] font-bold uppercase tracking-[.12em] text-slate-500', className)}>{children}</p>
  );
}

export function Panel({ as: Component = 'div', className, children, ...rest }) {
  return React.createElement(
    Component,
    { className: cx('rounded-xl border border-slate-200 bg-white p-5', className), ...rest },
    children,
  );
}

export function SectionHead({ eyebrow, title, lede, aside }) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-4">
      <div className="min-w-0">
        {eyebrow && <p className="text-xs font-bold uppercase tracking-[.18em] text-blue-700">{eyebrow}</p>}
        <h1 className="mt-2 text-3xl font-black tracking-tight text-slate-950">{title}</h1>
        {lede && <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-600">{lede}</p>}
      </div>
      {aside}
    </div>
  );
}

export function DefList({ rows }) {
  return (
    <dl className="divide-y divide-slate-200 border-y border-slate-200 text-sm">
      {rows.map(([label, value, options]) => (
        <div key={label} className="grid gap-1 py-3.5 md:grid-cols-[190px_minmax(0,1fr)] md:gap-4">
          <dt className="font-semibold text-slate-800">{label}</dt>
          <dd className="min-w-0">
            {value === undefined || value === null || value === '' ? (
              <Gap label="Value" owner={options?.owner || 'owner projection'} />
            ) : options?.mono !== false ? (
              // A typed ref has no word boundaries to break at, so it breaks
              // anywhere rather than overflowing its column.
              <span className="break-all font-mono text-xs text-slate-600">{value}</span>
            ) : (
              // Prose does have word boundaries, and breaking anywhere splits
              // "provider" across two lines. It also needs a measure: the value
              // column is ~590px wide here, about 95 characters, well past a
              // comfortable one.
              <span className="block max-w-[62ch] leading-6 text-slate-600">{value}</span>
            )}
          </dd>
        </div>
      ))}
    </dl>
  );
}

// A list whose read failed is not an empty list. The empty state is a finding —
// "nothing has been created yet", with an invitation to create the first one —
// and rendering it over a failed read turns an outage into a statement about
// the user's account. Seven surfaces did exactly that: a broken catalogue
// produced "No public workers yet.", a broken instances read produced "Nothing
// running yet."
export function Unreadable({ error, subject, onRetry }) {
  // Whether asking again could change the answer is a property of the failure,
  // not of the surface, and not of which fields the payload happened to carry.
  // A 4xx is fail-closed: the read did not fall over, it was declined, and in a
  // receipted estate each retry is another attempt against a door meant to stay
  // shut. A 5xx, or no status at all, is the opposite case, where asking again
  // is the entire remedy. 408 and 429 are the two 4xx that say "later", so they
  // keep the offer.
  //
  // An earlier cut tested `Boolean(error?.owner)` and got both directions
  // wrong: an outage inside an authority-owned component names an owner and is
  // still an outage, and a denial that names none is still a denial.
  const status = error?.status;
  const retryable = !status || status >= 500 || status === 408 || status === 429;
  const missing = error?.details?.missing;
  return (
    <div role="alert" className="rounded-xl border border-amber-300 bg-amber-50 px-6 py-12 text-center">
      <p className="font-mono text-[11px] uppercase tracking-[.12em] text-amber-800">
        {error?.code || 'request_failed'}
      </p>
      <p className="mt-2.5 text-sm font-bold text-slate-900">{subject} could not be read.</p>
      <p className="mx-auto mt-1.5 max-w-md text-sm leading-6 text-slate-700">
        {error?.message || 'The request did not complete.'} This says nothing about what exists.
      </p>
      {/* Where it broke is worth knowing in every class, and gating it on the
          verdict lost it for exactly the failures a reader would have pasted
          into an incident report. Only the verb changes with the class. */}
      {error?.owner && (
        <p className="mt-3 font-mono text-[11px] text-slate-600">
          {retryable ? 'Failed inside' : 'Refused by'} {error.owner}
        </p>
      )}
      {/* Carried over from the notice this panel replaced, which rendered it and
          would otherwise have taken it with it. */}
      {missing?.length ? (
        <p className="mt-2 font-mono text-[11px] text-slate-600">Missing: {missing.join(', ')}</p>
      ) : null}
      {!retryable ? (
        <p className="mx-auto mt-4 max-w-md text-xs leading-5 text-slate-600">
          This read was declined rather than dropped. Asking again does not change the answer.
        </p>
      ) : onRetry ? (
        // The only move a reader had was to reload the whole document. Re-running
        // the one read that failed is cheaper and keeps the rest of the page.
        <div className="mt-5 flex justify-center">
          <Button variant="secondary" onClick={onRetry}>Try this read again</Button>
        </div>
      ) : null}
    </div>
  );
}

export function Empty({ title, children, action }) {
  return (
    <div className="rounded-xl border border-dashed border-slate-300 bg-white/60 px-6 py-16 text-center">
      <p className="text-sm font-bold text-slate-700">{title}</p>
      {children && <p className="mx-auto mt-1.5 max-w-md text-sm leading-6 text-slate-500">{children}</p>}
      {action && <div className="mt-5 flex justify-center">{action}</div>}
    </div>
  );
}

// A refusal is typed: the domain returns a code, a message, sometimes the owner
// that refused, and sometimes the fields that were missing. Rendering a hollow
// page with empty fields instead loses all of it — and looks like a product
// that shipped broken rather than one that declined.
export function LoadFailure({ error, title, action }) {
  const missing = error?.details?.missing;
  return (
    <div className="mx-auto max-w-[70ch] py-16 text-center">
      <p className="font-mono text-[11px] uppercase tracking-[.12em] text-slate-500">
        {error?.code || 'request_failed'}
      </p>
      <h1 className="mt-3 text-2xl font-black tracking-tight text-slate-950">{title}</h1>
      <p className="mt-2.5 text-sm leading-6 text-slate-600">{error?.message || 'The request could not be completed.'}</p>
      {(error?.owner || missing) && (
        <dl className="mx-auto mt-5 max-w-sm divide-y divide-slate-200 border-y border-slate-200 text-left text-sm">
          {error?.owner && (
            <div className="flex justify-between gap-4 py-2.5">
              <dt className="text-slate-500">Refused by</dt>
              <dd className="font-mono text-xs text-slate-700">{error.owner}</dd>
            </div>
          )}
          {missing && (
            <div className="flex justify-between gap-4 py-2.5">
              <dt className="text-slate-500">Missing</dt>
              <dd className="text-right font-mono text-xs text-slate-700">{missing.join(', ')}</dd>
            </div>
          )}
        </dl>
      )}
      {action && <div className="mt-6 flex justify-center">{action}</div>}
    </div>
  );
}

export function ErrorNotice({ error }) {
  if (!error) return null;
  return (
    <div role="alert" className="mt-5 rounded-lg border border-red-200 bg-red-50 p-3.5 text-sm leading-6 text-red-800">
      <strong className="font-bold">{error.code || 'Request failed'}.</strong> {error.message}
      {error.owner ? ` Owner: ${error.owner}.` : ''}
      {error.details?.missing ? ` Missing: ${error.details.missing.join(', ')}.` : ''}
    </div>
  );
}

export function Skeleton({ count = 6, className }) {
  return (
    <div className={className}>
      {Array.from({ length: count }, (_, index) => (
        <div key={index} className="h-full animate-pulse rounded-xl border border-slate-200 bg-white">
          <div className="h-28 rounded-t-xl bg-slate-100" />
          <div className="space-y-2.5 p-4">
            <div className="h-3.5 w-2/3 rounded bg-slate-100" />
            <div className="h-3 w-full rounded bg-slate-100" />
            <div className="h-3 w-4/5 rounded bg-slate-100" />
          </div>
        </div>
      ))}
    </div>
  );
}

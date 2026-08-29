import React, { Suspense, lazy, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link, NavLink, Route, Routes, useLocation, useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { api, productSession } from './api';
import {
  Button, Card, Chip, DefList, Drawer, Empty, ErrorNotice, Field, Gap, Handle, ModeCard, Pill, RailSection,
  DisclosureNote, Eyebrow, LoadFailure, Panel, InertPanel, ReadState, Unreadable, Requirement, SearchInput, SectionHead, Skeleton, Spine, State, StatRow, Stepper, SubHeading,
  TermList,
} from './ui';
import {
  actionLabel, buttonStyles, cx, formatAmount, formatCadence, formatDate, identityStyle, inputStyles,
  relativeTime, shortRef, workerHandle,
} from './presentation';

// three.js and the 2.4MB figure are the lander's cost alone — no other route
// pays for them, and the lander itself pays after its own facts render.
const CyborgHero = lazy(() => import('./CyborgHero.jsx'));

function useLoad(loader, deps = []) {
  const [state, setState] = useState({ loading: true, value: null, error: null });
  const reload = useCallback(async () => {
    setState((current) => ({ ...current, loading: true, error: null }));
    try { setState({ loading: false, value: await loader(), error: null }); }
    catch (error) { setState({ loading: false, value: null, error }); }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  useEffect(() => { reload(); }, [reload]);
  return { ...state, reload };
}

// Four states, never three, and never a default that stands in for all four.
//
// A read in flight is not an empty list. A read that failed is not an empty
// list. A response that resolved without the key it was asked for is not an
// account with nothing in it. Each call site had been collapsing some subset of
// those into a falsy default — `|| []`, `?? 0` — and every one of them rendered
// as a finding about the reader rather than about the read.
//
// Derived here rather than at each site so the four cannot drift apart between
// two panels that are looking at the same read, which is how the Agent Map came
// to report "0 receipts" on the node while the rail beside it said "reading…".
const READ_LABELS = { reading: 'reading…', unreadable: 'unreadable', not_reported: 'not reported' };

// One field of a listing's disclosure projection, or the reason there isn't one.
// Never undefined: `Requirement` reads undefined as "no owner exists for this",
// and a listing whose composition could not be reached is the opposite claim —
// an owner that answered, and could not be shown to have answered about this
// exact admitted package.
function disclosureField(listing, name) {
  const disclosure = listing?.disclosure;
  if (!disclosure) return { state: 'not_reported' };
  if (disclosure.resolved === false) return { state: 'unresolved' };
  return disclosure.fields?.[name] || { state: 'not_reported' };
}

// One row of a disclosure that is more than one field. Canon's worker package
// carries "model route options" — plural — and this domain's composition carries
// a single `model_route_ref` and a single `runtime_profile_ref`, so the honest
// answer to "what are the options" is the two refs it declares and the fact that
// it declares no alternatives. Merging propagates the first state that is not a
// disclosure rather than quietly showing the half that resolved.
function mergedDisclosure(listing, names) {
  const parts = names.map((name) => disclosureField(listing, name));
  const unavailable = parts.find((part) => part.state !== 'disclosed');
  if (unavailable) return unavailable;
  return { state: 'disclosed', value: parts.flatMap((part) => (Array.isArray(part.value) ? part.value : [part.value])) };
}

function listState(load, key = 'items') {
  if (load.loading) return { status: 'reading' };
  if (load.error) return { status: 'unreadable' };
  if (!Array.isArray(load.value?.[key])) return { status: 'not_reported' };
  return { status: 'read', items: load.value[key] };
}

/* ── shell ──────────────────────────────────────────────────────────── */

// The surface has two audiences and they were sharing one nav row: browse
// ("Explore") sat beside supply tooling ("Builder", "My workers") and a
// dashboard ("Instances"). Split them. Which view you are in is derived from the
// route rather than stored, so there is no hidden mode to get out of sync.
// Canon calls this surface "the managed-worker cockpit" and is explicit that the
// dashboard "is not just a first-run wizard; it is the ongoing cockpit for
// status, runtime placement, package version, ModelRoute, HarnessProfile,
// memory profile, connectors, contact channels, schedules, recent runs,
// receipts, spend, authority grants, update availability, rollback targets,
// archive state, export state, and delete or forget posture."
//
// That is infrastructure, and it does not fit a storefront's horizontal tabs.
// So there are two contexts: a wide marketplace for browsing supply, and a
// console with a persistent rail for operating what you are already running.
// Canon calls these Sparse Worker Categories: "narrow labor markets with
// explicit benchmark profiles, evaluation rubrics, runtime requirements, policy
// posture, receipt obligations, and routing eligibility criteria."
//
// No SparseWorkerCategory record exists in this store yet, and a listing carries
// no category field, so these routes are navigation and positioning — not a
// claim that any worker has been admitted to a category. Each page says so.
const CATEGORIES = [
  ['/operations', 'Operations',
   'Billing, claims, reconciliation, intake, and back-office work that has to run every day.'],
  ['/research', 'Research',
   'Standing literature, market, and diligence work that reports on a cadence rather than on request.'],
  ['/gaming', 'Gaming',
   'Licensed in-game agents operating under explicit parameters and server rules.'],
  ['/trading', 'Trading',
   'Monitoring, signal, and reconciliation work bounded by mandate and budget.'],
  ['/coding', 'Coding',
   'Regression, review, and maintenance work on a codebase you already own.'],
];

const inConsole = (pathname) =>
  ['/console', '/instances', '/templates', '/builder', '/my-workers', '/freelance']
    .some((route) => pathname.startsWith(route));

const CONSOLE_RAIL = [
  ['/console', 'Overview'],
  ['/instances', 'Running'],
  ['/templates', 'Templates'],
  ['/builder', 'Builder'],
  ['/my-workers', 'My workers'],
  // Owner direction, 2026-08-14: this was an amber "Freelance" tab wedged into
  // the storefront's category nav. It is not a category and never was — it is
  // the way in to the composition lens, which is a console destination. So it
  // leaves the storefront nav and takes the name of what it does.
  ['/freelance', 'New agent'],
];

// Held as its own component and remounted by `key` whenever the URL's q changes,
// so the field follows navigation without an effect writing state on every render.
function HeaderSearch({ initial }) {
  const navigate = useNavigate();
  const [query, setQuery] = useState(initial);
  const box = useRef(null);

  // "/" or Cmd/Ctrl-K jumps to search from anywhere, unless you are already typing.
  useEffect(() => {
    const onKey = (event) => {
      const tag = event.target?.tagName;
      if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return;
      if (event.key === '/' || ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k')) {
        event.preventDefault();
        box.current?.focus();
      }
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, []);

  return (
    <form
      onSubmit={(event) => { event.preventDefault(); navigate(query ? `/agents?q=${encodeURIComponent(query)}` : '/agents'); }}
      className="hidden min-w-0 flex-1 md:block"
    >
      <SearchInput ref={box} value={query} onChange={setQuery} placeholder="Search workers — press / to focus" className="max-w-xl" />
    </form>
  );
}

// Header popovers share `name`, so opening one closes the others.
const POPOVER = 'header-menu';

const iconButton =
  'grid h-9 w-9 cursor-pointer list-none place-items-center rounded-lg border border-transparent ' +
  'text-slate-600 transition hover:border-slate-300 hover:bg-slate-50 hover:text-slate-900';

// `max-w-[calc(100vw-1rem)]` because the panel is anchored to its icon, and at
// 375px an icon near the right edge with a fixed-width panel under it pushes the
// panel's left edge off the viewport: the eyebrow read "ART" and every row lost
// its first character. What survived the clip was the price on the right and
// what was cut was the validity on the left, which is exactly backwards.
// Below `sm` the popover is anchored to the header — the `<details>` goes
// `static`, so `right-2 left-2` resolve against the header's own box and the
// panel spans the viewport with a gutter either side. From `sm` up it returns to
// being anchored under its own control, which is where it belongs when there is
// room for it.
const panel = 'absolute inset-x-2 z-50 mt-2 w-auto rounded-xl border border-slate-200 bg-white p-4 shadow-xl '
  + 'sm:inset-x-auto sm:right-0 sm:w-80';
const popoverAnchor = 'static sm:relative';

// Receipts are a real per-principal activity stream, so the bell carries actual
// content. What it deliberately does not carry is an unread badge: no owner
// records what this principal has seen, and a count implying "unread" would be
// the same invention as a star rating.
function NotificationBell({ receipts }) {
  const items = [...(receipts.value?.items || [])].reverse().slice(0, 6);
  return (
    <details name={POPOVER} className={popoverAnchor}>
      <summary className={iconButton} aria-label="Activity">
        <svg className="h-[18px] w-[18px]" viewBox="0 0 24 24" fill="none" stroke="currentColor"
             strokeWidth="1.7" aria-hidden="true">
          <path strokeLinecap="round" strokeLinejoin="round"
                d="M15 17h5l-1.4-1.4A2 2 0 0 1 18 14.2V11a6 6 0 1 0-12 0v3.2a2 2 0 0 1-.6 1.4L4 17h5m6 0a3 3 0 1 1-6 0" />
        </svg>
      </summary>
      <div className={panel}>
        <Eyebrow>Recent activity</Eyebrow>
        {items.length ? (
          <ul className="mt-2 divide-y divide-slate-100">
            {items.map((receipt) => (
              <li key={receipt.receipt_ref} className="flex items-baseline justify-between gap-3 py-2">
                <span className="truncate text-sm font-semibold text-slate-800">{actionLabel(receipt.action)}</span>
                <span className="shrink-0 font-mono text-[10px] text-slate-500">{relativeTime(receipt.occurred_at)}</span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="mt-2 text-sm text-slate-500">
            {receipts.loading ? 'Reading receipts…' : receipts.error ? 'Receipts could not be read.' : 'No receipts yet.'}
          </p>
        )}
        <div className="mt-3 space-y-2 border-t border-slate-100 pt-3">
          <Gap wrap label="Unread and dismissal state" owner="notification read-state owner" />
          <Gap wrap label="Alerts, subscriptions, and delivery" owner="notification owner" />
        </div>
      </div>
    </details>
  );
}

// Hire is one worker at a time: a quote is minted per listing, expires in
// fifteen minutes, and is consumed on hire. There is no basket object to fill
// and no endpoint that lists open quotes, so the affordance names both.
// Minutes remaining on a quote, floored, never negative: a quote is expired or
// it is not, and "0m left" on something the domain will still honour for another
// forty seconds is a number that changes the reader's decision for the worse.
const minutesLeft = (value, now) => Math.max(0, Math.floor((Date.parse(value) - now) / 60_000));

// A clock that advances, because the thing being rendered does.
//
// "expires in 14m" was computed once, at render, and never again: a tab left
// open for twenty minutes reported live quotes that had lapsed ten minutes
// earlier — wrong with specifics, which is worse than the marker it replaced.
// Fifteen seconds is fine for minute granularity and cheap enough to run in the
// shell on every route.
function useTick(intervalMs = 15_000) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), intervalMs);
    return () => clearInterval(timer);
  }, [intervalMs]);
  return now;
}

function CartButton({ quotes }) {
  // Opening it re-asks. The clock here can only ever withdraw a claim; whether a
  // quote is still open is the domain's verdict, and this is the moment someone
  // is about to act on it.
  const held = listState(quotes);
  const now = useTick();
  // The domain decides `expired` at read time and is the authority for it. The
  // clock here can only ever take a claim away — a quote the server called open
  // whose deadline has since passed stops counting as open and says so. It never
  // adds one back, so a skewed client can under-claim and never over-claim.
  const all = held.status === 'read' ? held.items.filter((quote) => quote.state === 'open') : [];
  // Soonest first. The endpoint returns newest first, which is the right order
  // for a record list and the wrong one for a cart: it put the quote with five
  // minutes left below the one with fourteen, and at six quotes on a phone the
  // only time-critical row was the one pushed off the bottom.
  const byDeadline = [...all].sort((left, right) => Date.parse(left.expires_at) - Date.parse(right.expires_at));
  const open = byDeadline.filter((quote) => Date.parse(quote.expires_at) > now);
  const lapsed = byDeadline.filter((quote) => Date.parse(quote.expires_at) <= now);
  return (
    <details name={POPOVER} className={popoverAnchor}
             onToggle={(event) => { if (event.currentTarget.open) quotes.reload(); }}>
      {/* The label carries the count for a reader who never sees the badge. It
          distinguishes the same states the panel does: a read still moving has
          not failed, and neither of them is a count. */}
      <summary className={cx(iconButton, 'relative')} aria-label={held.status === 'read'
        ? `Cart: ${open.length} open quote${open.length === 1 ? '' : 's'}`
        : held.status === 'reading' ? 'Cart: reading the quotes you hold'
        : 'Cart: the quotes you hold could not be read'}>
        {/* No badge while the read is in flight or broken. A zero on a cart is a
            statement that you hold nothing, and neither of those states knows
            that. The popover says which it is; the icon says nothing. */}
        {open.length ? (
          <span className="absolute -right-0.5 -top-0.5 grid h-4 min-w-4 place-items-center rounded-full bg-blue-700 px-1 text-[10px] font-bold text-white">
            {open.length}
          </span>
        ) : null}
        <svg className="h-[18px] w-[18px]" viewBox="0 0 24 24" fill="none" stroke="currentColor"
             strokeWidth="1.7" aria-hidden="true">
          <path strokeLinecap="round" strokeLinejoin="round"
                d="M3 4h2l2.4 10.4a2 2 0 0 0 2 1.6h7.5a2 2 0 0 0 2-1.55L20.5 8H6.2" />
          <circle cx="10" cy="20" r="1.4" /><circle cx="17" cy="20" r="1.4" />
        </svg>
      </summary>
      <div className={panel}>
        <Eyebrow>Cart</Eyebrow>
        <p className="mt-2 text-sm leading-6 text-slate-600">
          Hire runs one worker at a time. A quote is minted against a single listing, expires fifteen
          minutes later, and is consumed when the managed run is set up.
        </p>
        <div className="mt-3 border-t border-slate-100 pt-3">
          <div className="flex items-baseline justify-between gap-3">
            <Eyebrow>Open quotes</Eyebrow>
            {held.status === 'read'
              ? <span className="text-[11px] font-medium text-slate-500">{open.length} open</span>
              : <ReadState status={held.status} />}
          </div>
          {held.status === 'read' ? (
            open.length || lapsed.length ? (
              // Bounded, and scrolls inside itself. Unbounded, six quotes ran the
              // panel off the bottom of a 375px viewport: the last row was
              // sliced, and the disclosure under the list — the one line saying
              // a multi-worker basket does not exist — went with it, along with
              // any sign that more was there. A panel has to terminate on the
              // screen it is drawn on.
              <ul className="mt-2 max-h-[17rem] space-y-2 overflow-y-auto pr-0.5">
                {[...open, ...lapsed].map((quote) => {
                  const live = Date.parse(quote.expires_at) > now;
                  const Row = live ? Link : 'div';
                  return (
                    <li key={quote.quote_ref}>
                      {/* A lapsed quote stops being a link: the destination
                          would mint a new one, and a row that still looks
                          pressable is a row that says this one is still good.
                          It stays on screen rather than vanishing, because a
                          quote disappearing while you look at it hides the one
                          fact you came here for. */}
                      <Row {...(live ? { to: `/agents/${quote.worker_id}/hire` } : {})}
                           className={cx('block rounded-lg border px-3 py-2',
                             live ? 'border-slate-200 hover:border-slate-400' : 'border-slate-200 bg-slate-50')}>
                        <span className="flex items-baseline justify-between gap-2">
                          {/* A quote whose listing is no longer published still
                              exists and still expires. Naming that is not the
                              same as naming the worker. */}
                          <span className={cx('truncate text-sm font-semibold', live ? 'text-slate-800' : 'text-slate-500')}>
                            {quote.worker_name || 'Listing no longer published'}
                          </span>
                          <span className={cx('shrink-0 text-xs font-semibold', live ? 'text-slate-700' : 'text-slate-500')}>
                            {live ? formatAmount(quote.amount) : 'Expired'}
                          </span>
                        </span>
                        <span className="mt-0.5 block text-[11px] text-slate-500">
                          {live
                            ? `expires in ${minutesLeft(quote.expires_at, now)}m · ${formatCadence(quote.amount)}`
                            : 'It expired while this page was open. Setting up a run mints a new one.'}
                        </span>
                      </Row>
                    </li>
                  );
                })}
              </ul>
            ) : (
              <p className="mt-2 text-sm leading-6 text-slate-500">
                No quote is open. One is minted when you start setting up a managed run.
              </p>
            )
          ) : (
            <p className="mt-2 text-sm leading-6 text-slate-500">
              {held.status === 'reading' ? 'Reading the quotes you hold…'
                : held.status === 'unreadable' ? 'The quotes you hold could not be read. This says nothing about whether you hold any.'
                : 'The read completed without reporting a quote list.'}
            </p>
          )}
        </div>
        <div className="mt-3 border-t border-slate-100 pt-3">
          <Gap wrap label="Multi-worker basket" owner="basket owner" />
        </div>
      </div>
    </details>
  );
}

// Legacy put a "Log In" button here. There is no login flow to run: the server
// binds the session and returns the principal, and no network identity owner
// exists to switch or revoke it. So this carries the button weight legacy had,
// shows the principal actually bound, and names what is missing behind it.
function AccountMenu() {
  const session = useLoad(() => productSession(), []);
  const principal = session.value?.principal_ref;
  return (
    <details name={POPOVER} className={popoverAnchor}>
      <summary className="flex cursor-pointer list-none items-center gap-2 rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm font-semibold text-slate-800 hover:border-slate-500 hover:bg-slate-50">
        <span className="grid h-5 w-5 place-items-center rounded-full bg-slate-900 text-[10px] font-bold text-white">
          {principal ? principal.replace(/.*\//, '').slice(0, 1).toUpperCase() : '?'}
        </span>
        {/* The identity, not a truncated URI. The full ref is in the panel. */}
        <span className="hidden sm:inline">{principal ? principal.split('/').pop() : 'Sign in'}</span>
        <svg className="h-3 w-3 text-slate-500" viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="1.8" aria-hidden="true">
          <path strokeLinecap="round" strokeLinejoin="round" d="M3 4.5 6 7.5l3-3" />
        </svg>
      </summary>
      <div className={panel}>
        <Eyebrow>Bound session</Eyebrow>
        <dl className="mt-2 space-y-1.5 text-xs">
          {/* Deliberately never the csrf token, which this payload also carries. */}
          {[['Principal', principal], ['Tenant', session.value?.tenant_ref],
            ['Authority', session.value?.authority_mode]]
            .map(([label, value]) => (
              <div key={label} className="flex justify-between gap-3">
                <dt className="text-slate-500">{label}</dt>
                <dd className="truncate text-right font-mono text-slate-700" title={value}>{value || '—'}</dd>
              </div>
            ))}
        </dl>
        <p className="mt-3 border-t border-slate-100 pt-3 text-[11px] leading-5 text-slate-500">
          The server binds this principal. The browser is never an identity authority.
        </p>
        <div className="mt-3 space-y-2">
          <Gap wrap label="Sign in with a network identity" owner="network identity owner" />
          <Gap wrap label="Switch principal or organisation" owner="multi-principal session owner" />
          <Gap wrap label="Sign out" owner="session revocation endpoint" />
        </div>
      </div>
    </details>
  );
}

function Shell({ children }) {
  const status = useLoad(() => api('/v1/status'), []);
  const receipts = useLoad(() => api('/v1/receipts'), []);
  const quotes = useLoad(() => api('/v1/marketplace/quotes'), []);
  const [params] = useSearchParams();
  const { pathname } = useLocation();
  const query = params.get('q') || '';
  const development = status.value?.authority_mode === 'development';

  return (
    <div className="flex min-h-screen flex-col bg-slate-50 text-slate-950">
      {/* `relative` so a popover can be anchored to the header rather than to
          its own icon at narrow widths. Anchored to the icon, a 320px panel
          under a control whose right edge sits at x=245 starts at x=-75: the
          eyebrow read "ART" and every row lost its first character. */}
      <header className="relative sticky top-0 z-40 border-b border-slate-200 bg-white">
        {development && (
          <div className="bg-gradient-to-r from-cyan-600 via-teal-500 to-cyan-400 text-white">
            <div className="mx-auto flex max-w-[1536px] items-center justify-center gap-2 px-4 py-1.5 text-center text-[11px] font-bold uppercase tracking-[.12em]">
              Local development authority — not network state
            </div>
          </div>
        )}

        {/* The retired prototype ran a market ticker here with invented prices.
            These are the store's own facts — but they are operational telemetry,
            and on a storefront they read as noise above the merchandise. The
            console is where they belong. */}
        {inConsole(pathname) && (
        <div className="hidden border-b border-slate-200 bg-slate-50 md:block">
          <div className="mx-auto flex max-w-[1536px] gap-6 overflow-x-auto px-4 py-1 font-mono text-[11px] whitespace-nowrap text-slate-500">
            <span><span className="font-bold text-slate-600">STORE</span> {status.value?.storage || '—'}</span>
            <span><span className="font-bold text-slate-600">REVISION</span> {status.value?.revision ?? '—'}</span>
            <span><span className="font-bold text-slate-600">RECEIPTS</span> {receipts.value?.items?.length ?? '—'}</span>
            <span>
              <span className="font-bold text-slate-600">CHAIN</span>{' '}
              {/* Same rule as the landing figure: only a reported `false` is
                  BROKEN. A response without the key is not a verdict. */}
              <span className={typeof status.value?.receipt_chain_valid !== 'boolean' ? 'text-slate-600'
                : status.value.receipt_chain_valid ? 'text-emerald-700' : 'text-red-700'}>
                {typeof status.value?.receipt_chain_valid !== 'boolean' ? 'not reported'
                  : status.value.receipt_chain_valid ? 'verified' : 'BROKEN'}
              </span>
            </span>
          </div>
        </div>
        )}

        <div className="mx-auto flex max-w-[1536px] items-center gap-6 px-4 py-3">
          <Link to="/agents" aria-label="aiagent.xyz home" className="block h-11 w-[202px] shrink-0">
            <img src="/animated-logo.svg" alt="aiagent.xyz" className="block h-full w-full object-contain object-left" />
          </Link>
          <HeaderSearch key={query} initial={query} />
          <div className="ml-auto flex shrink-0 items-center gap-1.5">
            {/* Both sides of the marketplace need a persistent way in. Supply
                belongs beside the account controls, not inside the row of
                Sparse Worker Categories — that row filters workers to hire, and
                an entry there reads as a sixth kind of worker. */}
            <NavLink
              to="/freelance"
              className={({ isActive }) => cx(
                'hidden rounded-lg px-3 py-2 text-sm font-bold transition sm:block',
                isActive ? 'bg-slate-950 text-white' : 'text-slate-700 hover:bg-slate-100',
              )}
            >
              New agent
            </NavLink>
            {/* A persistent destination, not a mode swap: entering the console
                must not rearrange the storefront's navigation. */}
            <NavLink
              to="/console"
              className={({ isActive }) => cx(
                'mr-1.5 hidden rounded-lg px-3 py-2 text-sm font-bold transition sm:block',
                isActive ? 'bg-slate-950 text-white' : 'text-slate-700 hover:bg-slate-100',
              )}
            >
              Console
            </NavLink>
            <NotificationBell receipts={receipts} />
            <CartButton quotes={quotes} />
            <AccountMenu />
          </div>
        </div>

        {/* The row scrolls, because Sparse Worker Categories are a growing set
            and an "everything" tab is not coming back. At 420px it overflowed by
            25px, so the last category was sliced mid-word against the viewport
            edge with nothing saying the row continues — four separate reviews
            read that as a rendering fault rather than as scrollable content.
            Tighter rungs below sm make the five that exist today fit exactly;
            the fade is what keeps the sixth honest. */}
        <div className="mx-auto max-w-[1536px] overflow-x-auto px-4
                        [mask-image:linear-gradient(to_right,black_calc(100%-1.5rem),transparent)]
                        sm:[mask-image:none]">
          <nav aria-label="Categories" className="flex min-w-max items-center gap-1">
            {/* Owner direction, 2026-08-14: "view all agents is not the move for
                an agent marketplace", against a reference storefront whose nav
                is categories and nothing else. An "everything" tab is a database
                view, and it was the one entry in this row that is not a Sparse
                Worker Category.

                It was also, until this cut, the only thing on the catalogue that
                said which page you were on — a blind review of removing it alone
                caught exactly that and rejected the change. The count in the
                results toolbar now carries the page's identity instead, which is
                where a count with a subject belongs. */}
            {CATEGORIES.map(([to, label]) => (
              <NavLink
                key={to}
                to={to}
                className={({ isActive }) => cx(
                  'whitespace-nowrap border-b-2 px-2.5 py-3 text-sm transition-colors sm:px-4',
                  isActive
                    ? 'border-blue-600 bg-blue-50/50 font-semibold text-blue-700'
                    : 'border-transparent text-slate-600 hover:border-slate-300 hover:text-slate-900',
                )}
              >
                {label}
              </NavLink>
            ))}
          </nav>
        </div>
      </header>

      {status.error && (
        <div className="border-b border-red-200 bg-red-50 px-4 py-3 text-center text-sm text-red-800">
          Domain API unavailable: {status.error.message}
        </div>
      )}

      <div className="flex-1">{children}</div>

      <footer className="mt-16 border-t border-slate-200 bg-white">
        <div className="mx-auto grid max-w-[1536px] gap-8 px-4 py-10 md:grid-cols-[minmax(0,2fr)_1fr_1fr_1fr]">
          <div>
            <div className="h-10 w-[183px]">
              <img src="/animated-logo.svg" alt="aiagent.xyz" className="block h-full w-full object-contain object-left" />
            </div>
            <p className="mt-3 max-w-md text-sm leading-6 text-slate-600">
              The worker-supply marketplace for the IOI network. This surface never owns package admission, benchmark
              authority, credentials, monetary movement, or runtime execution.
            </p>
            <p className="mt-3 font-mono text-[11px] leading-5 text-slate-500">
              draft ≠ release ≠ registration ≠ listing ≠ quote ≠ entitlement ≠ install ≠ instance
            </p>
          </div>
          <nav className="text-sm">
            <p className="font-bold text-slate-900">Marketplace</p>
            <ul className="mt-3 space-y-2 text-slate-600">
              <li><Link className="hover:text-blue-700" to="/agents">Explore</Link></li>
              {CATEGORIES.map(([to, label]) => (
                <li key={to}><Link className="hover:text-blue-700" to={to}>{label}</Link></li>
              ))}
            </ul>
          </nav>
          <nav className="text-sm">
            <p className="font-bold text-slate-900">Console</p>
            <ul className="mt-3 space-y-2 text-slate-600">
              {CONSOLE_RAIL.map(([to, label]) => (
                <li key={to}><Link className="hover:text-blue-700" to={to}>{label}</Link></li>
              ))}
            </ul>
          </nav>
          <div className="text-sm">
            <p className="font-bold text-slate-900">Network</p>
            <ul className="mt-3 space-y-2 text-slate-600">
              <li><a className="hover:text-blue-700" href="https://developers.ioi.ai" target="_blank" rel="noreferrer">Developer docs</a></li>
              <li><Gap label="Status page" owner="public status owner" /></li>
              <li><Gap label="Support" owner="support desk owner" /></li>
            </ul>
          </div>
        </div>
      </footer>
    </div>
  );
}

/* ── explore ────────────────────────────────────────────────────────── */

const SORTS = {
  recent: ['Recently published', (a, b) => String(b.published_at || '').localeCompare(String(a.published_at || ''))],
  name: ['Name', (a, b) => String(a.name || '').localeCompare(String(b.name || ''))],
  price_low: ['Price: low to high', (a, b) => (a.pricing?.amount_minor || 0) - (b.pricing?.amount_minor || 0)],
  price_high: ['Price: high to low', (a, b) => (b.pricing?.amount_minor || 0) - (a.pricing?.amount_minor || 0)],
};

function WorkerCard({ worker, selected }) {
  return (
    <Card
      as={Link}
      to={`/agents/${worker.worker_id}`}
      className={cx('group h-full', selected && 'ring-2 ring-blue-600 ring-offset-2')}
    >
      <div className="relative h-28 shrink-0" style={identityStyle(worker.composition_root)}>
        <span className="absolute left-3 top-3 rounded bg-black/35 px-2 py-1 text-[11px] font-medium text-white backdrop-blur-sm">
          {worker.license}
        </span>
        {/* Canon requires unbenchmarked supply to be labelled as such, and the
            posture shown is the word the evaluations owner returned. */}
        <span className={cx('absolute right-3 top-3 rounded px-2 py-1 text-[11px] font-bold text-white backdrop-blur-sm',
          worker.benchmark?.status ? 'bg-emerald-700/90' : 'bg-slate-900/60')}>
          {worker.benchmark?.status ? `Benchmark ${worker.benchmark.status}` : 'Unbenchmarked'}
        </span>
        <span
          className="absolute bottom-2 left-3 rounded bg-black/30 px-1.5 py-0.5 font-mono text-[10px] font-bold text-white/85 backdrop-blur-sm"
          title={`Derived shorthand. Composition root ${worker.composition_root}`}
        >
          {workerHandle(worker.name, worker.composition_root)}
        </span>
      </div>

      <div className="flex flex-1 flex-col p-4">
        <h3 className="truncate font-bold text-slate-900 group-hover:text-blue-700" title={worker.name}>{worker.name}</h3>
        <p className="mt-1 truncate text-xs text-slate-500" title={worker.seller_ref}>
          by <span className="text-blue-600">{shortRef(worker.seller_ref, 20)}</span>
        </p>

        <p className="mt-3 line-clamp-3 text-sm leading-5 text-slate-600">{worker.description}</p>

        {/* The media badges already carry licence and benchmark posture; a second
            chip row repeated it and pushed the price below the fold. */}
        <div className="mt-auto flex items-center justify-end gap-3 border-t border-slate-100 pt-4">
          <span className="shrink-0 rounded bg-slate-100 px-2 py-1 text-right text-sm font-bold text-slate-900">
            {formatAmount(worker.pricing)}
            <span className="ml-1 text-xs font-medium text-slate-600">{formatCadence(worker.pricing)}</span>
          </span>
        </div>
      </div>
    </Card>
  );
}

// The prototype's hero declared a "FEATURED SERVICE MODULE" — an editorial
// claim with no owner behind it. This one states a fact the store can prove:
// which listing was published most recently, and the exact refs admitting it.
function Hero({ worker }) {
  if (!worker) return null;
  const provenance = [
    ['release', worker.release_ref],
    ['composition', worker.composition_root],
    ['benchmark', worker.benchmark?.receipt_ref],
    ['plan', worker.benchmark?.evaluation_plan_ref],
  ].filter(([, value]) => value);

  return (
    <section className="overflow-hidden rounded-2xl" style={identityStyle(worker.composition_root)}>
      <div className="grid gap-8 p-8 md:grid-cols-[minmax(0,1fr)_340px] md:p-10">
        <div className="min-w-0">
          <span className="inline-flex rounded bg-white/15 px-2.5 py-1 text-[11px] font-bold uppercase tracking-[.12em] text-white backdrop-blur-sm">
            Most recently published
          </span>
          <h2 className="mt-4 text-3xl font-black tracking-tight text-white md:text-4xl">{worker.name}</h2>
          <p className="mt-3 max-w-xl text-sm leading-6 text-white/75">{worker.description}</p>
          <div className="mt-6 flex flex-wrap items-center gap-4">
            <Link
              to={`/agents/${worker.worker_id}`}
              className="inline-flex min-h-10 items-center rounded-lg bg-white px-4 py-2 text-sm font-bold text-slate-950 transition hover:bg-slate-100"
            >
              View worker
            </Link>
            <Link to="/builder" className="text-sm font-semibold text-white/80 transition hover:text-white">
              Publish a worker →
            </Link>
            <span className="text-sm font-bold text-white">
              {formatAmount(worker.pricing)}
              <span className="ml-1 font-medium text-white/60">{formatCadence(worker.pricing)}</span>
            </span>
          </div>
        </div>

        <div className="rounded-xl border border-white/15 bg-black/25 p-4 backdrop-blur-sm">
          <p className="font-mono text-[10px] uppercase tracking-[.12em] text-white/50">Receipted admission</p>
          <dl className="mt-3 space-y-2.5">
            {provenance.map(([label, value]) => (
              <div key={label}>
                <dt className="font-mono text-[10px] uppercase tracking-[.12em] text-white/40">{label}</dt>
                <dd className="truncate font-mono text-[11px] text-white/80" title={value}>{shortRef(value, 28)}</dd>
              </div>
            ))}
          </dl>
          <p className="mt-3 border-t border-white/10 pt-3 font-mono text-[10px] text-white/40">
            published {formatDate(worker.published_at)}
          </p>
        </div>
      </div>
    </section>
  );
}

function FilterRail({ licenses, license, sort, benchmarked, setParam }) {
  return (
    <aside className="space-y-7">
      <RailSection title="Sort by">
        <select
          aria-label="Sort listings"
          value={sort}
          onChange={(event) => setParam('sort', event.target.value)}
          className={cx(inputStyles, 'py-2 text-sm')}
        >
          {Object.entries(SORTS).map(([key, [label]]) => <option key={key} value={key}>{label}</option>)}
        </select>
      </RailSection>

      <RailSection title="License">
        <ul className="space-y-1 text-sm">
          {['all', ...licenses].map((value) => (
            <li key={value}>
              {/* The selected license was carried by colour and weight alone.
                  A reader who cannot see the blue learns nothing about which
                  filter is in force, and pressing the one already in force is
                  the only control on the catalogue that changes nothing — which
                  is how it was found. `Pill`, the facet control 40px away, has
                  always announced itself this way. */}
              <button
                type="button"
                aria-pressed={license === value}
                onClick={() => setParam('license', value)}
                className={cx(
                  'w-full truncate rounded px-2 py-1.5 text-left transition',
                  license === value ? 'bg-blue-50 font-semibold text-blue-700' : 'text-slate-600 hover:bg-slate-100',
                )}
              >
                {value === 'all' ? 'All licenses' : value}
              </button>
            </li>
          ))}
        </ul>
      </RailSection>

      <RailSection title="Admission">
        <label className="flex cursor-pointer items-center gap-2 px-2 text-sm text-slate-600">
          <input
            type="checkbox"
            checked={benchmarked}
            onChange={(event) => setParam('bench', event.target.checked ? '1' : '')}
            className="h-4 w-4 rounded border-slate-300 text-blue-600 focus:ring-blue-500"
          />
          Benchmark admitted
        </label>
      </RailSection>

      {/* The prototype filtered by an "execution shape" taxonomy (Agent,
          Workflow, Swarm, Operator Pack…). No owner classifies listings that
          way here. It stays named, but as one line under the working facets
          rather than a bordered block with the same weight as a live filter. */}
      <div className="border-t border-slate-200 pt-4">
        <Gap wrap label="Execution shape" owner="worker taxonomy owner" />
      </div>
    </aside>
  );
}

// Replaces the prototype's "Recent Bounties" panel, whose bids, ages, and
// dollar amounts were hard-coded. This reads the receipt log.
function ActivityRail({ receipts }) {
  const chain = listState(receipts);
  const items = useMemo(() => [...(receipts.value?.items || [])].reverse().slice(0, 9), [receipts.value]);
  return (
    <aside>
      <div className="flex items-baseline justify-between gap-2">
        <Eyebrow>Recent activity</Eyebrow>
        {/* A count is not zero because the read has not returned — and not zero
            because the response did not carry the key either. `?? 0` collapsed
            those two into the number that means "your account has none", which
            is the same defect `StatRow` was repaired for and this call site kept.
            Four states, four renderings. */}
        <span className="font-mono text-[10px] text-slate-500">
          {chain.status === 'read' ? `${chain.items.length} receipts` : READ_LABELS[chain.status]}
        </span>
      </div>
      <div className="mt-3 overflow-hidden rounded-xl border border-slate-200 bg-white">
        {items.length ? (
          <ul className="divide-y divide-slate-100">
            {items.map((receipt) => (
              <li key={receipt.receipt_ref} className="px-3.5 py-2.5">
                <div className="flex items-baseline justify-between gap-2">
                  <span className="truncate text-sm font-semibold text-slate-800">{actionLabel(receipt.action)}</span>
                  <span className="shrink-0 font-mono text-[10px] text-slate-500">{relativeTime(receipt.occurred_at)}</span>
                </div>
                <p className="truncate font-mono text-[10px] text-slate-500" title={receipt.object_ref}>
                  #{receipt.sequence} · {shortRef(receipt.object_ref, 22)}
                </p>
              </li>
            ))}
          </ul>
        ) : (
          // The count above this list already distinguished four states; the
          // list itself knew three, so a response that resolved without an items
          // key was labelled "not reported" and then explained as "No receipts
          // recorded yet." — two halves of one panel disagreeing about one read.
          <p className={cx('px-4 py-8 text-center text-sm',
            chain.status === 'unreadable' ? 'text-amber-800' : 'text-slate-500')}>
            {chain.status === 'reading' ? 'Loading receipts…'
              : chain.status === 'unreadable' ? 'The receipt chain could not be read. This says nothing about what exists.'
              : chain.status === 'not_reported' ? 'The read completed without reporting a receipt chain.'
              : 'No receipts recorded yet.'}
          </p>
        )}
      </div>
      <div className="mt-3">
        <Gap block label="Open bounties and demand" owner="bounty owner" />
      </div>
    </aside>
  );
}

function Workers() {
  const workers = useLoad(() => api('/v1/marketplace/workers'), []);
  const receipts = useLoad(() => api('/v1/receipts'), []);
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const [cursor, setCursor] = useState(-1);
  const query = params.get('q') || '';
  const license = params.get('license') || 'all';
  const sort = params.get('sort') || 'recent';
  const benchmarked = params.get('bench') === '1';

  const items = useMemo(() => workers.value?.items || [], [workers.value]);
  const licenses = useMemo(() => [...new Set(items.map((item) => item.license).filter(Boolean))].sort(), [items]);

  const featured = useMemo(
    () => [...items].sort(SORTS.recent[1])[0] || null,
    [items],
  );

  const visible = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return items
      .filter((item) => license === 'all' || item.license === license)
      .filter((item) => !benchmarked || item.benchmark?.status === 'admitted')
      .filter((item) => !needle || [item.name, item.description, item.release_ref, item.composition_root]
        .some((field) => String(field || '').toLowerCase().includes(needle)))
      .sort(SORTS[sort]?.[1] || SORTS.recent[1]);
  }, [items, query, license, sort, benchmarked]);

  const setParam = (key, value) => {
    const next = new URLSearchParams(params);
    if (!value || value === 'all' || (key === 'sort' && value === 'recent')) next.delete(key); else next.set(key, value);
    setParams(next, { replace: true });
  };

  const filtered = license !== 'all' || benchmarked || Boolean(query);

  // j/k or arrows move a selection ring; Enter opens it. Purely local UI state.
  useEffect(() => {
    const onKey = (event) => {
      const tag = event.target?.tagName;
      if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return;
      const last = visible.length - 1;
      if (last < 0) return;
      if (event.key === 'j' || event.key === 'ArrowDown') {
        event.preventDefault();
        setCursor((index) => Math.min(index + 1, last));
      } else if (event.key === 'k' || event.key === 'ArrowUp') {
        event.preventDefault();
        setCursor((index) => Math.max(index - 1, 0));
      } else if (event.key === 'Enter') {
        // Navigating from inside a setState updater would run a router update
        // during render, so the cursor is read from state, not from the updater.
        if (cursor >= 0 && cursor <= last) navigate(`/agents/${visible[cursor].worker_id}`);
      } else if (event.key === 'Escape') {
        setCursor(-1);
      }
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [visible, navigate, cursor]);

  return (
    <main className="mx-auto max-w-[1536px] px-4 py-8">
      {/* Owner direction, 2026-08-14: "might be stronger without text". The
          catalogue's own title block sat between the hero and the merchandise
          and said what the page already shows. It stays for assistive
          technology — the document keeps an h1, and it now precedes the hero's
          h2 rather than following it. */}
      <h1 className="sr-only">Admitted workers</h1>
      {/* The hero promotes the most recently published listing. While a filter
          or a query is applied it kept promoting it — full width, with its own
          View worker button — even when that worker is not among the results.
          Making the count authoritative made the contradiction legible: the
          page's largest element said "here is the newest" while its count said
          "1 of 7 matching". The hero belongs to the unfiltered catalogue. */}
      {!workers.loading && !filtered && <Hero worker={featured} />}

      <div className="mt-8 grid gap-8 xl:grid-cols-[190px_minmax(0,1fr)_280px]">
        <div className="hidden xl:block">
          <FilterRail licenses={licenses} license={license} sort={sort} benchmarked={benchmarked} setParam={setParam} />
        </div>

        <section className="min-w-0">
          {/* Sticky under the header. The catalogue-wide disclosure lives here, and
              a buyer comparing cards mid-scroll should still see it — otherwise
              only the affirmative per-card badges stay in view. Filters staying
              reachable while scrolling is the same win. */}
          <div className="sticky top-[138px] z-20 -mx-1 flex flex-wrap items-center gap-2 bg-slate-50/95 px-1 py-2 backdrop-blur">
            <Pill active={license === 'all' && !benchmarked} onClick={() => { setParams(new URLSearchParams(query ? { q: query } : {}), { replace: true }); }}>
              All listings
            </Pill>
            {licenses.map((value) => (
              <Pill key={value} active={license === value} onClick={() => setParam('license', license === value ? 'all' : value)}>
                {value}
              </Pill>
            ))}
            <Pill active={benchmarked} onClick={() => setParam('bench', benchmarked ? '' : '1')}>
              Benchmarked
            </Pill>
            {/* Two different kinds of statement: a catalogue-wide disclosure and
                the page's own identity. Side by side at 420px, with only
                whitespace between them and both in muted 11px, they fused into
                one run-on line. They share a row only where there is room for
                one. */}
            <span className="ml-auto flex w-full flex-col items-start gap-1 text-xs text-slate-500
                             sm:w-auto sm:flex-row sm:items-center sm:gap-3">
              {/* Canon names the records a worker should accumulate — task success,
                  failure class, cost, latency, human override, dispute rate. No
                  owner produces any of them, and that is true of the whole
                  catalogue, so it is said once here rather than on every card. */}
              <Gap label="Track record" owner="outcome telemetry owner" />
              {/* This count is the only thing on the page that can say what page
                  this is. It used to read "7 results" — a number with no
                  subject — and the lit `All agents` tab carried the identity.
                  With that tab gone the count has to carry it, so it names what
                  is being counted and whether anything is being withheld. */}
              <span className="font-semibold text-slate-700">
                {workers.loading ? 'Loading…'
                  : workers.error ? 'catalogue unreadable'
                  : filtered
                    ? `${visible.length} of ${items.length} workers${query.trim() ? ` matching “${query.trim()}”` : ''}`
                    : `all ${items.length} admitted worker${items.length === 1 ? '' : 's'}`}
              </span>
            </span>
          </div>

          <div className="mt-4 xl:hidden">
            <SearchInput value={query} onChange={(value) => setParam('q', value)} placeholder="Search workers" />
          </div>


          <h2 className="sr-only">Results</h2>
          {workers.loading ? (
            <Skeleton count={4} className="mt-6 grid gap-5 sm:grid-cols-2" />
          ) : workers.error ? (
            <div className="mt-6"><Unreadable error={workers.error} subject="The catalogue" onRetry={workers.reload} /></div>
          ) : visible.length ? (
            <div className="mt-6 grid gap-5 sm:grid-cols-2">
              {visible.map((worker, index) => (
                <WorkerCard key={worker.worker_id} worker={worker} selected={index === cursor} />
              ))}
            </div>
          ) : (
            <div className="mt-6">
              <Empty
                title={items.length ? 'No workers match these filters.' : 'No public workers yet.'}
                action={filtered
                  ? <Button variant="secondary" onClick={() => setParams(new URLSearchParams(), { replace: true })}>Clear filters</Button>
                  : <Link className={buttonStyles.primary} to="/builder">Open Builder</Link>}
              >
                {items.length
                  ? 'Every admitted listing is hidden by the current filters.'
                  : 'Publication is explicit. Draft a worker, release an immutable package, register it, then promote it through benchmark and publication.'}
              </Empty>
            </div>
          )}
        </section>

        <div className="min-w-0">
          <ActivityRail receipts={receipts} />
        </div>
      </div>
    </main>
  );
}

/* ── worker detail ──────────────────────────────────────────────────── */

// Canon, worker-marketplace.md, "Invocation And Management Modes": "The
// buyer-facing marketplace should present three simple modes before exposing
// advanced runtime detail." Held as data rather than three hand-written cards
// so the page can count how many are actually reachable instead of asserting a
// number — a link that said "the three ways to run it" was promising a choice
// two thirds of which the destination refuses.
const RUN_MODES = [
  {
    key: 'ephemeral',
    title: 'Run once',
    blurb: 'A single invocation. Output, artifacts, and run receipts are delivered, then the runtime is torn down.',
    detail: 'No managed instance, SLA, or acceptance contract implied.',
    owner: 'ephemeral run endpoint',
  },
  {
    key: 'install',
    title: 'Install',
    blurb: 'Install the package into your own Hypervisor node, local runtime, or org cloud. Your policy owns execution.',
    detail: 'Package rights and update posture stay tracked here.',
    owner: 'package install-rights endpoint',
  },
  {
    key: 'managed',
    title: 'Run managed',
    blurb: 'A managed instance with a console, lifecycle controls, connector onboarding, delivery channels, and revoke controls.',
  },
];

function WorkerDetail() {
  const { workerId } = useParams();
  const worker = useLoad(() => api(`/v1/marketplace/workers/${workerId}`), [workerId]);

  if (worker.loading) return <main className="mx-auto max-w-[1536px] px-4 py-16 text-sm text-slate-500">Loading listing…</main>;
  if (worker.error || !worker.value) {
    return (
      <main className="mx-auto max-w-[1536px] px-4">
        <LoadFailure
          error={worker.error}
          title="This listing is not available."
          action={<Link className={buttonStyles.primary} to="/agents">Browse admitted agents</Link>}
        />
      </main>
    );
  }
  const item = worker.value;

  // Only the managed mode reaches an endpoint. Which ones do is derived here
  // and counted once, so the wayfinder above cannot drift from the cards below.
  const modes = RUN_MODES.map((mode) => (mode.key === 'managed'
    ? {
      ...mode,
      detail: `${formatAmount(item?.pricing)} ${formatCadence(item?.pricing) || ''}`,
      action: (
        <Link className={cx(buttonStyles.primary, 'w-full')} to={`/agents/${workerId}/hire`}>
          Set up managed run
        </Link>
      ),
    }
    : mode));
  const reachable = modes.filter((mode) => mode.action);

  return (
    <main className="mx-auto max-w-[1536px] px-4 py-10">
      <Link className="inline-flex min-h-11 items-center py-2 text-sm font-medium text-blue-700 hover:underline" to="/agents">← Explore</Link>

      {/* Three grid children, not two, so source order and column layout can
          disagree. On a phone this stacks hero → price and provenance → the
          rest. It previously stacked the whole body first, putting the price
          panel at y≈2,160 of a 3,550px page — below the track record and both
          disclosures, immediately above the footer. What was buried there was
          not the buy control (that lives in the Run managed card, at y≈1,234)
          but the price itself and the three lines that say who stands behind
          this listing: benchmark authority, published date, publisher. On a
          listing whose track record is three named absences, that attribution
          is the only evidence a buyer has, and it was arriving after the
          decision. The explicit rows and columns reproduce the wide layout
          exactly — a pixel diff of the body at 1600px is empty. */}
      <div className="mt-5 grid gap-x-10 gap-y-8 lg:grid-cols-[minmax(0,1fr)_360px]">
        <div className="min-w-0 lg:col-start-1 lg:row-start-1">
          {/* The identity band was 128px of empty gradient at the top of the
              page where a worker is actually chosen. On a card the same band
              carries the licence, the handle and the benchmark badge; here it
              carried nothing, while the handle and the licence were repeated
              below it as chips and again in the aside. It becomes the hero it
              was standing in for. The colour is still derived from the
              composition root and still encodes nothing else. */}
          <div className="relative overflow-hidden rounded-xl px-6 py-7 sm:px-8 sm:py-9"
               style={identityStyle(item?.composition_root)}>
            <div className="flex flex-wrap items-center gap-2">
              <span className="rounded bg-black/40 px-2 py-1 text-[11px] font-bold text-white backdrop-blur-sm">
                {item?.license}
              </span>
              <span
                title={`Derived shorthand. Composition root ${item?.composition_root}`}
                className="rounded bg-black/40 px-2 py-1 font-mono text-[11px] font-bold text-white backdrop-blur-sm"
              >
                {workerHandle(item?.name, item?.composition_root)}
              </span>
            </div>
            {/* A display measure, not the container's width and not 20ch.
                20ch broke a 26-character name onto two lines inside an 1104px
                bed and made the hero's height a function of name length; no
                clamp at all leaves a 55-character name running ~900px of 36px
                type, about twice a readable measure, and it wraps anyway at the
                full width with a worse rag. 32ch keeps every name in this
                catalogue on one line and still protects a long one. */}
            <h1 className="mt-4 max-w-[32ch] text-4xl font-black tracking-tight text-white">{item?.name}</h1>
          </div>

          <div className="mt-4 flex flex-wrap items-center gap-2">
            {/* Two separate postures with two separate vocabularies; showing the
                word the owner returned, never a remapped one. */}
            <State label="listing" value={item?.state} />
            <State label="benchmark" value={item?.benchmark?.status || 'unbenchmarked'} />
          </div>
        </div>

        <Panel as="aside" className="h-fit lg:sticky lg:top-40 lg:col-start-2 lg:row-start-1 lg:row-span-2">
          <p className="text-xs font-bold uppercase tracking-[.18em] text-slate-500">Managed run</p>
          <p className="mt-2 text-3xl font-black text-slate-950">{formatAmount(item?.pricing)}</p>
          <p className="text-sm font-medium text-slate-500">{formatCadence(item?.pricing)}</p>

          {/* The panel stated a price and offered nothing to do about it: the
              only control that acts on it lives in the Run managed card, and
              on a phone that is ~1,200px further down, past two modes that are
              unavailable. This is not a second buy button — the choice of mode
              is the decision canon puts first, and this goes to it. On a wide
              viewport the panel is sticky, so it stays reachable while the
              body scrolls.

              A link, not a button. At primary weight the page carried two
              identical full-width black buttons and the one in the buy-box
              position — top right, directly under the price — was the one that
              does not buy. Demoting it to an outlined button only moved the
              problem: a low-contrast outline sitting immediately above three
              greyed ⊘ rows reads as a fourth unavailable item, which is a worse
              failure because it is silent. A button-shaped object in the buy
              box reads as the buy box's button whatever its fill. This is
              shaped like the other navigation on the page instead.

              No "today": there is no roadmap on this page, no date and no
              notify-me, so a word implying one manufactures a "when, then?" and
              answers it with nothing. What can be said is what a buyer can do
              now, which is the same fact without the promise.

              The label names the working path rather than scoring the page.
              "The three ways to run it" was a choice claim the destination
              refuses two thirds of; "1 of 3 available" fixed the honesty and
              introduced an ambiguity — beside a price, "available" reads as
              inventory ("1 of 3 left") at least as readily as capability. When
              exactly one mode is reachable the link says which one it is; if a
              second endpoint lands it falls back to the count. Both are derived
              from the same list the cards render, so neither can drift. */}
          <a href="#run-modes"
             className="mt-3 inline-flex min-h-11 items-center gap-1.5 py-2 text-sm font-semibold text-blue-700 hover:underline">
            {reachable.length === 1
              ? `${reachable[0].title} — the only one you can start`
              : `How you can run it — ${reachable.length} of ${modes.length} you can start`}
            <span aria-hidden="true">↓</span>
          </a>

          <dl className="mt-5 space-y-2.5 border-t border-slate-200 pt-4 text-sm">
            {/* Licence moved to the hero, where it is stated once. What is left
                here is what the hero does not say: who admitted the benchmark,
                and when and by whom the listing was published. */}
            {[['Benchmark authority', item?.benchmark?.owner || 'not benchmarked'],
              ['Published', formatDate(item?.published_at)],
              ['Publisher', shortRef(item?.seller_ref, 18)]].map(([label, value]) => (
              <div key={label} className="flex justify-between gap-3">
                <dt className="text-slate-500">{label}</dt>
                <dd className="text-right font-medium text-slate-800">{value}</dd>
              </div>
            ))}
          </dl>

          <p className="mt-4 text-xs leading-5 text-slate-500">
            Setting up a managed run creates separate quote, entitlement, install, and runtime-assignment
            records. Any missing owner fails closed before you are charged.
          </p>

          <div className="mt-4 space-y-2 border-t border-slate-200 pt-4">
            <Gap label="Free trial" owner="trial entitlement owner" />
            <Gap label="Save for later" owner="saved-listing owner" />
            <Gap label="Contact the publisher" owner="publisher messaging owner" />
          </div>
        </Panel>

        <section className="min-w-0 lg:col-start-1 lg:row-start-2">
          <SubHeading>What it does</SubHeading>
          <p className="mt-2.5 max-w-[62ch] text-xl leading-9 text-slate-700">{item?.description}</p>
          {/* One of the three arrived. The task contract is a typed declaration
              the publisher makes and the allowlist admits, so it is rendered as
              what it is — the shape of the work, in the publisher's own type
              names. Responsibilities and worked examples are long-form prose no
              record in this estate carries, and the marker narrows to them
              rather than covering all three as it did when none was available.
              The row stays open in the handoff, with two thirds of its scope. */}
          <div className="mt-5 max-w-[62ch] space-y-3">
            {(() => {
              const contract = disclosureField(item, 'task_contract');
              if (contract.state !== 'disclosed' || !contract.value?.input) {
                return <DisclosureNote state={contract.state} />;
              }
              return (
                <div className="border-y border-slate-200 py-3">
                  <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
                    <p className="text-xs font-bold text-slate-800">Task contract</p>
                    {/* Micro-weight, like the counters further down: provenance
                        was reading heavier than the payload it attributes. */}
                    <p className="text-[11px] font-medium text-slate-500">declared by the publisher</p>
                  </div>
                  {/* An arrow, not two chips side by side: the contract is
                      directional, and a pair of equal pills says nothing about
                      which end is the input. */}
                  <p className="mt-1.5 flex flex-wrap items-center gap-2 font-mono text-xs text-slate-700">
                    <span className="rounded border border-slate-200 bg-slate-50 px-2 py-1">{contract.value.input}</span>
                    <span aria-hidden="true" className="text-slate-500">→</span>
                    <span className="sr-only">produces</span>
                    <span className="rounded border border-slate-200 bg-slate-50 px-2 py-1">{contract.value.output}</span>
                  </p>
                  {/* What a reviewer asked for here was a gloss — "one inbound
                      ticket in; one resolution record out" — which would be this
                      surface writing the meaning of the publisher's type. What
                      can be said is what the record holds and what it does not:
                      two type names, and no fields behind them. A buyer who
                      needs to know whether a resolution is a drafted reply or a
                      closed ticket learns here that the package does not say. */}
                  <p className="mt-1.5 max-w-[62ch] text-xs leading-5 text-slate-500">
                    Type names only. The package declares no fields behind them, so what a
                    {' '}<span className="font-mono">{contract.value.output}</span> contains is not stated here.
                  </p>
                </div>
              );
            })()}
            <Gap block label="Responsibilities and worked examples"
                 owner="long-form disclosure on the listing projection" />
          </div>

          {/* Canon: present the three invocation modes before any runtime
              detail (worker-marketplace.md, Invocation And Management Modes). */}
          <SubHeading id="run-modes" className="mt-10">How you can run it</SubHeading>
          <div className="mt-3 grid gap-4 sm:grid-cols-3">
            {modes.map((mode) => (
              <ModeCard
                key={mode.key}
                selected={Boolean(mode.action)}
                title={mode.title}
                blurb={mode.blurb}
                detail={mode.detail}
                owner={mode.owner}
                action={mode.action}
              />
            ))}
          </div>

          <SubHeading className="mt-10">What it needs from you</SubHeading>
          <p className="mt-1.5 max-w-[62ch] text-sm leading-6 text-slate-600">
            Connector access and delivery channels stay separate: a worker may read from a system it never
            reports into, and report into a channel it holds no credentials for.
          </p>
          <div className="mt-3 divide-y divide-slate-200 border-y border-slate-200">
            {/* The listing projects what the seller admitted of the exact
                composition the package owner released. `integration_surface_refs`
                resolving to an IntegrationSurfaceProfile and its default posture
                is still owner work; the declared surfaces themselves are on the
                record and are what canon has the buyer inspect before hiring. */}
            <Requirement label="Apps and data it connects to"
                         field={disclosureField(item, 'integration_surfaces')} />
            {/* Same projection, same allowlist decision, one more field: canon
                puts "authority, data, privacy, retention, export, and license
                posture" among a registration's bindings, and the hire flow has
                the buyer inspect access needs before hiring. Scopes are the
                sharper half of that — what it may DO, against what it may read. */}
            <Requirement label="Permissions it will hold"
                         field={disclosureField(item, 'authority_scopes')} />
            <Requirement label="Where it reports back to you"
                         owner="delivery channel disclosure" />
            {/* Canon makes ModelRoute policy and runtime profile default
                metadata on every public listing, so these do not wait on a
                seller's allowlist. The typed refs name their own kind, which is
                why they are shown as they are rather than relabelled. */}
            <Requirement label="Model and runtime options"
                         field={mergedDisclosure(item, ['model_route_ref', 'runtime_profile_ref'])}
                         supplies={false} />
          </div>

          <SubHeading className="mt-10">Track record</SubHeading>
          <div className="mt-3 grid gap-3 sm:grid-cols-3">
            {/* One owner, one slot — canon's measurable records for it are listed
                inside rather than split across two identically-blocked gaps. */}
            <Gap block label="Task success, failure class, cost, and latency" owner="outcome telemetry owner" />
            <Gap block label="Human override and dispute rate" owner="dispute owner" />
            <Gap block label="Reviews and rating" owner="review owner" />
          </div>

          {/* Canon: audit drawers disclose refs behind the buyer-facing steps. */}
          <div className="mt-10 space-y-3">
            <Drawer title="Admission and provenance" hint="how this listing got here">
              <Spine nodes={[
                {
                  title: 'Package released',
                  done: Boolean(item?.release_ref),
                  rows: [['release', item?.release_ref], ['composition', item?.composition_root]],
                },
                {
                  title: 'Registered',
                  done: Boolean(item?.registration_ref),
                  rows: [['registration', item?.registration_ref]],
                },
                {
                  title: item?.benchmark ? 'Benchmark admitted' : 'Benchmark',
                  done: item?.benchmark?.status === 'admitted',
                  when: item?.benchmark?.observed_at ? formatDate(item.benchmark.observed_at) : null,
                  rows: item?.benchmark
                    ? [['owner', item.benchmark.owner], ['plan', item.benchmark.evaluation_plan_ref],
                       ['receipt', item.benchmark.receipt_ref]]
                    : [['owner', 'no evaluations decision on this release']],
                },
                {
                  title: 'Listing published',
                  done: item?.state === 'published',
                  when: formatDate(item?.published_at),
                  rows: [['worker', item?.worker_id], ['license', item?.license], ['seller', item?.seller_ref]],
                },
              ]} />
            </Drawer>

            <Drawer title="Category and routing eligibility" hint="market structure">
              <p className="max-w-[62ch] text-sm leading-6 text-slate-600">
                Sparse Worker Categories are the narrow labour markets that define a task class, benchmark
                suite, evaluation rubric, runtime requirements, and routing-eligibility criteria. Admission
                to a category is not the same as routing eligibility, and neither is purchasable.
              </p>
              <div className="mt-3 space-y-2">
                <Gap block label="Category membership" owner="sparse worker category record" />
                <Gap block label="Routing eligibility" owner="MoW routing owner" />
              </div>
            </Drawer>
          </div>
        </section>
      </div>
    </main>
  );
}

/* ── freelance: the compositor lens ─────────────────────────────────── */

// Canon (components/hypervisor/core-clients-surfaces.md) gives this surface its
// owner and its object: the Workflow Compositor owns "service and workflow graph
// shape", and its reusable canonical object is `WorkflowTemplateEnvelope` — "an
// immutable, content-addressed directed graph revision. A template never runs
// itself." Line 609 already anticipates a "Workflow Compositor graph projection"
// consumed by other product surfaces.
//
// So this page is a lens, not a builder: the graph belongs to the compositor,
// and nothing here may mint a second copy of it. Until the projection is
// reachable from this surface, the page states what it will bind and names what
// is missing, rather than shipping a canvas backed by marketplace-local state.

// The bindings a benchmarkable composition must carry, verbatim from
// worker-marketplace.md, "Composable Open Worker Supply" — grouped into the
// stages they actually flow through, because the compositor owns a *directed*
// graph and a flat grid of ten cards hides that entirely.
const COMPOSITION_STAGES = [
  ['Identity', [
    ['Source and licence', 'Provenance, licence, maintainer, and version refs.'],
  ]],
  ['Execution', [
    ['Model route', 'Route options or requirements — local, BYOK, hosted, provider, DePIN, TEE.'],
    ['Harness and entrypoint', 'HarnessProfile or AgentHarnessAdapter plus the runtime entrypoint.'],
    ['Placement and privacy', 'Runtime placement and privacy posture.'],
  ]],
  ['Access', [
    ['Tools and connectors', 'The integration surfaces it reads from and acts inside.'],
    ['Authority and approvals', 'Scopes it may hold and the approval policy over them.'],
  ]],
  ['State', [
    ['Memory and persistence', 'Retention, export, and forget posture.'],
  ]],
  ['Proof', [
    ['Verifier path', 'Acceptance posture and who checks the work.'],
    ['Benchmark profile', 'The suite and rubric a score will attach to.'],
  ]],
  ['Package', [
    ['Package policy', 'Artifact, receipt, and contribution policy.'],
  ]],
];

function Freelance() {
  return (
    <main>
      <SectionHead
        eyebrow="New agent"
        title="Build your own worker."
        lede="Bind a model route, a harness, connectors, authority scopes, and a runtime into one composition
              you can benchmark, publish, and hire out — on the Hypervisor substrate, through this surface."
      />

      <div className="mt-8 grid gap-8 lg:grid-cols-[minmax(0,1fr)_380px]">
        <section className="min-w-0">
          <SubHeading>What you compose</SubHeading>
          <p className="mt-1.5 max-w-[70ch] text-sm leading-6 text-slate-600">
            A worker is not a prompt or a model checkpoint. It is a composition that binds all of the
            following — and a material change to any one of them produces a new composition version, or
            requires rebenchmarking before the old score can be used again.
          </p>

          {/* Laid out as the editor this becomes: stages in flow order, with the
              canvas itself named as the projection that is missing. */}
          <div className="mt-5 rounded-2xl border border-slate-200 bg-white p-4">
            {/* One row, scrolling. Wrapping broke the directed reading: an arrow
                at the end of a row pointed into nothing. Wide content scrolls
                inside its own container rather than widening the page. */}
            <div className="flex items-stretch gap-2 overflow-x-auto pb-1">
              {COMPOSITION_STAGES.map(([stage, bindings], index) => (
                <React.Fragment key={stage}>
                  <div className="w-[210px] shrink-0 rounded-xl bg-slate-50 p-3">
                    <p className="text-[10px] font-bold uppercase tracking-[.12em] text-slate-500">{stage}</p>
                    <div className="mt-2 space-y-2">
                      {bindings.map(([label, blurb]) => (
                        <div key={label} className="rounded-lg border border-slate-200 bg-white p-2.5">
                          <p className="text-sm font-bold leading-4 text-slate-900">{label}</p>
                          <p className="mt-1 text-[11px] leading-4 text-slate-500">{blurb}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                  {index < COMPOSITION_STAGES.length - 1 && (
                    <div aria-hidden="true" className="flex shrink-0 items-center text-slate-500">→</div>
                  )}
                </React.Fragment>
              ))}
            </div>
            <div className="mt-4 border-t border-slate-100 pt-3">
              <Gap wrap label="Editable canvas" owner="Workflow Compositor graph projection on this surface" />
            </div>
          </div>

          <SubHeading className="mt-10">Why it is a lens</SubHeading>
          <p className="mt-1.5 max-w-[62ch] text-sm leading-6 text-slate-600">
            The graph belongs to the Hypervisor Workflow Compositor, whose canonical object is an immutable,
            content-addressed directed graph revision. This surface projects and edits that object; it does not
            keep its own copy, and it never executes the result. A template never runs itself — activation and
            execution identity come from a typed run owner.
          </p>

          <div className="mt-5 space-y-2.5">
            <Gap block label="Compositor graph projection" owner="Workflow Compositor projection on this surface" />
            <Gap block label="Template read and revise" owner="WorkflowTemplateEnvelope read/write binding" />
            <Gap block label="Connector binding from the canvas" owner="connector authority grant flow" />
            <Gap block label="Live benchmark staleness while editing" owner="rebenchmark projection" />
          </div>
        </section>

        <aside className="h-fit space-y-4">
          <Panel>
            <h2 className="text-sm font-bold text-slate-900">What works today</h2>
            <p className="mt-1.5 text-xs leading-5 text-slate-600">
              Builder composes from registered starter templates and carries a draft through the full
              admission ladder — validate, release, register, propose, submit, benchmark, publish.
            </p>
            <Link className={cx(buttonStyles.primary, 'mt-4 w-full')} to="/builder">Open Builder</Link>
          </Panel>

          <Panel>
            <h2 className="text-sm font-bold text-slate-900">Where the work goes</h2>
            <p className="mt-1.5 text-xs leading-5 text-slate-600">
              A composition you publish here becomes hireable supply. Commissioned outcomes — bids, escrow,
              acceptance criteria, disputes — are a separate lifecycle and a separate property.
            </p>
            <a className={cx(buttonStyles.secondary, 'mt-4 w-full')} href="https://sas.xyz"
               target="_blank" rel="noreferrer">Service outcomes ↗</a>
          </Panel>
        </aside>
      </div>
    </main>
  );
}

/* ── hire and configure ─────────────────────────────────────────────── */

// Canon, "Hire And Configure Flow": listing -> hire/subscribe/install ->
// "choose supported model, runtime, and persistence options" -> "choose memory
// persistence, export, retention, and forget posture" -> "connect required apps
// and set permissions" -> "choose contact and delivery channels" -> "configure
// standing orders, schedules, escalation, quiet hours, and approvals" -> "start
// managed instance".
//
// Two of those inputs reach an endpoint today: runtime and persistence profile
// refs are accepted by the hire call. The rest have no owner, so they render as
// designed-but-inert steps naming what they wait on. The sequence is built in
// full so wiring a step later is a data change, not a redesign.
const HIRE_STEPS = [
  { key: 'runtime', title: 'Runtime', blurb: 'Where it runs' },
  { key: 'memory', title: 'Memory', blurb: 'Retention and forget posture', pending: true,
    owner: 'memory policy owner' },
  { key: 'connections', title: 'Connections', blurb: 'Apps and permissions', pending: true,
    owner: 'connector authority grant flow' },
  { key: 'delivery', title: 'Delivery', blurb: 'Where it reports back', pending: true,
    owner: 'delivery channel owner' },
  { key: 'orders', title: 'Standing orders', blurb: 'Schedules and escalation', pending: true,
    owner: 'standing order owner' },
  { key: 'review', title: 'Review and start', blurb: 'What gets created' },
];

// Canon's six default product modes for managed-instance memory, verbatim from
// worker-marketplace.md, "Portable Managed-Instance Memory". The step used to
// show three generic slots — retention, export, forget — which described the
// shape of a control rather than the choice a buyer is actually making.
const MEMORY_MODES = [
  ['Ephemeral', 'No durable memory after the run.'],
  ['Session', 'Survives only inside the session or the active instance.'],
  ['Grace archive',
   'An encrypted memory archive retained for a bounded period after cancellation, uninstall, or provider exit.'],
  ['Persistent', 'Retained while the install, subscription, or enterprise policy remains active.'],
  ['Exportable', 'You or your organisation can export a portable Agent Wiki or memory bundle.'],
  ['Forget',
   'You or your organisation can delete semantic memory, subject to policy, legal holds, audit retention, and marketplace dispute requirements.'],
];

// Canon, "Hire And Configure Flow": "Connector access and user communication
// must stay separate in the product model. […] If Slack is only a delivery
// channel, it may receive summaries and deep links but not durable secrets,
// decryption leases, or high-risk approvals. If the worker acts inside Slack as
// part of the job, that Slack workspace is also an `IntegrationSurface` with its
// own connector, authority scopes, policy posture, and receipts."
//
// Connections and Delivery are the two sides of that sentence. Neither can be
// bound here yet — but which of the two a buyer is agreeing to is the whole
// difference between a worker that posts a digest into a channel and one that
// reads, writes, and acts inside that workspace. Naming the boundary costs
// nothing and is the one thing this rung can honestly say today.
const CONNECTION_KINDS = [
  {
    title: 'A work integration',
    object: 'IntegrationSurface',
    blurb: 'Somewhere the worker observes or acts as part of the job.',
    carries: [
      'A connector binding and the exact authority scopes it resolves',
      'Allowed and forbidden action classes for that class of surface',
      'Approval defaults, abuse controls, and platform-policy posture',
      'An action receipt for every act taken inside it',
    ],
    note: 'Forbidden action classes are fixed by the surface class, not by this listing.',
  },
  {
    title: 'A delivery channel',
    object: 'ContactDeliveryChannel',
    blurb: 'Somewhere the instance reports back to you.',
    carries: [
      'Redacted summaries and delivery artifacts',
      'Status and approval deep links',
      'A redaction policy and quiet-hours policy',
      'A delivery receipt',
    ],
    refuses: ['Durable secrets', 'Decryption leases', 'High-risk approvals'],
    note: 'A digest destination is never proof that the worker may read or mutate that workspace.',
  },
];

// integration-surface-taxonomy.md, "Integration Classes" — the whole table. A
// worker binds to a class rather than to a bespoke runtime, and the class is
// what fixes its default posture, so this is the vocabulary the sentence above
// is written in. It is canon reference, not a claim about any listing.
const INTEGRATION_CLASSES = [
  ['chat_community', 'Discord, Slack, Matrix', 'external messages, moderation, audit receipts'],
  ['contact_delivery', 'email, SMS, Slack, Discord, Telegram, mobile push, webhook, MCP callback',
   'notification/delivery only unless upgraded to a work integration'],
  ['game_platform', 'Steam, Xbox, game server selection', 'platform terms, rate limits, anti-cheat care'],
  ['browser_saas', 'CRM, helpdesk, admin dashboards', 'browser-use receipts and step-up for destructive actions'],
  ['developer_code', 'GitHub, GitLab, local repos', 'patch receipts, tests, branch policy'],
  ['commerce', 'Shopify, Stripe-like admin, marketplaces', 'funds/PII risk and transaction receipts'],
  ['finance_trading', 'broker APIs, exchange/trade candidates', 'wallet authority, risk labels, max-loss policy'],
  ['local_computer_use', 'desktop apps, file systems', 'local authority and workspace trust'],
  ['enterprise_vpc', 'customer cloud, private APIs', 'org policy, audit export, data boundaries'],
  ['webhook_api', 'typed HTTP/RPC integrations', 'schema validation and signed receipts'],
  ['voice_sms_access', 'SMS, voice, phone links', 'notification/intent only unless step-up'],
  ['robotics_physical', 'robot arms, mobile robots', 'physical-action safety required'],
  ['embodied_humanoid', 'humanoids, facility assistants', 'supervision and e-stop required'],
  ['vehicles_mobility', 'vehicle-adjacent or mobility systems', 'high-risk physical policy'],
  ['field_service_inspection', 'site visits, inspections', 'sensor evidence and liability hooks'],
  ['education_tutoring', 'learner support', 'safety, privacy, age/jurisdiction policy'],
  ['creative_media', 'design, video, publishing', 'rights and disclosure policy'],
  ['support_operations', 'tickets, operations consoles', 'escalation and audit trails'],
];

// integration-surface-taxonomy.md, "Minimal Implementation Object" — the
// ContactDeliveryChannel `channel_kind` and `posture` vocabularies in full.
// Both are rendered as vocabulary rather than as described options: canon fixes
// the names and fixes exactly one constraint on them, so anything further would
// be this surface inventing semantics for an object it does not own.
const DELIVERY_CHANNEL_KINDS = [
  'web console', 'email', 'sms', 'slack', 'discord', 'telegram',
  'webhook', 'mcp callback', 'mobile push', 'custom channel',
];

const DELIVERY_POSTURES = [
  'notification only', 'summary delivery', 'interactive thread',
  'approval deeplink', 'workflow callback',
];

// Canon's ladder, worker-marketplace.md: "configure standing orders, schedules,
// escalation, quiet hours, and approvals". The same doc's change lifecycle
// already prices each of those — and prices them differently. "quiet hours" and
// "delivery cadence" are safe live config; "standing order" and "schedule" need
// a change plan and a dry run or canary. Bundling them into one control, as
// this rung did, hides the one fact a buyer can act on today: which of these
// decisions is cheap to revisit and which is not.
//
// `tierItem` is the exact string canon puts in a tier, looked up rather than
// restated, so the two surfaces cannot drift. A setting canon does not place in
// a tier gets no claim about what changing it costs.
const ORDER_SETTINGS = [
  {
    title: 'Standing orders and schedules',
    blurb: 'Work it should do without being asked each time, and when it should do it.',
    owner: 'standing order owner',
    tierItem: 'standing order',
  },
  {
    title: 'Quiet hours and delivery cadence',
    blurb: 'When it must stay silent, and how often it reports without being asked.',
    owner: 'schedule owner',
    tierItem: 'quiet hours',
  },
  {
    title: 'Escalation and approvals',
    blurb: 'What it must hand to a person instead of deciding.',
    owner: 'approval policy owner',
    // integration-surface-taxonomy.md, "Minimal Implementation Object":
    //   approval_defaults: low_risk: session_envelope | high_risk: step_up_review
    note: 'Defaults are set by risk class: low risk resolves inside the session envelope, high risk '
        + 'requires a step-up review. A delivery channel may carry the approval deep link; it never '
        + 'carries the approval.',
  },
];

// The stack that makes the modes above mean anything: which owner holds what.
const MEMORY_STACK = [
  ['Worker package', 'Declares supported memory kinds, portability, retention, and projection needs.'],
  ['This instance', 'Binds owner-scoped wiki, memory profile, archive, and projection refs.'],
  ['Agentgres', 'Admits context mutations, provenance, receipts, state roots, restore and forget truth.'],
  ['Storage backend', 'Stores encrypted archive payload bytes and large private memory payloads.'],
  ['Authority provider', 'Gates decryption, restore, export, and cross-domain sharing when required.'],
  ['Console, API, MCP', 'Receive a policy-filtered projection, never raw private memory by default.'],
];

function HireFlow() {
  const { workerId } = useParams();
  const navigate = useNavigate();
  const worker = useLoad(() => api(`/v1/marketplace/workers/${workerId}`), [workerId]);
  const [step, setStep] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [form, setForm] = useState({
    runtime_profile_ref: 'runtime-profile://zero-to-idle/v1',
    persistence_profile_ref: 'storage-profile://encrypted-backup/v1',
  });

  const item = worker.value;

  const start = async () => {
    setBusy(true); setError(null);
    try {
      const quote = await api(`/v1/marketplace/workers/${workerId}/quote`, { method: 'POST', body: { intent: 'hire' } });
      const result = await api(`/v1/marketplace/workers/${workerId}/instances`, {
        method: 'POST',
        body: {
          quote_ref: quote.quote_ref,
          runtime_profile_ref: form.runtime_profile_ref,
          persistence_profile_ref: form.persistence_profile_ref,
          authority_grant_refs: [],
        },
      });
      navigate(`/instances/${result.instance.worker_instance_id}`);
    } catch (cause) { setError(cause); } finally { setBusy(false); }
  };

  if (worker.loading) {
    return <main className="mx-auto max-w-[1100px] px-4 py-16 text-sm text-slate-500">Loading listing…</main>;
  }
  if (worker.error || !worker.value) {
    return (
      <main className="mx-auto max-w-[1100px] px-4">
        <LoadFailure
          error={worker.error}
          title="This listing cannot be hired."
          action={<Link className={buttonStyles.primary} to="/agents">Browse admitted agents</Link>}
        />
      </main>
    );
  }

  const panels = {
    runtime: (
      <>
        <Field label="Runtime profile" value={form.runtime_profile_ref}
               onChange={(runtime_profile_ref) => setForm({ ...form, runtime_profile_ref })}
               hint="Sent with the hire request. The runtime owner admits or refuses this placement." />
        <Field label="Persistence profile" value={form.persistence_profile_ref}
               onChange={(persistence_profile_ref) => setForm({ ...form, persistence_profile_ref })}
               hint="Sent with the hire request. Governs where durable instance state is written." />
        {/* The rung asked which package-supported route to run on. The package
            names one, so the answer is the one it names and the fact that there
            is nothing else to pick — not a marker saying the question cannot be
            answered. The fields above stay editable because the runtime owner
            admits or refuses what is sent, which is a different question from
            what the package supports. */}
        <Panel>
          <p className="text-sm font-semibold text-slate-700">What the package runs on</p>
          <div className="mt-2 border-t border-slate-200">
            <Requirement
              label="Route, harness and runtime profile"
              field={mergedDisclosure(item, ['model_route_ref', 'harness_ref', 'runtime_profile_ref'])}
              note="Declared in the admitted package: one model route, one harness, one runtime profile. A managed instance may one day offer a choice among package-supported routes — local, BYOK, hosted, provider, DePIN, TEE, or Private Workspace cTEE — but this package declares no alternatives to choose between."
            />
          </div>
        </Panel>
      </>
    ),
    memory: (
      <>
        <p className="max-w-[62ch] text-sm leading-6 text-slate-600">
          What this worker learns about your work is bound to you, not to the model it happens to be running.
          Memory held inside a harness or a provider thread is a cache; the durable copy is an Agent Wiki bound
          to this instance. That is what lets you change model later and keep what it learned.
        </p>

        <div>
          <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
            <Eyebrow>Retention posture</Eyebrow>
            <Gap label="Not selectable yet" owner="memory policy on the listing projection" />
          </div>
          {/* Six named kinds and what each means — a definition list, which is
              what they are. They were a marker plus a label on divided rows,
              and a dashed circle is still a circle: that is the anatomy of a
              radio group, so a reader formed the belief that this was a choice
              and had to be corrected. Marking the affordance inert is weaker
              than not building the affordance. Same component as the drawer
              below, which has always rendered the memory stack this way. */}
          <div className="mt-2">
            <DefList rows={MEMORY_MODES.map(([name, blurb]) => [name, blurb, { mono: false }])} />
          </div>
        </div>

        <p className="max-w-[62ch] text-xs leading-5 text-slate-500">
          Deleting memory here would be a marketplace receipt for a marketplace act. It is not proof that a
          model provider deleted anything, and it never claims to be.
        </p>

        <Drawer title="Where memory actually lives" hint="which owner holds what">
          <DefList rows={MEMORY_STACK.map(([layer, holds]) => [layer, holds, { mono: false }])} />
        </Drawer>
      </>
    ),
    connections: (
      <>
        {/* No longer an inert panel: the listing discloses what the package
            declares it connects to, and this rung is where a buyer decides
            whether they can supply it. What is still inert is the rung's other
            half — binding a connector — and that keeps its named owner, so the
            step now separates a disclosure it has from an action it cannot take
            rather than marking both as missing. */}
        <Panel>
          <p className="text-sm font-semibold text-slate-700">Apps this worker needs</p>
          <p className="mt-1 max-w-[60ch] text-xs leading-5 text-slate-500">
            Declared in the admitted package. Binding each one is the step below, and needs an authority grant
            you hold rather than anything this listing can give.
          </p>
          {/* The sublabel is back, and the second reviewer who asked for it was
              right against the first who asked for its removal: it is the only
              place on this rung that names the class the reference block below
              spends its whole left column defining, so removing it took the
              vocabulary out and left the definition arguing with nothing. It is
              a label with a count opposite it now, which is the form the listing
              uses, rather than a bold sub-head that restated the panel title. */}
          <div className="mt-2 border-t border-slate-200">
            <Requirement label="Integration surfaces" field={disclosureField(item, 'integration_surfaces')} />
          </div>
        </Panel>
        <InertPanel label="Grant permissions"
          hint="Only credential references and exact scopes ever enter marketplace state. Secrets are refused."
          owner="connector authority grant flow" />
        <p className="text-xs leading-5 text-slate-500">
          Connections can also be bound after the instance is running, from its detail page.
        </p>

        {/* Framed as reference, below the rung's actual state. As two equal
            cards above the slots it read as a picker — the shape of "choose
            one" — and pushed the one true fact of the step, that nothing can
            be bound here yet, off the first screen at 420px. */}
        <section className="rounded-xl border border-slate-300 bg-slate-100 p-5">
          <Eyebrow>Reference · how connecting works</Eyebrow>
          <p className="mt-2 max-w-[62ch] text-sm leading-6 text-slate-600">
            Two different things get called connecting an app, and only one of them lets a worker act inside
            it. This rung and the next are those two things, kept apart on purpose. Neither describes this
            listing.
          </p>

          {/* Each definition opens with its own rule rather than sharing a
              column divider. A vertical divider exists only in the two-column
              case — it left an orphaned line beside the shorter column, and
              below md it vanished entirely, so the section whose whole point is
              "these are two things, kept apart" stacked them 24px apart with
              nothing between.
              The rule spans the definition when stacked, where it has to divide
              two things in one column; side by side it shortens to a kicker,
              because two full-width rules at the same y read as one rule with a
              notch punched out of it — a spanning line arguing against the
              sentence above it. */}
          <div className="mt-5 grid gap-x-8 gap-y-6 md:grid-cols-2">
            {CONNECTION_KINDS.map((kind) => (
              <div key={kind.object} className="min-w-0">
                <span aria-hidden="true" className="mb-4 block h-px w-full bg-slate-300 md:w-10" />
                <h3 className="text-sm font-bold text-slate-900">{kind.title}</h3>
                <p className="mt-0.5 font-mono text-[11px] text-slate-500">{kind.object}</p>
                <p className="mt-2 text-xs leading-5 text-slate-600">{kind.blurb}</p>
                <p className="mt-3 text-[11px] font-bold uppercase tracking-[.12em] text-slate-500">Carries</p>
                <ul className="mt-1.5 space-y-1 text-xs leading-5 text-slate-600">
                  {kind.carries.map((line) => (
                    <li key={line} className="flex gap-2">
                      <span aria-hidden="true" className="mt-[7px] h-1 w-1 shrink-0 rounded-full bg-slate-400" />
                      <span>{line}</span>
                    </li>
                  ))}
                </ul>
                {kind.refuses && (
                  <>
                    <p className="mt-3 text-[11px] font-bold uppercase tracking-[.12em] text-slate-500">Never carries</p>
                    <TermList className="mt-1.5" items={kind.refuses} />
                  </>
                )}
                <p className="mt-3 text-[11px] leading-5 text-slate-500">{kind.note}</p>
              </div>
            ))}
          </div>

          {/* The rule belongs to the section, so it runs the section's width;
              only the measure is constrained. Hanging the border on the
              paragraph stopped it at 62ch, leaving three internal hairlines
              that shared a left edge and ended at two different right ones. */}
          <div className="mt-5 border-t border-slate-300 pt-4">
            <p className="max-w-[62ch] text-xs leading-5 text-slate-500">
              The same platform can be both. Slack receiving a weekly digest is a delivery channel; a worker
              that reads threads and opens incidents inside Slack is bound to that workspace as a work
              integration too, with its own scopes, policy posture, and receipts.
            </p>
          </div>

          <div className="mt-4">
            <Drawer title="Integration classes and their default posture" hint="canon taxonomy">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="text-[10px] font-bold uppercase tracking-[.12em] text-slate-500">
                    <th scope="col" className="pb-2 pr-3 font-bold">Class</th>
                    <th scope="col" className="pb-2 pr-3 font-bold">Examples</th>
                    <th scope="col" className="pb-2 font-bold">Default posture</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {INTEGRATION_CLASSES.map(([surface, examples, posture]) => (
                    <tr key={surface} className="align-top">
                      <td className="py-2 pr-3 font-mono text-[11px] text-slate-700">{surface}</td>
                      <td className="py-2 pr-3 leading-5 text-slate-500">{examples}</td>
                      <td className="py-2 leading-5 text-slate-600">{posture}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Drawer>
          </div>
        </section>
      </>
    ),
    delivery: (
      <>
        <p className="max-w-[62ch] text-sm leading-6 text-slate-600">
          Where this worker reports back, and how much it is allowed to say there. Binding a channel here
          reaches you; it never reaches into that workspace — that is the previous rung.
        </p>

        <InertPanel
          label="Channel"
          marker="Not selectable yet"
          owner="delivery channel owner"
          hint="One binding per destination. Each carries its own redaction policy, quiet-hours policy, and a delivery receipt."
        >
          <TermList className="mt-3" items={DELIVERY_CHANNEL_KINDS} />
          <div className="mt-3 border-t border-slate-100 pt-3">
            <p className="max-w-[62ch] text-[11px] leading-5 text-slate-500">
              Every one of these defaults to notification and delivery only. SMS and voice cannot hold durable
              authority or secrets under any posture, and neither is ever authentication by itself.
            </p>
          </div>
        </InertPanel>

        <InertPanel
          label="Posture"
          marker="Not selectable yet"
          owner="channel posture owner"
          hint="How far the binding goes — from a one-way notice to a callback a workflow can drive."
        >
          <TermList className="mt-3" items={DELIVERY_POSTURES} />
          <div className="mt-3 border-t border-slate-100 pt-3">
            <p className="max-w-[62ch] text-[11px] leading-5 text-slate-500">
              A notification-only channel may receive redacted summaries, delivery artifacts, status, and
              approval deep links. It must not carry secrets, durable authority grants, protected plaintext,
              or high-risk approvals itself.
            </p>
          </div>
        </InertPanel>

        {/* Canon's ladder puts "standing orders, schedules, escalation, quiet
            hours, and approvals" on the rung after this one. A "Report cadence"
            control here was that rung's work, stated twice under two owners. */}
        <p className="text-xs leading-5 text-slate-500">
          How often it reports, when it must stay silent, and who it wakes when something cannot wait are the
          next rung.
        </p>
      </>
    ),
    orders: (
      <>
        <p className="max-w-[62ch] text-sm leading-6 text-slate-600">
          None of this can be set here yet. What it can tell you now is what each of these will cost to
          change once the worker is running — which is not the same for all of them.
        </p>

        {ORDER_SETTINGS.map((setting) => {
          const tier = setting.tierItem && CHANGE_TIERS.find((entry) => entry.items.includes(setting.tierItem));
          return (
            <InertPanel key={setting.title} label={setting.title} owner={setting.owner} hint={setting.blurb}>
              {tier ? (
                <div className="mt-3 border-t border-slate-100 pt-3">
                  <p className="flex items-baseline gap-2 text-xs font-semibold text-slate-700">
                    <span aria-hidden="true" className={cx('h-1.5 w-1.5 shrink-0 rounded-full', TIER_DOT[tier.tone])} />
                    Changing it later: {tier.title.toLowerCase()}
                  </p>
                  <p className="mt-1 max-w-[62ch] text-[11px] leading-5 text-slate-500">{tier.requires}</p>
                </div>
              ) : (
                <div className="mt-3 border-t border-slate-100 pt-3">
                  <p className="max-w-[62ch] text-[11px] leading-5 text-slate-500">{setting.note}</p>
                </div>
              )}
            </InertPanel>
          );
        })}

        <p className="text-xs leading-5 text-slate-500">
          The same three tiers govern every later edit, and a deployment shows them on its own page.
        </p>
      </>
    ),
    review: (
      <>
        <Panel>
          <p className="text-sm font-bold text-slate-900">Starting this run creates four separate records</p>
          <ol className="mt-3 space-y-2 text-sm text-slate-600">
            {[['Quote', 'priced against this listing, expires in 15 minutes'],
              ['Entitlement', 'your right to run this release'],
              ['Install', 'the package placed for execution'],
              ['Runtime assignment', 'the node the runtime owner admits']].map(([label, blurb], index) => (
              <li key={label} className="flex gap-3">
                <span className="mt-0.5 grid h-5 w-5 shrink-0 place-items-center rounded-full bg-slate-100 text-[10px] font-bold text-slate-600">
                  {index + 1}
                </span>
                <span><strong className="font-semibold text-slate-800">{label}</strong> — {blurb}</span>
              </li>
            ))}
          </ol>
          <p className="mt-3 border-t border-slate-100 pt-3 text-xs leading-5 text-slate-500">
            Each is admitted by an owner this surface does not control. Any missing owner fails closed
            before you are charged.
          </p>
        </Panel>
        <div>
          <Eyebrow>Sent with this request</Eyebrow>
          <div className="mt-2">
            <DefList rows={[
              ['Worker', item?.name, { mono: false }],
              ['Price', `${formatAmount(item?.pricing)} ${formatCadence(item?.pricing) || ''}`, { mono: false }],
              ['Runtime profile', form.runtime_profile_ref],
              ['Persistence profile', form.persistence_profile_ref],
            ]} />
          </div>
        </div>

        {/* The review must account for the whole ladder, not only the rungs
            that happen to be wired — otherwise the flow implies control the
            buyer does not have. */}
        <div>
          <Eyebrow>Not sent with this request</Eyebrow>
          <ul className="mt-2 divide-y divide-slate-200 border-y border-slate-200">
            {HIRE_STEPS.filter((entry) => entry.pending).map((entry) => (
              <li key={entry.key} className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1 py-2.5">
                <span className="text-sm font-semibold text-slate-700">{entry.title}</span>
                <Gap label="Awaiting" owner={entry.owner} />
              </li>
            ))}
          </ul>
          <p className="mt-2 text-xs leading-5 text-slate-500">
            These carry no value into the hire request. Whatever the runtime owner applies by default governs
            until an owner exists for each.
          </p>
        </div>
        <ErrorNotice error={error} />
      </>
    ),
  };

  const key = HIRE_STEPS[step].key;
  const last = step === HIRE_STEPS.length - 1;

  return (
    <main className="mx-auto max-w-[1100px] px-4 py-10">
      <Link className="inline-flex min-h-11 items-center py-2 text-sm font-medium text-blue-700 hover:underline" to={`/agents/${workerId}`}>
        ← {item?.name}
      </Link>

      <div className="mt-5 flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="text-xs font-bold uppercase tracking-[.18em] text-blue-700">Set up a managed run</p>
          <h1 className="mt-2 text-3xl font-black tracking-tight text-slate-950">{item?.name}</h1>
        </div>
        <p className="text-right">
          <span className="block text-2xl font-black text-slate-950">{formatAmount(item?.pricing)}</span>
          <span className="text-sm font-medium text-slate-500">{formatCadence(item?.pricing)}</span>
        </p>
      </div>

      <div className="mt-8 grid gap-8 md:grid-cols-[240px_minmax(0,1fr)]">
        <div className="md:sticky md:top-40 md:self-start">
          <Stepper steps={HIRE_STEPS} current={step} onSelect={setStep} />
        </div>

        <section className="min-w-0">
          <h2 className="text-lg font-bold text-slate-900">{HIRE_STEPS[step].title}</h2>
          <div className="mt-4 space-y-4">{panels[key]}</div>

          <div className="mt-8 flex flex-wrap items-center justify-between gap-3 border-t border-slate-200 pt-5">
            <Button variant="secondary" disabled={step === 0} onClick={() => setStep((index) => index - 1)}>
              Back
            </Button>
            <div className="flex items-center gap-4">
              {/* Four of the six rungs collect nothing yet. Showing the whole
                  ladder is right; charging four clicks to walk past it is not. */}
              {!last && HIRE_STEPS.slice(step + 1, -1).every((entry) => entry.pending) && (
                <button
                  type="button"
                  onClick={() => setStep(HIRE_STEPS.length - 1)}
                  className="inline-flex min-h-11 items-center py-2 text-sm font-semibold text-blue-700 hover:underline"
                >
                  Skip to review
                </button>
              )}
              {last ? (
                <Button onClick={start} disabled={busy}>
                  {busy ? 'Admitting owners…' : 'Start managed run'}
                </Button>
              ) : (
                <Button onClick={() => setStep((index) => index + 1)}>Continue</Button>
              )}
            </div>
          </div>
        </section>
      </div>
    </main>
  );
}

/* ── categories ─────────────────────────────────────────────────────── */

// What a category record must define before anything can be admitted to it,
// verbatim from worker-marketplace.md, "Sparse Worker Categories".
const CATEGORY_RECORD = [
  'task class', 'input/output schemas', 'benchmark suite', 'evaluation rubric',
  'runtime requirements', 'policy requirements', 'trust posture', 'receipt obligations',
  'submission fee or stake', 'routing eligibility criteria',
];

// Distinct publishing principals in a set of listings. Used twice on the
// landing page — as a figure and as the trigger for the first-party disclosure
// — so the two can never disagree about how concentration is measured.
const countPublishers = (items) =>
  new Set((items || []).map((item) => item.seller_ref).filter(Boolean)).size;

function CategoryHome() {
  const workers = useLoad(() => api('/v1/marketplace/workers'), []);
  const receipts = useLoad(() => api('/v1/receipts'), []);
  // The chain's validity is computed by the store and reported on /v1/status.
  // This page had been deriving it from the receipts list instead — "verified"
  // whenever any receipts loaded — which is a trust claim, rendered in green on
  // the front page, inferred from the fact that a list arrived. /v1/receipts
  // returns `{ items }` and nothing else; it cannot support that claim. The
  // header's ticker has always read the owner that can.
  const status = useLoad(() => api('/v1/status'), []);
  const items = workers.value?.items || [];
  const publishers = countPublishers(items);
  // Whether the catalogue's size is known at all. A count that is not yet read
  // is not zero, and a count that could not be read is not a count.
  const counted = !workers.loading && !workers.error;

  const recent = [...items]
    .sort((a, b) => String(b.published_at || '').localeCompare(String(a.published_at || '')))
    .slice(0, 3);
  return (
    <main className="mx-auto max-w-[1536px] px-4 py-10">
      {/* The lander's hero, in this site's own light idiom — the dark slab the
          reference prototypes carried was their skin, not ours. The copy claims
          nothing the store cannot prove: the pill and the band below are the
          store's own reads, and the figure is the estate's cyborg
          (CyborgHero.jsx) in the rig's light-ground palette. The prototype's
          "escrow protects every dollar" pitch stays refused — this surface does
          not own monetary movement. */}
      <section className="grid gap-8 md:grid-cols-[minmax(0,1fr)_minmax(300px,420px)] md:items-center">
        <div className="min-w-0">
          <p className="text-xs font-bold uppercase tracking-[.18em] text-blue-700">Hire an agent</p>
          <h1 className="mt-2 text-4xl font-black tracking-tight text-slate-950 md:text-5xl md:leading-[1.05]">
            Work you can hand off,
            <span className="block text-teal-600">permanently.</span>
          </h1>
          <p className="mt-4 max-w-xl text-base leading-7 text-slate-600">
            Not a coding copilot. These are agents that hold a job — billing runs on Tuesdays, the diligence
            report lands every Monday, the position is watched while you sleep — under parameters you set and
            can change afterwards.
          </p>
          <p className="mt-3 text-xs text-slate-500">Benchmark-admitted · Explicitly published · Receipted admission</p>
          <div className="mt-6 flex flex-wrap items-center gap-3">
            <Link to="/agents" className={buttonStyles.primary}>Browse agents →</Link>
            <Link to="/builder" className={buttonStyles.secondary}>Publish a worker</Link>
            <Link to="/my-workers/add" className="text-sm font-medium text-blue-700 hover:underline">
              Add your agent →
            </Link>
          </div>
        </div>
        {/* hidden below md: the figure is presence, not information, and a
            phone gives it neither the width nor the bandwidth. */}
        <Suspense fallback={null}>
          <CyborgHero className="relative hidden min-h-[400px] md:block [mask-image:linear-gradient(to_bottom,black_82%,transparent)]" />
        </Suspense>
      </section>

      <div className="mt-8 border-y border-slate-200 py-5">
        <StatRow items={[
          { label: 'Admitted agents', from: workers, select: (v) => v.items.length },
          {
            label: 'Publishers',
            from: workers,
            select: (v) => countPublishers(v.items),
            title: 'Distinct principals that published this supply. A single publisher means this is a first-party fleet, not independent network supply.',
          },
          { label: 'Receipts', from: receipts, select: (v) => v.items?.length },
          {
            label: 'Receipt chain',
            from: status,
            // A falsy default is not a finding. Reading the key with `?` and
            // falling through to 'BROKEN' alleges a hash-chain break — in red —
            // whenever the key is simply absent from an otherwise successful
            // response. Only a reported `false` is BROKEN; anything that is not
            // a boolean is not a verdict, and returning undefined says so.
            select: (v) => (typeof v.receipt_chain_valid === 'boolean'
              ? (v.receipt_chain_valid ? 'verified' : 'BROKEN')
              : undefined),
            tone: (v) => (v === 'verified' ? 'good' : 'bad'),
            title: 'Every receipt hash-links to its predecessor. The store verifies the whole chain on read and reports the result; this is that result, not an inference from receipts being present.',
          },
        ]} />
      </div>

      <p className="mt-6">
        <Gap label="Category admission" owner="sparse worker category record" />
      </p>

      {/* Canon's anti-pattern list forbids "a first-party seed fleet presented as
          independent network supply". Concentration is a fact this store can
          count, so it is counted rather than left for a buyer to notice — but
          only once the count is actually known, or the disclosure is itself a
          claim about a catalogue nobody has read. */}
      {counted && publishers === 1 && (
        <p className="mt-3 text-xs leading-5 text-slate-500">
          All supply here is published by a single principal. This is a first-party fleet, not independent
          network supply, and nothing about admission implies otherwise.
        </p>
      )}

      <div className="mt-8 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {CATEGORIES.map(([to, label, blurb]) => (
          <Card as={Link} to={to} key={to} className="group h-full p-5">
            <h2 className="font-bold text-slate-900 group-hover:text-blue-700">{label}</h2>
            <p className="mt-2 flex-1 text-sm leading-6 text-slate-600">{blurb}</p>
          </Card>
        ))}
        {/* Not a <Card>: its base classes hardcode bg-white, which collides with
            a dark tone and leaves white text on a white ground. */}
        <Link
          to="/agents"
          className="flex h-full flex-col justify-center rounded-xl border border-slate-950 bg-slate-950 p-5 text-white transition hover:bg-slate-800"
        >
          <h2 className="font-bold">All admitted agents</h2>
          <p className="mt-2 text-sm leading-6 text-white/70">
            Every worker that has cleared benchmark admission and explicit publication.
          </p>
          {counted ? (
            <p className="mt-4 text-2xl font-black">{items.length}</p>
          ) : workers.error ? (
            <p className="mt-4 text-sm font-bold text-amber-200">not reported</p>
          ) : (
            <span role="status" aria-label="Reading the catalogue size"
                  className="mt-4 block h-7 w-16 animate-pulse rounded bg-white/25" />
          )}
        </Link>
      </div>

      {/* A marketplace homepage that shows no merchandise is a menu. These are
          the most recently published, which is a fact rather than an editorial
          pick — canon's anti-patterns forbid a surface that can privilege
          supply by fiat. */}
      <div className="mt-12 flex flex-wrap items-baseline justify-between gap-3">
        <SubHeading>Recently admitted</SubHeading>
        <Link className="text-sm font-medium text-blue-700 hover:underline" to="/agents">
          Browse all{counted ? ` ${items.length}` : ''} →
        </Link>
      </div>
      {workers.loading ? (
        <Skeleton count={3} className="mt-4 grid gap-5 sm:grid-cols-2 lg:grid-cols-3" />
      ) : workers.error ? (
        <div className="mt-4"><Unreadable error={workers.error} subject="Admitted supply" onRetry={workers.reload} /></div>
      ) : recent.length ? (
        <div className="mt-4 grid gap-5 sm:grid-cols-2 lg:grid-cols-3">
          {recent.map((worker) => <WorkerCard key={worker.worker_id} worker={worker} />)}
        </div>
      ) : (
        <div className="mt-4">
          <Empty title="No admitted supply yet." action={<Link className={buttonStyles.primary} to="/builder">Open Builder</Link>}>
            Publication is explicit. A worker reaches this page only after benchmark admission and an
            explicit decision to publish.
          </Empty>
        </div>
      )}
    </main>
  );
}

function CategoryPage({ slug }) {
  const [, label, blurb] = CATEGORIES.find(([route]) => route === slug) || [];
  const workers = useLoad(() => api('/v1/marketplace/workers'), []);
  const items = workers.value?.items || [];

  return (
    <main className="mx-auto max-w-[1536px] px-4 py-10">
      <SectionHead eyebrow="Category" title={`${label}.`} lede={blurb} />

      {/* A storefront leads with supply. The category caveat is load-bearing and
          stays above the grid, but as one line plus a drawer rather than a
          five-line block that pushes every listing below the fold. */}
      <div className="mt-7 flex flex-wrap items-center justify-between gap-x-6 gap-y-2 border-y border-slate-200 py-3">
        <p className="flex items-center gap-2 text-sm text-slate-600">
          <Gap label="Category admission" owner="sparse worker category record" />
        </p>
        <p className="flex items-center gap-3 text-xs text-slate-500">
          <Gap label="Track record" owner="outcome telemetry owner" />
        </p>
        {/* Every tab in the category row narrows. Removing `All agents` from
            that row took away the only labelled control that widens, so each
            category carries the way back itself. */}
        <span className="flex items-center gap-3 text-xs text-slate-500">
          {workers.loading ? 'Loading…'
            : workers.error ? 'supply unreadable'
            : `${items.length} agent${items.length === 1 ? '' : 's'}`}
          <Link className="font-medium text-blue-700 hover:underline" to="/agents">All workers →</Link>
        </span>
      </div>

      {/* The grid's name was sr-only and the sentence saying it is unfiltered was
          `hidden sm:inline` — so under a heading reading "Gaming." a sighted
          reader saw seven cards and no caveat at all, and a phone reader saw no
          caveat at any width. The one thing this page must not do is let a grid
          of everything read as a category's supply. It is named where it is
          read, at every width. */}
      {/* Stacked, not justified apart: at 1600px the caveat sat about 1,200px
          to the right of the label it qualifies, on the same baseline and in
          the smallest type in the content area — the standard position for a
          filter-status readout rather than for the one sentence that stops this
          grid being read as the category's supply. It sits under its label, on
          the path from the label into the first card.
          One vocabulary, too: the strip above names the missing record as a
          sparse worker category record, and this said "category record", which
          read as two gaps rather than one. */}
      <div className="mt-8">
        <SubHeading>All admitted supply</SubHeading>
        {/* The same weight as the label above it. Spending the page's strongest
            type on the claim and its faintest on the retraction is the claim
            winning: a reader who skims headings saw a bold assertion of admitted
            supply and a grey footnote. */}
        <p className="mt-1 max-w-[70ch] text-sm leading-6 text-slate-700">
          Not filtered by {label} — no sparse worker category record exists to filter by.
        </p>
      </div>
      {workers.loading ? (
        <Skeleton count={3} className="mt-4 grid gap-5 sm:grid-cols-2 lg:grid-cols-3" />
      ) : workers.error ? (
        <div className="mt-4"><Unreadable error={workers.error} subject="Admitted supply" onRetry={workers.reload} /></div>
      ) : items.length ? (
        <div className="mt-4 grid gap-5 sm:grid-cols-2 lg:grid-cols-3">
          {items.map((worker) => <WorkerCard key={worker.worker_id} worker={worker} />)}
        </div>
      ) : (
        <div className="mt-4"><Empty title="No admitted supply yet." /></div>
      )}

      <div className="mt-10 max-w-[80ch]">
        <Drawer title={`How a worker joins ${label}`} hint="category admission">
          <p className="text-sm leading-6 text-slate-600">
            A worker enters a category by being benchmarked against that category&rsquo;s suite — membership is
            earned, not declared, and admission to a category is still not the same as routing eligibility.
            Canon requires a category record to define:
          </p>
          <TermList className="mt-3" items={CATEGORY_RECORD} />
          <p className="mt-3 text-sm leading-6 text-slate-600">
            No record is registered for this category yet, so nothing above has been admitted to it.
          </p>
        </Drawer>
      </div>
    </main>
  );
}

// Canon, "Managed Instance Dashboard And Change Lifecycle", shapes post-hire
// edits by risk. The three tiers and their contents are verbatim; what differs
// between them is not the control but what the change must clear before it
// applies. Showing the tier before the edit is the point — a buyer should know
// that adding a connector is not the same kind of act as changing quiet hours.
const CHANGE_TIERS = [
  {
    key: 'safe',
    title: 'Applies to the running instance',
    tone: 'emerald',
    requires: 'Recorded as a new config revision. No plan, no dry run.',
    items: ['delivery cadence', 'quiet hours', 'notification-only channels',
            'supported model route selection', 'budget caps',
            'memory-retention posture within policy'],
    owner: 'config revision endpoint',
  },
  {
    key: 'canary',
    title: 'Needs a dry run or canary first',
    tone: 'amber',
    requires: 'Needs a change plan, and must clear compatibility, authority, privacy, budget, benchmark and runtime gates before the daemon applies it.',
    items: ['connector binding', 'work integration', 'standing order', 'schedule',
            'tool binding', 'route policy', 'HarnessProfile', 'runtime assignment',
            'memory projection target'],
    owner: 'change plan owner',
  },
  {
    key: 'revision',
    title: 'Needs explicit review and a rollback target',
    tone: 'red',
    requires: 'A new composition version. Auto-update is not available for these, and the benchmark that admitted the old composition does not carry over.',
    items: ['new action class', 'new core ability', 'broader authority class',
            'changed safety envelope', 'new benchmark claim', 'changed package behaviour'],
    owner: 'package revision review owner',
  },
];

// Canon, worker-marketplace.md, "Managed Worker Onboarding Plans": "A managed
// instance may run only in the readiness mode admitted by its completed plan.
// Optional integrations may unlock broader capability later, but missing
// required connectors, authority grants, runtime assignments, or safety gates
// must block activation or force a clearly labeled degraded mode."
//
// The console never mentioned it. What it showed was `readiness`, which is the
// runtime's own word about its last check — not the mode the plan admits, and
// not from the same vocabulary. Two different facts under one name.
const READINESS_MODES = ['full', 'degraded', 'notification only', 'dry run only', 'blocked'];

// The plan those modes come out of. Compiled from the seller's manifest and the
// buyer's environment, per canon — "not hardcoded as a bespoke wizard per
// worker" — so its shape is a vocabulary rather than a screen.
const PLAN_STEP_KINDS = [
  'connector binding', 'authority grant', 'contact channel binding', 'runtime selection',
  'model route selection', 'harness selection', 'schedule or standing order',
  'notification policy', 'dry run', 'policy acceptance', 'admin review',
];
const PLAN_AXES = [
  ['Requirement', ['required', 'optional', 'recommended', 'degraded mode']],
  ['Fulfillment', ['automatic', 'assisted', 'manual', 'approval required', 'admin required']],
  ['Status', ['missing', 'ready', 'completed', 'blocked', 'unsupported', 'skipped']],
];

// Canon, worker-marketplace.md: "Payment lapse, provider exit, archive,
// restore, export, delete, and forget states are first-class lifecycle
// transitions; they cannot be hidden behind generic billing or console state."
// And managed-worker-instance-lifecycle.md: "Delete/forget semantics
// distinguish billing deletion, archive deletion, and policy-governed memory
// erasure."
//
// Three different deletions, and a console that offers one button called Delete
// has collapsed them. What each act does NOT do is the load-bearing half — it is
// the reason they are separate acts.
const ENDINGS = [
  {
    key: 'suspend',
    title: 'Suspend',
    does: 'Freezes work. The instance, its configuration and its memory all remain.',
    doesNot: 'Does not end the subscription, and does not revoke a credential grant.',
    live: true,
  },
  {
    key: 'archive',
    title: 'Archive',
    does: 'Stores the encrypted payload through artifact, memory-archive and storage-backend refs. Restorable.',
    doesNot: 'Does not delete those bytes, and is not a memory erasure.',
    live: true,
  },
  {
    key: 'export',
    title: 'Export',
    does: 'Produces a portable copy and an export receipt, through the authority gate that admits it.',
    doesNot: 'Does not remove anything. Portable delegated authority or decryption makes this a wallet-gated act.',
    owner: 'memory export receipt owner',
  },
  {
    key: 'delete_billing',
    title: 'Delete — billing',
    does: 'Ends the subscription and the entitlement to run this release.',
    doesNot: 'Does not delete the archive and does not erase memory. Prior receipts stand.',
    owner: 'subscription termination endpoint',
  },
  {
    key: 'delete_archive',
    title: 'Delete — archive',
    does: 'Removes the archived payload bytes held by the storage backend.',
    doesNot: 'Does not erase policy-governed memory, and does not undo a settled charge.',
    owner: 'archive deletion endpoint',
  },
  {
    key: 'forget',
    title: 'Forget',
    does: 'Policy-governed erasure of semantic memory, subject to legal holds, audit retention and dispute requirements.',
    doesNot: 'Is a marketplace act with a marketplace receipt. It is not proof that a model provider deleted anything.',
    owner: 'memory erasure owner',
  },
];

const TIER_RING = {
  emerald: 'border-emerald-200 bg-emerald-50/40',
  amber: 'border-amber-200 bg-amber-50/40',
  red: 'border-red-200 bg-red-50/40',
};

// The same three tones as a single mark, for referring to a tier away from the
// lifecycle block itself — one tone per tier across both surfaces.
const TIER_DOT = {
  emerald: 'bg-emerald-500',
  amber: 'bg-amber-500',
  red: 'bg-red-500',
};

function ChangeLifecycle({ revision }) {
  return (
    <section>
      <div className="flex flex-wrap items-baseline justify-between gap-3">
        <SubHeading>Changing this deployment</SubHeading>
        <Chip>config revision r{revision ?? '—'}</Chip>
      </div>
      <p className="mt-1.5 max-w-[70ch] text-sm leading-6 text-slate-600">
        A persistent worker stays customisable after hire. What an edit costs depends on what it changes:
        some settings apply to the running instance, some must be proved on a canary first, and some are a
        new composition that has to be reviewed and can be rolled back.
      </p>

      <div className="mt-4 space-y-3">
        {CHANGE_TIERS.map((tier) => (
          <div key={tier.key} className={cx('rounded-xl border p-4', TIER_RING[tier.tone])}>
            <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
              <h3 className="text-sm font-bold text-slate-900">{tier.title}</h3>
              <Gap label="Not editable here" owner={tier.owner} />
            </div>
            <TermList className="mt-2.5" items={tier.items} />
            <p className="mt-2.5 text-xs leading-5 text-slate-600">{tier.requires}</p>
          </div>
        ))}
      </div>

      <p className="mt-3 font-mono text-[11px] leading-5 text-slate-500">
        edit → config revision → change plan when risk requires → gates → dry run or canary →
        daemon applies, rejects, or rolls back → receipts → console refreshes
      </p>
    </section>
  );
}

/* ── the Agent Map panel ────────────────────────────────────────────── */

// Canon declares this panel and its feed table, and requires the aiagent.xyz
// managed console to project it (core-clients-surfaces.md, "The Agent Map Panel
// (projection-only)"):
//
//   live presence         subject attachments
//   delegation edges      thread-fork lineage (ADR 0034)
//   what may be touched   authority scopes
//   what was touched      effect admissions and receipts
//   where work runs       placement / runtime assignments
//   what changed          Agentgres heads
//   what is waiting       the approval queue
//   what was refused      typed refusals
//
// Four of those eight have an owner reachable from this surface. The other four
// do not, and the panel says which is which rather than drawing a graph that
// implies it knows more than it does.
//
// The binding rule is canon's, and it is why there is no avatar on this map:
//   "presence renders ONLY from a live subject attachment"
//   "a quiet node never implies a finished agent — silence is not success"
//   "map states grant nothing"
//
// A receipt is not an effect. Every action this domain mints against an
// instance is a lifecycle or authority event — hired, bound, tested, suspend
// requested. None of them is an effect admission, so the allowlist below is
// empty on purpose: "what was touched" reads zero because zero is the truth,
// and a receipt count in that row would have said the worker had acted.
// An effect action added to the domain later and not added here counts as
// nothing rather than as an effect, which is the safe direction to be wrong in.
const EFFECT_ADMISSION_ACTIONS = [];

const MAP_FEED = [
  ['Live presence', 'subject attachments', null, 'live subject attachment owner'],
  ['Delegation edges', 'thread-fork lineage', null, 'thread-fork lineage projection'],
  ['What may be touched', 'authority scopes', (i) =>
    `${i.integrations?.reduce((n, b) => n + (b.scope_refs?.length || 0), 0) || 0} scopes over ${i.integrations?.length || 0} surfaces`],
  // Returns nothing at all when the chain did not resolve, so the row renders
  // the read's state in the read's own treatment rather than a state word set in
  // the mono column that carries r1 and the runtime assignment ref.
  ['What was touched', 'effect admissions', (i, c) => (c.status === 'read'
    ? `${c.effects} admitted · ${c.receipts} lifecycle receipt${c.receipts === 1 ? '' : 's'}`
    : null)],
  ['Where work runs', 'placement / runtime assignment', (i) => shortRef(i.runtime_assignment_ref, 24)],
  ['What changed', 'config revision', (i) => `r${i.config_revision}`],
  ['What is waiting', 'the approval queue', null, 'approval queue owner'],
  ['What was refused', 'typed refusals', null, 'typed refusal record owner'],
];

// `receipts` is the read, not its items: the map has to say which of the four
// states it is in, and an array cannot carry that. It arrived here as
// `receipts.value?.items || []`, so a read still in flight drew a node labelled
// "0 receipts" and a feed row reading "0 admitted · 0 lifecycle receipts" — a
// deployment reported as having done nothing, on evidence that had not arrived.
// The steps the plan compiled, in the order it compiled them. Canon's step
// statuses are its own vocabulary and are shown in it — `State` maps all six —
// rather than remapped into words this surface preferred.
//
// The requirement level is the load-bearing column: `required` and *absent* are
// different facts, and a list that showed only the ones with a level would hide
// exactly the steps whose consequence nobody has declared.
function OnboardingSteps({ plan }) {
  const subject = (step) => step.integration_surface_ref
    || (step.authority_requirement_refs || [])[0]
    || shortRef(step.runtime_assignment_ref, 20)
    || null;
  return (
    <div className="mt-4">
      <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
        <Eyebrow>Steps this plan compiled</Eyebrow>
        {plan.value?.compiled ? (
          <span className="text-[11px] font-medium text-slate-500">
            {plan.value.steps.filter((step) => step.status === 'completed').length} of {plan.value.steps.length} completed
          </span>
        ) : null}
      </div>
      {plan.loading || plan.error || plan.value?.compiled === false ? (
        <div className="mt-2 border-l-[3px] border-slate-400 bg-slate-50 px-4 py-4">
          <ReadState
            size="panel"
            status={plan.loading ? 'reading' : plan.error ? 'unreadable' : 'not_reported'}
            label={plan.loading ? 'Compiling this deployment\u2019s onboarding plan…'
              : plan.error ? 'The onboarding plan could not be read. This says nothing about which steps remain.'
              : 'The admitted composition behind this deployment could not be reached, so no plan was compiled.'}
          />
        </div>
      ) : (
        <ul className="mt-2 divide-y divide-slate-200 border-y border-slate-200">
          {plan.value.steps.map((step) => (
            <li key={step.step_ref} className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1 py-2.5">
              <span className="min-w-0 text-sm text-slate-700">
                <strong className="font-semibold text-slate-900">{step.kind.replace(/_/g, ' ')}</strong>
                {subject(step) && <span className="ml-2 font-mono text-xs text-slate-600">{subject(step)}</span>}
              </span>
              {/* The words stay in the row, and are set as an absence rather
                  than as a fourth level. A blind review took the em dash that
                  replaced them and read it as "not applicable": recovering its
                  meaning cost a jump to a footnote sixty pixels below, and an
                  operator who skipped that footnote mis-filed three rows as
                  non-blocking. Italic rather than a lighter grey — lighter is
                  where this surface's contrast floor was breached last time, and
                  an absence should not be the first thing to disappear. */}
              <span className="flex items-baseline gap-3">
                <span className={cx('text-[11px] font-medium text-slate-500', !step.requirement && 'italic')}
                      title={step.requirement_source ? `declared by ${step.requirement_source}` : 'no requirement level is declared for this step'}>
                  {step.requirement || 'level not declared'}
                </span>
                <State value={step.status} vocabulary="plan_step" />
              </span>
            </li>
          ))}
        </ul>
      )}
      {plan.value?.compiled ? (
        <p className="mt-2 max-w-[70ch] text-xs leading-5 text-slate-500">
          Compiled from the admitted composition and this deployment&rsquo;s own bindings, over
          {' '}{plan.value.compiled_step_kinds.length} of the {plan.value.compiled_step_kinds.length + Object.keys(plan.value.uncompiled_step_kinds).length} step
          kinds canon defines. The rest have no record in this domain and are named in the drawer below.
          {plan.value.steps.some((step) => !step.requirement) && (
            // The clause the standalone footnote existed for, kept where the
            // same review put it: a step with no declared level is counted
            // neither as blocking nor as optional, which the completed count
            // above does not say.
            <> A step whose level the package never declared is counted neither as blocking nor as optional.</>
          )}
        </p>
      ) : null}
    </div>
  );
}

function AgentMap({ instance, receipts }) {
  const surfaces = instance?.integrations || [];
  const chain = listState(receipts);
  const counts = chain.status === 'read'
    ? {
      status: 'read',
      receipts: chain.items.length,
      effects: chain.items.filter((receipt) => EFFECT_ADMISSION_ACTIONS.includes(receipt.action)).length,
    }
    : { status: chain.status };
  // Evenly spaced on the upper arc, so one binding sits at the top rather than
  // in a corner and three still read as a fan rather than a pile.
  const place = (index) => {
    const spread = Math.min(64, 150 / Math.max(surfaces.length, 1));
    const degrees = -90 + (index - (surfaces.length - 1) / 2) * spread;
    const radians = (degrees * Math.PI) / 180;
    // Inside the ring with clearance: a bound surface is within scope, and a
    // node touching the boundary would say the opposite of what it is.
    return { x: 260 + 145 * Math.cos(radians), y: 138 + 58 * Math.sin(radians) };
  };

  return (
    <section>
      <div className="flex flex-wrap items-baseline justify-between gap-3">
        <SubHeading>Agent map</SubHeading>
        <span className="text-[11px] text-slate-500">projection only — the map mints nothing and grants nothing</span>
      </div>
      <p className="mt-1.5 max-w-[70ch] text-sm leading-6 text-slate-600">
        What this deployment may touch, and what it has touched. The boundary is the authority scope edge:
        nothing outside it is reachable. There is no presence marker because presence renders only from a live
        subject attachment, and none is projected here.
      </p>

      <div className="mt-4 overflow-hidden rounded-xl border border-slate-200 bg-white">
        <svg
          viewBox="0 0 520 268"
          className="block h-auto w-full"
          role="img"
          aria-label={`Authority scope of this deployment: ${surfaces.length} bound integration surface${surfaces.length === 1 ? '' : 's'}, one runtime assignment, no presence marker.`}
        >
          <ellipse cx="260" cy="128" rx="214" ry="104" fill="none" stroke="#cbd5e1" strokeWidth="1.5" strokeDasharray="5 5" />
          <text x="260" y="258" textAnchor="middle" className="fill-slate-500" fontSize="10">
            outside the ring: out of scope — not reachable under any grant on this instance
          </text>
          <text x="30" y="24" className="fill-slate-500" fontSize="10">authority scope edge</text>

          {surfaces.map((binding, index) => {
            const { x, y } = place(index);
            const ready = binding.state === 'ready';
            return (
              <g key={binding.binding_id}>
                <title>{`${binding.integration_surface} — ${binding.state}. Scopes: ${(binding.scope_refs || []).join(', ') || 'none declared'}`}</title>
                <line
                  x1="260" y1="132" x2={x} y2={y}
                  stroke={ready ? '#94a3b8' : '#cbd5e1'} strokeWidth="1.5"
                  strokeDasharray={ready ? undefined : '4 4'}
                />
                <rect x={x - 66} y={y - 22} width="132" height="44" rx="8"
                      fill="#ffffff" stroke={ready ? '#94a3b8' : '#cbd5e1'} strokeWidth="1.5" />
                <text x={x} y={y - 3} textAnchor="middle" className="fill-slate-900" fontSize="12" fontWeight="700">
                  {binding.integration_surface}
                </text>
                <text x={x} y={y + 13} textAnchor="middle" className="fill-slate-500" fontSize="10">
                  {(binding.scope_refs?.length || 0)} scope{binding.scope_refs?.length === 1 ? '' : 's'} · {binding.state.replace(/_/g, ' ')}
                </text>
              </g>
            );
          })}

          {/* The runtime assignment is where this deployment runs, not something
              it reaches: as a separate node it needed an edge, and the only edge
              vocabulary on this map is "binding tested / bound untested". A
              solid line there would have reported a test nobody ran, on a
              deployment whose observed state is unknown. It belongs on the node.

              Wrapped in a <g>: a <title> directly under <svg> would name the
              whole graphic rather than this node. */}
          <g>
            <title>{`this deployment — runs at ${instance?.runtime_assignment_ref}`}</title>
            <rect x="146" y="122" width="228" height="66" rx="10" fill="#020617" />
            <text x="260" y="142" textAnchor="middle" className="fill-white" fontSize="12" fontWeight="700">
              this deployment
            </text>
            {/* These two sit on the near-black node, not on the page. Darkening
                them with the rest of the map — a sweep that matched a class name
                instead of looking at what was behind it — took them from 7.9:1
                to 4.2:1, under the floor, while fixing the two that really were
                washed out on white. On this ground the token has to go the other
                way. */}
            {/* SVG cannot host the ReadState glyph, so the distinction it
                carries is made in colour here: amber for a read that broke,
                slate for one still moving, against the white the counts use. */}
            <text x="260" y="158" textAnchor="middle" fontSize="10" className="fill-slate-300">
              config r{instance?.config_revision} ·{' '}
              {/* The tint starts at the half that is a state. Colouring the whole
                  line dressed `config r1` — a value that resolved perfectly
                  well — as part of the failure. */}
              <tspan className={counts.status === 'read' ? 'fill-slate-300'
                : counts.status === 'unreadable' ? 'fill-amber-300' : 'fill-slate-400'}>
                {counts.status === 'read'
                  ? `${counts.receipts} receipt${counts.receipts === 1 ? '' : 's'}`
                  : `receipts ${READ_LABELS[counts.status]}`}
              </tspan>
            </text>
            {/* 10, not 9: the map's labels are on the same body scale as the rest
                of the page, and SVG text is outside the reach of the contrast
                sweep, so it should not be the smallest thing on the surface. */}
            <text x="260" y="176" textAnchor="middle" className="fill-slate-300" fontSize="10">
              runs at {shortRef(instance?.runtime_assignment_ref, 24)}
            </text>
          </g>
        </svg>

        <div className="flex flex-wrap gap-x-5 gap-y-1 border-t border-slate-100 px-4 py-2.5 text-[11px] text-slate-500">
          <span>solid edge — binding tested</span>
          <span>dashed edge — bound, untested</span>
          <span>dashed ring — authority scope edge</span>
          <span>no marker — presence is not projected here</span>
        </div>
      </div>

      <div className="mt-4">
        <Eyebrow>What feeds this map</Eyebrow>
        <ul className="mt-2 divide-y divide-slate-200 border-y border-slate-200">
          {MAP_FEED.map(([label, source, read, owner]) => (
            <li key={label} className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1 py-2.5">
              <span className="text-sm text-slate-700">
                <strong className="font-semibold text-slate-900">{label}</strong>
                <span className="ml-2 text-xs text-slate-500">{source}</span>
              </span>
              {!read ? <Gap label="Not projected" owner={owner} />
                : read(instance || {}, counts) !== null
                  ? <span className="font-mono text-[11px] text-slate-600">{read(instance || {}, counts)}</span>
                  : <ReadState status={counts.status} />}
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}

/* ── console shell ──────────────────────────────────────────────────── */

function ConsoleLayout({ children }) {
  const instances = useLoad(() => api('/v1/marketplace/instances'), []);
  const running = instances.value?.items?.length;
  return (
    <div className="mx-auto flex max-w-[1536px] gap-8 px-4 py-8">
      <aside className="hidden w-56 shrink-0 lg:block">
        <div className="sticky top-44">
          {/* Akash puts the create action above the rail, not inside it. */}
          <Link className={cx(buttonStyles.primary, 'w-full')} to="/agents">Run a worker</Link>

          <nav className="mt-5 space-y-0.5">
            {CONSOLE_RAIL.map(([to, label]) => (
              <NavLink
                key={to}
                to={to}
                end={to === '/console'}
                className={({ isActive }) => cx(
                  'flex items-center justify-between rounded-lg px-3 py-2 text-sm font-medium transition',
                  isActive ? 'bg-slate-950 text-white' : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900',
                )}
              >
                {label}
                {to === '/instances' && running > 0 && (
                  <span className="rounded bg-white/15 px-1.5 py-0.5 text-[10px] font-bold">{running}</span>
                )}
              </NavLink>
            ))}
          </nav>

          <div className="mt-6 border-t border-slate-200 pt-4">
            <p className="text-[11px] font-bold uppercase tracking-[.12em] text-slate-500">Infrastructure</p>
            <div className="mt-2.5 space-y-2">
              <Gap wrap label="Runtime nodes and placement" owner="provider inventory projection" />
              <Gap wrap label="Spend and budget caps" owner="settlement usage owner" />
            </div>
          </div>
        </div>
      </aside>

      <div className="min-w-0 flex-1">{children}</div>
    </div>
  );
}

// A deployment's projection carries `worker_id` but not the listing's name, so
// every row in the console was titled by a UUID and nothing on the page said
// which worker any of them runs. The listing set is a read this client already
// makes on four other surfaces; joining it here is read truth, not a value this
// surface invents. A deployment whose listing does not resolve — delisted,
// revoked, or never public — keeps its id rather than borrowing a name.
//
// Four states, and each has to look like itself. In flight, nothing is known.
// Resolved-and-absent means this worker has no public listing — delisted,
// revoked, or never published — which is a fact about the worker. A failed read
// is a fact about the catalogue and about nothing else: treating it as absence
// would make every card on the page assert "no public listing" on the strength
// of a 500, which is exactly the confident false claim this surface exists to
// prevent. And resolved-and-present is the ordinary case.
function useWorkerNames() {
  const workers = useLoad(() => api('/v1/marketplace/workers'), []);
  const names = useMemo(
    () => new Map((workers.value?.items || []).map((worker) => [worker.worker_id, worker.name])),
    [workers.value],
  );
  return { names, resolving: workers.loading, failed: Boolean(workers.error) };
}

// What a deployment card knows about the worker it runs. Returns the title and,
// where the title is not a name, the reason it is not — so the two callers
// cannot drift into disagreeing about what an id in the title slot means.
function deploymentIdentity({ instance, names, resolving, failed }) {
  if (resolving) return { kind: 'resolving' };
  if (failed) return { kind: 'unreadable' };
  const name = names.get(instance.worker_id);
  return name ? { kind: 'named', name } : { kind: 'unlisted' };
}

function DeploymentTitle({ identity, instance, className }) {
  if (identity.kind === 'resolving') {
    return (
      <span
        role="status"
        aria-label="Resolving which worker this deployment runs"
        className={cx('block h-4 w-40 max-w-full animate-pulse rounded bg-slate-200', className)}
      />
    );
  }
  if (identity.kind === 'named') return <span className={cx('block truncate', className)}>{identity.name}</span>;
  // No name to show, so the id carries the title rather than being repeated
  // under it — a card that printed the same 36-character string twice, once
  // bold and once muted, spent its strongest slot restating its weakest.
  return (
    <span className={cx('block truncate font-mono text-sm', className)} title={instance.worker_instance_id}>
      {instance.worker_instance_id}
    </span>
  );
}

// Why the title is an id. Absence names the owner that would supply the value;
// an unreadable catalogue says so instead, because it is not evidence of absence.
function DeploymentIdentityNote({ identity }) {
  if (identity.kind === 'unlisted') {
    return <span className="mt-1 block"><Gap wrap label="Worker" owner="public listing for this worker" /></span>;
  }
  if (identity.kind === 'unreadable') {
    return (
      <span className="mt-1 block text-[11px] leading-5 text-amber-700">
        Which worker this runs could not be read. This is not a claim that it has no listing.
      </span>
    );
  }
  return null;
}

function ConsoleHome() {
  const instances = useLoad(() => api('/v1/marketplace/instances'), []);
  const { names, resolving, failed } = useWorkerNames();
  const supply = useLoad(() => api('/v1/creator/supply'), []);
  const receipts = useLoad(() => api('/v1/receipts'), []);
  const items = instances.value?.items || [];
  // The deployments read has an Unreadable of its own below; the banner covers
  // only the reads that do not, so one failure is never stated twice.
  const failure = supply.error || receipts.error;

  return (
    <main>
      <SectionHead
        eyebrow="Console"
        title="Your deployments."
        lede="Persistent workers stay customisable after hire. Runtime placement, package version, connectors,
              schedules, authority grants, and rollback posture are all ongoing state — not first-run answers."
      />

      <ErrorNotice error={failure} />

      <div className="mt-7 border-y border-slate-200 py-5">
        <StatRow items={[
          { label: 'Running', from: instances, select: (v) => v.items?.length },
          { label: 'Drafts', from: supply, select: (v) => v.drafts?.length },
          { label: 'Published', from: supply, select: (v) => v.listings?.length },
          { label: 'Receipts', from: receipts, select: (v) => v.items?.length },
        ]} />
      </div>

      <SubHeading className="mt-8">Deployments</SubHeading>
      {instances.loading ? (
        <Skeleton count={2} className="mt-4 grid gap-4 sm:grid-cols-2" />
      ) : instances.error ? (
        <div className="mt-4"><Unreadable error={instances.error} subject="Your deployments" onRetry={instances.reload} /></div>
      ) : items.length ? (
        <div className="mt-4 grid gap-4 sm:grid-cols-2">
          {items.slice(0, 4).map((item) => {
            const identity = deploymentIdentity({ instance: item, names, resolving, failed });
            return (
            <Card as={Link} to={`/instances/${item.worker_instance_id}`} key={item.worker_instance_id}
                  className="group h-full p-4">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <DeploymentTitle identity={identity} instance={item}
                                   className="text-sm font-bold text-slate-900 group-hover:text-blue-700" />
                  {identity.kind === 'named' && (
                    <p className="mt-0.5 truncate font-mono text-[11px] text-slate-500" title={item.worker_instance_id}>
                      {item.worker_instance_id}
                    </p>
                  )}
                  <DeploymentIdentityNote identity={identity} />
                </div>
                <State label="readiness" value={item.readiness} />
              </div>
              <div className="mt-3 flex flex-wrap gap-2 border-t border-slate-100 pt-3">
                <State label="desired" value={item.desired_state} />
                <State label="observed" value={item.observed_state} />
                <Chip>config r{item.config_revision}</Chip>
              </div>
            </Card>
            );
          })}
        </div>
      ) : (
        <div className="mt-4">
          <Empty title="Nothing running yet." action={<Link className={buttonStyles.primary} to="/agents">Explore workers</Link>}>
            Hiring an admitted worker creates the quote, entitlement, install, and runtime records a deployment projects.
          </Empty>
        </div>
      )}

      <SubHeading className="mt-10">Not projected here yet</SubHeading>
      <div className="mt-3 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        <Gap block label="Update availability and rollback targets" owner="package-version notice owner" />
        <Gap block label="Agent Map: presence, delegation, effects" owner="Hypervisor Agent Map projection" />
      </div>
    </main>
  );
}

function Templates() {
  const templates = useLoad(() => api('/v1/worker-templates'), []);
  const items = templates.value?.items || [];
  return (
    <main>
      <SectionHead
        eyebrow="Console"
        title="Templates."
        lede="Registered starting points for a new worker. A template is a non-executable composition: creating a
              draft from one grants no runtime and no authority."
      />
      {templates.loading ? (
        <Skeleton count={2} className="mt-7 grid gap-4 sm:grid-cols-2" />
      ) : templates.error ? (
        <div className="mt-7"><Unreadable error={templates.error} subject="Starter templates" onRetry={templates.reload} /></div>
      ) : !items.length ? (
        <div className="mt-7">
          <Empty title="No templates registered.">
            A template is a registered starting point owned by the package plane. None is available to this
            principal, so a new worker has to start from an existing draft.
          </Empty>
        </div>
      ) : (
        <div className="mt-7 grid gap-4 sm:grid-cols-2">
          {items.map((item) => (
            <Card key={item.template_ref} className="h-full p-5 hover:shadow-none">
              <div className="flex items-start justify-between gap-3">
                <h2 className="font-bold text-slate-900">{item.name}</h2>
                <Chip>{item.executable ? 'executable' : 'non-executable'}</Chip>
              </div>
              <p className="mt-2 text-sm leading-6 text-slate-600">{item.description}</p>
              {item.required_integration_surfaces?.length > 0 && (
                <div className="mt-3">
                  <p className="text-[11px] font-bold uppercase tracking-[.12em] text-slate-500">Required surfaces</p>
                  <div className="mt-1.5 flex flex-wrap gap-1.5">
                    {item.required_integration_surfaces.map((surface) => <Chip key={surface}>{surface}</Chip>)}
                  </div>
                </div>
              )}
              <p className="mt-3 break-all font-mono text-[11px] text-slate-500">{item.template_ref}</p>
              <div className="mt-auto pt-4">
                <Link className={cx(buttonStyles.secondary, 'w-full')} to="/builder">Start a draft</Link>
              </div>
            </Card>
          ))}
        </div>
      )}
    </main>
  );
}

/* ── builder ────────────────────────────────────────────────────────── */

// The publication ladder is eight distinct receipted transitions. The retired
// prototype had no equivalent; showing the whole ladder is why Builder reads as
// a process rather than a list.
function ladderFor(draft, relation) {
  const submission = relation.submission;
  return [
    { key: 'draft', label: 'Draft', done: true },
    { key: 'validated', label: 'Validated', done: draft.state !== 'draft' },
    { key: 'released', label: 'Released', done: Boolean(draft.release_ref) },
    { key: 'registered', label: 'Registered', done: Boolean(relation.registration) },
    { key: 'proposed', label: 'Proposed', done: Boolean(relation.promotion) },
    { key: 'submitted', label: 'Submitted', done: Boolean(submission) },
    { key: 'benchmarked', label: 'Benchmarked', done: ['admitted', 'published'].includes(submission?.state) },
    { key: 'published', label: 'Published', done: Boolean(relation.listing) },
  ];
}

function Ladder({ steps }) {
  const current = steps.findIndex((step) => !step.done);
  return (
    <ol className="flex flex-wrap items-center gap-x-1.5 gap-y-2">
      {steps.map((step, index) => (
        <li key={step.key} className="flex items-center gap-1.5">
          <span className={cx(
            'inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-[10px] font-bold uppercase tracking-[.12em] ring-1 ring-inset',
            step.done ? 'bg-emerald-50 text-emerald-700 ring-emerald-600/20'
              : index === current ? 'bg-blue-50 text-blue-700 ring-blue-600/20'
              : 'bg-slate-50 text-slate-500 ring-slate-300',
          )}>
            {step.done && (
              <svg className="h-2.5 w-2.5" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
                <path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z" />
              </svg>
            )}
            {step.label}
          </span>
        </li>
      ))}
    </ol>
  );
}

function Builder() {
  const templates = useLoad(() => api('/v1/worker-templates'), []);
  const supply = useLoad(() => api('/v1/creator/supply'), []);
  const [form, setForm] = useState({
    template_ref: 'worker-template://telesupport/v1',
    name: 'Telesupport operator',
    description: 'Triages support tickets, drafts bounded replies, and escalates actions requiring human authority.',
    model_route_ref: 'model-route://support/default',
    harness_ref: 'harness://managed-worker/v1',
    runtime_profile_ref: 'runtime-profile://zero-to-idle/v1',
    // Collected, because the domain no longer writes them when nobody says
    // them. A task contract was being filled in as SupportTicket →
    // SupportResolution for every draft this form created, and a price as USD
    // 49.00 a month, both of which then entered the composition hash and were
    // admitted under it as the publisher's own declarations.
    task_input: 'SupportTicket',
    task_output: 'SupportResolution',
    price_usd_month: '49',
  });
  const [busy, setBusy] = useState('');
  const [error, setError] = useState(null);

  const act = async (key, operation) => {
    setBusy(key); setError(null);
    try { await operation(); await supply.reload(); } catch (cause) { setError(cause); } finally { setBusy(''); }
  };

  const relations = useMemo(() => {
    const value = supply.value || {};
    return Object.fromEntries((value.drafts || []).map((draft) => {
      const registration = (value.registrations || []).find((item) => item.draft_ref === draft.draft_ref);
      const promotion = registration && (value.promotions || []).find((item) => item.registration_ref === registration.registration_ref);
      const submission = promotion && (value.submissions || []).find((item) => item.promotion_ref === promotion.promotion_ref);
      const listing = registration && (value.listings || []).find((item) => item.registration_ref === registration.registration_ref);
      return [draft.draft_ref, { registration, promotion, submission, listing }];
    }));
  }, [supply.value]);

  const create = (event) => {
    event.preventDefault();
    const { task_input, task_output, price_usd_month, ...rest } = form;
    act('create', () => api('/v1/worker-package-drafts', {
      method: 'POST',
      body: {
        ...rest,
        task_contract: { input: task_input, output: task_output },
        pricing: { asset: 'USD', amount_minor: Math.round(Number(price_usd_month) * 100), cadence: 'month' },
        // The surfaces and scopes had been hard-coded here — every draft this
        // form created declared helpdesk, crm and email and three ticket scopes,
        // whatever it was for. The template's own required surfaces stand in
        // their place, and scopes stay undeclared until someone declares them,
        // which is a state the listing projection now renders as itself.
      },
    }));
  };

  const nextAction = (draft, relation) => {
    if (draft.state === 'draft') return ['Validate', () => api(`/v1/worker-package-drafts/${encodeURIComponent(draft.draft_ref)}/validate`, { method: 'POST', body: { expected_revision: draft.revision } })];
    if (draft.state === 'validated') return ['Release package', () => api(`/v1/worker-package-drafts/${encodeURIComponent(draft.draft_ref)}/package-candidates`, { method: 'POST', body: { version: '1.0.0', sbom_ref: 'sbom://generated/v1', provenance_ref: 'provenance://builder/local' } })];
    if (!relation.registration) return ['Save privately', () => api('/v1/worker-registrations', { method: 'POST', body: { draft_ref: draft.draft_ref, visibility: 'private' } })];
    if (!relation.promotion) return ['Propose publication', () => api(`/v1/worker-registrations/${encodeURIComponent(relation.registration.registration_ref)}/promotion-proposals`, { method: 'POST', body: { disclosure_allowlist: ['name', 'description', 'task_contract', 'pricing'], license: 'commercial-managed', pricing: draft.pricing } })];
    if (relation.promotion.state === 'draft') return ['Submit', () => api(`/v1/worker-registrations/${encodeURIComponent(relation.registration.registration_ref)}/promotion-proposals/${encodeURIComponent(relation.promotion.promotion_ref)}/submit`, { method: 'POST', body: {} })];
    if (relation.submission?.state === 'awaiting_benchmark') return ['Run benchmark', () => api(`/v1/marketplace/submissions/${relation.submission.submission_id}/benchmark`, { method: 'POST', body: { evaluation_plan_ref: 'evaluation-plan://telesupport/adversarial-v1' } })];
    if (relation.submission?.state === 'admitted') return ['Publish explicitly', () => api(`/v1/marketplace/submissions/${relation.submission.submission_id}/publish`, { method: 'POST', body: {} })];
    return null;
  };

  const drafts = supply.value?.drafts || [];

  return (
    <main>
      <SectionHead
        eyebrow="Supply lifecycle"
        title="Build an immutable worker package."
        lede="Draft, validation, package admission, private registration, disclosure, benchmark, and publication remain separate receipted transitions. Nothing advances implicitly."
      />
      <ErrorNotice error={error} />

      <div className="mt-8 grid gap-10 lg:grid-cols-[minmax(0,1fr)_360px]">
        <section className="min-w-0 space-y-4">
          {supply.loading && <Skeleton count={2} className="grid gap-4" />}

          {drafts.map((draft) => {
            const relation = relations[draft.draft_ref] || {};
            const action = nextAction(draft, relation);
            const state = relation.listing ? 'published'
              : relation.submission?.state || relation.promotion?.state || relation.registration?.state || draft.state;
            return (
              <Card key={draft.draft_ref} className="p-5 hover:shadow-none">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <h2 className="font-bold text-slate-900">{draft.name}</h2>
                      <State value={state} />
                    </div>
                    <p className="mt-1.5 max-w-2xl text-sm leading-6 text-slate-600">{draft.description}</p>
                  </div>
                  {action && (
                    <Button disabled={!!busy} onClick={() => act(draft.draft_ref, action[1])}>
                      {busy === draft.draft_ref ? 'Working…' : action[0]}
                    </Button>
                  )}
                </div>

                <div className="mt-4 border-t border-slate-100 pt-4">
                  <Ladder steps={ladderFor(draft, relation)} />
                </div>

                <p className="mt-3 font-mono text-[11px] text-slate-500" title={draft.release_ref || undefined}>
                  draft r{draft.revision} · {draft.release_ref ? shortRef(draft.release_ref, 24) : 'no immutable release yet'}
                </p>

                {relation.listing && (
                  <Link to={`/agents/${relation.listing.worker_id}`} className="mt-3 inline-flex min-h-11 items-center py-2 text-sm font-medium text-blue-700 hover:underline">
                    View public listing →
                  </Link>
                )}
              </Card>
            );
          })}

          {!supply.loading && supply.error && (
            <Unreadable error={supply.error} subject="Your drafts" onRetry={supply.reload} />
          )}
          {!supply.loading && !supply.error && !drafts.length && (
            <Empty title="No worker drafts yet.">Start from a non-executable template on the right. A draft is inert until you validate and release it.</Empty>
          )}
        </section>

        <Panel as="form" onSubmit={create} className="h-fit">
          <h2 className="text-lg font-bold text-slate-900">New draft</h2>
          <p className="mt-1 text-xs leading-5 text-slate-500">Templates are non-executable compositions. Creating a draft grants no runtime.</p>
          <div className="mt-4 space-y-4">
            <label className="block">
              <span className="text-sm font-semibold text-slate-800">Starter</span>
              <select
                className={cx(inputStyles, 'mt-1.5')}
                value={form.template_ref}
                onChange={(event) => setForm({ ...form, template_ref: event.target.value })}
              >
                {(templates.value?.items || []).map((item) => (
                  <option key={item.template_ref} value={item.template_ref}>{item.name} — non-executable</option>
                ))}
              </select>
            </label>
            <Field label="Name" value={form.name} onChange={(name) => setForm({ ...form, name })} />
            <Field label="Description" value={form.description} onChange={(description) => setForm({ ...form, description })} multiline />
            <Field label="Model route ref" value={form.model_route_ref} onChange={(model_route_ref) => setForm({ ...form, model_route_ref })} />
            <Field label="Harness ref" value={form.harness_ref} onChange={(harness_ref) => setForm({ ...form, harness_ref })} />
            <Field label="Runtime profile ref" value={form.runtime_profile_ref} onChange={(runtime_profile_ref) => setForm({ ...form, runtime_profile_ref })} />
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="Task input type" value={form.task_input} onChange={(task_input) => setForm({ ...form, task_input })} />
              <Field label="Task output type" value={form.task_output} onChange={(task_output) => setForm({ ...form, task_output })} />
            </div>
            <Field label="Price, USD per month" type="number" min="0" step="1"
                   value={form.price_usd_month} onChange={(price_usd_month) => setForm({ ...form, price_usd_month })}
                   hint="The currency and cadence are this form's, and are stated here rather than assumed: the draft records USD, monthly, at the amount you enter." />
            <Button className="w-full" disabled={!!busy}>{busy === 'create' ? 'Saving…' : 'Create durable draft'}</Button>
          </div>
        </Panel>
      </div>
    </main>
  );
}

/* ── my workers ─────────────────────────────────────────────────────── */

// A declared list on the composition — surfaces it works inside, scopes it may
// hold, goal spaces it is eligible for. An empty list is a fact the draft
// states, not a missing owner: the composition declares none. Saying "no owner"
// there would be false, and would also repeat one owner across seven cards.
function Declared({ label, values, none }) {
  return (
    <div>
      <p className="text-[11px] font-semibold text-slate-500">{label}</p>
      {values?.length ? (
        <div className="mt-1.5 flex flex-wrap gap-1.5">
          {values.map((value) => <Chip key={value}>{value}</Chip>)}
        </div>
      ) : (
        <p className="mt-1 text-xs leading-5 text-slate-500">{none}</p>
      )}
    </div>
  );
}

function MyWorkers() {
  const state = useLoad(() => api('/v1/creator/supply'), []);
  const registrations = state.value?.registrations || [];
  const listings = state.value?.listings || [];
  const drafts = state.value?.drafts || [];
  const promotions = state.value?.promotions || [];

  return (
    <main>
      {/* Canon, "Private Worker Registration And Explicit Promotion", makes
          "Save to My workers" the destination of a local agent's pairing
          session, and this surface had no way in at all.

          A link, not a button. The first cut was a black primary and a blind
          review refused it: the strongest affordance on the page offered
          pairing, four lines above this surface's own row saying pairing has no
          owner. Weight has to match what the destination can do, and what it
          can do is be read — so the offer states its own limit in its second
          line rather than leaving a button to imply otherwise.

          That limit is derived, not written. A hand-authored "none can be
          completed yet" is true only until the first rung gets an owner, and
          then it is a falsehood in 12px grey beside the link the eye reaches
          first, protected by nothing. Counting the ladder's own definitions
          cannot drift from the ladder, and the sentence retires itself one rung
          at a time as owners land. */}
      <SectionHead
        eyebrow="Private supply"
        title="My workers."
        lede="Private and organization registrations remain fully usable without public promotion. Publishing does not
              turn a registration public — it derives a separate listing object from it, and the registration's own
              visibility never changes."
        aside={(
          <div className="sm:text-right">
            <Link to="/my-workers/add" className="inline-flex min-h-11 items-center py-2 text-sm font-semibold text-blue-700 hover:underline">
              Add your agent →
            </Link>
            <p className="max-w-[34ch] text-xs leading-5 text-slate-500">
              Pairing an agent you already run. {settableSteps.length === ADD_AGENT_STEPS.length
                ? `All ${ADD_AGENT_STEPS.length} steps can be completed.`
                : settableSteps.length
                  ? `${settableSteps.length} of ${ADD_AGENT_STEPS.length} steps can be completed; the rest name the owner they wait on.`
                  : `None of its ${ADD_AGENT_STEPS.length} steps can be completed yet — each names the owner it waits on.`}
            </p>
          </div>
        )}
      />

      {/* Canon, "Default User And Integration Surfaces", says this surface should
          expose live posture, last preflight/invocation/evidence/failure
          summaries, and edit/re-pair/test/revoke/delete/export controls. None of
          those has an owner. They are absent from every registration equally, so
          they are stated once for the surface rather than seven times over. */}
      {/* `wrap`, because these two are the longest markers in the product and
          `Gap`'s default truncates — which needs a constrained width to work.
          In a flex row that gives them their content width, so at 375 and 390px
          they measured 390 and 396px inside the viewport and pushed the document
          sideways. The row also has to be allowed to break, or wrapping the text
          only moves the overflow onto the row. */}
      {/* Two markers wrap at phone widths, and a wrapped line sat 20px under its
          own first line while the next marker sat 8px under that — so the gap
          between two markers was smaller than the gap inside one, and the group
          boundaries inverted. Scanning the gutter gave glyph / blank / glyph,
          and the blanks read as markers whose glyph had failed to load.
          Stacked below sm with more room between items than a wrapped line
          takes, so the ordering is right; a row above it, where nothing wraps. */}
      <div className="mt-7 border-y border-slate-200 py-3 text-xs text-slate-500">
        <div className="flex flex-col gap-y-6 sm:flex-row sm:flex-wrap sm:items-center sm:gap-x-6 sm:gap-y-2">
          <Gap wrap className="min-w-0 max-w-full" label="Live posture" owner="local pairing and liveness owner" />
          <Gap wrap className="min-w-0 max-w-full" label="Preflight, invocation, and failure history" owner="private-worker telemetry owner" />
          <Gap wrap className="min-w-0 max-w-full" label="Edit, re-pair, test, revoke, delete, export" owner="private-worker lifecycle controls" />
          {/* Out of the wrapping flow below sm: `ml-auto` on a stacked column put
              the count on its own line directly under the last marker's orphan
              second line, where it read as a caption on that marker rather than
              as the page's own count. */}
          <span className="hidden sm:ml-auto sm:block">
            {state.loading ? 'Loading…'
              : state.error ? 'unreadable'
              : `${registrations.length} registration${registrations.length === 1 ? '' : 's'}`}
          </span>
        </div>
        <p className="mt-4 border-t border-slate-100 pt-3 font-semibold text-slate-700 sm:hidden">
          {state.loading ? 'Loading…'
            : state.error ? 'unreadable'
            : `${registrations.length} registration${registrations.length === 1 ? '' : 's'}`}
        </p>
      </div>

      {state.loading ? (
        <Skeleton count={2} className="mt-6 grid gap-5 lg:grid-cols-2" />
      ) : state.error ? (
        <div className="mt-6"><Unreadable error={state.error} subject="Your private registrations" onRetry={state.reload} /></div>
      ) : registrations.length ? (
        <div className="mt-6 grid gap-5 lg:grid-cols-2">
          {registrations.map((item) => {
            const listing = listings.find((entry) => entry.registration_ref === item.registration_ref);
            const draft = drafts.find((entry) => entry.draft_ref === item.draft_ref);
            const promotion = promotions.find((entry) => entry.registration_ref === item.registration_ref);
            return (
              <Card key={item.registration_ref} className="h-full p-5 hover:shadow-none">
                <div className="flex items-start justify-between gap-2">
                  <h2 className="min-w-0 truncate font-bold text-slate-900" title={item.name}>{item.name}</h2>
                  <div className="flex shrink-0 gap-1.5">
                    <State label="visibility" value={item.visibility} />
                    <State label="registration" value={item.state} />
                  </div>
                </div>
                {draft?.description && (
                  <p className="mt-2 line-clamp-2 text-sm leading-6 text-slate-600">{draft.description}</p>
                )}

                {/* Canon: "exact ModelRoute/HarnessProfile-or-AgentHarnessAdapter/
                    runtime/tool dependency disclosure". Every one of these is a
                    field the registration's draft already carries. */}
                <div className="mt-4">
                  <Eyebrow>What it is bound to</Eyebrow>
                  <div className="mt-1.5">
                    <DefList rows={[
                      ['Model route', draft?.model_route_ref],
                      ['Harness', draft?.harness_ref],
                      ['Runtime profile', draft?.runtime_profile_ref],
                      ['Memory policy', draft?.memory_policy, { mono: false }],
                      ['Goal spaces', item.goal_space_refs?.length
                        ? item.goal_space_refs.join(', ')
                        : 'none bound', { mono: false }],
                      ['Composition', shortRef(item.composition_root, 20)],
                      ['Package release', shortRef(item.release_ref, 20)],
                    ]} />
                  </div>
                </div>

                <div className="mt-4 space-y-3">
                  <Declared label="Works inside" values={draft?.integration_surfaces}
                            none="Declares no integration surface." />
                  <Declared label="Authority it may hold" values={draft?.authority_scopes}
                            none="Declares no authority scope." />
                </div>

                {/* Canon: no marketplace badge on a private worker unless it came
                    through an explicit public admission path. A listing is that
                    path; a registration without one shows nothing but the offer
                    to start the ladder, which lives in Builder.

                    The two badges in the header report the registration. These
                    report a different object — the listing derived from it —
                    and say so, or a card reads as claiming to be private and
                    published at once. */}
                <div role="group" aria-label="Public listing" className="mt-auto border-t border-slate-100 pt-4">
                  {/* The caption is what separates the objects. Everything above
                      it reports the registration; everything under it reports
                      the listing derived from it.

                      A caption can replace a SUBJECT prefix but not an ATTRIBUTE
                      name: `listing:` said whose state it was, so the region now
                      says it instead — but `benchmark:` says which property, and
                      no region caption supplies that. Bare, it would read as a
                      second state of the listing. A promotion is a third object,
                      so it still names itself. */}
                  <Eyebrow>Public listing</Eyebrow>
                  <div className="mt-2 flex flex-wrap items-center justify-between gap-3">
                    {listing ? (
                      <>
                        <span className="flex flex-wrap items-center gap-1.5">
                          <State value={listing.state} />
                          <State label="benchmark" value={listing.benchmark?.status || 'unbenchmarked'} />
                        </span>
                        <Link to={`/agents/${listing.worker_id}`} className="inline-flex min-h-11 items-center py-2 text-sm font-medium text-blue-700 hover:underline">
                          View public listing →
                        </Link>
                      </>
                    ) : (
                      <>
                        <span className="text-xs text-slate-500">
                          {promotion
                            ? <>None yet — <State label="promotion" value={promotion.state} /></>
                            : 'None. This registration is not publicly searchable, benchmarked, or ranked.'}
                        </span>
                        <Link to="/builder" className="text-sm font-medium text-blue-700 hover:underline">
                          Publish on aiagent.xyz →
                        </Link>
                      </>
                    )}
                  </div>
                </div>
              </Card>
            );
          })}
        </div>
      ) : (
        <div className="mt-6">
          <Empty title="No private workers." action={<Link className={buttonStyles.primary} to="/builder">Open Builder</Link>}>
            Release a package from Builder and save it privately. A private registration never appears in public supply.
          </Empty>
        </div>
      )}
    </main>
  );
}

/* ── add your agent ─────────────────────────────────────────────────── */

// Canon, worker-marketplace.md, "Managed Worker Onboarding Plans": "The same
// compiler should produce the screenshot-like **Add your agent** flow for a
// reusable local worker. The visual steps may be simple, but their source of
// truth is the manifest, pairing envelope, and observed readiness."
//
// The six steps are canon's, in canon's order, described in canon's own words.
// Not one of them is configurable here: every rung waits on an owner this
// estate has not built, and each names its own. The ladder is shown whole
// anyway, because what a person is being asked to do at the end of it — hand a
// bootstrap secret to an agent already running on their machine — is exactly
// the thing they should be able to read end to end before starting any of it.
const ADD_AGENT_STEPS = [
  {
    key: 'use',
    title: 'Choose use and visibility',
    slot: 'Target and visibility',
    blurb: 'Guest, private, or organization',
    // Only the clause nothing else carries. "Choose use and visibility" as the
    // section heading, "Target and visibility" as the slot label, and "Which
    // declared target this session is for" as the hint put the same word three
    // times inside a 130px band. The owner of the registration is the half of
    // this decision that appears nowhere else: not in the rail's subtitle, not
    // in the disclosure below, which speak only to targets.
    //
    // Conditional, because one of the three targets creates no registration at
    // all — the disclosure below says so in its own summary — so an unconditional
    // "the registration this creates" contradicts the row underneath it.
    //
    // And without the enumeration. Naming two values here put a binary choice on
    // the line above a count of three, and per-target enumeration belongs to the
    // disclosure that does it properly.
    canon: 'Who owns the registration, when one is created.',
    owner: 'private registration target owner',
    pending: true,
  },
  {
    key: 'runtime',
    title: 'Connect your runtime',
    slot: 'Local Hypervisor or home domain',
    blurb: 'Home domain and transport',
    // Not the two slot labels restated. What a reader cannot get from them is
    // whose machine this is about: canon puts pairing proof, adapter and MCP
    // mediation, credentials, execution and receipts with the local domain, and
    // is explicit that the private registry "is not a second runtime or a tunnel
    // into the user's machine".
    canon: 'Both choices are about your own machine. aiagent.xyz records the result; it never reaches into the runtime.',
    owner: 'home domain directory owner',
    pending: true,
  },
  {
    key: 'profile',
    title: 'Agent profile',
    slot: 'Worker composition and persona',
    blurb: 'Composition, and an optional persona',
    canon: 'Bind an accountable Worker composition, and optionally a descriptive persona.',
    owner: 'worker composition binding owner',
    pending: true,
  },
  {
    key: 'capabilities',
    title: 'Capabilities and limits',
    slot: 'Declared capabilities and limits',
    blurb: 'What it declares it can do',
    canon: 'Review declared tasks, outputs, tools, privacy, evidence, authority, cost, availability, and incompatible requirements.',
    owner: 'package manifest declaration owner',
    pending: true,
  },
  {
    key: 'bootstrap',
    title: 'Paste this on your agent',
    slot: 'Bootstrap projection',
    blurb: 'An expiring bootstrap projection',
    // Not canon's sentence any more: the panel below enumerates the three
    // actions it paraphrases, so left here it was the same fact twice, 40px
    // apart. What no other element on the rung says is what this rung is — the
    // one place a person is asked to put something into software running on
    // their own machine.
    canon: 'The one thing this flow asks you to paste into software running on your own machine. It expires, and ordinary participation begins only once the bootstrap is bound.',
    owner: 'bootstrap projection owner',
    pending: true,
  },
  {
    key: 'preflight',
    title: 'Preflight',
    slot: 'Preflight checks',
    blurb: 'Prove the binding before it is used',
    // The seven checks are behind the disclosure below; the hint says what the
    // rung is for rather than listing them twice.
    canon: 'Proof that the binding works before anything is asked of it.',
    owner: 'preflight evidence owner',
    pending: true,
  },
];

// Rungs of the pairing ladder that could actually collect a value today. Zero,
// and the sentence that says so on My workers is computed from this rather than
// typed, so the day a rung gets an owner the claim changes with it.
const settableSteps = ADD_AGENT_STEPS.filter((step) => !step.pending);

// Canon, worker-marketplace.md, "Managed Worker Onboarding Plans": "The product
// projects exact pairing state rather than an optimistic spinner", followed by
// the twelve states verbatim. What the ladder produces is one
// LocalAgentPairingSessionEnvelope, and its state is the fact this whole surface
// turns on — so it is stated at page altitude, once, rather than left for a
// reader to discover on the fifth rung.
//
// Twelve states, in two groups, because they are two different things. Seven are
// a session moving forward; five are a session that has stopped and will not
// move again. Rendering them as one flat list would put `revoked` next to
// `bootstrap_bound` as though a reader could be waiting for either.
const PAIRING_PROGRESS = [
  'created', 'challenge_issued', 'agent_proof_received', 'bootstrap_bound',
  'composition_submitted', 'participation_submitted', 'completed',
];
const PAIRING_ENDINGS = ['expired', 'rejected', 'cancelled', 'revoked', 'failed_closed'];

// Canon, worker-marketplace.md: "Its transport may be `loopback`, `device_code`,
// or `copy_command`." Three, and only three.
//
// What each one does mechanically is not in canon, and this surface does not
// invent it: a plausible description of a device-code exchange is a claim about
// behaviour no owner here has specified. What canon does fix is what all three
// have in common, and that is the part a reader needs before pasting anything
// anywhere.
const PAIRING_TRANSPORTS = ['loopback', 'device_code', 'copy_command'];

// Canon, worker-marketplace.md: "the bootstrap surface is restricted to
// `read_discovery`, `submit_worker_composition`, and
// `submit_room_participation_request`." Three, and the restriction is the point.
// Canon, worker-marketplace.md: "Completion returns the submitted composition
// and, when the target is a room guest, participation-request refs. It does not
// imply composition registration, room admission, context, budget, authority,
// benchmark standing, public visibility, or successful task execution."
//
// Eight things, and a reader who has just walked six rungs is at exactly the
// moment of assuming most of them.
// Canon's own list for the sixth step: "test origin/key binding, adapter
// compatibility, proposal interface, output schema, evidence delivery, revoke,
// and fail-closed behavior."
const PREFLIGHT_CHECKS = [
  'origin and key binding', 'adapter compatibility', 'proposal interface', 'output schema',
  'evidence delivery', 'revoke', 'fail-closed behaviour',
];

// And the ceiling those checks do not raise. Canon, worker-marketplace.md: "An
// `execution_posture: prompt_only` agent is confined to `contribution_lane:
// proposal_only` and an `attested` assurance ceiling until a named verifier
// independently evaluates a specific contribution. Preflight and pairing do not
// raise that ceiling or attest the hidden model or agent-runtime loop, tools,
// environment, reasoning, independence, or originality."
//
// This is the rung where a green tick is most likely to be read as a warrant, so
// what passing does not buy renders open, beside the checks that pass.
const PREFLIGHT_CEILING = [
  ['execution_posture', 'prompt_only'],
  ['contribution_lane', 'proposal_only'],
  ['assurance ceiling', 'attested'],
];
const PREFLIGHT_NOT_ATTESTED = [
  'the hidden model', 'the agent-runtime loop', 'tools', 'environment',
  'reasoning', 'independence', 'originality',
];

const COMPLETION_EXCLUDES = [
  'composition registration', 'room admission', 'context', 'budget',
  'authority', 'benchmark standing', 'public visibility', 'successful task execution',
];

const BOOTSTRAP_ACTIONS = ['read_discovery', 'submit_worker_composition', 'submit_room_participation_request'];

// The prohibitions, from the same paragraph and from worker-endpoints.md's
// "Pairing Session Projection". These are not footnotes and they do not go
// behind the disclosure this surface uses for reference. This is the one rung
// where a person is asked to paste something into software running on their own
// machine, and what that thing cannot be is the whole of what makes it safe.
const BOOTSTRAP_REFUSALS = [
  {
    never: 'A durable, broad-scope organization token',
    why: 'This flow never asks you to paste one into an agent. Anything that asks for an organization credential in order to pair is not this flow.',
  },
  {
    never: 'Shared bucket or room-database read or write access',
    why: 'Pairing grants neither, and the projection carries no raw connector secret, no ambient MCP access, and no permission to execute an effect.',
  },
  {
    never: 'Copied text treated as identity, capability, evidence or authority',
    why: 'A pasted instruction, persona, character profile or agent name proves nothing about what an agent is or may do. It is setup convenience and is treated as nothing more.',
  },
];

// What the closed disclosure says. It read "canon lifecycle" — small,
// right-aligned and grey, in the exact column and weight this product uses for
// a named gap, so a provenance label was impersonating an absence claim two rows
// under a real one. The summary carries the vocabulary's shape instead, counted
// from the vocabularies themselves.
//
// It does NOT report the current state. There isn't one, and this page's
// discipline is that an absence is a disabled slot naming its owner — which the
// panel header does, 129px above, in the owner-named form. A bare "none current"
// down here is the same fact restated without its owner, and it is the one fact
// canon cares most about, so the weaker copy is the wrong place to carry it.
const pairingStateCount = PAIRING_PROGRESS.length + PAIRING_ENDINGS.length;
const pairingSummary = (state) =>
  `${PAIRING_PROGRESS.length} forward · ${PAIRING_ENDINGS.length} terminal${state ? ` · at ${state}` : ''}`;

// The seam where the session read will go. No owner projects a
// LocalAgentPairingSessionEnvelope, so it reads nothing and returns nothing —
// but it is the single place both halves of the panel take their value from, so
// the header's slot and the disclosure's summary cannot disagree the day one
// arrives. Dropping the parameter from the summary optimised the empty case by
// deleting the populated one: the row would have read "7 forward · 5 terminal"
// whether a session was awaiting the agent or already expired.
const readPairingSession = () => null;

// Canon, "Private Worker Registration And Explicit Promotion", fixes the
// progression and the endpoints doc fixes the identifiers: the create route
// "accepts only one declared target" — room_guest | private_worker |
// organization_worker — each with its own scope ref.
//
// What each one does NOT do is the half that separates them. Two of these three
// look identical from the outside (a private registration and an organization
// one differ only in which principal owns it), and the first creates no
// aiagent.xyz record at all — which a reader choosing between them has no way to
// know from the names.
const REGISTRATION_TARGETS = [
  {
    kind: 'room_guest',
    scope: 'outcome-room://…',
    title: 'One-room guest in ioi.ai',
    does: 'Admits the agent to a single room. Optional and room-scoped; no aiagent.xyz record is required or created.',
    doesNot: 'Creates no reusable registration, and the room lease cannot afterwards be repurposed as ambient private access. Saving privately needs its own session.',
  },
  {
    kind: 'private_worker',
    scope: 'user://…',
    title: 'Save to My workers',
    does: 'Owner-private registration of the exact Worker composition, reusable by eligible Goal Spaces, Automations, Workflows, or direct calls.',
    doesNot: 'Creates no publisher profile, marketplace submission, benchmark job, public artifact, public reputation entry, settlement offer, or training-data permission.',
  },
  {
    kind: 'organization_worker',
    scope: 'org://…',
    title: 'Organization-private worker',
    does: 'The same registration, owned by an organization principal and governed by its visibility policy.',
    doesNot: 'Stays invisible to public search, category leaderboards, MoW Network routing, public benchmarks, and third-party install surfaces.',
  },
];

// What each rung would collect, at the shape it will have. A step with no entry
// here renders its slot and its owner and nothing else, which is the honest
// state for a rung whose contents have not been built yet — as opposed to a rung
// that has been built and happens to be empty.
//
// Detail sits behind the same disclosure the pairing card uses one row up. Open,
// this block measured ~580px — heavier than the pairing card and the whole
// six-rung ladder — inside the one panel whose own label reads "not configurable
// yet", so weight contradicted state: rung one read as the substantial rung while
// five equally inert rungs rendered as bare slots.
const panels = {
  preflight: (
    <>
      <Panel>
        {/* The qualifier belongs on the label. Three key/value rows in the
            treatment this product uses for state it has READ, 200px under a
            card saying nothing about this agent has been collected, read as a
            settings panel for a posture that had been measured. These three are
            confinements that hold by rule for any prompt_only registration. */}
        <Eyebrow>What passing does not raise — these hold by rule, not by measurement</Eyebrow>
        <div className="mt-2">
          <DefList rows={PREFLIGHT_CEILING.map(([axis, value]) => [axis, value])} />
        </div>
        <p className="mt-3 max-w-[70ch] text-xs leading-5 text-slate-600">
          They hold until a named verifier independently evaluates a specific contribution. Preflight does
          not move them, and neither does pairing.
        </p>
        <div className="mt-4 border-t border-slate-200 pt-4">
          <Eyebrow>What it does not attest</Eyebrow>
          <TermList className="mt-1.5" items={PREFLIGHT_NOT_ATTESTED} />
          <p className="mt-2 max-w-[62ch] border-l-2 border-slate-200 pl-2.5 text-xs leading-5 text-slate-600">
            Copied instructions and self-reported runtime or model metadata are not proof of any of them.
          </p>
        </div>
      </Panel>
      <Drawer title="What preflight tests" hint={`${PREFLIGHT_CHECKS.length} checks`}>
        <TermList items={PREFLIGHT_CHECKS} />
      </Drawer>
    </>
  ),
  // The refusals stay in front; the permitted actions go behind the disclosure,
  // with the restriction itself in the closed row so it is stated without anyone
  // opening anything. Open, the two halves ran 440px against a 105px slot — the
  // qualifier three times the weight of the rung it qualifies — and the mono
  // list was immediately restated in English underneath itself.
  bootstrap: (
    <>
      {/* The expiry moved to the slot it describes. Here it was orphaned prose
          at the top of a panel whose identity is the refusals — no eyebrow, a
          hairline between it and the block below, and two lines under a slot
          that had just named the projection's absence. */}
      <Panel>
        <div>
          <Eyebrow>What it never asks for, and never carries</Eyebrow>
          <ul className="mt-2 space-y-3">
            {BOOTSTRAP_REFUSALS.map((refusal) => (
              <li key={refusal.never}>
                <p className="text-xs font-bold text-slate-800">{refusal.never}</p>
                <p className="mt-1 max-w-[62ch] border-l-2 border-slate-200 pl-2.5 text-xs leading-5 text-slate-600">
                  {refusal.why}
                </p>
              </li>
            ))}
          </ul>
        </div>
      </Panel>
      <Drawer
        title="What the bootstrap surface can do"
        hint={`${BOOTSTRAP_ACTIONS.length} actions, and nothing else`}
      >
        <TermList className="font-mono" items={BOOTSTRAP_ACTIONS} />
      </Drawer>
    </>
  ),
  runtime: (
    <>
      <Gap block label="Pairing transport" owner="local pairing transport owner" />
      <Drawer
        title="What a transport proves, and what it does not"
        hint={`${PAIRING_TRANSPORTS.length} transports · none grants authority`}
      >
        <TermList className="font-mono" items={PAIRING_TRANSPORTS} />
        <p className="mt-3 max-w-[62ch] text-xs leading-5 text-slate-600">
          Whichever of the three is used, pairing turns on an expiring nonce and challenge, and what it
          establishes is the agent&rsquo;s own key and its origin binding. The first ordinary participation
          message happens only after that binding is made.
        </p>
        {/* Both negations, in the lane this page keeps for negations, in one
            sentence. Split across the paragraph above and this one they read as
            two topics; stated as two sentences here the second restated the
            proof clause the paragraph above had just established, and said
            "grants no authority" a third time after the closed row. */}
        <p className="mt-1.5 max-w-[62ch] border-l-2 border-slate-200 pl-2.5 text-xs leading-5 text-slate-600">
          None of the three is a credential you hold; proving control of a key and an origin is not
          permission to act.
        </p>
      </Drawer>
    </>
  ),
  use: (
    <div className="mt-4">
      <Drawer
        title="What each target is, and is not"
        hint={`${REGISTRATION_TARGETS.length} targets · 1 creates no record here`}
      >
        <div className="divide-y divide-slate-200">
          {REGISTRATION_TARGETS.map((target) => (
            <div key={target.kind} className="grid gap-1 py-3.5 first:pt-0 md:grid-cols-[210px_minmax(0,1fr)] md:gap-5">
              <div className="min-w-0">
                <span className="block text-sm font-bold text-slate-900">{target.title}</span>
                <span className="mt-0.5 block break-all font-mono text-[11px] text-slate-500">{target.kind}</span>
                <span className="block break-all font-mono text-[11px] text-slate-500">{target.scope}</span>
              </div>
              <div className="min-w-0">
                <p className="max-w-[62ch] text-xs leading-5 text-slate-600">{target.does}</p>
                {/* Same treatment the deployment console gives a negation: the
                    half that separates two otherwise identical acts is carried
                    by a rule, not by one step of grey. */}
                <p className="mt-1.5 max-w-[62ch] border-l-2 border-slate-200 pl-2.5 text-xs leading-5 text-slate-600">
                  {target.doesNot}
                </p>
              </div>
            </div>
          ))}
        </div>
      </Drawer>
    </div>
  ),
};

function AddYourAgent() {
  const session = readPairingSession();
  const [step, setStep] = useState(0);
  const current = ADD_AGENT_STEPS[step];
  const last = step === ADD_AGENT_STEPS.length - 1;

  return (
    <main>
      <Link className="inline-flex min-h-11 items-center py-2 text-sm font-medium text-blue-700 hover:underline" to="/my-workers">
        ← My workers
      </Link>

      <div className="mt-3">
        <SectionHead
          eyebrow="Private registration"
          title="Add your agent."
          lede="For an agent you already run on your own machine. This registers the exact composition privately in My workers,
                where eligible Goal Spaces, Automations and Workflows can reuse it. Composing a new worker here instead is New
                agent. Publishing on aiagent.xyz is neither — it is a separate later action against a registration that already
                exists."
        />
      </div>

      {/* The session, above the ladder that produces it. A reader arriving here
          needs to know two things before any rung: that this is one pairing
          session rather than six independent settings, and that no session
          exists — which is why every rung is inert. Canon is explicit that the
          state is projected exactly rather than as a spinner, so the absence of
          a session is stated as an absence, not as "not started".

          Progress and endings are separated because they answer different
          questions. A reader watching a session wants to know what comes next;
          a reader whose session stopped wants to know what stopped it. Flat,
          `revoked` sits beside `bootstrap_bound` as though one might be waiting
          for either. */}
      <section className="mt-7 rounded-xl border border-slate-200 bg-white p-5">
        <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
          <SubHeading>Pairing session</SubHeading>
          {session
            ? <State label="state" value={session.state} />
            : <Gap label="State" owner="local agent pairing session owner" />}
        </div>
        <p className="mt-2 max-w-[76ch] text-sm leading-6 text-slate-600">
          Everything below belongs to one session, and its state is projected exactly rather than as a spinner.
          No session exists here, so no rung on the ladder can collect a value — each names the owner it waits on
          instead. Completing one returns the submitted composition, and participation-request refs when the
          target is a one-room guest.
        </p>
        {/* Verbatim, underscores intact, in the face the rest of the product
            uses for a typed value. Rendered as prose — "agent proof received" —
            a reader cannot match what they see here to the identifier in an API
            response or a log line, and matching them is the entire point of a
            state being exact rather than a spinner.

            Behind a disclosure because the vocabulary is reference: no session
            exists, so none of these is this session's state. Open, it is the
            second-heaviest block on the page, and at 375px it filled the whole
            second screen and pushed the first rung 450px further down — a legend
            for a state machine with no instance, sitting above the thing it is
            a legend for. */}
        <div className="mt-4">
          <Drawer title={`The ${pairingStateCount} states a pairing session can hold`} hint={pairingSummary(session?.state)}>
            <div className="grid gap-x-8 gap-y-4 md:grid-cols-2">
              <div>
                <Eyebrow>Moving forward, in order</Eyebrow>
                <TermList className="mt-1.5 font-mono" items={PAIRING_PROGRESS} />
              </div>
              <div>
                <Eyebrow>Stopped, and will not move again</Eyebrow>
                <TermList className="mt-1.5 font-mono" items={PAIRING_ENDINGS} />
              </div>
            </div>
          </Drawer>
        </div>

        {/* Canon pairs this with the state vocabulary, and so does the page: a
            reader who has just met the word `completed` is one row from the
            eight things it does not mean. */}
        <div className="mt-3">
          {/* Both halves, and the count says both. The row advertised only the
              denial, so at rest the page said `completed` refuses eight things
              and never that it delivers any — which on an inert flow reads as a
              terminal state worth nothing. And the half it hid is conditional on
              the rung directly below: choosing the room-guest target is what
              earns the participation refs.
              "does not imply" rather than "never means": canon's modality is the
              weaker one, and the stronger one is a claim canon does not make. */}
          {/* The affirmative half is two things, so it goes in the panel's own
              prose where it needs no click: a count is not the content, and a
              reader entering a six-step flow should not have to open reference
              material to learn what finishing it gives them. The disclosure
              keeps the eight exclusions alone, and its summary counts them the
              way the row above counts states. */}
          <Drawer
            title="What completing does not imply"
            hint={`${COMPLETION_EXCLUDES.length} exclusions`}
          >
            <TermList items={COMPLETION_EXCLUDES} />
          </Drawer>
        </div>
      </section>

      <div className="mt-8 grid gap-8 md:grid-cols-[240px_minmax(0,1fr)]">
        <div className="md:sticky md:top-40 md:self-start">
          <Stepper steps={ADD_AGENT_STEPS} current={step} onSelect={setStep} />
        </div>

        <section className="min-w-0">
          <h2 className="text-lg font-bold text-slate-900">{current.title}</h2>
          {/* The slot and its detail are siblings, not nest and nested. Inside
              the dashed frame, the one working control on the step wore this
              product's standard "no owner, nothing here works" treatment — and a
              reader trained by that treatment does not click it. The frame now
              contains only the unowned slot and its named absence; the
              disclosure sits on solid ground beside it, exactly as the
              pairing-session drawer does. */}
          <div className="mt-4 space-y-3">
            <InertPanel label={current.slot} owner={current.owner} hint={current.canon} />
            {panels[current.key]}
          </div>

          {/* Both controls are secondary. On the hire ladder the black primary
              is the control that starts a paid run; here nothing commits at
              any rung, so a primary would be a weight the page cannot cash. */}
          <div className="mt-8 flex flex-wrap items-center justify-between gap-3 border-t border-slate-200 pt-5">
            <Button variant="secondary" disabled={step === 0} onClick={() => setStep((index) => index - 1)}>
              Back
            </Button>
            {last
              ? <Gap wrap label="Save to My workers" owner="private registration endpoint" />
              : <Button variant="secondary" onClick={() => setStep((index) => index + 1)}>Continue</Button>}
          </div>
        </section>
      </div>
    </main>
  );
}

/* ── instances ──────────────────────────────────────────────────────── */

function Instances() {
  const state = useLoad(() => api('/v1/marketplace/instances'), []);
  const { names, resolving, failed } = useWorkerNames();
  const items = state.value?.items || [];

  return (
    <main>
      <SectionHead
        eyebrow="Runtime"
        title="Managed instances."
        lede="Desired lifecycle and observed runtime are projected independently. A desired state is a request, never a claim about what is running."
      />

      {state.loading ? (
        <Skeleton count={2} className="mt-8 grid gap-5 sm:grid-cols-2" />
      ) : state.error ? (
        <div className="mt-8"><Unreadable error={state.error} subject="Managed instances" onRetry={state.reload} /></div>
      ) : items.length ? (
        <div className="mt-8 grid gap-5 sm:grid-cols-2">
          {items.map((item) => {
            const identity = deploymentIdentity({ instance: item, names, resolving, failed });
            return (
            <Card as={Link} to={`/instances/${item.worker_instance_id}`} key={item.worker_instance_id} className="group h-full p-5">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <DeploymentTitle identity={identity} instance={item}
                                   className="text-base font-bold text-slate-900 group-hover:text-blue-700" />
                  <DeploymentIdentityNote identity={identity} />
                  {identity.kind === 'named' && (
                    <p className="mt-1 truncate font-mono text-[11px] text-slate-500" title={item.worker_instance_id}>
                      {item.worker_instance_id}
                    </p>
                  )}
                  <p className="mt-0.5 break-all font-mono text-[11px] text-slate-500" title={item.release_ref}>
                    {shortRef(item.release_ref, 26)}
                  </p>
                </div>
                <State label="readiness" value={item.readiness} />
              </div>
              <div className="mt-4 grid grid-cols-2 gap-3 border-t border-slate-100 pt-4">
                <div>
                  <p className="text-[10px] font-bold uppercase tracking-[.12em] text-slate-500">Desired</p>
                  <p className="mt-1"><State value={item.desired_state} /></p>
                </div>
                <div>
                  <p className="text-[10px] font-bold uppercase tracking-[.12em] text-slate-500">Observed</p>
                  <p className="mt-1"><State value={item.observed_state} /></p>
                </div>
              </div>
            </Card>
            );
          })}
        </div>
      ) : (
        <div className="mt-8">
          <Empty title="No managed instances." action={<Link className={buttonStyles.primary} to="/agents">Explore workers</Link>}>
            Hiring an admitted worker creates the quote, entitlement, install, and runtime records that a managed instance projects.
          </Empty>
        </div>
      )}
    </main>
  );
}

function InstanceDetail() {
  const { instanceId } = useParams();
  const state = useLoad(() => api(`/v1/marketplace/instances/${instanceId}`), [instanceId]);
  const receipts = useLoad(() => api(`/v1/receipts?object_ref=${encodeURIComponent(`worker-instance://${instanceId}`)}`), [instanceId]);
  const chain = listState(receipts);
  const plan = useLoad(() => api(`/v1/marketplace/instances/${instanceId}/onboarding-plan`), [instanceId]);
  // Resolved from the instance's own worker_id, so a deployment can say what it
  // is running rather than only which uuid it is.
  const workerId = state.value?.worker_id;
  const worker = useLoad(() => (workerId ? api(`/v1/marketplace/workers/${workerId}`) : Promise.resolve(null)), [workerId]);
  // What the package declares, from the listing's own disclosure projection —
  // with the read's own two states in front of it, because a listing that has
  // not arrived is not a package that declares nothing.
  const declaredField = (name) => (worker.loading ? { state: 'reading' }
    : worker.error ? { state: 'unreadable' }
    : disclosureField(worker.value, name));
  const surfacesField = declaredField('integration_surfaces');
  const scopesField = declaredField('authority_scopes');
  const declaredSurfaces = surfacesField.state === 'disclosed' ? (surfacesField.value || []) : [];
  const declaredScopes = scopesField.state === 'disclosed' ? (scopesField.value || []) : [];
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState('');
  // The surface and the scopes are the package's to declare and the buyer's to
  // choose from. This form used to post a hard-coded `helpdesk` with
  // `tickets:read` and `replies:draft` — a surface that happened to be right for
  // one listing and two scopes that were right for none, since the composition
  // asks for `ticket:read`. The domain refuses both now, so the control offers
  // what the package actually declared and nothing else.
  const [integration, setIntegration] = useState({
    integration_surface: '',
    credential_ref: 'credential-grant://wallet-network/select-me',
    scope_refs: [],
  });

  const act = async (key, operation) => {
    setBusy(key); setError(null);
    try { await operation(); await state.reload(); await receipts.reload(); }
    catch (cause) { setError(cause); } finally { setBusy(''); }
  };

  if (state.loading) return <main className="py-16 text-sm text-slate-500">Loading deployment…</main>;
  if (state.error || !state.value) {
    return (
      <main>
        <LoadFailure
          error={state.error}
          title="This deployment is not available."
          action={<Link className={buttonStyles.primary} to="/instances">Back to Running</Link>}
        />
      </main>
    );
  }
  const item = state.value;

  return (
    <main>
      <Link to="/instances" className="inline-flex min-h-11 items-center py-2 text-sm font-medium text-blue-700 hover:underline">← Instances</Link>
      <div className="mt-5 flex flex-wrap items-end justify-between gap-4">
        <div className="min-w-0">
          <p className="text-xs font-bold uppercase tracking-[.18em] text-blue-700">Managed instance</p>
          {/* The page led with a UUID and never said which worker was running.
              The instance carries `worker_id`, so the listing is one read away
              and the deployment can identify itself. Until that read returns,
              the id is still the honest heading — no placeholder name. */}
          <h1 className={cx('mt-2 font-black tracking-tight text-slate-950',
            worker.value ? 'text-3xl' : 'break-all font-mono text-2xl')}>
            {worker.value?.name || instanceId}
          </h1>
          {worker.value && (
            <p className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-slate-500">
              <span className="break-all font-mono">{instanceId}</span>
              <Link to={`/agents/${item.worker_id}`} className="font-medium text-blue-700 hover:underline">
                View listing →
              </Link>
            </p>
          )}
        </div>
        {/* Desired and observed are the two halves of one question — what was
            asked for, and what the runtime reports. `readiness` is a third
            thing: the runtime's word about its last check, from a different
            vocabulary, and not the mode that governs whether this deployment
            may act. Standing here it read as their peer and as the answer to
            that question. It reads once now, in the section that says which
            reading it is. */}
        <div className="flex flex-wrap gap-2">
          <State label="desired" value={item?.desired_state} />
          <State label="observed" value={item?.observed_state} />
        </div>
      </div>
      <ErrorNotice error={error || state.error} />

      {/* Three grid children so source order and column layout can disagree. On
          a phone the single column stacked the whole body first and left the
          Spend panel — the only place this deployment's price appears — at about
          85% scroll depth, below the change tiers, the endings, the map and the
          receipt chain. It now follows the controls directly.

          Controls stay first, which is the older ruling and the stronger one: an
          operator mid-incident should not scroll a taxonomy to reach stop. */}
      {/* No row gap: the sections carry their own top margins, and adding one
          put a 92px seam at the new row boundary where every other seam on the
          page is 55-60px — an accidental-looking gap at the one place nothing
          changed. */}
      <div className="mt-8 grid gap-x-10 lg:grid-cols-[minmax(0,1fr)_380px]">
        <section className="min-w-0 lg:col-start-1 lg:row-start-1">
          <SubHeading>Owner-bound state</SubHeading>
          <div className="mt-3">
            {/* Canon lists what this cockpit projects, and names runtime
                placement, package version and memory profile among them. The
                release, the runtime profile and the persistence profile are all
                on the instance record and were being dropped: the two profiles
                are what the buyer chose at hire, and they were the only two
                rungs of that ladder an owner actually accepted. */}
            <DefList rows={[
              ['Instance', item?.worker_instance_id],
              ['Package release', item?.release_ref],
              ['Entitlement', item?.entitlement_ref],
              ['Install', item?.install_id],
              ['Runtime assignment', item?.runtime_assignment_ref, { owner: 'runtime owner projection' }],
              ['Runtime profile', item?.runtime_profile_ref],
              ['Persistence profile', item?.persistence_profile_ref],
              ['Runtime observed at', item?.runtime_observed_at, { owner: 'runtime observation yet' }],
              ['Hired', formatDate(item?.created_at), { mono: false }],
            ]} />
          </div>

          <SubHeading id="act" className="mt-10">Act on this deployment</SubHeading>
          <div className="mt-3 flex flex-wrap gap-2">
            {['suspend', 'resume', 'archive', 'restore'].map((transition) => (
              <Button
                key={transition}
                variant="secondary"
                disabled={!!busy}
                onClick={() => act(transition, () => api(`/v1/marketplace/instances/${instanceId}/${transition}`, { method: 'POST', body: { reason: 'operator request' } }))}
              >
                {busy === transition ? 'Requesting…' : transition}
              </Button>
            ))}
          </div>
          <p className="mt-2 text-xs leading-5 text-slate-500">
            Each transition is a request admitted by the runtime owner. Observed state changes only when the owner reports it.
          </p>
        </section>

        <aside className="h-fit space-y-6 lg:col-start-2 lg:row-start-1 lg:row-span-2">
          {/* Canon puts spend in this cockpit. The subscription record already
              carries the amount, the cadence and the receipt that admitted it;
              the page was rendering only the word "active". What no owner
              produces is what this deployment has actually consumed, which is a
              different question from what it costs. */}
          <Panel>
            <div className="flex flex-wrap items-baseline justify-between gap-2">
              <h2 id="spend" className="font-bold text-slate-900">Spend</h2>
              <State label="subscription" value={item?.subscription?.state} />
            </div>
            <p className="mt-3 text-2xl font-black text-slate-950">
              {formatAmount(item?.subscription?.amount)}
              <span className="ml-1.5 text-sm font-medium text-slate-500">
                {formatCadence(item?.subscription?.amount)}
              </span>
            </p>
            <p className="mt-2 break-all font-mono text-[10px] leading-4 text-slate-500"
               title={item?.subscription?.owner_receipt_ref}>
              {item?.subscription?.owner_receipt_ref}
            </p>
            <div className="mt-3 border-t border-slate-100 pt-3">
              <Gap wrap label="Metered usage against this price" owner="usage metering projection" />
            </div>
          </Panel>

          <Panel>
            <h2 className="font-bold text-slate-900">Integration authority</h2>
            <p className="mt-1 text-xs leading-5 text-slate-500">Only credential references and exact scopes enter marketplace state. Secrets are refused.</p>
            <div className="mt-4 space-y-3">
              <label className="block">
                <span className="text-sm font-semibold text-slate-800">Surface</span>
                <select
                  className={cx(inputStyles, 'mt-1.5')}
                  value={integration.integration_surface}
                  disabled={surfacesField.state !== 'disclosed'}
                  onChange={(event) => setIntegration({ ...integration, integration_surface: event.target.value })}
                >
                  {/* The placeholder states which of the three it is. "No
                      surface can be offered" was one sentence for all of them,
                      and under a read still in flight it reported an absence
                      that nothing had established. */}
                  <option value="">
                    {surfacesField.state === 'disclosed' ? 'Choose a declared surface…'
                      : surfacesField.state === 'reading' ? 'Reading what the package declares…'
                      : 'Cannot be offered — see below'}
                  </option>
                  {declaredSurfaces.map((surface) => (
                    <option key={surface} value={surface}>{surface}</option>
                  ))}
                </select>
                {surfacesField.state !== 'disclosed' && <DisclosureNote className="mt-1.5" state={surfacesField.state} />}
              </label>
              <Field label="Credential grant ref" value={integration.credential_ref} onChange={(credential_ref) => setIntegration({ ...integration, credential_ref })} />
              <fieldset>
                <legend className="text-sm font-semibold text-slate-800">Scopes</legend>
                {/* None selected to begin with. A grant is the ceiling on what
                    this worker may do inside a system you own, and a form that
                    pre-ticks the whole manifest hands over the maximum by
                    default. The package's declaration is the ceiling; the choice
                    inside it is the buyer's. */}
                <p className="mt-1 text-xs leading-5 text-slate-500">
                  Declared by the package. Grant the ones this binding needs; the domain refuses any scope the
                  package does not declare.
                </p>
                <div className="mt-2 space-y-1.5">
                  {scopesField.state !== 'disclosed' ? <DisclosureNote state={scopesField.state} />
                    : declaredScopes.length ? declaredScopes.map((scope) => (
                    <label key={scope} className="flex items-center gap-2 text-xs text-slate-700">
                      <input
                        type="checkbox"
                        className="h-4 w-4 rounded border-slate-300"
                        checked={integration.scope_refs.includes(scope)}
                        onChange={(event) => setIntegration({
                          ...integration,
                          scope_refs: event.target.checked
                            ? [...integration.scope_refs, scope]
                            : integration.scope_refs.filter((item) => item !== scope),
                        })}
                      />
                      <span className="font-mono">{scope}</span>
                    </label>
                  )) : (
                      <p className="text-xs leading-5 text-slate-600">The admitted package declares no authority scopes.</p>
                    )}
                </div>
              </fieldset>
              <Button
                className="w-full"
                disabled={!!busy || !integration.integration_surface || !integration.scope_refs.length}
                onClick={() => act('bind', () => api(`/v1/marketplace/instances/${instanceId}/integrations`, { method: 'POST', body: integration }))}
              >
                {busy === 'bind' ? 'Binding…' : 'Bind grant'}
              </Button>
            </div>
          </Panel>

          {item?.integrations?.length > 0 && (
            <div className="overflow-hidden rounded-xl border border-slate-200 bg-white">
              {item.integrations.map((binding) => (
                <div className="border-b border-slate-100 p-4 last:border-b-0" key={binding.binding_id}>
                  <div className="flex items-center justify-between gap-2">
                    <strong className="text-sm text-slate-900">{binding.integration_surface}</strong>
                    <State label="binding" value={binding.state} />
                  </div>
                  <p className="mt-1.5 break-all font-mono text-[10px] text-slate-500" title={binding.authority_receipt_ref}>
                    {binding.authority_receipt_ref}
                  </p>
                  {binding.state !== 'ready' && (
                    <Button
                      variant="secondary"
                      className="mt-3 w-full"
                      disabled={!!busy}
                      onClick={() => act(binding.binding_id, () => api(`/v1/marketplace/instances/${instanceId}/integrations/${binding.binding_id}/test`, { method: 'POST', body: {} }))}
                    >
                      {busy === binding.binding_id ? 'Testing…' : 'Test binding'}
                    </Button>
                  )}
                </div>
              ))}
            </div>
          )}

        </aside>

        <section className="min-w-0 lg:col-start-1 lg:row-start-2">

          {/* Readiness governs what this deployment may do at all, so it sits
              between the controls and the change tiers rather than below both. */}
          <SubHeading className="mt-10">Readiness</SubHeading>
          <p className="mt-1.5 max-w-[70ch] text-sm leading-6 text-slate-600">
            A managed instance runs only in the mode its completed onboarding plan admits. Missing required
            connectors, authority grants, runtime assignments or safety gates must block activation, or force
            a mode that says so.
          </p>

          <div className="mt-4 grid gap-3 sm:grid-cols-2">
            <Panel className="p-4">
              <p className="text-sm font-semibold text-slate-800">Reported by the runtime</p>
              <p className="mt-1 text-xs leading-5 text-slate-500">
                The runtime&rsquo;s own word about its last check. Not a mode, and not from the same vocabulary.
              </p>
              <div className="mt-2.5"><State label="readiness" value={item?.readiness} /></div>
            </Panel>
            {/* The plan is compiled from the package's declarations and this
                deployment's own bindings, so the mode is derived rather than
                reported — and where it cannot be derived, the panel says which
                of the two reasons applies instead of showing a mode. */}
            <Panel className="p-4">
              <p className="text-sm font-semibold text-slate-800">Mode admitted by the plan</p>
              <p className="mt-1 text-xs leading-5 text-slate-500">
                Which of the five modes this deployment was admitted to run in.
              </p>
              <div className="mt-2.5">
                {plan.loading ? <ReadState status="reading" />
                  : plan.error ? <ReadState status="unreadable" />
                  : plan.value?.compiled === false
                    ? <p className="text-xs leading-5 text-slate-600">
                        The admitted composition behind this deployment could not be reached, so no plan was compiled.
                      </p>
                  : plan.value?.readiness?.mode
                    ? <State label="mode" value={plan.value.readiness.mode} />
                    : (
                      <p className="max-w-[52ch] text-xs leading-5 text-slate-600">
                        No mode. Nothing required is missing and not every step is done, and the package declares
                        no requirement level for the steps that remain — so a mode here would be this surface
                        deciding how much of a publisher&rsquo;s manifest is optional.
                      </p>
                    )}
              </div>
              <div className="mt-3 border-t border-slate-100 pt-2.5">
                <TermList items={READINESS_MODES} />
              </div>
            </Panel>
          </div>

          <OnboardingSteps plan={plan} />

          <div className="mt-3">
            <Drawer title="What an onboarding plan is compiled from" hint="canon shape">
              <p className="max-w-[70ch] text-sm leading-6 text-slate-600">
                A plan is compiled from the seller&rsquo;s manifest and the buyer&rsquo;s environment rather
                than hardcoded per worker, so its shape is a vocabulary. Every step carries one value from
                each of the three axes below.
              </p>
              <div className="mt-4">
                <Eyebrow>Step kinds</Eyebrow>
                <TermList className="mt-1.5" items={PLAN_STEP_KINDS} />
              </div>
              {PLAN_AXES.map(([axis, values]) => (
                <div key={axis} className="mt-4">
                  <Eyebrow>{axis}</Eyebrow>
                  <TermList className="mt-1.5" items={values} />
                </div>
              ))}
              {plan.value?.uncompiled_step_kinds ? (
                <div className="mt-4 border-t border-slate-100 pt-3">
                  <Eyebrow>Not compiled here, and why</Eyebrow>
                  <dl className="mt-1.5 space-y-1 text-xs leading-5 text-slate-600">
                    {Object.entries(plan.value.uncompiled_step_kinds).map(([kind, reason]) => (
                      <div key={kind} className="flex flex-wrap gap-x-2">
                        <dt className="font-mono text-[11px] text-slate-700">{kind}</dt>
                        <dd className="min-w-0 flex-1">{reason}</dd>
                      </div>
                    ))}
                  </dl>
                </div>
              ) : null}
              <p className="mt-4 max-w-[70ch] border-t border-slate-100 pt-3 text-xs leading-5 text-slate-500">
                A step may be fulfilled automatically only where the platform can safely discover, reuse or
                prefill the state. External login, admin consent, destructive or regulated scopes,
                provider-trust acceptance, declassification, custom credentials, physical action, a high-risk
                approval, or a channel that is also a work integration all require a person.
              </p>
            </Drawer>
          </div>

          <div className="mt-12"><ChangeLifecycle revision={item?.config_revision} /></div>

          {/* Canon closes the hire ladder with what the buyer receives: "receipts,
              console URL, API/MCP/model-compatible exports, and revoke
              controls." Receipts are below and the lifecycle requests above are
              real; the rest name their owners. */}
          <SubHeading className="mt-10">Reaching this worker</SubHeading>
          <div className="mt-3 grid gap-3 sm:grid-cols-2">
            <Gap block label="Managed console URL" owner="managed console projection" />
            <Gap block label="Live logs and console output" owner="runtime log owner" />
            {/* "Exports" collided with the lifecycle export two sections down —
                two unavailabilities, two owners, no cross-reference, reading as
                the page repeating itself with a fresh excuse. These are
                endpoints; the other one is a copy of your data. */}
            <Gap block label="API, MCP, and model-compatible endpoints" owner="instance endpoint owner" />
            <Gap block label="Revoke credentials and authority" owner="authority revocation endpoint" />
          </div>
          <p className="mt-2 text-xs leading-5 text-slate-500">
            Stopping a deployment does not revoke a credential grant, which is a separate act against the
            authority that issued it.
          </p>

          {/* Canon: "Payment lapse, provider exit, archive, restore, export,
              delete, and forget states are first-class lifecycle transitions;
              they cannot be hidden behind generic billing or console state."
              This console offered suspend, resume, archive and restore, and
              nothing else — so export, three distinct deletions and a payment
              lapse were all hidden behind exactly the generic console state
              canon forbids. */}
          <SubHeading className="mt-10">Ending this deployment</SubHeading>
          <p className="mt-1.5 max-w-[70ch] text-sm leading-6 text-slate-600">
            Stopping, archiving, exporting and deleting are different acts with different consequences, and
            canon distinguishes three deletions rather than one. What each does <em>not</em> do is the half
            that matters; it is the reason they are separate.
          </p>

          <div className="mt-4 overflow-hidden rounded-xl border border-slate-200 bg-white">
            <dl className="divide-y divide-slate-100">
              {ENDINGS.map((ending) => (
                <div key={ending.key} className="grid gap-1 px-4 py-3.5 md:grid-cols-[210px_minmax(0,1fr)] md:gap-5">
                  {/* The marker wraps inside its own column. Inline, it is a
                      single truncating line that overran the label column and
                      printed across the description beside it. */}
                  <dt className="min-w-0">
                    <span className="block text-sm font-bold text-slate-900">{ending.title}</span>
                    {/* Availability was signalled only by its own absence: four
                        rows carried a marker and the two that work carried
                        nothing, so on a page where a marker means "dead", being
                        alive was rendered as blank space. The live rows say so,
                        and say where the control is — it sits two sections up. */}
                    {ending.live ? (
                      <a href="#act" className="mt-1 inline-flex min-h-11 items-center gap-1 py-2 text-[11px] font-semibold text-blue-700 hover:underline">
                        Available above
                        <span aria-hidden="true">↑</span>
                      </a>
                    ) : (
                      <span className="mt-1 block"><Gap wrap label="Not available" owner={ending.owner} /></span>
                    )}
                  </dt>
                  <dd className="min-w-0">
                    <p className="max-w-[62ch] text-xs leading-5 text-slate-600">{ending.does}</p>
                    {/* The section's thesis is that this half is the one that
                        matters, and it was carried by one step of grey. */}
                    <p className="mt-1.5 max-w-[62ch] border-l-2 border-slate-200 pl-2.5 text-xs leading-5 text-slate-600">
                      {ending.doesNot}
                    </p>
                  </dd>
                </div>
              ))}
            </dl>
          </div>

          {/* A payment lapse is a state, not an act — and canon gives it a
              consequence this console can state exactly. */}
          {/* The subscription's state is already a chip in the Spend card; one
              state rendered twice on one screen is the duplication this surface
              audits for elsewhere. What is not stated anywhere else is the
              consequence canon attaches to a lapse.
              The pointer carried a sentence explaining that the rail reflows
              below on a phone — an apology for a layout that has since been
              fixed, and, once it was, a false one, with a ↓ glyph aimed away
              from its target. The layout stopped needing the apology, so the
              apology goes. */}
          <p className="mt-3 max-w-[70ch] text-xs leading-5 text-slate-600">
            <span className="font-semibold text-slate-800">Payment lapse</span> is a lifecycle state in its own
            right, not a billing message: it freezes new billable work and high-risk standing orders. This
            deployment&rsquo;s subscription state is in{' '}
            <a href="#spend" className="font-semibold text-blue-700 hover:underline">the Spend panel</a>.
          </p>

          {/* Canon puts the receipt rail beside the map, so they sit together:
              the map shows the shape, the rail shows what actually happened. */}
          <div className="mt-12">
            <AgentMap instance={item} receipts={receipts} />
          </div>

          <SubHeading className="mt-10">Receipt chain</SubHeading>
          {/* A failed read gets the panel the rest of the estate gives a failed
              read: amber, the code the domain returned, the owner that broke if
              one was named, and the offer to re-run this one read. It had been a
              single grey sentence inside a card with the same border, padding and
              ground as the resolved-empty state, which is how a reviewer came to
              read an outage as a benign empty list. */}
          {chain.status === 'unreadable' ? (
            <div className="mt-3">
              <Unreadable error={receipts.error} subject="The receipt chain for this deployment"
                          onRetry={receipts.reload} />
            </div>
          ) : (
          <div className="mt-3 overflow-hidden rounded-xl border border-slate-200 bg-white">
            {chain.status === 'read' && chain.items.length ? (
              <ul className="divide-y divide-slate-100">
                {chain.items.map((receipt) => (
                  <li key={receipt.receipt_ref} className="flex flex-wrap items-center justify-between gap-2 px-4 py-3">
                    <div className="min-w-0">
                      <p className="truncate text-sm font-semibold text-slate-800">{receipt.action}</p>
                      <p className="truncate font-mono text-[11px] text-slate-500" title={receipt.receipt_ref}>
                        #{receipt.sequence} · {receipt.receipt_ref}
                      </p>
                    </div>
                    <span className="shrink-0 font-mono text-[11px] text-slate-500">{new Date(receipt.occurred_at).toLocaleTimeString()}</span>
                  </li>
                ))}
              </ul>
            ) : (
              // "No receipts recorded against this instance ref." over a failed
              // read is the exact defect the Unreadable panel was built for,
              // surviving at a call site nothing had faulted: the audit's glob
              // stopped at the query string, so this read — the one the whole
              // page hangs off — had never once been broken under test.
              // A read still moving had been a centred grey sentence in a plain
              // card — the same object, in the same place, as a settled empty
              // result. It keeps the failure panel's geometry and drops its
              // alarm: a rail and a glyph say "this is a state of the read",
              // slate rather than amber says "and nothing has gone wrong".
              chain.status === 'read' ? (
                <p className="px-4 py-6 text-center text-sm text-slate-500">
                  No receipts recorded against this instance ref.
                </p>
              ) : (
                // slate-400, not the slate-300 every card hairline uses: a
                // reviewer measured the rail as "the same slate as every card's
                // hairline border, just wider" and could not tell the panel from
                // an ordinary one at arm's length. Not amber, which the same
                // review proposed and its own second rule forbids — nothing has
                // gone wrong while a read is still moving, and alarm spent here
                // cannot be spent on the failure two states away.
                <div className="border-l-[3px] border-slate-400 bg-slate-50 px-4 py-5">
                  <ReadState
                    size="panel"
                    status={chain.status}
                    label={chain.status === 'reading'
                      ? 'Reading this deployment\u2019s receipt chain…'
                      : 'The read completed without reporting a receipt chain.'}
                  />
                </div>
              )
            )}
          </div>
          )}
        </section>

      </div>
    </main>
  );
}

/* ── routes ─────────────────────────────────────────────────────────── */

function NotFound() {
  return (
    <main className="mx-auto max-w-3xl px-4 py-24 text-center">
      <p className="text-xs font-bold uppercase tracking-[.18em] text-blue-700">404</p>
      <h1 className="mt-2 text-3xl font-black tracking-tight text-slate-950">Route not found.</h1>
      <p className="mt-2 text-sm text-slate-600">No product route serves this path.</p>
      <Link className={cx(buttonStyles.primary, 'mt-6')} to="/agents">Return to Explore</Link>
    </main>
  );
}

export default function MarketplaceApp() {
  return (
    <Shell>
      <Routes>
        <Route path="/" element={<CategoryHome />} />
        <Route path="/agents" element={<Workers />} />
        {CATEGORIES.map(([route]) => (
          <Route key={route} path={route} element={<CategoryPage slug={route} />} />
        ))}
        <Route path="/agents/:workerId" element={<WorkerDetail />} />
        <Route path="/agents/:workerId/hire" element={<HireFlow />} />
        <Route path="/console" element={<ConsoleLayout><ConsoleHome /></ConsoleLayout>} />
        <Route path="/templates" element={<ConsoleLayout><Templates /></ConsoleLayout>} />
        <Route path="/builder" element={<ConsoleLayout><Builder /></ConsoleLayout>} />
        <Route path="/freelance" element={<ConsoleLayout><Freelance /></ConsoleLayout>} />
        <Route path="/my-workers" element={<ConsoleLayout><MyWorkers /></ConsoleLayout>} />
        <Route path="/my-workers/add" element={<ConsoleLayout><AddYourAgent /></ConsoleLayout>} />
        <Route path="/instances" element={<ConsoleLayout><Instances /></ConsoleLayout>} />
        <Route path="/instances/:instanceId" element={<ConsoleLayout><InstanceDetail /></ConsoleLayout>} />
        <Route path="*" element={<NotFound />} />
      </Routes>
    </Shell>
  );
}

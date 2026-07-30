import { a as e } from "./rolldown-runtime-CGYlQKCx.js";
import { n as t } from "./@mux-DLaEVubF.js";
import {
  $l as n,
  Bg as r,
  Cl as i,
  El as a,
  Pg as o,
  Ql as s,
  Tl as c,
  Xl as l,
  Zl as u,
  au as d,
  cm as f,
  eu as p,
  iu as m,
  nu as h,
  ou as g,
  ru as _,
  su as v,
  tf as y,
  tu as b,
  v_ as x,
  wl as S,
} from "./vendor-DAwbZtf0.js";
import { t as C } from "./cn-DppMFCU8.js";
import { t as w } from "./radix-body-pointer-events-DJX9Yyw0.js";
import { n as T } from "./utils-C9bSuXia.js";
import { t as E } from "./tooltip-6hqVQbwq.js";
import { r as D } from "./dropdown-menu-D3UmjGpQ.js";
import { t as O } from "./use-is-mobile-viewport-Chw6u8QP.js";
import { t as ee } from "./IconChevronDownSmall-9zzbc23a.js";
var k = `size-4 shrink-0 text-content-secondary`,
  A = `size-4 shrink-0 text-content-secondary flex items-center justify-center`,
  j = new Set([`ioi-browser`, `ioi-swe-agent`, `codex-exec-agent`, `VS Code Server`]),
  M = e(t(), 1),
  N = x(),
  P = ({ modal: e, onOpenChange: t, ...n }) => {
    let r = w({ modal: e ?? !0, onOpenChange: t });
    return (0, N.jsx)(h, { ...n, modal: e, onOpenChange: r });
  },
  F = v,
  I = n,
  L = m,
  R = p,
  z = M.forwardRef(({ className: e, ...t }, n) =>
    (0, N.jsx)(_, { ref: n, className: C(`my-1 h-px bg-content-tertiary/20`, e), ...t }),
  );
z.displayName = u.displayName;
var B = M.forwardRef(({ className: e, onContextMenu: t, ...n }, r) =>
  (0, N.jsx)(l, {
    ref: r,
    className: C(
      `z-50 w-64 min-w-[8rem] overflow-hidden rounded-lg`,
      `border border-border-base bg-surface-popover p-0 shadow first:pt-1 last:pb-1`,
      `outline-none focus:outline-none focus-visible:ring-0`,
      `data-[state=open]:animate-in data-[state=closed]:animate-out duration-75`,
      `data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0`,
      `data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95`,
      `data-[side=bottom]:slide-in-from-top-2 data-[side=left]:slide-in-from-right-2 data-[side=right]:slide-in-from-left-2 data-[side=top]:slide-in-from-bottom-2`,
      `data-[state=closed]:data-[side=bottom]:slide-out-to-top-2 data-[state=closed]:data-[side=left]:slide-out-to-right-2 data-[state=closed]:data-[side=right]:slide-out-to-left-2 data-[state=closed]:data-[side=top]:slide-out-to-bottom-2`,
      e,
    ),
    onContextMenu: (e) => {
      (e.preventDefault(), t?.(e));
    },
    ...n,
  }),
);
B.displayName = u.displayName;
var V = o(
    C(
      `relative flex cursor-default select-none items-center rounded px-2 py-1.5 text-sm`,
      `cursor-pointer hover:bg-surface-hover`,
      `text-base focus:bg-surface-hover mx-1 h-8`,
      `focus:bg-surface-hover focus:text-content-primary focus-visible:ring-0`,
      `data-[disabled]:pointer-events-none data-[disabled]:opacity-50`,
    ),
    {
      variants: {
        variant: {
          default: ``,
          destructive: `text-content-destructive hover:text-content-destructive focus:text-content-destructive`,
        },
      },
      defaultVariants: { variant: `default` },
    },
  ),
  H = M.forwardRef(({ onClick: e, className: t, variant: n, LeadingIcon: r, children: i, ...a }, o) =>
    (0, N.jsxs)(u, {
      ref: o,
      className: C(V({ variant: n }), t),
      onClick: (t) => {
        e && (t.stopPropagation(), setTimeout(() => e(t), 0));
      },
      ...a,
      children: [r ? (0, N.jsx)(`span`, { className: `mr-2`, children: (0, N.jsx)(r, { size: `sm` }) }) : null, i],
    }),
  );
H.displayName = u.displayName;
var U = M.forwardRef(({ className: e, inset: t, children: n, ...r }, i) =>
  (0, N.jsxs)(g, {
    ref: i,
    className: C(V({ variant: `default` }), `data-[state=open]:bg-surface-hover`, t && `pl-8`, e),
    ...r,
    children: [n, (0, N.jsx)(y, { className: `ml-auto size-4` })],
  }),
);
U.displayName = g.displayName;
var W = M.forwardRef(({ className: e, ...t }, n) =>
  (0, N.jsx)(d, {
    ref: n,
    className: C(
      `z-50 min-w-[8rem] overflow-hidden rounded-lg border border-border-base bg-surface-popover p-0 py-1 shadow`,
      `outline-none focus:outline-none focus-visible:ring-0`,
      `data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0`,
      `data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95`,
      `data-[side=bottom]:slide-in-from-top-2 data-[side=left]:slide-in-from-right-2`,
      `data-[side=right]:slide-in-from-left-2 data-[side=top]:slide-in-from-bottom-2`,
      e,
    ),
    ...t,
  }),
);
W.displayName = d.displayName;
var G = M.forwardRef(({ className: e, children: t, ...n }, r) =>
  (0, N.jsxs)(b, {
    ref: r,
    className: C(V({ variant: `default` }), `pl-8`, e),
    ...n,
    children: [
      (0, N.jsx)(`span`, {
        className: `absolute left-2 flex h-3.5 w-3.5 items-center justify-center`,
        children: (0, N.jsx)(s, { children: (0, N.jsx)(f, { className: `size-4` }) }),
      }),
      t,
    ],
  }),
);
G.displayName = b.displayName;
var te = Object.assign(P, {
    Trigger: F,
    Portal: I,
    Sub: L,
    RadioGroup: R,
    Separator: z,
    Content: B,
    Item: H,
    SubTrigger: U,
    SubContent: W,
    RadioItem: G,
  }),
  K = M.forwardRef(({ children: e, className: t, borderClassName: n, size: r = `md` }, i) => {
    let a = (0, M.useRef)(null),
      o = (0, M.useRef)(null),
      s = (0, M.useRef)(null);
    M.useImperativeHandle(i, () => a.current);
    let c = (0, M.useCallback)(() => {
        let e = a.current,
          t = o.current,
          n = s.current;
        if (!e || !t || !n) return;
        let { scrollLeft: r, scrollWidth: i, clientWidth: c } = e;
        ((t.style.opacity = r > 2 ? `1` : `0`), (n.style.opacity = i - r - c > 2 ? `1` : `0`));
      }, []),
      l = (0, M.useCallback)((e) => {
        let t = a.current;
        if (t) {
          let n = t.getBoundingClientRect(),
            r = e.getBoundingClientRect();
          if (r.left >= n.left && r.right <= n.right) return;
        }
        let n = window.matchMedia?.(`(pointer: coarse)`).matches ? `auto` : `smooth`;
        e.scrollIntoView({ behavior: n, block: `nearest`, inline: `nearest` });
      }, []);
    return (
      (0, M.useEffect)(() => {
        let e = a.current;
        if (!e) return;
        c();
        let t = new MutationObserver(() => {
          let t = e.querySelector(`[data-state="active"]`);
          (t && l(t), c());
        });
        t.observe(e, { attributes: !0, attributeFilter: [`data-state`], subtree: !0 });
        let n = () => {
          c();
        };
        e.addEventListener(`scroll`, n, { passive: !0 });
        let r = (e) => {
          let t = e.target;
          t instanceof HTMLElement && t.role === `tab` && l(t);
        };
        return (
          e.addEventListener(`focusin`, r),
          () => {
            (t.disconnect(), e.removeEventListener(`scroll`, n), e.removeEventListener(`focusin`, r));
          }
        );
      }, [c, l]),
      (0, M.useEffect)(() => {
        let e = a.current;
        if (!e) return;
        c();
        let t = new ResizeObserver(c);
        return (t.observe(e), () => t.disconnect());
      }, [c, e]),
      (0, N.jsxs)(`div`, {
        className: C(`relative min-w-0 overflow-x-clip`),
        children: [
          (0, N.jsx)(S, {
            ref: a,
            className: C(
              `scrollbar-hide relative flex items-center gap-1 overflow-x-auto`,
              r === `sm` ? `h-8` : `h-10`,
              `after:absolute after:bottom-0 after:left-0 after:right-0 after:h-px after:bg-border-base`,
              n,
              t,
            ),
            children: e,
          }),
          (0, N.jsx)(`div`, {
            ref: o,
            "aria-hidden": !0,
            className: `pointer-events-none absolute bottom-0 left-0 top-0 z-10 w-6 bg-gradient-to-r from-surface-glass to-transparent transition-opacity duration-150`,
            style: { opacity: 0 },
          }),
          (0, N.jsx)(`div`, {
            ref: s,
            "aria-hidden": !0,
            className: `pointer-events-none absolute bottom-0 right-0 top-0 z-10 w-6 bg-gradient-to-l from-surface-glass to-transparent transition-opacity duration-150`,
            style: { opacity: 0 },
          }),
        ],
      })
    );
  });
K.displayName = `ScrollableTabList`;
var q = T(r),
  J = (0, M.createContext)(`md`),
  Y = M.forwardRef(({ className: e, ...t }, n) =>
    (0, N.jsx)(c, { ref: n, activationMode: `manual`, className: C(`flex flex-col`, e), ...t }),
  );
Y.displayName = `Tabs`;
var X = M.forwardRef(({ className: e, children: t, size: n = `md`, ...r }, i) =>
  (0, N.jsx)(J.Provider, {
    value: n,
    children: (0, N.jsx)(S, {
      ref: i,
      className: C(
        `relative flex items-center gap-1`,
        n === `sm` ? `h-8` : `h-10`,
        `after:absolute after:bottom-0 after:left-0 after:right-0 after:h-px after:bg-border-base`,
        e,
      ),
      ...r,
      children: t,
    }),
  }),
);
X.displayName = `TabsList`;
var Z = M.forwardRef(
  (
    {
      className: e,
      LeadingIcon: t,
      counter: n,
      onClose: r,
      closeStyle: i = `overlay`,
      contextMenuContent: o,
      children: s,
      ...c
    },
    l,
  ) => {
    let u = (0, M.useContext)(J),
      d = t ? (0, N.jsx)(t, { size: `sm`, "aria-hidden": !0, className: `shrink-0` }) : null,
      f = typeof s == `string` ? s : void 0,
      p = (0, M.useRef)(null),
      m = (0, M.useRef)(null),
      h = (0, M.useRef)(null),
      [g, _] = (0, M.useState)(!1),
      [v, y] = (0, M.useState)(!1),
      [b, x] = (0, M.useState)(!1);
    (0, M.useEffect)(() => {
      let e = h.current;
      if (!e) return;
      let t = () => x(e.scrollWidth > e.clientWidth);
      t();
      let n = new ResizeObserver(t);
      return (n.observe(e), () => n.disconnect());
    }, [s]);
    let S = !!o,
      w = !!r,
      T = C(
        `flex items-center justify-center rounded-sm`,
        `outline-none focus-visible:outline focus-visible:outline-1 focus-visible:-outline-offset-1 focus-visible:outline-border-brand`,
      ),
      O =
        S &&
        (0, N.jsx)(D.Trigger, {
          asChild: !0,
          children: (0, N.jsx)(`span`, {
            ref: m,
            tabIndex: -1,
            "aria-hidden": `true`,
            className: C(
              `flex shrink-0 cursor-pointer items-center justify-center self-stretch rounded-r-md text-content-tertiary`,
              `hover:bg-surface-03 hover:text-content-primary`,
              g && `bg-surface-03 text-content-primary`,
              u === `sm` ? `-mr-1.5 pr-1.5` : `-mr-2 pr-2`,
              `outline-none focus-visible:outline focus-visible:outline-1 focus-visible:-outline-offset-1 focus-visible:outline-border-brand`,
            ),
            "data-tracking-id": `tab-options`,
            onClick: (e) => e.stopPropagation(),
            onPointerDown: (e) => e.stopPropagation(),
            children: (0, N.jsx)(ee, { size: `sm` }),
          }),
        }),
      k =
        w &&
        !S &&
        i === `overlay` &&
        (0, N.jsx)(`span`, {
          className: C(
            `absolute bottom-px right-px top-px flex items-center gap-0.5 pl-4 pr-1`,
            `rounded-r-md bg-[image:linear-gradient(to_right,transparent,var(--tab-fade)_40%,var(--tab-fade))]`,
            `opacity-0 transition-opacity`,
            `group-hover/tab:opacity-100 group-focus-visible/tab:opacity-100`,
          ),
          children: (0, N.jsx)(`span`, {
            role: `button`,
            tabIndex: -1,
            className: C(`text-content-tertiary hover:text-content-primary`, T),
            "data-tracking-id": `tab-close`,
            onClick: (e) => {
              (e.stopPropagation(), e.preventDefault(), r());
            },
            onPointerDown: (e) => e.stopPropagation(),
            onMouseDown: (e) => e.stopPropagation(),
            "aria-label": f ? `Close ${f}` : `Close tab`,
            children: (0, N.jsx)(q, { size: `sm` }),
          }),
        }),
      A =
        w &&
        !S &&
        i === `inline-active` &&
        (0, N.jsx)(`span`, {
          role: `button`,
          tabIndex: -1,
          className: C(
            `hidden shrink-0 text-content-tertiary hover:text-content-primary`,
            `group-data-[state=active]/tab:flex`,
            T,
          ),
          "data-tracking-id": `tab-close-inline`,
          onClick: (e) => {
            (e.stopPropagation(), e.preventDefault(), r());
          },
          onPointerDown: (e) => e.stopPropagation(),
          onMouseDown: (e) => e.stopPropagation(),
          "aria-label": f ? `Close ${f}` : `Close tab`,
          children: (0, N.jsx)(q, { size: `sm` }),
        }),
      j = (0, N.jsx)(a, {
        ref: (e) => {
          ((p.current = e), typeof l == `function` ? l(e) : l && (l.current = e));
        },
        className: C(
          `group/tab relative flex h-full max-w-60 shrink-0 items-center font-medium transition-colors`,
          u === `sm` ? `text-sm` : `text-base`,
          `focus-visible:outline-none focus-visible:ring-0`,
          `text-content-strong hover:text-content-primary`,
          `data-[state=active]:text-content-primary`,
          `after:absolute after:bottom-0 after:left-0 after:right-0 after:z-10 after:h-0.5 after:scale-x-0 after:bg-content-primary`,
          `data-[state=active]:after:scale-x-100`,
          `disabled:pointer-events-none disabled:opacity-50`,
          g && `text-content-primary`,
          e,
        ),
        ...c,
        onKeyDown: (e) => {
          (c.onKeyDown?.(e),
            (e.key === `Delete` || e.key === `Backspace`) && r
              ? (e.stopPropagation(), e.preventDefault(), r())
              : e.key === `ArrowDown` && S && (e.stopPropagation(), e.preventDefault(), y(!0), _(!0)));
        },
        onMouseDown: (e) => {
          e.button === 1 && r && e.preventDefault();
        },
        onAuxClick: (e) => {
          e.button === 1 && r && (e.preventDefault(), e.stopPropagation(), r());
        },
        children: (0, N.jsxs)(`span`, {
          className: C(
            `relative flex min-w-0 items-center overflow-hidden rounded-md transition-colors`,
            u === `sm` ? `gap-1 px-1.5 py-1` : `gap-1.5 px-2 py-1.5`,
            `group-hover/tab:bg-surface-02`,
            g && `bg-surface-02`,
            v && `outline outline-1 -outline-offset-1 outline-border-brand`,
            `group-focus-visible/tab:bg-surface-02 group-focus-visible/tab:outline group-focus-visible/tab:outline-1 group-focus-visible/tab:-outline-offset-1 group-focus-visible/tab:outline-border-brand`,
          ),
          style: {
            "--tab-fade": `color-mix(in srgb, rgb(var(--surface-muted)) calc(var(--surface-muted-opacity) * 100%), rgb(var(--surface-primary)))`,
          },
          children: [
            d,
            (0, N.jsx)(E, {
              content: b ? f : void 0,
              children: (0, N.jsx)(`span`, { ref: h, className: `truncate`, children: s }),
            }),
            n,
            A,
            k,
            O,
          ],
        }),
      }),
      P = (0, M.useCallback)(() => {
        if (!p.current || !m.current) return 0;
        let e = p.current.getBoundingClientRect(),
          t = m.current.getBoundingClientRect();
        return e.left - t.left;
      }, []);
    return S
      ? (0, N.jsxs)(D, {
          open: g,
          onOpenChange: (e) => {
            _(e);
          },
          children: [
            (0, N.jsx)(`span`, {
              className: C(`flex h-full max-w-60 shrink-0 items-center`, e),
              onContextMenu: (e) => {
                (e.preventDefault(), _(!0));
              },
              children: j,
            }),
            (0, N.jsxs)(D.Content, {
              align: `start`,
              alignOffset: P(),
              onKeyDown: (e) => {
                if (e.key === `ArrowUp`) {
                  let t = e.currentTarget.querySelectorAll(`[role='menuitem']`);
                  t.length > 0 && document.activeElement === t[0] && (e.preventDefault(), _(!1));
                }
              },
              onCloseAutoFocus: (e) => {
                (e.preventDefault(), p.current?.focus(), requestAnimationFrame(() => y(!1)));
              },
              children: [
                o,
                r &&
                  (0, N.jsxs)(N.Fragment, {
                    children: [
                      (0, N.jsx)(D.Separator, {}),
                      (0, N.jsx)(D.Item, {
                        variant: `destructive`,
                        "data-tracking-id": `tab-close-menu`,
                        onClick: r,
                        children: `Close`,
                      }),
                    ],
                  }),
              ],
            }),
          ],
        })
      : j;
  },
);
Z.displayName = `TabsTrigger`;
var Q = M.forwardRef(({ className: e, ...t }, n) =>
  (0, N.jsx)(i, {
    ref: n,
    className: C(
      `focus-visible:outline-none focus-visible:ring-0`,
      `data-[state=active]:duration-200 data-[state=active]:animate-in data-[state=active]:fade-in-0`,
      e,
    ),
    ...t,
  }),
);
Q.displayName = `TabsContent`;
var $ = ({ className: e }) =>
  (0, N.jsx)(`div`, { "aria-hidden": !0, className: C(`mx-1 h-4 w-px shrink-0 self-center bg-border-subtle`, e) });
$.displayName = `TabsSeparator`;
var ne = Object.assign(Y, { List: X, Trigger: Z, Content: Q, Separator: $ });
function re() {
  let { isMobileViewport: e } = O();
  return !e && !window.isWebview;
}
export { j as a, te as i, ne as n, k as o, K as r, A as s, re as t };

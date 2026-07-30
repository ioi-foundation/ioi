import { a as e } from "./rolldown-runtime-CGYlQKCx.js";
import { n as t } from "./@mux-DLaEVubF.js";
import {
  Hp as n,
  Qp as r,
  Sh as i,
  Xm as a,
  Yg as o,
  Ym as s,
  ch as c,
  cm as l,
  dh as u,
  lh as d,
  sh as f,
  uh as p,
  v_ as m,
} from "./vendor-DAwbZtf0.js";
import { a as h } from "./button-6YP03Qf2.js";
import { t as g } from "./cn-DppMFCU8.js";
import { t as _ } from "./text-fFCFeCas.js";
var v = e(t(), 1),
  y = e(o(), 1),
  b = m(),
  x = `Select.Item`,
  S = `Select.Item.Icon`,
  C = `Select.Item.Description`,
  w = `Select.Footer`,
  T = `Select.Value`,
  E = `Select.ValueLabel`,
  D = (0, v.createContext)(new Map()),
  O = (e) => e.type.displayName,
  k = ({ children: e, className: t, ...n }) =>
    (0, b.jsx)(`span`, { className: g(`text-content-muted`, t), ...n, children: e });
k.displayName = `Select.Placeholder`;
var A = ({ children: e, className: t, ...n }) =>
  (0, b.jsx)(`div`, { className: g(`-mx-1 mt-1 border-t border-border-base px-1 pt-1`, t), ...n, children: e });
A.displayName = w;
var j = (0, v.createContext)(null),
  M = (e) => {
    let t = (0, v.useContext)(j);
    if (!t) throw Error(`${e} must be used inside a <Select>.`);
    return t;
  },
  N = ({ children: e, className: t, ...n }) =>
    (0, b.jsx)(`span`, { className: g(`truncate text-base text-content-primary`, t), ...n, children: e });
N.displayName = E;
var P = ({ children: e, ...t }) => {
  let { value: n, label: r } = M(`Select.Value`);
  return e
    ? typeof e == `function`
      ? (0, b.jsx)(b.Fragment, { children: e(n ?? ``, r) })
      : (0, b.jsx)(b.Fragment, { children: e })
    : (0, b.jsx)(N, { ...t, children: r });
};
P.displayName = T;
var F = ({ children: e, className: t, ...n }) =>
  e ? (0, b.jsx)(`span`, { className: g(`flex-none`, t), ...n, children: e }) : null;
F.displayName = S;
var I = ({ children: e, className: t, ...n }) =>
  (0, b.jsx)(_, { className: g(`text-sm text-content-secondary`, t), ...n, children: e });
I.displayName = C;
var L = (e) => {
    let t = [];
    return (
      v.Children.forEach(e, (e) => {
        if ((0, v.isValidElement)(e)) {
          let t = O(e);
          if (t === S || t === C) return;
        }
        t.push(e);
      }),
      t.length === 1 ? t[0] : t
    );
  },
  R = (e) => {
    let t = L(e);
    if (typeof t == `string`) return t;
    if (typeof t == `number`) return String(t);
    let n = [];
    return (
      v.Children.forEach(t, (e) => {
        (typeof e == `string` || typeof e == `number`) && n.push(String(e));
      }),
      n.join(``) || ``
    );
  },
  z = ({ children: e, state: t, className: n, triggerWidth: r, sameWidth: i = !1, ...a }) => {
    let o = (0, v.useRef)(null),
      { popoverProps: s } = p({ ...a, popoverRef: o, isNonModal: !0 }, t),
      c = r ? (i ? { width: r } : { minWidth: r }) : {},
      l = () => {
        (t.close(), a.triggerRef.current?.focus());
      },
      d = a.triggerRef.current?.closest(`[role='dialog']`) ?? document.body;
    return (0, y.createPortal)(
      (0, b.jsxs)(b.Fragment, {
        children: [
          (0, b.jsx)(`div`, {
            style: { position: `fixed`, inset: 0, zIndex: 998, pointerEvents: `auto` },
            onPointerDown: (e) => {
              (e.target === e.currentTarget && e.preventDefault(), l());
            },
          }),
          (0, b.jsxs)(`div`, {
            ...s,
            ref: o,
            className: n,
            style: { ...s.style, ...c, pointerEvents: `auto` },
            children: [(0, b.jsx)(u, { onDismiss: l }), e, (0, b.jsx)(u, { onDismiss: l })],
          }),
        ],
      }),
      d,
    );
  },
  B = ({ menuProps: e, state: t }) => {
    let n = (0, v.useRef)(null),
      { listBoxProps: r } = d(e, t, n);
    return (0, b.jsx)(`ul`, {
      ...r,
      ref: n,
      className: `m-0 min-h-0 flex-1 list-none overflow-auto p-0`,
      style: { outline: `none` },
      children: [...t.collection].map((e) => (0, b.jsx)(V, { item: e, state: t }, e.key)),
    });
  },
  V = ({ item: e, state: t }) => {
    let n = (0, v.useRef)(null),
      { optionProps: r, isSelected: i, isFocused: a } = f({ key: e.key }, t, n),
      o = (0, v.useContext)(D).get(String(e.key));
    return (0, b.jsxs)(`li`, {
      ...r,
      ref: n,
      "data-testid": o,
      className: g(
        `flex w-full cursor-pointer select-none items-center justify-between gap-2`,
        `rounded px-2 py-1.5`,
        `text-base text-content-primary`,
        `focus:outline-none focus:ring-0`,
        `aria-disabled:cursor-default aria-disabled:opacity-50`,
        a && `bg-surface-hover aria-disabled:bg-transparent`,
      ),
      children: [
        (0, b.jsx)(`div`, { className: `min-w-0 flex-1`, children: e.rendered }),
        i && (0, b.jsx)(`span`, { className: `flex-none`, children: (0, b.jsx)(l, { className: `size-4` }) }),
      ],
    });
  },
  H = ({
    triggerProps: e,
    triggerRef: t,
    valueProps: n,
    isOpen: a,
    displayContent: o,
    loading: s,
    disabled: c,
    size: l,
    className: u,
    "data-testid": d,
  }) => {
    let { buttonProps: f } = i(e, t);
    return (0, b.jsxs)(`button`, {
      ...f,
      ref: t,
      "data-testid": d,
      disabled: c || s,
      "aria-expanded": a || void 0,
      className: g(
        `flex w-full items-center justify-between gap-2`,
        l === `xs` ? `text-sm` : `text-base`,
        `text-content-primary`,
        `outline-none`,
        `disabled:cursor-not-allowed disabled:opacity-50`,
        l === `xs` ? `h-auto px-2 py-1` : l === `sm` ? `h-8 px-3` : `h-9 px-3`,
        `rounded-lg border border-border-input-default bg-surface-input`,
        `transition-all duration-150 ease-out`,
        `focus:border-border-input-active focus:ring-4 focus:ring-ring-default focus:ring-offset-0`,
        `aria-expanded:border-border-input-active aria-expanded:ring-4 aria-expanded:ring-ring-default aria-expanded:ring-offset-0`,
        u,
      ),
      children: [
        (0, b.jsx)(`span`, { ...n, className: `truncate`, children: o }),
        s ? (0, b.jsx)(h, { className: `animate-spin text-content-primary`, size: `sm` }) : (0, b.jsx)(r, { size: 20 }),
      ],
    });
  },
  U = (e) => {
    let t = null,
      n = null,
      r = [];
    return (
      v.Children.forEach(e, (e) => {
        if ((0, v.isValidElement)(e))
          switch (O(e)) {
            case S:
              t = e;
              break;
            case C:
              n = e;
              break;
            default:
              r.push(e);
          }
        else r.push(e);
      }),
      t || n
        ? (0, b.jsxs)(`div`, {
            className: `flex min-w-0 items-center gap-2`,
            children: [
              t,
              (0, b.jsxs)(`div`, {
                className: `flex min-w-0 flex-1 flex-col`,
                children: [(0, b.jsx)(`span`, { className: `truncate`, children: r }), n],
              }),
            ],
          })
        : e
    );
  },
  W = ({
    children: e,
    defaultValue: t,
    value: r,
    onValueChange: i,
    disabled: o = !1,
    loading: l = !1,
    placeholder: u = `Select...`,
    sameWidth: d = !1,
    size: f = `default`,
    inline: p = !1,
    name: m,
    id: h,
    "aria-label": _,
    "data-testid": y,
    className: S,
  }) => {
    let C = [],
      E = null,
      A = null;
    v.Children.forEach(e, (e) => {
      if ((0, v.isValidElement)(e)) {
        let t = O(e);
        t === x
          ? C.push({
              value: e.props.value,
              children: e.props.children,
              disabled: e.props.disabled,
              "data-testid": e.props[`data-testid`],
            })
          : t === w
            ? (E = e)
            : t === T && (A = e);
      }
    });
    let M = C.filter((e) => e.disabled).map((e) => e.value),
      N = new Map();
    for (let e of C) e[`data-testid`] && N.set(e.value, e[`data-testid`]);
    let P = C.map((e) => (0, b.jsx)(c, { textValue: R(e.children) || e.value, children: U(e.children) }, e.value)),
      F = (0, v.useRef)(null),
      I = (0, v.useRef)(null),
      V = (0, v.useRef)(void 0),
      W = {
        children: P,
        selectedKey: r ?? void 0,
        defaultSelectedKey: t ?? void 0,
        onSelectionChange: (e) => {
          e !== null && i?.(String(e));
        },
        onOpenChange: (e) => {
          let t = F.current?.closest(`[role='dialog']`);
          (t &&
            (e
              ? ((V.current = t.style.overflow), (t.style.overflow = `visible`))
              : ((t.style.overflow = V.current ?? ``), (V.current = void 0))),
            e || F.current?.focus());
        },
        isDisabled: o || l,
        disabledKeys: M,
        name: m,
        id: h,
        "aria-label": _ ?? `Select`,
      },
      G = n(W),
      { labelProps: K, triggerProps: q, valueProps: J, menuProps: ee } = a(W, G, F),
      Y = G.selectedItem,
      X = !!Y,
      Z = X ? C.find((e) => e.value === String(G.selectedKey)) : void 0,
      Q = X ? (Z ? L(Z.children) : Y.rendered) : null,
      te = { value: X ? String(G.selectedKey) : null, label: Q },
      $;
    return (
      ($ = A || (X ? Q : typeof u == `string` ? (0, b.jsx)(k, { children: u }) : u)),
      (0, b.jsx)(D.Provider, {
        value: N,
        children: (0, b.jsx)(j.Provider, {
          value: te,
          children: (0, b.jsxs)(`div`, {
            ref: I,
            className: g(`relative`, p ? `inline-flex w-auto` : `w-full`, S),
            children: [
              (0, b.jsx)(`span`, { ...K, className: `sr-only`, children: _ ?? `Select` }),
              (0, b.jsx)(s, { state: G, triggerRef: F, label: _ ?? `Select`, name: m, isDisabled: o || l }),
              (0, b.jsx)(H, {
                triggerProps: q,
                triggerRef: F,
                valueProps: J,
                isOpen: G.isOpen,
                displayContent: $,
                loading: l,
                disabled: o,
                size: f,
                "data-testid": y,
              }),
              G.isOpen &&
                (0, b.jsxs)(z, {
                  state: G,
                  triggerRef: F,
                  placement: `bottom start`,
                  offset: 4,
                  containerPadding: 0,
                  triggerWidth: F.current?.offsetWidth,
                  sameWidth: d,
                  maxHeight: 384,
                  className: g(
                    `z-[999]`,
                    `flex flex-col overflow-hidden`,
                    `rounded-lg border border-border-base bg-surface-popover shadow`,
                    `p-1`,
                  ),
                  children: [(0, b.jsx)(B, { menuProps: ee, state: G }), E],
                }),
            ],
          }),
        }),
      })
    );
  },
  G = ({ children: e }) => (0, b.jsx)(b.Fragment, { children: e });
((G.displayName = x),
  (G.Icon = F),
  (G.Description = I),
  (W.Item = G),
  (W.Placeholder = k),
  (W.Footer = A),
  (W.Value = P),
  (W.ValueLabel = N));
export { W as t };

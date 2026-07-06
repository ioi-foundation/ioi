import { a as e } from "./rolldown-runtime-CGYlQKCx.js";
import { n as t } from "./@mux-DLaEVubF.js";
import { Ig as n, v_ as r } from "./vendor-DAwbZtf0.js";
import { a as i, r as a } from "./button-6YP03Qf2.js";
import { t as o } from "./cn-DppMFCU8.js";
var s = e(t(), 1),
  c = r(),
  l = (0, s.createContext)(null),
  u = (0, s.forwardRef)(({ className: e, children: t, asChild: r = !1, variant: i, ...a }, s) =>
    (0, c.jsx)(r ? n : `div`, {
      ref: s,
      className: o(`inline-flex`, e),
      role: `group`,
      ...a,
      children: (0, c.jsx)(l.Provider, { value: { variant: i ?? `primary` }, children: t }),
    }),
  );
u.displayName = `ButtonGroup`;
var d = (0, s.forwardRef)(
  (
    {
      className: e,
      asChild: t = !1,
      LeadingIcon: r,
      loading: u,
      disabled: d,
      children: f,
      disableTracking: p,
      _disableTranslateWrapping: m,
      ...h
    },
    g,
  ) => {
    let _ = (0, s.useContext)(l);
    if (!_) throw Error(`ButtonGroupItem must be used within a ButtonGroup`);
    let { variant: v } = _,
      y = t ? n : `button`,
      b = o(
        `px-2 py-1.5 min-h-8`,
        `select-none`,
        `inline-flex items-center gap-2 text-sm font-medium justify-center whitespace-nowrap`,
        `disabled:opacity-50 disabled:pointer-events-none`,
        `focus:ring-0`,
        `focus-visible:outline focus-visible:outline-1 focus-visible:outline-offset-1 focus-visible:animate-focus-pulse motion-reduce:animate-none focus-visible:outline-border-brand active:outline-0`,
        `rounded-none`,
        `first:rounded-l-lg last:rounded-r-lg`,
      ),
      x = o(
        v === `primary` && [
          `text-content-primary-inverted hover:text-content-accent-inverted active:text-content-accent-inverted data-[state=open]:text-content-accent-inverted focus-visible:text-content-accent-inverted`,
          `bg-surface-button-primary hover:bg-surface-button-primary-accent active:bg-surface-button-primary-accent data-[state=open]:bg-surface-button-primary-accent focus-visible:bg-surface-button-primary-accent`,
        ],
        v === `secondary` && [
          `text-content-primary bg-surface-button-secondary hover:bg-surface-button-secondary-accent active:bg-surface-button-secondary-accent data-[state=open]:bg-surface-button-secondary-accent`,
        ],
        v === `ghost` && [
          `text-content-primary hover:text-content-accent active:text-content-accent data-[state=open]:text-content-accent focus-visible:text-content-accent`,
          `bg-surface-button-clear hover:bg-surface-button-clear-accent data-[state=open]:bg-surface-button-clear-accent focus-visible:bg-surface-button-clear-accent`,
        ],
      ),
      S;
    u
      ? (S = (0, c.jsx)(i, { className: `animate-spin`, size: `base`, "aria-hidden": !0 }))
      : r && (S = (0, c.jsx)(r, { size: `base`, "aria-hidden": !0 }));
    let C = ``;
    return (
      !f && r && (C = `aspect-square p-0`),
      (0, c.jsx)(a, {
        asChild: t,
        leftElement: S,
        className: o(b, x, C, e),
        disableTracking: p,
        _disableTranslateWrapping: m,
        ref: g,
        disabled: d || u,
        "aria-busy": u,
        as: y,
        ...h,
        children: f,
      })
    );
  },
);
d.displayName = `ButtonGroupItem`;
var f = Object.assign(u, { Item: d });
export { f as t };

import { a as e } from "./rolldown-runtime-CGYlQKCx.js";
import { n as t } from "./@mux-DLaEVubF.js";
import {
  Bg as n,
  Cm as r,
  Sm as i,
  _m as a,
  bm as o,
  v_ as s,
  vm as c,
  wm as l,
  xm as u,
  ym as d,
} from "./vendor-DAwbZtf0.js";
import { t as f } from "./button-6YP03Qf2.js";
import { t as p } from "./cn-DppMFCU8.js";
import { t as m } from "./radix-body-pointer-events-DJX9Yyw0.js";
var h = e(t(), 1),
  g = s(),
  _ = ({ defaultOpen: e, modal: t, onOpenChange: n, open: r, ...a }) => {
    let o = m({ defaultOpen: e, modal: t ?? !0, onOpenChange: n, open: r });
    return (0, g.jsx)(i, { ...a, defaultOpen: e, modal: t, open: r, onOpenChange: o });
  },
  v = h.forwardRef((e, t) => (0, g.jsx)(l, { ref: t, ...e }));
v.displayName = l.displayName;
var y = (e) => (0, g.jsx)(u, { ...e }),
  b = h.forwardRef(({ className: e, onClick: t, ...n }, r) =>
    (0, g.jsx)(a, {
      ...n,
      ref: r,
      className: e,
      onClick: (e) => {
        (e.stopPropagation(), t && t(e));
      },
    }),
  );
b.displayName = a.displayName;
var x = h.forwardRef(({ className: e, ...t }, n) =>
  (0, g.jsx)(o, {
    ref: n,
    className: p(
      `fixed inset-0 z-50 bg-surface-primary/50 dark:bg-surface-base/50 backdrop-blur-modal backdrop-opacity-modal data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0`,
      e,
    ),
    ...t,
  }),
);
x.displayName = o.displayName;
var S = h.forwardRef(
  ({ className: e, children: t, disableOverlay: r, viewportClassName: i, "data-track-location": a, ...o }, s) => {
    let l = (0, g.jsx)(`div`, {
      className: p(`fixed inset-0 z-50 flex items-center justify-center px-4`, i),
      children: (0, g.jsxs)(c, {
        ref: s,
        className: p(
          `relative flex max-h-[90%] w-full max-w-lg flex-col overflow-x-auto p-6`,
          `rounded-xl border border-border-base bg-surface-secondary shadow-modal`,
          `duration-200 @container data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95`,
          e,
        ),
        ...o,
        "data-track-location": a,
        children: [
          t,
          (0, g.jsx)(b, {
            asChild: !0,
            children: (0, g.jsx)(f, {
              variant: `ghost`,
              size: `sm`,
              className: `absolute right-4 top-4 aspect-square p-0 text-content-muted`,
              "aria-label": `Close`,
              children: (0, g.jsx)(n, {}),
            }),
          }),
        ],
      }),
    });
    return (0, g.jsx)(y, { children: r ? l : (0, g.jsx)(x, { children: l }) });
  },
);
S.displayName = c.displayName;
var C = ({ className: e, ...t }) =>
  (0, g.jsx)(g.Fragment, {
    children: (0, g.jsx)(`header`, { className: p(`mb-6 flex flex-col gap-1.5 text-left`, e), ...t }),
  });
C.displayName = `DialogHeader`;
var w = ({ className: e, ...t }) =>
  (0, g.jsx)(`footer`, {
    className: p(`flex flex-col-reverse justify-end gap-2 sm:flex-row`, `mt-6 flex-row justify-between`, e),
    ...t,
  });
w.displayName = `DialogFooter`;
var T = h.forwardRef(({ className: e, ...t }, n) =>
  (0, g.jsx)(r, {
    ref: n,
    className: p(`text-lg font-semibold leading-none tracking-tight text-content-primary`, e),
    ...t,
  }),
);
T.displayName = r.displayName;
var E = h.forwardRef(({ className: e, ...t }, n) =>
  (0, g.jsx)(d, { ref: n, className: p(`m-0 p-0 text-base text-content-secondary`, e), ...t }),
);
E.displayName = d.displayName;
var D = ({ className: e, ...t }) =>
  (0, g.jsx)(`div`, {
    className: p(`overflow-x-visible px-1 py-8 text-base text-content-primary`, `py-1.5 text-content-muted`, e),
    ...t,
  });
D.displayName = `DialogBody`;
var O = Object.assign(_, {
  Body: D,
  Close: b,
  Content: S,
  Description: E,
  Footer: w,
  Header: C,
  Overlay: x,
  Portal: y,
  Title: T,
  Trigger: v,
});
export { O as t };

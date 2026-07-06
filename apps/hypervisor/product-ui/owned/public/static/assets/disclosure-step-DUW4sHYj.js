import { a as e } from "./rolldown-runtime-CGYlQKCx.js";
import { n as t } from "./@mux-DLaEVubF.js";
import { Kg as n, Lh as r, Sh as i, Wp as a, bh as o, nh as s, v_ as c, yd as l } from "./vendor-DAwbZtf0.js";
import { t as u } from "./cn-DppMFCU8.js";
import { t as d } from "./text-fFCFeCas.js";
var f = e(t(), 1),
  p = c(),
  m = (0, f.createContext)(null),
  h = () => {
    let e = (0, f.useContext)(m);
    if (!e) throw Error(`DisclosureStepList.Item must be used within a DisclosureStepList`);
    return e;
  },
  g = ({ currentStep: e, onStepChange: t, children: n, className: r, canGoBack: i = !0 }) => {
    let a = f.Children.toArray(n).filter(f.isValidElement),
      o = a.reduce((e, t, n) => (t.props.completed === !0 ? n : e), -1);
    return (0, p.jsx)(`div`, {
      className: u(`flex flex-col`, r),
      children: a.map((n, r) => {
        let a = n.props.completed === !0,
          s = r === e,
          c = r === o + 1,
          l = !a && !s && !c,
          u = r === e;
        return (0, p.jsx)(
          m.Provider,
          {
            value: {
              index: r,
              currentStep: e,
              onStepChange: t,
              isCompleted: a,
              isActive: s,
              isLocked: l,
              canGoBack: i,
            },
            children: (0, f.cloneElement)(n, { isExpanded: u }),
          },
          r,
        );
      }),
    });
  },
  _ = 200,
  v = ({ title: e, description: t, children: c, className: m, isExpanded: g = !1 }) => {
    let { index: v, onStepChange: b, isCompleted: x, isLocked: S, canGoBack: C } = h(),
      [w, T] = (0, f.useState)(g);
    (0, f.useEffect)(() => {
      if (g) T(!0);
      else {
        let e = setTimeout(() => {
          T(!1);
        }, _);
        return () => clearTimeout(e);
      }
    }, [g]);
    let E = x && !C,
      D = !S && !E,
      O = (0, f.useRef)(null),
      k = (0, f.useRef)(null),
      A = {
        isExpanded: g,
        isDisabled: S,
        onExpandedChange: () => {
          D && b(v);
        },
      },
      { buttonProps: j, panelProps: M } = s(A, a(A), k),
      { buttonProps: N } = i(j, O),
      { isFocusVisible: P, focusProps: F } = o(),
      I = v + 1;
    return (0, p.jsxs)(`div`, {
      className: u(`text-content-primary`, m),
      children: [
        (0, p.jsx)(`h3`, {
          children: (0, p.jsxs)(`button`, {
            ref: O,
            ...r(N, F),
            className: u(`group flex w-full items-center gap-3 rounded-md px-3 py-2 text-left`, {
              "focus:ring-1 focus:ring-border-brand focus:ring-offset-1": P,
              "cursor-not-allowed opacity-50": S,
              "cursor-default": !S && (E || g),
              "cursor-pointer hover:bg-surface-hover": !S && !E && !g,
            }),
            "data-tracking-id": `disclosure-step-${I}`,
            children: [
              (0, p.jsx)(y, { stepNumber: I, isLocked: S }),
              (0, p.jsx)(d, { className: `flex-1 text-content-primary`, children: e }),
              x && (0, p.jsx)(n, { size: 16, className: `shrink-0 text-content-positive` }),
              (0, p.jsx)(l, {
                size: 10,
                className: u(`shrink-0 text-content-secondary transition-transform`, g && `rotate-90`),
              }),
            ],
          }),
        }),
        (0, p.jsx)(`div`, {
          ...M,
          className: u(
            `ml-[21px] grid border-l border-border-base pl-[22px] transition-[grid-template-rows] duration-200 ease-out motion-reduce:transition-none`,
            g ? `grid-rows-[1fr]` : `grid-rows-[0fr]`,
          ),
          children: (0, p.jsx)(`div`, {
            className: u(
              `min-h-0 transition-all duration-100 ease-out motion-reduce:transition-none`,
              g ? `scale-100 opacity-100 delay-75` : `opacity-0 delay-0`,
            ),
            children:
              w &&
              (0, p.jsxs)(p.Fragment, {
                children: [
                  t && (0, p.jsx)(`p`, { className: `pb-4 text-sm leading-none text-content-secondary`, children: t }),
                  c,
                ],
              }),
          }),
        }),
      ],
    });
  },
  y = ({ stepNumber: e, isLocked: t }) =>
    (0, p.jsx)(`span`, {
      className: u(
        `flex size-5 shrink-0 items-center justify-center rounded-full bg-content-primary text-sm font-medium text-content-primary-inverted`,
        t && `opacity-50`,
      ),
      children: e,
    }),
  b = g;
((b.displayName = `DisclosureStepList`), (v.displayName = `DisclosureStepList.Item`), (b.Item = v));
export { b as t };

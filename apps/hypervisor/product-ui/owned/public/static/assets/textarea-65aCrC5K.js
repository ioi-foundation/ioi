import { a as e } from "./rolldown-runtime-CGYlQKCx.js";
import { n as t } from "./@mux-DLaEVubF.js";
import { Bg as n, Bl as r, am as i, sm as a, v_ as o } from "./vendor-DAwbZtf0.js";
import { t as s } from "./button-6YP03Qf2.js";
import { t as c } from "./cn-DppMFCU8.js";
import { t as l } from "./hooks-Cxw5RI6a.js";
var u = e(t(), 1),
  d = ({
    textArea: e,
    triggerAutoSize: t,
    maxHeight: n = 2 ** 53 - 1,
    minHeight: i = 0,
    offsetBorder: a = 2,
    enabled: o = !0,
  }) => {
    let s = u.useRef(!0),
      [c] = r(t, 50),
      [l, d] = u.useState(0);
    (u.useEffect(() => {
      if (!o || !e) return;
      let t = new IntersectionObserver(
        ([e]) => {
          e?.isIntersecting && d((e) => e + 1);
        },
        { threshold: 0 },
      );
      return (t.observe(e), () => t.disconnect());
    }, [o, e]),
      u.useEffect(() => {
        if (!o || !e) return;
        let t = requestAnimationFrame(() => {
          ((s.current &&=
            ((e.style.minHeight = `${i + a}px`),
            n > i && (e.style.maxHeight = `${n}px`),
            e.style.setProperty(`transition`, `none`, `important`),
            !1)),
            (e.style.height = `${i + a}px`));
          let t = e.scrollHeight;
          e.style.height = `${Math.min(t + a, n)}px`;
        });
        return () => cancelAnimationFrame(t);
      }, [e, c, l, i, n, o, a]));
  },
  f = o(),
  p = c(
    `flex h-full w-full max-w-[600px] focus-visible:ring-0 text-base p-0 border-0 outline-none`,
    `file:border-0 file:bg-transparent file:text-sm file:font-medium`,
    `disabled:cursor-text`,
    `placeholder:text-content-muted border-border-base disabled:bg-surface-input text-content-primary bg-transparent`,
    `flex items-center gap-2 h-9 w-full max-w-[600px] px-3 py-2`,
    `rounded-lg border border-border-light text-base`,
    `focus-within:ring-content-primary disabled:cursor-text`,
    `focus-within:ring-4 focus-within:ring-ring-default focus-visible:ring-4 focus-visible:ring-ring-default`,
    `group-data-[state=error]:border-border-error group-data-[state=error]:ring-ring-destructive disabled:bg-inherit bg-surface-input`,
    `[&[readonly]]:border-border-subtle [&[readonly]]:bg-transparent`,
    `h-auto max-w-full resize-none overflow-y-auto leading-[18px]`,
  ),
  m = 0,
  h = u.forwardRef(
    (
      {
        maxHeight: e = 2 ** 53 - 1,
        minHeight: t,
        className: r,
        value: o,
        dontAutosize: h,
        copyable: g,
        appearance: _,
        onKeyDown: v,
        onCompositionStart: y,
        onCompositionEnd: b,
        title: x,
        readOnly: S,
        ...C
      },
      w,
    ) => {
      let [T, E] = u.useState(null),
        D = u.useRef(null),
        O = (0, u.useCallback)((e) => {
          ((D.current = e), E(e));
        }, []);
      (0, u.useImperativeHandle)(w, () => D.current);
      let k = (0, u.useRef)(!1),
        { copied: A, error: j, copy: M } = l(),
        N = S || g,
        P = h || g,
        F = _ === `code` ? `font-mono` : void 0,
        I = typeof o == `string` ? o : String(o ?? ``),
        L = (0, u.useMemo)(
          () =>
            I.split(`
`).length,
          [I],
        );
      d({
        textArea: T,
        triggerAutoSize: typeof o == `string` ? o : String(++m),
        maxHeight: e,
        minHeight: t,
        enabled: !P,
      });
      let R = (0, u.useCallback)(
          (e) => {
            ((k.current = !0), y?.(e));
          },
          [y],
        ),
        z = (0, u.useCallback)(
          (e) => {
            ((k.current = !1), b?.(e));
          },
          [b],
        ),
        B = (0, u.useCallback)(
          (e) => {
            if (k.current && (e.key === `Enter` || e.key === `Tab`)) {
              (e.preventDefault(), e.stopPropagation());
              return;
            }
            v?.(e);
          },
          [v],
        ),
        V = C[`data-tracking-id`];
      return g
        ? (0, f.jsxs)(`div`, {
            className: `relative`,
            children: [
              (0, f.jsx)(`textarea`, {
                ...C,
                value: o,
                ref: O,
                readOnly: N,
                rows: L,
                title: x,
                onKeyDown: B,
                onCompositionStart: R,
                onCompositionEnd: z,
                className: c(p, `leading-normal pr-12`, F, r),
              }),
              (0, f.jsx)(`div`, {
                className: c(`absolute inset-y-2 right-2 flex items-start`, { hidden: !I }),
                children: (0, f.jsx)(s, {
                  variant: `ghost`,
                  type: `button`,
                  className: `h-6 rounded-lg border-none p-1 text-content-tertiary hover:text-content-secondary hover:opacity-100`,
                  onClick: () => M(I),
                  "aria-label": x ?? `Copy to clipboard`,
                  title: x,
                  "data-tracking-id": V,
                  children: A
                    ? (0, f.jsx)(a, { className: `text-content-success`, "aria-hidden": !0, size: 16 })
                    : j
                      ? (0, f.jsx)(n, { className: `text-content-danger`, "aria-hidden": !0, size: 16 })
                      : (0, f.jsx)(i, { "aria-hidden": !0, size: 16 }),
                }),
              }),
            ],
          })
        : (0, f.jsx)(`textarea`, {
            ...C,
            value: o,
            ref: O,
            readOnly: N,
            title: x,
            onKeyDown: B,
            onCompositionStart: R,
            onCompositionEnd: z,
            className: c(p, F, r),
          });
    },
  );
h.displayName = `Textarea`;
export { h as t };

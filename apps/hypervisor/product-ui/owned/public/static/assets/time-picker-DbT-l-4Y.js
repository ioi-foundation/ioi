import { a as e } from "./rolldown-runtime-CGYlQKCx.js";
import { n as t } from "./@mux-DLaEVubF.js";
import { Qp as n, cm as r, v_ as i } from "./vendor-DAwbZtf0.js";
import { t as a } from "./cn-DppMFCU8.js";
import { r as o } from "./dropdown-menu-D3UmjGpQ.js";
var s = e(t(), 1),
  c = i(),
  l = (e) =>
    e === 0
      ? { hour12: 12, period: `AM` }
      : e < 12
        ? { hour12: e, period: `AM` }
        : e === 12
          ? { hour12: 12, period: `PM` }
          : { hour12: e - 12, period: `PM` },
  u = (e, t) => (t === `AM` ? (e === 12 ? 0 : e) : e === 12 ? 12 : e + 12),
  d = (e, t, n) => {
    let r = e,
      i = n;
    if (r >= 13 && r <= 23) {
      let e = l(r);
      ((r = e.hour12), (i = e.period));
    } else r === 0 || r === 24 ? ((r = 12), (i = `AM`)) : (isNaN(r) || r < 1 || r > 24) && ((r = t), (i = n));
    return { hour12: r, period: i };
  },
  f = ({
    value: e,
    onChange: t,
    className: i,
    disabled: f = !1,
    readOnly: p = !1,
    timezone: m = `UTC`,
    showTimezone: h = !0,
  }) => {
    let g = e?.hour ?? 0,
      _ = e?.minute ?? 0,
      { hour12: v, period: y } = l(g),
      [b, x] = s.useState(String(v).padStart(2, `0`)),
      [S, C] = s.useState(String(_).padStart(2, `0`)),
      [w, T] = s.useState(!1),
      E = s.useRef(null),
      D = s.useRef(null),
      O = s.useRef(null),
      [k, A] = s.useState(!1),
      [j, M] = s.useState(!1);
    (s.useEffect(() => {
      k || x(String(v).padStart(2, `0`));
    }, [v, k]),
      s.useEffect(() => {
        j || C(String(_).padStart(2, `0`));
      }, [_, j]));
    let N = (e) => {
        let t = e.target.value;
        (t === `` || /^\d{0,2}$/.test(t)) && x(t);
      },
      P = (e) => {
        let t = e.target.value;
        (t === `` || /^\d{0,2}$/.test(t)) && C(t);
      },
      F = (e) => {
        let n = u(v, e);
        t?.({ hour: n, minute: _ });
      },
      I = () => {
        A(!0);
      },
      L = () => {
        A(!1);
        let e = d(parseInt(b), v, y);
        x(String(e.hour12).padStart(2, `0`));
        let n = u(e.hour12, e.period);
        t?.({ hour: n, minute: _ });
      },
      R = () => {
        M(!0);
      },
      z = () => {
        M(!1);
        let e = parseInt(S);
        ((isNaN(e) || e < 0 || e > 59) && (e = _), C(String(e).padStart(2, `0`)), t?.({ hour: g, minute: e }));
      },
      B = (e) => {
        if (e.key === `Enter`) e.currentTarget.blur();
        else if (e.key === `:` || e.key === `;`) (e.preventDefault(), D.current?.focus(), D.current?.select());
        else if (e.key === `ArrowRight`) (e.preventDefault(), D.current?.focus(), D.current?.select());
        else if (e.key === `ArrowUp`) {
          e.preventDefault();
          let n = v + 1,
            r = y;
          (n > 12 ? (n = 1) : n === 12 && v === 11 && (r = y === `AM` ? `PM` : `AM`), x(String(n).padStart(2, `0`)));
          let i = u(n, r);
          t?.({ hour: i, minute: _ });
        } else if (e.key === `ArrowDown`) {
          e.preventDefault();
          let n = v - 1,
            r = y;
          (n < 1 ? (n = 12) : n === 11 && v === 12 && (r = y === `AM` ? `PM` : `AM`), x(String(n).padStart(2, `0`)));
          let i = u(n, r);
          t?.({ hour: i, minute: _ });
        }
      },
      V = (e) => {
        if (e.key === `Enter`) e.currentTarget.blur();
        else if (e.key === `Tab` && !e.shiftKey)
          (e.preventDefault(),
            z(),
            T(!0),
            setTimeout(() => {
              O.current?.focus();
            }, 0));
        else if (e.key === `ArrowLeft`) (e.preventDefault(), z(), E.current?.focus(), E.current?.select());
        else if (e.key === `ArrowRight`)
          (e.preventDefault(),
            z(),
            T(!0),
            setTimeout(() => {
              O.current?.focus();
            }, 0));
        else if (e.key === `ArrowUp`) {
          e.preventDefault();
          let n = _ + 1;
          (n > 59 && (n = 0), C(String(n).padStart(2, `0`)), t?.({ hour: g, minute: n }));
        } else if (e.key === `ArrowDown`) {
          e.preventDefault();
          let n = _ - 1;
          (n < 0 && (n = 59), C(String(n).padStart(2, `0`)), t?.({ hour: g, minute: n }));
        }
      },
      H = (e) => {
        e.key === `ArrowDown` || e.key === `ArrowUp` || e.key === ` ` || e.key === `Enter`
          ? (e.preventDefault(), T(!0))
          : e.key === `ArrowLeft` && (e.preventDefault(), D.current?.focus(), D.current?.select());
      },
      U = !f && !p;
    return (0, c.jsxs)(`div`, {
      className: a(`inline-flex items-center gap-2`, i),
      children: [
        (0, c.jsxs)(`div`, {
          className: a(
            `inline-flex items-center`,
            `h-8 pl-2 pr-3 rounded-lg`,
            `border border-border-base`,
            p ? `bg-surface-muted` : `bg-surface-pure`,
            U && `focus-within:outline focus-within:outline-1 focus-within:outline-border-brand`,
            f && `opacity-50 pointer-events-none`,
            p && `pointer-events-none`,
          ),
          children: [
            (0, c.jsx)(`input`, {
              ref: E,
              type: `text`,
              inputMode: `numeric`,
              value: b,
              onChange: N,
              onFocus: I,
              onBlur: L,
              onKeyDown: B,
              disabled: f,
              readOnly: p,
              className: a(`w-6 text-sm text-center bg-transparent border-0 outline-none`, `focus:ring-0 p-0`),
              maxLength: 2,
              "aria-label": `Hour`,
            }),
            (0, c.jsx)(`span`, { className: `text-sm text-content-secondary`, children: `:` }),
            (0, c.jsx)(`input`, {
              ref: D,
              type: `text`,
              inputMode: `numeric`,
              value: S,
              onChange: P,
              onFocus: R,
              onBlur: z,
              onKeyDown: V,
              disabled: f,
              readOnly: p,
              className: a(`w-6 text-sm text-center bg-transparent border-0 outline-none`, `focus:ring-0 p-0`),
              maxLength: 2,
              "aria-label": `Minute`,
            }),
            (0, c.jsxs)(o, {
              open: w,
              onOpenChange: T,
              children: [
                (0, c.jsxs)(o.Trigger, {
                  ref: O,
                  disabled: f || p,
                  onKeyDown: H,
                  className: a(
                    `ml-1 inline-flex items-center gap-1`,
                    `text-sm bg-transparent`,
                    U && `hover:text-content-accent`,
                    `focus:outline-none focus-visible:ring-0`,
                  ),
                  "data-tracking-id": `time-picker-period`,
                  children: [y, !p && (0, c.jsx)(n, { size: 14, className: `opacity-50` })],
                }),
                (0, c.jsxs)(o.Content, {
                  align: `end`,
                  alignOffset: -8,
                  className: `w-20 min-w-0`,
                  children: [
                    (0, c.jsxs)(o.Item, {
                      onClick: () => {
                        (F(`AM`), T(!1));
                      },
                      "data-tracking-id": `time-picker-period-am`,
                      className: `justify-between pr-2`,
                      children: [(0, c.jsx)(`span`, { children: `AM` }), y === `AM` && (0, c.jsx)(r, { size: 16 })],
                    }),
                    (0, c.jsxs)(o.Item, {
                      onClick: () => {
                        (F(`PM`), T(!1));
                      },
                      "data-tracking-id": `time-picker-period-pm`,
                      className: `justify-between pr-2`,
                      children: [(0, c.jsx)(`span`, { children: `PM` }), y === `PM` && (0, c.jsx)(r, { size: 16 })],
                    }),
                  ],
                }),
              ],
            }),
          ],
        }),
        h && (0, c.jsx)(`span`, { className: a(`text-sm text-content-secondary`, f && `opacity-50`), children: m }),
      ],
    });
  };
export { f as t };

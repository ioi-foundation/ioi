import { a as e } from "./rolldown-runtime-CGYlQKCx.js";
import { n as t } from "./@mux-DLaEVubF.js";
import { v_ as n, vg as r, wg as i, xg as a } from "./vendor-DAwbZtf0.js";
import { t as o } from "./button-6YP03Qf2.js";
import { t as s } from "./cn-DppMFCU8.js";
import { t as c } from "./tooltip-6hqVQbwq.js";
import { t as l } from "./use-escape-shortcut-gqfNaors.js";
import { t as u } from "./keyboard-key-Db4ECT0G.js";
import { t as d } from "./use-is-mobile-viewport-Chw6u8QP.js";
import { t as f } from "./IconArrowLeft-DER3051x.js";
var p = e(t(), 1),
  m = n(),
  h = ({ className: e, showLabel: t = !0 }) => {
    let { isMobileViewport: n } = d(),
      h = a(),
      g = r(),
      { environmentId: _ } = i(),
      v = g.pathname.includes(`/tasks`),
      y = g.pathname.includes(`/task/`),
      b = g.pathname.includes(`/services/`),
      x = g.pathname.endsWith(`${_}/logs`),
      S = (0, p.useCallback)(() => {
        if (_ && !(!v && !b && !x && !y)) {
          if (y) {
            h(`/details/${_}/tasks`);
            return;
          }
          h(`/details/${_}`);
        }
      }, [_, x, b, y, v, h]);
    return (
      l(
        (0, p.useCallback)(() => {
          _ && h(`/details/${_}`);
        }, [_, h]),
      ),
      (0, m.jsx)(c, {
        content: (0, m.jsxs)(`div`, {
          className: `flex flex-row items-center gap-2`,
          children: [`Back to environment`, !n && (0, m.jsx)(u, { children: `Esc` })],
        }),
        children: (0, m.jsx)(o, {
          disabled: !_,
          variant: `ghost`,
          className: s(`border-transparent pl-2 text-lg font-bold`, e),
          LeadingIcon: f,
          onClick: S,
          "aria-label": `Back`,
          "data-tracking-id": `back-button-environment-details`,
          children: t && (0, m.jsx)(`span`, { children: `Back` }),
        }),
      })
    );
  };
export { h as t };

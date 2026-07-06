import { a as e } from "./rolldown-runtime-CGYlQKCx.js";
import { n as t } from "./@mux-DLaEVubF.js";
import { em as n, im as r, nm as i, rm as a, tm as o, v_ as s } from "./vendor-DAwbZtf0.js";
import { t as c } from "./cn-DppMFCU8.js";
var l = e(t(), 1),
  u = s();
function d({
  children: e,
  content: t,
  delayDuration: s,
  align: d = `center`,
  alignOffset: f,
  side: p,
  sideOffset: m,
  usePortal: h = !1,
  inverted: g = !0,
  className: _,
  avoidCollisions: v = !0,
  collisionPadding: y,
}) {
  let b = h ? o : l.Fragment;
  return (0, u.jsx)(i, {
    delayDuration: s ?? 500,
    children: (0, u.jsxs)(a, {
      children: [
        (0, u.jsx)(r, { asChild: !0, children: e }),
        t &&
          (0, u.jsx)(b, {
            children: (0, u.jsx)(n, {
              side: p,
              align: d,
              alignOffset: f,
              sideOffset: m,
              avoidCollisions: v,
              collisionPadding: y,
              className: c(
                `group z-50 m-4 rounded-md px-3 py-2 text-sm`,
                g
                  ? `bg-surface-tooltip-primary text-content-tooltip`
                  : `border border-border-base bg-surface-01 text-content-primary`,
                _,
              ),
              "data-component": `tooltip`,
              hideWhenDetached: !0,
              children: t,
            }),
          }),
      ],
    }),
  });
}
export { d as t };

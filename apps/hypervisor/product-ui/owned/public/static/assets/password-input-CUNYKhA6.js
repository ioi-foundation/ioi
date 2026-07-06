import { a as e } from "./rolldown-runtime-CGYlQKCx.js";
import { n as t } from "./@mux-DLaEVubF.js";
import { Ac as n, jc as r, v_ as i } from "./vendor-DAwbZtf0.js";
import { t as a } from "./button-6YP03Qf2.js";
import { t as o } from "./cn-DppMFCU8.js";
import { t as s } from "./use-temporary-value-Bpxt61FD.js";
import { t as c } from "./input-C42Z_4fO.js";
var l = e(t(), 1),
  u = i(),
  d = (0, l.forwardRef)(({ revealable: e, ...t }, i) => {
    let [d, f] = s(!1, 5e3),
      p = (0, l.useCallback)(() => {
        f(!d);
      }, [d, f]);
    return (0, u.jsxs)(`div`, {
      className: `relative`,
      children: [
        (0, u.jsx)(c, { className: o(`ring-inset`, e ? `pr-12` : ``), ...t, type: d ? `text` : `password`, ref: i }),
        e &&
          (0, u.jsx)(`div`, {
            className: o(`absolute inset-y-0 right-2 flex items-center`, { hidden: !t.value }),
            children: (0, u.jsx)(a, {
              variant: `ghost`,
              type: `button`,
              className: `h-6 rounded-lg border-none p-1 text-content-tertiary hover:text-content-secondary hover:opacity-100`,
              onClick: p,
              disabled: t.disabled,
              "aria-label": d ? `Hide password` : `Reveal password`,
              "data-tracking-id": `reveal-password-password-input`,
              children: d ? (0, u.jsx)(n, { className: `text-red-500`, size: 16 }) : (0, u.jsx)(r, { size: 16 }),
            }),
          }),
      ],
    });
  });
d.displayName = `PasswordInput`;
export { d as t };

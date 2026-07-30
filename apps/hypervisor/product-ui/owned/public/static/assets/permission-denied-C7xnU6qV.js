import { a as e } from "./rolldown-runtime-CGYlQKCx.js";
import { n as t } from "./@mux-DLaEVubF.js";
import { v_ as n } from "./vendor-DAwbZtf0.js";
import { t as r } from "./cn-DppMFCU8.js";
import { t as i } from "./headings-CM9JBOhQ.js";
import { t as a } from "./text-fFCFeCas.js";
var o = e(t(), 1),
  s = n(),
  c = (0, o.forwardRef)(({ icon: e, title: t, description: n, className: o, "data-testid": c }, l) =>
    (0, s.jsx)(`div`, {
      ref: l,
      className: r(
        `flex flex-1 flex-col items-center justify-center rounded-xl border border-border-subtle p-6 md:p-12`,
        o,
      ),
      role: `alert`,
      "aria-live": `polite`,
      "data-testid": c,
      children: (0, s.jsxs)(`div`, {
        className: `flex flex-col items-center gap-4 text-center`,
        children: [
          (0, s.jsx)(`div`, {
            className: `flex size-12 items-center justify-center rounded-lg bg-surface-muted`,
            "aria-hidden": `true`,
            children: e,
          }),
          (0, s.jsxs)(`div`, {
            className: `flex flex-col gap-2`,
            children: [
              (0, s.jsx)(i, { className: `text-2xl`, children: t }),
              (0, s.jsx)(a, { className: `text-base text-content-strong`, children: n }),
            ],
          }),
        ],
      }),
    }),
  );
c.displayName = `PermissionDenied`;
export { c as t };

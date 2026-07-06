import { a as e } from "./rolldown-runtime-CGYlQKCx.js";
import { n as t } from "./@mux-DLaEVubF.js";
import { Pg as n, v_ as r } from "./vendor-DAwbZtf0.js";
import { t as i } from "./cn-DppMFCU8.js";
var a = e(t(), 1),
  o = r(),
  s = n(`min-w-[20px] rounded-[10px] px-[6px] py-[2px] font-bold font-mono text-sm text-center`, {
    variants: {
      variant: {
        default: `bg-surface-brand text-content-brand dark:bg-content-brand/25 dark:text-surface-brand/80`,
        muted: `bg-surface-accent text-content-strong`,
      },
    },
  }),
  c = (0, a.forwardRef)(({ children: e, variant: t, className: n, ...r }, a) =>
    (0, o.jsx)(`span`, { ref: a, className: i(s({ variant: t ?? `default` }), n), ...r, children: e }),
  );
c.displayName = `Notification`;
export { c as t };

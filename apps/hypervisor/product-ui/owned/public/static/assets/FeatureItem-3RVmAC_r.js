import { Pg as e, v_ as t } from "./vendor-DAwbZtf0.js";
import { t as n } from "./text-fFCFeCas.js";
var r = t(),
  i = e(`flex h-6 w-6 shrink-0 items-center justify-center rounded-lg`, {
    variants: {
      variant: {
        success: `bg-surface-success-subtle text-content-success`,
        warning: `bg-surface-warning-subtle text-content-warning`,
        destructive: `bg-surface-destructive-subtle text-content-destructive`,
        brand: `bg-surface-brand-subtle text-content-brand`,
        "brand-purple": `bg-surface-brand-accent-01 text-content-brand-accent-01`,
      },
    },
    defaultVariants: { variant: `brand` },
  }),
  a = ({ icon: e, variant: t, title: a, description: o }) =>
    (0, r.jsxs)(`div`, {
      className: `flex gap-3 rounded-xl border border-border-subtle bg-surface-popover p-4`,
      children: [
        (0, r.jsx)(`div`, { className: i({ variant: t }), children: e }),
        (0, r.jsxs)(`div`, {
          className: `flex flex-col gap-0.5`,
          children: [
            (0, r.jsx)(n, { className: `text-base font-medium text-content-primary`, children: a }),
            (0, r.jsx)(n, { className: `text-sm text-content-secondary`, children: o }),
          ],
        }),
      ],
    });
export { a as t };

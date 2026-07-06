import { a as e } from "./rolldown-runtime-CGYlQKCx.js";
import { n as t } from "./@mux-DLaEVubF.js";
import { Pg as n, v_ as r } from "./vendor-DAwbZtf0.js";
import { t as i } from "./cn-DppMFCU8.js";
var a = e(t(), 1),
  o = r(),
  s = n(`rounded-full px-2 py-0.5 font-medium font-mono text-sm`, {
    variants: {
      variant: {
        default: `bg-surface-secondary text-content-strong`,
        success: `bg-surface-success-subtle text-content-success dark:text-content-success-subtle`,
        brand: `bg-surface-brand text-content-brand dark:bg-content-brand/25 dark:text-surface-brand/80`,
      },
      defaultVariants: { variant: `default` },
    },
  }),
  c = (0, a.forwardRef)(({ counter: e, variant: t, className: n, ...r }, a) =>
    (0, o.jsx)(`span`, { ref: a, className: i(s({ variant: t }), n), ...r, children: e }),
  );
c.displayName = `Counter`;
var l = ({ size: e, className: t, ...n }) => {
    switch (e) {
      case `sm`:
        return (0, o.jsx)(`svg`, {
          className: t,
          ...n,
          width: `16`,
          height: `16`,
          viewBox: `0 0 24 24`,
          fill: `none`,
          xmlns: `http://www.w3.org/2000/svg`,
          children: (0, o.jsx)(`path`, {
            d: `M14 5.75L20.25 12L14 18.25M19.5 12H3.75`,
            stroke: `currentColor`,
            strokeWidth: `1.5`,
            strokeLinecap: `square`,
          }),
        });
      case `base`:
        return (0, o.jsx)(`svg`, {
          className: t,
          ...n,
          width: `20`,
          height: `20`,
          viewBox: `0 0 24 24`,
          fill: `none`,
          xmlns: `http://www.w3.org/2000/svg`,
          children: (0, o.jsx)(`path`, {
            d: `M14 5.75L20.25 12L14 18.25M19.5 12H3.75`,
            stroke: `currentColor`,
            strokeWidth: `1.5`,
            strokeLinecap: `square`,
          }),
        });
      case `lg`:
        return (0, o.jsx)(`svg`, {
          className: t,
          ...n,
          width: `24`,
          height: `24`,
          viewBox: `0 0 24 24`,
          fill: `none`,
          xmlns: `http://www.w3.org/2000/svg`,
          children: (0, o.jsx)(`path`, {
            d: `M14 5.75L20.25 12L14 18.25M19.5 12H3.75`,
            stroke: `currentColor`,
            strokeWidth: `1.5`,
            strokeLinecap: `square`,
          }),
        });
    }
  },
  u = ({ size: e, className: t, ...n }) => {
    switch (e) {
      case `sm`:
        return (0, o.jsxs)(`svg`, {
          className: t,
          ...n,
          width: `16`,
          height: `16`,
          viewBox: `0 0 16 16`,
          fill: `none`,
          xmlns: `http://www.w3.org/2000/svg`,
          children: [
            (0, o.jsx)(`path`, {
              d: `M14 10.6667V12.6667C14 13.0203 13.8595 13.3594 13.6095 13.6095C13.3594 13.8595 13.0203 14 12.6667 14H3.33333C2.97971 14 2.64057 13.8595 2.39052 13.6095C2.14048 13.3594 2 13.0203 2 12.6667V10.6667`,
              stroke: `currentColor`,
              strokeWidth: `1.33333`,
              strokeLinecap: `round`,
              strokeLinejoin: `round`,
            }),
            (0, o.jsx)(`path`, {
              d: `M4.66675 6.66669L8.00008 10.0001L11.3334 6.66669`,
              stroke: `currentColor`,
              strokeWidth: `1.33333`,
              strokeLinecap: `round`,
              strokeLinejoin: `round`,
            }),
            (0, o.jsx)(`path`, {
              d: `M8 10V2`,
              stroke: `currentColor`,
              strokeWidth: `1.33333`,
              strokeLinecap: `round`,
              strokeLinejoin: `round`,
            }),
          ],
        });
      case `lg`:
        return (0, o.jsxs)(`svg`, {
          className: t,
          ...n,
          width: `24`,
          height: `24`,
          viewBox: `0 0 24 24`,
          fill: `none`,
          xmlns: `http://www.w3.org/2000/svg`,
          children: [
            (0, o.jsx)(`path`, {
              d: `M21 15V19C21 19.5304 20.7893 20.0391 20.4142 20.4142C20.0391 20.7893 19.5304 21 19 21H5C4.46957 21 3.96086 20.7893 3.58579 20.4142C3.21071 20.0391 3 19.5304 3 19V15`,
              stroke: `currentColor`,
              strokeWidth: `2`,
              strokeLinecap: `round`,
              strokeLinejoin: `round`,
            }),
            (0, o.jsx)(`path`, {
              d: `M7 10L12 15L17 10`,
              stroke: `currentColor`,
              strokeWidth: `2`,
              strokeLinecap: `round`,
              strokeLinejoin: `round`,
            }),
            (0, o.jsx)(`path`, {
              d: `M12 15V3`,
              stroke: `currentColor`,
              strokeWidth: `2`,
              strokeLinecap: `round`,
              strokeLinejoin: `round`,
            }),
          ],
        });
      case `base`:
        return (0, o.jsxs)(`svg`, {
          className: t,
          ...n,
          width: `20`,
          height: `20`,
          viewBox: `0 0 20 20`,
          fill: `none`,
          xmlns: `http://www.w3.org/2000/svg`,
          children: [
            (0, o.jsx)(`path`, {
              d: `M17.5 12.5V15.8333C17.5 16.2754 17.3244 16.6993 17.0118 17.0118C16.6993 17.3244 16.2754 17.5 15.8333 17.5H4.16667C3.72464 17.5 3.30072 17.3244 2.98816 17.0118C2.67559 16.6993 2.5 16.2754 2.5 15.8333V12.5`,
              stroke: `currentColor`,
              strokeWidth: `1.66667`,
              strokeLinecap: `round`,
              strokeLinejoin: `round`,
            }),
            (0, o.jsx)(`path`, {
              d: `M5.83325 8.33331L9.99992 12.5L14.1666 8.33331`,
              stroke: `currentColor`,
              strokeWidth: `1.66667`,
              strokeLinecap: `round`,
              strokeLinejoin: `round`,
            }),
            (0, o.jsx)(`path`, {
              d: `M10 12.5V2.5`,
              stroke: `currentColor`,
              strokeWidth: `1.66667`,
              strokeLinecap: `round`,
              strokeLinejoin: `round`,
            }),
          ],
        });
    }
  };
export { l as n, c as r, u as t };

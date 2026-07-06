import { v_ as e } from "./vendor-DAwbZtf0.js";
import { n as t } from "./headings-CM9JBOhQ.js";
var n = e(),
  r = ({ title: e, description: r, children: i, "data-testid": a }) =>
    (0, n.jsx)(`div`, {
      className: `flex flex-col items-center gap-4 overflow-hidden rounded-xl border-[0.5px] border-border-base bg-surface-primary px-5 py-4`,
      "data-testid": a ?? `empty-state-card`,
      children: (0, n.jsxs)(`div`, {
        className: `flex flex-col items-center gap-2 py-10 text-center`,
        children: [
          (0, n.jsx)(t, { className: `text-xl text-content-primary`, children: e }),
          (0, n.jsx)(`div`, { className: `text-base text-content-secondary`, children: r }),
          i && (0, n.jsx)(`div`, { className: `mt-4 flex flex-row gap-2`, children: i }),
        ],
      }),
    });
export { r as t };

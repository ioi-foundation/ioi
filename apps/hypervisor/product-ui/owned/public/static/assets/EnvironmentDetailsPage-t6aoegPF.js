import { n as e } from "./rolldown-runtime-CGYlQKCx.js";
import { v_ as t, wg as n } from "./vendor-DAwbZtf0.js";
import { C as r } from "./environment-queries-zpiLcWfm.js";
import { t as i } from "./IconBox-CN7VludW.js";
import { t as a } from "./EnvironmentDetails-DdRfHTIu.js";
var o = e({ EnvironmentDetailsNotFound: () => l, EnvironmentDetailsPage: () => c }),
  s = t(),
  c = () => {
    let { environmentId: e } = n(),
      { data: t, isPending: i } = r(e);
    return !i && !t ? (0, s.jsx)(l, {}) : (0, s.jsx)(a, { environmentId: e || `` });
  },
  l = () =>
    (0, s.jsxs)(`div`, {
      className: `flex h-full flex-col items-center justify-center px-4 text-center`,
      children: [
        (0, s.jsx)(i, { state: `open`, className: `mb-10 h-16 w-16 shrink-0 animate-rotateBox text-content-primary` }),
        (0, s.jsx)(`h1`, {
          className: `mb-2 text-xl font-semibold text-content-primary`,
          children: `That environment doesn’t exist`,
        }),
        (0, s.jsx)(`p`, { className: `text-lg text-content-secondary`, children: `You can always create a new one.` }),
      ],
    });
export { o as n, l as t };

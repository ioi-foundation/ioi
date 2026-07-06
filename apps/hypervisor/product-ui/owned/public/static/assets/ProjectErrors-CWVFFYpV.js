import { a as e } from "./rolldown-runtime-CGYlQKCx.js";
import { n as t } from "./@mux-DLaEVubF.js";
import { $g as n, __ as r, cg as i, v_ as a } from "./vendor-DAwbZtf0.js";
import { tr as o } from "./use-boot-in-app-chat-t-J_VjKS.js";
import { t as s } from "./button-6YP03Qf2.js";
import { n as c } from "./headings-CM9JBOhQ.js";
import { t as l } from "./text-fFCFeCas.js";
import { t as u } from "./IconRefresh-Clasnt5q.js";
import { t as d } from "./SadBax-BJA2xvOe.js";
var f = e(t(), 1),
  p = a(),
  m = (e) => {
    let t = !0;
    return e instanceof n
      ? e.code === r.NotFound
        ? {
            title: `We could not find the project you're looking for.`,
            description: `It may have been deleted, or you might be lacking permissions to access it.`,
            retriable: !1,
          }
        : (e.code === r.InvalidArgument && (t = !1), { message: o(e), retriable: t })
      : { retriable: t };
  },
  h = ({ error: e }) => {
    let t = (0, f.useCallback)(() => {
        window.location.reload();
      }, []),
      { title: n, message: r, description: a, retriable: o } = m(e ?? void 0);
    return (0, p.jsxs)(`div`, {
      className: `flex flex-col items-center gap-5 p-12`,
      "data-testid": `error-failed-to-load-project-data`,
      children: [
        (0, p.jsx)(d, {}),
        (0, p.jsxs)(`div`, {
          className: `flex flex-col items-center gap-4`,
          children: [
            (0, p.jsx)(c, {
              className: `text-xl font-bold text-content-primary`,
              children: n ?? `We're having trouble loading the project.`,
            }),
            r && (0, p.jsx)(`pre`, { children: (0, p.jsx)(`code`, { children: r }) }),
            (0, p.jsx)(l, {
              className: `text-lg text-content-secondary`,
              children: a ?? `You can try refreshing the page. If the problem persists, please contact support.`,
            }),
          ],
        }),
        o
          ? (0, p.jsx)(s, {
              variant: `secondary`,
              LeadingIcon: u,
              onClick: t,
              "data-tracking-id": `refresh-page-project-failed-to-load`,
              children: `Refresh page`,
            })
          : (0, p.jsx)(s, { asChild: !0, children: (0, p.jsx)(i, { to: `/projects`, children: `Back to Projects` }) }),
      ],
    });
  };
export { h as t };

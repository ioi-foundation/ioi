import { a as e } from "./rolldown-runtime-CGYlQKCx.js";
import { n as t } from "./@mux-DLaEVubF.js";
import { v_ as n } from "./vendor-DAwbZtf0.js";
import { tr as r } from "./use-boot-in-app-chat-t-J_VjKS.js";
import { n as i } from "./toast-axaLeIzZ.js";
import { i as a, t as o } from "./button-6YP03Qf2.js";
import { t as s } from "./cn-DppMFCU8.js";
import { t as c } from "./use-temporary-value-Bpxt61FD.js";
import { t as l } from "./tooltip-6hqVQbwq.js";
import { t as u } from "./IconCopy-N69_gkkW.js";
import { t as d } from "./IconCheckCircle-D5lhsn3C.js";
import "./log-groups-DdYND1nW.js";
import { o as f } from "./use-stream-logs-base-CWzUgDEp.js";
var p = e(t(), 1),
  m = n(),
  h = ({ logGroups: e, trackingId: t = `copy-all-logs`, variant: n = `ghost`, size: h = `sm`, className: g }) => {
    let { toast: _ } = i(),
      [v, y] = c(0, 2e3),
      b = e && Object.keys(e).length === 1 && e[`no-log-group`]?.lines?.length > 0,
      x = (0, p.useCallback)(async () => {
        if (e)
          try {
            let t = f(e, !!b);
            (await navigator.clipboard.writeText(t), y(1));
          } catch (e) {
            _({ title: `Failed to copy logs`, description: r(e) });
          }
      }, [e, b, y, _]),
      S = v === 1,
      C = S || !e;
    return (0, m.jsx)(l, {
      content: e ? `Copy all logs to clipboard` : `No logs available to copy`,
      usePortal: !0,
      children: (0, m.jsx)(`span`, {
        className: `inline-flex`,
        tabIndex: C ? 0 : void 0,
        children: (0, m.jsxs)(o, {
          variant: n,
          size: h,
          className: s(`border-0`, S && `disabled:opacity-100`, g),
          disabled: C,
          onClick: x,
          "aria-label": `Copy all logs`,
          "data-tracking-id": t,
          children: [
            (0, m.jsx)(a, {
              icons: [(0, m.jsx)(u, { size: `sm` }, `copy`), (0, m.jsx)(d, { size: `sm` }, `check`)],
              activeIndex: v,
              className: `size-3.5`,
            }),
            (0, m.jsxs)(`span`, {
              className: `relative inline-flex h-5 overflow-hidden`,
              children: [
                (0, m.jsx)(`span`, {
                  className: s(
                    `inline-block transition-transform duration-300 ease-out motion-reduce:transition-none`,
                    S ? `-translate-y-full` : `translate-y-0`,
                  ),
                  children: `Copy logs`,
                }),
                (0, m.jsx)(`span`, {
                  className: s(
                    `absolute left-0 inline-block transition-transform duration-300 ease-out motion-reduce:transition-none`,
                    S ? `translate-y-0` : `translate-y-full`,
                  ),
                  children: `Copied!`,
                }),
              ],
            }),
          ],
        }),
      }),
    });
  };
export { h as t };

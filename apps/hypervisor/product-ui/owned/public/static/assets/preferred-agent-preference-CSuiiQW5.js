import { a as e } from "./rolldown-runtime-CGYlQKCx.js";
import { n as t } from "./@mux-DLaEVubF.js";
import { kp as n, v_ as r } from "./vendor-DAwbZtf0.js";
import { it as i, ot as a } from "./use-boot-in-app-chat-t-J_VjKS.js";
import { t as o } from "./cn-DppMFCU8.js";
import { R as s } from "./agent-queries-CGWy3JAw.js";
import { r as c } from "./dropdown-menu-D3UmjGpQ.js";
import { n as l, t as u } from "./agent-mode-visuals-DTOFpRnw.js";
import { a as d, g as f, s as p, t as m } from "./agent-mode-ClxEfnvU.js";
var h = r(),
  g = ({ mode: e, availableModes: t, onModeChange: r, trackingIdPrefix: i = `agent-mode` }) =>
    (0, h.jsx)(h.Fragment, {
      children: t.map((t) =>
        (0, h.jsxs)(
          c.Item,
          {
            onClick: () => r(t),
            "data-tracking-id": `${i}-${t}`,
            className: `h-auto items-start py-1.5`,
            children: [
              (0, h.jsx)(`div`, { className: `mt-0.5 shrink-0`, children: u(t, 16) }),
              (0, h.jsxs)(`div`, {
                className: `ml-2 flex min-w-0 flex-1 flex-col`,
                children: [
                  (0, h.jsx)(`span`, { className: o(`text-sm`, l(t)), children: p(t) }),
                  (0, h.jsx)(`span`, { className: `text-sm font-normal text-content-secondary`, children: d(t) }),
                ],
              }),
              e === t && (0, h.jsx)(n, { size: 14, className: `ml-auto mt-0.5 shrink-0` }),
            ],
          },
          t,
        ),
      ),
    }),
  _ = e(t(), 1),
  v = `PREFERRED_AGENT`;
function y(e) {
  return f(e) ? s.InEnvironmentCodexAppAgent.id : s.InEnvironmentIOI.id;
}
function b(e) {
  if (e === s.InEnvironmentCodexAppAgent.id) return m.CodexApp;
  if (e === s.InEnvironmentIOI.id) return m.Agent;
}
function x(e) {
  let t = e?.trim();
  if (t === s.InEnvironmentCodexAppAgent.id || t === s.InEnvironmentIOI.id) return t;
}
function S(e) {
  if (!(e.preferredAgentId === s.InEnvironmentCodexAppAgent.id && !e.codexRolloutEnabled)) return e.preferredAgentId;
}
function C(e) {
  let { data: t, isFetched: n } = i(v),
    { mutateAsync: r } = a(),
    o = (0, _.useMemo)(() => S({ preferredAgentId: x(t?.value), codexRolloutEnabled: e }), [e, t?.value]),
    s = (0, _.useCallback)(
      (e) => {
        r({ key: v, value: y(e) }).catch((e) => {
          console.error(`Failed to persist preferred agent`, e);
        });
      },
      [r],
    );
  return { preferredAgentId: o, preferredAgentMode: b(o), isFetched: n, setPreferredAgentMode: s };
}
export { g as n, C as t };

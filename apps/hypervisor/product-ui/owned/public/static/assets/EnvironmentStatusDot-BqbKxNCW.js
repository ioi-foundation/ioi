import { a as e } from "./rolldown-runtime-CGYlQKCx.js";
import { n as t } from "./@mux-DLaEVubF.js";
import { v_ as n } from "./vendor-DAwbZtf0.js";
import { so as r } from "./use-boot-in-app-chat-t-J_VjKS.js";
import { t as i } from "./cn-DppMFCU8.js";
import { n as a } from "./phase-DI4YEQQ1.js";
import { t as o } from "./status-dot-DyGV7NWq.js";
import { l as s } from "./environment-paa_Ds61.js";
var c = e(t(), 1),
  l = n(),
  u = ({ env: e, size: t, className: n }) => {
    let u = (0, c.useMemo)(() => a(e), [e]),
      d = (0, c.useMemo)(() => s(u), [u]),
      {
        color: f,
        variant: p,
        animation: m,
      } = (0, c.useMemo)(() => {
        switch (u.state) {
          case r.RUNNING:
            return { color: `green`, variant: `solid`, animation: `none` };
          case r.UPDATING:
          case r.STARTING:
          case r.CREATING:
            return { color: `brand`, variant: `ring`, animation: `none` };
          case r.STOPPING:
          case r.DELETING:
            return { color: `brand`, variant: `solid`, animation: `fade` };
          case r.STOPPED:
            return u.failures
              ? { color: `red`, variant: `solid`, animation: `none` }
              : { color: `gray`, variant: `small`, animation: `none` };
          default:
            return { color: `gray`, variant: `small`, animation: `none` };
        }
      }, [u]);
    return (0, l.jsx)(`span`, {
      "data-testid": `environment-status-dot`,
      className: i(`align-middle`, n),
      children: (0, l.jsx)(o, {
        size: t,
        color: f,
        variant: p,
        animation: m,
        tooltip: d,
        className: `inline-block align-middle`,
      }),
    });
  };
export { u as t };

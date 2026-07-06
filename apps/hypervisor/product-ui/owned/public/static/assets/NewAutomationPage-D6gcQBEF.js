import { a as e } from "./rolldown-runtime-CGYlQKCx.js";
import { Lt as t, Wr as n } from "./SegmentProvider-CXCNBY9U.js";
import { n as r } from "./@mux-DLaEVubF.js";
import { dg as i, v_ as a } from "./vendor-DAwbZtf0.js";
import { n as o, t as s } from "./automation-templates-DtH5fiQ2.js";
import { AutomationEditPage as c } from "./AutomationEditPage-B55rMjFC.js";
var l = e(r(), 1),
  u = a(),
  d = o(`start-from-scratch`),
  f = () => {
    t(`New Automation`);
    let [e] = i(),
      r = e.get(`template`),
      a = e.get(`duplicate`),
      { data: f } = n(a ?? void 0),
      p = (0, l.useMemo)(() => (a && f ? s(f) : (r && o(r)) || d), [r, a, f]);
    return a && !f ? null : (0, u.jsx)(c, { template: p });
  };
export { f as NewAutomationPage };

import { xn as e, yn as t } from "./SegmentProvider-CXCNBY9U.js";
import { fg as n, v_ as r } from "./vendor-DAwbZtf0.js";
import { at as i } from "./main-DLKYFe1Y.js";
var a = r(),
  o = ({ children: r }) => {
    let { accessLevel: o, isLoading: s } = e();
    return s
      ? (0, a.jsx)(i, {})
      : o === t.Full
        ? (0, a.jsx)(a.Fragment, { children: r })
        : (0, a.jsx)(n, { to: `/`, replace: !0 });
  };
export { o as RequireFullAutomationAccess };

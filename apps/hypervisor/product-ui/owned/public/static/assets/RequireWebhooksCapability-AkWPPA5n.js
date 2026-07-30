import { bn as e, xn as t } from "./SegmentProvider-CXCNBY9U.js";
import { fg as n, v_ as r } from "./vendor-DAwbZtf0.js";
import { N as i } from "./automations-CN21BoUy.js";
import { at as a } from "./main-DLKYFe1Y.js";
var o = r(),
  s = ({ children: r }) => {
    let { capabilities: s, isLoading: c } = t();
    return c
      ? (0, o.jsx)(a, {})
      : s.has(e.Webhooks)
        ? (0, o.jsx)(o.Fragment, { children: r })
        : (0, o.jsx)(n, { to: i(), replace: !0 });
  };
export { s as RequireWebhooksCapability };

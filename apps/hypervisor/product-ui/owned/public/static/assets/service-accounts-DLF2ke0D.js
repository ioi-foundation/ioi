import { Gs as e, v_ as t } from "./vendor-DAwbZtf0.js";
import { n } from "./utils-C9bSuXia.js";
import { t as r } from "./avatar-CjN22mGB.js";
var i = `` + globalThis.__toAssetUrl(`assets/ioi-service-account-avatar-C04VslwU.jpg`),
  a = t(),
  o = n(e),
  s = ({ id: e, size: t = 32, isIOIServiceAccount: n, className: s }) =>
    n
      ? (0, a.jsx)(r, { size: t, className: s, children: (0, a.jsx)(r.Image, { src: i, alt: `IOI` }) })
      : (0, a.jsx)(r, {
          size: t,
          children: (0, a.jsx)(r.StaticIcon, {
            identifier: e,
            size: t,
            className: s,
            children: (0, a.jsx)(o, { className: `shrink`, size: `sm` }),
          }),
        }),
  c = () => `/settings/members#service-accounts`,
  l = ({ id: e }) => `/settings/members/service-account/${e}`,
  u = new Date(`2099-01-01T00:00:00Z`),
  d = (e) => e >= u,
  f = (e) => (e ? !!e.systemManaged && e.name === `IOI` : !1);
export { s as a, c as i, f as n, l as r, d as t };

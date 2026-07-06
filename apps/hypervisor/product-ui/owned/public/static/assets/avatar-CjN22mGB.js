import { a as e } from "./rolldown-runtime-CGYlQKCx.js";
import { n as t } from "./@mux-DLaEVubF.js";
import { Ad as n, jd as r, kd as i, v_ as a } from "./vendor-DAwbZtf0.js";
import { t as o } from "./cn-DppMFCU8.js";
var s = e(t(), 1),
  c = a(),
  l = [
    o(`bg-surface-brand-accent-01 text-content-brand-accent-02`),
    o(`bg-surface-brand-accent-02 text-content-brand-accent-02`),
    o(`bg-surface-brand-accent-03 text-content-brand-accent-02`),
    o(`bg-surface-brand-accent-04 text-content-brand-accent-03`),
    o(`bg-surface-brand-accent-05 text-content-brand`),
    o(`bg-surface-brand-accent-06 text-content-brand-accent-04`),
    o(`bg-surface-brand-accent-07 text-content-brand-accent-05`),
    o(`bg-surface-brand-accent-08 text-content-brand-accent-06`),
    o(`bg-surface-brand-accent-09 text-content-brand-accent-07`),
  ],
  u = (e) => {
    let t = 0,
      n = e.length;
    for (let r = 0; r < n; r++) t = ((t << 5) - t + e.charCodeAt(r)) & 4294967295;
    return Math.abs(t);
  },
  d = (e) => {
    if (!e) return `?`;
    let t = e
      .split(` `)
      .filter((e) => !!e)
      .map((e) => e.replace(/[^a-zA-Z]/g, ``))
      .filter((e) => e.length > 0);
    return t.length === 0
      ? `?`
      : t.length === 1
        ? t[0].substring(0, 1).toUpperCase()
        : t
            .map((e) => e[0])
            .join(``)
            .substring(0, 2)
            .toUpperCase();
  },
  f = {
    16: { container: `size-4`, font: o(`text-[10px] leading-4`) },
    24: { container: `size-6`, font: o(`text-xs leading-6`) },
    32: { container: `size-8`, font: o(`text-xs leading-8`) },
    48: { container: `size-12`, font: o(`text-sm leading-12`) },
  },
  p = (0, s.forwardRef)(function ({ className: e, size: t = 32, ...n }, i) {
    let a = f[t];
    return (0, c.jsx)(r, {
      ref: i,
      "data-slot": `avatar`,
      className: o(`relative flex shrink-0 overflow-hidden rounded-full`, a.container, e),
      ...n,
    });
  });
p.displayName = `Avatar`;
function m({ className: e, loading: t = `lazy`, ...r }) {
  return (0, c.jsx)(n, {
    "data-slot": `avatar-image`,
    "data-testid": `avatar-image`,
    className: o(`aspect-square size-full object-cover`, e),
    referrerPolicy: `no-referrer`,
    loading: t,
    ...r,
  });
}
function h({ className: e, ...t }) {
  return (0, c.jsx)(i, {
    "data-slot": `avatar-fallback`,
    className: o(`flex size-full items-center justify-center rounded-full`, e),
    ...t,
  });
}
var g = (0, s.memo)(({ name: e, size: t = 32, className: n }) => {
  let r = (0, s.useMemo)(() => d(e), [e]),
    i = (0, s.useMemo)(() => l[u(e) % l.length], [e]),
    a = f[t];
  return (0, c.jsx)(`div`, {
    className: o(`inline-flex size-full select-none items-center justify-center font-medium`, a.font, i, n),
    role: `img`,
    "aria-label": `${e}'s avatar`,
    children: (0, c.jsx)(`span`, { className: `inline-block text-center`, children: r }),
  });
});
g.displayName = `AvatarInitials`;
var _ = (0, s.memo)(({ identifier: e, size: t = 32, children: n, className: r }) => {
  let i = (0, s.useMemo)(() => l[u(e) % l.length], [e]),
    a = f[t];
  return (0, c.jsx)(`div`, {
    className: o(`inline-flex size-full select-none items-center justify-center`, a.font, i, r),
    role: `img`,
    "aria-label": `${e}'s avatar`,
    children: n,
  });
});
_.displayName = `AvatarStaticIcon`;
var v = Object.assign(p, { Image: m, Fallback: h, Initials: g, StaticIcon: _ });
export { v as t };

import { v_ as e } from "./vendor-DAwbZtf0.js";
import { t } from "./cn-DppMFCU8.js";
var n = e(),
  r = { xs: `size-6 text-xs`, sm: `size-8 text-sm`, md: `size-10 text-sm`, lg: `size-12 text-base` },
  i = (e) => {
    let t = [
        `bg-blue-500`,
        `bg-green-500`,
        `bg-purple-500`,
        `bg-orange-500`,
        `bg-pink-500`,
        `bg-indigo-500`,
        `bg-teal-500`,
        `bg-red-500`,
        `bg-yellow-500`,
        `bg-cyan-500`,
      ],
      n = 0;
    for (let t = 0; t < e.length; t++) ((n = (n << 5) - n + e.charCodeAt(t)), (n &= n));
    return t[Math.abs(n) % t.length];
  },
  a = (e) =>
    e
      .split(/\s+/)
      .map((e) => e[0])
      .join(``)
      .toUpperCase()
      .substring(0, 2),
  o = ({ groupName: e, size: o = `md`, className: s }) => {
    let c = a(e),
      l = i(e);
    return (0, n.jsx)(`div`, {
      className: t(`flex items-center justify-center rounded-md font-medium text-white`, r[o], l, s),
      title: e,
      children: c,
    });
  };
export { o as t };

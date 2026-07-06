import { t as e } from "./strings-C6LrS0GJ.js";
import { t } from "./timestamp-CEKPQVte.js";
var n = new Intl.RelativeTimeFormat(`en`, { style: `narrow` });
function r(e, t = n) {
  let r = e.getTime(),
    i = Math.round((r - Date.now()) / 1e3),
    a = [
      [60, `second`],
      [3600, `minute`],
      [3600 * 24, `hour`],
      [3600 * 24 * 7, `day`],
      [3600 * 24 * 30, `week`],
      [3600 * 24 * 365, `month`],
      [1 / 0, `year`],
    ],
    o = a.findIndex(([e]) => e > Math.abs(i)),
    s = a[o],
    c = a[o - 1] ? a[o - 1][0] : 1;
  return t.format(Math.round(i / c), s[1]);
}
var i = Intl.DateTimeFormat(`en`, { timeStyle: `medium` });
function a(e) {
  return i.format(e);
}
var o = Intl.DateTimeFormat(`en`, { dateStyle: `medium`, timeStyle: `short` });
function s(e) {
  return o.format(e);
}
function c(t, n = `short`, r = `base`) {
  if (t < 60) {
    let r = Math.ceil(Math.max(t, 0));
    return n === `short` ? `${r}s` : `${r} ` + e(r, `second`);
  }
  let i = (t, r, i) => {
    if (t <= 0) return ``;
    let a = new Intl.NumberFormat(`en-US`, { minimumIntegerDigits: 1, maximumFractionDigits: 0 }).format(t);
    return n === `short` ? `${a}${r} ` : `${a} ${e(t, i)} `;
  };
  if (r === `coarse`) {
    let r = (t, r, i) => (n === `short` ? `${t}${r}` : `${t} ${e(t, i)}`),
      i = Math.round(t / (24 * 3600));
    if (i >= 28) return r(Math.round(i / 30), `mo`, `month`);
    if (i >= 1) return r(i, `d`, `day`);
    let a = Math.round(t / 3600);
    if (a >= 1) return r(a, `h`, `hour`);
    let o = Math.round(t / 60);
    return o >= 1 ? r(o, `m`, `minute`) : r(Math.ceil(t), `s`, `second`);
  }
  if (r === `base`) {
    let e = Math.floor(t / 3600),
      n = Math.floor((t % 3600) / 60),
      r = (t % 3600) % 60;
    return (i(e, `h`, `hour`) + i(n, `m`, `minute`) + i(r, `s`, `second`)).trim();
  }
  let a = Math.floor(t / (168 * 3600)),
    o = Math.floor((t % (168 * 3600)) / (24 * 3600)),
    s = Math.floor((t % (24 * 3600)) / 3600),
    c = Math.floor((t % 3600) / 60),
    l = (t % 3600) % 60;
  return (i(a, `w`, `week`) + i(o, `d`, `day`) + i(s, `h`, `hour`) + i(c, `m`, `minute`) + i(l, `s`, `second`)).trim();
}
var l = (t, n = `short`) => {
    let r = Math.floor(t / 3600),
      i = Math.floor((t % 3600) / 60);
    return r < 1
      ? n === `short`
        ? `${i}m`
        : `${i} ` + e(i, `minute`)
      : n === `short`
        ? `${r.toLocaleString()}h`
        : `${r.toLocaleString()} ` + e(r, `hour`);
  },
  u = (e) => {
    if (e <= 0) return `—`;
    let t = e / 60;
    if (t < 1) return `<1m`;
    if (t < 120) return `${Math.round(t)}m`;
    let n = e / 3600;
    return n < 24 ? `${n.toFixed(1)}h` : `${(n / 24).toFixed(1)}d`;
  },
  d = (e, t = !1) => {
    if (!e || isNaN(e.getTime())) return ``;
    let n = { month: `short`, day: `numeric` };
    return (t && (n.year = `numeric`), new Intl.DateTimeFormat(`en-US`, n).format(e));
  },
  f = (e, t = `short`, n) => {
    if (!e || isNaN(e.getTime())) return ``;
    let r = e.getFullYear() !== new Date().getFullYear(),
      i = { month: t, day: `numeric`, timeZone: n };
    return (r && (i.year = `numeric`), new Intl.DateTimeFormat(`en-US`, i).format(e));
  },
  p = (e, n, r = `short`, i = `base`) => m(t(e), t(n), r, i),
  m = (e, t, n = `short`, r = `base`) => c(Math.abs(t.getTime() - e.getTime()) / 1e3, n, r),
  h = (e) => {
    if (!e || isNaN(e.getTime())) return ``;
    let t = new Date(),
      n = e.getDate() === t.getDate() && e.getMonth() === t.getMonth() && e.getFullYear() === t.getFullYear(),
      r = new Intl.DateTimeFormat(`en-US`, { hour: `2-digit`, minute: `2-digit`, hour12: !1 }).format(e);
    return n
      ? `Today, ${r}`
      : `${new Intl.DateTimeFormat(`en-US`, { month: `short`, day: `numeric` }).format(e)}, ${r}`;
  };
export { f as a, a as c, r as d, s as i, l, m as n, h as o, p as r, u as s, c as t, d as u };

import { l as e } from "./time-DxjbKG-a.js";
var t = 3600,
  n = 24 * t;
function r(e) {
  let t = (e) => e.toString().padStart(2, `0`);
  return `${e.getFullYear()}-${t(e.getMonth() + 1)}-${t(e.getDate())}T${t(e.getHours())}:${t(e.getMinutes())}`;
}
var i = [
  { label: `1 hour`, value: 1 * t },
  { label: `8 hours`, value: 8 * t },
  { label: `1 day`, value: 1 * n },
  { label: `3 days`, value: 3 * n },
  { label: `1 week`, value: 7 * n },
  { label: `2 weeks`, value: 14 * n },
  { label: `1 month`, value: 30 * n },
];
function a(r) {
  let a = i.find((e) => e.value === r);
  if (a) return a.label;
  let o = Math.floor(r / t);
  if (o > 0 && r % t === 0 && o < 24) return `${o} hour${o === 1 ? `` : `s`}`;
  let s = Math.floor(r / n);
  return s > 0 && r % n === 0 ? `${s} day${s === 1 ? `` : `s`}` : e(r, `long`);
}
export { a as n, r, i as t };

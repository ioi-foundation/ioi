import { Fd as e, Nd as t, Vd as n } from "./vendor-DAwbZtf0.js";
var r = n(!1),
  i = n(!1),
  a = t((e) => n(!1)),
  o = n(null),
  s = n(null),
  c = n(0),
  l = n(0),
  u = n({ tab: `conversation`, seq: 0 }),
  d = n({ type: `changes` }),
  f = n({ filePath: ``, lineNumber: null, seq: 0 }),
  p = n(null),
  m = n(null),
  h = t((e) => n(!1)),
  g = (e, t) => `${e}:${t}`,
  _ = n(0),
  v = n(!1),
  y = n(!1),
  b = t((e) => n(`idle`)),
  x = t((e) => n(null)),
  S = n({ url: ``, seq: 0 }),
  C = n(0),
  w = n(0),
  T = t((e) => n(!1)),
  E = n(`sessions`),
  D = `sessions-filter`;
function O() {
  try {
    let e = localStorage.getItem(D);
    if (e === `project` || e === `recently-active`) return e;
  } catch {}
  return `project`;
}
var k = n(O()),
  A = e(`projects-view-mode`, `cards`);
export {
  c as C,
  E as D,
  k as E,
  s as S,
  d as T,
  _,
  S as a,
  A as b,
  i as c,
  T as d,
  o as f,
  h as g,
  g as h,
  y as i,
  u as l,
  f as m,
  m as n,
  x as o,
  p,
  v as r,
  b as s,
  D as t,
  w as u,
  C as v,
  l as w,
  a as x,
  r as y,
};

import { a as e } from "./rolldown-runtime-CGYlQKCx.js";
import { n as t } from "./@mux-DLaEVubF.js";
var n = e(t(), 1),
  r = new Map();
function i(e) {
  let t = r.get(e);
  if (t) return t;
  if (typeof window > `u`)
    return ((t = { subscribe: () => () => {}, getSnapshot: () => !1, getServerSnapshot: () => !1 }), r.set(e, t), t);
  let n = window.matchMedia(e),
    i = new Set();
  return (
    n.addEventListener(`change`, () => {
      for (let e of i) e();
    }),
    (t = {
      subscribe(e) {
        return (i.add(e), () => i.delete(e));
      },
      getSnapshot() {
        return n.matches;
      },
      getServerSnapshot() {
        return !1;
      },
    }),
    r.set(e, t),
    t
  );
}
function a(e) {
  let t = i(e);
  return (0, n.useSyncExternalStore)(t.subscribe, t.getSnapshot, t.getServerSnapshot);
}
var o = (0, n.createContext)(null);
o.Provider;
var s = (e = `(max-width: 767px)`) => {
  let t = (0, n.useContext)(o),
    r = a(e);
  return t || { isMobileViewport: r, isPending: !1 };
};
export { s as t };

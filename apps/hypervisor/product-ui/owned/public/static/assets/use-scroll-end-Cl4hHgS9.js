import { a as e } from "./rolldown-runtime-CGYlQKCx.js";
import { n as t } from "./@mux-DLaEVubF.js";
import { Rl as n } from "./vendor-DAwbZtf0.js";
var r = e(t(), 1);
function i({ onScrollEnd: e, threshold: t = 100, debounceMs: i = 500 }) {
  let a = (0, r.useRef)(null),
    o = n(
      () => {
        e?.();
      },
      i,
      { leading: !0, trailing: !0 },
    );
  return {
    scrollContainerRef: a,
    onScroll: (0, r.useCallback)(() => {
      if (!a.current || !e) return;
      let { scrollTop: n, scrollHeight: r, clientHeight: i } = a.current;
      n >= r - i - t && o();
    }, [e, o, t]),
  };
}
export { i as t };

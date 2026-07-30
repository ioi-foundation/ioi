import { a as e } from "./rolldown-runtime-CGYlQKCx.js";
import { n as t } from "./@mux-DLaEVubF.js";
import { vg as n, xg as r } from "./vendor-DAwbZtf0.js";
var i = e(t(), 1);
function a(e) {
  let t = r(),
    a = n();
  return (0, i.useCallback)(() => {
    a.state?.canGoBack ? t(-1) : t(e, { replace: !0 });
  }, [e, a, t]);
}
export { a as t };

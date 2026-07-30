import { a as e } from "./rolldown-runtime-CGYlQKCx.js";
import { n as t } from "./@mux-DLaEVubF.js";
import { Im as n, Lm as r, Rm as i } from "./vendor-DAwbZtf0.js";
var a = e(t(), 1),
  o = [
    `requires_action`,
    `requires_confirmation`,
    `requires_payment_method`,
    `requires_capture`,
    `processing`,
    `succeeded`,
    `canceled`,
  ];
function s() {
  let [e, t] = i(`payment_intent`, n.withDefault(``)),
    [s, c] = i(`payment_intent_client_secret`, n.withDefault(``)),
    [l, u] = i(`setup_intent`, n.withDefault(``)),
    [d, f] = i(`setup_intent_client_secret`, n.withDefault(``)),
    [p, m] = i(`redirect_status`, r(o)),
    h = (0, a.useCallback)(async () => {
      (await t(null), await c(null), await u(null), await f(null), await m(null));
    }, [t, c, u, f, m]);
  return {
    redirectResult: (0, a.useMemo)(
      () =>
        l && d && p
          ? { paymentIntent: l, paymentIntentClientSecret: d, redirectStatus: p }
          : !e || !s || !p
            ? null
            : { paymentIntent: e, paymentIntentClientSecret: s, redirectStatus: p },
      [e, s, l, d, p],
    ),
    clearStripePaymentRedirectParams: h,
  };
}
export { s as t };

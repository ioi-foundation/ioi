import { a as e } from "./rolldown-runtime-CGYlQKCx.js";
import { vn as t } from "./SegmentProvider-CXCNBY9U.js";
import { n } from "./@mux-DLaEVubF.js";
import { Bg as r, Rd as i, Vd as a, cg as o, pg as s, v_ as c, xg as l, zd as u } from "./vendor-DAwbZtf0.js";
import { tr as d } from "./use-boot-in-app-chat-t-J_VjKS.js";
import { p as f, u as p } from "./webhook_pb-C1T_Ekd7.js";
import { t as m } from "./button-6YP03Qf2.js";
import { t as h } from "./cn-DppMFCU8.js";
import { t as g } from "./strings-C6LrS0GJ.js";
import { t as _ } from "./timestamp-CEKPQVte.js";
import { d as v } from "./time-DxjbKG-a.js";
import { n as y } from "./utils-C9bSuXia.js";
import { t as b } from "./Pill-99RRpZf2.js";
import "./pill-AA_qJIlm.js";
import { t as x } from "./text-fFCFeCas.js";
import { t as S } from "./skeleton-Cm867Q_k.js";
import { C, N as w } from "./automations-CN21BoUy.js";
import { t as T } from "./IconRefresh-Clasnt5q.js";
import { t as E } from "./empty-state-D7Bh3L9e.js";
import { g as D, n as O, o as k, t as A } from "./webhook-config-CpInIrBu.js";
import { t as j } from "./NewWebhookConfigurationDialog-CEq61MPe.js";
import { t as M } from "./webhooks-panel-state-Z5IM56Mg.js";
var N = e(n(), 1),
  P = c(),
  F = ({ webhook: e, className: t }) => {
    let n = e.metadata?.name || `Unnamed webhook`,
      r = e.spec?.provider ?? p.UNSPECIFIED,
      i = O[e.spec?.type ?? f.UNSPECIFIED].name,
      a = e.boundWorkflowCount,
      s = A[r].icon,
      c = k(e),
      l = e.lastTriggeredAt ? `Last triggered ${v(_(e.lastTriggeredAt))}` : `Never triggered`;
    return (0, P.jsx)(`li`, {
      className: h(
        `flex items-start gap-3`,
        `hover:bg-surface-hover`,
        `has-[>a:focus-visible]:ring-1 has-[>a:focus-visible]:ring-inset has-[>a:focus-visible]:ring-content-primary`,
        t,
      ),
      "data-testid": `webhook-list-item`,
      children: (0, P.jsxs)(o, {
        to: C(e.id),
        state: { canGoBack: !0 },
        className: `flex min-w-0 flex-1 items-start gap-3 p-3 focus-visible:ring-0`,
        "data-tracking-id": `webhook-list-item`,
        children: [
          (0, P.jsx)(s, { size: `base`, className: `shrink-0` }),
          (0, P.jsxs)(`div`, {
            className: `flex min-w-0 flex-1 flex-col gap-0.5`,
            children: [
              (0, P.jsxs)(`div`, {
                className: `flex items-center gap-1.5`,
                children: [
                  (0, P.jsx)(x, { className: `truncate text-base font-medium`, children: n }),
                  !c && (0, P.jsx)(b, { variant: `warning`, size: `sm`, children: `Setup incomplete` }),
                ],
              }),
              (0, P.jsxs)(x, {
                className: `text-sm text-content-secondary`,
                children: [i, ` • `, a, ` `, g(a, `automation`), ` •`, ` `, l],
              }),
            ],
          }),
        ],
      }),
    });
  },
  I = () => {
    let { data: e, error: t, isPending: n, refetch: r } = D(),
      i = !n && t && (!e || e.length === 0),
      a = !n && !t && e?.length === 0;
    return i
      ? (0, P.jsx)(E, {
          title: `Failed to load webhooks`,
          description: t ? d(t) : `There was an error loading your webhooks.`,
          "data-testid": `webhooks-error-state`,
          children: (0, P.jsx)(m, {
            variant: `secondary`,
            LeadingIcon: T,
            onClick: () => r(),
            "data-tracking-id": `retry-load-webhooks`,
            children: `Retry`,
          }),
        })
      : a
        ? (0, P.jsx)(E, {
            title: `No webhooks configured`,
            description: `Webhooks allow external services to trigger your automations. Create a webhook to get started.`,
            "data-testid": `webhooks-empty-state`,
          })
        : n
          ? (0, P.jsxs)(`div`, {
              className: `flex flex-col gap-2`,
              "data-testid": `webhooks-list`,
              children: [
                (0, P.jsx)(S, { ready: !1, animate: !1, className: `h-[122px] rounded-xl opacity-55` }),
                (0, P.jsx)(S, { ready: !1, animate: !1, className: `h-[122px] rounded-xl opacity-35` }),
                (0, P.jsx)(S, { ready: !1, animate: !1, className: `h-[122px] rounded-xl opacity-15` }),
              ],
            })
          : (0, P.jsx)(`ul`, {
              className: `flex flex-col rounded-xl border border-border-base`,
              "data-testid": `webhooks-list`,
              children: e?.map((e) =>
                (0, P.jsx)(
                  F,
                  {
                    webhook: e,
                    className: `border-b border-border-subtle first:rounded-t-lg last:rounded-b-lg last:border-b-0`,
                  },
                  e.id,
                ),
              ),
            });
  },
  L = y(r),
  R = () => {
    let e = l(),
      n = (0, N.useMemo)(() => a(!1), []),
      r = u(n),
      [o, c] = (0, N.useState)(!1),
      d = (0, N.useRef)(!1),
      f = (0, N.useRef)(null),
      p = i(M),
      g = u(M);
    (0, N.useEffect)(() => {
      let e = requestAnimationFrame(() => {
        c(!0);
      });
      return () => cancelAnimationFrame(e);
    }, []);
    let _ = (0, N.useCallback)(() => {
      d.current || ((d.current = !0), c(!1));
    }, []);
    ((0, N.useEffect)(() => {
      p && (g(!1), _());
    }, [p, g, _]),
      (0, N.useEffect)(() => () => g(!1), [g]));
    let v = (0, N.useCallback)(
      (t) => {
        t.target === t.currentTarget && !o && e(w());
      },
      [o, e],
    );
    return (
      (0, N.useEffect)(() => {
        let e = (e) => {
          e.key === `Escape` && _();
        };
        return (document.addEventListener(`keydown`, e), () => document.removeEventListener(`keydown`, e));
      }, [_]),
      (0, P.jsxs)(P.Fragment, {
        children: [
          (0, P.jsx)(`div`, {
            className: h(
              `absolute inset-0 z-30 transition-opacity duration-300 ease-out`,
              o ? `bg-surface-primary-inverted/10 opacity-100` : `pointer-events-none opacity-0`,
            ),
            onClick: _,
            "aria-hidden": `true`,
            "data-testid": `webhooks-side-panel-backdrop`,
            "data-tracking-id": `close-webhooks-side-panel-backdrop`,
          }),
          (0, P.jsxs)(`div`, {
            ref: f,
            role: `dialog`,
            "aria-label": `Webhooks`,
            className: h(
              `absolute bottom-0 right-0 top-0 z-40 flex w-full max-w-2xl flex-col rounded-r-lg border-l border-border-base bg-surface-primary shadow-lg transition-transform duration-300 ease-out`,
              o ? `translate-x-0` : `translate-x-full`,
            ),
            onTransitionEnd: v,
            "data-testid": `webhooks-side-panel`,
            children: [
              (0, P.jsxs)(`header`, {
                className: `flex shrink-0 items-center justify-between p-6`,
                children: [
                  (0, P.jsx)(`h2`, {
                    className: `text-lg font-medium leading-none tracking-tight text-content-primary`,
                    children: `Webhooks`,
                  }),
                  (0, P.jsxs)(`div`, {
                    className: `flex items-center gap-2`,
                    children: [
                      (0, P.jsx)(m, {
                        variant: `primary`,
                        LeadingIcon: t,
                        onClick: () => r(!0),
                        "data-testid": `new-webhook-button`,
                        "data-tracking-id": `new-webhook-side-panel`,
                        children: `Webhook`,
                      }),
                      (0, P.jsx)(m, {
                        variant: `outline`,
                        "aria-label": `Close webhooks panel`,
                        onClick: _,
                        "data-tracking-id": `close-webhooks-side-panel`,
                        LeadingIcon: L,
                      }),
                    ],
                  }),
                ],
              }),
              (0, P.jsx)(`div`, { className: `flex-1 overflow-y-auto p-6 pt-0`, children: (0, P.jsx)(I, {}) }),
            ],
          }),
          (0, P.jsx)(s, {}),
          (0, P.jsx)(z, { isDialogOpenAtom: n }),
        ],
      })
    );
  },
  z = ({ isDialogOpenAtom: e }) => {
    let t = i(e),
      n = u(e);
    return (0, P.jsx)(j, { open: t, onClose: () => n(!1) });
  };
export { R as WebhooksSidePanel };

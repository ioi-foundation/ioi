const __vite__mapDeps = (
  i,
  m = __vite__mapDeps,
  d = m.f ||
    (m.f = [
      globalThis.__toAssetUrl("assets/vendor-DAwbZtf0.js"),
      globalThis.__toAssetUrl("assets/rolldown-runtime-CGYlQKCx.js"),
      globalThis.__toAssetUrl("assets/@mux-DLaEVubF.js"),
    ]),
) => i.map((i) => d[i]);
import { a as e } from "./rolldown-runtime-CGYlQKCx.js";
import { Br as t, Kr as n, Kt as r, Wr as i } from "./SegmentProvider-CXCNBY9U.js";
import { n as a } from "./@mux-DLaEVubF.js";
import {
  Al as o,
  Gg as s,
  Gh as c,
  Gl as l,
  c_ as u,
  dt as d,
  et as f,
  ft as p,
  nt as m,
  ut as h,
  v_ as g,
  vg as _,
  wg as ee,
  xf as v,
  xg as te,
  zg as y,
} from "./vendor-DAwbZtf0.js";
import { Dt as b, so as x, tr as S } from "./use-boot-in-app-chat-t-J_VjKS.js";
import { h as C, p as w } from "./workflow_pb-DOR6D5WK.js";
import { n as T, t as E } from "./toast-axaLeIzZ.js";
import { a as D, t as O } from "./button-6YP03Qf2.js";
import { t as k } from "./cn-DppMFCU8.js";
import { t as A } from "./dialog-BtjFqa-w.js";
import { t as ne } from "./banner-CFcSGYsz.js";
import { r as j } from "./time-DxjbKG-a.js";
import { n as M } from "./utils-C9bSuXia.js";
import { n as re } from "./headings-CM9JBOhQ.js";
import { t as ie } from "./tooltip-6hqVQbwq.js";
import { t as ae } from "./Pill-99RRpZf2.js";
import "./pill-AA_qJIlm.js";
import { t as N } from "./text-fFCFeCas.js";
import { f as P, u as oe } from "./agent-queries-CGWy3JAw.js";
import { n as se, r as F, t as ce } from "./dropdown-menu-D3UmjGpQ.js";
import { M as I, O as L, o as R } from "./automations-CN21BoUy.js";
import { C as z, v as B } from "./environment-queries-zpiLcWfm.js";
import { g as V } from "./project-queries-BMZ3qCU_.js";
import { i as H, n as U, r as W } from "./support-bundle-D0grXyZU.js";
import { t as G } from "./error-message-Az-KJctk.js";
import { t as le } from "./card-BxeZdx-o.js";
import { t as ue } from "./use-callback-prevent-default-ChBsYLGS.js";
import { n as de, t as fe } from "./use-conversation-stream-CTDIPeab.js";
import { i as pe } from "./StepListContainer-yN6PVsKT.js";
import { a as me, i as K, n as he, o as ge, s as _e } from "./automation-execution-action-DsjZnn4c.js";
var q = e(a(), 1),
  J = g(),
  ve = ({ action: e }) => (0, J.jsx)(ae, { variant: ye(e), size: `lg`, className: `w-fit`, children: _e(e) });
function ye(e) {
  let t = me(e);
  switch (e.status?.phase) {
    case w.PENDING:
    case w.UNSPECIFIED:
    case w.RUNNING:
    case w.STOPPING:
    case w.STOPPED:
    case w.DELETING:
    case w.DELETED:
      return `info`;
    case w.DONE:
      return t ? `warning` : `success`;
  }
}
var be = ({ action: e, open: n, onClose: r }) => {
  let { toast: i } = T(),
    a = t(),
    o = ue(async () => {
      try {
        (await a.mutateAsync(e), r());
      } catch (e) {
        i({ title: `Failed to cancel automation execution action`, description: S(e) });
      }
    }, [a, e, i, r]);
  return (0, J.jsx)(A, {
    open: n,
    onOpenChange: r,
    children: (0, J.jsxs)(A.Content, {
      "data-testid": `cancel-workflow-execution-action-dialog`,
      "data-track-location": b.CancelWorkflowExecutionActionDialog,
      children: [
        (0, J.jsxs)(A.Header, {
          children: [
            (0, J.jsx)(A.Title, { children: `Cancel Automation Execution Action` }),
            (0, J.jsx)(A.Description, {
              children: `Are you sure you want to cancel this automation execution action? Running steps will be stopped.`,
            }),
          ],
        }),
        (0, J.jsx)(A.Body, {
          children: (0, J.jsx)(le, {
            variant: `bordered`,
            className: `border bg-surface-secondary shadow-sm`,
            children: (0, J.jsx)(`div`, {
              className: `flex items-center justify-between gap-1`,
              children: (0, J.jsxs)(`div`, {
                className: `flex items-center gap-1`,
                children: [
                  (0, J.jsx)(N, { className: `text-base font-medium text-content-primary`, children: e.id }),
                  (0, J.jsx)(ve, { action: e }),
                ],
              }),
            }),
          }),
        }),
        (0, J.jsxs)(A.Footer, {
          children: [
            (0, J.jsx)(A.Close, {
              asChild: !0,
              children: (0, J.jsx)(O, {
                variant: `outline`,
                "data-testid": `cancel-workflow-execution-action-dialog-cancel`,
                children: `Cancel`,
              }),
            }),
            (0, J.jsx)(O, {
              variant: `destructive`,
              onClick: o,
              loading: a.isPending,
              "data-testid": `cancel-workflow-execution-action-dialog-confirm`,
              "data-tracking-id": `confirm-cancel-workflow-execution-action-cancel-workflow-execution-action-dialog`,
              children: `Cancel action`,
            }),
          ],
        }),
      ],
    }),
  });
};
function xe(e, t) {
  let n = {
    id: t.id,
    workflowId: t.metadata?.workflowId,
    workflowExecutionId: t.metadata?.workflowExecutionId,
    actionName: t.metadata?.actionName,
    startedAt: t.metadata?.startedAt,
    finishedAt: t.metadata?.finishedAt,
    phase: t.status?.phase,
    environmentId: t.status?.environmentId,
    agentExecutionId: t.status?.agentExecutionId,
    stepStatuses: t.status?.stepStatuses,
    failureMessage: t.status?.failureMessage,
    warningMessage: t.status?.warningMessage,
    failures: t.status?.failures,
    warnings: t.status?.warnings,
    spec: t.spec,
    exportedAt: new Date().toISOString(),
  };
  e.file(
    `action-metadata.json`,
    JSON.stringify(n, (e, t) => (typeof t == `bigint` ? t.toString() : t), 2),
  );
}
var Se = (t) => {
    let n = t?.status?.environmentId,
      r = t?.status?.agentExecutionId,
      { data: i } = z(n),
      { data: a } = B(n),
      { data: o } = P(r),
      { data: s } = oe(r),
      l = i?.status?.environmentUrls?.supportBundle,
      u = o?.status?.supportBundleUrl,
      d = !!l && !!a,
      f = !!u && !!s;
    return {
      downloadSupportBundle: (0, q.useCallback)(async () => {
        if (!t?.id || (!d && !f)) return;
        let n = E({ title: `Generating support bundle...`, indefinite: !0 });
        try {
          let r = (
              await c(
                async () => {
                  let { default: t } = await import(`./vendor-DAwbZtf0.js`).then((t) => e(t.Zt(), 1));
                  return { default: t };
                },
                __vite__mapDeps([0, 1, 2]),
                import.meta.url,
              )
            ).default,
            i = new r();
          (l && a && (await W(i, l, a)),
            u && s && (await U(i, u, s)),
            xe(i, t),
            H(await i.generateAsync({ type: `blob` }), `action-support-bundle-${t.id}.zip`),
            n.dismiss(),
            E({ title: `Support bundle downloaded` }));
        } catch (e) {
          (n.dismiss(), E({ title: `Failed to download support bundle`, description: S(e) }));
        }
      }, [l, u, a, s, d, f, t]),
      isSupportBundleAvailable: d || f,
      environment: i,
    };
  },
  Ce = ({ action: e }) => {
    let { toast: t } = T(),
      [n, r] = (0, q.useState)(!1),
      { downloadSupportBundle: i, isSupportBundleAvailable: a, environment: o } = Se(e),
      s = (0, q.useCallback)(async () => {
        try {
          (await navigator.clipboard.writeText(e.id), t({ title: `Action ID copied to clipboard`, description: e.id }));
        } catch (e) {
          t({ title: `Failed to copy action ID`, description: S(e) });
        }
      }, [t, e.id]),
      c = (0, q.useCallback)(() => r(!0), []),
      l = he(e);
    return (0, J.jsxs)(`div`, {
      onClick: (e) => {
        (e.preventDefault(), e.stopPropagation());
      },
      "data-tracking-id-none": !0,
      children: [
        (0, J.jsxs)(ce, {
          triggerTestId: `workflow-execution-action-dropdown-trigger`,
          triggerButton: (0, J.jsx)(O, { variant: `outline`, "aria-label": `More actions`, LeadingIcon: se }),
          children: [
            (0, J.jsx)(F.Item, {
              onClick: s,
              "data-testid": `workflow-execution-action-dropdown-copy-id`,
              "data-tracking-id": `copy-id-workflow-execution-action-dropdown`,
              children: `Copy Action ID`,
            }),
            (0, J.jsx)(ie, {
              content: (() => {
                let t = `Support bundle is temporarily unavailable`;
                if (!a) {
                  if (!e.status?.environmentId && !e.status?.agentExecutionId)
                    return `No environment or agent session associated with this action`;
                  if (!o) return t;
                  switch (o.status?.phase) {
                    case x.RUNNING:
                      return;
                    case x.UPDATING:
                    case x.CREATING:
                    case x.STARTING:
                      return t;
                    default:
                      return t;
                  }
                }
              })(),
              children: (0, J.jsx)(`div`, {
                children: (0, J.jsx)(F.Item, {
                  onClick: i,
                  disabled: !a,
                  "data-testid": `workflow-execution-action-dropdown-download-bundle`,
                  "data-tracking-id": `download-support-bundle-workflow-execution-action-dropdown`,
                  children: `Download support bundle`,
                }),
              }),
            }),
            l &&
              (0, J.jsxs)(J.Fragment, {
                children: [
                  (0, J.jsx)(F.Separator, {}),
                  (0, J.jsx)(F.Item, {
                    variant: `destructive`,
                    onClick: c,
                    "data-testid": `workflow-execution-action-dropdown-cancel`,
                    "data-tracking-id": `cancel-workflow-execution-action-dropdown`,
                    children: `Cancel`,
                  }),
                ],
              }),
          ],
        }),
        (0, J.jsx)(be, { open: n, action: e, onClose: () => r(!1) }),
      ],
    });
  },
  we = M(d),
  Y = M(s),
  X = M(o),
  Z = M(y),
  Te = ({ step: e, size: t = `sm` }) => {
    let n = e.phase,
      r = K(e),
      i = null,
      a = ``;
    if (r) ((i = Z), (a = `text-content-destructive`));
    else
      switch (n) {
        case C.PENDING:
          ((i = X), (a = `text-content-muted`));
          break;
        case C.RUNNING:
          ((i = D), (a = `animate-spin text-content-muted`));
          break;
        case C.FAILED:
          ((i = Z), (a = `text-content-destructive`));
          break;
        case C.DONE:
          ((i = Y), (a = `text-content-success`));
          break;
        case C.CANCELLED:
          ((i = we), (a = `text-content-muted`));
          break;
        case C.UNSPECIFIED:
          ((i = X), (a = `text-content-muted`));
          break;
      }
    return i ? (0, J.jsx)(i, { size: t, className: k(`shrink-0`, a), "aria-hidden": !0 }) : null;
  };
function Ee(e) {
  let t = e.step?.step;
  if (!t) return null;
  switch (t.case) {
    case `task`:
      return { type: `Shell script`, icon: l, variant: `warning`, content: t.value.command || ``, isShellScript: !0 };
    case `agent`:
      return { type: `Prompt`, icon: m, variant: `brand`, content: t.value.prompt || ``, isShellScript: !1 };
    case `pullRequest`:
      return { type: `Pull request`, icon: v, variant: `success`, content: t.value.title || ``, isShellScript: !1 };
    case `report`: {
      let e = t.value.outputs || [];
      return {
        type: `Report`,
        icon: f,
        variant: `neutral`,
        content: e.length > 0 ? e.map((e) => e.title || e.key).join(`, `) : `No outputs defined`,
        isShellScript: !1,
      };
    }
    default:
      return null;
  }
}
var Q = 96,
  De = ({ step: e }) => {
    let t = (e.startedAt && e.finishedAt ? j(e.startedAt, e.finishedAt) : void 0) || L(e.phase, e.failureMessage),
      n = (0, q.useMemo)(() => Ee(e), [e]),
      r = (0, q.useRef)(null),
      [i, a] = (0, q.useState)(!1),
      [o, s] = (0, q.useState)(!1),
      c = (0, q.useCallback)(() => {
        let e = r.current;
        e && a(e.scrollHeight > Q);
      }, []);
    ((0, q.useEffect)(() => {
      c();
    }, [c, n?.content]),
      (0, q.useEffect)(() => {
        let e = r.current;
        if (!e) return;
        let t = new ResizeObserver(c);
        return (t.observe(e), () => t.disconnect());
      }, [c]));
    let l = K(e) || e.phase === C.FAILED;
    return (0, J.jsxs)(`div`, {
      className: k(`overflow-hidden rounded-lg border`, l ? `border-border-warning` : `border-border-base`),
      children: [
        (0, J.jsxs)(`div`, {
          className: k(
            `flex items-center justify-between gap-3 border-b px-3 py-2`,
            l ? `border-border-warning bg-surface-warning-subtle` : `border-border-base bg-surface-primary`,
          ),
          children: [
            n && (0, J.jsx)(pe, { variant: n.variant, LeadingIcon: n.icon, className: `w-fit`, children: n.type }),
            (0, J.jsxs)(`div`, {
              className: `flex shrink-0 items-center gap-2`,
              children: [
                e.failureMessage
                  ? (0, J.jsx)(N, { className: `text-sm text-content-destructive`, children: e.failureMessage })
                  : (0, J.jsx)(N, { className: `text-sm text-content-muted`, children: t }),
                (0, J.jsx)(Te, { step: e, size: `base` }),
              ],
            }),
          ],
        }),
        n &&
          (0, J.jsx)(`div`, {
            className: `bg-surface-base px-3 py-3`,
            children: (0, J.jsxs)(`div`, {
              className: `relative`,
              children: [
                (0, J.jsx)(`div`, {
                  ref: r,
                  className: k(!o && i && `overflow-hidden`),
                  style: !o && i ? { maxHeight: Q } : void 0,
                  children: (0, J.jsxs)(N, {
                    className: `whitespace-pre-wrap break-words text-base text-content-primary`,
                    children: [
                      n.isShellScript && (0, J.jsx)(`span`, { className: `text-content-muted`, children: `$ ` }),
                      n.content,
                    ],
                  }),
                }),
                i &&
                  (0, J.jsx)(`button`, {
                    type: `button`,
                    onClick: () => s((e) => !e),
                    className: `mt-1 text-sm font-medium text-content-brand hover:underline`,
                    "data-tracking-id": `toggle-step-content-expand`,
                    children: o ? `Show less` : `Show more`,
                  }),
              ],
            }),
          }),
      ],
    });
  },
  Oe = ({ action: e }) =>
    (0, J.jsx)(`div`, {
      className: `flex flex-col gap-2`,
      children: e.status?.stepStatuses.map((e) => (0, J.jsx)(De, { step: e }, e.stepIndex)),
    }),
  ke = M(h),
  Ae = M(p),
  $ = ({ counters: e, className: t }) =>
    (0, J.jsxs)(`div`, {
      className: k(`flex flex-wrap gap-3`, t),
      children: [
        e.completed > 0 &&
          (0, J.jsxs)(`div`, {
            className: `flex items-center gap-1`,
            children: [
              (0, J.jsx)(s, { size: 16, className: `text-content-success` }),
              (0, J.jsxs)(N, { className: `text-sm text-content-success`, children: [e.completed, ` completed`] }),
            ],
          }),
        e.failed > 0 &&
          (0, J.jsxs)(`div`, {
            className: `flex items-center gap-1`,
            children: [
              (0, J.jsx)(y, { size: 16, className: `text-content-destructive` }),
              (0, J.jsxs)(N, { className: `text-sm text-content-destructive`, children: [e.failed, ` failed`] }),
            ],
          }),
        e.cancelled > 0 &&
          (0, J.jsxs)(`div`, {
            className: `flex items-center gap-1`,
            children: [
              (0, J.jsx)(d, { size: 16, className: `text-content-muted` }),
              (0, J.jsxs)(N, { className: `text-sm text-content-muted`, children: [e.cancelled, ` cancelled`] }),
            ],
          }),
        e.cancelling > 0 &&
          (0, J.jsxs)(`div`, {
            className: `flex items-center gap-1`,
            children: [
              (0, J.jsx)(o, { size: 16, className: `text-content-muted` }),
              (0, J.jsxs)(N, { className: `text-sm text-content-muted`, children: [e.cancelling, ` cancelling`] }),
            ],
          }),
        e.incomplete > 0 &&
          (0, J.jsxs)(`div`, {
            className: `flex items-center gap-1`,
            children: [
              (0, J.jsx)(o, { size: 16, className: `text-content-muted` }),
              (0, J.jsxs)(N, { className: `text-sm text-content-muted`, children: [e.incomplete, ` incomplete`] }),
            ],
          }),
      ],
    }),
  je = () => {
    let { workflowExecutionActionId: e } = ee(),
      t = _(),
      a = te(),
      o = t.hash === `#steps` ? `steps` : `conversation`,
      s = (0, q.useCallback)(
        (e) => {
          let n = e === `steps` ? `#steps` : ``;
          a(`${t.pathname}${n}`, { replace: !0 });
        },
        [a, t.pathname],
      ),
      { data: c, error: l } = n(e),
      { data: d } = i(c?.metadata?.workflowId),
      { data: f } = V(R(c?.spec?.context) ?? void 0),
      p = c?.status?.agentExecutionId,
      { data: m, isLoading: h } = P(p),
      g = fe(m?.id, m?.status?.conversationUrl, m?.metadata?.annotations, [], m?.status?.conversationUrls),
      v = g.kind === `v1` ? g.messages : [],
      y = g.kind === `v2` ? g.stream : null,
      b = c ? ge(c) : !1,
      x = (0, q.useMemo)(() => {
        let e = 0,
          t = 0,
          n = 0,
          r = 0,
          i = 0;
        return (
          c?.status?.stepStatuses.forEach((a) => {
            if (K(a)) t++;
            else
              switch (a.phase) {
                case C.DONE:
                  e++;
                  break;
                case C.FAILED:
                  t++;
                  break;
                case C.CANCELLED:
                  n++;
                  break;
                default:
                  b ? i++ : r++;
              }
          }),
          { completed: e, failed: t, cancelled: n, incomplete: r, cancelling: i }
        );
      }, [c, b]),
      S = c?.metadata?.startedAt,
      w = c?.metadata?.finishedAt,
      [T, E] = (0, q.useState)(0);
    (0, q.useEffect)(() => {
      if (!S || w) return;
      let e = setInterval(() => E((e) => e + 1), 1e4);
      return () => clearInterval(e);
    }, [S, w]);
    let D = (0, q.useMemo)(() => {
        if (S) return j(S, w ?? u());
      }, [S, w, T]),
      O = !!m,
      A = !h,
      M = o === `conversation` && !O ? `steps` : o;
    return !c || !A
      ? (0, J.jsx)(`div`, {
          "data-testid": `workflow-execution-action-page`,
          className: `flex size-full flex-col gap-4`,
          children: (0, J.jsx)(G, { error: l }),
        })
      : (0, J.jsxs)(`div`, {
          "data-testid": `workflow-execution-action-page`,
          className: `flex size-full flex-col gap-4`,
          children: [
            (0, J.jsx)(G, { error: l }),
            (0, J.jsx)(G, { error: g.error }),
            (0, J.jsxs)(`div`, {
              className: `flex flex-col gap-2`,
              children: [
                (0, J.jsxs)(`div`, {
                  className: `flex items-center justify-between gap-2`,
                  children: [
                    (0, J.jsxs)(re, {
                      className: `text-xl font-semibold leading-tight`,
                      children: [
                        `"`,
                        c.metadata?.actionName ?? (0, J.jsx)(`span`, { children: `-` }),
                        (0, J.jsx)(`span`, { children: `" Action Report` }),
                      ],
                    }),
                    (0, J.jsxs)(`div`, {
                      className: `flex shrink-0 items-center gap-3`,
                      children: [
                        (0, J.jsx)($, { counters: x, className: `hidden sm:flex` }),
                        (0, J.jsx)(Ce, { action: c }),
                      ],
                    }),
                  ],
                }),
                (0, J.jsxs)(N, {
                  className: `text-sm text-content-secondary`,
                  children: [I(d), ` / `, f?.metadata?.name],
                }),
                (0, J.jsx)($, { counters: x, className: `flex sm:hidden` }),
              ],
            }),
            c?.status?.failureMessage && (0, J.jsx)(ne, { variant: `danger`, text: c.status.failureMessage }),
            (0, J.jsxs)(r, {
              value: M,
              onValueChange: s,
              className: `flex min-h-0 flex-1 flex-col`,
              children: [
                (0, J.jsxs)(`div`, {
                  className: `flex items-center justify-between`,
                  children: [
                    (0, J.jsxs)(r.List, {
                      className: `w-auto flex-row`,
                      children: [
                        O &&
                          (0, J.jsx)(r.Trigger, { value: `conversation`, LeadingIcon: Ae, children: `Full session` }),
                        (0, J.jsx)(r.Trigger, { value: `steps`, LeadingIcon: ke, children: `Steps` }),
                      ],
                    }),
                    D && (0, J.jsx)(N, { className: `text-sm text-content-muted`, children: D }),
                  ],
                }),
                O &&
                  (0, J.jsx)(r.Content, {
                    value: `conversation`,
                    className: k(`mt-4 min-h-0 flex-1`, y ? `flex` : `overflow-auto`),
                    children: (0, J.jsx)(de, {
                      agentExecution: m,
                      messages: v,
                      stream: y,
                      readOnly: !0,
                      className: k(
                        `max-w-none grow self-stretch rounded-lg border border-border-base bg-surface-base p-4`,
                        y ? `min-h-0 flex-1` : `h-auto`,
                      ),
                    }),
                  }),
                (0, J.jsx)(r.Content, {
                  value: `steps`,
                  className: `mt-4 min-h-0 flex-1 overflow-auto`,
                  children: (0, J.jsx)(Oe, { action: c }),
                }),
              ],
            }),
          ],
        });
  };
export { je as AutomationExecutionActionPage };

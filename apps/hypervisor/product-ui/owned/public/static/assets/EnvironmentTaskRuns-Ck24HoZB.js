import { a as e } from "./rolldown-runtime-CGYlQKCx.js";
import { Cn as t } from "./SegmentProvider-CXCNBY9U.js";
import { n } from "./@mux-DLaEVubF.js";
import { Mu as r, v_ as i, xg as a } from "./vendor-DAwbZtf0.js";
import { js as o, tr as s } from "./use-boot-in-app-chat-t-J_VjKS.js";
import { n as c } from "./toast-axaLeIzZ.js";
import { a as l, t as u } from "./button-6YP03Qf2.js";
import { t as d } from "./cn-DppMFCU8.js";
import { t as f } from "./timestamp-CEKPQVte.js";
import { d as p } from "./time-DxjbKG-a.js";
import { t as m } from "./tooltip-6hqVQbwq.js";
import { t as h } from "./text-fFCFeCas.js";
import { t as g } from "./select-Ceshp72e.js";
import { t as _ } from "./skeleton-Cm867Q_k.js";
import { c as v, s as y, u as b } from "./automations-queries-HjQabXcP.js";
import { t as x } from "./IconWarning-bjnFo87N.js";
import { t as S } from "./IconCheck-CjhQLbZQ.js";
import { t as C } from "./IconWarningCircle-9yrh1wLR.js";
import { t as w } from "./EnvironmentDetailsSection-CUK_tKGQ.js";
import { t as T } from "./use-callback-prevent-default-ChBsYLGS.js";
import { t as E } from "./BackButton-Bppee2mo.js";
var D = e(n(), 1),
  O = i(),
  k = ({ size: e, className: t, ...n }) =>
    (0, O.jsx)(r, { size: `sm`, className: d(`size-4`, t), style: { strokeLinejoin: `round` }, ...n }),
  A = ({ task: e, runs: n, environmentId: r, disabled: i }) => {
    let o = a(),
      l = b(),
      { toast: d } = c(),
      { ensureEnvironmentStarted: m, isStarting: g } = t(r),
      _ = (0, D.useMemo)(
        () =>
          n
            .filter((t) => t.metadata?.taskId === e.id)
            .sort((e, t) => Number(e?.metadata?.createdAt?.seconds || 0) - Number(t?.metadata?.createdAt?.seconds || 0))
            .pop(),
        [n, e.id],
      ),
      v = _?.metadata?.createdAt,
      y = v && p(f(v)),
      x = T(async () => {
        try {
          await m();
          let t = await l.mutateAsync(e.id),
            n = `/details/${t.metadata?.environmentId}/task/${t.metadata?.taskId}/run/${t.id}`;
          d({
            title: (0, O.jsx)(O.Fragment, { children: `Task started` }),
            link: { label: `View Logs`, href: n, onClick: () => o(n), "data-tracking-id": `view-logs-task-card` },
          });
        } catch (e) {
          d({ title: `Failed to start task`, description: s(e) });
        }
      }, [m, o, l, e.id, d]),
      S = e.metadata?.triggeredBy.some((e) => e.trigger.case === `manual`),
      C = _ ? `/details/${_.metadata?.environmentId}/task/${_.metadata?.taskId}/run/${_.id}` : void 0,
      E = (0, O.jsxs)(O.Fragment, {
        children: [
          (0, O.jsxs)(w.List.Top, {
            children: [
              (0, O.jsx)(w.List.ItemTitle, { children: e.metadata?.name }),
              (0, O.jsxs)(w.List.ItemActions, {
                children: [
                  _ &&
                    (0, O.jsxs)(`div`, {
                      className: `flex items-center gap-1`,
                      children: [
                        (0, O.jsx)(N, { phase: _.status?.phase }),
                        (0, O.jsx)(h, { className: `text-sm text-content-tertiary`, children: y }),
                      ],
                    }),
                  S &&
                    (0, O.jsx)(u, {
                      LeadingIcon: k,
                      disabled: i,
                      loading: l.isPending || g,
                      size: `xs`,
                      className: `pointer-coarse:h-7 pointer-coarse:px-2.5`,
                      variant: `secondary`,
                      onClick: x,
                      "data-tracking-id": `run-task-task-card`,
                      children: `Run`,
                    }),
                ],
              }),
            ],
          }),
          (0, O.jsx)(w.List.Description, {
            title: e.metadata?.description || `Automated task`,
            children: e.metadata?.description || `Automated task`,
          }),
          (0, O.jsx)(j, { triggers: e.metadata?.triggeredBy ?? [] }),
        ],
      });
    return (0, O.jsx)(w.List.Item, {
      to: C,
      "data-testid": `task-card-${e.id}`,
      "data-tracking-id": `task-list-item-link`,
      children: E,
    });
  },
  j = ({ triggers: e }) => {
    let t = e
      .filter((e) => e.trigger.case !== `manual`)
      .map(M)
      .join(`, `);
    return (0, O.jsx)(h, {
      className: `truncate text-sm font-bold uppercase text-content-tertiary`,
      title: t,
      children: t,
    });
  };
function M(e) {
  switch (e.trigger.case) {
    case `manual`:
      return `Manual`;
    case `postDevcontainerStart`:
      return `Post dev container start`;
    case `postEnvironmentStart`:
      return `Post start`;
    case `prebuild`:
      return `Prebuild`;
  }
}
var N = ({ phase: e }) => {
    let t = {
      [o.SUCCEEDED]: { icon: S, label: `Task succeeded`, className: `text-content-green` },
      [o.FAILED]: { icon: x, label: `Task failed`, className: `text-content-destructive` },
      [o.RUNNING]: { icon: l, label: `Task is running`, className: `animate-spin text-content-brand` },
      [o.PENDING]: { icon: l, label: `Task is pending`, className: `animate-spin` },
      [o.STOPPED]: { icon: C, label: `Task was stopped`, className: `text-content-tertiary` },
    };
    if (!e || !t[e]) return null;
    let { icon: n, label: r, className: i } = t[e];
    return (0, O.jsx)(m, {
      content: r,
      usePortal: !0,
      children: (0, O.jsxs)(`div`, {
        children: [
          (0, O.jsx)(`span`, { className: `sr-only`, children: r }),
          (0, O.jsx)(n, { size: `sm`, className: i, "aria-hidden": !0 }),
        ],
      }),
    });
  },
  P = ({ environmentId: e, taskId: t, showBackButton: n = !0 }) => {
    let { data: r, isLoading: i, error: a } = v(e),
      { data: o } = y(e),
      s = (!i && r !== void 0) || !!a,
      [c, l] = (0, D.useState)(void 0),
      [u, f] = (0, D.useState)(void 0),
      p = (t ? o?.filter((e) => e.metadata?.taskId === t) : o) || [],
      m = p.filter((e) => !c || e.metadata?.taskId == c).filter((e) => !u || e.status?.phase === u),
      h = new Map(
        p?.map((e) => [
          e.metadata?.taskId || e.id,
          r?.find((t) => t.id === e.metadata?.taskId)?.metadata?.name || e.metadata?.taskId || ``,
        ]),
      );
    return (0, O.jsxs)(`div`, {
      className: `flex flex-col gap-4`,
      children: [
        (0, O.jsxs)(`div`, {
          className: d(`flex gap-4`, n ? `items-center justify-between` : `flex-col`),
          children: [
            n && (0, O.jsx)(E, {}),
            (0, O.jsxs)(`div`, {
              className: d(
                `grid min-w-0 w-full grid-cols-1 gap-2 sm:grid-cols-2`,
                n && `flex-1 md:ml-auto md:max-w-2xl`,
              ),
              children: [
                (0, O.jsx)(R, { placeholder: `All Tasks`, onChange: (e) => l(e), items: h }),
                (0, O.jsx)(R, {
                  placeholder: `All Status`,
                  onChange: (e) => f(parseInt(e)),
                  items: new Map(p?.map((e) => [e.status?.phase.toString() || ``, L(e.status?.phase)])),
                }),
              ],
            }),
          ],
        }),
        (0, O.jsx)(_, {
          failed: !!a,
          ready: s,
          className: `h-20`,
          children: (0, O.jsx)(F, { tasks: r || [], runs: m || [] }),
        }),
      ],
    });
  },
  F = ({ tasks: e, runs: t }) =>
    t.length === 0
      ? (0, O.jsx)(O.Fragment, { children: `No tasks runs available!` })
      : (0, O.jsx)(w.List, {
          "aria-label": `Task runs`,
          children: t.map((t) => (0, O.jsx)(I, { task: e.find((e) => e.id === t.metadata?.taskId), run: t }, t.id)),
        }),
  I = ({ task: e, run: t }) => {
    let n = (0, D.useMemo)(
        () => `/details/${t.metadata?.environmentId}/task/${t.metadata?.taskId}/run/${t.id}`,
        [t.metadata?.environmentId, t.metadata?.taskId, t.id],
      ),
      r = t?.metadata?.createdAt,
      i = r && p(f(r));
    return (0, O.jsx)(w.List.Item, {
      to: n,
      "data-tracking-id": `task-run-item-link`,
      children: (0, O.jsxs)(w.List.Top, {
        children: [
          (0, O.jsx)(w.List.ItemTitle, { children: e?.metadata?.name }),
          (0, O.jsx)(w.List.ItemActions, {
            children: (0, O.jsxs)(`div`, {
              className: `flex items-center gap-1`,
              children: [
                (0, O.jsx)(N, { phase: t?.status?.phase }),
                (0, O.jsx)(`span`, { className: `text-sm text-content-tertiary`, children: i || `not run yet` }),
              ],
            }),
          }),
        ],
      }),
    });
  };
function L(e) {
  switch (e) {
    case o.SUCCEEDED:
      return `Succeeded`;
    case o.FAILED:
      return `Failed`;
    case o.RUNNING:
      return `Running`;
    case o.PENDING:
      return `Pending`;
    case o.STOPPED:
      return `Stopped`;
    default:
      return ``;
  }
}
var R = ({ initialValue: e, placeholder: t, items: n, onChange: r, className: i }) => {
  let [a, o] = (0, D.useState)(e),
    s = (0, D.useCallback)(
      (e) => {
        let t = e === `*` ? `` : e;
        (o(t), r && r(t));
      },
      [r],
    );
  return (0, O.jsxs)(g, {
    value: a || `*`,
    onValueChange: s,
    className: d(`w-full`, i),
    children: [
      (0, O.jsx)(g.Item, { value: `*`, children: t }, `reset-item`),
      Array.from(n.entries()).map(([e, t]) => (0, O.jsx)(g.Item, { value: e, children: t }, `item-` + e)),
    ],
  });
};
export { A as n, P as t };

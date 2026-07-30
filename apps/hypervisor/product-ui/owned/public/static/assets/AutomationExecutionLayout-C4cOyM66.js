import { a as e } from "./rolldown-runtime-CGYlQKCx.js";
import {
  $r as t,
  Gn as n,
  Gr as r,
  Jr as i,
  Lt as a,
  Wr as o,
  d as s,
  f as c,
  u as l,
} from "./SegmentProvider-CXCNBY9U.js";
import { n as u } from "./@mux-DLaEVubF.js";
import {
  $p as d,
  Ll as f,
  Y as p,
  c_ as m,
  fg as h,
  nf as g,
  pg as _,
  v_ as v,
  vg as y,
  wg as ee,
  xg as b,
} from "./vendor-DAwbZtf0.js";
import { tr as x } from "./use-boot-in-app-chat-t-J_VjKS.js";
import { n as S } from "./toast-axaLeIzZ.js";
import { t as C } from "./button-6YP03Qf2.js";
import { t as w } from "./cn-DppMFCU8.js";
import { r as T } from "./time-DxjbKG-a.js";
import { n as E } from "./utils-C9bSuXia.js";
import { t as D } from "./text-fFCFeCas.js";
import { r as O } from "./dropdown-menu-D3UmjGpQ.js";
import { D as te, M as k, N as A, i as j, j as M, k as N, m as P } from "./automations-CN21BoUy.js";
import { r as F } from "./IconDownload-CbC2YHYb.js";
import { t as I } from "./collapsible-CijQ-f1P.js";
import { t as ne } from "./use-is-mobile-viewport-Chw6u8QP.js";
import { t as L } from "./button-group-BAfnksgW.js";
import { t as R } from "./scroll-area-DiWW0x8z.js";
import { t as z } from "./combobox-BkGa_nRF.js";
import { lt as B } from "./main-DLKYFe1Y.js";
import { r as V, t as H } from "./automation-execution-action-DsjZnn4c.js";
import { t as U } from "./CancelAutomationExecutionDialog-rm2UxTc-.js";
import { t as W } from "./RunAutomationDialog-GQ35_Wcn.js";
import { t as G } from "./page-uSfpPNk3.js";
var K = e(u(), 1),
  q = v(),
  J = ({ workflowExecutionId: e, actions: t }) => {
    let n = y(),
      r = b(),
      i = M({ id: e }),
      a = (0, K.useMemo)(
        () => [
          { id: `summary`, label: `Summary`, url: i },
          ...t.map((t) => ({
            id: t.id,
            label: t.metadata?.actionName || `-`,
            url: N({ actionId: t.id, executionId: e }),
          })),
        ],
        [t, i, e],
      ),
      o = (0, K.useMemo)(() => new Map(a.map((e) => [e.url, e.label])), [a]),
      s = a.find((e) => e.url === n.pathname)?.url || i;
    return (0, q.jsxs)(z, {
      value: s,
      onValueChange: (e) => {
        r(e);
      },
      filterPlaceholder: `Search pages...`,
      children: [
        (0, q.jsx)(z.Value, {
          children: (e) =>
            (0, q.jsxs)(`div`, {
              className: `flex items-center gap-2`,
              children: [
                e === i && (0, q.jsx)(p, { size: 16 }),
                (0, q.jsx)(z.ValueLabel, { children: o.get(e) || `Summary` }),
              ],
            }),
        }),
        (0, q.jsx)(z.List, {
          items: a,
          searchKeys: [`label`],
          children: (e) =>
            (0, q.jsxs)(
              z.ListItem,
              {
                value: e.url,
                children: [
                  e.id === `summary` && (0, q.jsx)(z.ListItemLeadingIcon, { children: (0, q.jsx)(p, { size: 16 }) }),
                  (0, q.jsx)(z.ListItemTitle, { children: e.label }),
                ],
              },
              e.id,
            ),
        }),
        (0, q.jsx)(z.Footer, {
          children: (0, q.jsxs)(`span`, {
            className: `text-xs text-content-secondary`,
            children: [t.length, ` actions`],
          }),
        }),
      ],
    });
  },
  Y = ({ groupType: e, count: t }) =>
    (0, q.jsxs)(`span`, {
      className: `flex items-center gap-1.5 text-sm font-medium text-content-primary`,
      children: [X(e), (0, q.jsx)(F, { counter: `${t}`, variant: `default` })],
    }),
  X = (e) => {
    switch (e) {
      case H.Active:
        return `Active`;
      case H.Pending:
        return `Pending`;
      case H.Completed:
        return `Completed`;
      case H.Failed:
        return `Failed`;
      case H.Stopped:
        return `Stopped`;
      case H.Deleted:
        return `Deleted`;
      default:
        return `Unknown`;
    }
  },
  Z = ({ action: e }) => {
    let t = e.metadata?.startedAt,
      n = e.metadata?.finishedAt,
      [, r] = (0, K.useState)(0);
    return (
      (0, K.useEffect)(() => {
        if (!t || n) return;
        let e = setInterval(() => r((e) => e + 1), 1e4);
        return () => clearInterval(e);
      }, [t, n]),
      t ? (0, q.jsx)(D, { className: `text-sm text-content-muted`, children: T(t, n ?? m()) }) : null
    );
  },
  Q = ({ groupType: e, actions: t, workflowExecutionId: r }) => {
    let [i, a] = (0, K.useState)(!0),
      o = y();
    return (0, q.jsx)(I, {
      open: i,
      onOpenChange: a,
      children: (0, q.jsxs)(`div`, {
        className: `flex flex-col gap-1`,
        children: [
          (0, q.jsx)(I.Trigger, {
            asChild: !0,
            children: (0, q.jsxs)(`button`, {
              type: `button`,
              className: `flex h-8 w-full items-center gap-1.5 rounded-lg px-2 py-1 text-left hover:bg-surface-hover`,
              "data-tracking-id": `toggle-action-group`,
              children: [
                (0, q.jsx)(g, {
                  size: 16,
                  className: w(`shrink-0 text-content-muted transition-transform`, { "rotate-90": i }),
                }),
                (0, q.jsx)(Y, { groupType: e, count: t.length }),
              ],
            }),
          }),
          (0, q.jsx)(I.Content, {
            children: (0, q.jsx)(`div`, {
              className: `ml-4 flex flex-col gap-1 border-l border-border-subtle p-[1px] pl-1`,
              children: t.map((e) => {
                let t = N({ actionId: e.id, executionId: r }),
                  i = o.pathname === t;
                return (0, q.jsx)(
                  n,
                  {
                    to: t,
                    label: e.metadata?.actionName || `-`,
                    active: i,
                    className: `text-base font-normal text-content-primary`,
                    iconRight: (0, q.jsx)(Z, { action: e }),
                  },
                  e.id,
                );
              }),
            }),
          }),
        ],
      }),
    });
  },
  $ = [H.Active, H.Failed, H.Completed, H.Stopped, H.Deleted, H.Pending],
  re = ({ workflowExecutionId: e, actions: t }) => {
    let r = y(),
      i = M({ id: e }),
      a = r.pathname === i,
      o = V(t);
    return (0, q.jsxs)(`div`, {
      className: `flex flex-col gap-4`,
      children: [
        (0, q.jsx)(n, { to: i, label: `Summary`, active: a, icon: (0, q.jsx)(p, { size: `16` }) }),
        (0, q.jsxs)(`div`, {
          className: `flex flex-col gap-1`,
          children: [
            (0, q.jsxs)(`div`, {
              className: `flex items-center`,
              children: [
                (0, q.jsx)(D, { className: `pl-2 text-sm text-content-strong`, children: `Actions` }),
                (0, q.jsx)(F, { counter: `${t.length}`, variant: `default` }),
              ],
            }),
            $.map((t) => {
              let n = o.get(t);
              return !n || n.actions.length === 0
                ? null
                : (0, q.jsx)(Q, { groupType: t, actions: n.actions, workflowExecutionId: e }, t);
            }),
          ],
        }),
      ],
    });
  },
  ie = E(f),
  ae = E(d),
  oe = () => {
    let { workflowExecutionId: e } = ee(),
      { data: n } = r(e),
      { data: u, isLoading: d } = i({ enabled: !!e, workflowExecutionId: e || `` }),
      { data: f } = o(n?.metadata?.workflowId),
      { isMobileViewport: p } = ne(),
      m = y(),
      g = b(),
      { toast: v } = S(),
      w = t();
    a(f ? `${k(f)} - Execution` : void 0);
    let T = u?.length === 1,
      E = (0, K.useMemo)(() => {
        if (!(!T || !e || !u?.[0]?.id)) return N({ actionId: u[0].id, executionId: e });
      }, [T, e, u]),
      D = M({ id: e || `` }),
      F = T && E && m.pathname === D,
      [I, z] = (0, K.useState)(!1),
      [V, H] = (0, K.useState)(!1),
      Y = n ? j(n) : !1,
      X = n ? P(n) : !1,
      Z = f?.id,
      Q = (0, K.useCallback)(async () => {
        if (Z)
          try {
            g(M({ id: (await w.mutateAsync({ workflowId: Z })).id }));
          } catch (e) {
            v({ title: `Failed to re-run automation`, description: x(e) });
          }
      }, [Z, w, g, v]),
      $ =
        Y || X
          ? (0, q.jsxs)(q.Fragment, {
              children: [
                Y &&
                  n &&
                  (0, q.jsxs)(q.Fragment, {
                    children: [
                      (0, q.jsx)(C, {
                        variant: `ghost`,
                        size: `sm`,
                        className: `text-content-destructive hover:text-content-destructive`,
                        onClick: () => z(!0),
                        "data-testid": `cancel-workflow-execution-button`,
                        "data-tracking-id": `cancel-workflow-execution-header`,
                        children: `Cancel`,
                      }),
                      (0, q.jsx)(U, { open: I, execution: n, onClose: () => z(!1) }),
                    ],
                  }),
                X &&
                  f &&
                  (0, q.jsxs)(q.Fragment, {
                    children: [
                      (0, q.jsxs)(O, {
                        children: [
                          (0, q.jsxs)(L, {
                            variant: `secondary`,
                            children: [
                              (0, q.jsx)(L.Item, {
                                LeadingIcon: ie,
                                onClick: Q,
                                disabled: w.isPending,
                                "data-testid": `rerun-workflow-execution-button`,
                                "data-tracking-id": `rerun-workflow-execution-header`,
                                children: `Re-run`,
                              }),
                              (0, q.jsx)(O.Trigger, {
                                asChild: !0,
                                children: (0, q.jsx)(L.Item, {
                                  LeadingIcon: ae,
                                  "aria-label": `Re-run options`,
                                  "data-testid": `rerun-workflow-execution-dropdown`,
                                  "data-tracking-id": `rerun-workflow-execution-dropdown`,
                                }),
                              }),
                            ],
                          }),
                          (0, q.jsx)(O.Content, {
                            align: `end`,
                            children: (0, q.jsx)(O.Item, {
                              onClick: () => H(!0),
                              "data-tracking-id": `rerun-with-options-workflow-execution`,
                              children: `Re-run with options...`,
                            }),
                          }),
                        ],
                      }),
                      (0, q.jsx)(W, { open: V, onOpenChange: H, workflow: f }),
                    ],
                  }),
              ],
            })
          : void 0;
    return (0, q.jsxs)(G, {
      "data-testid": `workflow-execution-layout`,
      children: [
        (0, q.jsx)(G.Header, {
          breadcrumbs: f
            ? (0, q.jsx)(B, {
                customBreadcrumbs: [
                  { label: `Automations`, href: A() },
                  { label: k(f), href: te(f) },
                  { label: `Execution report` },
                ],
              })
            : void 0,
          actions: $,
          loading: n && f ? void 0 : { breadcrumbItemCount: 3 },
        }),
        d
          ? (0, q.jsx)(G.Content, {})
          : F
            ? (0, q.jsx)(G.Content, { children: (0, q.jsx)(h, { to: E, replace: !0 }) })
            : T
              ? (0, q.jsx)(G.Content, { children: (0, q.jsx)(_, {}) })
              : p
                ? (0, q.jsx)(G.Content, {
                    children: (0, q.jsxs)(`div`, {
                      className: `flex flex-col gap-4`,
                      children: [(0, q.jsx)(J, { workflowExecutionId: e || ``, actions: u || [] }), (0, q.jsx)(_, {})],
                    }),
                  })
                : (0, q.jsx)(G.Content, {
                    padding: `none`,
                    scrollable: !1,
                    children: (0, q.jsxs)(c, {
                      direction: `horizontal`,
                      className: `flex h-full`,
                      autoSaveId: `workflow-execution-layout`,
                      children: [
                        (0, q.jsx)(s, {
                          defaultSize: 25,
                          minSize: 20,
                          maxSize: 40,
                          order: 1,
                          children: (0, q.jsx)(R, {
                            orientation: `vertical`,
                            className: `h-full`,
                            children: (0, q.jsx)(`div`, {
                              className: `py-6 pl-6 pr-[21px]`,
                              children: (0, q.jsx)(re, { workflowExecutionId: e || ``, actions: u || [] }),
                            }),
                          }),
                        }),
                        (0, q.jsx)(l, {}),
                        (0, q.jsx)(s, {
                          defaultSize: 75,
                          minSize: 60,
                          order: 2,
                          children: (0, q.jsx)(R, {
                            orientation: `vertical`,
                            className: `h-full`,
                            children: (0, q.jsx)(`div`, {
                              className: `py-6 pl-6 pr-[21px]`,
                              children: (0, q.jsx)(_, {}),
                            }),
                          }),
                        }),
                      ],
                    }),
                  }),
      ],
    });
  };
export { oe as AutomationExecutionLayout };

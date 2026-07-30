import { a as e } from "./rolldown-runtime-CGYlQKCx.js";
import { Gr as t, Jr as n, Wr as r, Yr as i } from "./SegmentProvider-CXCNBY9U.js";
import { n as a } from "./@mux-DLaEVubF.js";
import {
  $s as o,
  G as s,
  Vg as c,
  Xs as l,
  Ys as u,
  Zs as d,
  ac as f,
  am as p,
  ec as m,
  g_ as h,
  nc as ee,
  om as g,
  qh as _,
  qs as v,
  tc as y,
  v_ as b,
  wg as x,
} from "./vendor-DAwbZtf0.js";
import { Dr as S, _r as C, tr as w } from "./use-boot-in-app-chat-t-J_VjKS.js";
import { h as T, o as E, p as te } from "./workflow_pb-DOR6D5WK.js";
import { n as D, t as O } from "./toast-axaLeIzZ.js";
import { a as k, t as A } from "./button-6YP03Qf2.js";
import { t as j } from "./cn-DppMFCU8.js";
import { t as M } from "./banner-CFcSGYsz.js";
import { t as N } from "./timestamp-CEKPQVte.js";
import { d as P, r as ne } from "./time-DxjbKG-a.js";
import { n as F } from "./utils-C9bSuXia.js";
import { t as re } from "./hooks-Cxw5RI6a.js";
import { t as I } from "./tooltip-6hqVQbwq.js";
import { t as L } from "./text-fFCFeCas.js";
import { M as ie, o as R } from "./automations-CN21BoUy.js";
import { p as ae } from "./project-queries-BMZ3qCU_.js";
import { t as oe } from "./scroll-area-DiWW0x8z.js";
import { t as se } from "./error-message-Az-KJctk.js";
import { t as z } from "./card-BxeZdx-o.js";
import { a as ce, i as B, n as le, o as V, r as H } from "./data-table-hWj1SxAH.js";
import { Q as U, Y as W } from "./main-DLKYFe1Y.js";
import { a as G, i as ue, r as de, t as K } from "./automation-execution-action-DsjZnn4c.js";
import { t as fe } from "./AutomationExecutionStatusIcon-B3fEPOH1.js";
import { t as pe } from "./AutomationExecutionStatusPill-ofehSgsb.js";
var q = e(a(), 1),
  J = {
    completed: {
      stroke: `rgb(var(--surface-success))`,
      fill: `rgb(var(--surface-success))`,
      fillOpacity: 0.2,
      fillOpacityHover: 0.45,
    },
    running: {
      stroke: `rgb(var(--content-brand))`,
      fill: `rgb(var(--content-brand))`,
      fillOpacity: 0.4,
      fillOpacityHover: 0.65,
    },
    pending: { stroke: `transparent`, fill: `rgb(var(--surface-brand))`, fillOpacity: 0.35, fillOpacityHover: 0.6 },
    failed: {
      stroke: `rgb(var(--surface-destructive))`,
      fill: `rgb(var(--surface-destructive))`,
      fillOpacity: 0.2,
      fillOpacityHover: 0.45,
    },
  },
  Y = { height: 260, gapWidth: 0.06, yAxisPaddingMultiplier: 1.03 },
  X = b(),
  me = ({ workflow: e, actions: t, className: n }) => {
    let r = e?.spec?.action?.steps?.length ?? 0,
      i = (0, q.useMemo)(() => [...new Set(t.map((e) => R(e.spec?.context)).filter(Boolean))], [t]),
      { projects: a } = ae(i, { enabled: i.length > 0 }),
      [s, c] = (0, q.useState)(null),
      p = (0, q.useCallback)(
        (e) => {
          if (r !== 0)
            switch (e.key) {
              case `ArrowLeft`:
                (e.preventDefault(), c((e) => (e === null ? 0 : Math.max(0, e - 1))));
                break;
              case `ArrowRight`:
                (e.preventDefault(), c((e) => (e === null ? 0 : Math.min(r - 1, e + 1))));
                break;
              case `Escape`:
                (e.preventDefault(), c(null));
                break;
            }
        },
        [r],
      ),
      h = (0, q.useCallback)(
        (e) => {
          if (r === 0) return;
          let t = e.currentTarget.querySelector(`.recharts-surface`);
          if (!t) return;
          let n = t.getBoundingClientRect(),
            i = e.clientX - n.left,
            a = n.width - 48 - 8,
            o = i - 48;
          if (o >= 0 && o <= a) {
            let e = Math.floor((o / a) * r);
            e >= 0 && e < r && c((t) => (t === e ? t : e));
          }
        },
        [r],
      ),
      g = (0, q.useCallback)(() => {
        c(null);
      }, []),
      _ = (0, q.useMemo)(() => Object.fromEntries((a || []).map((e) => [e.id, e.metadata?.name || `-`])), [a]),
      b = (0, q.useCallback)((e, t) => {
        let n = e.status?.stepStatuses ?? [],
          r = n.find((e) => (e ? (e.stepIndex ?? 0) === t : !1)),
          i = G(e);
        return r?.phase === T.FAILED || (r && ue(r))
          ? `failed`
          : r?.phase === T.DONE
            ? `completed`
            : r?.phase === T.RUNNING
              ? `running`
              : r?.phase === T.PENDING
                ? `pending`
                : r?.phase === T.CANCELLED
                  ? `cancelled`
                  : n.some((e) => (e ? (e.stepIndex ?? -1) > t && e.phase === T.DONE : !1)) ||
                      (e.status?.phase === te.DONE && !i)
                    ? `completed`
                    : i && t === (n.length > 0 ? Math.max(...n.map((e) => e?.stepIndex ?? 0)) : 0)
                      ? `failed`
                      : `pending`;
      }, []),
      x = (0, q.useMemo)(
        () =>
          Array.from({ length: r }).map((n, r) => {
            let i = 0,
              a = 0,
              o = 0,
              s = 0,
              c = 0,
              l = 0,
              u = 0,
              d = [];
            for (let e of t) {
              let t = e.status?.stepStatuses ?? [],
                n = G(e);
              if (t.some((e) => (e ? (e.stepIndex ?? 0) < r && e.phase === T.FAILED : !1))) {
                u++;
                continue;
              }
              if (
                n &&
                !t.some((e) => e?.phase === T.FAILED) &&
                r > (t.length > 0 ? Math.max(...t.map((e) => e?.stepIndex ?? 0)) : 0)
              ) {
                u++;
                continue;
              }
              switch ((l++, b(e, r))) {
                case `completed`:
                  i++;
                  break;
                case `running`:
                  a++;
                  break;
                case `pending`:
                  o++;
                  break;
                case `failed`: {
                  s++;
                  let t = R(e.spec?.context);
                  t && d.push(_[t] || t);
                  break;
                }
                case `cancelled`:
                  c++;
                  break;
              }
            }
            let f = e?.spec?.action?.steps?.[r],
              p = `Step`,
              m = ``;
            switch (f?.step?.case) {
              case `agent`:
                ((p = `Prompt`), (m = f.step.value?.prompt || ``));
                break;
              case `task`:
                ((p = `Shell script`), (m = f.step.value?.command || ``));
                break;
              case `pullRequest`:
                ((p = `Pull request`), (m = f.step.value?.title || ``));
                break;
              case `report`:
                ((p = `Report`), (m = f.step.value?.outputs?.[0]?.title || ``));
                break;
              default:
                break;
            }
            return {
              stepIndex: r,
              step: `Step ${r + 1}`,
              completed: i,
              failed: s,
              pending: o,
              running: a,
              cancelled: c,
              excluded: u,
              failedThisStep: s,
              pendingThisStep: o,
              runningThisStep: a,
              cancelledThisStep: c,
              stepType: p,
              stepText: m,
              sampleFailedProject: d[0],
              failedMoreCount: Math.max(d.length - 1, 0),
              total: l,
              totalActions: t.length,
            };
          }),
        [t, r, e?.spec?.action?.steps, _, b],
      ),
      S = (0, q.useMemo)(() => {
        let e = Y.gapWidth,
          t = [];
        if (r === 0) return t;
        t.push({ x: 0, completed: null, failed: null, pending: null, running: null, cancelled: null, excluded: null });
        for (let n of x) {
          let r = n.stepIndex,
            i = n.stepIndex + e,
            a = n.stepIndex + 1 - e,
            o = n.stepIndex + 1;
          (t.push({
            x: r,
            completed: null,
            failed: null,
            pending: null,
            running: null,
            cancelled: null,
            excluded: null,
            stepIndex: n.stepIndex,
          }),
            t.push({
              x: i,
              step: n.step,
              completed: n.completed,
              failed: n.failed,
              pending: n.pending,
              running: n.running,
              cancelled: n.cancelled,
              excluded: n.excluded,
              failedThisStep: n.failedThisStep,
              cancelledThisStep: n.cancelledThisStep,
              stepIndex: n.stepIndex,
              stepType: n.stepType,
              stepText: n.stepText,
              sampleFailedProject: n.sampleFailedProject,
              failedMoreCount: n.failedMoreCount,
            }),
            t.push({
              x: n.stepIndex + 0.5,
              step: n.step,
              completed: n.completed,
              failed: n.failed,
              pending: n.pending,
              running: n.running,
              cancelled: n.cancelled,
              excluded: n.excluded,
              failedThisStep: n.failedThisStep,
              cancelledThisStep: n.cancelledThisStep,
              stepIndex: n.stepIndex,
              stepType: n.stepType,
              stepText: n.stepText,
              sampleFailedProject: n.sampleFailedProject,
              failedMoreCount: n.failedMoreCount,
            }),
            t.push({
              x: a,
              step: n.step,
              completed: n.completed,
              failed: n.failed,
              pending: n.pending,
              running: n.running,
              cancelled: n.cancelled,
              excluded: n.excluded,
              failedThisStep: n.failedThisStep,
              cancelledThisStep: n.cancelledThisStep,
              stepIndex: n.stepIndex,
              stepType: n.stepType,
              stepText: n.stepText,
              sampleFailedProject: n.sampleFailedProject,
              failedMoreCount: n.failedMoreCount,
            }),
            t.push({
              x: o,
              completed: null,
              failed: null,
              pending: null,
              running: null,
              cancelled: null,
              excluded: null,
              stepIndex: n.stepIndex,
            }));
        }
        return (
          t.push({
            x: r,
            completed: null,
            failed: null,
            pending: null,
            running: null,
            cancelled: null,
            excluded: null,
          }),
          t
        );
      }, [x, r]),
      C = {
        completed: { label: `Completed`, color: `rgb(var(--surface-success))` },
        running: { label: `Running`, color: `rgb(var(--content-brand))` },
        pending: { label: `Pending`, color: `rgb(var(--content-brand))` },
        failed: { label: `Failed`, color: `rgb(var(--surface-destructive))` },
        cancelled: { label: `Cancelled`, color: `rgb(var(--content-muted))` },
      },
      w = r === 0 || t.length === 0,
      E = !w && x.some((e) => (e.failed ?? 0) > 0),
      D = !w && x.some((e) => (e.pending ?? 0) > 0),
      O = !w && x.some((e) => (e.running ?? 0) > 0);
    return (0, X.jsxs)(z, {
      variant: `bordered`,
      className: j(`border bg-surface-primary p-0`, n),
      children: [
        (0, X.jsxs)(`div`, {
          className: `flex items-center justify-between p-4`,
          children: [
            (0, X.jsx)(L, { className: `text-lg`, children: `Run performance across steps` }),
            (0, X.jsxs)(`div`, {
              className: `flex items-center gap-4 pr-1`,
              children: [
                (0, X.jsxs)(`div`, {
                  className: `flex items-center gap-1.5 text-base`,
                  children: [
                    (0, X.jsx)(`span`, {
                      className: `size-[14px] rounded-[2px] border border-[rgb(var(--surface-success))] bg-[rgb(var(--surface-success)/0.2)]`,
                    }),
                    (0, X.jsx)(L, { className: `text-content-primary`, children: `Completed` }),
                  ],
                }),
                O &&
                  (0, X.jsxs)(`div`, {
                    className: `flex items-center gap-1.5 text-base`,
                    children: [
                      (0, X.jsx)(`span`, {
                        className: `size-[14px] rounded-[2px] border border-[rgb(var(--content-brand))] bg-[rgb(var(--content-brand)/0.4)]`,
                      }),
                      (0, X.jsx)(L, { className: `text-content-primary`, children: `Running` }),
                    ],
                  }),
                D &&
                  (0, X.jsxs)(`div`, {
                    className: `flex items-center gap-1.5 text-base`,
                    children: [
                      (0, X.jsx)(`span`, {
                        className: `size-[14px] rounded-[2px] border border-[rgb(var(--content-brand))] bg-[rgb(var(--surface-brand))]`,
                      }),
                      (0, X.jsx)(L, { className: `text-content-primary`, children: `Pending` }),
                    ],
                  }),
                E &&
                  (0, X.jsxs)(`div`, {
                    className: `flex items-center gap-1.5 text-base`,
                    children: [
                      (0, X.jsx)(`span`, {
                        className: `size-[14px] rounded-[2px] border border-[rgb(var(--surface-destructive))] bg-[rgb(var(--surface-destructive)/0.2)]`,
                      }),
                      (0, X.jsx)(L, { className: `text-content-primary`, children: `Failed` }),
                    ],
                  }),
              ],
            }),
          ],
        }),
        (0, X.jsx)(`div`, {
          className: `py-2`,
          children: w
            ? (0, X.jsx)(`div`, {
                className: `flex h-[260px] items-center justify-center`,
                role: `status`,
                "aria-live": `polite`,
                children: (0, X.jsx)(L, { children: `No data available` }),
              })
            : (0, X.jsx)(`div`, {
                role: `img`,
                "aria-label": `Automation execution performance chart showing completed, pending, and failed actions across steps`,
                tabIndex: 0,
                onKeyDown: p,
                onMouseMove: h,
                onMouseLeave: g,
                className: `rounded-lg focus:outline-none focus:ring-2 focus:ring-content-brand focus:ring-offset-2`,
                children: (0, X.jsx)(W, {
                  className: `h-[260px] w-full`,
                  config: C,
                  children: (0, X.jsxs)(v, {
                    data: S,
                    margin: { left: 8, right: 8, top: 8, bottom: 0 },
                    children: [
                      (0, X.jsx)(o, {
                        vertical: !1,
                        strokeDasharray: `2 4`,
                        stroke: `rgb(var(--border-base))`,
                        syncWithTicks: !0,
                      }),
                      (0, X.jsx)(l, {
                        dataKey: `x`,
                        type: `number`,
                        domain: [0, Math.max(r, 1)],
                        ticks: Array.from({ length: r }, (e, t) => t + 0.5),
                        tickFormatter: (e) => `Step ${Math.round(e)}`,
                        tickMargin: 8,
                        allowDecimals: !1,
                      }),
                      (0, X.jsx)(u, {
                        domain: [0, Math.max(t.length, 1) * Y.yAxisPaddingMultiplier],
                        ticks: [
                          0,
                          Math.max(t.length, 1) * 0.25,
                          Math.max(t.length, 1) * 0.5,
                          Math.max(t.length, 1) * 0.75,
                          Math.max(t.length, 1),
                        ],
                        tickFormatter: (e) => {
                          let n = (e / Math.max(t.length, 1)) * 100;
                          return n === 0 || n === 50 || n === 100 ? `${Math.round(n)}%` : ``;
                        },
                        width: 40,
                        allowDecimals: !1,
                      }),
                      (0, X.jsx)(d, {
                        type: `monotone`,
                        stackId: `1`,
                        dataKey: `completed`,
                        name: `completed`,
                        stroke: J.completed.stroke,
                        fill: J.completed.fill,
                        fillOpacity: J.completed.fillOpacity,
                        strokeWidth: 2,
                        dot: !1,
                        activeDot: !1,
                        isAnimationActive: !1,
                      }),
                      O &&
                        (0, X.jsx)(d, {
                          type: `monotone`,
                          stackId: `1`,
                          dataKey: `running`,
                          name: `running`,
                          stroke: J.running.stroke,
                          fill: J.running.fill,
                          fillOpacity: J.running.fillOpacity,
                          strokeWidth: 2,
                          dot: !1,
                          activeDot: !1,
                          isAnimationActive: !1,
                        }),
                      D &&
                        (0, X.jsx)(d, {
                          type: `monotone`,
                          stackId: `1`,
                          dataKey: `pending`,
                          name: `pending`,
                          stroke: J.pending.stroke,
                          fill: J.pending.fill,
                          fillOpacity: J.pending.fillOpacity,
                          strokeWidth: 0,
                          dot: !1,
                          activeDot: !1,
                          isAnimationActive: !1,
                        }),
                      (0, X.jsx)(d, {
                        type: `monotone`,
                        stackId: `1`,
                        dataKey: `failed`,
                        name: `failed`,
                        stroke: J.failed.stroke,
                        fill: J.failed.fill,
                        fillOpacity: J.failed.fillOpacity,
                        strokeWidth: 0,
                        dot: !1,
                        activeDot: !1,
                        isAnimationActive: !1,
                      }),
                      (0, X.jsx)(d, {
                        type: `monotone`,
                        stackId: `1`,
                        dataKey: `excluded`,
                        name: `excluded`,
                        stroke: `transparent`,
                        fill: `rgb(var(--surface-secondary))`,
                        fillOpacity: 0.1,
                        strokeWidth: 0,
                        dot: !1,
                        activeDot: !1,
                        isAnimationActive: !1,
                      }),
                      (0, X.jsx)(U, { cursor: !1, content: (0, X.jsx)(ge, {}), allowEscapeViewBox: { x: !1, y: !0 } }),
                      s !== null &&
                        (0, X.jsx)(m, {
                          x1: s,
                          x2: s + 1,
                          y1: 0,
                          y2: Math.max(t.length, 1) * Y.yAxisPaddingMultiplier,
                          fill: `rgb(var(--surface-hover))`,
                          fillOpacity: 0.03,
                          ifOverflow: `hidden`,
                        }),
                      s !== null &&
                        (0, X.jsx)(ee, {
                          x: s + 0.5,
                          stroke: `rgb(var(--border-base))`,
                          strokeWidth: 1,
                          strokeDasharray: `3 3`,
                          ifOverflow: `hidden`,
                        }),
                      x.map((e) =>
                        e.pendingThisStep > 0 && e.total > 0
                          ? (0, X.jsx)(
                              y,
                              {
                                x: e.stepIndex + 0.5,
                                y: 1,
                                r: 0,
                                fill: `none`,
                                stroke: `none`,
                                isFront: !0,
                                children: (0, X.jsx)(f, {
                                  content: ({ x: t = 0, y: n = 0 }) =>
                                    (0, X.jsxs)(`g`, {
                                      transform: `translate(${t}, ${Number(n) - 10})`,
                                      children: [
                                        (0, X.jsx)(`g`, {
                                          transform: `translate(-10,-2)`,
                                          children: (0, X.jsx)(k, {
                                            size: `sm`,
                                            className: `animate-spin text-[rgb(var(--content-brand))]`,
                                          }),
                                        }),
                                        (0, X.jsx)(`text`, {
                                          x: 0,
                                          y: 4,
                                          fontSize: 12,
                                          fill: `rgb(var(--content-brand))`,
                                          dominantBaseline: `middle`,
                                          children: e.pendingThisStep,
                                        }),
                                      ],
                                    }),
                                }),
                              },
                              `pending-dot-${e.stepIndex}`,
                            )
                          : null,
                      ),
                      x.map((e) =>
                        e.runningThisStep > 0 && e.total > 0
                          ? (0, X.jsx)(
                              y,
                              {
                                x: e.stepIndex + 0.5,
                                y: 1,
                                r: 0,
                                fill: `none`,
                                stroke: `none`,
                                isFront: !0,
                                children: (0, X.jsx)(f, {
                                  content: ({ x: t = 0, y: n = 0 }) =>
                                    (0, X.jsxs)(`g`, {
                                      transform: `translate(${t}, ${Number(n) - 10})`,
                                      children: [
                                        (0, X.jsx)(`g`, {
                                          transform: `translate(-10,-2)`,
                                          children: (0, X.jsx)(k, {
                                            size: `sm`,
                                            className: `animate-spin text-[rgb(var(--content-brand))]`,
                                          }),
                                        }),
                                        (0, X.jsx)(`text`, {
                                          x: 0,
                                          y: 4,
                                          fontSize: 12,
                                          fill: `rgb(var(--content-brand))`,
                                          dominantBaseline: `middle`,
                                          children: e.runningThisStep,
                                        }),
                                      ],
                                    }),
                                }),
                              },
                              `running-dot-${e.stepIndex}`,
                            )
                          : null,
                      ),
                    ],
                  }),
                }),
              }),
        }),
      ],
    });
  },
  he = (e, t = 40) => {
    if (!e) return ``;
    let n = (e.split(/[.\n]/)[0] || e).trim();
    return n.length <= t ? n : n.slice(0, t - 1) + `…`;
  },
  ge = ({ active: e, payload: t }) => {
    if (!e || !t?.length) return null;
    let n = t[0]?.payload;
    if (!n) return null;
    let r = he(n.stepText);
    return (0, X.jsxs)(`div`, {
      className: `grid min-w-[16rem] max-w-[24rem] items-start gap-0.5 rounded-lg border border-border-base/50 bg-surface-popover px-3 py-2.5 text-sm text-content-primary shadow-lg backdrop-blur-xl`,
      children: [
        (0, X.jsxs)(`div`, { className: `text-content-muted`, children: [`Step `, n.stepIndex + 1] }),
        (0, X.jsxs)(`div`, {
          className: `mb-1.5`,
          children: [
            (0, X.jsx)(`span`, { className: `font-medium text-content-primary`, children: n.stepType }),
            r && (0, X.jsxs)(`span`, { className: `text-content-strong`, children: [`: `, r] }),
          ],
        }),
        (0, X.jsxs)(`div`, {
          className: `grid gap-1.5`,
          children: [
            (0, X.jsxs)(`div`, {
              className: `flex items-center gap-2`,
              children: [
                (0, X.jsx)(`span`, {
                  className: `size-[14px] shrink-0 rounded-[2px] border border-[rgb(var(--surface-success))] bg-[rgb(var(--surface-success)/0.2)]`,
                }),
                (0, X.jsxs)(L, {
                  className: `text-content-primary`,
                  children: [(0, X.jsx)(`span`, { className: `font-medium`, children: n.completed }), ` completed`],
                }),
              ],
            }),
            (n.running ?? 0) > 0 &&
              (0, X.jsxs)(`div`, {
                className: `flex items-center gap-2`,
                children: [
                  (0, X.jsx)(`span`, {
                    className: `size-[14px] shrink-0 rounded-[2px] border border-[rgb(var(--content-brand))] bg-[rgb(var(--content-brand)/0.4)]`,
                  }),
                  (0, X.jsxs)(L, {
                    className: `text-content-primary`,
                    children: [(0, X.jsx)(`span`, { className: `font-medium`, children: n.running }), ` running`],
                  }),
                ],
              }),
            (n.pending ?? 0) > 0 &&
              (0, X.jsxs)(`div`, {
                className: `flex items-center gap-2`,
                children: [
                  (0, X.jsx)(`span`, {
                    className: `size-[14px] shrink-0 rounded-[2px] border border-[rgb(var(--content-brand))] bg-[rgb(var(--surface-brand))]`,
                  }),
                  (0, X.jsxs)(L, {
                    className: `text-content-primary`,
                    children: [(0, X.jsx)(`span`, { className: `font-medium`, children: n.pending }), ` pending`],
                  }),
                ],
              }),
            n.failed > 0 &&
              (0, X.jsxs)(`div`, {
                className: `flex items-center gap-2`,
                children: [
                  (0, X.jsx)(`span`, {
                    className: `size-[14px] shrink-0 rounded-[2px] border border-[rgb(var(--surface-destructive))] bg-[rgb(var(--surface-destructive)/0.2)]`,
                  }),
                  (0, X.jsxs)(L, {
                    className: `text-content-primary`,
                    children: [(0, X.jsx)(`span`, { className: `font-medium`, children: n.failed }), ` failed`],
                  }),
                ],
              }),
          ],
        }),
      ],
    });
  },
  _e = ({ workflowExecution: e }) => {
    let t = e.metadata?.startedAt && e.metadata?.finishedAt ? ne(e.metadata.startedAt, e.metadata.finishedAt) : void 0;
    return (0, X.jsxs)(`div`, {
      className: `flex justify-between gap-4 self-stretch rounded-xl border border-border-base bg-surface-primary p-4`,
      children: [
        (0, X.jsx)(Z, { label: `Status`, children: (0, X.jsx)(pe, { execution: e }) }),
        (0, X.jsx)(Z, {
          label: `Triggered on`,
          children: (0, X.jsx)(L, {
            className: `font-base content-primary`,
            children: e.metadata?.startedAt ? P(N(e.metadata?.startedAt)) : (0, X.jsx)(`span`, { children: `-` }),
          }),
        }),
        (0, X.jsx)(Z, {
          label: `Completed on`,
          children: (0, X.jsx)(L, {
            className: `font-base content-primary`,
            children: e.metadata?.finishedAt ? P(N(e.metadata?.finishedAt)) : (0, X.jsx)(`span`, { children: `-` }),
          }),
        }),
        (0, X.jsx)(Z, {
          label: `Duration`,
          children: (0, X.jsx)(L, {
            className: `font-base content-primary`,
            children: t || (0, X.jsx)(`span`, { children: `-` }),
          }),
        }),
      ],
    });
  },
  Z = ({ children: e, label: t }) =>
    (0, X.jsxs)(`div`, {
      className: `flex w-44 shrink flex-col gap-1`,
      children: [(0, X.jsx)(L, { className: `content-strong text-base`, children: t }), e],
    });
function ve(e) {
  return e.includes(`,`) ||
    e.includes(`"`) ||
    e.includes(`
`)
    ? `"${e.replace(/"/g, `""`)}"`
    : e;
}
function ye(e) {
  return e.map((e) => e.map(ve).join(`,`)).join(`
`);
}
function be(e, t) {
  let n = new Blob([e], { type: `text/csv;charset=utf-8;` }),
    r = document.createElement(`a`),
    i = URL.createObjectURL(n);
  (r.setAttribute(`href`, i),
    r.setAttribute(`download`, t),
    (r.style.visibility = `hidden`),
    document.body.appendChild(r),
    r.click(),
    document.body.removeChild(r),
    URL.revokeObjectURL(i));
}
function xe(e) {
  switch (e.value.case) {
    case `stringValue`:
      return e.value.value;
    case `intValue`:
      return e.value.value.toString();
    case `floatValue`:
      return parseFloat(e.value.value.toPrecision(10)).toString();
    case `boolValue`:
      return e.value.value ? `true` : `false`;
    default:
      return `-`;
  }
}
function Se(e, t) {
  return ye([e, ...t]);
}
function Ce(e) {
  let t = e.spec?.context;
  return t?.context.case === `contextUrl` ? t.context.value.url : ``;
}
var we = () => {
    let e = S();
    return _({
      mutationFn: async ({ workflowExecutionId: t, actions: n }) => {
        let r = (
            await C(
              (t) => e.workflowService.listWorkflowExecutionOutputs(t),
              h(E, { filter: { workflowExecutionIds: [t] } }),
              (e) => e.outputs,
            )
          ).map((e) => e),
          i = new Map();
        for (let e of r) i.set(e.actionId, e);
        let a = new Set();
        for (let e of r) for (let t of Object.keys(e.values)) a.add(t);
        let o = Array.from(a).sort(),
          s = [`Action`, `Repository URL`, ...o],
          c = [];
        for (let e of n) {
          let t = e.metadata?.actionName || e.id,
            n = Ce(e),
            r = i.get(e.id),
            a = [t, n];
          for (let e of o) {
            let t = r?.values[e];
            t ? a.push(xe(t)) : a.push(`-`);
          }
          c.push(a);
        }
        be(Se(s, c), `automation-outputs-${t}.csv`);
      },
      onError: (e) => {
        O({ title: `Failed to export CSV`, description: w(e) });
      },
    });
  },
  Te = F(s),
  Q = (e) => {
    switch (e.value.case) {
      case `stringValue`:
        return e.value.value;
      case `intValue`:
        return e.value.value.toString();
      case `floatValue`:
        return e.value.value.toFixed(2);
      case `boolValue`:
        return e.value.value ? `true` : `false`;
      default:
        return `-`;
    }
  },
  Ee = (e) => e.value.case === `boolValue`,
  De = (e) => {
    if (e.value.case === `floatValue`) return e.value.value;
    if (e.value.case === `intValue`) return Number(e.value.value);
  },
  $ = (e, t, n) => (n === t ? 100 : ((e - t) / (n - t)) * 100),
  Oe = (e) => (e?.spec?.report?.steps ? e.spec.report.steps.some((e) => e.step.case === `report`) : !1),
  ke = ({ outputs: e, actions: t, workflow: n, workflowExecutionId: r }) => {
    let i = we(),
      a = async () => {
        await i.mutateAsync({ workflowExecutionId: r, actions: s });
      },
      o = (0, q.useMemo)(() => {
        let t = new Map();
        for (let n of e) t.set(n.actionId, n);
        return t;
      }, [e]),
      s = (0, q.useMemo)(() => {
        let e = de(t),
          n = [K.Active, K.Failed, K.Completed, K.Stopped, K.Deleted, K.Pending],
          r = [];
        for (let t of n) {
          let n = e.get(t);
          n && n.actions.length > 0 && r.push(...n.actions);
        }
        return r;
      }, [t]),
      { outputSchemas: c, schemaOutputKeys: l } = (0, q.useMemo)(() => {
        let e = new Map(),
          t = new Set();
        if (!n?.spec?.report?.steps) return { outputSchemas: e, schemaOutputKeys: t };
        for (let r of n.spec.report.steps)
          if (r.step.case === `report`)
            for (let n of r.step.value.outputs) {
              let r = n.key;
              if ((t.add(r), n.schema.case === `integer` || n.schema.case === `float`)) {
                let t = n.schema.value;
                t.min !== void 0 && t.max !== void 0 && e.set(r, { min: t.min, max: t.max });
              }
            }
        return { outputSchemas: e, schemaOutputKeys: t };
      }, [n]),
      u = (0, q.useMemo)(() => {
        let t = new Set();
        for (let n of e) for (let e of Object.keys(n.values)) t.add(e);
        for (let e of l) t.add(e);
        return Array.from(t).sort((e, t) => e.localeCompare(t));
      }, [e, l]);
    return s.length === 0 || !(Oe(n) || u.length > 0)
      ? null
      : (0, X.jsx)(z, {
          variant: `bordered`,
          className: `flex max-h-[70vh] flex-col overflow-clip border bg-surface-secondary p-0`,
          children: (0, X.jsx)(oe, {
            orientation: `both`,
            children: (0, X.jsxs)(`div`, {
              className: `flex min-h-0 flex-col gap-1`,
              children: [
                (0, X.jsx)(Ae, { showExportButton: s.length > 0, onExportCSV: a, isPending: i.isPending }),
                (0, X.jsxs)(`table`, {
                  className: `border-separate border-spacing-0 text-left text-sm`,
                  children: [
                    (0, X.jsx)(ce, {
                      className: `sticky top-0 z-10 [&_th]:border-b-0.5 [&_th]:border-b-border-base [&_th]:bg-surface-secondary [&_th]:px-4 [&_th]:py-2`,
                      children: (0, X.jsxs)(V, {
                        className: `border-none`,
                        children: [
                          (0, X.jsx)(B, {
                            className: `sticky left-0 z-20 border-r-0.5 border-r-border-subtle bg-surface-secondary text-left`,
                            children: (0, X.jsx)(L, {
                              className: `h-5 font-medium text-content-strong`,
                              children: `Action`,
                            }),
                          }),
                          u.map((e) =>
                            (0, X.jsx)(
                              B,
                              {
                                className: `text-center`,
                                children: (0, X.jsx)(L, { className: `font-medium text-content-strong`, children: e }),
                              },
                              e,
                            ),
                          ),
                        ],
                      }),
                    }),
                    (0, X.jsx)(le, {
                      className: `[&_td:last-child]:text-center`,
                      children: s.map((e, t) => {
                        let n = e.metadata?.actionName || e.id,
                          r = o.get(e.id);
                        return (0, X.jsxs)(
                          V,
                          {
                            className: j(
                              `border-none bg-surface-primary [&_td]:border-border-subtle`,
                              t !== s.length - 1 && `[&_td]:border-b`,
                            ),
                            children: [
                              (0, X.jsx)(H, {
                                className: j(
                                  `sticky left-0 z-[5] border-r-0.5 border-border-subtle bg-surface-primary`,
                                ),
                                children: (0, X.jsx)(L, {
                                  className: `text-sm font-medium text-content-primary`,
                                  children: n,
                                }),
                              }),
                              u.map((e) => {
                                let t = r?.values[e];
                                if (!t)
                                  return (0, X.jsx)(
                                    H,
                                    {
                                      className: `text-center`,
                                      children: (0, X.jsx)(L, {
                                        className: `text-sm text-content-muted`,
                                        children: `-`,
                                      }),
                                    },
                                    e,
                                  );
                                if (Ee(t)) {
                                  let n = t.value.case === `boolValue` && t.value.value;
                                  return (0, X.jsx)(
                                    H,
                                    {
                                      className: `text-center`,
                                      children: (0, X.jsx)(`span`, {
                                        className: j(
                                          `inline-flex items-center justify-center rounded-full px-2 py-1 text-xs font-medium`,
                                          n ? `bg-green-500/10 text-green-500` : `bg-red-500/10 text-red-500`,
                                        ),
                                        children: n ? `✓` : `✗`,
                                      }),
                                    },
                                    e,
                                  );
                                }
                                let n = c.get(e),
                                  i = De(t);
                                if (n && i !== void 0) {
                                  let r = $(i, n.min, n.max);
                                  return (0, X.jsx)(
                                    H,
                                    {
                                      className: `text-center`,
                                      children: (0, X.jsxs)(`div`, {
                                        className: `flex items-center justify-center gap-2`,
                                        children: [
                                          (0, X.jsx)(`div`, {
                                            className: `h-2 w-24 overflow-hidden rounded-full bg-surface-tertiary`,
                                            children: (0, X.jsx)(`div`, {
                                              className: j(
                                                `h-full transition-all`,
                                                r >= 80
                                                  ? `bg-content-green`
                                                  : r >= 50
                                                    ? `bg-content-orange`
                                                    : `bg-content-red`,
                                              ),
                                              style: { width: `${Math.min(100, Math.max(0, r))}%` },
                                            }),
                                          }),
                                          (0, X.jsx)(L, {
                                            className: `w-12 text-right text-sm text-content-muted`,
                                            children: Q(t),
                                          }),
                                        ],
                                      }),
                                    },
                                    e,
                                  );
                                }
                                return (0, X.jsx)(
                                  H,
                                  {
                                    className: `text-center`,
                                    children: (0, X.jsx)(L, {
                                      className: `text-sm text-content-primary`,
                                      children: Q(t),
                                    }),
                                  },
                                  e,
                                );
                              }),
                            ],
                          },
                          e.id,
                        );
                      }),
                    }),
                  ],
                }),
              ],
            }),
          }),
        });
  },
  Ae = ({ showExportButton: e, onExportCSV: t, isPending: n }) =>
    (0, X.jsxs)(`div`, {
      className: `flex items-center justify-between p-4 pb-1`,
      children: [
        (0, X.jsx)(L, { className: `text-lg text-content-primary`, children: `Report` }),
        (0, X.jsx)(`div`, {
          className: `flex items-center gap-3`,
          children:
            e &&
            (0, X.jsx)(I, {
              content: `Export CSV`,
              children: (0, X.jsx)(A, {
                variant: `ghost`,
                size: `sm`,
                onClick: t,
                disabled: n,
                "data-tracking-id": `exportcsv`,
                LeadingIcon: Te,
                loading: n,
                "aria-label": `Export CSV`,
              }),
            }),
        }),
      ],
    }),
  je = F(p),
  Me = F(g),
  Ne = F(c),
  Pe = () => {
    let { workflowExecutionId: e } = x(),
      { data: a, error: o } = t(e),
      { data: s } = r(a?.metadata?.workflowId),
      { data: c } = n({ enabled: !!e, workflowExecutionId: e || `` }),
      { data: l } = i({ enabled: !!e, workflowExecutionId: e || `` }),
      { toast: u } = D(),
      { copied: d, error: f, copy: p } = re(),
      m = (0, q.useCallback)(async () => {
        a && (await p(a.id)) && u({ title: `Execution ID copied to clipboard`, description: a.id });
      }, [p, u, a]);
    return (0, X.jsxs)(`div`, {
      "data-testid": `workflow-execution-summary`,
      className: `flex size-full flex-col gap-4`,
      children: [
        a &&
          s &&
          (0, X.jsxs)(`div`, {
            className: `flex flex-col gap-1`,
            children: [
              (0, X.jsxs)(`div`, {
                className: `flex items-center gap-2`,
                children: [
                  (0, X.jsx)(fe, { size: `lg`, execution: a }),
                  (0, X.jsx)(`span`, { className: `text-xl font-semibold text-content-primary`, children: ie(s) }),
                ],
              }),
              (0, X.jsxs)(`div`, {
                className: `flex items-center gap-1`,
                children: [
                  (0, X.jsxs)(L, { className: `text-base text-content-secondary`, children: [`#`, a.id] }),
                  (0, X.jsx)(I, {
                    content: `Copy Execution ID`,
                    children: (0, X.jsx)(A, {
                      variant: `ghost`,
                      size: `sm`,
                      className: d
                        ? `pointer-events-none text-content-success`
                        : f
                          ? `text-content-danger pointer-events-none`
                          : ``,
                      LeadingIcon: d ? Me : f ? Ne : je,
                      onClick: m,
                      "aria-label": `Copy Execution ID`,
                      "data-testid": `copy-execution-id`,
                      "data-tracking-id": `copy-execution-id`,
                    }),
                  }),
                ],
              }),
            ],
          }),
        (0, X.jsx)(se, { error: o }),
        a?.status?.failureMessage && (0, X.jsx)(M, { variant: `danger`, text: a.status.failureMessage }),
        c
          ?.filter((e) => G(e) && e.status?.failureMessage)
          .map((e) => (0, X.jsx)(M, { variant: `danger`, text: e.status.failureMessage }, e.id)),
        a && (0, X.jsx)(_e, { workflowExecution: a }),
        a && c && (0, X.jsx)(me, { workflow: s, actions: c }),
        c && s && e && (0, X.jsx)(ke, { outputs: l || [], actions: c, workflow: s, workflowExecutionId: e }),
      ],
    });
  };
export { Pe as AutomationExecutionSummaryPage };

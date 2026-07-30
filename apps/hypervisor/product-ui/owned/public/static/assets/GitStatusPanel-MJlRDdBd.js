import { a as e } from "./rolldown-runtime-CGYlQKCx.js";
import { n as t } from "./@mux-DLaEVubF.js";
import { Pg as n, Sl as r, cg as i, hp as a, kf as o, kp as s, v_ as c } from "./vendor-DAwbZtf0.js";
import { So as l } from "./use-boot-in-app-chat-t-J_VjKS.js";
import { t as u } from "./button-6YP03Qf2.js";
import { t as d } from "./cn-DppMFCU8.js";
import { t as f } from "./strings-C6LrS0GJ.js";
import { t as p } from "./hooks-Cxw5RI6a.js";
import { t as m } from "./text-fFCFeCas.js";
import { C as h } from "./environment-queries-zpiLcWfm.js";
import { t as g } from "./use-is-mobile-viewport-Chw6u8QP.js";
import { t as _ } from "./git-status-BQMeC1k2.js";
import { t as v } from "./notification-DHNU01HE.js";
import { t as y } from "./scroll-area-DiWW0x8z.js";
var b = e(t(), 1),
  x = c(),
  S = ({ environmentId: e }) => {
    let { data: t } = h(e),
      n = t?.status?.content?.git,
      { copied: r, error: i, copy: c } = p(),
      l = (0, b.useCallback)(() => {
        n?.branch && c(n.branch);
      }, [n?.branch, c]);
    return n
      ? (0, x.jsx)(`div`, {
          className: `rounded-xl border-0.5 border-border-base bg-surface-secondary px-0.5 py-1.5 transition-shadow hover:shadow-md`,
          children: (0, x.jsxs)(y, {
            orientation: `vertical`,
            className: `max-h-[400px]`,
            children: [
              (0, x.jsxs)(`div`, {
                className: `flex w-full items-center justify-between rounded-xl px-[18px] py-2.5`,
                children: [
                  (0, x.jsx)(`span`, {
                    className: `mr-2 select-none text-start text-md font-medium`,
                    children: `Git Status`,
                  }),
                  n.totalChangedFiles > 0 && (0, x.jsx)(v, { children: _(n.totalChangedFiles) }),
                ],
              }),
              (0, x.jsxs)(`div`, {
                className: `px-5 pb-2`,
                children: [
                  (0, x.jsx)(m, {
                    className: `select-none font-mono text-base text-content-muted`,
                    children: `Branch`,
                  }),
                  (0, x.jsxs)(`div`, {
                    className: `flex items-center gap-2 pb-2`,
                    children: [
                      (0, x.jsx)(m, { className: `text-base text-content-primary`, children: n.branch }),
                      (0, x.jsx)(u, {
                        variant: `ghost`,
                        type: `button`,
                        className: `h-6 rounded-lg border-none p-1 text-content-tertiary hover:text-content-secondary hover:opacity-100`,
                        onClick: l,
                        "aria-label": `Copy branch ${n.branch}`,
                        "data-tracking-id": `copy-branch-git-status-panel`,
                        children: r
                          ? (0, x.jsx)(s, { className: `text-content-success`, "aria-hidden": !0, size: 16 })
                          : i
                            ? (0, x.jsx)(o, { className: `text-content-danger`, "aria-hidden": !0, size: 16 })
                            : (0, x.jsx)(a, { "aria-hidden": !0, size: 16 }),
                      }),
                    ],
                  }),
                  (0, x.jsx)(E, { gitStatus: n }),
                  n.changedFiles.length > 0
                    ? (0, x.jsxs)(x.Fragment, {
                        children: [
                          (0, x.jsx)(`hr`, { className: `my-2 border-border-subtle` }),
                          (0, x.jsx)(D, { gitStatus: n }),
                        ],
                      })
                    : null,
                ],
              }),
            ],
          }),
        })
      : null;
  },
  C = n(`flex size-4 items-center justify-center rounded-full bg-surface-accent text-sm font-medium select-none`, {
    variants: {
      count: { false: null, true: `bg-surface-accent text-content-muted` },
      status: {
        [l.UNSPECIFIED]: null,
        [l.MODIFIED]: `bg-surface-accent text-content-muted`,
        [l.DELETED]: `bg-surface-warning-subtle text-content-destructive`,
        [l.ADDED]: `bg-surface-success-subtle text-content-success`,
        [l.UNTRACKED]: `bg-surface-warning-subtle text-content-warning`,
        [l.RENAMED]: `bg-surface-success-subtle text-content-success`,
        [l.COPIED]: `bg-surface-success-subtle text-content-success`,
        [l.UPDATED_BUT_UNMERGED]: `bg-surface-warning-subtle text-content-warning`,
      },
    },
  }),
  w = {
    [l.UNSPECIFIED]: null,
    [l.MODIFIED]: { symbol: `M`, full: `modified` },
    [l.DELETED]: { symbol: `D`, full: `deleted` },
    [l.ADDED]: { symbol: `A`, full: `added` },
    [l.UNTRACKED]: { symbol: `U`, full: `untracked` },
    [l.RENAMED]: { symbol: `R`, full: `renamed` },
    [l.COPIED]: { symbol: `C`, full: `copied` },
    [l.UPDATED_BUT_UNMERGED]: { symbol: `!`, full: `unmerged` },
  },
  T = (e) => {
    if (`count` in e)
      return (0, x.jsx)(`span`, { "aria-hidden": `true`, className: d(C({ count: !0 })), children: e.count });
    let t = w[e.status];
    return t
      ? (0, x.jsx)(`span`, { "aria-hidden": `true`, className: d(C({ status: e.status })), children: t.symbol })
      : null;
  },
  E = ({ gitStatus: e }) => {
    let t = (0, b.useId)();
    return !e.unpushedCommits || e.unpushedCommits.length === 0
      ? null
      : (0, x.jsxs)(`div`, {
          className: `flex flex-col gap-1`,
          children: [
            (0, x.jsxs)(`div`, {
              className: `flex items-center justify-between gap-2`,
              children: [
                (0, x.jsx)(m, {
                  id: t,
                  className: `select-none font-mono text-base text-content-muted`,
                  children: `Unpushed commits`,
                }),
                (0, x.jsx)(T, { count: e.unpushedCommits.length }),
                (0, x.jsxs)(`span`, {
                  className: `sr-only`,
                  children: [e.unpushedCommits.length, ` unpushed `, f(e.unpushedCommits.length, `commit`)],
                }),
              ],
            }),
            (0, x.jsx)(`ul`, {
              className: `flex flex-col gap-1`,
              "aria-labelledby": t,
              children: e.unpushedCommits.map((e) =>
                (0, x.jsxs)(
                  `li`,
                  {
                    className: `flex items-center gap-2 text-base text-content-primary`,
                    title: e,
                    children: [
                      (0, x.jsx)(`span`, {
                        className: `flex size-4 shrink-0 items-center justify-center`,
                        children: (0, x.jsx)(r, { size: `sm` }),
                      }),
                      (0, x.jsx)(`span`, { className: `truncate`, children: e }),
                    ],
                  },
                  e,
                ),
              ),
            }),
          ],
        });
  },
  D = ({ gitStatus: e }) => {
    let t = (0, b.useId)();
    return (0, x.jsxs)(`div`, {
      className: `flex flex-col gap-1`,
      children: [
        (0, x.jsxs)(`div`, {
          className: `flex items-center justify-between gap-2`,
          children: [
            (0, x.jsx)(m, {
              id: t,
              className: `select-none font-mono text-base text-content-muted`,
              children: `Uncommitted files`,
            }),
            (0, x.jsx)(T, { count: e.changedFiles.length }),
            (0, x.jsxs)(`span`, {
              className: `sr-only`,
              children: [e.changedFiles.length, ` uncommitted `, f(e.changedFiles.length, `file`)],
            }),
          ],
        }),
        (0, x.jsx)(`ul`, {
          className: `flex flex-col gap-1`,
          "aria-labelledby": t,
          children: e.changedFiles.map((e) => (0, x.jsx)(O, { file: e }, e.path)),
        }),
      ],
    });
  },
  O = ({ file: e }) => {
    let t = e.path.split(`/`).at(-1),
      { isMobileViewport: n } = g();
    return (0, x.jsxs)(`li`, {
      className: `flex min-w-0 items-start gap-2 text-base text-content-primary`,
      children: [
        (0, x.jsx)(`span`, {
          className: `mt-0.5 flex size-4 shrink-0 items-center justify-center`,
          children: (0, x.jsx)(r, { size: `sm` }),
        }),
        (0, x.jsxs)(`div`, {
          className: `flex min-w-0 flex-1 flex-col`,
          children: [
            (0, x.jsxs)(`div`, {
              className: `flex items-center justify-between gap-2`,
              children: [
                n
                  ? (0, x.jsx)(i, {
                      className: `min-w-0 flex-1 truncate font-mono text-base underline`,
                      to: { pathname: `./code-changes`, hash: e.path },
                      title: t,
                      children: t,
                    })
                  : (0, x.jsx)(m, { className: `min-w-0 flex-1 truncate font-mono text-base`, title: t, children: t }),
                (0, x.jsx)(T, { status: e.changeType }),
              ],
            }),
            (0, x.jsx)(m, {
              className: `truncate font-mono text-sm text-content-muted`,
              title: e.path,
              children: e.path,
            }),
          ],
        }),
        w[e.changeType] ? (0, x.jsx)(`span`, { className: `sr-only`, children: w[e.changeType].full }) : null,
      ],
    });
  };
export { D as n, E as r, S as t };

import { a as e } from "./rolldown-runtime-CGYlQKCx.js";
import { $r as t, N as n, Rt as r, Vt as i, Wt as a, vn as o, zt as s } from "./SegmentProvider-CXCNBY9U.js";
import { n as c } from "./@mux-DLaEVubF.js";
import {
  Bg as l,
  Bl as u,
  K as d,
  Op as f,
  Tp as p,
  Vg as m,
  mp as h,
  v_ as g,
  vp as _,
  xg as v,
} from "./vendor-DAwbZtf0.js";
import { Dt as y, tr as b } from "./use-boot-in-app-chat-t-J_VjKS.js";
import { g as x } from "./runner_manager_pb-BYgy9Ytq.js";
import { n as S, t as C } from "./toast-axaLeIzZ.js";
import { t as w } from "./button-6YP03Qf2.js";
import { t as T } from "./dialog-BtjFqa-w.js";
import { t as E } from "./banner-CFcSGYsz.js";
import { n as D, t as O } from "./strings-C6LrS0GJ.js";
import { n as k } from "./utils-C9bSuXia.js";
import { t as A } from "./input-C42Z_4fO.js";
import { t as j } from "./Pill-99RRpZf2.js";
import "./pill-AA_qJIlm.js";
import { t as M } from "./text-fFCFeCas.js";
import { t as N } from "./select-Ceshp72e.js";
import { t as P } from "./skeleton-Cm867Q_k.js";
import { r as F } from "./dropdown-menu-D3UmjGpQ.js";
import { M as I, j as ee } from "./automations-CN21BoUy.js";
import { s as L } from "./use-environment-class-entries-DPBxsgJb.js";
import { _ as R } from "./runner-configuration-queries-CSQ6BmaB.js";
import { b as z, d as B, v as te } from "./runner-queries-BAY_7mHt.js";
import { g as ne, m as V, p as re } from "./project-queries-BMZ3qCU_.js";
import { t as ie } from "./external-link-BKbp1Q22.js";
import { t as ae } from "./scroll-area-DiWW0x8z.js";
import { t as H } from "./error-message-Az-KJctk.js";
import { t as U } from "./combobox-BkGa_nRF.js";
import { t as W } from "./form-control-BfDRQ8Xb.js";
import { t as G } from "./EnvironmentClassSelect-6hHp7UYU.js";
import { t as oe } from "./url-BsmuZGkW.js";
import { _ as se, g as K, l as ce, t as q } from "./automation-edit-form-data-CvP3_1II.js";
import { t as le } from "./IconGridEmpty-PvTa41AA.js";
var J = e(c(), 1),
  Y = g(),
  ue = ({ repositories: e, open: t, onOpenChange: n, hasNextPage: r, isFetchingNextPage: i, onLoadMore: a }) => {
    let o = (0, J.useCallback)(() => {
      r && !i && a && a();
    }, [r, i, a]);
    return (0, Y.jsx)(T, {
      open: t,
      onOpenChange: n,
      children: (0, Y.jsxs)(T.Content, {
        "data-track-location": y.WorkflowEditPageRepoTriggerSampleDialog,
        children: [
          (0, Y.jsx)(T.Header, {
            children: (0, Y.jsxs)(T.Title, {
              children: [
                (0, Y.jsxs)(`span`, { children: [e.length, ` `, O(e.length, `repository`, `repositories`)] }),
                r && (0, Y.jsx)(`span`, { children: ` (more available)` }),
              ],
            }),
          }),
          (0, Y.jsx)(T.Body, {
            className: `p-0`,
            children: (0, Y.jsx)(ae, {
              orientation: `vertical`,
              className: `max-h-80`,
              onScrollEnd: o,
              scrollEndThreshold: 100,
              children: (0, Y.jsxs)(`ul`, {
                className: `flex flex-col gap-2`,
                children: [
                  e.map((e) =>
                    (0, Y.jsxs)(
                      `li`,
                      {
                        className: `flex flex-col rounded-md border border-border-subtle px-3 py-2`,
                        children: [
                          (0, Y.jsx)(ie, {
                            className: `text-content-brand hover:underline`,
                            href: e.url,
                            children: oe(e.url),
                          }),
                          (0, Y.jsx)(M, { className: `text-content-secondary`, children: e.name }),
                        ],
                      },
                      e.url,
                    ),
                  ),
                  i &&
                    (0, Y.jsx)(`li`, {
                      className: `flex justify-center py-2`,
                      children: (0, Y.jsx)(M, {
                        className: `animate-pulse text-content-secondary`,
                        children: `Loading more...`,
                      }),
                    }),
                ],
              }),
            }),
          }),
          (0, Y.jsx)(T.Footer, {
            className: `justify-end`,
            children: (0, Y.jsx)(T.Close, {
              asChild: !0,
              children: (0, Y.jsx)(w, {
                variant: `outline`,
                "data-tracking-id": `workflow-edit-page-repo-trigger-sample-dialog-close`,
                children: `Close`,
              }),
            }),
          }),
        ],
      }),
    });
  };
function X(e) {
  switch (e.toLowerCase()) {
    case `github`:
      return `GitHub`;
    case `gitlab`:
      return `GitLab`;
    case `bitbucket`:
      return `Bitbucket`;
    case `azuredevops`:
      return `Azure DevOps`;
    default:
      return `repository`;
  }
}
var Z = (0, J.memo)(
  ({ disabled: e, repoSearchString: t, runnerId: n, scmHost: r, onAddFilter: a, onClearFilter: o }) => {
    let [s, c] = (0, J.useState)(!1),
      { data: l, isLoading: u, error: d, refetch: f } = R(n),
      { data: p } = te(n),
      m,
      h;
    if (l && l.length > 0) {
      let e = l.find((e) => e.host === r);
      e ? ((m = e.host), (h = e.scmId)) : ((m = l[0].host), (h = l[0].scmId));
    } else ((m = ``), (h = ``));
    let g = !!n && !!m,
      {
        data: _,
        isPending: v,
        error: b,
      } = B(n, m, { enabled: g, retryOnFailedPrecondition: !0, refetchUntilAuthenticated: !0 }),
      S = g && !v && _?.type === `AuthenticationRequired`,
      {
        data: C,
        isLoading: T,
        error: D,
        refetch: O,
        fetchNextPage: k,
        hasNextPage: A,
        isFetchingNextPage: j,
      } = z({ runnerId: n, query: t, scmHost: m, enabled: !e && m !== `` && t !== ``, searchMode: x.NATIVE }),
      N = (0, J.useMemo)(() => C?.pages.flatMap((e) => e.repositories) ?? [], [C]),
      P = C?.pages[0]?.totalCount ?? -1;
    if (u)
      return (0, Y.jsx)(M, {
        className: `animate-pulse text-base text-content-secondary`,
        children: `Finding suitable repository provider…`,
      });
    if (d)
      return (0, Y.jsxs)(`div`, {
        className: `flex flex-row items-baseline gap-2`,
        children: [
          (0, Y.jsx)(H, { error: d }),
          (0, Y.jsx)(w, {
            type: `button`,
            variant: `outline`,
            size: `sm`,
            onClick: () => {
              f();
            },
            "data-tracking-id": `retry`,
            children: `Retry`,
          }),
        ],
      });
    if (l && l.length === 0)
      return (0, Y.jsx)(`div`, {
        className: `flex items-center justify-between rounded-lg border border-border-base p-3`,
        children: (0, Y.jsxs)(M, {
          className: `text-content-muted`,
          children: [p?.name, ` does not support repository trigger. Please select a different runner.`],
        }),
      });
    let F;
    return (
      (F =
        g && v
          ? (0, Y.jsx)(`div`, {
              className: `flex items-center justify-between rounded-lg border border-border-base p-3`,
              children: (0, Y.jsx)(M, { className: `text-content-muted`, children: `Checking authentication` }),
            })
          : g && !v && b && !S
            ? (0, Y.jsx)(H, { error: b })
            : T
              ? (0, Y.jsx)(M, {
                  className: `animate-pulse text-base text-content-secondary`,
                  children: `Searching repositories…`,
                })
              : N.length > 0
                ? (0, Y.jsx)(pe, {
                    searchString: t,
                    repositories: N,
                    totalCount: P,
                    onClear: o,
                    hasNextPage: A,
                    isFetchingNextPage: j,
                    onLoadMore: () => void k(),
                  })
                : S
                  ? (0, Y.jsxs)(Y.Fragment, {
                      children: [
                        (0, Y.jsx)(H, { error: b }),
                        (0, Y.jsx)(E, {
                          action: {
                            text: `Authenticate`,
                            onClick: () => c(!0),
                            "data-tracking-id": `automation-edit-code-context-scm-authentication`,
                          },
                          variant: `warning`,
                          text: (0, Y.jsxs)(`span`, {
                            children: [
                              (0, Y.jsx)(`span`, { className: `font-bold`, children: p?.name || `Unknown runner` }),
                              ` requires authentication with `,
                              (0, Y.jsx)(`span`, { className: `font-bold`, children: m }),
                            ],
                          }),
                          className: `shadow-none`,
                        }),
                        m &&
                          n &&
                          _ &&
                          s &&
                          (0, Y.jsx)(i, {
                            repoURL: `https://` + m,
                            authResponse: _,
                            runnerId: n,
                            onAuthSuccess: () => {
                              c(!1);
                            },
                            onClose: () => {
                              c(!1);
                            },
                            "data-track-location": y.GitAuthenticationTokenCreateModal,
                          }),
                      ],
                    })
                  : (0, Y.jsx)(fe, {
                      initialSearchString: t,
                      loading: T,
                      disabled: e,
                      onAddFilter: a,
                      searchError: D,
                      onRetry: O,
                      scmId: h,
                    })),
      (0, Y.jsxs)(`div`, {
        className: `flex flex-col gap-2`,
        children: [
          (0, Y.jsx)(`span`, {
            className: `flex flex-col gap-1 text-base font-normal text-content-primary`,
            children: `Search expression`,
          }),
          F,
        ],
      })
    );
  },
);
Z.displayName = `RepoFilteringContent`;
var de = (0, J.memo)(({ scmIntegrations: e, selectedHost: t, onHostChange: n, disabled: r }) =>
  (0, Y.jsx)(N, {
    value: t,
    onValueChange: n,
    disabled: r,
    "data-testid": `scm-host-selector`,
    className: `w-full`,
    children: e.map((e) => (0, Y.jsx)(N.Item, { value: e.host, children: e.host }, e.id)),
  }),
);
de.displayName = `SCMHostSelector`;
var fe = (0, J.memo)(
  ({ initialSearchString: e, loading: t, disabled: n, onAddFilter: r, searchError: i, onRetry: a, scmId: o }) => {
    let s = (0, J.useRef)(null),
      [c, l] = (0, J.useState)(void 0),
      u = !!i && i !== c,
      d = () => {
        if (s.current) {
          let t = s.current.value;
          i && t === e && a ? a() : r(t);
        }
      },
      f = (e) => {
        e.key === `Enter` && (e.preventDefault(), d());
      },
      p = () => {
        u && l(i);
      },
      m = o ? X(o) : `repository`;
    return (0, Y.jsxs)(W, {
      hint: `The search expression will be evaluated when the automation is triggered`,
      children: [
        (0, Y.jsxs)(`div`, {
          className: `flex w-full flex-row items-center gap-2`,
          children: [
            (0, Y.jsx)(A, {
              ref: s,
              disabled: n,
              defaultValue: e,
              type: `text`,
              placeholder:
                m === `repository`
                  ? `Describe what repositories to include or paste a filter`
                  : `Describe what repositories to include or paste a ${m} filter`,
              className: `max-w-none`,
              onKeyDown: f,
              onChange: p,
            }),
            (0, Y.jsx)(w, {
              type: `button`,
              variant: `primary`,
              size: `md`,
              className: `aspect-square p-0`,
              loading: t,
              disabled: n,
              LeadingIcon: k(h),
              onClick: d,
              "aria-label": `Add repository search filter`,
              "data-tracking-id": `submitsearchstring`,
              children: (0, Y.jsx)(`span`, { className: `sr-only`, children: `Add repository search filter` }),
            }),
          ],
        }),
        u && i && (0, Y.jsx)(H, { error: i }),
      ],
    });
  },
);
fe.displayName = `RepoFilterInput`;
var pe = (0, J.memo)(
  ({
    searchString: e,
    repositories: t,
    totalCount: n,
    onClear: r,
    hasNextPage: i,
    isFetchingNextPage: a,
    onLoadMore: o,
  }) => {
    let [s, c] = (0, J.useState)(!1),
      l = (0, J.useMemo)(
        () =>
          n > 0
            ? `${n} matching repositories`
            : i
              ? `${t.length}+ matching repositories`
              : `${t.length} matching repositories`,
        [t.length, n, i],
      );
    return (0, Y.jsxs)(Y.Fragment, {
      children: [
        (0, Y.jsxs)(`div`, {
          className: `flex flex-col gap-2`,
          children: [
            (0, Y.jsxs)(`div`, {
              className: `flex items-center justify-between rounded-lg border border-border-base p-3`,
              children: [
                (0, Y.jsx)(j, { variant: `brand`, size: `md`, children: e }),
                (0, Y.jsx)(w, {
                  variant: `ghost`,
                  size: `sm`,
                  LeadingIcon: k(m),
                  onClick: r,
                  "data-tracking-id": `code-context-repo-search-clear`,
                  children: `Clear`,
                }),
              ],
            }),
            (0, Y.jsxs)(`div`, {
              className: `flex flex-row items-center gap-2`,
              children: [
                (0, Y.jsx)(M, { className: `flex-1 text-content-secondary`, children: l }),
                (0, Y.jsx)(w, {
                  type: `button`,
                  variant: `outline`,
                  size: `sm`,
                  LeadingIcon: k(d),
                  "data-tracking-id": `code-context-repo-search-view-sample`,
                  onClick: () => {
                    c(!0);
                  },
                  children: `View sample`,
                }),
              ],
            }),
          ],
        }),
        (0, Y.jsx)(ue, {
          repositories: t,
          open: s,
          onOpenChange: c,
          hasNextPage: i,
          isFetchingNextPage: a,
          onLoadMore: o,
        }),
      ],
    });
  },
);
pe.displayName = `RepoFilterResult`;
function me(e, t) {
  let n = [],
    r = ``,
    i = !1,
    a = 0;
  for (; a < e.length; ) {
    let o = e[a];
    i
      ? o === `"`
        ? a + 1 < e.length && e[a + 1] === `"`
          ? ((r += `"`), (a += 2))
          : ((i = !1), a++)
        : ((r += o), a++)
      : o === `"`
        ? ((i = !0), a++)
        : o === t
          ? (n.push(r.trim()), (r = ``), a++)
          : ((r += o), a++);
  }
  return (n.push(r.trim()), n);
}
function he(e) {
  let t = [`repository`, `repo`, `url`, `name`, `project`, `link`, `path`, `id`, `column`, `description`];
  return e.some((e) => {
    let t = e.trim().toLowerCase();
    return (
      t.startsWith(`http://`) ||
      t.startsWith(`https://`) ||
      t.includes(`.com/`) ||
      t.includes(`.org/`) ||
      t.includes(`.io/`) ||
      /^[a-z0-9_-]+\/[a-z0-9_-]+$/i.test(t)
    );
  })
    ? !1
    : e.some((e) => {
        let n = e.toLowerCase().trim();
        return t.some((e) => n === e || n.startsWith(e + `_`) || n.endsWith(`_` + e));
      });
}
function ge(e, t = {}) {
  let n = t.separator ?? `,`,
    r = e.split(/\r?\n/).filter((e) => e.trim() !== ``);
  if (r.length === 0) return { headers: [], rows: [], hasHeaders: !1 };
  let i = r.map((e) => me(e, n)),
    a = Math.max(...i.map((e) => e.length)),
    o = i.map((e) => {
      for (; e.length < a; ) e.push(``);
      return e;
    }),
    s = t.hasHeaders ?? he(o[0]),
    c,
    l;
  return (
    s && o.length > 0
      ? ((c = o[0]), (l = o.slice(1)))
      : ((c = Array.from({ length: a }, (e, t) => `Column ${t + 1}`)), (l = o)),
    { headers: c, rows: l, hasHeaders: s }
  );
}
function _e(e, t) {
  let n = [],
    r = 0;
  for (let i of e.rows) {
    let e = i[t]?.trim() ?? ``;
    e && Q(e) ? n.push(e) : e && r++;
  }
  return { validUrls: n, skippedCount: r, totalProcessed: e.rows.length };
}
function Q(e) {
  let t = e.trim();
  if (!t) return !1;
  if (t.startsWith(`http://`) || t.startsWith(`https://`)) {
    let e = t.replace(/^https?:\/\//, ``).split(`/`);
    return e.length >= 3 && e.every((e) => e.length > 0);
  }
  let n = t.split(`/`);
  return !!(n.length >= 3 && n.every((e) => e.length > 0) && n[0].includes(`.`));
}
function $(e) {
  let t = e.trim();
  for (; t.endsWith(`/`); ) t = t.slice(0, -1);
  for (t.endsWith(`.git`) && (t = t.slice(0, -4)); t.endsWith(`/`); ) t = t.slice(0, -1);
  return t;
}
function ve(e) {
  let t = new Set(),
    n = [];
  for (let r of e) {
    let e = $(r).toLowerCase();
    t.has(e) || (t.add(e), n.push($(r)));
  }
  return n;
}
function ye(e) {
  if (e.headers.length === 0) return 0;
  let t = Array(e.headers.length).fill(0),
    n = [/repo(sitory)?/i, /url/i, /github/i, /gitlab/i, /bitbucket/i, /clone/i, /source/i, /link/i];
  for (let r = 0; r < e.headers.length; r++) {
    let i = e.headers[r].toLowerCase();
    for (let e of n) e.test(i) && (t[r] += 10);
  }
  let r = e.rows.slice(0, Math.min(10, e.rows.length));
  for (let e of r)
    for (let n = 0; n < e.length; n++) {
      let r = e[n]?.trim() ?? ``;
      Q(r)
        ? (t[n] += 5)
        : r.includes(`github.com`) || r.includes(`gitlab.com`) || r.includes(`bitbucket.org`)
          ? (t[n] += 3)
          : r.includes(`/`) && r.split(`/`).length >= 2 && (t[n] += 1);
    }
  let i = 0,
    a = t[0];
  for (let e = 1; e < t.length; e++) t[e] > a && ((a = t[e]), (i = e));
  return i;
}
var be = ({ context: e, runnerId: t, disabled: n, onAddUrls: r, onRemoveUrl: i, onClearAll: a }) =>
    (0, Y.jsx)(Ce, { repoUrls: e.repoUrls, runnerId: t, disabled: n, onAddUrls: r, onRemoveUrl: i, onClearAll: a }),
  xe = ({ runnerId: e, disabled: t, existingUrls: n, onImport: r }) => {
    let [i, a] = (0, J.useState)(``),
      [o, s] = (0, J.useState)(``),
      [c, l] = (0, J.useState)([]),
      [u, d] = (0, J.useState)(!1),
      f = (0, J.useCallback)((e) => {
        (l(e.map((e) => e.url)), d(!0));
      }, []),
      p = (0, J.useCallback)(() => {
        let e = c.filter((e) => !n.includes(e));
        if (e.length === 0) {
          C({ title: `No new repositories`, description: `All found repositories are already in the list.` });
          return;
        }
        r(e);
      }, [c, n, r]),
      m = c.filter((e) => !n.includes(e)).length;
    return (0, Y.jsxs)(`div`, {
      className: `flex flex-col gap-3`,
      children: [
        (0, Y.jsx)(we, {
          disabled: t,
          runnerId: e,
          repoSearchString: i,
          scmHost: o,
          onScmHostChange: s,
          onAddFilter: a,
          onClearFilter: () => {
            (a(``), l([]), d(!1));
          },
          onSearchComplete: f,
        }),
        u &&
          c.length > 0 &&
          (0, Y.jsx)(`div`, {
            className: `flex flex-row justify-end`,
            children: (0, Y.jsx)(w, {
              type: `button`,
              variant: `primary`,
              size: `sm`,
              onClick: p,
              disabled: m === 0,
              "data-tracking-id": `import-search-results`,
              children: (0, Y.jsxs)(`span`, {
                children: [
                  `Add `,
                  m,
                  ` `,
                  m === 1
                    ? (0, Y.jsx)(`span`, { children: `repository` })
                    : (0, Y.jsx)(`span`, { children: `repositories` }),
                ],
              }),
            }),
          }),
      ],
    });
  },
  Se = [
    { value: `,`, label: `Comma (,)` },
    { value: `;`, label: `Semicolon (;)` },
    { value: `	`, label: `Tab` },
    { value: `|`, label: `Pipe (|)` },
  ],
  Ce = ({ repoUrls: e, runnerId: t, disabled: n, onAddUrls: r, onRemoveUrl: i, onClearAll: o }) => {
    let [s, c] = (0, J.useState)(``),
      [l, u] = (0, J.useState)(null),
      d = (0, J.useRef)(null),
      [m, h] = (0, J.useState)({ mode: `idle` }),
      [g, v] = (0, J.useState)(`,`),
      [y, b] = (0, J.useState)(!0),
      [x, S] = (0, J.useState)(0),
      [T, E] = (0, J.useState)(!1),
      D = (0, J.useCallback)(() => {
        let t = s.trim();
        if (t) {
          if (e.length >= 100) {
            u(`Maximum of 100 repositories allowed.`);
            return;
          }
          if (!Q(t)) {
            u(`Please enter a full URL (e.g., https://github.com/owner/repo or github.com/owner/repo)`);
            return;
          }
          (u(null), r([t]), c(``));
        }
      }, [s, e.length, r]),
      O = (0, J.useCallback)((e) => {
        (c(e.target.value), u(null));
      }, []),
      k = (0, J.useCallback)(
        (e) => {
          e.key === `Enter` && (e.preventDefault(), D());
        },
        [D],
      ),
      j = (0, J.useCallback)(() => {
        (E(!1), h({ mode: `search` }));
      }, []),
      P = (0, J.useCallback)(() => {
        (E(!1), d.current?.click());
      }, []),
      I = (0, J.useCallback)(() => {
        h({ mode: `idle` });
      }, []),
      ee = (0, J.useCallback)(
        (e) => {
          let t = e.target.files?.[0];
          if (!t) return;
          let n = new FileReader();
          ((n.onload = (e) => {
            let t = e.target?.result,
              n = ge(t, { separator: g, hasHeaders: y });
            if (n.rows.length === 0) {
              C({ title: `No data found`, description: `The file appears to be empty.` });
              return;
            }
            (S(ye(n)), h({ mode: `csv-preview`, data: n, fileContent: t }));
          }),
            (n.onerror = () => {
              C({
                title: `Failed to read file`,
                description: `There was an error reading the CSV file. Please try again.`,
              });
            }),
            n.readAsText(t),
            d.current && (d.current.value = ``));
        },
        [g, y],
      ),
      L = (0, J.useCallback)(
        (e, t) => {
          if (m.mode === `csv-preview`) {
            let n = { separator: e, hasHeaders: t },
              r = ge(m.fileContent, n);
            (S(ye(r)), h({ mode: `csv-preview`, data: r, fileContent: m.fileContent }));
          }
        },
        [m],
      ),
      R = (0, J.useCallback)(() => {
        if (m.mode !== `csv-preview`) return;
        let t = _e(m.data, x);
        if (t.validUrls.length === 0) {
          C({
            title: `No valid repositories found`,
            description:
              t.skippedCount > 0
                ? `${t.skippedCount} entries were skipped. URLs must include the host (e.g., github.com/owner/repo).`
                : `The selected column contains no data.`,
          });
          return;
        }
        let n = 100 - e.length;
        if (n <= 0) {
          C({
            title: `Limit reached`,
            description: `Maximum of 100 repositories allowed. Remove some repositories first.`,
          });
          return;
        }
        let i = t.validUrls.slice(0, n),
          a = t.validUrls.length - i.length;
        r(i);
        let o = ``;
        ((o =
          a > 0
            ? `${a} URLs were not imported (limit of 100 reached).`
            : t.skippedCount > 0
              ? `${t.skippedCount} entries were skipped (invalid format or missing host).`
              : `All entries were successfully imported.`),
          C({ title: `Imported ${i.length} repositories`, description: o }),
          h({ mode: `idle` }));
      }, [m, x, e.length, r]),
      z = (0, J.useCallback)(
        (t) => {
          let n = 100 - e.length;
          if (n <= 0) {
            C({ title: `Limit reached`, description: `Maximum of 100 repositories allowed.` });
            return;
          }
          let i = t.slice(0, n);
          (r(i),
            i.length < t.length
              ? C({
                  title: `Added ${i.length} repositories`,
                  description: `${t.length - i.length} were not added (limit of 100 reached).`,
                })
              : C({ title: `Added ${i.length} repositories` }),
            h({ mode: `idle` }));
        },
        [e.length, r],
      );
    if (!t)
      return (0, Y.jsx)(`div`, {
        className: `flex min-h-[46px] w-full items-center rounded-lg border border-border-subtle px-3`,
        children: (0, Y.jsx)(M, {
          className: `flex h-[30px] items-center text-base text-content-muted`,
          children: `Select an environment class to add repositories.`,
        }),
      });
    let B = (0, Y.jsx)(`input`, {
      ref: d,
      type: `file`,
      accept: `.csv,.txt`,
      onChange: ee,
      className: `hidden`,
      disabled: n,
    });
    return (0, Y.jsxs)(`div`, {
      className: `flex flex-col gap-3`,
      children: [
        B,
        (() => {
          switch (m.mode) {
            case `search`:
              return t
                ? (0, Y.jsxs)(`div`, {
                    className: `flex flex-col gap-3 rounded-lg border border-border-base p-3`,
                    children: [
                      (0, Y.jsxs)(`div`, {
                        className: `flex flex-row items-center justify-between`,
                        children: [
                          (0, Y.jsx)(M, { className: `text-base font-normal`, children: `Import from Search` }),
                          (0, Y.jsx)(w, {
                            type: `button`,
                            variant: `ghost`,
                            size: `sm`,
                            onClick: I,
                            "data-tracking-id": `cancel-search-import`,
                            children: `Cancel`,
                          }),
                        ],
                      }),
                      (0, Y.jsx)(xe, { runnerId: t, disabled: n, existingUrls: e, onImport: z }),
                    ],
                  })
                : null;
            case `csv-preview`:
              return (0, Y.jsxs)(`div`, {
                className: `flex flex-col overflow-hidden rounded-lg border border-border-base`,
                children: [
                  (0, Y.jsxs)(`div`, {
                    className: `flex flex-row items-center justify-between border-b border-border-base bg-surface-base px-3 py-2`,
                    children: [
                      (0, Y.jsx)(M, {
                        className: `text-base font-normal`,
                        children: `Select the column that contains your repository URLs`,
                      }),
                      (0, Y.jsxs)(`div`, {
                        className: `flex flex-row items-center gap-2`,
                        children: [
                          (0, Y.jsx)(w, {
                            type: `button`,
                            variant: `ghost`,
                            size: `sm`,
                            onClick: I,
                            "data-tracking-id": `cancel-csv-import`,
                            children: `Cancel`,
                          }),
                          (0, Y.jsx)(w, {
                            type: `button`,
                            variant: `primary`,
                            size: `sm`,
                            onClick: R,
                            "data-tracking-id": `confirm-csv-import`,
                            children: `Import rows`,
                          }),
                        ],
                      }),
                    ],
                  }),
                  (0, Y.jsxs)(`div`, {
                    className: `flex flex-row flex-wrap items-center justify-between gap-4 border-b border-border-base px-3 py-2`,
                    children: [
                      (0, Y.jsxs)(`div`, {
                        className: `flex flex-row flex-wrap items-center gap-4`,
                        children: [
                          (0, Y.jsxs)(`div`, {
                            className: `flex flex-row items-center gap-2`,
                            children: [
                              (0, Y.jsx)(M, {
                                className: `text-base text-content-secondary`,
                                children: `Columns separated by:`,
                              }),
                              (0, Y.jsx)(N, {
                                value: g,
                                onValueChange: (e) => {
                                  (v(e), L(e, y));
                                },
                                className: `w-32`,
                                children: Se.map((e) =>
                                  (0, Y.jsx)(
                                    N.Item,
                                    { value: e.value, children: (0, Y.jsx)(`span`, { children: e.label }) },
                                    e.value,
                                  ),
                                ),
                              }),
                            ],
                          }),
                          (0, Y.jsxs)(`div`, {
                            className: `flex cursor-pointer flex-row items-center gap-2`,
                            children: [
                              (0, Y.jsx)(`input`, {
                                id: `csv-has-headers-preview`,
                                type: `checkbox`,
                                checked: y,
                                onChange: (e) => {
                                  let t = e.target.checked;
                                  (b(t), L(g, t));
                                },
                                className: `size-4 rounded border-border-base`,
                              }),
                              (0, Y.jsx)(`label`, {
                                htmlFor: `csv-has-headers-preview`,
                                children: (0, Y.jsx)(M, {
                                  className: `text-base text-content-secondary`,
                                  children: `First row is a header`,
                                }),
                              }),
                            ],
                          }),
                        ],
                      }),
                      (0, Y.jsxs)(M, {
                        className: `text-base text-content-secondary`,
                        children: [m.data.rows.length, ` rows`],
                      }),
                    ],
                  }),
                  (0, Y.jsx)(`div`, {
                    className: `overflow-x-auto`,
                    children: (0, Y.jsxs)(`table`, {
                      className: `w-full border-separate border-spacing-0 text-base`,
                      children: [
                        (0, Y.jsx)(`thead`, {
                          children: (0, Y.jsx)(`tr`, {
                            children: m.data.headers.map((e, t) => {
                              let n = t === x;
                              return (0, Y.jsx)(
                                `th`,
                                {
                                  onClick: () => S(t),
                                  className: `min-w-[150px] cursor-pointer border-b border-l border-r border-t px-4 py-2 text-left transition-colors ${n ? `border-border-brand bg-surface-brand/10 font-bold text-content-primary` : `border-b-border-base border-l-transparent border-r-transparent border-t-transparent bg-surface-secondary font-medium text-content-secondary hover:bg-surface-01`}`,
                                  "data-tracking-id": `automations-repository-csv-import-column-clicked`,
                                  children: (0, Y.jsxs)(`div`, {
                                    className: `flex items-center gap-2`,
                                    children: [
                                      (0, Y.jsx)(`span`, {
                                        className: `flex size-4 shrink-0 items-center justify-center rounded-full border border-content-primary`,
                                        children:
                                          n &&
                                          (0, Y.jsx)(_, {
                                            className: `size-2 fill-content-primary text-content-primary`,
                                          }),
                                      }),
                                      (0, Y.jsx)(`span`, { className: `truncate`, children: e }),
                                    ],
                                  }),
                                },
                                t,
                              );
                            }),
                          }),
                        }),
                        (0, Y.jsx)(`tbody`, {
                          children: m.data.rows.slice(0, 5).map((e, t) => {
                            let n = t === Math.min(4, m.data.rows.length - 1);
                            return (0, Y.jsx)(
                              `tr`,
                              {
                                children: e.map((e, t) =>
                                  (0, Y.jsx)(
                                    `td`,
                                    {
                                      title: e,
                                      className: `min-w-[150px] border-b border-l border-r px-4 py-2 text-content-primary ${t === x ? `border-l-border-brand border-r-border-brand bg-surface-brand/5 ${n ? `border-b-border-brand` : `border-b-border-subtle`}` : `border-b-border-subtle border-l-transparent border-r-transparent`}`,
                                      children: (0, Y.jsx)(`span`, { className: `line-clamp-1`, children: e }),
                                    },
                                    t,
                                  ),
                                ),
                              },
                              t,
                            );
                          }),
                        }),
                      ],
                    }),
                  }),
                  m.data.rows.length > 5 &&
                    (0, Y.jsx)(`div`, {
                      className: `border-t border-border-base px-3 py-2`,
                      children: (0, Y.jsxs)(M, {
                        className: `text-xs text-content-muted`,
                        children: [`Showing 5 of `, m.data.rows.length, ` rows`],
                      }),
                    }),
                ],
              });
            default:
              return (0, Y.jsxs)(`div`, {
                className: `flex flex-col gap-1`,
                children: [
                  (0, Y.jsxs)(`div`, {
                    className: `flex flex-row items-center gap-2`,
                    children: [
                      (0, Y.jsx)(A, {
                        type: `text`,
                        value: s,
                        onChange: O,
                        onKeyDown: k,
                        placeholder: `Enter repository URL (e.g., https://github.com/owner/repo)`,
                        className: `max-w-none flex-1`,
                        disabled: n,
                      }),
                      (0, Y.jsxs)(`div`, {
                        className: `flex`,
                        children: [
                          (0, Y.jsx)(w, {
                            type: `button`,
                            variant: `secondary`,
                            size: `md`,
                            onClick: D,
                            disabled: n || !s.trim(),
                            className: `rounded-r-none`,
                            "data-tracking-id": `add-repo-url`,
                            children: `Add`,
                          }),
                          (0, Y.jsxs)(F, {
                            open: T,
                            onOpenChange: E,
                            children: [
                              (0, Y.jsx)(F.Trigger, {
                                asChild: !0,
                                children: (0, Y.jsx)(w, {
                                  type: `button`,
                                  variant: `secondary`,
                                  size: `md`,
                                  disabled: n,
                                  className: `rounded-l-none border-l border-l-border-base px-2`,
                                  "data-tracking-id": `import-dropdown`,
                                  children: T
                                    ? (0, Y.jsx)(p, { className: `size-4` })
                                    : (0, Y.jsx)(f, { className: `size-4` }),
                                }),
                              }),
                              (0, Y.jsxs)(F.Content, {
                                align: `end`,
                                children: [
                                  (0, Y.jsx)(F.Item, {
                                    onClick: j,
                                    "data-tracking-id": `import-from-search`,
                                    children: (0, Y.jsx)(`span`, { children: `Import from search` }),
                                  }),
                                  (0, Y.jsx)(F.Item, {
                                    onClick: P,
                                    "data-tracking-id": `import-from-csv`,
                                    children: (0, Y.jsx)(`span`, { children: `Import from CSV` }),
                                  }),
                                ],
                              }),
                            ],
                          }),
                        ],
                      }),
                    ],
                  }),
                  l && (0, Y.jsx)(M, { className: `text-sm text-content-destructive`, children: l }),
                ],
              });
          }
        })(),
        e.length > 0 &&
          (0, Y.jsxs)(`div`, {
            className: `overflow-hidden rounded-lg border border-border-base`,
            children: [
              (0, Y.jsxs)(`div`, {
                className: `flex flex-row items-center justify-between border-b border-border-base bg-surface-base px-3 py-1`,
                children: [
                  (0, Y.jsxs)(M, {
                    className: `text-sm text-content-secondary`,
                    children: [e.length, ` / `, 100, ` repositories`],
                  }),
                  (0, Y.jsx)(w, {
                    type: `button`,
                    variant: `ghost`,
                    size: `xs`,
                    onClick: o,
                    disabled: n,
                    "data-tracking-id": `clear-all-repo-urls`,
                    children: `Clear`,
                  }),
                ],
              }),
              (0, Y.jsx)(`div`, {
                className: `flex max-h-48 flex-col overflow-y-auto`,
                children: e.map((t, r) => {
                  let o = t.split(`/`).slice(-2).join(`/`);
                  return (0, Y.jsxs)(
                    `div`,
                    {
                      className: `flex flex-row items-center justify-between px-3 py-2 ${r < e.length - 1 ? `border-b border-border-subtle` : ``}`,
                      children: [
                        (0, Y.jsxs)(`div`, {
                          className: `flex min-w-0 flex-1 flex-col`,
                          children: [
                            (0, Y.jsx)(M, { className: `truncate text-base font-medium`, children: o }),
                            (0, Y.jsx)(M, { className: `truncate text-sm text-content-secondary`, children: t }),
                          ],
                        }),
                        (0, Y.jsx)(w, {
                          type: `button`,
                          variant: `ghost`,
                          size: `xs`,
                          disabled: n,
                          onClick: () => i(t),
                          LeadingIcon: a,
                          className: `shrink-0`,
                          "aria-label": `Remove repository`,
                          "data-tracking-id": `remove-repo-url`,
                        }),
                      ],
                    },
                    t,
                  );
                }),
              }),
            ],
          }),
      ],
    });
  },
  we = (0, J.memo)(
    ({
      repoSearchString: e,
      runnerId: t,
      scmHost: n,
      onAddFilter: r,
      onClearFilter: i,
      onScmHostChange: a,
      onSearchComplete: o,
    }) => {
      let { data: s, isLoading: c, error: l, refetch: u } = R(t),
        d,
        f;
      if (s && s.length > 0) {
        let e = s.find((e) => e.host === n);
        e ? ((d = e.host), (f = e.scmId)) : ((d = s[0].host), (f = s[0].scmId));
      } else ((d = ``), (f = ``));
      let {
          data: p,
          isLoading: m,
          error: h,
          refetch: g,
          fetchNextPage: _,
          hasNextPage: v,
          isFetchingNextPage: y,
        } = z({ runnerId: t, query: e, scmHost: d, enabled: d !== `` && e !== ``, searchMode: x.NATIVE }),
        b = (0, J.useMemo)(() => p?.pages.flatMap((e) => e.repositories) ?? [], [p]),
        S = p?.pages[0]?.totalCount ?? -1;
      return (
        (0, J.useEffect)(() => {
          s && s.length > 0 && !n && a(s[0].host);
        }, [s, a, n]),
        (0, J.useEffect)(() => {
          o && b && b.length > 0 && o(b.map((e) => ({ url: e.url })));
        }, [b, o]),
        c
          ? (0, Y.jsx)(M, {
              className: `animate-pulse text-base text-content-secondary`,
              children: `Finding suitable repository provider…`,
            })
          : l
            ? (0, Y.jsxs)(`div`, {
                className: `flex flex-row items-baseline gap-2`,
                children: [
                  (0, Y.jsx)(H, { error: l }),
                  (0, Y.jsx)(w, {
                    type: `button`,
                    variant: `outline`,
                    size: `sm`,
                    onClick: () => {
                      u();
                    },
                    "data-tracking-id": `retry`,
                    children: `Retry`,
                  }),
                ],
              })
            : m
              ? (0, Y.jsx)(M, {
                  className: `animate-pulse text-base text-content-secondary`,
                  children: `Searching repositories…`,
                })
              : b.length > 0
                ? (0, Y.jsx)(Ee, {
                    searchString: e,
                    repositories: b,
                    totalCount: S,
                    onClear: i,
                    hasNextPage: v,
                    isFetchingNextPage: y,
                    onLoadMore: () => void _(),
                  })
                : s && s.length === 0
                  ? (0, Y.jsx)(M, {
                      children: `The selected runner does not support repository trigger. Please select a different runner.`,
                    })
                  : (0, Y.jsx)(Te, {
                      initialSearchString: e,
                      loading: m,
                      onAddFilter: r,
                      error: h,
                      onRetry: g,
                      scmId: f,
                    })
      );
    },
  );
we.displayName = `RepoFilteringContent`;
var Te = (0, J.memo)(({ initialSearchString: e, loading: t, onAddFilter: n, error: r, onRetry: i, scmId: a }) => {
  let [o, s] = (0, J.useState)(e),
    [c, l] = (0, J.useState)(!1),
    u = !!r && !c,
    d = () => {
      let t = o.trim();
      t && (l(!1), r && t === e && i ? i() : n(t));
    },
    f = (e) => {
      e.key === `Enter` && (e.preventDefault(), d());
    },
    p = (e) => {
      (s(e.target.value), c || l(!0));
    },
    m = a ? X(a) : `repository`,
    g =
      m === `repository`
        ? `Describe what repositories to include or paste a filter`
        : `Describe what repositories to include or paste a ${m} filter`,
    _ = o.trim().length > 0;
  return (0, Y.jsxs)(`div`, {
    className: `flex w-full flex-col gap-2`,
    children: [
      (0, Y.jsxs)(`div`, {
        className: `flex w-full flex-row items-center gap-2`,
        children: [
          (0, Y.jsx)(A, {
            value: o,
            type: `text`,
            placeholder: g,
            className: `h-9 max-w-none flex-1 bg-transparent text-content-primary focus:outline-none focus:ring-0`,
            onKeyDown: f,
            onChange: p,
          }),
          (0, Y.jsx)(w, {
            type: `button`,
            variant: `primary`,
            size: `md`,
            className: `aspect-square p-0`,
            loading: t,
            disabled: !_,
            LeadingIcon: k(h),
            onClick: d,
            "aria-label": `Add repository search filter`,
            "data-tracking-id": `submitsearchstring`,
            children: (0, Y.jsx)(`span`, { className: `sr-only`, children: `Add repository search filter` }),
          }),
        ],
      }),
      u && r && (0, Y.jsx)(H, { error: r }),
    ],
  });
});
Te.displayName = `RepoFilterInput`;
var Ee = (0, J.memo)(
  ({
    searchString: e,
    repositories: t,
    totalCount: n,
    onClear: r,
    hasNextPage: i,
    isFetchingNextPage: a,
    onLoadMore: o,
  }) => {
    let s = (0, J.useMemo)(
      () =>
        n > 0
          ? `${t.length} of ${n} matching repositories`
          : i
            ? `${t.length}+ matching repositories`
            : `${t.length} matching repositories`,
      [t.length, n, i],
    );
    return (0, Y.jsxs)(`div`, {
      className: `flex flex-col gap-3`,
      children: [
        (0, Y.jsxs)(`div`, {
          className: `flex flex-row items-center gap-2`,
          children: [
            (0, Y.jsx)(j, { variant: `brand`, size: `md`, children: e }),
            (0, Y.jsx)(w, {
              type: `button`,
              variant: `ghost`,
              size: `xs`,
              onClick: r,
              "data-tracking-id": `code-context-repo-search-clear`,
              children: `Clear`,
            }),
          ],
        }),
        (0, Y.jsxs)(`div`, {
          className: `flex flex-col gap-2`,
          children: [
            (0, Y.jsx)(M, { className: `text-sm text-content-secondary`, children: s }),
            (0, Y.jsxs)(`div`, {
              className: `flex max-h-48 flex-col gap-1 overflow-y-auto`,
              children: [
                t.map((e) =>
                  (0, Y.jsx)(
                    `div`,
                    {
                      className: `flex flex-row items-center gap-2 rounded bg-surface-secondary px-2 py-1`,
                      children: (0, Y.jsx)(M, { className: `flex-1 truncate text-sm`, children: e.url }),
                    },
                    e.url,
                  ),
                ),
                i &&
                  (0, Y.jsx)(w, {
                    type: `button`,
                    variant: `ghost`,
                    size: `sm`,
                    onClick: o,
                    disabled: a,
                    className: `mt-2`,
                    "data-tracking-id": `code-context-repo-search-load-more`,
                    children: a ? `Loading...` : `Load more`,
                  }),
              ],
            }),
          ],
        }),
      ],
    });
  },
);
Ee.displayName = `RepoFilterResult`;
var De = ({ selectedProjectIds: e, onSelectionChange: t, disabled: n = !1 }) => {
    let [r, i] = (0, J.useState)(``),
      [a] = u(r, 250, { trailing: !0 }),
      {
        data: o,
        hasNextPage: s,
        fetchNextPage: c,
        isFetchingNextPage: l,
        isPending: d,
        isFetching: f,
      } = V({ search: a }),
      p = (0, J.useMemo)(() => (o ? o.pages.flatMap((e) => e.projects) : []), [o]),
      m = (0, J.useMemo)(() => new Set(e), [e]),
      h = (0, J.useCallback)(() => {
        s && !l && c();
      }, [s, l, c]);
    return (0, Y.jsxs)(U, {
      multiple: !0,
      value: m,
      onValueChange: t,
      disabled: n || (p.length === 0 && !d),
      loading: d,
      children: [
        (0, Y.jsx)(U.MultiValue, { children: () => (0, Y.jsx)(U.ValueLabel, { children: `Add projects` }) }),
        (0, Y.jsxs)(U.Popover, {
          className: `w-96 max-w-[calc(100vw-1rem)]`,
          sameWidth: !1,
          children: [
            (0, Y.jsx)(U.SearchBox, { onValueChanged: i, loading: f || l }),
            (0, Y.jsx)(U.List, {
              onScrollEnd: h,
              scrollEndThreshold: 1e3,
              items: p,
              searchKeys: [],
              disableFiltering: !0,
              noMatchesComponent: (0, Y.jsx)(U.Empty, { children: `No projects found` }),
              children: (e) =>
                (0, Y.jsx)(
                  U.ListItem,
                  { value: e.id, children: (0, Y.jsx)(U.ListItemTitle, { children: e.metadata?.name || e.id }) },
                  e.id,
                ),
            }),
            (0, Y.jsx)(U.Footer, { children: (0, Y.jsx)(U.SelectAll, {}) }),
          ],
        }),
      ],
    });
  },
  Oe = k(l),
  ke = ({ context: e, onChange: t, disabled: n = !1, showRepoListOption: r = !1 }) => {
    let { environmentClassEntries: i, isLoading: a } = L({ enabled: !0 }),
      o = e?.type === q.RepositoriesList,
      c = r || o,
      { data: l, isPending: u, error: d } = V({ enabled: e?.type === q.Projects }),
      f = (0, J.useMemo)(() => (u || d ? !1 : l ? l.pages.every((e) => e.projects.length === 0) : !0), [u, d, l]),
      { data: p } = R(e?.type === q.RepositoriesSearch ? e.runnerId : void 0);
    ((0, J.useEffect)(() => {
      if (e?.type === q.RepositoriesSearch && e.environmentClassId && !e.runnerId && i.length > 0) {
        let n = i.find((t) => t.clazz.id === e.environmentClassId);
        n && t({ ...e, runnerId: n.runner.runnerId });
      }
    }, [e, i, t]),
      (0, J.useEffect)(() => {
        e?.type === q.RepositoriesSearch && p && p.length > 0 && !e.scmHost && t({ ...e, scmHost: p[0].host });
      }, [e, p, t]));
    let m = (0, J.useMemo)(
        () => ({
          [q.Projects]: {
            name: `Projects`,
            description: `Run steps across your IOI projects`,
            enabled: !0,
            recommended: !0,
          },
          [q.RepositoriesSearch]: {
            name: `Repositories`,
            description: `Target code repositories by filter or search`,
            enabled: !0,
            recommended: !1,
          },
          [q.RepositoriesList]: {
            name: `Repositories - List`,
            description: `Target code repositories by explicit list`,
            enabled: c,
            recommended: !1,
          },
        }),
        [c],
      ),
      h = (e) => {
        let n;
        switch (e) {
          case q.Projects:
            n = { type: q.Projects, projectIds: [] };
            break;
          case q.RepositoriesSearch: {
            let e = i[0];
            n = {
              type: q.RepositoriesSearch,
              repoSearchString: ``,
              scmHost: ``,
              runnerId: ``,
              environmentClassId: e?.clazz.id ?? ``,
            };
            break;
          }
          case q.RepositoriesList: {
            let e = i[0];
            n = { type: q.RepositoriesList, repoUrls: [], environmentClassId: e?.clazz.id ?? `` };
            break;
          }
          default:
            n = { type: q.Projects, projectIds: [] };
            break;
        }
        t(n);
      },
      g = (0, J.useCallback)(
        (n) => {
          e?.type === q.Projects && t({ ...e, projectIds: n });
        },
        [e, t],
      ),
      _ = (0, J.useCallback)(
        (n) => {
          e?.type === q.RepositoriesSearch
            ? (e.runnerId !== n.runner.runnerId || e.environmentClassId !== n.clazz.id) &&
              t({ ...e, runnerId: n.runner.runnerId, environmentClassId: n.clazz.id })
            : e?.type === q.RepositoriesList &&
              e.environmentClassId !== n.clazz.id &&
              t({ ...e, environmentClassId: n.clazz.id });
        },
        [e, t],
      ),
      v = (0, J.useCallback)(
        (n) => {
          e?.type === q.Projects && t({ ...e, projectIds: e?.projectIds?.filter((e) => e !== n) || [] });
        },
        [e, t],
      ),
      y = (0, J.useCallback)(() => {
        e?.type === q.Projects && t({ ...e, projectIds: [] });
      }, [e, t]),
      b = (0, J.useCallback)(
        (e) => {
          g([...e]);
        },
        [g],
      ),
      x = (0, J.useCallback)(
        (t) => {
          e?.type === q.Projects && !e.projectIds.includes(t) && g([...e.projectIds, t]);
        },
        [e, g],
      ),
      S = (0, J.useCallback)(
        (n) => {
          e?.type === q.RepositoriesSearch && t({ ...e, repoSearchString: n });
        },
        [e, t],
      ),
      C = (0, J.useCallback)(() => {
        e?.type === q.RepositoriesSearch && t({ ...e, repoSearchString: `` });
      }, [e, t]),
      w = (0, J.useCallback)(
        (n) => {
          e?.type === q.RepositoriesSearch && t({ ...e, scmHost: n });
        },
        [e, t],
      ),
      T = (0, J.useCallback)(
        (n) => {
          if (e?.type === q.RepositoriesList) {
            let r = n.map($).filter(Boolean),
              i = ve([...e.repoUrls, ...r]).slice(0, 100);
            t({ ...e, repoUrls: i });
          }
        },
        [e, t],
      ),
      E = (0, J.useCallback)(
        (n) => {
          e?.type === q.RepositoriesList && t({ ...e, repoUrls: e.repoUrls.filter((e) => e !== n) });
        },
        [e, t],
      ),
      D = (0, J.useCallback)(() => {
        e?.type === q.RepositoriesList && t({ ...e, repoUrls: [] });
      }, [e, t]),
      O,
      k = null;
    switch (e?.type) {
      case q.Projects:
        k = (0, Y.jsx)(De, { selectedProjectIds: e.projectIds, onSelectionChange: b, disabled: n });
        break;
      case q.RepositoriesSearch: {
        let t = i.find((t) => t.clazz.id === e.environmentClassId);
        O = (0, Y.jsxs)(`div`, {
          className: `flex w-full flex-col gap-4`,
          children: [
            (0, Y.jsx)(W, {
              label: `Environment class`,
              hint: `Select the environment class you want to use for the automation`,
              children: (0, Y.jsx)(G, {
                environmentClassEntries: i,
                value: t,
                onChange: (e) => e && _(e),
                loading: a,
                disabled: n,
                name: `automation-environment-class`,
              }),
            }),
            p &&
              p.length > 1 &&
              (0, Y.jsx)(W, {
                label: `Repository provider`,
                hint: (0, Y.jsxs)(`span`, {
                  children: [
                    (0, Y.jsx)(`span`, { className: `font-bold`, children: t?.runner.name }),
                    ` has multiple repository providers configured, you need to select one of them`,
                  ],
                }),
                children: (0, Y.jsx)(de, { scmIntegrations: p, selectedHost: e.scmHost, onHostChange: w, disabled: n }),
              }),
          ],
        });
        break;
      }
      case q.RepositoriesList:
        O = (0, Y.jsx)(`div`, {
          className: `flex w-full flex-col gap-4`,
          children: (0, Y.jsx)(W, {
            label: `Environment class`,
            hint: `Select the environment class you want to use for the automation`,
            children: (0, Y.jsx)(G, {
              environmentClassEntries: i,
              value: i.find((t) => t.clazz.id === e.environmentClassId),
              onChange: (e) => e && _(e),
              loading: a,
              disabled: n,
              name: `automation-environment-class`,
            }),
          }),
        });
        break;
    }
    let A;
    switch (e?.type) {
      case q.Projects:
        A = d
          ? (0, Y.jsx)(H, { error: d })
          : (0, Y.jsx)(Ae, {
              selectedProjectIds: e.projectIds,
              disabled: n,
              onRemoveProject: v,
              onClearAll: y,
              onAddProject: x,
              orgHasNoProjects: f,
            });
        break;
      case q.RepositoriesSearch:
        A = e?.runnerId
          ? (0, Y.jsx)(Z, {
              disabled: n,
              runnerId: e?.runnerId,
              repoSearchString: e?.repoSearchString,
              scmHost: e?.scmHost,
              onAddFilter: S,
              onClearFilter: C,
            })
          : null;
        break;
      case q.RepositoriesList:
        A = (0, Y.jsx)(be, {
          context: e,
          runnerId: i.find((t) => t.clazz.id === e.environmentClassId)?.clazz.runnerId ?? ``,
          disabled: n,
          onAddUrls: T,
          onRemoveUrl: E,
          onClearAll: D,
        });
        break;
      default:
        A = null;
        break;
    }
    return (0, Y.jsxs)(`div`, {
      className: `flex flex-col gap-3`,
      children: [
        (0, Y.jsxs)(`div`, {
          className: `flex flex-row flex-wrap items-end justify-between gap-4`,
          children: [
            (0, Y.jsxs)(`div`, {
              className: `flex flex-col gap-2`,
              children: [
                (0, Y.jsx)(M, { className: `text-base font-medium text-content-primary`, children: `Runs on` }),
                (0, Y.jsx)(s, {
                  value: e?.type,
                  onValueChange: (e) => h(e),
                  disabled: n,
                  className: `flex flex-row items-center gap-4`,
                  children: Object.entries(m).map(([e, t]) =>
                    t.enabled
                      ? (0, Y.jsxs)(
                          `label`,
                          {
                            className: `flex cursor-pointer items-center gap-2`,
                            children: [
                              (0, Y.jsx)(s.Item, { value: e, disabled: !t.enabled }),
                              (0, Y.jsx)(M, {
                                className: `text-base font-medium text-content-primary`,
                                children: t.name,
                              }),
                              t.recommended && (0, Y.jsx)(j, { variant: `brand`, size: `sm`, children: `Recommended` }),
                            ],
                          },
                          e,
                        )
                      : null,
                  ),
                }),
              ],
            }),
            k,
          ],
        }),
        O && (0, Y.jsx)(`div`, { className: `flex flex-row items-center`, children: O }),
        A,
      ],
    });
  },
  Ae = ({ selectedProjectIds: e, onRemoveProject: t, onClearAll: n, onAddProject: r, orgHasNoProjects: i }) => {
    let a = (0, J.useId)();
    return i
      ? (0, Y.jsx)(Ne, { onProjectCreated: r })
      : e.length === 0
        ? (0, Y.jsx)(Me, {})
        : (0, Y.jsxs)(`div`, {
            className: `flex flex-col rounded-lg border border-border-base`,
            children: [
              (0, Y.jsxs)(`div`, {
                className: `flex flex-row items-center justify-between rounded-t-lg border-b border-border-base bg-surface-base py-0.5 pl-4 pr-2`,
                children: [
                  (0, Y.jsx)(M, {
                    className: `text-sm font-medium text-content-strong`,
                    id: a,
                    children: D(e.length, !1, `project`),
                  }),
                  (0, Y.jsx)(w, {
                    variant: `ghost`,
                    size: `xs`,
                    onClick: n,
                    "data-tracking-id": `clear-all-projects-automation-project-trigger-automation-edit-code-context`,
                    children: `Clear all`,
                  }),
                ],
              }),
              (0, Y.jsx)(ae, {
                children: (0, Y.jsx)(`ul`, {
                  className: `max-h-80 divide-y divide-border-subtle overflow-y-auto`,
                  "aria-labelledby": a,
                  children: e.map((e) => (0, Y.jsx)(je, { projectId: e, onRemove: t }, e)),
                }),
              }),
            ],
          });
  },
  je = ({ projectId: e, onRemove: t }) => {
    let { data: n, isPending: r } = ne(e),
      i = n?.metadata?.name || e;
    return (0, Y.jsxs)(`li`, {
      className: `flex flex-row items-center justify-between py-1 pl-4 pr-1`,
      children: [
        (0, Y.jsx)(P, {
          ready: !r,
          className: `h-5 w-40 rounded`,
          children: (0, Y.jsx)(M, { className: `text-base font-medium`, children: i }),
        }),
        (0, Y.jsx)(w, {
          variant: `ghost`,
          size: `sm`,
          LeadingIcon: Oe,
          "aria-label": `Remove '${i}' project`,
          onClick: () => t(e),
          "data-tracking-id": `remove-project-automation-project-trigger-automation-edit-code-context`,
        }),
      ],
    });
  },
  Me = () =>
    (0, Y.jsx)(`div`, {
      className: `flex min-h-[46px] w-full flex-row items-start gap-2 rounded-lg border border-border-subtle px-3 py-2 transition-colors ease-out`,
      children: (0, Y.jsx)(M, {
        className: `flex h-[30px] items-center text-base text-content-muted`,
        children: `Add projects to run the automation for each selected project.`,
      }),
    }),
  Ne = ({ onProjectCreated: e }) => {
    let [t, i] = (0, J.useState)(!1),
      { mayCreateProject: a } = n();
    return (0, Y.jsxs)(Y.Fragment, {
      children: [
        (0, Y.jsxs)(`div`, {
          className: `flex w-full flex-col items-center gap-4 rounded-lg border border-border-subtle px-6 py-8`,
          children: [
            (0, Y.jsx)(le, { className: `size-[40px] text-content-muted` }),
            (0, Y.jsxs)(`div`, {
              className: `flex flex-col items-center gap-1`,
              children: [
                (0, Y.jsx)(M, {
                  className: `text-md font-medium text-content-primary`,
                  children: `You currently have no projects`,
                }),
                (0, Y.jsx)(M, {
                  className: `text-center text-base text-content-secondary`,
                  children: `Automations work better with projects, to leverage the full power of automations we recommend creating a project to manage your repositories.`,
                }),
              ],
            }),
            a &&
              (0, Y.jsx)(w, {
                variant: `primary`,
                LeadingIcon: o,
                onClick: () => i(!0),
                "data-tracking-id": `create-project-automation-empty-state`,
                children: `Create project`,
              }),
          ],
        }),
        (0, Y.jsx)(r, { open: t, onClose: () => i(!1), navigateOnCreate: !1, onProjectCreated: e }),
      ],
    });
  },
  Pe = ({ open: e, onOpenChange: n, workflow: r }) => {
    let i = v(),
      { toast: a } = S(),
      o = t(),
      s = (0, J.useMemo)(() => se(r), [r]),
      [c, l] = (0, J.useState)(() => K(r));
    (0, J.useEffect)(() => {
      e && l(K(r));
    }, [e, r]);
    let u = (0, J.useMemo)(() => (c.type === q.Projects ? c.projectIds : []), [c]),
      { projects: d, isPending: f } = re(u, { enabled: u.length > 0 }),
      p = (0, J.useCallback)(async () => {
        try {
          let e = c;
          if (c.type === q.Projects && !f) {
            let t = new Set(d.map((e) => e.id));
            e = { ...c, projectIds: c.projectIds.filter((e) => t.has(e)) };
          }
          let t = ce(e),
            a = await o.mutateAsync({ workflowId: r.id, contextOverride: t });
          (n(!1), i(ee({ id: a.id })));
        } catch (e) {
          a({ title: `Failed to start automation`, description: b(e) });
        }
      }, [c, d, f, r.id, o, n, i, a]);
    return (0, Y.jsx)(T, {
      open: e,
      onOpenChange: (0, J.useCallback)(
        (e) => {
          o.isPending || n(e);
        },
        [n, o.isPending],
      ),
      children: (0, Y.jsxs)(T.Content, {
        "data-testid": `run-automation-dialog`,
        "data-track-location": y.RunAutomationModal,
        className: `max-w-2xl overflow-visible`,
        children: [
          (0, Y.jsx)(T.Header, { children: (0, Y.jsxs)(T.Title, { children: [`Manually run '`, I(r), `'`] }) }),
          (0, Y.jsx)(T.Body, {
            children: (0, Y.jsx)(ke, { context: c, onChange: l, disabled: o.isPending, showRepoListOption: s }),
          }),
          (0, Y.jsxs)(T.Footer, {
            className: `justify-end`,
            children: [
              (0, Y.jsx)(T.Close, {
                asChild: !0,
                children: (0, Y.jsx)(w, {
                  variant: `outline`,
                  disabled: o.isPending,
                  "data-testid": `run-automation-dialog-cancel`,
                  children: `Cancel`,
                }),
              }),
              (0, Y.jsx)(w, {
                variant: `primary`,
                onClick: p,
                disabled: o.isPending,
                loading: o.isPending,
                "data-testid": `run-automation-dialog-run`,
                "data-tracking-id": `run-automation-dialog-run`,
                autoFocus: !0,
                children: `Run`,
              }),
            ],
          }),
        ],
      }),
    });
  };
export { ke as n, Pe as t };

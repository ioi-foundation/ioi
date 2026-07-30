import { a as e } from "./rolldown-runtime-CGYlQKCx.js";
import {
  Fr as t,
  Gr as n,
  Hr as r,
  Ir as i,
  L as a,
  Lr as o,
  Rr as s,
  Ur as c,
  ei as l,
  pr as u,
} from "./SegmentProvider-CXCNBY9U.js";
import { n as d } from "./@mux-DLaEVubF.js";
import { Pu as f, Rg as p, v_ as m, xg as h } from "./vendor-DAwbZtf0.js";
import { Dt as g, Lr as _, Ls as v, hn as y, tr as b } from "./use-boot-in-app-chat-t-J_VjKS.js";
import { g as x } from "./workflow_pb-DOR6D5WK.js";
import { n as S } from "./toast-axaLeIzZ.js";
import { a as C, t as w } from "./button-6YP03Qf2.js";
import { t as T } from "./cn-DppMFCU8.js";
import { t as E } from "./dialog-BtjFqa-w.js";
import { t as D } from "./banner-CFcSGYsz.js";
import { t as O } from "./strings-C6LrS0GJ.js";
import { t as k } from "./timestamp-CEKPQVte.js";
import { d as A } from "./time-DxjbKG-a.js";
import { n as j } from "./utils-C9bSuXia.js";
import { t as M } from "./tooltip-6hqVQbwq.js";
import { t as N } from "./Pill-99RRpZf2.js";
import "./pill-AA_qJIlm.js";
import { t as P } from "./text-fFCFeCas.js";
import { n as F } from "./skeleton-Cm867Q_k.js";
import { n as ee, r as I, t as te } from "./dropdown-menu-D3UmjGpQ.js";
import {
  F as ne,
  M as L,
  S as re,
  T as ie,
  _ as ae,
  b as R,
  g as z,
  h as B,
  v as oe,
  x as se,
} from "./automations-CN21BoUy.js";
import { t as V } from "./avatar-CjN22mGB.js";
import { t as ce } from "./use-is-mobile-viewport-Chw6u8QP.js";
import { t as le } from "./error-message-Az-KJctk.js";
import { a as ue, n as de } from "./service-accounts-DLF2ke0D.js";
import { t as fe } from "./ResourceGroupAccess-AaZC0rTa.js";
import { t as pe } from "./use-share-resource-CE0EPrcD.js";
import { t as me } from "./SubjectDisplay-GaN_Sngp.js";
import { t as he } from "./RunAutomationDialog-GQ35_Wcn.js";
import { t as ge } from "./AutomationExecutionStatusIcon-B3fEPOH1.js";
var H = m(),
  U = ({ trigger: e, size: t = 32, className: n }) => {
    let r = R(e),
      i = se(e);
    return (0, H.jsx)(M, {
      content: i,
      usePortal: !0,
      children: (0, H.jsx)(`div`, {
        className: T(
          `flex shrink-0 items-center justify-center rounded-full border border-border-subtle bg-surface-base text-content-secondary`,
          n,
        ),
        style: { width: t, height: t },
        "aria-label": i,
        children: (0, H.jsx)(r, { size: t * 0.5 }),
      }),
    });
  },
  W = ({ actions: e }) => {
    let {
      isDeleting: t,
      isDisabled: n,
      isTogglingDisabled: r,
      canDeleteAutomation: i,
      canEditAutomation: a,
      canShareAutomation: o,
      handleShare: s,
      handleEdit: c,
      handleToggleDisabled: l,
      handleDuplicate: u,
      handleCopyId: d,
      handleDelete: f,
      handleForceDelete: p,
    } = e;
    return (0, H.jsxs)(H.Fragment, {
      children: [
        (0, H.jsx)(I.Item, {
          onClick: d,
          "data-testid": `workflow-actions-dropdown-copy-id`,
          "data-tracking-id": `copy-id-workflow-actions-dropdown`,
          children: `Copy Automation ID`,
        }),
        (0, H.jsx)(I.Item, {
          onClick: u,
          "data-testid": `workflow-actions-dropdown-duplicate`,
          "data-tracking-id": `duplicate-workflow-actions-dropdown`,
          children: `Duplicate`,
        }),
        o &&
          (0, H.jsx)(I.Item, {
            onClick: s,
            "data-testid": `workflow-actions-dropdown-share`,
            "data-tracking-id": `share-workflow-actions-dropdown`,
            children: `Share`,
          }),
        a &&
          (0, H.jsx)(I.Item, {
            onClick: c,
            disabled: t,
            "data-testid": `workflow-actions-dropdown-edit`,
            "data-tracking-id": `edit-workflow-actions-dropdown`,
            children: `Edit`,
          }),
        a &&
          (0, H.jsx)(I.Item, {
            onClick: l,
            disabled: t || r,
            "data-testid": `workflow-actions-dropdown-toggle-disabled`,
            "data-tracking-id": `toggle-disabled-workflow-actions-dropdown`,
            children: n ? `Enable` : `Disable`,
          }),
        i && (0, H.jsx)(I.Separator, {}),
        i &&
          (t
            ? (0, H.jsx)(I.Item, {
                variant: `destructive`,
                onClick: p,
                "data-testid": `workflow-actions-dropdown-force-delete`,
                "data-tracking-id": `force-delete-workflow-actions-dropdown`,
                children: `Force Delete`,
              })
            : (0, H.jsx)(I.Item, {
                variant: `destructive`,
                onClick: f,
                "data-testid": `workflow-actions-dropdown-delete`,
                "data-tracking-id": `delete-workflow-actions-dropdown`,
                children: `Delete`,
              })),
      ],
    });
  },
  G = e(d(), 1);
function K(e, n) {
  let { toast: r } = S(),
    a = h(),
    { openShareDialog: c } = pe(),
    [u, d] = (0, G.useState)(!1),
    [f, p] = (0, G.useState)(!1),
    [m, g] = (0, G.useState)(!1),
    v = e ? B(e) : !1,
    y = e ? z(e) : !1,
    { canDeleteAutomation: x } = t(e?.id),
    { canRunAutomation: C } = o(e?.id),
    { canEditAutomation: w } = i(e?.id),
    { canShareAutomation: T } = s(e?.id),
    E = l(),
    D = (0, G.useCallback)(() => {
      g(!0);
    }, []),
    O = (0, G.useCallback)(() => {
      if (!e) return;
      let t = !z(e);
      E.mutate(
        { workflowId: e.id, disabled: t },
        {
          onError: (e) => {
            r({ title: `Failed to ${t ? `disable` : `enable`} automation`, description: b(e) });
          },
        },
      );
    }, [e, E, r]),
    k = (0, G.useCallback)(() => {
      e && c({ resourceType: _.WORKFLOW, resourceId: e.id, resourceName: L(e) ?? e.id });
    }, [c, e]),
    A = (0, G.useCallback)(() => {
      e && a(ie({ id: e.id }));
    }, [a, e]),
    j = (0, G.useCallback)(async () => {
      if (e)
        try {
          (await navigator.clipboard.writeText(e.id),
            r({ title: `Automation ID copied to clipboard`, description: e.id }));
        } catch (e) {
          r({ title: `Failed to copy automation ID`, description: b(e) });
        }
    }, [r, e]),
    M = (0, G.useCallback)(() => {
      e && a(oe({ duplicateId: e.id }));
    }, [a, e]),
    N = (0, G.useCallback)(() => d(!0), []),
    P = (0, G.useCallback)(() => p(!0), []);
  if (e)
    return {
      isDeleting: v,
      isDisabled: y,
      isTogglingDisabled: E.isPending,
      canDeleteAutomation: x,
      canRunAutomation: n.showRunAction && C,
      canEditAutomation: w,
      canShareAutomation: T,
      showDeleteModal: u,
      setShowDeleteModal: d,
      showForceDeleteModal: f,
      setShowForceDeleteModal: p,
      showRunDialog: m,
      setShowRunDialog: g,
      handleRunWorkflow: D,
      handleToggleDisabled: O,
      handleShare: k,
      handleEdit: A,
      handleDuplicate: M,
      handleCopyId: j,
      handleDelete: N,
      handleForceDelete: P,
    };
}
var q = ({ workflow: e, showRunAction: t, buttonSize: n, buttonVariant: r = `outline`, open: i, onOpenChange: a }) => {
    let o = K(e, { showRunAction: t });
    return o
      ? (0, H.jsxs)(`div`, {
          className: `flex items-center`,
          onClick: (e) => {
            e.stopPropagation();
          },
          "data-tracking-id-none": !0,
          children: [
            (0, H.jsx)(te, {
              triggerTestId: `workflow-actions-dropdown-trigger`,
              open: i,
              triggerButton: (0, H.jsx)(w, { variant: r, "aria-label": `More actions`, LeadingIcon: ee, size: n }),
              onOpenChange: a,
              contentClassName: `w-48`,
              children: (0, H.jsx)(W, { actions: o }),
            }),
            (0, H.jsx)($, { workflow: e, actions: o }),
          ],
        })
      : null;
  },
  J = ({ workflowId: e, maxVisible: t, className: n }) =>
    (0, H.jsx)(fe, {
      resourceType: _.WORKFLOW,
      resourceId: e,
      maxVisible: t,
      className: n,
      trackingPrefix: `automation`,
    }),
  _e = j(f),
  Y = ({ member: e, size: t = 16 }) =>
    (0, H.jsxs)(V, {
      size: t,
      className: `border border-border-base`,
      children: [
        e.avatarUrl && (0, H.jsx)(V.Image, { src: e.avatarUrl, alt: `${e.fullName}'s avatar` }),
        (0, H.jsx)(V.Fallback, { children: (0, H.jsx)(V.Initials, { name: e.fullName, size: t }) }),
      ],
    }),
  ve = ({ workflow: e, editable: t, onEdit: n }) => {
    let r = e.spec?.triggers?.[0],
      i = B(e);
    return (0, H.jsxs)(`div`, {
      className: `flex flex-wrap items-center gap-1.5 text-sm`,
      children: [
        (0, H.jsx)(Ce, { workflow: e }),
        (0, H.jsx)(ye, { trigger: r }),
        (0, H.jsx)(be, { trigger: r }),
        (0, H.jsx)(Z, { limits: e.spec?.action?.limits }),
        t
          ? (0, H.jsx)(w, {
              size: `xs`,
              variant: `ghost`,
              className: `-translate-y-[1.5px]`,
              LeadingIcon: _e,
              onClick: n,
              disabled: i,
              "data-tracking-id": `edit`,
              children: (0, H.jsx)(`span`, { className: `sr-only`, children: `Edit` }),
            })
          : null,
      ],
    });
  },
  X = () => (0, H.jsx)(`span`, { className: `text-content-inactive`, children: `•` }),
  ye = ({ trigger: e }) => {
    if (!e?.trigger) return (0, H.jsx)(P, { children: `No configured trigger.` });
    switch (e.trigger.case) {
      case `manual`:
        return (0, H.jsx)(P, { className: `text-sm font-medium`, children: `Manual` });
      case `time`:
        return (0, H.jsxs)(`div`, {
          className: `flex items-center gap-1.5`,
          children: [
            (0, H.jsx)(P, { className: `text-sm text-content-muted`, children: `Scheduled:` }),
            (0, H.jsx)(ne, { value: e.trigger.value.cronExpression, readOnly: !0, showTimezone: !0 }),
          ],
        });
      case `pullRequest`: {
        let t = e.trigger.value.events.length;
        return (0, H.jsxs)(P, {
          className: `text-content-muted`,
          children: [
            `Pull Request:`,
            ` `,
            (0, H.jsxs)(`span`, { className: `font-medium text-content-primary`, children: [t, ` `, O(t, `event`)] }),
          ],
        });
      }
      default:
        return (0, H.jsx)(H.Fragment, { children: `Unknown` });
    }
  },
  be = ({ trigger: e }) => {
    if (!e?.context?.context) return null;
    switch (e.context.context.case) {
      case `repositories`: {
        if (e.context.context.value.repositorySelector.case !== `repositoryUrls`) return null;
        let t = e.context.context.value.repositorySelector.value.repoUrls.length;
        return (0, H.jsxs)(H.Fragment, {
          children: [
            (0, H.jsx)(X, {}),
            (0, H.jsxs)(P, { className: `text-content-muted`, children: [t, ` `, O(t, `repository`, `repositories`)] }),
          ],
        });
      }
      case `projects`: {
        let t = e.context.context.value.projectIds.length;
        return (0, H.jsxs)(H.Fragment, {
          children: [
            (0, H.jsx)(X, {}),
            (0, H.jsxs)(P, { className: `text-content-muted`, children: [t, ` `, O(t, `project`)] }),
          ],
        });
      }
      default:
        return null;
    }
  },
  xe = (e, t) => {
    let n = e.metadata?.creator;
    if (!(!n?.id || !t)) return t.find((e) => e.userId === n.id);
  },
  Se = (e, t, n) => {
    let r = e.metadata?.executor;
    if (!r) return null;
    if (r.principal === v.USER && t) {
      let e = t.find((e) => e.userId === r.id);
      if (e) return { name: e.fullName, avatar: (0, H.jsx)(Y, { member: e }) };
    } else if (r.principal === v.SERVICE_ACCOUNT && n) {
      let e = n.serviceAccounts.find((e) => e.id === r.id);
      if (e)
        return {
          name: e.name,
          avatar: (0, H.jsx)(ue, { className: `p-0.5`, id: e.id, size: 16, isIOIServiceAccount: de(e) }),
        };
    }
    return null;
  },
  Ce = ({ workflow: e }) => {
    let { data: t, isLoading: n, error: r } = u({ enabled: e.metadata?.executor?.principal === v.SERVICE_ACCOUNT }),
      {
        members: i,
        isLoading: o,
        isError: s,
      } = y(
        (0, G.useMemo)(() => {
          let t = [],
            n = e.metadata?.creator?.id;
          n && t.push(n);
          let r = a(e.metadata?.executor);
          return (r && t.push(r), t);
        }, [e.metadata?.creator, e.metadata?.executor]),
      ),
      c = o || n,
      l = r || (s ? Error(`Failed to fetch members`) : null);
    if (l)
      return (0, H.jsxs)(H.Fragment, {
        children: [
          (0, H.jsx)(F, { className: `w-48`, size: `sm`, ready: !c, children: (0, H.jsx)(we, { error: l }) }),
          (0, H.jsx)(X, {}),
        ],
      });
    if (o)
      return (0, H.jsxs)(H.Fragment, {
        children: [(0, H.jsx)(F, { className: `w-48`, size: `sm`, ready: !1, children: null }), (0, H.jsx)(X, {})],
      });
    let d = Array.from(i.values()),
      f = xe(e, d),
      p = Se(e, d, t),
      m = e.metadata?.creator,
      h = e.metadata?.executor,
      g = m?.id && h?.id && m.id === h.id,
      _ = null;
    return (
      g && f
        ? (_ = (0, H.jsxs)(P, {
            className: `flex items-center gap-1 text-content-muted`,
            children: [
              `Author / Runs as:`,
              (0, H.jsx)(`span`, { children: (0, H.jsx)(Y, { member: f }) }),
              (0, H.jsx)(`span`, { className: `font-medium text-content-primary`, children: f.fullName }),
            ],
          }))
        : (f || p) &&
          (_ = (0, H.jsxs)(P, {
            className: `flex items-center gap-1 text-content-muted`,
            children: [
              f &&
                (0, H.jsxs)(H.Fragment, {
                  children: [
                    `Author:`,
                    (0, H.jsx)(`span`, { children: (0, H.jsx)(Y, { member: f }) }),
                    (0, H.jsx)(`span`, { className: `font-medium text-content-primary`, children: f.fullName }),
                  ],
                }),
              f && p && (0, H.jsx)(X, {}),
              p &&
                (0, H.jsxs)(H.Fragment, {
                  children: [
                    `Runs as:`,
                    (0, H.jsx)(`span`, { children: p.avatar }),
                    (0, H.jsx)(`span`, { className: `font-medium text-content-primary`, children: p.name }),
                  ],
                }),
            ],
          })),
      _
        ? (0, H.jsxs)(H.Fragment, {
            children: [(0, H.jsx)(F, { className: `w-48`, size: `sm`, ready: !c, children: _ }), (0, H.jsx)(X, {})],
          })
        : null
    );
  },
  we = ({ error: e }) =>
    (0, H.jsxs)(`div`, {
      className: `flex flex-wrap items-center gap-x-1.5 gap-y-1`,
      children: [
        (0, H.jsxs)(P, {
          className: `flex select-none items-center text-content-destructive`,
          children: [`Executor info unavailable`, (0, H.jsx)(p, { className: `ml-1`, size: 16 })],
        }),
        (0, H.jsx)(le, { className: `text-sm text-content-destructive`, error: e }),
      ],
    }),
  Z = ({ limits: e }) => {
    if (!e) return null;
    let t = e.maxParallel,
      n = e.maxTotal;
    if (t === 0 && n === 0)
      return (0, H.jsxs)(H.Fragment, {
        children: [
          (0, H.jsx)(X, {}),
          (0, H.jsx)(P, { className: `text-content-muted`, children: `No concurrent or max action limits` }),
        ],
      });
    let r = t === 0 ? `No concurrent` : `${t} concurrent`,
      i = n === 0 ? `no action limit` : `max ${n} ${O(n, `action`)}`;
    return (0, H.jsxs)(H.Fragment, {
      children: [
        (0, H.jsx)(X, {}),
        (0, H.jsxs)(P, {
          className: `text-content-muted`,
          children: [
            (0, H.jsxs)(`span`, { className: `font-medium text-content-primary`, children: [r, ` `] }),
            `and`,
            (0, H.jsxs)(`span`, { className: `font-medium text-content-primary`, children: [` `, i] }),
          ],
        }),
      ],
    });
  },
  Te = ({ workflow: e, className: t, readonly: r = !1, variant: i = `standalone` }) => {
    let [a, o] = (0, G.useState)(!1),
      { isMobileViewport: s } = ce(),
      { data: l } = c({ enabled: !0, workflowId: e.id }),
      { data: u } = n(l ?? void 0),
      d = !!e.metadata?.description,
      f = B(e),
      p = u ? ae(u) : !1,
      m = !r,
      h = e.spec?.triggers?.[0],
      g = u?.metadata?.executor,
      _ = R(h),
      v =
        m &&
        (0, H.jsx)(q, {
          workflow: e,
          showRunAction: !0,
          buttonSize: `sm`,
          buttonVariant: i === `list-item` ? `ghost` : `outline`,
          open: a,
          onOpenChange: o,
        });
    return (0, H.jsxs)(`div`, {
      "data-active": a,
      className: T(
        `flex gap-3 p-4`,
        i === `standalone` && `rounded-xl border border-border-base`,
        i === `standalone` && !r && `data-[active=true]:shadow-sm`,
        i === `list-item` &&
          !r &&
          `hover:bg-surface-button-clear-accent data-[active=true]:bg-surface-button-clear-accent`,
        t,
      ),
      children: [
        !s && (0, H.jsx)(`div`, { children: (0, H.jsx)(U, { trigger: h, size: 40 }) }),
        (0, H.jsxs)(`div`, {
          className: `flex min-w-0 flex-1 flex-col gap-1`,
          children: [
            s &&
              (0, H.jsxs)(`div`, {
                className: `flex items-center justify-between`,
                children: [
                  (0, H.jsxs)(`span`, {
                    className: `inline-flex items-center gap-1 rounded-full bg-surface-muted px-1.5 py-0.5 text-xs text-content-strong`,
                    children: [(0, H.jsx)(_, { size: 16 }), re(h)],
                  }),
                  (0, H.jsxs)(`div`, {
                    className: `flex items-center gap-1`,
                    children: [(0, H.jsx)(J, { workflowId: e.id, maxVisible: 3 }), v],
                  }),
                ],
              }),
            (0, H.jsxs)(`div`, {
              children: [
                (0, H.jsxs)(`div`, {
                  className: `flex items-center gap-2`,
                  children: [
                    (0, H.jsx)(M, {
                      usePortal: !0,
                      side: `bottom`,
                      align: `start`,
                      content: (0, H.jsxs)(`div`, {
                        className: `flex max-w-xs flex-col gap-1`,
                        children: [
                          (0, H.jsx)(`span`, { className: `font-medium`, children: L(e) }),
                          d &&
                            (0, H.jsx)(`span`, {
                              className: `text-content-primary-inverted`,
                              children: e.metadata?.description,
                            }),
                        ],
                      }),
                      children: (0, H.jsx)(P, {
                        className: `text-base font-medium leading-none text-content-primary`,
                        children: L(e),
                      }),
                    }),
                    p && (0, H.jsx)(N, { size: `sm`, variant: `brand`, children: `Running` }),
                  ],
                }),
                i === `standalone` &&
                  (d
                    ? (0, H.jsx)(P, { className: `text-base text-content-strong`, children: e.metadata?.description })
                    : (0, H.jsx)(`div`, {
                        className: `mt-2`,
                        children: (0, H.jsx)(ve, { workflow: e, editable: !1 }),
                      })),
              ],
            }),
            (0, H.jsx)(`div`, {
              className: `flex flex-wrap items-center gap-1 text-base text-content-strong`,
              children: f
                ? (0, H.jsxs)(H.Fragment, {
                    children: [
                      (0, H.jsx)(C, { size: `sm`, className: `shrink-0 animate-spin` }),
                      (0, H.jsx)(`span`, { children: `Deleting` }),
                    ],
                  })
                : u
                  ? (0, H.jsxs)(H.Fragment, {
                      children: [
                        (0, H.jsx)(ge, { size: `sm`, execution: u }),
                        (0, H.jsxs)(`span`, {
                          children: [
                            p
                              ? (0, H.jsx)(`span`, { children: `Execution` })
                              : (0, H.jsx)(`span`, { children: `Last execution` }),
                            ` `,
                            Ee(u),
                          ],
                        }),
                        !s && (0, H.jsx)(`span`, { children: `by` }),
                        (0, H.jsx)(`span`, {
                          className: `font-medium`,
                          children: (0, H.jsx)(me, { subject: g, avatarSize: 16 }),
                        }),
                      ],
                    })
                  : (0, H.jsx)(`span`, { className: `text-content-inactive`, children: `No executions yet` }),
            }),
          ],
        }),
        !s &&
          (0, H.jsxs)(`div`, {
            className: `flex shrink-0 items-center gap-1 self-start`,
            children: [(0, H.jsx)(J, { workflowId: e.id, maxVisible: 3 }), v],
          }),
      ],
    });
  };
function Ee(e) {
  let t = e.status?.phase,
    n = e.metadata?.startedAt,
    r = e.metadata?.finishedAt;
  switch (t) {
    case x.COMPLETED:
      return r ? `finished ${A(k(r))}` : `finished`;
    case x.RUNNING:
      return n ? `started ${A(k(n))}` : `started`;
    case x.PENDING:
      return `pending`;
    case x.STOPPED:
      return r ? `stopped ${A(k(r))}` : `stopped`;
    case x.STOPPING:
      return `stopping`;
    case x.DELETED:
      return `deleted`;
    case x.DELETING:
      return `deleting`;
    default:
      return ``;
  }
}
var Q = ({ workflow: e, open: t, onClose: n, forceDelete: i = !1 }) => {
    let { toast: a } = S(),
      o = h(),
      s = r(),
      c = (0, G.useRef)(null),
      l = (0, G.useCallback)(async () => {
        try {
          (await s.mutateAsync({ workflowId: e.id, force: i }),
            a({
              title: i ? `Automation force deleted` : `Automation deleted`,
              description: i
                ? `${L(e)} has been force deleted. Check your cloud account for any remaining resources.`
                : `${L(e)} has been deleted successfully.`,
            }),
            n(),
            o(`/automations`));
        } catch (e) {
          a({ title: `Failed to delete automation`, description: b(e) });
        }
      }, [s, e, a, n, o, i]);
    return (0, H.jsx)(E, {
      open: t,
      onOpenChange: n,
      children: (0, H.jsxs)(E.Content, {
        "data-testid": `delete-workflow-dialog`,
        "data-track-location": g.DeleteWorkflowDialog,
        onOpenAutoFocus: (e) => {
          (e.preventDefault(), c.current?.focus());
        },
        children: [
          (0, H.jsxs)(E.Header, {
            children: [
              (0, H.jsx)(E.Title, { children: i ? `Force Delete Automation` : `Delete Automation` }),
              (0, H.jsx)(E.Description, {
                children: i
                  ? `Force deleting will immediately remove the automation from the system without waiting for proper cleanup. This may leave cloud resources (VMs, storage, etc.) running in your cloud account.`
                  : `Are you sure you want to delete this automation? This action cannot be undone.`,
              }),
            ],
          }),
          (0, H.jsxs)(E.Body, {
            className: `flex flex-col gap-3`,
            children: [
              i &&
                (0, H.jsx)(D, {
                  variant: `warning`,
                  text: `Warning: Force delete bypasses the normal cleanup process and may leave cloud resources running that will continue to incur costs. Use this only if normal deletion is stuck.`,
                }),
              (0, H.jsx)(Te, { workflow: e, readonly: !0 }),
            ],
          }),
          (0, H.jsxs)(E.Footer, {
            children: [
              (0, H.jsx)(E.Close, {
                asChild: !0,
                children: (0, H.jsx)(w, {
                  ref: c,
                  variant: `outline`,
                  "data-testid": `delete-workflow-dialog-cancel`,
                  children: `Cancel`,
                }),
              }),
              (0, H.jsx)(w, {
                variant: `destructive`,
                onClick: l,
                loading: s.isPending,
                "data-testid": `delete-workflow-dialog-confirm`,
                "data-tracking-id": i
                  ? `confirm-force-delete-workflow-delete-workflow-dialog`
                  : `confirm-delete-workflow-delete-workflow-dialog`,
                children: i ? `Force delete automation` : `Delete automation`,
              }),
            ],
          }),
        ],
      }),
    });
  },
  $ = ({ workflow: e, actions: t }) => {
    let {
      showDeleteModal: n,
      setShowDeleteModal: r,
      showForceDeleteModal: i,
      setShowForceDeleteModal: a,
      showRunDialog: o,
      setShowRunDialog: s,
    } = t;
    return (0, H.jsxs)(H.Fragment, {
      children: [
        (0, H.jsx)(Q, { open: n, workflow: e, onClose: () => r(!1) }),
        (0, H.jsx)(Q, { open: i, workflow: e, onClose: () => a(!1), forceDelete: !0 }),
        (0, H.jsx)(he, { open: o, onOpenChange: s, workflow: e }),
      ],
    });
  };
export { K as a, q as i, Q as n, W as o, J as r, U as s, $ as t };

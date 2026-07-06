import { a as e } from "./rolldown-runtime-CGYlQKCx.js";
import {
  $n as t,
  Er as n,
  L as r,
  P as i,
  er as a,
  ft as o,
  ir as s,
  jr as c,
  nr as l,
  or as u,
  pr as d,
  rr as f,
  tr as p,
  ur as m,
} from "./SegmentProvider-CXCNBY9U.js";
import { n as h } from "./@mux-DLaEVubF.js";
import {
  $f as g,
  $g as _,
  Hf as v,
  Hg as y,
  Jg as b,
  Kg as x,
  Op as S,
  __ as ee,
  cg as C,
  g_ as w,
  gm as T,
  i as E,
  i_ as D,
  kf as O,
  o_ as te,
  v_ as ne,
  vg as re,
  wg as ie,
} from "./vendor-DAwbZtf0.js";
import {
  $a as ae,
  Co as oe,
  Dt as k,
  H as se,
  Li as A,
  Lr as j,
  Ls as M,
  Rs as ce,
  Un as N,
  aa as le,
  ao as P,
  ca as ue,
  da as de,
  ia as fe,
  j as pe,
  lt as me,
  na as he,
  oo as ge,
  tr as F,
  vn as I,
} from "./use-boot-in-app-chat-t-J_VjKS.js";
import { n as L } from "./api-BgkI4l83.js";
import { d as R, h as z } from "./prebuild_pb-CVBD5kln.js";
import { u as _e } from "./runner_manager_pb-BYgy9Ytq.js";
import { n as B, r as ve } from "./toast-axaLeIzZ.js";
import { t as V } from "./button-6YP03Qf2.js";
import { t as ye } from "./cn-DppMFCU8.js";
import { t as H } from "./dialog-BtjFqa-w.js";
import { t as be } from "./banner-CFcSGYsz.js";
import { d as xe } from "./time-DxjbKG-a.js";
import { t as Se } from "./input-C42Z_4fO.js";
import { t as U } from "./tooltip-6hqVQbwq.js";
import { t as Ce } from "./text-fFCFeCas.js";
import { t as W } from "./select-Ceshp72e.js";
import { n as we, t as G } from "./skeleton-Cm867Q_k.js";
import { t as K } from "./use-resource-permission-Dd1Jv7de.js";
import { r as Te } from "./dropdown-menu-D3UmjGpQ.js";
import { o as Ee } from "./environment-queries-zpiLcWfm.js";
import { a as De, c as Oe, s as ke, t as Ae } from "./use-environment-class-entries-DPBxsgJb.js";
import { d as je } from "./runner-queries-BAY_7mHt.js";
import { b as q, g as J, u as Me, x as Ne } from "./project-queries-BMZ3qCU_.js";
import { t as Pe } from "./avatar-CjN22mGB.js";
import { t as Fe } from "./EditorIcon-CXY7bnUG.js";
import { t as Ie } from "./status-dot-DyGV7NWq.js";
import { t as Le } from "./external-link-BKbp1Q22.js";
import { n as Re, r as ze, t as Be } from "./popover-D9TQszBd.js";
import { t as Ve } from "./checkbox-nHTWcF6W.js";
import { t as He } from "./EnvironmentClassOrderedList-Cvz4tDL8.js";
import { t as Ue } from "./IconExternalLink-Be096l4a.js";
import { t as Y } from "./combobox-BkGa_nRF.js";
import { t as X } from "./label-5ATlPnPj.js";
import { t as We } from "./form-control-BfDRQ8Xb.js";
import { n as Ge } from "./SCMAuthentication-Cw9MmVYE.js";
import { t as Ke } from "./switch-CiuLW56f.js";
import { a as qe, i as Je, n as Ye, r as Xe } from "./service-accounts-DLF2ke0D.js";
import { t as Ze } from "./IconWarningCircle-9yrh1wLR.js";
import { t as Qe } from "./IconChevronDown-CeMEEmUt.js";
import { a as $e, n as et, o as tt, r as nt, s as rt } from "./insights-error-classifier-DorxrI3a.js";
import { t as it } from "./prebuild-schedule-DsXxMOcM.js";
import { t as at } from "./ProjectErrors-CWVFFYpV.js";
var Z = e(h(), 1),
  Q = ne(),
  ot = ({ value: e, onChange: t, onBlur: n, disabled: r, error: i }) => {
    let a = (0, Z.useId)();
    return (0, Q.jsx)(We, {
      label: `Display name`,
      id: a,
      error: i,
      children: (0, Q.jsx)(Se, {
        "data-testid": `project-name-input`,
        id: a,
        type: `text`,
        value: e,
        placeholder: `Ex: My Project`,
        disabled: r,
        onChange: (e) => t(e.target.value.trimStart().replace(/\s+/g, ` `)),
        onBlur: n,
      }),
    });
  },
  st = `project-settings-updated`;
function $() {
  b.custom((e) => (0, Q.jsx)(ve, { id: e, title: `Project updated`, type: `success`, dismissible: !0 }), {
    id: st,
    duration: 3e3,
  });
}
var ct = ({ projectId: e }) => {
    let { data: t } = J(e),
      { hasPermission: n } = K(j.PROJECT, e, `project:update`),
      r = q(),
      { toast: i } = B(),
      [a, o] = (0, Z.useState)(),
      s = t?.metadata?.name || ``,
      [c, l] = (0, Z.useState)(s),
      [u, d] = (0, Z.useState)(s);
    return (
      s !== u && s !== c && (l(s), d(s)),
      (0, Q.jsx)(ot, {
        value: c,
        onChange: l,
        onBlur: (0, Z.useCallback)(async () => {
          let t = c.trim();
          if (!t) {
            o(`Display name is required`);
            return;
          }
          if (t === u) {
            o(void 0);
            return;
          }
          o(void 0);
          try {
            (await r.mutateAsync({ projectId: e, name: t }), d(t), $());
          } catch (e) {
            (o(`Failed to save`), i({ title: `Failed to update display name`, description: F(e) }));
          }
        }, [c, u, e, r, i]),
        disabled: !n,
        error: a,
      })
    );
  },
  lt = ({ value: e, onChange: t, onBlur: n, disabled: r, error: i }) => {
    let a = (0, Z.useId)();
    return (0, Q.jsx)(We, {
      label: `Repository Clone URL`,
      id: a,
      error: i,
      children: (0, Q.jsx)(Se, {
        id: a,
        type: `text`,
        value: e,
        disabled: r,
        onChange: (e) => t(e.target.value.trimStart().replace(/\s+/g, ` `)),
        onBlur: n,
      }),
    });
  },
  ut = ({ projectId: e }) => {
    let { data: t } = J(e),
      { hasPermission: n } = K(j.PROJECT, e, `project:update`),
      r = q(),
      { toast: a } = B(),
      [o, s] = (0, Z.useState)(),
      c = t?.initializer?.specs[0]?.spec.case,
      l =
        c === `contextUrl`
          ? (t?.initializer?.specs[0]?.spec.value?.url ?? ``)
          : c === `git`
            ? (t?.initializer?.specs[0]?.spec.value?.remoteUri ?? ``)
            : ``,
      [u, d] = (0, Z.useState)(l),
      [f, p] = (0, Z.useState)(l);
    l !== f && l !== u && (d(l), p(l));
    let m = (0, Z.useCallback)(
      async (n) => {
        if (!n) {
          s(`Repository URL is required`);
          return;
        }
        try {
          new URL(n);
        } catch {
          s(`Invalid Repository URL`);
          return;
        }
        if (n === f) {
          s(void 0);
          return;
        }
        if ((s(void 0), !(c !== `contextUrl` && c !== `git`)))
          try {
            if (c === `contextUrl`)
              await r.mutateAsync({
                projectId: e,
                initializer: w(P, { specs: [w(ge, { spec: { case: `contextUrl`, value: w(ae, { url: n }) } })] }),
              });
            else if (c === `git`) {
              let i = t?.initializer?.specs[0]?.spec.value;
              await r.mutateAsync({
                projectId: e,
                initializer: w(P, {
                  specs: [
                    w(ge, {
                      spec: {
                        case: `git`,
                        value: w(oe, {
                          remoteUri: n,
                          upstreamRemoteUri: i?.upstreamRemoteUri,
                          targetMode: i?.targetMode,
                          cloneTarget: i?.cloneTarget,
                          checkoutLocation: i?.checkoutLocation,
                        }),
                      },
                    }),
                  ],
                }),
              });
            }
            (p(n), $());
          } catch (e) {
            (s(`Failed to save`), a({ title: `Failed to update repository URL`, description: F(e) }));
          }
      },
      [f, c, t, e, r, a],
    );
    return c === `contextUrl`
      ? (0, Q.jsx)(i, {
          label: `Context URL`,
          value: u,
          onChange: d,
          onBlur: () => void m(u),
          disabled: !n,
          errorMessage: o,
        })
      : (0, Q.jsx)(lt, { value: u, onChange: d, onBlur: () => void m(u), disabled: !n, error: o });
  },
  dt = ({ value: e, onChange: t, onBlur: n, disabled: r, error: i }) => {
    let a = (0, Z.useId)();
    return (0, Q.jsx)(We, {
      label: `Branch`,
      id: a,
      error: i,
      children: (0, Q.jsx)(Se, {
        id: a,
        type: `text`,
        value: e,
        disabled: r,
        onChange: (e) => t(e.target.value.trimStart().replace(/\s+/g, ` `)),
        onBlur: n,
      }),
    });
  },
  ft = ({ projectId: e }) => {
    let { data: t } = J(e),
      { hasPermission: n } = K(j.PROJECT, e, `project:update`),
      r = q(),
      { toast: i } = B(),
      [a, o] = (0, Z.useState)(),
      s = t?.initializer?.specs[0]?.spec,
      c = s?.case === `git`,
      l = c ? s.value : void 0,
      u = l?.cloneTarget ?? ``,
      [d, f] = (0, Z.useState)(u),
      [p, m] = (0, Z.useState)(u);
    u !== p && u !== d && (f(u), m(u));
    let h = (0, Z.useCallback)(async () => {
      let t = d.trim();
      if (!t) {
        o(`Branch is required`);
        return;
      }
      if (t === p) {
        o(void 0);
        return;
      }
      o(void 0);
      try {
        (await r.mutateAsync({
          projectId: e,
          initializer: w(P, {
            specs: [
              w(ge, {
                spec: {
                  case: `git`,
                  value: w(oe, {
                    remoteUri: l?.remoteUri,
                    upstreamRemoteUri: l?.upstreamRemoteUri,
                    targetMode: l?.targetMode,
                    cloneTarget: t,
                    checkoutLocation: l?.checkoutLocation,
                  }),
                },
              }),
            ],
          }),
        }),
          m(t),
          $());
      } catch (e) {
        (o(`Failed to save`), i({ title: `Failed to update branch`, description: F(e) }));
      }
    }, [d, p, l, e, r, i]);
    return c ? (0, Q.jsx)(dt, { value: d, onChange: f, onBlur: h, disabled: !n, error: a }) : null;
  },
  pt = ({ selectedExecutor: e, onExecutorChange: t, disabled: n = !1, className: i }) => {
    let { data: a, isPending: s } = d(),
      { data: c, isPending: l } = me(),
      { member: u, isPending: f } = o(r(e)),
      p = (0, Z.useMemo)(() => {
        let e = [];
        return (
          c && e.push({ id: c.id, name: c.name, principal: M.USER, avatarUrl: c.avatarUrl }),
          a?.serviceAccounts &&
            a.serviceAccounts.forEach((t) => {
              e.push({ id: t.id, name: t.name, principal: M.SERVICE_ACCOUNT, isIOIServiceAccount: Ye(t) });
            }),
          e
        );
      }, [c, a]),
      m = (0, Z.useMemo)(() => {
        let t = p.find((t) => t.id === e.id);
        if (t) return t;
        if (e.principal === M.USER && u)
          return { id: u.userId, name: u.fullName, principal: M.USER, avatarUrl: u.avatarUrl };
        if (e.principal === M.SERVICE_ACCOUNT)
          return { id: e.id, name: `Service Account`, principal: M.SERVICE_ACCOUNT };
      }, [p, e, u]),
      h = (0, Z.useCallback)(
        (e) => {
          let n = p.find((t) => t.id === e);
          n && t(w(ce, { id: n.id, principal: n.principal }));
        },
        [p, t],
      ),
      g = s || l || f,
      _ = (a?.serviceAccounts?.length ?? 0) > 0;
    return (0, Q.jsx)(`div`, {
      className: ye(i),
      children: (0, Q.jsxs)(Y, {
        value: e.id,
        onValueChange: h,
        disabled: n,
        loading: g,
        className: `w-full`,
        children: [
          (0, Q.jsx)(Y.Value, {
            children: m
              ? (0, Q.jsxs)(`div`, {
                  className: `flex min-w-0 items-center gap-2`,
                  children: [(0, Q.jsx)(mt, { option: m }), (0, Q.jsx)(Y.ValueLabel, { children: m.name })],
                })
              : `Select identity`,
          }),
          g
            ? (0, Q.jsx)(Y.Loading, { children: `Loading identities...` })
            : (0, Q.jsxs)(Y.Popover, {
                children: [
                  (0, Q.jsx)(Y.List, {
                    items: p,
                    searchKeys: [`name`],
                    noMatchesComponent: (0, Q.jsx)(Y.Empty, { children: `No matching identities.` }),
                    children: (e) =>
                      (0, Q.jsxs)(
                        Y.ListItem,
                        {
                          value: e.id,
                          children: [
                            (0, Q.jsx)(Y.ListItemLeadingIcon, { children: (0, Q.jsx)(mt, { option: e }) }),
                            (0, Q.jsx)(Y.ListItemTitle, { className: `text-base`, children: e.name }),
                          ],
                        },
                        e.id,
                      ),
                  }),
                  (0, Q.jsx)(Y.Footer, {
                    children: (0, Q.jsx)(C, {
                      to: Je(),
                      className: `text-sm text-content-secondary hover:text-content-primary`,
                      children: _ ? `Manage service accounts` : `Create a service account`,
                    }),
                  }),
                ],
              }),
        ],
      }),
    });
  },
  mt = ({ option: { id: e, principal: t, avatarUrl: n, name: r, isIOIServiceAccount: i } }) =>
    t === M.USER
      ? (0, Q.jsxs)(Pe, {
          size: 24,
          children: [
            n && (0, Q.jsx)(Pe.Image, { src: n, alt: `${r}'s avatar` }),
            (0, Q.jsx)(Pe.Fallback, { children: (0, Q.jsx)(Pe.Initials, { name: r, size: 24 }) }),
          ],
        })
      : (0, Q.jsx)(qe, { id: e, size: 24, isIOIServiceAccount: i }),
  ht = ({ executor: e, repoUrl: t, prebuildEnvironmentClassIds: n, canUpdateProject: r }) => {
    let { data: i } = me(),
      { environmentClasses: a } = Oe(),
      o = (0, Z.useMemo)(() => {
        if (n.length !== 0) return a[n[0]]?.runner?.runnerId;
      }, [n, a]),
      s = (0, Z.useMemo)(() => {
        if (t)
          try {
            return new URL(t).host;
          } catch {
            return;
          }
      }, [t]),
      c = e.principal === M.USER && e.id === i?.id,
      l = e.principal === M.SERVICE_ACCOUNT,
      u = e.principal === M.USER && e.id !== i?.id,
      { data: d } = m({ serviceAccountId: e.id, enabled: l }),
      f = (0, Z.useMemo)(() => {
        if (!(!l || !d)) return L({ serviceAccountId: e.id, serviceAccountAccessToken: d });
      }, [l, d, e.id]),
      { data: p, isPending: h } = je(o, s, { enabled: c && !!o && !!s, refetchUntilAuthenticated: !0 }),
      { data: g, isPending: _ } = je(o, s, {
        enabled: l && !!o && !!s && !!f,
        headers: f,
        refetchUntilAuthenticated: !0,
      }),
      v = c ? p : l ? g : void 0,
      y = c ? h : l ? _ : !1,
      [b, x] = (0, Z.useState)(!1),
      S = (0, Z.useCallback)(() => {
        x(!0);
      }, []),
      ee = (0, Z.useCallback)(() => {
        x(!1);
      }, []),
      w = (0, Z.useMemo)(
        () =>
          v?.type === `AuthenticationRequired`
            ? { url: v.url, patAuth: v.patAuth, scmId: v.scmId, scmName: v.scmName }
            : null,
        [v],
      );
    return !o || !s || !t || y || u || v?.type !== `AuthenticationRequired`
      ? null
      : c && w
        ? (0, Q.jsxs)(Q.Fragment, {
            children: [
              (0, Q.jsx)(be, {
                variant: `warning`,
                LeadingIcon: (0, Q.jsx)(Ze, { className: `text-content-warning`, size: `sm` }),
                text: `You don't have access to this repository on the selected runner. Prebuilds will fail until you authenticate.`,
                action: r
                  ? {
                      text: `Authenticate`,
                      onClick: S,
                      variant: `primary`,
                      size: `sm`,
                      responsive: !0,
                      "data-tracking-id": `prebuild-scm-authenticate`,
                    }
                  : void 0,
              }),
              b &&
                (0, Q.jsx)(Ge, {
                  repoURL: t,
                  runnerId: o,
                  authenticationUrl: w.url,
                  patAuth: w.patAuth,
                  scmId: w.scmId,
                  scmName: w.scmName,
                  onClose: () => x(!1),
                  onClickContinue: ee,
                  "data-track-location": k.EnvironmentSCMAuthenticationModal,
                }),
            ],
          })
        : l
          ? (0, Q.jsx)(be, {
              variant: `warning`,
              LeadingIcon: (0, Q.jsx)(Ze, { className: `text-content-warning`, size: `sm` }),
              text: `This service account doesn't have access to the repository on the selected runner. Prebuilds will fail until it's authenticated.`,
              link: (0, Q.jsx)(V, {
                variant: `primary`,
                size: `sm`,
                asChild: !0,
                children: (0, Q.jsxs)(C, {
                  to: Xe({ id: e.id }),
                  target: `_blank`,
                  rel: `noopener noreferrer`,
                  "data-tracking-id": `prebuild-scm-configure-service-account`,
                  children: [`Configure service account`, (0, Q.jsx)(Ue, { size: `sm` })],
                }),
              }),
            })
          : null;
  },
  gt = [
    { value: 300, label: `5 min` },
    { value: 600, label: `10 min` },
    { value: 900, label: `15 min` },
    { value: 1800, label: `30 min` },
    { value: 3600, label: `1 hr` },
    { value: 5400, label: `1.5 hr` },
    { value: 7200, label: `2 hr` },
  ],
  _t = ({
    enabled: e,
    onToggle: t,
    hourUtc: n,
    onHourUtcChange: r,
    executor: i,
    onExecutorChange: a,
    timeoutSeconds: o,
    onTimeoutChange: s,
    enableJetbrainsWarmup: c,
    onJetbrainsWarmupChange: l,
    prebuildEnvironmentClassIds: u,
    repoUrl: d,
    canUpdateProject: f = !0,
    disabled: p,
  }) => {
    let m = (0, Z.useId)(),
      h = (0, Z.useId)(),
      g = p || !f;
    return (0, Q.jsx)(`div`, {
      className: `rounded-lg border border-border-base p-4`,
      children: (0, Q.jsxs)(`div`, {
        className: `flex gap-4`,
        children: [
          (0, Q.jsx)(Ke, {
            id: `prebuild-enabled-switch`,
            state: e ? `checked` : `unchecked`,
            onToggle: t,
            disabled: g,
            "aria-label": `Enable prebuild environments`,
            "data-testid": `prebuild-enabled-toggle`,
          }),
          (0, Q.jsxs)(`div`, {
            className: `flex flex-col gap-1`,
            children: [
              (0, Q.jsx)(`label`, {
                className: `cursor-pointer font-bold`,
                htmlFor: `prebuild-enabled-switch`,
                children: `Prebuild Environments`,
              }),
              (0, Q.jsxs)(Ce, {
                className: `text-sm text-content-secondary`,
                children: [
                  `Faster starts, no surprises. IOI builds environments in the background so they're ready when you are.`,
                  ` `,
                  (0, Q.jsx)(Le, {
                    href: `https://ioi.com/docs/ioi/projects/prebuilds`,
                    className: `text-content-secondary underline`,
                    children: `Learn more`,
                  }),
                ],
              }),
              e &&
                (0, Q.jsxs)(`div`, {
                  className: `flex flex-col gap-4 pt-2`,
                  children: [
                    (0, Q.jsxs)(`div`, {
                      className: `flex flex-wrap items-center gap-x-4 gap-y-3`,
                      children: [
                        (0, Q.jsxs)(`div`, {
                          className: `flex items-center gap-2`,
                          children: [
                            (0, Q.jsx)(X, { htmlFor: m, className: `shrink-0 text-sm`, children: `Runs daily at` }),
                            (0, Q.jsx)(W, {
                              value: n.toString(),
                              onValueChange: (e) => r(parseInt(e, 10)),
                              disabled: g,
                              id: m,
                              className: `w-[100px]`,
                              placeholder: `Select time`,
                              children: Array.from({ length: 24 }, (e, t) => t).map((e) =>
                                (0, Q.jsx)(
                                  W.Item,
                                  {
                                    value: e.toString(),
                                    children: (0, Q.jsxs)(`span`, { children: [e.toString().padStart(2, `0`), `:00`] }),
                                  },
                                  e,
                                ),
                              ),
                            }),
                            (0, Q.jsx)(`span`, {
                              className: `shrink-0 text-sm text-content-tertiary`,
                              children: `UTC`,
                            }),
                          ],
                        }),
                        (0, Q.jsxs)(`div`, {
                          className: `flex items-center gap-2`,
                          children: [
                            (0, Q.jsx)(U, {
                              content: `Prebuilds use this identity's credentials to access the repository. User secrets are not included.`,
                              children: (0, Q.jsx)(X, {
                                className: `shrink-0 cursor-default text-sm underline decoration-dotted underline-offset-4`,
                                children: `Runs as`,
                              }),
                            }),
                            i && (0, Q.jsx)(pt, { selectedExecutor: i, onExecutorChange: a, disabled: g }),
                          ],
                        }),
                        (0, Q.jsxs)(`div`, {
                          className: `flex items-center gap-2`,
                          children: [
                            (0, Q.jsx)(X, { htmlFor: h, className: `shrink-0 text-sm`, children: `Times out after` }),
                            (0, Q.jsx)(W, {
                              value: o.toString(),
                              onValueChange: (e) => s(parseInt(e, 10)),
                              disabled: g,
                              id: h,
                              className: `w-[110px]`,
                              placeholder: `Timeout`,
                              children: gt.map((e) =>
                                (0, Q.jsx)(
                                  W.Item,
                                  { value: e.value.toString(), children: (0, Q.jsx)(`span`, { children: e.label }) },
                                  e.value,
                                ),
                              ),
                            }),
                          ],
                        }),
                      ],
                    }),
                    (0, Q.jsxs)(`div`, {
                      className: `flex items-center gap-2`,
                      children: [
                        (0, Q.jsx)(U, {
                          content: (0, Q.jsxs)(`span`, {
                            children: [
                              `Build indexes to make JetBrains IDEs start faster.`,
                              ` `,
                              (0, Q.jsx)(Le, {
                                href: `https://ioi.com/docs/ioi/projects/prebuilds#jetbrains-warmup`,
                                className: `text-content-tooltip underline`,
                                children: `Learn more`,
                              }),
                            ],
                          }),
                          children: (0, Q.jsx)(X, {
                            className: `cursor-pointer text-sm underline decoration-dotted underline-offset-4`,
                            htmlFor: `jetbrains-warmup-switch`,
                            children: `Warm up JetBrains`,
                          }),
                        }),
                        (0, Q.jsx)(Ke, {
                          id: `jetbrains-warmup-switch`,
                          state: c ? `checked` : `unchecked`,
                          onToggle: l,
                          disabled: g,
                          "aria-label": `Enable JetBrains editors warmup`,
                          "data-testid": `jetbrains-warmup-toggle`,
                        }),
                      ],
                    }),
                    i &&
                      d &&
                      u.length > 0 &&
                      (0, Q.jsx)(ht, { executor: i, repoUrl: d, prebuildEnvironmentClassIds: u, canUpdateProject: f }),
                  ],
                }),
            ],
          }),
        ],
      }),
    });
  },
  vt = 3600,
  yt = ({ projectId: e }) => {
    let { data: t } = J(e),
      { hasPermission: n } = K(j.PROJECT, e, `project:update`),
      { data: r } = me(),
      i = q(),
      { toast: a } = B(),
      { data: o } = Me(e),
      { environmentClassEntries: s, isLoading: c } = ke(),
      l = (0, Z.useMemo)(() => {
        if (!(!o?.environmentClasses || c))
          return o.environmentClasses
            .map((e) => {
              if (e.environmentClass.case === `environmentClassId`)
                return s.find((t) => t.clazz.id === e.environmentClass.value);
            })
            .filter((e) => !!e);
      }, [o, s, c]),
      u = it(),
      d = t?.prebuildConfiguration?.enabled || !1,
      f =
        t?.prebuildConfiguration?.trigger?.trigger?.case === `dailySchedule`
          ? (t.prebuildConfiguration.trigger.trigger.value.hourUtc ?? u)
          : u,
      p = t?.prebuildConfiguration?.executor,
      m = Number(t?.prebuildConfiguration?.timeout?.seconds) || vt,
      h = t?.prebuildConfiguration?.enableJetbrainsWarmup || !1,
      g = (0, Z.useMemo)(
        () => t?.prebuildConfiguration?.environmentClassIds || [],
        [t?.prebuildConfiguration?.environmentClassIds],
      ),
      [_, v] = (0, Z.useState)(d),
      [y, b] = (0, Z.useState)(d);
    d !== y && (v(d), b(d));
    let [x, S] = (0, Z.useState)(f),
      [ee, C] = (0, Z.useState)(f);
    f !== ee && (S(f), C(f));
    let [T, E] = (0, Z.useState)(p),
      [O, te] = (0, Z.useState)(p);
    p !== O && (E(p), te(p));
    let [ne, re] = (0, Z.useState)(m),
      [ie, ae] = (0, Z.useState)(m);
    m !== ie && (re(m), ae(m));
    let [oe, k] = (0, Z.useState)(h),
      [se, A] = (0, Z.useState)(h);
    h !== se && (k(h), A(h));
    let [N, P] = (0, Z.useState)(g),
      [de, pe] = (0, Z.useState)(g);
    g !== de && (P(g), pe(g));
    let he = (0, Z.useMemo)(() => {
        if (T) return T;
        if (r) return w(ce, { id: r.id, principal: M.USER });
      }, [T, r]),
      ge = (0, Z.useMemo)(() => Ee(t?.initializer), [t?.initializer]),
      I = (0, Z.useRef)({
        enabled: _,
        hourUtc: x,
        timeoutSeconds: ne,
        enableJetbrainsWarmup: oe,
        prebuildEnvironmentClassIds: N,
        executor: T,
      });
    I.current = {
      enabled: _,
      hourUtc: x,
      timeoutSeconds: ne,
      enableJetbrainsWarmup: oe,
      prebuildEnvironmentClassIds: N,
      executor: T,
    };
    let L = (0, Z.useCallback)(
      async (n, o) => {
        let s = I.current,
          c = n.enabled ?? s.enabled,
          l = n.hourUtc ?? s.hourUtc,
          u = n.timeoutSeconds ?? s.timeoutSeconds,
          d = n.enableJetbrainsWarmup ?? s.enableJetbrainsWarmup,
          f = n.environmentClassIds ?? s.prebuildEnvironmentClassIds,
          p;
        c &&
          (n.executor === void 0
            ? s.executor
              ? (p = s.executor)
              : t?.prebuildConfiguration?.executor
                ? (p = t.prebuildConfiguration.executor)
                : r && (p = w(ce, { id: r.id, principal: M.USER }))
            : (p = n.executor));
        let m = w(ue, {
          enabled: c,
          environmentClassIds: c ? f : [],
          trigger: c ? w(fe, { trigger: { case: `dailySchedule`, value: w(le, { hourUtc: l }) } }) : void 0,
          timeout: c ? w(D, { seconds: BigInt(u) }) : t?.prebuildConfiguration?.timeout || void 0,
          executor: p,
          enableJetbrainsWarmup: c ? d : !1,
        });
        try {
          (await i.mutateAsync({ projectId: e, prebuildConfiguration: m }), $());
        } catch (e) {
          (o?.(), a({ title: `Failed to update prebuild settings`, description: F(e) }));
        }
      },
      [t, r, e, i, a],
    );
    return (
      (0, Z.useEffect)(() => {
        if (_ && N.length === 0 && l?.length) {
          let e = l.find((e) => !!e.clazz?.id)?.clazz?.id;
          e && (P([e]), L({ environmentClassIds: [e] }));
        }
      }, [_, N.length, l, L]),
      (0, Q.jsx)(_t, {
        enabled: _,
        onToggle: (0, Z.useCallback)(
          (e) => {
            let t = I.current.enabled,
              n = I.current.prebuildEnvironmentClassIds;
            if ((v(e), e)) {
              if (N.length === 0 && l?.length) {
                let r = l.find((e) => !!e.clazz?.id)?.clazz?.id;
                if (r) {
                  (P([r]),
                    L({ enabled: e, environmentClassIds: [r] }, () => {
                      (v(t), P(n));
                    }));
                  return;
                }
              }
            } else P(g);
            L({ enabled: e }, () => {
              (v(t), P(n));
            });
          },
          [L, N.length, l, g],
        ),
        hourUtc: x,
        onHourUtcChange: (0, Z.useCallback)(
          (e) => {
            let t = I.current.hourUtc;
            (S(e), L({ hourUtc: e }, () => S(t)));
          },
          [L],
        ),
        executor: he,
        onExecutorChange: (0, Z.useCallback)(
          (e) => {
            let t = I.current.executor;
            (E(e), L({ executor: e }, () => E(t)));
          },
          [L],
        ),
        timeoutSeconds: ne,
        onTimeoutChange: (0, Z.useCallback)(
          (e) => {
            let t = I.current.timeoutSeconds;
            (re(e), L({ timeoutSeconds: e }, () => re(t)));
          },
          [L],
        ),
        enableJetbrainsWarmup: oe,
        onJetbrainsWarmupChange: (0, Z.useCallback)(
          (e) => {
            let t = I.current.enableJetbrainsWarmup;
            (k(e), L({ enableJetbrainsWarmup: e }, () => k(t)));
          },
          [L],
        ),
        prebuildEnvironmentClassIds: N,
        onPrebuildEnvironmentClassIdsChange: (0, Z.useCallback)(
          (e) => {
            let t = I.current.prebuildEnvironmentClassIds;
            (P(e), L({ environmentClassIds: e }, () => P(t)));
          },
          [L],
        ),
        repoUrl: ge,
        canUpdateProject: n,
      })
    );
  },
  bt = ({
    entries: e,
    allEntries: t,
    onChange: n,
    loading: r,
    error: i,
    disabled: a,
    minItems: o = 1,
    maxItems: s = 30,
    showPrebuildColumn: c,
    prebuildSelectedIds: l,
    onPrebuildSelectionChange: u,
    showWarmPoolColumn: d,
    showPrebuildStatusColumn: f,
    renderWarmPoolCell: p,
    renderPrebuildStatusCell: m,
  }) =>
    (0, Q.jsx)(He, {
      label: `Environment Classes`,
      environmentClassEntries: e,
      allEnvironmentClassEntries: t,
      onChange: n,
      loading: r,
      error: i,
      disabled: a,
      minItems: o,
      maxItems: s,
      showPrebuildColumn: c,
      prebuildSelectedIds: l,
      onPrebuildSelectionChange: u,
      showWarmPoolColumn: d,
      showPrebuildStatusColumn: f,
      renderWarmPoolCell: p,
      renderPrebuildStatusCell: m,
    }),
  xt = ({ prebuild: e, projectId: t, onTriggerPrebuild: n, isTriggeringPrebuild: r }) => {
    let i = e?.status?.phase !== void 0 && ![R.COMPLETED, R.FAILED, R.UNSPECIFIED].includes(e.status.phase);
    if (!e)
      return n
        ? (0, Q.jsxs)(V, {
            variant: `ghost`,
            size: `sm`,
            loading: r,
            disabled: r,
            onClick: (e) => {
              (e.preventDefault(), e.stopPropagation(), n());
            },
            "aria-label": `Run prebuild`,
            "data-tracking-id": `trigger-prebuild-cell`,
            children: [
              !r && (0, Q.jsx)(v, { size: 14 }),
              (0, Q.jsx)(`span`, { className: `hidden lg:inline`, children: `Run prebuild` }),
            ],
          })
        : (0, Q.jsx)(`span`, { className: `text-sm text-content-tertiary`, children: `--` });
    let a = e.status?.phase,
      o = !!e.status?.warningMessage,
      s = e.status?.completionTime,
      c = s ? xe(te(s)) : void 0,
      l = (() => {
        switch (a) {
          case R.COMPLETED:
            return o
              ? (0, Q.jsx)(Ze, { size: `sm`, className: `text-content-warning` })
              : (0, Q.jsx)(x, { size: 16, className: `text-content-success` });
          case R.FAILED:
            return (0, Q.jsx)(y, { size: 16, className: `text-content-destructive` });
          case R.PENDING:
          case R.STARTING:
          case R.RUNNING:
          case R.STOPPING:
          case R.SNAPSHOTTING:
          case R.CANCELLING:
          case R.DELETING:
            return (0, Q.jsx)(T, { size: 16, className: `animate-spin text-content-secondary` });
          default:
            return null;
        }
      })();
    if (!l) return (0, Q.jsx)(`span`, { className: `text-sm text-content-tertiary`, children: `--` });
    let u = (() => {
        switch (a) {
          case R.COMPLETED:
            return o
              ? `Completed with warnings${e.status?.warningMessage ? `: ${e.status.warningMessage}` : ``}`
              : `Last prebuild succeeded`;
          case R.FAILED:
            return e.status?.failureMessage ? `Failed: ${e.status.failureMessage}` : `Last prebuild failed`;
          case R.PENDING:
          case R.STARTING:
            return `Prebuild is starting`;
          case R.RUNNING:
            return `Prebuild is running`;
          case R.STOPPING:
            return `Prebuild is stopping`;
          case R.SNAPSHOTTING: {
            let t = e.status?.snapshotCompletionPercentage;
            return t && t > 0 ? `Saving prebuild snapshot (${t}%)` : `Saving prebuild snapshot`;
          }
          case R.CANCELLING:
            return `Prebuild is being cancelled`;
          case R.DELETING:
            return `Prebuild is being deleted`;
          default:
            return `Click to view prebuilds`;
        }
      })(),
      d = (() => {
        switch (a) {
          case R.COMPLETED:
            return c ?? null;
          case R.FAILED:
            return `Failed`;
          case R.PENDING:
          case R.STARTING:
            return `Starting...`;
          case R.RUNNING:
            return `Running...`;
          case R.STOPPING:
            return `Stopping...`;
          case R.SNAPSHOTTING:
            return `Snapshotting...`;
          case R.CANCELLING:
            return `Cancelling...`;
          case R.DELETING:
            return `Deleting...`;
          default:
            return null;
        }
      })();
    return (0, Q.jsxs)(`div`, {
      className: `flex items-center gap-1`,
      children: [
        (0, Q.jsx)(U, {
          content: u,
          side: `top`,
          className: `max-w-[240px] font-sans`,
          usePortal: !0,
          children: (0, Q.jsxs)(C, {
            to: `/projects/${t}/prebuilds`,
            onClick: (e) => e.stopPropagation(),
            className: `inline-flex items-center gap-1.5 text-sm leading-none text-content-secondary hover:text-content-primary`,
            "aria-label": `View prebuilds`,
            "data-tracking-id": `prebuild-status-cell`,
            children: [
              (0, Q.jsx)(`span`, { className: `flex size-4 shrink-0 items-center justify-center`, children: l }),
              d && (0, Q.jsx)(`span`, { children: d }),
            ],
          }),
        }),
        n &&
          !i &&
          (0, Q.jsx)(U, {
            content: `Run a new prebuild`,
            usePortal: !0,
            children: (0, Q.jsx)(V, {
              variant: `ghost`,
              size: `sm`,
              loading: r,
              disabled: r,
              onClick: (e) => {
                (e.preventDefault(), e.stopPropagation(), n());
              },
              "aria-label": `Run prebuild`,
              "data-tracking-id": `retrigger-prebuild-cell`,
              className: `size-7 p-0`,
              children: !r && (0, Q.jsx)(v, { size: 14 }),
            }),
          }),
      ],
    });
  },
  St = Array.from({ length: 11 }, (e, t) => 0 + t),
  Ct = Array.from({ length: 10 }, (e, t) => t + 1),
  wt = Array.from({ length: 10 }, (e, t) => t + 1);
function Tt(e, t) {
  return e.includes(t) ? e : [...e, t].sort((e, t) => e - t);
}
function Et(e, t, n, r, i) {
  if (t && e) return t;
  if (n) return `Previous pool is still shutting down`;
  if (!(!r || !i))
    switch (i) {
      case z.READY:
        return `Warm pool is ready`;
      case z.PENDING:
        return `Warm pool is pending — waiting for a prebuild snapshot`;
      case z.DEGRADED:
        return;
      case z.DELETING:
        return `Warm pool is shutting down`;
      default:
        return;
    }
}
function Dt(e, t) {
  switch (e) {
    case z.READY:
      return { color: `green`, animation: `none`, label: `Ready` };
    case z.PENDING:
      return { color: `orange`, animation: `spin`, label: `Pending` };
    case z.DEGRADED:
      return { color: `orange`, animation: `none`, label: t ?? `Degraded` };
    case z.DELETING:
      return { color: `gray`, animation: `fade`, label: `Shutting down` };
    default:
      return { color: `gray`, animation: `none`, label: `Unknown` };
  }
}
function Ot(e, t, n, r) {
  return e ? (r && t !== n ? `${t}–${n}` : `${r ? t : n}`) : `Off`;
}
var kt = ({
    envClassId: e,
    enabled: t,
    minSize: n,
    maxSize: r,
    supportsScaling: i = !1,
    currentSize: a,
    onToggle: o,
    onMinSizeChange: s,
    onMaxSizeChange: c,
    disabled: l,
    disabledReason: u,
    isLoading: d,
    isCleaningUp: f,
    phase: p,
    failureMessage: m,
    legacyWarning: h,
  }) => {
    let g = t && p === z.DEGRADED,
      _ = l || d || f,
      v = (d && !f) ?? !1,
      y = Et(!!l, u, !!f, t, p),
      [b, x] = (0, Z.useState)(!1),
      S = (0, Z.useCallback)(
        (e) => {
          o(e);
        },
        [o],
      ),
      ee = (0, Z.useCallback)(
        (e) => {
          (s(e), c(e));
        },
        [s, c],
      ),
      C = Ot(t, n, r, i),
      w = (0, Q.jsx)(ze, {
        asChild: !0,
        children: (0, Q.jsx)(V, {
          variant: `secondary`,
          size: `sm`,
          TrailingIcon: Qe,
          disabled: _,
          loading: v,
          "aria-label": `Configure warm pool: ${C}`,
          "data-testid": `warm-pool-select-${e}`,
          "data-tracking-id": `warm-pool-open-config`,
          children: C,
        }),
      });
    return (0, Q.jsxs)(`div`, {
      className: `flex items-center gap-1.5`,
      children: [
        (0, Q.jsxs)(Be, {
          open: b,
          onOpenChange: x,
          children: [
            y ? (0, Q.jsx)(U, { content: y, usePortal: !0, children: (0, Q.jsx)(`div`, { children: w }) }) : w,
            (0, Q.jsx)(Re, {
              align: `start`,
              className: `w-64 space-y-3`,
              "data-testid": `warm-pool-popover-${e}`,
              children: i
                ? (0, Q.jsx)(Mt, {
                    envClassId: e,
                    enabled: t,
                    minSize: n,
                    maxSize: r,
                    currentSize: a,
                    phase: p,
                    failureMessage: m,
                    onMinSizeChange: s,
                    onMaxSizeChange: c,
                    onToggle: S,
                  })
                : (0, Q.jsx)(Nt, {
                    envClassId: e,
                    enabled: t,
                    size: r,
                    currentSize: a,
                    phase: p,
                    failureMessage: m,
                    onSizeChange: ee,
                    onToggle: S,
                  }),
            }),
          ],
        }),
        g &&
          (0, Q.jsx)(U, {
            content: m || `Warm pool is degraded — some instances may be unavailable`,
            className: `max-w-[240px]`,
            usePortal: !0,
            children: (0, Q.jsx)(`span`, {
              className: `text-content-warning`,
              role: `img`,
              "aria-label": `Warm pool degraded`,
              children: (0, Q.jsx)(Ze, { size: `sm` }),
            }),
          }),
        h &&
          !g &&
          (0, Q.jsx)(U, {
            content: (0, Q.jsxs)(`span`, {
              children: [
                `This runner's infrastructure needs an upgrade to keep supporting warm pools and enable dynamic scaling.`,
                ` `,
                (0, Q.jsx)(Le, {
                  href: `https://ioi.com/docs/ioi/runners/aws/update-runner#upgrade-runner-infrastructure`,
                  className: `text-content-tooltip underline`,
                  children: `Learn how to upgrade`,
                }),
              ],
            }),
            className: `max-w-[280px]`,
            usePortal: !0,
            children: (0, Q.jsx)(`span`, {
              className: `text-content-warning`,
              role: `img`,
              "aria-label": `Runner upgrade required`,
              "data-testid": `warm-pool-legacy-warning-${e}`,
              children: (0, Q.jsx)(Ze, { size: `sm` }),
            }),
          }),
      ],
    });
  },
  At = ({ envClassId: e, enabled: t, onToggle: n }) =>
    (0, Q.jsxs)(`div`, {
      className: `flex items-center justify-between`,
      children: [
        (0, Q.jsx)(`span`, { className: `text-sm font-medium text-content-primary`, children: `Enabled` }),
        (0, Q.jsx)(Ke, {
          state: t ? `checked` : `unchecked`,
          onToggle: n,
          "aria-label": t ? `Disable warm pool` : `Enable warm pool`,
          "data-testid": `warm-pool-toggle-${e}`,
          "data-tracking-id": t ? `warm-pool-turn-off` : `warm-pool-turn-on`,
        }),
      ],
    }),
  jt = ({ phase: e, currentSize: t, failureMessage: n }) => {
    if (!e) return null;
    let { color: r, animation: i, label: a } = Dt(e, n),
      o = t === void 0 ? `` : `· ${t} running`;
    return (0, Q.jsxs)(`div`, {
      className: `flex items-center gap-1.5`,
      children: [
        (0, Q.jsx)(Ie, { size: `sm`, color: r, animation: i }),
        (0, Q.jsxs)(`span`, { className: `text-xs text-content-secondary`, children: [a, ` `, o] }),
      ],
    });
  },
  Mt = ({
    envClassId: e,
    enabled: t,
    minSize: n,
    maxSize: r,
    currentSize: i,
    phase: a,
    failureMessage: o,
    onMinSizeChange: s,
    onMaxSizeChange: c,
    onToggle: l,
  }) => {
    let u = (0, Z.useId)(),
      d = (0, Z.useId)();
    return (0, Q.jsxs)(Q.Fragment, {
      children: [
        (0, Q.jsx)(At, { envClassId: e, enabled: t, onToggle: l }),
        t && (0, Q.jsx)(jt, { phase: a, currentSize: i, failureMessage: o }),
        (0, Q.jsxs)(`div`, {
          className: `flex items-center justify-between`,
          children: [
            (0, Q.jsx)(X, {
              htmlFor: u,
              className: t ? `text-sm` : `text-sm text-content-tertiary`,
              children: `Min instances`,
            }),
            (0, Q.jsx)(W, {
              value: n.toString(),
              onValueChange: (e) => s(parseInt(e, 10)),
              disabled: !t,
              id: u,
              size: `sm`,
              className: `w-[72px]`,
              children: Tt(St, n)
                .filter((e) => e <= r)
                .map((e) =>
                  (0, Q.jsx)(W.Item, { value: e.toString(), children: (0, Q.jsx)(`span`, { children: e }) }, e),
                ),
            }),
          ],
        }),
        (0, Q.jsxs)(`div`, {
          className: `flex items-center justify-between`,
          children: [
            (0, Q.jsx)(X, {
              htmlFor: d,
              className: t ? `text-sm` : `text-sm text-content-tertiary`,
              children: `Max instances`,
            }),
            (0, Q.jsx)(W, {
              value: r.toString(),
              onValueChange: (e) => c(parseInt(e, 10)),
              disabled: !t,
              id: d,
              size: `sm`,
              className: `w-[72px]`,
              children: Tt(Ct, r)
                .filter((e) => e >= n)
                .map((e) =>
                  (0, Q.jsx)(W.Item, { value: e.toString(), children: (0, Q.jsx)(`span`, { children: e }) }, e),
                ),
            }),
          ],
        }),
        (0, Q.jsxs)(`p`, {
          className: `text-xs text-content-tertiary`,
          children: [
            `Scales automatically based on demand.`,
            ` `,
            (0, Q.jsx)(Le, {
              href: `https://ioi.com/docs/ioi/projects/warm-pools`,
              className: `text-content-tertiary underline`,
              iconSize: `sm`,
              children: `Learn more`,
            }),
          ],
        }),
      ],
    });
  },
  Nt = ({
    envClassId: e,
    enabled: t,
    size: n,
    currentSize: r,
    phase: i,
    failureMessage: a,
    onSizeChange: o,
    onToggle: s,
  }) => {
    let c = (0, Z.useId)();
    return (0, Q.jsxs)(Q.Fragment, {
      children: [
        (0, Q.jsx)(At, { envClassId: e, enabled: t, onToggle: s }),
        t && (0, Q.jsx)(jt, { phase: i, currentSize: r, failureMessage: a }),
        (0, Q.jsxs)(`div`, {
          className: `flex items-center justify-between`,
          children: [
            (0, Q.jsx)(X, {
              htmlFor: c,
              className: t ? `text-sm` : `text-sm text-content-tertiary`,
              children: `Pool size`,
            }),
            (0, Q.jsx)(W, {
              value: n.toString(),
              onValueChange: (e) => o(parseInt(e, 10)),
              disabled: !t,
              id: c,
              size: `sm`,
              className: `w-[72px]`,
              children: Tt(wt, n).map((e) =>
                (0, Q.jsx)(W.Item, { value: e.toString(), children: (0, Q.jsx)(`span`, { children: e }) }, e),
              ),
            }),
          ],
        }),
        (0, Q.jsxs)(`p`, {
          className: `text-xs text-content-tertiary`,
          children: [
            `Upgrade your runner to enable dynamic scaling.`,
            ` `,
            (0, Q.jsx)(Le, {
              href: `https://ioi.com/docs/ioi/projects/warm-pools`,
              className: `text-content-tertiary underline`,
              iconSize: `sm`,
              children: `Learn more`,
            }),
          ],
        }),
      ],
    });
  },
  Pt = ({ projectId: e, prebuildEnabled: n }) => {
    let { value: r } = se(),
      { data: i } = I(),
      o = i?.tier === A.ENTERPRISE,
      { data: c, isLoading: d } = s(e, r && n),
      m = !!c && c.size > 0,
      h = r && (o || m),
      g = l(),
      v = u(),
      y = f(),
      { toast: b } = B(),
      x = (0, Z.useRef)(g);
    x.current = g;
    let S = (0, Z.useRef)(v);
    S.current = v;
    let C = (0, Z.useRef)(y);
    C.current = y;
    let w = (0, Z.useRef)(b);
    w.current = b;
    let T = (0, Z.useRef)(c);
    T.current = c;
    let [E, D] = (0, Z.useState)(new Map()),
      O = (0, Z.useRef)(E);
    return (
      (O.current = E),
      (0, Z.useEffect)(() => {
        c &&
          D((e) => {
            let n = new Map(e);
            for (let [e, r] of c) {
              let i = n.get(e),
                o = t(r);
              i && i.mutating
                ? (i.enabled && !o && n.set(e, { ...i, mutating: !1 }), i.enabled || n.set(e, { ...i, mutating: !1 }))
                : n.set(e, { enabled: !o, minSize: p(r), maxSize: a(r), mutating: !1 });
            }
            for (let [e, t] of n) !c.has(e) && !t.mutating && n.delete(e);
            return n.size === e.size &&
              [...n].every(([t, n]) => {
                let r = e.get(t);
                return (
                  r &&
                  r.enabled === n.enabled &&
                  r.minSize === n.minSize &&
                  r.maxSize === n.maxSize &&
                  r.mutating === n.mutating
                );
              })
              ? e
              : n;
          });
      }, [c]),
      {
        warmPoolsEnabled: h,
        isLoading: d,
        warmPoolsByEnvClass: c,
        warmPoolLocalState: E,
        handleWarmPoolToggle: (0, Z.useCallback)(
          async (t, n, r) => {
            if (n) {
              let n = O.current.get(t),
                i = r?.minSize ?? n?.minSize ?? 1,
                o = r?.maxSize ?? n?.maxSize ?? 1;
              D((e) => {
                let n = new Map(e);
                return (n.set(t, { enabled: !0, minSize: i, maxSize: o, mutating: !0 }), n);
              });
              try {
                (await x.current.mutateAsync({ projectId: e, environmentClassId: t, minSize: i, maxSize: o }),
                  D((e) => {
                    let n = new Map(e),
                      r = n.get(t);
                    return (r && n.set(t, { ...r, mutating: !1 }), n);
                  }));
              } catch (e) {
                (e instanceof _ && e.code === ee.AlreadyExists
                  ? w.current({
                      title: `Warm pool already exists`,
                      description: `A warm pool for this environment class is still active. Wait for it to finish shutting down, then try again.`,
                    })
                  : w.current({ title: `Failed to enable warm pool`, description: F(e) }),
                  D((e) => {
                    let n = new Map(e),
                      r = T.current?.get(t);
                    return (r ? n.set(t, { enabled: !1, minSize: p(r), maxSize: a(r), mutating: !1 }) : n.delete(t), n);
                  }));
              }
            } else {
              let n = O.current.get(t),
                r = n?.minSize ?? 1,
                i = n?.maxSize ?? 1;
              D((e) => {
                let n = new Map(e);
                return (n.set(t, { enabled: !1, minSize: r, maxSize: i, mutating: !0 }), n);
              });
              try {
                let n = T.current?.get(t);
                n?.id && (await C.current.mutateAsync({ warmPoolId: n.id, projectId: e }));
              } catch (e) {
                w.current({ title: `Failed to disable warm pool`, description: F(e) });
                let n = T.current?.get(t);
                D((e) => {
                  let o = new Map(e);
                  return (o.set(t, { enabled: !0, minSize: n ? p(n) : r, maxSize: n ? a(n) : i, mutating: !1 }), o);
                });
              }
            }
          },
          [e],
        ),
        handleWarmPoolSizeChange: (0, Z.useCallback)(
          async (t, n, r) => {
            let i = T.current?.get(t);
            if (i?.id)
              try {
                await S.current.mutateAsync({ warmPoolId: i.id, projectId: e, minSize: n, maxSize: r });
              } catch (e) {
                w.current({ title: `Failed to update warm pool size`, description: F(e) });
              }
          },
          [e],
        ),
      }
    );
  },
  Ft = ({ projectId: e }) => {
    let { data: r } = J(e),
      { hasPermission: i } = K(j.PROJECT, e, `project:update`),
      { hasPermission: o } = K(j.PROJECT, e, `warmpool:create`),
      { data: s, isLoading: l, isError: u } = Me(e),
      { environmentClassEntries: d, isLoading: f } = ke(),
      m = Ne(),
      h = q(),
      { toast: g } = B(),
      _ = r?.prebuildConfiguration?.enabled ?? !1,
      v = (0, Z.useMemo)(
        () => r?.prebuildConfiguration?.environmentClassIds ?? [],
        [r?.prebuildConfiguration?.environmentClassIds],
      ),
      y =
        r?.environmentClass?.environmentClass.case === `environmentClassId`
          ? r.environmentClass.environmentClass.value
          : void 0,
      [b, x] = (0, Z.useState)(v),
      [S, ee] = (0, Z.useState)(v);
    v !== S && (x(v), ee(v));
    let [C, w] = (0, Z.useState)(),
      T = (0, Z.useRef)(!1),
      E = (0, Z.useCallback)(
        async (t) => {
          if (T.current) return;
          let n = new Set((C ?? []).map((e) => e.clazz.id));
          y && n.add(y);
          let i = t.filter((e) => n.has(e));
          if (_ && i.length === 0) {
            g({ title: `At least one environment class must have prebuilds enabled` });
            return;
          }
          (x(i), (T.current = !0));
          try {
            let t = r?.prebuildConfiguration;
            (await h.mutateAsync({
              projectId: e,
              prebuildConfiguration: {
                enabled: t?.enabled,
                trigger: t?.trigger,
                timeout: t?.timeout,
                executor: t?.executor,
                enableJetbrainsWarmup: t?.enableJetbrainsWarmup,
                environmentClassIds: i,
              },
            }),
              $());
          } catch (e) {
            (x(v), g({ title: `Failed to update prebuild classes`, description: F(e) }));
          } finally {
            T.current = !1;
          }
        },
        [C, y, _, e, r?.prebuildConfiguration, v, h, g],
      );
    (0, Z.useEffect)(() => {
      !C &&
        s?.environmentClasses &&
        !f &&
        w(
          s.environmentClasses
            .map((e) => {
              if (e.environmentClass.case === `environmentClassId`)
                return d.find((t) => t.clazz.id === e.environmentClass.value);
            })
            .filter((e) => !!e),
        );
    }, [s, C, d, f]);
    let D = (0, Z.useCallback)(
        async (t) => {
          let n = C,
            r = b,
            i = new Set(t.map((e) => e.clazz.id));
          y && i.add(y);
          let a = b.filter((e) => i.has(e));
          if (_ && b.length > 0 && a.length === 0) {
            g({ title: `At least one environment class must have prebuilds enabled` });
            return;
          }
          if ((w(t), a.length !== b.length && x(a), t.length !== 0))
            try {
              (await m.mutateAsync({ projectId: e, projectEnvironmentClasses: t.map((e, t) => Ae(e, t)) }), $());
            } catch (e) {
              (w(n), x(r), g({ title: `Failed to update environment classes`, description: F(e) }));
            }
        },
        [e, C, b, _, y, m, g],
      ),
      { data: O } = c(_ ? e : void 0),
      te = (0, Z.useMemo)(() => {
        let e = new Map();
        if (!O?.prebuilds) return e;
        for (let t of O.prebuilds) {
          let n = t.metadata?.environmentClassId;
          n && !e.has(n) && e.set(n, t);
        }
        return e;
      }, [O]),
      ne = n(),
      re = (0, Z.useRef)(ne);
    re.current = ne;
    let [ie, ae] = (0, Z.useState)(null),
      oe = (0, Z.useCallback)(
        (t) =>
          b.includes(t)
            ? (0, Q.jsx)(xt, {
                prebuild: te.get(t),
                projectId: e,
                onTriggerPrebuild: () => {
                  (ae(t),
                    re.current.mutate(
                      { projectId: e, environmentClassId: t },
                      {
                        onError: (e) => {
                          g({ title: `Could not run prebuild`, description: F(e) });
                        },
                        onSettled: () => ae(null),
                      },
                    ));
                },
                isTriggeringPrebuild: ie === t,
              })
            : (0, Q.jsx)(`span`, { className: `text-sm text-content-tertiary`, children: `--` }),
        [b, te, e, ie, g],
      ),
      k = Pt({ projectId: e, prebuildEnabled: _ }),
      [se, A] = (0, Z.useState)(new Map()),
      [M, ce] = (0, Z.useState)(!1);
    (0, Z.useEffect)(() => {
      if (!k.warmPoolsByEnvClass || M) return;
      let e = new Map();
      for (let [n, r] of k.warmPoolsByEnvClass) {
        let i = t(r);
        e.set(n, { enabled: !i, minSize: p(r), maxSize: a(r) });
      }
      (A(e), ce(!0));
    }, [k.warmPoolsByEnvClass, M]);
    let N = (0, Z.useRef)(se);
    N.current = se;
    let le = (0, Z.useCallback)(
        (e, t) => {
          let n = N.current.get(e),
            r = n?.minSize ?? 1,
            i = n?.maxSize ?? 1;
          (A((n) => {
            let a = new Map(n);
            return (a.set(e, { enabled: t, minSize: r, maxSize: i }), a);
          }),
            k.handleWarmPoolToggle(e, t, { minSize: r, maxSize: i }));
        },
        [k],
      ),
      P = (0, Z.useCallback)(
        (e, t) => {
          let n = N.current.get(e),
            r = n?.maxSize ?? 1;
          (A((i) => {
            let a = new Map(i);
            return (a.set(e, { enabled: n?.enabled ?? !0, minSize: t, maxSize: r }), a);
          }),
            k.handleWarmPoolSizeChange(e, t, r));
        },
        [k],
      ),
      ue = (0, Z.useCallback)(
        (e, t) => {
          let n = N.current.get(e),
            r = n?.minSize ?? 1;
          (A((i) => {
            let a = new Map(i);
            return (a.set(e, { enabled: n?.enabled ?? !0, minSize: r, maxSize: t }), a);
          }),
            k.handleWarmPoolSizeChange(e, r, t));
        },
        [k],
      ),
      de = (0, Z.useCallback)(
        (e) => {
          let n = C?.find((t) => t.clazz.id === e);
          if (!n) return null;
          let r = De(n, _e.WARM_POOL),
            i = De(n, _e.ASG_WARM_POOL),
            a = k.warmPoolsByEnvClass?.has(e),
            s = b.includes(e),
            c = r && !i;
          if (!s)
            return (0, Q.jsx)(U, {
              content: `Enable prebuilds on this class to configure warm pools`,
              usePortal: !0,
              children: (0, Q.jsx)(`span`, {
                className: `cursor-default text-sm text-content-tertiary`,
                children: `--`,
              }),
            });
          if (!r && !a)
            return (0, Q.jsx)(U, {
              content: (0, Q.jsxs)(`span`, {
                children: [
                  `This runner does not support warm pools.`,
                  ` `,
                  (0, Q.jsx)(Le, {
                    href: `https://ioi.com/docs/ioi/projects/warm-pools#prerequisites`,
                    className: `text-content-tooltip underline`,
                    children: `Learn more`,
                  }),
                ],
              }),
              className: `max-w-[240px]`,
              usePortal: !0,
              children: (0, Q.jsx)(`span`, {
                className: `cursor-default text-sm text-content-tertiary`,
                children: `--`,
              }),
            });
          if (c && !a)
            return (0, Q.jsx)(U, {
              content: (0, Q.jsxs)(`span`, {
                children: [
                  `This runner requires an infrastructure upgrade to support warm pools.`,
                  ` `,
                  (0, Q.jsx)(Le, {
                    href: `https://ioi.com/docs/ioi/runners/aws/update-runner#upgrade-runner-infrastructure`,
                    className: `text-content-tooltip underline`,
                    children: `Learn how to upgrade`,
                  }),
                ],
              }),
              className: `max-w-[280px]`,
              usePortal: !0,
              children: (0, Q.jsx)(`span`, {
                className: `cursor-default text-sm text-content-tertiary`,
                children: `--`,
              }),
            });
          let l = k.isLoading,
            u = se.get(e),
            d = u?.enabled ?? !1,
            f = u?.minSize ?? 1,
            p = u?.maxSize ?? 1,
            m = k.warmPoolsByEnvClass?.get(e),
            h = m?.status?.phase,
            g = m?.status?.failureMessage,
            _ = m?.status?.desiredSize,
            v = !!m && t(m),
            y = k.warmPoolLocalState.get(e)?.mutating ?? !1;
          return (0, Q.jsx)(kt, {
            envClassId: e,
            enabled: v ? !1 : d,
            minSize: f,
            maxSize: p,
            supportsScaling: i,
            currentSize: _,
            onToggle: (t) => le(e, t),
            onMinSizeChange: (t) => P(e, t),
            onMaxSizeChange: (t) => ue(e, t),
            disabled: !o || v || y || l,
            disabledReason: o ? void 0 : `Only project admins can manage warm pools`,
            isLoading: y || l,
            isCleaningUp: v,
            phase: h,
            failureMessage: g,
            legacyWarning: c,
          });
        },
        [C, b, k, se, le, P, ue, o],
      );
    return (0, Q.jsx)(bt, {
      entries: C,
      allEntries: d,
      onChange: D,
      loading: (f || l) && !C?.length,
      error: u,
      disabled: !i,
      showPrebuildColumn: _,
      prebuildSelectedIds: b,
      onPrebuildSelectionChange: E,
      showWarmPoolColumn: _ && k.warmPoolsEnabled,
      showPrebuildStatusColumn: _,
      renderWarmPoolCell: de,
      renderPrebuildStatusCell: oe,
    });
  },
  It = e(E(), 1),
  Lt = ({ value: e, onChange: t, disabled: n = !1 }) => {
    let [r, i] = (0, Z.useState)(!1),
      { data: a, isLoading: o } = N({ allowedByPolicy: !0 }),
      s = (0, Z.useMemo)(() => (a?.editors ? a.editors.filter((t) => t.alias && t.alias in e) : []), [a, e]),
      c = (0, Z.useCallback)(
        (e) => {
          (t(e), i(!1));
        },
        [t],
      );
    return (0, Q.jsxs)(`div`, {
      className: `flex flex-col gap-2`,
      children: [
        (0, Q.jsxs)(`div`, {
          className: `flex items-center justify-between`,
          children: [
            (0, Q.jsx)(Ce, {
              className: `text-sm text-content-secondary`,
              children:
                s.length === 0 ? `No editors recommended` : `${s.length} editor${s.length > 1 ? `s` : ``} recommended`,
            }),
            (0, Q.jsx)(V, {
              type: `button`,
              disabled: n,
              onClick: () => i(!0),
              variant: `secondary`,
              size: `sm`,
              "data-testid": `manage-recommended-editors-button`,
              "data-tracking-id": `manage-recommended-editors-element`,
              children: s.length === 0 ? `Add` : `Manage`,
            }),
          ],
        }),
        (0, Q.jsx)(G, {
          ready: !o,
          children:
            s.length > 0 &&
            (0, Q.jsx)(`div`, {
              className: `flex flex-wrap gap-2`,
              children: s.map((r) =>
                (0, Q.jsx)(
                  Rt,
                  {
                    editor: r,
                    versions: r.alias ? e[r.alias] : [],
                    onRemove: n
                      ? void 0
                      : () => {
                          if (!r.alias) return;
                          let n = { ...e };
                          (delete n[r.alias], t(n));
                        },
                  },
                  r.id,
                ),
              ),
            }),
        }),
        r &&
          a?.editors &&
          (0, Q.jsx)(zt, { onClose: () => i(!1), onSave: c, editors: a.editors, initialValue: e, disabled: n }),
      ],
    });
  },
  Rt = ({ editor: e, versions: t, onRemove: n }) => {
    let r = t && t.length > 0;
    return (0, Q.jsxs)(`div`, {
      className: `inline-flex h-9 select-none items-center gap-2 whitespace-nowrap rounded-xl border-0.5 border-border-base bg-surface-primary p-2 px-3 text-base font-medium`,
      children: [
        (0, Q.jsx)(Fe, { editor: e, size: `base` }),
        (0, Q.jsx)(`span`, { children: e.name }),
        r &&
          (0, Q.jsx)(`span`, {
            className: `rounded-md bg-surface-secondary px-2 py-0.5 text-xs text-content-secondary`,
            children: t.join(`, `),
          }),
        n &&
          (0, Q.jsx)(`button`, {
            type: `button`,
            onClick: n,
            className: `ml-1 rounded-full p-0.5 hover:bg-surface-secondary`,
            "aria-label": `Remove ${e.name}`,
            "data-tracking-id": `remove-recommended-editors-version-button`,
            children: (0, Q.jsx)(O, { className: `h-3 w-3 text-content-secondary` }),
          }),
      ],
    });
  },
  zt = ({ onClose: e, onSave: t, editors: n, initialValue: r, disabled: i = !1 }) => {
    let [a, o] = (0, Z.useState)(() => {
        let e = {};
        return (
          n.forEach((t) => {
            t.alias && (e[t.alias] = t.alias in r);
          }),
          e
        );
      }),
      [s, c] = (0, Z.useState)(() => ({ ...r })),
      [l, u] = (0, Z.useState)(!1),
      d = (0, Z.useCallback)(
        (t) => {
          t || e();
        },
        [e],
      ),
      f = (0, Z.useCallback)(() => {
        let e = {};
        (Object.entries(a).forEach(([t, n]) => {
          n && (e[t] = s[t] || []);
        }),
          t(e));
      }, [a, s, t]),
      p = (0, Z.useCallback)((e, t) => {
        (o((n) => ({ ...n, [e]: t })), u(!0));
      }, []),
      m = (0, Z.useCallback)((e, t) => {
        (c((n) => ({
          ...n,
          [e]: t.sort((e, t) => {
            let n = It.coerce(e),
              r = It.coerce(t);
            return n === null || r === null ? t.localeCompare(e) : It.compare(r, n);
          }),
        })),
          u(!0));
      }, []),
      h = (0, Z.useMemo)(() => n.filter((e) => !!e.alias), [n]);
    return (0, Q.jsx)(H, {
      open: !0,
      onOpenChange: d,
      children: (0, Q.jsxs)(H.Content, {
        className: `max-w-[600px]`,
        "data-testid": `recommended-editors-modal`,
        "data-track-location": k.RecommendedEditorsModal,
        children: [
          (0, Q.jsxs)(H.Header, {
            children: [
              (0, Q.jsx)(H.Title, { children: `Recommended editors` }),
              (0, Q.jsx)(H.Description, {
                children: `Select editors to recommend for this project. Users will see these as suggested options.`,
              }),
            ],
          }),
          (0, Q.jsx)(H.Body, {
            className: `max-h-[400px] space-y-1 overflow-y-auto`,
            children: h.map((e, t) => {
              let n = e.alias,
                r = e.versions?.map((e) => e.version) || [],
                o = r.length > 0,
                c = s[n] || [],
                l = c.length > 0,
                u = a[n];
              return (0, Q.jsxs)(
                `div`,
                {
                  children: [
                    (0, Q.jsxs)(`div`, {
                      className: `group flex min-h-[36px] flex-row items-center gap-3`,
                      children: [
                        (0, Q.jsx)(Ke, {
                          disabled: i,
                          state: u ? `checked` : `unchecked`,
                          onToggle: (e) => p(n, e),
                          id: `editor-toggle-${t}`,
                        }),
                        (0, Q.jsxs)(`div`, {
                          className: `flex flex-row items-center gap-2`,
                          children: [
                            (0, Q.jsx)(Fe, { editor: e, size: `base` }),
                            (0, Q.jsx)(`span`, { children: e.name }),
                          ],
                        }),
                        (0, Q.jsx)(`div`, {
                          className: `ml-auto flex items-center gap-2`,
                          children:
                            o &&
                            u &&
                            (0, Q.jsxs)(Te, {
                              children: [
                                (0, Q.jsx)(Te.Trigger, {
                                  asChild: !0,
                                  children: (0, Q.jsxs)(V, {
                                    disabled: i,
                                    variant: `secondary`,
                                    size: `md`,
                                    className: `font-sm h-7 gap-1 rounded-lg px-2 py-1.5 font-sans text-sm tracking-tight text-content-primary`,
                                    children: [`add version`, (0, Q.jsx)(S, { className: `h-3 w-3 opacity-60` })],
                                  }),
                                }),
                                (0, Q.jsxs)(Te.Content, {
                                  align: `end`,
                                  className: `min-w-[200px] !pb-0`,
                                  onCloseAutoFocus: (e) => e.preventDefault(),
                                  children: [
                                    r.map((e, t) =>
                                      (0, Q.jsxs)(
                                        X,
                                        {
                                          className: `relative flex cursor-pointer select-none items-center gap-2 rounded-md px-3 py-2 text-sm hover:bg-surface-hover`,
                                          children: [
                                            (0, Q.jsx)(Ve, {
                                              id: `${n}-${e}`,
                                              checked: c.includes(e),
                                              onCheckedChange: (t) => {
                                                m(n, t ? [...c, e] : c.filter((t) => t !== e));
                                              },
                                            }),
                                            e,
                                            t === 0 &&
                                              (0, Q.jsx)(`span`, {
                                                className: `ml-auto rounded-md bg-surface-secondary px-2 py-0.5 text-xs text-content-secondary`,
                                                children: `latest`,
                                              }),
                                          ],
                                        },
                                        e,
                                      ),
                                    ),
                                    c.length === 0 &&
                                      (0, Q.jsxs)(`div`, {
                                        className: `flex items-start gap-2 bg-surface-button-clear-accent px-3 py-2`,
                                        children: [
                                          (0, Q.jsx)(g, { className: `mt-0.5 h-4 w-4 shrink-0 text-content-brand` }),
                                          (0, Q.jsx)(`span`, {
                                            className: `text-sm text-content-brand`,
                                            children: `No selection means all versions are recommended`,
                                          }),
                                        ],
                                      }),
                                  ],
                                }),
                              ],
                            }),
                        }),
                      ],
                    }),
                    o &&
                      l &&
                      u &&
                      (0, Q.jsx)(`div`, {
                        className: `ml-12 flex flex-wrap items-center gap-1 pb-2`,
                        children: c.map((e) =>
                          (0, Q.jsxs)(
                            `span`,
                            {
                              className: `inline-flex h-6 items-center gap-0.5 rounded-[20px] bg-surface-brand px-2 py-1 font-mono text-xs font-normal text-[rgb(var(--ioi-blue-500))]`,
                              children: [
                                e,
                                (0, Q.jsx)(`button`, {
                                  type: `button`,
                                  disabled: i,
                                  onClick: (t) => {
                                    (t.stopPropagation(),
                                      m(
                                        n,
                                        c.filter((t) => t !== e),
                                      ));
                                  },
                                  className: `ml-0.5 rounded-full hover:bg-surface-secondary`,
                                  "data-tracking-id": `remove-version-button`,
                                  children: (0, Q.jsx)(O, { className: `h-3 w-3` }),
                                }),
                              ],
                            },
                            e,
                          ),
                        ),
                      }),
                  ],
                },
                e.id,
              );
            }),
          }),
          (0, Q.jsxs)(H.Footer, {
            children: [
              (0, Q.jsx)(H.Close, {
                asChild: !0,
                children: (0, Q.jsx)(V, { variant: `secondary`, children: `Cancel` }),
              }),
              (0, Q.jsx)(V, {
                variant: `primary`,
                onClick: f,
                disabled: i || !l,
                "data-tracking-id": `save`,
                children: `Save`,
              }),
            ],
          }),
        ],
      }),
    });
  },
  Bt = ({ value: e, onChange: t, disabled: n }) =>
    (0, Q.jsx)(`div`, {
      className: `rounded-lg border border-border-base p-4`,
      children: (0, Q.jsxs)(`div`, {
        className: `flex flex-col gap-3`,
        children: [
          (0, Q.jsxs)(`div`, {
            className: `flex flex-col gap-1`,
            children: [
              (0, Q.jsx)(Ce, { className: `text-base font-medium`, children: `Recommended Editors` }),
              (0, Q.jsx)(Ce, {
                className: `text-sm text-content-secondary`,
                children: `Suggest editors for this project. Users will see these as recommended options when opening environments.`,
              }),
            ],
          }),
          (0, Q.jsx)(Lt, { value: e, onChange: t, disabled: n }),
        ],
      }),
    }),
  Vt = ({ projectId: e }) => {
    let { data: t } = J(e),
      { hasPermission: n } = K(j.PROJECT, e, `project:update`),
      r = q(),
      { toast: i } = B();
    return (0, Q.jsx)(Bt, {
      value: (0, Z.useMemo)(() => {
        let e = {};
        return (
          t?.recommendedEditors?.editors &&
            Object.entries(t.recommendedEditors.editors).forEach(([t, n]) => {
              e[t] = n?.versions || [];
            }),
          e
        );
      }, [t?.recommendedEditors]),
      onChange: (0, Z.useCallback)(
        async (t) => {
          let n = {};
          Object.entries(t).forEach(([e, t]) => {
            n[e] = w(he, { versions: t });
          });
          try {
            (await r.mutateAsync({ projectId: e, recommendedEditors: w(de, { editors: n }) }), $());
          } catch (e) {
            i({ title: `Failed to update recommended editors`, description: F(e) });
          }
        },
        [e, r, i],
      ),
      disabled: !n,
    });
  };
function Ht(e) {
  return e.trim()
    ? /(?:^|\/)\.?devcontainer\.json$/.test(e)
      ? ``
      : `Filename must be devcontainer.json or .devcontainer.json`
    : ``;
}
var Ut = ({ value: e, onChange: t, onBlur: n, disabled: r, error: i }) => {
    let a = (0, Z.useId)(),
      o = Ht(e);
    return (0, Q.jsx)(We, {
      label: (0, Q.jsxs)(Q.Fragment, {
        children: [
          `Dev Container file path `,
          (0, Q.jsx)(`span`, { className: `font-normal text-content-secondary`, children: `(optional)` }),
        ],
      }),
      id: a,
      hint: `Example: .devcontainer/devcontainer.json`,
      error: i || o,
      children: (0, Q.jsx)(Se, {
        id: a,
        type: `text`,
        value: e,
        disabled: r,
        onChange: (e) => t(e.target.value),
        onBlur: n,
        placeholder: `default: auto discovered`,
        "data-testid": `project-dev-container-path`,
      }),
    });
  },
  Wt = ({ projectId: e }) => {
    let { data: t } = J(e),
      { hasPermission: n } = K(j.PROJECT, e, `project:update`),
      r = q(),
      { toast: i } = B(),
      [a, o] = (0, Z.useState)(),
      s = t?.devcontainerFilePath ?? ``,
      [c, l] = (0, Z.useState)(s),
      [u, d] = (0, Z.useState)(s);
    return (
      s !== u && s !== c && (l(s), d(s)),
      (0, Q.jsx)(Ut, {
        value: c,
        onChange: l,
        onBlur: (0, Z.useCallback)(async () => {
          if (c === u) {
            o(void 0);
            return;
          }
          let t = Ht(c);
          if (t) {
            o(t);
            return;
          }
          o(void 0);
          try {
            (await r.mutateAsync({ projectId: e, devcontainerFilePath: c }), d(c), $());
          } catch (e) {
            (o(`Failed to save`), i({ title: `Failed to update devcontainer file path`, description: F(e) }));
          }
        }, [c, u, e, r, i]),
        disabled: !n,
        error: a,
      })
    );
  },
  Gt = ({ value: e, onChange: t, onBlur: n, disabled: r, error: i }) => {
    let a = (0, Z.useId)();
    return (0, Q.jsx)(We, {
      label: (0, Q.jsxs)(Q.Fragment, {
        children: [
          `Automations file path `,
          (0, Q.jsx)(`span`, { className: `font-normal text-content-secondary`, children: `(optional)` }),
        ],
      }),
      id: a,
      hint: `Example: backend/automations.yaml`,
      error: i,
      children: (0, Q.jsx)(Se, {
        id: a,
        type: `text`,
        value: e,
        disabled: r,
        onChange: (e) => t(e.target.value),
        onBlur: n,
        placeholder: `default: .ioi/automations.yaml`,
        "data-testid": `project-automations-path`,
      }),
    });
  },
  Kt = ({ projectId: e }) => {
    let { data: t } = J(e),
      { hasPermission: n } = K(j.PROJECT, e, `project:update`),
      r = q(),
      { toast: i } = B(),
      [a, o] = (0, Z.useState)(),
      s = t?.automationsFilePath ?? ``,
      [c, l] = (0, Z.useState)(s),
      [u, d] = (0, Z.useState)(s);
    return (
      s !== u && s !== c && (l(s), d(s)),
      (0, Q.jsx)(Gt, {
        value: c,
        onChange: l,
        onBlur: (0, Z.useCallback)(async () => {
          if (c === u) {
            o(void 0);
            return;
          }
          o(void 0);
          try {
            (await r.mutateAsync({ projectId: e, automationsFilePath: c }), d(c), $());
          } catch (e) {
            (o(`Failed to save`), i({ title: `Failed to update automations file path`, description: F(e) }));
          }
        }, [c, u, e, r, i]),
        disabled: !n,
        error: a,
      })
    );
  },
  qt = ({
    id: e,
    enabled: t,
    onToggle: n,
    isLoading: r,
    disabled: i,
    description:
      a = `Automatically analyze development activity for this project to surface actionable insights. This runs automated analyses which incur usage costs.`,
  }) =>
    (0, Q.jsx)(`div`, {
      className: `rounded-lg border border-border-base p-4`,
      children: (0, Q.jsxs)(`div`, {
        className: `flex gap-4`,
        children: [
          (0, Q.jsx)(Ke, {
            id: e,
            state: t ? `checked` : `unchecked`,
            onToggle: n,
            isLoading: r,
            disabled: i,
            "aria-label": t ? `Disable project insights` : `Enable project insights`,
            "data-testid": `${e}-toggle`,
            "data-tracking-id": `${e}-toggle`,
          }),
          (0, Q.jsxs)(`div`, {
            className: `flex flex-col gap-1`,
            children: [
              (0, Q.jsx)(`label`, { className: `cursor-pointer font-bold`, htmlFor: e, children: `Insights` }),
              (0, Q.jsx)(Ce, { className: `text-sm text-content-secondary`, children: a }),
            ],
          }),
        ],
      }),
    }),
  Jt = ({ projectId: e }) => {
    let { value: t } = pe(),
      { data: n } = I(),
      r = n?.tier === A.ENTERPRISE,
      { hasPermission: i } = K(j.PROJECT, e, `project:insights_write`),
      { toast: a } = B(),
      { data: o, isLoading: s } = rt(e),
      c = tt(e),
      l = $e(e);
    if (!t || !r || s) return null;
    let u = o?.enabled ?? !1,
      d = c.isPending || l.isPending;
    return (0, Q.jsx)(`div`, {
      "data-testid": `insights-settings-section`,
      children: (0, Q.jsx)(qt, {
        id: `insights-enabled-switch`,
        enabled: u,
        onToggle: (t) => {
          (t ? c : l).mutate(void 0, {
            onSuccess: () => {
              $();
            },
            onError: (n) => {
              if (t) {
                let { title: t, description: r, action: i } = et(n),
                  o = i ? nt(i.target, { projectId: e }) : void 0;
                a({
                  type: `error`,
                  title: t,
                  description: r,
                  indefinite: !0,
                  link: i && o ? { label: i.label, href: o } : void 0,
                });
              } else a({ type: `error`, title: `Failed to disable insights`, description: F(n), indefinite: !0 });
            },
          });
        },
        isLoading: d,
        disabled: !i,
      }),
    });
  },
  Yt = ({ project: e }) =>
    (0, Q.jsxs)(`div`, {
      className: `flex max-w-3xl flex-col gap-6 [&_input]:max-w-full`,
      "data-testid": `project-details-form`,
      children: [
        (0, Q.jsx)(ct, { projectId: e.id }),
        (0, Q.jsx)(ut, { projectId: e.id }),
        (0, Q.jsx)(ft, { projectId: e.id }),
        (0, Q.jsx)(`div`, {
          id: `prebuilds`,
          className: `scroll-mt-16`,
          children: (0, Q.jsx)(yt, { projectId: e.id }),
        }),
        (0, Q.jsx)(`div`, {
          id: `environment-classes`,
          className: `scroll-mt-16`,
          children: (0, Q.jsx)(Ft, { projectId: e.id }),
        }),
        (0, Q.jsx)(`div`, { id: `editors`, className: `scroll-mt-16`, children: (0, Q.jsx)(Vt, { projectId: e.id }) }),
        (0, Q.jsx)(`div`, {
          id: `devcontainer`,
          className: `scroll-mt-16`,
          children: (0, Q.jsx)(Wt, { projectId: e.id }),
        }),
        (0, Q.jsx)(`div`, {
          id: `automations`,
          className: `scroll-mt-16`,
          children: (0, Q.jsx)(Kt, { projectId: e.id }),
        }),
        (0, Q.jsx)(`div`, { id: `insights`, className: `scroll-mt-16`, children: (0, Q.jsx)(Jt, { projectId: e.id }) }),
      ],
    }),
  Xt = () => {
    let { projectId: e } = ie(),
      t = re(),
      { data: n, error: r, isPending: i } = J(e);
    (0, Z.useEffect)(() => {
      if (!t.hash || i) return;
      let e = t.hash.slice(1),
        n = requestAnimationFrame(() => {
          document.getElementById(e)?.scrollIntoView({ behavior: `smooth`, block: `start` });
        });
      return () => cancelAnimationFrame(n);
    }, [t.hash, i]);
    let a = null;
    return (
      (a = i
        ? (0, Q.jsx)(Zt, {})
        : r || !e
          ? (0, Q.jsx)(at, { error: r })
          : (0, Q.jsx)(Q.Fragment, { children: n && (0, Q.jsx)(Yt, { project: n }, e) })),
      (0, Q.jsx)(`div`, { "data-testid": `project-details-settings-page`, children: a })
    );
  },
  Zt = () =>
    (0, Q.jsxs)(`div`, {
      className: `flex max-w-3xl flex-col gap-5`,
      children: [
        (0, Q.jsxs)(`div`, {
          className: `flex flex-col gap-1`,
          children: [
            (0, Q.jsx)(we, { size: `lg`, ready: !1, className: `w-[120px]` }),
            (0, Q.jsx)(G, { ready: !1, className: `h-9 w-full` }),
          ],
        }),
        (0, Q.jsxs)(`div`, {
          className: `flex flex-col gap-1`,
          children: [
            (0, Q.jsx)(we, { size: `lg`, ready: !1, className: `w-[120px]` }),
            (0, Q.jsx)(G, { ready: !1, className: `h-9 w-full` }),
          ],
        }),
        (0, Q.jsxs)(`div`, {
          className: `flex flex-col gap-1`,
          children: [
            (0, Q.jsx)(we, { size: `lg`, ready: !1, className: `w-[135px]` }),
            (0, Q.jsx)(G, { ready: !1, className: `h-14 w-full` }),
          ],
        }),
        (0, Q.jsxs)(`div`, {
          className: `flex flex-col gap-1`,
          children: [
            (0, Q.jsx)(we, { size: `lg`, ready: !1, className: `w-[160px]` }),
            (0, Q.jsx)(G, { ready: !1, className: `h-9 w-full` }),
          ],
        }),
        (0, Q.jsxs)(`div`, {
          className: `flex flex-col gap-1`,
          children: [
            (0, Q.jsx)(we, { size: `lg`, ready: !1, className: `w-[150px]` }),
            (0, Q.jsx)(G, { ready: !1, className: `h-9 w-full` }),
          ],
        }),
        (0, Q.jsx)(G, { ready: !1, className: `h-8 w-32` }),
      ],
    });
export { Xt as ProjectSettingsPage };

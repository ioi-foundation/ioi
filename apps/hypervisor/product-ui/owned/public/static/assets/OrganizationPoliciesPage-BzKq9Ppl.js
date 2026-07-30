import { a as e } from "./rolldown-runtime-CGYlQKCx.js";
import { It as t, Lt as n, _n as r, dt as i, vn as a } from "./SegmentProvider-CXCNBY9U.js";
import { n as o } from "./@mux-DLaEVubF.js";
import {
  $f as s,
  Op as c,
  cg as l,
  eg as u,
  g_ as d,
  i as f,
  i_ as p,
  kf as m,
  qh as h,
  v_ as g,
} from "./vendor-DAwbZtf0.js";
import {
  Bi as _,
  Dr as v,
  Dt as y,
  Eo as b,
  Fi as x,
  Fo as S,
  Ki as C,
  Li as w,
  Lr as T,
  Mo as E,
  Pn as D,
  Po as O,
  Qa as k,
  Ro as ee,
  To as A,
  Un as j,
  V as M,
  Xi as N,
  ct as P,
  j as te,
  jt as ne,
  k as re,
  ki as ie,
  m as ae,
  qi as oe,
  s as se,
  so as F,
  tn as I,
  tr as L,
  u as ce,
  vn as le,
} from "./use-boot-in-app-chat-t-J_VjKS.js";
import { n as R } from "./toast-axaLeIzZ.js";
import { a as ue, t as z } from "./button-6YP03Qf2.js";
import { t as B } from "./cn-DppMFCU8.js";
import { t as V } from "./dialog-BtjFqa-w.js";
import { t as de } from "./use-membership-CcV5kGny.js";
import { t as fe } from "./banner-CFcSGYsz.js";
import { l as H } from "./time-DxjbKG-a.js";
import { r as U } from "./headings-CM9JBOhQ.js";
import { t as W } from "./input-C42Z_4fO.js";
import { t as pe } from "./tooltip-6hqVQbwq.js";
import { t as G } from "./text-fFCFeCas.js";
import { t as K } from "./select-Ceshp72e.js";
import { t as q } from "./skeleton-Cm867Q_k.js";
import { t as me } from "./use-resource-permission-Dd1Jv7de.js";
import { r as J } from "./dropdown-menu-D3UmjGpQ.js";
import { E as he, H as ge, M as _e, R as ve, h as ye } from "./environment-queries-zpiLcWfm.js";
import { o as be, s as xe } from "./use-environment-class-entries-DPBxsgJb.js";
import { c as Se, r as Ce } from "./secret-queries-DrL94GSz.js";
import { t as we } from "./collapsible-CijQ-f1P.js";
import { t as Te } from "./EditorIcon-CXY7bnUG.js";
import { t as Ee } from "./IconDot-JLZkI4_Z.js";
import { i as De } from "./environment-paa_Ds61.js";
import { t as Oe } from "./EnvironmentStatusDot-BqbKxNCW.js";
import { t as ke } from "./IconChevronDownSmall-9zzbc23a.js";
import { t as Y } from "./external-link-BKbp1Q22.js";
import { t as Ae } from "./button-group-BAfnksgW.js";
import { t as je } from "./details-url-BbcIdGZp.js";
import { t as Me } from "./checkbox-nHTWcF6W.js";
import { t as Ne } from "./error-message-Az-KJctk.js";
import { t as Pe } from "./label-5ATlPnPj.js";
import { t as X } from "./form-control-BfDRQ8Xb.js";
import { t as Fe } from "./switch-CiuLW56f.js";
import { t as Ie } from "./checkbox-input-field-BnHkIfK1.js";
import { t as Le } from "./IconCheck-CjhQLbZQ.js";
import { t as Re } from "./IconWarningCircle-9yrh1wLR.js";
import { t as ze } from "./password-input-CUNYKhA6.js";
import { t as Be } from "./lifetime-C1J-eirn.js";
import { t as Ve } from "./IconSettings-DVEKmYpA.js";
import { r as He } from "./scim-queries-cZ83dwae.js";
var Z = e(o(), 1),
  Q = g(),
  Ue = ({ editable: e = !0 }) => {
    let { data: t, isLoading: n } = I(),
      r = D(),
      { toast: i } = R(),
      a = (0, Z.useMemo)(() => {
        let e = t?.archiveEnvironmentsAfter?.seconds;
        return typeof e == `bigint` ? Number(e) : 4320 * 60;
      }, [t]),
      o = (0, Z.useMemo)(() => {
        let e = [
          { label: `1 day`, value: 1440 * 60 },
          { label: `2 days`, value: 2880 * 60 },
          { label: `3 days`, value: 4320 * 60 },
          { label: `5 days`, value: 7200 * 60 },
          { label: `1 week`, value: 10080 * 60 },
          { label: `2 weeks`, value: 336 * 60 * 60 },
          { label: `4 weeks`, value: 672 * 60 * 60 },
          { label: `30 days`, value: 720 * 60 * 60 },
        ];
        return (e.some((e) => e.value === a) || e.push({ label: H(a, `long`), value: a }), e);
      }, [a]),
      s = (0, Z.useCallback)(
        async (e) => {
          let t = { archiveEnvironmentsAfter: d(p, { seconds: BigInt(parseInt(e, 10)), nanos: 0 }) };
          try {
            (await r.mutateAsync(t), i({ title: `Archive setting updated` }));
          } catch (e) {
            (console.error(e),
              i({ title: `We couldn't save your changes. Sorry about that! Please retry.`, description: L(e) }));
          }
        },
        [r, i],
      );
    return (0, Q.jsx)(`div`, {
      className: `flex flex-col gap-3 rounded-lg border border-border-subtle px-5 py-4`,
      children: (0, Q.jsxs)(q, {
        ready: !n,
        children: [
          (0, Q.jsxs)(`div`, {
            className: `flex flex-col gap-0.5`,
            children: [
              (0, Q.jsx)(U, { className: `text-base`, children: `Archive inactive environments` }),
              (0, Q.jsx)(G, {
                className: `text-sm text-content-secondary`,
                children: `Controls when stopped environments move to Archived.`,
              }),
            ],
          }),
          (0, Q.jsx)(K, {
            "data-testid": `archive-environments-after-select`,
            name: `archive-environments-after`,
            value: a.toString(),
            onValueChange: s,
            disabled: !e,
            placeholder: `Select archive period`,
            className: `w-full max-w-lg`,
            children: o.map((e) => (0, Q.jsx)(K.Item, { value: e.value.toString(), children: e.label }, e.value)),
          }),
        ],
      }),
    });
  },
  We = ({ editable: e = !0 }) => {
    let { data: t, isLoading: n } = I(),
      r = D(),
      { toast: i } = R(),
      a = (0, Z.useMemo)(() => {
        let e = t?.deleteArchivedEnvironmentsAfter?.seconds;
        return typeof e == `bigint` ? Number(e) : 0;
      }, [t]),
      o = (0, Z.useMemo)(() => {
        let e = [
          { label: `1 day`, value: 1440 * 60 },
          { label: `2 days`, value: 2880 * 60 },
          { label: `3 days`, value: 4320 * 60 },
          { label: `5 days`, value: 7200 * 60 },
          { label: `1 week`, value: 10080 * 60 },
          { label: `2 weeks`, value: 336 * 60 * 60 },
          { label: `4 weeks`, value: 672 * 60 * 60 },
          { label: `Never`, value: 0 },
        ];
        return (e.some((e) => e.value === a) || e.push({ label: H(a, `long`), value: a }), e);
      }, [a]),
      s = (0, Z.useCallback)(
        async (e) => {
          let t = { deleteArchivedEnvironmentsAfter: d(p, { seconds: BigInt(parseInt(e, 10)), nanos: 0 }) };
          try {
            (await r.mutateAsync(t), i({ title: `Auto-delete setting updated` }));
          } catch (e) {
            (console.error(e),
              i({ title: `We couldn't save your changes. Sorry about that! Please retry.`, description: L(e) }));
          }
        },
        [r, i],
      );
    return (0, Q.jsx)(`div`, {
      className: `flex flex-col gap-3 rounded-lg border border-border-subtle px-5 py-4`,
      children: (0, Q.jsxs)(q, {
        ready: !n,
        children: [
          (0, Q.jsxs)(`div`, {
            className: `flex flex-col gap-0.5`,
            children: [
              (0, Q.jsx)(U, { className: `text-base`, children: `Auto-delete archived environments` }),
              (0, Q.jsx)(G, {
                className: `text-sm text-content-secondary`,
                children: `Controls the maximum time an environment stays archived, before deletion.`,
              }),
            ],
          }),
          (0, Q.jsx)(K, {
            "data-testid": `auto-delete-archived-environments-select`,
            name: `auto-delete-archived-environments`,
            value: a.toString(),
            onValueChange: s,
            disabled: !e,
            placeholder: `Select auto-delete period`,
            className: `w-full max-w-lg`,
            children: o.map((e) => (0, Q.jsx)(K.Item, { value: e.value.toString(), children: e.label }, e.value)),
          }),
        ],
      }),
    });
  },
  Ge = e(f(), 1),
  Ke = ({ editable: e = !0 }) => {
    let [t, n] = (0, Z.useState)(!1),
      { data: r, isLoading: i } = j(),
      { data: a, isLoading: o } = I(),
      s = i || o,
      c = (0, Z.useMemo)(
        () =>
          a?.allowedEditorIds && a?.allowedEditorIds.length === 0
            ? r?.editors || []
            : r?.editors.filter((e) => a?.allowedEditorIds.includes(e.id)) || [],
        [r, a],
      );
    return (0, Q.jsxs)(`div`, {
      className: `flex flex-col gap-4 rounded-lg border border-border-subtle px-5 py-4`,
      children: [
        (0, Q.jsxs)(`div`, {
          className: `flex items-center justify-between`,
          children: [
            (0, Q.jsx)(U, { children: `Available editors` }),
            (0, Q.jsx)(z, {
              "data-testid": `manage-editors-button`,
              disabled: !e,
              onClick: () => n(!0),
              variant: `secondary`,
              size: `sm`,
              "data-tracking-id": `manage-editors-available-editors-element`,
              children: `Manage`,
            }),
          ],
        }),
        (0, Q.jsx)(q, {
          ready: !s && c.length > 0,
          children: (0, Q.jsx)(`div`, {
            className: `flex flex-wrap gap-2`,
            children: c.map((e, t) =>
              (0, Q.jsx)(qe, { editor: e, isDefault: e.id === a?.defaultEditorId }, `${e.id}-${t}`),
            ),
          }),
        }),
        t &&
          a &&
          (0, Q.jsx)(Je, {
            "data-testid": `manage-editors-modal`,
            onClose: () => n(!1),
            editors: r?.editors || [],
            policies: a,
            editable: e,
          }),
      ],
    });
  },
  qe = ({ editor: e, isDefault: t }) =>
    (0, Q.jsxs)(`div`, {
      className: B(
        `inline-flex h-9 select-none items-center gap-2 whitespace-nowrap rounded-xl border-0.5 bg-surface-primary p-2 px-4 pb-[6.5px] pt-[5.5px] text-base font-medium`,
        t ? `border-border-brand` : `border-border-base`,
      ),
      children: [
        (0, Q.jsx)(Te, { editor: e, size: `base` }),
        (0, Q.jsx)(`span`, { children: e.name }),
        t &&
          (0, Q.jsx)(`span`, {
            className: `rounded-md bg-surface-secondary px-2 py-0.5 text-xs text-content-secondary`,
            children: `default`,
          }),
      ],
    }),
  Je = ({ onClose: e, editors: t, policies: n, editable: r = !0 }) => {
    let [i, a] = (0, Z.useState)(() =>
        n.allowedEditorIds.length > 0
          ? n.allowedEditorIds.reduce((e, t) => ((e[t] = !0), e), {})
          : t.reduce((e, t) => ((e[t.id] = !0), e), {}),
      ),
      [o, l] = (0, Z.useState)(n.defaultEditorId || `invalid`),
      [u, f] = (0, Z.useState)(() => {
        let e = {};
        return (
          n.editorVersionRestrictions &&
            Object.entries(n.editorVersionRestrictions).forEach(([t, n]) => {
              e[t] = n.allowedVersions || [];
            }),
          e
        );
      }),
      [p, h] = (0, Z.useState)(!1),
      g = (0, Z.useMemo)(() => !Object.entries(i).some(([e, t]) => t), [i]),
      _ = (0, Z.useCallback)(
        (t) => {
          t || e();
        },
        [e],
      ),
      v = D(),
      { toast: b } = R(),
      x = (0, Z.useCallback)(async () => {
        let n = {
          allowedEditorIds: Object.entries(i)
            .filter(([e, t]) => t)
            .map(([e]) => e),
        };
        o !== `invalid` && (n.defaultEditorId = o);
        let r = {};
        (t.forEach((e) => {
          let t = u[e.id] || [];
          r[e.id] = d(ie, { allowedVersions: t });
        }),
          (n.editorVersionRestrictions = r));
        try {
          (await v.mutateAsync(n), e());
        } catch (e) {
          (console.error(e),
            b({ title: `We couldn't save your changes. Sorry about that! Please retry.`, description: L(e) }));
        }
      }, [i, o, u, t, v, e, b]),
      S = (0, Z.useCallback)(
        (e, t) => {
          if ((a((n) => ({ ...n, [e]: t })), h(!0), !t && o === e)) {
            let t = Object.entries(i).find(([t, n]) => n && t !== e)?.[0];
            l(t || `invalid`);
          }
          t && o === `invalid` && l(e);
        },
        [o, i],
      ),
      C = (0, Z.useCallback)((e) => {
        (l(e), h(!0));
      }, []),
      w = (0, Z.useCallback)((e, t) => {
        (f((n) => ({
          ...n,
          [e]: t.sort((e, t) => {
            let n = Ge.coerce(e),
              r = Ge.coerce(t);
            return n === null || r === null ? t.localeCompare(e) : Ge.compare(r, n);
          }),
        })),
          h(!0));
      }, []);
    return (0, Q.jsx)(V, {
      open: !0,
      onOpenChange: _,
      children: (0, Q.jsxs)(V.Content, {
        className: `max-w-[600px]`,
        "data-testid": `manage-editors-modal-content`,
        "data-track-location": y.ManageEditorsModal,
        children: [
          (0, Q.jsxs)(V.Header, {
            children: [
              (0, Q.jsx)(V.Title, { children: `Available editors` }),
              (0, Q.jsx)(V.Description, { children: `Manage the editors available to your members` }),
            ],
          }),
          (0, Q.jsx)(V.Body, {
            className: `overflow-x max-w-full space-y-1`,
            children: t.map((e, t) => {
              let n = e.versions?.map((e) => e.version) || [],
                a = n.length > 0,
                l = u[e.id] || [],
                d = l.length > 0;
              return (0, Q.jsxs)(
                `div`,
                {
                  children: [
                    (0, Q.jsxs)(`div`, {
                      className: `group flex min-h-[36px] flex-row items-center gap-3`,
                      children: [
                        (0, Q.jsx)(Fe, {
                          disabled: !r,
                          state: i[e.id] ? `checked` : `unchecked`,
                          onToggle: (t) => S(e.id, t),
                          id: `editor-toggle-${t}`,
                        }),
                        (0, Q.jsxs)(`div`, {
                          className: `flex flex-row items-center gap-2`,
                          children: [
                            (0, Q.jsx)(Te, { editor: e, size: `base` }),
                            (0, Q.jsx)(`span`, { children: e.name }),
                          ],
                        }),
                        (0, Q.jsxs)(`div`, {
                          className: `ml-auto flex items-center gap-2`,
                          children: [
                            o === e.id && (0, Q.jsx)(G, { className: `text-content-secondary`, children: `default` }),
                            o !== e.id &&
                              i[e.id] &&
                              (0, Q.jsx)(`span`, {
                                className: `relative inline-flex h-7 w-[90px] items-center justify-end`,
                                children: (0, Q.jsx)(z, {
                                  disabled: !r,
                                  variant: `ghost`,
                                  size: `md`,
                                  className: `absolute right-0 hidden h-7 border-0 bg-none p-0 text-content-secondary hover:bg-transparent group-hover:block`,
                                  onClick: () => C(e.id),
                                  "data-tracking-id": `make-default-manage-editors-modal`,
                                  children: `make default`,
                                }),
                              }),
                            a &&
                              i[e.id] &&
                              (0, Q.jsxs)(J, {
                                children: [
                                  (0, Q.jsx)(J.Trigger, {
                                    asChild: !0,
                                    children: (0, Q.jsxs)(z, {
                                      disabled: !r,
                                      variant: `secondary`,
                                      size: `md`,
                                      className: `font-sm h-7 gap-1 rounded-lg px-2 py-1.5 font-sans text-sm tracking-tight text-content-primary`,
                                      "data-tracking-id": `add-version-manage-editors-modal`,
                                      children: [`add version`, (0, Q.jsx)(c, { className: `h-3 w-3 opacity-60` })],
                                    }),
                                  }),
                                  (0, Q.jsxs)(J.Content, {
                                    align: `end`,
                                    className: `min-w-[200px] !pb-0`,
                                    onCloseAutoFocus: (e) => e.preventDefault(),
                                    children: [
                                      n.length > 0 &&
                                        n.map((t, n) =>
                                          (0, Q.jsxs)(
                                            Pe,
                                            {
                                              className: `relative flex cursor-pointer select-none items-center gap-2 rounded-md px-3 py-2 text-sm hover:bg-surface-hover`,
                                              "data-tracking-id": `version-checkbox-${e.alias}-${t}`,
                                              children: [
                                                (0, Q.jsx)(Me, {
                                                  id: `${e.alias}-${t}`,
                                                  checked: l.includes(t),
                                                  onCheckedChange: (n) => {
                                                    let r = n ? [...l, t] : l.filter((e) => e !== t);
                                                    w(e.id, r);
                                                  },
                                                }),
                                                t,
                                                n === 0 &&
                                                  (0, Q.jsx)(`span`, {
                                                    className: `ml-auto rounded-md bg-surface-secondary px-2 py-0.5 text-xs text-content-secondary`,
                                                    children: `current latest`,
                                                  }),
                                              ],
                                            },
                                            t,
                                          ),
                                        ),
                                      l.length === 0 &&
                                        (0, Q.jsxs)(`div`, {
                                          className: `flex items-start gap-2 bg-surface-button-clear-accent px-3 py-2`,
                                          children: [
                                            (0, Q.jsx)(s, { className: `mt-0.5 h-4 w-4 shrink-0 text-content-brand` }),
                                            (0, Q.jsx)(`span`, {
                                              className: `text-sm text-content-brand`,
                                              children: `No selection means latest version will be used`,
                                            }),
                                          ],
                                        }),
                                    ],
                                  }),
                                ],
                              }),
                          ],
                        }),
                      ],
                    }),
                    a &&
                      d &&
                      i[e.id] &&
                      (0, Q.jsx)(`div`, {
                        className: `ml-12 flex flex-wrap items-center gap-1`,
                        children: l.map((t) =>
                          (0, Q.jsxs)(
                            `span`,
                            {
                              className: `inline-flex h-6 items-center gap-0.5 rounded-[20px] bg-surface-brand px-2 py-1 font-mono text-xs font-normal text-[rgb(var(--ioi-blue-500))]`,
                              children: [
                                t,
                                (0, Q.jsx)(`button`, {
                                  type: `button`,
                                  disabled: !r,
                                  onClick: (r) => {
                                    r.stopPropagation();
                                    let i = d ? l.filter((e) => e !== t) : n.filter((e) => e !== t);
                                    w(e.id, i);
                                  },
                                  className: `inline-flex h-3.5 w-3.5 items-center justify-center rounded-full text-gray-900 hover:bg-content-brand/20 disabled:cursor-not-allowed disabled:opacity-50`,
                                  "data-tracking-id": d ? `remove-version-tag` : `remove-all-version-tag`,
                                  "aria-label": `Remove ${t}`,
                                  children: (0, Q.jsx)(m, { size: 11 }),
                                }),
                              ],
                            },
                            t,
                          ),
                        ),
                      }),
                  ],
                },
                `${e.id}-${t}`,
              );
            }),
          }),
          (0, Q.jsxs)(V.Footer, {
            className: `items-center`,
            children: [
              g &&
                (0, Q.jsx)(`div`, {
                  className: `grow`,
                  children: (0, Q.jsx)(G, {
                    className: `text-base text-content-red`,
                    children: `You must have 1 available editor`,
                  }),
                }),
              (0, Q.jsx)(V.Close, {
                asChild: !0,
                children: (0, Q.jsx)(z, { type: `button`, variant: `outline`, children: `Close` }),
              }),
              (0, Q.jsx)(z, {
                onClick: x,
                loading: v.isPending,
                disabled: !r || !p || g,
                "data-testid": `save-editors-button`,
                type: `button`,
                variant: `primary`,
                "data-tracking-id": `save-editors-manage-editors-modal`,
                children: `Save`,
              }),
            ],
          }),
        ],
      }),
    });
  },
  Ye = () => {
    let e = v(),
      t = u(),
      { mutateAsync: n } = h({
        mutationFn: async (n) => {
          let r = t.getQueryData(P.getAuthenticatedUserQueryKey()),
            i = d(oe, { customAgents: n });
          return await e.organizationService.updateOrganizationPolicies({
            organizationId: r?.organizationId,
            securityAgentPolicy: i,
          });
        },
        onSettled: () => {
          let e = t.getQueryData(P.getAuthenticatedUserQueryKey());
          e?.organizationId && t.invalidateQueries({ queryKey: ne.getOrganizationPolicies(e.organizationId) });
        },
      });
    return (0, Z.useCallback)((e) => n(e), [n]);
  },
  Xe = ({ agent: e, editable: t, onEdit: n }) => {
    let { data: r } = I(),
      i = Ye(),
      { toast: a } = R(),
      o = (0, Z.useCallback)(
        async (t) => {
          let n = (r?.securityAgentPolicy?.customAgents ?? []).map((n) => (n.id === e.id ? { ...n, enabled: t } : n));
          try {
            (await i(n), a({ title: t ? `${e.name} enabled` : `${e.name} disabled` }));
          } catch (e) {
            a({ title: `Failed to update agent`, description: L(e) });
          }
        },
        [e, r, i, a],
      );
    return (0, Q.jsx)(`div`, {
      className: `rounded-xl border border-border-base`,
      "data-testid": `custom-agent-card-${e.id}`,
      children: (0, Q.jsxs)(`div`, {
        className: `flex flex-col justify-between gap-4 px-5 py-4 lg:flex-row lg:items-center lg:gap-8`,
        children: [
          (0, Q.jsxs)(`div`, {
            className: `flex min-w-0 items-center gap-4`,
            children: [
              (0, Q.jsx)(Fe, {
                id: `custom-agent-switch-${e.id}`,
                state: e.enabled ? `checked` : `unchecked`,
                onToggle: o,
                disabled: !t,
                "aria-label": `Enable ${e.name}`,
              }),
              (0, Q.jsxs)(`div`, {
                className: `flex min-w-0 flex-col gap-1`,
                children: [
                  (0, Q.jsx)(G, { className: `text-base font-semibold`, children: e.name }),
                  (0, Q.jsx)(G, { className: `text-sm text-content-secondary`, children: e.description }),
                  e.envMappings.length > 0 &&
                    (0, Q.jsx)(G, {
                      className: `line-clamp-1 text-xs text-content-tertiary`,
                      "data-testid": `env-mappings-summary-${e.id}`,
                      children: e.envMappings.map((e) => `${e.name} → ${e.secretName}`).join(`, `),
                    }),
                ],
              }),
            ],
          }),
          (0, Q.jsxs)(z, {
            variant: `secondary`,
            onClick: () => n(e),
            disabled: !t,
            className: `flex items-center gap-2 self-start lg:self-auto`,
            "data-testid": `edit-custom-agent-${e.id}`,
            "data-tracking-id": `edit-custom-agent`,
            children: [(0, Q.jsx)(Ve, { size: `base` }), `Settings`],
          }),
        ],
      }),
    });
  },
  Ze = 0,
  Qe = ({ agent: e, onClose: t }) => {
    let n = !!e,
      [r, i] = (0, Z.useState)(e?.name ?? ``),
      [a, o] = (0, Z.useState)(e?.description ?? ``),
      [s, c] = (0, Z.useState)(e?.startCommand ?? ``),
      [l, u] = (0, Z.useState)(
        () => e?.envMappings?.map((e) => ({ key: Ze++, name: e.name, secretName: e.secretName })) ?? [],
      ),
      [d, f] = (0, Z.useState)(null),
      { data: p } = I(),
      h = Ye(),
      { toast: g } = R(),
      _ = (0, Z.useCallback)(() => {
        u((e) => [...e, { key: Ze++, name: ``, secretName: `` }]);
      }, []),
      v = (0, Z.useCallback)((e) => {
        u((t) => t.filter((t, n) => n !== e));
      }, []),
      b = (0, Z.useCallback)((e, t) => {
        u((n) => n.map((n, r) => (r === e ? { ...n, name: t } : n)));
      }, []),
      x = (0, Z.useCallback)((e, t) => {
        u((n) => n.map((n, r) => (r === e ? { ...n, secretName: t } : n)));
      }, []),
      S = (0, Z.useCallback)(() => {
        if (!r.trim()) return (f(`Name is required`), !1);
        if (!a.trim()) return (f(`Description is required`), !1);
        if (!s.trim()) return (f(`Start command is required`), !1);
        for (let e = 0; e < l.length; e++) {
          let t = l[e];
          if (!t.name.trim()) return (f(`Env mapping row ${e + 1}: variable name is required`), !1);
          if (!t.secretName.trim()) return (f(`Env mapping row ${e + 1}: organization secret name is required`), !1);
        }
        return (f(null), !0);
      }, [r, a, s, l]),
      C = (0, Z.useCallback)(async () => {
        if (!S()) return;
        let i = p?.securityAgentPolicy?.customAgents ?? [],
          o = {
            ...(n ? { id: e.id } : {}),
            enabled: e?.enabled ?? !0,
            name: r.trim(),
            description: a.trim(),
            startCommand: s.trim(),
            envMappings: l
              .filter((e) => e.name.trim() && e.secretName.trim())
              .map((e) => ({ name: e.name.trim(), secretName: e.secretName.trim() })),
          },
          c;
        c = n ? i.map((t) => (t.id === e.id ? { ...t, ...o } : t)) : [...i, o];
        try {
          (await h(c), g({ title: n ? `Custom agent updated` : `Custom agent added` }), t());
        } catch (e) {
          f(L(e));
        }
      }, [S, p, r, a, s, l, e, n, h, g, t]),
      w = (0, Z.useCallback)(async () => {
        if (!e) return;
        let n = (p?.securityAgentPolicy?.customAgents ?? []).filter((t) => t.id !== e.id);
        try {
          (await h(n), g({ title: `Custom agent removed` }), t());
        } catch (e) {
          f(L(e));
        }
      }, [e, p, h, g, t]);
    return (0, Q.jsx)(V, {
      open: !0,
      onOpenChange: (e) => !e && t(),
      children: (0, Q.jsxs)(V.Content, {
        className: `max-w-lg`,
        "data-track-location": y.CustomSecurityAgentModal,
        children: [
          (0, Q.jsxs)(V.Header, {
            children: [
              (0, Q.jsx)(V.Title, { children: n ? `Edit Custom Agent` : `Add Custom Agent` }),
              (0, Q.jsx)(V.Description, {
                children: `Configure a custom security agent to deploy to all environments.`,
              }),
            ],
          }),
          (0, Q.jsxs)(V.Body, {
            className: `flex flex-col gap-4`,
            children: [
              (0, Q.jsx)(X, {
                label: `Name`,
                children: (0, Q.jsx)(W, {
                  value: r,
                  onChange: (e) => i(e.target.value),
                  placeholder: `My Security Agent`,
                  "data-testid": `custom-agent-name`,
                }),
              }),
              (0, Q.jsx)(X, {
                label: `Description`,
                children: (0, Q.jsx)(W, {
                  value: a,
                  onChange: (e) => o(e.target.value),
                  placeholder: `Monitors environments for security threats`,
                  "data-testid": `custom-agent-description`,
                }),
              }),
              (0, Q.jsx)(X, {
                label: `Start Command`,
                children: (0, Q.jsx)(`textarea`, {
                  className: `focus-visible:ring-ring-focused flex min-h-[100px] w-full rounded-lg border border-border-base bg-surface-glass px-3 py-2 font-mono text-sm placeholder:text-content-tertiary focus-visible:outline-none focus-visible:ring-2`,
                  value: s,
                  onChange: (e) => c(e.target.value),
                  placeholder: `#!/bin/bash
export AGENT_ENDPOINT="https://api.example.com"
./run-agent.sh`,
                  "data-testid": `custom-agent-start-command`,
                }),
              }),
              (0, Q.jsxs)(`div`, {
                className: `flex flex-col gap-2`,
                children: [
                  (0, Q.jsx)(`label`, {
                    className: `text-base font-normal text-content-primary`,
                    children: `Environment Secrets`,
                  }),
                  (0, Q.jsx)(`span`, {
                    className: `text-sm text-content-tertiary`,
                    children: `Map environment variables to organization secrets. Secret values are injected at runtime.`,
                  }),
                  (0, Q.jsxs)(`div`, {
                    className: `flex flex-col gap-2`,
                    children: [
                      l.map((e, t) =>
                        (0, Q.jsxs)(
                          `div`,
                          {
                            className: `flex items-center gap-2`,
                            children: [
                              (0, Q.jsx)(W, {
                                type: `text`,
                                value: e.name,
                                onChange: (e) => b(t, e.target.value),
                                placeholder: `Env Variable Name`,
                                className: `w-40`,
                                "data-testid": `env-mapping-name-${t}`,
                              }),
                              (0, Q.jsx)(W, {
                                type: `text`,
                                value: e.secretName,
                                onChange: (e) => x(t, e.target.value),
                                placeholder: `Organization Secret Name`,
                                className: `flex-1`,
                                "data-testid": `env-mapping-secret-${t}`,
                              }),
                              (0, Q.jsx)(z, {
                                variant: `ghost`,
                                size: `sm`,
                                onClick: () => v(t),
                                className: `h-9 w-9 p-0`,
                                "data-testid": `remove-env-mapping-${t}`,
                                "data-tracking-id": `remove-env-mapping`,
                                children: (0, Q.jsx)(m, { className: `h-4 w-4` }),
                              }),
                            ],
                          },
                          e.key,
                        ),
                      ),
                      (0, Q.jsx)(z, {
                        variant: `secondary`,
                        size: `sm`,
                        onClick: _,
                        className: `self-start`,
                        "data-testid": `add-env-mapping-button`,
                        "data-tracking-id": `add-secret`,
                        children: `+ Add secret`,
                      }),
                    ],
                  }),
                ],
              }),
              d && (0, Q.jsx)(`p`, { className: `text-content-danger text-sm`, children: d }),
            ],
          }),
          (0, Q.jsx)(V.Footer, {
            children: (0, Q.jsxs)(`div`, {
              className: `flex w-full items-center justify-between`,
              children: [
                (0, Q.jsx)(`div`, {
                  children:
                    n &&
                    (0, Q.jsx)(z, {
                      variant: `destructive`,
                      onClick: w,
                      "data-testid": `delete-custom-agent`,
                      "data-tracking-id": `delete-custom-agent`,
                      children: `Delete`,
                    }),
                }),
                (0, Q.jsxs)(`div`, {
                  className: `flex gap-2`,
                  children: [
                    (0, Q.jsx)(V.Close, {
                      asChild: !0,
                      children: (0, Q.jsx)(z, { variant: `secondary`, children: `Cancel` }),
                    }),
                    (0, Q.jsx)(z, {
                      onClick: C,
                      "data-testid": `save-custom-agent`,
                      "data-tracking-id": `save-custom-agent`,
                      children: n ? `Save changes` : `Add agent`,
                    }),
                  ],
                }),
              ],
            }),
          }),
        ],
      }),
    });
  },
  $e = ({ editable: e }) => {
    let { data: t, isLoading: n } = I(),
      [r, i] = (0, Z.useState)(!1),
      [a, o] = (0, Z.useState)(void 0),
      s = t?.securityAgentPolicy?.customAgents ?? [],
      c = (0, Z.useCallback)(() => {
        (o(void 0), i(!0));
      }, []),
      l = (0, Z.useCallback)((e) => {
        (o(e), i(!0));
      }, []),
      u = (0, Z.useCallback)(() => {
        (i(!1), o(void 0));
      }, []);
    return (0, Q.jsxs)(q, {
      ready: !n,
      children: [
        (0, Q.jsxs)(`div`, {
          className: `flex flex-col gap-3`,
          children: [
            s.map((t) => (0, Q.jsx)(Xe, { agent: t, editable: e, onEdit: l }, t.id)),
            (0, Q.jsx)(`div`, {
              children: (0, Q.jsx)(z, {
                variant: `secondary`,
                onClick: c,
                disabled: !e,
                "data-testid": `add-custom-agent`,
                "data-tracking-id": `add-custom-agent`,
                children: `Add custom agent`,
              }),
            }),
          ],
        }),
        r && (0, Q.jsx)(Qe, { agent: a, onClose: u }),
      ],
    });
  },
  et =
    /^(?:(?:(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])(?:\.(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]))*(?::[0-9]+)?\/)?[a-z0-9]+(?:(?:(?:[._]|__|[-]*)[a-z0-9]+)+)?(?:\/[a-z0-9]+(?:(?:(?:[._]|__|[-]*)[a-z0-9]+)+)?)*(?::[a-zA-Z0-9_.-]{1,128})?(?:@[a-z][a-z0-9]*(?:[.-][a-z][a-z0-9]*)*:[a-f0-9]{64})?|[a-z0-9]+(?:[._][a-z0-9]+)*)$/i,
  tt = ({ editable: e = !0 }) => {
    let { data: t, isLoading: n } = I(),
      r = t?.defaultEnvironmentImage || ``,
      [i, a] = (0, Z.useState)(r),
      [o, s] = (0, Z.useState)(null),
      [c, l] = (0, Z.useState)(!1),
      [u, d] = (0, Z.useState)(r);
    r !== u && (d(r), a(r), l(!1), s(null));
    let f = D(),
      { toast: p } = R(),
      m = (0, Z.useCallback)((e) => {
        (a(e.target.value), l(!0), s(null));
      }, []),
      h = (0, Z.useCallback)(
        (e) =>
          e.trim()
            ? et.test(e)
              ? (s(null), !0)
              : (s(`Expected format: [HOST[:PORT]/]NAMESPACE/REPOSITORY[:TAG]`), !1)
            : !0,
        [],
      ),
      g = (0, Z.useCallback)(async () => {
        if (!c || !h(i)) return;
        let e = { defaultEnvironmentImage: i };
        try {
          (await f.mutateAsync(e), l(!1), p({ title: `Default environment image updated` }));
        } catch (e) {
          (console.error(e),
            p({ title: `We couldn't save your changes. Sorry about that! Please retry.`, description: L(e) }));
        }
      }, [i, f, c, p, h]),
      _ = (0, Z.useCallback)(() => {
        c && g();
      }, [c, g]),
      v = (0, Z.useCallback)(
        (e) => {
          e.key === `Enter` && c && g();
        },
        [c, g],
      );
    return (0, Q.jsx)(`div`, {
      className: `flex flex-col gap-3 rounded-lg border border-border-subtle px-5 py-4`,
      children: (0, Q.jsxs)(q, {
        ready: !n,
        children: [
          (0, Q.jsxs)(`div`, {
            className: `flex flex-col gap-0.5`,
            children: [
              (0, Q.jsx)(U, { className: `text-base`, children: `Default environment image` }),
              (0, Q.jsxs)(G, {
                className: `text-sm text-content-secondary`,
                children: [
                  `Default devcontainer image used when no configuration is present in the repository. Leave empty to use the IOI system default.`,
                  ` `,
                  (0, Q.jsx)(Y, {
                    href: `https://ioi.com/docs/ioi/organizations/policies/default-image`,
                    iconSize: `sm`,
                    children: `Learn more`,
                  }),
                ],
              }),
            ],
          }),
          (0, Q.jsx)(W, {
            "data-testid": `default-environment-image-input`,
            type: `text`,
            value: i,
            onChange: m,
            onBlur: _,
            onKeyDown: v,
            className: B(`max-w-none`, o && `border-border-error`),
            placeholder: `mcr.microsoft.com/devcontainers/base:ubuntu-24.04`,
            disabled: !e,
          }),
          (0, Q.jsx)(Ne, { error: o, className: `text-sm` }),
        ],
      }),
    });
  },
  nt = `https://ioi.com/docs/ioi/organizations/policies/environment-creation`,
  rt = ({ editable: e = !0 }) => {
    let { data: t, isLoading: n } = I(),
      r = D(),
      { toast: i } = R(),
      a = (0, Z.useCallback)(
        async (e) => {
          let t = { disableFromScratch: e === `indeterminate` ? !0 : e };
          try {
            (await r.mutateAsync(t), i({ title: `Environment creation policy updated` }));
          } catch (e) {
            (console.error(e),
              i({ title: `We couldn't save your changes. Sorry about that! Please retry.`, description: L(e) }));
          }
        },
        [r, i],
      );
    return (0, Q.jsx)(`div`, {
      className: `flex flex-col gap-4 rounded-lg border border-border-subtle px-5 py-4`,
      children: (0, Q.jsx)(q, {
        ready: !n,
        children: (0, Q.jsxs)(`div`, {
          className: `flex flex-col gap-1`,
          children: [
            (0, Q.jsx)(`div`, {
              className: `flex items-center gap-2`,
              children: (0, Q.jsxs)(Pe, {
                className: `flex items-center gap-2`,
                children: [
                  (0, Q.jsx)(Me, {
                    "data-testid": `disable-from-scratch-checkbox`,
                    id: `disable-from-scratch`,
                    checked: t?.disableFromScratch ?? !1,
                    onCheckedChange: a,
                    disabled: !e,
                  }),
                  (0, Q.jsx)(`span`, {
                    className: `text-base font-medium`,
                    children: `Only admins can start from scratch`,
                  }),
                ],
              }),
            }),
            (0, Q.jsxs)(G, {
              className: `pl-6 text-sm text-content-secondary`,
              children: [
                `When enabled, members can still create environments from projects and Git URLs, but cannot start blank environments.`,
                ` `,
                (0, Q.jsx)(Y, { href: nt, iconSize: `sm`, children: `Learn more` }),
              ],
            }),
          ],
        }),
      }),
    });
  },
  it = ({ editable: e = !0 }) => {
    let { data: t, isLoading: n } = I(),
      r = D(),
      { toast: i } = R(),
      a = (0, Z.useMemo)(() => {
        if (!t) return !1;
        let e = t.membersRequireProjects || !1,
          n = t.membersCreateProjects || !1;
        return e === n ? `indeterminate` : e && !n;
      }, [t]),
      o = (0, Z.useCallback)(
        async (e) => {
          let t = e === `indeterminate` ? !0 : e,
            n = { membersRequireProjects: t, membersCreateProjects: !t };
          try {
            (await r.mutateAsync(n), i({ title: `Environment creation policy updated` }));
          } catch (e) {
            (console.error(e),
              i({ title: `We couldn't save your changes. Sorry about that! Please retry.`, description: L(e) }));
          }
        },
        [r, i],
      );
    return (0, Q.jsx)(`div`, {
      className: `flex flex-col gap-4 rounded-lg border border-border-subtle px-5 py-4`,
      children: (0, Q.jsx)(q, {
        ready: !n,
        children: (0, Q.jsxs)(`div`, {
          className: `flex flex-col gap-1`,
          children: [
            (0, Q.jsx)(`div`, {
              className: `flex items-center gap-2`,
              children: (0, Q.jsxs)(Pe, {
                className: `flex items-center gap-2`,
                children: [
                  (0, Q.jsx)(Me, {
                    "data-testid": `environment-creation-role-checkbox`,
                    id: `members-require-projects`,
                    checked: a,
                    onCheckedChange: o,
                    disabled: !e,
                  }),
                  (0, Q.jsx)(`span`, {
                    className: `text-base font-medium`,
                    children: `Only admins can create projects`,
                  }),
                ],
              }),
            }),
            (0, Q.jsxs)(G, {
              className: `pl-6 text-sm text-content-secondary`,
              children: [
                `When enabled, members must use existing projects to create environments.`,
                ` `,
                (0, Q.jsx)(Y, {
                  href: `https://ioi.com/docs/ioi/organizations/policies/project-creation`,
                  iconSize: `sm`,
                  children: `Learn more`,
                }),
              ],
            }),
          ],
        }),
      }),
    });
  },
  at = ({ size: e, className: t, ...n }) => {
    switch (e) {
      case `sm`:
        return (0, Q.jsx)(`svg`, {
          className: t,
          ...n,
          width: `16`,
          height: `16`,
          viewBox: `0 0 16 16`,
          fill: `none`,
          xmlns: `http://www.w3.org/2000/svg`,
          children: (0, Q.jsx)(`path`, {
            d: `M2.333 3v6.333a.667.667 0 0 0 .667.667h10.667m0 0L10.667 7m3 3-3 3`,
            stroke: `currentColor`,
            strokeWidth: `1`,
            strokeLinecap: `round`,
            strokeLinejoin: `round`,
          }),
        });
      case `base`:
        return (0, Q.jsx)(`svg`, {
          className: t,
          ...n,
          width: `20`,
          height: `20`,
          viewBox: `0 0 20 20`,
          fill: `none`,
          xmlns: `http://www.w3.org/2000/svg`,
          children: (0, Q.jsx)(`path`, {
            d: `M2.917 3.75v7.917c0 .46.373.833.833.833h13.333m0 0L13.333 8.75m3.75 3.75-3.75 3.75`,
            stroke: `currentColor`,
            strokeWidth: `1.25`,
            strokeLinecap: `round`,
            strokeLinejoin: `round`,
          }),
        });
      case `lg`:
        return (0, Q.jsx)(`svg`, {
          className: t,
          ...n,
          width: `24`,
          height: `24`,
          viewBox: `0 0 24 24`,
          fill: `none`,
          xmlns: `http://www.w3.org/2000/svg`,
          children: (0, Q.jsx)(`path`, {
            d: `M3.5 4.5v9.5c0 .552.448 1 1 1H20.5m0 0-4.5-4.5m4.5 4.5-4.5 4.5`,
            stroke: `currentColor`,
            strokeWidth: `1.5`,
            strokeLinecap: `round`,
            strokeLinejoin: `round`,
          }),
        });
    }
  },
  ot = ({ rows: e, onChange: t, disabled: n = !1, resolveBareNames: i, maxEntries: o }) => {
    let { toast: s } = R(),
      c = (0, Z.useId)(),
      l = (0, Z.useRef)(0),
      u = (0, Z.useRef)(new Map()),
      d = (0, Z.useCallback)(() => ((l.current += 1), `${c}-row-${l.current}`), [c]),
      f = (0, Z.useMemo)(() => e.filter((e) => e.value.trim() !== ``), [e]),
      p = f.length >= o,
      [m, h] = (0, Z.useState)(null),
      g = (0, Z.useRef)(),
      _ = (0, Z.useCallback)(
        (e) => {
          (g.current && clearTimeout(g.current),
            h(e),
            (g.current = setTimeout(() => h(null), 1500)),
            s({ title: `Duplicate entry — already in the list` }));
        },
        [s],
      );
    (0, Z.useEffect)(
      () => () => {
        g.current && clearTimeout(g.current);
      },
      [],
    );
    let v = (0, Z.useCallback)(
        (t, n) => {
          let r = t.trim();
          if (r !== ``) return e.find((e) => e.id !== n && e.value.trim() === r)?.id;
        },
        [e],
      ),
      y = i ? `Enter executable path or bare name` : `Enter absolute executable path`,
      b = (0, Z.useCallback)(
        (e) => {
          let t = e[e.length - 1];
          return !t || t.value.trim() !== `` ? [...e, { id: d(), value: `` }] : e;
        },
        [d],
      ),
      x = (0, Z.useCallback)(
        (n, r) => {
          t(e.map((e) => (e.id === n ? { ...e, value: r } : e)));
        },
        [e, t],
      ),
      S = (0, Z.useCallback)(
        (n) => {
          let r = u.current.get(n)?.value.trim() ?? ``;
          if (r === ``) return;
          let i = v(r, n);
          i && (_(i), t(e.map((e) => (e.id === n ? { ...e, value: `` } : e))));
        },
        [e, t, v, _],
      ),
      C = (0, Z.useCallback)(
        (n) => {
          t(b(e.filter((e) => e.id !== n)));
        },
        [e, t, b],
      ),
      w = (0, Z.useCallback)(
        (n, r, i) => {
          if (n.key === `Enter`) {
            n.preventDefault();
            let a = r.value.trim();
            if (a === ``) return;
            let o = v(a, r.id);
            if (o) {
              (_(o), t(e.map((e) => (e.id === r.id ? { ...e, value: `` } : e))));
              return;
            }
            if (i === e.length - 1 && !p) {
              let n = d(),
                i = e.map((e) => (e.id === r.id ? { ...e, value: a } : e));
              (i.push({ id: n, value: `` }),
                t(i),
                requestAnimationFrame(() => {
                  u.current.get(n)?.focus();
                }));
            } else {
              t(e.map((e) => (e.id === r.id ? { ...e, value: a } : e)));
              let n = e[i + 1];
              n && u.current.get(n.id)?.focus();
            }
          }
        },
        [e, t, p, d, v, _],
      ),
      T = (0, Z.useCallback)(
        (n, r) => {
          let i = n.clipboardData
            .getData(`text/plain`)
            .split(
              `
`,
            )
            .map((e) => e.trim())
            .filter(Boolean);
          if (i.length <= 1) return;
          n.preventDefault();
          let a = new Set(e.filter((e) => e.id !== r.id).map((e) => e.value.trim())),
            s = new Set(),
            c = i.filter((e) => (a.has(e) || s.has(e) ? !1 : (s.add(e), !0))),
            l = o - f.length,
            u = c.slice(0, l);
          if (u.length === 0) return;
          let p = e.map((e) => (e.id === r.id ? { ...e, value: u[0] ?? `` } : e)),
            m = p.findIndex((e) => e.id === r.id) + 1,
            h = u.slice(1).map((e) => ({ id: d(), value: e }));
          t(b([...p.slice(0, m), ...h, ...p.slice(m)]));
        },
        [e, t, f.length, o, d, b],
      ),
      E = (0, Z.useCallback)(() => {
        if (p || n) return;
        let r = e[e.length - 1];
        if (r && r.value.trim() === ``) {
          u.current.get(r.id)?.focus();
          return;
        }
        let i = d();
        (t([...e, { id: i, value: `` }]),
          requestAnimationFrame(() => {
            u.current.get(i)?.focus();
          }));
      }, [p, n, e, t, d]),
      D = (0, Z.useCallback)((e, t) => {
        t ? u.current.set(e, t) : u.current.delete(e);
      }, []);
    return (0, Q.jsxs)(`div`, {
      className: `flex flex-col gap-4`,
      children: [
        (0, Q.jsxs)(`div`, {
          className: `flex items-center justify-between`,
          children: [
            (0, Q.jsxs)(G, {
              className: `text-base font-medium`,
              children: [
                (0, Q.jsx)(`span`, { children: i ? `Executable paths and names` : `Executable paths` }),
                (0, Q.jsxs)(`span`, {
                  className: `text-content-secondary`,
                  children: [` `, `(`, f.length.toLocaleString(), ` of `, o.toLocaleString(), `)`],
                }),
              ],
            }),
            (0, Q.jsx)(z, {
              onClick: E,
              LeadingIcon: a,
              "data-tracking-id": `add-row`,
              size: `sm`,
              variant: `secondary`,
              disabled: p || n,
              children: `Add row`,
            }),
          ],
        }),
        p &&
          (0, Q.jsx)(`p`, {
            className: `text-sm text-content-warning`,
            role: `status`,
            children: `Entry limit reached. Remove existing entries before adding new ones.`,
          }),
        (0, Q.jsxs)(`div`, {
          className: `flex flex-col rounded-lg border border-border-subtle`,
          "data-testid": `executable-row-list`,
          children: [
            f.length === 0 &&
              (0, Q.jsx)(`div`, {
                className: `px-3 py-2 text-sm text-content-tertiary`,
                children: `No executables added yet. Type below or paste a list to get started.`,
              }),
            e.map((t, i) => {
              let a = i === e.length - 1 && t.value.trim() === ``,
                o = t.id === m;
              return (0, Q.jsxs)(
                `div`,
                {
                  className: B(
                    `flex items-center gap-3 px-3 py-2 transition-colors duration-300`,
                    o && `bg-surface-warning-subtle`,
                  ),
                  "data-testid": `executable-row`,
                  "data-highlighted": o || void 0,
                  children: [
                    (0, Q.jsx)(W.Root, {
                      className: B(
                        `min-w-0 flex-1 max-w-none px-3 focus-within:border-transparent`,
                        o ? `border-content-warning` : `border-border-light`,
                      ),
                      children: (0, Q.jsx)(W.Control, {
                        ref: (e) => D(t.id, e),
                        appearance: `code`,
                        type: `text`,
                        value: t.value,
                        onChange: (e) => x(t.id, e.target.value),
                        onKeyDown: (e) => w(e, t, i),
                        onPaste: (e) => T(e, t),
                        onBlur: () => S(t.id),
                        placeholder: a ? y : void 0,
                        disabled: n,
                        className: `h-9 max-w-none text-sm disabled:cursor-not-allowed disabled:opacity-50`,
                        "data-testid": `executable-row-input`,
                        "aria-label": a ? `New executable entry` : `Executable ${t.value}`,
                      }),
                    }),
                    (0, Q.jsxs)(`div`, {
                      role: `combobox`,
                      "aria-disabled": `true`,
                      "aria-expanded": `false`,
                      "aria-label": `Scope (coming soon)`,
                      className: `flex h-9 w-20 shrink-0 cursor-not-allowed items-center gap-2 rounded-lg border border-border-light px-3 opacity-50 sm:w-40`,
                      "data-testid": `executable-row-scope`,
                      title: `Coming soon`,
                      children: [
                        (0, Q.jsx)(`span`, {
                          className: `flex-1 truncate text-sm text-content-primary`,
                          children: `Everyone`,
                        }),
                        (0, Q.jsx)(ke, { size: `sm`, className: `shrink-0 text-content-primary` }),
                      ],
                    }),
                    (0, Q.jsx)(z, {
                      LeadingIcon: r,
                      onClick: () => C(t.id),
                      "data-tracking-id": `delete-executable-row`,
                      disabled: n || a,
                      variant: `ghost`,
                      className: `text-content-secondary hover:text-content-destructive`,
                      "aria-label": `Delete ${t.value}`,
                    }),
                  ],
                },
                t.id,
              );
            }),
            (0, Q.jsxs)(`div`, {
              className: `flex items-center gap-1 border-t border-border-subtle px-4 py-2`,
              children: [
                (0, Q.jsx)(at, { size: `sm`, className: `text-content-tertiary` }),
                (0, Q.jsx)(z, {
                  onClick: E,
                  LeadingIcon: a,
                  variant: `secondary`,
                  size: `xs`,
                  disabled: p || n,
                  "data-testid": `add-row-button-bottom`,
                  "data-tracking-id": `add-executable-row-bottom`,
                  children: `Add row`,
                }),
              ],
            }),
          ],
        }),
      ],
    });
  };
function st(e, t) {
  return d(b, {
    veto: d(O, {
      exec: d(S, {
        enabled: e.length > 0,
        denylist: e,
        action: t,
        resolveBareNames: !0,
        untouchable: !0,
        watch: !0,
        denyBlockDevices: !0,
      }),
    }),
  });
}
function ct(e, t) {
  return e.length === t.length ? e.every((e, n) => e === t[n]) : !1;
}
function $(e) {
  return e.status?.phase === F.RUNNING;
}
function lt(e) {
  return e.status?.phase === F.STOPPED;
}
function ut(e) {
  let t = e.status?.phase;
  return t === F.STARTING || t === F.CREATING || t === F.UPDATING;
}
function dt(e) {
  return e
    ? $(e)
      ? `text-content-green`
      : ut(e)
        ? `text-content-orange`
        : `text-content-tertiary`
    : `text-content-tertiary`;
}
function ft(e) {
  return e
    ? $(e)
      ? `Environment running`
      : ut(e)
        ? `Environment starting`
        : lt(e)
          ? `Environment stopped`
          : `Unknown`
    : `No environment selected`;
}
function pt(e) {
  switch (e) {
    case `idle`:
      return `Test your deny list config against a running environment before saving`;
    case `applying`:
      return `Applying config…`;
    case `applied`:
      return `Config applied — click to open environment`;
    case `drifted`:
      return `Config changed since last preview — click to re-apply`;
  }
}
var mt = ({ state: e }) => {
    switch (e) {
      case `applying`:
        return (0, Q.jsx)(ue, {
          size: `sm`,
          className: `animate-spin text-content-secondary`,
          "aria-label": `Applying config`,
          "data-testid": `preview-state-applying`,
        });
      case `applied`:
        return (0, Q.jsx)(Le, {
          size: `sm`,
          className: `text-content-green`,
          "aria-label": `Config applied`,
          "data-testid": `preview-state-applied`,
        });
      case `drifted`:
        return (0, Q.jsx)(Re, {
          size: `sm`,
          className: `text-content-orange`,
          "aria-label": `Config out of sync`,
          "data-testid": `preview-state-drifted`,
        });
      default:
        return null;
    }
  },
  ht = ({ env: e }) => {
    if (!e) return null;
    let t = ft(e);
    return (0, Q.jsx)(pe, {
      content: t,
      usePortal: !0,
      children: (0, Q.jsx)(Ee, {
        size: `sm`,
        className: B(`shrink-0`, dt(e)),
        "aria-label": t,
        "data-testid": `preview-env-status-dot`,
      }),
    });
  },
  gt = ({ executables: e, action: t = A.BLOCK, disabled: n = !1 }) => {
    let { toast: r } = R(),
      i = ge(),
      o = ve(),
      s = ye(),
      { data: c } = _e(),
      { environmentClassEntries: l, isLoading: u } = xe(),
      [f, p] = (0, Z.useState)(null),
      [m, h] = (0, Z.useState)(null),
      [g, _] = (0, Z.useState)(null),
      [v, y] = (0, Z.useState)(!1),
      [b, x] = (0, Z.useState)(!1),
      S = (0, Z.useRef)(!1),
      C = (0, Z.useMemo)(() => c?.environments ?? [], [c]),
      w = (0, Z.useMemo)(() => C.find((e) => e.id === f), [C, f]),
      T = (0, Z.useMemo)(
        () => (v || b ? `applying` : m === null ? `idle` : !ct(e, m) || t !== g ? `drifted` : `applied`),
        [v, b, m, g, e, t],
      ),
      { runningEnvironments: D, stoppedEnvironments: O } = (0, Z.useMemo)(() => {
        let e = [],
          t = [];
        for (let n of C) $(n) || ut(n) ? e.push(n) : lt(n) && t.push(n);
        let n = (e, t) => De(e).localeCompare(De(t));
        return (e.sort(n), t.sort(n), { runningEnvironments: e, stoppedEnvironments: t });
      }, [C]),
      k = (0, Z.useCallback)(
        async (n) => {
          y(!0);
          try {
            (await i.mutateAsync({ req: { environmentId: n, spec: d(E, { kernelControlsConfig: st(e, t) }) } }),
              h([...e]),
              _(t),
              r({ title: `Deny list config applied to environment` }));
          } catch (e) {
            (console.error(e), r({ title: `Failed to apply config to environment`, description: L(e) }));
          } finally {
            y(!1);
          }
        },
        [e, t, i, r],
      );
    (0, Z.useEffect)(() => {
      S.current && w && $(w) && ((S.current = !1), k(w.id));
    }, [w, k]);
    let ee = (0, Z.useCallback)(
        async (e) => {
          if ((p(e.id), h(null), _(null), $(e))) await k(e.id);
          else if (lt(e)) {
            S.current = !0;
            try {
              await o.mutateAsync({ environmentId: e.id });
            } catch (e) {
              ((S.current = !1), console.error(e), r({ title: `Failed to start environment`, description: L(e) }));
            }
          }
        },
        [k, o, r],
      ),
      j = (0, Z.useCallback)(async () => {
        let e = be(l)[0];
        if (!e) {
          r({ title: `No environment class available` });
          return;
        }
        (x(!0), (S.current = !0));
        try {
          (p((await s.mutateAsync({ type: `blank`, classID: e.clazz.id })).id), h(null), _(null));
        } catch (e) {
          ((S.current = !1), console.error(e), r({ title: `Failed to create environment`, description: L(e) }));
        } finally {
          x(!1);
        }
      }, [l, s, r]),
      M = (0, Z.useCallback)(() => {
        f &&
          (T === `applied`
            ? window.open(je({ environment: { id: f } }), `_blank`)
            : (T === `drifted` || T === `idle`) && k(f));
      }, [f, T, k]),
      N = w ? De(w) : null,
      P = n || !f || T === `applying`;
    return (0, Q.jsxs)(`div`, {
      className: `flex flex-col gap-1.5`,
      "data-testid": `preview-in-environment`,
      children: [
        (0, Q.jsx)(pe, {
          content: pt(T),
          usePortal: !0,
          children: (0, Q.jsxs)(Ae, {
            variant: `secondary`,
            children: [
              (0, Q.jsx)(Ae.Item, {
                onClick: M,
                disabled: P,
                "data-testid": `preview-in-environment-button`,
                "data-tracking-id": `preview-in-environment`,
                children: (0, Q.jsxs)(`span`, {
                  className: `flex items-center gap-1.5`,
                  children: [
                    (0, Q.jsx)(mt, { state: T }),
                    (0, Q.jsx)(`span`, { children: N ? `Preview in ${N}` : `Preview in…` }),
                    (0, Q.jsx)(ht, { env: w }),
                  ],
                }),
              }),
              (0, Q.jsxs)(J, {
                children: [
                  (0, Q.jsx)(J.Trigger, {
                    asChild: !0,
                    children: (0, Q.jsx)(Ae.Item, {
                      "data-testid": `preview-in-environment-dropdown`,
                      LeadingIcon: ke,
                      "aria-label": `Select environment for preview`,
                      disabled: n,
                    }),
                  }),
                  (0, Q.jsx)(J.Portal, {
                    children: (0, Q.jsxs)(J.Content, {
                      align: `end`,
                      className: `max-h-80 w-auto min-w-64 overflow-y-auto`,
                      children: [
                        D.length > 0 &&
                          (0, Q.jsxs)(Q.Fragment, {
                            children: [
                              (0, Q.jsx)(J.Label, { children: `Running` }),
                              D.map((e) =>
                                (0, Q.jsx)(
                                  _t,
                                  {
                                    env: e,
                                    selected: e.id === f,
                                    onClick: () => ee(e),
                                    "data-tracking-id": `preview-select-running-env`,
                                  },
                                  e.id,
                                ),
                              ),
                            ],
                          }),
                        O.length > 0 &&
                          (0, Q.jsxs)(Q.Fragment, {
                            children: [
                              D.length > 0 && (0, Q.jsx)(J.Separator, {}),
                              (0, Q.jsx)(J.Label, { children: `Stopped` }),
                              O.map((e) =>
                                (0, Q.jsx)(
                                  _t,
                                  {
                                    env: e,
                                    selected: e.id === f,
                                    onClick: () => ee(e),
                                    "data-tracking-id": `preview-select-stopped-env`,
                                  },
                                  e.id,
                                ),
                              ),
                            ],
                          }),
                        C.length === 0 &&
                          (0, Q.jsx)(`div`, {
                            className: `px-3 py-2`,
                            children: (0, Q.jsx)(G, {
                              className: `text-sm text-content-secondary`,
                              children: `No environments found`,
                            }),
                          }),
                        (0, Q.jsx)(J.Separator, {}),
                        (0, Q.jsxs)(J.Item, {
                          onClick: j,
                          disabled: u || l.length === 0,
                          "data-testid": `preview-create-new-environment`,
                          "data-tracking-id": `preview-create-new-environment`,
                          children: [
                            (0, Q.jsx)(a, { size: `sm`, className: `mr-2`, "aria-hidden": !0 }),
                            (0, Q.jsx)(`span`, { children: `Create new environment` }),
                          ],
                        }),
                      ],
                    }),
                  }),
                ],
              }),
            ],
          }),
        }),
        T === `drifted` &&
          (0, Q.jsx)(G, {
            className: `text-xs text-content-orange`,
            "data-testid": `preview-config-drift-warning`,
            children: `Config changed since last preview`,
          }),
      ],
    });
  },
  _t = ({ env: e, selected: t, onClick: n, "data-tracking-id": r }) => {
    let i = De(e);
    return (0, Q.jsxs)(J.Item, {
      onClick: n,
      className: B(t && `bg-surface-secondary`),
      "aria-current": t ? `true` : void 0,
      "data-testid": `preview-env-item-${e.id}`,
      "data-tracking-id": r,
      children: [
        (0, Q.jsxs)(`span`, {
          className: `flex min-w-0 flex-1 items-center gap-2`,
          children: [
            (0, Q.jsx)(Oe, { env: e, size: `sm` }),
            (0, Q.jsx)(`span`, { className: `max-w-48 truncate`, children: i }),
          ],
        }),
        t && (0, Q.jsx)(Le, { size: `sm`, className: `ml-2 shrink-0 text-content-green`, "aria-hidden": !0 }),
      ],
    });
  },
  vt = 50,
  yt = ({ editable: e = !0 }) => {
    let { data: t } = I(),
      n = D(),
      { toast: r } = R(),
      a = (0, Z.useId)(),
      o = (0, Z.useRef)(0),
      s = (0, Z.useCallback)(() => ((o.current += 1), `${a}-${o.current}`), [a]),
      [c, l] = (0, Z.useState)(!1),
      [u, f] = (0, Z.useState)(() => [{ id: `initial-empty`, value: `` }]),
      [p, m] = (0, Z.useState)(A.BLOCK),
      [h, g] = (0, Z.useState)(!1),
      _ = (0, Z.useMemo)(() => new Set(t?.vetoExecPolicy?.safelist ?? []), [t?.vetoExecPolicy?.safelist]),
      v = (0, Z.useMemo)(() => u.map((e) => e.value.trim()).filter(Boolean), [u]),
      y = (0, Z.useMemo)(() => v.some((e) => _.has(e)), [v, _]);
    (0, Z.useEffect)(() => {
      if (t?.vetoExecPolicy) {
        l(t.vetoExecPolicy.enabled);
        let e = t.vetoExecPolicy.executables.map((e) => ({ id: s(), value: e }));
        (e.push({ id: s(), value: `` }), f(e));
        let n = t.vetoExecPolicy.action;
        m(n === A.AUDIT ? A.AUDIT : A.BLOCK);
      }
    }, [t, s]);
    let b = (0, Z.useCallback)(
        (e) => ({
          vetoExecPolicy: d(N, { enabled: e.enabled ?? c, executables: e.executables ?? v, action: e.action ?? p }),
        }),
        [c, p, v],
      ),
      x = (0, Z.useCallback)(
        async (e) => {
          if (e && v.length > vt) {
            r({
              title: `Maximum ${vt} executables allowed`,
              description: `You have ${v.length} entries. Please reduce the list before enabling.`,
            });
            return;
          }
          let t = c;
          l(e);
          try {
            (await n.mutateAsync(b({ enabled: e })),
              r({ title: e ? `Executable deny list enabled` : `Executable deny list disabled` }));
          } catch (e) {
            (console.error(e),
              l(t),
              r({ title: `We couldn't save your changes. Sorry about that! Please retry.`, description: L(e) }));
          }
        },
        [c, v, b, n, r],
      ),
      S = (0, Z.useCallback)((e) => {
        (f(e), g(!0));
      }, []),
      C = (0, Z.useCallback)((e) => {
        (m(e ? A.BLOCK : A.AUDIT), g(!0));
      }, []),
      w = (0, Z.useCallback)(async () => {
        try {
          (await n.mutateAsync(b({})), g(!1), r({ title: `Executable deny list updated` }));
        } catch (e) {
          (console.error(e),
            r({ title: `We couldn't save your changes. Sorry about that! Please retry.`, description: L(e) }));
        }
      }, [b, n, r]);
    return (0, Q.jsxs)(`div`, {
      className: `rounded-xl border border-border-base`,
      "data-testid": `executable-deny-list-section`,
      children: [
        (0, Q.jsx)(`div`, {
          className: `flex items-center gap-4 px-5 py-4`,
          children: (0, Q.jsx)(i, {
            id: `executable-deny-list-toggle`,
            label: `Executable Deny List`,
            description: (0, Q.jsxs)(Q.Fragment, {
              children: [
                `Block specific executables from running in all environments`,
                ` `,
                (0, Q.jsx)(Y, {
                  href: `https://ioi.com/docs/ioi/organizations/policies/executable-deny-list`,
                  iconSize: `sm`,
                  children: `Learn more`,
                }),
              ],
            }),
            state: c ? `checked` : `unchecked`,
            onCheckedChange: x,
            disabled: !e,
            "data-testid": `executable-deny-list-toggle`,
            "data-tracking-id": `toggle-executable-deny-list`,
          }),
        }),
        (0, Q.jsxs)(`div`, {
          className: `flex flex-col gap-4 border-t border-border-base px-5 py-4`,
          children: [
            (0, Q.jsx)(ot, { rows: u, onChange: S, disabled: !e, resolveBareNames: !0, maxEntries: vt }),
            y &&
              (0, Q.jsx)(fe, {
                variant: `warning`,
                "data-testid": `ioi-runtime-warning`,
                text: `One or more paths match IOI runtime binaries that are protected by the safelist and will be excluded from enforcement.`,
              }),
            (0, Q.jsx)(Ie, {
              checked: p === A.BLOCK,
              onChange: C,
              disabled: !e,
              label: `Block`,
              hint: p === A.BLOCK ? `Executions matching the deny list will be blocked.` : `Logged only, not blocked.`,
              "data-testid": `enforcement-mode-checkbox`,
            }),
            (0, Q.jsxs)(`div`, {
              className: `flex items-start gap-3`,
              children: [
                (0, Q.jsx)(z, {
                  onClick: w,
                  variant: `secondary`,
                  disabled: !h || !e,
                  loading: n.isPending,
                  "data-testid": `save-executable-deny-list-button`,
                  "data-tracking-id": `save-executable-deny-list`,
                  children: `Save changes`,
                }),
                (0, Q.jsx)(`div`, {
                  className: `ml-auto`,
                  children: (0, Q.jsx)(gt, { executables: v, action: p, disabled: !e }),
                }),
              ],
            }),
          ],
        }),
      ],
    });
  },
  bt = ({ editable: e = !0 }) => {
    let { data: t, isLoading: n } = I(),
      r = D(),
      { toast: i } = R(),
      a = (0, Z.useMemo)(() => {
        let e = t?.maximumEnvironmentLifetime?.seconds;
        return typeof e == `bigint` ? Number(e) : 0;
      }, [t]),
      o = t?.maximumEnvironmentLifetimeStrict ?? !1,
      [s, c] = (0, Z.useState)(void 0),
      [l, u] = (0, Z.useState)(a);
    l !== a && (u(a), c(void 0));
    let f = (0, Z.useMemo)(() => {
        let e = [...Be, { label: `No maximum lifetime`, value: 0 }];
        return (e.some((e) => e.value === a) || e.push({ label: H(a, `long`), value: a }), e);
      }, [a]),
      { data: m } = he(
        (0, Z.useMemo)(() => {
          if (a !== 0) return new Date();
        }, [a]),
      ),
      { data: h } = he(
        (0, Z.useMemo)(() => {
          if (a !== 0) return new Date(Date.now() + 1440 * 60 * 1e3);
        }, [a]),
      ),
      g = Math.max(0, (h ?? 0) - (m ?? 0)),
      _ = (0, Z.useCallback)(
        (e) => {
          let t = parseInt(e, 10);
          c(t === a ? void 0 : t);
        },
        [a],
      ),
      v = (0, Z.useCallback)(async () => {
        if (s === void 0) return;
        let e = { maximumEnvironmentLifetime: d(p, { seconds: BigInt(s), nanos: 0 }) };
        try {
          (await r.mutateAsync(e), i({ title: `Maximum environment lifetime updated` }), c(void 0));
        } catch (e) {
          (console.error(e), i({ title: `Save failed. Please try again.`, description: L(e) }));
        }
      }, [s, r, i]),
      y = (0, Z.useCallback)(() => {
        c(void 0);
      }, []),
      b = (0, Z.useCallback)(
        async (e) => {
          let t = { maximumEnvironmentLifetimeStrict: e };
          try {
            (await r.mutateAsync(t), i({ title: e ? `Strict enforcement on` : `Strict enforcement off` }));
          } catch (e) {
            (console.error(e), i({ title: `Save failed. Please try again.`, description: L(e) }));
          }
        },
        [r, i],
      );
    return (0, Q.jsx)(`div`, {
      className: `flex flex-col gap-3 rounded-lg border border-border-subtle px-5 py-4`,
      children: (0, Q.jsxs)(q, {
        ready: !n,
        children: [
          (0, Q.jsxs)(`div`, {
            className: `flex min-h-[3.5rem] flex-col gap-0.5`,
            children: [
              (0, Q.jsx)(U, { className: `text-base`, children: `Maximum environment lifetime` }),
              (0, Q.jsxs)(G, {
                className: `text-sm text-content-secondary`,
                children: [
                  `Sets the default maximum age for new environments. Environments past this limit become non-compliant. Users receive a warning, and restarting non-compliant environments may be restricted by policy. Existing environments are not affected.`,
                  ` `,
                  (0, Q.jsx)(Y, {
                    href: `https://ioi.com/docs/ioi/organizations/policies/environment-lifetime`,
                    iconSize: `sm`,
                    children: `Learn more`,
                  }),
                ],
              }),
            ],
          }),
          (0, Q.jsx)(K, {
            name: `maximum-environment-lifetime`,
            value: (s ?? a).toString(),
            onValueChange: _,
            disabled: !e || r.isPending,
            className: `max-w-lg`,
            "data-testid": `max-environment-lifetime-field`,
            placeholder: `Choose a duration`,
            children: f.map((e) =>
              (0, Q.jsx)(
                K.Item,
                {
                  value: e.value.toString(),
                  children: (0, Q.jsx)(`div`, {
                    className: `flex w-full items-center justify-between`,
                    children: e.label,
                  }),
                },
                e.value,
              ),
            ),
          }),
          s !== void 0 &&
            (0, Q.jsx)(`div`, {
              className: `flex max-w-lg flex-col gap-2`,
              children: (0, Q.jsxs)(`div`, {
                className: `flex gap-2`,
                children: [
                  (0, Q.jsx)(z, {
                    variant: `primary`,
                    size: `sm`,
                    onClick: v,
                    disabled: r.isPending,
                    loading: r.isPending,
                    "data-tracking-id": `save`,
                    children: `Save`,
                  }),
                  (0, Q.jsx)(z, {
                    variant: `secondary`,
                    size: `sm`,
                    onClick: y,
                    "data-tracking-id": `cancel`,
                    children: `Cancel`,
                  }),
                ],
              }),
            }),
          (0, Q.jsxs)(`div`, {
            className: `flex flex-col gap-3 border-t border-border-subtle pt-3`,
            "data-testid": `strict-enforcement-toggle`,
            children: [
              (0, Q.jsxs)(`div`, {
                className: `flex gap-4`,
                children: [
                  (0, Q.jsx)(`div`, {
                    className: `flex`,
                    children: (0, Q.jsx)(Fe, {
                      id: `strict-enforcement-switch`,
                      state: o ? `checked` : `unchecked`,
                      onToggle: b,
                      disabled: !e,
                      "aria-label": `Restrict starting environments past their set lifetime`,
                    }),
                  }),
                  (0, Q.jsxs)(`div`, {
                    className: `flex flex-col gap-0.5`,
                    children: [
                      (0, Q.jsx)(G, { className: `text-sm font-medium`, children: `Strict enforcement` }),
                      (0, Q.jsx)(G, {
                        className: `text-sm text-content-secondary`,
                        children: `Restricts starting environments past their set lifetime.`,
                      }),
                      (0, Q.jsx)(G, {
                        className: `text-sm text-content-secondary`,
                        children: o
                          ? `Non-compliant environments are blocked from restarting. Admins can grant extensions.`
                          : `Users see a warning but can still restart non-compliant environments.`,
                      }),
                    ],
                  }),
                ],
              }),
              a > 0 && (0, Q.jsx)(xt, { exceededCount: m ?? 0, expiringSoonCount: g }),
            ],
          }),
        ],
      }),
    });
  },
  xt = ({ exceededCount: e, expiringSoonCount: t }) => {
    let n = e > 0,
      r = t > 0;
    if (!n && !r) return null;
    let i = [];
    if (n) {
      let t = e === 1 ? `environment is` : `environments are`;
      i.push(`${e} ${t} non-compliant`);
    }
    if (r) {
      let e = t === 1 ? `environment` : `environments`;
      n
        ? i.push(`${t} more ${e} will become non-compliant within 24 hours`)
        : i.push(`${t} ${e} will become non-compliant within 24 hours`);
    }
    return (0, Q.jsx)(fe, {
      variant: `info`,
      text: (0, Q.jsxs)(`span`, {
        children: [
          i.join(`. `) + `.`,
          ` `,
          (0, Q.jsx)(l, {
            to: `/settings/environments?lifetime=Exceeded`,
            className: `underline underline-offset-2`,
            children: `Review environments`,
          }),
        ],
      }),
    });
  },
  St = ({ title: e, description: t, policyKey: n, dataTestId: r, editable: i = !0 }) => {
    let { data: a, isLoading: o } = I(),
      s = (0, Z.useMemo)(() => {
        if (a && n in a) {
          let e = a[n];
          if (e !== void 0) return Number(e);
        }
        return 10;
      }, [a, n]),
      [c, l] = (0, Z.useState)(void 0),
      u = c ?? s,
      d = c !== void 0 && c !== s,
      f = D(),
      { toast: p } = R(),
      m = (e) => {
        let t = e.target.value;
        if (t === ``) {
          l(``);
          return;
        }
        let n = parseInt(t, 10);
        !isNaN(n) && n >= 0 && l(n);
      },
      h = (0, Z.useCallback)(async () => {
        if (!d) return;
        let t = { [n]: BigInt(typeof u == `number` ? u : 0) };
        try {
          (await f.mutateAsync(t), l(void 0), p({ title: `${e} updated` }));
        } catch (e) {
          (console.error(e),
            p({ title: `We couldn't save your changes. Sorry about that! Please retry.`, description: L(e) }),
            l(void 0));
        }
      }, [d, n, u, f, p, e]),
      g = (0, Z.useCallback)(() => {
        d && h();
      }, [d, h]),
      _ = (0, Z.useCallback)(
        (e) => {
          e.key === `Enter` && d && h();
        },
        [d, h],
      );
    return (0, Q.jsx)(`div`, {
      className: `flex flex-col gap-3 rounded-lg border border-border-subtle px-5 py-4`,
      children: (0, Q.jsxs)(q, {
        ready: !o,
        children: [
          (0, Q.jsxs)(`div`, {
            className: `flex min-h-[3.5rem] flex-col gap-0.5`,
            children: [
              (0, Q.jsx)(U, { className: `text-base`, children: e }),
              (0, Q.jsxs)(G, {
                className: `text-sm text-content-secondary`,
                children: [
                  t,
                  ` `,
                  (0, Q.jsx)(Y, {
                    href: `https://ioi.com/docs/ioi/organizations/policies/environment-limits`,
                    iconSize: `sm`,
                    children: `Learn more`,
                  }),
                ],
              }),
            ],
          }),
          (0, Q.jsx)(W, {
            "data-testid": r,
            type: `number`,
            value: u,
            onChange: m,
            onBlur: g,
            onKeyDown: _,
            min: 1,
            className: `w-full`,
            disabled: !i,
          }),
        ],
      }),
    });
  },
  Ct = ({ editable: e = !0 }) =>
    (0, Q.jsx)(St, {
      dataTestId: `maximum-running-environments-field`,
      title: `Maximum concurrent environments`,
      description: `Maximum running environments per user.`,
      policyKey: `maximumRunningEnvironmentsPerUser`,
      editable: e,
    }),
  wt = ({ editable: e = !0 }) =>
    (0, Q.jsx)(St, {
      dataTestId: `maximum-total-environments-field`,
      title: `Maximum total environments`,
      description: `Limits total environments (running or stopped) per user. Reducing this limit helps control infrastructure costs.`,
      policyKey: `maximumEnvironmentsPerUser`,
      editable: e,
    }),
  Tt = ({ editable: e = !0 }) => {
    let { data: t, isLoading: n } = I(),
      r = D(),
      { toast: i } = R(),
      a = (0, Z.useMemo)(() => {
        let e = t?.maximumEnvironmentTimeout?.seconds;
        return typeof e == `bigint` ? Number(e) : 0;
      }, [t]),
      o = (0, Z.useMemo)(() => {
        let e = [
          { label: `30 minutes`, value: 1800 },
          { label: `1 hour`, value: 3600 },
          { label: `3 hours`, value: 10800 },
          { label: `8 hours`, value: 480 * 60 },
          { label: `No max timeout`, value: 0 },
        ];
        return (e.some((e) => e.value === a) || e.push({ label: H(a, `long`), value: a }), e);
      }, [a]),
      s = (0, Z.useCallback)(
        async (e) => {
          let t = { maximumEnvironmentTimeout: d(p, { seconds: BigInt(parseInt(e, 10)), nanos: 0 }) };
          try {
            (await r.mutateAsync(t), i({ title: `Maximum timeout updated` }));
          } catch (e) {
            (console.error(e),
              i({ title: `We couldn't save your changes. Sorry about that! Please retry.`, description: L(e) }));
          }
        },
        [r, i],
      );
    return (0, Q.jsxs)(`div`, {
      className: `flex flex-col gap-3 rounded-lg border border-border-subtle px-5 py-4`,
      children: [
        (0, Q.jsxs)(`div`, {
          className: `flex flex-col gap-0.5`,
          children: [
            (0, Q.jsx)(U, { className: `text-base`, children: `Maximum environment inactivity timeout` }),
            (0, Q.jsx)(G, {
              className: `text-sm text-content-secondary`,
              children: `Limit the maximum length of time that an environment can be in a running state without explicit user input`,
            }),
          ],
        }),
        (0, Q.jsx)(q, {
          ready: !n,
          children: (0, Q.jsx)(K, {
            name: `maximum-timeout`,
            value: a.toString(),
            onValueChange: s,
            disabled: !e,
            className: `max-w-lg`,
            placeholder: `Select a timeout`,
            children: o.map((e) =>
              (0, Q.jsx)(
                K.Item,
                {
                  value: e.value.toString(),
                  children: (0, Q.jsx)(`div`, {
                    className: `flex w-full items-center justify-between`,
                    children: e.label,
                  }),
                },
                e.value,
              ),
            ),
          }),
        }),
      ],
    });
  },
  Et = `https://ioi.com/docs/ioi/organizations/policies/port-sharing#maximum-port-admission-level`,
  Dt = [
    { label: `Creator only`, value: `creator-only` },
    { label: `Organization members only`, value: `organization` },
    { label: `Anyone (no login required)`, value: `everyone` },
  ];
function Ot(e) {
  switch (e?.maxPortAdmissionLevel) {
    case k.CREATOR_ONLY:
    case k.OWNER_ONLY:
      return `creator-only`;
    case k.ORGANIZATION:
      return `organization`;
    case k.EVERYONE:
    case k.UNSPECIFIED:
    default:
      return `everyone`;
  }
}
function kt(e) {
  switch (e) {
    case `creator-only`:
      return { maxPortAdmissionLevel: k.CREATOR_ONLY };
    case `organization`:
      return { maxPortAdmissionLevel: k.ORGANIZATION };
    case `everyone`:
      return { maxPortAdmissionLevel: k.UNSPECIFIED };
  }
}
var At = ({ editable: e = !0 }) => {
    let { data: t, isLoading: n } = I(),
      r = D(),
      { toast: a } = R(),
      o = !t?.portSharingDisabled,
      s = (0, Z.useMemo)(() => Ot(t), [t]),
      c = (0, Z.useCallback)(
        async (e) => {
          try {
            (await r.mutateAsync({ portSharingDisabled: !e }),
              a({ title: e ? `Port sharing enabled` : `Port sharing disabled` }));
          } catch (e) {
            (console.error(e),
              a({ title: `We couldn't save your changes. Sorry about that! Please retry.`, description: L(e) }));
          }
        },
        [r, a],
      ),
      l = (0, Z.useCallback)(
        async (e) => {
          try {
            (await r.mutateAsync(kt(e)), a({ title: `Port sharing access policy updated` }));
          } catch (e) {
            (console.error(e),
              a({ title: `We couldn't save your changes. Sorry about that! Please retry.`, description: L(e) }));
          }
        },
        [r, a],
      );
    return (0, Q.jsx)(`div`, {
      className: `flex flex-col gap-5 rounded-lg border border-border-subtle px-5 py-4`,
      children: (0, Q.jsxs)(q, {
        ready: !n,
        children: [
          (0, Q.jsx)(i, {
            label: `Allow Port Sharing in Environments`,
            description: `Control whether users can share ports from their environments with external access. VS Code Browser and agents are exempt from this policy and will continue to work when disabled.`,
            state: o ? `checked` : `unchecked`,
            onCheckedChange: c,
            disabled: !e,
            id: `port-sharing-switch`,
            "data-testid": `port-sharing-switch`,
          }),
          (0, Q.jsxs)(`div`, {
            className: `ml-12 flex flex-col gap-3`,
            children: [
              (0, Q.jsxs)(`div`, {
                className: `flex flex-col gap-1`,
                children: [
                  (0, Q.jsx)(G, { className: `text-base font-medium`, children: `Maximum port admission level` }),
                  (0, Q.jsxs)(G, {
                    className: `text-sm text-content-secondary`,
                    children: [
                      `Control the most permissive access level users can choose for shared environment ports.`,
                      ` `,
                      (0, Q.jsx)(Y, { href: Et, iconSize: `sm`, children: `Learn more` }),
                    ],
                  }),
                ],
              }),
              (0, Q.jsx)(K, {
                id: `max-port-admission-level-select`,
                name: `max-port-admission-level`,
                value: s,
                onValueChange: l,
                disabled: !e || !o,
                "data-testid": `max-port-admission-level-select`,
                "aria-label": `Maximum port admission level`,
                className: `w-full max-w-lg`,
                children: Dt.map((e) => (0, Q.jsx)(K.Item, { value: e.value, children: e.label }, e.value)),
              }),
            ],
          }),
        ],
      }),
    });
  },
  jt = () => {
    let { data: e, isLoading: t } = I(),
      { membership: n } = de(),
      r = n?.organizationId || ``,
      { hasPermission: i } = me(T.ORGANIZATION, r, `orgpolicy:update`);
    return (0, Q.jsxs)(`div`, {
      className: `flex flex-col gap-4`,
      children: [
        (0, Q.jsx)(`h3`, { className: `text-lg font-semibold`, children: `Project Creation Defaults` }),
        (0, Q.jsx)(Mt, { organizationPolicies: e, isLoading: t, disabled: !i }),
      ],
    });
  },
  Mt = ({ organizationPolicies: e, isLoading: t, disabled: n }) => {
    let r = D(),
      { value: i } = te(),
      { data: a } = le(),
      o = a?.tier === w.ENTERPRISE,
      { toast: s } = R(),
      c = e?.projectCreationDefaults?.insightsEnabled ?? !1,
      l = (0, Z.useCallback)(
        async (e) => {
          try {
            await r.mutateAsync({ projectCreationDefaults: d(_, { insightsEnabled: e === !0 }) });
          } catch (e) {
            (console.error(e),
              s({ title: `We couldn't save your changes. Sorry about that! Please retry.`, description: L(e) }));
          }
        },
        [r, s],
      );
    return !i || !o
      ? null
      : (0, Q.jsx)(`div`, {
          className: `flex flex-col gap-4 rounded-lg border border-border-subtle px-5 py-4`,
          children: (0, Q.jsx)(q, {
            ready: !t,
            children: (0, Q.jsxs)(`div`, {
              className: `flex flex-col gap-1`,
              children: [
                (0, Q.jsx)(`div`, {
                  className: `flex items-center gap-2`,
                  children: (0, Q.jsxs)(Pe, {
                    className: `flex items-center gap-2`,
                    children: [
                      (0, Q.jsx)(Me, {
                        "data-testid": `insights-enabled-checkbox`,
                        id: `insights-enabled`,
                        checked: c,
                        onCheckedChange: l,
                        disabled: n,
                      }),
                      (0, Q.jsx)(`span`, {
                        className: `text-base font-medium`,
                        children: `Enable Insights for new projects`,
                      }),
                    ],
                  }),
                }),
                (0, Q.jsx)(G, {
                  className: `pl-6 text-sm text-content-secondary`,
                  children: `Automatically enable Insights on newly created projects. Insights analyze development activity and incur usage costs.`,
                }),
              ],
            }),
          }),
        });
  },
  Nt = ({ editable: e = !0 }) => {
    let { data: t, isLoading: n } = I(),
      { data: r = [], isLoading: a } = He(),
      o = D(),
      { toast: s } = R(),
      c = t?.restrictAccountCreationToScim ?? !1,
      l = r.some((e) => e.enabled),
      u = !e || !l,
      d = n || a,
      f = (0, Z.useCallback)(
        async (e) => {
          let t = { restrictAccountCreationToScim: e };
          try {
            (await o.mutateAsync(t),
              s({ title: e ? `Account creation restricted to SCIM` : `Account creation restriction removed` }));
          } catch (e) {
            (console.error(e),
              s({ title: `We couldn't save your changes. Sorry about that! Please retry.`, description: L(e) }));
          }
        },
        [o, s],
      );
    return (0, Q.jsx)(`div`, {
      className: `flex flex-col gap-4 rounded-lg border border-border-subtle px-5 py-4`,
      children: (0, Q.jsx)(q, {
        ready: !d,
        children: (0, Q.jsxs)(`div`, {
          className: `flex flex-col gap-1`,
          children: [
            (0, Q.jsx)(i, {
              id: `scim-account-restriction-switch`,
              label: `Restrict Account Creation to SCIM`,
              description: `When enabled, only users provisioned via SCIM can access this organization. Users attempting to login via SSO without a SCIM-provisioned account will be blocked.`,
              state: c ? `checked` : `unchecked`,
              onCheckedChange: f,
              disabled: u,
            }),
            !l &&
              !d &&
              (0, Q.jsx)(G, {
                className: `ml-12 text-sm text-content-tertiary`,
                children: `Configure SCIM provisioning to enable this policy.`,
              }),
          ],
        }),
      }),
    });
  },
  Pt =
    /^(?:(?:(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])(?:\.(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]))*(?::[0-9]+)?\/)?[a-z0-9]+(?:(?:(?:[._]|__|[-]*)[a-z0-9]+)+)?(?:\/[a-z0-9]+(?:(?:(?:[._]|__|[-]*)[a-z0-9]+)+)?)*(?::[a-zA-Z0-9_.-]{1,128})?(?:@[a-z][a-z0-9]*(?:[.-][a-z][a-z0-9]*)*:[a-f0-9]{64})?|[a-z0-9]+(?:[._][a-z0-9]+)*)$/i,
  Ft = /^[a-zA-Z0-9/_-]+$/,
  It = ({ currentConfig: e, existingCustomAgents: t, onClose: n }) => {
    let { data: r } = le(),
      [i, a] = (0, Z.useState)(``),
      [o, s] = (0, Z.useState)(``),
      [l, u] = (0, Z.useState)(!1),
      [f, p] = (0, Z.useState)(``),
      [h, g] = (0, Z.useState)(``),
      [_, v] = (0, Z.useState)({}),
      [b, x] = (0, Z.useState)(!1),
      S = (0, Z.useRef)(null),
      [w, T] = (0, Z.useState)(null),
      [E, O] = (0, Z.useState)(null),
      [k, A] = (0, Z.useState)(null),
      j = D(),
      M = Ce(),
      N = Se(),
      { toast: P } = R();
    (0, Z.useEffect)(() => {
      e &&
        (s(e.cidSecretId || ``), u(!!e.cidSecretId), p(e.image || ``), g(e.tags || ``), v(e.additionalOptions || {}));
    }, [e]);
    let te = (0, Z.useCallback)(
        (e) =>
          e.trim()
            ? Pt.test(e)
              ? (O(null), !0)
              : (O(`Expected format: [HOST[:PORT]/]NAMESPACE/REPOSITORY[:TAG]`), !1)
            : (O(`Falcon sensor image is required`), !1),
        [],
      ),
      ne = (0, Z.useCallback)((e) => (!e.trim() && !o ? (T(`Customer ID is required`), !1) : (T(null), !0)), [o]),
      re = (0, Z.useCallback)((e) => {
        if (!e.trim()) return (A(null), !0);
        let t = e.split(`,`).map((e) => e.trim());
        for (let e of t) if (e && !Ft.test(e)) return (A(`Tags can only contain alphanumerics, '/', '-', and '_'`), !1);
        return (A(null), !0);
      }, []),
      ie = (0, Z.useCallback)(async () => {
        let e = ne(i),
          a = te(f),
          s = re(h);
        if (!(!e || !a || !s))
          try {
            let e = o;
            if (i.trim()) {
              if (!r?.id) throw Error(`Organization ID not available`);
              if (e)
                try {
                  await N.mutateAsync({ secretId: e, plaintextValue: i });
                } catch {
                  (console.log(`Secret not found, creating new one`),
                    (e = (
                      await M.mutateAsync({
                        scope: d(ee, { scope: { value: r.id, case: `organizationId` } }),
                        secretName: `crowdstrike_falcon_cid`,
                        plaintextValue: i,
                        mount: { case: `apiOnly`, value: !0 },
                      })
                    )?.id));
                }
              else
                e = (
                  await M.mutateAsync({
                    scope: d(ee, { scope: { value: r.id, case: `organizationId` } }),
                    secretName: `crowdstrike_falcon_cid`,
                    plaintextValue: i,
                    mount: { case: `apiOnly`, value: !0 },
                  })
                )?.id;
            }
            let a = d(oe, {
              crowdstrike: d(C, { cidSecretId: e, image: f, tags: h, additionalOptions: _ }),
              customAgents: t,
            });
            (await j.mutateAsync({ securityAgentPolicy: a }),
              P({ title: `CrowdStrike settings saved`, description: `Configuration has been updated successfully` }),
              n());
          } catch (e) {
            console.error(e);
            let t = L(e),
              n = String(e);
            (n.includes(`pattern`) || n.includes(`name`)
              ? (t = `Failed to save CrowdStrike configuration. Please check that all fields are valid.`)
              : n.includes(`secret`) && (t = `Failed to store Customer ID securely. Please try again.`),
              P({ title: `Failed to save CrowdStrike settings`, description: t }));
          }
      }, [i, o, f, h, _, t, r?.id, ne, te, re, M, N, j, P, n]),
      ae = (0, Z.useCallback)(() => {
        let e = `option_${Object.keys(_).length + 1}`;
        v({ ..._, [e]: `` });
      }, [_]),
      se = (0, Z.useCallback)(
        (e) => {
          let t = { ..._ };
          (delete t[e], v(t));
        },
        [_],
      ),
      F = (0, Z.useCallback)(
        (e, t) => {
          let n = { ..._ },
            r = n[e];
          (delete n[e], (n[t] = r), v(n));
        },
        [_],
      ),
      I = (0, Z.useCallback)(
        (e, t) => {
          v({ ..._, [e]: t });
        },
        [_],
      ),
      ce = o ? `Enter new value to update` : `Enter Customer ID`,
      ue = l ? `••••••••••••••••` : i,
      de = (i.trim() || o) && f.trim() && !w && !E;
    return (0, Q.jsx)(V, {
      open: !0,
      onOpenChange: (e) => !e && n(),
      children: (0, Q.jsxs)(V.Content, {
        className: `max-w-[600px]`,
        "data-testid": `configure-crowdstrike-modal`,
        "data-track-location": y.ConfigureCrowdStrikeModal,
        children: [
          (0, Q.jsxs)(V.Header, {
            children: [
              (0, Q.jsx)(V.Title, { children: `Configure CrowdStrike Falcon` }),
              (0, Q.jsx)(V.Description, { children: `Configure security agent deployment settings` }),
            ],
          }),
          (0, Q.jsxs)(V.Body, {
            className: `space-y-4`,
            children: [
              (0, Q.jsx)(X, {
                id: `crowdstrike-cid`,
                label: (0, Q.jsxs)(Q.Fragment, {
                  children: [
                    `Customer ID (CID) `,
                    (0, Q.jsx)(`span`, { className: `text-content-error`, children: `*` }),
                  ],
                }),
                hint: `Your CrowdStrike Customer ID for authentication`,
                error: w,
                children: (0, Q.jsx)(ze, {
                  ref: S,
                  id: `crowdstrike-cid`,
                  "data-testid": `crowdstrike-cid-input`,
                  "data-tracking-id-none": !0,
                  value: ue,
                  onChange: (e) => {
                    (a(e.target.value), T(null));
                  },
                  onFocus: () => {
                    l && (u(!1), a(``));
                  },
                  onClick: () => {
                    l && (u(!1), a(``));
                  },
                  onBlur: () => {
                    o && !i.trim() && u(!0);
                  },
                  placeholder: ce,
                  className: B(w && `border-border-error`),
                  "data-tracking-id": `default-tracking-id`,
                }),
              }),
              (0, Q.jsx)(X, {
                id: `crowdstrike-image`,
                label: (0, Q.jsxs)(Q.Fragment, {
                  children: [
                    `Falcon Sensor Image `,
                    (0, Q.jsx)(`span`, { className: `text-content-error`, children: `*` }),
                  ],
                }),
                hint: `Docker image reference for the CrowdStrike Falcon sensor`,
                error: E,
                children: (0, Q.jsx)(W, {
                  id: `crowdstrike-image`,
                  "data-testid": `crowdstrike-image-input`,
                  type: `text`,
                  value: f,
                  onChange: (e) => {
                    (p(e.target.value), O(null));
                  },
                  placeholder: `quay.io/crowdstrike/falcon-sensor:latest`,
                  className: B(E && `border-border-error`),
                }),
              }),
              (0, Q.jsxs)(we, {
                open: b,
                onOpenChange: x,
                children: [
                  (0, Q.jsx)(we.Trigger, {
                    asChild: !0,
                    children: (0, Q.jsxs)(z, {
                      variant: `ghost`,
                      className: `flex items-center gap-2 p-2 text-sm font-medium text-content-secondary hover:text-content-primary`,
                      "data-testid": `advanced-options-toggle`,
                      "data-tracking-id": `toggle-crowdstrike-advanced-options-modal`,
                      children: [
                        (0, Q.jsx)(c, { className: B(`h-4 w-4 transition-transform`, b && `rotate-180`) }),
                        `Advanced options`,
                      ],
                    }),
                  }),
                  (0, Q.jsxs)(we.Content, {
                    className: `mt-6 space-y-4`,
                    children: [
                      (0, Q.jsx)(X, {
                        id: `crowdstrike-tags`,
                        label: `Tags (optional)`,
                        hint: `Comma-separated tags to apply to the Falcon sensor`,
                        error: k,
                        children: (0, Q.jsx)(W, {
                          id: `crowdstrike-tags`,
                          "data-testid": `crowdstrike-tags-input`,
                          type: `text`,
                          value: h,
                          onChange: (e) => {
                            (g(e.target.value), A(null));
                          },
                          placeholder: `ioi,production,team/security`,
                        }),
                      }),
                      (0, Q.jsxs)(`div`, {
                        className: `flex flex-col gap-2`,
                        children: [
                          (0, Q.jsx)(`label`, {
                            className: `text-base font-normal text-content-primary`,
                            children: `Additional Falcon Options`,
                          }),
                          (0, Q.jsx)(`span`, {
                            className: `text-sm text-content-tertiary`,
                            children: `Additional FALCONCTL_OPT_* options as key-value pairs. Keys should NOT include the FALCONCTL_OPT_ prefix.`,
                          }),
                          (0, Q.jsxs)(`div`, {
                            className: `flex flex-col gap-2`,
                            children: [
                              Object.entries(_).map(([e, t]) =>
                                (0, Q.jsxs)(
                                  `div`,
                                  {
                                    className: `flex items-center gap-2`,
                                    children: [
                                      (0, Q.jsx)(W, {
                                        type: `text`,
                                        value: e,
                                        onChange: (t) => F(e, t.target.value),
                                        placeholder: `Key`,
                                        className: `w-40`,
                                        "data-testid": `option-key-${e}`,
                                      }),
                                      (0, Q.jsx)(W, {
                                        type: `text`,
                                        value: t,
                                        onChange: (t) => I(e, t.target.value),
                                        placeholder: `Value`,
                                        className: `flex-1`,
                                        "data-testid": `option-value-${e}`,
                                      }),
                                      (0, Q.jsx)(z, {
                                        variant: `ghost`,
                                        size: `sm`,
                                        onClick: () => se(e),
                                        className: `h-9 w-9 p-0`,
                                        "data-testid": `remove-option-${e}`,
                                        "data-tracking-id": `remove-option-${e}-modal`,
                                        children: (0, Q.jsx)(m, { className: `h-4 w-4` }),
                                      }),
                                    ],
                                  },
                                  e,
                                ),
                              ),
                              (0, Q.jsx)(z, {
                                variant: `secondary`,
                                size: `sm`,
                                onClick: ae,
                                className: `self-start`,
                                "data-testid": `add-option-button`,
                                "data-tracking-id": `add-falcon-option-modal`,
                                children: `+ Add option`,
                              }),
                            ],
                          }),
                        ],
                      }),
                    ],
                  }),
                ],
              }),
            ],
          }),
          (0, Q.jsxs)(V.Footer, {
            children: [
              (0, Q.jsx)(V.Close, {
                asChild: !0,
                children: (0, Q.jsx)(z, {
                  variant: `outline`,
                  "data-tracking-id": `cancel-crowdstrike-settings`,
                  children: `Cancel`,
                }),
              }),
              (0, Q.jsx)(z, {
                onClick: ie,
                disabled: !de,
                "data-testid": `save-crowdstrike-settings`,
                "data-tracking-id": `save-crowdstrike-settings`,
                children: `Save settings`,
              }),
            ],
          }),
        ],
      }),
    });
  },
  Lt = ({ editable: e = !0 }) => {
    let { data: t, isLoading: n } = I(),
      [r, a] = (0, Z.useState)(!1),
      o = D(),
      { toast: s } = R(),
      c = t?.securityAgentPolicy?.crowdstrike?.enabled ?? !1,
      l = (0, Z.useCallback)(
        async (e) => {
          try {
            let n = d(oe, {
              crowdstrike: d(C, { enabled: e }),
              customAgents: t?.securityAgentPolicy?.customAgents ?? [],
            });
            (await o.mutateAsync({ securityAgentPolicy: n }),
              s({ title: e ? `CrowdStrike Falcon enabled` : `CrowdStrike Falcon disabled` }));
          } catch (e) {
            (console.error(e),
              s({ title: `We couldn't save your changes. Sorry about that! Please retry.`, description: L(e) }));
          }
        },
        [o, s, t],
      ),
      u = (0, Z.useCallback)(() => {
        a(!0);
      }, []),
      f = (0, Z.useCallback)(() => {
        a(!1);
      }, []);
    return (0, Q.jsxs)(q, {
      ready: !n,
      children: [
        (0, Q.jsx)(`div`, {
          className: `rounded-xl border border-border-base`,
          children: (0, Q.jsxs)(`div`, {
            className: `flex flex-col justify-between gap-4 px-5 py-4 lg:flex-row lg:items-center lg:gap-8`,
            children: [
              (0, Q.jsx)(`div`, {
                className: `flex min-w-0 items-center`,
                children: (0, Q.jsx)(i, {
                  id: `crowdstrike-falcon-switch`,
                  label: `CrowdStrike Falcon`,
                  description: (0, Q.jsxs)(Q.Fragment, {
                    children: [
                      `Deploy CrowdStrike Falcon sensor to all environments.`,
                      ` `,
                      (0, Q.jsx)(Y, {
                        href: `https://ioi.com/docs/ioi/organizations/policies#security-agents`,
                        iconSize: `sm`,
                        children: `Learn more`,
                      }),
                    ],
                  }),
                  state: c ? `checked` : `unchecked`,
                  onCheckedChange: l,
                  disabled: !e,
                  "data-tracking-id": `toggle-crowdstrike-falcon`,
                }),
              }),
              (0, Q.jsxs)(z, {
                variant: `secondary`,
                onClick: u,
                disabled: !e,
                "data-testid": `configure-crowdstrike-button`,
                className: `flex items-center gap-2 self-start lg:self-auto`,
                "data-tracking-id": `configure-crowdstrike-settings`,
                children: [(0, Q.jsx)(Ve, { size: `base` }), `Settings`],
              }),
            ],
          }),
        }),
        r &&
          (0, Q.jsx)(It, {
            currentConfig: t?.securityAgentPolicy?.crowdstrike,
            existingCustomAgents: t?.securityAgentPolicy?.customAgents ?? [],
            onClose: f,
          }),
      ],
    });
  },
  Rt = ({ editable: e = !0 }) => {
    let { data: t, isLoading: n } = I(),
      r = D(),
      { toast: i } = R(),
      a = !t?.webBrowserDisabled,
      o = (0, Z.useCallback)(
        async (e) => {
          try {
            (await r.mutateAsync({ webBrowserDisabled: !e }),
              i({ title: e ? `Web browser enabled` : `Web browser disabled` }));
          } catch (e) {
            (console.error(e),
              i({ title: `We couldn't save your changes. Sorry about that! Please retry.`, description: L(e) }));
          }
        },
        [r, i],
      );
    return (0, Q.jsx)(`div`, {
      className: `flex flex-col gap-4 rounded-lg border border-border-subtle px-5 py-4`,
      children: (0, Q.jsx)(q, {
        ready: !n,
        children: (0, Q.jsxs)(`div`, {
          className: `flex gap-4`,
          children: [
            (0, Q.jsx)(`div`, {
              className: `flex`,
              children: (0, Q.jsx)(Fe, {
                id: `web-browser-switch`,
                state: a ? `checked` : `unchecked`,
                onToggle: o,
                disabled: !e,
                isLoading: r.isPending,
                "data-testid": `web-browser-switch`,
                "aria-label": `Allow web browser in environments`,
              }),
            }),
            (0, Q.jsxs)(`div`, {
              className: `flex flex-col gap-1`,
              children: [
                (0, Q.jsx)(G, { className: `text-base font-medium`, children: `Allow Web Browser in Environments` }),
                (0, Q.jsx)(G, {
                  className: `text-sm text-content-secondary`,
                  children: `Control whether users can open the built-in browser panel from environment pages. This does not affect VS Code Browser.`,
                }),
              ],
            }),
          ],
        }),
      }),
    });
  },
  zt = () => {
    n(`Policies`);
    let { membership: e, isPending: r } = de(),
      { data: i, isPending: a } = le(),
      { value: o } = M(),
      { value: s } = ae(),
      { value: c } = se(),
      { value: u } = re(),
      { value: d } = ce();
    if (r || !e || a || !i) return null;
    if (e.userRole !== x.ADMIN) return (0, Q.jsx)(t, {});
    let f = i.tier === w.ENTERPRISE,
      p = i.tier === w.CORE;
    return (0, Q.jsxs)(`div`, {
      className: `flex max-w-[46rem] flex-col gap-4`,
      "data-testid": `organization-policies-page`,
      children: [
        (0, Q.jsx)(G, {
          className: `text-base text-content-secondary`,
          children: `Configure organization-wide policies.`,
        }),
        !f &&
          (0, Q.jsx)(fe, {
            variant: `info`,
            className: `py-4`,
            "data-testid": `free-tier-banner`,
            text: (0, Q.jsxs)(Q.Fragment, {
              children: [
                `Upgrade to`,
                ` `,
                (0, Q.jsx)(l, {
                  to: `/settings/manage-organization`,
                  className: `font-medium text-content-brand hover:underline`,
                  children: `Enterprise tier`,
                }),
                ` `,
                `to manage policies and unlock more features.`,
              ],
            }),
          }),
        (0, Q.jsx)(Ke, { editable: f }),
        (0, Q.jsxs)(`div`, {
          className: `flex flex-col gap-4`,
          children: [
            (0, Q.jsx)(`h2`, { className: `text-xl font-semibold`, children: `Environment policies` }),
            (0, Q.jsx)(Tt, { editable: p || f }),
            (0, Q.jsx)(bt, { editable: f }),
            d && (0, Q.jsx)(Ue, { editable: f }),
            (0, Q.jsx)(We, { editable: f }),
            (0, Q.jsx)(wt, { editable: f }),
            (0, Q.jsx)(Ct, { editable: f }),
            (0, Q.jsx)(tt, { editable: f }),
            (0, Q.jsx)(rt, { editable: f }),
            (0, Q.jsx)(At, { editable: f }),
            c && (0, Q.jsx)(Rt, { editable: f }),
          ],
        }),
        (0, Q.jsxs)(`div`, {
          className: `flex flex-col gap-4`,
          children: [
            (0, Q.jsx)(`h2`, { className: `text-xl font-semibold`, children: `Project policies` }),
            (0, Q.jsx)(it, { editable: f }),
            u && (0, Q.jsx)(jt, {}),
          ],
        }),
        (0, Q.jsxs)(`div`, {
          className: `flex flex-col gap-4`,
          children: [
            (0, Q.jsx)(`h2`, { className: `text-xl font-semibold`, children: `Security Agents` }),
            (0, Q.jsx)(Lt, { editable: f }),
            s &&
              f &&
              (0, Q.jsxs)(Q.Fragment, {
                children: [
                  (0, Q.jsx)(`h3`, { className: `text-lg font-semibold`, children: `Custom Security Agents` }),
                  (0, Q.jsx)($e, { editable: f }),
                ],
              }),
          ],
        }),
        o &&
          (0, Q.jsxs)(`div`, {
            className: `flex flex-col gap-4`,
            children: [
              (0, Q.jsx)(`h2`, { className: `text-xl font-semibold`, children: `Veto` }),
              (0, Q.jsx)(yt, { editable: f }),
            ],
          }),
        (0, Q.jsxs)(`div`, {
          className: `flex flex-col gap-4`,
          children: [
            (0, Q.jsx)(`h2`, { className: `text-xl font-semibold`, children: `Identity & Access` }),
            (0, Q.jsx)(Nt, { editable: f }),
          ],
        }),
      ],
    });
  };
export { zt as OrganizationPoliciesPage };

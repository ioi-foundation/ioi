import { a as e } from "./rolldown-runtime-CGYlQKCx.js";
import { It as t, Kt as n, Lt as r, v as i, zt as a } from "./SegmentProvider-CXCNBY9U.js";
import { n as o } from "./@mux-DLaEVubF.js";
import { Xh as s, Yh as c, bc as l, cg as ee, eg as u, g_ as d, qh as f, v_ as p } from "./vendor-DAwbZtf0.js";
import {
  Ai as m,
  Dr as h,
  Dt as g,
  Fi as _,
  Gi as v,
  Li as te,
  Mi as y,
  Ni as b,
  Pi as x,
  Sr as S,
  hr as C,
  tr as ne,
  vn as re,
  xr as w,
} from "./use-boot-in-app-chat-t-J_VjKS.js";
import { t as T } from "./use-theme-DWCPVAsU.js";
import { n as ie } from "./toast-axaLeIzZ.js";
import { t as E } from "./button-6YP03Qf2.js";
import { t as D } from "./cn-DppMFCU8.js";
import { t as O } from "./dialog-BtjFqa-w.js";
import { t as ae } from "./use-membership-CcV5kGny.js";
import { t as oe } from "./banner-CFcSGYsz.js";
import { t as k } from "./timestamp-CEKPQVte.js";
import { r as A } from "./headings-CM9JBOhQ.js";
import { t as j } from "./text-fFCFeCas.js";
import { t as M } from "./external-link-BKbp1Q22.js";
import "./register-Cy3DR9hT.js";
var N = e(o(), 1),
  P = { oidcConfig: (e) => C([`oidcConfig`, e]) },
  F = (e) => {
    let t = h();
    return c({
      queryKey: P.oidcConfig(e),
      queryFn: async () => {
        if (!e) throw Error(`Organization ID is required`);
        return (await t.organizationService.getOIDCConfig(d(m, { organizationId: e }))).oidcConfig;
      },
      enabled: !!e,
      retry: w,
      throwOnError: S,
    });
  },
  I = (e) => s(F(e)),
  se = (e) => {
    let t = h(),
      n = u();
    return f({
      mutationFn: async (n) => {
        if (!e) throw Error(`Organization ID is required`);
        return (await t.organizationService.updateOIDCConfig(d(v, { organizationId: e, oidcConfig: n }))).oidcConfig;
      },
      onSuccess: () => {
        n.invalidateQueries({ queryKey: P.oidcConfig(e) });
      },
    });
  },
  L = new Date(`2026-04-18T00:00:00.000Z`);
function ce(e) {
  return e?.createdAt ? k(e.createdAt).getTime() >= L.getTime() : !1;
}
var R = p(),
  le = ({ open: e, onOpenChange: t, onConfirm: n, isLoading: r = !1, changeDescription: i }) =>
    (0, R.jsx)(O, {
      open: e,
      onOpenChange: t,
      children: (0, R.jsxs)(O.Content, {
        "data-testid": `oidc-save-confirmation-modal`,
        "data-track-location": g.OidcSaveConfirmationModal,
        children: [
          (0, R.jsxs)(O.Header, {
            children: [
              (0, R.jsx)(O.Title, { children: `Confirm OIDC Configuration Change` }),
              (0, R.jsx)(O.Description, { children: i }),
            ],
          }),
          (0, R.jsxs)(O.Footer, {
            children: [
              (0, R.jsx)(O.Close, {
                asChild: !0,
                children: (0, R.jsx)(E, { variant: `outline`, disabled: r, children: `Cancel` }),
              }),
              (0, R.jsx)(E, {
                variant: `destructive`,
                onClick: n,
                loading: r,
                disabled: r,
                "data-testid": `confirm-oidc-save`,
                "data-tracking-id": `confirm-oidc-save`,
                children: `Confirm`,
              }),
            ],
          }),
        ],
      }),
    }),
  z = 50,
  B = ({ fields: e, onChange: t, disabled: n = !1, className: r, "data-testid": i = `oidc-sub-claim-editor` }) => {
    let a = e.length < z && !n,
      o = (0, N.useCallback)(() => {
        a && t([...e, ``]);
      }, [a, e, t]),
      s = (0, N.useCallback)(
        (n) => {
          t(e.filter((e, t) => t !== n));
        },
        [e, t],
      ),
      c = (0, N.useCallback)(
        (n, r) => {
          let i = [...e];
          ((i[n] = r), t(i));
        },
        [e, t],
      ),
      l = V(e);
    return (0, R.jsxs)(`div`, {
      className: D(`flex flex-col gap-3`, r),
      "data-testid": i,
      children: [
        (0, R.jsxs)(`div`, {
          className: `flex flex-col gap-1`,
          children: [
            (0, R.jsx)(A, { children: `Custom Sub Claim Fields` }),
            (0, R.jsxs)(j, {
              className: `text-base text-content-secondary`,
              children: [
                (0, R.jsxs)(`span`, {
                  children: [
                    `Add additional property keys to include in the V3 token `,
                    (0, R.jsx)(`code`, { className: `font-mono`, children: `sub` }),
                    ` `,
                    `claim.`,
                  ],
                }),
                e.length > 0 &&
                  (0, R.jsxs)(`span`, {
                    className: `ml-1 text-content-tertiary`,
                    children: [`(`, e.length, `/`, z, `)`],
                  }),
                (0, R.jsx)(M, {
                  href: `https://ioi.com/docs/ioi/configuration/oidc#customizing-the-sub-claim`,
                  iconSize: `sm`,
                  className: `ml-1`,
                  children: `Learn more`,
                }),
              ],
            }),
          ],
        }),
        e.length > 0 &&
          (0, R.jsx)(`div`, {
            className: `flex flex-col gap-2`,
            "data-testid": `field-list`,
            children: e.map((e, t) => {
              let r = e.trim() === ``,
                i = l.has(t);
              return (0, R.jsxs)(
                `div`,
                {
                  className: `flex items-start gap-2`,
                  children: [
                    (0, R.jsxs)(`div`, {
                      className: `flex flex-1 flex-col gap-1`,
                      children: [
                        (0, R.jsx)(`input`, {
                          type: `text`,
                          value: e,
                          onChange: (e) => c(t, e.target.value),
                          disabled: n,
                          placeholder: `e.g. project_id, creator_email`,
                          className: D(
                            `h-9 w-full rounded-lg border bg-surface-primary px-3 py-2 text-base text-content-primary placeholder:text-content-muted`,
                            `focus-within:ring-4 focus-within:ring-ring-default focus-visible:ring-4 focus-visible:ring-ring-default focus:outline-none`,
                            (r || i) && !r ? `border-border-error` : `border-border-light`,
                            n && `cursor-not-allowed opacity-50`,
                          ),
                          "data-testid": `field-input-${t}`,
                        }),
                        i &&
                          (0, R.jsx)(`span`, {
                            className: `text-content-danger text-sm`,
                            "data-testid": `field-error-${t}`,
                            children: `Duplicate field`,
                          }),
                      ],
                    }),
                    (0, R.jsx)(E, {
                      variant: `ghost`,
                      onClick: () => s(t),
                      disabled: n,
                      "data-testid": `field-remove-${t}`,
                      "data-tracking-id": `remove-oidc-sub-field`,
                      "aria-label": `Remove field ${e || t}`,
                      children: `Remove`,
                    }),
                  ],
                },
                t,
              );
            }),
          }),
        (0, R.jsx)(`div`, {
          children: (0, R.jsx)(E, {
            variant: `outline`,
            onClick: o,
            disabled: !a,
            "data-testid": `add-field-button`,
            "data-tracking-id": `add-oidc-sub-field`,
            children: `Add field`,
          }),
        }),
      ],
    });
  };
function V(e) {
  let t = new Map();
  for (let n = 0; n < e.length; n++) {
    let r = e[n].trim();
    if (r === ``) continue;
    let i = t.get(r) || [];
    (i.push(n), t.set(r, i));
  }
  let n = new Set();
  for (let e of t.values()) if (e.length > 1) for (let t of e) n.add(t);
  return n;
}
var H = `a1b2c3d4-0000-4000-8000-000000000001`,
  U = `a1b2c3d4-0000-4000-8000-000000000002`,
  W = `a1b2c3d4-0000-4000-8000-000000000003`,
  G = `a1b2c3d4-0000-4000-8000-000000000004`,
  ue = `a1b2c3d4-0000-4000-8000-000000000005`,
  K = `a1b2c3d4-0000-4000-8000-000000000006`,
  q = `https://app.ioi.io`,
  J = [`sts.amazonaws.com`],
  Y = 1711929600,
  X = 1711926e3,
  de = {
    account: {
      iss: q,
      sub: `account:${H}:${U}`,
      aud: J,
      exp: Y,
      iat: X,
      gsub: { principal: `account`, id: U },
      org: H,
    },
    user: { iss: q, sub: `user:${H}:${W}`, aud: J, exp: Y, iat: X, gsub: { principal: `user`, id: W }, org: H },
    environment: {
      iss: q,
      sub: `environment:${H}:${G}`,
      aud: J,
      exp: Y,
      iat: X,
      gsub: { principal: `environment`, id: G },
      org: H,
    },
    serviceAccount: {
      iss: q,
      sub: `serviceaccount:${H}:${K}`,
      aud: J,
      exp: Y,
      iat: X,
      gsub: { principal: `serviceaccount`, id: K },
      org: H,
    },
  },
  fe = {
    account: {
      iss: q,
      aud: J,
      exp: Y,
      iat: X,
      account_id: U,
      organization_id: H,
      email: `admin@example.com`,
      name: `Jane Admin`,
      idp: `https://accounts.google.com`,
      idp_claims: { groups: [`engineering`, `platform`] },
    },
    user: {
      iss: q,
      aud: J,
      exp: Y,
      iat: X,
      account_id: U,
      user_id: W,
      organization_id: H,
      email: `dev@example.com`,
      name: `Jane Doe`,
      idp: `https://accounts.google.com`,
      idp_claims: { groups: [`engineering`] },
    },
    environment: {
      iss: q,
      aud: J,
      exp: Y,
      iat: X,
      account_id: U,
      user_id: W,
      organization_id: H,
      environment_id: G,
      project_id: ue,
      creator_principal: `user`,
      creator_id: W,
      creator_email: `dev@example.com`,
      creator_name: `Jane Doe`,
      creator_idp: `https://accounts.google.com`,
      creator_idp_claims: { groups: [`engineering`] },
    },
    serviceAccount: { iss: q, aud: J, exp: Y, iat: X, service_account_id: K, organization_id: H, name: `ci-bot` },
  },
  pe = {
    account: [`account_id`],
    user: [`organization_id`, `user_id`],
    environment: [`organization_id`, `environment_id`],
    serviceAccount: [`organization_id`, `service_account_id`],
  };
function me(e, t) {
  let n = [];
  for (let r of e) {
    let e = he(t, r);
    typeof e == `string` && n.push(`${r}:${e}`);
  }
  return n.join(`:`);
}
function he(e, t) {
  let n = t.split(`.`),
    r = e;
  for (let e of n) {
    if (typeof r != `object` || !r) return;
    r = r[e];
  }
  return r;
}
function ge(e, t, n = []) {
  if (e === `v2`) return { ...de[t] };
  let r = { ...fe[t] },
    i = me([...pe[t], ...n], r);
  return {
    iss: r.iss,
    sub: i,
    aud: r.aud,
    exp: r.exp,
    iat: r.iat,
    ...Object.fromEntries(Object.entries(r).filter(([e]) => ![`iss`, `aud`, `exp`, `iat`].includes(e))),
  };
}
var Z = { account: `Account`, user: `User`, environment: `Environment`, serviceAccount: `Service Account` },
  Q = [`account`, `user`, `environment`, `serviceAccount`],
  $ = ({ version: e, extraSubFields: t = [], className: r, "data-testid": i = `oidc-token-preview` }) => {
    let [a, o] = (0, N.useState)(`environment`);
    return (0, R.jsxs)(`div`, {
      className: D(`flex flex-col gap-3`, r),
      "data-testid": i,
      children: [
        (0, R.jsxs)(`div`, {
          className: `flex flex-col gap-1`,
          children: [
            (0, R.jsx)(A, { children: `Token Preview` }),
            (0, R.jsx)(j, {
              className: `text-base text-content-secondary`,
              children: `Example decoded JWT payload for each principal type.`,
            }),
          ],
        }),
        (0, R.jsxs)(n, {
          value: a,
          onValueChange: (e) => o(e),
          children: [
            (0, R.jsx)(n.List, {
              children: Q.map((e) => (0, R.jsx)(n.Trigger, { value: e, "data-testid": `tab-${e}`, children: Z[e] }, e)),
            }),
            Q.map((r) =>
              (0, R.jsx)(
                n.Content,
                { value: r, children: (0, R.jsx)(_e, { version: e, principal: r, extraSubFields: t }) },
                r,
              ),
            ),
          ],
        }),
      ],
    });
  },
  _e = ({ version: e, principal: t, extraSubFields: n }) => {
    let r = ge(e, t, n),
      a = JSON.stringify(r, null, 2),
      { effectiveTheme: o } = T(),
      s = (0, N.useMemo)(() => ({ name: `token.json`, contents: a, lang: `json` }), [a]),
      c = (0, N.useMemo)(
        () => ({
          theme: { dark: `ioi-dark`, light: `ioi-light` },
          themeType: o,
          disableFileHeader: !0,
          disableLineNumbers: !0,
          overflow: `wrap`,
        }),
        [o],
      );
    return (0, R.jsxs)(`div`, {
      className: `mt-3 overflow-hidden rounded-lg border border-border-base bg-surface-02`,
      children: [
        (0, R.jsxs)(`div`, {
          className: `flex items-center justify-between border-b border-border-base px-4 py-2.5`,
          children: [
            (0, R.jsxs)(`span`, {
              className: `text-sm font-medium text-content-secondary`,
              children: [
                (0, R.jsx)(`span`, { children: e === `v2` ? `V2 (Legacy)` : `V3` }),
                (0, R.jsx)(`span`, { children: ` — ` }),
                (0, R.jsx)(`span`, { children: Z[t] }),
              ],
            }),
            (0, R.jsx)(`span`, { className: `text-sm text-content-tertiary`, children: `Decoded payload` }),
          ],
        }),
        (0, R.jsx)(`pre`, {
          "data-testid": `token-payload`,
          className: `sr-only`,
          "aria-hidden": `true`,
          children: (0, R.jsx)(`code`, { children: a }),
        }),
        (0, R.jsx)(i, { children: (0, R.jsx)(l, { file: s, options: c }) }),
      ],
    });
  },
  ve = [
    { value: `v2`, label: `V2`, badge: `Legacy`, description: `Original token format with gsub and org claims.` },
    {
      value: `v3`,
      label: `V3`,
      badge: `Recommended`,
      description: `Enriched tokens with flat claims and optional sub claim customization.`,
    },
  ],
  ye = ({
    value: e,
    onChange: t,
    disabled: n = !1,
    v2Locked: r = !1,
    className: i,
    "data-testid": o = `oidc-version-selector`,
  }) =>
    (0, R.jsxs)(`div`, {
      className: D(`flex flex-col gap-3`, i),
      "data-testid": o,
      children: [
        (0, R.jsx)(A, { children: `Token Version` }),
        (0, R.jsx)(a, {
          value: e,
          onValueChange: (e) => t(e),
          disabled: n,
          className: `flex flex-col gap-2`,
          children: ve.map((t) => {
            let i = e === t.value,
              o = r && t.value === `v2`,
              s = n || o;
            return (0, R.jsxs)(
              `label`,
              {
                className: D(
                  `flex cursor-pointer items-start gap-3 rounded-lg border px-4 py-3 transition-colors`,
                  i ? `border-border-brand bg-surface-02` : `border-border-base hover:bg-surface-02`,
                  s && `cursor-not-allowed opacity-50`,
                ),
                "data-testid": `version-option-${t.value}`,
                "aria-disabled": s || void 0,
                children: [
                  (0, R.jsx)(a.Item, { value: t.value, className: `mt-1`, disabled: o || void 0 }),
                  (0, R.jsxs)(`div`, {
                    className: `flex flex-col gap-0.5`,
                    children: [
                      (0, R.jsxs)(`div`, {
                        className: `flex items-center gap-2`,
                        children: [
                          (0, R.jsx)(`span`, {
                            className: `text-base font-semibold text-content-primary`,
                            children: t.label,
                          }),
                          t.badge &&
                            (0, R.jsx)(`span`, {
                              className: D(
                                `rounded-full px-2 py-0.5 text-xs font-medium`,
                                t.value === `v2`
                                  ? `bg-surface-tertiary text-content-secondary`
                                  : `bg-surface-brand-secondary text-content-brand`,
                              ),
                              children: t.badge,
                            }),
                        ],
                      }),
                      (0, R.jsx)(j, { className: `text-base text-content-secondary`, children: t.description }),
                    ],
                  }),
                ],
              },
              t.value,
            );
          }),
        }),
        r &&
          (0, R.jsx)(j, {
            className: `text-sm text-content-secondary`,
            "data-testid": `oidc-v2-locked-note`,
            children: `V3 is required for this organization. V2 is no longer available for organizations created after V3 became the default.`,
          }),
      ],
    }),
  be = () => {
    r(`OIDC Tokens`);
    let { membership: e, isPending: n } = ae(),
      { data: i, isPending: a } = re(),
      o = i?.id,
      { data: s, isPending: c } = I(o),
      l = se(o),
      { toast: u } = ie(),
      f = s?.version?.case === `v3` ? `v3` : `v2`,
      p = (0, N.useMemo)(() => (s?.version?.case === `v3` ? [...(s.version.value.extraSubFields ?? [])] : []), [s]),
      [m, h] = (0, N.useState)(null),
      [g, v] = (0, N.useState)(null),
      [S, C] = (0, N.useState)(!1),
      w = m ?? f,
      T = g ?? p,
      D = (0, N.useCallback)((e) => {
        (h(e), e === `v2` && v(null));
      }, []),
      O = (0, N.useCallback)((e) => {
        v(e);
      }, []),
      k = (0, N.useMemo)(() => {
        if (w !== f) return !0;
        if (w === `v3`) {
          let e = T;
          return e.length === p.length ? e.some((e, t) => e !== p[t]) : !0;
        }
        return !1;
      }, [w, f, T, p]),
      A = (0, N.useMemo)(
        () =>
          w === f
            ? `You are updating the sub claim fields. Existing trust policies referencing the current sub claim format may need to be updated.`
            : `You are switching from ${f.toUpperCase()} to ${w.toUpperCase()}. This is a breaking change — existing trust policies referencing the old token format will stop working.`,
        [w, f],
      ),
      P = (0, N.useCallback)(
        () =>
          w === `v2`
            ? d(y, { version: { case: `v2`, value: d(b, {}) } })
            : d(y, { version: { case: `v3`, value: d(x, { extraSubFields: T.filter((e) => e.trim() !== ``) }) } }),
        [w, T],
      ),
      F = (0, N.useCallback)(async () => {
        try {
          (await l.mutateAsync(P()), C(!1), h(null), v(null), u({ title: `OIDC configuration updated` }));
        } catch (e) {
          (console.error(e), u({ title: `Failed to update OIDC configuration`, description: ne(e) }));
        }
      }, [l, P, u]);
    if (n || !e || a || !i) return null;
    if (e.userRole !== _.ADMIN) return (0, R.jsx)(t, {});
    let L = i.tier === te.ENTERPRISE,
      z = ce(i);
    if (!L)
      return (0, R.jsxs)(`div`, {
        className: `flex max-w-[46rem] flex-col gap-4`,
        "data-testid": `oidc-config-page`,
        children: [
          (0, R.jsxs)(`div`, {
            className: `text-base text-content-secondary`,
            children: [
              `Configure OIDC token settings for your organization.`,
              ` `,
              (0, R.jsx)(M, {
                href: `https://ioi.com/docs/ioi/configuration/oidc`,
                iconSize: `sm`,
                children: `Learn more.`,
              }),
            ],
          }),
          (0, R.jsx)(oe, {
            variant: `info`,
            className: `py-4`,
            "data-testid": `enterprise-tier-banner`,
            text: (0, R.jsxs)(R.Fragment, {
              children: [
                `Upgrade to`,
                ` `,
                (0, R.jsx)(ee, {
                  to: `/settings/manage-organization`,
                  className: `font-medium text-content-brand hover:underline`,
                  children: `Enterprise tier`,
                }),
                ` `,
                `to configure OIDC tokens.`,
              ],
            }),
          }),
        ],
      });
    if (c) return null;
    let V = w === `v3` && T.some((e) => e.trim() === ``),
      H = w === `v3` && new Set(T.filter((e) => e.trim() !== ``)).size !== T.filter((e) => e.trim() !== ``).length;
    return (0, R.jsxs)(`div`, {
      className: `flex max-w-[46rem] flex-col gap-6`,
      "data-testid": `oidc-config-page`,
      children: [
        (0, R.jsxs)(`div`, {
          className: `text-base text-content-secondary`,
          children: [
            `Configure OIDC token settings for your organization.`,
            ` `,
            (0, R.jsx)(M, {
              href: `https://ioi.com/docs/ioi/configuration/oidc`,
              iconSize: `sm`,
              children: `Learn more.`,
            }),
          ],
        }),
        (0, R.jsx)(ye, { value: w, onChange: D, v2Locked: z }),
        (0, R.jsx)($, { version: w, extraSubFields: w === `v3` ? T : [] }),
        w === `v3` && (0, R.jsx)(B, { fields: T, onChange: O }),
        (0, R.jsxs)(`div`, {
          className: `flex items-center gap-3`,
          children: [
            (0, R.jsx)(E, {
              variant: `primary`,
              onClick: () => C(!0),
              disabled: !k || V || H,
              "data-testid": `save-oidc-config`,
              "data-tracking-id": `save-oidc-config`,
              children: `Save`,
            }),
            k &&
              (0, R.jsx)(j, { className: `text-base text-content-secondary`, children: `You have unsaved changes.` }),
          ],
        }),
        (0, R.jsx)(le, { open: S, onOpenChange: C, onConfirm: F, isLoading: l.isPending, changeDescription: A }),
      ],
    });
  };
export { be as OidcConfigPage };

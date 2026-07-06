import { a as e } from "./rolldown-runtime-CGYlQKCx.js";
import { Lt as t, Yn as n, at as r, b as i, lt as a, st as o, ut as s } from "./SegmentProvider-CXCNBY9U.js";
import { n as c } from "./@mux-DLaEVubF.js";
import { Af as l, If as u, Zf as d, dm as f, g_ as p, jf as m, v_ as h, xg as g } from "./vendor-DAwbZtf0.js";
import {
  Kn as _,
  Li as v,
  Ro as y,
  lt as b,
  nt as x,
  p as S,
  vn as C,
  wt as w,
} from "./use-boot-in-app-chat-t-J_VjKS.js";
import { t as T } from "./toast-axaLeIzZ.js";
import { t as E } from "./button-6YP03Qf2.js";
import { t as D } from "./banner-CFcSGYsz.js";
import { n as O, r as k } from "./utils-C9bSuXia.js";
import { t as A } from "./headings-CM9JBOhQ.js";
import { t as j } from "./Pill-99RRpZf2.js";
import "./pill-AA_qJIlm.js";
import { t as M } from "./text-fFCFeCas.js";
import { t as N } from "./skeleton-Cm867Q_k.js";
import { a as P } from "./secret-queries-DrL94GSz.js";
import { t as F } from "./external-link-BKbp1Q22.js";
import { t as I } from "./EducationPageContainer-DEwJG2CF.js";
import { t as L } from "./FeatureItem-3RVmAC_r.js";
var R = e(c(), 1),
  z = h(),
  B = () => {
    let e = w(),
      { data: t } = _(),
      n = g(),
      { value: r, setValueAsync: a } = x(i),
      o = r === `true`,
      s = (0, R.useCallback)(async () => {
        try {
          (e(`trial_requested`, { type: `enterprise`, email: t?.email }),
            await a(`true`),
            T({
              title: `Trial requested!`,
              description: `Our team is working on your request and will be in touch soon.`,
            }));
        } catch (e) {
          T({
            title: `Failed to request trial`,
            description: e instanceof Error ? e.message : `An unknown error occurred.`,
          });
        }
      }, [t?.email, e, a]),
      c = (0, R.useCallback)(() => {
        n(`/settings/secrets`);
      }, [n]);
    return (0, z.jsxs)(I, {
      children: [
        (0, z.jsxs)(`div`, {
          className: `flex flex-col gap-2`,
          children: [
            (0, z.jsx)(j, { variant: `brand`, size: `lg`, className: `w-fit`, children: `Available on Enterprise ✨` }),
            (0, z.jsx)(A, { children: `Secure organization-wide secrets management` }),
            (0, z.jsx)(M, {
              className: `text-md text-content-secondary`,
              children: `Organization-wide secrets provide a centralized way to manage sensitive information like API keys, tokens, and credentials that are automatically available across all environments in your organization.`,
            }),
            (0, z.jsx)(D, {
              variant: `info`,
              text: `In the meantime, you can manage personal secrets that are available in your own environments.`,
              action: {
                text: `View personal secrets`,
                onClick: c,
                "data-tracking-id": `go-to-personal-secrets-organization-secrets-education-page`,
                responsive: !0,
              },
            }),
            (0, z.jsxs)(`div`, {
              className: `mt-2 flex flex-col gap-3 sm:flex-row`,
              children: [
                (0, z.jsx)(E, {
                  size: `md`,
                  onClick: s,
                  disabled: o,
                  "data-tracking-id": `request-trial-organization-secrets-education-page`,
                  children: o ? `Trial requested` : `Request trial`,
                }),
                (0, z.jsx)(E, {
                  variant: `outline`,
                  size: `md`,
                  asChild: !0,
                  children: (0, z.jsx)(F, {
                    href: `https://ioi.com/docs/ioi/organizations/organization-secrets`,
                    iconSize: `sm`,
                    children: `Learn more`,
                  }),
                }),
              ],
            }),
          ],
        }),
        (0, z.jsxs)(`div`, {
          className: `flex flex-col gap-3`,
          children: [
            (0, z.jsx)(M, { className: `text-base font-medium text-content-primary`, children: `Key benefits:` }),
            (0, z.jsx)(L, {
              icon: (0, z.jsx)(u, { size: 16 }),
              variant: `success`,
              title: `Centralized security management`,
              description: `Manage all your organization's secrets in one secure location. No more scattered API keys or credentials across different projects.`,
            }),
            (0, z.jsx)(L, {
              icon: (0, z.jsx)(d, { size: 16 }),
              variant: `brand`,
              title: `Automatic availability across environments`,
              description: `Organization secrets are automatically injected into all environments, ensuring consistent access to required credentials without manual setup.`,
            }),
            (0, z.jsx)(L, {
              icon: (0, z.jsx)(l, { size: 16 }),
              variant: `brand-purple`,
              title: `Team collaboration and access control`,
              description: `Enable secure collaboration by providing controlled access to shared secrets while maintaining security and audit trails.`,
            }),
          ],
        }),
      ],
    });
  },
  V = k(m),
  H = () => {
    t(`Organization Secrets`);
    let { data: e, isPending: r } = C(),
      { data: i, isPending: c, error: l } = b(),
      { data: u, isPending: d, error: m } = P(i?.organizationId),
      { setBreadCrumbRowAction: h, setCustomBreadcrumbs: g } = (0, R.useContext)(n),
      { value: _ } = S(),
      [x, w] = (0, R.useState)(!1),
      [T, D] = (0, R.useState)(!1),
      k = e?.tier === v.ENTERPRISE,
      A = (0, R.useCallback)(() => {
        w(!0);
      }, [w]),
      j = (0, R.useCallback)(() => {
        D(!0);
      }, []),
      M = (0, R.useMemo)(
        () =>
          m || l
            ? (0, z.jsx)(s, { error: m || l })
            : d || !i
              ? (0, z.jsx)(N, { ready: !d && !c, failed: !!m || !!l, className: `h-[160px] w-[800px]` })
              : (0, z.jsx)(U, {
                  scope: p(y, { scope: { case: `organizationId`, value: i?.organizationId } }),
                  secrets: u?.secrets ?? [],
                  onNewSecret: A,
                  enableSecretCredentialProxySettings: _,
                }),
        [m, l, d, c, i, u, A, _],
      );
    return (
      (0, R.useEffect)(
        () =>
          k
            ? (h(
                (0, z.jsxs)(`div`, {
                  className: `flex items-center gap-2`,
                  children: [
                    (0, z.jsx)(E, {
                      size: `sm`,
                      variant: `outline`,
                      LeadingIcon: V,
                      onClick: j,
                      "data-testid": `import-env-modal-trigger`,
                      "data-tracking-id": `import-env-organization-secrets-page`,
                      children: `Import .env`,
                    }),
                    (0, z.jsx)(E, {
                      size: `sm`,
                      LeadingIcon: O(f),
                      onClick: A,
                      "data-testid": `add-secret-modal-trigger`,
                      "data-tracking-id": `new-secret-organization-secrets-page`,
                      children: `New secret`,
                    }),
                  ],
                }),
              ),
              () => {
                h(null);
              })
            : (g([]),
              () => {
                g(null);
              }),
        [k, A, j, u?.secrets, h, g],
      ),
      r
        ? null
        : k
          ? (0, z.jsxs)(`div`, {
              "data-testid": `organization-secrets-page`,
              children: [
                M,
                (0, z.jsx)(o, {
                  open: x,
                  enableSecretContainerRegistry: !0,
                  enableSecretCredentialProxySettings: _,
                  scope: p(y, { scope: { case: `organizationId`, value: i.organizationId } }),
                  onClose: () => w(!1),
                }),
                (0, z.jsx)(a, {
                  open: T,
                  scope: p(y, { scope: { case: `organizationId`, value: i.organizationId } }),
                  onClose: () => D(!1),
                  existingSecrets: u?.secrets ?? [],
                }),
              ],
            })
          : (0, z.jsx)(B, {})
    );
  },
  U = ({ scope: e, secrets: t, onNewSecret: n, enableSecretCredentialProxySettings: i }) =>
    (0, z.jsxs)(`div`, {
      className: `flex flex-col gap-6`,
      children: [
        (0, z.jsx)(M, {
          className: `text-base text-content-secondary`,
          children: `These are organization-wide secrets that are available in all environments created within this organization.`,
        }),
        (0, z.jsx)(r, {
          scope: e,
          secrets: t,
          showCreatorColumn: !0,
          onNewSecret: n,
          enableSecretCredentialProxySettings: i,
        }),
      ],
    });
export { H as OrganizationSecretsPage };

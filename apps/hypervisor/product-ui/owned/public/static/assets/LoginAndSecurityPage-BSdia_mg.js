import { a as e } from "./rolldown-runtime-CGYlQKCx.js";
import { It as t, J as n, Lt as r, Wt as i, zt as a } from "./SegmentProvider-CXCNBY9U.js";
import { n as o } from "./@mux-DLaEVubF.js";
import { Op as s, cg as c, g_ as l, mu as u, n as d, r as f, v_ as p, xg as m, zg as h } from "./vendor-DAwbZtf0.js";
import {
  $t as g,
  Dn as _,
  Dt as v,
  Ei as y,
  En as b,
  Fi as x,
  Fn as S,
  Gt as C,
  Hi as w,
  Li as T,
  Ln as E,
  Oi as D,
  Qt as O,
  Si as k,
  Ui as A,
  Ut as j,
  Wt as M,
  Yi as N,
  cn as ee,
  en as te,
  qt as ne,
  r as P,
  tr as F,
  un as I,
  vn as re,
  yn as ie,
} from "./use-boot-in-app-chat-t-J_VjKS.js";
import { n as L } from "./toast-axaLeIzZ.js";
import { t as R } from "./button-6YP03Qf2.js";
import { t as z } from "./cn-DppMFCU8.js";
import { t as B } from "./dialog-BtjFqa-w.js";
import { t as ae } from "./use-membership-CcV5kGny.js";
import { t as V } from "./banner-CFcSGYsz.js";
import { n as oe } from "./strings-C6LrS0GJ.js";
import { i as se, n as ce, r as H } from "./headings-CM9JBOhQ.js";
import { t as U } from "./input-C42Z_4fO.js";
import { t as le } from "./tooltip-6hqVQbwq.js";
import { t as W } from "./text-fFCFeCas.js";
import { t as G } from "./skeleton-Cm867Q_k.js";
import { n as ue, r as K } from "./dropdown-menu-D3UmjGpQ.js";
import { r as de, s as q, t as fe } from "./url-validation-Ph7WWpDb.js";
import { t as J } from "./external-link-BKbp1Q22.js";
import { n as pe, r as me, t as he } from "./popover-D9TQszBd.js";
import { t as ge } from "./checkbox-nHTWcF6W.js";
import { t as _e } from "./error-message-Az-KJctk.js";
import { t as ve } from "./label-5ATlPnPj.js";
import { t as Y } from "./form-control-BfDRQ8Xb.js";
import { t as ye } from "./IconGitHub-DdVg_DwS.js";
import { t as X } from "./card-BxeZdx-o.js";
import { t as be } from "./switch-CiuLW56f.js";
import { t as xe } from "./textarea-65aCrC5K.js";
import { rt as Se } from "./main-DLKYFe1Y.js";
import { t as Ce } from "./IconCheckCircle-D5lhsn3C.js";
import { t as we } from "./IconWarningCircle-9yrh1wLR.js";
import { t as Te } from "./IconGrid-BLLeUfRm.js";
import { n as Ee, t as De } from "./use-canonical-domain-runners-Bd-geFJT.js";
var Z = e(o(), 1),
  Q = p();
function Oe(e) {
  return e.replace(/[-\s]/g, ``);
}
function ke(e) {
  if (!e || e.trim().length === 0) return !1;
  let t = Oe(e);
  return /^\d{12}$/.test(t);
}
function Ae(e) {
  return !e || e.trim().length === 0 ? !1 : /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/.test(e);
}
function je(e) {
  return e.trim() ? (fe(q(e)) ? `` : `Please enter a valid domain (e.g., company.com)`) : `Domain is required`;
}
function $(e, t) {
  if (!e.trim()) return t === y.AWS ? `AWS Account ID is required` : `GCP Project ID is required`;
  if (t === y.AWS) {
    if (!ke(e)) return `AWS Account ID must be exactly 12 digits`;
  } else if (t === y.GCP && !Ae(e))
    return `GCP Project ID must be 6-30 characters, lowercase letters, digits, and hyphens`;
  return ``;
}
var Me = ({ organizationId: e, isOpen: t, onClose: n, isEditing: r = !1, existingDomain: i }) => {
    let { toast: o } = L(),
      s = b(),
      [c, l] = (0, Z.useState)(y.AWS),
      [u, d] = (0, Z.useState)(``),
      [f, p] = (0, Z.useState)(``),
      [m, h] = (0, Z.useState)(``),
      [g, _] = (0, Z.useState)(``),
      [x, S] = (0, Z.useState)(!1),
      [C, w] = (0, Z.useState)(!1);
    (0, Z.useEffect)(() => {
      (r && i
        ? (d(i.domainName || ``), p(i.cloudAccountId || i.awsAccountId || ``), l(i.provider || y.AWS))
        : (d(``), p(``), l(y.AWS)),
        h(``),
        _(``),
        S(!1),
        w(!1));
    }, [r, i, t]);
    let T = (e) => {
        let t = e === `gcp` ? y.GCP : y.AWS;
        (l(t), C && _($(f, t)));
      },
      E = () => {
        (S(!0), h(je(u)));
      },
      D = () => {
        (w(!0), _($(f, c)));
      },
      O = async (t) => {
        t.preventDefault();
        let i = je(u),
          a = $(f, c);
        if ((h(i), _(a), S(!0), w(!0), i || a)) return;
        let l = c === y.AWS ? Oe(f) : f.trim().toLowerCase();
        try {
          (await s.mutateAsync({ organizationId: e, domainName: q(u), provider: c, cloudAccountId: l }),
            o({ title: r ? `Custom domain updated successfully` : `Custom domain configured successfully` }),
            n());
        } catch (e) {
          o({ title: r ? `Failed to update custom domain` : `Failed to configure custom domain`, description: F(e) });
        }
      },
      k = c === y.AWS,
      A = k ? `AWS Account ID` : `GCP Project ID`,
      j = k ? `123456789012` : `my-project-id`,
      M = k ? `Enter your 12-digit AWS account ID.` : `Enter your GCP project ID (6-30 characters, lowercase).`;
    return (0, Q.jsx)(B, {
      open: t,
      onOpenChange: n,
      children: (0, Q.jsxs)(B.Content, {
        "data-track-location": v.SetupCustomDomainModal,
        children: [
          (0, Q.jsxs)(B.Header, {
            children: [
              (0, Q.jsx)(B.Title, { children: r ? `Edit custom domain` : `Set up custom domain` }),
              (0, Q.jsxs)(B.Description, {
                children: [
                  `Register your custom domain to access IOI through a branded URL. See the`,
                  ` `,
                  (0, Q.jsx)(J, {
                    href: `https://ioi.com/docs/ioi/custom-domain`,
                    className: `text-sm`,
                    children: `infrastructure setup guide`,
                  }),
                  ` `,
                  `to complete configuration.`,
                ],
              }),
            ],
          }),
          (0, Q.jsx)(B.Body, {
            children: (0, Q.jsxs)(`form`, {
              onSubmit: O,
              className: `flex flex-col gap-4`,
              children: [
                (0, Q.jsxs)(`div`, {
                  className: `flex flex-col gap-2`,
                  children: [
                    (0, Q.jsx)(ve, { children: `Cloud Provider` }),
                    (0, Q.jsxs)(a, {
                      value: k ? `aws` : `gcp`,
                      onValueChange: T,
                      className: `flex flex-row gap-6`,
                      children: [
                        (0, Q.jsxs)(`label`, {
                          className: `flex cursor-pointer flex-row items-center gap-2`,
                          children: [
                            (0, Q.jsx)(a.Item, { value: `aws` }),
                            (0, Q.jsx)(`span`, { className: `text-sm`, children: `AWS` }),
                          ],
                        }),
                        (0, Q.jsxs)(`label`, {
                          className: `flex cursor-pointer flex-row items-center gap-2`,
                          children: [
                            (0, Q.jsx)(a.Item, { value: `gcp` }),
                            (0, Q.jsx)(`span`, { className: `text-sm`, children: `GCP` }),
                          ],
                        }),
                      ],
                    }),
                  ],
                }),
                (0, Q.jsxs)(`div`, {
                  className: `flex flex-col gap-2`,
                  children: [
                    (0, Q.jsx)(ve, { htmlFor: `cloud-account-id`, children: A }),
                    (0, Q.jsx)(U, {
                      id: `cloud-account-id`,
                      type: `text`,
                      placeholder: j,
                      value: f,
                      onChange: (e) => {
                        (p(e.target.value), C && _($(e.target.value, c)));
                      },
                      onBlur: D,
                      "aria-required": `true`,
                      "aria-invalid": !!g,
                      "aria-describedby": g ? `cloud-account-id-error` : `cloud-account-id-help`,
                    }),
                    g && C
                      ? (0, Q.jsx)(`p`, {
                          id: `cloud-account-id-error`,
                          className: `text-sm text-content-destructive`,
                          role: `alert`,
                          children: g,
                        })
                      : (0, Q.jsx)(`p`, {
                          id: `cloud-account-id-help`,
                          className: `text-sm text-content-secondary`,
                          children: M,
                        }),
                  ],
                }),
                (0, Q.jsxs)(`div`, {
                  className: `flex flex-col gap-2`,
                  children: [
                    (0, Q.jsx)(ve, { htmlFor: `domain`, children: `Domain name` }),
                    (0, Q.jsx)(U, {
                      id: `domain`,
                      type: `text`,
                      placeholder: `ioi.example.com`,
                      value: u,
                      onChange: (e) => {
                        (d(e.target.value), x && h(je(e.target.value)));
                      },
                      onBlur: E,
                      "aria-required": `true`,
                      "aria-invalid": !!m,
                      "aria-describedby": m ? `domain-error` : `domain-help`,
                    }),
                    m && x
                      ? (0, Q.jsx)(`p`, {
                          id: `domain-error`,
                          className: `text-sm text-content-destructive`,
                          role: `alert`,
                          children: m,
                        })
                      : (0, Q.jsxs)(Q.Fragment, {
                          children: [
                            (0, Q.jsx)(`p`, {
                              id: `domain-help`,
                              className: `text-sm text-content-secondary`,
                              children: `Enter domain without https:// (e.g., company.com or login.company.com)`,
                            }),
                            u &&
                              q(u) &&
                              (0, Q.jsxs)(`p`, {
                                className: `text-xs text-content-secondary`,
                                children: [
                                  `Will be accessible at:`,
                                  ` `,
                                  (0, Q.jsxs)(`span`, { className: `font-medium`, children: [`https://`, q(u)] }),
                                ],
                              }),
                          ],
                        }),
                  ],
                }),
              ],
            }),
          }),
          (0, Q.jsxs)(B.Footer, {
            children: [
              (0, Q.jsx)(B.Close, {
                asChild: !0,
                children: (0, Q.jsx)(R, { variant: `outline`, disabled: s.isPending, children: `Cancel` }),
              }),
              (0, Q.jsx)(R, {
                onClick: O,
                loading: s.isPending,
                "data-tracking-id": `submit-custom-domain`,
                children: r ? `Update` : `Save`,
              }),
            ],
          }),
        ],
      }),
    });
  },
  Ne = ({ organizationId: e, editable: t = !0 }) => {
    let { toast: n } = L(),
      [r, i] = (0, Z.useState)(!1),
      [a, o] = (0, Z.useState)(!1),
      [s, c] = (0, Z.useState)(!1),
      { data: l, isLoading: d } = O(e),
      { data: f } = I(),
      p = M(),
      m = _(),
      g = () => {
        (c(!0), i(!0));
      },
      b = () => {
        (c(!1), i(!0));
      },
      x = async () => {
        try {
          (await p.mutateAsync({ organizationId: e }),
            await m.mutateAsync({ organizationId: e, enforced: !1 }),
            n({ title: `Custom domain deleted successfully` }),
            o(!1));
        } catch (e) {
          n({ title: `Failed to delete custom domain`, description: F(e) });
        }
      };
    if (d)
      return (0, Q.jsx)(X, {
        className: `flex w-full max-w-[550px] flex-col gap-4 bg-surface-glass p-4`,
        variant: `bordered`,
        children: (0, Q.jsxs)(`div`, {
          className: `flex gap-4`,
          children: [
            (0, Q.jsx)(`div`, {
              className: `flex w-11 items-center justify-center`,
              children: (0, Q.jsx)(u, { size: 24, className: `text-content-primary` }),
            }),
            (0, Q.jsxs)(`div`, {
              className: `flex flex-col gap-3`,
              children: [
                (0, Q.jsx)(`p`, { className: `text-base font-normal text-content-primary`, children: `Custom domain` }),
                (0, Q.jsx)(G, { ready: !1, className: `h-16 w-full` }),
              ],
            }),
          ],
        }),
      });
    let S = !!l,
      C = f?.some((e) => e.providerType === A.CUSTOM);
    return (0, Q.jsxs)(Q.Fragment, {
      children: [
        (0, Q.jsxs)(X, {
          className: `flex w-full max-w-[550px] flex-col gap-4 bg-surface-glass p-4`,
          variant: `bordered`,
          children: [
            (0, Q.jsxs)(`div`, {
              className: `flex gap-4`,
              children: [
                (0, Q.jsx)(`div`, {
                  className: `flex w-11 items-center justify-center`,
                  children: (0, Q.jsx)(u, { size: 24, className: `text-content-primary` }),
                }),
                (0, Q.jsx)(`div`, {
                  className: `flex flex-1 flex-col gap-3`,
                  children: (0, Q.jsxs)(`div`, {
                    className: `flex flex-col gap-1`,
                    children: [
                      (0, Q.jsx)(`p`, {
                        className: `text-base font-normal text-content-primary`,
                        children: `Custom domain`,
                      }),
                      !S &&
                        (0, Q.jsx)(`span`, {
                          className: `text-sm text-content-secondary`,
                          children: `Set up a private, branded domain for your organization's IOI deployment.`,
                        }),
                      S &&
                        (0, Q.jsxs)(`div`, {
                          className: `flex flex-col gap-1`,
                          children: [
                            (0, Q.jsxs)(`div`, {
                              className: `text-sm text-content-secondary`,
                              children: [
                                `Your custom domain:`,
                                ` `,
                                (0, Q.jsx)(J, {
                                  href: `https://${l.domainName}`,
                                  className: `text-sm`,
                                  iconSize: `sm`,
                                  children: l.domainName,
                                }),
                              ],
                            }),
                            (0, Q.jsx)(`div`, {
                              className: `text-sm text-content-secondary`,
                              children:
                                l.provider === y.GCP
                                  ? `GCP Project ID: ${l.cloudAccountId || l.awsAccountId}`
                                  : `AWS Account ID: ${l.cloudAccountId || l.awsAccountId}`,
                            }),
                          ],
                        }),
                    ],
                  }),
                }),
                !S &&
                  (0, Q.jsx)(`div`, {
                    className: `flex items-start`,
                    children: (0, Q.jsx)(R, {
                      variant: `primary`,
                      size: `sm`,
                      onClick: b,
                      disabled: !t,
                      "data-tracking-id": `setup-custom-domain`,
                      children: `Set up`,
                    }),
                  }),
                S &&
                  (0, Q.jsxs)(`div`, {
                    className: `flex items-start gap-4`,
                    children: [
                      (0, Q.jsx)(R, {
                        variant: `secondary`,
                        size: `sm`,
                        onClick: g,
                        disabled: !t,
                        "data-tracking-id": `edit-custom-domain`,
                        children: `Edit`,
                      }),
                      (0, Q.jsx)(R, {
                        variant: `destructive`,
                        size: `sm`,
                        onClick: () => o(!0),
                        disabled: !t,
                        "data-tracking-id": `delete-custom-domain`,
                        children: `Delete`,
                      }),
                    ],
                  }),
              ],
            }),
            S &&
              !C &&
              (0, Q.jsx)(V, {
                "data-testid": `sso-warning-banner`,
                variant: `warning`,
                text: (0, Q.jsxs)(`div`, {
                  children: [
                    (0, Q.jsx)(`p`, { className: `mb-1 font-medium`, children: `Single Sign-On required` }),
                    (0, Q.jsx)(`p`, {
                      children: `Custom domains require Single Sign-On (SSO) to be configured. Please set up SSO in the Login Methods section below.`,
                    }),
                  ],
                }),
              }),
          ],
        }),
        r &&
          (0, Q.jsx)(Me, {
            organizationId: e,
            isOpen: r,
            onClose: () => {
              (i(!1), c(!1));
            },
            isEditing: s,
            existingDomain: s ? l : void 0,
          }),
        (0, Q.jsx)(B, {
          open: a,
          onOpenChange: o,
          children: (0, Q.jsxs)(B.Content, {
            "data-track-location": v.DeleteCustomDomainModal,
            children: [
              (0, Q.jsxs)(B.Header, {
                children: [
                  (0, Q.jsx)(B.Title, { children: `Delete custom domain` }),
                  (0, Q.jsxs)(B.Description, {
                    children: [
                      `Are you sure you want to delete the custom domain configuration for`,
                      ` `,
                      (0, Q.jsx)(`strong`, { className: `font-semibold`, children: l?.domainName }),
                      `? This action cannot be undone.`,
                    ],
                  }),
                ],
              }),
              (0, Q.jsx)(B.Body, {
                children: (0, Q.jsx)(`div`, {
                  className: `rounded-md border border-border-warning/30 bg-surface-warning-subtle/15 p-4`,
                  children: (0, Q.jsxs)(`div`, {
                    className: `flex`,
                    children: [
                      (0, Q.jsx)(h, { className: `mr-3 size-5 flex-shrink-0 text-content-warning` }),
                      (0, Q.jsxs)(`div`, {
                        className: `text-base text-content-orange`,
                        children: [
                          (0, Q.jsx)(`p`, { className: `mb-1 font-medium`, children: `This will:` }),
                          (0, Q.jsxs)(`ul`, {
                            className: `list-inside list-disc space-y-1`,
                            children: [
                              (0, Q.jsx)(`li`, { children: `Remove the custom domain configuration` }),
                              (0, Q.jsx)(`li`, { children: `Automatically disable domain enforcement` }),
                              (0, Q.jsx)(`li`, { children: `Require reconfiguration to use custom domain again` }),
                            ],
                          }),
                        ],
                      }),
                    ],
                  }),
                }),
              }),
              (0, Q.jsxs)(B.Footer, {
                children: [
                  (0, Q.jsx)(B.Close, {
                    asChild: !0,
                    children: (0, Q.jsx)(R, { variant: `outline`, disabled: p.isPending, children: `Cancel` }),
                  }),
                  (0, Q.jsx)(R, {
                    variant: `destructive`,
                    onClick: x,
                    loading: p.isPending,
                    "data-tracking-id": `confirm-delete-custom-domain`,
                    children: `Delete`,
                  }),
                ],
              }),
            ],
          }),
        }),
      ],
    });
  },
  Pe = ({ className: e, ...t }) =>
    (0, Q.jsxs)(`svg`, {
      className: e,
      ...t,
      width: `16`,
      height: `16`,
      viewBox: `0 0 16 16`,
      fill: `none`,
      xmlns: `http://www.w3.org/2000/svg`,
      children: [
        (0, Q.jsx)(`path`, {
          d: `M14.3334 7.99996C14.3334 11.4978 11.4978 14.3333 8.00002 14.3333C4.50222 14.3333 1.66669 11.4978 1.66669 7.99996C1.66669 4.50216 4.50222 1.66663 8.00002 1.66663C11.4978 1.66663 14.3334 4.50216 14.3334 7.99996Z`,
          stroke: `currentColor`,
          strokeLinecap: `round`,
          strokeLinejoin: `round`,
        }),
        (0, Q.jsx)(`path`, {
          d: `M8 5.17188V10.8287`,
          stroke: `currentColor`,
          strokeLinecap: `round`,
          strokeLinejoin: `round`,
        }),
        (0, Q.jsx)(`path`, {
          d: `M10.8284 8H5.17157`,
          stroke: `currentColor`,
          strokeLinecap: `round`,
          strokeLinejoin: `round`,
        }),
      ],
    }),
  Fe = ({ onCancel: e, domain: t = ``, onDomainCreated: n }) => {
    let { toast: r } = L(),
      i = P(),
      [a, o] = (0, Z.useState)(t),
      [s, c] = (0, Z.useState)(``),
      [l, u] = (0, Z.useState)(t),
      { domainVerification: d, error: f } = te(l || void 0),
      p = d?.verificationToken ?? ``,
      m = (0, Z.useRef)(!1);
    ((0, Z.useEffect)(() => {
      m.current = !1;
    }, [l]),
      (0, Z.useEffect)(() => {
        d && l && n && !m.current && ((m.current = !0), n(l));
      }, [d, l, n]));
    let h = E(),
      g = (0, Z.useCallback)(async () => {
        if (d)
          try {
            (r({
              title:
                (await h.mutateAsync(d))?.state === D.VERIFIED
                  ? `${l} is verified.`
                  : `${l} is not yet verified. Please try again later.`,
            }),
              e());
          } catch (e) {
            r({ title: `Failed to verify domain.`, description: F(e) });
          }
      }, [l, d, r, h, e]),
      _ = (0, Z.useCallback)(
        (e) => {
          e.preventDefault();
          let t = a.trim().toLowerCase();
          if (!t) {
            c(`Domain is required.`);
            return;
          }
          if (!fe(t)) {
            c(`Please enter a valid domain (e.g., example.com).`);
            return;
          }
          (c(``), u(t));
        },
        [a],
      ),
      v = (0, Z.useCallback)((e) => {
        (o(e.target.value), c(``));
      }, []),
      y = (0, Z.useId)(),
      b = (0, Z.useId)(),
      x = (0, Z.useId)(),
      S = (0, Z.useCallback)(() => {
        i(`Hi! I need to verify my "${l}" domain for SSO but cannot create any DNS TXT record. Can you help me?`);
      }, [i, l]);
    return l
      ? (0, Q.jsxs)(`div`, {
          children: [
            (0, Q.jsxs)(B.Header, {
              className: `flex flex-col gap-2`,
              children: [
                (0, Q.jsx)(B.Title, { children: `Verify your domain` }),
                (0, Q.jsx)(B.Description, {
                  children: `Configure OpenID Connect (OIDC) single sign-on with your identity provider.`,
                }),
              ],
            }),
            (0, Q.jsx)(B.Body, {
              className: `flex w-full py-6`,
              children: (0, Q.jsxs)(`div`, {
                className: `flex w-full flex-col gap-4`,
                children: [
                  (0, Q.jsxs)(W, {
                    children: [
                      `We need to ensure you own the domain. To do that, you'll need to create a new DNS TXT record for your domain.`,
                      ` `,
                      (0, Q.jsx)(J, { href: `https://ioi.com/docs/ioi/sso/overview`, children: `Learn more` }),
                      `.`,
                    ],
                  }),
                  f &&
                    (0, Q.jsx)(V, {
                      variant: `danger`,
                      text: (0, Q.jsxs)(Q.Fragment, {
                        children: [
                          (0, Q.jsx)(`div`, {
                            className: `font-bold`,
                            children: `Failed to fetch the verification data.`,
                          }),
                          (0, Q.jsx)(`div`, { className: `text-sm`, children: F(f) }),
                        ],
                      }),
                    }),
                  (0, Q.jsx)(Y, {
                    label: `Email domain`,
                    id: y,
                    hint: `This is the work email domain that people will use to sign in.`,
                    children: (0, Q.jsx)(U, {
                      "data-testid": `domain-input`,
                      id: y,
                      type: `text`,
                      name: `domain`,
                      value: l,
                      disabled: !0,
                    }),
                  }),
                  (0, Q.jsx)(Y, {
                    label: `TXT record name`,
                    id: b,
                    hint: `This is the name of the TXT record.`,
                    children: (0, Q.jsx)(U, {
                      copyable: !0,
                      disabled: !p,
                      "data-testid": `token-name-input`,
                      "data-tracking-id": `txt-record-name-domain-verification`,
                      id: b,
                      type: `text`,
                      name: `token-name`,
                      value: l,
                    }),
                  }),
                  (0, Q.jsx)(Y, {
                    label: `TXT record value`,
                    id: x,
                    hint: `This is the value of the TXT record.`,
                    children: (0, Q.jsx)(U, {
                      copyable: !0,
                      disabled: !p,
                      "data-testid": `token-value-input`,
                      "data-tracking-id": `txt-record-value-domain-verification`,
                      id: x,
                      type: `text`,
                      name: `token-value`,
                      value: p,
                    }),
                  }),
                  (0, Q.jsxs)(W, {
                    children: [
                      `If you cannot use TXT record validation,`,
                      ` `,
                      (0, Q.jsx)(R, {
                        variant: `link`,
                        className: `p-0 text-base text-content-link`,
                        onClick: S,
                        "data-tracking-id": `reach-out-to-us-domain-verification`,
                        children: `please reach out to us.`,
                      }),
                    ],
                  }),
                ],
              }),
            }),
            (0, Q.jsxs)(B.Footer, {
              children: [
                (0, Q.jsx)(B.Close, {
                  asChild: !0,
                  children: (0, Q.jsx)(R, {
                    variant: `outline`,
                    onClick: e,
                    "data-tracking-id": `cancel-domain-verification`,
                    children: `Later`,
                  }),
                }),
                (0, Q.jsx)(R, {
                  autoFocus: !0,
                  variant: `primary`,
                  disabled: !d,
                  onClick: g,
                  "data-tracking-id": `verify-domain-verification`,
                  children: `Verify`,
                }),
              ],
            }),
          ],
        })
      : (0, Q.jsxs)(`div`, {
          children: [
            (0, Q.jsxs)(B.Header, {
              className: `flex flex-col gap-2`,
              children: [
                (0, Q.jsx)(B.Title, { children: `Add email domain` }),
                (0, Q.jsx)(B.Description, {
                  children: `Enter the email domain you want to add for SSO authentication.`,
                }),
              ],
            }),
            (0, Q.jsx)(B.Body, {
              className: `flex w-full py-6`,
              children: (0, Q.jsxs)(`form`, {
                id: `add-domain-form`,
                onSubmit: _,
                className: `flex w-full flex-col gap-4`,
                children: [
                  (0, Q.jsx)(W, {
                    children: `After adding the domain, you'll need to verify ownership by adding a DNS TXT record.`,
                  }),
                  (0, Q.jsx)(Y, {
                    label: `Email domain`,
                    id: y,
                    hint: `This is the work email domain that people will use to sign in.`,
                    error: s,
                    children: (0, Q.jsx)(U, {
                      "data-testid": `new-domain-input`,
                      id: y,
                      type: `text`,
                      name: `domain`,
                      placeholder: `example.com`,
                      value: a,
                      onChange: v,
                      autoFocus: !0,
                    }),
                  }),
                ],
              }),
            }),
            (0, Q.jsxs)(B.Footer, {
              children: [
                (0, Q.jsx)(B.Close, {
                  asChild: !0,
                  children: (0, Q.jsx)(R, {
                    variant: `outline`,
                    onClick: e,
                    "data-tracking-id": `cancel-add-domain`,
                    children: `Later`,
                  }),
                }),
                (0, Q.jsx)(R, {
                  type: `submit`,
                  form: `add-domain-form`,
                  variant: `primary`,
                  disabled: !a.trim(),
                  "data-tracking-id": `continue-add-domain`,
                  children: `Continue`,
                }),
              ],
            }),
          ],
        });
  },
  Ie = (e) => (0, Q.jsx)(Fe, { ...e });
function Le(e) {
  return e
    ? e
        .split(`,`)
        .map((e) => e.trim())
        .filter((e) => e.length > 0)
    : [];
}
var Re = ({ organizationId: e, config: t, onClose: n, onVerify: r, testValidationOnly: i }) => {
    let { toast: a } = L(),
      [o, s] = (0, Z.useState)(`configure`),
      c = !!t,
      {
        register: u,
        handleSubmit: p,
        control: m,
        formState: { errors: h, isValid: g, isSubmitting: _, dirtyFields: v, isDirty: y },
        getValues: b,
      } = f({
        mode: `all`,
        defaultValues: c
          ? {
              display_name: t.displayName ?? ``,
              issuer_url: t.issuerUrl,
              client_id: t.clientId,
              client_secret: t.id,
              additional_scopes: t.additionalScopes?.join(`, `) ?? ``,
              claims_expression: t.claimsExpression ?? ``,
            }
          : void 0,
      }),
      x = j(),
      C = S(),
      w = ne(),
      [T, E] = (0, Z.useState)(),
      D = (0, Z.useCallback)(
        (e, t) => {
          let n = F(e);
          (E(n), a({ title: `Failed to create SSO configuration`, description: n }));
        },
        [a],
      ),
      O = (0, Z.useCallback)(
        async (n) => {
          await p(async (n) => {
            if (i) {
              console.warn(`Test validation only, not submitting form.`);
              return;
            }
            E(void 0);
            let r = ``;
            try {
              if (c) {
                r = t.id;
                let e = {
                  ssoConfigurationId: t.id,
                  displayName: v.display_name ? n.display_name : void 0,
                  clientId: v.client_id ? n.client_id : void 0,
                  issuerUrl: v.issuer_url ? n.issuer_url : void 0,
                  clientSecret: v.client_secret ? n.client_secret : void 0,
                  additionalScopes: v.additional_scopes ? l(k, { scopes: Le(n.additional_scopes) }) : void 0,
                  claimsExpression: n.claims_expression,
                };
                await C.mutateAsync(e);
              } else {
                let t = {
                  organizationId: e,
                  displayName: n.display_name,
                  issuerUrl: n.issuer_url,
                  clientId: n.client_id,
                  clientSecret: n.client_secret,
                  additionalScopes: Le(n.additional_scopes),
                  claimsExpression: n.claims_expression || void 0,
                };
                r = (await x.mutateAsync(t)).id;
              }
            } catch (e) {
              D(e, n);
              return;
            }
            (window.open(`/auth/oidc/start?ssoId=${r}&verify=true`, `_blank`), s(`confirm`));
          })(n);
        },
        [p, i, c, t?.id, C, v, x, e, D],
      ),
      A = (0, Z.useMemo)(() => new URL(`/auth/oidc/callback`, window.location.origin).toString(), []),
      M = (0, Z.useCallback)(
        (e) => {
          e.preventDefault();
          let t = b(`issuer_url`);
          t && window.open(`${t}/.well-known/openid-configuration`, `_blank`);
        },
        [b],
      ),
      N = (0, Z.useCallback)(async () => {
        if (t?.id)
          try {
            (await w.mutateAsync(t.id),
              a({ title: `SSO configuration removed`, description: `The SSO configuration has been removed.` }),
              n?.());
          } catch (e) {
            a({ title: `Failed to remove SSO configuration`, description: F(e) });
          }
      }, [t?.id, w, n, a]);
    return o === `confirm`
      ? (0, Q.jsxs)(`div`, {
          children: [
            (0, Q.jsx)(ze, {}),
            (0, Q.jsx)(B.Body, {
              className: `flex flex-col gap-2`,
              children: (0, Q.jsxs)(`div`, {
                className: `flex flex-col items-center gap-2 rounded-xl border-[0.5px] bg-surface-primary px-6 py-3 text-base text-content-tertiary`,
                children: [
                  (0, Q.jsx)(ce, { children: `SSO configured successfully!` }),
                  (0, Q.jsx)(W, { children: `The authentication test should have opened a new browser tab.` }),
                  (0, Q.jsx)(Ce, { size: `lg`, className: `size-16 text-green-500` }),
                  (0, Q.jsx)(W, {
                    children: `Add and verify the email domains you want to use for login, or use existing verified domains.`,
                  }),
                ],
              }),
            }),
            (0, Q.jsxs)(B.Footer, {
              children: [
                (0, Q.jsx)(R, {
                  type: `button`,
                  variant: `secondary`,
                  onClick: () => s(`configure`),
                  "data-tracking-id": `edit-configure-sso`,
                  children: `Edit`,
                }),
                (0, Q.jsx)(`div`, { className: `flex-grow` }),
                (0, Q.jsx)(R, {
                  variant: `primary`,
                  autoFocus: !0,
                  onClick: n,
                  "data-tracking-id": `confirm-sso-config`,
                  children: `OK`,
                }),
              ],
            }),
          ],
        })
      : o === `remove`
        ? (0, Q.jsxs)(`div`, {
            children: [
              (0, Q.jsx)(B.Header, {
                className: `flex flex-col gap-2`,
                children: (0, Q.jsx)(B.Title, { children: `Remove SSO configuration` }),
              }),
              (0, Q.jsxs)(B.Body, {
                className: `flex flex-col gap-2`,
                children: [
                  (0, Q.jsxs)(W, {
                    children: [
                      `This will delete your SSO configuration. Members will no longer be able to log in using SSO.`,
                      ` `,
                    ],
                  }),
                  (0, Q.jsx)(W, { children: `Are you sure you'd like to delete this configuration?` }),
                ],
              }),
              (0, Q.jsxs)(B.Footer, {
                children: [
                  (0, Q.jsx)(R, {
                    type: `button`,
                    variant: `outline`,
                    onClick: () => s(`configure`),
                    "data-tracking-id": `cancel-delete-sso-configure-sso`,
                    children: `Cancel`,
                  }),
                  (0, Q.jsx)(R, {
                    variant: `destructive`,
                    onClick: N,
                    "data-tracking-id": `confirm-delete-sso-configure-sso`,
                    children: `Yes, remove`,
                  }),
                ],
              }),
            ],
          })
        : (0, Q.jsxs)(`div`, {
            children: [
              (0, Q.jsx)(ze, {}),
              (0, Q.jsx)(B.Body, {
                className: `my-8 flex justify-between gap-3 overflow-y-auto py-0`,
                children: (0, Q.jsxs)(`form`, {
                  onSubmit: O,
                  id: `setup-sso-form`,
                  name: `Setup SSO`,
                  className: `flex w-full flex-col gap-4`,
                  children: [
                    (0, Q.jsxs)(W, {
                      children: [
                        `Find instructions for setting up an OIDC application in the`,
                        ` `,
                        (0, Q.jsx)(J, { href: `https://ioi.com/docs/ioi/sso/overview`, children: `documentation` }),
                        `.`,
                      ],
                    }),
                    T &&
                      (0, Q.jsx)(V, {
                        variant: `danger`,
                        text: (0, Q.jsxs)(Q.Fragment, {
                          children: [
                            (0, Q.jsx)(`div`, {
                              className: `font-bold`,
                              children: `Failed to update the SSO configuration`,
                            }),
                            (0, Q.jsx)(`div`, { className: `text-sm`, children: T }),
                          ],
                        }),
                      }),
                    (0, Q.jsx)(Y, {
                      label: `Display name`,
                      id: `display_name`,
                      hint: `This name appears on the selection screen when multiple SSO options are available.`,
                      error: h?.display_name?.message || ``,
                      children: (0, Q.jsx)(U, {
                        id: `display_name`,
                        placeholder: `Acme Inc.`,
                        type: `text`,
                        ...u(`display_name`, {
                          validate: (e) => e.trim().length >= 3 || `Display name must be at least 3 characters.`,
                          required: { value: !0, message: `Display name is required.` },
                          maxLength: { value: 64, message: `Display name must be 64 characters or fewer.` },
                        }),
                      }),
                    }),
                    (0, Q.jsx)(Y, {
                      label: `Issuer URL`,
                      id: `issuer_url`,
                      hint:
                        !h?.issuer_url?.message &&
                        (0, Q.jsxs)(`span`, {
                          children: [
                            `Check the`,
                            ` `,
                            (0, Q.jsx)(J, {
                              href: ``,
                              className: `text-sm`,
                              onClick: M,
                              "data-tracking-id": `open-oidc-discovery-metadata-configure-sso`,
                              children: `OIDC Discovery metadata`,
                            }),
                            ` `,
                            `of your identity provider.`,
                          ],
                        }),
                      error: h?.issuer_url?.message || ``,
                      children: (0, Q.jsx)(U, {
                        id: `issuer_url`,
                        placeholder: `https://sso.example.com/oauth2/default`,
                        type: `text`,
                        ...u(`issuer_url`, {
                          validate: (e) => de(e) || `Must be a valid URL starting with https://.`,
                          required: { value: !0, message: `Issuer URL is required.` },
                        }),
                      }),
                    }),
                    (0, Q.jsx)(Y, {
                      label: `Client ID`,
                      id: `client_id`,
                      error: h?.client_id?.message || ``,
                      children: (0, Q.jsx)(U, {
                        id: `client_id`,
                        type: `text`,
                        ...u(`client_id`, { required: { value: !0, message: `Client ID is required.` } }),
                      }),
                    }),
                    (0, Q.jsx)(Y, {
                      label: `Client secret`,
                      id: `client_secret`,
                      error: h?.client_secret?.message || ``,
                      children: (0, Q.jsx)(U, {
                        id: `client_secret`,
                        type: `password`,
                        ...u(`client_secret`, { required: { value: !0, message: `Client secret is required.` } }),
                      }),
                    }),
                    (0, Q.jsx)(Y, {
                      label: `Additional scopes`,
                      id: `additional_scopes`,
                      hint: `Comma-separated list of extra OIDC scopes to request from your identity provider (e.g. groups, roles).`,
                      error: h?.additional_scopes?.message || ``,
                      children: (0, Q.jsx)(U, {
                        id: `additional_scopes`,
                        type: `text`,
                        placeholder: `groups, roles`,
                        ...u(`additional_scopes`),
                      }),
                    }),
                    (0, Q.jsx)(Y, {
                      label: `Claims expression (Optional)`,
                      id: `claims_expression`,
                      hint: (0, Q.jsxs)(`span`, {
                        children: [
                          `A`,
                          ` `,
                          (0, Q.jsx)(J, {
                            href: `https://github.com/google/cel-spec/blob/master/doc/langdef.md`,
                            className: `text-sm`,
                            children: `CEL expression`,
                          }),
                          ` `,
                          `evaluated against OIDC token claims during login. Must evaluate to true for login to succeed.`,
                        ],
                      }),
                      error: h?.claims_expression?.message || ``,
                      children: (0, Q.jsx)(d, {
                        name: `claims_expression`,
                        control: m,
                        rules: {
                          maxLength: { value: 4096, message: `Claims expression must be 4096 characters or fewer.` },
                        },
                        render: ({ field: e }) =>
                          (0, Q.jsx)(xe, {
                            id: `claims_expression`,
                            placeholder: `claims.email_verified
&& claims.email.endsWith("@example.com")`,
                            minHeight: 60,
                            maxHeight: 300,
                            rows: 3,
                            value: e.value,
                            onChange: e.onChange,
                            onBlur: e.onBlur,
                            name: e.name,
                          }),
                      }),
                    }),
                    (0, Q.jsx)(Y, {
                      label: `Callback URL`,
                      id: `callback_url`,
                      hint: `Copy and paste this URL into the OIDC app of your identity provider.`,
                      children: (0, Q.jsx)(U, {
                        copyable: !0,
                        id: `callback_url`,
                        value: A,
                        title: `Copy callback URL`,
                        "data-tracking-id": `copy-callback-url-configure-sso`,
                        disabled: !0,
                      }),
                    }),
                  ],
                }),
              }),
              (0, Q.jsxs)(B.Footer, {
                className: `flex flex-row`,
                children: [
                  c &&
                    (0, Q.jsx)(R, {
                      variant: `destructive`,
                      onClick: () => s(`remove`),
                      "data-tracking-id": `remove-sso-config-configure-sso`,
                      children: `Remove`,
                    }),
                  (0, Q.jsx)(`div`, { className: `flex-grow` }),
                  (0, Q.jsx)(B.Close, {
                    asChild: !0,
                    children: (0, Q.jsx)(R, {
                      variant: `outline`,
                      onClick: n,
                      "data-tracking-id": `cancel-sso-config-configure-sso`,
                      children: `Cancel`,
                    }),
                  }),
                  (0, Q.jsx)(R, {
                    autoFocus: !0,
                    "aria-label": `test-and-continue`,
                    type: `submit`,
                    "data-testid": `test-and-continue-button`,
                    form: `setup-sso-form`,
                    variant: `primary`,
                    loading: _,
                    disabled: !g || !(y || c),
                    "data-tracking-id": `save-sso-config-configure-sso`,
                    children: `Save & test`,
                  }),
                ],
              }),
            ],
          });
  },
  ze = () =>
    (0, Q.jsxs)(B.Header, {
      className: `flex flex-col gap-2`,
      children: [
        (0, Q.jsx)(B.Title, { children: `Configure SSO` }),
        (0, Q.jsx)(B.Description, {
          children: `Configure OpenID Connect (OIDC) Single Sign-On with your identity provider.`,
        }),
      ],
    }),
  Be = () => void 0,
  Ve = ({ onClose: e = Be, testValidationOnly: t, organizationId: n, config: r, step: i }) => {
    let [a, o] = (0, Z.useState)(i ?? `configure-sso`);
    return (0, Q.jsx)(B, {
      open: !0,
      onOpenChange: (0, Z.useCallback)(
        (t) => {
          t || e?.();
        },
        [e],
      ),
      children: (0, Q.jsxs)(B.Content, {
        className: `flex max-w-[600px] flex-col p-6`,
        "data-track-location": `setup_sso_modal`,
        children: [
          a === `domain-verification` &&
            r?.emailDomain &&
            (0, Q.jsx)(Fe, { domain: r.emailDomain, onCancel: e, organizationId: n }),
          a === `configure-sso` &&
            (0, Q.jsx)(Re, {
              organizationId: n,
              config: r,
              onClose: e,
              onVerify: () => o(`domain-verification`),
              testValidationOnly: t,
            }),
          a === `configure-sso-v2` &&
            (0, Q.jsx)(Re, {
              organizationId: n,
              config: r,
              onClose: e,
              onVerify: () => o(`domain-verification`),
              testValidationOnly: t,
            }),
        ],
      }),
    });
  },
  He = ({ domain: e, verified: t = !0, onRemove: n, disabled: r = !1, className: a }) => {
    let o = (0, Q.jsxs)(`span`, {
      className: z(
        `inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-sm`,
        t
          ? `border-content-brand/30 bg-content-brand/10 text-content-brand`
          : `border-content-secondary/30 bg-content-secondary/10 text-content-secondary`,
        a,
      ),
      children: [
        (0, Q.jsx)(`span`, { className: `truncate`, children: e }),
        n &&
          (0, Q.jsx)(`button`, {
            type: `button`,
            onClick: n,
            disabled: r,
            className: z(
              `flex items-center justify-center rounded-full p-0.5`,
              t ? `hover:bg-content-brand/20` : `hover:bg-content-secondary/20`,
              r && `cursor-not-allowed opacity-50`,
            ),
            "aria-label": `Remove ${e}`,
            "data-testid": `remove-domain-${e}`,
            "data-tracking-id": `remove-domain-pill`,
            children: (0, Q.jsx)(i, { size: `sm`, className: `size-3` }),
          }),
      ],
    });
    return t
      ? o
      : (0, Q.jsx)(le, { content: `This domain is not enabled for this provider. Verify it first.`, children: o });
  },
  Ue = ({
    domainVerifications: e,
    assignedDomains: t,
    onAddDomains: n,
    onRemoveDomain: r,
    onNewDomain: i,
    disabled: a = !1,
    className: o,
  }) => {
    let [c, l] = (0, Z.useState)(!1),
      u = (0, Z.useMemo)(() => e.filter((e) => e.state === D.VERIFIED || e.state === D.PENDING), [e]),
      d = (0, Z.useCallback)(
        (e) => {
          t.includes(e) ? r?.(e) : n([e]);
        },
        [t, n, r],
      ),
      f = (0, Z.useCallback)(() => {
        (l(!1), i());
      }, [i]);
    return (0, Q.jsxs)(he, {
      open: c,
      onOpenChange: l,
      modal: !1,
      children: [
        (0, Q.jsx)(me, {
          asChild: !0,
          children: (0, Q.jsxs)(R, {
            variant: `secondary`,
            size: `sm`,
            disabled: a,
            className: z(`gap-1`, o),
            "data-testid": `domain-selector-trigger`,
            "data-tracking-id": `domain-selector-trigger`,
            children: [`Domains`, (0, Q.jsx)(s, { className: `size-4` })],
          }),
        }),
        (0, Q.jsxs)(pe, {
          align: `end`,
          className: `w-64 p-0`,
          sideOffset: 4,
          children: [
            (0, Q.jsxs)(`div`, {
              className: `max-h-64 overflow-y-auto`,
              children: [
                u.map((e) => {
                  let n = t.includes(e.domain);
                  return (0, Q.jsxs)(
                    `div`,
                    {
                      className: `flex cursor-pointer items-center gap-2 px-3 py-2 hover:bg-surface-02`,
                      onClick: () => d(e.domain),
                      "data-testid": `domain-selector-item-${e.domain}`,
                      "data-tracking-id": `domain-selector-item`,
                      children: [
                        (0, Q.jsx)(ge, {
                          checked: n,
                          onCheckedChange: () => d(e.domain),
                          onClick: (e) => e.stopPropagation(),
                          className: `data-[state=checked]:bg-content-primary`,
                          "data-testid": `domain-selector-checkbox-${e.domain}`,
                          "data-tracking-id": `domain-selector-checkbox`,
                        }),
                        (0, Q.jsx)(W, { className: `flex-1 truncate text-sm`, children: e.domain }),
                        e.state === D.PENDING &&
                          (0, Q.jsx)(`span`, { className: `text-xs text-content-secondary`, children: `Pending` }),
                      ],
                    },
                    e.id,
                  );
                }),
                u.length === 0 &&
                  (0, Q.jsx)(`div`, {
                    className: `px-3 py-4 text-center text-sm text-content-secondary`,
                    children: `No domains available`,
                  }),
              ],
            }),
            (0, Q.jsx)(`div`, {
              className: `border-t border-border-light`,
              children: (0, Q.jsxs)(`div`, {
                className: `flex cursor-pointer items-center gap-2 px-3 py-2 hover:bg-surface-02`,
                onClick: f,
                "data-testid": `domain-selector-new-domain`,
                "data-tracking-id": `domain-selector-new-domain`,
                children: [
                  (0, Q.jsx)(Pe, { size: `sm`, className: `size-4 text-content-secondary` }),
                  (0, Q.jsx)(W, { className: `text-sm`, children: `New email domain` }),
                ],
              }),
            }),
          ],
        }),
      ],
    });
  },
  We = ({ config: e, deactivateable: t, editable: n = !0, onEdit: r, domainVerifications: i = [], onNewDomain: a }) => {
    let { toast: o } = L(),
      s = S(),
      c = (0, Z.useMemo)(
        () => (e.emailDomains && e.emailDomains.length > 0 ? e.emailDomains : e.emailDomain ? [e.emailDomain] : []),
        [e.emailDomains, e.emailDomain],
      ),
      u = (0, Z.useCallback)((e) => i.find((t) => t.domain === e)?.state === D.VERIFIED, [i]),
      d = e.displayName || e.issuerUrl || `Custom SSO`,
      f = (0, Z.useCallback)(
        async (t) => {
          let n = c.filter((e) => e !== t);
          if (n.length === 0) {
            o({
              title: `Cannot remove the last domain`,
              description: `An SSO configuration must have at least one domain.`,
            });
            return;
          }
          try {
            (await s.mutateAsync(l(N, { ssoConfigurationId: e.id, emailDomains: n })),
              o({ title: `Removed ${t} from SSO configuration` }));
          } catch (e) {
            o({ title: `Failed to remove domain`, description: F(e) });
          }
        },
        [e.id, c, o, s],
      ),
      p = (0, Z.useCallback)(
        async (t) => {
          let n = [...c, ...t];
          try {
            (await s.mutateAsync(l(N, { ssoConfigurationId: e.id, emailDomains: n })),
              o({ title: `Added ${t.join(`, `)} to SSO configuration` }));
          } catch (e) {
            o({ title: `Failed to add domains`, description: F(e) });
          }
        },
        [e.id, c, o, s],
      );
    return (0, Q.jsxs)(X, {
      className: `flex w-full flex-col gap-3 bg-surface-glass p-4`,
      variant: `bordered`,
      children: [
        (0, Q.jsxs)(`div`, {
          className: `flex flex-wrap items-center gap-3`,
          children: [
            (0, Q.jsx)(Je, { config: e, title: d, deactivateable: t, editable: n }),
            (0, Q.jsx)(W, { className: `text-base font-medium text-content-primary`, children: d }),
            (0, Q.jsx)(`div`, {
              className: `ml-auto flex items-center gap-2`,
              children: (0, Q.jsxs)(Q.Fragment, {
                children: [
                  (0, Q.jsx)(R, {
                    disabled: !n,
                    variant: `secondary`,
                    size: `sm`,
                    onClick: () => r?.(e),
                    "data-tracking-id": `edit-sso-custom-sso-config-card`,
                    children: `Edit`,
                  }),
                  a &&
                    (0, Q.jsx)(Ue, {
                      domainVerifications: i,
                      assignedDomains: c,
                      onAddDomains: p,
                      onRemoveDomain: f,
                      onNewDomain: () => a(e.id),
                      disabled: !n,
                    }),
                ],
              }),
            }),
          ],
        }),
        c.length > 0 &&
          (0, Q.jsx)(`div`, {
            className: `flex flex-wrap gap-2`,
            children: c.map((e) =>
              (0, Q.jsx)(
                He,
                {
                  domain: e,
                  verified: u(e),
                  onRemove: c.length > 1 ? () => f(e) : void 0,
                  disabled: !n || s.isPending,
                },
                e,
              ),
            ),
          }),
      ],
    });
  },
  Ge = ({ config: e, deactivateable: t, editable: n = !0 }) => {
    let r = e ? Ke(e) : ``,
      i = e ? qe(e) : void 0;
    return (0, Q.jsx)(X, {
      className: `flex w-full max-w-[550px] flex-col gap-4 bg-surface-glass p-4`,
      variant: `bordered`,
      children: (0, Q.jsxs)(`div`, {
        className: `flex items-center gap-2`,
        children: [
          e && (0, Q.jsx)(Je, { title: r || Ke(e), config: e, deactivateable: t, editable: n }),
          i ?? (0, Q.jsx)(u, { size: 24, className: `text-content-primary` }),
          (0, Q.jsx)(`p`, { className: `text-base font-normal text-content-primary`, children: r }),
        ],
      }),
    });
  },
  Ke = (e) => (e.issuerUrl?.includes(`github`) ? `GitHub` : e.issuerUrl?.includes(`google`) ? `Google` : `Unknown`),
  qe = (e) => {
    if (e.issuerUrl?.includes(`github`)) return (0, Q.jsx)(ye, { size: `lg`, className: `size-6` });
    if (e.issuerUrl?.includes(`google`)) return (0, Q.jsx)(Se, { size: `lg`, className: `size-6` });
  },
  Je = ({ config: { id: e, state: t }, title: n, deactivateable: r, editable: i }) => {
    let a = S(),
      { toast: o } = L(),
      [s, c] = (0, Z.useState)(!1),
      u = t === w.SSO_CONFIGURATION_STATE_ACTIVE,
      d = (0, Z.useCallback)(
        async (t) => {
          try {
            await a.mutateAsync(l(N, { ssoConfigurationId: e, state: t }));
          } catch (e) {
            o({ title: `Failed to update SSO configuration`, description: F(e) });
          }
        },
        [e, o, a],
      ),
      f = (0, Z.useCallback)(async () => {
        u ? c(!0) : await d(w.SSO_CONFIGURATION_STATE_ACTIVE);
      }, [u, d]),
      p = (0, Z.useCallback)(
        async (e) => {
          (e.preventDefault(), await d(w.SSO_CONFIGURATION_STATE_INACTIVE), c(!1));
        },
        [d],
      );
    return (0, Q.jsxs)(Q.Fragment, {
      children: [
        (0, Q.jsx)(le, {
          content: !r && u ? `You can't deactivate the single remaining provider.` : ``,
          children: (0, Q.jsx)(`div`, {
            className: `flex items-center`,
            children: (0, Q.jsx)(be, {
              state: u ? `checked` : `unchecked`,
              disabled: u ? !r : !i,
              onToggle: f,
              id: `toggle-` + e,
            }),
          }),
        }),
        s &&
          (0, Q.jsx)(B, {
            open: !0,
            onOpenChange: c,
            children: (0, Q.jsxs)(B.Content, {
              className: `max-w-[600px]`,
              "data-testid": `deactivate-form-modal-content`,
              "data-track-location": v.DeactivateSSOModal,
              children: [
                (0, Q.jsxs)(B.Header, {
                  children: [
                    (0, Q.jsxs)(B.Title, { children: [`Deactivating `, n, ` log in `] }),
                    (0, Q.jsx)(B.Description, {}),
                  ],
                }),
                (0, Q.jsx)(B.Body, {
                  className: `overflow-x max-w-full`,
                  children: (0, Q.jsxs)(`form`, {
                    id: `deactivate-form`,
                    onSubmit: p,
                    className: `flex flex-col gap-4`,
                    children: [
                      (0, Q.jsxs)(W, {
                        className: `text-base`,
                        children: [`Users will no longer be able to log in with `, n, `.`],
                      }),
                      (0, Q.jsx)(W, {
                        className: `text-base`,
                        children: `They will need to create a new account using one of the other available log in methods.`,
                      }),
                    ],
                  }),
                }),
                (0, Q.jsxs)(B.Footer, {
                  children: [
                    (0, Q.jsx)(B.Close, {
                      asChild: !0,
                      children: (0, Q.jsx)(R, {
                        type: `button`,
                        variant: `outline`,
                        autoFocus: !0,
                        children: `Cancel`,
                      }),
                    }),
                    (0, Q.jsx)(R, {
                      type: `submit`,
                      variant: `destructive`,
                      form: `deactivate-form`,
                      loading: a.isPending,
                      disabled: a.isPending,
                      "data-testid": `deactivate-submit-button`,
                      "data-tracking-id": `deactivate-sso-config-toggle`,
                      children: `Deactivate`,
                    }),
                  ],
                }),
              ],
            }),
          }),
      ],
    });
  },
  Ye = ({ organizationId: e, configs: t, deactivateable: n, editable: r, className: i }) => {
    let { toast: a } = L(),
      [o, s] = (0, Z.useState)(void 0),
      [c, l] = (0, Z.useState)(!1),
      [u, d] = (0, Z.useState)(void 0),
      [f, p] = (0, Z.useState)(void 0),
      [m, h] = (0, Z.useState)(void 0),
      [g, _] = (0, Z.useState)(void 0),
      { data: y = [] } = ee(),
      b = C(),
      x = E(),
      S = (0, Z.useMemo)(
        () =>
          y
            .filter((e) => e.state === D.PENDING || e.state === D.VERIFIED)
            .sort((e, t) => (e.state === t.state ? e.domain.localeCompare(t.domain) : e.state === D.PENDING ? -1 : 1)),
        [y],
      ),
      w = (0, Z.useCallback)((e, t) => {
        s({ step: e, config: t });
      }, []),
      T = (0, Z.useCallback)(() => {
        s(void 0);
      }, []),
      O = (0, Z.useCallback)(() => {
        w(`configure-sso-v2`);
      }, [w]),
      k = (0, Z.useCallback)(
        (e) => {
          w(`configure-sso`, e);
        },
        [w],
      ),
      A = (0, Z.useCallback)(() => {
        l(!0);
      }, []),
      j = (0, Z.useCallback)(() => {
        l(!1);
      }, []),
      M = (0, Z.useCallback)((e) => {
        d({ domain: e });
      }, []),
      N = (0, Z.useCallback)(() => {
        d(void 0);
      }, []),
      te = (0, Z.useCallback)(
        async (e) => {
          p(e.id);
          try {
            a({
              title:
                (await x.mutateAsync(e))?.state === D.VERIFIED
                  ? `${e.domain} is verified.`
                  : `${e.domain} is not yet verified. Please try again later.`,
            });
          } catch (t) {
            d({
              domain: e.domain,
              error: F(t) || `TXT record not found. DNS changes can take up to 48 hours to propagate.`,
            });
          } finally {
            p(void 0);
          }
        },
        [a, x],
      ),
      ne = (0, Z.useCallback)((e) => {
        (_(void 0), h(e));
      }, []),
      P = (0, Z.useCallback)(() => {
        (_(void 0), h(void 0));
      }, []),
      I = (0, Z.useCallback)(async () => {
        if (m)
          try {
            (await b.mutateAsync(m.id), a({ title: `${m.domain} has been deleted.` }), P());
          } catch (e) {
            _(F(e));
          }
      }, [b, m, P, a]);
    return (0, Q.jsxs)(`div`, {
      className: z(`flex flex-col gap-4`, i),
      children: [
        (0, Q.jsxs)(`div`, {
          className: `flex flex-wrap items-center gap-2`,
          children: [
            (0, Q.jsx)(H, { children: `Single Sign On` }),
            (0, Q.jsx)(`div`, {
              className: `ml-auto`,
              children: (0, Q.jsx)(R, {
                disabled: !r,
                variant: `secondary`,
                size: `sm`,
                LeadingIcon: Pe,
                onClick: O,
                "data-tracking-id": `create-custom-sso`,
                children: `New SSO`,
              }),
            }),
          ],
        }),
        t.length === 0
          ? (0, Q.jsxs)(X, {
              className: `flex w-full flex-col gap-2 bg-surface-glass p-4`,
              variant: `bordered`,
              children: [
                (0, Q.jsx)(W, {
                  className: `text-base text-content-primary`,
                  children: `No custom SSO configurations yet.`,
                }),
                (0, Q.jsx)(W, {
                  className: `text-sm text-content-secondary`,
                  children: `Create an SSO configuration to restrict access based on email domain.`,
                }),
              ],
            })
          : (0, Q.jsx)(`div`, {
              className: `flex flex-col gap-3`,
              children: t.map((e) =>
                (0, Q.jsx)(
                  We,
                  { config: e, deactivateable: n, editable: r, onEdit: k, domainVerifications: y, onNewDomain: A },
                  e.id,
                ),
              ),
            }),
        (0, Q.jsxs)(`div`, {
          className: `flex flex-col gap-3`,
          children: [
            (0, Q.jsxs)(`div`, {
              className: `flex flex-wrap items-center gap-2`,
              children: [
                (0, Q.jsx)(se, { children: `Login Domains` }),
                (0, Q.jsx)(`div`, {
                  className: `ml-auto`,
                  children: (0, Q.jsx)(R, {
                    disabled: !r,
                    variant: `secondary`,
                    size: `sm`,
                    LeadingIcon: Pe,
                    onClick: A,
                    "data-tracking-id": `create-domain-verification`,
                    children: `New domain`,
                  }),
                }),
              ],
            }),
            S.length === 0
              ? (0, Q.jsxs)(X, {
                  className: `flex flex-col gap-2 bg-surface-glass p-4`,
                  variant: `bordered`,
                  children: [
                    (0, Q.jsx)(W, { className: `text-base text-content-primary`, children: `No email domains yet.` }),
                    (0, Q.jsx)(W, {
                      className: `text-sm text-content-secondary`,
                      children: `Add an email domain to control who can sign in with SSO.`,
                    }),
                  ],
                })
              : (0, Q.jsx)(`div`, {
                  className: `flex flex-col gap-3`,
                  children: S.map((e) =>
                    (0, Q.jsx)(
                      Xe,
                      {
                        verification: e,
                        editable: r,
                        onShowDnsRecord: M,
                        onVerify: te,
                        verifyingDomainId: f,
                        onDelete: ne,
                      },
                      e.id,
                    ),
                  ),
                }),
          ],
        }),
        o && (0, Q.jsx)(Ve, { organizationId: e, config: o.config, step: o.step, onClose: T }),
        c &&
          (0, Q.jsx)(B, {
            open: !0,
            onOpenChange: (e) => !e && j(),
            children: (0, Q.jsx)(B.Content, {
              className: `flex max-w-[600px] flex-col p-6`,
              "data-track-location": v.SetupSSOModal,
              children: (0, Q.jsx)(Ie, { organizationId: e, onCancel: j }),
            }),
          }),
        u &&
          (0, Q.jsx)(B, {
            open: !0,
            onOpenChange: (e) => !e && N(),
            children: (0, Q.jsxs)(B.Content, {
              className: `flex max-w-[600px] flex-col gap-4 p-6`,
              "data-track-location": v.SetupSSOModal,
              children: [
                u.error &&
                  (0, Q.jsx)(V, {
                    variant: `danger`,
                    text: (0, Q.jsxs)(`div`, {
                      className: `flex flex-col text-sm`,
                      children: [
                        (0, Q.jsx)(`span`, { children: u.error }),
                        (0, Q.jsx)(`span`, {
                          className: `text-content-secondary`,
                          children: `DNS changes can take up to 48 hours to propagate.`,
                        }),
                      ],
                    }),
                  }),
                (0, Q.jsx)(Ie, { organizationId: e, domain: u.domain, onCancel: N }),
              ],
            }),
          }),
        m &&
          (0, Q.jsx)(B, {
            open: !0,
            onOpenChange: (e) => !e && P(),
            children: (0, Q.jsxs)(B.Content, {
              className: `flex max-w-[480px] flex-col gap-4 p-6`,
              "data-track-location": v.SetupSSOModal,
              children: [
                (0, Q.jsxs)(B.Header, {
                  children: [
                    (0, Q.jsxs)(B.Title, { children: [`Delete `, m.domain, `?`] }),
                    (0, Q.jsx)(B.Description, {
                      children: `This will remove the domain from your SSO configuration. This action cannot be undone.`,
                    }),
                  ],
                }),
                g && (0, Q.jsx)(V, { variant: `danger`, text: g }),
                (0, Q.jsxs)(B.Footer, {
                  className: `gap-2`,
                  children: [
                    (0, Q.jsx)(B.Close, {
                      asChild: !0,
                      children: (0, Q.jsx)(R, {
                        variant: `outline`,
                        onClick: P,
                        "data-tracking-id": `cancel-delete-domain`,
                        children: `Cancel`,
                      }),
                    }),
                    (0, Q.jsx)(R, {
                      variant: `destructive`,
                      onClick: I,
                      loading: b.isPending,
                      "data-tracking-id": `confirm-delete-domain`,
                      children: `Delete`,
                    }),
                  ],
                }),
              ],
            }),
          }),
      ],
    });
  },
  Xe = ({ verification: e, editable: t, onShowDnsRecord: n, verifyingDomainId: r, onDelete: i }) => {
    let a = e.state === D.PENDING,
      o = r === e.id,
      s = (0, Q.jsxs)(`div`, {
        className: `flex items-start gap-3`,
        children: [
          a
            ? (0, Q.jsx)(we, { className: `mt-1 text-content-warning`, size: `sm` })
            : (0, Q.jsx)(Ce, { className: `mt-1 text-content-positive`, size: `sm` }),
          (0, Q.jsxs)(`div`, {
            className: `flex flex-col gap-1`,
            children: [
              (0, Q.jsx)(W, { className: `text-base font-medium text-content-primary`, children: e.domain }),
              a
                ? (0, Q.jsx)(`div`, {
                    className: `flex flex-wrap items-center gap-2 text-sm text-content-secondary`,
                    children: (0, Q.jsx)(R, {
                      variant: `text`,
                      size: `xs`,
                      className: `p-0 text-content-link hover:underline`,
                      onClick: () => n(e.domain),
                      "data-testid": `verification-required-${e.domain}`,
                      "data-tracking-id": `verification-required-link`,
                      "aria-label": `View DNS instructions for ${e.domain}`,
                      disabled: !t,
                      children: `Verify ownership`,
                    }),
                  })
                : (0, Q.jsx)(W, { className: `text-sm text-content-positive`, children: `Verified` }),
            ],
          }),
        ],
      });
    return (0, Q.jsxs)(X, {
      className: `flex flex-col gap-4 bg-surface-glass p-4 md:flex-row md:items-center md:justify-between`,
      "data-testid": `domain-card-${e.domain}`,
      children: [
        a
          ? (0, Q.jsx)(le, {
              content: `Domain not verified. Add a TXT record to your DNS settings to verify ownership.`,
              children: s,
            })
          : s,
        (0, Q.jsx)(`div`, {
          className: `flex items-center gap-2 self-stretch md:self-center`,
          children: (0, Q.jsxs)(K, {
            children: [
              (0, Q.jsx)(K.Trigger, {
                asChild: !0,
                children: (0, Q.jsx)(R, {
                  variant: `ghost`,
                  size: `sm`,
                  LeadingIcon: ue,
                  "aria-label": `Domain actions for ${e.domain}`,
                  disabled: !t,
                  "data-tracking-id": `domain-actions-trigger`,
                }),
              }),
              (0, Q.jsxs)(K.Content, {
                align: `end`,
                children: [
                  a &&
                    (0, Q.jsx)(K.Item, {
                      onClick: () => n(e.domain),
                      disabled: !t || o,
                      "data-tracking-id": `verify-domain-card`,
                      children: `Verify`,
                    }),
                  (0, Q.jsx)(K.Item, {
                    variant: `destructive`,
                    onClick: () => i(e),
                    "data-tracking-id": `delete-domain-card`,
                    children: `Delete`,
                  }),
                ],
              }),
            ],
          }),
        }),
      ],
    });
  },
  Ze = ({ isOpen: e, onClose: t, onConfirm: n, runners: r, canonicalDomain: i, isLoading: a = !1 }) =>
    (0, Q.jsx)(B, {
      open: e,
      onOpenChange: t,
      children: (0, Q.jsxs)(B.Content, {
        "data-track-location": v.EnforceCustomDomainConfirmationDialog,
        children: [
          (0, Q.jsxs)(B.Header, {
            children: [
              (0, Q.jsx)(`h2`, { className: `text-lg font-semibold`, children: `Confirm Custom Domain Enforcement` }),
              (0, Q.jsxs)(`div`, {
                className: `mt-2 flex gap-2`,
                children: [
                  (0, Q.jsx)(`span`, { className: `text-content-warning`, children: `⚠️` }),
                  (0, Q.jsxs)(`p`, {
                    className: `text-sm text-content-secondary`,
                    children: [
                      `Enabling this will prevent users from accessing your organization via `,
                      i,
                      `.`,
                      ` `,
                      r.length === 0
                        ? (0, Q.jsxs)(Q.Fragment, {
                            children: [`No runners are currently using `, i, `. You can safely enable enforcement.`],
                          })
                        : (0, Q.jsxs)(Q.Fragment, {
                            children: [
                              oe(r.length, !1, `runner`),
                              ` registered with`,
                              ` `,
                              i,
                              ` will become unusable.`,
                            ],
                          }),
                    ],
                  }),
                ],
              }),
            ],
          }),
          (0, Q.jsx)(`div`, {
            className: `flex flex-col gap-4`,
            children:
              r.length > 0 &&
              (0, Q.jsxs)(Q.Fragment, {
                children: [
                  (0, Q.jsxs)(`div`, {
                    children: [
                      (0, Q.jsx)(W, {
                        className: `mb-3 text-sm font-semibold text-content-primary`,
                        children: `Affected Runners`,
                      }),
                      (0, Q.jsx)(`div`, {
                        className: `max-h-64 overflow-y-auto`,
                        children: (0, Q.jsx)(`div`, {
                          className: `flex flex-col gap-2`,
                          children: r.map((e) => (0, Q.jsx)(Qe, { ...e }, e.runner.runnerId)),
                        }),
                      }),
                    ],
                  }),
                  (0, Q.jsx)(`div`, {
                    className: `rounded-lg bg-surface-secondary p-4`,
                    children: (0, Q.jsxs)(W, {
                      className: `text-sm text-content-secondary`,
                      children: [
                        (0, Q.jsx)(`strong`, { children: `Recommendation:` }),
                        ` Delete these environments and update project settings to use runners registered with your custom domain.`,
                      ],
                    }),
                  }),
                ],
              }),
          }),
          (0, Q.jsxs)(B.Footer, {
            children: [
              (0, Q.jsx)(R, {
                variant: `outline`,
                onClick: t,
                disabled: a,
                "data-tracking-id": `enforce-custom-domain-cancel`,
                children: `Cancel`,
              }),
              (0, Q.jsx)(R, {
                variant: `destructive`,
                onClick: n,
                loading: a,
                "data-tracking-id": `enforce-custom-domain-confirm`,
                children: `Enable enforcement`,
              }),
            ],
          }),
        ],
      }),
    }),
  Qe = ({ runner: e, projectCount: t, environmentCount: r, hasMoreEnvironments: i }) => {
    let a = m(),
      { projectCount: o, environmentCount: s, hasMoreEnvironments: c, isLoading: l } = Ee({ runnerId: e.runnerId }),
      u = l ? t : o,
      d = l ? r : s,
      f = l ? i : c,
      p = (0, Z.useMemo)(() => `/projects?runnerId=${e.runnerId}`, [e.runnerId]),
      h = (0, Z.useMemo)(() => `/settings/environments?runner=${e.runnerId}`, [e.runnerId]),
      g = (0, Z.useMemo)(() => `/settings/runners/${e.runnerId}`, [e.runnerId]);
    return (0, Q.jsxs)(`div`, {
      className: `border-border-primary flex items-center justify-between rounded-lg border bg-surface-primary p-3`,
      children: [
        (0, Q.jsxs)(`button`, {
          onClick: () => a(g),
          className: `flex flex-col gap-1 text-left transition-opacity hover:opacity-70`,
          "data-tracking-id": `enforce-custom-domain-runner-details`,
          children: [
            (0, Q.jsx)(W, {
              className: `text-sm font-semibold text-content-primary`,
              children: e.name || `Unnamed Runner`,
            }),
            (0, Q.jsxs)(W, { className: `text-xs text-content-tertiary`, children: [`ID: `, e.runnerId] }),
          ],
        }),
        (0, Q.jsxs)(`div`, {
          className: `flex gap-3`,
          children: [
            (0, Q.jsxs)(`button`, {
              onClick: () => a(p),
              disabled: u === 0 || l,
              className: `flex items-center gap-1.5 rounded px-2 py-1 transition-colors hover:bg-surface-secondary disabled:cursor-not-allowed disabled:opacity-50`,
              "data-tracking-id": `enforce-custom-domain-runner-projects`,
              children: [
                (0, Q.jsx)(Te, { size: `sm`, className: `text-content-secondary` }),
                (0, Q.jsx)(W, {
                  className: `text-sm text-content-secondary`,
                  children: l ? `...` : oe(u, !1, `project`),
                }),
              ],
            }),
            (0, Q.jsxs)(`button`, {
              onClick: () => a(h),
              disabled: d === 0 || l,
              className: `flex items-center gap-1.5 rounded px-2 py-1 transition-colors hover:bg-surface-secondary disabled:cursor-not-allowed disabled:opacity-50`,
              "data-tracking-id": `enforce-custom-domain-runner-environments`,
              children: [
                (0, Q.jsx)(n, { size: `sm`, className: `text-content-secondary` }),
                (0, Q.jsx)(W, { className: `text-sm text-content-secondary`, children: l ? `...` : oe(d, f, `env`) }),
              ],
            }),
          ],
        }),
      ],
    });
  },
  $e = ({ organizationId: e, editable: t = !0 }) => {
    let { toast: n } = L(),
      [r, i] = (0, Z.useState)(!1),
      [a, o] = (0, Z.useState)(!1),
      { data: s, isLoading: c } = O(e),
      { data: l, isLoading: u } = g(e),
      d = _(),
      f = (0, Z.useMemo)(() => `app.ioi.io`, []),
      { runners: p, isLoading: m } = De(f),
      h = c || u,
      v = !!s,
      y = l?.enforced ?? !1,
      b = (0, Z.useMemo)(
        () =>
          d.isPending
            ? `Updating domain enforcement policy...`
            : d.isSuccess
              ? y
                ? `Domain enforcement enabled`
                : `Domain enforcement disabled`
              : ``,
        [d.isPending, d.isSuccess, y],
      ),
      x = async (e) => {
        if (e && !m && p.length > 0) {
          (o(!0), i(!0));
          return;
        }
        await S(e);
      },
      S = async (t) => {
        try {
          (await d.mutateAsync({ organizationId: e, enforced: t }),
            n({ title: t ? `Domain enforcement enabled` : `Domain enforcement disabled` }),
            i(!1),
            o(!1));
        } catch (e) {
          (n({ title: `Failed to update enforcement policy`, description: F(e), variant: `default` }), o(!1));
        }
      };
    return h
      ? (0, Q.jsx)(X, {
          className: `flex w-full max-w-[550px] flex-col gap-4 bg-surface-glass p-4`,
          variant: `bordered`,
          children: (0, Q.jsxs)(`div`, {
            className: `flex gap-4`,
            children: [
              (0, Q.jsx)(`div`, {
                className: `flex w-11 items-center justify-center`,
                children: (0, Q.jsx)(G, { ready: !1, className: `h-6 w-11` }),
              }),
              (0, Q.jsxs)(`div`, {
                className: `flex flex-1 flex-col gap-3`,
                children: [
                  (0, Q.jsx)(`p`, {
                    className: `text-base font-normal text-content-primary`,
                    children: `Enforce custom domain at login`,
                  }),
                  (0, Q.jsx)(G, { ready: !1, className: `h-10 w-full` }),
                ],
              }),
            ],
          }),
        })
      : (0, Q.jsxs)(Q.Fragment, {
          children: [
            (0, Q.jsxs)(X, {
              className: `flex w-full max-w-[550px] flex-col gap-4 bg-surface-glass p-4`,
              variant: `bordered`,
              children: [
                (0, Q.jsx)(`div`, {
                  className: `sr-only`,
                  role: `status`,
                  "aria-live": `polite`,
                  "aria-atomic": `true`,
                  children: b,
                }),
                (0, Q.jsxs)(`div`, {
                  className: `flex gap-4`,
                  children: [
                    (0, Q.jsx)(`div`, {
                      className: `flex w-11 items-center justify-center`,
                      children: (0, Q.jsx)(be, {
                        state: y ? `checked` : `unchecked`,
                        isLoading: d.isPending || a,
                        onToggle: (e) => void x(e),
                        disabled: !v || !t || d.isPending || a,
                        id: `enforce-custom-domain-toggle`,
                        "aria-label": `Enforce custom domain at login`,
                      }),
                    }),
                    (0, Q.jsx)(`div`, {
                      className: `flex flex-1 flex-col gap-3`,
                      children: (0, Q.jsxs)(`div`, {
                        className: `flex flex-col gap-1`,
                        children: [
                          (0, Q.jsx)(`p`, {
                            className: `text-base font-normal text-content-primary`,
                            children: `Enforce custom domain at login`,
                          }),
                          (0, Q.jsx)(`span`, {
                            className: `text-sm text-content-secondary`,
                            children: v
                              ? `When enabled, all users must access your organization through your custom domain. Both web login and API access (including personal access tokens) via the canonical domain will be blocked.`
                              : `Configure a custom domain first to enable enforcement`,
                          }),
                        ],
                      }),
                    }),
                  ],
                }),
              ],
            }),
            r &&
              (0, Q.jsx)(et, {
                isOpen: r,
                onClose: () => {
                  (i(!1), o(!1));
                },
                onConfirm: () => {
                  S(!0);
                },
                runners: p,
                canonicalDomain: f,
                isLoading: d.isPending,
              }),
          ],
        });
  },
  et = ({ isOpen: e, onClose: t, onConfirm: n, runners: r, canonicalDomain: i, isLoading: a }) =>
    (0, Q.jsx)(Ze, {
      isOpen: e,
      onClose: t,
      onConfirm: n,
      runners: (0, Z.useMemo)(
        () => r.map((e) => ({ runner: e, projectCount: 0, environmentCount: 0, hasMoreEnvironments: !1 })),
        [r],
      ),
      canonicalDomain: i,
      isLoading: a,
    }),
  tt = ({ organizationId: e, isEnterpriseTier: t = !1 }) =>
    (0, Q.jsxs)(`div`, {
      className: `flex flex-col gap-6`,
      children: [
        (0, Q.jsx)(`div`, {
          className: `text-base text-content-secondary`,
          children: `Configure SSO for your organization.`,
        }),
        !t &&
          (0, Q.jsx)(V, {
            variant: `info`,
            className: `py-4`,
            "data-testid": `free-tier-banner`,
            text: (0, Q.jsxs)(Q.Fragment, {
              children: [
                `Upgrade to`,
                ` `,
                (0, Q.jsx)(c, {
                  to: `/settings/manage-organization`,
                  className: `font-medium text-content-brand hover:underline`,
                  children: `Enterprise tier`,
                }),
                ` `,
                `to manage login and security settings.`,
              ],
            }),
            action: {
              text: `Upgrade now`,
              onClick: () => (window.location.href = `/settings/manage-organization`),
              "data-tracking-id": `upgrade-enterprise-login-security`,
            },
          }),
        (0, Q.jsxs)(`div`, {
          className: `flex w-full max-w-[550px] flex-col gap-6`,
          children: [
            (0, Q.jsx)(it, {}),
            (0, Q.jsx)(nt, { organizationId: e, editable: t }),
            (0, Q.jsx)(rt, { organizationId: e, editable: t }),
          ],
        }),
      ],
    }),
  nt = ({ organizationId: e, editable: t }) =>
    (0, Q.jsxs)(`div`, {
      className: `flex flex-col gap-4`,
      children: [
        (0, Q.jsx)(H, { children: `Custom Domain` }),
        (0, Q.jsx)(Ne, { organizationId: e, editable: t }),
        (0, Q.jsx)($e, { organizationId: e, editable: t }),
      ],
    }),
  rt = ({ organizationId: e, editable: t }) => {
    let { data: n } = I(),
      r = (0, Z.useMemo)(() => n?.filter(ot) || [], [n]),
      i = (0, Z.useMemo)(
        () =>
          n?.filter(at).sort((e, t) => {
            let n = e.displayName.localeCompare(t.displayName);
            return n === 0 ? e.issuerUrl.localeCompare(t.issuerUrl) : n;
          }) || [],
        [n],
      ),
      a = (n?.filter((e) => e.state === w.SSO_CONFIGURATION_STATE_ACTIVE)?.length || 0) > 1;
    return (0, Q.jsxs)(`div`, {
      className: `flex flex-col gap-4`,
      children: [
        (0, Q.jsx)(H, { children: `Login Methods` }),
        r.map((e) => (0, Q.jsx)(Ge, { config: e, deactivateable: a, editable: t }, `built-in-config-${e.issuerUrl}`)),
        (0, Q.jsx)(Ye, { className: `mt-4`, organizationId: e, configs: i, deactivateable: a, editable: t }),
      ],
    });
  },
  it = () => {
    let { data: e, isPending: t, error: n } = ie(),
      r = (0, Z.useMemo)(
        () => (e?.inviteId ? `${window.location.origin}/login?inviteId=${encodeURIComponent(e.inviteId)}` : ``),
        [e?.inviteId],
      ),
      i = `Organization Login Link`;
    return t
      ? (0, Q.jsxs)(`div`, {
          className: `flex flex-col gap-4`,
          children: [(0, Q.jsx)(H, { children: i }), (0, Q.jsx)(G, { ready: !1, className: `h-10 w-full` })],
        })
      : n || !e?.inviteId
        ? (0, Q.jsxs)(`div`, {
            className: `flex flex-col gap-4`,
            children: [
              (0, Q.jsx)(H, { children: i }),
              (0, Q.jsx)(_e, { error: n }),
              !n &&
                (0, Q.jsx)(W, {
                  className: `text-base text-content-secondary`,
                  children: `Unable to load organization login link. Please try refreshing the page.`,
                }),
            ],
          })
        : (0, Q.jsxs)(`div`, {
            className: `flex flex-col gap-4`,
            children: [
              (0, Q.jsx)(H, { children: i }),
              (0, Q.jsx)(W, {
                className: `text-base text-content-secondary`,
                children: `Share this link with members to login using supported methods.`,
              }),
              (0, Q.jsx)(U, { copyable: !0, value: r, disabled: !0, "data-tracking-id": `organization-login-link` }),
            ],
          });
  },
  at = (e) => e.providerType === A.CUSTOM,
  ot = (e) => e.providerType === A.BUILTIN,
  st = () => {
    r(`Login Configuration`);
    let { membership: e, isPending: n } = ae(),
      { data: i, isPending: a } = re();
    if (n || !e || a || !i) return null;
    if (e.userRole !== x.ADMIN) return (0, Q.jsx)(t, {});
    let o = i.tier === T.ENTERPRISE;
    return (0, Q.jsx)(`div`, {
      className: `flex w-full max-w-none flex-col`,
      "data-testid": `login-and-security-page`,
      children: (0, Q.jsx)(tt, { organizationId: e.organizationId, isEnterpriseTier: o }),
    });
  };
export { st as LoginAndSecurityPage };

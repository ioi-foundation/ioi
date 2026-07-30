import { a as e } from "./rolldown-runtime-CGYlQKCx.js";
import {
  Dt as t,
  Et as n,
  Kt as r,
  Lt as i,
  Tt as a,
  Yn as o,
  _t as s,
  bt as c,
  jt as l,
  mt as u,
  nt as d,
  vt as f,
  xt as p,
} from "./SegmentProvider-CXCNBY9U.js";
import { n as m } from "./@mux-DLaEVubF.js";
import { Im as h, Rl as g, Rm as _, cg as v, dm as y, eg as b, g_ as x, v_ as S } from "./vendor-DAwbZtf0.js";
import {
  Dr as C,
  Dt as w,
  Fi as T,
  i as E,
  jr as D,
  lt as O,
  tr as k,
  v as A,
} from "./use-boot-in-app-chat-t-J_VjKS.js";
import { a as j, c as M, f as N, i as ee, l as P, m as F, o as I, r as te, s as L } from "./integration_pb-1Qh9FOHE.js";
import { n as ne } from "./toast-axaLeIzZ.js";
import { t as R } from "./button-6YP03Qf2.js";
import { t as z } from "./ipc-Dxb-zSYw.js";
import { t as re } from "./use-desktop-A2HAwVgY.js";
import { t as B } from "./dialog-BtjFqa-w.js";
import { t as ie } from "./use-membership-CcV5kGny.js";
import { t as V } from "./banner-CFcSGYsz.js";
import { n as ae } from "./utils-C9bSuXia.js";
import { t as H } from "./input-C42Z_4fO.js";
import { t as U } from "./Pill-99RRpZf2.js";
import "./pill-AA_qJIlm.js";
import { t as W } from "./text-fFCFeCas.js";
import { t as oe } from "./skeleton-Cm867Q_k.js";
import { n as se, r as G, t as ce } from "./dropdown-menu-D3UmjGpQ.js";
import { a as K } from "./url-validation-Ph7WWpDb.js";
import { t as le } from "./external-link-BKbp1Q22.js";
import { t as ue } from "./error-message-Az-KJctk.js";
import { t as q } from "./combobox-BkGa_nRF.js";
import { t as J } from "./label-5ATlPnPj.js";
import { t as Y } from "./form-control-BfDRQ8Xb.js";
import { t as de } from "./switch-CiuLW56f.js";
import { t as fe } from "./textarea-65aCrC5K.js";
import { t as X } from "./checkbox-input-field-BnHkIfK1.js";
import { tt as pe } from "./main-DLKYFe1Y.js";
import { n as me, t as he } from "./incident-integration-hosts-CgUiOu4A.js";
import { n as ge } from "./integration-oauth-channel-CACUIrLi.js";
var Z = e(m(), 1),
  _e = [
    `source-control`,
    `communication`,
    `project-management`,
    `observability`,
    `data-analytics`,
    `knowledge`,
    `ai`,
    `automation-triggers`,
    `mcp`,
  ],
  ve = {
    "source-control": { id: `source-control`, label: `Source control` },
    communication: { id: `communication`, label: `Communication` },
    "project-management": { id: `project-management`, label: `Project management` },
    observability: { id: `observability`, label: `Observability` },
    "data-analytics": { id: `data-analytics`, label: `Data & analytics` },
    knowledge: { id: `knowledge`, label: `Knowledge` },
    ai: { id: `ai`, label: `AI` },
    "automation-triggers": { id: `automation-triggers`, label: `Automation triggers` },
    mcp: { id: `mcp`, label: `MCP` },
  },
  ye = {
    [M.SOURCE_CONTROL]: `source-control`,
    [M.COMMUNICATION]: `communication`,
    [M.PROJECT_MANAGEMENT]: `project-management`,
    [M.OBSERVABILITY]: `observability`,
    [M.DATA_ANALYTICS]: `data-analytics`,
    [M.KNOWLEDGE]: `knowledge`,
    [M.AI]: `ai`,
    [M.AUTOMATION_TRIGGERS]: `automation-triggers`,
    [M.MCP]: `mcp`,
  },
  be = {
    "source-control": M.SOURCE_CONTROL,
    communication: M.COMMUNICATION,
    "project-management": M.PROJECT_MANAGEMENT,
    observability: M.OBSERVABILITY,
    "data-analytics": M.DATA_ANALYTICS,
    knowledge: M.KNOWLEDGE,
    ai: M.AI,
    "automation-triggers": M.AUTOMATION_TRIGGERS,
    mcp: M.MCP,
  };
function xe(e) {
  return e.map((e) => be[e]);
}
function Q(e) {
  let t = [];
  for (let n of e) {
    let e = ye[n];
    e && t.push(e);
  }
  return t;
}
function Se(e, t) {
  if (!t) return !0;
  let n = t.toLowerCase();
  return e.name.toLowerCase().includes(n) || e.description.toLowerCase().includes(n);
}
var $ = S(),
  Ce = ({ selected: e, onChange: t, lockedCategories: n = [] }) => {
    let r = (r, i) => {
      let a = i ? [...e, r] : e.filter((e) => e !== r);
      t([...a, ...n.filter((e) => !a.includes(e))]);
    };
    return (0, $.jsx)(`div`, {
      className: `flex flex-col gap-1`,
      children: _e
        .filter((e) => !n.includes(e))
        .map((t) =>
          (0, $.jsx)(
            X,
            {
              label: ve[t].label,
              checked: e.includes(t),
              onChange: (e) => r(t, e),
              "data-testid": `category-checkbox-${t}`,
            },
            t,
          ),
        ),
    });
  },
  we = `/integrations/oauth/mcp/callback`,
  Te = (e) =>
    e
      .split(/[\s,]+/)
      .map((e) => e.trim())
      .filter(Boolean),
  Ee = ({ isOpen: e, onClose: t }) => {
    let { toast: n } = ne(),
      i = s(),
      [a, o] = (0, Z.useState)(``),
      [c, l] = (0, Z.useState)(``),
      [u, d] = (0, Z.useState)(``),
      [f, p] = (0, Z.useState)([`mcp`]),
      [m, h] = (0, Z.useState)(`dcr`),
      [g, _] = (0, Z.useState)(``),
      [v, y] = (0, Z.useState)(``),
      [b, S] = (0, Z.useState)(``),
      [C, T] = (0, Z.useState)(``),
      [E, D] = (0, Z.useState)(``),
      [O, A] = (0, Z.useState)({}),
      j = (0, Z.useId)(),
      M = (0, Z.useId)(),
      N = (0, Z.useMemo)(() => `${window.location.origin}${we}`, []),
      ee = () => {
        (o(``), l(``), d(``), p([`mcp`]), h(`dcr`), _(``), y(``), S(``), T(``), D(``), A({}));
      },
      P = () => {
        (ee(), t());
      },
      F = () => {
        let e = {};
        return (
          a.trim() || (e.name = `Name is required`),
          u.trim() ? K(u.trim()) || (e.mcpUrl = `Please enter a valid HTTPS URL`) : (e.mcpUrl = `MCP URL is required`),
          f.length === 0 && (e.categories = `Select at least one category`),
          m === `manual` &&
            (g.trim() || (e.clientId = `Client ID is required`),
            v.trim() || (e.clientSecret = `Client secret is required`),
            b.trim() && !K(b.trim()) && (e.authUrl = `Please enter a valid HTTPS URL`),
            C.trim() && !K(C.trim()) && (e.tokenUrl = `Please enter a valid HTTPS URL`)),
          A(e),
          Object.keys(e).length === 0
        );
      },
      I = async (e) => {
        if ((e.preventDefault(), F()))
          try {
            let e =
              m === `dcr`
                ? { dynamicRegistration: !0 }
                : {
                    dynamicRegistration: !1,
                    clientId: g.trim(),
                    clientSecret: v.trim(),
                    authUrl: b.trim(),
                    tokenUrl: C.trim(),
                    scopes: Te(E),
                  };
            (await i.mutateAsync(
              x(te, {
                name: a.trim(),
                description: c.trim(),
                enabled: !1,
                categories: xe(f),
                capabilities: { mcp: { url: u.trim() } },
                auth: { requiresAuth: !0, oauth: e },
              }),
            ),
              n({
                title: `Custom integration created`,
                description: `${a.trim()} has been created. Enable it to make it available to your organization.`,
              }),
              P());
          } catch (e) {
            n({ title: `Failed to create integration`, description: k(e) });
          }
      };
    return (0, $.jsx)(B, {
      open: e,
      onOpenChange: (e) => !e && P(),
      children: (0, $.jsxs)(B.Content, {
        "data-track-location": w.IntegrationConfigModal,
        children: [
          (0, $.jsxs)(B.Header, {
            children: [
              (0, $.jsx)(B.Title, { children: `Add MCP Integration` }),
              (0, $.jsx)(B.Description, {
                children: `Connect an MCP server to make it available to your organization.`,
              }),
            ],
          }),
          (0, $.jsxs)(`form`, {
            onSubmit: (e) => void I(e),
            children: [
              (0, $.jsx)(B.Body, {
                children: (0, $.jsxs)(`div`, {
                  className: `flex flex-col gap-4`,
                  children: [
                    (0, $.jsx)(Y, {
                      label: `Name`,
                      error: O.name,
                      "data-testid": `custom-integration-name-field`,
                      children: (0, $.jsx)(H, {
                        placeholder: `e.g. Hex, Sentry`,
                        value: a,
                        onChange: (e) => o(e.target.value),
                        "data-testid": `custom-integration-name-input`,
                        autoFocus: !0,
                      }),
                    }),
                    (0, $.jsx)(Y, {
                      label: `MCP URL`,
                      error: O.mcpUrl,
                      hint: `The MCP server endpoint URL`,
                      "data-testid": `custom-integration-mcp-url-field`,
                      children: (0, $.jsx)(H, {
                        placeholder: `e.g. https://hex.tech/mcp/sse`,
                        value: u,
                        onChange: (e) => d(e.target.value),
                        "data-testid": `custom-integration-mcp-url-input`,
                      }),
                    }),
                    (0, $.jsxs)(`div`, {
                      className: `flex flex-col gap-1`,
                      children: [
                        (0, $.jsx)(J, { id: j, children: `OAuth setup` }),
                        (0, $.jsx)(r, {
                          value: m,
                          onValueChange: (e) => h(e),
                          children: (0, $.jsxs)(r.List, {
                            "aria-labelledby": j,
                            children: [
                              (0, $.jsx)(r.Trigger, { value: `dcr`, children: `Automatic (DCR)` }),
                              (0, $.jsx)(r.Trigger, { value: `manual`, children: `Manual` }),
                            ],
                          }),
                        }),
                      ],
                    }),
                    m === `dcr`
                      ? (0, $.jsx)(V, {
                          variant: `info`,
                          text: `The MCP server must support RFC 7591 OAuth 2.0 Dynamic Client Registration (DCR).`,
                          link: (0, $.jsx)(le, {
                            href: `https://ioi.com/docs/ioi/mcp#custom-organization-mcp-integrations`,
                            className: `text-sm font-medium text-content-primary`,
                            iconSize: `sm`,
                            children: `Learn more`,
                          }),
                        })
                      : (0, $.jsxs)($.Fragment, {
                          children: [
                            (0, $.jsx)(Y, {
                              id: M,
                              label: `Callback URL`,
                              hint: `Register this URL as the redirect URI in your OAuth provider before saving.`,
                              children: (0, $.jsx)(H, {
                                id: M,
                                value: N,
                                readOnly: !0,
                                copyable: !0,
                                "data-testid": `custom-integration-callback-url-input`,
                              }),
                            }),
                            (0, $.jsx)(Y, {
                              label: `Client ID`,
                              error: O.clientId,
                              children: (0, $.jsx)(H, {
                                value: g,
                                onChange: (e) => _(e.target.value),
                                "data-testid": `custom-integration-client-id-input`,
                              }),
                            }),
                            (0, $.jsx)(Y, {
                              label: `Client secret`,
                              error: O.clientSecret,
                              children: (0, $.jsx)(H, {
                                type: `password`,
                                value: v,
                                onChange: (e) => y(e.target.value),
                                "data-testid": `custom-integration-client-secret-input`,
                              }),
                            }),
                            (0, $.jsx)(Y, {
                              label: `Authorization URL`,
                              hint: `Optional. Auto-discovered from the MCP server if left blank.`,
                              error: O.authUrl,
                              children: (0, $.jsx)(H, {
                                placeholder: `https://example.com/oauth/authorize`,
                                value: b,
                                onChange: (e) => S(e.target.value),
                                "data-testid": `custom-integration-auth-url-input`,
                              }),
                            }),
                            (0, $.jsx)(Y, {
                              label: `Token URL`,
                              hint: `Optional. Auto-discovered from the MCP server if left blank.`,
                              error: O.tokenUrl,
                              children: (0, $.jsx)(H, {
                                placeholder: `https://example.com/oauth/token`,
                                value: C,
                                onChange: (e) => T(e.target.value),
                                "data-testid": `custom-integration-token-url-input`,
                              }),
                            }),
                            (0, $.jsx)(Y, {
                              label: `Scopes`,
                              hint: `Optional. Separate with newlines, spaces, or commas. Auto-discovered from the MCP server when Authorization URL is left blank.`,
                              children: (0, $.jsx)(fe, {
                                placeholder: `e.g.
read:user
repo`,
                                value: E,
                                onChange: (e) => D(e.target.value),
                                rows: 4,
                                minHeight: 96,
                                "data-testid": `custom-integration-scopes-input`,
                              }),
                            }),
                          ],
                        }),
                    (0, $.jsx)(Y, {
                      label: `Description`,
                      hint: `Optional`,
                      "data-testid": `custom-integration-description-field`,
                      children: (0, $.jsx)(H, {
                        placeholder: `A short description of this integration`,
                        value: c,
                        onChange: (e) => l(e.target.value),
                        "data-testid": `custom-integration-description-input`,
                      }),
                    }),
                    (0, $.jsx)(Y, {
                      label: `Categories`,
                      hint: `Select at least one`,
                      error: O.categories,
                      children: (0, $.jsx)(Ce, { selected: f, onChange: p, lockedCategories: [`mcp`] }),
                    }),
                  ],
                }),
              }),
              (0, $.jsxs)(B.Footer, {
                children: [
                  (0, $.jsx)(R, {
                    type: `button`,
                    variant: `outline`,
                    onClick: P,
                    "data-tracking-id": `create-custom-integration-cancel`,
                    children: `Cancel`,
                  }),
                  (0, $.jsx)(R, {
                    type: `submit`,
                    loading: i.isPending,
                    "data-tracking-id": `create-custom-integration-submit`,
                    children: `Create`,
                  }),
                ],
              }),
            ],
          }),
        ],
      }),
    });
  },
  De = ({
    definition: e,
    integration: t,
    onCreateAndInstall: r,
    onToggleEnabled: i,
    onInstall: a,
    isCreating: o,
    isUpdating: s,
  }) => {
    let c = !!t,
      u = c && t.enabled,
      [d, f] = (0, Z.useState)(!1),
      p = Q(e.categories).map((e) => ve[e].label),
      { data: m } = n(u ? t.id : void 0, { pendingReauth: d }),
      h = m?.checks.find((e) => e.check === F.APP_INSTALLATION),
      g = h !== void 0 && !h.message,
      _ = m?.checks.filter((e) => e.message) ?? [];
    (d && m && g && f(!1), ge(t?.id));
    let v = () => {
      (f(!0), a());
    };
    return (0, $.jsxs)(l.Item, {
      id: e.id,
      children: [
        (0, $.jsx)(l.ItemIcon, {
          size: 36,
          children: e.iconUrl
            ? (0, $.jsx)(`img`, { src: e.iconUrl, alt: `${e.name} icon`, className: `h-8 w-8` })
            : null,
        }),
        (0, $.jsx)(l.ItemTitle, {
          children: (0, $.jsxs)(`span`, {
            className: `flex items-center gap-2`,
            children: [
              e.name,
              p.map((e) => (0, $.jsx)(U, { variant: `neutral`, size: `sm`, children: e }, e)),
              u && g && (0, $.jsx)(U, { variant: `success`, size: `sm`, children: `Installed` }),
            ],
          }),
        }),
        (0, $.jsx)(l.ItemDescription, { children: e.description }),
        (0, $.jsx)(l.ItemContent, {
          alignment: `right`,
          children: (0, $.jsxs)(`div`, {
            className: `flex items-center gap-3`,
            children: [
              _.length > 0 &&
                (0, $.jsx)(`div`, {
                  className: `flex flex-col gap-2`,
                  children: _.map((e) =>
                    (0, $.jsx)(
                      V,
                      {
                        variant: `warning`,
                        className: `text-sm`,
                        text: e.message,
                        link: e.documentationUrl
                          ? (0, $.jsx)(le, {
                              href: e.documentationUrl,
                              iconSize: `sm`,
                              className: `text-content-warning hover:text-content-warning`,
                              children: `Learn more`,
                            })
                          : void 0,
                        action:
                          e.actionHint === `github_app_install`
                            ? {
                                text: `Install app`,
                                size: `sm`,
                                responsive: !0,
                                onClick: v,
                                "data-tracking-id": `install-github-app-v2`,
                              }
                            : void 0,
                      },
                      e.check,
                    ),
                  ),
                }),
              !c &&
                (0, $.jsx)(R, {
                  variant: `primary`,
                  size: `sm`,
                  onClick: r,
                  loading: o,
                  "data-testid": `create-${e.id}`,
                  "data-tracking-id": `create-github-app-integration`,
                  children: `Install app`,
                }),
              c &&
                (0, $.jsx)(de, {
                  state: u ? `checked` : `unchecked`,
                  onToggle: () => i(),
                  id: `toggle-org-${e.id}`,
                  disabled: s || o,
                }),
            ],
          }),
        }),
      ],
    });
  },
  Oe = (e, t) => (e ? `••••••••••••••••  (leave blank to keep current)` : t),
  ke = {
    setup: `Set up incident.io to send webhook events to IOI. Copy the webhook URL below into your incident.io webhook configuration, then paste the signing secret here.`,
    urlHint: `Copy this URL into incident.io -> Settings -> Webhooks -> Add endpoint.`,
    signingSecretError: `Enter the Svix signing secret from your incident.io webhook configuration.`,
    signingSecretHint: `The Svix signing secret from your incident.io webhook endpoint.`,
    signingSecretPlaceholder: `whsec_...`,
    savedDescription: `incident.io webhook settings have been saved.`,
  },
  Ae = {
    setup: `Set up PagerDuty to send webhook events to IOI. Copy the webhook URL below into your PagerDuty webhook subscription, then paste the signing secret here.`,
    urlHint: `Copy this URL into your PagerDuty webhook subscription.`,
    signingSecretError: `Enter the signing secret from your PagerDuty webhook subscription.`,
    signingSecretHint: `The signing secret from your PagerDuty webhook subscription.`,
    signingSecretPlaceholder: `secret`,
    savedDescription: `PagerDuty webhook settings have been saved.`,
  },
  je = ({ integration: e, isOpen: t, onClose: n }) => {
    let { toast: r } = ne(),
      i = a(),
      o = e.capabilities?.agentClient,
      [s, c] = (0, Z.useState)(``),
      [l, u] = (0, Z.useState)(),
      { providerSlug: d, copy: f } = (0, Z.useMemo)(() => {
        switch (e.host) {
          case me:
            return { providerSlug: `pagerduty`, copy: Ae };
          default:
            return { providerSlug: `incidentio`, copy: ke };
        }
      }, [e.host]),
      p = `${window.location.origin}/integrations/webhooks/${d}/${e.id}`,
      m = !!o,
      h = (0, Z.useCallback)(
        (e) => {
          (!e && i.isPending) || (e ? (c(``), u(void 0)) : n());
        },
        [n, i.isPending],
      ),
      g = (0, Z.useCallback)(async () => {
        if (!s && !m) {
          u(f.signingSecretError);
          return;
        }
        u(void 0);
        try {
          let t = x(L, {
              mcp: e.capabilities?.mcp,
              contextParsing: e.capabilities?.contextParsing,
              sourceCodeAccess: e.capabilities?.sourceCodeAccess,
              login: e.capabilities?.login,
              scmPrEvents: e.capabilities?.scmPrEvents,
              agentClient: x(j, {
                severityThreshold: o?.severityThreshold ?? ``,
                defaultProjectId: o?.defaultProjectId ?? ``,
              }),
            }),
            a = x(I, { proprietaryApp: x(P, { webhookSecret: s }) });
          (await i.mutateAsync(x(N, { id: e.id, capabilities: t, auth: a })),
            r({ title: `Webhook configured`, description: f.savedDescription }),
            n());
        } catch (e) {
          r({ title: `Failed to save webhook configuration`, description: k(e) });
        }
      }, [s, m, f, e, o, i, r, n]);
    return (0, $.jsx)(B, {
      open: t,
      onOpenChange: h,
      children: (0, $.jsxs)(B.Content, {
        "data-track-location": w.IntegrationConfigModal,
        className: `max-w-lg`,
        children: [
          (0, $.jsxs)(B.Header, {
            children: [
              (0, $.jsx)(B.Title, { children: `Configure Webhook` }),
              (0, $.jsx)(B.Description, { children: f.setup }),
            ],
          }),
          (0, $.jsx)(B.Body, {
            children: (0, $.jsxs)(`div`, {
              className: `flex flex-col gap-4`,
              children: [
                (0, $.jsx)(Y, {
                  label: `Webhook URL`,
                  id: `webhook-url`,
                  hint: f.urlHint,
                  children: (0, $.jsx)(H, {
                    id: `webhook-url`,
                    value: p,
                    readOnly: !0,
                    copyable: !0,
                    "data-testid": `webhook-url-input`,
                  }),
                }),
                (0, $.jsx)(Y, {
                  label: `Signing secret`,
                  id: `signing-secret`,
                  hint: f.signingSecretHint,
                  error: l,
                  children: (0, $.jsx)(H, {
                    id: `signing-secret`,
                    type: `password`,
                    value: s,
                    onChange: (e) => {
                      (c(e.target.value), l && u(void 0));
                    },
                    placeholder: Oe(m, f.signingSecretPlaceholder),
                    "data-testid": `signing-secret-input`,
                  }),
                }),
              ],
            }),
          }),
          (0, $.jsxs)(B.Footer, {
            children: [
              (0, $.jsx)(R, {
                variant: `outline`,
                onClick: n,
                disabled: i.isPending,
                "data-tracking-id": `configure-webhook-cancel`,
                children: `Cancel`,
              }),
              (0, $.jsx)(R, {
                onClick: () => void g(),
                loading: i.isPending,
                "data-tracking-id": `configure-webhook-save`,
                "data-testid": `configure-webhook-save`,
                children: m ? `Update` : `Save`,
              }),
            ],
          }),
        ],
      }),
    });
  },
  Me = ({ definition: e, integration: r, isAdmin: i, onToggleEnabled: a, onFixAction: o, isToggling: s }) => {
    let { toast: c } = ne(),
      u = f(),
      { value: d } = E(D.IncidentIOWebhookConfigEnabled, !1),
      { value: p } = E(D.PagerDutyWebhookConfigEnabled, !1),
      m = !e,
      h = !!r,
      g = h && r.enabled,
      [_, v] = (0, Z.useState)(!1),
      [y, b] = (0, Z.useState)(!1),
      [S, C] = (0, Z.useState)(!1),
      [w, T] = (0, Z.useState)(!1),
      O = r?.host || e?.host || ``,
      A = O === he,
      j = O === me,
      M = ((A && d) || (j && p)) && i && g,
      N = (A || j) && !!r?.capabilities?.agentClient,
      P = r?.name || e?.name || `Unnamed Integration`,
      F = r?.description || e?.description || ``,
      I = r?.iconUrl || e?.iconUrl,
      te = r?.id ?? e?.id ?? ``,
      L = Q(e?.categories ?? r?.categories ?? []).map((e) => ve[e].label),
      { data: z } = n(h && r.enabled ? r.id : void 0, { pendingReauth: _ }),
      re = z?.checks.filter((e) => e.message) ?? [];
    _ && z && re.length === 0 && v(!1);
    let B = async () => {
      if (r)
        try {
          (await u.mutateAsync(x(ee, { id: r.id })),
            c({ title: `Integration deleted`, description: `${P} has been deleted.` }),
            b(!1));
        } catch (e) {
          c({ title: `Failed to delete integration`, description: k(e) });
        }
    };
    return (0, $.jsxs)($.Fragment, {
      children: [
        (0, $.jsxs)(l.Item, {
          id: te,
          children: [
            (0, $.jsx)(l.ItemIcon, {
              size: 36,
              children: I
                ? (0, $.jsx)(`img`, { src: I, alt: `${P} icon`, className: `h-8 w-8` })
                : r?.capabilities?.mcp
                  ? (0, $.jsx)(t, { size: `lg` })
                  : null,
            }),
            (0, $.jsx)(l.ItemTitle, {
              children: (0, $.jsxs)(`span`, {
                className: `flex flex-wrap items-center gap-2`,
                children: [
                  (0, $.jsx)(`span`, { children: P }),
                  (0, $.jsxs)(`div`, {
                    className: `flex flex-wrap items-center gap-2`,
                    children: [
                      L.map((e) => (0, $.jsx)(U, { variant: `neutral`, size: `sm`, children: e }, e)),
                      M &&
                        (0, $.jsx)(U, {
                          variant: N ? `success` : `warning`,
                          size: `sm`,
                          "data-testid": `webhook-status-pill`,
                          children: N ? `Webhook configured` : `Webhook not configured`,
                        }),
                    ],
                  }),
                ],
              }),
            }),
            (0, $.jsx)(l.ItemDescription, { children: F }),
            (0, $.jsx)(l.ItemContent, {
              alignment: `right`,
              children: (0, $.jsxs)(`div`, {
                className: `flex items-center gap-3`,
                children: [
                  re.length > 0 &&
                    (0, $.jsx)(`div`, {
                      className: `flex flex-col gap-2`,
                      children: re.map((e) =>
                        (0, $.jsx)(
                          V,
                          {
                            variant: `warning`,
                            className: `text-sm`,
                            text: e.message,
                            link: e.documentationUrl
                              ? (0, $.jsx)(le, {
                                  href: e.documentationUrl,
                                  iconSize: `sm`,
                                  className: `text-content-warning hover:text-content-warning`,
                                  children: `Learn more`,
                                })
                              : void 0,
                            action: e.actionHint
                              ? {
                                  text: `Authorize app`,
                                  size: `sm`,
                                  responsive: !0,
                                  onClick: () => {
                                    (e.actionHint === `app_installation_oauth` && v(!0), o(e.actionHint));
                                  },
                                  "data-tracking-id": `fix-integration-check`,
                                }
                              : void 0,
                          },
                          e.check,
                        ),
                      ),
                    }),
                  i &&
                    r &&
                    (m || M) &&
                    (0, $.jsxs)(ce, {
                      triggerButton: (0, $.jsx)(R, {
                        variant: `ghost`,
                        size: `sm`,
                        LeadingIcon: se,
                        "aria-label": `More actions`,
                      }),
                      contentClassName: `w-48`,
                      children: [
                        M &&
                          (0, $.jsx)(G.Item, {
                            onClick: () => T(!0),
                            "data-testid": `configure-webhook-${r.id}`,
                            "data-tracking-id": `configure-webhook`,
                            children: `Configure webhook`,
                          }),
                        m &&
                          (0, $.jsxs)($.Fragment, {
                            children: [
                              (0, $.jsx)(G.Item, {
                                onClick: () => C(!0),
                                "data-testid": `edit-categories-${r.id}`,
                                "data-tracking-id": `edit-integration-categories`,
                                children: `Edit categories`,
                              }),
                              (0, $.jsx)(G.Item, {
                                onClick: () => b(!0),
                                "data-testid": `delete-custom-integration-${r.id}`,
                                "data-tracking-id": `delete-custom-integration`,
                                className: `text-content-destructive`,
                                children: `Delete`,
                              }),
                            ],
                          }),
                      ],
                    }),
                  i &&
                    (0, $.jsx)(de, {
                      state: g ? `checked` : `unchecked`,
                      onToggle: () => a(),
                      id: `toggle-org-${te}`,
                      disabled: s,
                    }),
                ],
              }),
            }),
          ],
        }),
        m &&
          r &&
          (0, $.jsxs)($.Fragment, {
            children: [
              (0, $.jsx)(Pe, {
                integration: r,
                isOpen: y,
                onClose: () => b(!1),
                onConfirm: () => void B(),
                isDeleting: u.isPending,
              }),
              (0, $.jsx)(Ne, { integration: r, isOpen: S, onClose: () => C(!1) }),
            ],
          }),
        M && r && (0, $.jsx)(je, { integration: r, isOpen: w, onClose: () => T(!1) }),
      ],
    });
  },
  Ne = ({ integration: e, isOpen: t, onClose: n }) => {
    let { toast: r } = ne(),
      i = a(),
      o = !!e.capabilities?.mcp,
      s = (e) => (o && !e.includes(`mcp`) ? [...e, `mcp`] : e),
      [c, l] = (0, Z.useState)(() => s(Q(e.categories))),
      u = (t) => {
        t ? l(s(Q(e.categories))) : n();
      },
      d = async () => {
        try {
          (await i.mutateAsync(x(N, { id: e.id, categories: xe(c) })),
            r({ title: `Categories updated`, description: `Categories for ${e.name} have been updated.` }),
            n());
        } catch (e) {
          r({ title: `Failed to update categories`, description: k(e) });
        }
      };
    return (0, $.jsx)(B, {
      open: t,
      onOpenChange: u,
      children: (0, $.jsxs)(B.Content, {
        "data-track-location": w.IntegrationConfigModal,
        children: [
          (0, $.jsxs)(B.Header, {
            children: [
              (0, $.jsx)(B.Title, { children: `Edit Categories` }),
              (0, $.jsxs)(B.Description, {
                children: [`Select categories for `, (0, $.jsx)(`strong`, { children: e.name }), `.`],
              }),
            ],
          }),
          (0, $.jsx)(B.Body, {
            children: (0, $.jsx)(Ce, { selected: c, onChange: l, lockedCategories: o ? [`mcp`] : [] }),
          }),
          (0, $.jsxs)(B.Footer, {
            children: [
              (0, $.jsx)(R, {
                variant: `outline`,
                onClick: n,
                disabled: i.isPending,
                "data-tracking-id": `edit-categories-cancel`,
                children: `Cancel`,
              }),
              (0, $.jsx)(R, {
                onClick: () => void d(),
                loading: i.isPending,
                disabled: c.length === 0,
                "data-tracking-id": `edit-categories-save`,
                children: `Save`,
              }),
            ],
          }),
        ],
      }),
    });
  },
  Pe = ({ integration: e, isOpen: t, onClose: n, onConfirm: r, isDeleting: i }) =>
    (0, $.jsx)(B, {
      open: t,
      onOpenChange: (e) => !e && n(),
      children: (0, $.jsxs)(B.Content, {
        "data-track-location": w.IntegrationConfigModal,
        children: [
          (0, $.jsxs)(B.Header, {
            children: [
              (0, $.jsx)(B.Title, { children: `Delete Integration` }),
              (0, $.jsxs)(B.Description, {
                children: [
                  `Are you sure you want to delete `,
                  (0, $.jsx)(`strong`, { children: e.name }),
                  `? This action cannot be undone.`,
                ],
              }),
            ],
          }),
          (0, $.jsxs)(B.Footer, {
            children: [
              (0, $.jsx)(R, {
                variant: `outline`,
                onClick: n,
                disabled: i,
                "data-tracking-id": `delete-custom-integration-cancel`,
                children: `Cancel`,
              }),
              (0, $.jsx)(R, {
                variant: `destructive`,
                onClick: r,
                loading: i,
                "data-tracking-id": `delete-custom-integration-confirm`,
                children: `Delete`,
              }),
            ],
          }),
        ],
      }),
    }),
  Fe = ({ isAdmin: e }) => {
    let { data: t } = O(),
      { toast: n } = ne(),
      { isDesktop: r } = re(),
      { data: i, isLoading: o, error: f } = c(),
      { data: m, isLoading: y, error: S } = p(t?.organizationId),
      w = C(),
      T = s(),
      E = a(),
      { value: D } = A(),
      [j, M] = (0, Z.useState)(null),
      [ee, P] = (0, Z.useState)(null),
      [F, I] = _(`q`, h.withDefault(``)),
      [L, R] = _(`category`, h.withDefault(`all`)),
      [B, ie] = (0, Z.useState)(F),
      V = g((e) => {
        I(e.trim() || null);
      }, 300),
      ae = (e) => {
        (ie(e), V(e));
      },
      H = () => {
        (V.cancel(), ie(``), I(null));
      },
      U = (0, Z.useRef)(F);
    (0, Z.useEffect)(() => {
      F !== U.current && ((U.current = F), V.cancel(), ie(F));
    }, [F, V]);
    let se = o || y,
      G = f || S,
      ce = (0, Z.useMemo)(() => {
        let e = new Map();
        return (
          m?.forEach((t) => {
            t.integrationDefinitionId && e.set(t.integrationDefinitionId, t);
          }),
          e
        );
      }, [m]),
      K = (0, Z.useMemo)(() => {
        let t = m?.filter((e) => !e.integrationDefinitionId).map((e) => ({ integration: e })) ?? [],
          n = i?.filter((e) => D || !pe(e)).map((e) => ({ definition: e, integration: ce.get(e.id) || null })) ?? [],
          r = [...t, ...n];
        return e ? r : r.filter((e) => e.integration?.enabled);
      }, [i, m, ce, e, D]),
      J = (0, Z.useMemo)(
        () =>
          F
            ? K.filter((e) => {
                if (e.definition) return Se(e.definition, F);
                let t = F.toLowerCase(),
                  n = e.integration;
                return n?.name.toLowerCase().includes(t) || n?.description.toLowerCase().includes(t);
              })
            : K,
        [K, F],
      ),
      Y = (0, Z.useMemo)(
        () =>
          L === `all` || !L
            ? J
            : J.filter((e) => Q(e.definition?.categories ?? e.integration?.categories ?? []).includes(L)),
        [J, L],
      ),
      de = (0, Z.useMemo)(() => {
        let e = new Map();
        for (let t of J) {
          let n = Q(t.definition?.categories ?? t.integration?.categories ?? []);
          if (n.length === 0) e.set(`mcp`, (e.get(`mcp`) ?? 0) + 1);
          else for (let t of n) e.set(t, (e.get(t) ?? 0) + 1);
        }
        return e;
      }, [J]),
      fe = (0, Z.useCallback)(
        (e, i) => {
          if (!t?.id) return;
          let a = i?.auth?.proprietaryApp !== void 0,
            o = i?.auth?.oauth !== void 0;
          if (!a || !o) return;
          let s = `/integrations/oauth/${e}/authorize?principal=${encodeURIComponent(`user/${t.id}`)}&app_installation=true`;
          (s.startsWith(`/`) && (s = `${window.location.origin}${s}`),
            r && z ? z.openExternal({ url: s }) : window.open(s, `_blank`, `noopener`),
            n({
              title: `OAuth window opened`,
              description: `Complete the authorization in the popup window. Your connection status will update automatically.`,
            }));
        },
        [r, n, t?.id],
      ),
      X = (0, Z.useCallback)(
        (e) => {
          if (!t?.id) return;
          let i = `/integrations/app/github/${e}/install?principal=${encodeURIComponent(`user/${t.id}`)}`;
          (i.startsWith(`/`) && (i = `${window.location.origin}${i}`),
            r && z ? z.openExternal({ url: i }) : window.open(i, `_blank`, `noopener`),
            n({
              title: `Install window opened`,
              description: `Complete the GitHub App installation in the popup window. Your connection status will update automatically.`,
            }));
        },
        [r, n, t?.id],
      ),
      me = (0, Z.useCallback)(
        async (e) => {
          if (t?.organizationId)
            try {
              let t = await T.mutateAsync(
                x(te, { integrationDefinitionId: e.id, enabled: !0, runnerId: ``, host: `` }),
              );
              (n({
                title: `Integration enabled`,
                description: `${e.name} has been enabled. Individual members will need to connect their personal accounts in User Settings > Integrations.`,
              }),
                e.auth?.proprietaryApp && t?.id && X(t.id));
            } catch (e) {
              n({ title: `Failed to enable integration`, description: k(e) });
            }
        },
        [T, X, n, t?.organizationId],
      ),
      he = b(),
      ge = (0, Z.useCallback)(
        async (e, t) => {
          M(t.id);
          try {
            if (!e) {
              await me(t);
              return;
            }
            let r = !e.enabled;
            if (
              (await E.mutateAsync(x(N, { id: e.id, enabled: r })),
              n({
                title: r ? `Integration enabled` : `Integration disabled`,
                description: r
                  ? `Individual members will need to connect their personal accounts in User Settings > Integrations.`
                  : `Integration has been disabled.`,
              }),
              r)
            )
              try {
                let n = await he.fetchQuery({
                    queryKey: u.validation(e.id),
                    queryFn: () => w.integrationService.validateIntegration({ integrationId: e.id }),
                    staleTime: 0,
                  }),
                  r = n.checks.some((e) => e.actionHint === `app_installation_oauth`),
                  i = n.checks.some((e) => e.actionHint === `github_app_install`);
                r ? fe(e.id, t) : i && X(e.id);
              } catch {}
          } catch (e) {
            n({ title: `Failed to update integration`, description: k(e) });
          } finally {
            M(null);
          }
        },
        [me, E, n, fe, X, he, w],
      ),
      ye = (0, Z.useCallback)(
        async (e) => {
          P(e.id);
          try {
            let t = !e.enabled;
            (await E.mutateAsync(x(N, { id: e.id, enabled: t })),
              n({
                title: t ? `Integration enabled` : `Integration disabled`,
                description: t
                  ? `Individual members will need to connect their personal accounts in User Settings > Integrations.`
                  : `Integration has been disabled.`,
              }));
          } catch (e) {
            n({ title: `Failed to update integration`, description: k(e) });
          } finally {
            P(null);
          }
        },
        [E, n],
      ),
      be = _e.filter((e) => (de.get(e) ?? 0) > 0),
      xe = (0, Z.useMemo)(
        () => [{ id: `all`, label: `All` }, ...be.map((e) => ({ id: e, label: ve[e].label }))],
        [be.join(`,`)],
      ),
      Ce = (0, Z.useMemo)(() => (L === `all` || !L ? `All` : (ve[L]?.label ?? `All`)), [L]);
    return (0, $.jsx)(`div`, {
      className: `flex flex-col gap-4`,
      children: (0, $.jsxs)(oe, {
        ready: !se,
        className: `min-h-[200px]`,
        children: [
          G &&
            (0, $.jsxs)(`div`, {
              className: `flex flex-col gap-2`,
              children: [
                (0, $.jsx)(W, {
                  className: `text-lg font-bold text-content-negative`,
                  children: `Failed to load integrations`,
                }),
                (0, $.jsx)(ue, { error: G }),
              ],
            }),
          !G &&
            (0, $.jsxs)(`div`, {
              className: `flex flex-col gap-6`,
              children: [
                (0, $.jsxs)(`div`, {
                  className: `flex flex-col`,
                  children: [
                    (0, $.jsxs)(W, {
                      className: `text-base text-content-secondary`,
                      children: [
                        `Manage integrations available to your organization members.`,
                        ` `,
                        (0, $.jsx)(le, {
                          href: `https://ioi.com/docs/ioi/agents/integrations`,
                          iconSize: `sm`,
                          children: `Learn more.`,
                        }),
                      ],
                    }),
                    (0, $.jsxs)(W, {
                      className: `text-base text-content-secondary`,
                      children: [
                        `To use the enabled integrations individual members will need to connect their personal accounts to the integrations in`,
                        ` `,
                        (0, $.jsx)(v, {
                          to: `?user-settings=integrations`,
                          className: `text-content-link`,
                          children: `User Settings > Integrations`,
                        }),
                        `.`,
                        ` `,
                      ],
                    }),
                  ],
                }),
                (0, $.jsxs)(`div`, {
                  className: `flex flex-col gap-3 sm:flex-row sm:items-center`,
                  children: [
                    (0, $.jsx)(d, {
                      placeholder: `Search integrations...`,
                      wrapperClassName: `flex-1`,
                      className: `max-w-none`,
                      value: B,
                      onChange: (e) => ae(e.target.value),
                      onClear: H,
                      "data-testid": `integration-search-input`,
                    }),
                    (0, $.jsxs)(q, {
                      value: L || `all`,
                      onValueChange: (e) => void R(e === `all` ? null : e),
                      "aria-label": `Filter by category`,
                      className: `w-48`,
                      children: [
                        (0, $.jsx)(q.Value, { children: (0, $.jsx)(q.ValueLabel, { children: Ce }) }),
                        (0, $.jsx)(q.List, {
                          items: xe,
                          searchKeys: [`label`],
                          noMatchesComponent: (0, $.jsx)(q.Empty, { children: `No categories found` }),
                          children: (e) => (0, $.jsx)(q.ListItem, { value: e.id, title: e.label }, e.id),
                        }),
                      ],
                    }),
                  ],
                }),
                Y.length > 0
                  ? (0, $.jsx)(l, {
                      "aria-label": `Integrations`,
                      alwaysShowIcon: !0,
                      children: Y.map((t) => {
                        let { definition: n, integration: r } = t,
                          i = !n,
                          a = r?.id ?? n?.id ?? ``;
                        return n && pe(n)
                          ? (0, $.jsx)(
                              De,
                              {
                                definition: n,
                                integration: r,
                                onCreateAndInstall: () => void ge(r, n),
                                onToggleEnabled: () => void ge(r, n),
                                onInstall: () => r && X(r.id),
                                isCreating: j === n.id,
                                isUpdating: j === n.id,
                              },
                              n.id,
                            )
                          : (0, $.jsx)(
                              Me,
                              {
                                definition: n,
                                integration: r,
                                isAdmin: e,
                                onToggleEnabled: () => (i && r ? void ye(r) : n && void ge(r, n)),
                                onFixAction: (e) => {
                                  e === `app_installation_oauth` && r && n && fe(r.id, n);
                                },
                                isToggling: i ? ee === r?.id : j === n?.id,
                              },
                              a,
                            );
                      }),
                    })
                  : F
                    ? (0, $.jsx)(Ie, { query: F, onClear: H })
                    : (0, $.jsxs)(`div`, {
                        className: `flex flex-col items-center gap-4 py-8`,
                        children: [
                          (0, $.jsx)(W, {
                            className: `text-lg font-bold text-content-secondary`,
                            children: `No integrations available`,
                          }),
                          (0, $.jsx)(W, {
                            className: `text-base text-content-secondary`,
                            children: `Integration definitions will appear here when available.`,
                          }),
                        ],
                      }),
              ],
            }),
        ],
      }),
    });
  },
  Ie = ({ query: e, onClear: t }) =>
    (0, $.jsxs)(`div`, {
      className: `flex flex-col items-center gap-4 py-8`,
      children: [
        (0, $.jsxs)(W, {
          className: `text-lg font-bold text-content-secondary`,
          children: [`No integrations matching “`, e, `”`],
        }),
        (0, $.jsx)(R, {
          variant: `secondary`,
          onClick: t,
          "data-tracking-id": `clear-integration-search`,
          children: `Clear search`,
        }),
      ],
    }),
  Le = () => {
    i(`Integrations`);
    let { membership: e, isPending: t } = ie(),
      { setBreadCrumbRowAction: n } = (0, Z.useContext)(o),
      [r, a] = (0, Z.useState)(!1),
      s = e?.userRole === T.ADMIN,
      c = (0, Z.useCallback)(() => {
        a(!0);
      }, []);
    return (
      (0, Z.useEffect)(() => {
        if (s)
          return (
            n(
              (0, $.jsx)(R, {
                size: `sm`,
                LeadingIcon: ae(y),
                onClick: c,
                "data-testid": `create-custom-integration-button`,
                "data-tracking-id": `create-custom-integration`,
                children: `Add MCP integration`,
              }),
            ),
            () => {
              n(null);
            }
          );
      }, [s, c, n]),
      !e && t
        ? null
        : (0, $.jsxs)(`div`, {
            "data-testid": `org-integrations-page`,
            children: [(0, $.jsx)(Fe, { isAdmin: s }), (0, $.jsx)(Ee, { isOpen: r, onClose: () => a(!1) })],
          })
    );
  };
export { Le as OrgIntegrationsPage };

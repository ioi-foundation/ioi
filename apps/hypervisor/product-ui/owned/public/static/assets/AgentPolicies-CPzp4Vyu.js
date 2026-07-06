import { a as e } from "./rolldown-runtime-CGYlQKCx.js";
import { It as t, Lt as n, dt as r } from "./SegmentProvider-CXCNBY9U.js";
import { n as i } from "./@mux-DLaEVubF.js";
import { Bl as a, g_ as o, v_ as s } from "./vendor-DAwbZtf0.js";
import {
  Ci as c,
  Dt as l,
  Fi as u,
  Pn as ee,
  l as te,
  tn as ne,
  tr as d,
  w as f,
  wi as p,
  za as re,
} from "./use-boot-in-app-chat-t-J_VjKS.js";
import { n as ie } from "./toast-axaLeIzZ.js";
import { t as m } from "./button-6YP03Qf2.js";
import { t as h } from "./cn-DppMFCU8.js";
import { _ as ae, f as oe } from "./group-queries-DjQDBYRu.js";
import { t as g } from "./dialog-BtjFqa-w.js";
import { t as se } from "./use-membership-CcV5kGny.js";
import { r as ce } from "./headings-CM9JBOhQ.js";
import { t as _ } from "./tooltip-6hqVQbwq.js";
import { t as v } from "./text-fFCFeCas.js";
import { t as y } from "./select-Ceshp72e.js";
import { t as le } from "./skeleton-Cm867Q_k.js";
import { R as ue } from "./agent-queries-CGWy3JAw.js";
import { t as b } from "./avatar-CjN22mGB.js";
import { r as x } from "./agent-mode-visuals-DTOFpRnw.js";
import { t as S } from "./IconInfo-Cl6kMnoJ.js";
import { n as C, t as w } from "./codex-settings-BPKiMIhT.js";
import { t as T } from "./combobox-BkGa_nRF.js";
import { t as E } from "./label-5ATlPnPj.js";
import { t as D } from "./switch-CiuLW56f.js";
import { t as de } from "./textarea-65aCrC5K.js";
import { c as O, o as fe, s as pe } from "./agent-policy-B3gLeo-x.js";
var k = e(i(), 1),
  A = s(),
  j = `__all__`,
  me = { id: j, name: `All` },
  M = w.map((e) => e.value),
  N = C.map((e) => e.value),
  he = [
    { key: `ioi`, name: `IOI` },
    { key: `codex`, name: `Codex` },
  ];
function ge(e) {
  for (let t = C.length - 1; t >= 0; t--) if (e.includes(C[t].value)) return C[t].value;
  return C[C.length - 1].value;
}
function _e(e) {
  let t = C.findIndex((t) => t.value === e),
    n = t === -1 ? C.length - 1 : t;
  return C.slice(0, n + 1).map((e) => e.value);
}
var ve = [
  { value: `standard`, label: `Standard` },
  { value: `fast`, label: `Fast` },
];
function ye(e) {
  return o(c, {
    mcpDisabled: !e.mcpEnabled,
    scmToolsDisabled: !e.scmToolsEnabled,
    scmToolsAllowedGroupId: e.scmToolsAllowedGroupId,
    commandDenyList: e.denyList
      .split(
        `
`,
      )
      .filter((e) => e.trim()),
    conversationSharingPolicy: e.conversationSharingEnabled ? p.ORGANIZATION : p.DISABLED,
    allowedAgentIds: fe(e.onaAgentAllowed, e.codexAgentAllowed),
    allowedCodexModels: O(e.allowedCodexModels, M),
    allowedCodexReasoningEfforts: O(e.allowedCodexReasoningEfforts, N),
    allowedCodexServiceTiers: pe(e.codexFastModeEnabled),
  });
}
function be(e, t) {
  return o(c, {
    mcpDisabled: t.mcpEnabled === void 0 ? (e?.mcpDisabled ?? !1) : !t.mcpEnabled,
    scmToolsDisabled: t.scmToolsEnabled === void 0 ? (e?.scmToolsDisabled ?? !1) : !t.scmToolsEnabled,
    scmToolsAllowedGroupId: t.scmToolsAllowedGroupId ?? e?.scmToolsAllowedGroupId ?? ``,
    commandDenyList: e?.commandDenyList ?? [],
    conversationSharingPolicy:
      t.conversationSharingEnabled === void 0
        ? (e?.conversationSharingPolicy ?? p.ORGANIZATION)
        : t.conversationSharingEnabled
          ? p.ORGANIZATION
          : p.DISABLED,
    allowedAgentIds: t.allowedAgentIds ?? e?.allowedAgentIds ?? [],
    allowedCodexModels: t.allowedCodexModels ?? e?.allowedCodexModels ?? [],
    allowedCodexReasoningEfforts: t.allowedCodexReasoningEfforts ?? e?.allowedCodexReasoningEfforts ?? [],
    allowedCodexServiceTiers: t.allowedCodexServiceTiers ?? e?.allowedCodexServiceTiers ?? [],
  });
}
var P = `inline-flex h-9 select-none items-center gap-2 whitespace-nowrap rounded-xl border-0.5 border-border-base bg-surface-primary p-2 px-4 pb-[6.5px] pt-[5.5px] text-base font-medium`,
  xe = ({ agentKey: e, name: t }) =>
    (0, A.jsxs)(`div`, {
      className: P,
      children: [
        (0, A.jsx)(`span`, { className: `flex size-[20px] items-center justify-center`, children: x(e, 20) }),
        (0, A.jsx)(`span`, { children: t }),
      ],
    }),
  F = ({ label: e, content: t }) =>
    (0, A.jsx)(_, {
      content: t,
      className: `max-w-xs`,
      usePortal: !0,
      children: (0, A.jsx)(m, {
        type: `button`,
        variant: `ghost`,
        size: `xs`,
        "aria-label": e,
        LeadingIcon: S,
        className: `size-5 shrink-0 text-content-tertiary hover:text-content-secondary`,
        disableTracking: !0,
      }),
    }),
  Se = ({ onaAgentAllowed: e, codexAgentAllowed: t, codexEnabled: n, isSaving: r, onClose: i, onSave: a }) => {
    let [o, s] = (0, k.useState)({ ioi: e, codex: t }),
      c = he.filter((e) => e.key !== `codex` || n),
      u = o.ioi !== e || o.codex !== t,
      ee = !c.some((e) => o[e.key]);
    return (0, A.jsx)(g, {
      open: !0,
      onOpenChange: (0, k.useCallback)(
        (e) => {
          e || i();
        },
        [i],
      ),
      children: (0, A.jsxs)(g.Content, {
        className: `max-w-[600px]`,
        "data-testid": `manage-agents-modal-content`,
        "data-track-location": l.ManageAgentsModal,
        children: [
          (0, A.jsxs)(g.Header, {
            children: [
              (0, A.jsx)(g.Title, { children: `Available agents` }),
              (0, A.jsx)(g.Description, { children: `Manage the agents available to your members` }),
            ],
          }),
          (0, A.jsx)(g.Body, {
            className: `overflow-x max-w-full space-y-1`,
            children: c.map((e, t) =>
              (0, A.jsxs)(
                `div`,
                {
                  className: `flex min-h-[36px] flex-row items-center gap-3`,
                  children: [
                    (0, A.jsx)(D, {
                      state: o[e.key] ? `checked` : `unchecked`,
                      onToggle: (t) => s((n) => ({ ...n, [e.key]: t })),
                      id: `agent-toggle-${t}`,
                      "data-testid": `agent-toggle-${e.key}`,
                    }),
                    (0, A.jsxs)(`div`, {
                      className: `flex flex-row items-center gap-2`,
                      children: [x(e.key), (0, A.jsx)(`span`, { children: e.name })],
                    }),
                  ],
                },
                e.key,
              ),
            ),
          }),
          (0, A.jsxs)(g.Footer, {
            className: `items-center`,
            children: [
              ee &&
                (0, A.jsx)(`div`, {
                  className: `grow`,
                  children: (0, A.jsx)(v, {
                    className: `text-base text-content-red`,
                    children: `You must have 1 available agent`,
                  }),
                }),
              (0, A.jsx)(g.Close, {
                asChild: !0,
                children: (0, A.jsx)(m, { type: `button`, variant: `outline`, children: `Close` }),
              }),
              (0, A.jsx)(m, {
                onClick: () => a(o.ioi, o.codex),
                loading: r,
                disabled: !u || ee,
                "data-testid": `save-agents-button`,
                type: `button`,
                variant: `primary`,
                "data-tracking-id": `save-agents-manage-agents-modal`,
                children: `Save`,
              }),
            ],
          }),
        ],
      }),
    });
  },
  Ce = ({ name: e, disabled: t }) =>
    (0, A.jsx)(`div`, {
      className: h(P, t && `border-border-subtle bg-surface-secondary text-content-tertiary opacity-60`),
      "data-disabled": t || void 0,
      children: e,
    }),
  we = ({ allowedCodexModels: e, isSaving: t, onClose: n, onSave: r }) => {
    let [i, a] = (0, k.useState)(e),
      o = i.length !== e.length || i.some((t) => !e.includes(t)),
      s = i.length === 0;
    return (0, A.jsx)(g, {
      open: !0,
      onOpenChange: (0, k.useCallback)(
        (e) => {
          e || n();
        },
        [n],
      ),
      children: (0, A.jsxs)(g.Content, {
        className: `max-w-[600px]`,
        "data-testid": `manage-models-modal-content`,
        "data-track-location": l.ManageModelsModal,
        children: [
          (0, A.jsxs)(g.Header, {
            children: [
              (0, A.jsx)(g.Title, { children: `Available models` }),
              (0, A.jsx)(g.Description, { children: `Manage the Codex models available to your members` }),
            ],
          }),
          (0, A.jsx)(g.Body, {
            className: `overflow-x max-w-full space-y-1`,
            children: w.map((e, t) =>
              (0, A.jsxs)(
                `div`,
                {
                  className: `flex min-h-[36px] flex-row items-center gap-3`,
                  children: [
                    (0, A.jsx)(D, {
                      state: i.includes(e.value) ? `checked` : `unchecked`,
                      onToggle: (t) => a((n) => (t ? [...n, e.value] : n.filter((t) => t !== e.value))),
                      id: `model-toggle-${t}`,
                      "data-testid": `model-toggle-${e.value}`,
                    }),
                    (0, A.jsx)(`span`, { children: e.label }),
                  ],
                },
                e.value,
              ),
            ),
          }),
          (0, A.jsxs)(g.Footer, {
            className: `items-center`,
            children: [
              s &&
                (0, A.jsx)(`div`, {
                  className: `grow`,
                  children: (0, A.jsx)(v, {
                    className: `text-base text-content-red`,
                    children: `You must have 1 available model`,
                  }),
                }),
              (0, A.jsx)(g.Close, {
                asChild: !0,
                children: (0, A.jsx)(m, { type: `button`, variant: `outline`, children: `Close` }),
              }),
              (0, A.jsx)(m, {
                onClick: () => r(i),
                loading: t,
                disabled: !o || s,
                "data-testid": `save-models-button`,
                type: `button`,
                variant: `primary`,
                "data-tracking-id": `save-models-manage-models-modal`,
                children: `Save`,
              }),
            ],
          }),
        ],
      }),
    });
  },
  I = () => {
    let [e, t] = (0, k.useState)(!0),
      [n, i] = (0, k.useState)(!0),
      [o, s] = (0, k.useState)(``),
      [c, l] = (0, k.useState)(!0),
      [u, f] = (0, k.useState)(!0),
      [h, g] = (0, k.useState)(!0),
      [se, _] = (0, k.useState)(!1),
      [x, S] = (0, k.useState)(!1),
      [D, P] = (0, k.useState)([...M]),
      [I, L] = (0, k.useState)([...N]),
      [R, z] = (0, k.useState)(!0),
      [B, Te] = (0, k.useState)(``),
      [V, Ee] = (0, k.useState)(!1),
      [De, Oe] = (0, k.useState)(``),
      [H] = a(De, 250, { trailing: !0 }),
      { value: U } = te(),
      { data: W, isLoading: ke } = ne(),
      { data: G, isLoading: Ae } = oe({ name: `org-admins` }),
      {
        data: je,
        isLoading: Me,
        isFetching: Ne,
        isFetchingNextPage: K,
        hasNextPage: Pe,
        fetchNextPage: Fe,
      } = ae({ search: H, filters: { systemManaged: !1, directShare: !1 } }),
      q = (0, k.useMemo)(() => je?.pages.flatMap((e) => e.groups) ?? [], [je]),
      { data: J, isLoading: Ie } = oe({ id: o }),
      Le = Ae || Me || (!!o && Ie),
      Re = (0, k.useCallback)(() => {
        Pe && !K && Fe();
      }, [Pe, K, Fe]),
      ze = (0, k.useMemo)(() => {
        let e = [];
        H || (e.push(me), G && e.push({ id: G.id, name: G.name }));
        for (let t of q) e.push({ id: t.id, name: t.name });
        return e;
      }, [H, G, q]),
      Be = (0, k.useMemo)(
        () => (o ? (J ? J.name : G?.id === o ? G.name : (q.find((e) => e.id === o)?.name ?? `Loading…`)) : `All`),
        [o, J, G, q],
      ),
      Y = ee(),
      { toast: X } = ie(),
      Ve = (0, k.useCallback)(
        (t = {}) =>
          ye({
            mcpEnabled: t.mcpEnabled ?? e,
            scmToolsEnabled: t.scmToolsEnabled ?? n,
            scmToolsAllowedGroupId: t.scmToolsAllowedGroupId ?? o,
            conversationSharingEnabled: t.conversationSharingEnabled ?? c,
            denyList: t.denyList ?? B,
            onaAgentAllowed: t.onaAgentAllowed ?? u,
            codexAgentAllowed: t.codexAgentAllowed ?? h,
            allowedCodexModels: t.allowedCodexModels ?? D,
            allowedCodexReasoningEfforts: t.allowedCodexReasoningEfforts ?? I,
            codexFastModeEnabled: t.codexFastModeEnabled ?? R,
          }),
        [e, n, o, c, B, u, h, D, I, R],
      ),
      Z = (0, k.useCallback)((e) => be(W?.agentPolicy, e), [W?.agentPolicy]);
    (0, k.useEffect)(() => {
      if (W?.agentPolicy) {
        (t(!W.agentPolicy.mcpDisabled),
          i(!W.agentPolicy.scmToolsDisabled),
          s(W.agentPolicy.scmToolsAllowedGroupId || ``),
          V ||
            Te(
              W.agentPolicy.commandDenyList.join(`
`),
            ),
          l(W.agentPolicy.conversationSharingPolicy !== p.DISABLED));
        let e = W.agentPolicy.allowedAgentIds;
        (f(e.length === 0 || e.includes(ue.IOI.id) || e.includes(ue.InEnvironmentIOI.id)),
          g(e.length === 0 || e.includes(ue.InEnvironmentCodexAppAgent.id)),
          P(
            W.agentPolicy.allowedCodexModels.length === 0
              ? [...M]
              : M.filter((e) => W.agentPolicy?.allowedCodexModels.includes(e)),
          ),
          L(
            W.agentPolicy.allowedCodexReasoningEfforts.length === 0
              ? [...N]
              : N.filter((e) => W.agentPolicy?.allowedCodexReasoningEfforts.includes(e)),
          ),
          z(
            W.agentPolicy.allowedCodexServiceTiers.length === 0 ||
              W.agentPolicy.allowedCodexServiceTiers.includes(re.FAST),
          ));
      }
    }, [V, W]);
    let He = (0, k.useCallback)(
        async (n) => {
          let r = e;
          t(n);
          let i = Z({ mcpEnabled: n });
          try {
            (await Y.mutateAsync({ agentPolicy: i }), X({ title: n ? `MCP enabled` : `MCP disabled` }));
          } catch (e) {
            (console.error(e),
              t(r),
              X({ title: `We couldn't save your changes. Sorry about that! Please retry.`, description: d(e) }));
          }
        },
        [e, Z, Y, X],
      ),
      Ue = (0, k.useCallback)(
        async (e) => {
          let t = n;
          i(e);
          let r = Z({ scmToolsEnabled: e });
          try {
            (await Y.mutateAsync({ agentPolicy: r }), X({ title: e ? `SCM tools enabled` : `SCM tools disabled` }));
          } catch (e) {
            (console.error(e),
              i(t),
              X({ title: `We couldn't save your changes. Sorry about that! Please retry.`, description: d(e) }));
          }
        },
        [n, Z, Y, X],
      ),
      We = (0, k.useCallback)(
        async (e) => {
          let t = e === j ? `` : e,
            n = o;
          s(t);
          let r = Z({ scmToolsAllowedGroupId: t });
          try {
            (await Y.mutateAsync({ agentPolicy: r }), X({ title: `SCM tools access updated` }));
          } catch (e) {
            (console.error(e),
              s(n),
              X({ title: `We couldn't save your changes. Sorry about that! Please retry.`, description: d(e) }));
          }
        },
        [o, Z, Y, X],
      ),
      Ge = (0, k.useCallback)(
        async (e) => {
          let t = c;
          l(e);
          let n = Z({ conversationSharingEnabled: e });
          try {
            (await Y.mutateAsync({ agentPolicy: n }),
              X({ title: `Conversation sharing ${e ? `enabled` : `disabled`}` }));
          } catch (e) {
            (console.error(e), l(t), X({ title: `Failed to update conversation sharing policy`, description: d(e) }));
          }
        },
        [c, Z, Y, X],
      ),
      Ke = (0, k.useCallback)((e) => {
        (Te(e), Ee(!0));
      }, []),
      qe = (0, k.useCallback)(
        async (e) => {
          let t = _e(Number(e)),
            n = I;
          L(t);
          try {
            (await Y.mutateAsync({ agentPolicy: Z({ allowedCodexReasoningEfforts: t }) }),
              X({ title: `Highest reasoning effort updated` }));
          } catch (e) {
            (console.error(e),
              L(n),
              X({ title: `We couldn't save your changes. Sorry about that! Please retry.`, description: d(e) }));
          }
        },
        [I, Z, Y, X],
      ),
      Je = (0, k.useCallback)(
        async (e) => {
          let t = e === `fast`,
            n = R;
          z(t);
          try {
            (await Y.mutateAsync({ agentPolicy: Z({ allowedCodexServiceTiers: pe(t) }) }),
              X({ title: `Highest service tier updated` }));
          } catch (e) {
            (console.error(e),
              z(n),
              X({ title: `We couldn't save your changes. Sorry about that! Please retry.`, description: d(e) }));
          }
        },
        [R, Z, Y, X],
      ),
      Ye = (0, k.useMemo)(() => ge(I), [I]),
      Xe = U,
      Q = !h,
      $ = (u || h) && (!(U && h) || (D.length > 0 && I.length > 0)),
      Ze = (0, k.useCallback)(
        async (e, t) => {
          let n = Z({ allowedAgentIds: fe(e, t) });
          try {
            (await Y.mutateAsync({ agentPolicy: n }), f(e), g(t), _(!1), X({ title: `Available agents updated` }));
          } catch (e) {
            (console.error(e),
              X({ title: `We couldn't save your changes. Sorry about that! Please retry.`, description: d(e) }));
          }
        },
        [Z, Y, X],
      ),
      Qe = (0, k.useCallback)(
        async (e) => {
          let t = Z({ allowedCodexModels: O(e, M) });
          try {
            (await Y.mutateAsync({ agentPolicy: t }), P(e), S(!1), X({ title: `Available models updated` }));
          } catch (e) {
            (console.error(e),
              X({ title: `We couldn't save your changes. Sorry about that! Please retry.`, description: d(e) }));
          }
        },
        [Z, Y, X],
      ),
      $e = (0, k.useCallback)(async () => {
        if (!$) {
          X({ title: `Select at least one agent, Codex model, and reasoning effort.` });
          return;
        }
        let e = { agentPolicy: Ve() };
        try {
          (await Y.mutateAsync(e), Ee(!1), X({ title: `Agent policies updated` }));
        } catch (e) {
          (console.error(e),
            X({ title: `We couldn't save your changes. Sorry about that! Please retry.`, description: d(e) }));
        }
      }, [$, Ve, Y, X]);
    return (0, A.jsxs)(`div`, {
      className: `flex max-w-[46rem] flex-col gap-4`,
      children: [
        (0, A.jsx)(le, {
          ready: !ke,
          children: (0, A.jsxs)(`div`, {
            className: `flex flex-col gap-4`,
            "data-testid": `agent-policies-section`,
            children: [
              (0, A.jsx)(v, {
                className: `text-base text-content-secondary`,
                children: `Configure security policies and restrictions for AI agents in your organization.`,
              }),
              (0, A.jsxs)(`div`, {
                className: `flex flex-col gap-4`,
                children: [
                  (0, A.jsx)(`h2`, { className: `text-xl font-semibold`, children: `Agents` }),
                  (0, A.jsxs)(`div`, {
                    className: `flex flex-col gap-4 rounded-lg border border-border-subtle px-5 py-4`,
                    children: [
                      (0, A.jsxs)(`div`, {
                        className: `flex items-center justify-between gap-4`,
                        children: [
                          (0, A.jsxs)(`div`, {
                            className: `flex items-center gap-1.5`,
                            children: [
                              (0, A.jsx)(ce, { children: `Available agents` }),
                              (0, A.jsx)(F, {
                                label: `About available agents`,
                                content: `Choose which agent families members can start. Disabling Codex hides Codex from conversation controls and disables Codex model, reasoning, and service-tier settings.`,
                              }),
                            ],
                          }),
                          (0, A.jsx)(m, {
                            "data-testid": `manage-agents-button`,
                            onClick: () => _(!0),
                            variant: `secondary`,
                            size: `sm`,
                            "data-tracking-id": `manage-agents-available-agents-element`,
                            children: `Manage`,
                          }),
                        ],
                      }),
                      (0, A.jsx)(`div`, {
                        className: `flex flex-wrap gap-2`,
                        children: he
                          .filter((e) => (e.key === `ioi` ? u : U && h))
                          .map((e) => (0, A.jsx)(xe, { agentKey: e.key, name: e.name }, e.key)),
                      }),
                    ],
                  }),
                  Xe &&
                    (0, A.jsxs)(`div`, {
                      className: `flex flex-col gap-5 rounded-lg border border-border-subtle px-5 py-4`,
                      children: [
                        (0, A.jsx)(`div`, {
                          className: `flex items-center justify-between gap-4`,
                          children: (0, A.jsxs)(`div`, {
                            className: `flex flex-col gap-1`,
                            children: [
                              (0, A.jsx)(ce, { children: `Codex settings` }),
                              (0, A.jsx)(v, {
                                className: `text-sm text-content-secondary`,
                                children: `Manage the Codex models, reasoning effort, and service tier available to members.`,
                              }),
                            ],
                          }),
                        }),
                        Q &&
                          (0, A.jsx)(v, {
                            className: `text-sm text-content-secondary`,
                            children: `Enable Codex in available agents to change these settings.`,
                          }),
                        (0, A.jsxs)(`div`, {
                          className: `flex flex-col gap-4`,
                          children: [
                            (0, A.jsxs)(`div`, {
                              className: `flex items-center justify-between`,
                              children: [
                                (0, A.jsx)(E, { className: `text-sm`, children: `Available models` }),
                                (0, A.jsx)(m, {
                                  "data-testid": `manage-models-button`,
                                  onClick: () => S(!0),
                                  variant: `secondary`,
                                  size: `sm`,
                                  disabled: Q,
                                  "data-tracking-id": `manage-models-available-models-element`,
                                  children: `Manage`,
                                }),
                              ],
                            }),
                            (0, A.jsx)(`div`, {
                              className: `flex flex-wrap gap-2`,
                              children: w
                                .filter((e) => D.includes(e.value))
                                .map((e) => (0, A.jsx)(Ce, { name: e.label, disabled: Q }, e.value)),
                            }),
                          ],
                        }),
                        (0, A.jsxs)(`div`, {
                          className: `grid gap-x-8 gap-y-5 md:grid-cols-2`,
                          children: [
                            (0, A.jsxs)(`div`, {
                              className: `flex flex-col gap-2`,
                              children: [
                                (0, A.jsxs)(`div`, {
                                  className: `flex items-center gap-1.5`,
                                  children: [
                                    (0, A.jsx)(E, {
                                      htmlFor: `codex-reasoning-ceiling`,
                                      className: `text-sm`,
                                      children: `Highest reasoning effort`,
                                    }),
                                    (0, A.jsx)(F, {
                                      label: `About highest reasoning effort`,
                                      content: `Members can select this reasoning effort or any lower effort. Lower ceilings can reduce latency and usage, but may make complex tasks less capable.`,
                                    }),
                                  ],
                                }),
                                (0, A.jsxs)(y, {
                                  id: `codex-reasoning-ceiling`,
                                  className: `w-full max-w-64`,
                                  value: String(Ye),
                                  onValueChange: qe,
                                  disabled: Q,
                                  "data-testid": `codex-reasoning-ceiling`,
                                  children: [
                                    (0, A.jsx)(y.Value, {}),
                                    C.map((e) =>
                                      (0, A.jsx)(y.Item, { value: String(e.value), children: e.label }, e.value),
                                    ),
                                  ],
                                }),
                              ],
                            }),
                            (0, A.jsxs)(`div`, {
                              className: `flex flex-col gap-2`,
                              children: [
                                (0, A.jsxs)(`div`, {
                                  className: `flex items-center gap-1.5`,
                                  children: [
                                    (0, A.jsx)(E, {
                                      htmlFor: `codex-service-tier`,
                                      className: `text-sm`,
                                      children: `Highest service tier`,
                                    }),
                                    (0, A.jsx)(F, {
                                      label: `About highest service tier`,
                                      content: `Members can select this service tier or any lower tier. Choosing Standard disables Fast mode, which may reduce fast-tier usage but can make Codex responses slower.`,
                                    }),
                                  ],
                                }),
                                (0, A.jsxs)(y, {
                                  id: `codex-service-tier`,
                                  className: `w-full max-w-64`,
                                  value: R ? `fast` : `standard`,
                                  onValueChange: Je,
                                  disabled: Q,
                                  "data-testid": `codex-service-tier`,
                                  children: [
                                    (0, A.jsx)(y.Value, {}),
                                    ve.map((e) => (0, A.jsx)(y.Item, { value: e.value, children: e.label }, e.value)),
                                  ],
                                }),
                              ],
                            }),
                          ],
                        }),
                        !$ &&
                          (0, A.jsx)(v, {
                            className: `text-sm text-content-destructive`,
                            children: `Select at least one available agent, Codex model, and reasoning effort.`,
                          }),
                      ],
                    }),
                ],
              }),
              (0, A.jsxs)(`div`, {
                className: `flex flex-col gap-4`,
                children: [
                  (0, A.jsx)(`h2`, { className: `text-xl font-semibold`, children: `Agent capabilities` }),
                  (0, A.jsx)(`div`, {
                    className: `flex flex-col gap-3 rounded-lg border border-border-subtle px-5 py-4`,
                    children: (0, A.jsx)(r, {
                      id: `mcp-toggle`,
                      "data-testid": `mcp-toggle`,
                      label: `Model Context Protocol (MCP)`,
                      description: `Allow agents to use MCP servers for extended functionality`,
                      state: e ? `checked` : `unchecked`,
                      onCheckedChange: He,
                      isLoading: Y.isPending,
                      disabled: Y.isPending,
                    }),
                  }),
                  (0, A.jsxs)(`div`, {
                    className: `flex flex-col gap-3 rounded-lg border border-border-subtle px-5 py-4`,
                    children: [
                      (0, A.jsx)(r, {
                        id: `scm-tools-toggle`,
                        "data-testid": `scm-tools-toggle`,
                        label: `SCM Tools`,
                        description: `Allow agents to interact with source control management systems (GitHub, GitLab, etc.)`,
                        state: n ? `checked` : `unchecked`,
                        onCheckedChange: Ue,
                        isLoading: Y.isPending,
                        disabled: Y.isPending,
                      }),
                      n &&
                        (0, A.jsxs)(`div`, {
                          className: `ml-12 flex flex-col gap-2`,
                          "data-testid": `scm-tools-group-select`,
                          children: [
                            (0, A.jsx)(E, { className: `text-sm`, children: `Restrict access to` }),
                            (0, A.jsxs)(T, {
                              className: `w-fit max-w-80`,
                              value: o || j,
                              onValueChange: We,
                              disabled: Le || Y.isPending,
                              loading: Le,
                              children: [
                                (0, A.jsx)(T.Value, {
                                  children: (0, A.jsxs)(T.ValueLabel, {
                                    className: `flex items-center gap-2`,
                                    children: [
                                      o
                                        ? (0, A.jsx)(b, {
                                            size: 24,
                                            className: `size-5 rounded`,
                                            children: (0, A.jsx)(b.Initials, { name: Be, size: 24 }),
                                          })
                                        : (0, A.jsx)(`span`, {
                                            className: `flex size-5 items-center justify-center rounded bg-surface-tertiary text-xs`,
                                            children: `∞`,
                                          }),
                                      (0, A.jsx)(`span`, { children: Be }),
                                    ],
                                  }),
                                }),
                                (0, A.jsxs)(T.Popover, {
                                  sameWidth: !1,
                                  className: `min-w-56 max-w-80`,
                                  children: [
                                    (0, A.jsx)(T.SearchBox, { onValueChanged: Oe, loading: Ne || K }),
                                    (0, A.jsx)(T.List, {
                                      onScrollEnd: Re,
                                      scrollEndThreshold: 200,
                                      items: ze,
                                      searchKeys: [],
                                      disableFiltering: !0,
                                      noMatchesComponent: (0, A.jsx)(T.Empty, { children: `No groups found` }),
                                      children: (e) =>
                                        (0, A.jsxs)(
                                          T.ListItem,
                                          {
                                            value: e.id,
                                            children: [
                                              e.id === j
                                                ? (0, A.jsx)(T.ListItemLeadingIcon, {
                                                    children: (0, A.jsx)(`span`, {
                                                      className: `flex size-5 items-center justify-center rounded bg-surface-tertiary text-xs`,
                                                      children: `∞`,
                                                    }),
                                                  })
                                                : (0, A.jsx)(T.ListItemLeadingIcon, {
                                                    children: (0, A.jsx)(b, {
                                                      size: 24,
                                                      className: `size-5 rounded`,
                                                      children: (0, A.jsx)(b.Initials, { name: e.name, size: 24 }),
                                                    }),
                                                  }),
                                              (0, A.jsx)(T.ListItemTitle, { children: e.name }),
                                            ],
                                          },
                                          e.id,
                                        ),
                                    }),
                                  ],
                                }),
                              ],
                            }),
                          ],
                        }),
                    ],
                  }),
                  (0, A.jsx)(`div`, {
                    className: `flex flex-col gap-3 rounded-lg border border-border-subtle px-5 py-4`,
                    children: (0, A.jsx)(r, {
                      id: `conversation-sharing-toggle`,
                      "data-testid": `conversation-sharing-toggle`,
                      label: `Conversation sharing`,
                      description: `Allow users to share agent conversation transcripts with other members of the organization.`,
                      state: c ? `checked` : `unchecked`,
                      onCheckedChange: Ge,
                      isLoading: Y.isPending,
                      disabled: Y.isPending,
                    }),
                  }),
                ],
              }),
              (0, A.jsxs)(`div`, {
                className: `flex flex-col gap-4`,
                children: [
                  (0, A.jsx)(`h2`, { className: `text-xl font-semibold`, children: `Command deny list` }),
                  (0, A.jsxs)(`div`, {
                    className: `flex flex-col gap-3 rounded-lg border border-border-subtle px-5 py-4`,
                    children: [
                      (0, A.jsx)(v, {
                        className: `text-sm text-content-secondary`,
                        children: `Enter commands or patterns that should be blocked (one per line).`,
                      }),
                      (0, A.jsx)(de, {
                        id: `deny-list-textarea`,
                        value: B,
                        onChange: (e) => Ke(e.target.value),
                        placeholder: `rm -rf
sudo
curl
wget`,
                        minHeight: 120,
                        maxHeight: 400,
                        className: `font-mono text-sm`,
                        "data-testid": `deny-list-textarea`,
                        "aria-label": `Command deny list`,
                      }),
                    ],
                  }),
                ],
              }),
              (0, A.jsx)(`div`, {
                className: `flex gap-2`,
                children: (0, A.jsx)(m, {
                  onClick: $e,
                  variant: `primary`,
                  disabled: !V || !$,
                  loading: Y.isPending,
                  "data-testid": `save-policies-button`,
                  "data-tracking-id": `save-changes-agent-policies`,
                  children: `Save changes`,
                }),
              }),
            ],
          }),
        }),
        se &&
          (0, A.jsx)(Se, {
            onaAgentAllowed: u,
            codexAgentAllowed: h,
            codexEnabled: U,
            isSaving: Y.isPending,
            onClose: () => _(!1),
            onSave: Ze,
          }),
        x && (0, A.jsx)(we, { allowedCodexModels: D, isSaving: Y.isPending, onClose: () => S(!1), onSave: Qe }),
      ],
    });
  },
  L = () => {
    n(`Policies`);
    let { membership: e, isPending: r } = se(),
      { value: i, loading: a } = f();
    return !e && r
      ? null
      : e?.userRole === u.ADMIN
        ? a
          ? null
          : i
            ? (0, A.jsx)(I, {})
            : (0, A.jsx)(t, {})
        : (0, A.jsx)(t, {});
  };
export { L as AgentPoliciesPage };

import { a as e } from "./rolldown-runtime-CGYlQKCx.js";
import { n as t } from "./@mux-DLaEVubF.js";
import { df as n, kp as r, sf as i, tf as a, v_ as o } from "./vendor-DAwbZtf0.js";
import { tn as s, za as c } from "./use-boot-in-app-chat-t-J_VjKS.js";
import { t as l } from "./cn-DppMFCU8.js";
import { _ as u, a as d, t as f } from "./keyboard-combo--XtLCmBU.js";
import { t as p } from "./tooltip-6hqVQbwq.js";
import { r as m } from "./dropdown-menu-D3UmjGpQ.js";
import { t as ee } from "./use-is-mobile-viewport-Chw6u8QP.js";
import { t as h } from "./IconChevronDownSmall-9zzbc23a.js";
import { n as g, r as _, t as v } from "./agent-mode-visuals-DTOFpRnw.js";
import { a as y, d as b, g as x, i as S, p as te, r as ne, s as C, t as w } from "./agent-mode-ClxEfnvU.js";
import { n as T } from "./preferred-agent-preference-CSuiiQW5.js";
import { t as E } from "./IconArrowLeft-DER3051x.js";
import { c as D, l as re, o as O, p as k, s as A } from "./codex-settings-BPKiMIhT.js";
import { a as ie, i as ae, n as j, r as M, t as N } from "./agent-policy-B3gLeo-x.js";
var P = e(t(), 1),
  F = o(),
  I = `M9.8 1.75L2.75 8.7H7.3L5.55 14.25L13.25 6.85H8.85L9.8 1.75Z`,
  L = ({ size: e, className: t, ...n }) => {
    switch (e) {
      case `sm`:
        return (0, F.jsx)(`svg`, {
          width: `16`,
          height: `16`,
          viewBox: `0 0 16 16`,
          fill: `none`,
          className: t,
          ...n,
          xmlns: `http://www.w3.org/2000/svg`,
          children: (0, F.jsx)(`path`, {
            d: I,
            stroke: `currentColor`,
            strokeWidth: `1`,
            strokeLinecap: `round`,
            strokeLinejoin: `round`,
          }),
        });
      case `base`:
        return (0, F.jsx)(`svg`, {
          width: `20`,
          height: `20`,
          viewBox: `0 0 16 16`,
          fill: `none`,
          className: t,
          ...n,
          xmlns: `http://www.w3.org/2000/svg`,
          children: (0, F.jsx)(`path`, {
            d: I,
            stroke: `currentColor`,
            strokeWidth: `1`,
            strokeLinecap: `round`,
            strokeLinejoin: `round`,
          }),
        });
      case `lg`:
        return (0, F.jsx)(`svg`, {
          width: `24`,
          height: `24`,
          viewBox: `0 0 16 16`,
          fill: `none`,
          className: t,
          ...n,
          xmlns: `http://www.w3.org/2000/svg`,
          children: (0, F.jsx)(`path`, {
            d: I,
            stroke: `currentColor`,
            strokeWidth: `1`,
            strokeLinecap: `round`,
            strokeLinejoin: `round`,
          }),
        });
    }
  };
function oe({ children: e, className: t }) {
  let [n, r] = (0, P.useState)(void 0),
    i = (0, P.useRef)(null),
    a = (0, P.useCallback)((e) => {
      if ((i.current?.disconnect(), (i.current = null), !e)) return;
      r(e.getBoundingClientRect().height);
      let t = new ResizeObserver((e) => {
        for (let t of e) {
          let e = t.borderBoxSize?.[0]?.blockSize;
          r(e ?? t.contentRect.height);
        }
      });
      (t.observe(e, { box: `border-box` }), (i.current = t));
    }, []);
  return (0, F.jsx)(`div`, {
    className: l(`overflow-hidden transition-[height] duration-200 ease-out motion-reduce:transition-none`, t),
    style: { height: n },
    children: (0, F.jsx)(`div`, { ref: a, children: e }),
  });
}
var se = 24,
  R = ({
    mode: e,
    onModeChange: t,
    availableModes: n,
    disabled: r,
    codexPickerEnabled: i,
    codexRolloutEnabled: a,
    fixedAgent: o,
    codexSettings: c,
    onCodexSettingsChange: y,
    onCodexModelSelected: b,
    codexLoginOffer: te,
    codexSubscriptionStatus: C,
    openPanelRequest: w,
    hideModeSelector: E,
    triggerClassName: D,
    tooltipContent: re,
  }) => {
    let [k, A] = (0, P.useState)(!1),
      [j, M] = (0, P.useState)(`root`),
      N = (0, P.useRef)(void 0),
      I = (0, P.useRef)(!1),
      { isMobileViewport: L } = ee(),
      { data: oe, isLoading: se } = s({ enabled: !!a }),
      R = oe?.agentPolicy,
      z = !!a && se,
      B = r || z,
      V = (0, P.useMemo)(() => ie(n, { agentPolicy: R, isCodexRolloutEnabled: a }), [n, R, a]),
      H = (0, P.useMemo)(() => (i ? S(e, V) : V), [V, i, e]),
      U = (0, P.useMemo)(() => (i ? ae(c, R, a) : void 0), [i, c, R, a]);
    ((0, P.useEffect)(() => {
      z || (!V.includes(e) && V[0] && t(V[0]));
    }, [z, e, t, V]),
      (0, P.useEffect)(() => {
        if (!i || !y || !U || !c) return;
        let e = O(c);
        (e.model !== U.model || e.reasoningEffort !== U.reasoningEffort || e.serviceTier !== U.serviceTier) && y(U);
      }, [i, c, y, U]),
      (0, P.useEffect)(() => {
        !i || B || !w || (N.current !== w.id && ((N.current = w.id), M(w.panel), A(!0)));
      }, [i, B, w]));
    let W = (0, P.useCallback)((e) => {
        (A(e), e || M(`root`));
      }, []),
      G = (0, P.useCallback)(() => {
        I.current = !0;
      }, []),
      K = (0, P.useCallback)(
        (e) => {
          I.current && (e.preventDefault(), (I.current = !1), b?.());
        },
        [b],
      );
    return (
      (0, P.useEffect)(() => {
        if (B) return;
        let n = (n) => {
          (u() ? n.metaKey : n.ctrlKey) &&
            n.shiftKey &&
            n.code === `KeyM` &&
            (n.preventDefault(), n.stopPropagation(), t(ne(e, H)));
        };
        return (document.addEventListener(`keydown`, n, !0), () => document.removeEventListener(`keydown`, n, !0));
      }, [e, t, H, B]),
      (0, F.jsxs)(m, {
        open: k,
        onOpenChange: W,
        children: [
          (0, F.jsx)(p, {
            content:
              !k && !L
                ? (re ??
                  (0, F.jsxs)(`div`, {
                    className: `flex flex-row items-center gap-2`,
                    children: [`Change mode`, (0, F.jsx)(f, { keys: d })],
                  }))
                : void 0,
            children: (0, F.jsx)(`span`, {
              className: `inline-flex`,
              children: (0, F.jsxs)(m.Trigger, {
                disabled: B,
                "aria-label": `Change agent mode`,
                className: l(
                  `inline-flex h-8 items-center gap-1.5 rounded-md border border-border-base px-2 text-sm font-normal`,
                  g(e),
                  `hover:opacity-80 focus:outline-none focus-visible:outline focus-visible:outline-1 focus-visible:outline-offset-1 focus-visible:outline-border-brand data-[state=open]:opacity-80`,
                  B && `pointer-events-none opacity-50`,
                  D,
                ),
                children: [
                  (0, F.jsxs)(`div`, {
                    className: `flex min-w-0 items-center gap-1.5`,
                    children: [
                      E && !x(e) ? _(`ioi`, 16) : v(e, 16),
                      (0, F.jsx)(Se, { mode: e, codexSettings: U, showAgentFamilyLabel: E }),
                    ],
                  }),
                  (0, F.jsx)(h, { size: `sm` }),
                ],
              }),
            }),
          }),
          i
            ? (0, F.jsx)(ce, {
                mode: e,
                onModeChange: t,
                availableModes: V,
                codexRolloutEnabled: a,
                agentPolicy: R,
                fixedAgent: o,
                codexSettings: c,
                onCodexSettingsChange: y,
                onCodexModelSelected: G,
                codexLoginOffer: te,
                codexSubscriptionStatus: C,
                showShortcut: !L,
                open: k,
                requestedPanel: j,
                onCloseAutoFocus: K,
                hideModeSelector: E,
              })
            : (0, F.jsxs)(m.Content, {
                align: `end`,
                side: `top`,
                className: `min-w-72`,
                children: [
                  (0, F.jsxs)(`div`, {
                    className: `flex items-center justify-between px-2 py-1.5`,
                    children: [
                      (0, F.jsx)(m.Label, { className: `p-0`, children: `Mode` }),
                      !L && (0, F.jsx)(f, { keys: d, variant: `muted` }),
                    ],
                  }),
                  (0, F.jsx)(T, { mode: e, availableModes: V, onModeChange: t }),
                ],
              }),
        ],
      })
    );
  };
function ce({
  mode: e,
  onModeChange: t,
  availableModes: n,
  codexRolloutEnabled: r,
  agentPolicy: i,
  fixedAgent: a,
  codexSettings: o,
  onCodexSettingsChange: s,
  onCodexModelSelected: c,
  codexLoginOffer: l,
  codexSubscriptionStatus: u,
  showShortcut: d,
  open: f,
  requestedPanel: p,
  onCloseAutoFocus: m,
  hideModeSelector: ee,
}) {
  let h = te(n),
    g = b(n),
    _ = ae(o, i, r),
    v = x(e) ? `codex` : `ioi`,
    y = v === `codex` ? g : h,
    S = k(_.model) && N(i, r),
    {
      canUseFlyout: ne,
      rootMeasureRef: C,
      submenuMeasureRef: w,
    } = ye({
      measureKey: [
        v,
        e,
        a ? `fixed` : `switchable`,
        _.model,
        _.reasoningEffort,
        _.serviceTier,
        S ? `fast` : `standard`,
        l ? `codex-login-offer` : u ? `codex-subscription` : `no-codex-tip`,
        n.join(`|`),
      ].join(`:`),
    }),
    T = {
      mode: e,
      onModeChange: t,
      availableModes: n,
      fixedAgent: a,
      selectedCodexSettings: _,
      onCodexSettingsChange: s,
      onCodexModelSelected: c,
      showShortcut: d,
      onaModes: h,
      codexModes: g,
      selectedAgent: v,
      selectedModeOptions: y,
      fastModeSupported: S,
      codexRolloutEnabled: r,
      agentPolicy: i,
      codexLoginOffer: l,
      codexSubscriptionStatus: u,
      onCloseAutoFocus: m,
      hideModeSelector: ee,
    };
  return (0, F.jsxs)(F.Fragment, {
    children: [
      (0, F.jsx)(fe, { rootMeasureRef: C, submenuMeasureRef: w, ...T }),
      ne ? (0, F.jsx)(z, { ...T, requestedPanel: p }) : (0, F.jsx)(B, { ...T, open: f, requestedPanel: p }),
    ],
  });
}
function z(e) {
  let [t, n] = (0, P.useState)(`root`);
  (0, P.useEffect)(() => {
    n(e.requestedPanel);
  }, [e.requestedPanel]);
  let r = (0, P.useCallback)(
    (e) => (t) => {
      n((n) => (t ? e : n === e ? `root` : n));
    },
    [],
  );
  return (0, F.jsx)(m.Content, {
    align: `end`,
    side: `top`,
    className: `min-w-72 max-w-[calc(100vw-16px)]`,
    onCloseAutoFocus: e.onCloseAutoFocus,
    children: (0, F.jsxs)(oe, {
      children: [
        !e.fixedAgent &&
          (0, F.jsxs)(F.Fragment, {
            children: [
              (0, F.jsx)(m.Label, { children: `Agent` }),
              (0, F.jsx)(V, { ...e }),
              (!e.hideModeSelector || e.selectedAgent === `codex`) && (0, F.jsx)(m.Separator, {}),
            ],
          }),
        !e.hideModeSelector &&
          (0, F.jsxs)(m.Sub, {
            open: t === `mode`,
            onOpenChange: r(`mode`),
            children: [
              (0, F.jsx)($, {
                label: `Mode`,
                value: C(e.mode),
                extra: e.showShortcut
                  ? (0, F.jsx)(f, { keys: d, variant: `muted`, size: `sm`, className: `ml-2` })
                  : void 0,
              }),
              (0, F.jsx)(m.SubContent, {
                className: `min-w-64 max-w-[calc(100vw-16px)]`,
                children: (0, F.jsx)(T, {
                  mode: e.mode,
                  availableModes: e.selectedModeOptions,
                  onModeChange: e.onModeChange,
                }),
              }),
            ],
          }),
        e.selectedAgent === `codex` &&
          (0, F.jsxs)(F.Fragment, {
            children: [
              (0, F.jsxs)(m.Sub, {
                open: t === `model`,
                onOpenChange: r(`model`),
                children: [
                  (0, F.jsx)($, { label: `Model`, value: A(e.selectedCodexSettings.model) }),
                  (0, F.jsx)(m.SubContent, {
                    className: `min-w-64 max-w-[calc(100vw-16px)]`,
                    children: (0, F.jsx)(G, { ...e }),
                  }),
                ],
              }),
              (0, F.jsxs)(m.Sub, {
                open: t === `reasoning`,
                onOpenChange: r(`reasoning`),
                children: [
                  (0, F.jsx)($, { label: `Reasoning`, value: D(e.selectedCodexSettings.reasoningEffort) }),
                  (0, F.jsx)(m.SubContent, {
                    className: `min-w-64 max-w-[calc(100vw-16px)]`,
                    children: (0, F.jsx)(K, { ...e }),
                  }),
                ],
              }),
              (0, F.jsxs)(m.Sub, {
                open: t === `speed`,
                onOpenChange: r(`speed`),
                children: [
                  (0, F.jsx)($, {
                    label: `Speed`,
                    value: Te(e.selectedCodexSettings.serviceTier, e.fastModeSupported),
                    disabled: !e.fastModeSupported,
                  }),
                  (0, F.jsx)(m.SubContent, {
                    className: `min-w-64 max-w-[calc(100vw-16px)]`,
                    children: (0, F.jsx)(le, { ...e }),
                  }),
                ],
              }),
            ],
          }),
        (0, F.jsx)(U, { ...e }),
      ],
    }),
  });
}
function B(e) {
  let [t, n] = (0, P.useState)(`root`);
  return (
    (0, P.useEffect)(() => {
      e.open && n(e.requestedPanel);
    }, [e.open, e.requestedPanel]),
    (0, F.jsx)(m.Content, {
      align: `end`,
      side: `top`,
      className: `max-h-[min(420px,calc(100dvh-96px))] w-[calc(100vw-16px)] max-w-sm overflow-y-auto`,
      onCloseAutoFocus: e.onCloseAutoFocus,
      children:
        t === `root`
          ? (0, F.jsxs)(F.Fragment, {
              children: [
                !e.fixedAgent &&
                  (0, F.jsxs)(F.Fragment, {
                    children: [
                      (0, F.jsx)(m.Label, { children: `Agent` }),
                      (0, F.jsx)(V, { ...e }),
                      (!e.hideModeSelector || e.selectedAgent === `codex`) && (0, F.jsx)(m.Separator, {}),
                    ],
                  }),
                !e.hideModeSelector && (0, F.jsx)(q, { label: `Mode`, value: C(e.mode), onSelect: () => n(`mode`) }),
                e.selectedAgent === `codex` &&
                  (0, F.jsxs)(F.Fragment, {
                    children: [
                      (0, F.jsx)(q, {
                        label: `Model`,
                        value: A(e.selectedCodexSettings.model),
                        onSelect: () => n(`model`),
                      }),
                      (0, F.jsx)(q, {
                        label: `Reasoning`,
                        value: D(e.selectedCodexSettings.reasoningEffort),
                        onSelect: () => n(`reasoning`),
                      }),
                      (0, F.jsx)(q, {
                        label: `Speed`,
                        value: Te(e.selectedCodexSettings.serviceTier, e.fastModeSupported),
                        disabled: !e.fastModeSupported,
                        onSelect: () => n(`speed`),
                      }),
                    ],
                  }),
                (0, F.jsx)(U, { ...e }),
              ],
            })
          : (0, F.jsxs)(F.Fragment, {
              children: [
                (0, F.jsx)(ue, { label: de(t), onBack: () => n(`root`) }),
                t === `mode` &&
                  (0, F.jsx)(T, { mode: e.mode, availableModes: e.selectedModeOptions, onModeChange: e.onModeChange }),
                t === `model` && (0, F.jsx)(G, { ...e }),
                t === `reasoning` && (0, F.jsx)(K, { ...e }),
                t === `speed` && (0, F.jsx)(le, { ...e }),
              ],
            }),
    })
  );
}
function V({
  fixedAgent: e,
  selectedAgent: t,
  onaModes: n,
  codexModes: i,
  mode: a,
  onModeChange: o,
  codexRolloutEnabled: s,
}) {
  if (e) return null;
  let c = (e, t) => {
      (e.preventDefault(), o(t));
    },
    l = (0, F.jsxs)(
      m.Item,
      {
        onSelect: (e) => c(e, n.includes(a) ? a : (n[0] ?? w.Agent)),
        children: [
          _(`ioi`, 16),
          (0, F.jsx)(`span`, { className: `ml-2 min-w-0 flex-1 truncate`, children: `IOI Agent` }),
          t === `ioi` && (0, F.jsx)(r, { size: 14, className: `ml-auto shrink-0` }),
        ],
      },
      `ioi`,
    ),
    u =
      i.length > 0
        ? (0, F.jsxs)(
            m.Item,
            {
              onSelect: (e) => c(e, i.includes(a) ? a : (i[0] ?? w.CodexApp)),
              children: [
                _(`codex`, 16),
                (0, F.jsx)(`span`, { className: `ml-2 min-w-0 flex-1 truncate`, children: `Codex` }),
                t === `codex` && (0, F.jsx)(r, { size: 14, className: `ml-auto shrink-0` }),
              ],
            },
            `codex`,
          )
        : null;
  return (0, F.jsx)(F.Fragment, { children: s ? [u, l] : [l, u] });
}
function H({ offer: e }) {
  return (0, F.jsxs)(m.Item, {
    onClick: e.onConnect,
    disabled: e.isConnecting,
    className: `mx-1 mt-2 h-auto min-h-0 flex-col items-start gap-0.5 rounded-lg bg-surface-button-secondary px-3 py-2 text-left text-sm text-content-secondary hover:bg-surface-button-secondary-accent focus:bg-surface-button-secondary-accent disabled:opacity-50`,
    "data-tracking-id": `agent-mode-codex-login-offer`,
    children: [
      (0, F.jsx)(`span`, { className: `font-medium text-content-primary`, children: `Already have ChatGPT or Codex?` }),
      (0, F.jsx)(`span`, {
        className: `font-normal text-content-secondary`,
        children: `Use your ChatGPT plan for Codex and save your IOI credits.`,
      }),
    ],
  });
}
function U({ selectedAgent: e, codexLoginOffer: t, codexSubscriptionStatus: n }) {
  return W({ selectedAgent: e, codexLoginOffer: t, codexSubscriptionStatus: n })
    ? t
      ? (0, F.jsx)(H, { offer: t })
      : n
        ? (0, F.jsxs)(F.Fragment, {
            children: [
              (0, F.jsx)(m.Separator, { className: `my-0` }),
              (0, F.jsxs)(m.Item, {
                onClick: n.onOpenSettings,
                className: `mt-1 h-auto min-h-0 flex-col items-start px-2 pb-2 pt-2 text-left text-sm text-content-secondary hover:bg-surface-hover focus:bg-surface-hover`,
                "data-tracking-id": `agent-mode-codex-subscription-settings`,
                children: [
                  (0, F.jsx)(`span`, {
                    className: `text-content-primary`,
                    children: `Using your ChatGPT subscription`,
                  }),
                  (0, F.jsx)(`span`, {
                    className: `font-normal text-content-secondary`,
                    children: `Codex runs on your ChatGPT plan.`,
                  }),
                ],
              }),
            ],
          })
        : null
    : null;
}
function W({ selectedAgent: e, codexLoginOffer: t, codexSubscriptionStatus: n }) {
  return e === `codex` && (t !== void 0 || n !== void 0);
}
function G({
  selectedCodexSettings: e,
  onCodexSettingsChange: t,
  onCodexModelSelected: n,
  agentPolicy: r,
  codexRolloutEnabled: i,
}) {
  let a = j(r, i);
  return (0, F.jsx)(m.RadioGroup, {
    value: String(e.model),
    onValueChange: (r) => {
      let i = Number(r);
      (t?.(O({ ...e, model: i, serviceTier: k(i) ? e.serviceTier : c.UNSPECIFIED })), n?.());
    },
    children: a.map((e) => (0, F.jsx)(J, { value: String(e.value), children: e.label }, e.value)),
  });
}
function K({
  selectedCodexSettings: e,
  onCodexSettingsChange: t,
  onCodexModelSelected: n,
  agentPolicy: r,
  codexRolloutEnabled: i,
}) {
  let a = M(r, i);
  return (0, F.jsx)(m.RadioGroup, {
    value: String(e.reasoningEffort),
    onValueChange: (r) => {
      (t?.(O({ ...e, reasoningEffort: Number(r) })), n?.());
    },
    children: a.map((e) => (0, F.jsx)(J, { value: String(e.value), children: e.label }, e.value)),
  });
}
function le({ selectedCodexSettings: e, onCodexSettingsChange: t, agentPolicy: n, codexRolloutEnabled: r }) {
  let i = N(n, r);
  return (0, F.jsxs)(m.RadioGroup, {
    value: String(e.serviceTier),
    onValueChange: (n) => {
      t?.(O({ ...e, serviceTier: Number(n) }));
    },
    children: [
      (0, F.jsx)(J, { value: String(c.UNSPECIFIED), children: `Standard` }),
      i && (0, F.jsx)(J, { value: String(c.FAST), children: `Fast` }),
    ],
  });
}
function q({ label: e, value: t, disabled: n, onSelect: r }) {
  return (0, F.jsxs)(m.Item, {
    disabled: n,
    onSelect: (e) => {
      (e.preventDefault(), r());
    },
    children: [
      (0, F.jsx)(`span`, { className: `min-w-0 shrink-0`, children: e }),
      (0, F.jsx)(`span`, { className: `flex-1` }),
      (0, F.jsx)(`span`, { className: `ml-3 min-w-0 truncate text-content-secondary`, children: t }),
      (0, F.jsx)(a, { size: 16, className: `ml-2 shrink-0` }),
    ],
  });
}
function ue({ label: e, onBack: t }) {
  return (0, F.jsxs)(m.Item, {
    "aria-label": `Back to settings`,
    className: `mb-1 h-9 gap-1 rounded-none border-b border-border-base px-1 text-content-muted hover:text-content-primary focus:text-content-primary`,
    "data-tracking-id": `agent-mode-drill-in-back`,
    onSelect: (e) => {
      (e.preventDefault(), t());
    },
    children: [
      (0, F.jsx)(E, { size: `sm`, className: `shrink-0` }),
      (0, F.jsx)(`span`, {
        "aria-hidden": !0,
        className: `pointer-events-none min-w-0 flex-1 truncate font-medium text-content-muted`,
        children: e,
      }),
    ],
  });
}
function de(e) {
  switch (e) {
    case `mode`:
      return `Mode`;
    case `model`:
      return `Model`;
    case `reasoning`:
      return `Reasoning`;
    case `speed`:
      return `Speed`;
    case `root`:
      return `Settings`;
  }
}
function J({ value: e, children: t }) {
  return (0, F.jsxs)(n, {
    value: e,
    className: `relative mx-1 flex h-8 cursor-pointer select-none items-center rounded px-2 text-base hover:bg-surface-hover focus:bg-surface-hover focus:text-content-primary focus-visible:ring-0 data-[disabled]:pointer-events-none data-[disabled]:opacity-50`,
    children: [
      (0, F.jsx)(`span`, { className: `min-w-0 truncate`, children: t }),
      (0, F.jsx)(i, { className: `ml-auto shrink-0 pl-3`, children: (0, F.jsx)(r, { size: 14 }) }),
    ],
  });
}
function fe({ rootMeasureRef: e, submenuMeasureRef: t, ...n }) {
  return (0, F.jsxs)(`div`, {
    "aria-hidden": !0,
    className: `pointer-events-none fixed left-[-10000px] top-0 z-[-1] whitespace-nowrap opacity-0`,
    children: [
      (0, F.jsx)(`div`, {
        ref: e,
        "data-testid": `codex-picker-root-measure`,
        className: `w-max min-w-72 py-1`,
        children: (0, F.jsx)(pe, { ...n }),
      }),
      (0, F.jsxs)(`div`, {
        ref: t,
        "data-testid": `codex-picker-submenu-measure`,
        className: `w-max min-w-64 py-1`,
        children: [
          (0, F.jsx)(ge, { ...n }),
          n.selectedAgent === `codex` &&
            (0, F.jsxs)(F.Fragment, {
              children: [
                (0, F.jsx)(Y, { labels: j(n.agentPolicy, n.codexRolloutEnabled).map((e) => e.label) }),
                (0, F.jsx)(Y, { labels: M(n.agentPolicy, n.codexRolloutEnabled).map((e) => e.label) }),
                (0, F.jsx)(Y, {
                  labels: N(n.agentPolicy, n.codexRolloutEnabled) ? [`Standard`, `Fast`] : [`Standard`],
                }),
              ],
            }),
        ],
      }),
    ],
  });
}
function pe(e) {
  return (0, F.jsxs)(F.Fragment, {
    children: [
      !e.fixedAgent &&
        (0, F.jsxs)(F.Fragment, { children: [(0, F.jsx)(_e, { children: `Agent` }), (0, F.jsx)(he, { ...e })] }),
      (0, F.jsx)(X, { label: `Mode`, value: C(e.mode), extra: e.showShortcut ? d.join(``) : void 0 }),
      e.selectedAgent === `codex` &&
        (0, F.jsxs)(F.Fragment, {
          children: [
            (0, F.jsx)(X, { label: `Model`, value: A(e.selectedCodexSettings.model) }),
            (0, F.jsx)(X, { label: `Reasoning`, value: D(e.selectedCodexSettings.reasoningEffort) }),
            (0, F.jsx)(X, { label: `Speed`, value: Te(e.selectedCodexSettings.serviceTier, e.fastModeSupported) }),
          ],
        }),
      W(e) && (0, F.jsx)(me, { ...e }),
    ],
  });
}
function me(e) {
  return (0, F.jsx)(Z, {
    children: (0, F.jsx)(`div`, {
      className: `flex flex-col`,
      children: (e.codexLoginOffer
        ? [`Already have ChatGPT or Codex?`, `Use your ChatGPT plan for Codex and save your IOI credits.`]
        : [`Using your ChatGPT subscription`, `Codex runs on your ChatGPT plan.`]
      ).map((e) => (0, F.jsx)(Q, { className: `text-sm`, children: e }, e)),
    }),
  });
}
function he({ codexModes: e }) {
  return (0, F.jsx)(F.Fragment, {
    children: (e.length > 0 ? [`IOI Agent`, `Codex`] : [`IOI Agent`]).map((e) =>
      (0, F.jsxs)(
        Z,
        {
          children: [
            (0, F.jsx)(`div`, { className: `shrink-0`, children: _(`ioi`, 16) }),
            (0, F.jsx)(Q, { className: `ml-2`, children: e }),
            (0, F.jsx)(r, { size: 14, className: `ml-auto shrink-0` }),
          ],
        },
        e,
      ),
    ),
  });
}
function ge({ selectedModeOptions: e }) {
  return (0, F.jsx)(F.Fragment, {
    children: e.map((e) =>
      (0, F.jsxs)(
        Z,
        {
          children: [
            (0, F.jsx)(`div`, { className: `shrink-0`, children: v(e, 16) }),
            (0, F.jsxs)(`div`, {
              className: `ml-2 flex min-w-0 flex-1 flex-col`,
              children: [
                (0, F.jsx)(Q, { className: `text-sm`, children: C(e) }),
                (0, F.jsx)(Q, { className: `text-sm font-normal`, children: y(e) }),
              ],
            }),
            (0, F.jsx)(r, { size: 14, className: `ml-3 shrink-0` }),
          ],
        },
        e,
      ),
    ),
  });
}
function Y({ labels: e }) {
  return (0, F.jsx)(F.Fragment, {
    children: e.map((e) =>
      (0, F.jsxs)(
        Z,
        { children: [(0, F.jsx)(Q, { children: e }), (0, F.jsx)(r, { size: 14, className: `ml-auto shrink-0 pl-3` })] },
        e,
      ),
    ),
  });
}
function X({ label: e, value: t, extra: n }) {
  return (0, F.jsxs)(Z, {
    children: [
      (0, F.jsx)(Q, { children: e }),
      n && (0, F.jsx)(Q, { className: `ml-2 text-xs`, children: n }),
      (0, F.jsx)(Q, { className: `px-4`, children: t }),
      (0, F.jsx)(a, { size: 16, className: `shrink-0` }),
    ],
  });
}
function _e({ children: e }) {
  return (0, F.jsx)(`div`, { className: `mx-1 px-2 py-1.5 text-sm font-medium`, children: ve(e) });
}
function Z({ children: e }) {
  return (0, F.jsx)(`div`, { className: `mx-1 flex h-8 w-max items-center rounded px-2 text-base`, children: e });
}
function Q({ children: e, className: t }) {
  return (0, F.jsx)(`span`, { className: t, children: ve(e) });
}
function ve(e) {
  return typeof e == `string` ? e.split(``).join(`​`) : e;
}
function ye({ measureKey: e }) {
  let t = (0, P.useRef)(null),
    n = (0, P.useRef)(null),
    [r, i] = (0, P.useState)(!1);
  return (
    (0, P.useLayoutEffect)(() => {
      let e = () => {
        let e = t.current?.scrollWidth ?? 0,
          r = n.current?.scrollWidth ?? 0,
          a = typeof window > `u` ? 0 : window.innerWidth;
        i(e + r + se <= a);
      };
      e();
      let r =
        typeof ResizeObserver > `u`
          ? void 0
          : new ResizeObserver(() => {
              e();
            });
      return (
        t.current && r?.observe(t.current),
        n.current && r?.observe(n.current),
        window.addEventListener(`resize`, e),
        () => {
          (r?.disconnect(), window.removeEventListener(`resize`, e));
        }
      );
    }, [e]),
    { canUseFlyout: r, rootMeasureRef: t, submenuMeasureRef: n }
  );
}
function be(e, t) {
  if (!t || !x(e)) return C(e);
  let n = xe(t);
  return e === w.CodexApp ? n : `${C(e)} - ${n}`;
}
function xe(e) {
  return `${re(e.model)} ${D(e.reasoningEffort)}`;
}
function Se({ mode: e, codexSettings: t, showAgentFamilyLabel: n }) {
  if (n && !x(e)) return (0, F.jsx)(`span`, { className: `truncate`, children: `IOI Agent` });
  if (!t || !x(e) || !we(t)) return (0, F.jsx)(`span`, { className: `truncate`, children: be(e, t) });
  let r = xe(t);
  return e === w.CodexApp
    ? (0, F.jsxs)(F.Fragment, {
        children: [(0, F.jsx)(Ce, {}), (0, F.jsx)(`span`, { className: `truncate`, children: r })],
      })
    : (0, F.jsxs)(F.Fragment, {
        children: [
          (0, F.jsxs)(`span`, { className: `shrink-0`, children: [C(e), ` -`] }),
          (0, F.jsx)(Ce, {}),
          (0, F.jsx)(`span`, { className: `truncate`, children: r }),
        ],
      });
}
function Ce() {
  return (0, F.jsx)(L, { size: `sm`, className: `shrink-0`, "data-testid": `codex-fast-mode-icon` });
}
function we(e) {
  return e.serviceTier === c.FAST && k(e.model);
}
function $({ label: e, value: t, extra: n, disabled: r }) {
  return (0, F.jsxs)(m.SubTrigger, {
    disabled: r,
    children: [
      (0, F.jsx)(`span`, { className: `min-w-0 shrink-0`, children: e }),
      n,
      (0, F.jsx)(`span`, { className: `flex-1` }),
      (0, F.jsx)(`span`, { className: `mr-2 truncate text-content-secondary`, children: t }),
    ],
  });
}
function Te(e, t) {
  return t ? (e === c.FAST ? `Fast` : `Standard`) : `Unavailable`;
}
export { R as t };

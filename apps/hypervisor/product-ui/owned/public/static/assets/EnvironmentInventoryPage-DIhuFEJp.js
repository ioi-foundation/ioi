const __vite__mapDeps = (
  i,
  m = __vite__mapDeps,
  d = m.f ||
    (m.f = [
      globalThis.__toAssetUrl("assets/inline-date-time-picker-DOoMQE8a.js"),
      globalThis.__toAssetUrl("assets/rolldown-runtime-CGYlQKCx.js"),
      globalThis.__toAssetUrl("assets/vendor-DAwbZtf0.js"),
      globalThis.__toAssetUrl("assets/@mux-DLaEVubF.js"),
      globalThis.__toAssetUrl("assets/time-picker-DbT-l-4Y.js"),
      globalThis.__toAssetUrl("assets/dropdown-menu-D3UmjGpQ.js"),
      globalThis.__toAssetUrl("assets/button-6YP03Qf2.js"),
      globalThis.__toAssetUrl("assets/cn-DppMFCU8.js"),
      globalThis.__toAssetUrl("assets/radix-body-pointer-events-DJX9Yyw0.js"),
      globalThis.__toAssetUrl("assets/lifetime-C1J-eirn.js"),
      globalThis.__toAssetUrl("assets/time-DxjbKG-a.js"),
      globalThis.__toAssetUrl("assets/strings-C6LrS0GJ.js"),
      globalThis.__toAssetUrl("assets/timestamp-CEKPQVte.js"),
    ]),
) => i.map((i) => d[i]);
import { a as e } from "./rolldown-runtime-CGYlQKCx.js";
import { It as t, Lt as n, fr as r, mr as i, sr as a } from "./SegmentProvider-CXCNBY9U.js";
import { n as o } from "./@mux-DLaEVubF.js";
import {
  Ep as s,
  Gh as c,
  Op as l,
  Rl as u,
  Xf as d,
  dg as f,
  eg as p,
  g_ as m,
  l_ as h,
  o_ as g,
  s_ as _,
  v_ as v,
  wp as y,
} from "./vendor-DAwbZtf0.js";
import {
  Dt as b,
  Fi as x,
  Ls as S,
  Ot as C,
  jo as w,
  mn as T,
  so as E,
  ss as D,
  tn as O,
  tr as k,
  xn as A,
} from "./use-boot-in-app-chat-t-J_VjKS.js";
import { n as j } from "./toast-axaLeIzZ.js";
import { a as ee, t as M } from "./button-6YP03Qf2.js";
import { t as N } from "./cn-DppMFCU8.js";
import { t as P } from "./dialog-BtjFqa-w.js";
import { t as F } from "./use-membership-CcV5kGny.js";
import { t as I } from "./banner-CFcSGYsz.js";
import { t as L } from "./strings-C6LrS0GJ.js";
import { a as R, d as te, t as z } from "./time-DxjbKG-a.js";
import { t as ne } from "./input-C42Z_4fO.js";
import { t as re } from "./tooltip-6hqVQbwq.js";
import { t as B } from "./Pill-99RRpZf2.js";
import "./pill-AA_qJIlm.js";
import { t as V } from "./text-fFCFeCas.js";
import { t as H } from "./select-Ceshp72e.js";
import { t as ie } from "./use-cursor-pagination-D6xO6NZ2.js";
import { r as U } from "./dropdown-menu-D3UmjGpQ.js";
import { H as W, j as ae, x as oe, z as se } from "./environment-queries-zpiLcWfm.js";
import { m as G } from "./runner-queries-BAY_7mHt.js";
import { g as K } from "./project-queries-BMZ3qCU_.js";
import { t as q } from "./avatar-CjN22mGB.js";
import { t as J } from "./collapsible-CijQ-f1P.js";
import { n as ce } from "./phase-DI4YEQQ1.js";
import { t as le } from "./IconDot-JLZkI4_Z.js";
import { l as ue } from "./environment-paa_Ds61.js";
import { t as Y } from "./repo-url-BreAEtzd.js";
import { n as de, r as fe, t as pe } from "./popover-D9TQszBd.js";
import { t as X } from "./combobox-BkGa_nRF.js";
import { t as me } from "./delayed-DmSSX8Yq.js";
import { s as Z } from "./data-table-hWj1SxAH.js";
import { t as he } from "./empty-state-D7Bh3L9e.js";
import { d as ge, s as _e } from "./main-DLKYFe1Y.js";
import { n as ve, r as ye } from "./lifetime-C1J-eirn.js";
import { t as be } from "./ProjectCombobox-DA6I4hur.js";
import { n as xe, r as Se, t as Ce } from "./run-batched-0sqU5SvM.js";
var Q = e(o(), 1),
  $ = v(),
  we = ({ dotBgColor: e, pulse: t }) =>
    (0, $.jsx)(`div`, {
      className: N(`inline-flex h-4 flex-row items-center gap-2 rounded-full text-sm`, t && `animate-pulse`),
      children: (0, $.jsx)(`div`, { className: N(`size-2 rounded-full`, e) }),
    }),
  Te = ({ state: e, variant: t = `label`, truncate: n, size: r = `sm` }) => {
    let {
        pillVariant: i,
        fgColor: a,
        dotBgColor: o,
        pulse: s,
        name: c,
        warnings: u,
        failures: d,
        timeout: f,
      } = (0, Q.useMemo)(() => {
        if (e.failures && e.state !== E.DELETING)
          return {
            pillVariant: `danger`,
            bgColor: `bg-surface-negative/10`,
            fgColor: `text-content-negative`,
            dotBgColor: `bg-content-negative`,
            pulse: !1,
            name: `Failed`,
            ...e,
          };
        let t = `default`,
          n = `bg-content-tertiary`,
          r = `text-content-tertiary`,
          i = `Unknown`,
          a = !1;
        switch (e.state) {
          case E.RUNNING:
            ((t = `success`),
              (n = `bg-content-positive`),
              (r = `text-content-positive`),
              (i = `Running`),
              (a = !1),
              e.warnings && ((t = `warning`), (n = `bg-content-yield`), (r = `text-content-yield`)));
            break;
          case E.CREATING:
            ((t = `warning`), (n = `bg-content-yield`), (r = `text-content-yield`), (i = `Creating...`), (a = !0));
            break;
          case E.STARTING:
            ((t = `success`),
              (n = `bg-content-positive`),
              (r = `text-content-positive`),
              (i = `Starting...`),
              (a = !0));
            break;
          case E.UPDATING:
            ((t = `warning`), (n = `bg-content-yield`), (r = `text-content-yield`), (i = `Updating...`), (a = !0));
            break;
          case E.STOPPING:
            ((t = `warning`),
              (n = `bg-content-yield`),
              (r = `text-content-yield`),
              (i = `Stopping...`),
              e.timeout && (i = `Auto-stopping...`),
              (a = !0));
            break;
          case E.STOPPED:
            ((t = `neutral`),
              (n = `bg-content-tertiary`),
              (r = `text-content-primary`),
              (i = `Stopped`),
              e.timeout && (i = `Auto-stopped`));
            break;
          case E.DELETING:
            ((t = `danger`), (n = `bg-content-negative`), (r = `text-content-negative`), (i = `Deleting...`), (a = !0));
            break;
        }
        return { pillVariant: t, fgColor: r, dotBgColor: n, pulse: a, name: i, ...e };
      }, [e]),
      p = (0, Q.useMemo)(() => (e) => (0, $.jsx)(we, { ...e, dotBgColor: o, pulse: s }), [o, s]);
    if (t === `dot`) return (0, $.jsx)($.Fragment, { children: (0, $.jsx)(le, { size: `lg`, className: a }) });
    let m = f || u || d ? [...(f ? [f] : []), ...(d || []), ...(u || [])] : void 0;
    return (0, $.jsxs)(`span`, {
      className: `inline-flex items-center gap-0.5`,
      children: [
        (0, $.jsx)(B, {
          variant: i,
          size: r,
          LeadingIcon: p,
          className: N(s && `animate-pulse`),
          truncate: n,
          children: c,
        }),
        m &&
          (0, $.jsxs)(pe, {
            children: [
              (0, $.jsx)(fe, {
                "data-testid": `problems-popover-trigger`,
                className: `inline-flex items-center rounded p-0.5 text-current hover:bg-surface-hover`,
                children: (0, $.jsx)(l, { size: 16 }),
              }),
              (0, $.jsx)(de, {
                align: `end`,
                children: (0, $.jsx)(`div`, {
                  className: `text-base text-content-secondary`,
                  children: m
                    .map((e) =>
                      e.split(`
`),
                    )
                    .flat()
                    .map((e, t) => (0, $.jsx)(`p`, { children: e }, t)),
                }),
              }),
            ],
          }),
      ],
    });
  };
function Ee(e) {
  let t = e.status?.phase;
  return t === E.CREATING || t === E.STARTING || t === E.RUNNING || t === E.UPDATING;
}
var De = [
    { label: `hours`, seconds: 3600 },
    { label: `days`, seconds: 86400 },
    { label: `weeks`, seconds: 604800 },
    { label: `months`, seconds: 2592e3 },
  ],
  Oe = ({ onChange: e, initialAmount: t = 3, initialUnitIndex: n = 0 }) => {
    let [r, i] = (0, Q.useState)(t),
      [a, o] = (0, Q.useState)(n),
      s = (0, Q.useCallback)(
        (t, n) => {
          if (t <= 0) return;
          let r = t * De[n].seconds;
          e(ye(new Date(Date.now() + r * 1e3)));
        },
        [e],
      ),
      c = (0, Q.useRef)(!1);
    (0, Q.useEffect)(() => {
      c.current || ((c.current = !0), s(t, n));
    }, [s, t, n]);
    let l = (0, Q.useCallback)(
        (e) => {
          let t = Math.max(1, parseInt(e.target.value, 10) || 1);
          (i(t), s(t, a));
        },
        [a, s],
      ),
      u = (0, Q.useCallback)(
        (e) => {
          let t = parseInt(e, 10);
          (o(t), s(r, t));
        },
        [r, s],
      );
    return (0, $.jsxs)($.Fragment, {
      children: [
        (0, $.jsx)(ne, {
          type: `number`,
          min: 1,
          value: r,
          onChange: l,
          className: `w-16 text-center`,
          "aria-label": `Amount`,
        }),
        (0, $.jsx)(H, {
          value: String(a),
          onValueChange: u,
          className: `w-auto`,
          children: De.map((e, t) => (0, $.jsx)(H.Item, { value: String(t), children: e.label }, e.label)),
        }),
      ],
    });
  },
  ke = (0, Q.lazy)(() =>
    c(
      () => import(`./inline-date-time-picker-DOoMQE8a.js`).then((e) => ({ default: e.InlineDateTimePicker })),
      __vite__mapDeps([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]),
      import.meta.url,
    ),
  );
function Ae(e) {
  return e.metadata?.name ? e.metadata.name : Y(e)?.repoUrl?.replace(`https://github.com/`, ``) || e.id;
}
function je(e) {
  return { id: e.id, label: Ae(e), secondary: e.id, status: `pending` };
}
var Me = {
    stop: {
      title: `Stop environments`,
      confirmLabel: `Stop`,
      description: `This will stop the selected environments. Users won't lose any changes.`,
    },
    delete: {
      title: `Delete environments`,
      confirmLabel: `Delete`,
      description: `This will delete the selected environments. Affected users may lose uncommitted changes.`,
    },
    "force-delete": {
      title: `Force delete environments`,
      confirmLabel: `Force Delete`,
      description: `This will force delete the selected environments. This may leave infrastructure or files behind that require manual cleanup.`,
    },
  },
  Ne = ({ open: e, onOpenChange: t, action: n, environments: r, onComplete: i }) => {
    let [a, o] = (0, Q.useState)(`confirm`),
      [s, c] = (0, Q.useState)([]),
      [l, u] = (0, Q.useState)(!1),
      d = se(),
      f = oe(),
      p = Me[n],
      m = n === `delete` || n === `force-delete`,
      h = (0, Q.useCallback)(
        (e) => {
          if (!e) {
            let e = s.length > 0 && s.every((e) => e.status === `success` || e.status === `error`);
            (a === `confirm` || e) && (o(`confirm`), c([]), u(!1), t(!1), e && i());
            return;
          }
          t(e);
        },
        [t, i, a, s],
      ),
      g = (0, Q.useCallback)(
        async (e) => {
          switch (n) {
            case `stop`:
              await d.mutateAsync(e.id);
              break;
            case `delete`:
              await f.mutateAsync({ environmentId: e.id, force: !1 });
              break;
            case `force-delete`:
              await f.mutateAsync({ environmentId: e.id, force: !0 });
              break;
          }
        },
        [n, d, f],
      ),
      _ = (0, Q.useCallback)(async () => {
        (c(r.map(je)), o(`progress`));
        let e = (e, t, n) => {
          c((r) => r.map((r, i) => (i === e ? { ...r, status: t, error: n } : r)));
        };
        await Ce(
          r,
          async (t, n) => {
            (e(n, `running`), await g(t));
          },
          (t, n) => {
            e(t, n ? `error` : `success`, n);
          },
        );
      }, [r, g]),
      v = (0, Q.useMemo)(() => Se(s), [s]),
      x = (0, Q.useMemo)(() => {
        if (n === `stop`) {
          let e = r.filter((e) => !Ee(e)).length;
          if (e > 0) return `${e} already stopped or deleting ${L(e, `environment`)} will be skipped.`;
        }
      }, [n, r]);
    return (0, $.jsx)(P, {
      open: e,
      onOpenChange: h,
      children: (0, $.jsx)(P.Content, {
        className: `max-w-lg`,
        "data-track-location": b.InventoryBulkActionModal,
        children:
          a === `confirm`
            ? (0, $.jsxs)($.Fragment, {
                children: [
                  (0, $.jsxs)(P.Header, {
                    children: [
                      (0, $.jsx)(P.Title, { children: p.title }),
                      (0, $.jsx)(P.Description, { children: p.description }),
                    ],
                  }),
                  (0, $.jsxs)(V, {
                    className: `text-base text-content-secondary`,
                    children: [
                      `This action will be applied to`,
                      ` `,
                      (0, $.jsxs)(`strong`, { children: [r.length, ` `, L(r.length, `environment`)] }),
                      `.`,
                    ],
                  }),
                  x &&
                    (0, $.jsxs)(`div`, {
                      className: `flex items-center gap-2 rounded-md border border-border-base px-3 py-2.5`,
                      children: [
                        (0, $.jsx)(y, { className: `h-4 w-4 shrink-0 text-content-yield` }),
                        (0, $.jsx)(`span`, { className: `text-sm text-content-primary`, children: x }),
                      ],
                    }),
                  (0, $.jsxs)(P.Footer, {
                    children: [
                      (0, $.jsx)(P.Close, {
                        asChild: !0,
                        children: (0, $.jsx)(M, { type: `button`, variant: `outline`, children: `Cancel` }),
                      }),
                      (0, $.jsx)(M, {
                        type: `submit`,
                        autoFocus: !0,
                        variant: m ? `destructive` : `primary`,
                        onClick: () => void _(),
                        "data-tracking-id": `confirm-bulk-action`,
                        children: p.confirmLabel,
                      }),
                    ],
                  }),
                ],
              })
            : (0, $.jsx)(xe, {
                title: p.title,
                items: s,
                summary: v,
                detailsOpen: l,
                onDetailsOpenChange: u,
                onClose: () => h(!1),
                closeTrackingId: `close-bulk-action-progress`,
              }),
      }),
    });
  },
  Pe = ({ open: e, onOpenChange: t, environments: n, maxEnvLifetime: r, onComplete: i }) => {
    let [a, o] = (0, Q.useState)(`input`),
      [s, c] = (0, Q.useState)([]),
      [u, d] = (0, Q.useState)(!1),
      [f, p] = (0, Q.useState)(`extend`),
      [g, v] = (0, Q.useState)(``),
      [y, x] = (0, Q.useState)(void 0),
      S = W(),
      C = (0, Q.useCallback)(
        (e) => {
          if (!e) {
            let e = s.length > 0 && s.every((e) => e.status === `success` || e.status === `error`);
            (a === `input` || e) && (o(`input`), c([]), d(!1), p(`extend`), v(``), x(void 0), t(!1), e && i());
            return;
          }
          t(e);
        },
        [t, i, a, s],
      ),
      T = (0, Q.useMemo)(() => {
        if (!(r <= 0)) return ve(r);
      }, [r]),
      E = n.length === 1,
      D = (0, Q.useMemo)(() => {
        if (r <= 0 || !E) return;
        let e = n[0],
          t = e.metadata?.createdAt ? Number(e.metadata.createdAt.seconds) : Math.floor(Date.now() / 1e3);
        return ye(new Date((t + r) * 1e3));
      }, [r, E, n]),
      O = (0, Q.useCallback)(
        () => (
          c(n.map(je)),
          o(`progress`),
          (e, t, n) => {
            c((r) => r.map((r, i) => (i === e ? { ...r, status: t, error: n } : r)));
          }
        ),
        [n],
      ),
      k = (0, Q.useCallback)(async () => {
        if (!f) {
          x(`Please select an option.`);
          return;
        }
        let e;
        switch (f) {
          case `clear`:
            e = () => m(h, { seconds: BigInt(0), nanos: 0 });
            break;
          case `now`:
            e = () => _(new Date());
            break;
          case `policy`:
            e = (e) => {
              let t = e.metadata?.createdAt ? Number(e.metadata.createdAt.seconds) : Math.floor(Date.now() / 1e3);
              return _(new Date((t + r) * 1e3));
            };
            break;
          case `extend`:
          case `custom`: {
            if (!g) {
              x(`Please select a date and time.`);
              return;
            }
            let t = new Date(g);
            if (isNaN(t.getTime())) {
              x(`Invalid date.`);
              return;
            }
            if (t <= new Date()) {
              x(`Date must be in the future.`);
              return;
            }
            let n = _(t);
            e = () => n;
            break;
          }
        }
        x(void 0);
        let t = O();
        await Ce(
          n,
          async (n, r) => {
            (t(r, `running`),
              await S.mutateAsync({ req: { environmentId: n.id, metadata: m(w, { lockdownAt: e(n) }) } }));
          },
          (e, n) => t(e, n ? `error` : `success`, n),
        );
      }, [f, g, n, S, O, r]),
      A = (0, Q.useMemo)(() => Se(s), [s]),
      j = (0, Q.useMemo)(() => {
        switch (f) {
          case `extend`:
            return `Extend`;
          case `now`:
            return `Current Date/Time`;
          case `custom`:
            return `Custom`;
          case `policy`:
            return `Restore Org Policy: ${T}`;
          case `clear`:
            return `Clear limit`;
          default:
            return `Select lifetime`;
        }
      }, [f, T]);
    return (0, $.jsx)(P, {
      open: e,
      onOpenChange: C,
      children: (0, $.jsx)(P.Content, {
        className: `max-w-md`,
        "data-track-location": b.InventoryBulkUpdateLifetimeModal,
        children:
          a === `input`
            ? (0, $.jsxs)($.Fragment, {
                children: [
                  (0, $.jsxs)(P.Header, {
                    children: [
                      (0, $.jsx)(P.Title, { children: `Update environment lifetime` }),
                      (0, $.jsxs)(P.Description, {
                        children: [
                          `Set a new lifetime limit for`,
                          ` `,
                          (0, $.jsxs)(`strong`, { children: [n.length, ` `, L(n.length, `environment`)] }),
                          `. After this date, the environments become non-compliant and may be restricted from starting.`,
                        ],
                      }),
                    ],
                  }),
                  (0, $.jsxs)(`div`, {
                    className: `flex flex-col gap-3 py-2`,
                    children: [
                      (0, $.jsxs)(`div`, {
                        className: `flex items-center gap-2`,
                        children: [
                          (0, $.jsxs)(U, {
                            children: [
                              (0, $.jsx)(U.Trigger, {
                                asChild: !0,
                                children: (0, $.jsxs)(M, {
                                  type: `button`,
                                  variant: `outline`,
                                  className: `gap-1.5`,
                                  "data-tracking-id": `bulk-lifetime-picker`,
                                  children: [(0, $.jsx)(`span`, { children: j }), (0, $.jsx)(l, { size: 14 })],
                                }),
                              }),
                              (0, $.jsxs)(U.Content, {
                                align: `start`,
                                className: `w-52`,
                                children: [
                                  (0, $.jsx)(U.Item, {
                                    onClick: () => {
                                      (p(`extend`), v(``), x(void 0));
                                    },
                                    "data-tracking-id": `bulk-mode-extend`,
                                    children: `Extend`,
                                  }),
                                  (0, $.jsx)(U.Item, {
                                    onClick: () => {
                                      (p(`now`), v(``), x(void 0));
                                    },
                                    "data-tracking-id": `bulk-mode-now`,
                                    children: `Current Date/Time`,
                                  }),
                                  (0, $.jsx)(U.Item, {
                                    onClick: () => {
                                      (p(`custom`), v(``), x(void 0));
                                    },
                                    "data-tracking-id": `bulk-mode-custom`,
                                    children: `Custom`,
                                  }),
                                  T &&
                                    (0, $.jsxs)($.Fragment, {
                                      children: [
                                        (0, $.jsx)(U.Separator, {}),
                                        (0, $.jsxs)(U.Item, {
                                          onClick: () => {
                                            (p(`policy`), v(``), x(void 0));
                                          },
                                          "data-tracking-id": `bulk-mode-policy`,
                                          children: [`Restore Org Policy: `, T],
                                        }),
                                      ],
                                    }),
                                  (0, $.jsx)(U.Separator, {}),
                                  (0, $.jsx)(U.Item, {
                                    onClick: () => {
                                      (p(`clear`), v(``), x(void 0));
                                    },
                                    className: `text-content-red`,
                                    "data-tracking-id": `bulk-mode-clear`,
                                    children: `Clear limit`,
                                  }),
                                ],
                              }),
                            ],
                          }),
                          f === `extend` &&
                            (0, $.jsx)(Oe, {
                              onChange: (e) => {
                                (v(e), x(void 0));
                              },
                            }),
                        ],
                      }),
                      f === `custom` &&
                        (0, $.jsx)(Q.Suspense, {
                          fallback: (0, $.jsx)(`div`, { className: `h-[340px]` }),
                          children: (0, $.jsx)(ke, {
                            value: g,
                            onChange: (e) => {
                              (v(e), x(void 0));
                            },
                          }),
                        }),
                      f === `now` &&
                        (0, $.jsx)(I, {
                          variant: `info`,
                          text: `Lifetime limit will be set to the current time on save.`,
                        }),
                      f === `clear` && (0, $.jsx)(I, { variant: `info`, text: `Limit will be cleared.` }),
                      f === `policy` &&
                        (0, $.jsx)(I, {
                          variant: `info`,
                          text:
                            E && D
                              ? `New lifetime limit: ${new Date(D).toLocaleString()}`
                              : `Each environment will be set to creation time + ${T}`,
                        }),
                      (f === `extend` || f === `custom`) &&
                        g &&
                        (0, $.jsx)(I, { variant: `info`, text: `New lifetime limit: ${new Date(g).toLocaleString()}` }),
                      y && (0, $.jsx)(V, { className: `text-center text-sm text-content-red`, children: y }),
                    ],
                  }),
                  (0, $.jsxs)(P.Footer, {
                    children: [
                      (0, $.jsx)(P.Close, {
                        asChild: !0,
                        children: (0, $.jsx)(M, {
                          type: `button`,
                          variant: `outline`,
                          "data-tracking-id": `cancel-bulk-update-lifetime`,
                          children: `Cancel`,
                        }),
                      }),
                      (0, $.jsx)(M, {
                        type: `submit`,
                        autoFocus: !0,
                        variant: `primary`,
                        onClick: (e) => {
                          (e.preventDefault(), k());
                        },
                        "data-tracking-id": `confirm-bulk-update-lifetime`,
                        children: `Update`,
                      }),
                    ],
                  }),
                ],
              })
            : (0, $.jsx)(xe, {
                title: `Update environment lifetime`,
                items: s,
                summary: A,
                detailsOpen: u,
                onDetailsOpenChange: d,
                onClose: () => C(!1),
                closeTrackingId: `close-bulk-update-lifetime-progress`,
              }),
      }),
    });
  },
  Fe = (0, Q.lazy)(() =>
    c(
      () => import(`./inline-date-time-picker-DOoMQE8a.js`).then((e) => ({ default: e.InlineDateTimePicker })),
      __vite__mapDeps([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]),
      import.meta.url,
    ),
  );
function Ie(e) {
  let t = e.metadata?.lockdownAt;
  if (t) return Number(t.seconds) * 1e3 + Math.floor(t.nanos / 1e6) - Date.now();
}
var Le = [],
  Re = () => {
    let [e, t] = f(),
      n = e.get(`runner`) || void 0,
      r = (0, Q.useMemo)(() => {
        for (let e of Ve) if (n === e.key) return e.kind;
      }, [n]),
      i = (0, Q.useMemo)(() => (r ? void 0 : n), [r, n]),
      a = e.get(`creator`) || void 0,
      o = e.get(`lifetime`) || void 0,
      s = o === Be ? o : void 0,
      c = e.get(`search`) || void 0,
      [l, u] = (0, Q.useState)(() => (typeof window < `u` ? window.location.hash : ``)),
      d = c !== void 0 && l === `#!update-lifetime`,
      p = (0, Q.useCallback)(() => {
        (t((e) => {
          let t = new URLSearchParams(e);
          return (t.delete(`search`), t);
        }),
          window.location.hash && history.replaceState(null, ``, window.location.pathname + window.location.search),
          u(``));
      }, [t]),
      { data: m, isLoading: h } = G({}),
      { data: g, isLoading: _ } = O(),
      [v, y] = (0, Q.useState)({ runnerID: i, creatorID: a, runnerKind: r, lifetime: s }),
      b = (0, Q.useCallback)((e) => {
        y(e);
      }, []),
      x = g?.maximumEnvironmentLifetime?.seconds ? Number(g.maximumEnvironmentLifetime.seconds) : 0,
      S = (0, Q.useMemo)(() => (v.lifetime === Be ? new Date() : void 0), [v.lifetime]),
      C = (0, Q.useMemo)(
        () => ({
          runnerID: v.runnerID,
          creatorID: v.creatorID,
          projectID: v.projectID,
          phase: v.phase,
          runnerKind: v.runnerKind,
          lockdownBefore: x > 0 ? S : void 0,
          search: c,
        }),
        [v, x, S, c],
      ),
      [w, T] = (0, Q.useState)(new Set()),
      E = (0, Q.useMemo)(() => m || [], [m]),
      D = (0, Q.useMemo)(() => ({ runnerID: i, creatorID: a, runnerKind: r, lifetime: s }), [i, a, r, s]),
      k = (0, Q.useMemo)(() => (x > 0 ? [{ id: Be, name: Be }] : Le), [x]),
      A = (0, Q.useCallback)(() => {
        T(new Set());
      }, []),
      { data: j, isLoading: N, error: P } = ae(d ? { search: c } : { search: void 0 }),
      F = d ? j?.environments?.[0] : void 0;
    return h || _
      ? null
      : d
        ? (0, $.jsxs)(`div`, {
            className: `flex h-full flex-col`,
            children: [
              (0, $.jsx)(`div`, {
                className: `text-base`,
                children: `Inventory of running and stopped environments in your organization.`,
              }),
              N &&
                (0, $.jsx)(me, {
                  wait: 300,
                  children: (0, $.jsx)(`div`, {
                    className: `mt-8 flex items-center justify-center`,
                    children: (0, $.jsx)(ee, { className: `animate-spin`, size: `sm` }),
                  }),
                }),
              (P || (j && !F)) &&
                (0, $.jsxs)(`div`, {
                  className: `mt-8`,
                  children: [
                    (0, $.jsx)(he, {
                      title: `Environment not found`,
                      description: `Could not load environment ${c?.slice(0, 8)}…`,
                      "data-testid": `deeplink-error-state`,
                    }),
                    (0, $.jsx)(`div`, {
                      className: `mt-4`,
                      children: (0, $.jsx)(M, {
                        variant: `secondary`,
                        onClick: p,
                        "data-tracking-id": `deeplink-show-all`,
                        children: `Show all environments`,
                      }),
                    }),
                  ],
                }),
              F &&
                (0, $.jsx)(nt, {
                  environmentId: F.id,
                  createdAt: F.metadata?.createdAt,
                  currentLockdownAt: F.metadata?.lockdownAt,
                  maxEnvLifetime: x,
                  onClose: p,
                  environment: F,
                  runners: m,
                }),
            ],
          })
        : (0, $.jsxs)(`div`, {
            className: `flex h-full flex-col`,
            children: [
              (0, $.jsx)(`div`, {
                className: `text-base`,
                children: `Inventory of running and stopped environments in your organization.`,
              }),
              c &&
                (0, $.jsxs)(`div`, {
                  className: `mt-2 flex items-center gap-2 rounded-md border border-border-light bg-surface-secondary px-3 py-2`,
                  children: [
                    (0, $.jsxs)(V, {
                      className: `text-sm`,
                      children: [`Searching for `, (0, $.jsx)(`strong`, { children: c })],
                    }),
                    (0, $.jsx)(M, {
                      type: `button`,
                      variant: `ghost`,
                      size: `sm`,
                      onClick: p,
                      "data-tracking-id": `clear-search-filter`,
                      children: `Show all`,
                    }),
                  ],
                }),
              (0, $.jsx)(Ge, { runners: E, initialValue: D, lifetimeOptions: k, onFilterChange: b, className: `pt-4` }),
              (0, $.jsx)(Ze, {
                filterValue: C,
                runners: m || [],
                maxEnvLifetime: x,
                showLifetime: x > 0,
                selectedIds: w,
                onSelectionChange: T,
                onBulkComplete: A,
                className: `flex flex-grow flex-col pt-4`,
              }),
            ],
          });
  },
  ze = {
    Creating: E.CREATING,
    Starting: E.STARTING,
    Running: E.RUNNING,
    Updating: E.UPDATING,
    Stopping: E.STOPPING,
    Stopped: E.STOPPED,
    Deleting: E.DELETING,
    Deleted: E.DELETED,
  },
  Be = `Exceeded`,
  Ve = [{ kind: D.REMOTE, key: `remote`, name: `All remote runners` }],
  He = { id: `all`, name: `All runners` },
  Ue = { id: `all`, name: `All phases` },
  We = { id: `all`, name: `All lifetime states` },
  Ge = (0, Q.memo)(({ className: e, runners: t, initialValue: n, lifetimeOptions: r, onFilterChange: i }) => {
    let [a, o] = (0, Q.useState)(n),
      [s, c] = (0, Q.useState)(n.runnerID),
      [l, d] = (0, Q.useState)(n.creatorID),
      [f, p] = (0, Q.useState)(n.projectID),
      [m, h] = (0, Q.useState)(n.runnerKind),
      [g, _] = (0, Q.useState)(),
      [v, y] = (0, Q.useState)(n.lifetime),
      b = (0, Q.useCallback)((e) => {
        if (e === `all`) {
          (h(void 0), c(void 0));
          return;
        }
        for (let t of Ve)
          if (e === t.key) {
            (h(t.kind), c(void 0));
            return;
          }
        (h(void 0), c(e));
      }, []),
      x = u((e) => {
        i && i(e);
      }, 100);
    ((0, Q.useEffect)(() => {
      x({ ...a });
    }, [a, x]),
      (0, Q.useEffect)(() => {
        o((e) =>
          s !== e.runnerID ||
          l !== e.creatorID ||
          f !== e.projectID ||
          m !== e.runnerKind ||
          g !== e.phase ||
          v !== e.lifetime
            ? {
                ...e,
                runnerID: s,
                creatorID: l,
                projectID: f,
                runnerKind: m,
                phase: g ? ze[g] : void 0,
                lifetime: v || void 0,
              }
            : e,
        );
      }, [s, l, f, m, g, v]));
    let S = (0, Q.useMemo)(() => {
        let e = [He];
        for (let t of Ve) e.push({ id: t.key, name: t.name });
        for (let n of t) e.push({ id: n.runnerId, name: n.name });
        return e;
      }, [t]),
      C = (0, Q.useMemo)(() => [Ue, ...Object.keys(ze).map((e) => ({ id: e, name: e }))], []),
      w = (0, Q.useMemo)(() => (r.length === 0 ? [] : [We, ...r]), [r]),
      T = (0, Q.useMemo)(() => {
        for (let e of Ve) if (m === e.kind) return e.key;
        return s ?? `all`;
      }, [s, m]),
      E = (0, Q.useMemo)(() => S.find((e) => e.id === T)?.name ?? `All runners`, [S, T]),
      D = (0, Q.useCallback)(
        (e) => {
          p(e === `all` ? void 0 : e);
        },
        [p],
      ),
      O = (0, Q.useCallback)(
        (e) => {
          d(e === `all` ? void 0 : e);
        },
        [d],
      ),
      k = (0, Q.useCallback)(
        (e) => {
          _(e === `all` ? void 0 : e);
        },
        [_],
      ),
      A = (0, Q.useCallback)(
        (e) => {
          y(e === `all` ? void 0 : e);
        },
        [y],
      );
    return (0, $.jsxs)(`div`, {
      className: N(`grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5`, e),
      children: [
        (0, $.jsx)(be, { selectedProject: f ?? null, onProjectChange: D, placeholder: `All projects` }),
        (0, $.jsx)(ge, { selectedMember: l ?? null, onMemberChange: O, includeServiceAccounts: !0 }),
        (0, $.jsxs)(X, {
          value: T,
          onValueChange: b,
          filterPlaceholder: `Search runners...`,
          children: [
            (0, $.jsx)(X.Value, { children: (0, $.jsx)(X.ValueLabel, { children: E }) }),
            (0, $.jsx)(X.Popover, {
              children: (0, $.jsx)(X.List, {
                items: S,
                searchKeys: [`name`],
                noMatchesComponent: (0, $.jsx)(X.Empty, { children: `No runners found` }),
                children: (e) =>
                  (0, $.jsx)(
                    X.ListItem,
                    { value: e.id, children: (0, $.jsx)(X.ListItemTitle, { children: e.name }) },
                    e.id,
                  ),
              }),
            }),
          ],
        }),
        (0, $.jsxs)(X, {
          value: g ?? `all`,
          onValueChange: k,
          filterPlaceholder: `Search phases...`,
          children: [
            (0, $.jsx)(X.Value, { children: (0, $.jsx)(X.ValueLabel, { children: g ?? `All phases` }) }),
            (0, $.jsx)(X.Popover, {
              children: (0, $.jsx)(X.List, {
                items: C,
                searchKeys: [`name`],
                noMatchesComponent: (0, $.jsx)(X.Empty, { children: `No phases found` }),
                children: (e) =>
                  (0, $.jsx)(
                    X.ListItem,
                    { value: e.id, children: (0, $.jsx)(X.ListItemTitle, { children: e.name }) },
                    e.id,
                  ),
              }),
            }),
          ],
        }),
        w.length > 0 &&
          (0, $.jsxs)(X, {
            value: v ?? `all`,
            onValueChange: A,
            filterPlaceholder: `Search lifetimes...`,
            children: [
              (0, $.jsx)(X.Value, { children: (0, $.jsx)(X.ValueLabel, { children: v ?? `All lifetime states` }) }),
              (0, $.jsx)(X.Popover, {
                children: (0, $.jsx)(X.List, {
                  items: w,
                  searchKeys: [`name`],
                  noMatchesComponent: (0, $.jsx)(X.Empty, { children: `No lifetime filters found` }),
                  children: (e) =>
                    (0, $.jsx)(
                      X.ListItem,
                      { value: e.id, children: (0, $.jsx)(X.ListItemTitle, { children: e.name }) },
                      e.id,
                    ),
                }),
              }),
            ],
          }),
      ],
    });
  });
Ge.displayName = `Filter`;
var Ke = ({ environment: e }) => {
    let { data: t } = K(e.metadata?.projectId),
      n = (0, Q.useMemo)(
        () =>
          t?.metadata?.name ? t?.metadata?.name : Y(e)?.repoUrl?.replace(`https://github.com/`, ``) || `From scratch`,
        [e, t?.metadata?.name],
      );
    return (0, $.jsx)(V, { className: `block truncate text-base`, title: n, children: n });
  },
  qe = ({ environment: e }) => {
    let t = e.metadata?.creator,
      n = t?.principal === S.USER,
      i = t?.principal === S.SERVICE_ACCOUNT,
      { data: a } = T(t?.id ?? ``, { enabled: n && !!t?.id }),
      { data: o } = r({ serviceAccountId: t?.id ?? ``, enabled: i && !!t?.id }),
      s = a?.fullName || o?.name,
      c = a?.avatarUrl;
    return (0, $.jsxs)(`div`, {
      className: `inline-flex grow items-center gap-2 overflow-hidden`,
      children: [
        (0, $.jsxs)(q, {
          size: 32,
          className: `shrink-0`,
          children: [
            c && (0, $.jsx)(q.Image, { src: c, alt: `${s || `Unknown`}'s avatar` }),
            (0, $.jsx)(q.Fallback, { children: (0, $.jsx)(q.Initials, { name: s || `Unknown`, size: 32 }) }),
          ],
        }),
        (0, $.jsx)(V, { className: `truncate text-base`, title: s, children: s }),
      ],
    });
  },
  Je = ({ environment: e, runnersMap: t }) =>
    (0, $.jsx)(V, { className: `text-base`, children: t.get(e.metadata?.runnerId)?.name }),
  Ye = ({ date: e, className: t, title: n }) =>
    e
      ? (0, $.jsxs)(V, {
          className: t,
          title: n,
          children: [
            (0, $.jsx)(`span`, { className: `@[1650px]:hidden`, children: R(e, `short`) }),
            (0, $.jsx)(`span`, { className: `hidden @[1650px]:inline`, children: R(e, `long`) }),
          ],
        })
      : (0, $.jsx)(V, { className: t, children: `` }),
  Xe = ({ remainingMs: e }) => {
    if (e === void 0) return (0, $.jsx)(`span`, { className: `text-base text-content-tertiary`, children: `—` });
    let t = Math.abs(e) / 1e3,
      n = z(t, `long`, `coarse`),
      r = z(t, `short`, `coarse`);
    if (e <= 0) {
      let e = `Exceeded by ${n}`,
        t = `Exceeded by ${r}`;
      return (0, $.jsxs)(`span`, {
        className: `flex items-center gap-1`,
        title: e,
        children: [
          (0, $.jsx)(y, { className: `h-4 w-4 shrink-0 text-content-red` }),
          (0, $.jsxs)(`span`, {
            className: `text-base text-content-red`,
            children: [
              (0, $.jsx)(`span`, { className: `@[1650px]:hidden`, children: t }),
              (0, $.jsx)(`span`, { className: `hidden @[1650px]:inline`, children: e }),
            ],
          }),
        ],
      });
    }
    let i = `${n} remaining`;
    return (0, $.jsxs)(`span`, {
      className: `text-base`,
      title: i,
      children: [
        (0, $.jsx)(`span`, { className: `@[1650px]:hidden`, children: `${r} remaining` }),
        (0, $.jsx)(`span`, { className: `hidden @[1650px]:inline`, children: i }),
      ],
    });
  },
  Ze = ({
    filterValue: e,
    className: t,
    runners: n,
    maxEnvLifetime: r,
    showLifetime: o,
    selectedIds: s,
    onSelectionChange: c,
    onBulkComplete: u,
  }) => {
    let d = p(),
      f = ie(),
      m = JSON.stringify(e),
      h = (0, Q.useRef)(m);
    (0, Q.useEffect)(() => {
      h.current !== m && ((h.current = m), f.reset(), c(new Set()));
    }, [m, f, c]);
    let { data: _, isFetching: v } = ae({ ...e, token: f.currentToken }),
      b = (0, Q.useMemo)(() => _?.environments ?? [], [_?.environments]),
      { memberIds: x, serviceAccountIds: w } = (0, Q.useMemo)(() => {
        let e = new Set(),
          t = new Set();
        for (let n of b) {
          let r = n.metadata?.creator;
          r?.id && (r.principal === S.USER ? e.add(r.id) : r.principal === S.SERVICE_ACCOUNT && t.add(r.id));
        }
        return { memberIds: Array.from(e), serviceAccountIds: Array.from(t) };
      }, [b]);
    (A(x, { enabled: x.length > 0 }), i(w, { enabled: w.length > 0 }));
    let T = (0, Q.useCallback)(
        (e) => {
          if (e) return C(d, e);
        },
        [d],
      ),
      D = (0, Q.useCallback)(
        (e) => {
          if (e) return a(d, e);
        },
        [d],
      ),
      O = (0, Q.useMemo)(() => {
        let e = new Map();
        for (let t of n) e.set(t.runnerId, t);
        return e;
      }, [n]),
      ee = (0, Q.useMemo)(() => s, [s]),
      P = (0, Q.useCallback)(
        (e) => {
          c(e === `all` ? new Set(b.map((e) => e.id)) : e);
        },
        [c, b],
      ),
      F = (0, Q.useRef)(new Map());
    (0, Q.useEffect)(() => {
      for (let e of b) F.current.set(e.id, e);
    }, [b]);
    let I = (0, Q.useMemo)(() => {
        let e = [];
        for (let t of s) {
          let n = F.current.get(t);
          n && e.push(n);
        }
        return e;
      }, [s, b]),
      [R, z] = (0, Q.useState)(null),
      [ne, B] = (0, Q.useState)(!1),
      V = (0, Q.useCallback)(() => {
        (z(null), B(!1), u());
      }, [u]),
      [H, W] = (0, Q.useState)(null),
      { toast: G } = j(),
      K = se(),
      J = oe(),
      le = (0, Q.useCallback)(
        (e) => {
          K.mutate(e, {
            onError: (e) => {
              G({ title: `Failed to stop environment`, description: k(e) });
            },
          });
        },
        [K, G],
      ),
      Y = (0, Q.useCallback)(
        (e, t) => {
          J.mutate(
            { environmentId: e, force: t },
            {
              onError: (e) => {
                G({
                  title: t ? `Failed to force delete environment` : `Failed to delete environment`,
                  description: k(e),
                });
              },
            },
          );
        },
        [J, G],
      ),
      de = (0, Q.useCallback)(
        async (e) => {
          (await navigator.clipboard.writeText(e), G({ title: `Environment ID copied to clipboard`, description: e }));
        },
        [G],
      ),
      fe = (0, Q.useMemo)(() => {
        let e = [
          {
            id: `project`,
            header: `Project`,
            isRowHeader: !0,
            className: `max-w-[280px]`,
            cell: (e) => (0, $.jsx)(Ke, { environment: e }),
          },
          {
            id: `member`,
            header: `Member`,
            className: `max-w-[200px]`,
            cell: (e) => (0, $.jsx)(qe, { environment: e }),
          },
          { id: `runner`, header: `Runner`, cell: (e) => (0, $.jsx)(Je, { environment: e, runnersMap: O }) },
          {
            id: `created`,
            header: `Created`,
            cell: (e) => {
              let t = e.metadata?.createdAt ? g(e.metadata.createdAt) : void 0,
                n = t ? t.toLocaleString() : void 0,
                i = !o || r <= 0 || !t ? !1 : Date.now() - t.getTime() > r * 1e3;
              return (0, $.jsxs)(`div`, {
                className: `flex items-center gap-1`,
                children: [
                  (0, $.jsx)(Ye, { date: t, className: N(`truncate text-base`, i && `text-content-red`), title: n }),
                  i &&
                    (0, $.jsx)(re, {
                      content: `Environment lifetime exceeded`,
                      children: (0, $.jsx)(y, { className: `h-4 w-4 text-content-red` }),
                    }),
                ],
              });
            },
          },
          {
            id: `lastStarted`,
            header: `Last started`,
            cell: (e) => {
              let t = e.metadata?.lastStartedAt ? g(e.metadata.lastStartedAt) : void 0;
              return (0, $.jsx)(Ye, {
                date: t,
                className: `truncate text-base`,
                title: t ? t.toLocaleString() : void 0,
              });
            },
          },
        ];
        return (
          o &&
            e.push({
              id: `lifetime`,
              header: `Lifetime`,
              className: `max-w-[160px]`,
              cell: (e) => (0, $.jsx)(Xe, { remainingMs: Ie(e) }),
            }),
          e.push({
            id: `phase`,
            header: `Phase`,
            cell: (e) => {
              let t = ce(e);
              return t
                ? (0, $.jsx)(`div`, {
                    onClick: (e) => e.stopPropagation(),
                    onPointerDown: (e) => e.stopPropagation(),
                    onKeyDown: (e) => e.stopPropagation(),
                    "data-tracking-id": `phase-tag-container-environment-inventory`,
                    children: (0, $.jsx)(`div`, {
                      className: `max-w-[140px]`,
                      children: (0, $.jsx)(Te, { state: t, size: `md`, truncate: !0 }),
                    }),
                  })
                : null;
            },
          }),
          e
        );
      }, [O, o, r]),
      pe = (0, Q.useCallback)(
        (e) => {
          let t = e.metadata?.creator,
            n = t?.principal === S.USER ? T(t.id) : void 0,
            r = t?.principal === S.SERVICE_ACCOUNT ? D(t.id) : void 0,
            i = O.get(e.metadata?.runnerId);
          return (0, $.jsxs)($.Fragment, {
            children: [
              (0, $.jsx)(Z.RowActionsItem, {
                onClick: () => void de(e.id),
                "data-tracking-id": `copy-environment-id-environment-inventory-item`,
                children: `Copy ID`,
              }),
              (0, $.jsx)(U.Separator, {}),
              (0, $.jsx)(Z.RowActionsItem, {
                onClick: () =>
                  W({ action: `update-lifetime`, environment: e, member: n, serviceAccount: r, runner: i }),
                "data-tracking-id": `show-update-lifetime-modal-environment-inventory-item`,
                children: `Update Lifetime`,
              }),
              (0, $.jsx)(U.Separator, {}),
              (0, $.jsx)(Z.RowActionsItem, {
                disabled: !Ee(e),
                onClick: () => W({ action: `stop`, environment: e, member: n, serviceAccount: r, runner: i }),
                "data-tracking-id": `show-stop-environment-modal-environment-inventory-item`,
                children: `Stop`,
              }),
              e.spec?.desiredPhase !== E.DELETED &&
                (0, $.jsx)(Z.RowActionsItem, {
                  onClick: () => W({ action: `delete`, environment: e, member: n, serviceAccount: r, runner: i }),
                  className: `text-red-500`,
                  "data-tracking-id": `show-delete-environment-modal-environment-inventory-item`,
                  children: `Delete`,
                }),
              e.spec?.desiredPhase === E.DELETED &&
                (0, $.jsx)(Z.RowActionsItem, {
                  onClick: () => W({ action: `force-delete`, environment: e, member: n, serviceAccount: r, runner: i }),
                  className: `text-red-500`,
                  "data-tracking-id": `show-force-delete-environment-modal-environment-inventory-item`,
                  children: `Force Delete`,
                }),
            ],
          });
        },
        [T, D, O, de],
      ),
      X = (0, Q.useCallback)(
        ({ selectedCount: e }) =>
          (0, $.jsxs)($.Fragment, {
            children: [
              (0, $.jsxs)(`span`, {
                className: `text-sm font-medium text-content-primary`,
                "data-tracking-id": `selection-count-environment-inventory`,
                children: [e, ` `, L(e, `item`), ` selected`],
              }),
              (0, $.jsxs)(U, {
                children: [
                  (0, $.jsx)(U.Trigger, {
                    asChild: !0,
                    children: (0, $.jsxs)(M, {
                      size: `sm`,
                      variant: `outline`,
                      "data-tracking-id": `bulk-actions-menu-environment-inventory`,
                      children: [`Actions`, (0, $.jsx)(l, { className: `ml-1 h-3.5 w-3.5` })],
                    }),
                  }),
                  (0, $.jsxs)(U.Content, {
                    align: `start`,
                    children: [
                      (0, $.jsx)(U.Item, {
                        onClick: () => z({ action: `stop`, open: !0 }),
                        "data-tracking-id": `bulk-stop-environment-inventory`,
                        children: `Stop`,
                      }),
                      (0, $.jsx)(U.Item, {
                        onClick: () => z({ action: `delete`, open: !0 }),
                        "data-tracking-id": `bulk-delete-environment-inventory`,
                        children: `Delete`,
                      }),
                      (0, $.jsx)(U.Item, {
                        onClick: () => z({ action: `force-delete`, open: !0 }),
                        "data-tracking-id": `bulk-force-delete-environment-inventory`,
                        children: `Force Delete`,
                      }),
                      (0, $.jsx)(U.Separator, {}),
                      (0, $.jsx)(U.Item, {
                        onClick: () => B(!0),
                        "data-tracking-id": `bulk-update-lifetime-environment-inventory`,
                        children: `Update Lifetime`,
                      }),
                    ],
                  }),
                ],
              }),
            ],
          }),
        [],
      ),
      me = (0, Q.useCallback)(
        (e) => {
          let t = e.metadata?.creator,
            n = t?.principal === S.USER ? T(t.id) : void 0,
            r = t?.principal === S.SERVICE_ACCOUNT ? D(t.id) : void 0,
            i = n?.fullName || r?.name,
            a = n?.avatarUrl,
            s = O.get(e.metadata?.runnerId),
            c = ce(e),
            l = e.metadata?.createdAt ? g(e.metadata.createdAt) : void 0,
            u = e.metadata?.lastStartedAt ? g(e.metadata.lastStartedAt) : void 0,
            d = [
              ...(l
                ? [{ label: `Created`, value: (0, $.jsx)(`span`, { title: l.toLocaleString(), children: te(l) }) }]
                : []),
              ...(u
                ? [{ label: `Started`, value: (0, $.jsx)(`span`, { title: u.toLocaleString(), children: te(u) }) }]
                : []),
              ...(s ? [{ label: `Runner`, value: s.name }] : []),
            ];
          if (o) {
            let t = Ie(e);
            t !== void 0 && d.push({ label: `Lifetime`, value: (0, $.jsx)(Xe, { remainingMs: t }) });
          }
          return {
            icon: (0, $.jsxs)(q, {
              size: 24,
              children: [
                a && (0, $.jsx)(q.Image, { src: a, alt: `${i || `Unknown`}'s avatar` }),
                (0, $.jsx)(q.Fallback, { children: (0, $.jsx)(q.Initials, { name: i || `Unknown`, size: 24 }) }),
              ],
            }),
            title: (0, $.jsxs)(`span`, {
              className: `flex items-center gap-2`,
              children: [
                (0, $.jsx)(Ke, { environment: e }),
                c &&
                  (0, $.jsx)(re, {
                    content: ue(c),
                    children: (0, $.jsx)(`span`, { children: (0, $.jsx)(Te, { state: c, variant: `dot` }) }),
                  }),
              ],
            }),
            description: i,
            details: d,
          };
        },
        [T, D, O, o],
      ),
      ge = (0, Q.useMemo)(
        () =>
          e.runnerID || e.creatorID || e.projectID || e.phase || e.createdBefore
            ? (0, $.jsx)(he, {
                title: `No matches`,
                description: `No environments matching the filters.`,
                "data-testid": `no-matches-empty-state`,
              })
            : (0, $.jsx)(he, {
                title: `It's quiet here`,
                description: `Currently, there are no environments in your organization.`,
                "data-testid": `no-environments-empty-state`,
              }),
        [e],
      );
    return (0, $.jsxs)(`div`, {
      className: N(`flex flex-col`, t),
      children: [
        (0, $.jsx)(Z, {
          "aria-label": `Environment inventory`,
          columns: fe,
          data: b,
          getRowId: (e) => e.id,
          getRowTextValue: (e) => e.metadata?.name || e.id,
          stickyHeader: !0,
          selectionMode: `multiple`,
          selectedKeys: ee,
          onSelectionChange: P,
          actionBar: X,
          rowActions: pe,
          mobileRow: me,
          emptyState: ge,
          isLoading: v,
        }),
        (0, $.jsx)(_e, {
          onNext: () => {
            _?.nextToken && f.goToNextPage(_.nextToken);
          },
          onPrevious: f.goToPreviousPage,
          hasNextPage: !!_?.nextToken,
          hasPreviousPage: f.hasPreviousPage,
          isLoading: v,
          currentItemsCount: b.length,
        }),
        R &&
          (0, $.jsx)(Ne, {
            open: R.open,
            onOpenChange: (e) => {
              e || z(null);
            },
            action: R.action,
            environments: I,
            onComplete: V,
          }),
        ne && (0, $.jsx)(Pe, { open: ne, onOpenChange: B, environments: I, maxEnvLifetime: r, onComplete: V }),
        H?.action === `stop` &&
          (H.member || H.serviceAccount) &&
          H.runner &&
          (0, $.jsx)(Qe, {
            environment: H.environment,
            member: H.member,
            serviceAccount: H.serviceAccount,
            runner: H.runner,
            onContinue: () => {
              let e = H.environment.id;
              (W(null), le(e));
            },
            onClose: () => W(null),
          }),
        H?.action === `delete` &&
          (H.member || H.serviceAccount) &&
          H.runner &&
          (0, $.jsx)($e, {
            environment: H.environment,
            member: H.member,
            serviceAccount: H.serviceAccount,
            runner: H.runner,
            onContinue: () => {
              let e = H.environment.id;
              (W(null), Y(e, !1));
            },
            onClose: () => W(null),
          }),
        H?.action === `force-delete` &&
          (H.member || H.serviceAccount) &&
          H.runner &&
          (0, $.jsx)(et, {
            environment: H.environment,
            member: H.member,
            serviceAccount: H.serviceAccount,
            runner: H.runner,
            onContinue: () => {
              let e = H.environment.id;
              (W(null), Y(e, !0));
            },
            onClose: () => W(null),
          }),
        H?.action === `update-lifetime` &&
          (0, $.jsx)(nt, {
            environmentId: H.environment.id,
            createdAt: H.environment.metadata?.createdAt,
            currentLockdownAt: H.environment.metadata?.lockdownAt,
            maxEnvLifetime: r,
            onClose: () => W(null),
            environment: H.environment,
            runners: H.runner ? [H.runner] : void 0,
          }),
      ],
    });
  },
  Qe = (e) =>
    (0, $.jsx)(P, {
      open: !0,
      onOpenChange: e.onClose,
      children: (0, $.jsxs)(P.Content, {
        className: `max-w-lg`,
        "data-track-location": b.InventoryStopEnvironmentModal,
        children: [
          (0, $.jsxs)(P.Header, {
            children: [(0, $.jsx)(P.Title, { children: `Stop environment` }), (0, $.jsx)(P.Description, {})],
          }),
          (0, $.jsxs)(P.Description, {
            children: [
              e.serviceAccount
                ? (0, $.jsx)(`span`, { children: `This will stop the service account's environment.` })
                : (0, $.jsx)(`span`, {
                    children: `This will stop the user's environment. They won't lose any changes.`,
                  }),
              (0, $.jsx)(rt, { ...e, className: `mt-4` }),
              e.member &&
                (0, $.jsxs)(`div`, {
                  className: `mt-4`,
                  children: [
                    `Tip: You may want to let `,
                    e.member.fullName,
                    ` know that you've stopped their environment.`,
                  ],
                }),
            ],
          }),
          (0, $.jsxs)(P.Footer, {
            children: [
              (0, $.jsx)(P.Close, {
                asChild: !0,
                children: (0, $.jsx)(M, {
                  type: `button`,
                  variant: `outline`,
                  onClick: e.onClose,
                  "data-tracking-id": `cancel-stop-environment-inventory-modal`,
                  children: `Cancel`,
                }),
              }),
              (0, $.jsx)(M, {
                type: `submit`,
                autoFocus: !0,
                variant: `destructive`,
                onClick: (t) => {
                  (t.preventDefault(), e.onContinue());
                },
                "data-tracking-id": `confirm-stop-environment-inventory-modal`,
                children: `Stop`,
              }),
            ],
          }),
        ],
      }),
    }),
  $e = (e) =>
    (0, $.jsx)(P, {
      open: !0,
      onOpenChange: e.onClose,
      children: (0, $.jsxs)(P.Content, {
        className: `max-w-lg`,
        "data-track-location": b.InventoryDeleteEnvironmentModal,
        children: [
          (0, $.jsxs)(P.Header, {
            children: [(0, $.jsx)(P.Title, { children: `Delete environment` }), (0, $.jsx)(P.Description, {})],
          }),
          (0, $.jsxs)(P.Description, {
            children: [
              e.serviceAccount
                ? (0, $.jsx)(`span`, { children: `This will delete the service account's environment.` })
                : (0, $.jsx)(`span`, {
                    children: `This will delete the user's environment. They may lose any uncommitted changes.`,
                  }),
              (0, $.jsx)(rt, { ...e, className: `mt-4` }),
              e.member &&
                (0, $.jsxs)(`div`, {
                  className: `mt-4`,
                  children: [
                    `Tip: You may want to let `,
                    e.member.fullName,
                    ` know that you've deleted their environment.`,
                  ],
                }),
            ],
          }),
          (0, $.jsxs)(P.Footer, {
            children: [
              (0, $.jsx)(P.Close, {
                asChild: !0,
                children: (0, $.jsx)(M, {
                  type: `button`,
                  variant: `outline`,
                  onClick: e.onClose,
                  "data-tracking-id": `cancel-delete-environment-inventory-modal`,
                  children: `Cancel`,
                }),
              }),
              (0, $.jsx)(M, {
                type: `submit`,
                autoFocus: !0,
                variant: `destructive`,
                onClick: (t) => {
                  (t.preventDefault(), e.onContinue());
                },
                "data-tracking-id": `confirm-delete-environment-inventory-modal`,
                children: `Delete`,
              }),
            ],
          }),
        ],
      }),
    }),
  et = (e) =>
    (0, $.jsx)(P, {
      open: !0,
      onOpenChange: e.onClose,
      children: (0, $.jsxs)(P.Content, {
        className: `max-w-lg`,
        "data-track-location": b.InventoryForceDeleteEnvironmentModal,
        children: [
          (0, $.jsxs)(P.Header, {
            children: [(0, $.jsx)(P.Title, { children: `Irreversible Action` }), (0, $.jsx)(P.Description, {})],
          }),
          (0, $.jsxs)(P.Description, {
            children: [
              e.serviceAccount
                ? (0, $.jsx)(`span`, {
                    children: `This will force delete the service account's environment, which may leave some infrastructure or files behind that require manual cleanup.`,
                  })
                : (0, $.jsx)(`span`, {
                    children: `This will force delete the user's environment, which may leave some infrastructure or files behind that require manual cleanup.`,
                  }),
              (0, $.jsx)(rt, { ...e, className: `mt-4` }),
              e.member &&
                (0, $.jsxs)(`div`, {
                  className: `mt-4`,
                  children: [
                    `Tip: You may want to let `,
                    e.member.fullName,
                    ` know that you've force deleted their environment.`,
                  ],
                }),
            ],
          }),
          (0, $.jsxs)(P.Footer, {
            children: [
              (0, $.jsx)(P.Close, {
                asChild: !0,
                children: (0, $.jsx)(M, {
                  type: `button`,
                  variant: `outline`,
                  onClick: e.onClose,
                  "data-tracking-id": `cancel-force-delete-environment-force-delete-environment-modal`,
                  children: `Cancel`,
                }),
              }),
              (0, $.jsx)(M, {
                type: `submit`,
                autoFocus: !0,
                variant: `destructive`,
                onClick: (t) => {
                  (t.preventDefault(), e.onContinue());
                },
                "data-tracking-id": `confirm-force-delete-environment-force-delete-environment-modal`,
                children: `Force delete`,
              }),
            ],
          }),
        ],
      }),
    }),
  tt = ({ environment: e, runners: t }) => {
    let [n, r] = (0, Q.useState)(!1),
      { data: i } = K(e.metadata?.projectId),
      a = t?.find((t) => t.runnerId === e.metadata?.runnerId),
      o = (0, Q.useMemo)(() => ce(e), [e]),
      c = (0, Q.useMemo)(() => Y(e)?.repoUrl?.replace(`https://github.com/`, ``) || void 0, [e]),
      u = i?.metadata?.name,
      d = e.metadata?.name || u || c || e.id.slice(0, 8),
      f = e.metadata?.createdAt ? g(e.metadata.createdAt).toLocaleString() : void 0,
      p = e.metadata?.lastStartedAt ? g(e.metadata.lastStartedAt).toLocaleString() : void 0,
      m = Ie(e);
    return (0, $.jsxs)(`div`, {
      className: `py-1`,
      children: [
        (0, $.jsxs)(V, {
          className: `text-sm text-content-secondary`,
          children: [
            `This change will be applied to environment `,
            (0, $.jsx)(`strong`, { className: `text-content-primary`, children: d }),
            `.`,
          ],
        }),
        (0, $.jsxs)(J, {
          open: n,
          onOpenChange: r,
          children: [
            (0, $.jsxs)(J.Trigger, {
              className: `mt-1.5 flex items-center gap-1 text-sm text-content-secondary hover:text-content-primary focus-visible:underline focus-visible:outline-none`,
              children: [
                n ? (0, $.jsx)(l, { size: 12 }) : (0, $.jsx)(s, { size: 12 }),
                (0, $.jsx)(`span`, { children: n ? `Hide details` : `Show details` }),
              ],
            }),
            (0, $.jsx)(J.Content, {
              children: (0, $.jsxs)(`dl`, {
                className: `mt-2 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1.5 rounded-lg border border-border-light bg-surface-secondary p-3 text-sm`,
                children: [
                  (0, $.jsx)(`dt`, { className: `text-content-tertiary`, children: `ID` }),
                  (0, $.jsx)(`dd`, {
                    className: `overflow-x-auto font-mono text-xs text-content-secondary`,
                    children: e.id,
                  }),
                  o &&
                    (0, $.jsxs)($.Fragment, {
                      children: [
                        (0, $.jsx)(`dt`, { className: `text-content-tertiary`, children: `Phase` }),
                        (0, $.jsx)(`dd`, { className: `text-content-secondary`, children: ue(o) }),
                      ],
                    }),
                  m !== void 0 &&
                    (0, $.jsxs)($.Fragment, {
                      children: [
                        (0, $.jsx)(`dt`, { className: `text-content-tertiary`, children: `Lifetime` }),
                        (0, $.jsx)(`dd`, {
                          className: N(m <= 0 ? `text-content-red` : `text-content-secondary`),
                          children:
                            m <= 0
                              ? `${z(Math.abs(m) / 1e3, `long`, `coarse`)} over`
                              : `${z(m / 1e3, `long`, `coarse`)} remaining`,
                        }),
                      ],
                    }),
                  u &&
                    (0, $.jsxs)($.Fragment, {
                      children: [
                        (0, $.jsx)(`dt`, { className: `text-content-tertiary`, children: `Project` }),
                        (0, $.jsx)(`dd`, { className: `truncate text-content-secondary`, children: u }),
                      ],
                    }),
                  c &&
                    (0, $.jsxs)($.Fragment, {
                      children: [
                        (0, $.jsx)(`dt`, { className: `text-content-tertiary`, children: `Repository` }),
                        (0, $.jsx)(`dd`, { className: `truncate text-content-secondary`, children: c }),
                      ],
                    }),
                  a &&
                    (0, $.jsxs)($.Fragment, {
                      children: [
                        (0, $.jsx)(`dt`, { className: `text-content-tertiary`, children: `Runner` }),
                        (0, $.jsx)(`dd`, { className: `truncate text-content-secondary`, children: a.name }),
                      ],
                    }),
                  f &&
                    (0, $.jsxs)($.Fragment, {
                      children: [
                        (0, $.jsx)(`dt`, { className: `text-content-tertiary`, children: `Created` }),
                        (0, $.jsx)(`dd`, { className: `text-content-secondary`, children: f }),
                      ],
                    }),
                  p &&
                    (0, $.jsxs)($.Fragment, {
                      children: [
                        (0, $.jsx)(`dt`, { className: `text-content-tertiary`, children: `Last started` }),
                        (0, $.jsx)(`dd`, { className: `text-content-secondary`, children: p }),
                      ],
                    }),
                ],
              }),
            }),
          ],
        }),
      ],
    });
  },
  nt = ({
    environmentId: e,
    createdAt: t,
    currentLockdownAt: n,
    maxEnvLifetime: r,
    onClose: i,
    environment: a,
    runners: o,
  }) => {
    let s = W(),
      { toast: c } = j(),
      [u, f] = (0, Q.useState)(`extend`),
      [p, g] = (0, Q.useState)(``),
      [v, y] = (0, Q.useState)(void 0),
      x = (0, Q.useMemo)(() => {
        if (!(r <= 0)) return ve(r);
      }, [r]),
      S = (0, Q.useMemo)(() => {
        if (r <= 0 || !t) return;
        let e = Number(t.seconds) * 1e3;
        return ye(new Date(e + r * 1e3));
      }, [r, t]),
      C = !!n,
      T = (0, Q.useCallback)(async () => {
        try {
          (await s.mutateAsync({
            req: { environmentId: e, metadata: m(w, { lockdownAt: m(h, { seconds: BigInt(0), nanos: 0 }) }) },
          }),
            c({ title: `Lifetime limit removed` }),
            i());
        } catch (e) {
          c({ title: `Failed to remove lifetime limit`, description: k(e) });
        }
      }, [e, s, c, i]),
      E = (0, Q.useCallback)(async () => {
        if (!u) {
          y(`Please select an option.`);
          return;
        }
        let t;
        switch (u) {
          case `clear`:
            (y(void 0), T());
            return;
          case `now`:
            t = _(new Date());
            break;
          case `extend`:
          case `custom`:
          case `policy`: {
            let e = u === `policy` ? (S ?? ``) : p;
            if (!e) {
              y(`Please select a date and time.`);
              return;
            }
            let n = new Date(e);
            if (isNaN(n.getTime())) {
              y(`Invalid date.`);
              return;
            }
            if (n <= new Date()) {
              y(`Date must be in the future.`);
              return;
            }
            t = _(n);
            break;
          }
        }
        y(void 0);
        try {
          (await s.mutateAsync({ req: { environmentId: e, metadata: m(w, { lockdownAt: t }) } }),
            c({ title: `Environment lifetime updated` }),
            i());
        } catch (e) {
          c({ title: `Failed to update environment lifetime`, description: k(e) });
        }
      }, [u, p, S, e, s, c, i, T]),
      D = (0, Q.useMemo)(() => {
        switch (u) {
          case `extend`:
            return `Extend`;
          case `custom`:
            return `Custom`;
          case `now`:
            return `Current Date/Time`;
          case `policy`:
            return `Restore Org Policy: ${x}`;
          case `clear`:
            return `Clear limit`;
          default:
            return `Select lifetime`;
        }
      }, [u, x]),
      O = (0, Q.useMemo)(() => {
        if (u === `policy`) return S;
        if (u === `extend` || u === `custom`) return p || void 0;
      }, [u, p, S]);
    return (0, $.jsx)(P, {
      open: !0,
      onOpenChange: i,
      children: (0, $.jsxs)(P.Content, {
        className: `max-w-lg overflow-hidden p-0`,
        "data-track-location": b.InventoryUpdateLifetimeModal,
        children: [
          (0, $.jsxs)(P.Header, {
            className: `shrink-0 px-6 pt-6`,
            children: [
              (0, $.jsx)(P.Title, { children: `Update environment lifetime` }),
              (0, $.jsx)(P.Description, {
                children:
                  r > 0
                    ? `Set a new lifetime limit for this environment.`
                    : `This environment has a lifetime limit from a previous policy. You can update or clear it.`,
              }),
            ],
          }),
          (0, $.jsxs)(`div`, {
            className: `flex items-center gap-2 px-6 pt-2`,
            children: [
              (0, $.jsxs)(U, {
                children: [
                  (0, $.jsx)(U.Trigger, {
                    asChild: !0,
                    children: (0, $.jsxs)(M, {
                      type: `button`,
                      variant: `outline`,
                      className: `gap-1.5`,
                      "data-tracking-id": `lifetime-picker`,
                      children: [(0, $.jsx)(`span`, { children: D }), (0, $.jsx)(l, { size: 14 })],
                    }),
                  }),
                  (0, $.jsxs)(U.Content, {
                    align: `start`,
                    className: `w-52`,
                    children: [
                      (0, $.jsx)(U.Item, {
                        onClick: () => {
                          (f(`extend`), g(``), y(void 0));
                        },
                        "data-tracking-id": `mode-extend-lifetime`,
                        children: `Extend`,
                      }),
                      (0, $.jsx)(U.Item, {
                        onClick: () => {
                          (f(`now`), g(``), y(void 0));
                        },
                        "data-tracking-id": `mode-now-lifetime`,
                        children: `Current Date/Time`,
                      }),
                      (0, $.jsx)(U.Item, {
                        onClick: () => {
                          (f(`custom`), g(``), y(void 0));
                        },
                        "data-tracking-id": `mode-custom-lifetime`,
                        children: `Custom`,
                      }),
                      x &&
                        S &&
                        (0, $.jsxs)($.Fragment, {
                          children: [
                            (0, $.jsx)(U.Separator, {}),
                            (0, $.jsxs)(U.Item, {
                              onClick: () => {
                                (f(`policy`), g(``), y(void 0));
                              },
                              "data-tracking-id": `mode-policy-lifetime`,
                              children: [`Restore Org Policy: `, x],
                            }),
                          ],
                        }),
                      C &&
                        (0, $.jsxs)($.Fragment, {
                          children: [
                            (0, $.jsx)(U.Separator, {}),
                            (0, $.jsx)(U.Item, {
                              onClick: () => {
                                (f(`clear`), g(``), y(void 0));
                              },
                              className: `text-content-red`,
                              "data-tracking-id": `mode-clear-lifetime`,
                              children: `Clear limit`,
                            }),
                          ],
                        }),
                    ],
                  }),
                ],
              }),
              u === `extend` &&
                (0, $.jsx)(Oe, {
                  onChange: (e) => {
                    (g(e), y(void 0));
                  },
                }),
            ],
          }),
          (0, $.jsxs)(`div`, {
            className: `min-h-0 overflow-y-auto overscroll-contain px-6`,
            children: [
              a && (0, $.jsx)(tt, { environment: a, runners: o }),
              (0, $.jsxs)(`div`, {
                className: `flex flex-col gap-3 py-2`,
                children: [
                  u === `custom` &&
                    (0, $.jsx)(Q.Suspense, {
                      fallback: (0, $.jsx)(`div`, {
                        className: `flex h-[300px] items-center justify-center`,
                        children: (0, $.jsx)(d, { className: `h-5 w-5 animate-spin text-content-secondary` }),
                      }),
                      children: (0, $.jsx)(Fe, {
                        value: p,
                        onChange: (e) => {
                          (g(e), y(void 0));
                        },
                      }),
                    }),
                  u === `now` &&
                    (0, $.jsx)(I, { variant: `info`, text: `Lifetime limit will be set to the current time on save.` }),
                  u === `clear` && (0, $.jsx)(I, { variant: `info`, text: `Limit will be cleared.` }),
                  u === `policy` &&
                    S &&
                    (0, $.jsx)(I, { variant: `info`, text: `New lifetime limit: ${new Date(S).toLocaleString()}` }),
                  O &&
                    u !== `policy` &&
                    (0, $.jsx)(I, { variant: `info`, text: `New lifetime limit: ${new Date(O).toLocaleString()}` }),
                  v && (0, $.jsx)(V, { className: `text-center text-sm text-content-red`, children: v }),
                ],
              }),
            ],
          }),
          (0, $.jsxs)(P.Footer, {
            className: `shrink-0 border-t border-border-base px-6 py-4`,
            children: [
              (0, $.jsx)(P.Close, {
                asChild: !0,
                children: (0, $.jsx)(M, {
                  type: `button`,
                  variant: `outline`,
                  onClick: i,
                  "data-tracking-id": `cancel-update-lifetime-environment-inventory-modal`,
                  children: `Cancel`,
                }),
              }),
              (0, $.jsx)(M, {
                type: `submit`,
                autoFocus: !0,
                variant: `primary`,
                onClick: (e) => {
                  (e.preventDefault(), E());
                },
                loading: s.isPending,
                disabled: s.isPending,
                "data-tracking-id": `confirm-update-lifetime-environment-inventory-modal`,
                children: `Save`,
              }),
            ],
          }),
        ],
      }),
    });
  },
  rt = (e) => {
    let t = e.member?.fullName || e.serviceAccount?.name,
      n = e.member?.avatarUrl,
      { data: r } = K(e.environment.metadata?.projectId),
      i = (0, Q.useMemo)(
        () =>
          r?.metadata?.name
            ? r?.metadata?.name
            : Y(e.environment)?.repoUrl?.replace(`https://github.com/`, ``) || `From scratch`,
        [e.environment, r?.metadata?.name],
      );
    return (0, $.jsxs)(`div`, {
      className: N(
        `flex w-full flex-row rounded-lg border border-solid border-border-light bg-surface-secondary px-4 py-2`,
        e.className,
      ),
      children: [
        (0, $.jsxs)(`div`, {
          className: `flex flex-grow flex-col`,
          children: [
            (0, $.jsx)(V, { className: `text-base font-bold`, children: i }),
            (0, $.jsx)(V, { className: `text-base`, children: e.runner.name }),
          ],
        }),
        (0, $.jsxs)(`div`, {
          className: `inline-flex items-center space-x-2`,
          children: [
            (0, $.jsxs)(q, {
              size: 32,
              children: [
                n && (0, $.jsx)(q.Image, { src: n, alt: `${t || `Unknown`}'s avatar` }),
                (0, $.jsx)(q.Fallback, { children: (0, $.jsx)(q.Initials, { name: t || `Unknown`, size: 32 }) }),
              ],
            }),
            (0, $.jsx)(V, { className: `text-base`, children: t }),
          ],
        }),
      ],
    });
  },
  it = () => {
    n(`Environments`);
    let { membership: e, isPending: r } = F();
    return r
      ? null
      : e
        ? e.userRole === x.ADMIN
          ? (0, $.jsx)(Re, {})
          : (0, $.jsx)(t, {})
        : (0, $.jsx)($.Fragment, {});
  };
export { it as EnvironmentInventoryPage };
